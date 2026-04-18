"""
GHArchive discovery scraper.

Bypasses the GitHub search API by downloading hourly public dumps from
https://data.gharchive.org/ and picking PushEvents against IaC-related
repositories, then resolving each push's head commit via the GitHub API.

Schema note: as of GHArchive ~2015+ the PushEvent payload no longer carries
an inline `commits:[{message}]` array — it only carries `{ref, head, before,
push_id}`. So we cannot filter on commit message at the dump level. Instead
we apply a two-stage filter:

  1. Pre-filter by REPO NAME — keep only pushes against repos whose full
     name matches an IaC-related regex (terraform, k8s, kube, helm, docker,
     ansible, pulumi, cloudformation, iac, infra, …).
  2. Enrich via the commit API — fetch each candidate head commit through
     `_process_commit()`, which applies the full IaC-file + security-smell
     filter. Non-matches are dropped.

This is still massively cheaper than using the search API because:
  - GHArchive is free and unthrottled for discovery.
  - The GitHub core API has a 5000 req/hr quota (search API has 30 req/min).
  - One commit API call per push vs. search → much higher effective rate.

Over a week: 5000 core req/h × 168 h = ~840k commit fetches. With the repo
prefilter yielding ~1-5k candidates/hour, the scraper can keep up with a
near-real-time firehose of IaC-relevant commits.
"""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator, Dict, List, Optional, Set, Tuple

import aiohttp

from scraping.config import GITHUB_TOKEN
from scraping.scrapers.github import (
    GitHubSession,
    _get_repo_meta,
    _process_commit,
)
from scraping.schemas import IaCRecord

logger = logging.getLogger(__name__)


GHARCHIVE_BASE = "https://data.gharchive.org"


# Commit message regex (used at enrichment time, not dump time)
_SECURITY_MSG_REGEX = re.compile(
    r"(?ix)"
    r"\b("
    r"fix(?:es|ed|ing)?|patch(?:es|ed|ing)?|resolv\w*|"
    r"remediat\w*|harden\w*|secur\w*|mitigat\w*|disable|enable|remove"
    r")\b"
    r".{0,120}?"
    r"("
    r"cve|cwe|vulnerab|security|secret|password|credential|token|api[- ]?key|"
    r"tls|ssl|encrypt|iam|rbac|privileg|public[- ]?access|exposed|leak|"
    r"checkov|tfsec|kics|terrascan|snyk|trivy|prowler|"
    r"s3\s*bucket|open\s*port|0\.0\.0\.0|cidr|hardcod"
    r")"
)

# Repo name prefilter — only pushes against repos matching this regex are
# considered candidates. Applied at dump-parse time so we avoid calling the
# GitHub API for obviously-irrelevant pushes.
_REPO_HINT_REGEX = re.compile(
    r"(?i)("
    r"terraform|tf-|\bk8s\b|kube|kubernetes|helm|kustomize|"
    r"docker|dockerfile|ansible|pulumi|cloudformation|\bcfn\b|bicep|"
    r"\biac\b|infra|infrastructure|devops|platform|"
    r"aws[-_]|azure[-_]|gcp[-_]|cloud"
    r")"
)


# ---------------------------------------------------------------------------
# Dump download
# ---------------------------------------------------------------------------

async def _download_dump(
    session: aiohttp.ClientSession,
    hour: datetime,
) -> Optional[bytes]:
    """Download one hourly GHArchive dump. Returns gzipped bytes or None."""
    stamp = hour.strftime("%Y-%m-%d-") + str(hour.hour)
    url = f"{GHARCHIVE_BASE}/{stamp}.json.gz"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=300)) as resp:
            if resp.status != 200:
                logger.warning("GHArchive %s → HTTP %d", stamp, resp.status)
                return None
            return await resp.read()
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        logger.warning("GHArchive %s download failed: %s", stamp, exc)
        return None


def _iter_events(raw: bytes):
    """Yield events from a gzipped newline-delimited JSON dump."""
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
        for line in gz:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _extract_push_candidates(event: Dict) -> List[Tuple[str, str]]:
    """
    From a PushEvent, return [(repo_full_name, head_sha), ...] for repos
    that pass the IaC-name prefilter.

    The modern GHArchive PushEvent payload does not include commit messages
    (only {ref, head, before, push_id}), so we can't filter on message here.
    We return the head SHA per push — the enrichment step will fetch the
    full commit and apply further filters.
    """
    if event.get("type") != "PushEvent":
        return []
    repo = (event.get("repo") or {}).get("name") or ""
    if "/" not in repo:
        return []
    if not _REPO_HINT_REGEX.search(repo):
        return []
    payload = event.get("payload") or {}
    head = payload.get("head") or ""
    if not head:
        return []
    # Also include distinct commit SHAs if GHArchive still provides them
    out: List[Tuple[str, str]] = [(repo, head)]
    for c in payload.get("commits") or []:
        sha = c.get("sha") or ""
        if sha and sha != head:
            out.append((repo, sha))
    return out


def _is_security_relevant(message: str) -> bool:
    return bool(_SECURITY_MSG_REGEX.search(message or ""))


# ---------------------------------------------------------------------------
# Candidate discovery
# ---------------------------------------------------------------------------

async def discover_candidates(
    hours_back: int = 24,
    max_candidates: int = 20_000,
) -> List[Tuple[str, str]]:
    """
    Download the last `hours_back` hourly GHArchive dumps and return a
    deduplicated list of (repo, sha) candidates for IaC-related repos.
    """
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    # GHArchive publishes ~1 hour behind live, skip the current hour
    hours = [now - timedelta(hours=h) for h in range(1, hours_back + 1)]

    seen: Set[Tuple[str, str]] = set()
    candidates: List[Tuple[str, str]] = []

    async with aiohttp.ClientSession() as http:
        sem = asyncio.Semaphore(4)  # parallel dump downloads

        async def _one(hour: datetime) -> List[Tuple[str, str]]:
            async with sem:
                raw = await _download_dump(http, hour)
            if not raw:
                return []
            local: List[Tuple[str, str]] = []
            for ev in _iter_events(raw):
                for repo, sha in _extract_push_candidates(ev):
                    local.append((repo, sha))
            logger.info("GHArchive %s — %d IaC-repo push candidates",
                        hour.strftime("%Y-%m-%d-%H"), len(local))
            return local

        results = await asyncio.gather(*[_one(h) for h in hours])

    for bucket in results:
        for repo, sha in bucket:
            key = (repo, sha)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((repo, sha))
            if len(candidates) >= max_candidates:
                return candidates
    return candidates


# ---------------------------------------------------------------------------
# Candidate enrichment — use GitHub API to fetch per-commit details
# ---------------------------------------------------------------------------

async def enrich_candidates(
    candidates: List[Tuple[str, str]],
    token: Optional[str] = None,
    progress=None,
) -> AsyncIterator[IaCRecord]:
    """
    For each (repo, sha) candidate, fetch the full commit via the GitHub API
    and yield IaCRecord objects (one per changed IaC file). Filtering by
    commit message happens inside _process_commit (has_security_signal check).
    """
    async with GitHubSession(token=token or GITHUB_TOKEN) as session:
        # Group candidates by repo to reuse repo meta
        by_repo: Dict[str, List[str]] = {}
        for repo, sha in candidates:
            by_repo.setdefault(repo, []).append(sha)

        for repo, shas in by_repo.items():
            try:
                owner, repo_name = repo.split("/", 1)
            except ValueError:
                continue
            repo_meta = await _get_repo_meta(session, owner, repo_name)
            for sha in shas:
                # Build the minimal commit dict that _process_commit expects
                fake_commit = {"sha": sha}
                try:
                    records = await _process_commit(
                        session, owner, repo_name, fake_commit, repo_meta
                    )
                except Exception as exc:
                    logger.warning("Enrich error on %s/%s: %s", repo, sha, exc)
                    continue
                for r in records:
                    yield r
                if progress:
                    progress.increment_written(len(records))


# ---------------------------------------------------------------------------
# High-level entry point — used by main.py --gharchive
# ---------------------------------------------------------------------------

async def scrape_gharchive(
    hours_back: int = 24,
    token: Optional[str] = None,
    progress=None,
    max_candidates: int = 20_000,
) -> AsyncIterator[IaCRecord]:
    """
    End-to-end GHArchive scrape: discover candidates → enrich → yield records.
    """
    logger.info("GHArchive: discovering candidates from last %dh", hours_back)
    candidates = await discover_candidates(
        hours_back=hours_back, max_candidates=max_candidates,
    )
    logger.info("GHArchive: %d unique security candidates found", len(candidates))
    async for r in enrich_candidates(candidates, token=token, progress=progress):
        yield r
