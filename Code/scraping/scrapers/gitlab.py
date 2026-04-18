"""
GitLab commit scraper — mirrors the GitHub commit-search shape but
uses GitLab's /search?scope=commits API.

Records emitted here go through the same classifier + tiering + validator
pipeline as GitHub records. `source="gitlab_commit"` and `repo` is set to
the project `path_with_namespace` (owner/group/repo).

Rate limits: authenticated GitLab.com allows ~2000 req/min — far more
generous than GitHub's 5000/hr. We throttle conservatively at 4 req/s to
stay friendly.

Usage:
    python -m scraping.scrapers.gitlab \\
        --output scraping/output/raw/dataset.jsonl \\
        --max-queries 30
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import random
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import aiohttp

from scraping.config import (
    GITLAB_API_BASE,
    GITLAB_TOKEN,
    MAX_FILE_BYTES,
)
from scraping.processors.classifier import (
    classify_diff_smells,
    classify_smells,
    detect_iac_tool,
)
from scraping.processors.tiering import assign_tier
from scraping.schemas import IaCRecord

logger = logging.getLogger(__name__)

GITLAB_RPS = 4.0                  # requests per second
MAX_CONCURRENCY = 8
PER_PAGE = 50                     # GitLab max per search page
MAX_PAGES_PER_QUERY = 4           # ~200 commits per query
SEARCH_TIMEOUT = aiohttp.ClientTimeout(total=25, connect=10, sock_read=20)

_IAC_EXTENSIONS = {".tf", ".tfvars", ".yml", ".yaml", ".json", ".dockerfile"}
_IAC_FILENAMES = {"dockerfile", "vagrantfile"}


def _is_iac_path(path: str) -> bool:
    p = Path(path)
    if p.name.lower() in _IAC_FILENAMES:
        return True
    return p.suffix.lower() in _IAC_EXTENSIONS


def _make_id(project: str, sha: str, file_path: str) -> str:
    raw = f"{project}:{sha}:{file_path}"
    return "GL-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


class GitLabSession:
    """Thin async wrapper with shared rate limiter + retry."""

    def __init__(self, token: str = GITLAB_TOKEN):
        self._token = token
        self._headers = {
            "PRIVATE-TOKEN": token,
            "User-Agent": "iac-security-scraper/1.0",
        }
        self._session: Optional[aiohttp.ClientSession] = None
        self._interval = 1.0 / GITLAB_RPS
        self._last = 0.0
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def __aenter__(self) -> "GitLabSession":
        self._session = aiohttp.ClientSession(headers=self._headers)
        return self

    async def __aexit__(self, *_) -> None:
        if self._session:
            await self._session.close()

    async def _throttle(self) -> None:
        async with self._lock:
            delta = time.monotonic() - self._last
            if delta < self._interval:
                await asyncio.sleep(self._interval - delta)
            self._last = time.monotonic()

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        max_retries: int = 3,
    ) -> Tuple[int, Any]:
        async with self._sem:
            for attempt in range(max_retries):
                await self._throttle()
                try:
                    async with self._session.get(
                        url, params=params, timeout=SEARCH_TIMEOUT
                    ) as r:
                        status = r.status
                        if status == 429:
                            wait = int(r.headers.get("Retry-After", "5"))
                            logger.warning("GitLab 429 — sleeping %ds", wait)
                            await asyncio.sleep(wait)
                            continue
                        if status >= 500:
                            await asyncio.sleep(2 * (attempt + 1))
                            continue
                        if r.headers.get("Content-Type", "").startswith("application/json"):
                            return status, await r.json()
                        return status, await r.text()
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug("GitLab transient %s — retry %d", e, attempt)
                    await asyncio.sleep(2 * (attempt + 1) + random.random())
            return 0, None


_SECURITY_KEYWORDS = (
    "security", "vulnerab", "cve-", "cwe-", "exploit", "credential",
    "password", "secret", "hardcoded", "encrypt", "unencrypt",
    "privilege esc", "misconfig", "harden", "patch ", "fix ",
    "tls", "ssl", "rbac", "iam", "insecure",
)

_PROJECT_SEARCH_TERMS = [
    "terraform", "ansible", "kubernetes", "helm chart",
    "dockerfile", "cloudformation", "pulumi",
    "infrastructure as code", "iac security", "devsecops",
    "terraform module", "kubernetes manifest",
]


async def _search_projects(
    session: GitLabSession, term: str, max_pages: int = 3
) -> AsyncIterator[Dict[str, Any]]:
    """Yield IaC-ish projects matching `term`. Ordered by last-activity."""
    for page in range(1, max_pages + 1):
        status, body = await session.get(
            f"{GITLAB_API_BASE}/projects",
            params={"search": term, "per_page": PER_PAGE, "page": page,
                    "order_by": "last_activity_at", "simple": "true"},
        )
        if status != 200 or not isinstance(body, list) or not body:
            return
        for p in body:
            yield p
        if len(body) < PER_PAGE:
            return


async def _iter_project_commits(
    session: GitLabSession,
    project_id: int,
    max_pages: int = 2,
) -> AsyncIterator[Dict[str, Any]]:
    """Yield recent commits from a project, filtered by security keywords."""
    for page in range(1, max_pages + 1):
        status, body = await session.get(
            f"{GITLAB_API_BASE}/projects/{project_id}/repository/commits",
            params={"per_page": PER_PAGE, "page": page, "all": "false"},
        )
        if status != 200 or not isinstance(body, list) or not body:
            return
        for c in body:
            msg = (c.get("message", "") or c.get("title", "") or "").lower()
            if any(kw in msg for kw in _SECURITY_KEYWORDS):
                yield c
        if len(body) < PER_PAGE:
            return


async def _fetch_commit_diff(
    session: GitLabSession, project_id: int, sha: str
) -> List[Dict[str, Any]]:
    status, body = await session.get(
        f"{GITLAB_API_BASE}/projects/{project_id}/repository/commits/{sha}/diff"
    )
    if status == 200 and isinstance(body, list):
        return body
    return []


async def _fetch_file_at_ref(
    session: GitLabSession, project_id: int, path: str, ref: str
) -> Optional[str]:
    from urllib.parse import quote
    enc = quote(path, safe="")
    url = f"{GITLAB_API_BASE}/projects/{project_id}/repository/files/{enc}/raw"
    status, body = await session.get(url, params={"ref": ref})
    if status == 200 and isinstance(body, str) and len(body) <= MAX_FILE_BYTES:
        return body
    return None


def _diff_to_patch_text(d: Dict[str, Any]) -> str:
    """GitLab returns pre-formatted unified diff in the `diff` key."""
    return d.get("diff") or ""


async def _process_commit(
    session: GitLabSession,
    commit: Dict[str, Any],
    project: Dict[str, Any],
) -> List[Dict[str, Any]]:
    sha = commit.get("id", "")
    project_id = commit.get("project_id") or project.get("id")
    parent_ids = commit.get("parent_ids") or []
    parent_sha = parent_ids[0] if parent_ids else None
    message = commit.get("message", "") or commit.get("title", "")
    author = commit.get("author_name", "")
    committed = commit.get("committed_date", "")
    path_with_ns = project.get("path_with_namespace", "")

    if not project_id or not sha:
        return []

    diffs = await _fetch_commit_diff(session, project_id, sha)
    out: List[Dict[str, Any]] = []

    for d in diffs:
        new_path = d.get("new_path", "")
        old_path = d.get("old_path", "") or new_path
        path = new_path or old_path
        if not _is_iac_path(path):
            continue
        if d.get("deleted_file"):
            continue

        patch = _diff_to_patch_text(d)
        is_new_file = bool(d.get("new_file"))

        code_after = await _fetch_file_at_ref(session, project_id, new_path, sha) or ""
        code_before = ""
        before_quality = "unavailable"
        if is_new_file:
            before_quality = "new_file"
        elif parent_sha and old_path:
            fetched = await _fetch_file_at_ref(session, project_id, old_path, parent_sha)
            if fetched:
                code_before = fetched
                before_quality = "api"

        if not code_before and not patch:
            continue

        tool = detect_iac_tool(path, code_before or code_after)
        if tool == "unknown":
            continue

        if patch:
            smells_before, _ = classify_diff_smells(patch)
        else:
            smells_before = classify_smells(code_before or code_after)

        if not smells_before and not any(
            kw in (message or "").lower()
            for kw in ["security", "vulner", "cve", "cwe", "exploit",
                       "credential", "password", "secret", "fix"]
        ):
            continue

        rec = IaCRecord(
            id=_make_id(path_with_ns, sha, path),
            source="gitlab_commit",
            iac_tool=tool,
            file_path=path,
            code_before=code_before or f"# [before content unavailable]\n{patch}",
            code_after=code_after or None,
            diff=patch or None,
            has_fix=bool(code_after),
            smells=smells_before,
            repo=path_with_ns,
            repo_stars=project.get("star_count"),
            repo_description=project.get("description"),
            commit_sha=sha,
            parent_sha=parent_sha,
            commit_message=(message or "")[:500],
            commit_date=committed,
            commit_author=author,
            code_before_quality=before_quality,
        )
        d_rec = asdict(rec)
        d_rec["tier"] = assign_tier(d_rec)
        out.append(d_rec)

    return out


async def _get_project(
    session: GitLabSession, project_id: int
) -> Optional[Dict[str, Any]]:
    status, body = await session.get(f"{GITLAB_API_BASE}/projects/{project_id}")
    if status == 200 and isinstance(body, dict):
        return body
    return None


async def run(
    output_path: Path,
    terms: Optional[List[str]] = None,
    max_terms: Optional[int] = None,
) -> Dict[str, int]:
    if not GITLAB_TOKEN:
        raise RuntimeError("GITLAB_TOKEN not set — aborting.")

    terms = terms or _PROJECT_SEARCH_TERMS
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {"terms": 0, "projects_seen": 0, "commits_seen": 0, "records": 0}
    seen_ids: set = set()
    seen_projects: set = set()

    if output_path.exists():
        with output_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    seen_ids.add(json.loads(line).get("id"))
                except Exception:
                    continue

    async with GitLabSession() as session:
        with output_path.open("a", encoding="utf-8") as dst:
            for term in (terms if max_terms is None else terms[:max_terms]):
                stats["terms"] += 1
                logger.info("gitlab project search: %s", term)
                async for project in _search_projects(session, term):
                    pid = project.get("id")
                    if not pid or pid in seen_projects:
                        continue
                    seen_projects.add(pid)
                    stats["projects_seen"] += 1
                    async for commit in _iter_project_commits(session, pid):
                        stats["commits_seen"] += 1
                        recs = await _process_commit(session, commit, project)
                        for r in recs:
                            rid = r.get("id")
                            if rid in seen_ids:
                                continue
                            seen_ids.add(rid)
                            dst.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
                            dst.flush()
                            stats["records"] += 1
                logger.info("  … stats=%s", stats)

    return stats


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--max-terms", type=int, default=None,
                   help="Limit how many project-search terms to run (for testing)")
    args = p.parse_args()
    stats = asyncio.run(run(args.output, max_terms=args.max_terms))
    logger.info("GitLab scrape complete: %s", json.dumps(stats))


if __name__ == "__main__":
    main()
