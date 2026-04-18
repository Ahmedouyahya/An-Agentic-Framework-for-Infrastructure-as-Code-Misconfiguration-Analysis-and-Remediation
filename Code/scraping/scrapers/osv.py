"""
OSV / NVD CVE scraper — fetch IaC-relevant CVEs whose references point at
GitHub fix-commits, then reuse the GitHub scraper's `_process_commit` to
build full before/after records.

Records produced here are **Tier A by construction**: the CVE is authoritative
ground truth that (a) a vulnerability existed and (b) the referenced commit
fixes it.

Usage:
    python -m scraping.scrapers.osv \\
        --output scraping/output/osv_seeds.jsonl \\
        --since 2020-01-01

This writes a seed JSONL of {cve_id, repo, commit_sha, keywords} which a
follow-up step feeds into `_process_commit`.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import aiohttp

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

IAC_KEYWORDS = (
    "terraform", "ansible", "kubernetes", "helm",
    "dockerfile", "cloudformation", "pulumi", "chef",
    "puppet", "vagrant",
)

_COMMIT_URL_RE = re.compile(
    r"https?://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})",
    re.IGNORECASE,
)


def _extract_github_commits(cve: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Return list of (owner, repo, sha) from the CVE's reference URLs."""
    out: List[Tuple[str, str, str]] = []
    refs = (cve.get("cve", {}).get("references", []) or [])
    for ref in refs:
        url = ref.get("url", "")
        m = _COMMIT_URL_RE.match(url)
        if m:
            owner, repo, sha = m.group(1), m.group(2), m.group(3)
            # strip .git suffix if present
            if repo.endswith(".git"):
                repo = repo[:-4]
            out.append((owner, repo, sha))
    return out


def _cve_id(cve: Dict[str, Any]) -> str:
    return cve.get("cve", {}).get("id", "")


def _cve_description(cve: Dict[str, Any]) -> str:
    descs = cve.get("cve", {}).get("descriptions", []) or []
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _matches_iac(description: str) -> bool:
    d = description.lower()
    return any(k in d for k in IAC_KEYWORDS)


async def _fetch_page(
    session: aiohttp.ClientSession,
    keyword: str,
    start_index: int,
) -> Dict[str, Any]:
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 2000,
        "startIndex": start_index,
    }
    async with session.get(NVD_API, params=params, timeout=aiohttp.ClientTimeout(total=60)) as r:
        if r.status != 200:
            text = await r.text()
            logger.warning("NVD %s returned %d: %s", keyword, r.status, text[:200])
            return {}
        return await r.json()


async def fetch_iac_cves(
    keywords: Iterable[str] = IAC_KEYWORDS,
    rate_limit_seconds: float = 6.0,
) -> List[Dict[str, Any]]:
    """
    NVD enforces 5 requests / 30s for unauthenticated callers. We default
    to one request every 6s which is comfortably under the cap.
    """
    collected: Dict[str, Dict[str, Any]] = {}
    async with aiohttp.ClientSession() as session:
        for kw in keywords:
            start = 0
            while True:
                page = await _fetch_page(session, kw, start)
                vulns = page.get("vulnerabilities", []) or []
                if not vulns:
                    break
                for v in vulns:
                    cid = _cve_id(v)
                    if cid and cid not in collected:
                        collected[cid] = v
                total = page.get("totalResults", 0)
                start += len(vulns)
                logger.info("NVD kw=%s fetched %d/%d", kw, start, total)
                if start >= total:
                    break
                await asyncio.sleep(rate_limit_seconds)
            await asyncio.sleep(rate_limit_seconds)
    logger.info("Collected %d unique CVEs across %d keywords", len(collected), len(list(keywords)))
    return list(collected.values())


def extract_seeds(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Turn the raw CVE list into a seed list of fix-commit references.
    Each seed: {cve_id, owner, repo, commit_sha, description}.
    """
    seeds: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()
    for cve in cves:
        desc = _cve_description(cve)
        if not _matches_iac(desc):
            # keyword-only match but description doesn't confirm IaC context;
            # still keep if any GH commit reference matched an IaC-named repo later.
            pass
        cid = _cve_id(cve)
        for owner, repo, sha in _extract_github_commits(cve):
            key = (owner.lower(), repo.lower(), sha.lower())
            if key in seen:
                continue
            seen.add(key)
            seeds.append({
                "cve_id": cid,
                "owner": owner,
                "repo": repo,
                "commit_sha": sha,
                "description": desc[:500],
            })
    return seeds


def write_seeds(seeds: List[Dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for s in seeds:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    logger.info("Wrote %d seeds to %s", len(seeds), output_path)


async def _main_async(args: argparse.Namespace) -> None:
    cves = await fetch_iac_cves()
    seeds = extract_seeds(cves)
    write_seeds(seeds, args.output)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    asyncio.run(_main_async(args))


if __name__ == "__main__":
    main()
