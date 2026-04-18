"""
Hydrate OSV/CVE seeds into full IaC records.

Reads a seed JSONL produced by `scrapers/osv.py` and, for each seed,
calls the GitHub commit API path reused by `scrapers/github.py` to build
IaCRecord entries. Records are tagged with `source="cve_osv"` and the
`cve_id` is stored in `notes` so downstream tiering can promote them to
Tier A by construction (after scanner validation confirms the smell).

Usage:
    python -m scraping.scrapers.osv_hydrate \\
        --seeds  scraping/output/osv_seeds.jsonl \\
        --output scraping/output/osv_records.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

from scraping.config import GITHUB_TOKEN, MAX_CONCURRENT_REQUESTS
from scraping.scrapers.github import GitHubSession, _get_repo_meta, _process_commit

logger = logging.getLogger(__name__)


async def _hydrate_one(
    session: GitHubSession,
    seed: Dict[str, Any],
) -> List[Dict[str, Any]]:
    owner, repo, sha = seed["owner"], seed["repo"], seed["commit_sha"]
    meta = await _get_repo_meta(session, owner, repo)
    # _process_commit expects a commit dict with at least {"sha": ...}
    records = await _process_commit(session, owner, repo, {"sha": sha}, meta)
    out = []
    for r in records:
        d = asdict(r)
        d["source"] = "cve_osv"
        d["notes"] = f"cve_id={seed.get('cve_id')}"
        out.append(d)
    return out


async def run(seeds_path: Path, output_path: Path) -> Dict[str, int]:
    seeds = [json.loads(l) for l in seeds_path.open("r", encoding="utf-8") if l.strip()]
    logger.info("Hydrating %d seeds", len(seeds))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {"seeds": len(seeds), "records": 0, "errors": 0}

    sem = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async with GitHubSession(token=GITHUB_TOKEN) as gh:

        async def _worker(seed):
            async with sem:
                try:
                    return await _hydrate_one(gh, seed)
                except Exception as e:
                    logger.warning("seed %s failed: %s", seed.get("cve_id"), e)
                    stats["errors"] += 1
                    return []

        with output_path.open("w", encoding="utf-8") as dst:
            for coro in asyncio.as_completed([_worker(s) for s in seeds]):
                records = await coro
                for r in records:
                    dst.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
                    stats["records"] += 1

    return stats


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("--seeds",  type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    stats = asyncio.run(run(args.seeds, args.output))
    logger.info("Hydrate complete: %s", json.dumps(stats))


if __name__ == "__main__":
    main()
