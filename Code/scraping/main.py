#!/usr/bin/env python3
"""
IaC Security Dataset Scraper — CLI entry point.

Designed for long runs (24h+). Fully resumable: if stopped for any reason
(Ctrl-C, power off, crash), just re-run the same command and it will pick up
exactly where it left off — skipping completed queries/repos and appending
only new records.

Two-account parallel setup (run in separate terminals):

  # Account 1 — first half of queries + odd-indexed repos
  python -m scraping.main --account 1

  # Account 2 — second half of queries + even-indexed repos
  python -m scraping.main --account 2

  # Merge all results when done (or any time during the run)
  python -m scraping.main --merge

Single account:
  python -m scraping.main --all
  python -m scraping.main --github-commits --known-repos

Environment variables (in .env):
  GITHUB_TOKEN    — primary account token
  GITHUB_TOKEN_2  — secondary account token (for --account 2)
"""

import argparse
import asyncio
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Load .env before importing config (so GITHUB_TOKEN is set)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

from scraping.config import (
    CODE_SEARCH_QUERIES,
    COMMIT_SEARCH_QUERIES,
    KNOWN_REPOS,
    MERGED_DIR,
    OUTPUT_DIR,
    RAW_DIR,
)
from scraping.processors.merger import merge, print_stats
from scraping.schemas import ScrapeManifest
from scraping.storage.progress import ProgressTracker
from scraping.storage.writer import JsonlWriter, count_existing, load_existing_hashes


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Account configuration
# ---------------------------------------------------------------------------

def _resolve_account(account: int):
    """
    Return (token, output_dir, commit_queries, code_queries, repos, progress_path)
    for the given account number (1 or 2).

    Queries and repos are split so both accounts cover different ground.
    """
    token1 = os.getenv("GITHUB_TOKEN", "")
    token2 = os.getenv("GITHUB_TOKEN_2", "")

    mid_c = len(COMMIT_SEARCH_QUERIES) // 2
    mid_q = len(CODE_SEARCH_QUERIES) // 2

    if account == 1:
        token       = token1
        output_dir  = RAW_DIR
        commit_q    = COMMIT_SEARCH_QUERIES[:mid_c]          # first half
        code_q      = CODE_SEARCH_QUERIES[:mid_q]
        repos       = KNOWN_REPOS[::2]                       # odd-indexed repos
        prog_path   = OUTPUT_DIR / "progress_1.json"
    elif account == 2:
        token       = token2 or token1                       # fallback to token1
        output_dir  = OUTPUT_DIR / "raw2"
        commit_q    = COMMIT_SEARCH_QUERIES[mid_c:]          # second half
        code_q      = CODE_SEARCH_QUERIES[mid_q:]
        repos       = KNOWN_REPOS[1::2]                      # even-indexed repos
        prog_path   = OUTPUT_DIR / "progress_2.json"
    else:
        raise ValueError(f"--account must be 1 or 2, got {account}")

    return token, output_dir, commit_q, code_q, repos, prog_path


# ---------------------------------------------------------------------------
# Scrape runners
# ---------------------------------------------------------------------------

async def run_github_commits(
    output_path: Path,
    manifest: ScrapeManifest,
    max_pages: int,
    token: str,
    queries: list,
    progress: ProgressTracker,
) -> int:
    from scraping.scrapers.github import search_commits

    existing_hashes = load_existing_hashes(output_path)
    n_before = count_existing(output_path)
    print(f"[commits] {n_before} existing records | {len(queries)} queries | resuming...")

    written = 0
    with JsonlWriter(output_path) as writer:
        async for record in search_commits(
            queries=queries, max_pages=max_pages, token=token, progress=progress
        ):
            h = record.compute_hash()
            if h in existing_hashes:
                continue
            existing_hashes.add(h)
            writer.write(record)
            written += 1
            progress.increment_written(1)
            if written % 50 == 0:
                print(f"  [commits] +{written} new records (total written this session)")

    manifest.output_files.append(str(output_path))
    print(f"[commits] Done — {written} new records this session")
    return written


async def run_github_code(
    output_path: Path,
    manifest: ScrapeManifest,
    max_pages: int,
    token: str,
    queries: list,
    progress: ProgressTracker,
) -> int:
    from scraping.scrapers.github import search_code

    existing_hashes = load_existing_hashes(output_path)
    n_before = count_existing(output_path)
    print(f"[code] {n_before} existing records | {len(queries)} queries | resuming...")

    written = 0
    with JsonlWriter(output_path) as writer:
        async for record in search_code(
            queries=queries, max_pages=max_pages, token=token, progress=progress
        ):
            h = record.compute_hash()
            if h in existing_hashes:
                continue
            existing_hashes.add(h)
            writer.write(record)
            written += 1
            progress.increment_written(1)
            if written % 50 == 0:
                print(f"  [code] +{written} new records")

    manifest.output_files.append(str(output_path))
    print(f"[code] Done — {written} new records this session")
    return written


async def run_known_repos(
    output_path: Path,
    manifest: ScrapeManifest,
    token: str,
    repos: list,
    progress: ProgressTracker,
) -> int:
    from scraping.scrapers.known_repos import scrape_all_known_repos

    existing_hashes = load_existing_hashes(output_path)
    n_before = count_existing(output_path)
    print(f"[repos] {n_before} existing records | {len(repos)} repos | resuming...")

    written = 0
    with JsonlWriter(output_path) as writer:
        async for record in scrape_all_known_repos(
            token=token, progress=progress, repos=repos
        ):
            h = record.compute_hash()
            if h in existing_hashes:
                continue
            existing_hashes.add(h)
            writer.write(record)
            written += 1
            progress.increment_written(1)
            if written % 100 == 0:
                print(f"  [repos] +{written} new records")

    manifest.output_files.append(str(output_path))
    print(f"[repos] Done — {written} new records this session")
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="IaC Security Dataset Scraper — resumable, multi-account",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Account shortcut (recommended)
    p.add_argument("--account", type=int, choices=[1, 2], default=None,
                   help="Run as account 1 or 2 (auto-splits queries, token, output dir)")

    # Manual scrape mode flags (used when --account not set)
    p.add_argument("--github-commits", action="store_true")
    p.add_argument("--github-code",    action="store_true")
    p.add_argument("--known-repos",    action="store_true")
    p.add_argument("--all",            action="store_true",
                   help="Run all scrapers (commits + code + known repos)")

    # Merge
    p.add_argument("--merge", action="store_true",
                   help="Merge all raw JSONL files into one deduplicated dataset")
    p.add_argument("--input-dir",    type=Path, default=None,
                   help="Directory (or comma-separated dirs) to merge from")
    p.add_argument("--merge-output", type=Path, default=None,
                   help="Output path for merged file")

    # Options
    p.add_argument("--max-pages", type=int, default=10,
                   help="Max search pages per query (default: 10 = 300 commits/query)")
    p.add_argument("--output-dir", type=Path, default=None,
                   help="Override output directory")
    p.add_argument("--token", type=str, default=None,
                   help="GitHub token override")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--seed", type=int, default=42)

    return p


async def _async_main(args: argparse.Namespace) -> None:
    from scraping.scrapers.github import _GlobalRateLimiter
    _GlobalRateLimiter.reset()

    # ---------------------------------------------------------------------------
    # Resolve configuration (account mode vs manual mode)
    # ---------------------------------------------------------------------------
    if args.account:
        token, output_dir, commit_queries, code_queries, repos, prog_path = \
            _resolve_account(args.account)
        do_commits = True
        do_code    = True
        do_known   = True
        do_merge   = False  # merge separately after both accounts finish
    else:
        token       = args.token or os.getenv("GITHUB_TOKEN", "")
        output_dir  = args.output_dir or RAW_DIR
        commit_queries = COMMIT_SEARCH_QUERIES
        code_queries   = CODE_SEARCH_QUERIES
        repos          = KNOWN_REPOS
        prog_path      = OUTPUT_DIR / "progress.json"
        do_commits = args.github_commits or args.all
        do_code    = args.github_code    or args.all
        do_known   = args.known_repos    or args.all
        do_merge   = args.merge          or args.all

    if args.output_dir:
        output_dir = args.output_dir
    if args.token:
        token = args.token

    output_dir.mkdir(parents=True, exist_ok=True)

    # Progress tracker — persists to disk, survives restarts
    progress = ProgressTracker(prog_path)
    print(f"Progress: {progress.summary()}")

    manifest = ScrapeManifest(run_id=str(uuid.uuid4())[:8], started_at=_utcnow())

    # ---------------------------------------------------------------------------
    # Run scrapers concurrently
    # ---------------------------------------------------------------------------
    total_written = 0
    tasks = {}

    if do_commits:
        tasks["commits"] = run_github_commits(
            output_dir / "github_commits.jsonl", manifest,
            args.max_pages, token, commit_queries, progress,
        )
    if do_code:
        tasks["code"] = run_github_code(
            output_dir / "github_code.jsonl", manifest,
            3, token, code_queries, progress,
        )
    if do_known:
        tasks["repos"] = run_known_repos(
            output_dir / "known_repos.jsonl", manifest,
            token, repos, progress,
        )

    if tasks:
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                print(f"[{name}] ERROR: {result}")
                import traceback; traceback.print_exception(type(result), result, result.__traceback__)
            else:
                total_written += result

    # ---------------------------------------------------------------------------
    # Merge
    # ---------------------------------------------------------------------------
    if do_merge or args.merge:
        # Collect all raw dirs
        if args.input_dir:
            raw_dirs = [Path(d.strip()) for d in str(args.input_dir).split(",")]
        else:
            raw_dirs = [RAW_DIR, OUTPUT_DIR / "raw2"]

        jsonl_files = []
        for d in raw_dirs:
            if d.exists():
                jsonl_files.extend(sorted(d.glob("*.jsonl")))

        if not jsonl_files:
            print("[merge] No JSONL files found to merge")
        else:
            date_str = datetime.now().strftime("%Y%m%d_%H%M")
            merge_out = args.merge_output or (MERGED_DIR / f"dataset_{date_str}.jsonl")
            merge_out.parent.mkdir(parents=True, exist_ok=True)
            print(f"[merge] Merging {len(jsonl_files)} files → {merge_out}")
            _, stats = merge(jsonl_files, merge_out, manifest=manifest, seed=args.seed)
            print_stats(stats)

    manifest.finished_at = _utcnow()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    manifest.save(OUTPUT_DIR / "manifest.json")
    print(f"\nDone. New records this session: {total_written}")
    print(f"Progress saved: {prog_path}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    _setup_logging(args.verbose)

    nothing_selected = not any([
        args.account, args.github_commits, args.github_code,
        args.known_repos, args.all, args.merge,
    ])
    if nothing_selected:
        parser.print_help()
        sys.exit(0)

    asyncio.run(_async_main(args))


if __name__ == "__main__":
    main()
