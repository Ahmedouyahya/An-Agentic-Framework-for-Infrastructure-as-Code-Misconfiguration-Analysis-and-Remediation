"""
Dataset merger and deduplicator.

Loads IaCRecord objects from multiple JSONL files, deduplicates by
content_hash, then writes the merged result with train/val/test splits.
"""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from scraping.config import SPLIT_RATIOS
from scraping.schemas import IaCRecord, ScrapeManifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_jsonl(path: Path) -> List[IaCRecord]:
    """Load all records from a JSONL file."""
    records: List[IaCRecord] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(IaCRecord.from_json(line))
            except (json.JSONDecodeError, TypeError, KeyError) as exc:
                print(f"  [warn] {path.name}:{line_no} — skipped ({exc})")
    return records


def deduplicate(records: List[IaCRecord]) -> Tuple[List[IaCRecord], int]:
    """
    Remove duplicate records by content_hash.
    When duplicates exist, keep the one with has_fix=True, then most smells.
    Returns (deduped_records, n_removed).
    """
    buckets: Dict[str, List[IaCRecord]] = defaultdict(list)
    for r in records:
        key = r.content_hash or r.compute_hash()
        buckets[key].append(r)

    deduped: List[IaCRecord] = []
    for key, bucket in buckets.items():
        # Prefer records with a fix
        with_fix = [r for r in bucket if r.has_fix]
        pool = with_fix if with_fix else bucket
        # Pick the one with the most smells annotated
        best = max(pool, key=lambda r: len(r.smells))
        deduped.append(best)

    n_removed = len(records) - len(deduped)
    return deduped, n_removed


def assign_splits(
    records: List[IaCRecord],
    ratios: Optional[Dict[str, float]] = None,
    seed: int = 42,
) -> List[IaCRecord]:
    """
    Assign train/val/test splits to records in-place.
    Stratified by iac_tool to keep tool distribution balanced.
    Returns the same list with .split updated.
    """
    ratios = ratios or SPLIT_RATIOS
    rng = random.Random(seed)

    # Group by tool
    by_tool: Dict[str, List[IaCRecord]] = defaultdict(list)
    for r in records:
        by_tool[r.iac_tool].append(r)

    for tool, group in by_tool.items():
        rng.shuffle(group)
        n = len(group)
        n_train = int(n * ratios["train"])
        n_val   = int(n * ratios["val"])
        for i, r in enumerate(group):
            if i < n_train:
                r.split = "train"
            elif i < n_train + n_val:
                r.split = "val"
            else:
                r.split = "test"

    return records


# ---------------------------------------------------------------------------
# Main merge function
# ---------------------------------------------------------------------------

def merge(
    input_paths: List[Path],
    output_path: Path,
    manifest: Optional[ScrapeManifest] = None,
    seed: int = 42,
) -> Tuple[List[IaCRecord], Dict[str, int]]:
    """
    Load records from all input_paths, deduplicate, assign splits,
    and write to output_path (JSONL).

    Returns (merged_records, stats_dict).
    """
    # 1. Load all
    all_records: List[IaCRecord] = []
    for path in input_paths:
        loaded = load_jsonl(path)
        print(f"  Loaded {len(loaded):>5} records from {path.name}")
        all_records.extend(loaded)

    print(f"  Total before dedup: {len(all_records)}")

    # 2. Finalize hashes (in case some records were saved without finalize())
    for r in all_records:
        if not r.content_hash:
            r.content_hash = r.compute_hash()

    # 3. Deduplicate
    deduped, n_removed = deduplicate(all_records)
    print(f"  Removed {n_removed} duplicates → {len(deduped)} unique records")

    # 4. Assign splits
    assign_splits(deduped, seed=seed)

    # 5. Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for r in deduped:
            fh.write(r.to_json() + "\n")

    # 6. Build stats
    stats: Dict[str, int] = {
        "total": len(deduped),
        "with_fix": sum(1 for r in deduped if r.has_fix),
        "without_fix": sum(1 for r in deduped if not r.has_fix),
        "duplicates_removed": n_removed,
        "split_train": sum(1 for r in deduped if r.split == "train"),
        "split_val":   sum(1 for r in deduped if r.split == "val"),
        "split_test":  sum(1 for r in deduped if r.split == "test"),
    }

    # Per-tool
    tool_counts = Counter(r.iac_tool for r in deduped)
    for tool, count in tool_counts.items():
        stats[f"tool_{tool}"] = count

    # Per-source
    source_counts = Counter(r.source for r in deduped)
    for source, count in source_counts.items():
        stats[f"source_{source}"] = count

    if manifest:
        manifest.total_records = stats["total"]
        manifest.records_with_fix = stats["with_fix"]
        manifest.records_by_tool = dict(tool_counts)
        manifest.records_by_source = dict(source_counts)
        manifest.output_files.append(str(output_path))

    return deduped, stats


def print_stats(stats: Dict[str, int]) -> None:
    """Print a formatted stats summary."""
    print("\n" + "=" * 50)
    print(f"  Total records  : {stats.get('total', 0)}")
    print(f"  With fix       : {stats.get('with_fix', 0)}")
    print(f"  Without fix    : {stats.get('without_fix', 0)}")
    print(f"  Duplicates rm  : {stats.get('duplicates_removed', 0)}")
    print(f"  Train / Val / Test: "
          f"{stats.get('split_train', 0)} / "
          f"{stats.get('split_val', 0)} / "
          f"{stats.get('split_test', 0)}")
    print("-" * 50)
    print("  By tool:")
    for key in sorted(stats):
        if key.startswith("tool_"):
            print(f"    {key[5:]:15s}: {stats[key]}")
    print("  By source:")
    for key in sorted(stats):
        if key.startswith("source_"):
            print(f"    {key[7:]:15s}: {stats[key]}")
    print("=" * 50)
