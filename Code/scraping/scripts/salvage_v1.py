"""
One-shot script to salvage the v1 dataset into v2 quality.

Given the existing dataset.jsonl (33,667 records), for each record:

  1. If `code_before` is the `[before content unavailable]` placeholder AND a
     diff is present, re-run the improved unidiff-based reverse-patch to
     recover a real `code_before`. Sets `code_before_quality` accordingly.
  2. Re-run the extended smell classifier on the (possibly recovered)
     `code_before` so the record picks up any of the 22 new smell categories.
  3. Leave everything else untouched (commit metadata, repo info, etc.).
  4. Write a rewritten JSONL. Optionally chain the validator next to attach
     scanner ground-truth labels.

Usage:
    python -m scraping.scripts.salvage_v1 \
        --input  ../../iac-security-dataset/dataset.jsonl \
        --output ./output/dataset_v1_salvaged.jsonl
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Dict

from scraping.processors.classifier import classify_smells, classify_diff_smells
from scraping.processors.tiering import assign_tier
from scraping.scrapers.github import _reverse_apply_patch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def _salvage_one(rec: Dict) -> Dict:
    cb = rec.get("code_before") or ""
    ca = rec.get("code_after") or ""
    diff = rec.get("diff") or ""

    # Step 1: recover placeholder before-content
    is_placeholder = "[before content unavailable]" in cb
    if is_placeholder and diff and ca:
        # Detect new-file creations: unified-diff header "@@ -0,0 +N,M @@"
        # means the file did not exist before, so there is no "before" content
        # to recover. These records are detection-only, not fix records.
        is_new_file = "@@ -0,0" in diff
        if is_new_file:
            rec["code_before"] = ""          # file didn't exist pre-commit
            rec["code_before_quality"] = "new_file"
            rec["has_fix"] = False           # not a fix pair anymore
            cb = ""
        else:
            recovered, quality = _reverse_apply_patch(ca, diff)
            if recovered and recovered.strip():
                rec["code_before"] = recovered
                rec["code_before_quality"] = quality
                cb = recovered
            else:
                rec["code_before_quality"] = "unavailable"
    else:
        # Pre-existing real before-content: tag it so tier logic treats it as real.
        rec.setdefault("code_before_quality", "api")

    # Step 2: re-classify using the extended taxonomy. For new-file records
    # we classify against `code_after` (only content that exists); for normal
    # fix-pair records we prefer diff-based classification.
    smells = []
    if rec.get("code_before_quality") == "new_file" and ca:
        smells = [s.__dict__ for s in classify_smells(ca)]
    else:
        if diff:
            before_smells, _ = classify_diff_smells(diff)
            smells = [s.__dict__ for s in before_smells]
        if not smells and cb:
            smells = [s.__dict__ for s in classify_smells(cb)]

    # Merge with existing v1 smells (which used the narrower classifier),
    # deduplicating by `type`.
    existing = rec.get("smells") or []
    seen_types = {s.get("type") for s in existing if isinstance(s, dict)}
    for s in smells:
        t = s.get("type") if isinstance(s, dict) else None
        if t and t not in seen_types:
            existing.append(s)
            seen_types.add(t)
    rec["smells"] = existing

    # Step 3: mark source_version so downstream dedup keeps newer over older.
    rec.setdefault("notes", None)
    rec["source_version"] = "v1_salvaged"

    # Step 4: tier (may be upgraded later by the validator step).
    rec["tier"] = assign_tier(rec)
    return rec


def run(input_path: Path, output_path: Path) -> Dict[str, int]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    stats = {
        "total": 0,
        "placeholder_recovered_exact": 0,
        "placeholder_recovered_partial": 0,
        "placeholder_unrecoverable": 0,
        "smells_added": 0,
    }
    tiers = {"A": 0, "B": 0, "C": 0, "D": 0}

    with input_path.open("r", encoding="utf-8", errors="replace") as src, \
         output_path.open("w", encoding="utf-8") as dst:
        for i, line in enumerate(src):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            stats["total"] += 1
            before_smell_count = len(rec.get("smells") or [])
            was_placeholder = "[before content unavailable]" in (rec.get("code_before") or "")

            rec = _salvage_one(rec)

            if was_placeholder:
                q = rec.get("code_before_quality")
                if q == "exact":
                    stats["placeholder_recovered_exact"] += 1
                elif q == "partial":
                    stats["placeholder_recovered_partial"] += 1
                else:
                    stats["placeholder_unrecoverable"] += 1

            after_smell_count = len(rec.get("smells") or [])
            stats["smells_added"] += max(0, after_smell_count - before_smell_count)

            tiers[rec.get("tier", "D")] += 1

            dst.write(json.dumps(rec, ensure_ascii=False) + "\n")

            if (i + 1) % 5000 == 0:
                logger.info("... processed %d records", i + 1)

    stats["tiers"] = tiers
    return stats


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input",  required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()

    stats = run(args.input, args.output)
    logger.info("Salvage complete: %s", json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
