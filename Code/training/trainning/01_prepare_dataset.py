"""
Step 1 — Prepare the v1 dataset for QLoRA fine-tuning.

Reads:   ../scraping/output/dataset_v1_validated.jsonl  (31,748 records, 322 MB)
Writes:  training/data/{train,val,test}.jsonl          (filtered, ~10k records)
         training/data/stats.json                       (record counts + stats)

Filters:
  - has_fix == True  (must have before→after pair)
  - code_before, code_after both non-empty
  - combined length < MAX_CHARS (drops the long tail)
  - validated_smells_before non-empty when GOLD_ONLY=True (10,791 gold records)

Run locally (NOT on Kaggle):
    python training/trainning/01_prepare_dataset.py
    python training/trainning/01_prepare_dataset.py --all       # keep non-validated
    python training/trainning/01_prepare_dataset.py --max-chars 12000

Then zip `training/data/` and upload as a Kaggle dataset.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRAINING_DIR = HERE.parent
REPO_ROOT = TRAINING_DIR.parent

DEFAULT_SRC = REPO_ROOT / "scraping" / "output" / "dataset_v1_validated.jsonl"
OUT_DIR = TRAINING_DIR / "data"


def record_is_usable(r: dict, max_chars: int, gold_only: bool) -> bool:
    if not r.get("has_fix"):
        return False
    cb = r.get("code_before") or ""
    ca = r.get("code_after") or ""
    if not cb.strip() or not ca.strip():
        return False
    if len(cb) + len(ca) > max_chars:
        return False
    if cb.strip() == ca.strip():  # no-op fixes
        return False
    if gold_only and not r.get("validated_smells_before"):
        return False
    return True


def to_training_sample(r: dict) -> dict:
    """Slim record — only fields the trainer needs."""
    smells = r.get("smells") or []
    smell_types = sorted({s.get("type", "") for s in smells if s.get("type")})
    cwes = sorted({s.get("cwe", "") for s in smells if s.get("cwe")})
    return {
        "id": r.get("id"),
        "iac_tool": r.get("iac_tool", "unknown"),
        "smell_types": smell_types,
        "cwes": cwes,
        "code_before": r["code_before"],
        "code_after": r["code_after"],
        "split": r.get("split", "train"),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--src", type=Path, default=DEFAULT_SRC, help="Source JSONL")
    p.add_argument("--out-dir", type=Path, default=OUT_DIR, help="Output dir")
    p.add_argument("--max-chars", type=int, default=8000,
                   help="Max combined len(before)+len(after) to keep")
    p.add_argument("--all", action="store_true",
                   help="Keep all fix pairs, not only scanner-validated (gold)")
    args = p.parse_args()

    if not args.src.exists():
        print(f"ERROR: source not found: {args.src}", file=sys.stderr)
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    gold_only = not args.all

    split_files = {s: (args.out_dir / f"{s}.jsonl").open("w") for s in ("train", "val", "test")}
    split_counts = Counter()
    tool_counts = Counter()
    smell_counts = Counter()
    total_in = 0
    total_kept = 0

    try:
        with args.src.open() as fh:
            for line in fh:
                total_in += 1
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not record_is_usable(r, args.max_chars, gold_only):
                    continue
                sample = to_training_sample(r)
                split = sample["split"] if sample["split"] in split_files else "train"
                split_files[split].write(json.dumps(sample, ensure_ascii=False) + "\n")
                split_counts[split] += 1
                tool_counts[sample["iac_tool"]] += 1
                for t in sample["smell_types"]:
                    smell_counts[t] += 1
                total_kept += 1
    finally:
        for f in split_files.values():
            f.close()

    stats = {
        "source": str(args.src),
        "total_input_records": total_in,
        "total_kept": total_kept,
        "kept_pct": round(100 * total_kept / max(total_in, 1), 2),
        "gold_only": gold_only,
        "max_chars": args.max_chars,
        "splits": dict(split_counts),
        "by_iac_tool": dict(tool_counts.most_common()),
        "top_smells": dict(smell_counts.most_common(25)),
    }
    (args.out_dir / "stats.json").write_text(json.dumps(stats, indent=2))

    print(f"\nInput:  {total_in:,} records")
    print(f"Kept:   {total_kept:,} records ({stats['kept_pct']}%)")
    print(f"  train={split_counts['train']:,}  val={split_counts['val']:,}  test={split_counts['test']:,}")
    print(f"  tools: {dict(tool_counts.most_common(5))}")
    print(f"\nWrote {args.out_dir}/")
    for s in ("train", "val", "test"):
        f = args.out_dir / f"{s}.jsonl"
        if f.exists():
            print(f"  {f.name}  {f.stat().st_size / 1e6:.1f} MB")
    print(f"  stats.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
