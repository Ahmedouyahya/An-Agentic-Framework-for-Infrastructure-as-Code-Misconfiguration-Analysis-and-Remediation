"""
Build the v2 dataset release from stable JSONL snapshots.

The builder is intentionally dict-based instead of IaCRecord-based because
older records may contain extra fields such as validated_smells_before,
validation_scanners, and source_version.

Default inputs target the current repo state:

    python -m scraping.scripts.build_v2

Outputs are written under output/v2/:

    dataset_v2_full.jsonl       all tiers
    dataset_v2_gold.jsonl       Tier A only
    dataset_v2_fix_pairs.jsonl  Tiers A/B with fix pairs
    dataset_v2_detection.jsonl  Tiers A/B/C
    manifest_v2.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from scraping.config import OUTPUT_DIR, SPLIT_RATIOS
from scraping.processors.classifier import classify_diff_smells, classify_smells
from scraping.processors.tiering import assign_tier


DEFAULT_INPUTS = (
    OUTPUT_DIR / "dataset_v1_validated.jsonl",
    OUTPUT_DIR / "dataset_v1_salvaged.jsonl",
    OUTPUT_DIR / "gitlab" / "dataset.jsonl",
)

TIER_SCORE = {"A": 4, "B": 3, "C": 2, "D": 1}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:64]


def _load_jsonl(path: Path) -> Iterable[Tuple[int, Dict[str, Any]]]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except json.JSONDecodeError:
                continue


def _smell_dicts(smells) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for smell in smells or []:
        if hasattr(smell, "to_dict"):
            out.append(smell.to_dict())
        elif isinstance(smell, dict):
            out.append(smell)
    return out


def _dedupe_smells(smells: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for smell in smells:
        key = (
            smell.get("type"),
            smell.get("cwe"),
            smell.get("checkov_id"),
            smell.get("line_number"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(smell)
    return out


def _classify_record(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    diff = rec.get("diff") or ""
    code_before = rec.get("code_before") or ""
    code_after = rec.get("code_after") or ""
    quality = rec.get("code_before_quality")

    if diff and quality != "new_file":
        before, _after = classify_diff_smells(diff)
        smells = _smell_dicts(before)
        if smells:
            return smells

    content = code_before or code_after
    if content:
        return _smell_dicts(classify_smells(content))
    return []


def normalize_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize legacy/scraper records into the v2 contract.

    New-file additions are not fix pairs. If the added file contains insecure
    code, v2 stores that code in code_before as a detection-only example and
    clears code_after.
    """
    rec = dict(rec)
    code_before = rec.get("code_before") or ""
    code_after = rec.get("code_after") or ""
    diff = rec.get("diff") or ""
    quality = rec.get("code_before_quality")
    placeholder = "[before content unavailable]" in code_before
    is_new_file = quality == "new_file" or "@@ -0,0" in diff

    if is_new_file:
        added_code = code_after
        if not added_code and placeholder:
            # Some GitLab records stored only the patch text in code_before.
            # Keep the record, but mark it weak if no concrete added code exists.
            added_code = ""
        rec["code_before"] = added_code
        rec["code_after"] = None
        rec["has_fix"] = False
        rec["code_before_quality"] = "new_file"
    elif placeholder:
        rec["code_before_quality"] = quality or "unavailable"
    elif code_before:
        rec["code_before_quality"] = quality or "api"
    else:
        rec["code_before_quality"] = quality or "unavailable"

    existing_smells = _smell_dicts(rec.get("smells") or [])
    # Most source files have already gone through the classifier during
    # scraping/salvage. Avoid re-running full-file regexes unless v2 changed
    # the content shape or the record arrived without smells.
    inferred_smells = _classify_record(rec) if is_new_file else []
    rec["smells"] = _dedupe_smells(existing_smells + inferred_smells)

    content_for_hash = rec.get("code_before") or rec.get("code_after") or ""
    rec["content_hash"] = _sha256(content_for_hash)
    rec["tier"] = assign_tier(rec)
    rec["source_version"] = rec.get("source_version") or "v2_normalized"
    rec["labels"] = _labels(rec)
    return rec


def _labels(rec: Dict[str, Any]) -> List[str]:
    labels = {rec.get("iac_tool")}
    for smell in rec.get("smells") or []:
        if not isinstance(smell, dict):
            continue
        labels.add(smell.get("type"))
        labels.add(smell.get("severity"))
        labels.add(smell.get("cwe"))
    return sorted(str(x) for x in labels if x)


def _primary_key(rec: Dict[str, Any]) -> Tuple[Any, ...]:
    repo = rec.get("repo")
    sha = rec.get("commit_sha")
    path = rec.get("file_path")
    if repo and sha and path:
        return ("repo_commit_path", repo, sha, path)
    return ("content", rec.get("content_hash") or _sha256(rec.get("code_before") or ""))


def _has_validated(rec: Dict[str, Any]) -> bool:
    return bool(rec.get("validated_smells_before") or rec.get("validated_smells_after"))


def _fixed_rule_count(rec: Dict[str, Any]) -> int:
    before = {
        f.get("rule_id")
        for f in rec.get("validated_smells_before") or []
        if isinstance(f, dict) and f.get("rule_id")
    }
    after = {
        f.get("rule_id")
        for f in rec.get("validated_smells_after") or []
        if isinstance(f, dict) and f.get("rule_id")
    }
    return len(before - after)


def _real_before(rec: Dict[str, Any]) -> bool:
    cb = rec.get("code_before") or ""
    if not cb.strip():
        return False
    if "[before content unavailable]" in cb:
        return False
    return True


def _score(rec: Dict[str, Any], input_rank: int) -> Tuple[int, int, int, int, int, int, int]:
    tier = assign_tier(rec)
    return (
        TIER_SCORE.get(tier, 0),
        _fixed_rule_count(rec),
        int(_has_validated(rec)),
        int(bool(rec.get("has_fix"))),
        int(_real_before(rec)),
        len(rec.get("smells") or []),
        input_rank,
    )


def _assign_splits(records: List[Dict[str, Any]], seed: int = 42) -> None:
    rng = random.Random(seed)
    ratios = SPLIT_RATIOS
    by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for rec in records:
        by_tool.setdefault(rec.get("iac_tool") or "unknown", []).append(rec)

    for group in by_tool.values():
        rng.shuffle(group)
        n = len(group)
        n_train = int(n * ratios["train"])
        n_val = int(n * ratios["val"])
        for i, rec in enumerate(group):
            if i < n_train:
                rec["split"] = "train"
            elif i < n_train + n_val:
                rec["split"] = "val"
            else:
                rec["split"] = "test"


def build_v2(
    input_paths: List[Path],
    output_dir: Path,
    seed: int = 42,
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    best: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    best_rank: Dict[Tuple[Any, ...], int] = {}
    input_counts: Counter = Counter()
    invalid_inputs: List[str] = []
    total_loaded = 0

    for input_rank, path in enumerate(input_paths):
        if not path.exists():
            invalid_inputs.append(str(path))
            continue
        for _line_no, raw in _load_jsonl(path):
            total_loaded += 1
            input_counts[str(path)] += 1
            rec = normalize_record(raw)
            key = _primary_key(rec)
            if key not in best or _score(rec, input_rank) > _score(best[key], best_rank[key]):
                best[key] = rec
                best_rank[key] = input_rank

    records = list(best.values())
    records.sort(key=lambda r: (r.get("source") or "", r.get("id") or ""))
    _assign_splits(records, seed=seed)

    full = output_dir / "dataset_v2_full.jsonl"
    gold = output_dir / "dataset_v2_gold.jsonl"
    fix_pairs = output_dir / "dataset_v2_fix_pairs.jsonl"
    detection = output_dir / "dataset_v2_detection.jsonl"

    _write_jsonl(full, records)
    _write_jsonl(gold, [r for r in records if r.get("tier") == "A"])
    _write_jsonl(
        fix_pairs,
        [r for r in records if r.get("tier") in ("A", "B") and r.get("has_fix")],
    )
    _write_jsonl(detection, [r for r in records if r.get("tier") in ("A", "B", "C")])

    manifest = _manifest(records, input_paths, input_counts, invalid_inputs, total_loaded)
    manifest["outputs"] = {
        "full": str(full),
        "gold": str(gold),
        "fix_pairs": str(fix_pairs),
        "detection": str(detection),
    }
    (output_dir / "manifest_v2.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def _write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> int:
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n


def _manifest(
    records: List[Dict[str, Any]],
    input_paths: List[Path],
    input_counts: Counter,
    invalid_inputs: List[str],
    total_loaded: int,
) -> Dict[str, Any]:
    tier = Counter(r.get("tier") or "<missing>" for r in records)
    source = Counter(r.get("source") or "<missing>" for r in records)
    tool = Counter(r.get("iac_tool") or "<missing>" for r in records)
    split = Counter(r.get("split") or "<missing>" for r in records)
    quality = Counter(r.get("code_before_quality") or "<missing>" for r in records)
    smells = Counter()
    scanners = Counter()
    for rec in records:
        for smell in rec.get("smells") or []:
            if isinstance(smell, dict) and smell.get("type"):
                smells[smell["type"]] += 1
        for finding in (rec.get("validated_smells_before") or []) + (rec.get("validated_smells_after") or []):
            if isinstance(finding, dict) and finding.get("scanner"):
                scanners[finding["scanner"]] += 1

    return {
        "built_at": _utcnow(),
        "total_loaded": total_loaded,
        "total_records": len(records),
        "duplicates_removed": total_loaded - len(records),
        "input_paths": [str(p) for p in input_paths],
        "input_counts": dict(input_counts),
        "missing_inputs": invalid_inputs,
        "records_with_fix": sum(1 for r in records if r.get("has_fix")),
        "records_without_fix": sum(1 for r in records if not r.get("has_fix")),
        "validated_records": sum(1 for r in records if _has_validated(r)),
        "scanner_confirmed_fixes": sum(1 for r in records if _fixed_rule_count(r)),
        "by_tier": dict(sorted(tier.items())),
        "by_source": dict(sorted(source.items())),
        "by_tool": dict(sorted(tool.items())),
        "by_split": dict(sorted(split.items())),
        "by_code_before_quality": dict(sorted(quality.items())),
        "by_smell_top_25": dict(smells.most_common(25)),
        "by_scanner": dict(sorted(scanners.items())),
    }


def _parse_paths(raw: Optional[str]) -> List[Path]:
    if not raw:
        return list(DEFAULT_INPUTS)
    return [Path(p.strip()) for p in raw.split(",") if p.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build v2 tiered dataset release")
    parser.add_argument(
        "--inputs",
        type=str,
        default=None,
        help="Comma-separated JSONL paths. Defaults to current validated/salvaged/GitLab files.",
    )
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR / "v2")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    manifest = build_v2(_parse_paths(args.inputs), args.output_dir, seed=args.seed)
    print(json.dumps({
        "total_records": manifest["total_records"],
        "duplicates_removed": manifest["duplicates_removed"],
        "by_tier": manifest["by_tier"],
        "outputs": manifest["outputs"],
    }, indent=2))


if __name__ == "__main__":
    main()
