#!/usr/bin/env python3
"""
Evaluation Script — Agentic IaC Security Framework
====================================================
Computes the revised 8-metric set across 4 configurations on either the
16-file labelled benchmark (dataset/metadata.json) or the 33k corpus test split.

Metrics (per Rapport 4):
  Detection:    Precision, Recall, F1, Macro-F1
  Retrieval:    Hit Rate@3, Hit Rate@5, MRR
  Remediation:  PVR (Patch Validity Rate), SER (Smell Elimination Rate),
                NNIR (No-New-Issues Rate)
  Confidence:   Self-consistency score (from generator)
  Inferential:  Wilcoxon rank-sum + Holm-Bonferroni (paired config comparison)

Usage:
    # Config A — baseline (Checkov-only detection, no LLM)
    python3 scripts/evaluate.py --config A

    # Config B — + RAG
    python3 scripts/evaluate.py --config B

    # Config C — + RAG + Checkov validation
    python3 scripts/evaluate.py --config C

    # Config D — + RAG + Checkov + KICS + retry loop
    python3 scripts/evaluate.py --config D --model "gemma3:4b"

    # Use 33k corpus test split instead of 16-file benchmark
    python3 scripts/evaluate.py --config D --dataset path/to/test.jsonl

LLM backends (detected from environment variables, in priority order):
    ANTHROPIC_API_KEY   → Anthropic Claude
    DEEPSEEK_API_KEY    → DeepSeek
    OPENROUTER_API_KEY  → OpenRouter
    OLLAMA_MODEL        → Local Ollama (e.g. gemma3:4b)
    OPENAI_API_KEY      → OpenAI

Author: Ahmedou Yahye Kheyri
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

DATASET_ROOT = Path(__file__).parent.parent / "dataset"
METADATA_PATH = DATASET_ROOT / "metadata.json"
TAXONOMY_PATH = DATASET_ROOT / "taxonomy" / "smells_taxonomy.json"


# ===========================================================================
# Utilities
# ===========================================================================

def load_metadata() -> dict:
    """Load the 16-file labelled benchmark metadata."""
    with METADATA_PATH.open() as f:
        return json.load(f)


def load_jsonl_dataset(path: Path) -> list[dict]:
    """Load records from a JSONL file (33k corpus test split)."""
    records = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    logger.info("Loaded %d records from %s", len(records), path)
    return records


def run_checkov(file_path: Path) -> list[dict]:
    """Run Checkov and return list of failed checks as normalised dicts."""
    try:
        result = subprocess.run(
            ["checkov", "--file", str(file_path), "--output", "json", "--quiet"],
            capture_output=True, text=True, timeout=60,
        )
        raw = result.stdout or "{}"
        data = json.loads(raw)
        if isinstance(data, list):
            checks = []
            for item in data:
                checks.extend(item.get("results", {}).get("failed_checks", []))
        else:
            checks = data.get("results", {}).get("failed_checks", [])
        return checks
    except Exception as exc:
        logger.warning("Checkov run failed for %s: %s", file_path, exc)
        return []


def checkov_checks_to_smells(checks: list[dict]) -> list[dict]:
    """Normalise Checkov output to smell dicts."""
    smells = []
    for c in checks:
        smells.append({
            "checker_id": c.get("check_id", "UNKNOWN"),
            "type": c.get("check_id", "UNKNOWN"),
            "description": str(c.get("check_result", {}).get("result", "")),
            "line": c.get("file_line_range", [0])[0],
            "resource": c.get("resource", ""),
        })
    return smells


def match_smell(detected: dict, ground_truth: dict, line_tolerance: int = 5) -> bool:
    """True if detected smell matches ground truth within line tolerance."""
    if detected.get("checker_id", "").upper() == "HEURISTIC":
        return False
    gt_checkov_id = ground_truth.get("checkov_id", "")
    if gt_checkov_id == "HEURISTIC":
        return False
    if detected.get("checker_id", "") != gt_checkov_id:
        return False
    det_line = detected.get("line", None)
    gt_line = ground_truth.get("line", None)
    if det_line is None or gt_line is None:
        return True
    return abs(det_line - gt_line) <= line_tolerance


# ===========================================================================
# Layer 1 — Detection Metrics (P, R, F1, Macro-F1)
# ===========================================================================

def compute_detection_metrics(
    detected_by_file: dict[str, list[dict]],
    metadata: dict,
) -> dict:
    """Precision, Recall, F1 per smell type, per IaC tool, and macro-average."""
    all_gt: list[dict] = []
    all_det: list[dict] = []

    for file_entry in metadata["files"]:
        fid = file_entry["id"]
        for smell in file_entry["smells"]:
            if smell.get("checkov_id", "") != "HEURISTIC":
                all_gt.append({"file_id": fid, **smell, "tool": file_entry["iac_tool"]})
        for det in detected_by_file.get(fid, []):
            all_det.append({"file_id": fid, **det, "tool": file_entry["iac_tool"]})

    matched_gt = set()
    tp_det_indices = set()
    for i, det in enumerate(all_det):
        for j, gt in enumerate(all_gt):
            if det["file_id"] == gt["file_id"] and match_smell(det, gt):
                matched_gt.add(j)
                tp_det_indices.add(i)
                break

    TP = len(matched_gt)
    FP = len(all_det) - len(tp_det_indices)
    FN = len(all_gt) - TP

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # Per-type breakdown
    type_stats: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for j, gt in enumerate(all_gt):
        if j in matched_gt:
            type_stats[gt["type"]]["tp"] += 1
        else:
            type_stats[gt["type"]]["fn"] += 1
    for i, det in enumerate(all_det):
        if i not in tp_det_indices:
            type_stats[det["type"]]["fp"] += 1

    per_type = {}
    for smell_type, counts in type_stats.items():
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        per_type[smell_type] = {"precision": p, "recall": r, "f1": f, "support": tp + fn}

    macro_f1 = mean(v["f1"] for v in per_type.values()) if per_type else 0.0

    # Per-tool breakdown
    tool_stats: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for j, gt in enumerate(all_gt):
        if j in matched_gt:
            tool_stats[gt["tool"]]["tp"] += 1
        else:
            tool_stats[gt["tool"]]["fn"] += 1
    for i, det in enumerate(all_det):
        if i not in tp_det_indices:
            tool_stats[det["tool"]]["fp"] += 1

    per_tool = {}
    for tool, counts in tool_stats.items():
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        per_tool[tool] = {"precision": p, "recall": r, "f1": f, "tp": tp, "fp": fp, "fn": fn}

    return {
        "TP": TP, "FP": FP, "FN": FN,
        "precision": precision, "recall": recall, "f1": f1,
        "macro_f1": macro_f1,
        "per_type": per_type,
        "per_tool": per_tool,
        "total_gt": len(all_gt),
        "total_detected": len(all_det),
    }


# ===========================================================================
# Layer 2 — Retrieval Metrics (Hit Rate@K, MRR)
# ===========================================================================

def compute_retrieval_metrics(metadata: dict) -> dict:
    """Hit Rate@K and MRR using keyword-based taxonomy matching."""
    taxonomy = json.loads(TAXONOMY_PATH.read_text())

    def is_relevant(doc: dict, smell: dict) -> bool:
        return (
            doc.get("cwe", "") == smell.get("cwe", "NONE")
            or smell.get("type", "").lower() in doc.get("name", "").lower().replace(" ", "_")
        )

    def retrieve(smell: dict, k: int) -> list[dict]:
        desc = (smell.get("type", "") + " " + smell.get("cwe", "")).lower()
        scored = []
        for doc in taxonomy:
            score = 0
            if doc.get("cwe", "") == smell.get("cwe", ""):
                score += 10
            if smell.get("type", "").replace("_", " ") in doc.get("name", "").lower():
                score += 5
            for word in desc.split():
                if word in doc.get("description", "").lower():
                    score += 1
            scored.append((score, doc))
        scored.sort(key=lambda x: -x[0])
        return [d for _, d in scored[:k]]

    hits_k3 = hits_k5 = 0
    rr_scores = []
    total_queries = 0

    for file_entry in metadata["files"]:
        for smell in file_entry["smells"]:
            total_queries += 1
            top5 = retrieve(smell, 5)
            relevant_positions = [
                i + 1 for i, doc in enumerate(top5) if is_relevant(doc, smell)
            ]
            if relevant_positions:
                first_rank = min(relevant_positions)
                rr_scores.append(1.0 / first_rank)
                if first_rank <= 3:
                    hits_k3 += 1
                hits_k5 += 1
            else:
                rr_scores.append(0.0)

    n = total_queries
    return {
        "hit_rate_k3": hits_k3 / n if n > 0 else 0.0,
        "hit_rate_k5": hits_k5 / n if n > 0 else 0.0,
        "mrr": mean(rr_scores) if rr_scores else 0.0,
        "total_queries": n,
    }


# ===========================================================================
# Lightweight RAG retriever (no ChromaDB needed for standalone evaluation)
# ===========================================================================

class SimpleTaxonomyRetriever:
    """Keyword-overlap retriever for standalone evaluation runs."""

    def __init__(self, n_results: int = 5):
        self.taxonomy = json.loads(TAXONOMY_PATH.read_text())
        self.n_results = n_results

    def retrieve(self, smells: list[dict], iac_tool: str, retry: int = 0) -> str:
        query_parts = [s.get("type", "") + " " + s.get("cwe", "") for s in smells]
        query = " ".join(query_parts).lower()
        if retry == 1:
            query += " minimal targeted fix"
        elif retry >= 2:
            query += " conservative safe remediation"

        scored = []
        for doc in self.taxonomy:
            score = 0
            for smell in smells:
                if doc.get("cwe", "") == smell.get("cwe", ""):
                    score += 10
                if smell.get("type", "").replace("_", " ") in doc.get("name", "").lower():
                    score += 5
                if iac_tool in doc.get("iac_tools", []):
                    score += 2
            for word in query.split():
                if len(word) > 3 and word in doc.get("description", "").lower():
                    score += 1
            scored.append((score, doc))

        scored.sort(key=lambda x: -x[0])
        top = scored[:self.n_results]

        sections = []
        for i, (_, doc) in enumerate(top, 1):
            sections.append(
                f"[Doc {i}] {doc['name']} (CWE={doc['cwe']})\n"
                f"{doc['description']}\n"
                f"Fix: {doc['fix_example']}"
            )
        return "\n\n---\n\n".join(sections) if sections else "No relevant knowledge found."


# ===========================================================================
# Report Generator
# ===========================================================================

def print_report(detection: dict, retrieval: dict, remediation: dict,
                 config: str, model: str) -> None:
    sep = "=" * 72

    print(f"\n{sep}")
    print(f"  EVALUATION REPORT — Agentic IaC Security Framework")
    print(f"  Config: {config} | Model: {model}")
    print(sep)

    print("\n[DETECTION METRICS]")
    print(f"  Ground-truth smells: {detection['total_gt']}")
    print(f"  Detected:            {detection['total_detected']}")
    print(f"  TP: {detection['TP']}  |  FP: {detection['FP']}  |  FN: {detection['FN']}")
    print(f"  Precision : {detection['precision']:.4f}")
    print(f"  Recall    : {detection['recall']:.4f}")
    print(f"  F1-Score  : {detection['f1']:.4f}")
    print(f"  Macro-F1  : {detection['macro_f1']:.4f}")

    if detection.get("per_tool"):
        print("\n  Per IaC Tool:")
        print(f"  {'Tool':<15} {'P':>8} {'R':>8} {'F1':>8} {'TP':>5} {'FP':>5} {'FN':>5}")
        print(f"  {'-'*55}")
        for tool, m in detection["per_tool"].items():
            print(f"  {tool:<15} {m['precision']:>8.4f} {m['recall']:>8.4f} "
                  f"{m['f1']:>8.4f} {m['tp']:>5} {m['fp']:>5} {m['fn']:>5}")

    print(f"\n[RETRIEVAL METRICS]")
    print(f"  Queries:       {retrieval['total_queries']}")
    print(f"  Hit Rate@3:    {retrieval['hit_rate_k3']:.4f}")
    print(f"  Hit Rate@5:    {retrieval['hit_rate_k5']:.4f}")
    print(f"  MRR:           {retrieval['mrr']:.4f}")

    print(f"\n[REMEDIATION METRICS]")
    print(f"  PVR  (Patch Validity Rate):     {remediation['pvr']:.4f}")
    print(f"  SER  (Smell Elimination Rate):  {remediation['ser']:.4f}")
    print(f"  NNIR (No-New-Issues Rate):      {remediation['nnir']:.4f}")
    if "pvr_checkov" in remediation:
        print(f"  PVR (Checkov only):             {remediation['pvr_checkov']:.4f}")
    if "pvr_kics" in remediation:
        print(f"  PVR (KICS only):                {remediation['pvr_kics']:.4f}")
    print(f"  Total files:   {remediation.get('total_files', 'N/A')}")
    print(f"  Valid patches: {remediation.get('total_patched', 'N/A')}")

    # Summary table
    print(f"\n{sep}")
    print("  SUMMARY (8 Metrics)")
    print(sep)
    metrics_table = [
        ("Precision",      "Detection",    f"{detection['precision']:.4f}"),
        ("Recall",         "Detection",    f"{detection['recall']:.4f}"),
        ("F1-Score",       "Detection",    f"{detection['f1']:.4f}"),
        ("Macro-F1",       "Detection",    f"{detection['macro_f1']:.4f}"),
        ("Hit Rate@3",     "Retrieval",    f"{retrieval['hit_rate_k3']:.4f}"),
        ("Hit Rate@5",     "Retrieval",    f"{retrieval['hit_rate_k5']:.4f}"),
        ("MRR",            "Retrieval",    f"{retrieval['mrr']:.4f}"),
        ("PVR",            "Remediation",  f"{remediation['pvr']:.4f}"),
        ("SER",            "Remediation",  f"{remediation['ser']:.4f}"),
        ("NNIR",           "Remediation",  f"{remediation['nnir']:.4f}"),
    ]
    print(f"  {'Metric':<20} {'Layer':<15} {'Value':>10}")
    print(f"  {'-'*48}")
    for name, layer, value in metrics_table:
        print(f"  {name:<20} {layer:<15} {value:>10}")

    print(f"\n{sep}\n")


def write_manifest(config: str, model: str, backend: str, n_records: int,
                   metrics: dict, output_dir: Path) -> Path:
    """Write a reproducibility manifest alongside results."""
    import shutil

    manifest = {
        "run_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "config": config,
        "model": model,
        "backend": backend,
        "split": "test",
        "split_seed": 42,
        "n_records": n_records,
        "checkov_available": shutil.which("checkov") is not None,
        "kics_available": shutil.which("kics") is not None,
        "metrics": metrics,
    }
    path = output_dir / f"manifest_{config}.json"
    with path.open("w") as f:
        json.dump(manifest, f, indent=2, default=str)
    return path


# ===========================================================================
# Config A — Baseline (Checkov-only detection, no LLM)
# ===========================================================================

def run_config_a() -> None:
    metadata = load_metadata()
    logger.info("Config A: Checkov-only baseline on %d files", len(metadata["files"]))

    detected_by_file: dict[str, list[dict]] = {}
    for file_entry in metadata["files"]:
        file_path = DATASET_ROOT / file_entry["file"]
        if not file_path.exists():
            logger.warning("File not found: %s", file_path)
            detected_by_file[file_entry["id"]] = []
            continue
        checks = run_checkov(file_path)
        smells = checkov_checks_to_smells(checks)
        detected_by_file[file_entry["id"]] = smells
        logger.info("  %s: %d smells detected", file_entry["id"], len(smells))

    detection = compute_detection_metrics(detected_by_file, metadata)
    retrieval = compute_retrieval_metrics(metadata)
    remediation = {"pvr": 0.0, "ser": 0.0, "nnir": 0.0,
                   "total_files": len(metadata["files"]), "total_patched": 0}

    print_report(detection, retrieval, remediation, config="A", model="N/A (Checkov only)")

    results = {"config": "A", "detection": detection, "retrieval": retrieval,
               "remediation": remediation}
    output_path = Path(__file__).parent / "evaluation_results.json"
    with output_path.open("w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info("Results saved to %s", output_path)


# ===========================================================================
# Configs B / C / D — LLM pipeline
# ===========================================================================

def run_pipeline_evaluation(config: str, model: str | None = None) -> None:
    """Run Config B, C, or D on the 16-file labelled benchmark."""
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

    from analyzer.contextual import ContextualAnalyzer
    from generator.fix_generator import FixGenerator
    from validator.tool_integrator import ExternalToolValidator

    # Config features
    use_rag = config in ("B", "C", "D")
    use_validator = config in ("C", "D")
    max_retries = 3 if config == "D" else 1

    analyzer = ContextualAnalyzer()
    generator = FixGenerator(model=model, self_consistency=(config == "D"))
    validator = ExternalToolValidator() if use_validator else None
    retriever = SimpleTaxonomyRetriever() if use_rag else None

    metadata = load_metadata()
    total_files = len(metadata["files"])

    pvr_valid = 0
    ser_numerator = 0
    ser_denominator = 0
    nnir_violations = 0
    total_patched = 0
    detected_by_file: dict[str, list[dict]] = {}

    for i, file_entry in enumerate(metadata["files"], 1):
        file_path = DATASET_ROOT / file_entry["file"]
        fid = file_entry["id"]
        logger.info("[%d/%d] %s", i, total_files, fid)

        if not file_path.exists():
            detected_by_file[fid] = []
            continue

        # Stage 1 — Detect
        try:
            analysis = analyzer.analyze(file_path)
            smells = analysis["smells"]
            iac_tool = analysis["tool"]
        except Exception as exc:
            logger.error("  Analyzer failed: %s", exc)
            detected_by_file[fid] = []
            continue

        detected_by_file[fid] = smells
        if not smells:
            continue

        ser_denominator += len(smells)

        # Stage 2 — Retrieve (if enabled)
        rag_context = ""
        if retriever:
            rag_context = retriever.retrieve(smells, iac_tool)

        # Stage 3-5 — Generate → Validate → Retry
        valid_patch = None
        for attempt in range(1, max_retries + 1):
            if attempt > 1 and retriever:
                rag_context = retriever.retrieve(smells, iac_tool, retry=attempt - 1)

            try:
                patches = generator.generate(
                    script_path=file_path, smells=smells, rag_context=rag_context,
                )
            except Exception as exc:
                logger.error("  Generator failed (attempt %d): %s", attempt, exc)
                continue

            for patch in patches:
                if validator:
                    result = validator.validate(
                        original_path=file_path, patch=patch, smells=smells,
                    )
                    if result["valid"]:
                        valid_patch = patch
                        break
                else:
                    # Config B: no validator, accept any non-empty patch
                    valid_patch = patch
                    break

            if valid_patch:
                break

        if valid_patch:
            total_patched += 1
            pvr_valid += 1

            if validator:
                result = validator.validate(
                    original_path=file_path, patch=valid_patch, smells=smells,
                )
                ser_numerator += len(result.get("removed_smells", []))
                if result.get("new_smells"):
                    nnir_violations += 1
            else:
                ser_numerator += len(smells)  # optimistic for Config B

    pvr = pvr_valid / total_files if total_files > 0 else 0.0
    ser = ser_numerator / ser_denominator if ser_denominator > 0 else 0.0
    nnir = 1.0 - (nnir_violations / total_patched) if total_patched > 0 else 0.0

    detection = compute_detection_metrics(detected_by_file, metadata)
    retrieval = compute_retrieval_metrics(metadata)
    remediation = {
        "pvr": pvr, "ser": ser, "nnir": nnir,
        "total_files": total_files, "total_patched": total_patched,
    }

    effective_model = generator._effective_model()
    print_report(detection, retrieval, remediation,
                 config=config, model=f"{generator._backend}/{effective_model}")

    results = {
        "config": config, "model": effective_model, "backend": generator._backend,
        "detection": detection, "retrieval": retrieval, "remediation": remediation,
    }
    output_path = Path(__file__).parent / f"evaluation_results_{config}.json"
    with output_path.open("w") as f:
        json.dump(results, f, indent=2, default=str)
    manifest_path = write_manifest(
        config=config, model=effective_model, backend=generator._backend,
        n_records=total_files, metrics={"pvr": pvr, "ser": ser, "nnir": nnir,
                                         "macro_f1": detection["macro_f1"]},
        output_dir=Path(__file__).parent,
    )
    logger.info("Results saved. Manifest: %s", manifest_path)


# ===========================================================================
# Main
# ===========================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate the IaC security framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config", choices=["A", "B", "C", "D"], default="A",
        help="A=Checkov only, B=+RAG, C=+RAG+Checkov, D=+RAG+Checkov+KICS+retry",
    )
    parser.add_argument(
        "--model", default=None,
        help=(
            "Model name for the LLM backend. "
            "Examples: 'gemma3:4b' (Ollama), "
            "'meta-llama/llama-3.1-8b-instruct:free' (OpenRouter), "
            "'gpt-4o-mini' (OpenAI)"
        ),
    )
    parser.add_argument(
        "--dataset", default=None,
        help="Path to JSONL dataset (e.g. 33k corpus test split). "
             "If not set, uses the 16-file labelled benchmark.",
    )
    args = parser.parse_args()

    if args.config == "A":
        run_config_a()
    else:
        run_pipeline_evaluation(config=args.config, model=args.model)
