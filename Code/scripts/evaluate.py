#!/usr/bin/env python3
"""
Evaluation Script — Agentic IaC Security Framework
====================================================
Computes all 18 metrics across the 4 evaluation layers on the ground-truth
dataset (dataset/metadata.json).

Usage:
    python3 scripts/evaluate.py [--mode baseline|full] [--model MODEL]

Modes:
    baseline  (default) — Config A: Checkov-only detection, no LLM
    full                — Config D: Full pipeline with LLM patch generation

LLM backends (detected from environment variables, in priority order):
    ANTHROPIC_API_KEY   → Anthropic Claude
    OPENROUTER_API_KEY  → OpenRouter free models (Llama, MiniMax, Mistral, Gemma…)
    MINIMAX_API_KEY     → MiniMax API directly
    OPENAI_API_KEY      → OpenAI

Example — run full evaluation with a free OpenRouter model:
    export OPENROUTER_API_KEY="sk-or-..."
    python3 scripts/evaluate.py --mode full --model "meta-llama/llama-3.1-8b-instruct:free"

Example — run with MiniMax:
    export OPENROUTER_API_KEY="sk-or-..."
    python3 scripts/evaluate.py --mode full --model "minimax/minimax-01"

Author: Ahmedou Yahye Kheyri
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

DATASET_ROOT = Path(__file__).parent.parent / "dataset"
METADATA_PATH = DATASET_ROOT / "metadata.json"
TAXONOMY_PATH = DATASET_ROOT / "taxonomy" / "smells_taxonomy.json"


# ===========================================================================
# Utilities
# ===========================================================================

def load_metadata() -> dict:
    with METADATA_PATH.open() as f:
        return json.load(f)


def run_checkov(file_path: Path) -> list[dict]:
    """Run Checkov and return list of failed checks as normalised dicts."""
    try:
        result = subprocess.run(
            ["checkov", "--file", str(file_path), "--output", "json", "--quiet"],
            capture_output=True, text=True, timeout=60,
        )
        raw = result.stdout or "{}"
        data = json.loads(raw)
        # Checkov may return a list (one entry per framework: terraform, secrets, etc.)
        # or a single dict
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
    """Normalise Checkov output to smell dicts matching metadata format."""
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
    """
    True if detected smell matches ground truth.
    Matching criteria: checker_id == checkov_id AND line within ±tolerance.
    If either line is null, accept on checker_id match alone.
    Line tolerance increased to 5 to account for Checkov reporting the start of
    the resource block rather than the specific misconfigured line.
    """
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
        return True  # Accept on ID match when line is unavailable
    return abs(det_line - gt_line) <= line_tolerance


# ===========================================================================
# Layer 1 — Detection Metrics
# ===========================================================================

def compute_detection_metrics(
    detected_by_file: dict[str, list[dict]],
    metadata: dict,
) -> dict:
    """
    Precision, Recall, F1 per smell type, per IaC tool, and macro-average.
    Only evaluates smells that have a non-HEURISTIC Checkov ID.
    """
    # Collect all ground-truth instances with Checkov IDs
    all_gt: list[dict] = []       # (file_id, smell_dict)
    all_det: list[dict] = []      # (file_id, smell_dict)

    for file_entry in metadata["files"]:
        fid = file_entry["id"]
        for smell in file_entry["smells"]:
            if smell.get("checkov_id", "") != "HEURISTIC":
                all_gt.append({"file_id": fid, **smell, "tool": file_entry["iac_tool"]})
        for det in detected_by_file.get(fid, []):
            all_det.append({"file_id": fid, **det, "tool": file_entry["iac_tool"]})

    # Match detected to ground truth
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
        per_tool[tool] = {"precision": p, "recall": r, "f1": f,
                          "tp": tp, "fp": fp, "fn": fn}

    return {
        "TP": TP, "FP": FP, "FN": FN,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "macro_f1": macro_f1,
        "per_type": per_type,
        "per_tool": per_tool,
        "total_gt_with_checkov_id": len(all_gt),
        "total_detected": len(all_det),
    }


# ===========================================================================
# Layer 2 — Retrieval Metrics (simplified without vector store)
# ===========================================================================

def compute_retrieval_metrics_simple(metadata: dict) -> dict:
    """
    Simplified retrieval evaluation: keyword-based matching against the
    taxonomy JSON to simulate Hit Rate without requiring ChromaDB.
    """
    taxonomy = json.loads(TAXONOMY_PATH.read_text())

    def is_relevant(doc: dict, smell: dict) -> bool:
        """A taxonomy entry is relevant if CWE or type matches the smell."""
        return (
            doc.get("cwe", "") == smell.get("cwe", "NONE")
            or smell.get("type", "").lower() in doc.get("name", "").lower().replace(" ", "_")
        )

    def retrieve(smell: dict, k: int) -> list[dict]:
        """Score taxonomy entries by keyword overlap with smell description."""
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

    hits_k1 = hits_k3 = hits_k5 = 0
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
                if first_rank <= 1:
                    hits_k1 += 1
                if first_rank <= 3:
                    hits_k3 += 1
                hits_k5 += 1
            else:
                rr_scores.append(0.0)

    n = total_queries
    return {
        "hit_rate_k1": hits_k1 / n if n > 0 else 0.0,
        "hit_rate_k3": hits_k3 / n if n > 0 else 0.0,
        "hit_rate_k5": hits_k5 / n if n > 0 else 0.0,
        "mrr_k5": mean(rr_scores) if rr_scores else 0.0,
        "total_queries": n,
        "note": "Keyword-based approximation. Run with ChromaDB for RAGAS metrics.",
    }


# ===========================================================================
# Layer 3 — Remediation Metrics (baseline: no patch generation)
# ===========================================================================

def compute_remediation_baseline() -> dict:
    """
    Baseline (Config A): Checkov does not generate patches.
    PVR, SER, NNIR are 0 for the baseline.
    """
    return {
        "pvr": 0.0,
        "ser": 0.0,
        "nnir": 0.0,
        "note": "Config A (Checkov only) — no patch generation. PVR/SER/NNIR require LLM.",
    }


# ===========================================================================
# Layer 4 — Agentic Loop (baseline: N/A)
# ===========================================================================

def compute_agentic_baseline() -> dict:
    return {
        "fa_sr": 0.0,
        "delta_r2": 0.0,
        "delta_r3": 0.0,
        "fleiss_kappa": "N/A",
        "rpa": "N/A",
        "note": "Config A (Checkov only) — no retry loop. Metrics require full pipeline.",
    }


# ===========================================================================
# Cost Estimation
# ===========================================================================

def estimate_cost(n_scripts: int, avg_tokens_in: int = 2000, avg_tokens_out: int = 500) -> dict:
    """Estimate API cost for running the full pipeline on n_scripts."""
    # GPT-4o-mini pricing (as of 2025): $0.15/1M input, $0.60/1M output
    cost_per_script = (avg_tokens_in * 0.15 + avg_tokens_out * 0.60) / 1_000_000
    total_cost = cost_per_script * n_scripts
    return {
        "model": "gpt-4o-mini",
        "avg_input_tokens": avg_tokens_in,
        "avg_output_tokens": avg_tokens_out,
        "cost_per_script_usd": round(cost_per_script, 6),
        "total_cost_usd": round(total_cost, 4),
        "n_scripts": n_scripts,
    }


# ===========================================================================
# Report Generator
# ===========================================================================

def print_report(detection: dict, retrieval: dict, remediation: dict, agentic: dict,
                 cost: dict, mode: str) -> None:
    sep = "=" * 72

    print(f"\n{sep}")
    print(f"  EVALUATION REPORT — Agentic IaC Security Framework")
    print(f"  Mode: {mode.upper()} | Dataset: {METADATA_PATH}")
    print(sep)

    print("\n[LAYER 1 — DETECTION METRICS]")
    print(f"  Total ground-truth smells (Checkov-traceable): {detection['total_gt_with_checkov_id']}")
    print(f"  Total detected by Checkov:                     {detection['total_detected']}")
    print(f"  TP: {detection['TP']}  |  FP: {detection['FP']}  |  FN: {detection['FN']}")
    print(f"  Precision : {detection['precision']:.4f}")
    print(f"  Recall    : {detection['recall']:.4f}")
    print(f"  F1-Score  : {detection['f1']:.4f}")
    print(f"  Macro-F1  : {detection['macro_f1']:.4f}")

    print("\n  Per IaC Tool:")
    print(f"  {'Tool':<15} {'Precision':>10} {'Recall':>10} {'F1':>10} {'TP':>5} {'FP':>5} {'FN':>5}")
    print(f"  {'-'*60}")
    for tool, m in detection["per_tool"].items():
        print(f"  {tool:<15} {m['precision']:>10.4f} {m['recall']:>10.4f} "
              f"{m['f1']:>10.4f} {m['tp']:>5} {m['fp']:>5} {m['fn']:>5}")

    print("\n  Per Smell Type:")
    print(f"  {'Type':<35} {'P':>8} {'R':>8} {'F1':>8} {'N':>5}")
    print(f"  {'-'*65}")
    for stype, m in sorted(detection["per_type"].items()):
        print(f"  {stype:<35} {m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['f1']:>8.4f} {m['support']:>5}")

    print(f"\n[LAYER 2 — RETRIEVAL METRICS] ({retrieval['note']})")
    print(f"  Total queries (smell instances):  {retrieval['total_queries']}")
    print(f"  Hit Rate @ K=1 :  {retrieval['hit_rate_k1']:.4f}")
    print(f"  Hit Rate @ K=3 :  {retrieval['hit_rate_k3']:.4f}")
    print(f"  Hit Rate @ K=5 :  {retrieval['hit_rate_k5']:.4f}")
    print(f"  MRR @ K=5      :  {retrieval['mrr_k5']:.4f}")

    print(f"\n[LAYER 3 — REMEDIATION METRICS]")
    print(f"  Patch Validity Rate  (PVR):  {remediation['pvr']:.4f}")
    print(f"  Smell Elimination Rate (SER): {remediation['ser']:.4f}")
    print(f"  No-New-Issues Rate  (NNIR):  {remediation['nnir']:.4f}")
    print(f"  Note: {remediation['note']}")

    print(f"\n[LAYER 4 — AGENTIC LOOP METRICS]")
    print(f"  First-Attempt Success Rate (FA-SR): {agentic['fa_sr']:.4f}")
    print(f"  ΔR@2 (retry benefit attempt 2):      {agentic['delta_r2']:.4f}")
    print(f"  ΔR@3 (retry benefit attempt 3):      {agentic['delta_r3']:.4f}")
    print(f"  Fleiss' Kappa: {agentic['fleiss_kappa']}")
    print(f"  Note: {agentic['note']}")

    print(f"\n[OPERATIONAL COST ESTIMATE]")
    print(f"  Model: {cost['model']}")
    print(f"  Avg input tokens / script:  {cost['avg_input_tokens']}")
    print(f"  Avg output tokens / script: {cost['avg_output_tokens']}")
    print(f"  Estimated cost / script:    ${cost['cost_per_script_usd']:.6f}")
    print(f"  Total for {cost['n_scripts']} scripts:      ${cost['total_cost_usd']:.4f}")

    print(f"\n{sep}")
    print("  SUMMARY TABLE (18 Metrics)")
    print(sep)
    metrics_table = [
        ("Precision",          "Detection",    f"{detection['precision']:.4f}",  "> 0.85"),
        ("Recall",             "Detection",    f"{detection['recall']:.4f}",     "> 0.85"),
        ("F1-Score",           "Detection",    f"{detection['f1']:.4f}",         "> 0.80"),
        ("Macro-F1",           "Detection",    f"{detection['macro_f1']:.4f}",   "> 0.80"),
        ("Hit Rate@1",         "Retrieval",    f"{retrieval['hit_rate_k1']:.4f}", "> 0.60"),
        ("Hit Rate@3",         "Retrieval",    f"{retrieval['hit_rate_k3']:.4f}", "> 0.70"),
        ("Hit Rate@5",         "Retrieval",    f"{retrieval['hit_rate_k5']:.4f}", "> 0.80"),
        ("MRR@5",              "Retrieval",    f"{retrieval['mrr_k5']:.4f}",      "> 0.70"),
        ("Context Recall",     "Retrieval",    "N/A (RAGAS)",                     "> 0.70"),
        ("Context Precision",  "Retrieval",    "N/A (RAGAS)",                     "> 0.75"),
        ("PVR",                "Remediation",  f"{remediation['pvr']:.4f}",       "> 0.70"),
        ("SER",                "Remediation",  f"{remediation['ser']:.4f}",       "> 0.80"),
        ("NNIR",               "Remediation",  f"{remediation['nnir']:.4f}",      "> 0.90"),
        ("FA-SR",              "Agentic",      f"{agentic['fa_sr']:.4f}",         "> 0.50"),
        ("ΔR@3",               "Agentic",      f"{agentic['delta_r3']:.4f}",      "> 0.10"),
        ("Fleiss' Kappa",      "Agentic",      str(agentic['fleiss_kappa']),      "> 0.90"),
        ("Cost/script (USD)",  "Operational",  f"${cost['cost_per_script_usd']:.6f}", "< $0.05"),
        ("Cost/valid patch",   "Operational",  "N/A",                             "< $0.10"),
    ]
    print(f"  {'Metric':<25} {'Layer':<15} {'Value':>14}  {'Target':>12}")
    print(f"  {'-'*70}")
    for name, layer, value, target in metrics_table:
        print(f"  {name:<25} {layer:<15} {value:>14}  {target:>12}")

    print(f"\n{sep}\n")


# ===========================================================================
# Main
# ===========================================================================

def run_baseline_evaluation() -> None:
    metadata = load_metadata()

    logger.info("Running Checkov on all %d dataset files...", len(metadata["files"]))
    detected_by_file: dict[str, list[dict]] = {}

    for file_entry in metadata["files"]:
        file_path = DATASET_ROOT / file_entry["file"]
        if not file_path.exists():
            logger.warning("Dataset file not found: %s", file_path)
            detected_by_file[file_entry["id"]] = []
            continue

        checks = run_checkov(file_path)
        smells = checkov_checks_to_smells(checks)
        detected_by_file[file_entry["id"]] = smells
        logger.info("  %s: %d smells detected", file_entry["id"], len(smells))

    detection = compute_detection_metrics(detected_by_file, metadata)
    retrieval = compute_retrieval_metrics_simple(metadata)
    remediation = compute_remediation_baseline()
    agentic = compute_agentic_baseline()
    cost = estimate_cost(n_scripts=len(metadata["files"]))

    print_report(detection, retrieval, remediation, agentic, cost, mode="baseline (Config A)")

    # Save results to JSON for inclusion in the report
    results = {
        "mode": "baseline",
        "detection": detection,
        "retrieval": retrieval,
        "remediation": remediation,
        "agentic": agentic,
        "cost": cost,
    }
    output_path = Path(__file__).parent / "evaluation_results.json"
    with output_path.open("w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info("Results saved to %s", output_path)


# ===========================================================================
# Simple Taxonomy Retriever (no ChromaDB needed)
# ===========================================================================

class SimpleTaxonomyRetriever:
    """
    Lightweight retriever that scores taxonomy entries by keyword overlap.
    Replaces ChromaDB for standalone evaluation runs.
    """

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
# Full Pipeline Evaluation (Config D)
# ===========================================================================

def run_full_evaluation(model: str | None = None) -> None:
    """Run Config D: full LLM pipeline on all dataset files."""
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

    # Check that at least one API key is set
    backends = ["ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "MINIMAX_API_KEY", "OPENAI_API_KEY"]
    active = next((b for b in backends if os.getenv(b)), None)
    if not active:
        logger.error(
            "No API key found. Set one of: %s", ", ".join(backends)
        )
        logger.error(
            "For free models: export OPENROUTER_API_KEY=<key> then run with "
            "--model 'meta-llama/llama-3.1-8b-instruct:free'"
        )
        sys.exit(1)

    logger.info("Using backend key: %s", active)

    from analyzer.contextual import ContextualAnalyzer
    from generator.fix_generator import FixGenerator
    from validator.tool_integrator import ExternalToolValidator

    analyzer  = ContextualAnalyzer()
    generator = FixGenerator(model=model)
    validator = ExternalToolValidator()
    retriever = SimpleTaxonomyRetriever()

    metadata = load_metadata()

    # Per-file tracking
    total_files     = len(metadata["files"])
    pvr_numerator   = 0   # patches that pass Checkov
    ser_numerator   = 0   # smells eliminated by valid patches
    ser_denominator = 0   # total smells in files that got a valid patch
    nnir_violations = 0   # files where patch introduced new issues
    fa_sr_hits      = 0   # files where patch was valid on attempt 1
    delta_r2_hits   = 0   # files fixed only on attempt 2
    delta_r3_hits   = 0   # files fixed only on attempt 3
    total_patched   = 0   # files where any valid patch was found

    # Detection metrics (LLM-based analyzer, not Checkov-only)
    detected_by_file: dict[str, list[dict]] = {}

    for i, file_entry in enumerate(metadata["files"], 1):
        file_path = DATASET_ROOT / file_entry["file"]
        fid = file_entry["id"]
        logger.info("[%d/%d] Processing %s ...", i, total_files, fid)

        if not file_path.exists():
            logger.warning("  File not found: %s", file_path)
            detected_by_file[fid] = []
            continue

        # Stage 1 – Detect smells
        try:
            analysis = analyzer.analyze(file_path)
            smells   = analysis["smells"]
            iac_tool = analysis["tool"]
        except Exception as exc:
            logger.error("  Analyzer failed: %s", exc)
            detected_by_file[fid] = []
            continue

        detected_by_file[fid] = smells
        logger.info("  Detected %d smells (tool=%s)", len(smells), iac_tool)

        if not smells:
            continue

        ser_denominator += len(smells)

        # Stage 2 – Retrieve context
        rag_context = retriever.retrieve(smells, iac_tool)

        # Stage 3-5 – Generate → Validate (up to 3 attempts)
        valid_patch   = None
        success_attempt = None

        for attempt in range(1, 4):
            if attempt > 1:
                rag_context = retriever.retrieve(smells, iac_tool, retry=attempt - 1)

            try:
                patches = generator.generate(
                    script_path=file_path,
                    smells=smells,
                    rag_context=rag_context,
                )
            except Exception as exc:
                logger.error("  Generator failed (attempt %d): %s", attempt, exc)
                continue

            for patch in patches:
                result = validator.validate(
                    original_path=file_path,
                    patch=patch,
                    smells=smells,
                )
                if result["valid"]:
                    valid_patch = patch
                    success_attempt = attempt
                    logger.info("  Valid patch on attempt %d", attempt)
                    break

            if valid_patch:
                break

        if valid_patch:
            total_patched += 1
            pvr_numerator += 1

            if success_attempt == 1:
                fa_sr_hits += 1
            elif success_attempt == 2:
                delta_r2_hits += 1
            elif success_attempt == 3:
                delta_r3_hits += 1

            # SER: count how many targeted smells are gone in the valid patch
            validation = validator.validate(
                original_path=file_path,
                patch=valid_patch,
                smells=smells,
            )
            ser_numerator += len(validation.get("removed_smells", []))
            if validation.get("new_smells"):
                nnir_violations += 1
        else:
            logger.warning("  No valid patch found after 3 attempts.")

    # Compute metrics
    pvr  = pvr_numerator / total_files if total_files > 0 else 0.0
    ser  = ser_numerator / ser_denominator if ser_denominator > 0 else 0.0
    nnir = 1.0 - (nnir_violations / total_patched) if total_patched > 0 else 0.0
    fa_sr    = fa_sr_hits / total_files if total_files > 0 else 0.0
    delta_r2 = delta_r2_hits / total_files if total_files > 0 else 0.0
    delta_r3 = delta_r3_hits / total_files if total_files > 0 else 0.0

    detection  = compute_detection_metrics(detected_by_file, metadata)
    retrieval  = compute_retrieval_metrics_simple(metadata)
    remediation = {
        "pvr":  pvr,
        "ser":  ser,
        "nnir": nnir,
        "total_files": total_files,
        "total_patched": total_patched,
        "note": f"Config D — {generator._backend} / {generator._effective_model()}",
    }
    agentic = {
        "fa_sr":        fa_sr,
        "delta_r2":     delta_r2,
        "delta_r3":     delta_r3,
        "fleiss_kappa": "N/A (single annotator)",
        "rpa":          "N/A",
        "note": f"Retry loop active (MAX_RETRIES=3). FA-SR={fa_sr:.3f}",
    }
    cost = estimate_cost(n_scripts=total_files)
    cost["model"] = generator._effective_model()

    mode_label = f"full (Config D) — {generator._backend} / {generator._effective_model()}"
    print_report(detection, retrieval, remediation, agentic, cost, mode=mode_label)

    results = {
        "mode": "full",
        "model": generator._effective_model(),
        "backend": generator._backend,
        "detection":   detection,
        "retrieval":   retrieval,
        "remediation": remediation,
        "agentic":     agentic,
        "cost":        cost,
    }
    output_path = Path(__file__).parent / "evaluation_results_full.json"
    with output_path.open("w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info("Full results saved to %s", output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate the IaC security framework.")
    parser.add_argument("--mode", choices=["baseline", "full"], default="baseline",
                        help="baseline = Checkov only (Config A); full = LLM pipeline (Config D)")
    parser.add_argument("--model", default=None,
                        help=(
                            "Model name for the active backend. "
                            "OpenRouter examples: 'meta-llama/llama-3.1-8b-instruct:free', "
                            "'minimax/minimax-01', 'mistralai/mistral-7b-instruct:free'. "
                            "MiniMax direct: 'MiniMax-Text-01'. "
                            "Defaults to backend-specific free/cheap model."
                        ))
    args = parser.parse_args()

    if args.mode == "baseline":
        run_baseline_evaluation()
    else:
        run_full_evaluation(model=args.model)
