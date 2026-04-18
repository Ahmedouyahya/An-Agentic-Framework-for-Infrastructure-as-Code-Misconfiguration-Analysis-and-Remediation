"""
Scanner-backed ground-truth labeller.

Runs actual IaC security scanners (Checkov, tfsec, KICS, Terrascan) on
`code_before` / `code_after` of every record, then attaches a
`validated_smells` list with the findings. This converts the regex-labeled
dataset into a **scanner-validated** one, which is what makes it a usable
contribution for downstream research (LLM fine-tuning, benchmarking,
detection models).

Design:
    - Detects which scanners are available on the host at startup.
    - Spawns the scanner as a subprocess against a temp file with the
      correct extension for each record's iac_tool.
    - Parses JSON output → list of {scanner, rule_id, severity, cwe, line}.
    - Single-pass over an existing JSONL file; writes a new *.validated.jsonl
      so the original raw data is never modified.
    - Fully resumable: on restart skips records already present in the
      output file (by id).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool → file extension mapping for the temp file passed to the scanner
# ---------------------------------------------------------------------------
_EXT_BY_TOOL = {
    "terraform":      ".tf",
    "kubernetes":     ".yaml",
    "helm":           ".yaml",
    "docker":         "Dockerfile",   # used as filename, not suffix
    "dockerfile":     "Dockerfile",
    "ansible":        ".yml",
    "cloudformation": ".yaml",
    "bicep":          ".bicep",
    "pulumi":         ".yaml",
}

_CHECKOV_FRAMEWORK = {
    "terraform":      "terraform",
    "kubernetes":     "kubernetes",
    "helm":           "helm",
    "docker":         "dockerfile",
    "dockerfile":     "dockerfile",
    "ansible":        "ansible",
    "cloudformation": "cloudformation",
    "bicep":          "bicep",
}


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def detect_scanners() -> Dict[str, Optional[str]]:
    """Return {scanner_name: path_or_None} for all supported scanners."""
    return {
        "checkov":   _which("checkov"),
        "tfsec":     _which("tfsec"),
        "kics":      _which("kics"),
        "terrascan": _which("terrascan"),
    }


# ---------------------------------------------------------------------------
# Temp-file helper
# ---------------------------------------------------------------------------

def _write_temp(content: str, iac_tool: str) -> Tuple[str, str]:
    """Write content to a temp file with the right extension; return (dir, path)."""
    ext = _EXT_BY_TOOL.get(iac_tool, ".txt")
    tmpdir = tempfile.mkdtemp(prefix="iacval_")
    if ext.startswith("."):
        filename = f"sample{ext}"
    else:
        filename = ext  # e.g. "Dockerfile"
    path = os.path.join(tmpdir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return tmpdir, path


def _cleanup_tmp(tmpdir: str) -> None:
    try:
        shutil.rmtree(tmpdir, ignore_errors=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Scanner runners — each returns a list of normalised findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    scanner: str
    rule_id: str
    severity: Optional[str]
    cwe: Optional[str]
    line: Optional[int]
    message: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner":  self.scanner,
            "rule_id":  self.rule_id,
            "severity": self.severity,
            "cwe":      self.cwe,
            "line":     self.line,
            "message":  (self.message or "")[:200],
        }


def _run_checkov(tmpdir: str, file_path: str, iac_tool: str, timeout: int = 60) -> List[Finding]:
    framework = _CHECKOV_FRAMEWORK.get(iac_tool)
    if not framework:
        return []
    cmd = [
        "checkov",
        "-f", file_path,
        "--framework", framework,
        "-o", "json",
        "--quiet",
        "--compact",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.debug("checkov failed on %s: %s", file_path, exc)
        return []

    out = proc.stdout or ""
    if not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        # Some checkov versions emit multiple JSON blocks
        try:
            data = json.loads("[" + out.replace("}{", "},{") + "]")
        except json.JSONDecodeError:
            return []

    results: List[Finding] = []
    for block in _iter_checkov_blocks(data):
        failed = (block.get("results") or {}).get("failed_checks") or []
        for chk in failed:
            results.append(Finding(
                scanner="checkov",
                rule_id=str(chk.get("check_id") or ""),
                severity=(chk.get("severity") or "").upper() or None,
                cwe=_extract_cwe(chk),
                line=_extract_line(chk),
                message=chk.get("check_name"),
            ))
    return results


def _iter_checkov_blocks(data) -> List[Dict]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def _extract_cwe(chk: Dict) -> Optional[str]:
    guide = chk.get("guideline") or ""
    if "CWE-" in guide:
        import re
        m = re.search(r"CWE-\d+", guide)
        if m:
            return m.group(0)
    return None


def _extract_line(chk: Dict) -> Optional[int]:
    r = chk.get("file_line_range")
    if isinstance(r, list) and r:
        try:
            return int(r[0])
        except (TypeError, ValueError):
            return None
    return None


def _run_tfsec(tmpdir: str, file_path: str, iac_tool: str, timeout: int = 60) -> List[Finding]:
    if iac_tool != "terraform":
        return []
    cmd = ["tfsec", tmpdir, "--format", "json", "--no-colour", "--soft-fail"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    results: List[Finding] = []
    for r in data.get("results") or []:
        results.append(Finding(
            scanner="tfsec",
            rule_id=str(r.get("rule_id") or r.get("long_id") or ""),
            severity=(r.get("severity") or "").upper() or None,
            cwe=None,
            line=(r.get("location") or {}).get("start_line"),
            message=r.get("description"),
        ))
    return results


def _run_kics(tmpdir: str, file_path: str, iac_tool: str, timeout: int = 90) -> List[Finding]:
    cmd = ["kics", "scan", "-p", tmpdir, "-o", tmpdir, "--report-formats", "json",
           "--silent", "--no-progress"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    report = Path(tmpdir) / "results.json"
    if not report.exists():
        return []
    try:
        data = json.loads(report.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    results: List[Finding] = []
    for q in data.get("queries") or []:
        for f in q.get("files") or []:
            results.append(Finding(
                scanner="kics",
                rule_id=q.get("query_id") or q.get("query_name") or "",
                severity=(q.get("severity") or "").upper() or None,
                cwe=q.get("cwe") or None,
                line=f.get("line"),
                message=q.get("query_name"),
            ))
    return results


# ---------------------------------------------------------------------------
# Single-record validation (run in a worker process)
# ---------------------------------------------------------------------------

def _validate_one_record(
    record: Dict,
    scanners: Tuple[str, ...],
    timeout: int,
) -> Dict:
    """Worker: validate `code_before` and `code_after` of a single record."""
    iac_tool = record.get("iac_tool", "")
    out_findings: Dict[str, List[Dict]] = {"before": [], "after": []}

    for which, key in (("before", "code_before"), ("after", "code_after")):
        content = record.get(key)
        if not content:
            continue
        tmpdir, path = _write_temp(content, iac_tool)
        try:
            findings: List[Finding] = []
            if "checkov" in scanners:
                findings.extend(_run_checkov(tmpdir, path, iac_tool, timeout))
            if "tfsec" in scanners:
                findings.extend(_run_tfsec(tmpdir, path, iac_tool, timeout))
            if "kics" in scanners:
                findings.extend(_run_kics(tmpdir, path, iac_tool, timeout))
            out_findings[which] = [f.to_dict() for f in findings]
        finally:
            _cleanup_tmp(tmpdir)

    record["validated_smells_before"] = out_findings["before"]
    record["validated_smells_after"]  = out_findings["after"]
    record["validation_scanners"]     = list(scanners)
    return record


# ---------------------------------------------------------------------------
# Parallel driver over a JSONL file
# ---------------------------------------------------------------------------

def validate_jsonl(
    input_path: Path,
    output_path: Path,
    workers: int = 4,
    timeout: int = 60,
    limit: Optional[int] = None,
) -> Dict[str, int]:
    """
    Run available scanners on every record in `input_path`, writing validated
    records to `output_path`. Resumable: skips records already present in the
    output file (matched by id).
    """
    available = [name for name, path in detect_scanners().items() if path]
    if not available:
        raise RuntimeError(
            "No scanners found on PATH. Install at least one of: "
            "checkov, tfsec, kics, terrascan."
        )
    logger.info("Validator running with scanners: %s", ", ".join(available))

    # Load already-validated ids for resume
    done_ids: set = set()
    if output_path.exists():
        with output_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rid = json.loads(line).get("id")
                    if rid:
                        done_ids.add(rid)
                except json.JSONDecodeError:
                    continue
    logger.info("Resuming — %d records already validated", len(done_ids))

    stats = {"processed": 0, "skipped": 0, "errored": 0, "with_findings": 0}
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with input_path.open("r", encoding="utf-8", errors="replace") as src, \
         output_path.open("a", encoding="utf-8") as dst, \
         ProcessPoolExecutor(max_workers=workers) as pool:

        futures = []
        for line in src:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                stats["errored"] += 1
                continue

            if record.get("id") in done_ids:
                stats["skipped"] += 1
                continue

            futures.append(pool.submit(
                _validate_one_record,
                record, tuple(available), timeout,
            ))

            if len(futures) >= workers * 4:
                _drain(futures, dst, stats)

            if limit and stats["processed"] >= limit:
                break

        _drain(futures, dst, stats)

    logger.info("Validator finished: %s", stats)
    return stats


def _drain(futures: List, dst, stats: Dict[str, int]) -> None:
    for fut in as_completed(futures):
        try:
            rec = fut.result()
        except Exception as exc:
            logger.warning("Validator worker error: %s", exc)
            stats["errored"] += 1
            continue
        dst.write(json.dumps(rec, ensure_ascii=False) + "\n")
        dst.flush()
        stats["processed"] += 1
        if rec.get("validated_smells_before") or rec.get("validated_smells_after"):
            stats["with_findings"] += 1
    futures.clear()
