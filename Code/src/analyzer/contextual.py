"""
Contextual Analyzer
-------------------
Identifies the IaC tool type (Terraform, Ansible, Kubernetes, Docker, …),
extracts structural metrics, and detects candidate smell locations.

Phase-1 implementation uses heuristic rules and Checkov output.
Phase-2 can swap in CodeBERT embeddings for semantic smell localization.
"""

from __future__ import annotations

import re
import subprocess
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Heuristic signatures for IaC tool detection
_TOOL_SIGNATURES = {
    "terraform": [r"resource\s+\"", r"provider\s+\"", r"terraform\s*\{"],
    "ansible":   [r"^\s*-\s+name:", r"^\s*hosts:", r"^\s*tasks:"],
    "kubernetes": [r"apiVersion:", r"kind:\s+(Deployment|Pod|Service|ConfigMap)"],
    "docker":    [r"^FROM\s+", r"^RUN\s+", r"^EXPOSE\s+"],
}


class ContextualAnalyzer:
    """
    Analyzes an IaC script to produce:
      - tool: str             e.g. "terraform"
      - smells: list[dict]    each with keys: line, type, description, cwe, checker_id
      - metrics: dict         token count, line count, complexity proxy
    """

    def analyze(self, script_path: Path) -> dict:
        content = script_path.read_text(errors="replace")
        tool = self._detect_tool(content, script_path)
        metrics = self._extract_metrics(content)
        smells = self._detect_smells_checkov(script_path, tool)

        logger.info("Tool=%s | lines=%d | smells=%d", tool, metrics["line_count"], len(smells))
        return {"tool": tool, "smells": smells, "metrics": metrics}

    # ------------------------------------------------------------------
    def _detect_tool(self, content: str, path: Path) -> str:
        suffix = path.suffix.lower()
        name = path.name.lower()

        if suffix == ".tf":
            return "terraform"
        if name in ("dockerfile", "dockerfile.insecure") or name.startswith("dockerfile"):
            return "docker"

        # Check kubernetes before ansible: both use YAML, but kubernetes has
        # unambiguous markers (apiVersion + kind) that must take priority.
        priority_order = ["kubernetes", "terraform", "ansible", "docker"]
        for tool in priority_order:
            patterns = _TOOL_SIGNATURES.get(tool, [])
            if any(re.search(p, content, re.MULTILINE) for p in patterns):
                return tool

        return "unknown"

    def _extract_metrics(self, content: str) -> dict:
        lines = content.splitlines()
        tokens = len(content.split())
        return {
            "line_count": len(lines),
            "token_count": tokens,
            "blank_lines": sum(1 for l in lines if not l.strip()),
            "comment_lines": sum(1 for l in lines if l.strip().startswith(("#", "//", "/*"))),
        }

    def _detect_smells_checkov(self, path: Path, tool: str) -> list[dict]:
        """Run Checkov and parse its JSON output into a normalized smell list."""
        try:
            result = subprocess.run(
                ["checkov", "--file", str(path), "--output", "json", "--quiet"],
                capture_output=True, text=True, timeout=60,
            )
            data = json.loads(result.stdout or "{}")
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
            logger.warning("Checkov unavailable (%s), falling back to heuristics.", exc)
            return self._heuristic_smells(path.read_text(errors="replace"), tool)

        # Checkov 3.2+ returns a list when multiple scanners apply (e.g. terraform + secrets)
        entries = data if isinstance(data, list) else [data]
        smells = []
        for entry in entries:
            for item in entry.get("results", {}).get("failed_checks", []):
                smells.append({
                    "checker_id": item.get("check_id", ""),
                    "type": item.get("check_id", "UNKNOWN"),
                    "description": item.get("check_result", {}).get("result", ""),
                    "cwe": "",          # populated later by knowledge retriever
                    "line": item.get("file_line_range", [0])[0],
                    "resource": item.get("resource", ""),
                })
        return smells

    def _heuristic_smells(self, content: str, tool: str) -> list[dict]:
        """Fallback: simple regex-based smell detection."""
        smells = []
        patterns = [
            (r'password\s*=\s*"[^"]+"',        "hardcoded_secret",       "CWE-259"),
            (r'secret\s*=\s*"[^"]+"',          "hardcoded_secret",       "CWE-259"),
            (r'access_key\s*=\s*"[^"]+"',      "hardcoded_credential",   "CWE-798"),
            (r'0\.0\.0\.0/0',                  "overly_permissive_cidr", "CWE-732"),
            (r'privileged\s*:\s*true',          "privileged_container",   "CWE-250"),
            (r'runAsRoot\s*:\s*true',           "run_as_root",            "CWE-250"),
            (r'validate_certs\s*:\s*no',        "tls_disabled",           "CWE-295"),
            (r'mode\s*[=:]\s*[\'"]?0?777',     "world_writable",         "CWE-732"),
        ]
        for i, line in enumerate(content.splitlines(), 1):
            for pattern, smell_type, cwe in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    smells.append({
                        "checker_id": "HEURISTIC",
                        "type": smell_type,
                        "description": f"Potential {smell_type.replace('_', ' ')} on line {i}",
                        "cwe": cwe,
                        "line": i,
                        "resource": "",
                    })
        return smells
