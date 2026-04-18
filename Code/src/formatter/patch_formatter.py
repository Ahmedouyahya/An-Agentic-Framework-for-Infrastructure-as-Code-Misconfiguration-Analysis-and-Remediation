"""
Patch Formatter and Explanation Generator
------------------------------------------
Takes a validated patch and produces:
  1. A clean unified diff file (ready for `git apply` or `patch -u`).
  2. A natural language explanation of each fix, with CWE references.

CWE descriptions are loaded from the taxonomy file at startup so they stay
in sync with the Knowledge Base. A hardcoded fallback covers the most common
CWEs in case the taxonomy file is missing.
"""

from __future__ import annotations

import difflib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

TAXONOMY_PATH = Path(__file__).parent.parent.parent / "dataset" / "taxonomy" / "smells_taxonomy.json"

# Fallback CWE descriptions (used if taxonomy file is missing)
_FALLBACK_CWE = {
    "CWE-259": "Use of Hard-coded Password",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-295": "Improper Certificate Validation",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
}


def _load_cwe_descriptions() -> dict[str, str]:
    """Load CWE descriptions from the taxonomy JSON, with fallback."""
    descriptions = dict(_FALLBACK_CWE)
    if TAXONOMY_PATH.exists():
        try:
            taxonomy = json.loads(TAXONOMY_PATH.read_text())
            for entry in taxonomy:
                cwe = entry.get("cwe", "")
                name = entry.get("name", "")
                if cwe and name:
                    descriptions[cwe] = name
            logger.debug("Loaded %d CWE descriptions from taxonomy", len(descriptions))
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Failed to load taxonomy CWEs: %s — using fallback", exc)
    else:
        logger.debug("Taxonomy file not found at %s — using fallback CWEs", TAXONOMY_PATH)
    return descriptions


CWE_DESCRIPTIONS = _load_cwe_descriptions()


class PatchFormatter:
    """
    Formats a validated patch for developer consumption.
    """

    def format(self, original_path: Path, patch: str, smells: list[dict]) -> dict:
        """
        Returns:
          {"diff": str, "explanation": str}
        """
        diff = self._ensure_unified_diff(original_path, patch)
        explanation = self._generate_explanation(smells, diff)
        return {"diff": diff, "explanation": explanation}

    def _ensure_unified_diff(self, original_path: Path, patch: str) -> str:
        """If patch is already a unified diff, return it. Otherwise, compute one."""
        if patch.strip().startswith("---"):
            return patch

        # patch is the full fixed content — compute diff against original
        original_lines = original_path.read_text(errors="replace").splitlines(keepends=True)
        patched_lines  = patch.splitlines(keepends=True)
        diff = "".join(difflib.unified_diff(
            original_lines, patched_lines,
            fromfile=f"a/{original_path.name}",
            tofile=f"b/{original_path.name}",
        ))
        return diff

    def _generate_explanation(self, smells: list[dict], diff: str) -> str:
        lines = ["## Security Patch Explanation\n"]
        for smell in smells:
            cwe = smell.get("cwe", "")
            cwe_desc = CWE_DESCRIPTIONS.get(cwe, "")
            smell_type = smell.get("type", "unknown").replace("_", " ").title()
            line_no = smell.get("line", "?")

            lines.append(f"### {smell_type}")
            lines.append(f"- **Location:** Line {line_no}")
            if cwe:
                lines.append(f"- **CWE Reference:** [{cwe}] {cwe_desc}")
            lines.append(f"- **Issue:** {smell.get('description', 'Security misconfiguration detected.')}")
            lines.append(f"- **Remediation:** The patch removes the insecure configuration "
                         f"and replaces it with a secure alternative.")
            lines.append("")

        lines.append("### Diff Summary")
        added   = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))
        lines.append(f"- Lines added: {added}")
        lines.append(f"- Lines removed: {removed}")
        lines.append(f"- Net change: {added - removed:+d} lines")

        return "\n".join(lines)
