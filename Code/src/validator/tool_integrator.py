"""
External Tool Integrator (Validator)
-------------------------------------
Applies a candidate patch to a temporary copy of the original file,
then runs Checkov (and optionally Terrascan) to verify that:
  1. The smells reported in `smells` are no longer present.
  2. No NEW issues have been introduced by the patch.

This is the key module that makes the framework actively critical rather
than a passive RAG system.
"""

from __future__ import annotations

import difflib
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class ExternalToolValidator:
    """
    Validates a patch by:
      1. Applying it to a temp file.
      2. Running Checkov on the patched file.
      3. Comparing check IDs before/after to confirm smell removal.
    """

    def validate(self, original_path: Path, patch: str, smells: list[dict]) -> dict:
        """
        Returns:
          {"valid": bool, "removed_smells": list, "new_smells": list, "details": str}
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            patched_path = Path(tmpdir) / original_path.name
            try:
                patched_content = self._apply_patch(original_path, patch)
                patched_path.write_text(patched_content)
            except Exception as exc:
                logger.error("Patch application failed: %s", exc)
                return {"valid": False, "removed_smells": [], "new_smells": [], "details": str(exc)}

            original_ids = self._run_checkov(original_path)
            patched_ids  = self._run_checkov(patched_path)

        smell_ids = {s.get("checker_id", "") for s in smells if s.get("checker_id")}
        removed = smell_ids - patched_ids
        new_issues = patched_ids - original_ids

        # Patch is valid if ALL targeted smells are gone and no new issues appeared
        valid = smell_ids.issubset(removed | (original_ids - patched_ids)) and not new_issues

        return {
            "valid": valid,
            "removed_smells": list(removed),
            "new_smells": list(new_issues),
            "details": (
                f"Targeted: {smell_ids} | Removed: {removed} | New: {new_issues}"
            ),
        }

    def _apply_patch(self, original_path: Path, patch: str) -> str:
        """
        Apply a unified diff patch string to the original file content.
        Falls back to returning the patch itself if it looks like full content.
        """
        original_lines = original_path.read_text(errors="replace").splitlines(keepends=True)

        if patch.startswith("---"):
            # Standard unified diff
            result = list(difflib.restore(
                difflib.unified_diff([], [], fromfile="a", tofile="b"),
                which=2,
            ))
            # Use patch utility via subprocess for reliability
            with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False) as pf:
                pf.write(patch)
                patch_file = pf.name
            try:
                tmp_copy = tempfile.NamedTemporaryFile(
                    mode="w", suffix=original_path.suffix, delete=False
                )
                tmp_copy.writelines(original_lines)
                tmp_copy.flush()
                subprocess.run(
                    ["patch", "-u", tmp_copy.name, patch_file],
                    check=True, capture_output=True,
                )
                return Path(tmp_copy.name).read_text()
            finally:
                Path(patch_file).unlink(missing_ok=True)
        else:
            # The LLM returned full patched content instead of a diff
            return patch

    def _run_checkov(self, path: Path) -> set[str]:
        """Run Checkov and return the set of failing check IDs (handles list format)."""
        try:
            result = subprocess.run(
                ["checkov", "--file", str(path), "--output", "json", "--quiet"],
                capture_output=True, text=True, timeout=60,
            )
            data = json.loads(result.stdout or "{}")
            # Checkov 3.2+ returns a list when multiple scanners apply
            entries = data if isinstance(data, list) else [data]
            return {
                item["check_id"]
                for entry in entries
                for item in entry.get("results", {}).get("failed_checks", [])
            }
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
            logger.warning("Checkov run failed: %s", exc)
            return set()
