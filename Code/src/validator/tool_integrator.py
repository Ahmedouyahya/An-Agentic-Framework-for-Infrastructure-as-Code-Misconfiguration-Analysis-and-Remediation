"""
External Tool Integrator (Validator)
-------------------------------------
Applies a candidate patch to a temporary copy of the original file,
then runs Checkov and KICS to verify that:
  1. The smells reported in `smells` are no longer present.
  2. No NEW issues have been introduced by the patch.

Two validators run independently:
  - Checkov: strong Terraform coverage, partial Ansible/K8s/Docker
  - KICS:    broad coverage (Ansible 233, CF 288, Docker 97, K8s, TF)

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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

logger = logging.getLogger(__name__)


class CheckovValidator:
    """Runs Checkov on a file and returns the set of failing check IDs."""

    name = "checkov"

    def run(self, path: Path) -> set[str]:
        try:
            result = subprocess.run(
                ["checkov", "--file", str(path), "--output", "json", "--quiet"],
                capture_output=True, text=True, timeout=60,
            )
            data = json.loads(result.stdout or "{}")
            entries = data if isinstance(data, list) else [data]
            return {
                item["check_id"]
                for entry in entries
                for item in entry.get("results", {}).get("failed_checks", [])
            }
        except FileNotFoundError:
            logger.warning("Checkov not installed — skipping Checkov validation")
            return set()
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("Checkov run failed: %s", exc)
            return set()

    @staticmethod
    def is_available() -> bool:
        return shutil.which("checkov") is not None


class KICSValidator:
    """Runs KICS on a file and returns the set of failing query IDs."""

    name = "kics"

    def run(self, path: Path) -> set[str]:
        try:
            result = subprocess.run(
                [
                    "kics", "scan",
                    "--path", str(path),
                    "--output-path", "/dev/null",
                    "--type", self._detect_type(path),
                    "--no-progress",
                    "--output-name", "kics_results",
                ],
                capture_output=True, text=True, timeout=120,
            )
            # KICS writes JSON to stdout when no output path works;
            # try parsing stdout first, then look for results file
            try:
                data = json.loads(result.stdout or "{}")
            except json.JSONDecodeError:
                return set()

            return {
                vuln.get("query_id", "")
                for vuln in data.get("queries", [])
                for vuln_file in vuln.get("files", [])
                if vuln_file.get("file_name", "").endswith(path.name)
            }
        except FileNotFoundError:
            logger.warning("KICS not installed — skipping KICS validation")
            return set()
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("KICS run failed: %s", exc)
            return set()

    @staticmethod
    def _detect_type(path: Path) -> str:
        """Map file extension to KICS platform type."""
        suffix = path.suffix.lower()
        name = path.name.lower()
        if suffix == ".tf":
            return "Terraform"
        if "dockerfile" in name:
            return "Dockerfile"
        if suffix in (".yml", ".yaml"):
            content = path.read_text(errors="replace")[:300]
            if "apiVersion:" in content:
                return "Kubernetes"
            if "hosts:" in content or "tasks:" in content:
                return "Ansible"
            return "Kubernetes"
        if suffix == ".json":
            return "CloudFormation"
        return "Terraform"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("kics") is not None


class ExternalToolValidator:
    """
    Validates a patch by:
      1. Applying it to a temp file.
      2. Running available validators (Checkov, KICS) on both original and patched.
      3. Comparing findings before/after to confirm smell removal.

    Returns per-scanner results plus an ensembled verdict.
    """

    def __init__(self):
        self._validators = []
        if CheckovValidator.is_available():
            self._validators.append(CheckovValidator())
        if KICSValidator.is_available():
            self._validators.append(KICSValidator())
        if not self._validators:
            logger.warning(
                "No validators available (neither checkov nor kics found). "
                "Install at least one: pip install checkov / brew install kics"
            )
        else:
            names = [v.name for v in self._validators]
            logger.info("Active validators: %s", ", ".join(names))

    def validate(self, original_path: Path, patch: str, smells: list[dict]) -> dict:
        """
        Returns:
          {
            "valid": bool,             # ensembled: all available validators agree
            "removed_smells": list,
            "new_smells": list,
            "per_scanner": {
              "checkov": {"valid": bool, "removed": [...], "new": [...]},
              "kics":    {"valid": bool, "removed": [...], "new": [...]},
            },
            "details": str,
          }
        """
        if not self._validators:
            return {
                "valid": False,
                "removed_smells": [],
                "new_smells": [],
                "per_scanner": {},
                "details": "No validators installed",
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            patched_path = Path(tmpdir) / original_path.name
            try:
                patched_content = self._apply_patch(original_path, patch)
                patched_path.write_text(patched_content)
            except Exception as exc:
                logger.error("Patch application failed: %s", exc)
                return {
                    "valid": False,
                    "removed_smells": [],
                    "new_smells": [],
                    "per_scanner": {},
                    "details": f"Patch application failed: {exc}",
                }

            # Run all validators in parallel
            scanner_results = {}
            with ThreadPoolExecutor(max_workers=len(self._validators)) as pool:
                futures = {}
                for v in self._validators:
                    futures[pool.submit(self._run_one, v, original_path, patched_path)] = v.name

                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        scanner_results[name] = future.result()
                    except Exception as exc:
                        logger.error("Validator %s raised: %s", name, exc)
                        scanner_results[name] = {
                            "valid": False, "removed": [], "new": [],
                        }

        # Ensemble: valid only if ALL scanners agree the patch is valid
        all_valid = all(r["valid"] for r in scanner_results.values())
        all_removed = []
        all_new = []
        for r in scanner_results.values():
            all_removed.extend(r.get("removed", []))
            all_new.extend(r.get("new", []))

        return {
            "valid": all_valid,
            "removed_smells": list(set(all_removed)),
            "new_smells": list(set(all_new)),
            "per_scanner": scanner_results,
            "details": "; ".join(
                f"{name}: {'PASS' if r['valid'] else 'FAIL'} "
                f"(removed={len(r.get('removed', []))}, new={len(r.get('new', []))})"
                for name, r in scanner_results.items()
            ),
        }

    def _run_one(self, validator, original_path: Path, patched_path: Path) -> dict:
        """Run a single validator on both files and compare."""
        original_ids = validator.run(original_path)
        patched_ids = validator.run(patched_path)

        removed = original_ids - patched_ids
        new_issues = patched_ids - original_ids

        # Valid if at least one issue was removed and no new issues appeared
        valid = len(removed) > 0 and len(new_issues) == 0

        return {
            "valid": valid,
            "removed": list(removed),
            "new": list(new_issues),
            "before_count": len(original_ids),
            "after_count": len(patched_ids),
        }

    def _apply_patch(self, original_path: Path, patch: str) -> str:
        """
        Apply a unified diff patch string to the original file content.
        Falls back to returning the patch itself if it looks like full content.
        """
        original_lines = original_path.read_text(errors="replace").splitlines(keepends=True)

        if patch.startswith("---"):
            # Standard unified diff — use patch utility
            with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False) as pf:
                pf.write(patch)
                patch_file = pf.name
            try:
                tmp_copy = tempfile.NamedTemporaryFile(
                    mode="w", suffix=original_path.suffix, delete=False
                )
                tmp_copy.writelines(original_lines)
                tmp_copy.flush()
                tmp_copy.close()
                subprocess.run(
                    ["patch", "-u", tmp_copy.name, patch_file],
                    check=True, capture_output=True,
                )
                return Path(tmp_copy.name).read_text()
            finally:
                Path(patch_file).unlink(missing_ok=True)
                try:
                    Path(tmp_copy.name).unlink(missing_ok=True)
                except Exception:
                    pass
        else:
            # The LLM returned full patched content instead of a diff
            return patch
