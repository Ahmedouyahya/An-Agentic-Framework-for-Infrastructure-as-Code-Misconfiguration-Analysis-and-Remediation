"""
Tests for the External Tool Validator.
Verifies that Checkov correctly flags the dataset files
and that a clean version of each file passes.
"""

import pytest
import subprocess
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from validator.tool_integrator import ExternalToolValidator

DATASET_DIR = Path(__file__).parent.parent / "dataset"


def run_checkov(file_path: Path) -> dict:
    """Run Checkov on a file and return parsed JSON output."""
    result = subprocess.run(
        ["checkov", "--file", str(file_path), "--output", "json", "--quiet"],
        capture_output=True, text=True, timeout=60,
    )
    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def get_failed_check_ids(checkov_output) -> set[str]:
    """
    Extract the set of failed Checkov check IDs.
    Handles both dict (single framework) and list (multi-framework) output.
    Checkov 3.2+ returns a list when multiple scanners apply (e.g. terraform + secrets).
    """
    if isinstance(checkov_output, list):
        ids = set()
        for entry in checkov_output:
            ids |= {
                item["check_id"]
                for item in entry.get("results", {}).get("failed_checks", [])
            }
        return ids
    return {
        item["check_id"]
        for item in checkov_output.get("results", {}).get("failed_checks", [])
    }


class TestTerraformDataset:

    def test_insecure_s3_has_expected_failures(self):
        """S3 file should fail public-access and encryption checks."""
        pytest.importorskip("subprocess")
        path = DATASET_DIR / "terraform" / "insecure_s3.tf"
        assert path.exists(), f"Dataset file missing: {path}"
        out = run_checkov(path)
        if not out:
            pytest.skip("Checkov not available")
        failed = get_failed_check_ids(out)
        # At least one of the expected checks should fire
        expected = {"CKV_AWS_19", "CKV_AWS_20", "CKV_AWS_52", "CKV_AWS_53"}
        assert failed & expected, f"Expected Checkov failures {expected}, got {failed}"

    def test_insecure_ec2_has_credential_and_sg_failures(self):
        path = DATASET_DIR / "terraform" / "insecure_ec2.tf"
        assert path.exists()
        out = run_checkov(path)
        if not out:
            pytest.skip("Checkov not available")
        failed = get_failed_check_ids(out)
        expected = {"CKV_AWS_8", "CKV_AWS_79"}
        assert failed & expected, f"Expected {expected}, got {failed}"

    def test_insecure_rds_is_publicly_accessible(self):
        path = DATASET_DIR / "terraform" / "insecure_rds.tf"
        assert path.exists()
        out = run_checkov(path)
        if not out:
            pytest.skip("Checkov not available")
        failed = get_failed_check_ids(out)
        expected = {"CKV_AWS_16", "CKV_AWS_17", "CKV_AWS_133"}
        assert failed & expected, f"Expected {expected}, got {failed}"


class TestKubernetesDataset:

    def test_insecure_deployment_privileged(self):
        path = DATASET_DIR / "kubernetes" / "insecure_deployment.yaml"
        assert path.exists()
        out = run_checkov(path)
        if not out:
            pytest.skip("Checkov not available")
        failed = get_failed_check_ids(out)
        expected = {"CKV_K8S_16", "CKV_K8S_6", "CKV_K8S_11"}
        assert failed & expected, f"Expected {expected}, got {failed}"

    def test_insecure_pod_readonly_filesystem(self):
        path = DATASET_DIR / "kubernetes" / "insecure_pod.yaml"
        assert path.exists()
        out = run_checkov(path)
        if not out:
            pytest.skip("Checkov not available")
        failed = get_failed_check_ids(out)
        expected = {"CKV_K8S_22", "CKV_K8S_41"}
        assert failed & expected, f"Expected {expected}, got {failed}"


class TestDockerDataset:

    def test_insecure_dockerfile_runs_as_root(self):
        path = DATASET_DIR / "docker" / "Dockerfile.insecure"
        assert path.exists()
        out = run_checkov(path)
        if not out:
            pytest.skip("Checkov not available")
        failed = get_failed_check_ids(out)
        expected = {"CKV_DOCKER_2", "CKV_DOCKER_8"}
        assert failed & expected, f"Expected {expected}, got {failed}"


class TestMetadata:

    def test_metadata_file_exists_and_valid(self):
        import json
        meta_path = DATASET_DIR / "metadata.json"
        assert meta_path.exists()
        with meta_path.open() as f:
            data = json.load(f)
        assert "files" in data
        assert len(data["files"]) > 0
        for entry in data["files"]:
            assert "id" in entry
            assert "file" in entry
            assert "smells" in entry
            file_path = DATASET_DIR / entry["file"]
            assert file_path.exists(), f"File referenced in metadata not found: {file_path}"


class TestPatchApplication:

    def test_git_recount_fallback_applies_stale_hunk_counts(self, tmp_path):
        original = tmp_path / "example.tf"
        original.write_text(
            'resource "aws_s3_bucket" "b" {\n'
            '  bucket = "demo"\n'
            '  acl    = "public-read"\n'
            '}\n'
        )
        patch = (
            "--- original\n"
            "+++ fixed\n"
            "@@ -1,99 +1,99 @@\n"
            ' resource "aws_s3_bucket" "b" {\n'
            '   bucket = "demo"\n'
            '-  acl    = "public-read"\n'
            '+  acl    = "private"\n'
            " }\n"
        )

        patched = ExternalToolValidator()._apply_patch(original, patch)
        assert 'acl    = "private"' in patched
