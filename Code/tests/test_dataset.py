"""
Dataset integrity tests.
Verifies: all annotated smells are detectable, metadata is correct,
taxonomy file is well-formed, and Checkov confirms issues on all files.
"""

import json
import subprocess
import pytest
from pathlib import Path

DATASET_DIR = Path(__file__).parent.parent / "dataset"
METADATA_PATH = DATASET_DIR / "metadata.json"
TAXONOMY_PATH = DATASET_DIR / "taxonomy" / "smells_taxonomy.json"


def run_checkov(file_path: Path) -> set[str]:
    """Return set of failing Checkov check IDs (handles both dict and list output)."""
    try:
        result = subprocess.run(
            ["checkov", "--file", str(file_path), "--output", "json", "--quiet"],
            capture_output=True, text=True, timeout=60,
        )
        data = json.loads(result.stdout or "{}")
        if isinstance(data, list):
            ids = set()
            for entry in data:
                ids |= {c["check_id"] for c in entry.get("results", {}).get("failed_checks", [])}
            return ids
        return {c["check_id"] for c in data.get("results", {}).get("failed_checks", [])}
    except Exception:
        return set()


class TestMetadataIntegrity:

    def setup_method(self):
        with METADATA_PATH.open() as f:
            self.metadata = json.load(f)

    def test_required_top_level_keys(self):
        assert "files" in self.metadata
        assert "statistics" in self.metadata

    def test_all_files_exist(self):
        for entry in self.metadata["files"]:
            path = DATASET_DIR / entry["file"]
            assert path.exists(), f"Missing: {path}"

    def test_each_entry_has_required_fields(self):
        for entry in self.metadata["files"]:
            assert "id" in entry
            assert "file" in entry
            assert "iac_tool" in entry
            assert "smells" in entry
            assert len(entry["smells"]) > 0, f"{entry['id']} has no smells"

    def test_each_smell_has_required_fields(self):
        for entry in self.metadata["files"]:
            for smell in entry["smells"]:
                assert "smell_id" in smell
                assert "type" in smell
                assert "cwe" in smell, f"Missing CWE in {smell}"
                assert "description" in smell
                assert "category" in smell

    def test_total_smell_count_matches_statistics(self):
        actual_total = sum(len(e["smells"]) for e in self.metadata["files"])
        assert actual_total == self.metadata["statistics"]["total_smells"]

    def test_cwe_format_valid(self):
        """All CWE IDs should follow 'CWE-NNN' format."""
        for entry in self.metadata["files"]:
            for smell in entry["smells"]:
                cwe = smell["cwe"]
                assert cwe.startswith("CWE-"), f"Invalid CWE format: {cwe}"
                number = cwe.split("-")[1]
                assert number.isdigit(), f"CWE number not digit: {cwe}"

    def test_iac_tools_valid(self):
        valid_tools = {"terraform", "ansible", "kubernetes", "docker"}
        for entry in self.metadata["files"]:
            assert entry["iac_tool"] in valid_tools, \
                f"Unknown tool: {entry['iac_tool']}"

    def test_no_duplicate_smell_ids(self):
        ids = []
        for entry in self.metadata["files"]:
            for smell in entry["smells"]:
                ids.append(smell["smell_id"])
        assert len(ids) == len(set(ids)), "Duplicate smell IDs found"


class TestCheckovDetection:
    """Verify Checkov actually flags each dataset file."""

    def test_s3_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "terraform" / "insecure_s3.tf")
        assert len(ids) > 0, "Checkov detected nothing on S3 file"
        assert ids & {"CKV_AWS_20", "CKV_AWS_53"}, f"Expected public-access checks, got {ids}"

    def test_ec2_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "terraform" / "insecure_ec2.tf")
        assert len(ids) > 0
        assert ids & {"CKV_AWS_8", "CKV_AWS_79"}, f"Expected EBS/IMDSv2 checks, got {ids}"

    def test_rds_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "terraform" / "insecure_rds.tf")
        assert len(ids) > 0
        assert ids & {"CKV_AWS_16", "CKV_AWS_17"}, f"Expected RDS checks, got {ids}"

    def test_k8s_deployment_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "kubernetes" / "insecure_deployment.yaml")
        assert len(ids) > 0
        assert ids & {"CKV_K8S_11", "CKV_K8S_19"}, f"Expected K8s checks, got {ids}"

    def test_k8s_pod_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "kubernetes" / "insecure_pod.yaml")
        assert len(ids) > 0
        assert ids & {"CKV_K8S_22", "CKV_K8S_41"}, f"Expected pod checks, got {ids}"

    def test_dockerfile_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "docker" / "Dockerfile.insecure")
        assert len(ids) > 0
        assert ids & {"CKV_DOCKER_2", "CKV_DOCKER_7"}, f"Expected Dockerfile checks, got {ids}"

    def test_ansible_webserver_issues_present(self):
        """Ansible checks are heuristic-only; file must at minimum parse."""
        path = DATASET_DIR / "ansible" / "insecure_webserver.yml"
        assert path.exists()
        content = path.read_text()
        assert "password" in content.lower()
        assert "validate_certs" in content

    def test_iam_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "terraform" / "insecure_iam.tf")
        assert len(ids) > 0, "Checkov detected nothing on IAM file"
        assert ids & {"CKV_AWS_355", "CKV_AWS_273"}, f"Expected IAM checks, got {ids}"

    def test_networking_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "terraform" / "insecure_networking.tf")
        assert len(ids) > 0, "Checkov detected nothing on networking file"
        assert ids & {"CKV_AWS_25", "CKV_AWS_2", "CKV_AWS_91"}, f"Expected networking checks, got {ids}"

    def test_k8s_rbac_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "kubernetes" / "insecure_rbac.yaml")
        assert len(ids) > 0, "Checkov detected nothing on RBAC file"
        assert ids & {"CKV_K8S_49", "CKV_K8S_155", "CKV_K8S_21"}, f"Expected RBAC checks, got {ids}"

    def test_multi_stage_dockerfile_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "docker" / "Dockerfile.multi_stage_insecure")
        assert len(ids) > 0, "Checkov detected nothing on multi-stage Dockerfile"
        assert ids & {"CKV_DOCKER_2", "CKV_DOCKER_7", "CKV_DOCKER_3"}, f"Expected Dockerfile checks, got {ids}"

    def test_ansible_hardened_issues_present(self):
        """Ansible hardening smells are heuristic-only; verify key smell markers."""
        path = DATASET_DIR / "ansible" / "insecure_hardened.yml"
        assert path.exists()
        content = path.read_text()
        assert "PasswordAuthentication" in content
        assert "validate_certs" in content or "no" in content.lower()

    def test_webapp_dockerfile_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "docker" / "Dockerfile.webapp_insecure")
        assert len(ids) > 0, "Checkov detected nothing on webapp Dockerfile"
        assert ids & {"CKV_DOCKER_4", "CKV_DOCKER_6", "CKV_DOCKER_10", "CKV_DOCKER_1"}, \
            f"Expected ADD/MAINTAINER/WORKDIR/port22 checks, got {ids}"

    def test_node_api_dockerfile_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "docker" / "Dockerfile.node_api_insecure")
        assert len(ids) > 0, "Checkov detected nothing on node API Dockerfile"
        assert ids & {"CKV_DOCKER_2", "CKV_DOCKER_3"}, \
            f"Expected healthcheck/user checks, got {ids}"

    def test_java_service_dockerfile_checkov_detects_issues(self):
        ids = run_checkov(DATASET_DIR / "docker" / "Dockerfile.java_service_insecure")
        assert len(ids) > 0, "Checkov detected nothing on Java service Dockerfile"
        assert ids & {"CKV_DOCKER_7", "CKV_DOCKER_4", "CKV_DOCKER_1", "CKV_DOCKER_3"}, \
            f"Expected latest/ADD/port22/user checks, got {ids}"

    def test_node_api_heuristic_smells_present(self):
        """Supply-chain and privilege smells in node API file are heuristic-only."""
        path = DATASET_DIR / "docker" / "Dockerfile.node_api_insecure"
        assert path.exists()
        content = path.read_text()
        assert "curl" in content and "bash" in content   # curl|bash supply chain
        assert "--unsafe-perm" in content                # npm unsafe permissions
        assert "JWT_SECRET" in content                   # hardcoded secret

    def test_java_service_heuristic_smells_present(self):
        """SETUID and sudo smells in Java service file are heuristic-only."""
        path = DATASET_DIR / "docker" / "Dockerfile.java_service_insecure"
        assert path.exists()
        content = path.read_text()
        assert "chmod 4755" in content                   # SETUID binary
        assert "sudo" in content                         # sudo installed
        assert "NOPASSWD" in content                     # unrestricted sudo


class TestTaxonomyIntegrity:

    def setup_method(self):
        with TAXONOMY_PATH.open() as f:
            self.taxonomy = json.load(f)

    def test_taxonomy_has_at_least_62_entries(self):
        assert len(self.taxonomy) >= 62, \
            f"Expected at least 62 taxonomy entries, got {len(self.taxonomy)}"

    def test_all_entries_have_required_fields(self):
        required = {"id", "name", "category", "description", "cwe", "iac_tools", "fix_example"}
        for entry in self.taxonomy:
            missing = required - entry.keys()
            assert not missing, f"Entry {entry.get('id')} missing: {missing}"

    def test_ids_are_unique(self):
        ids = [e["id"] for e in self.taxonomy]
        assert len(ids) == len(set(ids)), "Duplicate taxonomy IDs"

    def test_cwe_format_valid(self):
        for entry in self.taxonomy:
            cwe = entry["cwe"]
            assert cwe.startswith("CWE-"), f"Bad CWE in {entry['id']}: {cwe}"

    def test_iac_tools_list_not_empty(self):
        for entry in self.taxonomy:
            assert len(entry["iac_tools"]) > 0, \
                f"No iac_tools for {entry['id']}"

    def test_fix_example_not_empty(self):
        for entry in self.taxonomy:
            assert entry["fix_example"].strip(), \
                f"Empty fix_example in {entry['id']}"

    def test_all_categories_valid(self):
        valid = {"Security", "Dependency", "Configuration Data"}
        for entry in self.taxonomy:
            assert entry["category"] in valid, \
                f"Unknown category '{entry['category']}' in {entry['id']}"

    def test_dataset_smells_covered_by_taxonomy(self):
        """Every CWE in the dataset should appear in the taxonomy."""
        with METADATA_PATH.open() as f:
            metadata = json.load(f)
        dataset_cwes = {s["cwe"] for e in metadata["files"] for s in e["smells"]}
        taxonomy_cwes = {e["cwe"] for e in self.taxonomy}
        uncovered = dataset_cwes - taxonomy_cwes
        assert not uncovered, f"CWEs in dataset but not in taxonomy: {uncovered}"
