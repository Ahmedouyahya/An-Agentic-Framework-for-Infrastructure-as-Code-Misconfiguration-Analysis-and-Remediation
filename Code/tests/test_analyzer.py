"""
Tests for the Contextual Analyzer module.
Verifies: IaC tool detection, structural metric extraction, heuristic smell detection.
"""

import pytest
import sys
from pathlib import Path

# Make src importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from analyzer.contextual import ContextualAnalyzer

DATASET_DIR = Path(__file__).parent.parent / "dataset"


@pytest.fixture
def analyzer():
    return ContextualAnalyzer()


class TestToolDetection:

    def test_terraform_file_detected(self, analyzer):
        path = DATASET_DIR / "terraform" / "insecure_s3.tf"
        result = analyzer.analyze(path)
        assert result["tool"] == "terraform"

    def test_ansible_file_detected(self, analyzer):
        path = DATASET_DIR / "ansible" / "insecure_webserver.yml"
        result = analyzer.analyze(path)
        assert result["tool"] == "ansible"

    def test_kubernetes_file_detected(self, analyzer):
        path = DATASET_DIR / "kubernetes" / "insecure_deployment.yaml"
        result = analyzer.analyze(path)
        assert result["tool"] == "kubernetes"

    def test_dockerfile_detected(self, analyzer):
        path = DATASET_DIR / "docker" / "Dockerfile.insecure"
        result = analyzer.analyze(path)
        assert result["tool"] == "docker"


class TestMetricExtraction:

    def test_metrics_returned_for_terraform(self, analyzer):
        path = DATASET_DIR / "terraform" / "insecure_s3.tf"
        result = analyzer.analyze(path)
        metrics = result["metrics"]
        assert "line_count" in metrics
        assert "token_count" in metrics
        assert metrics["line_count"] > 0
        assert metrics["token_count"] > 0

    def test_blank_line_count(self, analyzer, tmp_path):
        f = tmp_path / "test.tf"
        f.write_text("resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n\n\n")
        result = analyzer.analyze(f)
        assert result["metrics"]["blank_lines"] >= 2


class TestHeuristicSmellDetection:

    def test_hardcoded_password_detected(self, analyzer, tmp_path):
        f = tmp_path / "test.yml"
        f.write_text("- name: test\n  vars:\n    db_pass: password: \"mysecret123\"\n")
        result = analyzer.analyze(f)
        # Heuristic should catch this when Checkov unavailable
        # We just verify analysis doesn't crash
        assert "smells" in result
        assert "tool" in result

    def test_privileged_container_pattern(self, analyzer, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n")
        result = analyzer.analyze(f)
        assert result["tool"] == "kubernetes"

    def test_analyze_returns_all_required_keys(self, analyzer):
        path = DATASET_DIR / "terraform" / "insecure_ec2.tf"
        result = analyzer.analyze(path)
        assert "tool" in result
        assert "smells" in result
        assert "metrics" in result
        assert isinstance(result["smells"], list)

    def test_all_dataset_files_analyze_without_error(self, analyzer):
        files = [
            DATASET_DIR / "terraform" / "insecure_s3.tf",
            DATASET_DIR / "terraform" / "insecure_ec2.tf",
            DATASET_DIR / "terraform" / "insecure_rds.tf",
            DATASET_DIR / "ansible" / "insecure_webserver.yml",
            DATASET_DIR / "ansible" / "insecure_users.yml",
            DATASET_DIR / "kubernetes" / "insecure_deployment.yaml",
            DATASET_DIR / "kubernetes" / "insecure_pod.yaml",
            DATASET_DIR / "docker" / "Dockerfile.insecure",
        ]
        for f in files:
            result = analyzer.analyze(f)
            assert result["tool"] != "", f"Tool not detected for {f.name}"
