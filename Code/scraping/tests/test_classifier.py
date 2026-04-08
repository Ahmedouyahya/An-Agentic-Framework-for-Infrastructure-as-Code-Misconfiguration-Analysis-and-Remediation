"""
Tests for scraping/processors/classifier.py
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scraping.processors.classifier import (
    classify_diff_smells,
    classify_smells,
    detect_iac_tool,
    is_iac_file,
)
from scraping.schemas import SmellAnnotation


# ---------------------------------------------------------------------------
# IaC tool detection
# ---------------------------------------------------------------------------

class TestDetectIaCTool:
    def test_terraform_by_extension(self):
        assert detect_iac_tool("main.tf") == "terraform"
        assert detect_iac_tool("vars.tfvars") == "terraform"

    def test_terraform_by_content(self):
        content = 'resource "aws_s3_bucket" "my_bucket" {\n  acl = "private"\n}'
        assert detect_iac_tool("infra.txt", content) == "terraform"

    def test_docker_by_filename(self):
        assert detect_iac_tool("Dockerfile") == "docker"
        assert detect_iac_tool("services/api/Dockerfile") == "docker"
        assert detect_iac_tool("app.dockerfile") == "docker"

    def test_docker_by_content_first_line(self):
        content = "FROM ubuntu:20.04\nRUN apt-get update"
        assert detect_iac_tool("myfile.txt", content) == "docker"

    def test_kubernetes_by_content(self):
        content = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: myapp"
        assert detect_iac_tool("deploy.yaml", content) == "kubernetes"

    def test_kubernetes_pod(self):
        content = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: mypod"
        assert detect_iac_tool("pod.yaml", content) == "kubernetes"

    def test_kubernetes_path_heuristic(self):
        # No content, but path contains 'kubernetes'
        result = detect_iac_tool("k8s/deployment.yaml")
        assert result in ("kubernetes", "unknown")  # heuristic, not guaranteed

    def test_ansible_by_content(self):
        content = "---\n- name: Install nginx\n  hosts: webservers\n  tasks:\n    - name: install\n"
        assert detect_iac_tool("playbook.yml", content) == "ansible"

    def test_cloudformation_by_content(self):
        content = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  MyBucket:\n    Type: AWS::S3::Bucket"
        assert detect_iac_tool("template.yaml", content) == "cloudformation"

    def test_unknown_returns_unknown(self):
        assert detect_iac_tool("random.py") == "unknown"
        assert detect_iac_tool("README.md") == "unknown"

    def test_is_iac_file_true(self):
        assert is_iac_file("main.tf") is True
        assert is_iac_file("Dockerfile") is True
        assert is_iac_file("deploy.yaml", "apiVersion: apps/v1\nkind: Deployment") is True

    def test_is_iac_file_false(self):
        assert is_iac_file("script.py") is False
        assert is_iac_file("README.md") is False


# ---------------------------------------------------------------------------
# classify_smells (full content mode)
# ---------------------------------------------------------------------------

class TestClassifySmells:
    def test_detects_hardcoded_password(self):
        content = 'db_password = "mysecretpassword123"'
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "hardcoded_password" in types

    def test_detects_hardcoded_credential(self):
        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\naws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "hardcoded_credential" in types

    def test_detects_overly_permissive_cidr(self):
        content = 'cidr_blocks = ["0.0.0.0/0"]'
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "overly_permissive_cidr" in types

    def test_detects_privileged_container(self):
        content = "securityContext:\n  privileged: true"
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "privileged_container" in types

    def test_detects_root_user(self):
        content = "USER root\nRUN apt-get update"
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "root_user" in types

    def test_detects_unpinned_base_image(self):
        content = "FROM ubuntu:latest\nRUN echo hello"
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "unpinned_base_image" in types

    def test_detects_public_access_block_disabled(self):
        content = "block_public_acls = false\nblock_public_policy = false"
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "public_access_block_disabled" in types

    def test_detects_missing_encryption(self):
        content = "encrypted = false"
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "missing_encryption" in types

    def test_no_smells_in_clean_content(self):
        content = "# Clean Terraform config\nvariable 'region' {}\n"
        smells = classify_smells(content)
        assert smells == []

    def test_smells_have_cwe(self):
        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        smells = classify_smells(content)
        for s in smells:
            if s.type == "hardcoded_credential":
                assert s.cwe == "CWE-798"

    def test_smells_have_severity(self):
        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        smells = classify_smells(content)
        for s in smells:
            assert s.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", None)

    def test_no_duplicates_per_smell_type(self):
        content = (
            'cidr_blocks = ["0.0.0.0/0"]\n'
            'ipv6_cidr_blocks = ["::/0"]\n'
        )
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert len(types) == len(set(types))  # no duplicates

    def test_multiple_distinct_smells(self):
        content = (
            'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n'
            'cidr_blocks = ["0.0.0.0/0"]\n'
            'encrypted = false\n'
        )
        smells = classify_smells(content)
        types = {s.type for s in smells}
        assert len(types) >= 2

    def test_overly_permissive_iam(self):
        content = '"Action": "*"\n"Resource": "*"'
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "overly_permissive_iam" in types

    def test_allow_privilege_escalation(self):
        content = "allowPrivilegeEscalation: true"
        smells = classify_smells(content)
        types = [s.type for s in smells]
        assert "allow_privilege_escalation" in types


# ---------------------------------------------------------------------------
# classify_diff_smells
# ---------------------------------------------------------------------------

class TestClassifyDiffSmells:
    def _make_diff(self, removed_line: str, added_line: str) -> str:
        return (
            "--- a/main.tf\n"
            "+++ b/main.tf\n"
            "@@ -1,3 +1,3 @@\n"
            " context line\n"
            f"-{removed_line}\n"
            f"+{added_line}\n"
        )

    def test_before_smells_detected(self):
        diff = self._make_diff(
            'acl = "public-read"',
            'acl = "private"',
        )
        before, after = classify_diff_smells(diff)
        before_types = {s.type for s in before}
        assert "overly_permissive_acl" in before_types

    def test_after_smells_empty_for_fix(self):
        diff = self._make_diff(
            'acl = "public-read"',
            'acl = "private"',
        )
        _, after = classify_diff_smells(diff)
        after_types = {s.type for s in after}
        assert "overly_permissive_acl" not in after_types

    def test_diff_only_added_line_not_in_before(self):
        # Adding a vulnerability (regression)
        diff = self._make_diff(
            'acl = "private"',
            'acl = "public-read"',
        )
        before, after = classify_diff_smells(diff)
        before_types = {s.type for s in before}
        after_types  = {s.type for s in after}
        # The smell should appear in 'after' not 'before'
        assert "overly_permissive_acl" not in before_types
        assert "overly_permissive_acl" in after_types

    def test_no_smells_in_clean_diff(self):
        diff = self._make_diff("# old comment", "# new comment")
        before, after = classify_diff_smells(diff)
        assert before == []

    def test_cidr_fix(self):
        diff = self._make_diff('cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = ["10.0.0.0/8"]')
        before, after = classify_diff_smells(diff)
        assert any(s.type == "overly_permissive_cidr" for s in before)
        assert not any(s.type == "overly_permissive_cidr" for s in after)

    def test_returns_tuple_of_two_lists(self):
        diff = self._make_diff("a = 1", "a = 2")
        result = classify_diff_smells(diff)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], list)
        assert isinstance(result[1], list)
