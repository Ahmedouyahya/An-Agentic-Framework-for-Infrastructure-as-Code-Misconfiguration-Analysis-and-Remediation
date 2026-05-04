"""
Tests for the Patch Formatter module.
Verifies: unified diff generation, CWE explanation output, explanation structure.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from formatter.patch_formatter import PatchFormatter
from generator.fix_generator import FixGenerator

DATASET_DIR = Path(__file__).parent.parent / "dataset"


@pytest.fixture
def formatter():
    return PatchFormatter()


@pytest.fixture
def sample_smells():
    return [
        {
            "type": "hardcoded_password",
            "cwe": "CWE-259",
            "line": 5,
            "description": "Plaintext password in vars block",
            "checker_id": "HEURISTIC",
        },
        {
            "type": "overly_permissive_cidr",
            "cwe": "CWE-732",
            "line": 20,
            "description": "Security group allows 0.0.0.0/0",
            "checker_id": "CKV_AWS_25",
        },
    ]


class TestExplanationGeneration:

    def test_explanation_contains_cwe_reference(self, formatter, sample_smells):
        result = formatter.format(
            original_path=DATASET_DIR / "terraform" / "insecure_s3.tf",
            patch="",
            smells=sample_smells,
        )
        assert "CWE-259" in result["explanation"]
        assert "CWE-732" in result["explanation"]

    def test_explanation_contains_smell_types(self, formatter, sample_smells):
        result = formatter.format(
            original_path=DATASET_DIR / "terraform" / "insecure_s3.tf",
            patch="",
            smells=sample_smells,
        )
        explanation = result["explanation"]
        assert "Hardcoded Password" in explanation or "hardcoded" in explanation.lower()

    def test_explanation_contains_line_numbers(self, formatter, sample_smells):
        result = formatter.format(
            original_path=DATASET_DIR / "terraform" / "insecure_s3.tf",
            patch="",
            smells=sample_smells,
        )
        assert "5" in result["explanation"]
        assert "20" in result["explanation"]

    def test_diff_summary_section_present(self, formatter, sample_smells):
        result = formatter.format(
            original_path=DATASET_DIR / "terraform" / "insecure_s3.tf",
            patch="",
            smells=sample_smells,
        )
        assert "Diff Summary" in result["explanation"]
        assert "Lines added" in result["explanation"]
        assert "Lines removed" in result["explanation"]

    def test_empty_smells_list(self, formatter):
        result = formatter.format(
            original_path=DATASET_DIR / "terraform" / "insecure_s3.tf",
            patch="",
            smells=[],
        )
        assert "explanation" in result
        assert "diff" in result

    def test_format_returns_both_keys(self, formatter, sample_smells):
        result = formatter.format(
            original_path=DATASET_DIR / "terraform" / "insecure_s3.tf",
            patch="--- a/test\n+++ b/test\n@@ -1 +1 @@\n-old\n+new\n",
            smells=sample_smells,
        )
        assert "diff" in result
        assert "explanation" in result

    def test_valid_unified_diff_preserved(self, formatter, sample_smells):
        patch = "--- a/file.tf\n+++ b/file.tf\n@@ -1,2 +1,2 @@\n-old_line\n+new_line\n"
        result = formatter.format(
            original_path=DATASET_DIR / "terraform" / "insecure_s3.tf",
            patch=patch,
            smells=sample_smells,
        )
        assert result["diff"].startswith("---")


class TestDiffGeneration:

    def test_full_content_patch_generates_diff(self, formatter, tmp_path):
        original = tmp_path / "original.tf"
        original.write_text("resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n")
        patched_content = "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"private\"\n}\n"
        result = formatter.format(
            original_path=original,
            patch=patched_content,
            smells=[{"type": "overly_permissive_acl", "cwe": "CWE-732", "line": 2,
                     "description": "public-read ACL", "checker_id": "CKV_AWS_20"}],
        )
        # Should generate a diff from the content
        assert "diff" in result


class TestGeneratorResponseParsing:

    def test_parse_response_strips_markdown_fences(self):
        raw = """```diff
--- original
+++ fixed
@@ -1 +1 @@
-acl = "public-read"
+acl = "private"
```"""
        patches = FixGenerator("dummy:model", self_consistency=False)._parse_response(raw)
        assert patches == [
            '--- original\n+++ fixed\n@@ -1 +1 @@\n-acl = "public-read"\n+acl = "private"'
        ]

    def test_parse_response_stops_at_trailing_fence(self):
        raw = """--- original
+++ fixed
@@ -1 +1 @@
-old
+new
```"""
        patch = FixGenerator("dummy:model", self_consistency=False)._parse_response(raw)[0]
        assert "```" not in patch
