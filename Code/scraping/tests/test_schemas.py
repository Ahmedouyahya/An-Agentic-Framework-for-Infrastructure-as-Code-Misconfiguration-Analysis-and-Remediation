"""
Tests for scraping/schemas.py
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scraping.schemas import IaCRecord, SmellAnnotation, ScrapeManifest


# ---------------------------------------------------------------------------
# SmellAnnotation
# ---------------------------------------------------------------------------

class TestSmellAnnotation:
    def test_basic_construction(self):
        smell = SmellAnnotation(
            type="hardcoded_credential",
            cwe="CWE-798",
            checkov_id="CKV_AWS_41",
            severity="CRITICAL",
            category="Security",
            description="AWS access key hardcoded",
        )
        assert smell.type == "hardcoded_credential"
        assert smell.cwe == "CWE-798"
        assert smell.severity == "CRITICAL"

    def test_optional_fields_default_none(self):
        smell = SmellAnnotation(type="root_user")
        assert smell.cwe is None
        assert smell.checkov_id is None
        assert smell.severity is None
        assert smell.line_number is None

    def test_to_dict(self):
        smell = SmellAnnotation(type="overly_permissive_cidr", cwe="CWE-732")
        d = smell.to_dict()
        assert isinstance(d, dict)
        assert d["type"] == "overly_permissive_cidr"
        assert d["cwe"] == "CWE-732"
        assert "checkov_id" in d


# ---------------------------------------------------------------------------
# IaCRecord
# ---------------------------------------------------------------------------

class TestIaCRecord:
    def _make_record(self, **kwargs) -> IaCRecord:
        defaults = dict(
            id="TEST-001",
            source="github_commit",
            iac_tool="terraform",
            file_path="main.tf",
            code_before='resource "aws_s3_bucket" "b" { acl = "public-read" }',
            code_after='resource "aws_s3_bucket" "b" { acl = "private" }',
            diff='--- a/main.tf\n+++ b/main.tf\n- acl = "public-read"\n+ acl = "private"',
            has_fix=True,
        )
        defaults.update(kwargs)
        return IaCRecord(**defaults)

    def test_basic_construction(self):
        r = self._make_record()
        assert r.id == "TEST-001"
        assert r.iac_tool == "terraform"
        assert r.has_fix is True

    def test_compute_hash_deterministic(self):
        r1 = self._make_record()
        r2 = self._make_record()
        assert r1.compute_hash() == r2.compute_hash()

    def test_compute_hash_differs_on_different_content(self):
        r1 = self._make_record(code_before="content A")
        r2 = self._make_record(code_before="content B")
        assert r1.compute_hash() != r2.compute_hash()

    def test_compute_hash_length(self):
        r = self._make_record()
        h = r.compute_hash()
        assert len(h) == 64  # SHA-256 hex

    def test_finalize_sets_hash(self):
        r = self._make_record()
        assert r.content_hash is None
        r.finalize()
        assert r.content_hash is not None
        assert len(r.content_hash) == 64

    def test_finalize_builds_labels(self):
        r = self._make_record()
        r.smells = [
            SmellAnnotation(type="overly_permissive_acl", severity="HIGH", cwe="CWE-732"),
        ]
        r.finalize()
        assert "overly_permissive_acl" in r.labels
        assert "HIGH" in r.labels
        assert "CWE-732" in r.labels
        assert "terraform" in r.labels

    def test_finalize_returns_self(self):
        r = self._make_record()
        result = r.finalize()
        assert result is r

    def test_to_dict(self):
        r = self._make_record()
        r.smells = [SmellAnnotation(type="root_user")]
        d = r.to_dict()
        assert isinstance(d, dict)
        assert d["id"] == "TEST-001"
        assert isinstance(d["smells"], list)
        assert d["smells"][0]["type"] == "root_user"

    def test_to_json(self):
        r = self._make_record()
        j = r.to_json()
        assert isinstance(j, str)
        parsed = json.loads(j)
        assert parsed["id"] == "TEST-001"

    def test_from_dict_roundtrip(self):
        r = self._make_record()
        r.smells = [SmellAnnotation(type="hardcoded_password", severity="HIGH")]
        d = r.to_dict()
        r2 = IaCRecord.from_dict(d)
        assert r2.id == r.id
        assert r2.smells[0].type == "hardcoded_password"

    def test_from_json_roundtrip(self):
        r = self._make_record()
        r.finalize()
        j = r.to_json()
        r2 = IaCRecord.from_json(j)
        assert r2.id == r.id
        assert r2.content_hash == r.content_hash

    def test_defaults(self):
        r = self._make_record()
        assert r.split == "train"
        assert r.smells == []
        assert r.labels == []
        assert r.repo is None
        assert r.content_hash is None

    def test_no_fix_record(self):
        r = self._make_record(code_after=None, diff=None, has_fix=False)
        assert r.has_fix is False
        assert r.code_after is None

    def test_scraped_at_set(self):
        r = self._make_record()
        assert r.scraped_at is not None
        assert "T" in r.scraped_at  # ISO-8601

    def test_unicode_content(self):
        r = self._make_record(code_before="# حماية\nacl = \"private\"")
        j = r.to_json()
        r2 = IaCRecord.from_json(j)
        assert "حماية" in r2.code_before


# ---------------------------------------------------------------------------
# ScrapeManifest
# ---------------------------------------------------------------------------

class TestScrapeManifest:
    def test_construction(self):
        m = ScrapeManifest(run_id="abc", started_at="2026-04-06T10:00:00Z")
        assert m.run_id == "abc"
        assert m.total_records == 0

    def test_to_dict(self):
        m = ScrapeManifest(run_id="xyz", started_at="2026-04-06T10:00:00Z")
        m.total_records = 100
        d = m.to_dict()
        assert d["total_records"] == 100
        assert isinstance(d["queries_run"], list)

    def test_save_and_load(self, tmp_path):
        m = ScrapeManifest(run_id="test", started_at="2026-04-06T00:00:00Z")
        m.total_records = 42
        path = tmp_path / "manifest.json"
        m.save(path)
        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded["total_records"] == 42
        assert loaded["run_id"] == "test"
