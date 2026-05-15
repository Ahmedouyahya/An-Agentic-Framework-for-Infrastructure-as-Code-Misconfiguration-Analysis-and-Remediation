"""
Tests for v2 dataset builder.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scraping.scripts.build_v2 import build_v2, normalize_record


def _record(**overrides):
    rec = {
        "id": "R-1",
        "source": "github_commit",
        "iac_tool": "terraform",
        "file_path": "main.tf",
        "code_before": 'resource "aws_s3_bucket" "b" { acl = "public-read" }',
        "code_after": 'resource "aws_s3_bucket" "b" { acl = "private" }',
        "diff": '- acl = "public-read"\n+ acl = "private"',
        "has_fix": True,
        "smells": [{"type": "overly_permissive_acl", "severity": "HIGH"}],
        "repo": "o/r",
        "commit_sha": "abc",
        "content_hash": "old",
    }
    rec.update(overrides)
    return rec


def _write(path: Path, records):
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def test_normalize_new_file_becomes_detection_record():
    rec = normalize_record(_record(
        code_before="# [before content unavailable]\n@@ -0,0 +1 @@",
        code_after="password = \"supersecret\"",
        diff="@@ -0,0 +1 @@\n+password = \"supersecret\"",
        code_before_quality="new_file",
        has_fix=True,
    ))

    assert rec["has_fix"] is False
    assert rec["code_before"] == "password = \"supersecret\""
    assert rec["code_after"] is None
    assert rec["code_before_quality"] == "new_file"
    assert rec["tier"] in {"C", "D"}


def test_build_prefers_validated_duplicate(tmp_path):
    weak = _record(id="weak", smells=[], code_before_quality="api")
    strong = _record(
        id="strong",
        code_before_quality="api",
        validated_smells_before=[{"scanner": "checkov", "rule_id": "CKV_AWS_1"}],
        validated_smells_after=[],
    )
    f1 = tmp_path / "weak.jsonl"
    f2 = tmp_path / "strong.jsonl"
    _write(f1, [weak])
    _write(f2, [strong])

    manifest = build_v2([f1, f2], tmp_path / "out")
    full = tmp_path / "out" / "dataset_v2_full.jsonl"
    records = [json.loads(line) for line in full.read_text().splitlines()]

    assert manifest["total_loaded"] == 2
    assert manifest["total_records"] == 1
    assert records[0]["id"] == "strong"
    assert records[0]["tier"] == "A"


def test_build_writes_tiered_outputs_and_manifest(tmp_path):
    a = _record(
        id="A",
        repo="o/a",
        commit_sha="a",
        code_before_quality="api",
        validated_smells_before=[{"scanner": "checkov", "rule_id": "CKV_AWS_1"}],
        validated_smells_after=[],
    )
    c = _record(
        id="C",
        repo="o/c",
        commit_sha="c",
        code_before="password = \"supersecret\"",
        code_after=None,
        has_fix=False,
        code_before_quality="api",
        smells=[{"type": "hardcoded_password", "severity": "HIGH"}],
    )
    f = tmp_path / "input.jsonl"
    _write(f, [a, c])

    manifest = build_v2([f], tmp_path / "out")

    assert (tmp_path / "out" / "dataset_v2_full.jsonl").exists()
    assert (tmp_path / "out" / "dataset_v2_gold.jsonl").exists()
    assert (tmp_path / "out" / "dataset_v2_fix_pairs.jsonl").exists()
    assert (tmp_path / "out" / "dataset_v2_detection.jsonl").exists()
    assert (tmp_path / "out" / "manifest_v2.json").exists()
    assert manifest["by_tier"]["A"] == 1
    assert manifest["by_tier"]["C"] == 1
