"""
Tests for scraping/processors/merger.py and scraping/storage/writer.py
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scraping.processors.merger import (
    assign_splits,
    deduplicate,
    load_jsonl,
    merge,
)
from scraping.schemas import IaCRecord, SmellAnnotation
from scraping.storage.writer import JsonlWriter, count_existing, load_existing_hashes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_record(
    id: str = "R-001",
    tool: str = "terraform",
    code_before: str = "resource aws {}",
    has_fix: bool = True,
    n_smells: int = 1,
    source: str = "github_commit",
) -> IaCRecord:
    r = IaCRecord(
        id=id,
        source=source,
        iac_tool=tool,
        file_path="main.tf",
        code_before=code_before,
        code_after="resource aws { encrypted = true }" if has_fix else None,
        diff=None,
        has_fix=has_fix,
        smells=[SmellAnnotation(type="missing_encryption", severity="HIGH") for _ in range(n_smells)],
    )
    r.finalize()
    return r


# ---------------------------------------------------------------------------
# load_jsonl
# ---------------------------------------------------------------------------

class TestLoadJsonl:
    def test_load_empty_file(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        assert load_jsonl(f) == []

    def test_load_nonexistent_file(self, tmp_path):
        assert load_jsonl(tmp_path / "nope.jsonl") == []

    def test_load_single_record(self, tmp_path):
        r = _make_record()
        f = tmp_path / "data.jsonl"
        f.write_text(r.to_json() + "\n")
        records = load_jsonl(f)
        assert len(records) == 1
        assert records[0].id == "R-001"

    def test_load_multiple_records(self, tmp_path):
        records = [_make_record(id=f"R-{i:03d}", code_before=f"content {i}") for i in range(5)]
        f = tmp_path / "data.jsonl"
        f.write_text("\n".join(r.to_json() for r in records) + "\n")
        loaded = load_jsonl(f)
        assert len(loaded) == 5

    def test_skips_blank_lines(self, tmp_path):
        r = _make_record()
        f = tmp_path / "data.jsonl"
        f.write_text("\n\n" + r.to_json() + "\n\n")
        loaded = load_jsonl(f)
        assert len(loaded) == 1

    def test_skips_invalid_json(self, tmp_path):
        r = _make_record()
        f = tmp_path / "data.jsonl"
        f.write_text("NOT JSON\n" + r.to_json() + "\n")
        loaded = load_jsonl(f)
        assert len(loaded) == 1  # one good record, one skipped


# ---------------------------------------------------------------------------
# deduplicate
# ---------------------------------------------------------------------------

class TestDeduplicate:
    def test_no_duplicates(self):
        records = [_make_record(id=f"R-{i}", code_before=f"unique content {i}") for i in range(5)]
        deduped, n_removed = deduplicate(records)
        assert len(deduped) == 5
        assert n_removed == 0

    def test_removes_exact_duplicates(self):
        r1 = _make_record(id="R-001", code_before="identical content")
        r2 = _make_record(id="R-002", code_before="identical content")
        deduped, n_removed = deduplicate([r1, r2])
        assert len(deduped) == 1
        assert n_removed == 1

    def test_prefers_record_with_fix(self):
        r_no_fix = _make_record(id="R-001", code_before="same", has_fix=False)
        r_with_fix = _make_record(id="R-002", code_before="same", has_fix=True)
        deduped, _ = deduplicate([r_no_fix, r_with_fix])
        assert len(deduped) == 1
        assert deduped[0].has_fix is True

    def test_prefers_record_with_more_smells(self):
        r_few = _make_record(id="R-001", code_before="same", n_smells=1, has_fix=True)
        r_many = _make_record(id="R-002", code_before="same", n_smells=3, has_fix=True)
        deduped, _ = deduplicate([r_few, r_many])
        assert len(deduped) == 1
        assert len(deduped[0].smells) == 3

    def test_different_content_not_deduplicated(self):
        r1 = _make_record(code_before="content A")
        r2 = _make_record(code_before="content B")
        deduped, n_removed = deduplicate([r1, r2])
        assert len(deduped) == 2
        assert n_removed == 0


# ---------------------------------------------------------------------------
# assign_splits
# ---------------------------------------------------------------------------

class TestAssignSplits:
    def _make_records(self, n: int, tool: str = "terraform") -> list:
        return [_make_record(id=f"R-{i:04d}", code_before=f"content {i} {tool}", tool=tool)
                for i in range(n)]

    def test_all_records_get_split(self):
        records = self._make_records(20)
        assign_splits(records)
        for r in records:
            assert r.split in ("train", "val", "test")

    def test_approximate_ratios(self):
        records = self._make_records(100)
        assign_splits(records)
        train = sum(1 for r in records if r.split == "train")
        val   = sum(1 for r in records if r.split == "val")
        test  = sum(1 for r in records if r.split == "test")
        assert 70 <= train <= 90
        assert 5 <= val <= 20
        assert 5 <= test <= 20

    def test_deterministic_with_seed(self):
        records1 = self._make_records(50)
        records2 = self._make_records(50)
        assign_splits(records1, seed=42)
        assign_splits(records2, seed=42)
        for r1, r2 in zip(records1, records2):
            assert r1.split == r2.split

    def test_different_seeds_may_differ(self):
        records1 = self._make_records(50)
        records2 = self._make_records(50)
        assign_splits(records1, seed=1)
        assign_splits(records2, seed=99)
        splits1 = [r.split for r in records1]
        splits2 = [r.split for r in records2]
        # Very unlikely to be identical with different seeds on 50 records
        assert splits1 != splits2

    def test_stratified_by_tool(self):
        tf_records = self._make_records(30, tool="terraform")
        k8s_records = self._make_records(30, tool="kubernetes")
        all_records = tf_records + k8s_records
        assign_splits(all_records, seed=42)
        # Each tool should have records in all splits
        for tool in ("terraform", "kubernetes"):
            tool_records = [r for r in all_records if r.iac_tool == tool]
            splits = {r.split for r in tool_records}
            assert "train" in splits

    def test_small_group_handled(self):
        records = self._make_records(1)
        assign_splits(records)
        assert records[0].split in ("train", "val", "test")


# ---------------------------------------------------------------------------
# merge (integration)
# ---------------------------------------------------------------------------

class TestMerge:
    def _write_jsonl(self, path: Path, records: list) -> None:
        with open(path, "w") as f:
            for r in records:
                f.write(r.to_json() + "\n")

    def test_merge_single_file(self, tmp_path):
        records = [_make_record(id=f"R-{i}", code_before=f"content {i}") for i in range(5)]
        inp = tmp_path / "input.jsonl"
        self._write_jsonl(inp, records)
        out = tmp_path / "merged.jsonl"
        merged, stats = merge([inp], out)
        assert len(merged) == 5
        assert stats["total"] == 5
        assert out.exists()

    def test_merge_multiple_files(self, tmp_path):
        f1 = tmp_path / "a.jsonl"
        f2 = tmp_path / "b.jsonl"
        r1 = [_make_record(id=f"A-{i}", code_before=f"alpha {i}") for i in range(3)]
        r2 = [_make_record(id=f"B-{i}", code_before=f"beta {i}") for i in range(4)]
        self._write_jsonl(f1, r1)
        self._write_jsonl(f2, r2)
        out = tmp_path / "merged.jsonl"
        merged, stats = merge([f1, f2], out)
        assert len(merged) == 7
        assert stats["total"] == 7

    def test_merge_deduplicates(self, tmp_path):
        r_shared = _make_record(id="SHARED", code_before="same content here")
        r_unique = _make_record(id="UNIQUE", code_before="different content")
        f1 = tmp_path / "a.jsonl"
        f2 = tmp_path / "b.jsonl"
        self._write_jsonl(f1, [r_shared, r_unique])
        self._write_jsonl(f2, [r_shared])  # duplicate of r_shared
        out = tmp_path / "merged.jsonl"
        merged, stats = merge([f1, f2], out)
        assert len(merged) == 2
        assert stats["duplicates_removed"] == 1

    def test_merge_assigns_splits(self, tmp_path):
        records = [_make_record(id=f"R-{i}", code_before=f"content {i}") for i in range(20)]
        inp = tmp_path / "input.jsonl"
        self._write_jsonl(inp, records)
        out = tmp_path / "merged.jsonl"
        merged, _ = merge([inp], out)
        splits = {r.split for r in merged}
        assert "train" in splits

    def test_merge_creates_output_file(self, tmp_path):
        records = [_make_record()]
        inp = tmp_path / "input.jsonl"
        self._write_jsonl(inp, records)
        out = tmp_path / "subdir" / "merged.jsonl"
        merge([inp], out)
        assert out.exists()

    def test_merge_stats_have_required_keys(self, tmp_path):
        records = [_make_record(id=f"R-{i}", code_before=f"content {i}") for i in range(5)]
        inp = tmp_path / "input.jsonl"
        self._write_jsonl(inp, records)
        out = tmp_path / "merged.jsonl"
        _, stats = merge([inp], out)
        required = {"total", "with_fix", "without_fix", "duplicates_removed",
                    "split_train", "split_val", "split_test"}
        assert required.issubset(stats.keys())


# ---------------------------------------------------------------------------
# JsonlWriter and storage helpers
# ---------------------------------------------------------------------------

class TestJsonlWriter:
    def test_write_single_record(self, tmp_path):
        path = tmp_path / "out.jsonl"
        r = _make_record()
        with JsonlWriter(path) as writer:
            writer.write(r)
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1

    def test_write_many(self, tmp_path):
        path = tmp_path / "out.jsonl"
        records = [_make_record(id=f"R-{i}", code_before=f"c {i}") for i in range(10)]
        with JsonlWriter(path) as writer:
            n = writer.write_many(records)
        assert n == 10
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 10

    def test_count_property(self, tmp_path):
        path = tmp_path / "out.jsonl"
        with JsonlWriter(path) as writer:
            for i in range(7):
                writer.write(_make_record(id=f"R-{i}", code_before=f"c {i}"))
            assert writer.count == 7

    def test_append_mode(self, tmp_path):
        path = tmp_path / "out.jsonl"
        r1 = _make_record(id="R-001", code_before="first")
        r2 = _make_record(id="R-002", code_before="second")
        with JsonlWriter(path) as w:
            w.write(r1)
        with JsonlWriter(path) as w:
            w.write(r2)
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "a" / "b" / "c" / "out.jsonl"
        with JsonlWriter(path) as w:
            w.write(_make_record())
        assert path.exists()

    def test_finalize_called_automatically(self, tmp_path):
        path = tmp_path / "out.jsonl"
        r = _make_record()
        r.content_hash = None  # reset
        with JsonlWriter(path) as w:
            w.write(r)
        loaded = load_jsonl(path)
        assert loaded[0].content_hash is not None


class TestStorageHelpers:
    def test_count_existing_empty(self, tmp_path):
        path = tmp_path / "out.jsonl"
        path.write_text("")
        assert count_existing(path) == 0

    def test_count_existing_nonexistent(self, tmp_path):
        assert count_existing(tmp_path / "nope.jsonl") == 0

    def test_count_existing_records(self, tmp_path):
        path = tmp_path / "out.jsonl"
        records = [_make_record(id=f"R-{i}", code_before=f"c {i}") for i in range(5)]
        path.write_text("\n".join(r.to_json() for r in records) + "\n")
        assert count_existing(path) == 5

    def test_load_existing_hashes(self, tmp_path):
        path = tmp_path / "out.jsonl"
        r1 = _make_record(id="R-001", code_before="alpha")
        r2 = _make_record(id="R-002", code_before="beta")
        path.write_text(r1.to_json() + "\n" + r2.to_json() + "\n")
        hashes = load_existing_hashes(path)
        assert len(hashes) == 2
        assert r1.content_hash in hashes
        assert r2.content_hash in hashes

    def test_load_existing_hashes_nonexistent(self, tmp_path):
        hashes = load_existing_hashes(tmp_path / "nope.jsonl")
        assert hashes == set()
