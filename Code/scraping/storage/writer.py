"""
JSONL writer for IaCRecord objects.
Supports append mode for incremental scraping runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from scraping.schemas import IaCRecord


class JsonlWriter:
    """
    Thread-safe-ish JSONL writer (single-threaded use assumed).
    Opens in append mode so partial runs can resume.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self._count = 0

    def write(self, record: IaCRecord) -> None:
        """Write one record as a JSONL line."""
        record.finalize()
        self._fh.write(record.to_json() + "\n")
        self._fh.flush()
        self._count += 1

    def write_many(self, records: Iterable[IaCRecord]) -> int:
        """Write multiple records. Returns count written."""
        n = 0
        for r in records:
            self.write(r)
            n += 1
        return n

    @property
    def count(self) -> int:
        return self._count

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "JsonlWriter":
        return self

    def __exit__(self, *args) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Utility: count existing records without loading all into memory
# ---------------------------------------------------------------------------

def count_existing(path: Path) -> int:
    """Count lines in a JSONL file (= number of existing records)."""
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                count += 1
    return count


def load_existing_hashes(path: Path) -> set:
    """Return the set of content_hash values already in a JSONL file (for dedup on resume)."""
    hashes: set = set()
    if not path.exists():
        return hashes
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                h = obj.get("content_hash")
                if h:
                    hashes.add(h)
            except json.JSONDecodeError:
                pass
    return hashes
