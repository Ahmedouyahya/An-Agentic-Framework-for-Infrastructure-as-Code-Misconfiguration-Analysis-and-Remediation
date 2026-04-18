"""
Crash-safe JSONL writer for IaCRecord objects.

Designed for very long (days-to-weeks) scraping runs:

- Append mode, one JSON object per line (JSONL).
- On open, the writer walks the file backward from EOF and truncates any
  trailing partial line — so a crash mid-write leaves a clean file.
- Every FSYNC_EVERY records we call os.fsync() to flush the file to disk,
  so a power-loss or kernel-panic cannot lose more than ~FSYNC_EVERY records.
- Progress/hash side-files are written via tmp + os.replace() for atomicity.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable

from scraping.schemas import IaCRecord


FSYNC_EVERY = 50            # fsync every N records (amortises IO cost)
PARTIAL_SCAN_WINDOW = 16384  # bytes to scan from EOF looking for last newline


def _truncate_partial_last_line(path: Path) -> int:
    """
    If the file exists and does not end with a newline, truncate the trailing
    partial line (caused by a crash mid-write). Returns the number of bytes
    removed. Safe to call on a non-existent or empty file.
    """
    if not path.exists():
        return 0
    size = path.stat().st_size
    if size == 0:
        return 0

    with path.open("rb+") as fh:
        window = min(PARTIAL_SCAN_WINDOW, size)
        fh.seek(size - window)
        tail = fh.read(window)

        if tail.endswith(b"\n"):
            return 0  # clean EOF, nothing to do

        last_nl = tail.rfind(b"\n")
        if last_nl == -1:
            if window < size:
                return 0
            fh.seek(0)
            fh.truncate(0)
            return size

        new_size = (size - window) + last_nl + 1
        fh.truncate(new_size)
        return size - new_size


class JsonlWriter:
    """
    Append-only JSONL writer. Crash-safe at the record boundary.

    Usage:
        with JsonlWriter(path) as w:
            w.write(record)
    """

    def __init__(self, path: Path, fsync_every: int = FSYNC_EVERY) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

        removed = _truncate_partial_last_line(self.path)
        if removed:
            import logging
            logging.getLogger(__name__).warning(
                "Recovered %s: truncated %d bytes of partial trailing line",
                path, removed,
            )

        self._fh = self.path.open("a", encoding="utf-8")
        self._fsync_every = max(1, int(fsync_every))
        self._count = 0
        self._since_fsync = 0

    def write(self, record: IaCRecord) -> None:
        record.finalize()
        line = record.to_json() + "\n"
        self._fh.write(line)
        self._count += 1
        self._since_fsync += 1
        if self._since_fsync >= self._fsync_every:
            self._flush_and_sync()

    def write_many(self, records: Iterable[IaCRecord]) -> int:
        n = 0
        for r in records:
            self.write(r)
            n += 1
        return n

    def _flush_and_sync(self) -> None:
        try:
            self._fh.flush()
            os.fsync(self._fh.fileno())
        except OSError:
            pass
        self._since_fsync = 0

    @property
    def count(self) -> int:
        return self._count

    def close(self) -> None:
        try:
            self._flush_and_sync()
        finally:
            self._fh.close()

    def __enter__(self) -> "JsonlWriter":
        return self

    def __exit__(self, *args) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Utilities — counting and hash loading for dedup on resume
# ---------------------------------------------------------------------------

def count_existing(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                count += 1
    return count


def load_existing_hashes(path: Path) -> set:
    """Return content_hash set already in the JSONL file (for resume dedup)."""
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
                continue
    return hashes


def atomic_write_text(path: Path, data: str) -> None:
    """Atomic text write via tmp + os.replace() — safe for checkpoint files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    os.replace(tmp, path)
