"""
Progress tracker — crash-safe, per-page, resumable.

Schema (v2):
    {
        "schema_version": 2,
        "commit_queries":   {"<query>": {"last_page": int, "done": bool}},
        "commit_windows":   {"<query>::<start>..<end>": {"last_page": int, "done": bool}},
        "code_queries":     {"<query>": {"last_page": int, "done": bool}},
        "completed_repos":  ["owner/repo", ...],
        "total_written":    int,
        "errors_seen":      int,
        "started_at":       "ISO-8601",
        "last_updated":     "ISO-8601",
    }

Backward compatible with v1 (flat lists).

All writes go through atomic_write_text() so the progress file is never
left half-written on crash.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from scraping.storage.writer import atomic_write_text


SCHEMA_VERSION = 2


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _empty_state() -> Dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "commit_queries":   {},
        "commit_windows":   {},
        "code_queries":     {},
        "completed_repos":  [],
        "total_written":    0,
        "errors_seen":      0,
        "started_at":       _utcnow(),
        "last_updated":     None,
    }


def _migrate_v1(old: Dict) -> Dict:
    """Migrate flat-list v1 progress to dict-based v2."""
    state = _empty_state()
    for q in old.get("completed_commit_queries", []) or []:
        state["commit_queries"][q] = {"last_page": 99, "done": True}
    for q in old.get("completed_code_queries", []) or []:
        state["code_queries"][q] = {"last_page": 99, "done": True}
    state["completed_repos"] = list(old.get("completed_repos", []) or [])
    state["total_written"]   = int(old.get("total_written", 0) or 0)
    state["started_at"]      = old.get("started_at") or state["started_at"]
    return state


class ProgressTracker:
    """
    Persistent per-page progress. Atomic on-disk updates.

    Terminology:
        "query"  — a plain search query string (no date filter)
        "window" — a query + date range, tracked separately so the same
                   query can be fanned out over many 14-day windows
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: Dict = self._load()
        self._dirty_count = 0
        self._flush_interval = 1

    def _load(self) -> Dict:
        if not self.path.exists():
            return _empty_state()
        try:
            raw = json.loads(self.path.read_text())
        except Exception:
            return _empty_state()
        if not isinstance(raw, dict):
            return _empty_state()
        if raw.get("schema_version") == SCHEMA_VERSION:
            for k, v in _empty_state().items():
                raw.setdefault(k, v)
            return raw
        return _migrate_v1(raw)

    def _save(self) -> None:
        self._data["last_updated"] = _utcnow()
        atomic_write_text(self.path, json.dumps(self._data, indent=2))

    def _mark_dirty(self) -> None:
        self._dirty_count += 1
        if self._dirty_count >= self._flush_interval:
            self._save()
            self._dirty_count = 0

    def flush(self) -> None:
        self._save()
        self._dirty_count = 0

    # ------------------------------------------------------------------
    # Commit queries (no date window)
    # ------------------------------------------------------------------

    def commit_query_last_page(self, query: str) -> int:
        entry = self._data["commit_queries"].get(query, {})
        return int(entry.get("last_page", 0))

    def is_commit_query_done(self, query: str) -> bool:
        return bool(self._data["commit_queries"].get(query, {}).get("done"))

    def mark_commit_query_page(self, query: str, page: int) -> None:
        entry = self._data["commit_queries"].setdefault(query, {"last_page": 0, "done": False})
        if page > entry.get("last_page", 0):
            entry["last_page"] = page
            self._mark_dirty()

    def mark_commit_query_done(self, query: str) -> None:
        entry = self._data["commit_queries"].setdefault(query, {"last_page": 0, "done": False})
        entry["done"] = True
        self._save()

    # ------------------------------------------------------------------
    # Commit windows (query + date range)
    # ------------------------------------------------------------------

    @staticmethod
    def _window_key(query: str, start: str, end: str) -> str:
        return f"{query}::{start}..{end}"

    def window_last_page(self, query: str, start: str, end: str) -> int:
        k = self._window_key(query, start, end)
        return int(self._data["commit_windows"].get(k, {}).get("last_page", 0))

    def is_window_done(self, query: str, start: str, end: str) -> bool:
        k = self._window_key(query, start, end)
        return bool(self._data["commit_windows"].get(k, {}).get("done"))

    def mark_window_page(self, query: str, start: str, end: str, page: int) -> None:
        k = self._window_key(query, start, end)
        entry = self._data["commit_windows"].setdefault(k, {"last_page": 0, "done": False})
        if page > entry.get("last_page", 0):
            entry["last_page"] = page
            self._mark_dirty()

    def mark_window_done(self, query: str, start: str, end: str) -> None:
        k = self._window_key(query, start, end)
        entry = self._data["commit_windows"].setdefault(k, {"last_page": 0, "done": False})
        entry["done"] = True
        self._save()

    # ------------------------------------------------------------------
    # Code search queries
    # ------------------------------------------------------------------

    def code_query_last_page(self, query: str) -> int:
        return int(self._data["code_queries"].get(query, {}).get("last_page", 0))

    def is_code_query_done(self, query: str) -> bool:
        return bool(self._data["code_queries"].get(query, {}).get("done"))

    def mark_code_query_page(self, query: str, page: int) -> None:
        entry = self._data["code_queries"].setdefault(query, {"last_page": 0, "done": False})
        if page > entry.get("last_page", 0):
            entry["last_page"] = page
            self._mark_dirty()

    def mark_code_query_done(self, query: str) -> None:
        entry = self._data["code_queries"].setdefault(query, {"last_page": 0, "done": False})
        entry["done"] = True
        self._save()

    # ------------------------------------------------------------------
    # Repos
    # ------------------------------------------------------------------

    def is_repo_done(self, repo: str) -> bool:
        return repo in self._data["completed_repos"]

    def mark_repo_done(self, repo: str) -> None:
        if repo not in self._data["completed_repos"]:
            self._data["completed_repos"].append(repo)
            self._save()

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    def increment_written(self, n: int = 1) -> None:
        self._data["total_written"] = int(self._data.get("total_written", 0)) + n
        self._mark_dirty()

    def increment_errors(self, n: int = 1) -> None:
        self._data["errors_seen"] = int(self._data.get("errors_seen", 0)) + n
        self._mark_dirty()

    @property
    def total_written(self) -> int:
        return int(self._data.get("total_written", 0))

    @property
    def errors_seen(self) -> int:
        return int(self._data.get("errors_seen", 0))

    @property
    def done_commit_queries(self) -> List[str]:
        return [q for q, e in self._data["commit_queries"].items() if e.get("done")]

    @property
    def done_code_queries(self) -> List[str]:
        return [q for q, e in self._data["code_queries"].items() if e.get("done")]

    @property
    def done_windows(self) -> List[str]:
        return [k for k, e in self._data["commit_windows"].items() if e.get("done")]

    @property
    def done_repos(self) -> List[str]:
        return list(self._data["completed_repos"])

    def summary(self) -> str:
        return (
            f"commit_queries_done={len(self.done_commit_queries)} | "
            f"windows_done={len(self.done_windows)} | "
            f"code_queries_done={len(self.done_code_queries)} | "
            f"repos_done={len(self.done_repos)} | "
            f"total_written={self.total_written} | "
            f"errors={self.errors_seen}"
        )
