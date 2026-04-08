"""
Progress tracker — saves completed queries and repos to disk.
Safe to stop the scraper at any point; on restart it skips already-done work
and appends new records to the existing JSONL files.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ProgressTracker:
    """
    Persists scraping progress to a JSON file so runs are fully resumable.

    Tracks:
      - completed_commit_queries: search queries fully fetched
      - completed_code_queries:   code search queries fully fetched
      - completed_repos:          known repos fully scraped
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except Exception:
                pass
        return {
            "completed_commit_queries": [],
            "completed_code_queries": [],
            "completed_repos": [],
            "total_written": 0,
            "started_at": _utcnow(),
            "last_updated": None,
        }

    def _save(self) -> None:
        self._data["last_updated"] = _utcnow()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))

    # ------------------------------------------------------------------
    # Commit queries
    # ------------------------------------------------------------------

    def is_commit_query_done(self, query: str) -> bool:
        return query in self._data["completed_commit_queries"]

    def mark_commit_query_done(self, query: str) -> None:
        if query not in self._data["completed_commit_queries"]:
            self._data["completed_commit_queries"].append(query)
            self._save()

    # ------------------------------------------------------------------
    # Code search queries
    # ------------------------------------------------------------------

    def is_code_query_done(self, query: str) -> bool:
        return query in self._data["completed_code_queries"]

    def mark_code_query_done(self, query: str) -> None:
        if query not in self._data["completed_code_queries"]:
            self._data["completed_code_queries"].append(query)
            self._save()

    # ------------------------------------------------------------------
    # Known repos
    # ------------------------------------------------------------------

    def is_repo_done(self, repo: str) -> bool:
        return repo in self._data["completed_repos"]

    def mark_repo_done(self, repo: str) -> None:
        if repo not in self._data["completed_repos"]:
            self._data["completed_repos"].append(repo)
            self._save()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def increment_written(self, n: int = 1) -> None:
        self._data["total_written"] = self._data.get("total_written", 0) + n
        self._save()

    @property
    def total_written(self) -> int:
        return self._data.get("total_written", 0)

    @property
    def done_commit_queries(self) -> List[str]:
        return list(self._data["completed_commit_queries"])

    @property
    def done_code_queries(self) -> List[str]:
        return list(self._data["completed_code_queries"])

    @property
    def done_repos(self) -> List[str]:
        return list(self._data["completed_repos"])

    def summary(self) -> str:
        return (
            f"commit_queries_done={len(self.done_commit_queries)} | "
            f"code_queries_done={len(self.done_code_queries)} | "
            f"repos_done={len(self.done_repos)} | "
            f"total_written={self.total_written}"
        )
