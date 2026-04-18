"""
Lightweight in-process metrics + watchdog for long-running scrapes.

Writes one JSONL metric line per minute to output/metrics.jsonl and keeps
a running stall detector: if no new records have been written for
WATCHDOG_STALL_SECONDS, .stalled() returns True so the main loop can
exit non-zero and let a supervisor script restart the process.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from scraping.storage.writer import atomic_write_text

logger = logging.getLogger(__name__)


@dataclass
class MetricsCollector:
    metrics_path: Path
    stall_seconds: int = 900
    _start_ts: float = field(default_factory=time.time)
    _last_write_ts: float = field(default_factory=time.time)
    _last_report_ts: float = field(default_factory=time.time)
    _report_interval: int = 60
    _records_written: int = 0
    _records_this_minute: int = 0
    _api_calls: int = 0
    _status_counts: Dict[int, int] = field(default_factory=dict)
    _current_phase: str = "init"
    _current_query: str = ""

    def __post_init__(self) -> None:
        self.metrics_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Event hooks
    # ------------------------------------------------------------------

    def record_written(self, n: int = 1) -> None:
        self._records_written += n
        self._records_this_minute += n
        self._last_write_ts = time.time()

    def api_call(self, status: int) -> None:
        self._api_calls += 1
        self._status_counts[status] = self._status_counts.get(status, 0) + 1

    def set_phase(self, phase: str, query: str = "") -> None:
        self._current_phase = phase
        self._current_query = query

    # ------------------------------------------------------------------
    # Periodic reporting / stall detection
    # ------------------------------------------------------------------

    def tick(self) -> Optional[Dict]:
        """
        Call frequently from the main loop. When a report interval has
        elapsed, writes a metrics line and returns it. Otherwise returns None.
        """
        now = time.time()
        if now - self._last_report_ts < self._report_interval:
            return None
        entry = self._build_entry(now)
        self._append(entry)
        self._records_this_minute = 0
        self._last_report_ts = now
        return entry

    def _build_entry(self, now: float) -> Dict:
        uptime = int(now - self._start_ts)
        rate = self._records_this_minute  # per minute
        return {
            "ts":          int(now),
            "uptime_s":    uptime,
            "records":     self._records_written,
            "rate_per_min": rate,
            "api_calls":   self._api_calls,
            "status":      dict(self._status_counts),
            "phase":       self._current_phase,
            "query":       self._current_query[:120],
            "idle_s":      int(now - self._last_write_ts),
        }

    def _append(self, entry: Dict) -> None:
        line = json.dumps(entry) + "\n"
        try:
            with self.metrics_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            logger.warning("Metrics write failed: %s", exc)

    def stalled(self) -> bool:
        return (time.time() - self._last_write_ts) > self.stall_seconds

    def final_summary(self) -> Dict:
        now = time.time()
        return self._build_entry(now)

    def save_snapshot(self, path: Path) -> None:
        atomic_write_text(path, json.dumps(self.final_summary(), indent=2))
