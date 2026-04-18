"""
Data schemas for scraped IaC security records.
Every scraped entry is stored as an IaCRecord, serialized to JSONL.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Sub-schemas
# ---------------------------------------------------------------------------

@dataclass
class SmellAnnotation:
    """One detected security smell in a file."""
    type: str                       # taxonomy key, e.g. "hardcoded_credential"
    cwe: Optional[str] = None       # e.g. "CWE-798"
    checkov_id: Optional[str] = None  # e.g. "CKV_AWS_41"
    severity: Optional[str] = None  # CRITICAL / HIGH / MEDIUM / LOW
    category: Optional[str] = None  # Security / ConfigurationData / Dependency
    description: Optional[str] = None
    line_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Main record
# ---------------------------------------------------------------------------

@dataclass
class IaCRecord:
    """
    A single dataset record representing an IaC file with security smells.

    When has_fix=True:  code_before contains the insecure code,
                        code_after contains the fixed code,
                        diff contains the unified diff.
    When has_fix=False: code_before contains the insecure code only
                        (useful for detection training, not fix training).
    """

    # --- Identity ---
    id: str                         # unique record ID, e.g. "GH-abc123-main.tf"
    source: str                     # github_commit | github_code | known_repo | checkov | kics
    iac_tool: str                   # terraform | ansible | kubernetes | docker | cloudformation

    # --- Content ---
    file_path: str                  # original file path in repo
    code_before: str                # insecure code
    code_after: Optional[str]       # fixed code (None if no fix available)
    diff: Optional[str]             # unified diff (None if no fix available)
    has_fix: bool                   # True if code_after is available

    # --- Annotations ---
    smells: List[SmellAnnotation] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)  # ["hardcoded_credential", "CRITICAL", ...]

    # --- GitHub metadata ---
    repo: Optional[str] = None              # "owner/repo"
    repo_stars: Optional[int] = None
    repo_description: Optional[str] = None
    commit_sha: Optional[str] = None
    parent_sha: Optional[str] = None
    commit_message: Optional[str] = None
    commit_date: Optional[str] = None      # ISO-8601
    commit_author: Optional[str] = None

    # --- Dataset metadata ---
    split: str = "train"                   # train | val | test
    content_hash: Optional[str] = None     # SHA-256 of code_before for dedup
    scraped_at: str = field(default_factory=_utcnow)
    notes: Optional[str] = None           # any free-text notes

    # --- Quality tracking (v2) ---
    code_before_quality: Optional[str] = None  # api | exact | partial | heuristic | unavailable
    tier: Optional[str] = None                 # A (gold) | B (silver) | C (bronze) | D (weak)
    validated_smells: List[Dict[str, Any]] = field(default_factory=list)  # scanner ground truth

    # ------------------------------------------------------------------

    def compute_hash(self) -> str:
        """SHA-256 of code_before (first 64 chars of hex) for deduplication."""
        return hashlib.sha256(self.code_before.encode("utf-8", errors="replace")).hexdigest()[:64]

    def finalize(self) -> "IaCRecord":
        """Compute hash and build label list before saving. Returns self."""
        self.content_hash = self.compute_hash()
        # Build labels from smells
        smell_types = {s.type for s in self.smells}
        severities   = {s.severity for s in self.smells if s.severity}
        cwes         = {s.cwe for s in self.smells if s.cwe}
        self.labels = sorted(smell_types | severities | cwes | {self.iac_tool})
        return self

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # smells are already dicts via asdict
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "IaCRecord":
        smells = [SmellAnnotation(**s) for s in d.pop("smells", [])]
        record = cls(**d)
        record.smells = smells
        return record

    @classmethod
    def from_json(cls, line: str) -> "IaCRecord":
        return cls.from_dict(json.loads(line))


# ---------------------------------------------------------------------------
# Scrape run manifest
# ---------------------------------------------------------------------------

@dataclass
class ScrapeManifest:
    """Written to output/manifest.json to track what was collected."""
    run_id: str
    started_at: str
    finished_at: Optional[str] = None
    total_records: int = 0
    records_with_fix: int = 0
    records_by_tool: Dict[str, int] = field(default_factory=dict)
    records_by_source: Dict[str, int] = field(default_factory=dict)
    queries_run: List[str] = field(default_factory=list)
    repos_scraped: List[str] = field(default_factory=list)
    output_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, path) -> None:
        import pathlib
        pathlib.Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        )
