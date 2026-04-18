"""
Tier assignment for v2 records.

Four tiers, highest quality first:

    A (gold)   — before+after, scanner-validated smell that disappears in after
    B (silver) — before+after, any validated OR regex-classified smell, clean before-content
    C (bronze) — before+after, security-related commit, no confirmed smell
    D (weak)   — placeholder/heuristic before, no confirmed smell, weak signal

Call `assign_tier(record_dict) -> str` on any record (raw v1 or freshly scraped v2).
The caller writes the returned letter into record["tier"].
"""

from __future__ import annotations

from typing import Any, Dict, Set

_STRONG_KEYWORDS = (
    "cve-", "cwe-", "vulnerab", "exploit",
    "hardcoded", "privilege esc", "unencrypt",
    "insecure", "cleartext", "plaintext",
    "secret leak", "credential", "token leak",
)


def _before_is_real(rec: Dict[str, Any]) -> bool:
    q = rec.get("code_before_quality")
    cb = rec.get("code_before") or ""
    if q in ("api", "exact", "partial"):
        return True
    if q in ("unavailable", "heuristic", "new_file"):
        return False
    # legacy v1 records — no quality field, infer from content
    if "[before content unavailable]" in cb:
        return False
    return bool(cb and len(cb) > 20)


def _validated_before(rec: Dict[str, Any]) -> list:
    # Two possible schemas: `validated_smells_before` (validator's key) and
    # the generic `validated_smells` list with direction='before'.
    if "validated_smells_before" in rec:
        return rec["validated_smells_before"] or []
    return [v for v in (rec.get("validated_smells") or []) if v.get("direction", "before") == "before"]


def _validated_after(rec: Dict[str, Any]) -> list:
    if "validated_smells_after" in rec:
        return rec["validated_smells_after"] or []
    return [v for v in (rec.get("validated_smells") or []) if v.get("direction") == "after"]


def _fixed_smells(rec: Dict[str, Any]) -> Set[str]:
    before_ids = {f.get("rule_id") for f in _validated_before(rec) if f.get("rule_id")}
    after_ids  = {f.get("rule_id") for f in _validated_after(rec)  if f.get("rule_id")}
    return before_ids - after_ids


def _has_strong_commit_signal(rec: Dict[str, Any]) -> bool:
    msg = (rec.get("commit_message") or "").lower()
    return any(k in msg for k in _STRONG_KEYWORDS)


def assign_tier(rec: Dict[str, Any]) -> str:
    has_fix = bool(rec.get("has_fix"))
    real_before = _before_is_real(rec)
    regex_smells = rec.get("smells") or []
    is_new_file = rec.get("code_before_quality") == "new_file"
    code_after = rec.get("code_after") or ""
    validated_before = _validated_before(rec)

    # Tier A: scanner-validated before/after transition (smell fixed)
    if has_fix and real_before and _fixed_smells(rec):
        return "A"

    # Tier B: before/after pair + any smell (scanner or regex)
    if has_fix and real_before and (validated_before or regex_smells):
        return "B"

    # Tier B (commit-signal variant): before/after pair + strong security signal
    if has_fix and real_before and _has_strong_commit_signal(rec):
        return "B"

    # Tier C: no fix pair but genuine real code + scanner-validated smell
    # → useful as insecure-code detection training data.
    if real_before and validated_before:
        return "C"

    # Tier C: new-file additions whose content contains regex-detected smells.
    if is_new_file and code_after and regex_smells:
        return "C"

    # Tier C: real code + regex smell (even without fix pair).
    if real_before and regex_smells:
        return "C"

    # Tier D: everything else — no useful signal
    return "D"


def tier_stats(records) -> Dict[str, int]:
    counts = {"A": 0, "B": 0, "C": 0, "D": 0}
    for r in records:
        t = assign_tier(r)
        counts[t] = counts.get(t, 0) + 1
    return counts
