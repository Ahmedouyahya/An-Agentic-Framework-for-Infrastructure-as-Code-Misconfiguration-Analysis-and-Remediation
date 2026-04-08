"""
Scraper for known IaC security repositories.

Handles three types:
  1. Intentionally vulnerable repos (TerraGoat, KuberGoat…) — insecure-only records
  2. Checkov test resources — PASS/FAIL paired files
  3. KICS query examples — vulnerable/fixed paired files
  4. tfsec / defsec — scanner test resources

All fetches use the GitHub Contents API (no git clone required).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from scraping.config import GITHUB_API_BASE, GITHUB_TOKEN, KNOWN_REPOS, MAX_FILE_BYTES
from scraping.processors.classifier import classify_smells, detect_iac_tool
from scraping.scrapers.github import GitHubSession, _get_file_at_ref
from scraping.schemas import IaCRecord

logger = logging.getLogger(__name__)

CHUNK = 25  # concurrent fetch batch size


def _record_id(owner: str, repo: str, path: str) -> str:
    raw = f"{owner}/{repo}:{path}"
    return "KR-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Generic repo file lister (recursive via tree API, handles truncation)
# ---------------------------------------------------------------------------

async def _list_repo_files(
    session: GitHubSession,
    owner: str, repo: str,
    extensions: Tuple[str, ...] = (".tf", ".yaml", ".yml", ".dockerfile", ".json"),
    path_filter: Optional[str] = None,
    max_files: int = 8000,
) -> List[Dict[str, str]]:
    """
    Return {path, sha, default_branch} for all matching files in a repo.
    Uses the git tree API (single request). Handles truncated trees by
    walking subdirectories individually.
    """
    # Get default branch
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    status, meta = await session.get(url)
    if status != 200 or not isinstance(meta, dict):
        logger.warning("Cannot read repo meta for %s/%s (status=%d)", owner, repo, status)
        return []
    default_branch = meta.get("default_branch", "main")

    files = await _fetch_tree(session, owner, repo, default_branch, extensions, path_filter, max_files)
    return files


async def _fetch_tree(
    session: GitHubSession,
    owner: str, repo: str,
    ref: str,
    extensions: Tuple[str, ...],
    path_filter: Optional[str],
    max_files: int,
) -> List[Dict[str, str]]:
    tree_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/trees/{ref}"
    status, tree_body = await session.get(tree_url, params={"recursive": "1"})
    if status != 200 or not isinstance(tree_body, dict):
        logger.warning("Cannot read tree for %s/%s @ %s", owner, repo, ref)
        return []

    truncated = tree_body.get("truncated", False)
    items = tree_body.get("tree", [])
    files = _filter_tree_items(items, extensions, path_filter)

    if truncated:
        logger.info("  Tree truncated for %s/%s — walking subdirs", owner, repo)
        # Walk top-level subdirectories separately
        top_dirs = [i for i in items if i.get("type") == "tree"]
        extra: List[Dict] = []
        for d in top_dirs[:40]:  # limit to 40 subdirs
            sub_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/trees/{d['sha']}"
            s2, body2 = await session.get(sub_url, params={"recursive": "1"})
            if s2 == 200 and isinstance(body2, dict):
                sub_items = [
                    {**i, "path": d["path"] + "/" + i["path"]}
                    for i in body2.get("tree", [])
                ]
                extra.extend(_filter_tree_items(sub_items, extensions, path_filter))
        files.extend(extra)

    # Deduplicate and cap
    seen = set()
    result = []
    for f in files:
        if f["path"] not in seen:
            seen.add(f["path"])
            result.append({**f, "default_branch": ref})
            if len(result) >= max_files:
                break
    return result


def _filter_tree_items(
    items: List[Dict],
    extensions: Tuple[str, ...],
    path_filter: Optional[str],
) -> List[Dict]:
    result = []
    for item in items:
        if item.get("type") != "blob":
            continue
        item_path = item.get("path", "")
        p = Path(item_path)
        name_lower = p.name.lower()
        ext_ok = (p.suffix.lower() in extensions or name_lower in {"dockerfile", "vagrantfile"})
        if not ext_ok:
            continue
        if path_filter and path_filter not in item_path:
            continue
        size = item.get("size", 0)
        if size and size > MAX_FILE_BYTES:
            continue
        result.append(item)
    return result


# ---------------------------------------------------------------------------
# Directory listing via Contents API (for truncated trees)
# ---------------------------------------------------------------------------

async def _list_dir_contents(
    session: GitHubSession,
    owner: str, repo: str, dir_path: str,
    branch: str = "main",
) -> List[Dict]:
    """List files in a specific directory using the Contents API."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{dir_path}"
    status, body = await session.get(url, params={"ref": branch})
    if status != 200 or not isinstance(body, list):
        return []
    return body


# ---------------------------------------------------------------------------
# Intentionally vulnerable repos (insecure-only)
# ---------------------------------------------------------------------------

async def scrape_vulnerable_repo(
    session: GitHubSession,
    owner: str, repo: str,
    repo_description: str,
) -> AsyncIterator[IaCRecord]:
    logger.info("Scraping vulnerable repo: %s/%s", owner, repo)
    files = await _list_repo_files(session, owner, repo)
    logger.info("  Found %d IaC files in %s/%s", len(files), owner, repo)

    for i in range(0, len(files), CHUNK):
        chunk = files[i:i + CHUNK]

        async def _fetch(info: Dict) -> Optional[IaCRecord]:
            content = await _get_file_at_ref(
                session, owner, repo, info["path"], info["default_branch"]
            )
            if not content:
                return None
            tool = detect_iac_tool(info["path"], content)
            if tool == "unknown":
                return None
            smells = classify_smells(content)
            return IaCRecord(
                id=_record_id(owner, repo, info["path"]),
                source="known_repo",
                iac_tool=tool,
                file_path=info["path"],
                code_before=content,
                code_after=None,
                diff=None,
                has_fix=False,
                smells=smells,
                repo=f"{owner}/{repo}",
                repo_description=repo_description,
                notes=f"Intentionally vulnerable: {repo_description}",
            )

        results = await asyncio.gather(*[_fetch(info) for info in chunk])
        for r in results:
            if r is not None:
                yield r


# ---------------------------------------------------------------------------
# Checkov test resources — PASS/FAIL pairs
# Uses Contents API on specific directories to bypass tree truncation
# ---------------------------------------------------------------------------

_CHECKOV_TEST_DIRS = [
    "tests/resources",
    "tests/unit/resources",
    "tests/unit/example_",
]

_PASS_KEYWORDS = {"pass", "passed", "positive", "good", "compliant", "secure", "correct", "allowed"}
_FAIL_KEYWORDS = {"fail", "failed", "negative", "bad", "example_", "wrong", "insecure",
                  "violated", "denied", "vulnerable"}


def _is_pass_path(path: str) -> bool:
    lower = path.lower()
    parts = set(Path(lower).parts)
    stem = Path(lower).stem
    return bool((_PASS_KEYWORDS & parts) or any(k in stem for k in _PASS_KEYWORDS))


def _is_fail_path(path: str) -> bool:
    lower = path.lower()
    parts = set(Path(lower).parts)
    stem = Path(lower).stem
    return bool((_FAIL_KEYWORDS & parts) or any(k in stem for k in _FAIL_KEYWORDS))


async def scrape_checkov_examples(session: GitHubSession) -> AsyncIterator[IaCRecord]:
    owner, repo = "bridgecrewio", "checkov"
    logger.info("Scraping Checkov examples from %s/%s", owner, repo)

    # Get branch first
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    status, meta = await session.get(url)
    if status != 200:
        return
    branch = meta.get("default_branch", "main")

    # Use targeted subtree fetch for each top-level checker directory
    # Checkov structure: checkov/<tool>/checks/*.py + example_* resources
    # Resources live under tests/resources/example_CheckId/ or similar
    checkov_tools = ["terraform", "kubernetes", "dockerfile", "ansible",
                     "cloudformation", "arm", "helm"]

    all_files: List[Dict] = []
    for tool in checkov_tools:
        for base_dir in [f"tests/resources/example_{tool}", f"tests/{tool}/resources",
                         f"tests/resources/{tool}"]:
            sub_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{base_dir}"
            s, body = await session.get(sub_url, params={"ref": branch})
            if s == 200 and isinstance(body, list):
                for item in body:
                    if item.get("type") == "dir":
                        # recurse one level
                        s2, body2 = await session.get(item["url"])
                        if s2 == 200 and isinstance(body2, list):
                            all_files.extend([
                                {**f, "default_branch": branch}
                                for f in body2
                                if f.get("type") == "file"
                                and Path(f.get("name", "")).suffix.lower()
                                in {".tf", ".yaml", ".yml", ".json", ".dockerfile", ""}
                            ])
                    elif item.get("type") == "file":
                        if Path(item.get("name", "")).suffix.lower() in {".tf", ".yaml", ".yml", ".json"}:
                            all_files.append({**item, "default_branch": branch})

    # Also try the full tree with path filter for "example_"
    tree_files = await _list_repo_files(
        session, owner, repo,
        path_filter="example_",
        max_files=3000,
    )
    # Merge
    seen_paths = {f.get("path", f.get("name", "")) for f in all_files}
    for f in tree_files:
        if f["path"] not in seen_paths:
            all_files.append(f)
            seen_paths.add(f["path"])

    logger.info("  Found %d Checkov example files", len(all_files))

    # Group by parent directory (each group = one check example)
    groups: Dict[str, List[Dict]] = {}
    for f in all_files:
        path = f.get("path", f.get("name", ""))
        parent = str(Path(path).parent)
        groups.setdefault(parent, []).append({**f, "path": path})

    group_items = list(groups.items())
    for i in range(0, len(group_items), CHUNK):
        batch = group_items[i:i + CHUNK]

        async def _process_group(parent: str, files_info: List[Dict]) -> List[IaCRecord]:
            records = []
            contents = await asyncio.gather(*[
                _get_file_at_ref_any(session, owner, repo, f, branch)
                for f in files_info
            ])
            pass_files, fail_files = [], []
            for info, content in zip(files_info, contents):
                if not content:
                    continue
                path = info.get("path", info.get("name", ""))
                if _is_pass_path(path):
                    pass_files.append((path, content))
                elif _is_fail_path(path):
                    fail_files.append((path, content))
                else:
                    smells = classify_smells(content)
                    if smells:
                        fail_files.append((path, content))
                    else:
                        pass_files.append((path, content))

            pass_content = pass_files[0][1] if pass_files else None
            for fail_path, fail_content in fail_files:
                tool = detect_iac_tool(fail_path, fail_content)
                if tool == "unknown" and pass_content:
                    tool = detect_iac_tool(pass_files[0][0] if pass_files else "", pass_content)
                if tool == "unknown":
                    continue
                smells = classify_smells(fail_content)
                records.append(IaCRecord(
                    id=_record_id(owner, repo, fail_path),
                    source="checkov",
                    iac_tool=tool,
                    file_path=fail_path,
                    code_before=fail_content,
                    code_after=pass_content,
                    diff=None,
                    has_fix=bool(pass_content),
                    smells=smells,
                    repo=f"{owner}/{repo}",
                    notes=f"Checkov example group: {parent}",
                ))
            return records

        batch_results = await asyncio.gather(*[_process_group(d, fs) for d, fs in batch])
        for records in batch_results:
            for r in records:
                yield r


async def _get_file_at_ref_any(
    session: GitHubSession,
    owner: str, repo: str,
    file_info: Dict,
    branch: str,
) -> Optional[str]:
    """Get file content, supporting both tree-style and contents-API-style dicts."""
    path = file_info.get("path", file_info.get("name", ""))
    if not path:
        return None
    # If contents API already gave us content
    if file_info.get("content") and file_info.get("encoding") == "base64":
        try:
            return base64.b64decode(
                file_info["content"].replace("\n", "")
            ).decode("utf-8", errors="replace")
        except Exception:
            pass
    # Otherwise fetch by path
    return await _get_file_at_ref(session, owner, repo, path, branch)


# ---------------------------------------------------------------------------
# KICS examples — positive (vulnerable) / negative (compliant) pairs
# ---------------------------------------------------------------------------

async def scrape_kics_examples(session: GitHubSession) -> AsyncIterator[IaCRecord]:
    owner, repo = "Checkmarx", "kics"
    logger.info("Scraping KICS examples from %s/%s", owner, repo)

    all_files = await _list_repo_files(
        session, owner, repo,
        path_filter="assets/queries",
        max_files=8000,
    )
    # Filter to IaC files only (exclude metadata.json, rego, etc.)
    iac_files = [
        f for f in all_files
        if Path(f["path"]).suffix.lower() in {".tf", ".yaml", ".yml", ".dockerfile", ""}
        and not f["path"].endswith(".json")
        and not f["path"].endswith(".rego")
        and not f["path"].endswith(".graphql")
    ]
    logger.info("  Found %d KICS IaC example files", len(iac_files))

    # Group by query directory (assets/queries/<tool>/<category>/<check>/)
    groups: Dict[str, List[Dict]] = {}
    for f in iac_files:
        parts = Path(f["path"]).parts
        query_dir = "/".join(parts[:5]) if len(parts) >= 5 else str(Path(f["path"]).parent)
        groups.setdefault(query_dir, []).append(f)

    items = list(groups.items())
    logger.info("  Processing %d KICS query groups", len(items))

    for i in range(0, len(items), CHUNK):
        batch = items[i:i + CHUNK]

        async def _process_kics(query_dir: str, files_info: List[Dict]) -> List[IaCRecord]:
            records = []
            contents = await asyncio.gather(*[
                _get_file_at_ref(session, owner, repo, f["path"], f["default_branch"])
                for f in files_info
            ])
            positive, negative = [], []
            for info, content in zip(files_info, contents):
                if not content:
                    continue
                path_lower = info["path"].lower()
                if "/positive" in path_lower or Path(info["path"]).stem.lower().startswith("positive"):
                    positive.append((info["path"], content))
                elif "/negative" in path_lower or Path(info["path"]).stem.lower().startswith("negative"):
                    negative.append((info["path"], content))
                else:
                    smells = classify_smells(content)
                    if smells:
                        positive.append((info["path"], content))
                    else:
                        negative.append((info["path"], content))

            neg_content = negative[0][1] if negative else None
            neg_path    = negative[0][0] if negative else None
            for pos_path, pos_content in positive:
                tool = detect_iac_tool(pos_path, pos_content)
                if tool == "unknown" and neg_content:
                    tool = detect_iac_tool(neg_path or "", neg_content)
                if tool == "unknown":
                    continue
                smells = classify_smells(pos_content)
                records.append(IaCRecord(
                    id=_record_id(owner, repo, pos_path),
                    source="kics",
                    iac_tool=tool,
                    file_path=pos_path,
                    code_before=pos_content,
                    code_after=neg_content,
                    diff=None,
                    has_fix=bool(neg_content),
                    smells=smells,
                    repo=f"{owner}/{repo}",
                    notes=f"KICS query: {query_dir}",
                ))
            return records

        batch_results = await asyncio.gather(*[_process_kics(d, fs) for d, fs in batch])
        for records in batch_results:
            for r in records:
                yield r


# ---------------------------------------------------------------------------
# tfsec / defsec — scanner test resources (PASSED/FAILED pairs)
# ---------------------------------------------------------------------------

async def scrape_tfsec_examples(session: GitHubSession) -> AsyncIterator[IaCRecord]:
    """
    tfsec (now merged into aquasecurity/defsec) has example Terraform resources
    under internal/adapters/terraform and pkg/rules in the form of
    good_example / bad_example Go test files. But it also has:
    - aquasecurity/tfsec: _examples/ directories with .tf files
    - aquasecurity/defsec: test/testdata/ directories
    """
    for owner, repo, dir_hint in [
        ("aquasecurity", "tfsec",    ""),
        ("aquasecurity", "defsec",   "test"),
    ]:
        logger.info("Scraping %s/%s", owner, repo)
        files = await _list_repo_files(
            session, owner, repo,
            extensions=(".tf", ".yaml", ".yml", ".dockerfile"),
            path_filter=dir_hint or None,
            max_files=3000,
        )
        logger.info("  Found %d files in %s/%s", len(files), owner, repo)

        for i in range(0, len(files), CHUNK):
            chunk = files[i:i + CHUNK]

            async def _fetch(info: Dict, o=owner, r=repo) -> Optional[IaCRecord]:
                content = await _get_file_at_ref(session, o, r, info["path"], info["default_branch"])
                if not content:
                    return None
                tool = detect_iac_tool(info["path"], content)
                if tool == "unknown":
                    return None
                smells = classify_smells(content)
                path_lower = info["path"].lower()
                is_bad = any(k in path_lower for k in ["bad", "fail", "insecure", "wrong", "deny", "vuln"])
                is_good = any(k in path_lower for k in ["good", "pass", "secure", "allow", "compliant"])
                if not smells and not is_bad:
                    return None
                return IaCRecord(
                    id=_record_id(o, r, info["path"]),
                    source="tfsec",
                    iac_tool=tool,
                    file_path=info["path"],
                    code_before=content if (smells or is_bad) else "",
                    code_after=content if is_good else None,
                    diff=None,
                    has_fix=False,
                    smells=smells,
                    repo=f"{o}/{r}",
                    notes=f"tfsec/defsec example: {info['path']}",
                )

            results = await asyncio.gather(*[_fetch(info) for info in chunk])
            for r in results:
                if r is not None and r.code_before:
                    yield r


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def scrape_all_known_repos(
    token: Optional[str] = None,
    progress=None,  # Optional[ProgressTracker]
    repos: Optional[list] = None,
) -> AsyncIterator[IaCRecord]:
    """
    Yield IaCRecord objects from all known IaC security repositories.
    Resumable: skips repos already marked done in the progress tracker.

    Args:
        token:    GitHub token override
        progress: ProgressTracker for resumability
        repos:    subset of KNOWN_REPOS to scrape (defaults to all)
    """
    from scraping.config import GITHUB_TOKEN as _DEFAULT_TOKEN
    repos = repos or KNOWN_REPOS

    async with GitHubSession(token=token or _DEFAULT_TOKEN) as session:
        for owner, repo, description, has_fix_commits in repos:
            repo_key = f"{owner}/{repo}"

            if progress and progress.is_repo_done(repo_key):
                logger.info("Repo SKIP (already done): %s", repo_key)
                continue

            if owner == "bridgecrewio" and repo == "checkov":
                async for r in scrape_checkov_examples(session):
                    yield r
            elif owner == "Checkmarx" and repo == "kics":
                async for r in scrape_kics_examples(session):
                    yield r
            elif owner == "aquasecurity" and repo in ("tfsec", "defsec"):
                async for r in scrape_tfsec_examples(session):
                    yield r
            else:
                async for r in scrape_vulnerable_repo(session, owner, repo, description):
                    yield r

            if progress:
                progress.mark_repo_done(repo_key)
