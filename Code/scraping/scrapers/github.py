"""
Async GitHub scraper — two modes:

1. commit_search():  Search commits whose messages contain security keywords,
                     then extract before/after pairs from the changed IaC files.

2. code_search():    Search for IaC files containing insecure patterns.
                     These yield insecure-only records (has_fix=False).

Uses aiohttp with a rate-limit-aware semaphore.
GitHub tokens are required for meaningful throughput.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import time
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import aiohttp

from scraping.config import (
    CODE_SEARCH_QUERIES,
    COMMIT_SEARCH_QUERIES,
    COMMITS_PER_PAGE,
    GITHUB_API_BASE,
    GITHUB_TOKEN,
    MAX_CONCURRENT_REQUESTS,
    MAX_FILE_BYTES,
    MAX_SEARCH_PAGES,
    REST_REQUESTS_PER_SECOND,
    SEARCH_DELAY_SECONDS,
)
from scraping.processors.classifier import classify_diff_smells, classify_smells, detect_iac_tool, is_iac_file
from scraping.schemas import IaCRecord, SmellAnnotation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IaC file extension filter
# ---------------------------------------------------------------------------
_IAC_EXTENSIONS = {".tf", ".tfvars", ".yml", ".yaml", ".json", ".dockerfile"}
_IAC_FILENAMES  = {"dockerfile", "vagrantfile"}


def _is_iac_path(file_path: str) -> bool:
    p = Path(file_path)
    if p.name.lower() in _IAC_FILENAMES:
        return True
    if p.suffix.lower() in _IAC_EXTENSIONS:
        return True
    return False


def _make_record_id(repo: str, commit_sha: str, file_path: str) -> str:
    raw = f"{repo}:{commit_sha}:{file_path}"
    return "GH-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Global shared rate limiter — ALL GitHubSession instances share this.
# Enforces the 5000 req/hr GitHub API limit across parallel scrapers.
# ---------------------------------------------------------------------------

class _GlobalRateLimiter:
    """
    Token-bucket rate limiter shared across all GitHubSession instances.
    Controls total throughput to stay within GitHub's 5000 req/hr limit.
    """
    _instance: Optional["_GlobalRateLimiter"] = None

    def __init__(self) -> None:
        self._interval = 1.0 / REST_REQUESTS_PER_SECOND  # seconds between requests
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()
        self._burst_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self._search_semaphore = asyncio.Semaphore(1)

    @classmethod
    def get(cls) -> "_GlobalRateLimiter":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Call this at the start of a new asyncio.run() to reset state."""
        cls._instance = None

    async def acquire_rest(self) -> None:
        """Acquire a REST API slot — rate-limited to REST_REQUESTS_PER_SECOND."""
        async with self._burst_semaphore:
            async with self._lock:
                now = asyncio.get_event_loop().time()
                wait = self._interval - (now - self._last_request_time)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last_request_time = asyncio.get_event_loop().time()

    async def acquire_search(self) -> None:
        """Acquire a search API slot (serialised + SEARCH_DELAY_SECONDS after)."""
        await self._search_semaphore.acquire()

    def release_search(self) -> None:
        self._search_semaphore.release()


# ---------------------------------------------------------------------------
# Rate-limit aware HTTP session
# ---------------------------------------------------------------------------

class GitHubSession:
    """
    Async HTTP session for GitHub API with shared global rate limiting.
    All instances of GitHubSession share one rate limiter so parallel
    scrapers never exceed the 5000 req/hr limit.
    """

    def __init__(self, token: str = GITHUB_TOKEN) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "iac-security-scraper/1.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._headers = headers
        self._session: Optional[aiohttp.ClientSession] = None
        self._rl = _GlobalRateLimiter.get()  # shared across all sessions

    async def __aenter__(self) -> "GitHubSession":
        self._session = aiohttp.ClientSession(headers=self._headers)
        return self

    async def __aexit__(self, *args) -> None:
        if self._session:
            await self._session.close()

    async def get(self, url: str, params: Optional[Dict] = None,
                  accept: Optional[str] = None) -> Tuple[int, Any]:
        """
        GET url with shared global rate limiting.
        Returns (status_code, body). Body is dict/list or str.
        """
        hdrs = {}
        if accept:
            hdrs["Accept"] = accept

        # Throttle via shared global rate limiter
        await self._rl.acquire_rest()

        for attempt in range(4):
            try:
                async with self._session.get(url, params=params, headers=hdrs) as resp:
                    remaining = int(resp.headers.get("X-RateLimit-Remaining", "999"))
                    reset_at   = int(resp.headers.get("X-RateLimit-Reset", "0"))

                    if resp.status == 429 or remaining <= 5:
                        wait = max(reset_at - int(time.time()), 10)
                        logger.warning("Rate limited (remaining=%d) — sleeping %ds", remaining, wait)
                        await asyncio.sleep(wait)
                        await self._rl.acquire_rest()  # re-throttle before retry
                        continue

                    if resp.status == 202:  # GitHub processing async request
                        await asyncio.sleep(3)
                        continue

                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct:
                        body = await resp.json(content_type=None)
                    else:
                        raw = await resp.read()
                        body = raw.decode("utf-8", errors="replace")
                    return resp.status, body

            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                logger.warning("Request error (%s) — retry %d/3", exc, attempt + 1)
                await asyncio.sleep(2 ** attempt)

        return 0, None

    async def search_get(self, url: str, params: Optional[Dict] = None) -> Tuple[int, Any]:
        """Serialised search request (respects 30 req/min search API limit)."""
        await self._rl.acquire_search()
        try:
            status, body = await self.get(url, params=params,
                                          accept="application/vnd.github.cloak-preview+json")
            await asyncio.sleep(SEARCH_DELAY_SECONDS)
            return status, body
        finally:
            self._rl.release_search()


# ---------------------------------------------------------------------------
# Commit helper: get file content at a specific ref
# ---------------------------------------------------------------------------

async def _get_file_at_ref(
    session: GitHubSession,
    owner: str, repo: str,
    path: str, ref: str,
) -> Optional[str]:
    """Fetch raw file content at a git ref. Returns text or None on error."""
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"
    status, body = await session.get(url, params={"ref": ref})
    if status != 200 or not isinstance(body, dict):
        return None
    if body.get("size", 0) > MAX_FILE_BYTES:
        logger.debug("Skipping large file %s (%d bytes)", path, body.get("size"))
        return None
    content_b64 = body.get("content", "")
    try:
        return base64.b64decode(content_b64.replace("\n", "")).decode("utf-8", errors="replace")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Commit scraper
# ---------------------------------------------------------------------------

async def _process_commit(
    session: GitHubSession,
    owner: str, repo: str,
    commit: Dict[str, Any],
    repo_meta: Dict[str, Any],
) -> List[IaCRecord]:
    """
    Given a commit dict from the search API, fetch its full details and
    build one IaCRecord per changed IaC file.
    """
    sha = commit.get("sha", "")
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits/{sha}"
    status, detail = await session.get(url)
    if status != 200 or not isinstance(detail, dict):
        return []

    parents = detail.get("parents", [])
    parent_sha = parents[0]["sha"] if parents else None

    commit_meta = detail.get("commit", {})
    message = commit_meta.get("message", "")
    date    = (commit_meta.get("author") or {}).get("date", "")
    author  = (commit_meta.get("author") or {}).get("name", "")

    records: List[IaCRecord] = []

    files = detail.get("files", []) or []
    tasks = []
    for f in files:
        file_path = f.get("filename", "")
        if not _is_iac_path(file_path):
            continue
        patch = f.get("patch", "")
        status_str = f.get("status", "")
        if status_str in ("removed",):
            continue
        tasks.append((file_path, patch, f))

    # Fetch before/after content concurrently
    async def _fetch_pair(file_path: str, patch: str, file_info: Dict) -> Optional[IaCRecord]:
        # After content (new version)
        raw_url = file_info.get("raw_url", "")
        code_after: Optional[str] = None
        code_before: Optional[str] = None

        if raw_url:
            status2, body2 = await session.get(raw_url, accept="text/plain")
            if status2 == 200 and isinstance(body2, str):
                if len(body2) <= MAX_FILE_BYTES:
                    code_after = body2

        # Before content (parent version)
        if parent_sha and file_info.get("status") not in ("added",):
            code_before = await _get_file_at_ref(session, owner, repo, file_path, parent_sha)

        if not code_before and not patch:
            return None

        # Reconstruct before from after + reverse patch if API failed
        if not code_before and patch and code_after:
            code_before = _reverse_apply_patch(code_after, patch)

        if not code_before:
            code_before = f"# [before content unavailable]\n{patch}"

        # Detect IaC tool
        tool = detect_iac_tool(file_path, code_before)
        if tool == "unknown" and code_after:
            tool = detect_iac_tool(file_path, code_after)
        if tool == "unknown":
            return None

        # Classify smells
        if patch:
            smells_before, _ = classify_diff_smells(patch)
        else:
            smells_before = classify_smells(code_before)

        # Only include if we found smells OR the commit message mentions security
        has_security_signal = (
            smells_before
            or any(kw in message.lower() for kw in ["security", "vulner", "cve", "cwe", "exploit",
                                                      "credential", "password", "secret", "fix"])
        )
        if not has_security_signal:
            return None

        record_id = _make_record_id(f"{owner}/{repo}", sha, file_path)
        return IaCRecord(
            id=record_id,
            source="github_commit",
            iac_tool=tool,
            file_path=file_path,
            code_before=code_before,
            code_after=code_after,
            diff=patch or None,
            has_fix=bool(code_after),
            smells=smells_before,
            repo=f"{owner}/{repo}",
            repo_stars=repo_meta.get("stargazers_count"),
            repo_description=repo_meta.get("description"),
            commit_sha=sha,
            parent_sha=parent_sha,
            commit_message=message[:500] if message else None,
            commit_date=date,
            commit_author=author,
        )

    results = await asyncio.gather(*[_fetch_pair(fp, patch, fi) for fp, patch, fi in tasks])
    return [r for r in results if r is not None]


def _reverse_apply_patch(after: str, patch: str) -> str:
    """
    Very simple patch reversal: reconstruct 'before' by reversing added/removed lines.
    Not a full unified diff parser — just a heuristic for when the API is unavailable.
    """
    lines_after = after.splitlines()
    # From the patch, collect removed lines (they were in 'before')
    removed = [line[1:] for line in patch.splitlines() if line.startswith("-") and not line.startswith("---")]
    # Collect added lines (they are in 'after', not 'before')
    added   = {line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++")}
    before_lines = [l for l in lines_after if l not in added] + removed
    return "\n".join(before_lines)


async def _get_repo_meta(session: GitHubSession, owner: str, repo: str) -> Dict[str, Any]:
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    status, body = await session.get(url)
    if status == 200 and isinstance(body, dict):
        return body
    return {}


async def search_commits(
    queries: Optional[List[str]] = None,
    max_pages: int = MAX_SEARCH_PAGES,
    token: Optional[str] = None,
    progress=None,  # Optional[ProgressTracker]
) -> AsyncIterator[IaCRecord]:
    """
    Async generator that yields IaCRecord objects from GitHub commit search.
    Resumable: skips queries already marked done in the progress tracker.

    Args:
        queries:  list of search query strings (defaults to COMMIT_SEARCH_QUERIES)
        max_pages: number of result pages per query
        token:    GitHub token (overrides config default)
        progress: ProgressTracker instance for resumability
    """
    queries = queries or COMMIT_SEARCH_QUERIES

    async with GitHubSession(token=token or GITHUB_TOKEN) as session:
        for query in queries:
            # Skip already-completed queries (resumability)
            if progress and progress.is_commit_query_done(query):
                logger.info("Commit search: SKIP (already done) %r", query)
                continue

            logger.info("Commit search: %r", query)
            for page in range(1, max_pages + 1):
                url = f"{GITHUB_API_BASE}/search/commits"
                params = {
                    "q": query,
                    "sort": "author-date",
                    "order": "desc",
                    "per_page": COMMITS_PER_PAGE,
                    "page": page,
                }
                status, body = await session.search_get(url, params=params)
                if status != 200 or not isinstance(body, dict):
                    logger.warning("Search failed (status=%d) for query %r", status, query)
                    break

                items = body.get("items", [])
                if not items:
                    break

                logger.info("  Query %r — page %d — %d commits", query, page, len(items))

                # Group by repo to reuse meta fetch
                repo_groups: Dict[str, List[Dict]] = {}
                for item in items:
                    repo_info = item.get("repository", {})
                    full_name = repo_info.get("full_name", "unknown/unknown")
                    repo_groups.setdefault(full_name, []).append((item, repo_info))

                for full_name, pairs in repo_groups.items():
                    try:
                        owner, repo_name = full_name.split("/", 1)
                        repo_meta = await _get_repo_meta(session, owner, repo_name)
                        tasks = [
                            _process_commit(session, owner, repo_name, item, repo_meta)
                            for item, _ in pairs
                        ]
                        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                        for result in batch_results:
                            if isinstance(result, Exception):
                                logger.warning("Commit processing error (skipped): %s", result)
                                continue
                            for r in result:
                                yield r
                    except Exception as exc:
                        logger.warning("Repo %s skipped due to error: %s", full_name, exc)
                        continue

                total = body.get("total_count", 0)
                if page * COMMITS_PER_PAGE >= min(total, 1000):
                    break

            # Mark query done after all pages fetched
            if progress:
                progress.mark_commit_query_done(query)


# ---------------------------------------------------------------------------
# Code search scraper (insecure patterns → insecure-only records)
# ---------------------------------------------------------------------------

async def search_code(
    queries: Optional[List[str]] = None,
    max_pages: int = 3,
    token: Optional[str] = None,
    progress=None,  # Optional[ProgressTracker]
) -> AsyncIterator[IaCRecord]:
    """
    Async generator that yields insecure IaCRecord objects (has_fix=False)
    from GitHub code search. Resumable via progress tracker.
    """
    queries = queries or CODE_SEARCH_QUERIES

    async with GitHubSession(token=token or GITHUB_TOKEN) as session:
        for query in queries:
            if progress and progress.is_code_query_done(query):
                logger.info("Code search: SKIP (already done) %r", query)
                continue

            logger.info("Code search: %r", query)
            for page in range(1, max_pages + 1):
                url = f"{GITHUB_API_BASE}/search/code"
                params = {"q": query, "per_page": 30, "page": page}
                status, body = await session.search_get(url, params=params)
                if status != 200 or not isinstance(body, dict):
                    logger.warning("Code search failed (status=%d)", status)
                    break

                items = body.get("items", [])
                if not items:
                    break

                logger.info("  Code query %r — page %d — %d files", query, page, len(items))

                async def _fetch_code_item(item: Dict) -> Optional[IaCRecord]:
                    file_path = item.get("path", "")
                    repo_info = item.get("repository", {})
                    full_name = repo_info.get("full_name", "")
                    if not full_name or not _is_iac_path(file_path):
                        return None
                    owner, repo_name = full_name.split("/", 1)
                    branch = repo_info.get("default_branch", "main")
                    content = await _get_file_at_ref(session, owner, repo_name, file_path, branch)
                    if not content:
                        return None
                    tool = detect_iac_tool(file_path, content)
                    if tool == "unknown":
                        return None
                    smells = classify_smells(content)
                    if not smells:
                        return None
                    record_id = _make_record_id(full_name, branch, file_path)
                    return IaCRecord(
                        id=record_id,
                        source="github_code",
                        iac_tool=tool,
                        file_path=file_path,
                        code_before=content,
                        code_after=None,
                        diff=None,
                        has_fix=False,
                        smells=smells,
                        repo=full_name,
                        repo_stars=repo_info.get("stargazers_count"),
                        repo_description=repo_info.get("description"),
                    )

                results = await asyncio.gather(*[_fetch_code_item(item) for item in items])
                for r in results:
                    if r is not None:
                        yield r

                total = body.get("total_count", 0)
                if page * 30 >= min(total, 1000):
                    break

            if progress:
                progress.mark_code_query_done(query)
