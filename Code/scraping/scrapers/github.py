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
import random
import re
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import aiohttp

from scraping.config import (
    CODE_SEARCH_QUERIES,
    COMMIT_SEARCH_QUERIES,
    COMMITS_PER_PAGE,
    DATE_WINDOW_DAYS,
    DATE_WINDOW_END,
    DATE_WINDOW_START,
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
# Small helpers — rate limit math & date window iteration
# ---------------------------------------------------------------------------

def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _backoff(attempt: int, base: int = 2, cap: int = 300, jitter: bool = True) -> int:
    """Exponential backoff with optional ±25% jitter."""
    wait = min(cap, base * (2 ** attempt))
    if jitter:
        wait = int(wait * (0.75 + random.random() * 0.5))
    return max(1, wait)


def _iter_date_windows(
    start: date,
    end: date,
    days: int,
) -> List[Tuple[str, str]]:
    """
    Yield (start_iso, end_iso) tuples walking BACKWARD from `end` to `start`
    in `days`-long windows. Most recent first (yields the newest fixes first
    during a long scrape).
    """
    windows: List[Tuple[str, str]] = []
    cur_end = end
    while cur_end >= start:
        cur_start = max(start, cur_end - timedelta(days=days - 1))
        windows.append((cur_start.isoformat(), cur_end.isoformat()))
        cur_end = cur_start - timedelta(days=1)
    return windows


# ---------------------------------------------------------------------------
# Global shared rate limiter — ALL GitHubSession instances share this.
# Enforces the 5000 req/hr GitHub API limit across parallel scrapers.
# ---------------------------------------------------------------------------

class _GlobalRateLimiter:
    """
    Token-bucket rate limiter + circuit breaker shared across all
    GitHubSession instances.

    Enforces:
      - GitHub 5000 req/hr limit (via REST_REQUESTS_PER_SECOND interval)
      - Max MAX_CONCURRENT_REQUESTS in-flight requests
      - Serialised search API requests (30/min)
      - Circuit breaker: pauses ALL requests for a cooldown period after
        repeated 403/429 responses (secondary rate limit / abuse detection).
    """
    _instance: Optional["_GlobalRateLimiter"] = None

    # Circuit breaker thresholds
    _CB_FAIL_THRESHOLD = 3      # consecutive 403/429 before tripping
    _CB_COOLDOWN_SECS  = 600    # 10-minute pause when tripped

    def __init__(self) -> None:
        self._interval = 1.0 / REST_REQUESTS_PER_SECOND
        self._last_request_time: float = 0.0
        self._lock = asyncio.Lock()
        self._burst_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self._search_semaphore = asyncio.Semaphore(1)

        # Circuit-breaker state
        self._cb_fail_count = 0
        self._cb_pause_until: float = 0.0

        # Preemptive pause state (remaining quota low)
        self._quota_pause_until: float = 0.0

        # Dedup pause logging across concurrent coroutines
        self._logged_pause_until: float = 0.0

    @classmethod
    def get(cls) -> "_GlobalRateLimiter":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    async def _wait_for_pauses(self) -> None:
        while True:
            now = time.time()
            until = max(self._cb_pause_until, self._quota_pause_until)
            if until <= now:
                return
            wait = until - now
            if until > self._logged_pause_until + 1 and wait > 5:
                logger.info("Rate limiter paused until %s (%.0fs)",
                            time.strftime("%H:%M:%S", time.localtime(until)), wait)
                self._logged_pause_until = until
            await asyncio.sleep(min(wait, 30))

    async def acquire_rest(self) -> None:
        await self._wait_for_pauses()
        async with self._burst_semaphore:
            async with self._lock:
                now = asyncio.get_event_loop().time()
                wait = self._interval - (now - self._last_request_time)
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last_request_time = asyncio.get_event_loop().time()

    async def acquire_search(self) -> None:
        await self._wait_for_pauses()
        await self._search_semaphore.acquire()

    def release_search(self) -> None:
        self._search_semaphore.release()

    # ------------------------------------------------------------------
    # Circuit breaker interactions
    # ------------------------------------------------------------------

    def on_success(self) -> None:
        self._cb_fail_count = 0

    def on_auth_failure(self) -> None:
        """Record a 403/429 response. May trip the circuit breaker."""
        self._cb_fail_count += 1
        if self._cb_fail_count >= self._CB_FAIL_THRESHOLD:
            self._cb_pause_until = time.time() + self._CB_COOLDOWN_SECS
            logger.error(
                "Circuit breaker TRIPPED after %d consecutive auth failures — "
                "pausing all requests for %ds",
                self._cb_fail_count, self._CB_COOLDOWN_SECS,
            )
            self._cb_fail_count = 0

    def preemptive_pause(self, seconds: float) -> None:
        """Pause requests for N seconds (called when remaining quota is low)."""
        self._quota_pause_until = max(self._quota_pause_until, time.time() + seconds)


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
                  accept: Optional[str] = None,
                  max_retries: int = 4) -> Tuple[int, Any]:
        """
        GET with robust rate-limit handling:

        - Honours Retry-After header (secondary rate limit / abuse detection)
        - Honours X-RateLimit-Reset on 403/429
        - Exponential backoff with jitter on transient 5xx and network errors
        - Preemptive pause when X-RateLimit-Remaining drops below 20
        - Circuit breaker trips after repeated 403/429
        """
        hdrs = {}
        if accept:
            hdrs["Accept"] = accept

        for attempt in range(max_retries):
            await self._rl.acquire_rest()

            try:
                async with self._session.get(
                    url, params=params, headers=hdrs,
                    timeout=aiohttp.ClientTimeout(
                        total=25, connect=10, sock_connect=10, sock_read=20,
                    ),
                ) as resp:
                    status = resp.status

                    # Rate limit headers (present on most authenticated calls)
                    remaining = _safe_int(resp.headers.get("X-RateLimit-Remaining"), default=999)
                    reset_at  = _safe_int(resp.headers.get("X-RateLimit-Reset"), default=0)
                    retry_after = _safe_int(resp.headers.get("Retry-After"), default=0)

                    # Preemptive pause if quota is nearly exhausted
                    if remaining <= 20 and reset_at > 0:
                        cooldown = max(reset_at - int(time.time()), 5)
                        logger.warning(
                            "Quota low (remaining=%d) — preemptive pause %ds",
                            remaining, cooldown,
                        )
                        self._rl.preemptive_pause(cooldown)

                    # ----------------------------------------------------
                    # 429 / 403: rate limit or secondary (abuse) limit
                    # ----------------------------------------------------
                    if status in (429, 403):
                        self._rl.on_auth_failure()
                        if retry_after:
                            wait = retry_after + 2
                        elif reset_at:
                            wait = max(reset_at - int(time.time()) + 2, 30)
                        else:
                            wait = _backoff(attempt, base=30, cap=600)
                        logger.warning(
                            "Rate-limit response %d — sleeping %ds (attempt %d/%d) url=%s",
                            status, wait, attempt + 1, max_retries, url,
                        )
                        await asyncio.sleep(wait)
                        continue

                    # ----------------------------------------------------
                    # 202: GitHub still computing — just wait and retry
                    # ----------------------------------------------------
                    if status == 202:
                        await asyncio.sleep(3 + attempt * 2)
                        continue

                    # ----------------------------------------------------
                    # 5xx: transient — exponential backoff
                    # ----------------------------------------------------
                    if 500 <= status < 600:
                        wait = _backoff(attempt, base=2, cap=120)
                        logger.warning(
                            "Server error %d — retry in %ds (attempt %d/%d)",
                            status, wait, attempt + 1, max_retries,
                        )
                        await asyncio.sleep(wait)
                        continue

                    # ----------------------------------------------------
                    # 2xx / 4xx (not rate limit): return directly
                    # ----------------------------------------------------
                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct:
                        try:
                            body = await resp.json(content_type=None)
                        except Exception:
                            body = None
                    else:
                        try:
                            raw = await resp.read()
                            body = raw.decode("utf-8", errors="replace")
                        except Exception:
                            body = None

                    if 200 <= status < 300:
                        self._rl.on_success()
                    return status, body

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                wait = _backoff(attempt, base=2, cap=20)
                logger.warning(
                    "Network error %s — retry in %ds (attempt %d/%d)",
                    type(exc).__name__, wait, attempt + 1, max_retries,
                )
                await asyncio.sleep(wait)
                continue

        logger.error("GET failed after %d attempts: %s", max_retries, url)
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
        before_quality = "api"
        if not code_before and patch and code_after:
            code_before, before_quality = _reverse_apply_patch(code_after, patch)

        if not code_before:
            # Final fallback: we keep the record but mark it so downstream
            # tiering can route it to a lower quality bucket.
            code_before = f"# [before content unavailable]\n{patch}"
            before_quality = "unavailable"

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
            code_before_quality=before_quality,
        )

    results = await asyncio.gather(*[_fetch_pair(fp, patch, fi) for fp, patch, fi in tasks])
    return [r for r in results if r is not None]


def _reverse_apply_patch(after: str, patch: str) -> Tuple[str, str]:
    """
    Reconstruct 'before' content by reverse-applying a unified diff to 'after'.

    Uses the `unidiff` library to parse hunk headers and apply them exactly,
    so if the patch covers the full file we recover `before` losslessly.
    For sparse patches (partial hunks), we still reverse-apply the known
    hunks and leave the rest of the file untouched — much better than the
    earlier set-based heuristic which lost line ordering.

    Returns: (before_text, quality)
      quality: 'exact'   — patch covered the whole file
               'partial' — patch covered only parts (still useful)
               'heuristic' — parsing failed, fell back to naive reversal
    """
    try:
        from unidiff import PatchSet  # local import keeps top-level deps slim
    except Exception:
        # Fallback: keep the old naive behaviour but clearly tag it.
        lines_after = after.splitlines()
        removed = [l[1:] for l in patch.splitlines() if l.startswith("-") and not l.startswith("---")]
        added = {l[1:] for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++")}
        before_lines = [l for l in lines_after if l not in added] + removed
        return "\n".join(before_lines), "heuristic"

    # `unidiff` expects a full patch with a header. GitHub's per-file `patch`
    # field omits the --- / +++ preamble, so synthesise one.
    if not patch.lstrip().startswith(("---", "diff ")):
        header = "--- a/file\n+++ b/file\n"
        patch_text = header + patch
    else:
        patch_text = patch

    try:
        ps = PatchSet(patch_text)
    except Exception:
        return _reverse_apply_patch(after, patch)[0], "heuristic"  # unlikely but safe

    after_lines = after.splitlines(keepends=False)
    before_lines = list(after_lines)
    covered_lines = 0

    # Walk hunks in reverse so later line-number edits don't shift earlier ones.
    for pf in ps:
        for hunk in reversed(list(pf)):
            # target_start is 1-based line in 'after'; we slice it out and
            # replace with the 'source' (before) lines from the hunk.
            tgt_start = hunk.target_start - 1 if hunk.target_start > 0 else 0
            tgt_end   = tgt_start + hunk.target_length
            source_lines = [
                str(line)[1:].rstrip("\n")
                for line in hunk
                if line.is_context or line.is_removed
            ]
            before_lines[tgt_start:tgt_end] = source_lines
            covered_lines += hunk.target_length

    quality = "exact" if covered_lines >= len(after_lines) else "partial"
    return "\n".join(before_lines), quality


# In-memory LRU for repo metadata — the commit scraper sees the same repo
# dozens of times per window, and each previous iteration was making a fresh
# /repos/owner/name call (~10% of all API traffic). Cap at 4000 to bound
# memory; evict oldest when full.
_REPO_META_CACHE: Dict[str, Dict[str, Any]] = {}
_REPO_META_CACHE_MAX = 4000


async def _get_repo_meta(session: GitHubSession, owner: str, repo: str) -> Dict[str, Any]:
    key = f"{owner}/{repo}"
    cached = _REPO_META_CACHE.get(key)
    if cached is not None:
        return cached

    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    status, body = await session.get(url)
    meta = body if (status == 200 and isinstance(body, dict)) else {}

    if len(_REPO_META_CACHE) >= _REPO_META_CACHE_MAX:
        # Evict ~10% of oldest entries (dict preserves insertion order on 3.7+)
        drop = max(1, _REPO_META_CACHE_MAX // 10)
        for k in list(_REPO_META_CACHE.keys())[:drop]:
            _REPO_META_CACHE.pop(k, None)
    _REPO_META_CACHE[key] = meta
    return meta


async def _run_commit_page(
    session: GitHubSession,
    q: str,
    page: int,
) -> Tuple[int, List[Dict], int]:
    """Run one commit-search page. Returns (status, items, total_count)."""
    url = f"{GITHUB_API_BASE}/search/commits"
    params = {
        "q": q,
        "sort": "author-date",
        "order": "desc",
        "per_page": COMMITS_PER_PAGE,
        "page": page,
    }
    status, body = await session.search_get(url, params=params)
    if status != 200 or not isinstance(body, dict):
        return status, [], 0
    return status, body.get("items", []) or [], _safe_int(body.get("total_count"))


async def _yield_records_from_commit_items(
    session: GitHubSession,
    items: List[Dict],
) -> AsyncIterator[IaCRecord]:
    """Group by repo (to reuse meta fetch), process commits, yield records."""
    repo_groups: Dict[str, List[Dict]] = {}
    for item in items:
        repo_info = item.get("repository", {}) or {}
        full_name = repo_info.get("full_name", "unknown/unknown")
        repo_groups.setdefault(full_name, []).append((item, repo_info))

    for full_name, pairs in repo_groups.items():
        try:
            owner, repo_name = full_name.split("/", 1)
        except ValueError:
            continue
        try:
            repo_meta = await _get_repo_meta(session, owner, repo_name)
            tasks = [
                _process_commit(session, owner, repo_name, item, repo_meta)
                for item, _ in pairs
            ]
            batch = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch:
                if isinstance(result, Exception):
                    logger.warning("Commit processing error (skipped): %s", result)
                    continue
                for r in result:
                    yield r
        except Exception as exc:
            logger.warning("Repo %s skipped due to error: %s", full_name, exc)
            continue


async def search_commits(
    queries: Optional[List[str]] = None,
    max_pages: int = MAX_SEARCH_PAGES,
    token: Optional[str] = None,
    progress=None,  # Optional[ProgressTracker]
    use_date_windows: bool = True,
) -> AsyncIterator[IaCRecord]:
    """
    Async generator yielding IaCRecord from GitHub commit search.

    Resumable at per-(query, window, page) granularity. For each query we
    iterate date windows walking backward in time from DATE_WINDOW_END to
    DATE_WINDOW_START in DATE_WINDOW_DAYS-long steps. Each window is an
    independent unit in the progress tracker — so the same base query can
    yield 10–50× more unique commits than a single un-windowed search.

    Args:
        queries:          list of base query strings
        max_pages:        max pages per window
        token:            GitHub token override
        progress:         ProgressTracker (required for resumability)
        use_date_windows: if False, fall back to single un-windowed search
    """
    queries = queries or COMMIT_SEARCH_QUERIES

    if use_date_windows:
        windows = _iter_date_windows(DATE_WINDOW_START, DATE_WINDOW_END, DATE_WINDOW_DAYS)
    else:
        windows = [("", "")]  # single no-window pass

    async with GitHubSession(token=token or GITHUB_TOKEN) as session:
        for query in queries:
            if progress and progress.is_commit_query_done(query):
                logger.info("Commit search: SKIP (query done) %r", query)
                continue

            for win_start, win_end in windows:
                if win_start:
                    q = f"{query} committer-date:{win_start}..{win_end}"
                    window_label = f"{win_start}..{win_end}"
                else:
                    q = query
                    window_label = "all-time"

                if progress and progress.is_window_done(query, win_start, win_end):
                    continue

                start_page = 1
                if progress:
                    start_page = progress.window_last_page(query, win_start, win_end) + 1

                if start_page > max_pages:
                    if progress:
                        progress.mark_window_done(query, win_start, win_end)
                    continue

                logger.info("Commit search: %r [%s] pages %d..%d",
                            query, window_label, start_page, max_pages)

                consecutive_empty = 0
                for page in range(start_page, max_pages + 1):
                    status, items, total = await _run_commit_page(session, q, page)

                    if status != 200:
                        logger.warning("Search failed (status=%d) query=%r window=%s page=%d",
                                       status, query, window_label, page)
                        if progress:
                            progress.increment_errors()
                        break

                    if not items:
                        consecutive_empty += 1
                        if consecutive_empty >= 2:
                            break
                        continue
                    consecutive_empty = 0

                    logger.info("  %r [%s] page %d — %d commits (total=%d)",
                                query, window_label, page, len(items), total)

                    async for r in _yield_records_from_commit_items(session, items):
                        yield r

                    if progress:
                        progress.mark_window_page(query, win_start, win_end, page)

                    if page * COMMITS_PER_PAGE >= min(total, 1000):
                        break

                if progress:
                    progress.mark_window_done(query, win_start, win_end)

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

            start_page = 1
            if progress:
                start_page = progress.code_query_last_page(query) + 1
            if start_page > max_pages:
                if progress:
                    progress.mark_code_query_done(query)
                continue

            logger.info("Code search: %r (pages %d..%d)", query, start_page, max_pages)
            for page in range(start_page, max_pages + 1):
                url = f"{GITHUB_API_BASE}/search/code"
                params = {"q": query, "per_page": 30, "page": page}
                status, body = await session.search_get(url, params=params)
                if status != 200 or not isinstance(body, dict):
                    logger.warning("Code search failed (status=%d)", status)
                    if progress:
                        progress.increment_errors()
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

                if progress:
                    progress.mark_code_query_page(query, page)

                total = body.get("total_count", 0)
                if page * 30 >= min(total, 1000):
                    break

            if progress:
                progress.mark_code_query_done(query)
