# IaC Security Dataset Scraper

This module collects a large-scale dataset of Infrastructure as Code (IaC) security smells with before/after fix pairs. It was built as part of a Master's thesis on agentic IaC security analysis at the Faculté des Sciences de Sfax.

The resulting dataset contains **33,667 unique records** across five IaC technologies: Terraform, Kubernetes, Ansible, Docker, and CloudFormation.

---

## How It Works

The scraper uses **five** complementary strategies to collect as much data as possible.

### 1. GitHub Commit Search with date-window partitioning

Searches GitHub for commits whose messages contain security-related keywords (e.g. `fix hardcoded credentials terraform`). For each matching commit:

1. Identifies which changed files are IaC files (`.tf`, `.yaml`, `.yml`, `Dockerfile`)
2. Downloads the file **before** the fix using the parent commit SHA
3. Downloads the file **after** the fix from the commit's current state
4. Extracts the unified diff
5. Detects which security smell was fixed using regex patterns on the removed lines

**Date-window partitioning**: GitHub search is hard-capped at 1000 results per query. To break that cap, every base query is fanned out across ~295 non-overlapping 14-day `committer-date:` windows walking backward from today to 2015-01-01. Each window is tracked independently in the progress file, so the effective discovery space is `(base queries) × (windows) ≈ 3000 × 295 ≈ 900,000` unique search scopes.

The base query set itself is generated programmatically from `(fix_verb × security_issue × iac_tool)` + CWE IDs + scanner rule prefixes, yielding ~3,000 queries out of the box.

### 2. GHArchive discovery mode (`--gharchive`)

Downloads hourly public dumps from https://data.gharchive.org/, pre-filters `PushEvent`s by a repo-name regex (terraform / k8s / docker / ansible / …), then resolves each push's head commit through the GitHub Core API (which has 166× more quota than Search API). One hour of GHArchive typically yields **~1,700 candidate IaC-repo pushes**, so a week of continuous discovery produces ~280k candidate commits with zero Search-API usage.

### 3. IaC Security Scanner Resources

Checkov and KICS include labelled example files as part of their test suites. Each security check has a "failed" example and a "passed" example — a natural before/after pair. These are scraped directly from the repositories:

- **Checkov** (bridgecrewio/checkov)
- **KICS** (Checkmarx/kics)
- **tfsec/defsec** (aquasecurity/tfsec, aquasecurity/defsec)

### 4. Known Vulnerable Repositories

Curated repositories with intentionally insecure IaC configurations:

- **TerraGoat** — deliberately vulnerable Terraform
- **Kubernetes-Goat** — deliberately vulnerable Kubernetes manifests
- **OWASP WrongSecrets** — secrets management anti-patterns

These contribute insecure-only records (no fix available) useful for smell detection training.

### 5. Scanner-validated labels (`--validate`)

After scraping, a separate pass runs **Checkov**, **tfsec**, and **KICS** on every `code_before` / `code_after` and attaches a `validated_smells_before` / `validated_smells_after` list of real findings (rule_id, severity, CWE, line number). This converts the regex-labelled dataset into a **scanner-validated** ground-truth dataset — which is what makes it usable for downstream LLM fine-tuning and benchmarking contributions.

Install any subset of the scanners; the validator auto-detects which are available on `$PATH`.

### 2. IaC Security Scanner Resources (1,855 records)

Checkov and KICS include labelled example files as part of their test suites. Each security check has a "failed" example and a "passed" example — a natural before/after pair. These are scraped directly from the repositories:

- **Checkov** (bridgecrewio/checkov): 502 records
- **KICS** (Checkmarx/kics): 1,336 records
- **tfsec** (aquasecurity/tfsec): 17 records

### 3. Known Vulnerable Repositories (464 records)

Curated repositories with intentionally insecure IaC configurations:

- **TerraGoat** — deliberately vulnerable Terraform
- **Kubernetes-Goat** — deliberately vulnerable Kubernetes manifests
- **OWASP WrongSecrets** — secrets management anti-patterns

These contribute insecure-only records (no fix available) useful for smell detection training.

---

## Folder Structure

```
scraping/
  main.py                  — CLI entry point
  config.py                — all settings (queries, rate limits, paths)
  schemas.py               — IaCRecord and SmellAnnotation data models
  check_progress.sh        — monitor running scrapers

  scrapers/
    github.py              — GitHub Commit Search + Code Search scrapers
    known_repos.py         — scraper for TerraGoat, KICS, Checkov, tfsec

  processors/
    classifier.py          — detects IaC tool type + classifies security smells
    merger.py              — deduplication + train/val/test split

  storage/
    writer.py              — JSONL append-mode writer
    progress.py            — resumability tracker (survives shutdown)

  tests/
    test_schemas.py
    test_classifier.py
    test_merger.py

  output/                  — generated at runtime (not in git)
    raw/                   — Account 1 raw JSONL files
    raw2/                  — Account 2 raw JSONL files
    merged/                — final deduplicated dataset
    progress_1.json        — Account 1 progress (for resuming)
    progress_2.json        — Account 2 progress (for resuming)
```

---

## Setup

```bash
# Install dependencies
pip install aiohttp python-dotenv

# Create a .env file with your GitHub token(s)
echo "GITHUB_TOKEN=ghp_your_token_here" > .env
echo "GITHUB_TOKEN_2=ghp_second_token_here" >> .env  # optional, for two-account mode
```

You need a GitHub Personal Access Token (classic) with no special scopes — public repo access is enough.

---

## Running the Scraper

### Single account (simplest)
```bash
python -m scraping.main --all
```

### Two accounts in parallel (recommended for large runs)
Open two terminals:
```bash
# Terminal 1 — first half of queries + odd-indexed repos
python -m scraping.main --account 1

# Terminal 2 — second half of queries + even-indexed repos
python -m scraping.main --account 2
```

### Merge results when done (or any time during the run)
```bash
python -m scraping.main --merge
```

### Monitor progress
```bash
bash scraping/check_progress.sh
```

### Week-long unattended runs (`run_forever.sh`)

For multi-day scrapes, use the supervisor script:

```bash
# default: up to 7 days (set MAX_RUNTIME_HOURS for shorter/longer)
./scraping/run_forever.sh 1       # account 1
./scraping/run_forever.sh 2       # account 2 (separate terminal)

MAX_RUNTIME_HOURS=168 ./scraping/run_forever.sh 1
```

The supervisor restarts the scraper on any non-clean exit: watchdog stalls (exit 2 → 30 s backoff + retry), unexpected crashes (→ 2 min backoff + retry), network blips, kernel signals. It stops cleanly when the scraper exhausts its queries (exit 0).

### Options
| Flag | Description |
|---|---|
| `--account 1/2` | Run as account 1 or 2 (recommended for multi-account) |
| `--all` | Run all scrapers with a single account |
| `--github-commits` | Run only the commit search scraper |
| `--github-code` | Run only the code search scraper |
| `--known-repos` | Run only the known vulnerable repos scraper |
| `--gharchive` | Enable GHArchive discovery mode (bypasses Search API) |
| `--gharchive-hours N` | Hours of GHArchive to scan (default 24) |
| `--validate PATH` | Run Checkov/tfsec/KICS on an existing JSONL and attach validated labels |
| `--validate-workers N` | Parallel validator workers (default 4) |
| `--validate-limit N` | Max records to validate (for smoke tests) |
| `--merge` | Merge all raw JSONL files into one deduplicated dataset |
| `--max-pages N` | Search pages per query/window (default: 10) |
| `--verbose` | Enable debug logging |

---

## Resumability & crash-safety

The scraper is engineered for week-long unattended runs:

- **Per-page progress**: each `(query, date_window, page)` tuple is tracked independently in `progress_*.json`. A crash mid-query resumes on the next page, not the next query.
- **Atomic progress writes**: the progress file is always written via `tmp + os.replace()`, so a crash during a write cannot produce a half-corrupted file.
- **Crash-safe JSONL writes**: `os.fsync()` every 50 records. On open, the writer seeks to EOF, walks backward to the last newline, and truncates any trailing partial line, so a power-off mid-write leaves a clean file.
- **Robust rate-limit layer**: honours `Retry-After`, `X-RateLimit-Reset`, exponential backoff with jitter on 403/429/5xx, preemptive pause when remaining quota drops below 20, and a circuit breaker that pauses all requests for 10 minutes after 3 consecutive 403 responses (GitHub abuse-detection secondary limit).
- **Watchdog + supervisor**: if no new records are written for 15 minutes, the scraper exits with code 2. The `run_forever.sh` supervisor restarts it. Crashes are logged to `output/run_forever*.log`.
- **Metrics**: one JSON line per minute to `output/metrics_*.jsonl` (records, rate/min, API-call count, status-code histogram, idle time, current query).
- **Hash dedup on resume**: SHA-256 of `code_before` is computed for every record and matched against previously written hashes, so re-runs never produce duplicates.

---

## Output Format

Each record is one JSON object per line (JSONL):

```json
{
  "id": "a1b2c3d4",
  "source": "github_commit",
  "iac_tool": "terraform",
  "file_path": "main.tf",
  "code_before": "...",
  "code_after": "...",
  "diff": "--- a/main.tf\n+++ b/main.tf\n...",
  "has_fix": true,
  "smells": [
    {
      "type": "hardcoded_credential",
      "cwe": "CWE-798",
      "checkov_id": "CKV_AWS_41",
      "severity": "CRITICAL",
      "category": "Security",
      "description": "Hardcoded credential detected"
    }
  ],
  "labels": ["hardcoded_credential", "CWE-798", "CRITICAL"],
  "split": "train",
  "repo": "owner/repo",
  "repo_stars": 142,
  "commit_sha": "abc123...",
  "commit_message": "fix: remove hardcoded AWS credentials",
  "commit_date": "2024-03-15T10:22:00Z",
  "content_hash": "sha256:..."
}
```

---

## Dataset Statistics

| Property | Value |
|---|---|
| Total unique records | 33,667 |
| With fix (before + after) | 32,960 (97.9%) |
| Without fix (insecure only) | 707 (2.1%) |
| Duplicates removed | 4,165 |
| Train / Val / Test | 26,931 / 3,365 / 3,371 |
| IaC tools | 5 |
| Security smell types | 18 |
| Source repositories | >2,000 |

### By IaC Tool

| Tool | Records | % |
|---|---|---|
| Terraform | 16,386 | 48.7% |
| Kubernetes | 9,242 | 27.5% |
| Ansible | 4,498 | 13.4% |
| Docker | 2,471 | 7.3% |
| CloudFormation | 1,070 | 3.2% |

---

## Security Smell Types

18 smell types mapped to CWE identifiers, detected by regex on the diff:

| Smell | CWE | Severity |
|---|---|---|
| hardcoded_credential | CWE-798 | CRITICAL |
| hardcoded_password | CWE-259 | HIGH |
| secrets_in_env | CWE-798 | CRITICAL |
| overly_permissive_cidr | CWE-732 | HIGH |
| overly_permissive_acl | CWE-732 | HIGH |
| overly_permissive_iam | CWE-732 | HIGH |
| privileged_container | CWE-250 | HIGH |
| root_user | CWE-250 | MEDIUM |
| allow_privilege_escalation | CWE-250 | HIGH |
| missing_encryption | CWE-312 | HIGH |
| unencrypted_database | CWE-312 | HIGH |
| insecure_tls | CWE-326 | HIGH |
| missing_network_policy | CWE-923 | MEDIUM |
| public_access_block_disabled | CWE-732 | HIGH |
| missing_resource_limits | CWE-400 | MEDIUM |
| logging_disabled | CWE-778 | MEDIUM |
| versioning_disabled | CWE-693 | LOW |
| unpinned_base_image | CWE-1357 | MEDIUM |

---

## Extending the Dataset

To collect more data, edit `config.py`:

**Add more search queries** — extend `COMMIT_SEARCH_QUERIES`:
```python
COMMIT_SEARCH_QUERIES = [
    ...
    "fix insecure helm chart",
    "CWE-306 fix terraform",
    "remove eval dynamic code",
]
```

**Add more known repos** — extend `KNOWN_REPOS`:
```python
KNOWN_REPOS = [
    ...
    {"owner": "org", "repo": "my-vulnerable-repo", "type": "vulnerable"},
]
```

**Increase pages per query** — for bigger runs:
```bash
python -m scraping.main --account 1 --max-pages 30
```

**Add a new smell type** — in `processors/classifier.py`, add an entry to `SMELL_PATTERNS`:
```python
{
    "type": "my_new_smell",
    "cwe": "CWE-XXX",
    "checkov_id": "CKV_XX_00",
    "severity": "HIGH",
    "category": "Security",
    "description": "Description of the smell",
    "pattern": re.compile(r"your_regex_pattern", re.IGNORECASE),
},
```

---

## Running Tests

```bash
cd Code/
python -m pytest scraping/tests/ -v
```

88 tests — all passing.

---

## Rate Limiting

The scraper respects GitHub's API limits:
- **5,000 requests/hour** per token
- Global rate limiter shared across all scrapers: **1.1 req/sec**
- Search API: additional 2.1s delay between pages (30 searches/min limit)
- Automatic retry on 429 responses

With two accounts running in parallel, effective throughput is ~2 req/sec = ~7,200 req/hour combined.

---

## Dataset Download

The full dataset (33,667 records, JSONL format) is available separately at:
**https://github.com/Ahmedouyahya/iac-security-dataset**
