# Scraping Pipeline Plan

Goal: maximize **useful** IaC security fix data without discarding volume. Combine v1 salvage + v2 improvements + new sources, label everything with scanner ground truth, tier by quality.

## Status legend
- [x] done & tested
- [~] in progress
- [ ] pending

---

## Quality tiers

The dataset is released by tier so v2 can be both larger and more honest about label quality.

| Tier | Name | Definition | Use |
|---|---|---|---|
| A | Gold | Before/after fix pair where scanner findings are present before and disappear after. | Trusted fix benchmarks, high-quality fine-tuning, headline stats. |
| B | Silver | Before/after fix pair with strong evidence from scanner-before findings, regex smell labels, or strong security commit text. | Fix training and analysis with caution. |
| C | Bronze | Detection-quality insecure examples without a strong fix pair, including new-file additions or real code with scanner/regex findings. | Smell detection and classification. |
| D | Weak | Weak/noisy raw material with incomplete evidence or no confirmed smell. | Triage pool only; not trusted training data. |

LLM review may help sort B/C/D, explain fixes, and remove noise, but Tier A remains scanner-confirmed only.

---

## Phase 1 — Classifier quality [x]
- [x] Extended `SMELL_TAXONOMY` to 44 entries (CWE + severity + checkov_ids)
- [x] Removed catastrophic-backtracking patterns (absence checks → delegated to Checkov)
- [x] Benchmark: 0 timeouts, 5.4ms avg over 33,667 records
- [x] Diff-based classification (before vs after smells separately)

## Phase 2 — Scraper throughput [x]
- [x] Request timeouts tightened (`total=25, connect=10, sock_read=20`)
- [x] Retry backoff cap reduced 60s→20s, max_retries 6→4
- [x] `_REPO_META_CACHE` LRU (4000 entries, 10% eviction)
- [x] Unidiff-based `_reverse_apply_patch` returning `(text, quality)`
- [x] Quality tag written into every new record (`code_before_quality`)

## Phase 3 — Tiering & salvage [x]
- [x] `processors/tiering.py` with A/B/C/D logic
- [x] `scripts/salvage_v1.py` — detects new-file diffs, recovers before-content via unidiff, re-classifies
- [x] Salvage results: 33,667 → 14,368 new smells; tiers B=7721, C=5263, D=20683 pre-validation
- [x] Tier logic widened so validated detection-only records reach Tier C (verified on 77-rec sample)

## Phase 4 — Ground-truth validation [~]
- [x] `processors/validator.py` — Checkov subprocess, 4-worker `ProcessPoolExecutor`
- [x] `validated_smells_before` / `validated_smells_after` attached to records
- [~] Validator partially completed on salvaged v1: 31,748 / 33,667 records
- [ ] Finish/resume validation for the remaining 1,919 salvaged records
- [ ] Re-tier after validation; current recompute shows A=2,324 already available

## Phase 5 — New sources
### 5a. GitLab scraper [~]
- [x] Implemented `scrapers/gitlab.py`
- [x] First run produced 5,498 records from 1,623 projects / 7,281 commits
- [ ] Add resumable progress tracking and deeper historical pagination
- [ ] Normalize/salvage GitLab placeholders and recompute tiers

### 5b. OSV.dev + NVD CVE feed [x] — **low yield, deprioritised**
- Implemented: `scrapers/osv.py` (seed extraction) + `scrapers/osv_hydrate.py` (full records)
- Smoke-tested: "terraform" keyword → 33 CVEs → 17 fix-commit seeds → **0 IaC records**
- **Root cause:** CVE catalog tracks *tool* vulnerabilities (controller Go/Ruby code), not
  *user-written IaC misconfigurations*. Fix commits touch source code, not `.tf`/`.yaml`.
- Kept as a skippable module for completeness; not a volume driver.
- Real Tier A source is Checkov validation of our existing before/after pairs (Phase 4).

### 5c. Academic datasets [ ] (stretch)
- Rahman et al. Ansible / Chef smell datasets
- GLITCH benchmark dataset
- Terraform / Ansible / Helm registry historical diffs

## Phase 6 — Throughput scaling [ ]
- [ ] GraphQL batch fetch for multi-file content (one round-trip per commit)
- [ ] Concurrent date-window processing (not sequential)
- [ ] Validator: increase workers if CPU headroom allows

## Phase 7 — Unified dataset [ ]
- [x] Added `scripts/build_v2.py` for v2 normalization, quality-aware dedup, re-tiering, manifest, and tiered exports
- [x] Built first v2 snapshot under `output/v2/`: full=39,165, gold=2,324, fix-pairs=11,608, detection=16,159
- [x] Dedup on `(repo, commit_sha, file_path)` first, content hash fallback
- [x] Recompute tier during v2 build
- [x] Emit manifest with counts per tier, source, tool, quality, smell, and scanner
- [ ] Add current raw GitHub/GHArchive snapshots into the v2 build after salvage/validation

## Phase 8 — Parallel v2 execution [~]
- [~] Run data expansion and quality improvement in parallel, but only on separate output paths
- [x] Lane A: build v2 normalizer/merger/exporter under `output/v2/`
- [~] Lane B: attempted GitHub account 1 + account 2 restart; currently blocked by GitHub API 401 from configured tokens
- [~] Lane C: GitLab deep expansion running into `output/gitlab/dataset_deep_20260511.jsonl`
- [~] Lane D: Checkov validation running/resuming into `output/dataset_v1_validated.jsonl`
- [~] Auto-rebuild queued: once validation exits, `scripts/build_v2.py` rebuilds `output/v2/`
- [x] Publish first tiered v2 releases: gold, fix-pairs, detection, full

---

## Known limits & risks
- Only Checkov is installed locally right now. Checkov supports multiple frameworks in this pipeline, but KICS/tfsec/Trivy/Terrascan would improve validation coverage and confidence.
- GitHub search API caps at 1000 results per query. Already partially mitigated by date-window splitting.
- GitLab search API is similar but token scopes differ — will need `read_api` scope.
- OSV feed is high-quality but low-volume (thousands, not tens of thousands).

## Priority order (revised after 5b finding)
1. **Build Phase 7/8 v2 exporter** so all current and future data has a trustworthy release path
2. **Finish Phase 4 validator + re-tier** to expose existing Tier A records
3. **Normalize and expand GitLab** because it has already shown good volume
4. **Continue GitHub/GHArchive long runs** because most query windows are still untouched
5. **Install more scanners** to convert more records from regex-only to validated
6. **Phase 5c academic datasets** (Rahman Ansible/Chef, GLITCH) — authoritative labels
