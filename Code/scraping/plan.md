# Scraping Pipeline Plan

Goal: maximize **useful** IaC security fix data without discarding volume. Combine v1 salvage + v2 improvements + new sources, label everything with scanner ground truth, tier by quality.

## Status legend
- [x] done & tested
- [~] in progress
- [ ] pending

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
- [~] Validator running on salvaged v1 (~18 rec/min × 33,667 ≈ 17h wall clock)
- [ ] Re-tier after validator finishes; expect Tier A to populate from has_fix=True records

## Phase 5 — New sources
### 5a. GitLab scraper [ ]
- Mirror of `scrapers/github.py` using `/api/v4/search?scope=commits`
- Needs user-provided `GITLAB_TOKEN`
- Same query set as GitHub (security/CVE/fix keywords × IaC file extensions)

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
- [ ] Merge `dataset_v1_validated.jsonl` + live v2 JSONL
- [ ] Dedup on `(repo, commit_sha, file_path)` preferring `source_version` newest
- [ ] Assign tier in the writer (so live v2 records get tiered at ingest)
- [ ] Emit final `dataset_v2_final.jsonl` with manifest (counts per tier, per source, per smell category)

---

## Known limits & risks
- Checkov is terraform-only; Ansible / Kubernetes / Dockerfile records only get regex smell labels. → Tier A currently only reachable for Terraform.
  - Mitigation: add tfsec/kics/terrascan later, or use Checkov's k8s/docker framework flags.
- GitHub search API caps at 1000 results per query. Already partially mitigated by date-window splitting.
- GitLab search API is similar but token scopes differ — will need `read_api` scope.
- OSV feed is high-quality but low-volume (thousands, not tens of thousands).

## Priority order (revised after 5b finding)
1. **Finish Phase 4 validator** (running — produces the real Tier A signal)
2. **Phase 5a GitLab** (biggest untapped volume; needs user-provided `GITLAB_TOKEN`)
3. **Phase 7 unified merge** (v1_validated + v2 live + osv records, dedup on repo/sha/file)
4. **Phase 6 GraphQL batching** (if scraper remains bottlenecked)
5. **Phase 5c academic datasets** (Rahman Ansible/Chef, GLITCH) — authoritative labels
