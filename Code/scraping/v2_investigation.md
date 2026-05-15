# Dataset v2 Investigation

Date: 2026-05-11

## Current Assets

The repo already contains four important dataset states:

| File | Records | Notes |
|---|---:|---|
| `output/merged_v1/dataset_20260407_2233.jsonl` | 33,667 | Original merged v1; no v2 quality fields. |
| `output/dataset_v1_salvaged.jsonl` | 33,667 | v1 after reverse-patch salvage and expanded regex labels. |
| `output/dataset_v1_validated.jsonl` | 31,748 | Partially scanner-validated salvaged v1. Missing 1,919 salvaged records. |
| `output/gitlab/dataset.jsonl` | 5,498 | GitLab records from 1,623 projects / 7,281 commits. |

Current raw GitHub/GHArchive files contain 47,486 records before dedup, but they still need salvage, validation, and v2 merge logic before release.

## Quality Snapshot

## Tier Definitions

The v2 dataset uses quality tiers so bigger volume does not hide weaker labels.

| Tier | Name | Meaning | Recommended use |
|---|---|---|---|
| A | Gold | Real before/after pair where a scanner finding exists in `code_before` and disappears in `code_after`. This is the strongest evidence that the commit fixed a concrete IaC security issue. | Evaluation, fine-tuning fix generation, benchmark examples, headline quality stats. |
| B | Silver | Real before/after pair with strong evidence, but not a scanner-confirmed disappearing finding. Evidence can be scanner findings before, regex smell labels, or a strong security commit message. | Fix generation training, supervised learning with caution, manual review candidates. |
| C | Bronze | Security-relevant insecure-code examples without a strong fix pair. This includes detection-only records, new-file additions containing smells, or real code with scanner/regex findings. | Smell detection training, classification, retrieval examples. Not ideal for fix generation. |
| D | Weak | Records with weak or incomplete evidence: no confirmed smell, placeholder/unavailable before-content, vague security signal, or otherwise noisy raw material. | Raw mining pool, LLM/manual triage, future validation. Do not use as trusted labels. |

Important interpretation:

- Tier A is scanner-grounded, not LLM-grounded.
- Tiers B and C are useful but should be described as silver/bronze labels.
- Tier D should not be used directly for training unless filtered or reviewed.
- LLM review can help promote/demote B/C/D confidence, but it should not create Tier A by itself.

### Salvaged v1

- Records: 33,667
- Fix pairs: 18,156
- Detection-only / no fix: 15,511
- Tiers currently stored: B=7,721, C=5,263, D=20,683
- `code_before_quality`: api=18,863, new_file=14,804
- Regex-labelled records: 12,034
- Remaining placeholder before-content: 21

### Validated v1

- Records: 31,748, so validation did not finish.
- Scanner available locally: Checkov only.
- Records with any scanner finding: 10,791
- Records with scanner findings before and after: before=7,002, after=9,729
- Scanner-confirmed fixed findings: 2,898 records have at least one rule present before and absent after.
- Stored tier field was not recomputed after validation, so there are no stored Tier A records.
- Recomputed tiers from existing validated data: A=2,324, B=7,816, C=4,342, D=17,266

### GitLab

- Records: 5,498
- Fix pairs: 5,490
- Tiers: B=424, D=5,074
- Tool mix: kubernetes=1,792, terraform=1,480, ansible=1,373, docker=631, cloudformation=222
- Content-hash duplicates: 1,286 extra duplicates.
- Problem: new-file and unavailable records keep placeholder patch text in `code_before`, while `code_before_quality` is `new_file` or `unavailable`. These should be normalized like salvaged v1 before release.

## Candidate v2 Merge

If we merge:

- `output/dataset_v1_validated.jsonl`
- the 1,919 records missing from validation via `output/dataset_v1_salvaged.jsonl`
- `output/gitlab/dataset.jsonl`

and deduplicate by `(repo, commit_sha, file_path)` with quality-aware preference, the current candidate is:

- Unique records: 39,165
- Recomputed tiers: A=2,324, B=9,284, C=4,354, D=23,203
- Validated records: 10,791
- Scanner-confirmed fixed records: 2,898
- Tool mix: terraform=17,866, kubernetes=11,034, ansible=5,871, docker=3,102, cloudformation=1,292

Recommended publishable subsets:

- `v2_gold.jsonl`: Tier A only, scanner-confirmed fix pairs.
- `v2_fix_pairs.jsonl`: Tiers A+B, before/after pairs with strong labels or validation.
- `v2_detection.jsonl`: Tiers A+B+C, includes detection-only useful insecure examples.
- `v2_full.jsonl`: all tiers, but clearly mark Tier D as weak/noisy raw material.

## First v2 Snapshot

Built with `python -m scraping.scripts.build_v2` on 2026-05-11.

| Output | Records | Meaning |
|---|---:|---|
| `output/v2/dataset_v2_gold.jsonl` | 2,324 | Tier A scanner-confirmed fix pairs. |
| `output/v2/dataset_v2_fix_pairs.jsonl` | 11,608 | Tiers A/B with before/after fixes. |
| `output/v2/dataset_v2_detection.jsonl` | 16,159 | Tiers A/B/C, including detection-only examples. |
| `output/v2/dataset_v2_full.jsonl` | 39,165 | All tiers, including weak Tier D raw material. |

Manifest: `output/v2/manifest_v2.json`

Snapshot stats:

- Loaded records before dedup: 70,913
- Unique records after quality-aware dedup: 39,165
- Duplicates removed: 31,748
- Tiers: A=2,324, B=9,284, C=4,551, D=23,006
- Records with fixes: 22,867
- Detection-only / no-fix records: 16,298
- Validated records: 10,791
- Scanner-confirmed fixes: 2,898

## Main Issues Blocking a Good v2

1. Validation is incomplete.
   `dataset_v1_validated.jsonl` has 31,748 records, but salvaged v1 has 33,667.

2. Tiering is stale after validation.
   Tier A exists logically, but was never written into the validated file.

3. GitLab needs salvage normalization.
   New-file records should become detection-only instead of pretending to be fix pairs with placeholder `code_before`.

4. Existing merger is too weak for v2.
   `processors/merger.py` deduplicates by `content_hash` only. v2 should dedup by `(repo, commit_sha, file_path)` first, then content hash fallback, while preferring validated and higher-tier records.

5. Validation coverage is Checkov-only.
   That is good for Terraform/Kubernetes/Docker/CloudFormation via Checkov frameworks, but Ansible and some Docker/K8s findings would improve with KICS/tfsec/Terrascan installed.

6. Raw crawl progress is still low.
   Account 1 completed about 2.5% of its commit query windows; account 2 about 9.8%. More scraping can grow v2, but quality cleanup should happen first.

## Recommended v2 Build Order

1. Finish validation for the missing 1,919 salvaged v1 records, or resume validation safely against `output/dataset_v1_salvaged.jsonl`.
2. Recompute `tier` after validation for every record.
3. Run a GitLab salvage pass: normalize new-file records, recompute smells, recompute tier.
4. Add a v2 merger script that:
   - accepts validated v1, salvaged fallback, GitLab, and current raw sources,
   - deduplicates by `(repo, commit_sha, file_path)` first,
   - falls back to content hash,
   - prefers Tier A > B > C > D,
   - prefers scanner-validated records,
   - writes a manifest with counts by tier/source/tool/smell/scanner.
5. Emit tiered release files instead of one ambiguous dataset.
6. Only then continue long-running GitHub/GHArchive scraping and feed new raw records through the same v2 pipeline.

## Parallel Execution Plan

The v2 target is both bigger and cleaner than v1, so the work should run in four lanes:

| Lane | Goal | Can run while scraping? | Writes to |
|---|---|---:|---|
| A. Quality pipeline | Normalize, validate, re-tier, dedup, export releases | Yes | `output/v2/` only |
| B. GitHub/GHArchive expansion | Keep collecting public GitHub records | Yes | `output/raw/`, `output/raw2/` |
| C. GitLab expansion | Collect more GitLab records with deeper/project-history search | Yes | `output/gitlab/` |
| D. Validation/scanner upgrade | Install/run KICS, tfsec/Trivy, Terrascan where useful | Yes, CPU-heavy | validated JSONL snapshots |

Safe to run in parallel:

- Account 1 GitHub scraper and Account 2 GitHub scraper, because they write separate raw/progress files.
- GHArchive discovery with either account, as long as each account writes to its own raw directory.
- GitLab scraper, because it writes under `output/gitlab/`.
- Validation against stable snapshot files, not against files that are actively being appended.
- v2 merge/export against immutable snapshots.

Do not run in parallel:

- Two writers appending to the same JSONL file.
- A validator reading a JSONL file while a scraper is actively appending to that exact same file.
- Two merge/export jobs writing the same output path.

Recommended layout:

```text
Terminal 1: GitHub account 1 long run
Terminal 2: GitHub account 2 long run
Terminal 3: GitLab long run
Terminal 4: validation on stable snapshots
Terminal 5: v2 merge/export after each validation checkpoint
```

Release strategy:

1. Keep scrapers running continuously into raw append-only files.
2. Periodically snapshot raw files into a dated staging folder.
3. Run salvage/normalization on the snapshot.
4. Run scanner validation on the normalized snapshot.
5. Recompute tiers.
6. Merge into `output/v2/dataset_v2_full.jsonl`.
7. Export tiered subsets: gold, fix-pairs, detection, full.

This keeps volume growth and quality improvement moving at the same time without corrupting active scraper outputs.

## Verification Run

- Test suite: `88 passed in 0.12s`
- Local scanners found: Checkov only.
