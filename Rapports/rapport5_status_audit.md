# Rapport 5 Status Audit

## Purpose

This note maps the claims and planned amendments from `rapport4` to the current codebase state in `Code/`.

## Files inspected

- `Code/src/validator/tool_integrator.py`
- `Code/src/generator/fix_generator.py`
- `Code/scripts/evaluate.py`
- `Code/src/analyzer/contextual.py`
- `Code/src/agent/orchestrator.py`

## High-level conclusion

The codebase does **not** yet match the final framing of `rapport4`.

What exists today is closer to:
- a working `Config A` baseline
- a partial `Config D` prototype
- `Checkov`-only validation
- model-reported confidence filtering

It is **not yet** the `rapport4` target system with:
- `Checkov + KICS` validation
- self-consistency confidence
- explicit support for `Config B`, `Config C`, and `Config D`
- evaluation wired to the final large corpus protocol described in `rapport4`

## Detailed audit

### 1. Validator status

Current implementation:
- `Code/src/validator/tool_integrator.py` validates patches using `Checkov` only.
- It computes:
  - removed targeted check IDs
  - newly introduced check IDs
  - binary patch validity

What is missing relative to `rapport4`:
- no `KICS` integration
- no dual-validator agreement logic
- no tool-aware fallback policy for unsupported scanners
- no explicit validator coverage reporting by IaC tool

Impact on writing:
- `rapport5` must not claim `Checkov + KICS` unless the code is updated first.

### 2. Generator confidence status

Current implementation:
- `Code/src/generator/fix_generator.py` asks the model to output:
  - a unified diff
  - `CONFIDENCE: 0.0-1.0`
- the parser keeps patches only if confidence is above `0.6`

What is missing relative to `rapport4`:
- no self-consistency wrapper
- no sampling of multiple generations
- no agreement-based confidence score
- no replacement of log-prob / self-reported confidence by an empirical surrogate

Impact on writing:
- `rapport5` must not state that the final generator uses self-consistency confidence unless implemented.

### 3. Evaluation configuration status

Current implementation in `Code/scripts/evaluate.py`:
- `baseline` mode = `Config A`
- `full` mode = effectively a partial `Config D`

What exists:
- baseline detection with `Checkov`
- simplified retrieval approximation from taxonomy entries
- full mode with analyzer, retriever, generator, validator, and up to 3 attempts

What is missing:
- no explicit `Config B`
- no explicit `Config C`
- no direct switchable ablation runner for `A/B/C/D`
- no dual-validator mode
- no clear final corpus test-split protocol matching `rapport4`

Impact on writing:
- `rapport5` can safely report:
  - `Config A`
  - current full-pipeline prototype
- `rapport5` cannot honestly claim completed `B/C/D` ablation results unless those runs are added.

### 4. Metrics status

Current implementation computes or approximates:
- detection:
  - precision
  - recall
  - F1
  - macro-F1
  - per-tool breakdown
  - per-type breakdown
- retrieval:
  - Hit Rate@1
  - Hit Rate@3
  - Hit Rate@5
  - MRR@5
- remediation:
  - `PVR`
  - `SER`
  - `NNIR`
- agentic:
  - first-attempt success proxy
  - delta attempt 2
  - delta attempt 3

But:
- retrieval metrics are explicitly simplified approximations
- some "18 metrics" table entries are still placeholders or `N/A`
- the printed report still reflects the older inflated framing

Impact on writing:
- `rapport5` should focus on the defensible subset:
  - detection metrics
  - `PVR`
  - `SER`
  - `NNIR`
  - retry benefit
- the report should describe retrieval metrics carefully as approximations unless the real retrieval pipeline is used.

### 5. Dataset protocol status

Current evaluation script expects:
- `Code/dataset/metadata.json`
- local dataset files referenced from that metadata

What is actually present:
- `Code/dataset/metadata.json` contains `16` files, not the promoted large corpus
- the full released corpus exists separately in `iac-security-dataset/dataset.jsonl`
- that external JSONL contains `33,667` records
- the README in `iac-security-dataset/` declares the intended split:
  - train: `26,931`
  - validation: `3,365`
  - test: `3,371`

Concrete mismatch:
- the current evaluation code is wired to the small local dataset under `Code/dataset/`
- it is **not** yet wired to the full corpus in `iac-security-dataset/dataset.jsonl`
- therefore the current script does **not** implement the `rapport4` held-out large-corpus protocol

Impact on writing:
- dataset claims in `rapport5` must be tied to the exact metadata file and split actually used for experiments
- if experiments are run with the current code unchanged, they should be described as small-scale prototype experiments, not full-corpus evaluation

## Safe claims for Rapport 5 right now

These are the claims that appear supportable from the inspected code.

1. A baseline `Checkov`-based evaluation path exists.
2. A prototype end-to-end pipeline exists with:
   - smell analysis
   - retrieval
   - LLM patch generation
   - external validation
   - up to 3 attempts
3. The external validator currently relies on `Checkov`.
4. The evaluation script computes `PVR`, `SER`, and `NNIR`.
5. The current generator uses model-reported confidence filtering, not self-consistency.

## Claims that should be avoided until implemented

1. `Checkov + KICS` are both integrated and used in the final pipeline.
2. Self-consistency confidence has replaced the previous confidence mechanism.
3. `Configurations B, C, D` have all been implemented and compared.
4. The final `rapport4` experimental plan has been fully executed.

## Recommended writing strategy for Rapport 5

### Option A: Honest interim Rapport 5

Frame `rapport5` as:
- implementation and prototype evaluation report
- current results on the implemented pipeline
- explicit statement of what remains unfinished

This is the safest route if code changes are not completed first.

### Option B: Bring code up to rapport4, then write Rapport 5

Required coding tasks before writing:
- add `KICS` support to `tool_integrator.py`
- add self-consistency sampling to `fix_generator.py`
- refactor `evaluate.py` to run `Config B`, `C`, and `D`
- ensure the script reads the actual held-out corpus split
- run the experiments and save the results

## Recommendation

Do not start with polished `rapport5` prose yet.

The next concrete task should be:
1. verify the dataset path and split actually used by `evaluate.py`
2. decide whether to write an honest prototype-based `rapport5` or to first implement the missing `rapport4` requirements
3. only then draft the LaTeX report and updated presentation
