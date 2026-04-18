# Rapport 5 Preparation

## What I read

- `Rapports/drafts/rapport1/rapport1.tex`
- `Rapports/drafts/rapport2/rapport2.tex`
- `Rapports/drafts/rapport3/rapport3.tex`
- `Rapports/drafts/rapport-critique/rapport-critique.tex`
- `Rapports/drafts/rapport4/rapport4.tex`
- `Presentations/present2/presentation.tex`

## Current progression of the work

### Rapport 1

Bibliographic foundation:
- RAG evolution: `CRAG`, `Self-RAG`, `FLARE`
- Tool-using LLMs and agents: `Toolformer`, `Gorilla`, `CodeAct`
- Evaluation motivation: `GAIA`
- Initial thesis direction: hybrid agent for secure code and IaC-oriented reasoning

### Rapport 2

First full technical framing:
- problem statement and objectives
- proposed 6-module agentic architecture
- small 8-file, 27-smell evaluation dataset
- ambitious 18-metric evaluation plan
- early baseline results
- implementation timeline

### Rapport 3

Main empirical asset:
- large IaC security-fix corpus
- `33,667` unique records
- `32,960` with before/after fixes
- 5 IaC technologies
- 18 smell types documented in the report text
- dataset collection, deduplication, schema, and examples

### Rapport critique

Internal correction of the thesis positioning:
- several claims from `rapport2` were too strong
- the small 8-file dataset should be demoted to a sanity suite
- the "18 metrics" framing was inflated
- some metrics were not computable or not yet computed
- contribution must be reframed around a real niche with evidence

### Rapport 4

Repositioned thesis:
- primary contribution becomes the large corpus from `rapport3`
- target niche becomes: `agentic IaC remediation with independent scanner-based validation`
- architecture is retained, but with two required amendments:
  - add `KICS` as second validator
  - replace log-prob confidence with self-consistency confidence
- evaluation is reduced to a defensible core set
- `rapport5` is explicitly defined as the report that must contain real end-to-end numbers

## Main problems to fix in Rapport 5

These are the points that clearly need to be addressed.

1. The report must show real experimental results, not only plans.
2. The contribution claims must stay aligned with what is actually implemented and measured.
3. The large dataset must be used as the primary evaluation input, not the old 8-file suite.
4. The architecture updates from `rapport4` must be reflected in both text and implementation:
   - `KICS` integration
   - self-consistency confidence
5. The evaluation section must focus on the defensible metrics, especially:
   - `PVR`
   - `SER`
   - `NNIR`
6. The baseline comparison should reference the newer landscape introduced in `rapport4`, especially `IntelliSA`, `PatchEval`, `AutoPatchBench`, `SEC-bench`, `SecRepoBench`, `IaC-Eval`, and `Multi-IaC-Eval`.
7. The presentation currently reflects the older `rapport2` framing and should be updated to match the thesis repositioning from April 2026.

## Minimum structure for Rapport 5

Recommended structure:

1. Introduction
2. Final research positioning
3. System under evaluation
4. Dataset and test split
5. Experimental protocol
6. Results
7. Comparison with baselines and recent literature
8. Threats to validity
9. Conclusion

## What Rapport 5 should prove

At minimum, `rapport5` should answer these questions with numbers:

1. Does the validator-guided agent produce patches that pass independent validation?
2. Does the agent remove the targeted smell without introducing new issues?
3. Does retrieval and/or the retry loop improve results over simpler configurations?
4. Does adding `KICS` improve multi-tool coverage beyond `Checkov` alone?
5. How does the final system compare to the strongest relevant baselines available for detection or remediation?

## Recommended chapter focus

### Chapter 1: Introduction

- restate the problem in IaC security remediation
- state the thesis exactly as repositioned in `rapport4`
- avoid claiming novelty that is not experimentally supported

### Chapter 2: Positioning

- keep the 2025-2026 landscape
- explain why the thesis cell is still distinct
- distinguish clearly between:
  - detection benchmarks
  - remediation benchmarks
  - IaC-specific generation benchmarks

### Chapter 3: Final system

- describe only the implemented system
- include the amendments:
  - `Checkov + KICS`
  - self-consistency confidence
- specify input/output contracts and retry behavior

### Chapter 4: Experimental setup

- define dataset split used for the main results
- define configurations `A/B/C/D` only if they are actually run
- specify models, validator versions, compute budget, stopping rules

### Chapter 5: Results

- this is the most important chapter
- headline tables should report:
  - patch validity
  - smell elimination
  - no-new-issues
  - per-tool performance
  - per-smell performance where sample size is sufficient
- include failure analysis, not only averages

### Chapter 6: Discussion

- where the agent helps
- where validators block invalid fixes
- where retrieval helps or does not help
- gaps in generalization across IaC tools

### Chapter 7: Conclusion

- summarize the validated contribution
- state what remains future work

## Presentation direction

The current `present2` slides are still centered on:
- the small 8-file dataset
- the old 18-metric framing
- an in-progress architecture story

The next presentation should instead be built around a timeline and progression narrative:

1. Research timeline
2. Technology timeline
3. Evolution of the thesis idea
4. What was changed after critique
5. What was actually built
6. What remains to finish for `rapport5`

## Proposed presentation outline

### Part 1: Timeline of the field

- 2019-2022: rule-based IaC security analysis and static scanners
- 2023-2024: RAG, tool-using LLMs, and secure-code generation become practical
- 2025: patch-repair and security benchmark ecosystem expands
- 2026: stronger IaC semantic baselines appear, forcing thesis repositioning

### Part 2: Timeline of this thesis

- `rapport1`: bibliography and conceptual foundation
- `rapport2`: first architecture and evaluation plan
- `rapport3`: large dataset construction
- `rapport-critique`: correction of claims and evaluation framing
- `rapport4`: updated positioning and experimental plan
- `rapport5`: final empirical validation

### Part 3: Progress by deliverable

- literature review
- architecture
- dataset
- validators
- evaluation pipeline
- experiments
- writing

### Part 4: Current blockers

- finishing validator coverage
- running end-to-end experiments
- filling headline result tables
- updating slides to match the final thesis framing

## Immediate next steps

1. Inspect the codebase to verify whether the `rapport4` required changes are already implemented.
2. Draft `rapport5.tex` from the `rapport4` structure instead of starting from `rapport2`.
3. Replace the old presentation narrative with a timeline/progress presentation.
4. Pull exact experimental outputs and use them to drive the writing, not the other way around.
