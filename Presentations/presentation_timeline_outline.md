# Presentation Timeline Outline

## Objective

Build the next presentation around:
- timeline of the field
- timeline of the thesis
- current technical progress
- what changed after critique
- what remains to finish for `rapport5`

This should replace the old `present2` narrative, which still reflects the `rapport2` framing.

## Suggested title

`Progression of the Research and Technology Landscape for Agentic IaC Security Remediation`

## Recommended slide flow

### 1. Title slide

- thesis title
- student
- supervisor
- date
- short subtitle:
  `From literature review to empirical validation`

### 2. Roadmap

- context
- technology timeline
- thesis timeline
- current implementation progress
- next steps toward `rapport5`

### 3. Problem context

- IaC is now a major operational layer in cloud systems
- security smells in IaC create real attack surfaces
- detection tools exist, but validated remediation remains limited

### 4. Technology timeline: early stage

Suggested time range:
- `2019-2022`

Main message:
- rule-based IaC security analysis dominates
- static scanners such as `Checkov`, `KICS`, and related tools structure the field
- emphasis is on detection rather than automated repair

### 5. Technology timeline: LLM transition

Suggested time range:
- `2023-2024`

Main message:
- RAG becomes practical
- tool-using LLMs become realistic
- agentic workflows and executable actions become stronger design patterns

Suggested references already present in the reports:
- `Toolformer`
- `CRAG`
- `Self-RAG`
- `FLARE`
- `Gorilla`
- `CodeAct`

### 6. Technology timeline: benchmark expansion

Suggested time range:
- `2025`

Main message:
- security patching benchmarks expand quickly
- evaluation becomes stricter
- the thesis must position itself relative to new benchmark families

Suggested references:
- `PatchEval`
- `AutoPatchBench`
- `SEC-bench`
- `SecRepoBench`
- `IaC-Eval`
- `Multi-IaC-Eval`

### 7. Technology timeline: repositioning pressure

Suggested time range:
- `2026`

Main message:
- stronger IaC detection baselines appear
- simple "framework proposal" is no longer enough
- the thesis must prove a distinct and defensible contribution

Suggested reference:
- `IntelliSA`

### 8. Thesis timeline

Use a left-to-right progression:
- `rapport1`: bibliography and conceptual foundation
- `rapport2`: first architecture and evaluation plan
- `rapport3`: large dataset construction
- `rapport-critique`: correction of claims and metrics
- `rapport4`: repositioning and experimental plan
- `rapport5`: empirical validation

### 9. Evolution of the thesis idea

Show how the project changed:

Initial idea:
- broad agentic IaC framework

After data collection:
- large corpus becomes a major contribution

After critique:
- claims are narrowed
- metrics are reduced to defensible ones
- contribution is reframed around validated remediation

### 10. What has actually been built

Keep this grounded in the current code:
- analyzer
- retriever
- generator
- validator
- retry loop
- evaluation script

Important:
- present `Checkov` validation as current fact
- do not present `KICS` integration as completed unless implemented

### 11. Dataset progress

Based on the reports:
- large corpus created
- multiple IaC technologies covered
- before/after fix pairs available for most records
- corpus promoted from auxiliary asset to primary empirical contribution

### 12. What changed after critique

This slide is important.

Show clearly:
- old small 8-file dataset demoted to sanity suite
- "18 metrics" framing reduced
- novelty claims narrowed
- benchmark landscape updated
- `rapport5` redefined around real numbers

### 13. Current technical status

Split into two columns:

Implemented:
- baseline evaluation
- prototype full pipeline
- patch validation with `Checkov`
- computation of `PVR`, `SER`, `NNIR`

Still missing or incomplete:
- `KICS` integration
- self-consistency confidence
- explicit `Config B/C/D` ablation support
- full final experiment campaign

### 14. What Rapport 5 must deliver

This should be the core "target" slide.

At minimum:
- real end-to-end experimental results
- honest baseline comparison
- validated remediation metrics
- per-tool and per-smell analysis
- discussion of failure cases

### 15. Remaining work plan

Suggested sequence:

1. finalize code alignment with `rapport4`
2. verify dataset split and protocol
3. run experiments
4. fill headline tables
5. write `rapport5`
6. prepare defense-ready slides

### 16. Conclusion

Key message:
- the thesis matured from a broad idea into a more defensible empirical contribution
- the next milestone is no longer design, but validation

## Visual recommendations

- Use a timeline visual for both the field and the thesis
- Keep architecture to one compact reminder slide only
- Avoid centering the talk on modules; center it on progression and evidence
- Use color coding:
  - literature / landscape
  - thesis milestones
  - implemented work
  - remaining work

## Speaker message

The presentation should communicate:
- the work progressed
- the direction became more rigorous over time
- the critique improved the thesis
- `rapport5` is the step where the contribution must be validated quantitatively
