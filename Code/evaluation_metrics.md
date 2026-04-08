# Evaluation Metrics for the Agentic IaC Security Framework

**Author:** Ahmedou Yahye Kheyri
**Supervisor:** Hala Bezine
**Institution:** Faculté des Sciences de Sfax — Master MRSI
**Date:** March 2026

---

> **Reading note:** Inline citations follow the format `[N]` and refer to the numbered
> bibliography at the end of this document. Every metric, formula, and experimental
> protocol is sourced from a peer-reviewed publication or a widely adopted research
> framework. Metrics introduced specifically for this framework are explicitly marked
> **(This work)**.

---

## 1. Evaluation Structure

The framework is evaluated along four distinct layers, each addressed by specific metrics:

```
Layer 1 — Detection    : Did the analyzer correctly identify the security smells?
Layer 2 — Retrieval    : Did the RAG retrieve the right knowledge?
Layer 3 — Remediation  : Did the generated patch actually fix the smells?
Layer 4 — Agentic loop : Did the retry/validation mechanism add measurable value?
```

A final **ablation study** cuts across all layers to isolate each module's individual contribution.

This evaluation structure follows the research questions (RQ) methodology adopted by De Vito et al. [1] (SecLLM, IEEE Access 2025) and War et al. [2] (arXiv:2509.18790), the two most closely related papers to this work.

---

## 2. Layer 1 — Detection Metrics

These metrics are the standard evaluation protocol for IaC security smell detection tools. They are used universally across the literature: SecLLM [1], War et al. [2], GLITCH [3], SLAC [4], SLIC [4], and the defect prediction work of Dalla Palma et al. [5].

### 2.1 Precision

**Definition:**

$$\text{Precision} = \frac{TP}{TP + FP}$$

- **True Positive (TP):** The analyzer reports a smell of type $T$ at line $L$, and the ground truth oracle (`metadata.json`) confirms a smell of type $T$ at line $L$ (±2 line tolerance).
- **False Positive (FP):** The analyzer reports a smell not present in the ground truth.

**Meaning:** Measures how many of the *reported* smells are genuine. A low precision value indicates excessive false alarms that would burden developers.

**Source:** Standard classification metric, applied to IaC security smell detection by Rahman et al. [4] and adopted by every subsequent paper in this domain.

**Reference results:**
- SecLLM [1], Qwen-2.5 32B on Ansible: Precision = **1.00 (SD=0.00)**
- GLITCH [3] on Ansible: Precision = **0.76**

---

### 2.2 Recall

**Definition:**

$$\text{Recall} = \frac{TP}{TP + FN}$$

- **False Negative (FN):** A smell present in the ground truth that was not detected.

**Meaning:** Measures how many of the *actual* smells were found. A low recall means the tool misses real vulnerabilities — the more dangerous failure mode in a security context.

**Source:** Same as Precision — standard IR/classification metric [4][1][2][3].

**Reference results:**
- SecLLM [1], Qwen-2.5 32B on Ansible: Recall = **0.99 (SD=0.00)**
- GLITCH [3] on Ansible: Recall = **0.86**
- War et al. [2], fine-tuned LongFormer on Puppet: Recall = **0.75**

---

### 2.3 F1-Score (Macro-F1)

**Definition:**

$$F_1 = \frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

The harmonic mean of Precision and Recall. When the dataset is **imbalanced** (more "no smell" scripts than "smell" scripts, as is the case in our dataset), using accuracy alone would be misleading. The F1-score provides a balanced measure of both false positives and false negatives [1][2].

**Macro-F1:** The unweighted average of F1 computed independently for each smell category. It treats all smell types equally regardless of their frequency, which is appropriate here since rare smells (e.g., CWE-295) are as important as common ones (e.g., CWE-732).

$$\text{Macro-F1} = \frac{1}{|C|} \sum_{c \in C} F_1^{(c)}$$

**Source:** De Vito et al. [1] use Macro-F1 as the primary comparison metric across Tables 4, 5, 6. War et al. [2] use it in Table 1. This is also the metric used in the GLITCH evaluation [3].

**Reference results:**
- SecLLM [1] (all models, all technologies): F1 = **0.87–0.94**
- War et al. [2], fine-tuned LongFormer (Puppet): F1 = **0.79**
- GLITCH [3]: F1 = **0.63–0.77** (lower baseline)

---

### 2.4 Per-Smell-Type Reporting Table

Following the exact structure of SecLLM Tables 4, 5, and 6 [1], results must be reported **per smell type**, not only as aggregates. This is essential for identifying which categories the system handles well and which require improvement.

| Smell Type | Occurrences | Precision (SD) | Recall (SD) | F1 |
|---|---|---|---|---|
| `hardcoded_secret` | 6 | | | |
| `overly_permissive_cidr` | 2 | | | |
| `privileged_container` | 1 | | | |
| `run_as_root` | 3 | | | |
| `tls_disabled` | 1 | | | |
| `world_writable` | 2 | | | |
| `unencrypted_storage` | 3 | | | |
| `no_resource_limits` | 2 | | | |
| `no_smell` (negative class) | — | | | |
| **Macro Average** | **27** | | | |

---

### 2.5 Standard Deviation Across Multiple Runs

Because LLM outputs are inherently **non-deterministic** [1][6], each experiment must be repeated multiple times and the standard deviation reported alongside the mean. De Vito et al. [1] perform **5 independent runs** and report `Metric_mean (SD)` for each configuration. They note that a standard deviation of 0.00 indicates full determinism.

**Protocol for this work:** Run each test file through the detection pipeline 5 times independently. Report:

$$\bar{x} \pm \sigma \quad \text{(e.g., Precision = 0.92 ± 0.03)}$$

**Source:** De Vito et al. [1], Section IV-F ("Research Method for RQ1"): *"We decided to perform five executions due to the non-deterministic nature of LLMs."*

---

## 3. Layer 2 — Retrieval Metrics (Knowledge Retriever / RAG)

These metrics evaluate the quality of the Knowledge Retriever (ChromaDB + sentence-transformers). They are drawn from the Information Retrieval (IR) literature and the RAGAS evaluation framework [7].

### 3.1 Hit Rate @ K

**Definition:**

$$\text{Hit Rate@}K = \frac{|\{q \in Q : \exists \text{ relevant doc in top-}K \text{ for } q\}|}{|Q|}$$

Where $Q$ is the set of all test queries (one query per smell instance in the dataset), and a document is **relevant** if its `smell_type` or `cwe` field matches the queried smell.

**Meaning:** Measures whether the retriever can find *at least one* useful document for a given smell. It is the most basic retrieval quality check.

**Source:** Standard IR metric, widely used in RAG evaluation benchmarks [7][8].

Report for **K = 1, 3, 5**. **Target: Hit Rate@5 ≥ 0.80.**

---

### 3.2 Mean Reciprocal Rank (MRR@K)

**Definition:**

$$\text{MRR@}K = \frac{1}{|Q|} \sum_{q=1}^{|Q|} \frac{1}{\text{rank}_q}$$

Where $\text{rank}_q$ is the position (1-indexed) of the first relevant document for query $q$ in the top-$K$ results. If no relevant document appears in the top-$K$, that query contributes 0.

**Meaning:** Unlike Hit Rate, MRR rewards systems that rank the relevant document *higher*. MRR@5 = 0.75 means the first relevant document appears at position ~1.3 on average.

**Source:** Standard IR metric described in Manning et al. [9], adopted in modern RAG evaluation frameworks [7][8].

---

### 3.3 Context Recall (RAGAS)

**Definition** (Es et al. [7], EACL 2024):

$$\text{Context Recall} = \frac{\text{sentences in ground truth attributable to retrieved context}}{\text{total sentences in ground truth}}$$

**Application for this work:** The ground truth is the `fix_example` field from the smell taxonomy (the correct remediation text). For each sentence in that reference, an LLM judge is prompted to determine whether the sentence can be attributed to the retrieved documents. The fraction of attributable sentences is the Context Recall.

**Meaning:** Measures completeness — did the retriever surface all the information needed to generate a correct fix?

**Source:** Es et al. [7], RAGAS framework (arXiv:2309.15217, EACL 2024). **Target: > 0.70.**

---

### 3.4 Context Precision (RAGAS)

**Definition** (Es et al. [7]):

$$\text{Context Precision@}K = \frac{\sum_{k=1}^{K} \text{Precision@}k \times \text{rel}(k)}{\text{number of relevant documents in top-}K}$$

Where $\text{rel}(k) = 1$ if the document at rank $k$ is relevant, 0 otherwise. This weighted formulation gives more credit to relevant documents ranked higher.

**Meaning:** Measures signal-to-noise ratio. A high Context Precision means the most useful documents appear first, with little irrelevant context mixed in.

**Source:** Es et al. [7]. **Target: > 0.75.**

---

## 4. Layer 3 — Remediation Metrics

These metrics evaluate the Fix Generator and the External Validator together. They are **novel to this framework** **(This work)**, motivated by the core thesis objective: producing *validated*, not merely *plausible*, corrections.

### 4.1 Patch Validity Rate (PVR) ← Primary Metric

**Definition (This work):**

$$\text{PVR} = \frac{|\text{patches accepted by Checkov validator}|}{|\text{total patches generated}|}$$

A patch is **valid** if and only if, after applying it to a temporary copy of the original file and running Checkov [10]:

1. All `checkov_id` values from the targeted smells are **absent** from the new Checkov output.
2. **No new** `checkov_id` values appear that were absent in the original scan.

Both conditions must hold simultaneously. This binary criterion is inspired by the patch correctness evaluation in PatchEval [11]: *"A patch is correct if and only if: (1) the PoC exploit fails on the patched version, AND (2) all existing tests pass."*

**Motivation:** A standard RAG system has no PVR concept — it cannot verify its own output. PVR is the metric that directly quantifies the value of the validation loop.

**Expected range (first prototype):** 0.40–0.75. **Target: > 0.70.**

---

### 4.2 Smell Elimination Rate (SER)

**Definition (This work):**

$$\text{SER} = \frac{|\text{targeted smells removed from Checkov output after patch}|}{|\text{total targeted smells}|}$$

**Motivation:** PVR is binary — a patch that removes 3 out of 4 smells still counts as a failure. SER provides **partial credit** and is useful for fine-grained analysis of which smell types are harder to fix.

---

### 4.3 No-New-Issues Rate (NNIR)

**Definition (This work):**

$$\text{NNIR} = \frac{|\text{patches introducing 0 new Checkov check failures}|}{|\text{total patches applied}|}$$

**Motivation:** A patch that fixes smell A while introducing smell B is worse than doing nothing. NNIR explicitly penalises regressions. It is the complement of the "new issues introduced" metric implicitly evaluated in any before/after tool comparison.

**Target: > 0.90.**

---

### 4.4 Confidence Score Calibration

De Vito et al. [1] (SecLLM, Eq. 1 and Table 7) propose computing a **confidence score** from LLM log-probabilities to filter uncertain predictions:

$$\text{confidence} = \exp\!\left(\frac{1}{n} \sum_{i=1}^{n} \log p_i\right)$$

Where $p_i$ is the probability assigned by the model to its $i$-th output token and $n$ is the total number of output tokens. The geometric mean of token probabilities gives a scalar confidence in $[0, 1]$.

**Calibration protocol** (adapted from SecLLM [1], Section IV-H):

1. Collect confidence scores for all generated patches.
2. Compute PVR at confidence thresholds from 0.5 to 1.0 in steps of 0.05.
3. Apply the **Wilcoxon Rank-Sum Test** [12] to verify that valid patches have significantly higher confidence than invalid ones ($\alpha = 0.05$, Holm-Bonferroni correction for multiple comparisons [13]).
4. Select the **optimal threshold** that maximises F1 between automatic acceptance and human review.

**Reference (SecLLM [1], Table 7):** False positives cluster at confidence 0.853–0.977; correct predictions above 0.973. Establishing a threshold ≥ 0.96 discarded 83% of false positives without losing any real detections.

---

## 5. Layer 4 — Agentic Loop Metrics

These metrics evaluate the orchestration logic — specifically the retry mechanism and the system's reproducibility. They are drawn from SecLLM [1] (for determinism) and SELF-REFINE [14] (for iterative improvement).

### 5.1 First-Attempt Success Rate (FA-SR)

**Definition (This work, inspired by [14]):**

$$\text{FA-SR} = \frac{|\text{patches valid on attempt 1}|}{|\text{total problem instances}|}$$

This is the baseline — the system's performance with no retry. It is the starting point for measuring the benefit of the agentic loop.

---

### 5.2 Retry Benefit (ΔR)

**Definition (This work, inspired by SELF-REFINE [14]):**

$$\Delta R@k = \text{CumulativeSR}@\text{attempt}_k - \text{FA-SR}$$

| Attempt | Cumulative Success Rate | Gain over Attempt 1 |
|---|---|---|
| 1 | FA-SR | 0 (baseline) |
| 2 | SR@2 | $\Delta R@2 = \text{SR}@2 - \text{FA-SR}$ |
| 3 | SR@3 | $\Delta R@3 = \text{SR}@3 - \text{FA-SR}$ |

**Inspiration:** Madaan et al. [14] (SELF-REFINE, NeurIPS 2023) report an average absolute improvement of ~20 percentage points across 7 tasks after iterative self-correction. We adapt this concept to patch validation.

**Target: ΔR@3 > 0.10** (the retry loop should add at least 10 percentage points).

---

### 5.3 Fleiss' Kappa — Reproducibility

**Definition** (Fleiss, Levin, and Paik [15]):

$$\kappa = \frac{\bar{P} - \bar{P}_e}{1 - \bar{P}_e}$$

Where:
- $\bar{P}$ = observed agreement (proportion of cases where all runs assign the same label)
- $\bar{P}_e$ = expected agreement by chance (computed from marginal proportions)

**Scale (Landis & Koch [16]):**

| $\kappa$ | Interpretation |
|---|---|
| < 0.20 | Slight |
| 0.21–0.40 | Fair |
| 0.41–0.60 | Moderate |
| 0.61–0.80 | Substantial |
| **0.81–1.00** | **Almost perfect ← target** |

**Source and motivation:** De Vito et al. [1] introduce Fleiss' Kappa as an essential metric for LLM-based tools (Section IV-H): *"Traditional precision-recall metrics fall short for non-deterministic systems. Evaluations of LLM-based tools should pair accuracy with measures like Fleiss' Kappa."*

**Reference results (SecLLM [1], Table 9):**
- GPT-4o-mini on Ansible: κ = **0.9936**, RPA = **0.9964**
- Qwen-2.5 32B on Ansible and Puppet: κ = **1.0000**

**How to measure:** Run the full pipeline **5 times** on the same input. If all 5 runs produce the same detection output, κ = 1.00. Enable **response caching** (SHA-256 keyed on request parameters, as in SecLLM [1]) to achieve κ = 1.00 at 0.2× the API cost.

---

### 5.4 Raw Percentage Agreement (RPA)

**Definition** (De Vito et al. [1], Section IV-H):

$$\text{RPA} = \frac{|\text{cases where all 5 runs produce the same output}|}{|\text{total cases}|}$$

*"The raw percentage of agreement is calculated as the proportion of smell detections where all experimental iterations assigned the same label."* [1]

Simpler than Fleiss' Kappa but does not account for chance. Both are reported together in SecLLM (Table 9) for completeness.

---

### 5.5 Operational Cost

**Motivation:** De Vito et al. [1] (RQ2) explicitly evaluate whether LLM-based security detection is **economically viable** for production deployment. We apply the same methodology to our patch generation system.

**Metrics to track** (following SecLLM [1], Table 8):

| Metric | Definition |
|---|---|
| Avg. input tokens / script | Mean tokens in the LLM prompt |
| Avg. output tokens / script | Mean tokens in the generated patch |
| Cost / script (USD) | `input_tokens × price_in + output_tokens × price_out` |
| Cost / validated patch (USD) | `total_cost / number_of_valid_patches` |

**Reference API prices (2025, from SecLLM [1]):**
- GPT-4o-mini: $0.15/1M input, $0.60/1M output → ~**$0.003/script**
- Qwen-2.5 14B (local): ~**$0.007/script** (cloud simulation)
- Qwen-2.5 32B (local): ~**$0.015/script**

---

## 6. Ablation Study

An ablation study isolates the contribution of each module by disabling it and measuring the resulting performance drop. This methodology is used by War et al. [2] (Section 4.2, "Ablation Design") and SecLLM [1] (Section IV-B, baseline comparisons).

| Config | Modules Active | What is measured |
|---|---|---|
| **A — Static only** | Checkov alone, no LLM | Baseline performance |
| **B — LLM only** | LLM generates patch, no RAG, no validation | LLM contribution |
| **C — LLM + RAG** | LLM + ChromaDB context, no Checkov validation | RAG contribution |
| **D — Full system** | LLM + RAG + Checkov validator + retry loop | Full system |

**Key differences to measure:**

$$\text{Contribution of validation loop} = \text{PVR}(D) - \text{PVR}(C)$$
$$\text{Contribution of RAG} = \text{PVR}(C) - \text{PVR}(B)$$
$$\text{Contribution of LLM over static} = \text{PVR}(B) - \text{PVR}(A)$$

This design follows War et al. [2]: *"We created reduced datasets [...] to evaluate the impact of richer semantic context."*

---

## 7. Research Questions and Metric Mapping

| RQ | Question | Primary Metric | Secondary Metrics |
|---|---|---|---|
| **RQ1** | How accurate is the detection vs. Checkov and GLITCH? | Macro-F1 [1][2][3] | Precision, Recall per tool and smell type |
| **RQ2** | Does RAG improve patch quality over LLM-only? | ΔPVR (Config C − B) | Context Recall [7], Hit Rate@5 [8] |
| **RQ3** | Does the retry loop add measurable value? | ΔR@3 [14] | FA-SR, SR@2, SR@3 |
| **RQ4** | How reproducible is the system? | Fleiss' Kappa [15][1] | RPA [1], SD across runs |
| **RQ5** | Is the system economically viable? | Cost/validated patch [1] | Cost/script, token counts |

---

## 8. Ground Truth Protocol

Following the oracle construction methodology of GLITCH [3] and SecLLM [1]:

1. **Oracle source:** `dataset/metadata.json` — 27 manually labeled smell instances, each with `(file, line, smell_type, cwe, checkov_id)`.
2. **Instance-level matching:** A detection is a TP only if the tuple `(file, smell_type, line ± 2)` matches the oracle. The ±2 line tolerance is standard in smell detection evaluation [3][4].
3. **Multiple runs:** 5 independent runs per file. Report mean ± SD following [1].
4. **Per-technology reporting:** Results must be reported separately for Terraform, Ansible, Kubernetes, and Docker. Aggregating across technologies without breakdown is discouraged [1] (SecLLM reports Tables 4, 5, 6 separately for Ansible, Chef, and Puppet).
5. **Inter-rater agreement (future work):** Involve a second independent annotator and compute **Cohen's Kappa** [17] to validate oracle quality, as recommended by Reis et al. [18] who showed that involving code authors can uncover annotation inconsistencies.

---

## 9. Threats to Validity

Following the threat classification used in SecLLM [1] (Section VI-B):

**Internal validity:** LLM non-determinism may affect reproducibility of results. Mitigated by 5 independent runs, Fleiss' Kappa measurement [15], and response caching [1].

**Construct validity:** Our dataset contains 27 smells across 8 files — small relative to the 196,755 scripts used in the GLITCH evaluation [3]. Results may not generalise to all IaC patterns. Future work should extend to GitHub-mined real-world IaC repositories.

**External validity:** Currently limited to Terraform, Ansible, Kubernetes, and Docker. Puppet and Chef — the primary targets of GLITCH [3] and SecLLM [1] — are not covered, limiting direct comparability.

**Oracle bias (construct validity):** Ground truth was created by a single annotator. Future work should involve a second annotator and measure inter-rater agreement with Cohen's Kappa [17], following the methodology of Saavedra and Ferreira [3] who used 7 independent raters.

**Data leakage:** LLMs may have seen IaC scripts during pre-training. Mitigated by using custom-crafted files (not taken from public repositories), following the data leakage protocol of SecLLM [1] (Section IV-D, four-experiment protocol).

---

## 10. Summary Table — All Metrics

| Metric | Layer | Formula | Source | Target |
|---|---|---|---|---|
| Precision | Detection | $TP/(TP+FP)$ | [1][2][3][4] | > 0.85 |
| Recall | Detection | $TP/(TP+FN)$ | [1][2][3][4] | > 0.85 |
| Macro-F1 | Detection | $2PR/(P+R)$ avg over categories | [1][2][3] | > 0.80 |
| SD across 5 runs | Detection | $\sigma$ of metric | [1] | < 0.05 |
| Hit Rate@5 | Retrieval | relevant in top-5 / total queries | [7][8] | > 0.80 |
| MRR@5 | Retrieval | $\frac{1}{|Q|}\sum 1/\text{rank}$ | [9][7] | > 0.70 |
| Context Recall | Retrieval | attributable sentences / total | [7] | > 0.70 |
| Context Precision | Retrieval | weighted $P@K$ | [7] | > 0.75 |
| Patch Validity Rate | Remediation | valid patches / total | This work | > 0.70 |
| Smell Elim. Rate | Remediation | smells removed / targeted | This work | > 0.80 |
| No-New-Issues Rate | Remediation | 0-regression patches / total | This work | > 0.90 |
| Confidence calibration | Remediation | Wilcoxon $p < 0.05$ | [1][12] | threshold > 0.80 |
| FA-SR | Agentic | valid@attempt1 / total | This work, [14] | > 0.50 |
| $\Delta R@3$ | Agentic | $\text{SR}@3 - \text{FA-SR}$ | [14] | > 0.10 |
| Fleiss' Kappa | Determinism | $(P_o - P_e)/(1-P_e)$ | [15][1] | > 0.90 |
| Raw % Agreement | Determinism | agree / total | [1] | > 0.95 |
| Cost / script (USD) | Operational | tokens × price | [1] | < $0.05 |
| Cost / valid patch | Operational | total cost / valid patches | [1] | < $0.10 |

---

## References

[1] G. De Vito, F. Palomba, and F. Ferrucci, "SecLLM: Enhancing Security Smell Detection in IaC With Large Language Models," *IEEE Access*, vol. 13, pp. 204480–204498, 2025.
DOI: [10.1109/ACCESS.2025.3617505](https://doi.org/10.1109/ACCESS.2025.3617505)

[2] A. War, A. N. Rawass, A. K. Kabore, J. Samhi, J. Klein, and T. F. Bissyande, "Detection of Security Smells in IaC Scripts through Semantics-Aware Code and Language Processing," *arXiv preprint*, arXiv:2509.18790v1, Sep. 2025.
URL: [https://arxiv.org/abs/2509.18790](https://arxiv.org/abs/2509.18790)

[3] N. Saavedra and J. F. Ferreira, "GLITCH: Automated Polyglot Security Smell Detection in Infrastructure as Code," in *Proc. 37th IEEE/ACM Int. Conf. Automated Softw. Eng. (ASE)*, 2022, pp. 1–12.
DOI: [10.1145/3551349.3556945](https://doi.org/10.1145/3551349.3556945)

[4] A. Rahman, C. Parnin, and L. Williams, "The Seven Sins: Security Smells in Infrastructure as Code Scripts," in *Proc. 41st IEEE/ACM Int. Conf. Softw. Eng. (ICSE)*, 2019, pp. 164–175.
DOI: [10.1109/ICSE.2019.00033](https://doi.org/10.1109/ICSE.2019.00033)

[5] S. Dalla Palma, D. Di Nucci, F. Palomba, and D. A. Tamburri, "Within-Project Defect Prediction of Infrastructure-as-Code Using Product and Process Metrics," *IEEE Trans. Softw. Eng.*, vol. 48, no. 6, pp. 2086–2104, Jun. 2022.
DOI: [10.1109/TSE.2020.3040028](https://doi.org/10.1109/TSE.2020.3040028)

[6] S. Ouyang, J. M. Zhang, M. Harman, and M. Wang, "An Empirical Study of the Non-determinism of ChatGPT in Code Generation," *ACM Trans. Softw. Eng. Methodol.*, vol. 34, no. 2, pp. 1–28, Feb. 2025.
DOI: [10.1145/3697010](https://doi.org/10.1145/3697010)

[7] S. Es, J. James, L. Espinosa-Anke, and S. Schockaert, "RAGAS: Automated Evaluation of Retrieval Augmented Generation," in *Proc. 18th Conf. European Chapter of the ACL (EACL)*, 2024.
arXiv: [https://arxiv.org/abs/2309.15217](https://arxiv.org/abs/2309.15217)

[8] Z. Jiang, F. F. Xu, L. Gao, Z. Sun, Q. Liu, J. Dwivedi-Yu, Y. Yang, J. Callan, and G. Neubig, "Active Retrieval Augmented Generation," in *Proc. EMNLP*, 2023.
arXiv: [https://arxiv.org/abs/2305.06983](https://arxiv.org/abs/2305.06983)

[9] C. D. Manning, P. Raghavan, and H. Schütze, *Introduction to Information Retrieval*. Cambridge, UK: Cambridge University Press, 2008.
URL: [https://nlp.stanford.edu/IR-book/](https://nlp.stanford.edu/IR-book/)

[10] Bridgecrew, "Checkov — Static Analysis for Infrastructure as Code," 2024.
URL: [https://www.checkov.io](https://www.checkov.io)

[11] X. Lyu, S. Wang, C. Li, and C. Liu, "PatchEval: A Benchmark for Evaluating LLMs on Patching Real-World Vulnerabilities," *arXiv preprint*, arXiv:2511.11019, Nov. 2024.
URL: [https://arxiv.org/abs/2511.11019](https://arxiv.org/abs/2511.11019)

[12] F. Wilcoxon, "Individual Comparisons by Ranking Methods," *Biometrics Bulletin*, vol. 1, no. 6, pp. 80–83, 1945.
DOI: [10.2307/3001968](https://doi.org/10.2307/3001968)

[13] S. Holm, "A Simple Sequentially Rejective Multiple Test Procedure," *Scandinavian Journal of Statistics*, vol. 6, no. 2, pp. 65–70, 1979.
URL: [https://www.jstor.org/stable/4615733](https://www.jstor.org/stable/4615733)

[14] A. Madaan, N. Tandon, P. Gupta, S. Hallinan, L. Gao, S. Wiegreffe, U. Alon, N. Dziri, S. Prabhumoye, Y. Yang, S. Gupta, B. P. Majumder, K. Hermann, S. Welleck, A. Yazdanbakhsh, and P. Clark, "SELF-REFINE: Iterative Refinement with Self-Feedback," in *Advances in Neural Information Processing Systems (NeurIPS)*, vol. 36, 2023.
arXiv: [https://arxiv.org/abs/2303.17651](https://arxiv.org/abs/2303.17651)

[15] J. L. Fleiss, B. Levin, and M. C. Paik, *Statistical Methods for Rates and Proportions*, 3rd ed. Hoboken, NJ, USA: Wiley, 2013.

[16] J. R. Landis and G. G. Koch, "The Measurement of Observer Agreement for Categorical Data," *Biometrics*, vol. 33, no. 1, pp. 159–174, Mar. 1977.
DOI: [10.2307/2529310](https://doi.org/10.2307/2529310)

[17] J. Cohen, "A Coefficient of Agreement for Nominal Scales," *Educational and Psychological Measurement*, vol. 20, no. 1, pp. 37–46, 1960.
DOI: [10.1177/001316446002000104](https://doi.org/10.1177/001316446002000104)

[18] S. Reis, R. Abreu, M. d'Amorim, and D. Fortunato, "Leveraging Practitioners' Feedback to Improve a Security Linter," in *Proc. 37th IEEE/ACM Int. Conf. Automated Softw. Eng. (ASE)*, 2022, pp. 1–12.
DOI: [10.1145/3551349.3561161](https://doi.org/10.1145/3551349.3561161)
