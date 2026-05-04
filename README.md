# An Agentic Framework for Infrastructure-as-Code Misconfiguration Analysis and Remediation

Master's thesis (PFE) — **Mastère MRSI**, Faculté des Sciences de Sfax,
Université de Sfax.

- **Student:** Ahmedou Yahye Kheyri
- **Supervisor:** Hala Bezine
- **Keywords:** agentic framework, IaC misconfigurations, RAG, Self-RAG / CRAG,
  external tool validation.

---

## 1. Problem Statement

A standard Retrieval-Augmented Generation (RAG) system is, at best, a
well-informed *responder*: it produces security advice without any means of
verifying whether that advice is correct, applicable to the code under
analysis, or actually effective at removing the underlying risk. For
Infrastructure-as-Code (IaC), where a single misconfiguration can expose
production assets, this lack of self-verification is a real risk.

The aim of this thesis is to turn the RAG pipeline into an **active,
critical agent** that does not merely suggest fixes but also challenges
them, validates them using specialised security tools, and returns a
concrete patch the developer can apply directly — moving from *informative
assistance* to a *trustworthy technical collaborator*.

## 2. Tasks (from the subject proposal)

1. **Response validation mechanism.** Design a self-verification loop that
   confirms generated security recommendations are correct, applicable to
   the IaC script under analysis, and genuinely reduce the identified risks.
2. **Advanced remediation beyond CRAG.** Go past purely retrieval-based
   correction by introducing iterative, critical, context-aware fix
   strategies.
3. **Integrate specialised security scanners.** Use industry tools such as
   Checkov (and additional IaC scanners) to automatically verify proposed
   patches and provide cross-validation independent of the language model.
4. **Actionable, ready-to-use corrections.** Produce secure IaC patches
   that developers can apply directly, accompanied by clear technical
   explanations that justify each remediation choice.

## 3. Framework Overview

The framework is organised as seven modules coordinated by a **Central
Agent**:

| # | Module                                 | Role                                                                                                   |
|---|----------------------------------------|--------------------------------------------------------------------------------------------------------|
| 1 | Central Agent                          | Orchestrator of the iterative analyse → retrieve → generate → validate → refine loop.                  |
| 2 | Contextual Analyzer                    | Identifies the IaC tool and pinpoints risky regions using structural metrics and a code model.         |
| 3 | Knowledge Base                         | Vector DB seeded from the War et al. 62-category IaC security smell taxonomy, extended in this implementation to 65 entries. |
| 4 | Knowledge Retriever (CRAG / Self-RAG)  | Fetches relevant security patterns and fix examples for the flagged smell.                             |
| 5 | Fix Generator                          | A fine-tuned small LLM that produces candidate patches with confidence scores.                         |
| 6 | External Tool Integrator               | Runs Checkov and KICS-oriented validation hooks to check each candidate patch.                         |
| 7 | Patch Formatter & Explanation Generator| Emits a unified diff plus a natural-language rationale with CWE references.                            |

```
IaC Script → Contextual Analyzer → RAG Retriever → Fix Generator
                                                        │
                    ┌── Valid? ← Checkov / KICS
                    │
             YES  → Format patch + explanation → return to user
             NO   → Refine (loop back to Fix Generator)
```

The external validators are the mechanism that breaks the RAG
overfitting / underfitting failure mode: the LLM's output is never trusted
until at least one independent scanner confirms the smell is gone and no
new finding was introduced.

## 4. Repository Layout

```
PFE/
├── Code/              Source code of the framework, scraping pipeline, and
│                      QLoRA fine-tuning scripts.
├── Bibliographie/     ~50 research papers (RAG, IaC security, LLM agents).
├── Rapports/          Thesis drafts (progress reports) and the final report.
├── Presentations/     Defense slides (Beamer).
├── Documentation/     Architecture diagrams and meeting notes.
├── Ressources/        Sample IaC files and tool documentation.
└── sijet/             The original subject proposal.
```

See **`Code/README.md`** for setup, how to run the framework end-to-end,
the evaluation protocol, and the folder-level README files for the
scraping pipeline (`Code/scraping/`) and the fine-tuning pipeline
(`Code/training/`).

## 5. Datasets

Two distinct datasets are used, with different purposes:

- **Evaluation benchmark** — `Code/dataset/`: a hand-crafted set of 16
  deliberately-insecure IaC files (Terraform, Docker, Kubernetes, Ansible)
  with 79 annotated smells. Used as ground truth for integration tests and
  for the Configuration A / B / C comparisons reported in the thesis.
- **Fine-tuning corpus** — scraped via `Code/scraping/` from GitHub commit
  history, GHArchive, GitLab, and the test suites of Checkov / KICS / tfsec.
  The frozen **v1** release contains 33,667 deduplicated records validated
  by static scanners and is published separately at:
  **https://github.com/Ahmedouyahya/iac-security-dataset**

## 6. Stack

- **Language:** Python 3.12
- **RAG / orchestration:** LangChain, ChromaDB
- **LLM APIs:** DeepSeek / OpenAI / Anthropic / OpenRouter / Ollama (pluggable)
- **Fine-tuned local model:** `google/gemma-2-2b-it` with QLoRA (see
  `Code/training/trainning/README.md`), served via Ollama
- **IaC scanners:** Checkov, KICS; tfsec fixtures are used only as historical dataset sources
- **Reports / slides:** LaTeX (`glossaries`, `tcolorbox`, `tikz`, Beamer)

## 7. Status

Implementation phase. The theoretical design is complete and documented
in the progress reports (`Rapports/drafts/`). A first, preliminary
QLoRA fine-tuning experiment is documented in
`Rapports/drafts/rapport5/` — see that report for the exact scope,
results and limitations of that experiment.

## 8. Key References

1. Yao, S., et al. (2024). *CRAG: Corrective Retrieval Augmented Generation*. arXiv:2401.15884.
2. Asai, A., et al. (2023). *Self-RAG: Learning to Retrieve, Generate, and Critique through Self-Reflection*. arXiv:2310.11511.
3. Jiang, Z., et al. (2023). *Active Retrieval Augmented Generation*. EMNLP.
4. Schick, T., et al. (2023). *Toolformer: Language Models Can Teach Themselves to Use Tools*. arXiv:2302.04761.
5. Chen, Z., et al. (2023). *Towards Reliable AI for Code Security: Verification Mechanisms for Retrieval-Augmented Systems*. ACM CCS Workshop on AI and Security.

Full annotated bibliography in `Bibliographie/README.md`.
