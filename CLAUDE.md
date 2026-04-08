# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Master's thesis research project (PFE - Projet de Fin d'Études) at the Faculty of Sciences of Sfax, Tunisia. The goal is to design and implement an **agentic framework for Infrastructure as Code (IaC) security analysis and remediation**.

- **Student:** Ahmedou Yahye Kheyri
- **Supervisor:** Hala Bezine
- **Status:** Implementation phase (theoretical design complete)

## Implementation Stack

- **Language:** Python
- **RAG/LLM orchestration:** LangChain or LlamaIndex
- **IaC security scanners:** Checkov, GLITCH, Terrascan
- **LLM APIs:** OpenAI, Anthropic, or similar
- **Code analysis models:** CodeBERT, LongFormer
- **Fine-tuned models for fix generation:** GenSIAC, SecLLM

## Directory Layout

```
Code/           Source code (to be implemented)
Bibliographie/  40+ research papers on RAG, IaC security, LLMs
Rapports/       Thesis documents (drafts/, final/, soutenance/)
Presentations/  Defense slides
sijet/          Thesis subject proposal and RAG guide
Ressources/     Datasets, IaC samples, tool documentation
Documentation/  Architecture diagrams, meeting notes
```

## Intended Code Structure (per `Code/README.md`)

```
Code/
  src/          Main framework source
  tests/        Unit and integration tests
  notebooks/    Jupyter notebooks for experiments
  scripts/      Utility scripts
```

## System Architecture

The framework has 7 modules orchestrated by a **Central Agent**:

1. **Central Agent** — Orchestrator; receives IaC scripts, manages the iterative workflow loop
2. **Contextual Analyzer** — Uses CodeBERT + structural metrics to identify the IaC tool type and pinpoint risk areas
3. **Knowledge Base** — Vector DB built from a 62-category IaC security smell taxonomy (Configuration Data, Dependency, Security categories)
4. **Knowledge Retriever** — RAG/CRAG component that fetches relevant security patterns and fix examples
5. **Fix Generator** — Fine-tuned LLM (GenSIAC/SecLLM) that produces security patches with confidence scores
6. **External Tool Integrator** — Runs Checkov, GLITCH, and Terrascan independently to validate proposed patches
7. **Patch Formatter & Explanation Generator** — Produces unified diffs and natural language explanations with CWE references

### Workflow

```
IaC Script → Contextual Analyzer → RAG Retriever → Fix Generator
                                                         ↓
                     ┌── Valid? ←── Checkov / GLITCH / Terrascan
                     │
              YES → Format patch + CWE explanation → Return to user
              NO  → Refine (iterative loop back to Fix Generator)
```

**Key design decision:** External validators (Checkov/GLITCH/Terrascan) are used to break the RAG overfitting/underfitting problem — the LLM's output is never trusted without tool-based validation.

## Key Research References

The `Bibliographie/` directory contains the theoretical foundation. Notable papers (summarized in `Bibliographie/README.md`):
- CRAG (Corrective RAG) and Self-RAG — active retrieval strategies used as the RAG approach
- Toolformer — inspiration for tool-augmented LLM agents
- GenSIAC / SecLLM — fine-tuned models for secure IaC generation
