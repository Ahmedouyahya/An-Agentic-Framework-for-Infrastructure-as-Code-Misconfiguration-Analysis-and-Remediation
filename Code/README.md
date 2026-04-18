# Agentic IaC Security Framework — Developer Guide

**Author:** Ahmedou Yahye Kheyri  
**Supervisor:** Pr. Hala Bezine  
**Institution:** Faculté des Sciences de Sfax — Master MRSI

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Prerequisites](#2-prerequisites)
3. [Setup](#3-setup)
4. [Directory Structure](#4-directory-structure)
5. [Running the Tests](#5-running-the-tests)
6. [Running Each Module Individually](#6-running-each-module-individually)
7. [Running the Full Pipeline](#7-running-the-full-pipeline)
8. [Running the Evaluation](#8-running-the-evaluation)
9. [Environment Variables Reference](#9-environment-variables-reference)
10. [API Backends Supported](#10-api-backends-supported)
11. [Dataset Overview](#11-dataset-overview)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Project Overview

This framework takes an IaC script (Terraform, Ansible, Kubernetes, or Dockerfile) and:

1. **Detects** security smells using Checkov + heuristic rules
2. **Retrieves** relevant fixes from a RAG knowledge base (65-entry taxonomy)
3. **Generates** a patch using an LLM (OpenAI / Anthropic / OpenRouter / local via Ollama)
4. **Validates** the patch by re-running Checkov before/after
5. **Formats** a unified diff with CWE-referenced explanations

```
IaC Script
    │
    ▼
[Contextual Analyzer]  — detects tool type + smells (Checkov + heuristics)
    │
    ▼
[Knowledge Retriever]  — RAG query against 65-smell ChromaDB vector store
    │
    ▼
[Fix Generator]        — LLM generates unified diff patch
    │
    ▼
[External Validator]   — Checkov before/after comparison
    │
  valid? ──NO──► refine query (CRAG retry, max 3x)
    │
   YES
    │
    ▼
[Patch Formatter]      — unified diff + CWE explanation
    │
    ▼
  Result: patch + explanation
```

---

## 2. Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.10+ | system |
| Checkov | 3.2+ | `pip install checkov` |
| patch | any | `sudo apt install patch` |

Check your versions:
```bash
python3 --version
checkov --version
patch --version
```

---

## 3. Setup

### Step 1 — Clone or navigate to the project

```bash
cd /home/ahmedouyahye/Desktop/PFE/Code
```

### Step 2 — Create and activate the virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

> Every time you open a new terminal, run `source .venv/bin/activate` first.

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
pip install checkov pytest pytest-cov
```

### Step 4 — Configure your API key

Open `.env` and set your key and base URL:

```bash
# .env (already created — just edit the values)
OPENCODE_API_KEY=sk-your-key-here
OPENCODE_API_BASE=https://api.your-provider.com/v1   # set the correct URL for your service
```

**Common base URLs by provider:**

| Provider | OPENCODE_API_BASE |
|----------|-------------------|
| OpenAI | `https://api.openai.com/v1` |
| OpenRouter | `https://openrouter.ai/api/v1` |
| Groq | `https://api.groq.com/openai/v1` |
| Together AI | `https://api.together.xyz/v1` |
| Ollama (local) | `http://localhost:11434/v1` |

The generator also reads these standard env vars directly:
- `ANTHROPIC_API_KEY` → uses Anthropic Claude
- `OPENROUTER_API_KEY` → uses OpenRouter (many free models)
- `OPENAI_API_KEY` → uses OpenAI

### Step 5 — Verify everything works

```bash
source .venv/bin/activate
python scripts/test_rag_and_api.py
```

Expected output:
```
STEP 1 — Building RAG knowledge base from taxonomy
✓ Knowledge base built successfully

STEP 2 — Testing RAG retrieval
Query: Terraform — hardcoded credential + overly permissive CIDR
[Doc 1] CWE=CWE-798 ...
[Doc 2] CWE=CWE-732 ...

STEP 3 — Testing OpenCode API connection
✓ Connected to API at: https://...
✓ API response: IaC security test OK
```

---

## 4. Directory Structure

```
Code/
├── .env                               # API keys (never commit this)
├── .gitignore
├── requirements.txt
├── README.md                          # This file
├── TESTING.md                         # Detailed test documentation + known bugs
│
├── src/                               # Main framework source
│   ├── agent/
│   │   └── orchestrator.py            # Central Agent — drives the full pipeline loop
│   ├── analyzer/
│   │   └── contextual.py              # Tool detection + Checkov + heuristic smell detection
│   ├── knowledge/
│   │   ├── knowledge_base.py          # ChromaDB vector store (build + query)
│   │   └── retriever.py               # CRAG-style retriever (retry-aware)
│   ├── generator/
│   │   └── fix_generator.py           # LLM patch generation (multi-backend)
│   ├── validator/
│   │   └── tool_integrator.py         # Apply patch → re-run Checkov → compare
│   └── formatter/
│       └── patch_formatter.py         # Unified diff + CWE explanation generator
│
├── dataset/
│   ├── terraform/                     # 5 insecure Terraform files
│   ├── ansible/                       # 3 insecure Ansible playbooks
│   ├── kubernetes/                    # 3 insecure Kubernetes manifests
│   ├── docker/                        # 5 insecure Dockerfiles
│   ├── taxonomy/
│   │   └── smells_taxonomy.json       # 65 IaC security smells (War et al. 2025)
│   └── metadata.json                  # Ground-truth oracle (79 annotated smells)
│
├── tests/
│   ├── test_analyzer.py               # 10 tests — tool detection, metrics, smell detection
│   ├── test_formatter.py              # 8 tests  — explanation, CWE references, diff output
│   ├── test_validator.py              # 7 tests  — Checkov integration per tool type
│   └── test_dataset.py                # 33 tests — metadata integrity, taxonomy, Checkov coverage
│
├── scripts/
│   ├── test_rag_and_api.py            # Quick smoke test: RAG build + API connection
│   ├── evaluate.py                    # 18-metric evaluation (Config A baseline → Config D full)
│   ├── evaluation_results.json        # Latest saved evaluation results
│   └── run_checkov.sh                 # Batch Checkov scan on all dataset files
│
├── notebooks/                         # Jupyter notebooks for experiments
└── chroma_db/                         # ChromaDB vector store (auto-created on first run)
```

---

## 5. Running the Tests

All tests use pytest. Activate the venv first.

```bash
source .venv/bin/activate
cd /home/ahmedouyahye/Desktop/PFE/Code
```

### Run all tests

```bash
python -m pytest tests/ -v
```

### Run a specific test file

```bash
python -m pytest tests/test_analyzer.py -v      # tool detection + metrics
python -m pytest tests/test_formatter.py -v     # explanation + diff output
python -m pytest tests/test_validator.py -v     # Checkov integration
python -m pytest tests/test_dataset.py -v       # dataset + taxonomy integrity
```

### Run with coverage report

```bash
python -m pytest tests/ --cov=src --cov-report=term-missing
```

### Run fast tests only (no Checkov calls)

```bash
python -m pytest tests/test_formatter.py tests/test_analyzer.py -v
```

### Run a single test by name

```bash
python -m pytest tests/test_analyzer.py::TestToolDetection::test_terraform_file_detected -v
python -m pytest tests/test_dataset.py::TestTaxonomyIntegrity::test_taxonomy_has_at_least_62_entries -v
```

### Test Suite Summary

| File | Module | Tests | Requires Checkov |
|------|--------|-------|-----------------|
| `test_analyzer.py` | Contextual Analyzer | 10 | Optional (falls back to heuristics) |
| `test_formatter.py` | Patch Formatter | 8 | No |
| `test_validator.py` | External Validator | 7 | Yes |
| `test_dataset.py` | Dataset + Taxonomy | 33 | Yes |
| **Total** | | **58** | |

All 58 tests pass on Python 3.13, Checkov 3.2.513.

---

## 6. Running Each Module Individually

You can test each module in isolation using the Python REPL or a script.

### 6.1 — Contextual Analyzer

Detects the IaC tool type and security smells in a file.

```python
import sys
sys.path.insert(0, 'src')
from analyzer.contextual import ContextualAnalyzer
from pathlib import Path

analyzer = ContextualAnalyzer()
result = analyzer.analyze(Path('dataset/terraform/insecure_s3.tf'))

print("Tool:", result['tool'])
print("Smells found:", len(result['smells']))
print("Metrics:", result['metrics'])
for smell in result['smells']:
    print(f"  Line {smell['line']}: [{smell['checker_id']}] {smell['description']}")
```

Try with other files:
```python
# Ansible
analyzer.analyze(Path('dataset/ansible/insecure_webserver.yml'))

# Kubernetes
analyzer.analyze(Path('dataset/kubernetes/insecure_deployment.yaml'))

# Dockerfile
analyzer.analyze(Path('dataset/docker/Dockerfile.insecure'))
```

### 6.2 — Knowledge Base (RAG)

Builds the vector store and queries it.

```python
import sys
sys.path.insert(0, 'src')
from knowledge.knowledge_base import KnowledgeBase

# Build once (persists to ./chroma_db)
kb = KnowledgeBase(persist_dir='./chroma_db')
kb.build()

# Query
results = kb.query('hardcoded password in Terraform provider block', n_results=3)
for doc in results:
    print(f"CWE={doc['metadata']['cwe']}  distance={doc['distance']:.3f}")
    print(doc['text'][:200])
    print()
```

### 6.3 — Knowledge Retriever (CRAG)

Builds a formatted context string from detected smells.

```python
import sys
sys.path.insert(0, 'src')
from knowledge.knowledge_base import KnowledgeBase
from knowledge.retriever import KnowledgeRetriever

kb = KnowledgeBase('./chroma_db')
kb.build()
retriever = KnowledgeRetriever(kb, n_results=5)

smells = [
    {'type': 'hardcoded_credential', 'description': 'AWS access key hardcoded'},
    {'type': 'overly_permissive_cidr', 'description': '0.0.0.0/0 in security group'},
]
context = retriever.retrieve(smells, iac_tool='terraform')
print(context)

# Retry with more conservative query (CRAG strategy)
context_retry = retriever.retrieve(smells, iac_tool='terraform', retry=1)
```

### 6.4 — Fix Generator (LLM)

Generates a patch given a file, smells, and RAG context.
Requires an API key in `.env`.

```python
import sys
from dotenv import load_dotenv
from pathlib import Path
load_dotenv('.env')

sys.path.insert(0, 'src')
from generator.fix_generator import FixGenerator

# Uses OPENROUTER_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY from env
generator = FixGenerator()  # auto-detects backend

patches = generator.generate(
    script_path=Path('dataset/terraform/insecure_s3.tf'),
    smells=[{'type': 'overly_permissive_acl', 'description': 'public-read ACL', 'cwe': 'CWE-732', 'line': 18}],
    rag_context="Fix: change ACL to private. Never use public-read on S3 buckets.",
)
for patch in patches:
    print(patch[:500])
```

To use a specific model:
```python
# Free model via OpenRouter
generator = FixGenerator(model='meta-llama/llama-3.1-8b-instruct:free')

# MiniMax via OpenRouter
generator = FixGenerator(model='minimax/minimax-01')

# Local Ollama model (set OPENAI_API_KEY=ollama and base URL in .env)
generator = FixGenerator(model='qwen2.5-coder:3b')
```

### 6.5 — External Validator (Checkov)

Applies a patch and validates it with Checkov.

```python
import sys
sys.path.insert(0, 'src')
from validator.tool_integrator import ExternalToolValidator
from pathlib import Path

validator = ExternalToolValidator()
result = validator.validate(
    original_path=Path('dataset/terraform/insecure_s3.tf'),
    patch="--- a/insecure_s3.tf\n+++ b/insecure_s3.tf\n@@ -18 +18 @@\n- acl = \"public-read\"\n+ acl = \"private\"\n",
    smells=[{'checker_id': 'CKV_AWS_20'}],
)
print("Valid:", result['valid'])
print("Removed:", result['removed_smells'])
print("New issues:", result['new_smells'])
print("Details:", result['details'])
```

### 6.6 — Patch Formatter

Formats a patch with CWE-referenced explanations.

```python
import sys
sys.path.insert(0, 'src')
from formatter.patch_formatter import PatchFormatter
from pathlib import Path

formatter = PatchFormatter()
result = formatter.format(
    original_path=Path('dataset/terraform/insecure_s3.tf'),
    patch="--- a/insecure_s3.tf\n+++ b/insecure_s3.tf\n@@ -18 +18 @@\n- acl = \"public-read\"\n+ acl = \"private\"\n",
    smells=[{
        'type': 'overly_permissive_acl',
        'cwe': 'CWE-732',
        'line': 18,
        'description': 'S3 bucket ACL set to public-read',
    }],
)
print(result['diff'])
print(result['explanation'])
```

---

## 7. Running the Full Pipeline

This wires all 6 modules together through the Central Agent.

```python
import sys
from dotenv import load_dotenv
from pathlib import Path
load_dotenv('.env')

sys.path.insert(0, 'src')
from agent.orchestrator import CentralAgent
from analyzer.contextual import ContextualAnalyzer
from knowledge.knowledge_base import KnowledgeBase
from knowledge.retriever import KnowledgeRetriever
from generator.fix_generator import FixGenerator
from validator.tool_integrator import ExternalToolValidator
from formatter.patch_formatter import PatchFormatter

# Build knowledge base (only needed once per session)
kb = KnowledgeBase(persist_dir='./chroma_db')
kb.build()

# Assemble the agent
agent = CentralAgent(
    analyzer=ContextualAnalyzer(),
    retriever=KnowledgeRetriever(kb, n_results=5),
    generator=FixGenerator(),          # auto-detects backend from env
    validator=ExternalToolValidator(),
    formatter=PatchFormatter(),
)

# Run on any IaC file
result = agent.run('dataset/terraform/insecure_s3.tf')

print("Success:", result['success'])
print("Smells detected:", len(result['smells']))
print()
if result['patch']:
    print("=== PATCH ===")
    print(result['patch'])
    print()
print("=== EXPLANATION ===")
print(result['explanation'])
```

Try all dataset files:
```python
files = [
    'dataset/terraform/insecure_s3.tf',
    'dataset/terraform/insecure_ec2.tf',
    'dataset/terraform/insecure_iam.tf',
    'dataset/ansible/insecure_webserver.yml',
    'dataset/kubernetes/insecure_deployment.yaml',
    'dataset/docker/Dockerfile.insecure',
]
for f in files:
    result = agent.run(f)
    status = "OK" if result['success'] else "FAIL"
    print(f"[{status}] {f} — {len(result['smells'])} smells")
```

---

## 8. Running the Evaluation

The evaluation script measures 18 metrics across all dataset files.

### Config A — Checkov baseline (no LLM, no API key needed)

```bash
source .venv/bin/activate
python scripts/evaluate.py --mode baseline
```

Results are saved to `scripts/evaluation_results.json`.

### Config D — Full pipeline (LLM required)

```bash
# Set your API key first, then:
export OPENROUTER_API_KEY="sk-or-..."
python scripts/evaluate.py --mode full --model "meta-llama/llama-3.1-8b-instruct:free"

# Or with Anthropic:
export ANTHROPIC_API_KEY="sk-ant-..."
python scripts/evaluate.py --mode full
```

### Batch Checkov scan

Scans all dataset files and saves individual JSON reports:

```bash
bash scripts/run_checkov.sh
# Reports saved to: results/checkov/
```

---

## 9. Environment Variables Reference

All variables are stored in `Code/.env`. Never commit this file.

| Variable | Purpose | Example |
|----------|---------|---------|
| `OPENCODE_API_KEY` | Your API key | `sk-abc123...` |
| `OPENCODE_API_BASE` | API endpoint URL | `https://openrouter.ai/api/v1` |
| `ANTHROPIC_API_KEY` | Anthropic Claude key | `sk-ant-...` |
| `OPENROUTER_API_KEY` | OpenRouter key (free models available) | `sk-or-v1-...` |
| `MINIMAX_API_KEY` | MiniMax direct API key | `...` |
| `OPENAI_API_KEY` | OpenAI key | `sk-...` |
| `OLLAMA_BASE_URL` | Local Ollama server | `http://localhost:11434` |
| `CHROMA_PERSIST_DIR` | Where ChromaDB stores data | `./chroma_db` |

The `FixGenerator` auto-detects the backend in this priority order:
`ANTHROPIC_API_KEY` → `OPENROUTER_API_KEY` → `MINIMAX_API_KEY` → `OPENAI_API_KEY`

---

## 10. API Backends Supported

### OpenRouter (recommended — free models available)

```bash
# .env
OPENROUTER_API_KEY=sk-or-v1-your-key
```

Free models you can use:
```python
FixGenerator("meta-llama/llama-3.1-8b-instruct:free")  # fast, good at code
FixGenerator("mistralai/mistral-7b-instruct:free")
FixGenerator("minimax/minimax-01")                       # strong reasoning
FixGenerator("google/gemma-3-12b-it:free")              # Gemma 3
```

### Anthropic Claude

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-your-key
```

```python
FixGenerator("claude-sonnet-4-6")   # best quality
FixGenerator("claude-haiku-4-5")    # fastest + cheapest
```

### Ollama (fully local, no API key)

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a model
ollama pull qwen2.5-coder:3b

# 3. Set in .env
OPENAI_API_KEY=ollama
OPENCODE_API_BASE=http://localhost:11434/v1
```

```python
FixGenerator("qwen2.5-coder:3b")   # best for IaC/code tasks on limited hardware
FixGenerator("gemma3:4b")
FixGenerator("phi4-mini")
```

---

## 11. Dataset Overview

The dataset contains 16 insecure IaC files with 79 annotated security smells.

| Tool | Files | Smells | Detection Method |
|------|-------|--------|-----------------|
| Terraform | 5 | 22 | Checkov |
| Ansible | 3 | 13 | Heuristic (no Checkov support) |
| Kubernetes | 3 | 13 | Checkov |
| Docker | 5 | 31 | Checkov |
| **Total** | **16** | **79** | |

**Taxonomy:** `dataset/taxonomy/smells_taxonomy.json` — 65 smell types across 3 categories:
- **Security** (49 entries) — credentials, permissions, privilege escalation
- **Configuration Data** (10 entries) — missing configs, deprecated settings
- **Dependency** (6 entries) — unpinned images, supply chain risks

> This `dataset/` folder is the hand-crafted evaluation benchmark. The
> large-scale scraped corpus used for fine-tuning (33,667 records) is produced
> by `scraping/` and published separately at
> **https://github.com/Ahmedouyahya/iac-security-dataset**.

---

## 12. Troubleshooting

### `ModuleNotFoundError: No module named 'chromadb'`

The venv is not activated or packages are not installed:
```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### `Checkov not available` warning in tests

Install Checkov in the venv:
```bash
pip install checkov
```

### Checkov returns empty output on YAML files

Checkov may need the framework specified explicitly:
```bash
checkov --file dataset/kubernetes/insecure_deployment.yaml --framework kubernetes --output json
```

### API returns 401 Unauthorized

The API key or base URL is wrong. Open `.env` and check `OPENCODE_API_BASE` matches your provider.

### ChromaDB error on second run: `Collection already exists`

The vector store is already built. This is normal — `get_or_create_collection` handles it.
To rebuild from scratch:
```bash
rm -rf chroma_db/
python scripts/test_rag_and_api.py
```

### Patch application fails in validator

The `patch` command must be installed:
```bash
sudo apt install patch
```

### Tests fail with `assert result["tool"] == "kubernetes"` → got `"ansible"`

This was a known bug (fixed). Both use YAML; the analyzer now checks Kubernetes markers first.
Make sure you have the latest version of `src/analyzer/contextual.py`.
