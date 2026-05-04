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
6. [Quick Demo CLI](#6-quick-demo-cli)
7. [Running Each Module Individually](#7-running-each-module-individually)
8. [Running the Full Pipeline](#8-running-the-full-pipeline)
9. [Running the Evaluation](#9-running-the-evaluation)
10. [Environment Variables Reference](#10-environment-variables-reference)
11. [API Backends Supported](#11-api-backends-supported)
12. [Dataset Overview](#12-dataset-overview)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Project Overview

This framework takes an IaC script (Terraform, Ansible, Kubernetes, or Dockerfile) and:

1. **Detects** security smells using Checkov + heuristic rules
2. **Retrieves** relevant fixes from a RAG knowledge base (War et al. 62-category taxonomy, extended locally to 65 entries)
3. **Generates** a patch using an LLM (DeepSeek / OpenAI / Anthropic / OpenRouter / local via Ollama)
4. **Validates** the patch by re-running Checkov before/after
5. **Formats** a unified diff with CWE-referenced explanations

```
IaC Script
    │
    ▼
[Contextual Analyzer]  — detects tool type + smells (Checkov + heuristics)
    │
    ▼
[Knowledge Retriever]  — RAG query against the ChromaDB vector store
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
cd Code
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

Create `.env` locally and set your provider key:

```bash
# .env (never commit this file)
DEEPSEEK_API_KEY=your-key-here
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_BASE_URL=https://api.deepseek.com
```

**Common variables by provider:**

| Provider | Variables |
|----------|-----------|
| DeepSeek | `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL`, `DEEPSEEK_BASE_URL` |
| OpenAI | `OPENAI_API_KEY` |
| OpenRouter | `OPENROUTER_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Ollama (local) | `OLLAMA_MODEL`, `OLLAMA_BASE_URL` |

The generator also reads these standard env vars directly:
- `ANTHROPIC_API_KEY` → uses Anthropic Claude
- `DEEPSEEK_API_KEY` → uses DeepSeek
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

STEP 3 — Testing LLM backend connection
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
│   │   └── smells_taxonomy.json       # 62 War et al. categories + 3 local extension entries
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
cd Code
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
| `test_analyzer.py` | Contextual Analyzer | 12 | Optional (falls back to heuristics) |
| `test_formatter.py` | Patch Formatter | 10 | No |
| `test_validator.py` | External Validator | 8 | Yes |
| `test_dataset.py` | Dataset + Taxonomy | 33 | Yes |
| **Total** | | **63** | |

All 63 tests pass on Python 3.13, Checkov 3.2.513.

---

## 6. Quick Demo CLI

For the final presentation, the most reliable demo path is the local analyzer.
It does not require an API key and shows the project value immediately:

```bash
cd Code
source .venv/bin/activate

# Human-readable analysis
python3 scripts/run_agent.py analyze dataset/docker/Dockerfile.node_api_insecure

# JSON output for screenshots, scripts, or result tables
python3 scripts/run_agent.py analyze dataset/ansible/insecure_hardened.yml --json
```

The analyzer combines Checkov findings with project heuristics. The heuristics
cover smells that Checkov may miss, including SSH password authentication,
curl/wget piped to a shell, SETUID/SETGID container binaries, passwordless sudo,
and unpinned `latest` base images.

To run the full agentic loop, configure one LLM backend first:

```bash
# Example: DeepSeek
export DEEPSEEK_API_KEY="your-key-here"
export DEEPSEEK_MODEL="deepseek-v4-flash"

# Or OpenAI
export OPENAI_API_KEY="sk-..."

# Or local Ollama
export OLLAMA_MODEL="iac-fixer"
export OLLAMA_BASE_URL="http://localhost:11434/v1"
```

Then run:

```bash
python3 scripts/run_agent.py full dataset/terraform/insecure_s3.tf --model deepseek-v4-flash
python3 scripts/run_agent.py full dataset/docker/Dockerfile.node_api_insecure --json
```

For a focused live demo, start with a small target set:

```bash
python3 scripts/run_agent.py full dataset/terraform/insecure_s3.tf \
  --model deepseek-v4-flash \
  --no-self-consistency \
  --max-smells 3
```

The full mode builds/uses the ChromaDB knowledge base, retrieves relevant
taxonomy entries, asks the selected model for patches, validates candidates with
available scanners, and prints the validated patch plus explanation.

---

## 7. Running Each Module Individually

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

# Uses DEEPSEEK_API_KEY / OPENROUTER_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY from env
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
# DeepSeek
generator = FixGenerator(model='deepseek-v4-flash')

# Free model via OpenRouter
generator = FixGenerator(model='meta-llama/llama-3.1-8b-instruct:free')

# Local Ollama model
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

## 8. Running the Full Pipeline

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

## 9. Running the Evaluation

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

## 10. Environment Variables Reference

All variables are stored in `Code/.env`. Never commit this file.

| Variable | Purpose | Example |
|----------|---------|---------|
| `DEEPSEEK_API_KEY` | DeepSeek API key | `sk-...` |
| `DEEPSEEK_MODEL` | DeepSeek model name | `deepseek-v4-flash` |
| `DEEPSEEK_BASE_URL` | DeepSeek OpenAI-compatible endpoint | `https://api.deepseek.com` |
| `ANTHROPIC_API_KEY` | Anthropic Claude key | `sk-ant-...` |
| `OPENROUTER_API_KEY` | OpenRouter key (free models available) | `sk-or-v1-...` |
| `OPENAI_API_KEY` | OpenAI key | `sk-...` |
| `OLLAMA_MODEL` | Local Ollama model | `gemma3:4b` |
| `OLLAMA_BASE_URL` | Local Ollama server | `http://localhost:11434/v1` |
| `CHROMA_PERSIST_DIR` | Where ChromaDB stores data | `./chroma_db` |

The `FixGenerator` auto-detects the backend in this priority order:
`ANTHROPIC_API_KEY` → `DEEPSEEK_API_KEY` → `OPENROUTER_API_KEY` → `OLLAMA_MODEL` → `OPENAI_API_KEY`

---

## 11. API Backends Supported

### DeepSeek

```bash
# .env
DEEPSEEK_API_KEY=your-key
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_BASE_URL=https://api.deepseek.com
```

Use `deepseek-v4-flash` for fast and economical tests. You can switch to
`deepseek-v4-pro` by changing `DEEPSEEK_MODEL`.

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
OLLAMA_MODEL=qwen2.5-coder:3b
OLLAMA_BASE_URL=http://localhost:11434/v1
```

```python
FixGenerator("qwen2.5-coder:3b")   # best for IaC/code tasks on limited hardware
FixGenerator("gemma3:4b")
FixGenerator("phi4-mini")
```

---

## 12. Dataset Overview

The dataset contains 16 insecure IaC files with 79 annotated security smells.

| Tool | Files | Smells | Detection Method |
|------|-------|--------|-----------------|
| Terraform | 5 | 22 | Checkov |
| Ansible | 3 | 13 | Heuristic (no Checkov support) |
| Kubernetes | 3 | 13 | Checkov |
| Docker | 5 | 31 | Checkov |
| **Total** | **16** | **79** | |

**Taxonomy:** `dataset/taxonomy/smells_taxonomy.json` — 65 implementation entries across 3 categories. The base reference is the 62-category taxonomy of War et al. (2025); this project adds 3 local extension entries for benchmark coverage:
- `SS-063` — SSH Password Authentication Enabled
- `SS-064` — SETUID/SETGID Binary in Container
- `SS-065` — Remote Script Execution Without Integrity Check

Current category counts:
- **Security** (52 entries) — credentials, permissions, privilege escalation
- **Configuration Data** (8 entries) — missing configs, deprecated settings
- **Dependency** (5 entries) — unpinned images, supply chain risks

> This `dataset/` folder is the hand-crafted evaluation benchmark. The
> large-scale scraped corpus used for fine-tuning (33,667 records) is produced
> by `scraping/` and published separately at
> **https://github.com/Ahmedouyahya/iac-security-dataset**.

---

## 13. Troubleshooting

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

The API key or base URL is wrong. Open `.env` and check the variables for your provider.

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
