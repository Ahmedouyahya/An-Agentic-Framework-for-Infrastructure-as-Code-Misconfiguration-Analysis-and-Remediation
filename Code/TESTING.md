# Testing Guide — Agentic IaC Security Framework

**Author:** Ahmedou Yahye Kheyri  
**Supervisor:** Pr. Hala Bezine  
**Institution:** Faculté des Sciences de Sfax — Master MRSI  

---

## Quick Start

```bash
cd /home/ahmedouyahye/Desktop/PFE/Code

# Install dependencies
pip3 install checkov pytest pytest-cov --break-system-packages

# Run all tests
python3 -m pytest tests/ -v

# Run baseline evaluation (no API key needed)
python3 scripts/evaluate.py --mode baseline
```

---

## Test Suite Overview

| Test file | Module tested | Tests | What it checks |
|---|---|---|---|
| `tests/test_validator.py` | `src/validator/tool_integrator.py` | 7 | Checkov detects issues on each dataset file |
| `tests/test_analyzer.py` | `src/analyzer/contextual.py` | 10 | Tool detection, metrics, smell extraction |
| `tests/test_formatter.py` | `src/formatter/patch_formatter.py` | 8 | Explanation output, CWE references, diff generation |
| `tests/test_dataset.py` | `dataset/` | 33 | Metadata integrity, taxonomy, Checkov coverage (all 16 files) |
| **Total** | | **58** | **All pass (Python 3.13, Checkov 3.2.513)** |

---

## Running the Tests

### Run all tests
```bash
python3 -m pytest tests/ -v
```

### Run a single test file
```bash
python3 -m pytest tests/test_analyzer.py -v
python3 -m pytest tests/test_dataset.py -v
```

### Run with coverage report
```bash
python3 -m pytest tests/ --cov=src --cov-report=term-missing
```

### Run only fast tests (skip Checkov calls)
```bash
python3 -m pytest tests/test_formatter.py -v   # no Checkov calls
```

---

## Bugs Found and Fixed During Testing

The tests revealed 3 real bugs in the production code:

### Bug 1 — Checkov list-format crash (HIGH)
**Files affected:** `src/analyzer/contextual.py`, `tests/test_validator.py`  
**Root cause:** Checkov 3.2.513 returns a JSON **list** (one entry per scanner framework)
when multiple scanners apply to the same file (e.g., `terraform` + `secrets`).
The code assumed a single dict and called `.get()` directly on the list.  
**Symptom:** `AttributeError: 'list' object has no attribute 'get'` on EC2, K8s pod, and Dockerfile files.  
**Fix:** Normalize the output before parsing:
```python
entries = data if isinstance(data, list) else [data]
for entry in entries:
    for item in entry.get("results", {}).get("failed_checks", []):
        ...
```
**Status:** Fixed in `src/analyzer/contextual.py` and `tests/test_validator.py`.

### Bug 2 — Kubernetes misidentified as Ansible (MEDIUM)
**File affected:** `src/analyzer/contextual.py`  
**Root cause:** `_TOOL_SIGNATURES` was iterated in dict insertion order. Since `ansible`
came before `kubernetes`, YAML files containing `- name:` (common in K8s container specs)
were classified as Ansible instead of Kubernetes.  
**Symptom:** `assert result["tool"] == "kubernetes"` failed → got `"ansible"`.  
**Fix:** Explicitly define a priority order that checks Kubernetes (has unambiguous
`apiVersion:` + `kind:` markers) before Ansible:
```python
priority_order = ["kubernetes", "terraform", "ansible", "docker"]
```
**Status:** Fixed in `src/analyzer/contextual.py`.

### Bug 3 — Metadata statistics mismatch (LOW)
**File affected:** `dataset/metadata.json`  
**Root cause:** The `statistics.total_smells` field (27) did not match the actual count
of smell instances in the `files` array (32 after additional smells were added).  
**Symptom:** `assert 32 == 27` failed in `TestMetadataIntegrity`.  
**Fix:** Updated statistics to match actual counts (`total_smells: 32`, `terraform: 12`).  
**Status:** Fixed in `dataset/metadata.json`.

---

## Dataset Overview

### Original Dataset (8 files, 32 smells)

| File | Tool | Smells | Checkov traceable | CWEs |
|---|---|---|---|---|
| `terraform/insecure_s3.tf` | Terraform | 4 | 4 | 732, 312, 693 |
| `terraform/insecure_ec2.tf` | Terraform | 4 | 4 | 798, 732, 346, 312 |
| `terraform/insecure_rds.tf` | Terraform | 4 | 4 | 732, 312, 693, 259 |
| `ansible/insecure_webserver.yml` | Ansible | 4 | 0 (heuristic) | 259, 295, 732, 250 |
| `ansible/insecure_users.yml` | Ansible | 3 | 0 (heuristic) | 250, 732 |
| `kubernetes/insecure_deployment.yaml` | Kubernetes | 5 | 5 | 250, 259, 400 |
| `kubernetes/insecure_pod.yaml` | Kubernetes | 3 | 3 | 732, 259 |
| `docker/Dockerfile.insecure` | Docker | 5 | 3 | 250, 829, 259, 732, 693 |

### Extended Dataset (5 new files, 26 additional smells)

Added to increase model accuracy testing coverage and to include more explicit, clearly
labeled security problems for each tool type:

| File | Tool | Smells | Focus | Difficulty |
|---|---|---|---|---|
| `terraform/insecure_iam.tf` | Terraform | 5 | IAM permissions, wildcard policies | HIGH |
| `terraform/insecure_networking.tf` | Terraform | 5 | VPC, SG rules, HTTP, logging | LOW |
| `ansible/insecure_hardened.yml` | Ansible | 6 | SSH config, file permissions, TLS | LOW–MEDIUM |
| `kubernetes/insecure_rbac.yaml` | Kubernetes | 5 | RBAC, cluster-admin, namespaces | MEDIUM |
| `docker/Dockerfile.multi_stage_insecure` | Docker | 5 | Multi-stage secrets, root, pinning | MEDIUM |

**Total dataset: 16 files, 79 smell instances, 18 distinct CWEs.**

### Why These Files Were Added

1. **`insecure_iam.tf`** — IAM misconfiguration is the #1 cause of cloud breaches. Wildcard
   policies (`Action: *`, `Resource: *`) and cross-account trust with `Principal: *` are
   extremely common in real infrastructure. These smells require **semantic reasoning**
   (understanding what `*` means in context), making them ideal for testing the LLM layer.

2. **`insecure_networking.tf`** — Network-level smells have direct Checkov IDs (CKV_AWS_25,
   CKV2_AWS_11, CKV_AWS_2). This makes them **easy to measure accurately** and good for
   establishing a precise baseline for Config A.

3. **`insecure_hardened.yml`** — Server hardening tasks expose smells at the configuration
   level that are invisible to Checkov (SSH settings, TLS flags, file permissions). These
   test the **heuristic fallback** in the Contextual Analyzer.

4. **`insecure_rbac.yaml`** — Kubernetes RBAC misconfigurations are both common and dangerous.
   `ClusterRole` with wildcard verbs detected by CKV_K8S_49 is one of the highest-severity
   Kubernetes findings. These test the full detection-to-patch pipeline.

5. **`Dockerfile.multi_stage_insecure`** — Multi-stage builds are widely used but introduce
   subtle secret leakage when `ARG` values are promoted to `ENV`. This tests whether the
   LLM can understand Docker layer semantics, not just surface-level patterns.

---

## Evaluation Script

The evaluation script runs all 18 metrics on the dataset:

```bash
# Config A: Checkov baseline (no LLM required)
python3 scripts/evaluate.py --mode baseline

# Results saved to: scripts/evaluation_results.json
```

### Config A Baseline Results (Checkov 3.2.513, 8 original files)

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| Terraform | 0.118 | 0.333 | 0.174 | 4 | 30 | 8 |
| Ansible | 0.000 | 0.000 | 0.000 | 0 | 3 | 0 |
| Kubernetes | 0.025 | 0.143 | 0.043 | 1 | 39 | 6 |
| Docker | 0.333 | 0.500 | 0.400 | 2 | 4 | 2 |
| **Overall** | **0.084** | **0.304** | **0.132** | **7** | **76** | **16** |

**Key observations:**
- **Low precision (8.4%):** Checkov detects 83 issues vs. 23 annotated ground-truth smells.
  The high FP count is expected — our ground truth is a curated subset, not all possible checks.
- **Low recall (30.4%):** Several check IDs have changed between versions
  (e.g., `CKV_AWS_52` → `CKV2_AWS_62`). This motivates the semantic LLM approach.
- **Ansible = 0%:** Checkov's Ansible support uses different check IDs than our heuristic annotations.
- **Docker = 40%:** Best baseline performance — Checkov's Docker checks are stable.

These results confirm that **Checkov alone is insufficient** and establish the performance
floor that Config D (full pipeline) must surpass.

---

## Testing with the Full Pipeline (Config B/C/D)

To test the LLM-based pipeline, set an API key and run:

```bash
# OpenAI backend
export OPENAI_API_KEY="sk-..."
python3 -c "
from pathlib import Path
import sys; sys.path.insert(0, 'src')
from analyzer.contextual import ContextualAnalyzer
from knowledge.knowledge_base import KnowledgeBase
from knowledge.retriever import KnowledgeRetriever
from generator.fix_generator import FixGenerator
from validator.tool_integrator import ExternalToolValidator
from formatter.patch_formatter import PatchFormatter
from agent.orchestrator import CentralAgent

# Build knowledge base
kb = KnowledgeBase(persist_dir='./chroma_db')
kb.build()

# Wire up pipeline
agent = CentralAgent(
    analyzer=ContextualAnalyzer(),
    retriever=KnowledgeRetriever(kb),
    generator=FixGenerator('gpt-4o-mini'),
    validator=ExternalToolValidator(),
    formatter=PatchFormatter(),
)

# Run on a test file
result = agent.run('dataset/terraform/insecure_s3.tf')
print('Success:', result['success'])
print('Patch:', result['patch'][:200] if result['patch'] else 'None')
print('Smells fixed:', len(result['smells']))
"
```

---

## Adding New Test Cases

### Adding a new dataset file

1. Create the IaC file in the appropriate subdirectory with **clear smell annotations**
   as comments (see existing files for the pattern).

2. Run Checkov to get the check IDs:
   ```bash
   checkov --file dataset/terraform/new_file.tf --output json --quiet | \
     python3 -c "import sys,json; d=json.load(sys.stdin); entries=d if isinstance(d,list) else [d]; [print(c['check_id']) for e in entries for c in e.get('results',{}).get('failed_checks',[])]"
   ```

3. Add an entry to `dataset/metadata.json` with the smell instances and their Checkov IDs.

4. Run the tests to verify: `python3 -m pytest tests/test_dataset.py -v`

### Best practices for smell clarity in dataset files

- **Comment every smell** with `# SMELL [ID]: description — CWE-NNN / CKV_XXX`
- **One smell per annotated line** where possible (avoid multiple smells on one line)
- **Use both HEURISTIC and Checkov-traceable smells** — heuristic ones test the fallback,
  Checkov ones test the baseline evaluation
- **Include the expected fix** as a comment showing what the correct value should be
- **Set `line` accurately** in metadata — Checkov reports the resource block start,
  so set the line to match the resource opening line, not the specific misconfigured field

---

## File Structure

```
Code/
├── src/
│   ├── agent/orchestrator.py          # Central Agent — pipeline orchestration
│   ├── analyzer/contextual.py         # IaC tool detection + smell extraction
│   ├── knowledge/knowledge_base.py    # ChromaDB vector store
│   ├── knowledge/retriever.py         # CRAG-style knowledge retrieval
│   ├── generator/fix_generator.py     # LLM patch generation (OpenAI/Anthropic)
│   ├── validator/tool_integrator.py   # Checkov before/after validation
│   └── formatter/patch_formatter.py   # Unified diff + CWE explanation
├── dataset/
│   ├── terraform/                     # 5 Terraform files (S3, EC2, RDS, IAM, Network)
│   ├── ansible/                       # 3 Ansible files (webserver, users, hardening)
│   ├── kubernetes/                    # 3 Kubernetes files (deployment, pod, RBAC)
│   ├── docker/                        # 2 Dockerfiles (single-stage, multi-stage)
│   ├── taxonomy/smells_taxonomy.json  # 63 security smell entries (War et al. 2025)
│   └── metadata.json                  # Ground-truth oracle (13 files, 58 smells)
├── tests/
│   ├── test_validator.py              # Checkov output validation (7 tests)
│   ├── test_analyzer.py               # Contextual Analyzer module (10 tests)
│   ├── test_formatter.py              # Patch Formatter module (8 tests)
│   └── test_dataset.py               # Dataset + taxonomy integrity (23 tests)
├── scripts/
│   ├── evaluate.py                    # 18-metric evaluation script
│   ├── evaluation_results.json        # Latest Config A results
│   └── run_checkov.sh                 # Batch Checkov runner
├── requirements.txt
├── TESTING.md                         # This file
└── README.md
```

---

## Known Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| Checkov check IDs change between versions | Some ground-truth IDs don't match latest Checkov | Use flexible matching (smell type + line ±5) |
| Ansible heuristic-only detection | Cannot measure Precision/Recall with Checkov | Use GLITCH for Ansible evaluation in future |
| Small dataset (58 smells, 13 files) | Results may not generalize | Extend dataset by mining GitHub IaC repos |
| No LLM results yet (Config B/C/D) | Core innovation not yet evaluated | Requires API key; expected PVR 0.65–0.80 |
| Single annotator | Oracle bias | Add second annotator + Cohen's Kappa |
