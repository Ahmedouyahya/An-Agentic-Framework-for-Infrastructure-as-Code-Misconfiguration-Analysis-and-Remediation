# QLoRA fine-tuning for IaC security fixes

Training pipeline for teaching a small LLM (2-3B) to patch insecure IaC scripts,
using the v1 scraped dataset (31,748 records → ~10k gold subset).

## Files

| File | Where to run | Purpose |
|---|---|---|
| `01_prepare_dataset.py` | **Local laptop** | Filter v1 JSONL → `training/data/{train,val,test}.jsonl` |
| `02_train_qlora.py`     | **Kaggle T4 x2** | QLoRA fine-tuning (≈50 MB adapter out) |
| `03_inference.py`       | Kaggle or local | Generate fixes with the trained adapter |
| `04_merge_adapter.py`   | **Local laptop** | Fuse LoRA into base weights → standalone HF model |
| `05_convert_to_gguf.sh` | **Local laptop** | HF model → GGUF (q4_K_M) via llama.cpp |
| `06_ollama_create.sh`   | **Local laptop** | Register the GGUF as Ollama model `iac-fixer` |
| `requirements.txt`      | Kaggle          | Pinned versions known to co-install |

## End-to-end recipe

### 1. Prepare data (once, on your laptop)

The full v1 dataset (~322 MB, 31,748 records) is published at
**https://github.com/Ahmedouyahya/iac-security-dataset**. Download
`dataset.jsonl` from there and place it at
`Code/scraping/output/dataset_v1_validated.jsonl`.

Then:

```bash
cd Code
python training/trainning/01_prepare_dataset.py
# → training/data/{train,val,test}.jsonl  +  stats.json
```

This reads `scraping/output/dataset_v1_validated.jsonl` and emits only
scanner-validated fix pairs with combined length < 8000 chars.

### 2. Upload to Kaggle

Create a new Kaggle **dataset** and drag `training/data/` into it.
Call it e.g. `iac-security-v1`. Note the path — Kaggle mounts it at
`/kaggle/input/iac-security-v1`.

### 3. Create a Kaggle notebook

- Accelerator: **GPU T4 x2**
- Add dataset: `iac-security-v1`
- If using Gemma: add `HF_TOKEN` as a notebook **secret** (Add-ons → Secrets)

Paste into cells:

```python
# Cell 1 — deps
!pip install -q -U transformers==4.44.2 datasets==2.21.0 peft==0.12.0 \
    accelerate==0.34.2 bitsandbytes==0.43.3 trl==0.10.1

# Cell 2 — upload 02_train_qlora.py (drag-drop) then:
!python 02_train_qlora.py \
    --model google/codegemma-2b-it \
    --data-dir /kaggle/input/iac-security-v1 \
    --output-dir /kaggle/working/lora_out \
    --epochs 1 --batch-size 1 --grad-accum 8 --lr 2e-4

# Cell 3 — smoke-test inference
!python 03_inference.py \
    --model google/codegemma-2b-it \
    --adapter /kaggle/working/lora_out \
    --input-file /kaggle/input/iac-security-v1/test.jsonl \
    --n-samples 3
```

### 4. Download the adapter

From Kaggle: `/kaggle/working/lora_out` → "Download output" (zip, ~50 MB).

### 5. Deploy locally via Ollama

Once the adapter is on your laptop under `training/lora_out/...`:

```bash
# a) Merge LoRA into base weights (CPU is fine, ~5 min for 2B)
export HF_TOKEN=hf_...   # Gemma is gated
python training/trainning/04_merge_adapter.py

# b) Convert to GGUF (clones llama.cpp on first run, ~10 min)
bash  training/trainning/05_convert_to_gguf.sh

# c) Register as Ollama model `iac-fixer`
bash  training/trainning/06_ollama_create.sh

# d) Try it
ollama run iac-fixer
```

The three scripts chain by default: each prints the command to run next.

## Model choices

Default is `google/codegemma-2b-it` — code-specialised, fits T4 with QLoRA
at seq_len=2048, uses the Gemma chat template.

Alternatives (swap via `--model`):

| Model | Size | Notes |
|---|---|---|
| `google/codegemma-2b-it` | 2 B | **Default** — code-specialised |
| `google/gemma-2-2b-it` | 2 B | General Gemma 2, same family as local Ollama stack |
| `Qwen/Qwen2.5-Coder-3B-Instruct` | 3 B | Stronger code model, still fits T4 |
| `bigcode/starcoder2-3b` | 3 B | No chat template (needs custom formatting) |

## Expected runtime (T4 x2)

- Full gold subset (~10k records, 1 epoch, seq_len=2048): **~3–5 hours**
- Smoke test (`--max-train-samples 200`, 1 epoch): **~15 minutes**

Always run the smoke test first to confirm loss decreases before committing
the full run.

## Hyperparameters (safe starting point)

| Param | Value | Rationale |
|---|---|---|
| LoRA r / alpha | 16 / 32 | Standard for 2-3B models |
| Target modules | q/k/v/o_proj | Attention-only; 10× smaller adapter than MLP too |
| LR | 2e-4 | Conservative for QLoRA |
| Scheduler | cosine | Best for 1-epoch runs |
| Warmup | 3% | Prevents early instability |
| Batch / grad_accum | 1 / 8 | Effective batch 8 fits T4 at seq 2048 |
| fp16 | True | bf16 not supported on T4 |
| Grad checkpointing | True | Required to fit in 16 GB |

## Troubleshooting

- **OOM**: drop `--max-seq-len` to 1024 or `--lora-r` to 8.
- **Loss stays flat**: check `train.jsonl` formatting, verify the chat template
  renders correctly by printing `ds['train'][0]['text']`.
- **HF auth error**: set `HF_TOKEN` (Gemma is a gated model).
- **`bitsandbytes` install fails**: pin `bitsandbytes==0.43.3`; newer versions
  have broken wheels on Kaggle's CUDA 12.1 image.
