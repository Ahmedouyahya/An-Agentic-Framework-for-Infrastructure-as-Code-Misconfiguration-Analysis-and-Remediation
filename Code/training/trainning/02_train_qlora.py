"""
Step 2 — QLoRA fine-tuning on Kaggle (T4 x2, 16 GB).

Intended to run inside a Kaggle notebook after:
  - Uploading training/data/ as a Kaggle dataset (or placing train.jsonl/val.jsonl
    in the paths set below).
  - Adding a model: either pass `--model google/codegemma-2b-it` (downloads from HF)
    or attach a Kaggle model and pass its input path.

Kaggle setup (cell before running this script):
    !pip install -q -U transformers==4.44.2 datasets==2.21.0 \
        peft==0.12.0 accelerate==0.34.2 bitsandbytes==0.43.3 trl==0.10.1

Usage on Kaggle (as a !python cell, or paste into a notebook cell):
    !python 02_train_qlora.py \
        --model google/codegemma-2b-it \
        --data-dir /kaggle/input/iac-security-v1 \
        --output-dir /kaggle/working/lora_out \
        --epochs 1 --batch-size 1 --grad-accum 8 --lr 2e-4

Notes:
  - Default model is codegemma-2b-it (code-specialised, fits a T4 with QLoRA).
  - For gemma-2-2b-it (general) or qwen2.5-coder-3b, see RECOMMENDED_MODELS below.
  - Gated HF models (Gemma) require HF_TOKEN as a Kaggle secret.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

# Models known to fit a T4 (16 GB) with 4-bit QLoRA + seq_len=2048.
RECOMMENDED_MODELS = {
    "google/codegemma-2b-it":           "Code-specialised Gemma 2B — best default",
    "google/gemma-2-2b-it":             "General Gemma 2B — matches local Ollama stack",
    "Qwen/Qwen2.5-Coder-3B-Instruct":   "Stronger code model, still fits a T4",
    "bigcode/starcoder2-3b":            "Solid code LM, no chat template",
}

INSTRUCTION_TEMPLATE = """You are a security expert specializing in Infrastructure as Code (IaC).
Fix the following {iac_tool} script. Detected smells: {smells}.
Return ONLY the corrected script, no explanation."""


def format_sample(sample: dict, tokenizer) -> dict:
    smells = ", ".join(sample.get("smell_types") or []) or "security issues"
    iac_tool = sample.get("iac_tool", "IaC")
    user_msg = INSTRUCTION_TEMPLATE.format(iac_tool=iac_tool, smells=smells) + \
               f"\n\n```\n{sample['code_before']}\n```"
    assistant_msg = sample["code_after"]
    messages = [
        {"role": "user", "content": user_msg},
        {"role": "assistant", "content": assistant_msg},
    ]
    text = tokenizer.apply_chat_template(messages, tokenize=False)
    return {"text": text}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="google/codegemma-2b-it",
                    help=f"HF model id or local path. Recommended: {list(RECOMMENDED_MODELS)}")
    ap.add_argument("--data-dir", default="/kaggle/input/iac-security-v1",
                    help="Dir with train.jsonl and val.jsonl")
    ap.add_argument("--output-dir", default="/kaggle/working/lora_out")
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--max-seq-len", type=int, default=2048)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--max-train-samples", type=int, default=0,
                    help="Cap training set size (0 = all). Useful for smoke tests.")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    import torch
    from datasets import load_dataset
    from transformers import (AutoModelForCausalLM, AutoTokenizer,
                              BitsAndBytesConfig, TrainingArguments)
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from trl import SFTTrainer

    data_dir = Path(args.data_dir)
    train_path = data_dir / "train.jsonl"
    val_path = data_dir / "val.jsonl"
    assert train_path.exists(), f"Missing {train_path}"
    assert val_path.exists(), f"Missing {val_path}"

    print(f"[info] model={args.model}")
    print(f"[info] data_dir={data_dir}")
    print(f"[info] output_dir={args.output_dir}")

    # ── Load data ────────────────────────────────────────────────────────
    ds = load_dataset("json", data_files={
        "train": str(train_path),
        "val": str(val_path),
    })
    if args.max_train_samples > 0:
        ds["train"] = ds["train"].select(range(min(args.max_train_samples, len(ds["train"]))))
    print(f"[info] train={len(ds['train'])}  val={len(ds['val'])}")

    # ── Tokenizer ────────────────────────────────────────────────────────
    tok = AutoTokenizer.from_pretrained(args.model, token=os.getenv("HF_TOKEN"))
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "right"

    ds = ds.map(lambda s: format_sample(s, tok),
                remove_columns=ds["train"].column_names,
                num_proc=2)

    # ── 4-bit base model ─────────────────────────────────────────────────
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=bnb,
        device_map="auto",
        token=os.getenv("HF_TOKEN"),
    )
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model)

    # ── LoRA ─────────────────────────────────────────────────────────────
    lora = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    # ── TrainingArguments ────────────────────────────────────────────────
    targs = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        logging_steps=25,
        eval_strategy="steps",
        eval_steps=200,
        save_strategy="steps",
        save_steps=200,
        save_total_limit=2,
        bf16=False,
        fp16=True,
        optim="paged_adamw_8bit",
        report_to="none",
        seed=args.seed,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tok,
        args=targs,
        train_dataset=ds["train"],
        eval_dataset=ds["val"],
        dataset_text_field="text",
        max_seq_length=args.max_seq_len,
        packing=False,
    )

    print("[info] starting training…")
    trainer.train()

    # ── Save LoRA adapter only (small, ~50 MB) ───────────────────────────
    trainer.model.save_pretrained(args.output_dir)
    tok.save_pretrained(args.output_dir)
    (Path(args.output_dir) / "training_args.json").write_text(
        json.dumps(vars(args), indent=2))
    print(f"[done] adapter saved to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
