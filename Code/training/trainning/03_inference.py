"""
Step 3 — Load the fine-tuned LoRA adapter and generate a fixed IaC script.

Run on Kaggle (after 02_train_qlora.py) or locally (if you download the adapter).

Kaggle usage:
    !python 03_inference.py \
        --model google/codegemma-2b-it \
        --adapter /kaggle/working/lora_out \
        --input-file /kaggle/input/iac-security-v1/test.jsonl \
        --n-samples 5
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


INSTRUCTION_TEMPLATE = """You are a security expert specializing in Infrastructure as Code (IaC).
Fix the following {iac_tool} script. Detected smells: {smells}.
Return ONLY the corrected script, no explanation."""


def build_prompt(sample: dict, tokenizer) -> str:
    smells = ", ".join(sample.get("smell_types") or []) or "security issues"
    iac_tool = sample.get("iac_tool", "IaC")
    user_msg = (INSTRUCTION_TEMPLATE.format(iac_tool=iac_tool, smells=smells)
                + f"\n\n```\n{sample['code_before']}\n```")
    return tokenizer.apply_chat_template(
        [{"role": "user", "content": user_msg}],
        tokenize=False,
        add_generation_prompt=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, help="Base HF model id (same as training)")
    ap.add_argument("--adapter", required=True, help="Path to saved LoRA adapter")
    ap.add_argument("--input-file", default=None,
                    help="JSONL file (each line = a sample). Defaults to stdin.")
    ap.add_argument("--n-samples", type=int, default=5, help="How many samples to run")
    ap.add_argument("--max-new-tokens", type=int, default=1024)
    ap.add_argument("--temperature", type=float, default=0.2)
    args = ap.parse_args()

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from peft import PeftModel

    tok = AutoTokenizer.from_pretrained(args.model, token=os.getenv("HF_TOKEN"))
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    base = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=bnb,
        device_map="auto",
        token=os.getenv("HF_TOKEN"),
    )
    model = PeftModel.from_pretrained(base, args.adapter)
    model.eval()

    # Load samples
    if args.input_file:
        lines = Path(args.input_file).read_text().splitlines()
    else:
        lines = sys.stdin.read().splitlines()
    samples = [json.loads(l) for l in lines if l.strip()][: args.n_samples]

    for i, s in enumerate(samples, 1):
        prompt = build_prompt(s, tok)
        inputs = tok(prompt, return_tensors="pt", truncation=True, max_length=2048).to(model.device)
        with torch.no_grad():
            out = model.generate(
                **inputs,
                max_new_tokens=args.max_new_tokens,
                temperature=args.temperature,
                do_sample=args.temperature > 0,
                pad_token_id=tok.pad_token_id,
            )
        generated = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        print(f"\n===== Sample {i}/{len(samples)}  tool={s.get('iac_tool')}  smells={s.get('smell_types')} =====")
        print("--- INPUT (code_before) ---")
        print(s["code_before"][:500] + ("…" if len(s["code_before"]) > 500 else ""))
        print("--- GROUND TRUTH (code_after) ---")
        print(s["code_after"][:500] + ("…" if len(s["code_after"]) > 500 else ""))
        print("--- MODEL OUTPUT ---")
        print(generated[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
