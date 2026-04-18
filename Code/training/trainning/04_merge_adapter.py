"""Merge the QLoRA adapter into the base Gemma-2-2B-IT weights.

The output is a standalone HF model directory that can then be converted to
GGUF with llama.cpp (see 05_convert_to_gguf.sh) and loaded by Ollama.

Usage:
    python 04_merge_adapter.py \\
        --base-model google/gemma-2-2b-it \\
        --adapter ../lora_out/kaggle/working/lora_out \\
        --output ../merged_model

Requirements: transformers, peft, torch (CPU is fine for a 2B model).
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def parse_args() -> argparse.Namespace:
    here = Path(__file__).resolve().parent
    default_adapter = here.parent / "lora_out" / "kaggle" / "working" / "lora_out"
    default_output = here.parent / "merged_model"

    p = argparse.ArgumentParser(description="Merge LoRA adapter into base model.")
    p.add_argument("--base-model", default="google/gemma-2-2b-it")
    p.add_argument("--adapter", default=str(default_adapter))
    p.add_argument("--output", default=str(default_output))
    p.add_argument(
        "--dtype",
        default="float16",
        choices=["float16", "bfloat16", "float32"],
        help="Precision for the merged weights. float16 halves the disk size.",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    adapter_path = Path(args.adapter).resolve()
    output_path = Path(args.output).resolve()

    if not adapter_path.exists():
        raise FileNotFoundError(f"Adapter directory not found: {adapter_path}")
    if not (adapter_path / "adapter_config.json").exists():
        raise FileNotFoundError(
            f"No adapter_config.json under {adapter_path}. "
            "Point --adapter at the directory containing the adapter files."
        )

    output_path.mkdir(parents=True, exist_ok=True)

    dtype = {"float16": torch.float16, "bfloat16": torch.bfloat16, "float32": torch.float32}[
        args.dtype
    ]

    hf_token = os.environ.get("HF_TOKEN")

    print(f"[1/4] Loading base model {args.base_model} (dtype={args.dtype})")
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=dtype,
        low_cpu_mem_usage=True,
        token=hf_token,
    )

    print(f"[2/4] Attaching adapter from {adapter_path}")
    model = PeftModel.from_pretrained(base, str(adapter_path))

    print("[3/4] Merging LoRA weights into base weights")
    merged = model.merge_and_unload()

    print(f"[4/4] Saving merged model to {output_path}")
    merged.save_pretrained(str(output_path), safe_serialization=True)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, token=hf_token)
    tokenizer.save_pretrained(str(output_path))

    print("\nDone. Next step:")
    print(f"  bash 05_convert_to_gguf.sh {output_path}")


if __name__ == "__main__":
    main()
