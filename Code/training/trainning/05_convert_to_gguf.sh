#!/usr/bin/env bash
# Convert the merged HF model to GGUF (q4_K_M) for Ollama.
#
# Usage:
#   bash 05_convert_to_gguf.sh [MERGED_DIR] [QUANT]
#
# Defaults:
#   MERGED_DIR = ../merged_model
#   QUANT      = q4_K_M   (good size/quality trade-off for CPU inference)
#
# Produces: ../merged_model.gguf  (or <MERGED_DIR>.gguf)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MERGED_DIR="${1:-$HERE/../merged_model}"
QUANT="${2:-q4_K_M}"

MERGED_DIR="$(readlink -f "$MERGED_DIR")"
OUT_F16="${MERGED_DIR}.f16.gguf"
OUT_Q="${MERGED_DIR}.${QUANT}.gguf"

LLAMA_CPP_DIR="${LLAMA_CPP_DIR:-$HOME/llama.cpp}"

if [[ ! -d "$LLAMA_CPP_DIR" ]]; then
  echo "Cloning llama.cpp into $LLAMA_CPP_DIR"
  git clone --depth 1 https://github.com/ggerganov/llama.cpp "$LLAMA_CPP_DIR"
fi

cd "$LLAMA_CPP_DIR"

# The convert script lives at convert_hf_to_gguf.py in recent versions.
CONVERT_SCRIPT="convert_hf_to_gguf.py"
if [[ ! -f "$CONVERT_SCRIPT" ]]; then
  CONVERT_SCRIPT="convert-hf-to-gguf.py"
fi

echo "[1/3] Installing llama.cpp Python deps"
pip install -q -r requirements.txt

echo "[2/3] Converting $MERGED_DIR -> $OUT_F16"
python "$CONVERT_SCRIPT" "$MERGED_DIR" --outtype f16 --outfile "$OUT_F16"

echo "[3/3] Quantising $OUT_F16 -> $OUT_Q ($QUANT)"
if [[ ! -x "./llama-quantize" && ! -x "./build/bin/llama-quantize" ]]; then
  echo "Building llama-quantize"
  cmake -B build -DGGML_CUDA=OFF >/dev/null
  cmake --build build --target llama-quantize -j
fi
QUANTIZE_BIN="./build/bin/llama-quantize"
[[ -x "$QUANTIZE_BIN" ]] || QUANTIZE_BIN="./llama-quantize"

"$QUANTIZE_BIN" "$OUT_F16" "$OUT_Q" "$QUANT"

echo
echo "Done. Artifact: $OUT_Q"
echo "Next: bash 06_ollama_create.sh $OUT_Q"
