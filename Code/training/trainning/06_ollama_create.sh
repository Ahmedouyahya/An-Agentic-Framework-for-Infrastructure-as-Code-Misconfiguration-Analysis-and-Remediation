#!/usr/bin/env bash
# Register the quantised GGUF as an Ollama model named `iac-fixer`.
#
# Usage:
#   bash 06_ollama_create.sh [GGUF_PATH] [MODEL_NAME]
#
# Defaults:
#   GGUF_PATH  = ../merged_model.q4_K_M.gguf
#   MODEL_NAME = iac-fixer

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GGUF_PATH="${1:-$HERE/../merged_model.q4_K_M.gguf}"
MODEL_NAME="${2:-iac-fixer}"

GGUF_PATH="$(readlink -f "$GGUF_PATH")"

if [[ ! -f "$GGUF_PATH" ]]; then
  echo "GGUF file not found: $GGUF_PATH" >&2
  exit 1
fi

MODELFILE="$(dirname "$GGUF_PATH")/Modelfile.${MODEL_NAME}"

cat >"$MODELFILE" <<EOF
FROM ${GGUF_PATH}

TEMPLATE """<start_of_turn>user
{{ .Prompt }}<end_of_turn>
<start_of_turn>model
"""

PARAMETER temperature 0.2
PARAMETER top_p 0.9
PARAMETER num_ctx 4096
PARAMETER stop "<end_of_turn>"

SYSTEM """You patch insecure Infrastructure-as-Code snippets (Terraform, Dockerfile, Kubernetes, Ansible, CloudFormation). Given a smell and a snippet, return a unified diff that fixes the smell without breaking functionality."""
EOF

echo "Wrote $MODELFILE"
echo "Registering with Ollama as '$MODEL_NAME'"
ollama create "$MODEL_NAME" -f "$MODELFILE"

echo
echo "Done. Try:"
echo "  ollama run $MODEL_NAME"
