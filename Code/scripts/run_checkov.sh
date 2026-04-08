#!/usr/bin/env bash
# ============================================================
# run_checkov.sh
# Runs Checkov on all dataset files and produces a summary report.
# Usage: bash scripts/run_checkov.sh [--output-dir results/]
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DATASET_DIR="$ROOT_DIR/dataset"
OUTPUT_DIR="${1:-$ROOT_DIR/results/checkov}"

mkdir -p "$OUTPUT_DIR"

echo "=== Checkov Scan — IaC Security Dataset ==="
echo "Dataset: $DATASET_DIR"
echo "Results: $OUTPUT_DIR"
echo ""

TOTAL_PASSED=0
TOTAL_FAILED=0

scan_file() {
    local file="$1"
    local label
    label=$(basename "$file")
    local out_file="$OUTPUT_DIR/${label}.json"

    echo "Scanning: $file"
    checkov --file "$file" --output json --quiet > "$out_file" 2>/dev/null || true

    local passed failed
    passed=$(python3 -c "
import json, sys
d = json.load(open('$out_file'))
print(len(d.get('results',{}).get('passed_checks',[])))
" 2>/dev/null || echo 0)
    failed=$(python3 -c "
import json, sys
d = json.load(open('$out_file'))
print(len(d.get('results',{}).get('failed_checks',[])))
" 2>/dev/null || echo 0)

    echo "  PASSED: $passed  FAILED: $failed"
    TOTAL_PASSED=$((TOTAL_PASSED + passed))
    TOTAL_FAILED=$((TOTAL_FAILED + failed))
}

# Terraform
for f in "$DATASET_DIR"/terraform/*.tf; do
    scan_file "$f"
done

# Ansible
for f in "$DATASET_DIR"/ansible/*.yml; do
    scan_file "$f"
done

# Kubernetes
for f in "$DATASET_DIR"/kubernetes/*.yaml; do
    scan_file "$f"
done

# Docker
for f in "$DATASET_DIR"/docker/Dockerfile*; do
    scan_file "$f"
done

echo ""
echo "=== Summary ==="
echo "Total PASSED checks : $TOTAL_PASSED"
echo "Total FAILED checks : $TOTAL_FAILED"
echo "Results saved to    : $OUTPUT_DIR"
