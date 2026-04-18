#!/usr/bin/env bash
#
# Supervisor loop: keeps the scraper running for days/weeks across
# crashes, stalls, network blips, and watchdog exits.
#
# Usage:
#   ./run_forever.sh              # single-account mode, uses GITHUB_TOKEN
#   ./run_forever.sh 1            # account 1
#   ./run_forever.sh 2            # account 2
#   MAX_RUNTIME_HOURS=168 ./run_forever.sh 1   # cap at 7 days
#
# Exit codes interpreted:
#   0   — scraper exited cleanly (queries exhausted) → stop the loop
#   2   — watchdog stall → short pause and restart
#   *   — unexpected crash → longer pause and restart
#
set -u

cd "$(dirname "$0")/.." || exit 1   # run from Code/

ACCOUNT="${1:-}"
MAX_RUNTIME_HOURS="${MAX_RUNTIME_HOURS:-168}"   # default 7 days
BACKOFF_SHORT=30
BACKOFF_LONG=120
LOG_DIR="scraping/output"
mkdir -p "$LOG_DIR"

start_ts=$(date +%s)
iter=0

GHARCHIVE_HOURS="${GHARCHIVE_HOURS:-168}"  # default: scan last 7 days of GHArchive

if [[ -n "$ACCOUNT" ]]; then
    CMD=(python -m scraping.main --account "$ACCOUNT" --gharchive --gharchive-hours "$GHARCHIVE_HOURS")
    LOG_FILE="$LOG_DIR/run_forever_account${ACCOUNT}.log"
else
    CMD=(python -m scraping.main --all --gharchive --gharchive-hours "$GHARCHIVE_HOURS")
    LOG_FILE="$LOG_DIR/run_forever.log"
fi

echo "=== run_forever starting $(date -u +%FT%TZ) ===" | tee -a "$LOG_FILE"
echo "cmd: ${CMD[*]}" | tee -a "$LOG_FILE"
echo "max_runtime_hours: $MAX_RUNTIME_HOURS" | tee -a "$LOG_FILE"

while true; do
    iter=$((iter + 1))
    now_ts=$(date +%s)
    elapsed_h=$(( (now_ts - start_ts) / 3600 ))
    if (( elapsed_h >= MAX_RUNTIME_HOURS )); then
        echo "[$(date -u +%FT%TZ)] reached max runtime ${elapsed_h}h, stopping" | tee -a "$LOG_FILE"
        exit 0
    fi

    echo "[$(date -u +%FT%TZ)] iteration $iter (elapsed=${elapsed_h}h)" | tee -a "$LOG_FILE"
    "${CMD[@]}" >> "$LOG_FILE" 2>&1
    rc=$?

    case "$rc" in
        0)
            echo "[$(date -u +%FT%TZ)] scraper exited 0 (clean) — loop done" | tee -a "$LOG_FILE"
            exit 0
            ;;
        2)
            echo "[$(date -u +%FT%TZ)] watchdog stall (rc=2), sleeping ${BACKOFF_SHORT}s" | tee -a "$LOG_FILE"
            sleep "$BACKOFF_SHORT"
            ;;
        130|143)
            echo "[$(date -u +%FT%TZ)] interrupted (rc=$rc), stopping" | tee -a "$LOG_FILE"
            exit "$rc"
            ;;
        *)
            echo "[$(date -u +%FT%TZ)] crash rc=$rc, sleeping ${BACKOFF_LONG}s" | tee -a "$LOG_FILE"
            sleep "$BACKOFF_LONG"
            ;;
    esac
done
