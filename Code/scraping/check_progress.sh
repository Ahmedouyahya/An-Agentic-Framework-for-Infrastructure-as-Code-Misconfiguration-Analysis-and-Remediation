#!/bin/bash
# Progress check for both scraping accounts.
# Runs from any working directory — paths are resolved relative to this script.
# Usage: bash check_progress.sh   (or: bash scraping/check_progress.sh)

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$SCRIPT_DIR/output"

echo "=== Process status ==="
ps -eo pid,pcpu,lstart,args | grep "scraping.main" | grep -v grep \
  | awk '{printf "PID:%s | CPU:%s%% | Started:%s %s %s | CMD: ", $1,$2,$3,$4,$5; for (i=9;i<=NF;i++) printf "%s ", $i; print ""}'

echo ""
echo "=== Progress (resumability) ==="
OUT="$OUT" python3 - <<'PY'
import json, os
from pathlib import Path
out = Path(os.environ["OUT"])
for i in (1, 2):
    f = out / f"progress_{i}.json"
    if not f.exists():
        print(f"  Account {i}: no progress file ({f})")
        continue
    d = json.loads(f.read_text())
    cq = len(d.get("completed_commit_queries", []))
    qq = len(d.get("completed_code_queries", []))
    rp = len(d.get("completed_repos", []))
    gh = len(d.get("completed_gharchive_hours", []))
    tw = d.get("total_written", 0)
    lu = d.get("last_updated", "never")
    print(f"  Account {i}: commits={cq}/30 | code={qq}/5 | repos={rp} | gharchive_hours={gh} | written={tw} | last={lu}")
PY

echo ""
echo "=== Records collected (by source) ==="
OUT="$OUT" python3 - <<'PY'
import json, os
from pathlib import Path
out = Path(os.environ["OUT"])
grand_total = grand_fix = 0
for label, d in [("Account 1 (raw/)", out/"raw"), ("Account 2 (raw2/)", out/"raw2")]:
    if not d.exists():
        print(f"  {label}: not started"); continue
    by_source = {}
    total = with_fix = 0
    tools = {}
    for f in sorted(d.glob("*.jsonl")):
        n = wf = 0
        with f.open() as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                n += 1
                if r.get("has_fix"): wf += 1
                t = r.get("iac_tool")
                if t: tools[t] = tools.get(t, 0) + 1
        by_source[f.name] = (n, wf)
        total += n; with_fix += wf
    grand_total += total; grand_fix += with_fix
    print(f"  {label}: {total} records | with_fix={with_fix}")
    for name, (n, wf) in by_source.items():
        print(f"      {name:<24} {n:>7} rows  (with_fix={wf})")
    if tools:
        top = sorted(tools.items(), key=lambda x: -x[1])[:6]
        print(f"      tools: {dict(top)}")
print(f"  GRAND TOTAL: {grand_total} records | {grand_fix} with fix | {grand_total-grand_fix} insecure-only")
PY

echo ""
echo "=== Last 6 lines — Account 1 ==="
tail -6 "$OUT/run_account1.log" 2>/dev/null || echo "  (no log)"

echo ""
echo "=== Last 6 lines — Account 2 ==="
tail -6 "$OUT/run_account2.log" 2>/dev/null || echo "  (no log)"
