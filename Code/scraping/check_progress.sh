#!/bin/bash
# Progress check for both scraping accounts
# Usage: bash scraping/check_progress.sh

echo "=== Process status ==="
ps aux | grep "scraping.main" | grep -v grep | awk '{print "PID:", $2, "| CPU:", $3"%", "| Started:", $9}'

echo ""
echo "=== Progress (resumability) ==="
python3 -c "
import json
from pathlib import Path
for i, f in enumerate([
    Path('scraping/output/progress_1.json'),
    Path('scraping/output/progress_2.json'),
], 1):
    if not f.exists():
        print(f'  Account {i}: no progress file yet')
        continue
    d = json.loads(f.read_text())
    cq = len(d.get('completed_commit_queries', []))
    qq = len(d.get('completed_code_queries', []))
    rp = len(d.get('completed_repos', []))
    tw = d.get('total_written', 0)
    lu = d.get('last_updated', 'never')
    print(f'  Account {i}: commit_queries={cq}/30 | code_queries={qq}/5 | repos={rp} | written={tw} | last={lu}')
" 2>/dev/null

echo ""
echo "=== Records collected ==="
python3 -c "
import json
from pathlib import Path
grand_total, grand_fix = 0, 0
for label, d in [('Account 1 (raw/)', Path('scraping/output/raw')),
                 ('Account 2 (raw2/)', Path('scraping/output/raw2'))]:
    if not d.exists():
        print(f'  {label}: not started')
        continue
    total, with_fix = 0, 0
    tools = {}
    for f in sorted(d.glob('*.jsonl')):
        for l in f.read_text().strip().splitlines():
            if not l.strip(): continue
            r = json.loads(l)
            total += 1
            if r['has_fix']: with_fix += 1
            tools[r['iac_tool']] = tools.get(r['iac_tool'], 0) + 1
    grand_total += total; grand_fix += with_fix
    print(f'  {label}: {total:5d} records | with_fix={with_fix:5d} | {tools}')
print(f'  GRAND TOTAL: {grand_total} records | {grand_fix} with fix | {grand_total-grand_fix} insecure-only')
" 2>/dev/null

echo ""
echo "=== Last 4 lines — Account 1 ==="
tail -4 scraping/output/run_account1.log 2>/dev/null

echo ""
echo "=== Last 4 lines — Account 2 ==="
tail -4 scraping/output/run_account2.log 2>/dev/null
