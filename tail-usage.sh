#!/usr/bin/env bash
# Beautified live tail of MCP usage log
tail -f registry/mcp_usage.jsonl | python3 -c "
import sys, json

RESET = '\033[0m'
GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
CYAN = '\033[36m'
DIM = '\033[2m'
BOLD = '\033[1m'

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        r = json.loads(line)
        ok = r.get('success', True)
        status = f'{GREEN}OK{RESET}' if ok else f'{RED}FAIL{RESET}'
        ts = r.get('ts', '?')[11:19]
        tool = r.get('tool', '?')
        dur = r.get('duration_ms', 0)
        caller = r.get('caller', '?')
        params = r.get('params', {})
        case = params.pop('case_id', None)
        err = r.get('error')

        print(f'{DIM}{ts}{RESET}  {status}  {BOLD}{CYAN}{tool}{RESET}  {DIM}{dur}ms{RESET}', end='')
        if case:
            print(f'  {YELLOW}{case}{RESET}', end='')
        if caller != 'local':
            print(f'  {DIM}({caller}){RESET}', end='')
        print()

        for k, v in params.items():
            val = str(v)
            if len(val) > 120:
                val = val[:117] + '...'
            print(f'    {DIM}{k}:{RESET} {val}')

        if err:
            print(f'    {RED}error: {err}{RESET}')

        print()
    except json.JSONDecodeError:
        print(line)
"
