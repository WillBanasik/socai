#!/usr/bin/env python3
"""
Run a KQL query against Azure Log Analytics, safely bypassing shell escaping.

Reads KQL from a file (or stdin) and passes it to `az monitor log-analytics query`
via subprocess with list-based arguments — no shell interpretation.

Usage:
    python3 scripts/run_kql.py -w <workspace_id> -f <query.kql>
    python3 scripts/run_kql.py -w <workspace_id> -f <query.kql> --timeout 300
    python3 scripts/run_kql.py -w <workspace_id> --code PER -f <query.kql>
    echo "SecurityEvent | take 5" | python3 scripts/run_kql.py -w <workspace_id>

Workspace codes (--code) resolve via config/workspace_tables.json.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_WORKSPACE_FILE = _REPO_ROOT / "config" / "workspace_tables.json"


def _resolve_workspace(workspace_id: str | None, code: str | None) -> str:
    """Return a workspace ID from explicit ID or workspace code."""
    if workspace_id:
        return workspace_id
    if not code:
        print("Error: supply --workspace-id or --code", file=sys.stderr)
        sys.exit(1)
    try:
        with open(_WORKSPACE_FILE) as f:
            ws = json.load(f)
        # Try exact match first, then uppercase (legacy), then case-insensitive
        entry = ws.get(code) or ws.get(code.upper()) or ws.get(code.lower())
        if not entry:
            print(f"Error: unknown workspace code '{code}'. "
                  f"Valid: {', '.join(sorted(ws))}", file=sys.stderr)
            sys.exit(1)
        return entry["workspace_id"]
    except FileNotFoundError:
        print(f"Error: {_WORKSPACE_FILE} not found", file=sys.stderr)
        sys.exit(1)


def run_kql(workspace_id: str, query: str, timeout: int = 120) -> list[dict]:
    """Execute KQL via az CLI with list-based subprocess (no shell)."""
    cmd = [
        "az", "monitor", "log-analytics", "query",
        "-w", workspace_id,
        "--analytics-query", query,
        "-o", "json",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            print(f"Error: {result.stderr.strip()}", file=sys.stderr)
            return []
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"Error: query timed out ({timeout}s)", file=sys.stderr)
        return []
    except json.JSONDecodeError:
        print("Error: invalid JSON in az response", file=sys.stderr)
        return []


def main():
    parser = argparse.ArgumentParser(description="Run KQL against Azure Log Analytics")
    parser.add_argument("-w", "--workspace-id", help="Log Analytics workspace ID")
    parser.add_argument("--code", help="Workspace name (e.g. example-client) — resolved from config")
    parser.add_argument("-f", "--file", help="Path to .kql file (reads stdin if omitted)")
    parser.add_argument("--timeout", type=int, default=120, help="Query timeout in seconds")
    args = parser.parse_args()

    workspace_id = _resolve_workspace(args.workspace_id, args.code)

    if args.file:
        query = Path(args.file).read_text()
    else:
        query = sys.stdin.read()

    if not query.strip():
        print("Error: empty query", file=sys.stderr)
        sys.exit(1)

    rows = run_kql(workspace_id, query, timeout=args.timeout)
    json.dump(rows, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
