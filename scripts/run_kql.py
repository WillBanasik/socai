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


class KqlQueryError(RuntimeError):
    """An ``az`` KQL query failed to execute.

    Raised on a non-zero ``az`` exit (bad column/table/syntax, auth, throttling),
    a timeout, or an unparseable response. Distinct from a query that succeeds
    and legitimately returns zero rows — callers must never conflate the two
    (a swallowed failure looks identical to "0 rows matched").
    """

    def __init__(self, message: str, *, kind: str = "error"):
        super().__init__(message)
        self.kind = kind  # "error" | "timeout" | "decode"


def _resolve_workspace(workspace_id: str | None, code: str | None) -> str:
    """Return a workspace ID from explicit ID or workspace code.

    Deliberately no environment-variable fallback: an implicit default
    workspace is how unscoped queries leak into the wrong tenant (the
    2026-06-01 incident). Scoping must be explicit per invocation.
    """
    if workspace_id:
        return workspace_id
    if not code:
        print("Error: supply --workspace-id or --code (no default workspace)", file=sys.stderr)
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


def run_kql(workspace_id: str, query: str, timeout: int = 120, skip_validation: bool = False) -> list[dict]:
    """Execute KQL via az CLI with list-based subprocess (no shell)."""
    if not skip_validation:
        try:
            from config.sentinel_schema import extract_tables_from_kql, validate_tables, has_registry
            if has_registry():
                tables = extract_tables_from_kql(query)
                if tables:
                    validation = validate_tables(list(tables))
                    for w in validation.get("warnings", []):
                        print(f"Schema warning: {w}", file=sys.stderr)
        except Exception:
            pass
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
    except subprocess.TimeoutExpired:
        raise KqlQueryError(f"query timed out after {timeout}s", kind="timeout")

    if result.returncode != 0:
        # A failed query (bad column/table/syntax, auth, throttling) must NOT be
        # silently flattened to an empty list — surface the az error so callers
        # can tell "query failed" apart from "0 rows matched".
        detail = (result.stderr.strip() or result.stdout.strip()
                  or f"az exited with status {result.returncode}")
        raise KqlQueryError(detail[:2000], kind="error")

    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise KqlQueryError(
            f"invalid JSON in az response: {result.stdout[:300]}", kind="decode"
        )
    # Some az versions return a 200 carrying an error object instead of rows.
    if isinstance(rows, dict) and rows.get("error"):
        raise KqlQueryError(str(rows["error"])[:2000], kind="error")
    return rows


def main():
    parser = argparse.ArgumentParser(description="Run KQL against Azure Log Analytics")
    parser.add_argument("-w", "--workspace-id", help="Log Analytics workspace ID")
    parser.add_argument("--code", help="Workspace name (e.g. acme-corp) — resolved from config")
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

    try:
        rows = run_kql(workspace_id, query, timeout=args.timeout)
    except KqlQueryError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    json.dump(rows, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
