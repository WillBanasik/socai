#!/usr/bin/env python3
"""
Discover all Sentinel Log Analytics tables + schemas across workspaces.
Requires: az cli logged in with reader access to each workspace.

Outputs:
  - config/sentinel_tables.json   (universal table registry)
  - config/workspace_tables.json  (per-workspace table availability)
"""

import argparse
import json
import subprocess
import sys
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


def _load_workspaces() -> dict[str, str]:
    """Load workspace map from config/client_entities.json."""
    cfg_path = Path(__file__).resolve().parent.parent / "config" / "client_entities.json"
    try:
        with open(cfg_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: {cfg_path} not found. Copy from client_entities.example.json.", file=sys.stderr)
        sys.exit(1)
    workspaces = {}
    for client in data.get("clients", []):
        name = client.get("name", "")
        wid = (client.get("platforms", {}).get("sentinel", {}).get("workspace_id")
               or client.get("workspace_id", ""))
        if name and wid and not wid.startswith("00000000"):
            workspaces[name] = wid
    return workspaces


WORKSPACES = _load_workspaces()

# Step 1 query: get active tables; window is parameterised
TABLE_LIST_QUERY_TPL = """Usage
| where TimeGenerated > ago({window_days}d)
| distinct DataType
| order by DataType asc"""

# Step 2 query: get schema for a specific table
SCHEMA_QUERY_TPL = """{table}
| getschema
| project ColumnName, DataType, ColumnType"""


def az_query(workspace_id: str, query: str, timeout: int = 120) -> list[dict]:
    """Run a KQL query via az cli and return parsed JSON rows."""
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
            print(f"  ✗ Query failed: {result.stderr.strip()[:200]}", file=sys.stderr)
            return []
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        print(f"  ✗ Query timed out ({timeout}s)", file=sys.stderr)
        return []
    except json.JSONDecodeError:
        print(f"  ✗ Invalid JSON response", file=sys.stderr)
        return []


def discover_workspace(code: str, workspace_id: str, window_days: int = 7) -> dict:
    """Discover all tables and their schemas for a workspace."""
    print(f"\n[{code}] Discovering tables for workspace {workspace_id[:8]} ({window_days}d window)...")

    # Get table list
    rows = az_query(workspace_id, TABLE_LIST_QUERY_TPL.format(window_days=window_days))
    if not rows:
        print(f"  [{code}] No tables found or query failed")
        return {"code": code, "workspace_id": workspace_id, "tables": {}}

    table_names = sorted(set(r.get("DataType", "") for r in rows if r.get("DataType")))
    print(f"  [{code}] Found {len(table_names)} active tables")

    # Get schema for each table
    tables = {}
    for i, table in enumerate(table_names):
        query = SCHEMA_QUERY_TPL.format(table=table)
        schema_rows = az_query(workspace_id, query, timeout=60)
        if schema_rows:
            columns = {}
            for row in schema_rows:
                col_name = row.get("ColumnName", "")
                col_type = row.get("DataType") or row.get("ColumnType", "")
                if col_name:
                    columns[col_name] = col_type
            tables[table] = columns
            print(f"  [{code}] {i+1}/{len(table_names)} {table}: {len(columns)} columns")
        else:
            print(f"  [{code}] {i+1}/{len(table_names)} {table}: ✗ schema query failed")

    return {"code": code, "workspace_id": workspace_id, "tables": tables}


def build_universal_registry(all_results: list[dict]) -> dict:
    """Merge all workspace schemas into a single universal table registry."""
    universal = {}

    for ws in all_results:
        code = ws["code"]
        for table_name, columns in ws["tables"].items():
            if table_name not in universal:
                universal[table_name] = {
                    "columns": {},
                    "workspaces": [],
                }
            # Merge columns (union of all columns seen across workspaces)
            for col, dtype in columns.items():
                if col not in universal[table_name]["columns"]:
                    universal[table_name]["columns"][col] = dtype
            universal[table_name]["workspaces"].append(code)

    # Sort by table name
    return dict(sorted(universal.items()))


def build_workspace_index(all_results: list[dict]) -> dict:
    """Per-workspace table availability index."""
    index = {}
    for ws in all_results:
        index[ws["code"]] = {
            "workspace_id": ws["workspace_id"],
            "tables": sorted(ws["tables"].keys()),
            "table_count": len(ws["tables"]),
        }
    return dict(sorted(index.items()))


def _load_json(path: Path) -> dict:
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"  ! Existing {path.name} is not valid JSON — overwriting", file=sys.stderr)
    return {}


def _merge_universal(existing: dict, fresh: dict, refreshed_codes: set[str]) -> dict:
    """Merge freshly discovered tables into the existing universal registry.

    For tables present in `fresh`, the fresh column map wins (refresh).
    For workspaces in refreshed_codes, the membership is rebuilt from fresh
    (so a table that disappeared from a workspace is removed there).
    Tables / workspaces outside refreshed_codes are left untouched.
    """
    merged = {k: {"columns": dict(v.get("columns", {})), "workspaces": list(v.get("workspaces", []))}
              for k, v in existing.items()}

    # First, strip the refreshed workspaces from every existing table's membership.
    for entry in merged.values():
        entry["workspaces"] = [w for w in entry["workspaces"] if w not in refreshed_codes]

    # Then layer the fresh data on top.
    for table, entry in fresh.items():
        slot = merged.setdefault(table, {"columns": {}, "workspaces": []})
        # Refresh column map for any column we just observed; keep older columns from other workspaces.
        for col, dtype in entry.get("columns", {}).items():
            slot["columns"][col] = dtype
        # Append fresh workspaces (already stripped above).
        for w in entry.get("workspaces", []):
            if w not in slot["workspaces"]:
                slot["workspaces"].append(w)
        slot["workspaces"].sort()

    # Drop tables nobody references any more.
    merged = {k: v for k, v in merged.items() if v["workspaces"]}
    return dict(sorted(merged.items()))


def main():
    parser = argparse.ArgumentParser(description="Discover Sentinel tables + schemas across workspaces")
    parser.add_argument("--codes", help="Comma-separated workspace codes to discover (default: all)")
    parser.add_argument("--window-days", type=int, default=7, help="Lookback window for active-table detection (default: 7)")
    parser.add_argument("--workers", type=int, default=int(os.getenv("SOCAI_DISCOVER_WORKERS", "3")),
                        help="Parallel workspace discovery workers (default: 3)")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    config_dir = repo_root / "config"
    config_dir.mkdir(exist_ok=True)

    # Check az cli is available
    try:
        subprocess.run(["az", "account", "show"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: az cli not logged in. Run 'az login' first.", file=sys.stderr)
        sys.exit(1)

    # Resolve the workspace set
    if args.codes:
        requested = [c.strip() for c in args.codes.split(",") if c.strip()]
        unknown = [c for c in requested if c not in WORKSPACES]
        if unknown:
            print(f"ERROR: unknown workspace codes: {unknown}. Known: {sorted(WORKSPACES)}", file=sys.stderr)
            sys.exit(1)
        target_workspaces = {c: WORKSPACES[c] for c in requested}
        merge_mode = True
    else:
        target_workspaces = WORKSPACES
        merge_mode = False

    max_parallel = max(1, args.workers)
    all_results = []

    label = f"{len(target_workspaces)} workspaces ({max_parallel} parallel)" if max_parallel > 1 else f"{len(target_workspaces)} workspaces (sequential)"
    print(f"Running discovery across {label}, window={args.window_days}d, merge={merge_mode}...")

    if max_parallel > 1:
        with ThreadPoolExecutor(max_workers=max_parallel) as pool:
            futures = {
                pool.submit(discover_workspace, code, wid, args.window_days): code
                for code, wid in target_workspaces.items()
            }
            for future in as_completed(futures):
                code = futures[future]
                try:
                    result = future.result(timeout=1200)
                    all_results.append(result)
                except Exception as e:
                    print(f"  [{code}] Discovery failed: {e}", file=sys.stderr)
    else:
        for code, wid in target_workspaces.items():
            all_results.append(discover_workspace(code, wid, args.window_days))

    # Build outputs from this run
    fresh_universal = build_universal_registry(all_results)
    fresh_workspace_index = build_workspace_index(all_results)

    out_universal = config_dir / "sentinel_tables.json"
    out_workspaces = config_dir / "workspace_tables.json"

    if merge_mode:
        existing_universal = _load_json(out_universal)
        existing_workspace_index = _load_json(out_workspaces)

        refreshed_codes = {r["code"] for r in all_results}
        universal = _merge_universal(existing_universal, fresh_universal, refreshed_codes)

        workspace_index = dict(existing_workspace_index)
        workspace_index.update(fresh_workspace_index)
        workspace_index = dict(sorted(workspace_index.items()))
    else:
        universal = fresh_universal
        workspace_index = fresh_workspace_index

    with open(out_universal, "w") as f:
        json.dump(universal, f, indent=2)
    print(f"\n✓ Universal registry: {out_universal} ({len(universal)} tables)")

    with open(out_workspaces, "w") as f:
        json.dump(workspace_index, f, indent=2)
    print(f"✓ Workspace index:   {out_workspaces} ({len(workspace_index)} workspaces)")

    print(f"\n{'='*60}")
    print(f"SUMMARY (this run)")
    print(f"{'='*60}")
    for r in sorted(all_results, key=lambda x: x['code']):
        print(f"  {r['code']}: {len(r['tables'])} tables")
    print(f"  {'─'*40}")
    print(f"  TOTAL UNIQUE TABLES IN REGISTRY: {len(universal)}")


if __name__ == "__main__":
    main()
