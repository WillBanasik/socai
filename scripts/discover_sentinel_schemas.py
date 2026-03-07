#!/usr/bin/env python3
"""
Discover all Sentinel Log Analytics tables + schemas across workspaces.
Requires: az cli logged in with reader access to each workspace.

Outputs:
  - config/sentinel_tables.json   (universal table registry)
  - config/workspace_tables.json  (per-workspace table availability)
"""

import json
import subprocess
import sys
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

WORKSPACES = {
    "example-client": "00000000-0000-0000-0000-000000000000",
}

# Step 1 query: get active tables from last 7 days
TABLE_LIST_QUERY = """Usage
| where TimeGenerated > ago(7d)
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


def discover_workspace(code: str, workspace_id: str) -> dict:
    """Discover all tables and their schemas for a workspace."""
    print(f"\n[{code}] Discovering tables for workspace {workspace_id[:8]}...")

    # Get table list
    rows = az_query(workspace_id, TABLE_LIST_QUERY)
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


def main():
    repo_root = Path(__file__).resolve().parent.parent
    config_dir = repo_root / "config"
    config_dir.mkdir(exist_ok=True)

    # Check az cli is available
    try:
        subprocess.run(["az", "account", "show"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: az cli not logged in. Run 'az login' first.", file=sys.stderr)
        sys.exit(1)

    # Discover schemas — sequential per workspace (each workspace does N serial table queries)
    # but we can parallelise across workspaces
    max_parallel = int(os.getenv("SOCAI_DISCOVER_WORKERS", "3"))
    all_results = []

    if max_parallel > 1:
        print(f"Running discovery across {len(WORKSPACES)} workspaces ({max_parallel} parallel)...")
        with ThreadPoolExecutor(max_workers=max_parallel) as pool:
            futures = {
                pool.submit(discover_workspace, code, wid): code
                for code, wid in WORKSPACES.items()
            }
            for future in as_completed(futures):
                code = futures[future]
                try:
                    result = future.result(timeout=600)
                    all_results.append(result)
                except Exception as e:
                    print(f"  [{code}] Discovery failed: {e}", file=sys.stderr)
    else:
        print(f"Running discovery across {len(WORKSPACES)} workspaces (sequential)...")
        for code, wid in WORKSPACES.items():
            all_results.append(discover_workspace(code, wid))

    # Build outputs
    universal = build_universal_registry(all_results)
    workspace_index = build_workspace_index(all_results)

    # Write universal table registry
    out_universal = config_dir / "sentinel_tables.json"
    with open(out_universal, "w") as f:
        json.dump(universal, f, indent=2)
    print(f"\n✓ Universal registry: {out_universal} ({len(universal)} tables)")

    # Write per-workspace index
    out_workspaces = config_dir / "workspace_tables.json"
    with open(out_workspaces, "w") as f:
        json.dump(workspace_index, f, indent=2)
    print(f"✓ Workspace index:   {out_workspaces} ({len(workspace_index)} workspaces)")

    # Summary
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    for code in sorted(workspace_index.keys()):
        info = workspace_index[code]
        print(f"  {code}: {info['table_count']} tables")
    print(f"  {'─'*40}")
    print(f"  TOTAL UNIQUE TABLES: {len(universal)}")


if __name__ == "__main__":
    main()
