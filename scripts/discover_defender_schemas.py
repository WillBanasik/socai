#!/usr/bin/env python3
"""
Discover Microsoft Defender XDR Advanced Hunting tables + schemas
across all clients that have ``platforms.defender_xdr.api_enabled: true``
in config/client_entities.json.

Outputs:
  - config/defender_tables.json     (per-client table availability + schemas)

Requires:
  - SOCAI_DEFENDER_APP_CLIENT_ID and SOCAI_DEFENDER_APP_CLIENT_SECRET in .env
  - The multi-tenant app reg admin-consented in each client tenant
"""
from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.common import load_json
from tools.defender_hunting import (
    DefenderHuntingError,
    is_defender_configured,
    run_defender_kql,
)

# Canonical set of tables exposed by Defender XDR Advanced Hunting.
# A tenant may not see all of these — Device* requires MDE, Identity* requires
# MDI, Email*/Url* require MDO, CloudApp* requires MDCA, Exposure* requires MDE
# attack-surface-management.  We probe each and record which ones return a
# schema.
CANDIDATE_TABLES = [
    # Endpoint (MDE)
    "DeviceEvents",
    "DeviceProcessEvents",
    "DeviceFileEvents",
    "DeviceNetworkEvents",
    "DeviceImageLoadEvents",
    "DeviceLogonEvents",
    "DeviceRegistryEvents",
    "DeviceFileCertificateInfo",
    "DeviceInfo",
    "DeviceNetworkInfo",
    "DeviceBaselineComplianceProfiles",
    "DeviceBaselineComplianceAssessment",
    "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareVulnerabilitiesKB",
    "DeviceTvmSecureConfigurationAssessment",
    # Email / URL (MDO)
    "EmailEvents",
    "EmailAttachmentInfo",
    "EmailUrlInfo",
    "EmailPostDeliveryEvents",
    "UrlClickEvents",
    # Identity (MDI)
    "IdentityInfo",
    "IdentityLogonEvents",
    "IdentityDirectoryEvents",
    "IdentityQueryEvents",
    # Cloud Apps (MDCA)
    "CloudAppEvents",
    # Unified alerting
    "AlertEvidence",
    "AlertInfo",
    # Exposure Management
    "ExposureGraphEdges",
    "ExposureGraphNodes",
]

SCHEMA_QUERY_TPL = "{table}\n| getschema\n| project ColumnName, DataType, ColumnType"


def _load_enabled_clients() -> list[str]:
    cfg = Path(__file__).resolve().parent.parent / "config" / "client_entities.json"
    data = load_json(cfg)
    return [c["name"] for c in data.get("clients", []) if is_defender_configured(c["name"])]


def discover_client(client: str) -> dict:
    print(f"\n[{client}] Discovering Defender XDR tables...")
    tables: dict[str, dict[str, str]] = {}
    for i, table in enumerate(CANDIDATE_TABLES, 1):
        try:
            result = run_defender_kql(client, SCHEMA_QUERY_TPL.format(table=table), timeout=30)
        except DefenderHuntingError as exc:
            msg = str(exc)
            # Table-not-found / licence-missing surfaces as a 400 with a parser
            # error mentioning the table.  Treat as "not in this tenant".
            if "could not be found" in msg.lower() or "semanticerror" in msg.lower():
                print(f"  [{client}] {i}/{len(CANDIDATE_TABLES)} {table}: not available")
            else:
                print(f"  [{client}] {i}/{len(CANDIDATE_TABLES)} {table}: ✗ {msg[:120]}")
            continue

        columns = {}
        for row in result.get("rows", []):
            col_name = row.get("ColumnName", "")
            col_type = row.get("DataType") or row.get("ColumnType", "")
            if col_name:
                columns[col_name] = col_type
        if columns:
            tables[table] = columns
            print(f"  [{client}] {i}/{len(CANDIDATE_TABLES)} {table}: {len(columns)} columns")
        else:
            print(f"  [{client}] {i}/{len(CANDIDATE_TABLES)} {table}: empty schema")

    return {"client": client, "tables": tables}


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    config_dir = repo_root / "config"
    out_path = config_dir / "defender_tables.json"

    clients = _load_enabled_clients()
    if not clients:
        print("No clients have platforms.defender_xdr.api_enabled=true in client_entities.json", file=sys.stderr)
        print("(Or the SOCAI_DEFENDER_APP_CLIENT_ID/SECRET env vars are not set.)", file=sys.stderr)
        return 1

    print(f"Discovering across {len(clients)} configured client(s)...")
    max_parallel = int(os.getenv("SOCAI_DEFENDER_DISCOVER_WORKERS", "3"))
    all_results: list[dict] = []

    if max_parallel > 1 and len(clients) > 1:
        with ThreadPoolExecutor(max_workers=max_parallel) as pool:
            futures = {pool.submit(discover_client, c): c for c in clients}
            for fut in as_completed(futures):
                try:
                    all_results.append(fut.result(timeout=600))
                except Exception as exc:
                    print(f"  [{futures[fut]}] discovery failed: {exc}", file=sys.stderr)
    else:
        for c in clients:
            all_results.append(discover_client(c))

    index = {
        r["client"]: {
            "tables": sorted(r["tables"].keys()),
            "table_count": len(r["tables"]),
            "schemas": r["tables"],
        }
        for r in sorted(all_results, key=lambda x: x["client"])
    }

    with open(out_path, "w") as f:
        json.dump(index, f, indent=2)
        f.write("\n")

    print(f"\n✓ {out_path} ({len(index)} clients)")
    print("\n=== SUMMARY ===")
    for client, info in index.items():
        print(f"  {client}: {info['table_count']} tables")
    return 0


if __name__ == "__main__":
    sys.exit(main())
