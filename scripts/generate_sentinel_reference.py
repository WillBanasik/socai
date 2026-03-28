#!/usr/bin/env python3
"""
Generate a Sentinel reference markdown file for a client from the schema registry.

Reads config/sentinel_tables.json and config/workspace_tables.json, then writes
config/clients/{client}/sentinel.md with table descriptions and column schemas
tiered by investigation relevance.

Usage:
    python3 scripts/generate_sentinel_reference.py performanta
    python3 scripts/generate_sentinel_reference.py --all
"""

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from config.sentinel_schema import (
    _load_registry,
    _load_workspace_tables,
    _table_description,
    _SKIP_TABLES,
    _CONTEXT_PRIORITY,
    _IP_FIELDS, _DOMAIN_FIELDS, _URL_FIELDS, _EMAIL_FIELDS, _HASH_FIELDS,
)

# Investigation-critical tables — full schema (tier 1)
_TIER1_TABLES = {
    # Identity & sign-in
    "SigninLogs", "AADNonInteractiveUserSignInLogs",
    "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
    "AADRiskyUsers", "AADUserRiskEvents", "AuditLogs",
    "IdentityLogonEvents", "IdentityDirectoryEvents", "IdentityQueryEvents",
    "BehaviorAnalytics",
    # Endpoint
    "DeviceProcessEvents", "DeviceFileEvents", "DeviceNetworkEvents",
    "DeviceLogonEvents", "DeviceEvents", "DeviceRegistryEvents",
    "DeviceImageLoadEvents",
    # Email
    "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo",
    "EmailPostDeliveryEvents", "UrlClickEvents",
    # Alerts & incidents
    "SecurityAlert", "SecurityIncident", "AlertEvidence", "AlertInfo",
    # Cloud & SaaS
    "CloudAppEvents", "OfficeActivity",
    # Network
    "CommonSecurityLog",
    # Windows
    "SecurityEvent",
}

# Category groupings for readable markdown
_CATEGORIES = [
    ("Identity & Sign-in", [
        "SigninLogs", "AADNonInteractiveUserSignInLogs",
        "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
        "AADRiskyUsers", "AADUserRiskEvents",
        "IdentityLogonEvents", "IdentityDirectoryEvents", "IdentityQueryEvents",
        "IdentityInfo", "AuditLogs", "BehaviorAnalytics", "UserPeerAnalytics",
    ]),
    ("Endpoint (Defender for Endpoint / MDE)", [
        "DeviceEvents", "DeviceProcessEvents", "DeviceFileEvents",
        "DeviceNetworkEvents", "DeviceLogonEvents", "DeviceRegistryEvents",
        "DeviceImageLoadEvents", "DeviceInfo", "DeviceNetworkInfo",
        "DeviceFileCertificateInfo",
    ]),
    ("Email (Defender for Office 365)", [
        "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo",
        "EmailPostDeliveryEvents", "UrlClickEvents",
    ]),
    ("Alerts & Incidents", [
        "SecurityAlert", "SecurityIncident", "AlertInfo", "AlertEvidence",
        "Anomalies", "ThreatIntelIndicators",
    ]),
    ("Cloud & SaaS", [
        "CloudAppEvents", "OfficeActivity", "McasShadowItReporting",
        "MicrosoftGraphActivityLogs", "AzureActivity", "AzureDevOpsAuditing",
    ]),
    ("Device Management (Intune)", [
        "IntuneDevices", "IntuneDeviceComplianceOrg",
        "IntuneAuditLogs", "IntuneOperationalLogs",
    ]),
    ("Infrastructure & Other", [
        "SecurityEvent", "CommonSecurityLog", "Syslog", "Heartbeat",
        "SentinelHealth", "LAQueryLogs", "Watchlist", "NetworkAccessTraffic",
    ]),
]

_TYPE_SIMPLIFY = {
    "System.String": "String",
    "System.DateTime": "DateTime",
    "System.Int32": "Int",
    "System.Int64": "Long",
    "System.Double": "Double",
    "System.Boolean": "Bool",
    "System.Guid": "Guid",
    "System.Object": "Dynamic",
    "System.SByte": "SByte",
    "System.TimeSpan": "TimeSpan",
    "string": "String", "datetime": "DateTime", "int": "Int",
    "long": "Long", "double": "Double", "bool": "Bool",
    "guid": "Guid", "dynamic": "Dynamic", "timespan": "TimeSpan",
    "real": "Double",
}

_ALL_IOC_FIELDS = (
    _IP_FIELDS | _DOMAIN_FIELDS | _URL_FIELDS | _EMAIL_FIELDS | set(_HASH_FIELDS.keys())
)


def _simplify_type(t: str) -> str:
    return _TYPE_SIMPLIFY.get(t, t.replace("System.", ""))


def _order_columns(columns: dict[str, str]) -> list[str]:
    """Order columns by investigation relevance."""
    ordered: list[str] = []
    seen: set[str] = set()
    for col in _CONTEXT_PRIORITY:
        if col in columns and col not in seen:
            ordered.append(col)
            seen.add(col)
    for col in sorted(_ALL_IOC_FIELDS):
        if col in columns and col not in seen:
            ordered.append(col)
            seen.add(col)
    for col in sorted(columns.keys()):
        if col not in seen:
            ordered.append(col)
            seen.add(col)
    return ordered


def generate_reference(client: str) -> str:
    """Generate sentinel.md content for a client."""
    registry = _load_registry()
    ws_registry = _load_workspace_tables()

    ws_info = ws_registry.get(client, {})
    ws_id = ws_info.get("workspace_id", "")
    ws_tables = set(ws_info.get("tables", []))

    if not ws_tables:
        print(f"Warning: no workspace data for '{client}' in workspace_tables.json", file=sys.stderr)
        return ""

    lines = [
        f"# {client.replace('-', ' ').title()} — Sentinel Reference",
        "",
        "> Technical reference for querying the Sentinel workspace.",
        "> Used by the agent when building KQL queries during investigations.",
        "> **Auto-generated** from schema registry by `scripts/generate_sentinel_reference.py`.",
        "",
        "---",
        "",
        "## Workspace",
        "",
        f"- **Workspace ID:** `{ws_id}`",
        f"- **Workspace name:** `{client}`",
        "",
        "---",
        "",
        f"## Available Tables ({len(ws_tables)})",
        "",
    ]

    # Track tables we've listed to catch uncategorised ones
    listed: set[str] = set()

    for category_name, category_tables in _CATEGORIES:
        available = [t for t in category_tables if t in ws_tables]
        if not available:
            continue

        lines.append(f"### {category_name}")
        lines.append("")

        for table in available:
            listed.add(table)
            desc = _table_description(table)
            entry = registry.get(table, {})
            columns = entry.get("columns", {})

            if table in _TIER1_TABLES and columns:
                # Tier 1: full schema with column table
                ordered = _order_columns(columns)
                max_cols = 25
                display = ordered[:max_cols]
                lines.append(f"#### {table} — {desc} ({len(columns)} columns)")
                lines.append("")
                lines.append("| Column | Type |")
                lines.append("|--------|------|")
                for col in display:
                    lines.append(f"| {col} | {_simplify_type(columns[col])} |")
                if len(ordered) > max_cols:
                    lines.append(f"| *... +{len(ordered) - max_cols} more* | |")
                lines.append("")
            elif table not in _SKIP_TABLES and columns:
                # Tier 2: abbreviated (10 columns)
                ordered = _order_columns(columns)
                display = ordered[:10]
                col_str = ", ".join(display)
                if len(ordered) > 10:
                    col_str += f", ... (+{len(ordered) - 10} more)"
                lines.append(f"**{table}** — {desc} ({len(columns)} columns)")
                lines.append(f"  Key columns: {col_str}")
                lines.append("")
            else:
                # Tier 3: name only
                lines.append(f"**{table}** — {desc}")
                lines.append("")

    # Uncategorised tables (custom _CL tables, etc.)
    uncategorised = ws_tables - listed - _SKIP_TABLES
    if uncategorised:
        lines.append("### Custom / Other")
        lines.append("")
        for table in sorted(uncategorised):
            desc = _table_description(table)
            entry = registry.get(table, {})
            columns = entry.get("columns", {})
            if columns:
                ordered = _order_columns(columns)
                display = ordered[:10]
                col_str = ", ".join(display)
                if len(ordered) > 10:
                    col_str += f", ... (+{len(ordered) - 10} more)"
                lines.append(f"**{table}** — {desc} ({len(columns)} columns)")
                lines.append(f"  Key columns: {col_str}")
            else:
                lines.append(f"**{table}** — {desc}")
            lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate Sentinel reference markdown from schema registry"
    )
    parser.add_argument("client", nargs="?", help="Client workspace code (e.g. performanta)")
    parser.add_argument("--all", action="store_true", help="Generate for all clients")
    parser.add_argument("--dry-run", action="store_true", help="Print to stdout instead of writing")
    args = parser.parse_args()

    registry = _load_registry()
    if not registry:
        print("Error: config/sentinel_tables.json not found or empty. "
              "Run scripts/discover_sentinel_schemas.py first.", file=sys.stderr)
        sys.exit(1)

    ws_registry = _load_workspace_tables()
    if not ws_registry:
        print("Error: config/workspace_tables.json not found or empty.", file=sys.stderr)
        sys.exit(1)

    clients = list(ws_registry.keys()) if args.all else [args.client]
    if not args.all and not args.client:
        parser.error("Provide a client name or use --all")

    for client in clients:
        content = generate_reference(client)
        if not content:
            continue

        if args.dry_run:
            print(content)
            print(f"\n{'='*60}\n")
        else:
            out_dir = _REPO_ROOT / "config" / "clients" / client
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / "sentinel.md"
            out_path.write_text(content, encoding="utf-8")
            print(f"✓ {out_path} ({len(content)} chars)")


if __name__ == "__main__":
    main()
