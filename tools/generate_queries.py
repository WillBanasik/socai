"""
tool: generate_queries
----------------------
Generates SIEM hunt queries (KQL, Splunk SPL, LogScale) from a case's
IOCs and threat findings detected in the investigation report.

Supports:
  - KQL  (Microsoft Sentinel / Defender for Endpoint)
  - Splunk SPL
  - LogScale / CrowdStrike Falcon

Outputs:
  cases/<case_id>/artefacts/queries/hunt_queries.md
  cases/<case_id>/artefacts/queries/hunt_queries.yaml
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from config.sentinel_schema import (
    get_ip_tables, get_domain_tables, get_url_tables,
    get_hash_tables, get_email_tables, has_registry,
)
from tools.common import load_json, log_error, utcnow, write_artefact


# ---------------------------------------------------------------------------
# KQL table / field definitions
# Each entry: (table_name, [fields], project_columns, description)
#
# When config/sentinel_tables.json exists (populated by
# scripts/discover_sentinel_schemas.py), tables are loaded dynamically from
# the real Sentinel schema registry.  Otherwise these hardcoded fallbacks
# are used.
# ---------------------------------------------------------------------------

_FALLBACK_IP_TABLES = [
    (
        "DeviceNetworkEvents",
        ["RemoteIP", "LocalIP"],
        "TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, "
        "LocalIP, RemoteIP, RemotePort, RemoteUrl, ActionType, BytesSent, BytesReceived",
        "Network connections",
    ),
    (
        "IdentityLogonEvents",
        ["SourceIPAddress", "DestinationIPAddress"],
        "TimeGenerated, AccountName, AccountDomain, DeviceName, LogonType, ActionType, "
        "FailureReason, SourceIPAddress, DestinationIPAddress",
        "Authentication events",
    ),
    (
        "IdentityQueryEvents",
        ["IPAddress"],
        "TimeGenerated, AccountName, DeviceName, IPAddress, QueryType, QueryTarget, Protocol",
        "Directory service queries",
    ),
    (
        "DeviceLogonEvents",
        ["RemoteIP"],
        "TimeGenerated, DeviceName, AccountName, AccountDomain, LogonType, RemoteIP, "
        "IsLocalAdmin, ActionType",
        "Device logon events",
    ),
    (
        "SecurityEvent",
        ["IpAddress"],
        "TimeGenerated, Computer, Account, EventID, Activity, IpAddress",
        "Windows security events",
    ),
    (
        "BehaviorAnalytics",
        None,  # handled specially
        "TimeGenerated, UserName, DeviceName, ActionType, ActivityType, "
        "ActivityInsights, InvestigationPriority",
        "UEBA anomalies",
    ),
    (
        "Syslog",
        ["HostIP"],
        "TimeGenerated, Computer, Facility, SeverityLevel, ProcessName, SyslogMessage",
        "Linux/Unix syslog",
    ),
    (
        "DeviceNetworkInfo",
        None,  # handled specially (IPAddresses is dynamic)
        "TimeGenerated, DeviceName, IPAddresses, MacAddress, NetworkAdapterType, ConnectedNetworks",
        "Network adapter / IP assignment",
    ),
]

_FALLBACK_DOMAIN_TABLES = [
    (
        "DeviceNetworkEvents",
        ["RemoteUrl"],
        "TimeGenerated, DeviceName, InitiatingProcessFileName, LocalIP, RemoteIP, "
        "RemotePort, RemoteUrl, ActionType",
        "Network connections",
    ),
    (
        "IdentityQueryEvents",
        ["QueryTarget"],
        "TimeGenerated, AccountName, DeviceName, IPAddress, QueryType, QueryTarget",
        "Directory service queries",
    ),
]

_FALLBACK_URL_TABLES = [
    (
        "DeviceNetworkEvents",
        ["RemoteUrl"],
        "TimeGenerated, DeviceName, InitiatingProcessFileName, LocalIP, RemoteIP, "
        "RemotePort, RemoteUrl, ActionType, BytesSent, BytesReceived",
        "Network connections",
    ),
]

_FALLBACK_HASH_TABLES: dict[str, list] = {
    "sha256": [
        (
            "DeviceFileEvents",
            ["SHA256"],
            "TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, FolderPath, "
            "SHA256, ActionType",
            "File system events",
        ),
        (
            "DeviceProcessEvents",
            ["SHA256", "InitiatingProcessSHA256"],
            "TimeGenerated, DeviceName, AccountName, FileName, FolderPath, "
            "ProcessCommandLine, SHA256, InitiatingProcessSHA256",
            "Process creation events",
        ),
        (
            "DeviceImageLoadEvents",
            ["SHA256"],
            "TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName",
            "Module / DLL load events",
        ),
        (
            "AlertEvidence",
            ["Sha256"],
            "TimeGenerated, AlertId, Title, Sha256, EvidenceRole, EntityType",
            "Alert evidence",
        ),
    ],
    "md5": [
        (
            "DeviceFileEvents",
            ["MD5"],
            "TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, FolderPath, "
            "MD5, ActionType",
            "File system events",
        ),
        (
            "DeviceProcessEvents",
            ["MD5", "InitiatingProcessMD5"],
            "TimeGenerated, DeviceName, AccountName, FileName, FolderPath, "
            "ProcessCommandLine, MD5",
            "Process creation events",
        ),
    ],
    "sha1": [
        (
            "DeviceFileEvents",
            ["SHA1"],
            "TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, FolderPath, "
            "SHA1, ActionType",
            "File system events",
        ),
        (
            "DeviceProcessEvents",
            ["SHA1"],
            "TimeGenerated, DeviceName, AccountName, FileName, FolderPath, "
            "ProcessCommandLine, SHA1",
            "Process creation events",
        ),
    ],
}

_FALLBACK_EMAIL_TABLES = [
    (
        "EmailEvents",
        ["SenderFromAddress", "RecipientEmailAddress"],
        "TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, "
        "DeliveryAction, ThreatTypes",
        "Email delivery events",
    ),
    (
        "EmailUrlInfo",
        ["Url"],
        "TimeGenerated, Url, UrlDomain, UrlLocation, NetworkMessageId",
        "URLs embedded in emails",
    ),
]


def _get_kql_ip_tables(allowed: list[str] | None = None) -> list:
    if has_registry():
        return get_ip_tables(allowed)
    return _FALLBACK_IP_TABLES


def _get_kql_domain_tables(allowed: list[str] | None = None) -> list:
    if has_registry():
        return get_domain_tables(allowed)
    return _FALLBACK_DOMAIN_TABLES


def _get_kql_url_tables(allowed: list[str] | None = None) -> list:
    if has_registry():
        return get_url_tables(allowed)
    return _FALLBACK_URL_TABLES


def _get_kql_hash_tables(hash_type: str, allowed: list[str] | None = None) -> list:
    if has_registry():
        return get_hash_tables(hash_type, allowed)
    return _FALLBACK_HASH_TABLES.get(hash_type, [])


def _get_kql_email_tables(allowed: list[str] | None = None) -> list:
    if has_registry():
        return get_email_tables(allowed)
    return _FALLBACK_EMAIL_TABLES


# ---------------------------------------------------------------------------
# KQL helpers
# ---------------------------------------------------------------------------

def _active_tables(table_defs: list, allowed: list[str] | None) -> list:
    """Filter table definitions to only those in the allowed list.

    NOTE: When the sentinel schema registry is active, tables are already
    filtered by the _get_kql_*() helpers.  This function is kept for
    backward-compat with fallback table lists and explicit --tables scoping.
    """
    if allowed is None:
        return table_defs
    return [t for t in table_defs if t[0] in allowed]


def _kql_code(query: str, *, collector: list | None = None,
              category: str = "", table: str = "", description: str = "") -> str:
    if collector is not None:
        collector.append({
            "platform": "kql",
            "category": category,
            "table": table,
            "description": description,
            "query": query.strip(),
        })
    return f"```kql\n{query.strip()}\n```"


def _extract_table_from_query(query: str) -> str:
    """Extract the primary table name from a KQL query string."""
    for line in query.strip().split("\n"):
        line = line.strip()
        if line and not line.startswith("//") and not line.startswith("let ") and not line.startswith("|"):
            return line
    return "unknown"


def _ip_dynamic(ips: list[str]) -> str:
    quoted = ", ".join(f'"{ip}"' for ip in ips)
    return f"dynamic([{quoted}])"


# ---------------------------------------------------------------------------
# KQL — IOC-type query builders
# ---------------------------------------------------------------------------

def _build_kql_ipv4(ips: list[str], tables: list[str] | None, collector: list | None = None) -> str:
    if not ips:
        return ""

    ip_dyn = _ip_dynamic(ips)
    let_line = f"let suspect_ips = {ip_dyn};"
    parts = []

    active = _active_tables(_get_kql_ip_tables(tables), tables)
    for table, fields, project, desc in active:
        if table == "BehaviorAnalytics":
            cond = " or ".join(f'ActivityInsights has "{ip}"' for ip in ips)
            query = (
                f"{let_line}\n// {table} — {desc}\n{table}\n"
                f"| where {cond}\n"
                f"| project {project}\n"
                f"| order by InvestigationPriority desc"
            )
        elif table == "DeviceNetworkInfo":
            cond = " or ".join(f'IPAddresses has "{ip}"' for ip in ips)
            query = (
                f"{let_line}\n// {table} — {desc}\n{table}\n"
                f"| where {cond}\n"
                f"| project {project}\n"
                f"| order by TimeGenerated desc"
            )
        elif table == "Syslog":
            msg_cond = " or ".join(f'SyslogMessage contains "{ip}"' for ip in ips)
            query = (
                f"{let_line}\n// {table} — {desc}\n{table}\n"
                f"| where HostIP in (suspect_ips)\n"
                f"      or {msg_cond}\n"
                f"| project {project}\n"
                f"| order by TimeGenerated asc"
            )
        else:
            where = " or ".join(f"{f} in (suspect_ips)" for f in fields)
            query = (
                f"{let_line}\n// {table} — {desc}\n{table}\n"
                f"| where {where}\n"
                f"| project {project}\n"
                f"| order by TimeGenerated asc"
            )
        parts.append(_kql_code(query, collector=collector, category="ipv4",
                                table=table, description=desc))

    return "\n\n".join(parts)


def _build_kql_domains(domains: list[str], tables: list[str] | None, collector: list | None = None) -> str:
    if not domains:
        return ""

    active = _active_tables(_get_kql_domain_tables(tables), tables)
    parts = []
    for table, fields, project, desc in active:
        # Fields containing URL-like data use "has" (substring), others use "in" (exact)
        url_like = {"RemoteUrl", "Url", "UrlFull", "RequestURL"}
        has_fields = [f for f in fields if f in url_like]
        in_fields = [f for f in fields if f not in url_like]
        conds = []
        for f in has_fields:
            conds.extend(f'{f} has "{d}"' for d in domains)
        if in_fields:
            quoted = ", ".join(f'"{d}"' for d in domains)
            conds.extend(f'{f} in ({quoted})' for f in in_fields)
        cond = " or ".join(conds)
        query = (
            f"// {table} — {desc}\n{table}\n"
            f"| where {cond}\n"
            f"| project {project}\n"
            f"| order by TimeGenerated asc"
        )
        parts.append(_kql_code(query, collector=collector, category="domain",
                                table=table, description=desc))

    return "\n\n".join(parts)


def _build_kql_hashes(hashes: dict[str, list[str]], tables: list[str] | None, collector: list | None = None) -> str:
    parts = []
    for hash_type, values in hashes.items():
        if not values or hash_type not in ("sha256", "md5", "sha1"):
            continue
        all_defs = _get_kql_hash_tables(hash_type, tables)
        # Hash tables are not network tables — always include all of them
        # but still respect any explicit table filter if provided
        table_defs = _active_tables(all_defs, tables) \
            if tables and any(t[0] in tables for t in all_defs) \
            else all_defs

        quoted = ", ".join(f'"{v}"' for v in values)
        for table, fields, project, desc in table_defs:
            where = " or ".join(f'{f} in ({quoted})' for f in fields)
            query = (
                f"// {table} — {desc} [{hash_type.upper()}]\n{table}\n"
                f"| where {where}\n"
                f"| project {project}\n"
                f"| order by TimeGenerated asc"
            )
            parts.append(_kql_code(query, collector=collector,
                                    category=f"hash_{hash_type}",
                                    table=table, description=desc))

    return "\n\n".join(parts)


def _build_kql_urls(urls: list[str], tables: list[str] | None, collector: list | None = None) -> str:
    if not urls:
        return ""

    active = _active_tables(_get_kql_url_tables(tables), tables)
    parts = []
    for table, fields, project, desc in active:
        url_fields = fields if fields else ["RemoteUrl"]
        cond = " or ".join(
            f'{f} has "{u}"' for f in url_fields for u in urls[:20]
        )
        query = (
            f"// {table} — {desc}\n{table}\n"
            f"| where {cond}\n"
            f"| project {project}\n"
            f"| order by TimeGenerated asc"
        )
        parts.append(_kql_code(query, collector=collector, category="url",
                                table=table, description=desc))

    return "\n\n".join(parts)


def _build_kql_emails(emails: list[str], tables: list[str] | None, collector: list | None = None) -> str:
    if not emails:
        return ""

    quoted = ", ".join(f'"{e}"' for e in emails)
    parts = []
    # Email tables won't appear in a network table filter — always include
    for table, fields, project, desc in _get_kql_email_tables(tables):
        where = " or ".join(f'{f} in ({quoted})' for f in fields)
        query = (
            f"// {table} — {desc}\n{table}\n"
            f"| where {where}\n"
            f"| project {project}\n"
            f"| order by TimeGenerated asc"
        )
        parts.append(_kql_code(query, collector=collector, category="email",
                                table=table, description=desc))

    return "\n\n".join(parts)


def _build_kql_timeline(iocs: dict, tables: list[str] | None, collector: list | None = None) -> str:
    """Single unified timeline query across all relevant tables."""
    ips = iocs.get("ipv4", [])
    domains = iocs.get("domain", [])
    sha256s = iocs.get("sha256", [])

    union_parts = []
    let_lines = []

    if ips:
        ip_dyn = _ip_dynamic(ips[:20])
        let_lines.append(f"let ips = {ip_dyn};")

        if tables is None or "DeviceNetworkEvents" in tables:
            union_parts.append(
                "DeviceNetworkEvents\n"
                "| where RemoteIP in (ips) or LocalIP in (ips)\n"
                "| project TimeGenerated, Source=\"DeviceNetworkEvents\",\n"
                "          Entity=DeviceName,\n"
                "          Detail=strcat(LocalIP, \" -> \", RemoteIP, \":\",\n"
                "                       tostring(RemotePort), \" [\",\n"
                "                       InitiatingProcessFileName, \"]\")"
            )
        if tables is None or "IdentityLogonEvents" in tables:
            union_parts.append(
                "IdentityLogonEvents\n"
                "| where SourceIPAddress in (ips) or DestinationIPAddress in (ips)\n"
                "| project TimeGenerated, Source=\"IdentityLogonEvents\",\n"
                "          Entity=AccountName,\n"
                "          Detail=strcat(ActionType, \" from \", SourceIPAddress,\n"
                "                       \" to \", DestinationIPAddress)"
            )
        if tables is None or "IdentityQueryEvents" in tables:
            union_parts.append(
                "IdentityQueryEvents\n"
                "| where IPAddress in (ips)\n"
                "| project TimeGenerated, Source=\"IdentityQueryEvents\",\n"
                "          Entity=AccountName,\n"
                "          Detail=strcat(QueryType, \" -> \", QueryTarget)"
            )

    if domains and (tables is None or "DeviceNetworkEvents" in tables):
        dom_cond = " or ".join(f'RemoteUrl has "{d}"' for d in domains[:10])
        union_parts.append(
            f"DeviceNetworkEvents\n"
            f"| where {dom_cond}\n"
            f"| project TimeGenerated, Source=\"DeviceNetworkEvents (domain)\",\n"
            f"          Entity=DeviceName,\n"
            f"          Detail=strcat(LocalIP, \" -> \", RemoteUrl)"
        )

    if sha256s:
        quoted = ", ".join(f'"{h}"' for h in sha256s[:10])
        union_parts.append(
            f"DeviceFileEvents\n"
            f"| where SHA256 in ({quoted})\n"
            f"| project TimeGenerated, Source=\"DeviceFileEvents\",\n"
            f"          Entity=DeviceName,\n"
            f"          Detail=strcat(ActionType, \" \", FileName, \" [\", FolderPath, \"]\")"
        )

    if not union_parts:
        return ""

    let_block = "\n".join(let_lines) + "\n" if let_lines else ""
    union_block = "\nunion\n".join(union_parts)
    query = f"{let_block}{union_block}\n| order by TimeGenerated asc"
    return _kql_code(query, collector=collector, category="timeline",
                      table="union", description="Unified IOC timeline")


# ---------------------------------------------------------------------------
# Threat pattern detection
# ---------------------------------------------------------------------------

_THREAT_PATTERNS: dict[str, list[str]] = {
    "beaconing": [
        "DGA", "beaconing", "Fast Beaconing", "T1568", "C2",
        "command and control", "Compromise/Fast Beaconing",
    ],
    "cryptomining": [
        "mining", "Monero", "crypto currency", "cryptocurrency",
        "T1496", "Compromise/Monero", "mining pool", "xmrig",
    ],
    "smb_ransomware": [
        "SMB", "ransomware", "T1486", "Unusual SMB", "write ratio",
        "Suspicious Read Write Ratio",
    ],
    "lateral_movement": [
        "lateral", "brute force", "brute-force", "password spray",
        "T1021", "T1110", "SSH brute",
    ],
    "exfiltration": [
        "exfiltration", "T1041", "Data Exfiltration",
    ],
    "scanning": [
        "scan", "recon", "T1046", "Network Scan", "port scan",
        "Device/Network Scan", "Device/Attack and Recon",
    ],
}


def _detect_patterns(text: str) -> list[str]:
    text_lower = text.lower()
    return [
        pattern
        for pattern, keywords in _THREAT_PATTERNS.items()
        if any(kw.lower() in text_lower for kw in keywords)
    ]


# ---------------------------------------------------------------------------
# Threat-specific KQL queries
# ---------------------------------------------------------------------------

def _build_threat_queries(patterns: list[str], iocs: dict, tables: list[str] | None, collector: list | None = None) -> str:
    if not patterns:
        return ""

    ips = iocs.get("ipv4", [])
    sections: list[tuple[str, str]] = []

    if "beaconing" in patterns:
        ip_quoted = ", ".join(f'"{ip}"' for ip in ips[:10]) if ips else '""'
        sections.append((
            "Beaconing Interval Analysis (T1568.002)",
            f"// Detect automated beaconing: consistent inter-connection intervals = C2\n"
            f"DeviceNetworkEvents\n"
            f"| where RemoteIP in ({ip_quoted})\n"
            f"| order by DeviceName, TimeGenerated asc\n"
            f"| extend PrevTime = prev(TimeGenerated, 1, datetime(null))\n"
            f"| extend IntervalSec = datetime_diff(\"second\", TimeGenerated, PrevTime)\n"
            f"| where isnotnull(IntervalSec)\n"
            f"| summarize\n"
            f"    ConnectionCount = count(),\n"
            f"    AvgIntervalSec  = round(avg(IntervalSec), 1),\n"
            f"    StdevInterval   = round(stdev(IntervalSec), 1),\n"
            f"    MinInterval     = min(IntervalSec),\n"
            f"    MaxInterval     = max(IntervalSec),\n"
            f"    TotalBytesSent  = sum(BytesSent)\n"
            f"  by DeviceName, RemoteIP, RemotePort\n"
            f"// Low StdevInterval relative to AvgIntervalSec = highly regular (automated)\n"
            f"| extend BeaconingScore = round(1.0 - (StdevInterval / (AvgIntervalSec + 1)), 2)\n"
            f"| order by BeaconingScore desc"
        ))
        sections.append((
            "Process Responsible for C2 Connections",
            f"// Identify the initiating process — key pivot to determine if implant or legit app\n"
            f"DeviceNetworkEvents\n"
            f"| where RemoteIP in ({ip_quoted})\n"
            f"| summarize\n"
            f"    ConnectionCount = count(),\n"
            f"    FirstSeen       = min(TimeGenerated),\n"
            f"    LastSeen        = max(TimeGenerated),\n"
            f"    TotalBytesSent  = sum(BytesSent),\n"
            f"    Ports           = make_set(RemotePort)\n"
            f"  by DeviceName, InitiatingProcessFileName,\n"
            f"     InitiatingProcessCommandLine, RemoteIP\n"
            f"| order by ConnectionCount desc"
        ))

    if "cryptomining" in patterns:
        sections.append((
            "Crypto Mining — DNS Queries to Mining Pools (T1496)",
            "// Detect DNS queries matching known mining pool name patterns\n"
            "DeviceEvents\n"
            "| where ActionType == \"DnsQueryResponse\"\n"
            "| extend DnsQuery = tostring(parse_json(AdditionalFields).DnsQuery)\n"
            "| where DnsQuery has_any (\"pool\", \"xmr\", \"monero\", \"mining\",\n"
            "                          \"miner\", \"xmrig\", \"coinhive\", \"minergate\")\n"
            "| project TimeGenerated, DeviceName, LocalIP, DnsQuery\n"
            "| summarize QueryCount=count() by DnsQuery, DeviceName, LocalIP\n"
            "| order by QueryCount desc"
        ))
        sections.append((
            "Crypto Mining — High-Volume DNS from 192.168.x.x Segment",
            "// Darktrace flagged 192.168.x.x hosts with anomalous DNS volume to internal resolvers\n"
            "DeviceNetworkEvents\n"
            "| where RemotePort == 53\n"
            "      and LocalIP startswith \"192.168.\"\n"
            "| summarize\n"
            "    QueryCount = count(),\n"
            "    Resolvers  = make_set(RemoteIP)\n"
            "  by DeviceName, LocalIP\n"
            "| where QueryCount > 100\n"
            "| order by QueryCount desc"
        ))

    if "smb_ransomware" in patterns:
        sections.append((
            "SMB Anomaly — File Write Volume (T1486 Ransomware Indicator)",
            "// High-volume file writes with unusual extensions may indicate ransomware staging\n"
            "DeviceFileEvents\n"
            "| where ActionType in (\"FileCreated\", \"FileModified\", \"FileRenamed\")\n"
            "      and InitiatingProcessFileName != \"System\"\n"
            "| summarize\n"
            "    WriteCount     = count(),\n"
            "    FilesAffected  = dcount(FileName),\n"
            "    Extensions     = make_set(tostring(split(FileName, \".\")[-1]))\n"
            "  by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine\n"
            "| where WriteCount > 50\n"
            "| order by WriteCount desc"
        ))
        sections.append((
            "SMB Anomaly — Lateral SMB Traffic",
            "// Identify hosts making unusually high-volume SMB connections\n"
            "DeviceNetworkEvents\n"
            "| where RemotePort in (445, 139)\n"
            "| summarize\n"
            "    Connections    = count(),\n"
            "    Targets        = make_set(RemoteIP),\n"
            "    TotalBytesSent = sum(BytesSent)\n"
            "  by DeviceName, LocalIP\n"
            "| where Connections > 20\n"
            "| order by TotalBytesSent desc"
        ))

    if "lateral_movement" in patterns:
        if tables is None or "IdentityLogonEvents" in tables:
            sections.append((
                "Lateral Movement — Authentication Failure Spike (T1110)",
                "// Brute-force / credential spray: many failures from one source\n"
                "IdentityLogonEvents\n"
                "| where ActionType == \"LogonFailed\"\n"
                "| summarize\n"
                "    FailCount      = count(),\n"
                "    TargetAccounts = dcount(AccountName),\n"
                "    SourceDevices  = dcount(DeviceName)\n"
                "  by SourceIPAddress, FailureReason\n"
                "| where FailCount > 10\n"
                "| order by FailCount desc"
            ))
        if tables is None or "SecurityEvent" in tables:
            sections.append((
                "Lateral Movement — Windows Logon Events 4624/4625 (T1021)",
                "// Track network and remote-interactive logon successes and failures\n"
                "SecurityEvent\n"
                "| where EventID in (4624, 4625, 4648)\n"
                "      and LogonType in (3, 10)\n"
                "| summarize\n"
                "    Count        = count(),\n"
                "    Accounts     = make_set(Account),\n"
                "    Workstations = make_set(WorkstationName)\n"
                "  by IpAddress, EventID, Computer\n"
                "| order by Count desc"
            ))

    if "exfiltration" in patterns and ips:
        ip_quoted = ", ".join(f'"{ip}"' for ip in ips[:10])
        sections.append((
            "Exfiltration — Large Data Transfer to Suspect Destinations (T1041)",
            f"// Identify hosts transferring unusual data volumes to suspect external IPs\n"
            f"DeviceNetworkEvents\n"
            f"| where RemoteIP in ({ip_quoted})\n"
            f"| summarize\n"
            f"    TotalBytesSent = sum(BytesSent),\n"
            f"    Connections    = count(),\n"
            f"    FirstSeen      = min(TimeGenerated),\n"
            f"    LastSeen       = max(TimeGenerated)\n"
            f"  by DeviceName, LocalIP, RemoteIP, RemotePort\n"
            f"| extend MBSent = round(TotalBytesSent / 1048576.0, 2)\n"
            f"| order by TotalBytesSent desc"
        ))

    if "scanning" in patterns:
        sections.append((
            "Network Scanning — Port / IP Sweep Detection (T1046)",
            "// Hosts connecting to many distinct ports or IPs within the observation window\n"
            "DeviceNetworkEvents\n"
            "| where ActionType in (\"ConnectionAttempt\", \"ConnectionFailed\", \"ConnectionSuccess\")\n"
            "| summarize\n"
            "    DistinctPorts = dcount(RemotePort),\n"
            "    DistinctIPs   = dcount(RemoteIP),\n"
            "    Connections   = count()\n"
            "  by DeviceName, LocalIP\n"
            "| where DistinctPorts > 20 or DistinctIPs > 50\n"
            "| order by DistinctPorts desc"
        ))

    if not sections:
        return ""

    parts_out = []
    for title, query in sections:
        tbl = _extract_table_from_query(query)
        md = _kql_code(query, collector=collector, category="threat",
                        table=tbl, description=title)
        parts_out.append(f"#### {title}\n\n{md}")
    return "\n\n".join(parts_out)


# ---------------------------------------------------------------------------
# Splunk SPL
# ---------------------------------------------------------------------------

def _build_splunk(iocs: dict, collector: list | None = None) -> str:
    parts: list[tuple[str, str]] = []

    ips = iocs.get("ipv4", [])
    domains = iocs.get("domain", [])
    sha256s = iocs.get("sha256", [])
    md5s = iocs.get("md5", [])
    sha1s = iocs.get("sha1", [])
    emails = iocs.get("email", [])

    if ips:
        ip_in = " ".join(ips)
        parts.append((
            "IPv4 Lookups",
            f'index=* (src_ip IN ({ip_in}) OR dest_ip IN ({ip_in}))\n'
            f'| eval direction=if(src_ip IN ({ip_in}), "outbound", "inbound")\n'
            f'| table _time, src_ip, src_host, dest_ip, dest_port,\n'
            f'        bytes_out, bytes_in, direction, action\n'
            f'| sort _time',
        ))

    if domains:
        dom_search = " OR ".join(
            f'query="{d}" OR dest_domain="{d}" OR url="*{d}*"' for d in domains
        )
        parts.append((
            "Domain Lookups",
            f'index=* ({dom_search})\n'
            f'| table _time, src_ip, dest_domain, url, bytes_out, action\n'
            f'| sort _time',
        ))

    for hash_type, values in [("sha256", sha256s), ("md5", md5s), ("sha1", sha1s)]:
        if values:
            h_search = " OR ".join(
                f'hash="{v}" OR {hash_type}="{v}" OR file_hash="{v}"' for v in values
            )
            parts.append((
                f"{hash_type.upper()} Hash Lookups",
                f'index=* ({h_search})\n'
                f'| table _time, src_ip, file_name, file_path, hash, action\n'
                f'| sort _time',
            ))

    if emails:
        em_search = " OR ".join(
            f'src_user="{e}" OR recipient="{e}" OR sender="{e}"' for e in emails
        )
        parts.append((
            "Email Lookups",
            f'index=* ({em_search})\n'
            f'| table _time, src_user, recipient, subject, action\n'
            f'| sort _time',
        ))

    out = []
    for title, query in parts:
        if collector is not None:
            collector.append({
                "platform": "splunk",
                "category": title.lower().split()[0],
                "table": "",
                "description": title,
                "query": query.strip(),
            })
        out.append(f"#### {title}\n\n```spl\n{query.strip()}\n```")
    return "\n\n".join(out)


# ---------------------------------------------------------------------------
# LogScale / CrowdStrike Falcon
# ---------------------------------------------------------------------------

def _build_logscale(iocs: dict, collector: list | None = None) -> str:
    parts: list[tuple[str, str]] = []

    ips = iocs.get("ipv4", [])
    domains = iocs.get("domain", [])
    sha256s = iocs.get("sha256", [])
    md5s = iocs.get("md5", [])

    if ips:
        ip_filter = " OR ".join(f'RemoteAddressIP4 = "{ip}"' for ip in ips)
        parts.append((
            "IPv4 — Network Connections (CrowdStrike Falcon)",
            f'#event_simpleName = NetworkConnectIP4\n'
            f'| {ip_filter}\n'
            f'| table([@timestamp, ComputerName, LocalAddressIP4, RemoteAddressIP4,\n'
            f'         RemotePort, FileName, CommandLine])',
        ))
        parts.append((
            "IPv4 — DNS Resolution to Suspect IPs",
            f'#event_simpleName = DnsRequest\n'
            f'| {ip_filter}\n'
            f'| table([@timestamp, ComputerName, DomainName, RemoteAddressIP4, FileName])',
        ))

    if domains:
        dom_filter = " OR ".join(f'DomainName = "*{d}*"' for d in domains)
        parts.append((
            "Domain — DNS Requests (CrowdStrike Falcon)",
            f'#event_simpleName = DnsRequest\n'
            f'| {dom_filter}\n'
            f'| table([@timestamp, ComputerName, DomainName, RemoteAddressIP4, FileName])',
        ))

    if sha256s:
        h_filter = " OR ".join(f'SHA256HashData = "{h}"' for h in sha256s)
        parts.append((
            "SHA256 — File Write / Process Execution (CrowdStrike Falcon)",
            f'#event_simpleName IN (NewExecutableWritten, ProcessRollup2)\n'
            f'| {h_filter}\n'
            f'| table([@timestamp, ComputerName, FileName, FilePath,\n'
            f'         SHA256HashData, ParentBaseFileName, CommandLine])',
        ))

    if md5s:
        h_filter = " OR ".join(f'MD5HashData = "{h}"' for h in md5s)
        parts.append((
            "MD5 — File Write / Process Execution (CrowdStrike Falcon)",
            f'#event_simpleName IN (NewExecutableWritten, ProcessRollup2)\n'
            f'| {h_filter}\n'
            f'| table([@timestamp, ComputerName, FileName, FilePath,\n'
            f'         MD5HashData, ParentBaseFileName, CommandLine])',
        ))

    out = []
    for title, query in parts:
        if collector is not None:
            collector.append({
                "platform": "logscale",
                "category": title.lower().split()[0],
                "table": "",
                "description": title,
                "query": query.strip(),
            })
        out.append(f"#### {title}\n\n```logscale\n{query.strip()}\n```")
    return "\n\n".join(out)


# ---------------------------------------------------------------------------
# Main tool function
# ---------------------------------------------------------------------------

def generate_queries(
    case_id: str,
    platforms: list[str] | None = None,
    tables: list[str] | None = None,
) -> dict:
    """
    Generate SIEM hunt queries for a case's IOCs and detected threat patterns.

    Parameters
    ----------
    case_id : str
        Case identifier.
    platforms : list[str], optional
        SIEM platforms to generate for. Default: ["kql", "splunk", "logscale"].
    tables : list[str], optional
        Confirmed KQL tables where IOC data was found. When supplied, KQL queries
        are scoped to only these tables. Example:
        ["DeviceNetworkEvents", "IdentityLogonEvents", "SecurityEvent", "Syslog"]

    Returns
    -------
    dict
        Manifest with the path to the generated hunt_queries.md file.
    """
    if platforms is None:
        platforms = ["kql", "splunk", "logscale"]

    case_dir = CASES_DIR / case_id
    ioc_path = case_dir / "iocs" / "iocs.json"
    if not ioc_path.exists():
        return {
            "case_id": case_id,
            "status": "no_iocs",
            "message": f"No IOC file found at {ioc_path}. Run extract_iocs first.",
            "ts": utcnow(),
        }

    ioc_data = load_json(ioc_path)

    # Normalise: canonical format has iocs as a dict keyed by type;
    # some manually-created cases use a list of {"type":..., "value":...} objects.
    raw_iocs = ioc_data.get("iocs", {})
    if isinstance(raw_iocs, list):
        iocs: dict[str, list[str]] = {}
        for entry in raw_iocs:
            ioc_type = entry.get("type", "unknown")
            ioc_val  = entry.get("value", "")
            if ioc_val:
                iocs.setdefault(ioc_type, []).append(ioc_val)
    else:
        iocs = raw_iocs

    totals = ioc_data.get("total", {t: len(v) for t, v in iocs.items()})

    meta_path = case_dir / "case_meta.json"
    meta = load_json(meta_path) if meta_path.exists() else {"case_id": case_id}

    # Collect all text in the case dir for threat pattern detection
    scan_text = ""
    for md_file in list(case_dir.glob("*.md")) + list((case_dir / "reports").glob("*.md")):
        try:
            scan_text += md_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            log_error(case_id, "generate_queries.read_md", str(exc),
                      severity="warning", context={"file": str(md_file)})

    patterns = _detect_patterns(scan_text)
    ioc_summary = ", ".join(f"{v} {k}" for k, v in totals.items() if v > 0)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Build document
    lines: list[str] = [
        f"# Hunt Queries — {case_id}",
        f"\n_Generated: {now_str}_\n",
        f"**Case:** {meta.get('title', case_id)}  ",
        f"**Severity:** {meta.get('severity', 'unknown').upper()}  ",
        f"**IOC Summary:** {ioc_summary or 'none'}  ",
    ]
    if has_registry():
        lines.append(f"**Schema Source:** Sentinel registry (auto-discovered)  ")
    if tables:
        lines.append(f"**Confirmed KQL Tables:** `{'`, `'.join(tables)}`  ")
    if patterns:
        lines.append(f"**Detected Threat Patterns:** {', '.join(patterns)}  ")
    lines.append("\n---")

    # Collector for structured YAML output
    yaml_collector: list[dict] = []

    # KQL
    if "kql" in platforms:
        lines.append("\n## KQL — Microsoft Sentinel / Defender for Endpoint\n")

        for label, content in [
            ("IPv4 Lookups",   _build_kql_ipv4(iocs.get("ipv4", []), tables, yaml_collector)),
            ("Domain Lookups", _build_kql_domains(iocs.get("domain", []), tables, yaml_collector)),
            ("Hash Lookups",   _build_kql_hashes(
                {k: iocs.get(k, []) for k in ("sha256", "md5", "sha1")}, tables, yaml_collector
            )),
            ("URL Lookups",    _build_kql_urls(iocs.get("url", []), tables, yaml_collector)),
            ("Email Lookups",  _build_kql_emails(iocs.get("email", []), tables, yaml_collector)),
        ]:
            if content:
                lines.append(f"### {label}\n")
                lines.append(content)

        timeline = _build_kql_timeline(iocs, tables, yaml_collector)
        if timeline:
            lines.append("\n### Unified Timeline\n")
            lines.append(timeline)

        threat_qs = _build_threat_queries(patterns, iocs, tables, yaml_collector)
        if threat_qs:
            lines.append("\n### Threat-Specific Queries\n")
            lines.append(threat_qs)

        lines.append("\n---")

    # Splunk
    if "splunk" in platforms:
        lines.append("\n## Splunk SPL\n")
        splunk_content = _build_splunk(iocs, yaml_collector)
        lines.append(splunk_content if splunk_content else "_No IOCs available._")
        lines.append("\n---")

    # LogScale
    if "logscale" in platforms:
        lines.append("\n## LogScale / CrowdStrike Falcon\n")
        logscale_content = _build_logscale(iocs, yaml_collector)
        lines.append(logscale_content if logscale_content else "_No IOCs available._")
        lines.append("\n---")

    # Write markdown artefact
    out_path = case_dir / "artefacts" / "queries" / "hunt_queries.md"
    manifest = write_artefact(out_path, "\n".join(lines))

    # Write YAML artefact — use literal block scalars for query readability
    class _LiteralStr(str):
        pass

    class _QueryDumper(yaml.Dumper):
        pass

    _QueryDumper.add_representer(
        _LiteralStr,
        lambda dumper, data: dumper.represent_scalar(
            "tag:yaml.org,2002:str", data, style="|"
        ),
    )

    yaml_path = case_dir / "artefacts" / "queries" / "hunt_queries.yaml"
    for entry in yaml_collector:
        entry["query"] = _LiteralStr(entry["query"])
    yaml_data = {
        "metadata": {
            "case_id": case_id,
            "generated": now_str,
            "title": meta.get("title", case_id),
            "severity": meta.get("severity", "unknown").upper(),
            "ioc_summary": ioc_summary or "none",
            "threat_patterns": patterns,
            "platforms": platforms,
            "tables": tables,
        },
        "queries": yaml_collector,
    }
    yaml_manifest = write_artefact(
        yaml_path, yaml.dump(yaml_data, Dumper=_QueryDumper,
                              default_flow_style=False, sort_keys=False,
                              allow_unicode=True)
    )

    ioc_counts = {k: len(v) for k, v in iocs.items() if v}
    print(f"[generate_queries] Hunt queries written to {out_path}")
    print(f"[generate_queries] YAML queries written to {yaml_path}")
    print(f"[generate_queries] Platforms: {platforms} | Patterns detected: {patterns}")

    return {
        "case_id":     case_id,
        "query_path":  str(out_path),
        "yaml_path":   str(yaml_path),
        "platforms":   platforms,
        "ioc_counts":  ioc_counts,
        "patterns":    patterns,
        "tables":      tables,
        "ts":          utcnow(),
        **manifest,
    }


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="Generate hunt queries for a case.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument(
        "--platforms", nargs="*", default=["kql", "splunk", "logscale"],
        choices=["kql", "splunk", "logscale"],
    )
    p.add_argument(
        "--tables", nargs="*", default=None,
        help="Confirmed KQL tables (scopes KQL queries to these tables only)",
    )
    args = p.parse_args()

    result = generate_queries(args.case_id, platforms=args.platforms, tables=args.tables)
    print(json.dumps(result, indent=2))
