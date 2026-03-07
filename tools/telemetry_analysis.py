"""
tool: telemetry_analysis
------------------------
Parse EDR / SIEM telemetry exports (CrowdStrike CSV/JSON, generic CSV/JSON logs)
and return structured summary for investigation sessions.

Returns a dict with:
    event_types     — Counter of event types
    tactics         — Counter of MITRE tactics
    techniques      — Counter of MITRE techniques
    processes       — Counter of process names
    computers       — Counter of hostnames
    users           — Counter of usernames
    domains_queried — sorted unique DNS domains
    remote_ips      — Counter of remote IPs contacted
    command_lines   — unique command lines observed
    file_paths      — unique file paths accessed
    time_range      — {start, end} ISO timestamps
    event_count     — total events parsed
    source_file     — filename analysed
    platform        — detected platform (crowdstrike, generic)
    key_findings    — list of auto-detected notable items
"""
from __future__ import annotations

import collections
import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Known-benign patterns for flagging
# ---------------------------------------------------------------------------

_MS_DOMAIN_KEYWORDS = frozenset([
    "microsoft", "msedge", "office", "bing", "azure", "teams", "windows",
    "msn", "akamai", "adobe", "live.com", "outlook", "sharepoint",
])

_KNOWN_SYSTEM_PROCS = frozenset([
    "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "smss.exe", "System", "dwm.exe",
    "explorer.exe", "taskhostw.exe", "conhost.exe", "RuntimeBroker.exe",
    "MsSense.exe", "MsMpEng.exe", "SenseIR.exe", "SenseCncProxy.exe",
])


def analyse_telemetry(file_path: str, session_id: str | None = None) -> dict:
    """
    Parse a telemetry export file and return structured analysis.

    Supports:
      - CrowdStrike CSV exports (quoted JSON per row)
      - CrowdStrike JSON exports (array or NDJSON)
      - Generic CSV (auto-detect columns)
      - Generic NDJSON
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    content = path.read_text(encoding="utf-8", errors="replace")
    filename = path.name

    # Detect format and parse events
    events = _parse_events(content, filename)
    if not events:
        return {
            "error": "Could not parse any events from file",
            "source_file": filename,
            "event_count": 0,
        }

    # Detect platform
    platform = _detect_platform(events)

    # Extract fields
    result = _extract_summary(events, platform)
    result["source_file"] = filename
    result["platform"] = platform
    result["event_count"] = len(events)

    # Auto-detect key findings
    result["key_findings"] = _detect_findings(result, events)

    # Build human-readable message
    result["_message"] = _build_message(result)

    return result


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_events(content: str, filename: str) -> list[dict]:
    """Auto-detect format and parse into list of event dicts."""
    stripped = content.strip()

    # Try JSON array
    if stripped.startswith("["):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

    # Try NDJSON
    if stripped.startswith("{"):
        events = []
        for line in stripped.split("\n"):
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        if events:
            return events

    # CrowdStrike CSV: first line is header, each subsequent line is quoted JSON
    lines = content.strip().split("\n")
    if len(lines) >= 2:
        # Check if it looks like CrowdStrike format (header + quoted JSON rows)
        first_data = lines[1].strip()
        if first_data.startswith('"') and "{" in first_data:
            return _parse_crowdstrike_csv(lines)

    # Generic CSV
    if filename.lower().endswith(".csv"):
        return _parse_generic_csv(content)

    return []


def _parse_crowdstrike_csv(lines: list[str]) -> list[dict]:
    """Parse CrowdStrike CSV where each row is a quoted JSON object."""
    events = []
    for line in lines[1:]:  # skip header
        line = line.strip()
        if not line:
            continue
        # Un-quote and un-escape
        if line.startswith('"') and line.endswith('"'):
            line = line[1:-1].replace('""', '"')
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _parse_generic_csv(content: str) -> list[dict]:
    """Parse generic CSV into list of dicts."""
    try:
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def _detect_platform(events: list[dict]) -> str:
    """Detect the telemetry source platform."""
    if not events:
        return "generic"

    sample = events[0]

    # CrowdStrike
    if any(k in sample for k in ("event_simpleName", "aid", "cid", "aip")):
        return "crowdstrike"

    # Microsoft Defender / Sentinel
    if any(k in sample for k in ("DeviceId", "MachineId", "ActionType", "DeviceName")):
        return "defender"

    # Windows Event Log
    if any(k in sample for k in ("EventID", "EventId", "SourceName", "LogName")):
        return "windows_eventlog"

    # Syslog / generic
    return "generic"


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------

def _extract_summary(events: list[dict], platform: str) -> dict:
    """Extract aggregated fields from parsed events."""
    event_types = collections.Counter()
    tactics = collections.Counter()
    techniques = collections.Counter()
    processes = collections.Counter()
    computers = collections.Counter()
    users = collections.Counter()
    domains = []
    remote_ips = collections.Counter()
    cmdlines = set()
    file_paths = set()
    timestamps = []

    # Field mappings per platform
    fm = _field_map(platform)

    for ev in events:
        # Event type
        etype = _get(ev, fm["event_type"])
        if etype:
            event_types[etype] += 1

        # Tactics / techniques
        tactic = _get(ev, fm["tactic"])
        if tactic:
            tactics[tactic] += 1
        technique = _get(ev, fm["technique"])
        if technique:
            techniques[technique] += 1

        # Processes
        for pfield in fm["process"]:
            pval = ev.get(pfield, "")
            if pval:
                # Extract filename from path
                name = pval.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                if name:
                    processes[name] += 1

        # Computer
        comp = _get(ev, fm["computer"])
        if comp:
            computers[comp] += 1

        # User
        user = _get(ev, fm["user"])
        if user:
            users[user] += 1

        # DNS domains
        domain = _get(ev, fm["domain"])
        if domain:
            domains.append(domain)

        # Remote IPs
        rip = _get(ev, fm["remote_ip"])
        if rip:
            remote_ips[rip] += 1

        # Command lines
        cmd = _get(ev, fm["cmdline"])
        if cmd:
            cmdlines.add(cmd)

        # File paths
        for fp_field in fm["file_path"]:
            fpv = ev.get(fp_field, "")
            if fpv and len(fpv) > 5:
                file_paths.add(fpv)

        # Timestamps
        ts = _get(ev, fm["timestamp"])
        if ts:
            try:
                timestamps.append(int(ts))
            except (ValueError, TypeError):
                pass

    # Build time range
    time_range = {}
    if timestamps:
        # Auto-detect epoch precision: seconds, millis, micros, nanos
        max_ts = max(timestamps)
        if max_ts > 1e18:
            divisor = 1_000_000_000  # nanoseconds
        elif max_ts > 1e15:
            divisor = 1_000_000  # microseconds
        elif max_ts > 1e12:
            divisor = 1_000  # milliseconds
        else:
            divisor = 1  # seconds
        try:
            mn = datetime.fromtimestamp(min(timestamps) / divisor, tz=timezone.utc)
            mx = datetime.fromtimestamp(max(timestamps) / divisor, tz=timezone.utc)
            time_range = {"start": mn.isoformat(), "end": mx.isoformat()}
        except (ValueError, OSError):
            time_range = {"start": str(min(timestamps)), "end": str(max(timestamps))}

    return {
        "event_types": dict(event_types.most_common(30)),
        "tactics": dict(tactics.most_common(20)),
        "techniques": dict(techniques.most_common(20)),
        "processes": dict(processes.most_common(30)),
        "computers": dict(computers.most_common(10)),
        "users": dict(users.most_common(20)),
        "domains_queried": sorted(set(domains)),
        "remote_ips": dict(remote_ips.most_common(30)),
        "command_lines": sorted(cmdlines),
        "file_paths": sorted(file_paths)[:50],
        "time_range": time_range,
    }


def _field_map(platform: str) -> dict:
    """Return field name mappings for a given platform."""
    if platform == "crowdstrike":
        return {
            "event_type": ["event_simpleName"],
            "tactic": ["Tactic"],
            "technique": ["Technique"],
            "process": ["ContextBaseFileName", "ImageFileName", "ParentBaseFileName"],
            "computer": ["ComputerName"],
            "user": ["UserName"],
            "domain": ["DomainName"],
            "remote_ip": ["RemoteAddressIP4", "RemoteAddressIP6"],
            "cmdline": ["CommandLine"],
            "file_path": ["TargetFileName", "ImageFileName"],
            "timestamp": ["timestamp"],
        }
    elif platform == "defender":
        return {
            "event_type": ["ActionType"],
            "tactic": ["AttackTechniques"],
            "technique": ["AttackTechniques"],
            "process": ["FileName", "InitiatingProcessFileName", "ProcessCommandLine"],
            "computer": ["DeviceName"],
            "user": ["AccountName", "InitiatingProcessAccountName"],
            "domain": ["RemoteUrl"],
            "remote_ip": ["RemoteIP", "LocalIP"],
            "cmdline": ["ProcessCommandLine", "InitiatingProcessCommandLine"],
            "file_path": ["FolderPath", "InitiatingProcessFolderPath"],
            "timestamp": ["Timestamp"],
        }
    elif platform == "windows_eventlog":
        return {
            "event_type": ["EventID", "EventId"],
            "tactic": [],
            "technique": [],
            "process": ["ProcessName", "NewProcessName"],
            "computer": ["ComputerName", "Computer"],
            "user": ["TargetUserName", "SubjectUserName"],
            "domain": [],
            "remote_ip": ["IpAddress", "SourceAddress"],
            "cmdline": ["CommandLine", "ProcessCommandLine"],
            "file_path": ["ObjectName", "NewProcessName"],
            "timestamp": ["TimeCreated", "TimeGenerated"],
        }
    else:
        return {
            "event_type": ["event_type", "EventType", "type", "action"],
            "tactic": ["tactic", "Tactic"],
            "technique": ["technique", "Technique"],
            "process": ["process", "process_name", "ProcessName", "Image"],
            "computer": ["computer", "hostname", "ComputerName", "host"],
            "user": ["user", "UserName", "username", "Account"],
            "domain": ["domain", "DomainName", "dns_query"],
            "remote_ip": ["remote_ip", "dest_ip", "DestinationIP", "RemoteIP"],
            "cmdline": ["command_line", "CommandLine", "cmdline"],
            "file_path": ["file_path", "TargetFilename", "FilePath"],
            "timestamp": ["timestamp", "Timestamp", "@timestamp", "EventTime"],
        }


def _get(event: dict, fields: list[str]) -> str | None:
    """Get first non-empty value from a list of candidate field names."""
    for f in fields:
        val = event.get(f, "")
        if val:
            return str(val)
    return None


# ---------------------------------------------------------------------------
# Auto-finding detection
# ---------------------------------------------------------------------------

def _detect_findings(summary: dict, events: list[dict]) -> list[dict]:
    """Auto-detect notable items from the parsed telemetry."""
    findings = []

    # Non-standard domains
    domains = summary.get("domains_queried", [])
    suspicious_domains = []
    for d in domains:
        if not any(kw in d.lower() for kw in _MS_DOMAIN_KEYWORDS):
            suspicious_domains.append(d)
    if suspicious_domains:
        findings.append({
            "type": "non_standard_domains",
            "summary": f"{len(suspicious_domains)} non-Microsoft/CDN domain(s) queried",
            "detail": ", ".join(suspicious_domains[:10]),
        })

    # Unusual processes (not in known system procs)
    procs = summary.get("processes", {})
    unusual_procs = [p for p in procs if p not in _KNOWN_SYSTEM_PROCS]
    if unusual_procs:
        findings.append({
            "type": "unusual_processes",
            "summary": f"{len(unusual_procs)} non-standard process(es)",
            "detail": ", ".join(unusual_procs[:10]),
        })

    # Lateral movement indicators
    tactics = summary.get("tactics", {})
    for tactic_name, count in tactics.items():
        if "lateral movement" in tactic_name.lower():
            findings.append({
                "type": "lateral_movement",
                "summary": f"Lateral Movement tactic detected ({count} event(s))",
                "detail": tactic_name,
            })
            break

    # Internal IP connections (potential lateral movement)
    remote_ips = summary.get("remote_ips", {})
    internal_ips = [ip for ip in remote_ips
                    if ip.startswith("10.") or ip.startswith("192.168.") or
                    re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip)]
    if internal_ips:
        findings.append({
            "type": "internal_connections",
            "summary": f"Internal network connections to {len(internal_ips)} IP(s)",
            "detail": ", ".join(internal_ips[:5]),
        })

    # Multiple users
    users = summary.get("users", {})
    if len(users) > 3:
        findings.append({
            "type": "multiple_users",
            "summary": f"Activity from {len(users)} distinct user account(s)",
            "detail": ", ".join(list(users.keys())[:5]),
        })

    # Suspicious command lines (encoded, download cradles, etc.)
    cmdlines = summary.get("command_lines", [])
    sus_cmds = []
    for cmd in cmdlines:
        cmd_lower = cmd.lower()
        if any(kw in cmd_lower for kw in (
            "powershell", "-encodedcommand", "-enc ", "invoke-", "iex(",
            "downloadstring", "certutil", "bitsadmin", "mshta",
            "regsvr32", "rundll32", "wscript", "cscript",
        )):
            sus_cmds.append(cmd[:200])
    if sus_cmds:
        findings.append({
            "type": "suspicious_commands",
            "summary": f"{len(sus_cmds)} potentially suspicious command line(s)",
            "detail": "\n".join(sus_cmds[:5]),
        })

    # Single process dominance (like MsSense.exe being sole actor)
    total_proc_events = sum(procs.values())
    if procs and total_proc_events > 10:
        top_proc, top_count = next(iter(procs.items()))
        ratio = top_count / total_proc_events
        if ratio > 0.8:
            findings.append({
                "type": "single_process_dominance",
                "summary": f"{top_proc} accounts for {ratio:.0%} of all process events",
                "detail": f"{top_count}/{total_proc_events} events",
            })

    return findings


# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

def _build_message(result: dict) -> str:
    """Build a concise human-readable summary."""
    lines = []
    lines.append(f"**Telemetry Analysis** — {result['source_file']} "
                 f"({result['event_count']} events, platform: {result['platform']})")

    tr = result.get("time_range", {})
    if tr:
        lines.append(f"Time range: {tr.get('start', '?')} → {tr.get('end', '?')}")

    # Computers & users
    computers = result.get("computers", {})
    users = result.get("users", {})
    if computers:
        lines.append(f"Host(s): {', '.join(list(computers.keys())[:5])}")
    if users:
        lines.append(f"User(s): {', '.join(list(users.keys())[:5])}")

    # Event types
    etypes = result.get("event_types", {})
    if etypes:
        top5 = list(etypes.items())[:5]
        lines.append(f"\nTop event types: " + ", ".join(f"{k} ({v})" for k, v in top5))

    # Tactics
    tactics = result.get("tactics", {})
    if tactics:
        lines.append(f"MITRE tactics: " + ", ".join(f"{k} ({v})" for k, v in list(tactics.items())[:5]))

    # Top processes
    procs = result.get("processes", {})
    if procs:
        lines.append(f"Top processes: " + ", ".join(f"{k} ({v})" for k, v in list(procs.items())[:5]))

    # Remote IPs
    rips = result.get("remote_ips", {})
    if rips:
        lines.append(f"Remote IPs ({len(rips)}): " + ", ".join(list(rips.keys())[:8]))

    # Domains
    domains = result.get("domains_queried", [])
    if domains:
        lines.append(f"Unique domains ({len(domains)}): " + ", ".join(domains[:8])
                     + (f" (+{len(domains)-8} more)" if len(domains) > 8 else ""))

    # Key findings
    findings = result.get("key_findings", [])
    if findings:
        lines.append(f"\n**Key findings ({len(findings)}):**")
        for f in findings:
            lines.append(f"- {f['summary']}")
            if f.get("detail"):
                detail = f["detail"]
                if len(detail) > 200:
                    detail = detail[:200] + "..."
                lines.append(f"  {detail}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys as _sys
    if len(_sys.argv) < 2:
        print("Usage: python3 tools/telemetry_analysis.py <file_path>")
        _sys.exit(1)
    result = analyse_telemetry(_sys.argv[1])
    if result.get("_message"):
        print(result["_message"])
    else:
        print(json.dumps(result, indent=2, default=str))
