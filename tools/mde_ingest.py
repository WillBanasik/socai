"""
tool: mde_ingest
----------------
Ingest Microsoft Defender for Endpoint (MDE) investigation package ZIPs.

The MDE "Collect investigation package" action produces a ZIP with a known
folder structure containing triage artefacts from a Windows endpoint.
This tool normalises them into the same schema that downstream tools
(evtx_correlate, detect_anomalies, extract_iocs, timeline_reconstruct)
already consume — making MDE packages interchangeable with Velociraptor
collections from the analysis pipeline's perspective.

Supported MDE package folders:
  Autoruns/              → Registry ASEP persistence entries
  Installed programs/    → CSV of installed software
  Network connections/   → ActiveNetConnections, Arp, DnsCache, IpConfig, firewall
  Prefetch files/        → .pf binaries + file listing
  Processes/             → CSV of running processes
  Scheduled tasks/       → CSV of scheduled tasks
  Security event log/    → Security .evtx file
  Services/              → CSV of services and states
  SMB sessions/          → Inbound + outbound SMB session text files
  System Information/    → SystemInformation.txt
  Temp Directories/      → Per-user temp file listings
  Users and Groups/      → Group membership text files
  WdSupportLogs/         → Defender antimalware logs
  CollectionSummaryReport.xls  → Package metadata

Writes:
  cases/<case_id>/artefacts/mde/ingest_manifest.json
  cases/<case_id>/artefacts/mde/system_info.json            (if present)
  cases/<case_id>/artefacts/mde/collection_summary.xls      (if present)
  cases/<case_id>/artefacts/mde/security_evtx/              (raw .evtx)
  cases/<case_id>/logs/mde_<artefact>.parsed.json
  cases/<case_id>/logs/mde_<artefact>.entities.json

Usage (standalone):
  python3 tools/mde_ingest.py /path/to/investigation_package.zip --case C001
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import log_error, save_json, utcnow, write_artefact

# ---------------------------------------------------------------------------
# Regex patterns — reused from velociraptor_ingest
# ---------------------------------------------------------------------------

_RE_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_PATH_WIN = re.compile(r"[A-Za-z]:\\[\w\\\-. ]{4,}")
_RE_PATH_UNIX = re.compile(r"/(?:[\w.\-]+/){1,}[\w.\-]+")
_RE_HTTP = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
_RE_HTTP_STATUS = re.compile(r"\b[1-5]\d{2}\b")
_RE_EVENTID = re.compile(r"\bEvent(?:ID)?[: ]+(\d{3,5})\b", re.IGNORECASE)

_IP_FIELDS = {"src_ip", "dst_ip", "source_ip", "dest_ip", "clientip", "remote_addr",
              "src", "dst", "ip", "remoteip", "sourceaddress", "destinationaddress",
              "ipaddress", "sourceip", "laddr", "raddr", "localaddress",
              "foreignaddress", "remoteaddress"}
_USER_FIELDS = {"user", "username", "account", "accountname", "userid",
                "subject_account_name", "subjectusername", "targetusername", "fqdn",
                "owner", "logonuser"}
_CMD_FIELDS = {"commandline", "command_line", "cmdline", "process_command_line",
               "parentcommandline", "exe", "imagepath", "pathname"}
_PROC_FIELDS = {"process", "processname", "image", "parentimage",
                "process_name", "imagename", "name", "exe"}


# ---------------------------------------------------------------------------
# MDE-specific parsers
# ---------------------------------------------------------------------------

def _parse_csv_text(text: str) -> list[dict]:
    """Parse CSV text into list of dicts, handling various MDE CSV quirks."""
    if not text.strip():
        return []
    try:
        # MDE CSVs sometimes have BOM
        text = text.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(text))
        return [row for row in reader]
    except Exception:
        return []


def _parse_netstat_txt(text: str) -> list[dict]:
    """Parse ActiveNetConnections.txt (netstat -ano style output).

    Expected format:
      Proto  Local Address          Foreign Address        State           PID
      TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       924
    """
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Proto") or line.startswith("="):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0]
        local = parts[1]
        foreign = parts[2]
        state = parts[3] if len(parts) >= 5 else ""
        pid = parts[-1] if parts[-1].isdigit() else ""

        local_ip, local_port = _split_address(local)
        foreign_ip, foreign_port = _split_address(foreign)

        rows.append({
            "Protocol": proto,
            "LocalAddress": local_ip,
            "LocalPort": local_port,
            "ForeignAddress": foreign_ip,
            "ForeignPort": foreign_port,
            "State": state,
            "PID": pid,
        })
    return rows


def _split_address(addr: str) -> tuple[str, str]:
    """Split 'IP:port' or '[IPv6]:port' into (ip, port)."""
    if addr.startswith("["):
        # IPv6: [::1]:445
        bracket_end = addr.rfind("]")
        if bracket_end >= 0 and bracket_end + 1 < len(addr) and addr[bracket_end + 1] == ":":
            return addr[1:bracket_end], addr[bracket_end + 2:]
        return addr, ""
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        return parts[0], parts[1]
    return addr, ""


def _parse_arp_txt(text: str) -> list[dict]:
    """Parse Arp.txt (arp -a output).

    Expected format:
      Interface: 192.168.1.5 --- 0xb
        Internet Address      Physical Address      Type
        192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
    """
    rows = []
    current_interface = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Interface:"):
            m = _RE_IP.search(line)
            current_interface = m.group(0) if m else ""
            continue
        if not line or line.startswith("Internet") or line.startswith("="):
            continue
        parts = line.split()
        if len(parts) >= 3 and _RE_IP.match(parts[0]):
            rows.append({
                "Interface": current_interface,
                "IPAddress": parts[0],
                "MACAddress": parts[1],
                "Type": parts[2],
            })
    return rows


def _parse_dns_cache_txt(text: str) -> list[dict]:
    """Parse DnsCache.txt (ipconfig /displaydns style output).

    Looks for record entries with Name, Type, Data fields.
    """
    rows = []
    current: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            if current.get("RecordName"):
                rows.append(current)
            current = {}
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().replace(" ", "")
            val = val.strip()
            if "RecordName" in key or "EntryName" in key:
                current["RecordName"] = val
            elif "RecordType" in key or "Type" in key:
                current["RecordType"] = val
            elif "Data" in key or "Section" in key:
                if "Record" in key and "Data" not in current:
                    current["Data"] = val
                elif val and "Data" not in current:
                    current["Data"] = val
            elif "TimeToLive" in key or "TTL" in key:
                current["TTL"] = val
    if current.get("RecordName"):
        rows.append(current)
    return rows


def _parse_system_info_txt(text: str) -> dict:
    """Parse SystemInformation.txt into a flat dict.

    Format: 'Key:  Value' pairs, one per line.
    """
    info: dict = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key and val:
                info[key] = val
    return info


def _parse_autoruns_registry(text: str, filename: str) -> list[dict]:
    """Parse MDE Autoruns registry files.

    Each file in the Autoruns/ folder represents one ASEP registry key.
    Format varies — may be reg export or plain text key/value lines.
    """
    rows = []
    current: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            if current:
                current["_asep_file"] = filename
                rows.append(current)
                current = {}
            continue
        if line.startswith("ERROR:"):
            return []
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if key:
                current[key] = val
        elif line.startswith('"') or line.startswith("REG_"):
            # reg query output: "ValueName"    REG_SZ    Data
            parts = re.split(r"\s{2,}", line.strip('"'))
            if len(parts) >= 3:
                current["ValueName"] = parts[0].strip('"')
                current["Type"] = parts[1]
                current["Data"] = parts[2]
            elif len(parts) >= 1:
                current["RawEntry"] = line
        else:
            # Registry key path line
            if line.startswith("HKEY_") or line.startswith("HK"):
                if current:
                    current["_asep_file"] = filename
                    rows.append(current)
                current = {"RegistryKey": line}
            else:
                current["RawEntry"] = current.get("RawEntry", "") + " " + line

    if current:
        current["_asep_file"] = filename
        rows.append(current)
    return rows


def _parse_smb_sessions_txt(text: str) -> list[dict]:
    """Parse SMB session files (net session output or similar)."""
    rows = []
    if "no SMB sessions found" in text.lower() or "no entries" in text.lower():
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Computer") or line.startswith("-") or line.startswith("="):
            continue
        parts = line.split()
        if parts:
            row: dict = {"RawEntry": line}
            # Try to extract IPs and usernames
            for part in parts:
                if _RE_IP.match(part.strip("\\")):
                    row["RemoteIP"] = part.strip("\\")
                elif "\\" in part and not part.startswith("\\\\"):
                    row["User"] = part
            rows.append(row)
    return rows


def _parse_temp_dir_listing(text: str, filename: str) -> list[dict]:
    """Parse temp directory listing files."""
    rows = []
    if "cannot find the path" in text.lower():
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Volume") or line.startswith("Directory") or line.startswith("Total"):
            continue
        # dir output: date time <DIR>/size filename
        parts = line.split()
        if len(parts) >= 4:
            name = " ".join(parts[3:])
            if name in (".", ".."):
                continue
            is_dir = "<DIR>" in line
            rows.append({
                "FileName": name,
                "IsDirectory": is_dir,
                "DateModified": f"{parts[0]} {parts[1]}" if len(parts) >= 2 else "",
                "Size": parts[2] if not is_dir and len(parts) >= 3 else "",
                "SourceUser": filename,
            })
    return rows


def _parse_users_groups_txt(text: str, filename: str) -> list[dict]:
    """Parse Users and Groups files (one file per group)."""
    rows = []
    group_name = Path(filename).stem
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("="):
            continue
        if line.startswith("Members") or line.startswith("Group") or line.startswith("Comment"):
            continue
        rows.append({
            "GroupName": group_name,
            "Member": line,
        })
    return rows


def _parse_prefetch_listing(text: str) -> list[dict]:
    """Parse PrefetchFilesList.txt — simple listing of .pf filenames."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Extract executable name from prefetch filename: NOTEPAD.EXE-12345678.pf
        m = re.match(r"^(.+?)(-[A-F0-9]{8})?\.pf$", line, re.IGNORECASE)
        if m:
            rows.append({
                "PrefetchFile": line,
                "ProcessName": m.group(1),
                "PrefetchHash": (m.group(2) or "").lstrip("-"),
            })
        else:
            rows.append({"PrefetchFile": line, "ProcessName": line})
    return rows


# ---------------------------------------------------------------------------
# Normalisers — map parsed MDE data into standard schema
# ---------------------------------------------------------------------------

def _norm_processes(row: dict) -> dict:
    return {
        "TimeCreated": row.get("CreationDate", row.get("Creation Date", "")),
        "ProcessName": row.get("Name", row.get("name", row.get("Image Name", ""))),
        "CommandLine": row.get("CommandLine", row.get("Command Line", "")),
        "ParentProcessName": row.get("ParentProcessName", ""),
        "Pid": row.get("PID", row.get("ProcessId", row.get("Process Id", ""))),
        "Ppid": row.get("ParentProcessId", row.get("PPID", "")),
        "TargetUserName": row.get("UserName", row.get("User Name", row.get("Owner", ""))),
        "SessionId": row.get("SessionId", row.get("Session#", "")),
        "Memory": row.get("WorkingSetSize", row.get("Mem Usage", "")),
        "_source": "mde",
        "_artefact": "processes",
    }


def _norm_services(row: dict) -> dict:
    return {
        "TimeCreated": "",
        "ServiceName": row.get("Name", row.get("DisplayName", row.get("Display Name", ""))),
        "CommandLine": row.get("PathName", row.get("Path Name", row.get("Binary Path", ""))),
        "ProcessName": row.get("PathName", row.get("Path Name", "")),
        "StartMode": row.get("StartMode", row.get("Start Mode", row.get("Start Type", ""))),
        "State": row.get("State", row.get("Status", "")),
        "TargetUserName": row.get("StartName", row.get("Log On As", "")),
        "_source": "mde",
        "_artefact": "services",
    }


def _norm_tasks(row: dict) -> dict:
    return {
        "TimeCreated": row.get("Last Run Time", row.get("LastRunTime", "")),
        "TaskName": row.get("TaskName", row.get("Task Name", row.get("Name", ""))),
        "CommandLine": row.get("Task To Run", row.get("TaskToRun", row.get("Command", ""))),
        "TargetUserName": row.get("Run As User", row.get("Author", "")),
        "Status": row.get("Status", ""),
        "NextRunTime": row.get("Next Run Time", row.get("NextRunTime", "")),
        "Schedule": row.get("Schedule Type", row.get("ScheduleType", "")),
        "_source": "mde",
        "_artefact": "scheduled_tasks",
    }


def _norm_installed_programs(row: dict) -> dict:
    return {
        "Name": row.get("Name", row.get("DisplayName", "")),
        "Version": row.get("Version", row.get("DisplayVersion", "")),
        "Vendor": row.get("Vendor", row.get("Publisher", "")),
        "InstallDate": row.get("InstallDate", row.get("Install Date", "")),
        "InstallLocation": row.get("InstallLocation", row.get("Install Location", "")),
        "_source": "mde",
        "_artefact": "installed_programs",
    }


def _norm_netstat(row: dict) -> dict:
    return {
        "TimeCreated": "",
        "SourceIP": row.get("LocalAddress", ""),
        "DestIP": row.get("ForeignAddress", ""),
        "SourcePort": row.get("LocalPort", ""),
        "DestPort": row.get("ForeignPort", ""),
        "Protocol": row.get("Protocol", ""),
        "ProcessName": "",
        "Pid": row.get("PID", ""),
        "Status": row.get("State", ""),
        "_source": "mde",
        "_artefact": "network_connections",
    }


def _norm_arp(row: dict) -> dict:
    return {
        "Interface": row.get("Interface", ""),
        "IPAddress": row.get("IPAddress", ""),
        "MACAddress": row.get("MACAddress", ""),
        "Type": row.get("Type", ""),
        "_source": "mde",
        "_artefact": "arp_cache",
    }


def _norm_dns_cache(row: dict) -> dict:
    return {
        "RecordName": row.get("RecordName", ""),
        "RecordType": row.get("RecordType", ""),
        "Data": row.get("Data", ""),
        "TTL": row.get("TTL", ""),
        "_source": "mde",
        "_artefact": "dns_cache",
    }


def _norm_autoruns(row: dict) -> dict:
    return {
        "TimeCreated": "",
        "RegistryKey": row.get("RegistryKey", ""),
        "ValueName": row.get("ValueName", ""),
        "ProcessName": row.get("Data", row.get("RawEntry", "")),
        "CommandLine": row.get("Data", ""),
        "Category": row.get("_asep_file", ""),
        "Type": row.get("Type", ""),
        "_source": "mde",
        "_artefact": "autoruns",
    }


def _norm_prefetch(row: dict) -> dict:
    return {
        "TimeCreated": "",
        "ProcessName": row.get("ProcessName", row.get("PrefetchFile", "")),
        "PrefetchHash": row.get("PrefetchHash", ""),
        "PrefetchFile": row.get("PrefetchFile", ""),
        "_source": "mde",
        "_artefact": "prefetch",
    }


def _norm_smb_sessions(row: dict) -> dict:
    return {
        "RemoteIP": row.get("RemoteIP", ""),
        "User": row.get("User", ""),
        "RawEntry": row.get("RawEntry", ""),
        "_source": "mde",
        "_artefact": "smb_sessions",
    }


def _norm_system_info(row: dict) -> dict:
    """System info is a single-record dict, not row-based."""
    normalised = dict(row)
    normalised["_source"] = "mde"
    normalised["_artefact"] = "system_info"
    return normalised


def _norm_users_groups(row: dict) -> dict:
    return {
        "GroupName": row.get("GroupName", ""),
        "TargetUserName": row.get("Member", ""),
        "_source": "mde",
        "_artefact": "users_groups",
    }


def _norm_temp_dirs(row: dict) -> dict:
    return {
        "FileName": row.get("FileName", ""),
        "IsDirectory": row.get("IsDirectory", False),
        "DateModified": row.get("DateModified", ""),
        "Size": row.get("Size", ""),
        "TargetUserName": row.get("SourceUser", ""),
        "_source": "mde",
        "_artefact": "temp_directories",
    }


def _norm_generic(row: dict) -> dict:
    normalised = dict(row)
    normalised["_source"] = "mde"
    normalised["_artefact"] = "generic"
    return normalised


# ---------------------------------------------------------------------------
# Entity extraction (same logic as velociraptor_ingest)
# ---------------------------------------------------------------------------

def _extract_entities(rows: list[dict]) -> dict:
    """Extract security-relevant entities from normalised rows."""
    entities: dict[str, set] = {
        "ips": set(), "users": set(), "processes": set(),
        "commands": set(), "file_paths": set(),
        "http_methods": set(), "http_statuses": set(),
        "event_ids": set(), "timestamps": set(),
        "domains": set(), "mac_addresses": set(),
    }

    for row in rows:
        row_lower = {k.lower(): v for k, v in row.items() if not k.startswith("_")}
        row_str = json.dumps(row, default=str)

        # Timestamps
        for ts in _RE_ISO.findall(row_str):
            entities["timestamps"].add(ts)

        # IPs from known fields
        for field in _IP_FIELDS:
            val = row_lower.get(field)
            if val and _RE_IP.match(str(val)):
                entities["ips"].add(str(val))

        # IPs from full row text
        for ip in _RE_IP.findall(row_str):
            entities["ips"].add(ip)

        # Users
        for field in _USER_FIELDS:
            val = row_lower.get(field)
            if val and str(val).strip() and str(val) != "-":
                entities["users"].add(str(val).strip())

        # Processes
        for field in _PROC_FIELDS:
            val = row_lower.get(field)
            if val and str(val).strip():
                entities["processes"].add(str(val).strip())

        # Commands
        for field in _CMD_FIELDS:
            val = row_lower.get(field)
            if val and str(val).strip():
                entities["commands"].add(str(val).strip())

        # File paths
        for p in _RE_PATH_WIN.findall(row_str):
            entities["file_paths"].add(p)
        for p in _RE_PATH_UNIX.findall(row_str):
            entities["file_paths"].add(p)

        # HTTP
        for m in _RE_HTTP.findall(row_str):
            entities["http_methods"].add(m)
        for s in _RE_HTTP_STATUS.findall(row_str):
            entities["http_statuses"].add(s)

        # Event IDs
        for e in _RE_EVENTID.findall(row_str):
            entities["event_ids"].add(e)
        eid = row_lower.get("eventid")
        if eid:
            try:
                entities["event_ids"].add(str(int(eid)))
            except (ValueError, TypeError):
                pass

        # DNS cache record names (domains)
        rname = row_lower.get("recordname")
        if rname and "." in str(rname):
            entities["domains"].add(str(rname).strip().rstrip("."))

        # MAC addresses
        mac = row_lower.get("macaddress")
        if mac and str(mac).strip():
            entities["mac_addresses"].add(str(mac).strip())

    return {k: sorted(v) for k, v in entities.items()}


# ---------------------------------------------------------------------------
# Core: normalise and write
# ---------------------------------------------------------------------------

def _normalise_and_write(
    artefact_name: str,
    rows: list[dict],
    case_id: str,
    normaliser: callable,
    fmt: str = "parsed",
) -> dict:
    """Normalise rows and write parsed.json + entities.json."""
    logs_dir = CASES_DIR / case_id / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    normalised_rows = []
    for row in rows:
        try:
            normalised_rows.append(normaliser(row))
        except Exception:
            normalised_rows.append(_norm_generic(row))

    entities = _extract_entities(normalised_rows)

    stem = f"mde_{artefact_name}"

    result = {
        "source_file": f"mde:{artefact_name}",
        "case_id": case_id,
        "format": fmt,
        "ts": utcnow(),
        "row_count": len(normalised_rows),
        "entities": entities,
        "entity_totals": {k: len(v) for k, v in entities.items()},
        "rows_sample": normalised_rows,
    }

    write_artefact(logs_dir / f"{stem}.parsed.json",
                   json.dumps(result, indent=2, default=str))
    write_artefact(logs_dir / f"{stem}.entities.json",
                   json.dumps(entities, indent=2))

    print(f"[mde] {artefact_name}: {len(rows)} row(s)")

    return {
        "name": artefact_name,
        "rows": len(rows),
        "format": fmt,
        "normalised_to": stem,
        "entity_totals": result["entity_totals"],
    }


# ---------------------------------------------------------------------------
# MDE package detection + folder routing
# ---------------------------------------------------------------------------

# Folder names as they appear inside the MDE investigation package ZIP
_MDE_FOLDERS = {
    "Autoruns",
    "Installed programs",
    "Network connections",
    "Prefetch files",
    "Processes",
    "Scheduled tasks",
    "Security event log",
    "Services",
    "SMB sessions",
    "System Information",
    "Temp Directories",
    "Users and Groups",
    "WdSupportLogs",
}


def _is_mde_package(zf: zipfile.ZipFile) -> bool:
    """Detect whether a ZIP is an MDE investigation package."""
    names = zf.namelist()
    # Look for at least 3 known MDE folder names
    found = 0
    for name in names:
        parts = Path(name).parts
        for part in parts:
            if part in _MDE_FOLDERS:
                found += 1
                break
        if found >= 3:
            return True
    # Also check for CollectionSummaryReport
    for name in names:
        if "CollectionSummaryReport" in name:
            return True
    return False


def _find_prefix(zf: zipfile.ZipFile) -> str:
    """Find common prefix inside the ZIP (MDE packages may nest one level)."""
    for name in zf.namelist():
        for folder in _MDE_FOLDERS:
            if f"/{folder}/" in name or name.startswith(f"{folder}/"):
                # Extract prefix before the known folder
                idx = name.find(f"{folder}/")
                return name[:idx] if idx > 0 else ""
    return ""


def _read_zip_text(zf: zipfile.ZipFile, name: str, pwd: bytes | None) -> str:
    """Read a text file from the ZIP, handling encoding."""
    raw = zf.read(name, pwd=pwd)
    # Try UTF-16 (common for Windows tool output), then UTF-8
    for enc in ("utf-16", "utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def mde_ingest(
    source_path: str | Path,
    case_id: str,
    *,
    password: str | None = None,
) -> dict:
    """Ingest an MDE investigation package ZIP into a socai case.

    Args:
        source_path: Path to MDE investigation package ZIP.
        case_id: Target case ID.
        password: Optional ZIP password.

    Returns:
        Manifest dict with processing summary.
    """
    source = Path(source_path)
    if not source.exists():
        return {"status": "error", "reason": f"Source not found: {source_path}"}

    if not source.is_file() or source.suffix.lower() != ".zip":
        return {"status": "error", "reason": f"Expected a ZIP file: {source_path}"}

    mde_dir = CASES_DIR / case_id / "artefacts" / "mde"
    logs_dir = CASES_DIR / case_id / "logs"
    mde_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    pwd = password.encode() if password else None
    artefacts_processed = []
    raw_files_extracted = []
    warnings = []
    system_info = {}

    try:
        with zipfile.ZipFile(source) as zf:
            if not _is_mde_package(zf):
                return {"status": "error",
                        "reason": "ZIP does not appear to be an MDE investigation package"}

            prefix = _find_prefix(zf)
            names = sorted(zf.namelist())

            # ----- CollectionSummaryReport -----
            for name in names:
                if "CollectionSummaryReport" in name and not name.endswith("/"):
                    try:
                        data = zf.read(name, pwd=pwd)
                        dest = mde_dir / "collection_summary.xls"
                        write_artefact(dest, data)
                        raw_files_extracted.append({
                            "source": name, "dest": str(dest), "size": len(data),
                        })
                    except Exception as exc:
                        warnings.append(f"Failed to extract CollectionSummaryReport: {exc}")

            # ----- System Information -----
            for name in names:
                if _in_folder(name, prefix, "System Information") and not name.endswith("/"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        system_info = _parse_system_info_txt(text)
                        if system_info:
                            save_json(mde_dir / "system_info.json", system_info)
                            r = _normalise_and_write(
                                "system_info", [system_info], case_id,
                                _norm_system_info, "txt",
                            )
                            artefacts_processed.append(r)
                    except Exception as exc:
                        warnings.append(f"Error parsing System Information: {exc}")

            # ----- Processes -----
            for name in names:
                if _in_folder(name, prefix, "Processes") and name.lower().endswith(".csv"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_csv_text(text)
                        if rows:
                            r = _normalise_and_write(
                                "processes", rows, case_id, _norm_processes, "csv",
                            )
                            artefacts_processed.append(r)
                    except Exception as exc:
                        warnings.append(f"Error parsing Processes: {exc}")

            # ----- Services -----
            for name in names:
                if _in_folder(name, prefix, "Services") and name.lower().endswith(".csv"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_csv_text(text)
                        if rows:
                            r = _normalise_and_write(
                                "services", rows, case_id, _norm_services, "csv",
                            )
                            artefacts_processed.append(r)
                    except Exception as exc:
                        warnings.append(f"Error parsing Services: {exc}")

            # ----- Scheduled tasks -----
            for name in names:
                if _in_folder(name, prefix, "Scheduled tasks") and name.lower().endswith(".csv"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_csv_text(text)
                        if rows:
                            r = _normalise_and_write(
                                "scheduled_tasks", rows, case_id, _norm_tasks, "csv",
                            )
                            artefacts_processed.append(r)
                    except Exception as exc:
                        warnings.append(f"Error parsing Scheduled tasks: {exc}")

            # ----- Installed programs -----
            for name in names:
                if _in_folder(name, prefix, "Installed programs") and name.lower().endswith(".csv"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_csv_text(text)
                        if rows:
                            r = _normalise_and_write(
                                "installed_programs", rows, case_id,
                                _norm_installed_programs, "csv",
                            )
                            artefacts_processed.append(r)
                    except Exception as exc:
                        warnings.append(f"Error parsing Installed programs: {exc}")

            # ----- Network connections -----
            for name in names:
                if not _in_folder(name, prefix, "Network connections") or name.endswith("/"):
                    continue
                fname = Path(name).name.lower()
                try:
                    text = _read_zip_text(zf, name, pwd)
                    if "activenetconnections" in fname:
                        rows = _parse_netstat_txt(text)
                        if rows:
                            r = _normalise_and_write(
                                "network_connections", rows, case_id,
                                _norm_netstat, "txt",
                            )
                            artefacts_processed.append(r)
                    elif "arp" in fname:
                        rows = _parse_arp_txt(text)
                        if rows:
                            r = _normalise_and_write(
                                "arp_cache", rows, case_id, _norm_arp, "txt",
                            )
                            artefacts_processed.append(r)
                    elif "dnscache" in fname:
                        rows = _parse_dns_cache_txt(text)
                        if rows:
                            r = _normalise_and_write(
                                "dns_cache", rows, case_id, _norm_dns_cache, "txt",
                            )
                            artefacts_processed.append(r)
                    elif "ipconfig" in fname:
                        # Store as raw text — not tabular
                        dest = mde_dir / "ipconfig.txt"
                        write_artefact(dest, text.encode("utf-8"))
                        raw_files_extracted.append({
                            "source": name, "dest": str(dest),
                            "size": len(text),
                        })
                    elif "firewall" in fname:
                        dest = mde_dir / Path(name).name
                        write_artefact(dest, text.encode("utf-8"))
                        raw_files_extracted.append({
                            "source": name, "dest": str(dest),
                            "size": len(text),
                        })
                except Exception as exc:
                    warnings.append(f"Error parsing Network connections/{Path(name).name}: {exc}")

            # ----- Security event log (.evtx) -----
            for name in names:
                if _in_folder(name, prefix, "Security event log") and not name.endswith("/"):
                    try:
                        data = zf.read(name, pwd=pwd)
                        evtx_dir = mde_dir / "security_evtx"
                        evtx_dir.mkdir(parents=True, exist_ok=True)
                        dest = evtx_dir / Path(name).name
                        write_artefact(dest, data)
                        raw_files_extracted.append({
                            "source": name, "dest": str(dest),
                            "size": len(data),
                        })
                        print(f"[mde] Extracted security EVTX: {Path(name).name} ({len(data)} bytes)")
                    except Exception as exc:
                        warnings.append(f"Error extracting Security event log: {exc}")

            # ----- Autoruns -----
            all_autorun_rows = []
            for name in names:
                if _in_folder(name, prefix, "Autoruns") and not name.endswith("/"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_autoruns_registry(text, Path(name).name)
                        all_autorun_rows.extend(rows)
                    except Exception as exc:
                        warnings.append(f"Error parsing Autoruns/{Path(name).name}: {exc}")
            if all_autorun_rows:
                r = _normalise_and_write(
                    "autoruns", all_autorun_rows, case_id, _norm_autoruns, "txt",
                )
                artefacts_processed.append(r)

            # ----- Prefetch files -----
            for name in names:
                if not _in_folder(name, prefix, "Prefetch files") or name.endswith("/"):
                    continue
                fname = Path(name).name.lower()
                try:
                    if fname == "prefetchfileslist.txt":
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_prefetch_listing(text)
                        if rows:
                            r = _normalise_and_write(
                                "prefetch", rows, case_id, _norm_prefetch, "txt",
                            )
                            artefacts_processed.append(r)
                    elif fname.endswith(".pf"):
                        # Raw prefetch binary — store for external analysis
                        data = zf.read(name, pwd=pwd)
                        pf_dir = mde_dir / "prefetch"
                        pf_dir.mkdir(parents=True, exist_ok=True)
                        dest = pf_dir / Path(name).name
                        write_artefact(dest, data)
                        raw_files_extracted.append({
                            "source": name, "dest": str(dest),
                            "size": len(data),
                        })
                except Exception as exc:
                    warnings.append(f"Error processing Prefetch/{Path(name).name}: {exc}")

            # ----- SMB sessions -----
            all_smb_rows = []
            for name in names:
                if _in_folder(name, prefix, "SMB sessions") and not name.endswith("/"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_smb_sessions_txt(text)
                        all_smb_rows.extend(rows)
                    except Exception as exc:
                        warnings.append(f"Error parsing SMB sessions: {exc}")
            if all_smb_rows:
                r = _normalise_and_write(
                    "smb_sessions", all_smb_rows, case_id, _norm_smb_sessions, "txt",
                )
                artefacts_processed.append(r)

            # ----- Temp Directories -----
            all_temp_rows = []
            for name in names:
                if _in_folder(name, prefix, "Temp Directories") and not name.endswith("/"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_temp_dir_listing(text, Path(name).stem)
                        all_temp_rows.extend(rows)
                    except Exception as exc:
                        warnings.append(f"Error parsing Temp Directories: {exc}")
            if all_temp_rows:
                r = _normalise_and_write(
                    "temp_directories", all_temp_rows, case_id, _norm_temp_dirs, "txt",
                )
                artefacts_processed.append(r)

            # ----- Users and Groups -----
            all_ug_rows = []
            for name in names:
                if _in_folder(name, prefix, "Users and Groups") and not name.endswith("/"):
                    try:
                        text = _read_zip_text(zf, name, pwd)
                        rows = _parse_users_groups_txt(text, Path(name).name)
                        all_ug_rows.extend(rows)
                    except Exception as exc:
                        warnings.append(f"Error parsing Users and Groups: {exc}")
            if all_ug_rows:
                r = _normalise_and_write(
                    "users_groups", all_ug_rows, case_id, _norm_users_groups, "txt",
                )
                artefacts_processed.append(r)

            # ----- WdSupportLogs (Defender logs) -----
            for name in names:
                if _in_folder(name, prefix, "WdSupportLogs") and not name.endswith("/"):
                    try:
                        data = zf.read(name, pwd=pwd)
                        wd_dir = mde_dir / "wd_support_logs"
                        wd_dir.mkdir(parents=True, exist_ok=True)
                        dest = wd_dir / Path(name).name
                        write_artefact(dest, data)
                        raw_files_extracted.append({
                            "source": name, "dest": str(dest),
                            "size": len(data),
                        })
                    except Exception as exc:
                        warnings.append(f"Error extracting WdSupportLogs: {exc}")

    except zipfile.BadZipFile as exc:
        return {"status": "error", "reason": f"Bad ZIP file: {exc}"}
    except Exception as exc:
        log_error(case_id, "mde_ingest", str(exc), severity="error",
                  context={"source": str(source)})
        return {"status": "error", "reason": str(exc)}

    # Build manifest
    total_rows = sum(a["rows"] for a in artefacts_processed)
    logs_written = [f"logs/{a['normalised_to']}.parsed.json" for a in artefacts_processed]

    manifest = {
        "status": "ok",
        "case_id": case_id,
        "ts": utcnow(),
        "source": str(source),
        "source_type": "mde_investigation_package",
        "system_info": system_info,
        "artefacts_processed": artefacts_processed,
        "raw_files_extracted": raw_files_extracted,
        "warnings": warnings,
        "manifest": {
            "total_artefacts": len(artefacts_processed),
            "total_rows_ingested": total_rows,
            "total_raw_files": len(raw_files_extracted),
            "logs_written": logs_written,
        },
    }

    save_json(mde_dir / "ingest_manifest.json", manifest)

    print(f"[mde] Ingest complete: {len(artefacts_processed)} artefact(s), "
          f"{total_rows} row(s), {len(raw_files_extracted)} raw file(s)")
    if warnings:
        print(f"[mde] {len(warnings)} warning(s)")

    return manifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _in_folder(zip_name: str, prefix: str, folder: str) -> bool:
    """Check if a ZIP entry belongs to a specific MDE folder."""
    # Match with prefix: "prefix/Folder/file.txt"
    if prefix and zip_name.startswith(f"{prefix}{folder}/"):
        return True
    # Match without prefix: "Folder/file.txt"
    if zip_name.startswith(f"{folder}/"):
        return True
    # Also handle case-insensitive and nested
    parts = Path(zip_name).parts
    return folder in parts


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Ingest MDE investigation package.")
    p.add_argument("target", help="Path to MDE investigation package ZIP")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--password", default=None, help="ZIP password")
    args = p.parse_args()

    result = mde_ingest(args.target, args.case_id, password=args.password)
    print(json.dumps(result, indent=2, default=str))
