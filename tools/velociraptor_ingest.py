"""
tool: velociraptor_ingest
-------------------------
Ingest Velociraptor offline collector ZIPs, VQL result files (JSONL/CSV),
or directories of exported artefacts.  Normalises VQL-specific field names
into the schema that downstream tools (evtx_correlate, detect_anomalies,
extract_iocs, timeline_reconstruct) already consume.

Three input modes:
  A) Offline collector ZIP — contains collection_context.json, results/, uploads/
  B) Individual VQL result files (JSONL or CSV)
  C) Directory of VQL result files

Writes:
  cases/<case_id>/artefacts/velociraptor/ingest_manifest.json
  cases/<case_id>/artefacts/velociraptor/collection_context.json  (if present)
  cases/<case_id>/artefacts/velociraptor/host_info.json           (if present)
  cases/<case_id>/artefacts/velociraptor/uploads/                 (raw files)
  cases/<case_id>/logs/vr_<artefact_name>.parsed.json
  cases/<case_id>/logs/vr_<artefact_name>.entities.json

Usage (standalone):
  python3 tools/velociraptor_ingest.py /path/to/collection.zip --case IV_CASE_001
  python3 tools/velociraptor_ingest.py /path/to/results/ --case IV_CASE_001
  python3 tools/velociraptor_ingest.py /path/to/Windows.System.Autoruns.json --case IV_CASE_001
"""
from __future__ import annotations

import csv
import io
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import log_error, save_json, utcnow, write_artefact

# ---------------------------------------------------------------------------
# Regex patterns for entity extraction (shared with parse_logs)
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
              "ipaddress", "sourceip", "laddr", "raddr"}
_USER_FIELDS = {"user", "username", "account", "accountname", "userid",
                "subject_account_name", "subjectusername", "targetusername", "fqdn"}
_CMD_FIELDS = {"commandline", "command_line", "cmdline", "process_command_line",
               "parentcommandline", "exe"}
_PROC_FIELDS = {"process", "processname", "image", "parentimage",
                "process_name", "imagename", "name", "exe"}


# ---------------------------------------------------------------------------
# VQL artefact normalisers
# ---------------------------------------------------------------------------

def _flatten_event_data(row: dict) -> dict:
    """Flatten nested EventData / System dicts commonly seen in VQL EVTX output."""
    system = row.get("System", {}) or {}
    event_data = row.get("EventData", {}) or {}
    flat = {}

    # System-level fields
    time_created = system.get("TimeCreated", {})
    if isinstance(time_created, dict):
        flat["TimeCreated"] = time_created.get("SystemTime", "")
    elif isinstance(time_created, str):
        flat["TimeCreated"] = time_created

    event_id = system.get("EventID", "")
    if isinstance(event_id, dict):
        flat["EventID"] = event_id.get("Value", "")
    else:
        flat["EventID"] = event_id

    flat["Channel"] = system.get("Channel", "")
    flat["Computer"] = system.get("Computer", "")

    # EventData fields — promote to top level
    for k, v in event_data.items():
        if k not in flat:
            flat[k] = v

    return flat


def _norm_evtx(row: dict) -> dict:
    """Normalise VQL Windows.EventLogs.Evtx output."""
    # VQL EVTX may be pre-flattened or nested
    if "System" in row or "EventData" in row:
        flat = _flatten_event_data(row)
    else:
        flat = row

    return {
        "TimeCreated": flat.get("TimeCreated") or row.get("Timestamp", ""),
        "EventID": flat.get("EventID", ""),
        "SourceIP": flat.get("IpAddress", ""),
        "TargetUserName": flat.get("TargetUserName", ""),
        "LogonType": flat.get("LogonType", ""),
        "ProcessName": flat.get("ProcessName", flat.get("NewProcessName", "")),
        "ParentProcessName": flat.get("ParentProcessName", ""),
        "CommandLine": flat.get("CommandLine", ""),
        "ServiceName": flat.get("ServiceName", ""),
        "TaskName": flat.get("TaskName", ""),
        "EncryptionType": flat.get("EncryptionType", flat.get("TicketEncryptionType", "")),
        "LogonProcessName": flat.get("LogonProcessName", ""),
        "SubjectUserSid": flat.get("SubjectUserSid", ""),
        "TargetDomainName": flat.get("TargetDomainName", ""),
        "Channel": flat.get("Channel", ""),
        "Computer": flat.get("Computer", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.EventLogs.Evtx",
    }


def _norm_autoruns(row: dict) -> dict:
    return {
        "TimeCreated": row.get("Mtime", row.get("Modified", "")),
        "ProcessName": row.get("Entry", row.get("ImagePath", "")),
        "CommandLine": row.get("CommandLine", row.get("ImagePath", "")),
        "TargetUserName": row.get("ProfilePath", ""),
        "Category": row.get("Category", row.get("Type", "")),
        "Description": row.get("Description", ""),
        "Enabled": row.get("Enabled", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.System.Autoruns",
    }


def _norm_netstat(row: dict) -> dict:
    return {
        "TimeCreated": row.get("Timestamp", ""),
        "SourceIP": row.get("Laddr", {}).get("IP", "") if isinstance(row.get("Laddr"), dict) else str(row.get("Laddr", "")),
        "DestIP": row.get("Raddr", {}).get("IP", "") if isinstance(row.get("Raddr"), dict) else str(row.get("Raddr", "")),
        "SourcePort": row.get("Laddr", {}).get("Port", "") if isinstance(row.get("Laddr"), dict) else "",
        "DestPort": row.get("Raddr", {}).get("Port", "") if isinstance(row.get("Raddr"), dict) else "",
        "ProcessName": row.get("Name", ""),
        "Pid": row.get("Pid", ""),
        "Status": row.get("Status", ""),
        "Family": row.get("FamilyString", row.get("Family", "")),
        "_source": "velociraptor",
        "_artefact": "Windows.Network.Netstat",
    }


def _norm_processes(row: dict) -> dict:
    return {
        "TimeCreated": row.get("CreateTime", row.get("create_time", "")),
        "ProcessName": row.get("Name", row.get("Exe", "")),
        "CommandLine": row.get("CommandLine", row.get("Cmdline", "")),
        "ParentProcessName": row.get("ParentName", ""),
        "Pid": row.get("Pid", row.get("pid", "")),
        "Ppid": row.get("Ppid", row.get("ppid", "")),
        "TargetUserName": row.get("Username", row.get("username", "")),
        "_source": "velociraptor",
        "_artefact": "Windows.System.Pslist",
    }


def _norm_services(row: dict) -> dict:
    return {
        "TimeCreated": row.get("Created", ""),
        "ServiceName": row.get("Name", row.get("DisplayName", "")),
        "CommandLine": row.get("PathName", row.get("ImagePath", "")),
        "ProcessName": row.get("PathName", ""),
        "StartMode": row.get("StartMode", row.get("Start", "")),
        "State": row.get("State", row.get("Status", "")),
        "TargetUserName": row.get("StartName", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.System.Services",
    }


def _norm_tasks(row: dict) -> dict:
    return {
        "TimeCreated": row.get("LastRunTime", row.get("Created", "")),
        "TaskName": row.get("Name", row.get("Path", "")),
        "CommandLine": row.get("Command", row.get("Actions", "")),
        "TargetUserName": row.get("UserId", row.get("Author", "")),
        "Enabled": row.get("Enabled", ""),
        "NextRunTime": row.get("NextRunTime", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.System.TaskScheduler",
    }


def _norm_prefetch(row: dict) -> dict:
    return {
        "TimeCreated": row.get("LastRunTimes", row.get("SourceModified", "")),
        "ProcessName": row.get("Executable", row.get("Name", "")),
        "RunCount": row.get("RunCount", ""),
        "PrefetchHash": row.get("Hash", row.get("PrefetchHash", "")),
        "_source": "velociraptor",
        "_artefact": "Windows.Forensics.Prefetch",
    }


def _norm_shimcache(row: dict) -> dict:
    return {
        "TimeCreated": row.get("ModifiedTimestamp", row.get("LastModified", "")),
        "ProcessName": row.get("Path", row.get("Entry", "")),
        "Executed": row.get("Executed", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.Forensics.Shimcache",
    }


def _norm_amcache(row: dict) -> dict:
    return {
        "TimeCreated": row.get("KeyLastWriteTimestamp", row.get("FileKeyLastWriteTimestamp", "")),
        "ProcessName": row.get("FullPath", row.get("Path", "")),
        "SHA1": row.get("SHA1", row.get("FileId", "")),
        "Size": row.get("Size", ""),
        "Publisher": row.get("Publisher", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.Forensics.Amcache",
    }


def _norm_mft(row: dict) -> dict:
    return {
        "TimeCreated": row.get("Created0x10", row.get("SI_Created", "")),
        "Modified": row.get("Modified0x10", row.get("SI_Modified", "")),
        "ProcessName": row.get("FullPath", row.get("FileName", "")),
        "Size": row.get("FileSize", row.get("Size", "")),
        "InUse": row.get("InUse", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.Forensics.NTFS.MFT",
    }


def _norm_usn(row: dict) -> dict:
    return {
        "TimeCreated": row.get("Timestamp", row.get("TimeStamp", "")),
        "ProcessName": row.get("FullPath", row.get("Name", "")),
        "Reason": row.get("Reason", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.Forensics.USN",
    }


def _norm_users(row: dict) -> dict:
    return {
        "TargetUserName": row.get("Name", row.get("Username", "")),
        "Uid": row.get("Uid", row.get("SID", "")),
        "Description": row.get("Description", ""),
        "_source": "velociraptor",
        "_artefact": "Windows.Sys.Users",
    }


def _norm_generic(row: dict) -> dict:
    """Fallback normaliser — pass through as-is with source tag."""
    normalised = dict(row)
    normalised["_source"] = "velociraptor"
    normalised["_artefact"] = "generic"
    return normalised


# Registry: VQL artefact name pattern → normaliser function
_NORMALISERS: dict[str, callable] = {
    "Windows.EventLogs.Evtx": _norm_evtx,
    "Windows.System.Autoruns": _norm_autoruns,
    "Windows.Network.Netstat": _norm_netstat,
    "Windows.System.Services": _norm_services,
    "Windows.System.TaskScheduler": _norm_tasks,
    "Windows.System.Pslist": _norm_processes,
    "Generic.System.Pstree": _norm_processes,
    "Windows.Forensics.Prefetch": _norm_prefetch,
    "Windows.Forensics.Shimcache": _norm_shimcache,
    "Windows.Forensics.Amcache": _norm_amcache,
    "Windows.Forensics.NTFS.MFT": _norm_mft,
    "Windows.Forensics.USN": _norm_usn,
    "Windows.Sys.Users": _norm_users,
}


def _match_normaliser(artefact_name: str) -> callable:
    """Find the best normaliser for a given artefact name."""
    # Exact match first
    if artefact_name in _NORMALISERS:
        return _NORMALISERS[artefact_name]
    # Partial match — artefact name may have suffixes like /Logs or /All
    for pattern, fn in _NORMALISERS.items():
        if artefact_name.startswith(pattern):
            return fn
    return _norm_generic


# ---------------------------------------------------------------------------
# Entity extraction (mirrors parse_logs._extract_entities)
# ---------------------------------------------------------------------------

def _extract_entities(rows: list[dict]) -> dict:
    """Extract security-relevant entities from normalised rows."""
    entities: dict[str, set] = {
        "ips": set(), "users": set(), "processes": set(),
        "commands": set(), "file_paths": set(),
        "http_methods": set(), "http_statuses": set(),
        "event_ids": set(), "timestamps": set(),
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
        # Also grab EventID field directly
        eid = row_lower.get("eventid")
        if eid:
            try:
                entities["event_ids"].add(str(int(eid)))
            except (ValueError, TypeError) as exc:
                log_error("", "velociraptor_ingest:extract_entities",
                          str(exc), severity="info", traceback=True,
                          context={"field": "eventid", "value": str(eid)})

    return {k: sorted(v) for k, v in entities.items()}


# ---------------------------------------------------------------------------
# File parsing helpers
# ---------------------------------------------------------------------------

def _parse_jsonl(text: str) -> list[dict]:
    """Parse JSON Lines (one JSON object per line)."""
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
            elif isinstance(obj, list):
                rows.extend(o for o in obj if isinstance(o, dict))
        except json.JSONDecodeError as exc:
            log_error("", "velociraptor_ingest:parse_jsonl",
                      str(exc), severity="warning", traceback=True,
                      context={"line_preview": line[:200]})
            continue
    return rows


def _parse_json_array(text: str) -> list[dict]:
    """Parse a JSON array of objects."""
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("records", "events", "logs", "items", "data", "rows"):
                if key in data and isinstance(data[key], list):
                    return [r for r in data[key] if isinstance(r, dict)]
            return [data]
    except json.JSONDecodeError as exc:
        log_error("", "velociraptor_ingest:parse_json_array",
                  str(exc), severity="warning", traceback=True)
    return []


def _parse_csv_text(text: str) -> list[dict]:
    """Parse CSV text into list of dicts."""
    try:
        reader = csv.DictReader(io.StringIO(text))
        return [row for row in reader]
    except Exception as exc:
        log_error("", "velociraptor_ingest:parse_csv",
                  str(exc), severity="warning", traceback=True)
        return []


def _load_vql_file(file_path: Path) -> tuple[list[dict], str]:
    """Load a VQL result file — tries JSONL, JSON array, then CSV."""
    text = file_path.read_text(errors="ignore")
    ext = file_path.suffix.lower()

    if ext == ".csv":
        rows = _parse_csv_text(text)
        if rows:
            return rows, "csv"

    # Try JSONL first (most common VQL output)
    rows = _parse_jsonl(text)
    if rows:
        return rows, "jsonl"

    # Try JSON array
    rows = _parse_json_array(text)
    if rows:
        return rows, "json_array"

    # Fallback CSV
    if ext != ".csv":
        rows = _parse_csv_text(text)
        if rows:
            return rows, "csv_fallback"

    return [], "unknown"


def _guess_artefact_name(filename: str) -> str:
    """Guess the VQL artefact name from a filename.

    Velociraptor result files are often named like:
      Windows.EventLogs.Evtx.json
      Windows.System.Autoruns.json
      Generic.Client.Info_info.json
    """
    stem = Path(filename).stem
    # Remove common suffixes
    for suffix in ("_info", "_results", "_data"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    return stem


# ---------------------------------------------------------------------------
# ZIP handling
# ---------------------------------------------------------------------------

def _is_collector_zip(zf: zipfile.ZipFile) -> bool:
    """Check if a ZIP looks like a Velociraptor offline collector."""
    names = zf.namelist()
    # Look for collection_context.json at root or one level down
    for name in names:
        parts = Path(name).parts
        if parts and parts[-1] == "collection_context.json" and len(parts) <= 2:
            return True
    # Also check for results/ directory pattern
    for name in names:
        if "/results/" in name or name.startswith("results/"):
            return True
    return False


def _find_prefix(zf: zipfile.ZipFile) -> str:
    """Find the common prefix inside the ZIP (some collectors nest everything)."""
    for name in zf.namelist():
        if name.endswith("collection_context.json"):
            prefix = str(Path(name).parent)
            return prefix + "/" if prefix != "." else ""
    return ""


def _extract_collector_zip(
    zip_path: Path,
    case_id: str,
    password: str | None = None,
) -> dict:
    """Extract and ingest a Velociraptor offline collector ZIP."""
    vr_dir = CASES_DIR / case_id / "artefacts" / "velociraptor"
    logs_dir = CASES_DIR / case_id / "logs"
    uploads_dir = vr_dir / "uploads"
    vr_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    pwd = password.encode() if password else None
    artefacts_processed = []
    uploads_extracted = []
    warnings = []
    collection_meta = {}
    host_info = {}

    with zipfile.ZipFile(zip_path) as zf:
        prefix = _find_prefix(zf)

        # 1. Extract collection_context.json
        ctx_path = f"{prefix}collection_context.json"
        if ctx_path in zf.namelist():
            try:
                raw = zf.read(ctx_path, pwd=pwd)
                collection_meta = json.loads(raw)
                write_artefact(vr_dir / "collection_context.json", raw)
            except Exception as exc:
                log_error(case_id, "velociraptor_ingest:parse_collection_context",
                          str(exc), severity="warning", traceback=True)
                warnings.append(f"Failed to parse collection_context.json: {exc}")

        # 2. Process results/ directory (VQL outputs)
        result_files = sorted(
            n for n in zf.namelist()
            if (n.startswith(f"{prefix}results/") or n.startswith("results/"))
            and not n.endswith("/")
        )

        for name in result_files:
            try:
                raw = zf.read(name, pwd=pwd).decode("utf-8", errors="ignore")
                filename = Path(name).name
                artefact_name = _guess_artefact_name(filename)
                rows, fmt = _load_vql_file_from_text(raw, filename)

                if not rows:
                    warnings.append(f"Empty or unparseable: {name}")
                    continue

                # Check for client info
                if "Generic.Client.Info" in artefact_name and not host_info:
                    host_info = rows[0] if rows else {}

                result = _normalise_and_write(artefact_name, rows, case_id, fmt)
                artefacts_processed.append(result)

            except Exception as exc:
                log_error(case_id, "velociraptor_ingest.result_file",
                          str(exc), severity="warning", traceback=True,
                          context={"file": name})
                warnings.append(f"Error processing {name}: {exc}")

        # 3. Extract uploads/ directory (raw files: EVTX, MFT, prefetch, etc.)
        upload_files = [
            n for n in zf.namelist()
            if (n.startswith(f"{prefix}uploads/") or n.startswith("uploads/"))
            and not n.endswith("/")
        ]

        for name in upload_files:
            try:
                data = zf.read(name, pwd=pwd)
                # Preserve directory structure under uploads/
                rel = name.split("uploads/", 1)[-1]
                dest = uploads_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                write_artefact(dest, data)
                uploads_extracted.append({
                    "source": name,
                    "dest": str(dest),
                    "size": len(data),
                })
            except Exception as exc:
                log_error(case_id, "velociraptor_ingest.upload_extract",
                          str(exc), severity="warning", traceback=True,
                          context={"file": name})
                warnings.append(f"Error extracting {name}: {exc}")

    # Save host info
    if host_info:
        save_json(vr_dir / "host_info.json", host_info)

    return {
        "collection_metadata": collection_meta,
        "artefacts_processed": artefacts_processed,
        "uploads_extracted": uploads_extracted,
        "host_info": host_info,
        "warnings": warnings,
    }


def _load_vql_file_from_text(text: str, filename: str) -> tuple[list[dict], str]:
    """Parse VQL output from text (used when reading from ZIP)."""
    ext = Path(filename).suffix.lower()
    if ext == ".csv":
        rows = _parse_csv_text(text)
        if rows:
            return rows, "csv"

    rows = _parse_jsonl(text)
    if rows:
        return rows, "jsonl"

    rows = _parse_json_array(text)
    if rows:
        return rows, "json_array"

    if ext != ".csv":
        rows = _parse_csv_text(text)
        if rows:
            return rows, "csv_fallback"

    return [], "unknown"


# ---------------------------------------------------------------------------
# Core normalisation and writing
# ---------------------------------------------------------------------------

def _normalise_and_write(
    artefact_name: str,
    rows: list[dict],
    case_id: str,
    fmt: str,
) -> dict:
    """Normalise VQL rows and write parsed.json + entities.json."""
    logs_dir = CASES_DIR / case_id / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    normaliser = _match_normaliser(artefact_name)
    normalised_rows = []
    for row in rows:
        try:
            normalised_rows.append(normaliser(row))
        except Exception as exc:
            log_error(case_id, "velociraptor_ingest:normalise_row",
                      str(exc), severity="warning", traceback=True,
                      context={"artefact": artefact_name})
            normalised_rows.append(_norm_generic(row))

    entities = _extract_entities(normalised_rows)

    # Safe filename — replace dots with underscores for filesystem
    safe_name = artefact_name.replace("/", "_").replace("\\", "_")
    stem = f"vr_{safe_name}"

    result = {
        "source_file": f"velociraptor:{artefact_name}",
        "case_id": case_id,
        "format": fmt,
        "ts": utcnow(),
        "row_count": len(normalised_rows),
        "entities": entities,
        "entity_totals": {k: len(v) for k, v in entities.items()},
        "rows_sample": normalised_rows,  # all rows — downstream tools read this key
    }

    write_artefact(logs_dir / f"{stem}.parsed.json", json.dumps(result, indent=2, default=str))
    write_artefact(logs_dir / f"{stem}.entities.json", json.dumps(entities, indent=2))

    print(f"[velociraptor] {artefact_name}: {len(rows)} row(s), format={fmt}")

    return {
        "name": artefact_name,
        "rows": len(rows),
        "format": fmt,
        "normalised_to": stem,
        "entity_totals": result["entity_totals"],
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def velociraptor_ingest(
    source_path: str | Path,
    case_id: str,
    *,
    password: str | None = None,
    host_label: str = "",
) -> dict:
    """Ingest Velociraptor collection exports into a socai case.

    Args:
        source_path: Path to collector ZIP, result directory, or individual VQL file.
        case_id: Target case ID.
        password: Optional ZIP password.
        host_label: Optional hostname label for hunt ZIPs.

    Returns:
        Manifest dict with processing summary.
    """
    source = Path(source_path)
    if not source.exists():
        return {"status": "error", "reason": f"Source not found: {source_path}"}

    vr_dir = CASES_DIR / case_id / "artefacts" / "velociraptor"
    vr_dir.mkdir(parents=True, exist_ok=True)

    artefacts_processed = []
    uploads_extracted = []
    warnings = []
    collection_meta = {}
    host_info = {}

    # Mode A: ZIP file
    if source.is_file() and source.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(source) as zf:
                if _is_collector_zip(zf):
                    result = _extract_collector_zip(source, case_id, password=password)
                    artefacts_processed = result["artefacts_processed"]
                    uploads_extracted = result["uploads_extracted"]
                    warnings = result["warnings"]
                    collection_meta = result["collection_metadata"]
                    host_info = result["host_info"]
                else:
                    # Not a collector ZIP — treat as a regular ZIP with VQL files
                    pwd = password.encode() if password else None
                    for name in sorted(zf.namelist()):
                        if name.endswith("/"):
                            continue
                        ext = Path(name).suffix.lower()
                        if ext not in (".json", ".csv", ".jsonl"):
                            continue
                        try:
                            raw = zf.read(name, pwd=pwd).decode("utf-8", errors="ignore")
                            filename = Path(name).name
                            artefact_name = _guess_artefact_name(filename)
                            rows, fmt = _load_vql_file_from_text(raw, filename)
                            if rows:
                                r = _normalise_and_write(artefact_name, rows, case_id, fmt)
                                artefacts_processed.append(r)
                        except Exception as exc:
                            log_error(case_id, "velociraptor_ingest:zip_vql_file",
                                      str(exc), severity="warning", traceback=True,
                                      context={"file": name})
                            warnings.append(f"Error processing {name}: {exc}")
        except zipfile.BadZipFile as exc:
            log_error(case_id, "velociraptor_ingest:open_zip",
                      str(exc), severity="error", traceback=True,
                      context={"source": str(source)})
            return {"status": "error", "reason": f"Bad ZIP file: {exc}"}

    # Mode B: Single file
    elif source.is_file():
        artefact_name = _guess_artefact_name(source.name)
        rows, fmt = _load_vql_file(source)
        if rows:
            r = _normalise_and_write(artefact_name, rows, case_id, fmt)
            artefacts_processed.append(r)
        else:
            warnings.append(f"No parseable rows in {source.name}")

    # Mode C: Directory
    elif source.is_dir():
        for f in sorted(source.iterdir()):
            if f.is_file() and f.suffix.lower() in (".json", ".csv", ".jsonl"):
                artefact_name = _guess_artefact_name(f.name)
                rows, fmt = _load_vql_file(f)
                if rows:
                    r = _normalise_and_write(artefact_name, rows, case_id, fmt)
                    artefacts_processed.append(r)
                else:
                    warnings.append(f"No parseable rows in {f.name}")
        # Also check for nested results/ and uploads/ dirs
        results_dir = source / "results"
        if results_dir.is_dir():
            for f in sorted(results_dir.iterdir()):
                if f.is_file() and f.suffix.lower() in (".json", ".csv", ".jsonl"):
                    artefact_name = _guess_artefact_name(f.name)
                    rows, fmt = _load_vql_file(f)
                    if rows:
                        r = _normalise_and_write(artefact_name, rows, case_id, fmt)
                        artefacts_processed.append(r)
        uploads_src = source / "uploads"
        if uploads_src.is_dir():
            uploads_dest = vr_dir / "uploads"
            for f in sorted(uploads_src.rglob("*")):
                if f.is_file():
                    rel = f.relative_to(uploads_src)
                    dest = uploads_dest / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(f, dest)
                    uploads_extracted.append({
                        "source": str(f),
                        "dest": str(dest),
                        "size": f.stat().st_size,
                    })
        # Check for collection_context.json
        ctx_file = source / "collection_context.json"
        if ctx_file.is_file():
            try:
                collection_meta = json.loads(ctx_file.read_text())
                write_artefact(vr_dir / "collection_context.json",
                               ctx_file.read_bytes())
            except Exception as exc:
                log_error(case_id, "velociraptor_ingest:dir_collection_context",
                          str(exc), severity="warning", traceback=True,
                          context={"file": str(ctx_file)})
                warnings.append(f"Failed to parse collection_context.json: {exc}")
    else:
        return {"status": "error", "reason": f"Unsupported source: {source_path}"}

    # Compute totals
    total_rows = sum(a["rows"] for a in artefacts_processed)
    logs_written = [f"logs/{a['normalised_to']}.parsed.json" for a in artefacts_processed]

    manifest = {
        "status": "ok",
        "case_id": case_id,
        "ts": utcnow(),
        "source": str(source),
        "collection_metadata": collection_meta,
        "artefacts_processed": artefacts_processed,
        "uploads_extracted": uploads_extracted,
        "host_info": host_info,
        "warnings": warnings,
        "manifest": {
            "total_vql_artefacts": len(artefacts_processed),
            "total_rows_ingested": total_rows,
            "total_raw_files": len(uploads_extracted),
            "logs_written": logs_written,
        },
    }

    save_json(vr_dir / "ingest_manifest.json", manifest)

    print(f"[velociraptor] Ingest complete: {len(artefacts_processed)} artefact(s), "
          f"{total_rows} row(s), {len(uploads_extracted)} raw file(s)")
    if warnings:
        print(f"[velociraptor] {len(warnings)} warning(s)")

    return manifest


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Ingest Velociraptor collection results.")
    p.add_argument("target", help="Path to collector ZIP, result directory, or VQL file")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--password", default=None, help="ZIP password")
    args = p.parse_args()

    result = velociraptor_ingest(args.target, args.case_id, password=args.password)
    print(json.dumps(result, indent=2, default=str))
