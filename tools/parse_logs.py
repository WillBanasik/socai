"""
tool: parse_logs
----------------
Accepts CSV or JSON log files and performs basic entity extraction:
  - Timestamps (normalised to ISO-8601)
  - Source/destination IPs
  - Usernames
  - Process names / command lines
  - HTTP methods / status codes / URIs
  - Event IDs (Windows)
  - File paths

Writes:
  cases/<case_id>/logs/<filename>.parsed.json
  cases/<case_id>/logs/<filename>.entities.json
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import log_error, utcnow, write_artefact

_RE_ISO  = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_RE_IP   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_PATH_WIN  = re.compile(r"[A-Za-z]:\\[\w\\\-. ]{4,}")
_RE_PATH_UNIX = re.compile(r"/(?:[\w.\-]+/){1,}[\w.\-]+")
_RE_HTTP = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
_RE_HTTP_STATUS = re.compile(r"\b[1-5]\d{2}\b")
_RE_EVENTID = re.compile(r"\bEvent(?:ID)?[: ]+(\d{3,5})\b", re.IGNORECASE)

# Common field names used across log formats
_IP_FIELDS   = {"src_ip", "dst_ip", "source_ip", "dest_ip", "clientip", "remote_addr",
                "src", "dst", "ip", "remoteip", "sourceaddress", "destinationaddress"}
_USER_FIELDS = {"user", "username", "account", "accountname", "userid",
                "subject_account_name", "subjectusername", "targetusername"}
_CMD_FIELDS  = {"commandline", "command_line", "cmdline", "process_command_line",
                "parentcommandline"}
_PROC_FIELDS = {"process", "processname", "image", "parentimage",
                "process_name", "imagename"}


def _parse_csv(text: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(text))
    return [row for row in reader]


def _parse_json_lines(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            log_error("", "parse_logs.jsonl_line", str(exc),
                      severity="warning", context={"line_preview": line[:200]})
    return rows


def _parse_json_array(text: str) -> list[dict]:
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            # Common wrappers
            for key in ("records", "events", "logs", "items", "data", "hits"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            return [data]
    except json.JSONDecodeError as exc:
        log_error("", "parse_logs.json_array", str(exc), severity="warning")
    return []


def _load_log(file_path: Path) -> tuple[list[dict], str]:
    text = file_path.read_text(errors="ignore")
    ext  = file_path.suffix.lower()

    if ext == ".csv":
        return _parse_csv(text), "csv"
    if ext == ".json":
        rows = _parse_json_array(text)
        if rows:
            return rows, "json_array"
        rows = _parse_json_lines(text)
        if rows:
            return rows, "jsonl"
    # Try JSON fallback on unknown ext
    rows = _parse_json_lines(text)
    if rows:
        return rows, "jsonl"
    return _parse_csv(text), "csv_fallback"


def _extract_entities(rows: list[dict]) -> dict:
    entities: dict[str, set] = {
        "ips": set(), "users": set(), "processes": set(),
        "commands": set(), "file_paths": set(),
        "http_methods": set(), "http_statuses": set(),
        "event_ids": set(), "timestamps": set(),
    }

    for row in rows:
        # Normalised lowercase key view for field matching
        row_lower = {k.lower(): v for k, v in row.items()}
        row_str = json.dumps(row, default=str)

        # Timestamps
        for ts in _RE_ISO.findall(row_str):
            entities["timestamps"].add(ts)

        # IPs from known fields
        for field in _IP_FIELDS:
            val = row_lower.get(field.lower())
            if val and _RE_IP.match(str(val)):
                entities["ips"].add(str(val))

        # IPs from full row text
        for ip in _RE_IP.findall(row_str):
            entities["ips"].add(ip)

        # Users
        for field in _USER_FIELDS:
            val = row_lower.get(field.lower())
            if val:
                entities["users"].add(str(val).strip())

        # Processes
        for field in _PROC_FIELDS:
            val = row_lower.get(field.lower())
            if val:
                entities["processes"].add(str(val).strip())

        # Commands
        for field in _CMD_FIELDS:
            val = row_lower.get(field.lower())
            if val:
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

    return {k: sorted(v) for k, v in entities.items()}


def parse_logs(
    log_path: str | Path,
    case_id: str,
) -> dict:
    """
    Parse *log_path* and write structured results under the case logs dir.
    """
    log_path = Path(log_path)
    logs_dir = CASES_DIR / case_id / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    rows, fmt = _load_log(log_path)
    entities  = _extract_entities(rows)

    result = {
        "source_file": str(log_path),
        "case_id": case_id,
        "format": fmt,
        "ts": utcnow(),
        "row_count": len(rows),
        "entities": entities,
        "entity_totals": {k: len(v) for k, v in entities.items()},
        "rows_sample": rows[:20],
    }

    stem = log_path.stem
    write_artefact(logs_dir / f"{stem}.parsed.json",  json.dumps(result, indent=2))
    write_artefact(logs_dir / f"{stem}.entities.json", json.dumps(entities, indent=2))
    print(f"[parse_logs] {log_path.name}: {len(rows)} row(s), format={fmt}")
    return result


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Parse logs for a case.")
    p.add_argument("log_path")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = parse_logs(args.log_path, args.case_id)
    print(json.dumps(result, indent=2))
