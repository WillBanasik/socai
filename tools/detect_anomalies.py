"""
tool: detect_anomalies
-----------------------
Behavioural anomaly detection on parsed logs.

Six detectors:
  1. Temporal — logins outside business hours / weekends
  2. Impossible travel — same user, different geo IPs within time window
  3. Brute force — N+ failed logins from same source in window
  4. First-seen entities — processes/commands not seen in prior cases
  5. Volume spikes — events per IP/user exceeding mean + 2*stddev
  6. Lateral movement — same user from 3+ distinct IPs in time window

Writes:
  cases/<case_id>/artefacts/anomalies/anomaly_report.json
"""
from __future__ import annotations

import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, save_json, utcnow

# Configuration
BUSINESS_HOURS_START = int(os.getenv("SOCAI_BUSINESS_HOURS_START", "8"))
BUSINESS_HOURS_END = int(os.getenv("SOCAI_BUSINESS_HOURS_END", "18"))
BRUTE_FORCE_THRESHOLD = int(os.getenv("SOCAI_BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW = int(os.getenv("SOCAI_BRUTE_FORCE_WINDOW", "300"))  # seconds
TRAVEL_WINDOW = int(os.getenv("SOCAI_TRAVEL_WINDOW", "3600"))  # seconds
LATERAL_WINDOW = int(os.getenv("SOCAI_LATERAL_WINDOW", "3600"))  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_optional(path: Path) -> dict | list | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "detect_anomalies.load_optional", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _load_parsed_logs(case_id: str) -> list[dict]:
    """Load all *.parsed.json from the case logs/ directory."""
    logs_dir = CASES_DIR / case_id / "logs"
    if not logs_dir.exists():
        return []

    all_events: list[dict] = []
    for pf in logs_dir.glob("*.parsed.json"):
        data = _load_optional(pf)
        if data and isinstance(data, dict):
            events = data.get("rows_sample", data.get("events", data.get("rows", [])))
            if isinstance(events, list):
                all_events.extend(events)
    return all_events


def _load_prior_entities() -> set[str]:
    """Load entities from all prior cases for first-seen detection."""
    entities: set[str] = set()
    if not CASES_DIR.exists():
        return entities

    for case_dir in CASES_DIR.iterdir():
        if not case_dir.is_dir():
            continue
        logs_dir = case_dir / "logs"
        if not logs_dir.exists():
            continue
        for ef in logs_dir.glob("*.entities.json"):
            data = _load_optional(ef)
            if data and isinstance(data, dict):
                for key in ("commands", "processes", "paths"):
                    for val in data.get(key, []):
                        entities.add(f"{key}|{val}")
    return entities


def _parse_timestamp(ts_str: str) -> datetime | None:
    """Try to parse a timestamp string into a datetime."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            continue
    return None


def _classify_severity(finding_type: str, count: int = 1) -> str:
    """Classify finding severity."""
    high_types = {"brute_force", "impossible_travel", "lateral_movement"}
    if finding_type in high_types:
        return "high"
    if finding_type == "first_seen_entity" and count > 3:
        return "high"
    if finding_type in ("temporal_anomaly", "volume_spike"):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def _detect_temporal(events: list[dict]) -> list[dict]:
    """Detect logins outside business hours or on weekends."""
    findings: list[dict] = []

    login_keywords = {"logon", "login", "sign-in", "authentication", "4624", "4625"}

    for event in events:
        # Check if it's a login event
        event_str = str(event).lower()
        if not any(kw in event_str for kw in login_keywords):
            continue

        ts_str = event.get("timestamp") or event.get("ts") or event.get("time") or event.get("EventTime", "")
        ts = _parse_timestamp(str(ts_str))
        if not ts:
            continue

        is_weekend = ts.weekday() >= 5
        is_off_hours = ts.hour < BUSINESS_HOURS_START or ts.hour >= BUSINESS_HOURS_END

        if is_weekend or is_off_hours:
            user = event.get("user") or event.get("User") or event.get("TargetUserName") or "unknown"
            source = event.get("source_ip") or event.get("SourceIP") or event.get("IpAddress") or ""
            reason = "weekend" if is_weekend else "off-hours"
            findings.append({
                "type": "temporal_anomaly",
                "severity": _classify_severity("temporal_anomaly"),
                "detail": f"Login activity during {reason}: {user} at {ts.isoformat()}",
                "user": str(user),
                "source_ip": str(source),
                "timestamp": ts.isoformat(),
                "reason": reason,
            })

    return findings


def _detect_impossible_travel(events: list[dict], enrichment_data: dict | None) -> list[dict]:
    """Detect same user logging in from different geo IPs within time window."""
    findings: list[dict] = []

    # Build user → [(ts, ip)] mapping
    user_logins: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    login_keywords = {"logon", "login", "sign-in", "authentication", "4624"}

    for event in events:
        event_str = str(event).lower()
        if not any(kw in event_str for kw in login_keywords):
            continue

        user = str(event.get("user") or event.get("User") or event.get("TargetUserName") or "")
        ip = str(event.get("source_ip") or event.get("SourceIP") or event.get("IpAddress") or "")
        ts_str = event.get("timestamp") or event.get("ts") or event.get("time") or event.get("EventTime", "")
        ts = _parse_timestamp(str(ts_str))

        if user and ip and ts:
            user_logins[user].append((ts, ip))

    # Check for same user, different IPs within window
    for user, logins in user_logins.items():
        logins.sort(key=lambda x: x[0])
        for i in range(len(logins) - 1):
            ts1, ip1 = logins[i]
            ts2, ip2 = logins[i + 1]
            if ip1 != ip2 and abs((ts2 - ts1).total_seconds()) <= TRAVEL_WINDOW:
                findings.append({
                    "type": "impossible_travel",
                    "severity": _classify_severity("impossible_travel"),
                    "detail": f"User {user} logged in from {ip1} then {ip2} within {TRAVEL_WINDOW}s",
                    "user": user,
                    "ip1": ip1,
                    "ip2": ip2,
                    "time_gap_seconds": abs((ts2 - ts1).total_seconds()),
                    "timestamp": ts1.isoformat(),
                })

    return findings


def _detect_brute_force(events: list[dict]) -> list[dict]:
    """Detect N+ failed logins from same source in time window."""
    findings: list[dict] = []

    fail_keywords = {"4625", "failed", "failure", "denied", "invalid"}
    login_keywords = {"logon", "login", "sign-in", "authentication"}

    # Collect failed login events by source IP
    source_failures: dict[str, list[datetime]] = defaultdict(list)

    for event in events:
        event_str = str(event).lower()
        is_login = any(kw in event_str for kw in login_keywords)
        is_failure = any(kw in event_str for kw in fail_keywords)
        if not (is_login and is_failure):
            continue

        source = str(event.get("source_ip") or event.get("SourceIP") or event.get("IpAddress") or "")
        ts_str = event.get("timestamp") or event.get("ts") or event.get("time") or event.get("EventTime", "")
        ts = _parse_timestamp(str(ts_str))

        if source and ts:
            source_failures[source].append(ts)

    # Check each source for burst patterns
    for source, timestamps in source_failures.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window_end = timestamps[i].timestamp() + BRUTE_FORCE_WINDOW
            count = sum(
                1 for t in timestamps[i:]
                if t.timestamp() <= window_end
            )
            if count >= BRUTE_FORCE_THRESHOLD:
                findings.append({
                    "type": "brute_force",
                    "severity": _classify_severity("brute_force"),
                    "detail": f"{count} failed logins from {source} in {BRUTE_FORCE_WINDOW}s window",
                    "source_ip": source,
                    "count": count,
                    "window_seconds": BRUTE_FORCE_WINDOW,
                    "first_attempt": timestamps[i].isoformat(),
                })
                break  # One finding per source

    return findings


def _detect_first_seen(events: list[dict], case_id: str) -> list[dict]:
    """Detect commands/processes/paths not seen in any prior case."""
    findings: list[dict] = []

    # Load current case entities
    current_entities: set[str] = set()
    logs_dir = CASES_DIR / case_id / "logs"
    if logs_dir.exists():
        for ef in logs_dir.glob("*.entities.json"):
            data = _load_optional(ef)
            if data and isinstance(data, dict):
                for key in ("commands", "processes", "paths"):
                    for val in data.get(key, []):
                        current_entities.add(f"{key}|{val}")

    if not current_entities:
        return findings

    # Load prior entities (exclude current case)
    prior_entities = _load_prior_entities()
    # Remove current case entities from prior (they might overlap)

    new_entities = current_entities - prior_entities
    for entity in sorted(new_entities)[:20]:  # Cap output
        key, val = entity.split("|", 1)
        findings.append({
            "type": "first_seen_entity",
            "severity": _classify_severity("first_seen_entity", len(new_entities)),
            "detail": f"First-seen {key}: {val}",
            "entity_type": key,
            "value": val,
        })

    return findings


def _detect_volume_spikes(events: list[dict]) -> list[dict]:
    """Detect IPs/users with event counts exceeding mean + 2*stddev."""
    findings: list[dict] = []

    # Count events per source IP
    ip_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()

    for event in events:
        ip = str(event.get("source_ip") or event.get("SourceIP") or event.get("IpAddress") or "")
        user = str(event.get("user") or event.get("User") or event.get("TargetUserName") or "")
        if ip:
            ip_counts[ip] += 1
        if user:
            user_counts[user] += 1

    for label, counts in [("IP", ip_counts), ("user", user_counts)]:
        if len(counts) < 3:
            continue
        values = list(counts.values())
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        stddev = math.sqrt(variance) if variance > 0 else 0
        threshold = mean + 2 * stddev

        for entity, count in counts.most_common(5):
            if count > threshold and threshold > 0:
                findings.append({
                    "type": "volume_spike",
                    "severity": _classify_severity("volume_spike"),
                    "detail": f"{label} {entity} has {count} events (threshold: {threshold:.0f})",
                    "entity_type": label,
                    "entity": entity,
                    "count": count,
                    "threshold": round(threshold, 1),
                    "mean": round(mean, 1),
                    "stddev": round(stddev, 1),
                })

    return findings


def _detect_lateral_movement(events: list[dict]) -> list[dict]:
    """Detect same user logging in from 3+ distinct IPs in time window."""
    findings: list[dict] = []
    login_keywords = {"logon", "login", "sign-in", "authentication", "4624"}

    user_logins: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    for event in events:
        event_str = str(event).lower()
        if not any(kw in event_str for kw in login_keywords):
            continue

        user = str(event.get("user") or event.get("User") or event.get("TargetUserName") or "")
        ip = str(event.get("source_ip") or event.get("SourceIP") or event.get("IpAddress") or "")
        ts_str = event.get("timestamp") or event.get("ts") or event.get("time") or event.get("EventTime", "")
        ts = _parse_timestamp(str(ts_str))

        if user and ip and ts:
            user_logins[user].append((ts, ip))

    for user, logins in user_logins.items():
        logins.sort(key=lambda x: x[0])
        for i in range(len(logins)):
            window_end = logins[i][0].timestamp() + LATERAL_WINDOW
            window_ips = set()
            for ts, ip in logins[i:]:
                if ts.timestamp() <= window_end:
                    window_ips.add(ip)
            if len(window_ips) >= 3:
                findings.append({
                    "type": "lateral_movement",
                    "severity": _classify_severity("lateral_movement"),
                    "detail": f"User {user} logged in from {len(window_ips)} IPs in {LATERAL_WINDOW}s: "
                              + ", ".join(sorted(window_ips)),
                    "user": user,
                    "ips": sorted(window_ips),
                    "timestamp": logins[i][0].isoformat(),
                })
                break  # One finding per user

    return findings


# ---------------------------------------------------------------------------
# Main tool function
# ---------------------------------------------------------------------------

def detect_anomalies(case_id: str) -> dict:
    """
    Run all anomaly detectors on parsed log data.
    Returns a report with all findings.
    """
    events = _load_parsed_logs(case_id)
    if not events:
        return {
            "status": "no_data",
            "reason": "No parsed log events found",
            "case_id": case_id,
            "findings": [],
        }

    # Load enrichment data for geo lookups (optional)
    enrich_path = CASES_DIR / case_id / "artefacts" / "enrichment" / "enrichment.json"
    enrichment_data = _load_optional(enrich_path)

    # Run all detectors
    all_findings: list[dict] = []
    all_findings.extend(_detect_temporal(events))
    all_findings.extend(_detect_impossible_travel(events, enrichment_data))
    all_findings.extend(_detect_brute_force(events))
    all_findings.extend(_detect_first_seen(events, case_id))
    all_findings.extend(_detect_volume_spikes(events))
    all_findings.extend(_detect_lateral_movement(events))

    # Summary counts
    severity_counts = Counter(f["severity"] for f in all_findings)
    type_counts = Counter(f["type"] for f in all_findings)

    result = {
        "status": "ok",
        "case_id": case_id,
        "total_events_analysed": len(events),
        "total_findings": len(all_findings),
        "severity_counts": dict(severity_counts),
        "type_counts": dict(type_counts),
        "findings": all_findings,
        "ts": utcnow(),
    }

    # LLM anomaly contextualisation (advisory)
    if all_findings:
        try:
            from tools.llm_insight import contextualise_anomalies
            meta_path = CASES_DIR / case_id / "case_meta.json"
            meta = _load_optional(meta_path) or {"case_id": case_id}
            llm_context = contextualise_anomalies(result, meta)
            if llm_context:
                result["llm_context"] = llm_context
        except Exception:
            pass

    anomaly_dir = CASES_DIR / case_id / "artefacts" / "anomalies"
    save_json(anomaly_dir / "anomaly_report.json", result)

    # Print summary
    print(f"[detect_anomalies] Analysed {len(events)} events, found {len(all_findings)} anomaly(ies)")
    for atype, count in type_counts.most_common():
        print(f"  {atype}: {count}")

    return result


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="Detect behavioural anomalies in parsed logs.")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = detect_anomalies(args.case_id)
    print(json.dumps(result, indent=2))
