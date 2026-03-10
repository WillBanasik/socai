"""
tool: evtx_correlate
--------------------
Windows Event Log correlation — detects multi-step attack chains
across parsed EVTX log data.

Seven chain detectors:
  1. Brute force → success  (4625 failures then 4624 success)
  2. Lateral movement       (type 3 logon from internal IP → process creation)
  3. Persistence            (scheduled task 4698 / service install 7045 after logon)
  4. Privilege escalation   (low-priv parent → elevated child, or type 10 → group add)
  5. Account manipulation   (4720 account created → 4732 added to group)
  6. Kerberos abuse         (4768/4769 with RC4-HMAC encryption)
  7. Pass-the-hash          (NTLM type 3 logon without 4776 validation)

Writes:
  cases/<case_id>/artefacts/evtx/evtx_correlation.json

Usage (standalone):
  python3 tools/evtx_correlate.py --case IV_CASE_001
"""
from __future__ import annotations

import ipaddress
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_model, load_json, log_error, save_json, utcnow

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BRUTE_FORCE_THRESHOLD = int(os.getenv("SOCAI_BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW = int(os.getenv("SOCAI_BRUTE_FORCE_WINDOW", "300"))  # seconds

# Window (seconds) for lateral-movement logon→exec and persistence logon→install
_LATERAL_EXEC_WINDOW = 300
_PERSISTENCE_WINDOW = 600
_PRIV_ESC_WINDOW = 600
_ACCOUNT_MANIP_WINDOW = 600
_PTH_VALIDATION_WINDOW = 30  # seconds to look for nearby 4776

# Elevated / system processes (heuristic for priv-esc detection)
_LOW_PRIV_PARENTS = {"explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
                     "wscript.exe", "cscript.exe", "mshta.exe"}
_ELEVATED_CHILDREN = {"lsass.exe", "services.exe", "svchost.exe", "winlogon.exe",
                      "csrss.exe", "smss.exe", "wininit.exe", "taskmgr.exe",
                      "mmc.exe", "dism.exe", "bcdedit.exe", "vssadmin.exe",
                      "ntdsutil.exe", "dsquery.exe", "net.exe", "net1.exe",
                      "nltest.exe", "whoami.exe", "reg.exe", "sc.exe"}

# Severity mapping
_CHAIN_SEVERITY: dict[str, str] = {
    "brute_force_success": "high",
    "lateral_movement": "high",
    "kerberos_abuse": "high",
    "pass_the_hash": "high",
    "persistence": "medium",
    "privilege_escalation": "medium",
    "account_manipulation": "medium",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_optional(path: Path) -> dict | list | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "evtx_correlate.load_optional", str(exc),
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
            events = data.get("rows_sample", [])
            if isinstance(events, list):
                all_events.extend(events)
    return all_events


def _parse_ts(raw: str) -> datetime | None:
    """Parse an ISO-format timestamp string, returning None on failure."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
        # Ensure timezone-aware (assume UTC if naive)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _normalize_event(evt: dict) -> dict | None:
    """Return a standardised event dict, or None if timestamp is unparseable."""
    ts_raw = str(evt.get("TimeCreated") or evt.get("timestamp") or "")
    ts = _parse_ts(ts_raw)
    if ts is None:
        return None

    # Event ID — coerce to int
    raw_eid = evt.get("EventID", "")
    try:
        event_id = int(raw_eid)
    except (ValueError, TypeError):
        event_id = 0

    # Logon type — coerce to int or None
    raw_lt = evt.get("LogonType")
    logon_type: int | None = None
    if raw_lt is not None:
        try:
            logon_type = int(raw_lt)
        except (ValueError, TypeError):
            logon_type = None

    return {
        "event_id": event_id,
        "timestamp": ts,
        "source_ip": str(evt.get("SourceIP") or evt.get("IpAddress") or ""),
        "target_user": str(evt.get("TargetUserName") or evt.get("UserName") or ""),
        "logon_type": logon_type,
        "process_name": str(evt.get("ProcessName") or evt.get("NewProcessName") or "").lower(),
        "parent_process": str(evt.get("ParentProcessName") or "").lower(),
        "domain": str(evt.get("TargetDomainName") or ""),
        "service_name": str(evt.get("ServiceName") or ""),
        "task_name": str(evt.get("TaskName") or ""),
        "encryption_type": str(evt.get("EncryptionType") or evt.get("TicketEncryptionType") or ""),
        "logon_process": str(evt.get("LogonProcessName") or ""),
        "subject_sid": str(evt.get("SubjectUserSid") or ""),
        "group_name": str(evt.get("TargetUserName") or evt.get("GroupName") or ""),
        "raw": evt,
    }


def _is_private_ip(ip_str: str) -> bool:
    """Check whether an IP address is RFC 1918 / private."""
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return False


def _basename(proc: str) -> str:
    """Extract filename from a full process path."""
    if not proc:
        return ""
    return proc.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()


# ---------------------------------------------------------------------------
# Attack chain detectors
# ---------------------------------------------------------------------------


def _detect_brute_force_success(events: list[dict]) -> list[dict]:
    """
    Brute force followed by successful logon.
    4625 failures then 4624 success from same source_ip within window.
    """
    chains: list[dict] = []

    # Group events by source_ip
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["event_id"] in (4625, 4624) and e["source_ip"]:
            by_ip[e["source_ip"]].append(e)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda x: x["timestamp"])

        failures: list[dict] = []
        for e in ip_events:
            if e["event_id"] == 4625:
                failures.append(e)
            elif e["event_id"] == 4624 and len(failures) >= BRUTE_FORCE_THRESHOLD:
                # Check window: failures must be within BRUTE_FORCE_WINDOW of the success
                first_fail_ts = failures[0]["timestamp"]
                success_ts = e["timestamp"]
                window_secs = (success_ts - first_fail_ts).total_seconds()
                if window_secs <= BRUTE_FORCE_WINDOW:
                    chains.append({
                        "chain": "brute_force_success",
                        "severity": _CHAIN_SEVERITY["brute_force_success"],
                        "source_ip": ip,
                        "target_user": e["target_user"],
                        "failures": len(failures),
                        "success_time": success_ts.isoformat(),
                        "window_seconds": round(window_secs, 1),
                        "events": [f["raw"] for f in failures[-3:]] + [e["raw"]],
                    })
                    break  # One chain per IP

    return chains


def _detect_lateral_movement(events: list[dict]) -> list[dict]:
    """
    Type 3 (network) logon from internal IP followed by process creation (4688).
    """
    chains: list[dict] = []

    logons_type3: list[dict] = [
        e for e in events
        if e["event_id"] == 4624 and e["logon_type"] == 3
        and _is_private_ip(e["source_ip"])
    ]
    proc_creations: list[dict] = [
        e for e in events if e["event_id"] == 4688
    ]

    for logon in logons_type3:
        for proc in proc_creations:
            delta = (proc["timestamp"] - logon["timestamp"]).total_seconds()
            if 0 <= delta <= _LATERAL_EXEC_WINDOW:
                # Match by target user if available
                if logon["target_user"] and proc["target_user"] \
                        and logon["target_user"].lower() != proc["target_user"].lower():
                    continue
                chains.append({
                    "chain": "lateral_movement",
                    "severity": _CHAIN_SEVERITY["lateral_movement"],
                    "source_ip": logon["source_ip"],
                    "target_user": logon["target_user"],
                    "process": proc["process_name"],
                    "logon_time": logon["timestamp"].isoformat(),
                    "exec_time": proc["timestamp"].isoformat(),
                })
                break  # One chain per logon event

    return chains


def _detect_persistence(events: list[dict]) -> list[dict]:
    """
    Scheduled task (4698) or service install (7045) within 600s of a logon (4624).
    """
    chains: list[dict] = []

    logons: list[dict] = [e for e in events if e["event_id"] == 4624]
    persistence_events: list[dict] = [
        e for e in events if e["event_id"] in (4698, 7045)
    ]

    for pers in persistence_events:
        method = "scheduled_task" if pers["event_id"] == 4698 else "service_install"
        detail = pers["task_name"] if method == "scheduled_task" else pers["service_name"]

        for logon in logons:
            delta = (pers["timestamp"] - logon["timestamp"]).total_seconds()
            if 0 <= delta <= _PERSISTENCE_WINDOW:
                chains.append({
                    "chain": "persistence",
                    "severity": _CHAIN_SEVERITY["persistence"],
                    "method": method,
                    "target_user": logon["target_user"],
                    "logon_time": logon["timestamp"].isoformat(),
                    "persistence_time": pers["timestamp"].isoformat(),
                    "detail": detail or "unknown",
                })
                break  # One chain per persistence event

    return chains


def _detect_privilege_escalation(events: list[dict]) -> list[dict]:
    """
    Two heuristics:
      1. 4688 with low-privilege parent spawning elevated child process
      2. Type 10 (RemoteInteractive) logon followed by 4728/4732 (group add) within window
    """
    chains: list[dict] = []

    # Heuristic 1: suspicious parent → elevated child
    for e in events:
        if e["event_id"] != 4688:
            continue
        parent = _basename(e["parent_process"])
        child = _basename(e["process_name"])
        if parent in _LOW_PRIV_PARENTS and child in _ELEVATED_CHILDREN:
            chains.append({
                "chain": "privilege_escalation",
                "severity": _CHAIN_SEVERITY["privilege_escalation"],
                "method": "suspicious_parent_child",
                "target_user": e["target_user"],
                "detail": f"{parent} spawned {child}",
            })

    # Heuristic 2: type 10 logon → group membership change
    type10_logons = [e for e in events if e["event_id"] == 4624 and e["logon_type"] == 10]
    group_adds = [e for e in events if e["event_id"] in (4728, 4732)]

    for logon in type10_logons:
        for ga in group_adds:
            delta = (ga["timestamp"] - logon["timestamp"]).total_seconds()
            if 0 <= delta <= _PRIV_ESC_WINDOW:
                chains.append({
                    "chain": "privilege_escalation",
                    "severity": _CHAIN_SEVERITY["privilege_escalation"],
                    "method": "remote_logon_group_add",
                    "target_user": logon["target_user"],
                    "detail": f"Type 10 logon then added to group (EID {ga['event_id']})",
                })
                break

    return chains


def _detect_account_manipulation(events: list[dict]) -> list[dict]:
    """
    User account created (4720) followed by group add (4732) within window.
    """
    chains: list[dict] = []

    creates = [e for e in events if e["event_id"] == 4720]
    group_adds = [e for e in events if e["event_id"] == 4732]

    for cr in creates:
        for ga in group_adds:
            delta = (ga["timestamp"] - cr["timestamp"]).total_seconds()
            if 0 <= delta <= _ACCOUNT_MANIP_WINDOW:
                chains.append({
                    "chain": "account_manipulation",
                    "severity": _CHAIN_SEVERITY["account_manipulation"],
                    "created_user": cr["target_user"],
                    "group": ga.get("group_name", ga["domain"]),
                    "timestamps": {
                        "account_created": cr["timestamp"].isoformat(),
                        "group_add": ga["timestamp"].isoformat(),
                    },
                })
                break  # One chain per created account

    return chains


def _detect_kerberos_abuse(events: list[dict]) -> list[dict]:
    """
    4768/4769 with RC4-HMAC encryption (0x17) — potential Kerberoasting or
    overpass-the-hash.
    """
    chains: list[dict] = []

    for e in events:
        if e["event_id"] not in (4768, 4769):
            continue
        enc = e["encryption_type"].strip().lower()
        # 0x17 = 23 decimal = RC4-HMAC
        if enc in ("0x17", "23", "rc4-hmac", "rc4_hmac_md5"):
            chains.append({
                "chain": "kerberos_abuse",
                "severity": _CHAIN_SEVERITY["kerberos_abuse"],
                "target_user": e["target_user"],
                "encryption_type": e["encryption_type"],
                "event_id": e["event_id"],
                "timestamp": e["timestamp"].isoformat(),
            })

    return chains


def _detect_pass_the_hash(events: list[dict]) -> list[dict]:
    """
    Type 3 logon via NTLM (NtLmSsp) without a corresponding 4776
    credential validation event nearby.
    """
    chains: list[dict] = []

    # Collect all 4776 timestamps for quick lookup
    validation_times: list[datetime] = [
        e["timestamp"] for e in events if e["event_id"] == 4776
    ]
    validation_times.sort()

    ntlm_logons = [
        e for e in events
        if e["event_id"] == 4624 and e["logon_type"] == 3
        and "ntlmssp" in e["logon_process"].lower()
    ]

    for logon in ntlm_logons:
        # Check if any 4776 is within _PTH_VALIDATION_WINDOW seconds
        has_validation = False
        for vt in validation_times:
            delta = abs((logon["timestamp"] - vt).total_seconds())
            if delta <= _PTH_VALIDATION_WINDOW:
                has_validation = True
                break

        if not has_validation:
            chains.append({
                "chain": "pass_the_hash",
                "severity": _CHAIN_SEVERITY["pass_the_hash"],
                "source_ip": logon["source_ip"],
                "target_user": logon["target_user"],
                "timestamp": logon["timestamp"].isoformat(),
            })

    return chains


# ---------------------------------------------------------------------------
# LLM analysis (optional)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a Windows forensics expert specialising in EVTX event log analysis \
and attack chain reconstruction. You have deep expertise in Active Directory \
attack patterns, lateral movement techniques, persistence mechanisms, and \
credential abuse.

When presented with detected attack chains from Windows Event Logs, you:
- Reconstruct the likely attack narrative in chronological order
- Map each chain to MITRE ATT&CK tactics and techniques
- Assess attacker sophistication based on the techniques used
- Recommend specific detection rules for each observed pattern

Be precise and evidence-based. Only reference techniques supported by the \
provided event data."""

_SYSTEM_CACHED = [
    {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
]

def _llm_analyse(case_id: str, chains: list[dict]) -> dict | None:
    """Send detected chains to Claude for narrative and MITRE mapping."""
    if not ANTHROPIC_KEY:
        return None
    if not chains:
        return None

    import json as _json

    try:
        from tools.structured_llm import structured_call
        from tools.schemas import EvtxAnalysis
    except ImportError:
        log_error(case_id, "evtx_correlate.llm", "structured_llm or schemas not available",
                  severity="info")
        return None

    chains_text = _json.dumps(chains, indent=2, default=str)

    try:
        try:
            _meta = load_json(CASES_DIR / case_id / "case_meta.json")
        except Exception:
            _meta = {}
        _severity = _meta.get("severity", "medium")
        _model = get_model("evtx", _severity)
        print(f"[evtx_correlate] Querying {_model} for attack chain analysis...")

        result, usage = structured_call(
            model=_model,
            system=_SYSTEM_CACHED,
            messages=[{
                "role": "user",
                "content": (
                    f"Analyse the following detected attack chains from Windows Event Logs "
                    f"for case {case_id}. Provide your structured analysis.\n\n{chains_text}"
                ),
            }],
            output_schema=EvtxAnalysis,
            max_tokens=4096,
        )

        tokens_in = usage.get("input_tokens", 0)
        tokens_out = usage.get("output_tokens", 0)
        tokens_cache_read = usage.get("cache_read_input_tokens", 0)
        tokens_cache_write = usage.get("cache_creation_input_tokens", 0)
        print(
            f"[evtx_correlate] Tokens: {tokens_in} in / {tokens_out} out "
            f"| cache_read={tokens_cache_read} cache_write={tokens_cache_write}"
        )

        return result.model_dump() if result else None

    except Exception as exc:
        log_error(case_id, "evtx_correlate.llm", str(exc), severity="warning")
        print(f"[evtx_correlate] LLM analysis failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Main tool function
# ---------------------------------------------------------------------------


def evtx_correlate(case_id: str) -> dict:
    """
    Correlate Windows Event Log data to detect multi-step attack chains.
    Returns a dict with detected chains, summary, and optional LLM analysis.
    """
    raw_events = _load_parsed_logs(case_id)
    if not raw_events:
        return {"status": "no_logs", "reason": "No parsed log files found"}

    # Normalize events — skip those with unparseable timestamps
    events: list[dict] = []
    for evt in raw_events:
        norm = _normalize_event(evt)
        if norm is not None:
            events.append(norm)

    if not events:
        return {
            "status": "no_logs",
            "reason": "All events had unparseable timestamps",
        }

    # Sort by timestamp
    events.sort(key=lambda e: e["timestamp"])

    print(f"[evtx_correlate] Analysing {len(events)} normalised events "
          f"(from {len(raw_events)} raw) for case {case_id}...")

    # Run all detectors
    all_chains: list[dict] = []
    all_chains.extend(_detect_brute_force_success(events))
    all_chains.extend(_detect_lateral_movement(events))
    all_chains.extend(_detect_persistence(events))
    all_chains.extend(_detect_privilege_escalation(events))
    all_chains.extend(_detect_account_manipulation(events))
    all_chains.extend(_detect_kerberos_abuse(events))
    all_chains.extend(_detect_pass_the_hash(events))

    # Summary
    chain_summary: dict[str, int] = defaultdict(int)
    for c in all_chains:
        chain_summary[c["chain"]] += 1

    print(f"[evtx_correlate] Detected {len(all_chains)} attack chain(s)")
    for ctype, count in sorted(chain_summary.items()):
        print(f"  {ctype}: {count}")

    # Optional LLM analysis
    llm_analysis = _llm_analyse(case_id, all_chains)

    result = {
        "status": "ok",
        "case_id": case_id,
        "total_events_analysed": len(events),
        "chains": all_chains,
        "chain_summary": dict(chain_summary),
        "llm_analysis": llm_analysis,
        "manifest": {
            "raw_events": len(raw_events),
            "normalised_events": len(events),
            "chains_detected": len(all_chains),
            "llm_used": llm_analysis is not None,
            "ts": utcnow(),
        },
    }

    # Write output
    out_dir = CASES_DIR / case_id / "artefacts" / "evtx"
    save_json(out_dir / "evtx_correlation.json", result)

    return result


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="Correlate Windows EVTX logs for attack chains.")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = evtx_correlate(args.case_id)
    print(json.dumps(result, indent=2, default=str))
