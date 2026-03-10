"""
tool: timeline_reconstruct
--------------------------
Forensic timeline reconstruction from all available case artefacts.

Scans every time-stamped artefact in the case directory (web captures,
email headers, enrichment first/last seen, sandbox detonations, triage,
anomaly events, parsed logs, IOC index entries) and assembles a unified
chronological timeline.

When ANTHROPIC_API_KEY is set, an LLM step analyses the raw events to
produce MITRE ATT&CK phase mapping, dwell-time gap analysis, key event
identification, and a narrative summary.

Output:
  cases/<case_id>/artefacts/timeline/timeline.json

Usage (standalone):
  python3 tools/timeline_reconstruct.py --case IV_CASE_001
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_model, load_json, log_error, save_json, utcnow


# ---------------------------------------------------------------------------
# System prompt (cached)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a forensic timeline analyst specialising in cybersecurity incident \
reconstruction. Given a chronologically sorted list of events extracted from \
investigation artefacts, you will:

1. Map events to MITRE ATT&CK tactics (Initial Access, Execution, Persistence, \
   Privilege Escalation, Defence Evasion, Credential Access, Discovery, Lateral \
   Movement, Collection, Command and Control, Exfiltration, Impact).
2. Identify significant dwell-time gaps between activity clusters.
3. Select the 5-10 most forensically important events with reasoning.
4. Write a concise 2-3 sentence narrative summary of the attack timeline.

Produce a structured timeline analysis with all required fields.\
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_optional(path: Path):
    """Load JSON, returning None on missing file or error."""
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "timeline_reconstruct.load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _add(events: list[dict], timestamp: str | None, source: str,
         event_type: str, detail: str) -> None:
    """Append an event if timestamp is truthy."""
    if timestamp:
        events.append({
            "timestamp": str(timestamp),
            "source": source,
            "event_type": event_type,
            "detail": detail,
        })


# ---------------------------------------------------------------------------
# Event extraction from artefacts
# ---------------------------------------------------------------------------

def _extract_events(case_id: str) -> tuple[list[dict], list[str]]:
    """
    Scan all available case artefacts and extract timestamped events.
    Returns (events_list, sources_scanned).
    """
    case_dir = CASES_DIR / case_id
    events: list[dict] = []
    sources: list[str] = []

    # -- case_meta.json -------------------------------------------------------
    meta = _load_optional(case_dir / "case_meta.json")
    if meta:
        sources.append("case_meta.json")
        _add(events, meta.get("created_at") or meta.get("created"),
             "case_meta.json", "case_created",
             f"Case {case_id} created — {meta.get('title', 'N/A')}")

    # -- artefacts/web/*/capture_manifest.json --------------------------------
    web_dir = case_dir / "artefacts" / "web"
    if web_dir.exists():
        for manifest_path in web_dir.rglob("capture_manifest.json"):
            data = _load_optional(manifest_path)
            if not data:
                continue
            rel = str(manifest_path.relative_to(case_dir))
            sources.append(rel)
            _add(events, data.get("captured_at") or data.get("ts"),
                 rel, "web_capture",
                 f"Captured {data.get('url', 'unknown URL')}"
                 + (" [CLOUDFLARE BLOCKED]" if data.get("cloudflare_blocked") else ""))

    # -- artefacts/web/*/redirect_chain.json ----------------------------------
    if web_dir.exists():
        for chain_path in web_dir.rglob("redirect_chain.json"):
            data = _load_optional(chain_path)
            if not data or not isinstance(data, list):
                continue
            rel = str(chain_path.relative_to(case_dir))
            if rel not in sources:
                sources.append(rel)
            for i, hop in enumerate(data):
                _add(events, hop.get("timestamp") or hop.get("ts"),
                     rel, "redirect_hop",
                     f"Hop {i}: {hop.get('status', '?')} → {hop.get('url', '?')}")

    # -- artefacts/email/email_analysis.json ----------------------------------
    email_data = _load_optional(case_dir / "artefacts" / "email" / "email_analysis.json")
    if email_data:
        sources.append("artefacts/email/email_analysis.json")
        # Date header
        _add(events, email_data.get("date"),
             "email_analysis", "email_sent",
             f"Email sent: {email_data.get('subject', 'N/A')}")
        # Received chain
        for entry in email_data.get("received_chain", []):
            _add(events, entry.get("timestamp") or entry.get("date"),
                 "email_analysis", "email_received_hop",
                 f"Received by {entry.get('by', '?')} from {entry.get('from', '?')}")

    # -- artefacts/enrichment/enrichment.json ---------------------------------
    enrichment = _load_optional(case_dir / "artefacts" / "enrichment" / "enrichment.json")
    if enrichment:
        sources.append("artefacts/enrichment/enrichment.json")
        ioc_results = enrichment.get("results", enrichment)
        if isinstance(ioc_results, dict):
            for ioc_val, providers in ioc_results.items():
                if not isinstance(providers, dict):
                    continue
                for provider, result in providers.items():
                    if not isinstance(result, dict):
                        continue
                    for ts_key in ("first_seen", "last_seen", "created", "registered"):
                        ts = result.get(ts_key)
                        if ts:
                            _add(events, ts,
                                 "enrichment", f"ioc_{ts_key}",
                                 f"{ioc_val} ({provider}): {ts_key}")

    # -- artefacts/sandbox/sandbox_results.json --------------------------------
    sandbox = _load_optional(case_dir / "artefacts" / "sandbox" / "sandbox_results.json")
    if sandbox:
        sources.append("artefacts/sandbox/sandbox_results.json")
        results_list = sandbox.get("results", [])
        if isinstance(results_list, list):
            for entry in results_list:
                if not isinstance(entry, dict):
                    continue
                _add(events, entry.get("submitted_at") or entry.get("timestamp") or entry.get("ts"),
                     "sandbox_results", "sandbox_detonation",
                     f"Sandbox: {entry.get('provider', '?')} — {entry.get('sha256', '?')[:16]}...")
        elif isinstance(results_list, dict):
            for sha, providers in results_list.items():
                if not isinstance(providers, dict):
                    continue
                for prov, result in providers.items():
                    if not isinstance(result, dict):
                        continue
                    _add(events, result.get("submitted_at") or result.get("timestamp") or result.get("ts"),
                         "sandbox_results", "sandbox_detonation",
                         f"Sandbox: {prov} — {sha[:16]}...")

    # -- artefacts/triage/triage_summary.json ---------------------------------
    triage = _load_optional(case_dir / "artefacts" / "triage" / "triage_summary.json")
    if triage:
        sources.append("artefacts/triage/triage_summary.json")
        _add(events, triage.get("ts") or triage.get("timestamp"),
             "triage_summary", "triage_completed",
             f"Triage completed — {triage.get('total_checked', '?')} IOCs checked")

    # -- artefacts/anomalies/anomaly_report.json ------------------------------
    anomalies = _load_optional(case_dir / "artefacts" / "anomalies" / "anomaly_report.json")
    if anomalies:
        sources.append("artefacts/anomalies/anomaly_report.json")
        findings = anomalies.get("findings", anomalies.get("anomalies", []))
        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                _add(events,
                     finding.get("timestamp") or finding.get("event_time"),
                     "anomaly_report", f"anomaly_{finding.get('type', 'unknown')}",
                     f"[{finding.get('severity', '?').upper()}] {finding.get('detail', finding.get('description', '?'))}")

    # -- logs/*.parsed.json ---------------------------------------------------
    logs_dir = case_dir / "logs"
    if logs_dir.exists():
        for parsed_path in logs_dir.glob("*.parsed.json"):
            data = _load_optional(parsed_path)
            if not data:
                continue
            rel = str(parsed_path.relative_to(case_dir))
            sources.append(rel)
            rows = []
            if isinstance(data, dict):
                rows = data.get("rows_sample", data.get("rows", data.get("events", [])))
            elif isinstance(data, list):
                rows = data
            for row in rows:
                if not isinstance(row, dict):
                    continue
                ts = (row.get("timestamp") or row.get("TimeGenerated")
                      or row.get("EventTime") or row.get("_time") or row.get("ts"))
                if ts:
                    event_type = row.get("EventID", row.get("event_type", "log_event"))
                    detail = row.get("Message", row.get("message",
                             row.get("summary", json.dumps(row, default=str)[:200])))
                    _add(events, ts, rel, str(event_type), str(detail)[:300])

    # -- registry/ioc_index.json (filtered to this case) ----------------------
    ioc_index_path = CASES_DIR.parent / "registry" / "ioc_index.json"
    ioc_index = _load_optional(ioc_index_path)
    if ioc_index:
        found_any = False
        for ioc_val, entry in ioc_index.items():
            if not isinstance(entry, dict):
                continue
            cases = entry.get("cases", [])
            if case_id not in cases:
                continue
            if not found_any:
                sources.append("registry/ioc_index.json")
                found_any = True
            _add(events, entry.get("first_seen"),
                 "ioc_index", "ioc_first_seen",
                 f"IOC first seen globally: {ioc_val}")
            _add(events, entry.get("last_seen"),
                 "ioc_index", "ioc_last_seen",
                 f"IOC last seen globally: {ioc_val}")

    # Deduplicate sources list
    sources = list(dict.fromkeys(sources))

    return events, sources


# ---------------------------------------------------------------------------
# LLM analysis step
# ---------------------------------------------------------------------------

def _llm_analyse(case_id: str, events: list[dict]) -> dict | None:
    """Send events to Claude for timeline analysis. Returns structured data or None."""
    try:
        from tools.structured_llm import structured_call
        from tools.schemas import TimelineAnalysis
    except ImportError as exc:
        log_error(case_id, "timeline_reconstruct.import", str(exc),
                  severity="info")
        return None

    system_cached = [
        {
            "type": "text",
            "text": _SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
    ]

    # Prepare event list with indices for the LLM
    indexed_events = [
        {"index": i, **evt} for i, evt in enumerate(events)
    ]

    user_message = (
        f"Analyse the following {len(events)} forensic timeline events "
        f"from case {case_id} and provide your structured analysis.\n\n"
        f"```json\n{json.dumps(indexed_events, indent=2, default=str)}\n```"
    )

    _meta = _load_optional(CASES_DIR / case_id / "case_meta.json")
    _severity = (_meta or {}).get("severity", "medium")
    _model = get_model("timeline", _severity)
    print(f"[timeline_reconstruct] Querying {_model} with {len(events)} events...")

    try:
        result, usage = structured_call(
            model=_model,
            system=system_cached,
            messages=[{"role": "user", "content": user_message}],
            output_schema=TimelineAnalysis,
            max_tokens=4096,
        )
    except Exception as exc:
        log_error(case_id, "timeline_reconstruct.llm_call", str(exc),
                  severity="error", context={"model": _model})
        print(f"[timeline_reconstruct] LLM call failed: {exc}")
        return None

    tokens_in = usage.get("input_tokens", 0)
    tokens_out = usage.get("output_tokens", 0)
    tokens_cache_read = usage.get("cache_read_input_tokens", 0)
    tokens_cache_write = usage.get("cache_creation_input_tokens", 0)

    print(
        f"[timeline_reconstruct] Tokens: {tokens_in} in / {tokens_out} out "
        f"| cache_read={tokens_cache_read} cache_write={tokens_cache_write}"
    )

    if not result:
        log_error(case_id, "timeline_reconstruct.llm_no_structured_output",
                  "LLM did not return structured timeline analysis",
                  severity="warning")
        print("[timeline_reconstruct] LLM did not return structured output")
        return None

    return result.model_dump()


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def timeline_reconstruct(case_id: str) -> dict:
    """
    Reconstruct a forensic timeline for *case_id* from all available artefacts.

    Returns a manifest dict with status, event count, and output path.
    Writes the timeline to:
      cases/<case_id>/artefacts/timeline/timeline.json
    """
    print(f"[timeline_reconstruct] Scanning artefacts for case {case_id}...")

    # ── 1. Extract events from all sources ───────────────────────────────
    try:
        events, sources = _extract_events(case_id)
    except Exception as exc:
        log_error(case_id, "timeline_reconstruct.extract_events", str(exc),
                  severity="error")
        return {
            "status": "error",
            "reason": f"Failed to extract events: {exc}",
            "case_id": case_id,
            "ts": utcnow(),
        }

    print(f"[timeline_reconstruct] Extracted {len(events)} events from {len(sources)} source(s)")

    if not events:
        return {
            "status": "skipped",
            "reason": "No timestamped events found in case artefacts.",
            "case_id": case_id,
            "total_events": 0,
            "sources_scanned": sources,
            "ts": utcnow(),
        }

    # ── 2. Sort events chronologically ───────────────────────────────────
    events.sort(key=lambda e: e.get("timestamp", ""))

    # ── 3. LLM analysis (optional) ───────────────────────────────────────
    llm_analysis = None
    if ANTHROPIC_KEY and events:
        llm_analysis = _llm_analyse(case_id, events)

    # ── 4. Build output ──────────────────────────────────────────────────
    timeline_data: dict = {
        "case_id": case_id,
        "generated_at": utcnow(),
        "total_events": len(events),
        "sources_scanned": sources,
        "events": events,
    }

    if llm_analysis:
        timeline_data["analysis"] = llm_analysis

    # ── 5. Write artefact ────────────────────────────────────────────────
    out_dir = CASES_DIR / case_id / "artefacts" / "timeline"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "timeline.json"

    save_json(out_path, timeline_data)

    print(f"[timeline_reconstruct] Timeline written to {out_path}")

    # ── 6. Build manifest ────────────────────────────────────────────────
    manifest = {
        "status": "ok",
        "case_id": case_id,
        "total_events": len(events),
        "sources_scanned": sources,
        "llm_analysis": bool(llm_analysis),
        "timeline_path": str(out_path),
        "ts": utcnow(),
    }

    return manifest


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(
        description="Forensic timeline reconstruction from case artefacts."
    )
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = timeline_reconstruct(args.case_id)
    print(json.dumps(result, indent=2, default=str))
