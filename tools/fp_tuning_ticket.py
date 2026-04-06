"""
tool: fp_tuning_ticket
----------------------
FP tuning ticket context builder and helpers.

The tuning ticket is now written by the local Claude Desktop agent using the
``write_fp_tuning`` MCP prompt, then persisted via
``save_report(type=fp_tuning_ticket)``.

This module retains ``_SYSTEM_PROMPT``, ``_SYSTEM_CACHED``, and
``_build_context()`` which the MCP prompt imports.  It also keeps
``_resolve_workspace_id()`` and ``_build_recurrence_context()`` for
live-query resolution and prior-case recall.

Unlike fp_ticket (2-sentence closure comment), the tuning ticket is a full
engineering handoff document with root cause analysis, before/after query
modifications, impact assessment, and recurrence data.  Auto-closes the case
with disposition ``false_positive`` on save.

Output (via save_report):
  cases/<case_id>/artefacts/fp_comms/fp_tuning_ticket.html
  cases/<case_id>/artefacts/fp_comms/fp_tuning_ticket_manifest.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, utcnow

# ---------------------------------------------------------------------------
# Workspace resolution helpers (shared with fp_ticket)
# ---------------------------------------------------------------------------

_CLIENT_ENTITIES_PATH = Path(__file__).resolve().parent.parent / "config" / "client_entities.json"


def _resolve_workspace_id(alert_data: dict | None, case_id: str) -> str | None:
    """
    Resolve the Log Analytics workspace ID from alert data or client entities.

    Resolution order:
      1. alert_data["WorkspaceId"] (direct Sentinel workspace GUID)
      2. alert_data["TenantId"]    matched against client_entities.json workspace_id
      3. alert_data["DataSources"] matched against client_entities.json (workspace name contains client name)
    """
    if not alert_data or not isinstance(alert_data, dict):
        return None

    wid = alert_data.get("WorkspaceId")
    if wid:
        return wid

    try:
        with open(_CLIENT_ENTITIES_PATH) as f:
            import json as _json
            entities = _json.load(f).get("clients", [])
    except (FileNotFoundError, Exception) as exc:
        log_error(case_id, "fp_tuning_ticket.resolve_workspace", str(exc), severity="info")
        return None

    def _get_ws(ent: dict) -> str:
        platforms = ent.get("platforms", {})
        if isinstance(platforms, dict):
            sentinel = platforms.get("sentinel", {})
            if isinstance(sentinel, dict) and sentinel.get("workspace_id"):
                return sentinel["workspace_id"]
        return ent.get("workspace_id", "")

    tenant_id = alert_data.get("TenantId", "")
    if tenant_id:
        for ent in entities:
            ws = _get_ws(ent)
            if ws and ws.lower() == tenant_id.lower():
                return ws

    data_sources = alert_data.get("DataSources", [])
    if data_sources:
        ds_str = " ".join(data_sources).lower()
        for ent in entities:
            ws = _get_ws(ent)
            if ent.get("name", "").lower() in ds_str and ws:
                return ws

    return None


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a SOC analyst writing a SIEM engineering tuning ticket. This document will be \
handed to a detection engineering team to modify or suppress a detection rule that is \
producing false positives.

Write a structured tuning ticket with the following sections. Use markdown formatting.

## SECTIONS (all required)

### 1. Detection Rule Identification
- Rule name / ID / analytic ID
- Detection platform (Sentinel, CrowdStrike, Defender, Entra ID, Splunk, etc.)
- Data source table(s)
- MITRE ATT&CK technique (if mapped)

### 2. Original Detection Query
- The current rule logic (KQL, SPL, or pseudocode if not available)
- If the exact query is not provided, describe the detection logic as precisely as possible

### 3. False Positive Evidence
- Specific evidence from the case data that proves this is a false positive
- Entity details: user(s), host(s), IP(s), process(es) involved
- Why the detected activity is benign (reference enrichment verdicts, known-good patterns)

### 4. Root Cause Analysis
- WHY the rule triggered incorrectly (e.g. overly broad entity match, missing allowlist, \
  threshold too low, legitimate admin activity pattern)
- Whether this is a design flaw (rule too broad) or an environment-specific gap (known \
  software/user/IP not excluded)

### 5. Proposed Tuning
Provide SPECIFIC, implementable modifications:
- **Before:** the current query/logic that causes the FP
- **After:** the modified query/logic with the fix applied
- Explain each change

Tuning strategies to consider (pick the most appropriate):
- Entity allowlisting (user, host, IP, process)
- Query condition refinement (tighter WHERE clauses)
- Threshold adjustment (count/time window changes)
- Correlation enrichment (join with additional context tables)
- Severity downgrade (if the activity is real but low-risk)

### 6. Impact Assessment
- Will the proposed tuning suppress detection of real threats? Evaluate honestly.
- What monitoring gap (if any) does the tuning create?
- Recommend compensating controls if a gap is introduced

### 7. Recurrence
- Has this false positive pattern been seen before? (Use the prior case data provided)
- How many times? Over what period?
- Is this a recurring operational pattern that needs permanent exclusion?

RULES:
1. Be SPECIFIC — generic recommendations like "add an allowlist" are useless without \
   the actual entities to allow.
2. Always provide before/after query modifications when possible.
3. Reference specific evidence from the case data — never speculate.
4. Tone: technical, direct, structured. This is an engineering document, not a narrative.
5. The proposed tuning MUST be implementable by a SIEM engineer who has not seen the \
   original alert. Include all necessary context.
6. If the exact detection query is not available, propose tuning as pseudocode with \
   clear comments explaining the logic.

WORKSPACE QUERY TOOL
--------------------
If the `query_workspace` tool is available, you may run up to 2 focused KQL queries to:
- Retrieve the current detection rule logic
- Check the historical frequency of the FP pattern
- Verify that proposed exclusions do not suppress real detections

OUTPUT:
Return the complete markdown tuning ticket. Nothing else — no preamble, no sign-off.
"""

_SYSTEM_CACHED = [
    {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
]

# Tool: read-only KQL query against the alert workspace
_QUERY_WORKSPACE_TOOL = {
    "name": "query_workspace",
    "description": (
        "Execute a READ-ONLY KQL query against the Sentinel Log Analytics workspace "
        "associated with this alert. Use this to retrieve the current detection rule, "
        "check historical FP frequency, or validate that proposed exclusions would not "
        "suppress real threats. "
        "The query runs via `az monitor log-analytics query` and returns up to 50 rows as JSON. "
        "Keep queries focused and time-bounded (use ago(7d) or narrower). "
        "Do NOT use this for destructive operations — this is strictly read-only."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "kql": {
                "type": "string",
                "description": "The KQL query to execute. Must be a valid read-only query.",
            },
            "purpose": {
                "type": "string",
                "description": "Brief explanation of why this query is needed for the ticket.",
            },
        },
        "required": ["kql", "purpose"],
    },
}

# Maximum rows returned per query, maximum queries per ticket
_QUERY_MAX_ROWS = 50
_QUERY_MAX_CALLS = 2

# Tool: request clarification when critical info is missing
_CLARIFICATION_TOOL = {
    "name": "request_clarification",
    "description": (
        "Call this tool when essential information is missing — e.g. the detection "
        "platform cannot be determined, or the alert data is too ambiguous to produce "
        "a useful tuning ticket. Ask the analyst a specific question."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": "Specific question to ask the analyst",
            }
        },
        "required": ["question"],
    },
}


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _safe_load(path: Path, case_id: str = "") -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error(case_id, "fp_tuning_ticket.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _build_context(case_id: str) -> str:
    """Assemble case context from all available artefacts."""
    case_dir = CASES_DIR / case_id
    parts: list[str] = [f"# Case: {case_id}\n"]

    # Case metadata
    meta = _safe_load(case_dir / "case_meta.json", case_id)
    if meta:
        parts.append("## Case Metadata")
        parts.append(f"- Title: {meta.get('title', 'N/A')}")
        parts.append(f"- Severity: {meta.get('severity', 'N/A')}")
        parts.append(f"- Status: {meta.get('status', 'N/A')}")
        parts.append(f"- Attack Type: {meta.get('attack_type', 'N/A')}")
        parts.append(f"- Analyst: {meta.get('analyst', 'unassigned')}")
        parts.append(f"- Created: {meta.get('created_at', 'N/A')}")
        parts.append("")

    # IOC list
    iocs_data = _safe_load(case_dir / "iocs" / "iocs.json", case_id)
    if iocs_data:
        ioc_dict = iocs_data.get("iocs", {})
        parts.append("## Extracted IOCs")
        for ioc_type, vals in ioc_dict.items():
            if vals:
                parts.append(f"### {ioc_type.upper()} ({len(vals)})")
                for v in vals[:30]:
                    parts.append(f"  - {v}")
        parts.append("")

    # Verdict summary
    verdict = _safe_load(
        case_dir / "artefacts" / "enrichment" / "verdict_summary.json", case_id
    )
    if verdict:
        parts.append("## Enrichment Verdict Summary")
        parts.append(f"- Total IOCs scored: {verdict.get('ioc_count', 0)}")
        parts.append(f"- Malicious: {len(verdict.get('high_priority', []))}")
        parts.append(f"- Suspicious: {len(verdict.get('needs_review', []))}")
        parts.append(f"- Clean: {len(verdict.get('clean', []))}")
        ioc_details = verdict.get("iocs", {})
        if ioc_details:
            parts.append("\n### Per-IOC Verdict")
            for ioc_val, info in list(ioc_details.items())[:30]:
                providers = ", ".join(
                    f"{p}:{v}" for p, v in info.get("providers", {}).items()
                )
                parts.append(
                    f"  - `{ioc_val}` | {info.get('ioc_type','?').upper()} | "
                    f"{info.get('verdict','?').upper()} ({info.get('confidence','?')}) | "
                    f"{providers}"
                )
        parts.append("")

    # Investigation report (capped)
    report_path = case_dir / "reports" / "investigation_report.md"
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8")
        if len(report_text) > 6000:
            report_text = report_text[:6000] + "\n\n[...report truncated...]"
        parts.append("## Investigation Report (excerpt)")
        parts.append(report_text)
        parts.append("")

    # Log files
    logs_dir = case_dir / "logs"
    if logs_dir.exists():
        log_chunks: list[str] = []
        total_chars = 0
        for log_file in sorted(logs_dir.iterdir()):
            if log_file.is_file() and total_chars < 4000:
                try:
                    text = log_file.read_text(encoding="utf-8", errors="replace")
                    if len(text) > 2000:
                        text = text[:2000] + "\n[...truncated...]"
                    log_chunks.append(f"### {log_file.name}\n{text}")
                    total_chars += len(text)
                except Exception as exc:
                    log_error(case_id, "fp_tuning_ticket.read_log", str(exc),
                              severity="info", context={"file": str(log_file)})
        if log_chunks:
            parts.append("## Log Records")
            parts.extend(log_chunks)
            parts.append("")

    # Web captures
    web_dir = case_dir / "artefacts" / "web"
    if web_dir.exists():
        capture_chunks: list[str] = []
        total_chars = 0
        for page_txt in web_dir.rglob("page.txt"):
            if total_chars >= 2000:
                break
            try:
                text = page_txt.read_text(encoding="utf-8", errors="replace")
                host = page_txt.parent.name
                if len(text) > 800:
                    text = text[:800] + "\n[...truncated...]"
                capture_chunks.append(f"### Capture: {host}\n{text}")
                total_chars += len(text)
            except Exception as exc:
                log_error(case_id, "fp_tuning_ticket.read_capture", str(exc),
                          severity="info", context={"file": str(page_txt)})
        if capture_chunks:
            parts.append("## Web Captures")
            parts.extend(capture_chunks)
            parts.append("")

    # FP ticket (if already generated — provides the closure justification)
    fp_ticket_path = case_dir / "artefacts" / "fp_comms" / "fp_ticket.md"
    if fp_ticket_path.exists():
        fp_text = fp_ticket_path.read_text(encoding="utf-8")
        if len(fp_text) > 1000:
            fp_text = fp_text[:1000] + "\n[...truncated...]"
        parts.append("## FP Closure Comment (already generated)")
        parts.append(fp_text)
        parts.append("")

    return "\n".join(parts)


def _build_recurrence_context(case_id: str, alert_data: str) -> str:
    """Check prior cases for recurrence of similar FP patterns."""
    try:
        from tools.recall import recall
        from tools.extract_iocs import extract_iocs_from_text

        # Extract IOCs from alert data for recall search
        iocs_result = extract_iocs_from_text(alert_data)
        iocs = iocs_result.get("iocs", {})
        flat_iocs: list[str] = []
        for vals in iocs.values():
            flat_iocs.extend(vals[:10])

        if not flat_iocs:
            return ""

        recall_result = recall(iocs=flat_iocs[:20])
        prior_cases = recall_result.get("prior_cases", [])
        known_iocs = recall_result.get("known_iocs", [])

        if not prior_cases and not known_iocs:
            return ""

        parts = ["## Prior Case Recurrence Data\n"]
        if prior_cases:
            parts.append(f"**{len(prior_cases)} prior case(s) with overlapping IOCs:**")
            for pc in prior_cases[:10]:
                parts.append(
                    f"- {pc.get('case_id', '?')} — {pc.get('title', 'N/A')} "
                    f"(disposition: {pc.get('disposition', 'N/A')}, "
                    f"overlap: {', '.join(pc.get('overlapping_iocs', [])[:5])})"
                )
            parts.append("")

        if known_iocs:
            parts.append(f"**{len(known_iocs)} IOC(s) seen in prior investigations:**")
            for ki in known_iocs[:10]:
                parts.append(
                    f"- `{ki.get('ioc', '?')}` — seen in {ki.get('case_count', '?')} case(s), "
                    f"last: {ki.get('last_seen', 'N/A')}"
                )
            parts.append("")

        return "\n".join(parts)

    except Exception as exc:
        log_error(case_id, "fp_tuning_ticket.recall", str(exc), severity="warning")
        return ""


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def fp_tuning_ticket(case_id, alert_data, query_text=None, platform=None, live_query=False):
    """Stub — direct LLM generation removed.

    Use the ``write_fp_tuning`` MCP prompt to generate the tuning ticket via
    the local Claude Desktop agent, then call
    ``save_report(type=fp_tuning_ticket)`` to persist it.
    """
    return {
        "status": "use_prompt",
        "prompt": "write_fp_tuning",
        "save_tool": "save_report",
        "save_args": {"report_type": "fp_tuning_ticket"},
        "case_id": case_id,
        "ts": utcnow(),
    }


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Generate a SIEM engineering tuning ticket for a case.")
    p.add_argument("--case",        required=True, dest="case_id")
    p.add_argument("--alert",       metavar="FILE", help="Path to alert JSON/text file")
    p.add_argument("--alert-text",  metavar="TEXT", help="Inline alert string")
    p.add_argument("--query",       metavar="FILE", help="Path to KQL rule file (Sentinel)")
    p.add_argument("--query-text",  metavar="KQL",  help="Inline KQL string")
    p.add_argument("--platform",    choices=["sentinel", "crowdstrike", "defender", "entra", "cloudapps", "splunk"])
    p.add_argument("--live-query",  action="store_true",
                   help="Enable read-only KQL queries against the alert workspace (requires az CLI auth)")
    args = p.parse_args()

    if args.alert:
        alert_str = Path(args.alert).read_text(encoding="utf-8")
    elif args.alert_text:
        alert_str = args.alert_text
    else:
        p.error("Provide --alert or --alert-text")

    query_str = None
    if args.query:
        query_str = Path(args.query).read_text(encoding="utf-8")
    elif args.query_text:
        query_str = args.query_text

    result = fp_tuning_ticket(
        case_id=args.case_id,
        alert_data=alert_str,
        query_text=query_str,
        platform=args.platform,
        live_query=args.live_query,
    )
    print(json.dumps(result, indent=2, default=str))
