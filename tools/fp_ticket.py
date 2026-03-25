"""
tool: fp_ticket
---------------
FP ticket context builder and helpers.

The FP ticket is now written by the local Claude Desktop agent using the
``write_fp_closure`` MCP prompt, then persisted via ``save_report``.

This module retains ``_SYSTEM_PROMPT``, ``_SYSTEM_CACHED``, and
``_build_context()`` which the MCP prompt imports.  It also keeps
``_resolve_workspace_id()`` for live-query resolution.

Output (via save_report):
  cases/<case_id>/artefacts/fp_comms/fp_ticket.md
  cases/<case_id>/artefacts/fp_comms/fp_ticket_manifest.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, utcnow

# ---------------------------------------------------------------------------
# Workspace resolution helpers
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

    # Direct workspace ID in alert
    wid = alert_data.get("WorkspaceId")
    if wid:
        return wid

    # Load client entities for fallback lookup
    try:
        with open(_CLIENT_ENTITIES_PATH) as f:
            import json as _json
            entities = _json.load(f).get("clients", [])
    except (FileNotFoundError, Exception) as exc:
        log_error(case_id, "fp_ticket.resolve_workspace", str(exc), severity="info")
        return None

    # Helper to extract sentinel workspace_id from an entity (new nested or legacy flat)
    def _get_ws(ent: dict) -> str:
        platforms = ent.get("platforms", {})
        if isinstance(platforms, dict):
            sentinel = platforms.get("sentinel", {})
            if isinstance(sentinel, dict) and sentinel.get("workspace_id"):
                return sentinel["workspace_id"]
        return ent.get("workspace_id", "")

    # Match by TenantId
    tenant_id = alert_data.get("TenantId", "")
    if tenant_id:
        for ent in entities:
            ws = _get_ws(ent)
            if ws and ws.lower() == tenant_id.lower():
                return ws

    # Match by DataSources name (e.g. "la-san-thungelasentinel" contains "thungela")
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
You are a SOC analyst closing a False Positive alert. Write a short FP closure comment \
(maximum two sentences) that explains why the alert poses no risk.

RULES:
1. Maximum TWO sentences. No headers, no tables, no bullet points, no markdown formatting.
2. Focus on WHY there is no risk — not on what the alert is or what fired.
3. Tailor the comment to the alert type:
   - IOC-based alerts (IPs, domains, URLs, hashes): state that no malicious indicators were identified \
     across threat intelligence sources (name the key ones checked if available: VirusTotal, AbuseIPDB, etc.).
   - Identity / authentication alerts (sign-ins, MFA, impossible travel): state that no evidence of \
     account compromise, credential abuse, or unauthorised access was found.
   - Endpoint / process alerts (suspicious execution, persistence, injection): state that no malicious \
     behaviour, payload delivery, or persistence mechanisms were confirmed.
   - Lateral movement / internal traffic alerts: state that no lateral movement, C2 communication, \
     or data exfiltration indicators were identified.
   - Data access / exfiltration alerts (DLP, unusual download, Key Vault access): state that the activity \
     is consistent with expected operational patterns and no data loss risk was identified.
4. Reference specific evidence from the case data (e.g. "enrichment confirmed all IPs are clean", \
   "sign-in originated from a known corporate location", "process is a legitimate scheduled task").
5. Do NOT suggest tuning, remediation, or follow-up actions — just the closure justification.
6. Tone: direct, factual, confident.

WORKSPACE QUERY TOOL
--------------------
If the `query_workspace` tool is available, you may run a single focused KQL query to confirm \
the benign nature of the activity (e.g. check historical pattern, verify named location). \
Maximum 1 query. Use only if essential — prefer the case artefacts already provided.

OUTPUT:
Return ONLY the two-sentence (or fewer) FP closure comment. Nothing else.
"""

# Cached system block
_SYSTEM_CACHED = [
    {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
]

# Tool: read-only KQL query against the alert workspace
_QUERY_WORKSPACE_TOOL = {
    "name": "query_workspace",
    "description": (
        "Execute a READ-ONLY KQL query against the Sentinel Log Analytics workspace "
        "associated with this alert. Use this to verify alert conditions, check recent "
        "activity for the caller/IP/resource, or validate that a proposed exclusion "
        "would not suppress real threats. "
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
_QUERY_MAX_CALLS = 1

# Tool: request clarification when platform cannot be determined
_CLARIFICATION_TOOL = {
    "name": "request_clarification",
    "description": (
        "Call this tool when the alerting platform cannot be confidently determined "
        "from the alert data and no --platform override was provided. "
        "Ask the analyst a specific question to resolve ambiguity."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": "Specific question to ask the analyst to identify the platform",
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
        log_error(case_id, "fp_ticket.safe_load", str(exc),
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
        if len(report_text) > 4000:
            report_text = report_text[:4000] + "\n\n[...report truncated...]"
        parts.append("## Investigation Report (excerpt)")
        parts.append(report_text)
        parts.append("")

    # Log files — especially relevant for Sentinel cases
    logs_dir = case_dir / "logs"
    if logs_dir.exists():
        log_chunks: list[str] = []
        total_chars = 0
        for log_file in sorted(logs_dir.iterdir()):
            if log_file.is_file() and total_chars < 3000:
                try:
                    text = log_file.read_text(encoding="utf-8", errors="replace")
                    if len(text) > 1500:
                        text = text[:1500] + "\n[...truncated...]"
                    log_chunks.append(f"### {log_file.name}\n{text}")
                    total_chars += len(text)
                except Exception as exc:
                    log_error(case_id, "fp_ticket.read_log", str(exc),
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
                log_error(case_id, "fp_ticket.read_capture", str(exc),
                          severity="info", context={"file": str(page_txt)})
        if capture_chunks:
            parts.append("## Web Captures")
            parts.extend(capture_chunks)
            parts.append("")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def fp_ticket(case_id, alert_data, query_text=None, platform=None, live_query=False):
    """Stub — direct LLM generation removed.

    Use the ``write_fp_closure`` MCP prompt to generate the FP ticket via
    the local Claude Desktop agent, then call ``save_report(type=fp_ticket)``
    to persist it.
    """
    return {
        "status": "use_prompt",
        "prompt": "write_fp_closure",
        "save_tool": "save_report",
        "save_args": {"report_type": "fp_ticket"},
        "case_id": case_id,
        "ts": utcnow(),
    }


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Generate an FP suppression ticket for a case.")
    p.add_argument("--case",        required=True, dest="case_id")
    p.add_argument("--alert",       metavar="FILE", help="Path to alert JSON/text file")
    p.add_argument("--alert-text",  metavar="TEXT", help="Inline alert string")
    p.add_argument("--query",       metavar="FILE", help="Path to KQL rule file (Sentinel)")
    p.add_argument("--query-text",  metavar="KQL",  help="Inline KQL string")
    p.add_argument("--platform",    choices=["sentinel", "crowdstrike", "defender", "entra", "cloudapps"])
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

    result = fp_ticket(
        case_id=args.case_id,
        alert_data=alert_str,
        query_text=query_str,
        platform=args.platform,
        live_query=args.live_query,
    )
    print(json.dumps(result, indent=2, default=str))
