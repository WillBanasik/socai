"""
tool: fp_ticket
---------------
LLM-assisted False Positive suppression ticket generator.

Given a case + alert data, the tool:
  1. Loads all available case artefacts as context
  2. Identifies the alerting platform (Sentinel, CrowdStrike, Defender,
     Entra ID, Cloud Apps) from the alert data — or uses the --platform override
  3. Calls Claude to produce a targeted, evidence-based FP suppression ticket
     with platform-specific improvement recommendations

Returns:
  {"status": "ok",                "ticket_path": "..."}
  {"status": "needs_clarification", "question":   "..."}
  {"status": "skipped",             "reason":     "..."}
  {"status": "error",               "reason":     "..."}

Output:
  cases/<case_id>/artefacts/fp_comms/fp_ticket.md
  cases/<case_id>/artefacts/fp_comms/fp_ticket_manifest.json

Usage (standalone):
  python3 tools/fp_ticket.py --case C001 --alert alert.json
  python3 tools/fp_ticket.py --case C001 --alert alert.json --query rule.kql
  python3 tools/fp_ticket.py --case C001 --alert alert.json --platform sentinel
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_alias_map, get_model, load_json, log_error, save_json, utcnow, write_artefact

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

    # Match by TenantId
    tenant_id = alert_data.get("TenantId", "")
    if tenant_id:
        for ent in entities:
            if ent.get("workspace_id", "").lower() == tenant_id.lower():
                return ent["workspace_id"]

    # Match by DataSources name (e.g. "la-san-thungelasentinel" contains "thungela")
    data_sources = alert_data.get("DataSources", [])
    if data_sources:
        ds_str = " ".join(data_sources).lower()
        for ent in entities:
            if ent.get("name", "").lower() in ds_str and ent.get("workspace_id"):
                return ent["workspace_id"]

    return None

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a junior SIEM/security analytics engineer working in an enterprise SOC. \
An analyst has reviewed an investigation and determined it is a False Positive (FP). \
Your job is to:
  1. Understand exactly why the alert fired (from case evidence, log records, and the original rule/policy)
  2. Explain clearly why it is a FP
  3. Recommend the smallest targeted change that prevents this FP from recurring without creating detection gaps

PLATFORM IDENTIFICATION
-----------------------
If the platform is not already specified, identify it from the alert data structure:

| Platform | Key signals |
|----------|-------------|
| Microsoft Sentinel | WorkspaceId, SystemAlertId, DetectionSource: "Scheduled", AlertRule, KQL query field |
| CrowdStrike Falcon | event_simpleName, FalconHostLink, SensorId, PatternDispositionDescription, cid |
| Defender for Endpoint | MachineId or DeviceId, serviceSource: "MicrosoftDefenderForEndpoint", IncidentId |
| Entra ID | UserPrincipalName + SignInEventTypes, riskEventType, ConditionalAccessStatus, correlationId |
| Microsoft Cloud Apps | activityId, service.displayName, rawActivity, governanceActions, appId |

If you cannot confidently determine the platform, call the `request_clarification` tool \
with a specific question for the analyst.

PER-PLATFORM IMPROVEMENT CATEGORIES
-------------------------------------

SENTINEL / KQL — Analytics rule modifications (SIEM engineering team owns these):
- Watchlist exclusion: | where AccountName !in (_GetWatchlist('FP_Exclusions') | project SearchKey)
- Threshold tuning: adjust count() > N or time window (ago(Xm))
- Summarise to reduce noise: | summarize count() by User, hour = bin(TimeGenerated, 1h) | where count_ > threshold
- Add table correlation: join/union to require co-occurrence with another table
- Field-level filter: | where <field> !has "<benign_value>" or !startswith
- Entity scope: restrict to specific device group, user group, or workspace
- Known-good path/process exclusion: | where FolderPath !startswith "C:\\ProgramData\\expected"

CROWDSTRIKE FALCON — Control recommendations (Falcon admin team):
- ML exclusion: by hash, path glob, or signer
- IOA exclusion: behavior + process + command line regex
- IOC allow: add known-clean hash/domain/IP as allow
- Prevention policy: reduce sensitivity for this detection category
- Sensor visibility exclusion: path-based

DEFENDER FOR ENDPOINT — Control recommendations (MDE admin team):
- Alert suppression rule (via Security portal)
- AV exclusion: path/extension/process
- Custom detection rule: add KQL exclusion condition
- ASR rule exception

ENTRA ID — Control recommendations (Entra admin team):
- Named location: add trusted IP range → reference in CA policy
- CA policy scope exclusion: exclude user/group/location
- Identity Protection: trusted IP / risk dismissal workflow

MICROSOFT CLOUD APPS — Control recommendations (MCAS admin team):
- Activity policy exclusion filter
- Anomaly detection scope / sensitivity reduction
- Corporate network IP range addition

OUTPUT FORMAT
-------------
Produce a markdown ticket with these sections exactly:

## Alert Summary
(table: Alert Name, Platform, Rule/Policy, Triggered timestamp, Determination)

## Why This Is a False Positive
(evidence-based explanation citing specific IOCs, log records, verdicts, and capture data)

## Recommended Changes

### [For Sentinel: "Analytics Rule Modifications (SIEM Engineering)"]
[For other platforms: "Control Recommendation — <Team Name>"]
(For each recommendation: **Change type:**, **Rationale:**, and a code/KQL snippet if applicable)

## Validation
(How to verify the fix works: re-trigger scenario, expected non-alert outcome, test query)

## IOCs — Clean Verdict (confirmed benign by enrichment)
(markdown table: IOC | Type | Providers | Verdict — only show IOCs with clean verdict)

---
*Generated by socai fp-ticket | Case: <case_id>*

WORKSPACE QUERY TOOL
--------------------
If the `query_workspace` tool is available, you can run READ-ONLY KQL queries against the \
Sentinel workspace that produced this alert. Use this to:
- Verify the caller's historical activity pattern (is this a daily occurrence?)
- Check how many other principals would match a proposed exclusion (blast radius)
- Confirm the alert condition would no longer fire with the proposed fix
- Look up the app registration display name from AADServicePrincipalSignInLogs

Guidelines:
- Keep queries time-bounded (ago(7d) or narrower) and focused
- Maximum 5 queries per ticket — be deliberate
- Always state the PURPOSE before querying
- Include relevant query results in the ticket as supporting evidence
- If the tool is NOT available, rely on the case artefacts and alert data provided

IMPORTANT:
- Be specific and minimal. Recommend the smallest change that addresses this exact FP.
- Do NOT suggest changes that would reduce detection coverage beyond this specific pattern.
- For Sentinel: always include the KQL snippet for the proposed change.
- Base your explanation entirely on the evidence provided — do not invent details.
- Tone: direct, technical, practitioner-level.
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
_QUERY_MAX_CALLS = 5

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

def fp_ticket(
    case_id: str,
    alert_data: str,
    query_text: str | None = None,
    platform: str | None = None,
    live_query: bool = False,
) -> dict:
    """
    Generate an FP suppression ticket for *case_id*.

    Parameters
    ----------
    case_id     : existing case ID
    alert_data  : raw alert JSON/text (as string)
    query_text  : original KQL rule or policy text (Sentinel cases)
    platform    : override — sentinel|crowdstrike|defender|entra|cloudapps
                  If None, the LLM identifies it from alert_data
    live_query  : if True, enable the query_workspace tool so the LLM can
                  run read-only KQL against the alert's workspace.
                  Requires `az` CLI authenticated. Default False.

    Returns a manifest dict.
    """
    # ── 1. Early-exit checks ──────────────────────────────────────────────
    if not ANTHROPIC_KEY:
        return {
            "status":  "skipped",
            "reason":  "ANTHROPIC_API_KEY not set — fp-ticket requires LLM access.",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    if not alert_data or not alert_data.strip():
        return {
            "status":  "error",
            "reason":  "alert_data is empty — provide alert JSON or text.",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    try:
        import anthropic
    except ImportError as exc:
        log_error(case_id, "fp_ticket.import_anthropic", str(exc), severity="info")
        return {
            "status":  "error",
            "reason":  "anthropic package not installed. Run: pip install anthropic",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    # ── 2. Load case metadata for header ──────────────────────────────────
    case_dir = CASES_DIR / case_id
    meta = _safe_load(case_dir / "case_meta.json", case_id) or {}
    analyst  = meta.get("analyst", "unassigned")
    severity = meta.get("severity", "N/A")

    # ── 3. Build context + apply aliasing ─────────────────────────────────
    context   = _build_context(case_id)
    alias_map = get_alias_map()

    if alias_map:
        context    = alias_map.alias_text(context)
        alert_data = alias_map.alias_text(alert_data)
        if query_text:
            query_text = alias_map.alias_text(query_text)

    # ── 4. Resolve workspace for live queries ─────────────────────────────
    workspace_id = None
    query_log: list[dict] = []  # track queries executed for manifest

    if live_query:
        try:
            alert_dict = json.loads(alert_data)
        except (json.JSONDecodeError, TypeError):
            alert_dict = None
        workspace_id = _resolve_workspace_id(alert_dict, case_id)
        if workspace_id:
            print(f"[fp_ticket] Live query enabled — workspace {workspace_id}")
        else:
            print("[fp_ticket] Live query requested but workspace ID could not be resolved. "
                  "Falling back to artefact-only mode.")
            live_query = False

    # ── 5. Assemble user message sections ─────────────────────────────────
    user_parts: list[str] = [
        "## Task\n"
        "An analyst has determined this investigation is a False Positive. "
        "Generate an FP suppression ticket.\n",
    ]

    if platform:
        user_parts.append(f"**Platform override:** {platform}\n")

    if live_query and workspace_id:
        user_parts.append(
            "**Live workspace query is ENABLED.** You can use the `query_workspace` tool "
            "to run read-only KQL queries against the alert's Log Analytics workspace "
            "to gather additional evidence.\n"
        )

    user_parts.append(f"## Case Context\n\n{context}\n")
    user_parts.append(f"## Alert Data\n\n```\n{alert_data}\n```\n")

    if query_text:
        user_parts.append(f"## Original Rule / Query\n\n```kql\n{query_text}\n```\n")

    user_parts.append("## Analyst Determination\n\nFalse Positive\n")

    user_message = "\n".join(user_parts)

    # ── 6. Build tools list ────────────────────────────────────────────────
    tools = [_CLARIFICATION_TOOL]
    if live_query and workspace_id:
        tools.append(_QUERY_WORKSPACE_TOOL)

    # ── 7. Call LLM (with tool-use conversation loop) ──────────────────────
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    _model = get_model("fp_ticket", severity)

    print(f"[fp_ticket] Querying {_model} for case {case_id}...")

    messages = [{"role": "user", "content": user_message}]
    tokens_in = tokens_out = tokens_cache_read = tokens_cache_write = 0
    ticket_text = ""
    clarification_question = None
    query_call_count = 0

    for _turn in range(1 + _QUERY_MAX_CALLS):  # initial + up to N tool rounds
        try:
            message = client.messages.create(
                model=_model,
                max_tokens=4096,
                system=_SYSTEM_CACHED,
                tools=tools,
                tool_choice={"type": "auto"},
                messages=messages,
            )
        except Exception as exc:
            log_error(case_id, "fp_ticket.llm_call", str(exc), severity="error")
            return {
                "status":  "error",
                "reason":  f"LLM API call failed: {exc}",
                "case_id": case_id,
                "ts":      utcnow(),
            }

        # Accumulate tokens
        tokens_in  += message.usage.input_tokens
        tokens_out += message.usage.output_tokens
        tokens_cache_read  += getattr(message.usage, "cache_read_input_tokens", 0) or 0
        tokens_cache_write += getattr(message.usage, "cache_creation_input_tokens", 0) or 0

        # Check for tool use
        has_tool_use = False
        tool_results: list[dict] = []

        for block in message.content:
            if block.type == "text":
                ticket_text += block.text
            elif block.type == "tool_use" and block.name == "request_clarification":
                clarification_question = block.input.get("question", "")
            elif block.type == "tool_use" and block.name == "query_workspace":
                has_tool_use = True
                query_call_count += 1
                kql = block.input.get("kql", "")
                purpose = block.input.get("purpose", "")
                print(f"[fp_ticket] Tool call #{query_call_count}: query_workspace — {purpose}")

                if query_call_count > _QUERY_MAX_CALLS:
                    result_text = json.dumps({
                        "error": f"Query limit reached ({_QUERY_MAX_CALLS} max). "
                                 "Use the evidence already gathered."
                    })
                else:
                    # Execute read-only KQL via run_kql
                    try:
                        from scripts.run_kql import run_kql
                        rows = run_kql(workspace_id, kql, timeout=60)
                        # Cap rows
                        if len(rows) > _QUERY_MAX_ROWS:
                            rows = rows[:_QUERY_MAX_ROWS]
                            rows.append({"_truncated": f"Results capped at {_QUERY_MAX_ROWS} rows"})
                        result_text = json.dumps(rows, indent=2, default=str)
                        print(f"[fp_ticket]   → {len(rows)} row(s) returned")
                    except Exception as exc:
                        log_error(case_id, "fp_ticket.query_workspace", str(exc),
                                  severity="warning", context={"kql": kql[:200]})
                        result_text = json.dumps({"error": str(exc)})
                        print(f"[fp_ticket]   → Error: {exc}")

                query_log.append({
                    "turn": _turn + 1,
                    "purpose": purpose,
                    "kql": kql,
                    "result_preview": result_text[:500],
                })

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text,
                })

        # If clarification was requested, stop
        if clarification_question:
            break

        # If no tool use, we're done
        if not has_tool_use or message.stop_reason == "end_turn":
            break

        # Continue conversation with tool results
        messages.append({"role": "assistant", "content": message.content})
        messages.append({"role": "user", "content": tool_results})

    print(
        f"[fp_ticket] Tokens: {tokens_in} in / {tokens_out} out "
        f"| cache_read={tokens_cache_read} cache_write={tokens_cache_write}"
        + (f" | queries={query_call_count}" if query_call_count else "")
    )

    # ── 8. Parse final response ────────────────────────────────────────────
    # Clarification takes priority
    if clarification_question:
        return {
            "status":   "needs_clarification",
            "question": clarification_question,
            "case_id":  case_id,
            "ts":       utcnow(),
        }

    ticket_text = ticket_text.strip()
    if not ticket_text:
        return {
            "status":  "error",
            "reason":  "LLM returned empty response.",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    # ── 9. Dealias output ─────────────────────────────────────────────────
    if alias_map:
        ticket_text = alias_map.dealias_text(ticket_text)

    # ── 10. Write artefact ────────────────────────────────────────────────
    out_dir = case_dir / "artefacts" / "fp_comms"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "fp_ticket.md"

    header = (
        f"# FP Suppression Ticket — {case_id}\n\n"
        f"**Date:** {utcnow()} | **Analyst:** {analyst} | **Severity:** {severity}"
        f" | Model: {_model} | Tokens: {tokens_in} in / {tokens_out} out"
        + (f" | Cache read: {tokens_cache_read}" if tokens_cache_read else "")
        + "\n\n---\n\n"
    )
    write_artefact(out_path, header + ticket_text)

    manifest = {
        "case_id":            case_id,
        "ticket_path":        str(out_path),
        "tokens_in":          tokens_in,
        "tokens_out":         tokens_out,
        "tokens_cache_read":  tokens_cache_read,
        "tokens_cache_write": tokens_cache_write,
        "model":              _model,
        "platform_override":  platform,
        "has_query":          bool(query_text),
        "live_query":         live_query,
        "workspace_id":       workspace_id,
        "workspace_queries":  query_log,
        "status":             "ok",
        "ts":                 utcnow(),
    }
    save_json(out_dir / "fp_ticket_manifest.json", manifest)

    print(f"[fp_ticket] Ticket written to {out_path}")
    return manifest


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
