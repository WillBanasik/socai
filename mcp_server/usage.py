"""MCP usage watcher — logs every tool invocation to JSONL + live stderr output.

Monkey-patches ``ToolManager.call_tool`` so that **zero** changes are needed in
the tool definitions in ``tools.py``.

Captures per-session tool sequences and emits ``workflow_summary`` events to
the metrics log on session expiry — enables weekly workflow analytics.

Usage::

    from mcp_server.usage import install_usage_watcher
    install_usage_watcher(server)
"""
from __future__ import annotations

import atexit
import json
import sys
import threading
import time
import uuid
from typing import IO, Any

from mcp.server.fastmcp import FastMCP

from config.settings import MCP_USAGE_LOG, MCP_LOG_RESULTS, MCP_LOG_MAX_RESULT
from tools.common import eprint, utcnow

_usage_lock = threading.Lock()
_usage_fh: IO[str] | None = None


def _get_usage_fh() -> IO[str]:
    """Return (lazily opening) the append-mode line-buffered usage log handle.

    Reopens if the file has been removed (log rotation, test teardown).
    """
    global _usage_fh
    if _usage_fh is None or not MCP_USAGE_LOG.exists():
        if _usage_fh is not None:
            try:
                _usage_fh.close()
            except Exception:
                pass
        MCP_USAGE_LOG.parent.mkdir(parents=True, exist_ok=True)
        _usage_fh = open(MCP_USAGE_LOG, "a", buffering=1)
    return _usage_fh


@atexit.register
def _close_usage_fh() -> None:
    global _usage_fh
    if _usage_fh is not None:
        try:
            _usage_fh.close()
        except Exception:
            pass
        _usage_fh = None

# Fields to strip from logged params (secrets / large blobs)
_SENSITIVE_KEYS = frozenset({"zip_pass", "password", "token", "secret", "api_key"})

# ---------------------------------------------------------------------------
# Tool taxonomy — maps each MCP tool function name to a workflow category
# and the goal it works towards.
#
# Categories:
#   lookup      — quick read-only information retrieval, no case mutation
#   enrichment  — IOC enrichment and scoring
#   triage      — initial classification and filtering
#   analysis    — deep investigation (correlation, forensics, timeline)
#   delivery    — report generation, ticket preparation, case closure
#   admin       — case lifecycle management (create, promote, close, link)
#   query       — SIEM/log queries and playbook generation
#   intel       — threat intelligence and article management
#   sandbox     — sandbox/browser detonation sessions
#   infra       — system maintenance (index rebuild, GeoIP refresh, etc.)
#
# Goals:
#   quick_answer     — analyst wants a fast answer, no case needed
#   investigate      — working through an active investigation
#   deliver          — producing a deliverable (report, ticket)
#   maintain         — system maintenance / housekeeping
# ---------------------------------------------------------------------------
TOOL_TAXONOMY: dict[str, dict[str, str]] = {
    # Lookup / read-only
    "lookup_client":            {"category": "lookup",      "goal": "investigate"},
    "list_clients":             {"category": "lookup",      "goal": "quick_answer"},
    "list_cases":               {"category": "lookup",      "goal": "quick_answer"},
    "case_summary":             {"category": "lookup",      "goal": "quick_answer"},
    "read_report":              {"category": "lookup",      "goal": "quick_answer"},
    "read_case_file":           {"category": "lookup",      "goal": "quick_answer"},
    "list_case_files":          {"category": "lookup",      "goal": "quick_answer"},
    "geoip_lookup":             {"category": "lookup",      "goal": "quick_answer"},
    "get_client_baseline":      {"category": "lookup",      "goal": "quick_answer"},
    "cyberint_metadata":        {"category": "lookup",      "goal": "quick_answer"},
    "load_ngsiem_reference":    {"category": "lookup",      "goal": "quick_answer"},
    "check_log_coverage":       {"category": "lookup",      "goal": "quick_answer"},
    "can_investigate_attack":   {"category": "lookup",      "goal": "quick_answer"},
    "get_client_exposure_report": {"category": "lookup",    "goal": "quick_answer"},
    "load_kql_playbook":        {"category": "lookup",      "goal": "investigate"},
    "load_cql_playbook":        {"category": "lookup",      "goal": "investigate"},
    "list_toolsets":            {"category": "lookup",      "goal": "quick_answer"},
    "load_toolset":             {"category": "triage",      "goal": "investigate"},

    # Quick enrichment — no case required
    "quick_enrich":             {"category": "enrichment",  "goal": "quick_answer"},
    "query_opencti":            {"category": "enrichment",  "goal": "quick_answer"},
    "extract_iocs_from_text":   {"category": "enrichment",  "goal": "quick_answer"},
    "xposed_breach_check":      {"category": "enrichment",  "goal": "quick_answer"},
    "web_search":               {"category": "enrichment",  "goal": "quick_answer"},
    "ahmia_darkweb_search":     {"category": "enrichment",  "goal": "quick_answer"},
    "intelx_search_tool":       {"category": "enrichment",  "goal": "quick_answer"},

    # Triage
    "new_investigation":        {"category": "triage",      "goal": "investigate"},
    "classify_attack":          {"category": "triage",      "goal": "investigate"},
    "plan_investigation":       {"category": "triage",      "goal": "investigate"},
    "triage_iocs":              {"category": "triage",      "goal": "investigate"},

    # Case admin
    "create_case":              {"category": "admin",       "goal": "investigate"},
    "promote_case":             {"category": "admin",       "goal": "investigate"},
    "discard_case":             {"category": "admin",       "goal": "deliver"},
    "close_case":               {"category": "admin",       "goal": "deliver"},
    "add_evidence":             {"category": "admin",       "goal": "investigate"},
    "add_finding":              {"category": "admin",       "goal": "investigate"},
    "import_enrichment":        {"category": "admin",       "goal": "investigate"},
    "link_cases":               {"category": "admin",       "goal": "investigate"},
    "merge_cases":              {"category": "admin",       "goal": "investigate"},
    "update_client_knowledge":  {"category": "admin",       "goal": "maintain"},

    # Case-bound enrichment
    "enrich_iocs":              {"category": "enrichment",  "goal": "investigate"},
    "score_ioc_verdicts":       {"category": "enrichment",  "goal": "investigate"},
    "contextualise_cves":       {"category": "enrichment",  "goal": "investigate"},
    "search_confluence":        {"category": "enrichment",  "goal": "investigate"},
    "darkweb_exposure_summary": {"category": "enrichment",  "goal": "investigate"},
    "parse_stealer_logs_tool":  {"category": "enrichment",  "goal": "investigate"},

    # Analysis
    "analyse_email":            {"category": "analysis",    "goal": "investigate"},
    "detect_phishing":          {"category": "analysis",    "goal": "investigate"},
    "correlate":                {"category": "analysis",    "goal": "investigate"},
    "reconstruct_timeline":     {"category": "analysis",    "goal": "investigate"},
    "campaign_cluster":         {"category": "analysis",    "goal": "investigate"},
    "recall_cases":             {"category": "analysis",    "goal": "investigate"},
    "recall_semantic":          {"category": "analysis",    "goal": "investigate"},
    "assess_landscape":         {"category": "analysis",    "goal": "investigate"},
    "detect_anomalies":         {"category": "analysis",    "goal": "investigate"},
    "correlate_evtx":           {"category": "analysis",    "goal": "investigate"},
    "analyse_file":             {"category": "analysis",    "goal": "investigate"},
    "prepare_file_upload":      {"category": "analysis",    "goal": "investigate"},
    "upload_file_content":      {"category": "analysis",    "goal": "investigate"},
    "yara_scan":                {"category": "analysis",    "goal": "investigate"},
    "analyse_memory_dump":      {"category": "analysis",    "goal": "investigate"},
    "analyse_memory_volatility": {"category": "analysis",   "goal": "investigate"},
    "memory_dump_guide":        {"category": "analysis",    "goal": "investigate"},
    "capture_urls":             {"category": "analysis",    "goal": "investigate"},
    "generate_investigation_matrix": {"category": "analysis", "goal": "investigate"},
    "run_determination":        {"category": "analysis",    "goal": "investigate"},
    "list_followups":           {"category": "analysis",    "goal": "investigate"},
    "execute_followup":         {"category": "analysis",    "goal": "investigate"},

    # SIEM queries
    "run_kql":                  {"category": "query",       "goal": "investigate"},
    "run_kql_batch":            {"category": "query",       "goal": "investigate"},
    "run_defender_kql":         {"category": "query",       "goal": "investigate"},
    "run_falcon_cql":           {"category": "query",       "goal": "investigate"},
    "query_falcon_detections":  {"category": "query",       "goal": "investigate"},
    "query_falcon_hosts":       {"category": "query",       "goal": "investigate"},
    "query_falcon_incidents":   {"category": "query",       "goal": "investigate"},
    "eql_entity_context":       {"category": "query",       "goal": "investigate"},
    "eql_identity_assessment":  {"category": "query",       "goal": "investigate"},
    "eql_query":                {"category": "query",       "goal": "investigate"},
    "eql_posture_context":      {"category": "query",       "goal": "investigate"},
    "eql_vuln_hunt":            {"category": "query",       "goal": "investigate"},
    "import_vuln_hunt":         {"category": "admin",       "goal": "investigate"},
    "eql_entity_lookup":        {"category": "query",       "goal": "investigate"},
    "eql_identity_scan":        {"category": "query",       "goal": "investigate"},
    "import_eql_lookup":        {"category": "admin",       "goal": "investigate"},
    "generate_queries":         {"category": "query",       "goal": "investigate"},
    "generate_sentinel_query":  {"category": "query",       "goal": "investigate"},
    "parse_logs":               {"category": "query",       "goal": "investigate"},
    "query_cyberint_alerts":    {"category": "query",       "goal": "investigate"},
    "cyberint_alert_artefact":  {"category": "query",       "goal": "investigate"},
    "run_client_exposure_test": {"category": "query",       "goal": "investigate"},
    "refresh_log_coverage":     {"category": "query",       "goal": "maintain"},

    # Sandbox / browser sessions
    "sandbox_api_lookup":       {"category": "sandbox",     "goal": "investigate"},
    "start_sandbox_session":    {"category": "sandbox",     "goal": "investigate"},
    "stop_sandbox_session":     {"category": "sandbox",     "goal": "investigate"},
    "list_sandbox_sessions":    {"category": "sandbox",     "goal": "quick_answer"},
    "start_browser_session":    {"category": "sandbox",     "goal": "investigate"},
    "stop_browser_session":     {"category": "sandbox",     "goal": "investigate"},
    "list_browser_sessions":    {"category": "sandbox",     "goal": "quick_answer"},
    "read_browser_session_file": {"category": "sandbox",    "goal": "quick_answer"},
    "list_browser_session_files": {"category": "sandbox",   "goal": "quick_answer"},
    "import_browser_session":   {"category": "sandbox",     "goal": "investigate"},

    # Forensics ingestion
    "ingest_velociraptor":      {"category": "analysis",    "goal": "investigate"},
    "ingest_mde_package":       {"category": "analysis",    "goal": "investigate"},

    # Delivery — reports, tickets, closures
    "generate_report":          {"category": "delivery",    "goal": "deliver"},
    "load_report_template":     {"category": "delivery",    "goal": "deliver"},
    "prepare_mdr_report":       {"category": "delivery",    "goal": "deliver"},
    "prepare_pup_report":       {"category": "delivery",    "goal": "deliver"},
    "prepare_executive_summary": {"category": "delivery",   "goal": "deliver"},
    "save_report":              {"category": "delivery",    "goal": "deliver"},
    "prepare_closure_comment":  {"category": "delivery",    "goal": "deliver"},
    "prepare_fp_tuning_ticket": {"category": "delivery",    "goal": "deliver"},
    "prepare_vuln_hunt_report": {"category": "delivery",    "goal": "deliver"},
    "response_actions":         {"category": "delivery",    "goal": "deliver"},
    "review_report_quality":    {"category": "delivery",    "goal": "deliver"},
    "security_arch_review":     {"category": "delivery",    "goal": "deliver"},
    "generate_weekly":          {"category": "delivery",    "goal": "deliver"},

    # Threat intelligence articles
    "search_threat_articles":   {"category": "intel",       "goal": "quick_answer"},
    "check_article_dedup":      {"category": "intel",       "goal": "quick_answer"},
    "generate_threat_article":  {"category": "intel",       "goal": "deliver"},
    "save_threat_article":      {"category": "intel",       "goal": "deliver"},
    "post_opencti_report":      {"category": "intel",       "goal": "deliver"},
    "generate_opencti_package": {"category": "intel",       "goal": "deliver"},

    # Infrastructure / maintenance
    "rebuild_case_memory":      {"category": "infra",       "goal": "maintain"},
    "rebuild_client_baseline":  {"category": "infra",       "goal": "maintain"},
    "refresh_geoip":            {"category": "infra",       "goal": "maintain"},
    "audit_user_activity":      {"category": "lookup",      "goal": "maintain"},
}

_DEFAULT_TAXONOMY = {"category": "unknown", "goal": "unknown"}


def _tool_category(tool_name: str) -> str:
    return TOOL_TAXONOMY.get(tool_name, _DEFAULT_TAXONOMY)["category"]


def _tool_goal(tool_name: str) -> str:
    return TOOL_TAXONOMY.get(tool_name, _DEFAULT_TAXONOMY)["goal"]


# ---------------------------------------------------------------------------
# Investigation session tracker
# ---------------------------------------------------------------------------
_SESSION_TIMEOUT = 3600  # 1 hour

_sessions: dict[str, dict[str, Any]] = {}   # case_id → session info
_session_lock = threading.Lock()


def _get_or_create_session(case_id: str, caller: str) -> str:
    """Return a session ID for *case_id*, creating one if needed.

    Returns ``""`` when *case_id* is empty/falsy.  Sessions expire after
    ``_SESSION_TIMEOUT`` seconds of inactivity — on expiry the completed
    session is flushed to the metrics log as a ``workflow_summary`` event.
    """
    if not case_id:
        return ""

    now = time.monotonic()

    with _session_lock:
        entry = _sessions.get(case_id)
        if entry is not None:
            # Expire stale sessions
            if now - entry["last_seen"] > _SESSION_TIMEOUT:
                _flush_session(entry)
                entry = None

        if entry is None:
            sid = f"inv_{case_id}_{uuid.uuid4().hex[:8]}"
            entry = {
                "session_id": sid,
                "caller": caller,
                "case_id": case_id,
                "started": now,
                "started_ts": utcnow(),
                "last_seen": now,
                "tool_count": 0,
                "steps": [],
            }
            _sessions[case_id] = entry

        return entry["session_id"]


def _record_step(
    case_id: str,
    tool: str,
    duration_ms: int,
    success: bool,
    error: str | None = None,
    *,
    result_bytes: int = 0,
    est_tokens: int = 0,
) -> None:
    """Append a tool call to the session's ordered step sequence."""
    if not case_id:
        return

    category = _tool_category(tool)
    goal = _tool_goal(tool)

    step = {
        "seq": 0,  # set below
        "tool": tool,
        "category": category,
        "goal": goal,
        "ts": utcnow(),
        "duration_ms": duration_ms,
        "success": success,
        "result_bytes": result_bytes,
        "est_tokens": est_tokens,
    }
    if error:
        step["error"] = error[:200]

    with _session_lock:
        entry = _sessions.get(case_id)
        if entry is None:
            return
        step["seq"] = len(entry["steps"]) + 1
        entry["steps"].append(step)
        entry["tool_count"] = len(entry["steps"])
        entry["last_seen"] = time.monotonic()


# ---------------------------------------------------------------------------
# Caseless session tracker — for quick_enrich and other no-case tools
# ---------------------------------------------------------------------------
# Keyed by (caller_email, token_fingerprint) so two concurrent MCP clients
# for the same user (e.g. desktop + web) don't get their step sequences
# interleaved into one session.
_caseless_sessions: dict[tuple[str, str], dict[str, Any]] = {}
_CASELESS_TIMEOUT = 600  # 10 min — shorter, these are quick lookups


def _caseless_key(caller: str) -> tuple[str, str]:
    """Per-connection key for the caseless session bucket.

    Combines caller email with a fingerprint of the current access token
    (or ``"local"`` under stdio). Different tokens → different buckets,
    so concurrent clients under the same user don't collide.
    """
    import hashlib

    from mcp_server.config import MCP_TRANSPORT

    if MCP_TRANSPORT == "stdio":
        return (caller, "local")
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token
        tok = get_access_token()
        if tok is None:
            return (caller, "")
        return (caller, hashlib.sha256(tok.token.encode()).hexdigest()[:12])
    except Exception:
        return (caller, "")


def _get_or_create_caseless_session(caller: str) -> str:
    """Return a session ID for caseless tool calls (quick_enrich, etc.)."""
    if not caller:
        return ""

    now = time.monotonic()
    key = _caseless_key(caller)

    with _session_lock:
        entry = _caseless_sessions.get(key)
        if entry is not None:
            if now - entry["last_seen"] > _CASELESS_TIMEOUT:
                _flush_session(entry)
                entry = None

        if entry is None:
            sid = f"adhoc_{uuid.uuid4().hex[:8]}"
            entry = {
                "session_id": sid,
                "caller": caller,
                "case_id": "",
                "started": now,
                "started_ts": utcnow(),
                "last_seen": now,
                "tool_count": 0,
                "steps": [],
            }
            _caseless_sessions[key] = entry

        return entry["session_id"]


def _record_caseless_step(
    caller: str,
    tool: str,
    duration_ms: int,
    success: bool,
    error: str | None = None,
    *,
    result_bytes: int = 0,
    est_tokens: int = 0,
) -> None:
    """Append a tool call to the caseless session's step sequence."""
    if not caller:
        return

    category = _tool_category(tool)
    goal = _tool_goal(tool)

    step = {
        "seq": 0,
        "tool": tool,
        "category": category,
        "goal": goal,
        "ts": utcnow(),
        "duration_ms": duration_ms,
        "success": success,
        "result_bytes": result_bytes,
        "est_tokens": est_tokens,
    }
    if error:
        step["error"] = error[:200]

    key = _caseless_key(caller)
    with _session_lock:
        entry = _caseless_sessions.get(key)
        if entry is None:
            return
        step["seq"] = len(entry["steps"]) + 1
        entry["steps"].append(step)
        entry["tool_count"] = len(entry["steps"])
        entry["last_seen"] = time.monotonic()


# ---------------------------------------------------------------------------
# Friction detection — rules applied when flushing a session
# ---------------------------------------------------------------------------

def _detect_friction(steps: list[dict]) -> list[dict]:
    """Analyse a completed tool sequence for workflow friction signals."""
    friction: list[dict] = []
    if not steps:
        return friction

    tool_names = [s["tool"] for s in steps]

    # 1. Unnecessary prerequisite — create_case called before enrichment
    #    when quick_enrich was available
    if "create_case" in tool_names and "enrich_iocs" in tool_names:
        ci = tool_names.index("create_case")
        ei = tool_names.index("enrich_iocs")
        # If create_case was called just to enable enrichment and nothing
        # else happened between them (no add_evidence, no other analysis)
        if ei == ci + 1 or (ei > ci and all(
            s["category"] in ("admin", "lookup") for s in steps[ci+1:ei]
        )):
            friction.append({
                "type": "unnecessary_prerequisite",
                "detail": "create_case called before enrich_iocs — "
                          "quick_enrich could have been used without a case",
                "step_range": [ci + 1, ei + 1],
            })

    # 2. Retry after error — same tool called consecutively after failure
    for i in range(1, len(steps)):
        if (steps[i]["tool"] == steps[i-1]["tool"]
                and not steps[i-1]["success"]):
            friction.append({
                "type": "retry_after_error",
                "detail": f"{steps[i]['tool']} retried after error: "
                          f"{steps[i-1].get('error', 'unknown')[:100]}",
                "step": i + 1,
            })

    # 3. Long gap — >120s between consecutive tool calls suggests analyst
    #    was stuck or Claude was slow to respond.
    #
    #    HITL touchpoints (add_evidence, add_finding, ingest_*, update_client_*,
    #    sandbox/browser start-and-wait) legitimately expect long analyst
    #    pauses. Exempt them so real friction isn't buried in HITL noise.
    _HITL_TOOLS = {
        "add_evidence", "add_finding",
        "ingest_velociraptor", "ingest_mde_package",
        "update_client_knowledge",
        "start_sandbox_session", "stop_sandbox_session",
        "start_browser_session", "stop_browser_session",
    }
    for i in range(1, len(steps)):
        if steps[i-1]["tool"] in _HITL_TOOLS or steps[i]["tool"] in _HITL_TOOLS:
            continue
        # Approximate gap: difference in timestamps
        try:
            from datetime import datetime
            t_prev = datetime.fromisoformat(steps[i-1]["ts"].replace("Z", "+00:00"))
            t_curr = datetime.fromisoformat(steps[i]["ts"].replace("Z", "+00:00"))
            gap_s = (t_curr - t_prev).total_seconds()
            if gap_s > 120:
                friction.append({
                    "type": "long_gap",
                    "detail": f"{int(gap_s)}s gap between "
                              f"{steps[i-1]['tool']} and {steps[i]['tool']}",
                    "gap_seconds": int(gap_s),
                    "step": i + 1,
                })
        except (ValueError, TypeError):
            pass

    # 4. Abandoned workflow — session ended without reaching a delivery goal
    #    (only flag if the session had investigation-oriented calls)
    has_investigation = any(s["goal"] == "investigate" for s in steps)
    has_delivery = any(s["category"] == "delivery" for s in steps)
    has_close = any(s["tool"] in ("close_case", "discard_case") for s in steps)
    if has_investigation and not has_delivery and not has_close and len(steps) >= 3:
        friction.append({
            "type": "abandoned_workflow",
            "detail": f"Session with {len(steps)} investigation steps "
                      "ended without a deliverable or case closure",
        })

    # 5. Repeated lookup — same read-only tool called 3+ times (suggests
    #    the result wasn't being retained / context was lost)
    from collections import Counter
    lookup_counts = Counter(
        s["tool"] for s in steps if s["category"] == "lookup"
    )
    for tool, count in lookup_counts.items():
        if count >= 3:
            friction.append({
                "type": "repeated_lookup",
                "detail": f"{tool} called {count} times — result may not "
                          "have been retained in context",
                "count": count,
            })

    return friction


# ---------------------------------------------------------------------------
# Session flush — emit workflow_summary to metrics log
# ---------------------------------------------------------------------------

def _flush_session(entry: dict[str, Any]) -> None:
    """Emit a ``workflow_summary`` event for a completed session."""
    steps = entry.get("steps", [])
    if not steps:
        return  # Nothing to report

    from tools.common import log_metric

    total_duration_ms = sum(s["duration_ms"] for s in steps)
    wall_clock_s = entry.get("last_seen", 0) - entry.get("started", 0)

    # Payload accounting — bytes/tokens socai shipped back into the client's
    # context this session. ``est_result_tokens`` is each result counted once
    # (raw data volume). ``est_context_input_tokens`` is a naive upper bound on
    # the *input* tokens those results drive: a result fed in at step i is
    # re-sent on every later turn, so it counts (n_steps - i) times. Real cost
    # sits below this because prompt caching bills re-sends at ~0.1x — the gap
    # is exactly what scripts/token_cost_report.py measures against client
    # telemetry. See _estimate_tokens.
    total_result_bytes = sum(s.get("result_bytes", 0) for s in steps)
    est_result_tokens = sum(s.get("est_tokens", 0) for s in steps)
    n_steps = len(steps)
    est_context_input_tokens = sum(
        s.get("est_tokens", 0) * (n_steps - i) for i, s in enumerate(steps)
    )

    # Category breakdown
    from collections import Counter
    cat_counts = Counter(s["category"] for s in steps)
    goal_counts = Counter(s["goal"] for s in steps)

    # Error count
    errors = [s for s in steps if not s["success"]]

    # Detect friction
    friction = _detect_friction(steps)

    # Determine final goal reached
    if any(s["category"] == "delivery" for s in steps):
        goal_reached = "deliver"
    elif any(s["tool"] in ("close_case", "discard_case") for s in steps):
        goal_reached = "deliver"
    elif any(s["goal"] == "investigate" for s in steps):
        goal_reached = "investigate"
    elif any(s["goal"] == "quick_answer" for s in steps):
        goal_reached = "quick_answer"
    else:
        goal_reached = "unknown"

    log_metric(
        "workflow_summary",
        case_id=entry.get("case_id", ""),
        session_id=entry.get("session_id", ""),
        caller=entry.get("caller", ""),
        started_ts=entry.get("started_ts", ""),
        wall_clock_s=int(wall_clock_s),
        tool_time_ms=total_duration_ms,
        step_count=len(steps),
        error_count=len(errors),
        total_result_bytes=total_result_bytes,
        est_result_tokens=est_result_tokens,
        est_context_input_tokens=est_context_input_tokens,
        goal_reached=goal_reached,
        category_breakdown=dict(cat_counts),
        goal_breakdown=dict(goal_counts),
        friction=friction,
        friction_count=len(friction),
        steps=steps,
    )


def flush_all_sessions() -> int:
    """Flush all active sessions — call on server shutdown.

    Returns the number of sessions flushed.
    """
    flushed = 0
    with _session_lock:
        for entry in _sessions.values():
            if entry.get("steps"):
                _flush_session(entry)
                flushed += 1
        _sessions.clear()
        for entry in _caseless_sessions.values():
            if entry.get("steps"):
                _flush_session(entry)
                flushed += 1
        _caseless_sessions.clear()
    return flushed


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _sanitise_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """Return a copy of *params* with sensitive fields redacted."""
    if not params:
        return {}
    out: dict[str, Any] = {}
    for k, v in params.items():
        if k in _SENSITIVE_KEYS:
            out[k] = "***"
        else:
            out[k] = v
    return out


# Rough token estimate. The real Claude tokenizer is not available
# server-side and socai never calls the model (see config/settings.py),
# so we approximate at ~4 chars/token — the standard heuristic. This counts
# only the raw result payload socai ships back into the client's context;
# under the full-payload policy (CLAUDE.md: "no slimming") those bytes
# dominate per-investigation *input* tokens on subsequent model turns. It
# excludes the client's system prompt, tool schemas, model output, and the
# per-turn context re-send — so treat it as a floor/proxy, not a bill.
# scripts/token_cost_report.py calibrates it against real client telemetry.
_CHARS_PER_TOKEN = 4


def _serialise_result(result: Any) -> str:
    """JSON-serialise a tool result (best-effort)."""
    try:
        return json.dumps(result, default=str)
    except (TypeError, ValueError):
        return str(result)


def _estimate_tokens(n_chars: int) -> int:
    """Approximate token count from a character length (~4 chars/token)."""
    return (n_chars + _CHARS_PER_TOKEN - 1) // _CHARS_PER_TOKEN


def _truncate_text(text: str, max_len: int = MCP_LOG_MAX_RESULT) -> str:
    """Truncate an already-serialised result string for logging."""
    if len(text) > max_len:
        return text[:max_len] + f"... [truncated, {len(text)} chars total]"
    return text


def log_mcp_call(
    caller: str,
    tool: str,
    params: dict[str, Any] | None,
    duration_ms: int,
    success: bool,
    error: str | None,
    session_id: str = "",
    result_bytes: int = 0,
    est_tokens: int = 0,
) -> None:
    """Append a single usage record to the JSONL log.

    ``result_bytes`` / ``est_tokens`` describe the payload shipped back to
    the client (0 on failure / when not measured) — see ``_estimate_tokens``.
    """
    taxonomy = TOOL_TAXONOMY.get(tool, _DEFAULT_TAXONOMY)
    record: dict[str, Any] = {
        "ts": utcnow(),
        "caller": caller,
        "tool": tool,
        "category": taxonomy["category"],
        "goal": taxonomy["goal"],
        "params": _sanitise_params(params),
        "duration_ms": duration_ms,
        "success": success,
        "error": error,
        "result_bytes": result_bytes,
        "est_tokens": est_tokens,
    }
    if session_id:
        record["session_id"] = session_id
    line = json.dumps(record) + "\n"
    with _usage_lock:
        _get_usage_fh().write(line)


def _emit_live(
    status: str,
    tool: str,
    caller: str,
    detail: str = "",
    duration_ms: int | None = None,
) -> None:
    """Print a status line to stderr for live tailing."""
    dur = f" {duration_ms}ms" if duration_ms is not None else ""
    det = f" — {detail}" if detail else ""
    eprint(f"[MCP {status:<4}] {tool}{dur} caller={caller}{det}")


def install_usage_watcher(server: FastMCP) -> None:
    """Wrap ``ToolManager.call_tool`` to log every invocation.

    The MCP low-level protocol handler dispatches tool calls via
    ``server._tool_manager.call_tool``, bypassing ``FastMCP.call_tool``.
    We patch at the ToolManager level so the watcher actually fires.
    """
    from mcp_server.logging_config import mcp_log

    tm = server._tool_manager
    original = tm.call_tool

    async def _watched(name: str, arguments: dict[str, Any], **kwargs: Any) -> Any:
        from mcp_server.auth import _get_caller_email
        caller = _get_caller_email()
        case_id = (arguments or {}).get("case_id", "")

        # Get or create the right session type
        if case_id:
            session_id = _get_or_create_session(case_id, caller)
        else:
            session_id = _get_or_create_caseless_session(caller)

        detail = f"case_id={case_id}" if case_id else ""
        _emit_live("CALL", name, caller, detail)

        # Structured log: tool call start
        mcp_log("tool_call", tool=name, caller=caller,
                params=_sanitise_params(arguments),
                case_id=case_id or None)

        t0 = time.monotonic()
        try:
            result = await original(name, arguments, **kwargs)
            duration_ms = int((time.monotonic() - t0) * 1000)

            # Only full-serialise when the result preview is needed for the
            # structured log.  For accounting alone a cheap str() proxy avoids
            # a second json.dumps of the same payload the framework is about
            # to serialise for the client.
            if MCP_LOG_RESULTS:
                result_text: str | None = _serialise_result(result)
                result_bytes = len(result_text)
            else:
                result_text = None
                result_bytes = len(str(result))
            est_tokens = _estimate_tokens(result_bytes)

            log_mcp_call(caller, name, arguments, duration_ms, True, None,
                         session_id=session_id,
                         result_bytes=result_bytes, est_tokens=est_tokens)
            _emit_live("OK  ", name, caller, duration_ms=duration_ms)

            # Record step in session sequence
            if case_id:
                _record_step(case_id, name, duration_ms, True,
                             result_bytes=result_bytes, est_tokens=est_tokens)
            else:
                _record_caseless_step(caller, name, duration_ms, True,
                                      result_bytes=result_bytes,
                                      est_tokens=est_tokens)

            # Structured log: tool result
            log_fields: dict[str, Any] = {
                "tool": name, "caller": caller,
                "duration_ms": duration_ms, "success": True,
                "case_id": case_id or None,
            }
            if MCP_LOG_RESULTS and result_text is not None:
                log_fields["result_preview"] = _truncate_text(result_text)
            mcp_log("tool_result", **log_fields)

            return result
        except Exception as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            err_msg = str(exc)[:500]
            log_mcp_call(caller, name, arguments, duration_ms, False, err_msg,
                         session_id=session_id)
            _emit_live("ERR ", name, caller, err_msg[:120], duration_ms)

            # Record failed step in session sequence
            if case_id:
                _record_step(case_id, name, duration_ms, False, err_msg)
            else:
                _record_caseless_step(caller, name, duration_ms, False, err_msg)

            # Structured log: tool error
            mcp_log("tool_error", tool=name, caller=caller,
                    duration_ms=duration_ms, error=err_msg,
                    case_id=case_id or None)
            raise

    tm.call_tool = _watched  # type: ignore[assignment]
