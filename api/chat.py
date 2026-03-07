"""LLM-backed chat engine for case investigation and session-based investigation."""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import anthropic

from api import actions, timeline
from api.prompts import build_system_prompt, build_session_prompt, _load_case_meta
from api.sessions import (
    SESSIONS_DIR,
    add_finding as _session_add_finding,
    add_iocs as _session_add_iocs,
    add_telemetry_summary as _session_add_telemetry,
    load_context as _session_load_context,
    load_history as _session_load_history,
    list_uploads as _session_list_uploads,
    save_history as _session_save_history,
    set_disposition as _session_set_disposition,
    upload_dir as _session_upload_dir,
)
from api.tool_schemas import TOOL_DEFS, SESSION_TOOL_DEFS
from config.settings import ANTHROPIC_KEY, CASES_DIR, SOCAI_COMPACTION_ENABLED
from tools.common import get_model

from tools.common import utcnow as _utcnow

MAX_TURNS = 10
MAX_HISTORY_MESSAGES = 20      # messages sent to API; full history still saved to disk
MAX_TOOL_RESULT_CHARS = 3000   # truncate long tool results in API payload
MAX_COMPACTION_MESSAGES = 200  # safety cap when compaction is active


def _trim_for_api(messages: list[dict], max_messages: int = MAX_HISTORY_MESSAGES) -> list[dict]:
    """Return a trimmed copy of *messages* suitable for the API.

    Keeps the most recent *max_messages* entries.  Ensures the returned list
    starts with a ``"user"`` role (Anthropic API requirement).  Long tool-result
    content blocks are truncated to save input tokens.
    """
    trimmed = messages[-max_messages:] if len(messages) > max_messages else list(messages)

    # Iteratively strip orphaned tool_results until stable.
    # Each pass may drop assistant messages (re-alignment), orphaning more
    # tool_results, which empties user messages, exposing new leading assistants.
    prev_len = -1
    while len(trimmed) != prev_len:
        prev_len = len(trimmed)

        # Ensure first message is role=user
        while trimmed and trimmed[0].get("role") != "user":
            trimmed.pop(0)

        # Collect tool_use IDs from remaining assistant messages
        tool_use_ids: set[str] = set()
        for msg in trimmed:
            if msg.get("role") != "assistant":
                continue
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        tool_use_ids.add(block.get("id", ""))

        # Strip orphaned tool_result blocks; drop empty messages
        cleaned = []
        for msg in trimmed:
            content = msg.get("content")
            if isinstance(content, list):
                new_blocks = [
                    b for b in content
                    if not (isinstance(b, dict) and b.get("type") == "tool_result"
                            and b.get("tool_use_id") not in tool_use_ids)
                ]
                if not new_blocks:
                    continue
                cleaned.append({**msg, "content": new_blocks})
            else:
                cleaned.append(msg)
        trimmed = cleaned

    # Truncate oversized tool-result blocks (they inflate token counts fast)
    # Also strip the `ts` metadata field — Anthropic API doesn't expect it.
    out = []
    for msg in trimmed:
        content = msg.get("content")
        clean = {k: v for k, v in msg.items() if k != "ts"}
        if isinstance(content, list):
            new_blocks = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    text = block.get("content", "")
                    if isinstance(text, str) and len(text) > MAX_TOOL_RESULT_CHARS:
                        block = {**block, "content": text[:MAX_TOOL_RESULT_CHARS] + "\n… [truncated]"}
                new_blocks.append(block)
            out.append({**clean, "content": new_blocks})
        else:
            out.append(clean)
    return out



def _supports_compaction(model: str) -> bool:
    """Return True if the model supports server-side compaction."""
    return "opus-4" in model and SOCAI_COMPACTION_ENABLED


def _trim_for_api_compaction(messages: list[dict]) -> list[dict]:
    """Lighter trimming for compaction-enabled models.

    Applies a safety cap (200 messages), orphan cleanup, and tool-result
    truncation, but does NOT hard-truncate to 20 messages — the server
    handles context management via compaction.
    """
    trimmed = messages[-MAX_COMPACTION_MESSAGES:] if len(messages) > MAX_COMPACTION_MESSAGES else list(messages)

    # Same orphan-cleanup loop as _trim_for_api
    prev_len = -1
    while len(trimmed) != prev_len:
        prev_len = len(trimmed)
        while trimmed and trimmed[0].get("role") != "user":
            trimmed.pop(0)
        tool_use_ids: set[str] = set()
        for msg in trimmed:
            if msg.get("role") != "assistant":
                continue
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        tool_use_ids.add(block.get("id", ""))
        cleaned = []
        for msg in trimmed:
            content = msg.get("content")
            if isinstance(content, list):
                new_blocks = [
                    b for b in content
                    if not (isinstance(b, dict) and b.get("type") == "tool_result"
                            and b.get("tool_use_id") not in tool_use_ids)
                ]
                if not new_blocks:
                    continue
                cleaned.append({**msg, "content": new_blocks})
            else:
                cleaned.append(msg)
        trimmed = cleaned

    # Truncate oversized tool-result blocks; strip `ts` metadata
    out = []
    for msg in trimmed:
        content = msg.get("content")
        clean = {k: v for k, v in msg.items() if k != "ts"}
        if isinstance(content, list):
            new_blocks = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    text = block.get("content", "")
                    if isinstance(text, str) and len(text) > MAX_TOOL_RESULT_CHARS:
                        block = {**block, "content": text[:MAX_TOOL_RESULT_CHARS] + "\n… [truncated]"}
                new_blocks.append(block)
            out.append({**clean, "content": new_blocks})
        else:
            out.append(clean)
    return out


def _prepare_messages_for_api(messages: list[dict], model: str) -> list[dict]:
    """Choose between hard trimming and compaction-aware trimming."""
    if _supports_compaction(model):
        return _trim_for_api_compaction(messages)
    return _trim_for_api(messages)


def _add_compaction_params(kwargs: dict, model: str) -> None:
    """Add compaction beta headers if the model supports it."""
    if _supports_compaction(model):
        kwargs["betas"] = ["interleaved-thinking-2025-05-14"]


# ---------------------------------------------------------------------------
# Tool execution dispatcher
# ---------------------------------------------------------------------------

def _run_kql_tool(tool_input: dict) -> dict:
    """Execute a read-only KQL query. Returns result dict."""
    query = tool_input.get("query", "").strip()
    workspace = tool_input.get("workspace", "").strip()
    if not query:
        return {"_message": "No KQL query provided."}
    if not workspace:
        return {"_message": "No workspace specified. Use a workspace name (example-client) or full GUID."}

    from scripts.run_kql import run_kql, _resolve_workspace

    # Resolve workspace name/code → GUID (pass through if already a GUID)
    ws_id = None
    import re
    _guid_re = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    if _guid_re.match(workspace):
        ws_id = workspace
    else:
        try:
            ws_id = _resolve_workspace(None, workspace)
        except SystemExit:
            return {"_message": f"Unknown workspace: {workspace}"}

    # Safety: enforce row limit
    q = query.rstrip().rstrip(";")
    if "| take " not in q.lower() and "| limit " not in q.lower():
        q += "\n| take 50"

    rows = run_kql(ws_id, q, timeout=60)
    if not rows:
        return {"_message": "Query returned no results (or execution failed — check az CLI auth)."}

    row_count = len(rows)
    # Truncate to avoid blowing up context
    display = json.dumps(rows[:50], indent=2, default=str)
    if len(display) > 12000:
        display = display[:12000] + "\n... [truncated]"
    return {"_message": f"**{row_count} row(s) returned:**\n```json\n{display}\n```"}


def _handle_kql_playbook(tool_input: dict) -> dict:
    """Handle the load_kql_playbook tool call."""
    from tools.kql_playbooks import list_playbooks, load_playbook, render_stage

    playbook_id = tool_input.get("playbook_id")
    stage_num = tool_input.get("stage")
    params = tool_input.get("params", {})

    # No playbook specified — list available
    if not playbook_id:
        playbooks = list_playbooks()
        if not playbooks:
            return {"_message": "No KQL playbooks found in config/kql_playbooks/."}
        lines = ["**Available KQL Playbooks:**\n"]
        for pb in playbooks:
            lines.append(f"### `{pb['id']}`")
            lines.append(f"{pb['description']}\n")
            if pb.get("parameters"):
                lines.append("**Parameters:**")
                for p in pb["parameters"]:
                    if isinstance(p, dict):
                        name = p.get("name", "?")
                        desc = p.get("description", "")
                        default = p.get("default", "")
                        lines.append(f"- `{name}`: {desc}" + (f" (default: {default})" if default else ""))
                lines.append("")
            if pb.get("stages"):
                lines.append("**Stages:**")
                for s in pb["stages"]:
                    if isinstance(s, dict):
                        label = s.get("stage", s.get("name", "?"))
                        name = s.get("name", "")
                        desc = s.get("description", "")
                        run = s.get("run", "always")
                        lines.append(f"- Stage {label}: {name} — {desc} (run: {run})")
                lines.append("")
            if pb.get("definitions"):
                lines.append("**Definitions:**")
                for d in pb["definitions"]:
                    if isinstance(d, dict):
                        lines.append(f"- **{d.get('term', '?')}** — {d.get('definition', '')}")
                lines.append("")
        return {"_message": "\n".join(lines)}

    # Load specific playbook
    pb = load_playbook(playbook_id)
    if not pb:
        available = [p["id"] for p in list_playbooks()]
        return {"_message": f"Playbook `{playbook_id}` not found. Available: {', '.join(available)}"}

    # Specific stage with params — render ready-to-run KQL
    if stage_num is not None and params:
        query = render_stage(pb, stage_num, params)
        if not query:
            stage_labels = [s.get("stage_label", str(s.get("stage", "?"))) for s in pb["stages"]]
            return {"_message": f"Stage {stage_num} not found in `{playbook_id}`. Available stages: {', '.join(stage_labels)}"}
        return {"_message": f"**{pb['name']} — Stage {stage_num}**\n\nReady-to-run KQL:\n```kql\n{query}\n```"}

    # Specific stage without params — show the template
    if stage_num is not None:
        for s in pb["stages"]:
            if s.get("stage") == stage_num:
                return {
                    "_message": (
                        f"**{pb['name']} — Stage {s.get('stage_label', stage_num)}: {s['name']}**\n\n"
                        f"Run condition: {s.get('run', 'always')}\n"
                        f"{s.get('description', '')}\n\n"
                        f"```kql\n{s['query']}\n```\n\n"
                        f"**Parameters to substitute:** Replace `{{{{param_name}}}}` placeholders "
                        f"with actual values, then execute via run_kql."
                    )
                }
        stage_labels = [s.get("stage_label", str(s.get("stage", "?"))) for s in pb["stages"]]
        return {"_message": f"Stage {stage_num} not found. Available: {', '.join(stage_labels)}"}

    # Full playbook overview
    lines = [f"**{pb['name']}**\n", f"{pb['description']}\n"]
    if pb.get("parameters"):
        lines.append("**Parameters:**")
        for p in pb["parameters"]:
            if isinstance(p, dict):
                name = p.get("name", "?")
                desc = p.get("description", "")
                default = p.get("default", "")
                lines.append(f"- `{name}`: {desc}" + (f" (default: {default})" if default else ""))
        lines.append("")

    lines.append(f"**{len(pb['stages'])} stages:**")
    for s in pb["stages"]:
        lines.append(f"- **Stage {s.get('stage_label', s['stage'])}** — {s['name']}")
        lines.append(f"  Run: {s.get('run', 'always')}")
        if s.get("description"):
            lines.append(f"  {s['description']}")
    lines.append("")
    if pb.get("definitions"):
        lines.append("**Definitions:**")
        for d in pb["definitions"]:
            if isinstance(d, dict):
                lines.append(f"- **{d.get('term', '?')}** — {d.get('definition', '')}")
        lines.append("")
    lines.append("Call again with `stage` and `params` to get a ready-to-run query.")
    return {"_message": "\n".join(lines)}


def execute_tool(case_id: str, tool_name: str, tool_input: dict, *, user_permissions: list[str] | None = None) -> str:
    """Execute a tool and return the result as a string for Claude."""
    try:
        result = _dispatch_tool(case_id, tool_name, tool_input, user_permissions=user_permissions or [])
        if isinstance(result, dict):
            # Return the _message if available, plus key data
            msg = result.get("message") or result.get("_message", "")
            if msg:
                return msg
            # Fall back to JSON
            return json.dumps(result, indent=2, default=str)[:8000]
        return str(result)[:8000]
    except Exception as exc:
        tb = traceback.format_exc()
        from tools.common import log_error
        log_error(case_id, f"chat.execute_tool.{tool_name}", str(exc),
                  severity="error", traceback=tb)
        return f"Error running {tool_name}: {exc}"


def _dispatch_tool(case_id: str, tool_name: str, tool_input: dict, *, user_permissions: list[str] | None = None) -> dict:
    """Route tool call to the appropriate action function."""
    perms = user_permissions or []

    if tool_name == "run_kql":
        if "sentinel:query" not in perms and "admin" not in perms:
            return {"_message": "Permission denied — Sentinel query execution requires admin privileges."}
        return _run_kql_tool(tool_input)

    if tool_name == "assess_landscape":
        from tools.case_landscape import assess_landscape
        result = assess_landscape(
            days=tool_input.get("days"),
            client=tool_input.get("client"),
        )
        return {"_message": result.get("summary", "No data."), **result}

    elif tool_name == "link_cases":
        from tools.case_links import link_cases
        result = link_cases(
            tool_input.get("case_a", ""),
            tool_input.get("case_b", ""),
            tool_input.get("link_type", "related"),
            canonical=tool_input.get("canonical"),
            reason=tool_input.get("reason", ""),
        )
        if result.get("status") == "ok":
            msg = f"Linked **{result['case_a']}** ↔ **{result['case_b']}** ({result['link_type']})"
            if result.get("canonical"):
                msg += f"\nCanonical case: **{result['canonical']}**"
        else:
            msg = result.get("reason", "Link failed.")
        return {"_message": msg, **result}

    elif tool_name == "merge_cases":
        from tools.case_links import merge_cases
        result = merge_cases(
            tool_input.get("source_ids", []),
            tool_input.get("target_id", ""),
        )
        if result.get("status") == "ok":
            msg = (f"Merged **{', '.join(result['sources'])}** → **{result['target']}**\n"
                   f"- Artefacts: {result['artefacts_merged']}\n"
                   f"- IOC types: {', '.join(result['ioc_types_merged']) or 'none'}\n"
                   f"- Findings: {result['findings_merged']}")
            if result.get("errors"):
                msg += f"\n- Warnings: {'; '.join(result['errors'])}"
        else:
            msg = result.get("reason", "Merge failed.")
        return {"_message": msg, **result}

    elif tool_name == "recall_cases":
        from tools.recall import recall
        result = recall(
            iocs=tool_input.get("iocs", []),
            emails=tool_input.get("emails", []),
            keywords=tool_input.get("keywords", []),
        )
        return {"_message": result.get("summary", "No results."), **result}

    elif tool_name == "capture_urls":
        urls = tool_input.get("urls", [])
        if not urls:
            return {"_message": "No URLs provided. Ask the analyst for URLs to capture."}
        return actions.capture_urls(case_id, urls)

    elif tool_name == "triage_iocs":
        urls = tool_input.get("urls")
        return actions.triage(case_id, urls=urls)

    elif tool_name == "enrich_iocs":
        return actions.extract_and_enrich(case_id)

    elif tool_name == "detect_phishing":
        return actions.detect_phishing(case_id)

    elif tool_name == "correlate":
        return actions.correlate(case_id)

    elif tool_name == "analyse_email":
        eml_dir = CASES_DIR / case_id / "uploads"
        eml_paths = [str(f) for f in eml_dir.glob("*.eml")] if eml_dir.exists() else []
        if not eml_paths:
            return {"_message": "No .eml files found in uploads. Ask the analyst to upload email files first."}
        return actions.analyse_email(case_id, eml_paths)

    elif tool_name == "generate_report":
        close_case = tool_input.get("close_case", False)
        return actions.generate_report(case_id, close_case=close_case)

    elif tool_name == "generate_mdr_report":
        from tools.generate_mdr_report import generate_mdr_report
        result = generate_mdr_report(case_id)
        if result.get("status") == "ok":
            report_path = Path(result["report_path"])
            report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
            return {"_message": report_text or "MDR report generated.", **result}
        return {"_message": result.get("reason", "MDR report generation failed."), **result}

    elif tool_name == "generate_fp_ticket":
        alert_data = tool_input.get("alert_data", "")
        platform = tool_input.get("platform")
        if not alert_data:
            return {"_message": "No alert data provided. Ask the analyst to paste the alert JSON."}
        return actions.generate_fp_ticket(case_id, alert_data=alert_data, platform=platform)

    elif tool_name == "generate_queries":
        platforms = tool_input.get("platforms")
        return actions.generate_queries(case_id, platforms=platforms)

    elif tool_name == "campaign_cluster":
        return actions.run_campaign_cluster(case_id)

    elif tool_name == "security_arch_review":
        return actions.security_arch_review(case_id)

    elif tool_name == "reconstruct_timeline":
        return actions.reconstruct_timeline(case_id)

    elif tool_name == "analyse_pe_files":
        return actions.analyse_pe_files(case_id)

    elif tool_name == "yara_scan":
        generate_rules = tool_input.get("generate_rules", False)
        return actions.yara_scan_action(case_id, generate_rules=generate_rules)

    elif tool_name == "correlate_event_logs":
        return actions.correlate_event_logs(case_id)

    elif tool_name == "contextualise_cves":
        return actions.contextualise_cves(case_id)

    elif tool_name == "generate_executive_summary":
        return actions.generate_exec_summary(case_id)

    elif tool_name == "add_evidence":
        text = tool_input.get("text", "")
        if not text:
            return {"_message": "No text provided to add as evidence."}
        return actions.add_evidence(case_id, text)

    elif tool_name == "read_case_file":
        file_path = tool_input.get("file_path", "")
        return read_case_file(case_id, file_path)

    elif tool_name == "run_full_pipeline":
        meta = _load_case_meta(case_id) or {}
        kwargs = {
            "title": meta.get("title", ""),
            "severity": meta.get("severity", "medium"),
            "analyst": meta.get("analyst", "chat"),
        }
        return actions.run_full_pipeline(case_id, kwargs)

    elif tool_name == "load_kql_playbook":
        return _handle_kql_playbook(tool_input)

    else:
        return {"_message": f"Unknown tool: {tool_name}"}


def read_case_file(case_id: str, file_path: str) -> dict:
    """Read an artefact file from the case directory."""
    # Sanitise: prevent directory traversal
    clean = Path(file_path).as_posix()
    if ".." in clean:
        return {"_message": "Invalid path — directory traversal not allowed."}

    full_path = CASES_DIR / case_id / clean
    if not full_path.exists():
        # Try common alternate locations
        alternates = [
            CASES_DIR / case_id / "artefacts" / clean,
            CASES_DIR / case_id / "artefacts" / "reports" / Path(clean).name,
        ]
        for alt in alternates:
            if alt.exists():
                full_path = alt
                break
        else:
            return {"_message": f"File not found: {file_path}"}

    try:
        content = full_path.read_text(encoding="utf-8", errors="replace")
        # Truncate very large files
        if len(content) > 15000:
            content = content[:15000] + "\n\n... [truncated — file is too large to display in full]"
        return {"_message": content}
    except Exception as exc:
        return {"_message": f"Error reading {file_path}: {exc}"}


# ---------------------------------------------------------------------------
# Chat history persistence
# ---------------------------------------------------------------------------

def _history_path(case_id: str, user_email: str | None = None) -> Path:
    if user_email:
        safe_email = user_email.replace("@", "_at_").replace(".", "_")
        return CASES_DIR / case_id / f"chat_history_{safe_email}.json"
    return CASES_DIR / case_id / "chat_history.json"


def load_history(case_id: str, user_email: str | None = None) -> list[dict]:
    """Load chat history for a case, scoped to a specific user when provided."""
    path = _history_path(case_id, user_email)
    if not path.exists():
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return []


def save_history(case_id: str, history: list[dict], user_email: str | None = None) -> None:
    """Save chat history for a case, scoped to a specific user when provided."""
    # Stamp any messages missing a timestamp
    now = _utcnow()
    for msg in history:
        if "ts" not in msg:
            msg["ts"] = now
    path = _history_path(case_id, user_email)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(history, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# Main chat function — multi-turn tool loop
# ---------------------------------------------------------------------------

def chat(case_id: str, user_message: str, history: list[dict] | None = None, *, model_override: str | None = None, user_email: str | None = None, user_permissions: list[str] | None = None) -> dict:
    """
    Process a user message in the case chat.

    Returns:
        {"reply": str, "tool_calls": list[dict], "history": list[dict]}
    """
    if not ANTHROPIC_KEY:
        return {
            "reply": "Chat requires an Anthropic API key. Set ANTHROPIC_API_KEY in .env.",
            "tool_calls": [],
            "history": history or [],
        }

    return _chat_inner(case_id, user_message, history, model_override=model_override,
                       user_email=user_email, user_permissions=user_permissions)


def _chat_inner(case_id: str, user_message: str, history: list[dict] | None = None, *, model_override: str | None = None, user_email: str | None = None, user_permissions: list[str] | None = None) -> dict:
    """Inner chat implementation — always runs inside force_fast_model context."""
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    system_prompt = build_system_prompt(case_id)

    # Two-tier model: fast for routing (tool selection), heavy for final response
    _meta = _load_case_meta(case_id) or {}
    _severity = _meta.get("severity", "medium")
    if model_override and model_override in ("fast", "standard", "heavy"):
        import config.settings as _s
        _tier_map = {"fast": "SOCAI_MODEL_FAST", "standard": "SOCAI_MODEL_STANDARD", "heavy": "SOCAI_MODEL_HEAVY"}
        # Override applies to both tiers
        _routing_model = getattr(_s, _tier_map[model_override])
        _response_model = _routing_model
    else:
        _routing_model = get_model("chat_routing", _severity)
        _response_model = get_model("chat_response", _severity)

    if history is None:
        history = load_history(case_id, user_email)

    # Append user message
    history.append({"role": "user", "content": user_message})

    # Log to timeline
    timeline.append(case_id, "analyst", {"message": user_message})

    tool_calls_log = []

    # Multi-turn loop: fast model routes, heavy model responds
    for _turn in range(MAX_TURNS):
        # Use routing model while tools are being selected;
        # switch to response model on final turn (no pending tool results)
        _model = _routing_model if _turn < MAX_TURNS - 1 else _response_model
        try:
            response = client.messages.create(
                model=_model,
                system=system_prompt,
                tools=TOOL_DEFS,
                tool_choice={"type": "auto"},
                messages=_prepare_messages_for_api(history, _model),
                max_tokens=4096,
            )
        except Exception as exc:
            from tools.common import log_error
            log_error(case_id, "chat.llm_call", str(exc), severity="error")
            error_msg = f"LLM API call failed: {exc}"
            timeline.append(case_id, "action_error", {"action": "chat", "error": error_msg})
            return {
                "reply": f"I encountered an error calling the AI model: {exc}",
                "tool_calls": tool_calls_log,
                "history": history,
            }

        # Convert response content to serialisable format
        assistant_content = _serialise_content(response.content)
        history.append({"role": "assistant", "content": assistant_content})

        # Process tool calls
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result_text = execute_tool(case_id, block.name, block.input, user_permissions=user_permissions)
                tool_calls_log.append({
                    "tool": block.name,
                    "input": block.input,
                    "result": result_text,
                })
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text,
                })

        if not tool_results:
            # No tools called — if this was a routing turn, re-run with heavy
            # model so the final analysis is meticulous
            if _model == _routing_model and _routing_model != _response_model:
                # Remove the fast model's response and re-generate with heavy
                history.pop()  # remove fast model's assistant message
                try:
                    response = client.messages.create(
                        model=_response_model,
                        system=system_prompt,
                        tools=TOOL_DEFS,
                        tool_choice={"type": "auto"},
                        messages=_prepare_messages_for_api(history, _model),
                        max_tokens=4096,
                    )
                except Exception as exc:
                    from tools.common import log_error
                    log_error(case_id, "chat.llm_call", str(exc), severity="error")
                    return {
                        "reply": f"I encountered an error calling the AI model: {exc}",
                        "tool_calls": tool_calls_log,
                        "history": history,
                    }
                assistant_content = _serialise_content(response.content)
                history.append({"role": "assistant", "content": assistant_content})

                # Heavy model might also call tools — process them
                for block in response.content:
                    if block.type == "tool_use":
                        result_text = execute_tool(case_id, block.name, block.input, user_permissions=user_permissions)
                        tool_calls_log.append({
                            "tool": block.name,
                            "input": block.input,
                            "result": result_text,
                        })
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result_text,
                        })
                if tool_results:
                    history.append({"role": "user", "content": tool_results})
                    continue  # keep looping with heavy model
            break

        # Feed tool results back
        history.append({"role": "user", "content": tool_results})

    # Extract final text response
    reply = _extract_text(response.content)

    # Log assistant response to timeline
    timeline.append(case_id, "action_done", {
        "action": "chat",
        "message": reply[:500] if reply else "Chat response",
    })

    # Save history
    save_history(case_id, history, user_email)

    return {
        "reply": reply,
        "tool_calls": tool_calls_log,
        "history": history,
    }


def _serialise_content(content) -> list[dict]:
    """Convert Anthropic content blocks to JSON-serialisable dicts.

    Preserves all block types so compaction/thinking blocks can round-trip
    through history save/load.
    """
    result = []
    for block in content:
        btype = getattr(block, "type", None)
        if btype == "text":
            result.append({"type": "text", "text": block.text})
        elif btype == "tool_use":
            result.append({
                "type": "tool_use",
                "id": block.id,
                "name": block.name,
                "input": block.input,
            })
        elif btype == "thinking":
            result.append({"type": "thinking", "thinking": getattr(block, "thinking", "")})
        elif btype == "redacted_thinking":
            result.append({"type": "redacted_thinking", "data": getattr(block, "data", "")})
        else:
            # Preserve unknown block types for forward compatibility
            serialised = {"type": btype}
            for attr in ("text", "id", "name", "input", "data"):
                val = getattr(block, attr, None)
                if val is not None:
                    serialised[attr] = val
            result.append(serialised)
    return result


def _extract_text(content) -> str:
    """Extract all text blocks from an Anthropic response."""
    parts = []
    for block in content:
        if block.type == "text":
            parts.append(block.text)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Streaming chat generators (SSE)
# ---------------------------------------------------------------------------

def _stream_one_turn(client, model, system, tools, messages, max_tokens):
    """Stream a single API turn, yielding SSE event dicts.

    Yields ``text_delta``, ``tool_start``, events. Returns the final
    ``Message`` object via ``stream.get_final_message()``.
    """
    with client.messages.stream(
        model=model,
        system=system,
        tools=tools,
        tool_choice={"type": "auto"},
        messages=messages,
        max_tokens=max_tokens,
    ) as stream:
        for event in stream:
            etype = getattr(event, "type", "")
            if etype == "content_block_delta":
                delta = getattr(event, "delta", None)
                if delta and getattr(delta, "type", "") == "text_delta":
                    yield {"type": "text_delta", "text": delta.text}
            elif etype == "content_block_start":
                block = getattr(event, "content_block", None)
                if block and getattr(block, "type", "") == "tool_use":
                    yield {"type": "tool_start", "name": block.name, "input": {}}
        final = stream.get_final_message()
    return final


def chat_stream(case_id: str, user_message: str, *, model_override: str | None = None, user_email: str | None = None, user_permissions: list[str] | None = None):
    """Streaming version of ``chat()`` — yields SSE event dicts.

    Event types: ``text_delta``, ``tool_start``, ``tool_result``, ``done``, ``error``.
    """
    if not ANTHROPIC_KEY:
        yield {"type": "error", "message": "Chat requires an Anthropic API key."}
        return

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        system_prompt = build_system_prompt(case_id)

        _meta = _load_case_meta(case_id) or {}
        _severity = _meta.get("severity", "medium")
        if model_override and model_override in ("fast", "standard", "heavy"):
            import config.settings as _s
            _tier_map = {"fast": "SOCAI_MODEL_FAST", "standard": "SOCAI_MODEL_STANDARD", "heavy": "SOCAI_MODEL_HEAVY"}
            _routing_model = getattr(_s, _tier_map[model_override])
            _response_model = _routing_model
        else:
            _routing_model = get_model("chat_routing", _severity)
            _response_model = get_model("chat_response", _severity)

        history = load_history(case_id, user_email)
        history.append({"role": "user", "content": user_message})
        timeline.append(case_id, "analyst", {"message": user_message})

        tool_calls_log = []
        reply_text = ""
        response = None

        for _turn in range(MAX_TURNS):
            _model = _routing_model if _turn < MAX_TURNS - 1 else _response_model

            # Stream this turn
            text_parts = []
            gen = _stream_one_turn(client, _model, system_prompt, TOOL_DEFS,
                                   _prepare_messages_for_api(history, _model), 4096)
            # Consume the generator — _stream_one_turn uses return for final message
            final_message = None
            try:
                while True:
                    evt = next(gen)
                    if evt["type"] == "text_delta":
                        text_parts.append(evt["text"])
                    yield evt
            except StopIteration as si:
                final_message = si.value

            if final_message is None:
                yield {"type": "error", "message": "Stream ended without final message"}
                return

            response = final_message
            assistant_content = _serialise_content(response.content)
            history.append({"role": "assistant", "content": assistant_content})

            # Process tool calls
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    yield {"type": "tool_start", "name": block.name, "input": block.input}
                    result_text = execute_tool(case_id, block.name, block.input, user_permissions=user_permissions)
                    tool_calls_log.append({"tool": block.name, "input": block.input, "result": result_text})
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_text,
                    })
                    yield {"type": "tool_result", "name": block.name, "result": result_text[:500]}

            if not tool_results:
                # Re-stream with response model if routing model answered without tools
                if _model == _routing_model and _routing_model != _response_model:
                    history.pop()  # remove fast model response
                    text_parts = []
                    gen = _stream_one_turn(client, _response_model, system_prompt, TOOL_DEFS,
                                           _prepare_messages_for_api(history, _model), 4096)
                    try:
                        while True:
                            evt = next(gen)
                            if evt["type"] == "text_delta":
                                text_parts.append(evt["text"])
                            yield evt
                    except StopIteration as si:
                        final_message = si.value

                    if final_message is None:
                        yield {"type": "error", "message": "Stream ended without final message"}
                        return

                    response = final_message
                    assistant_content = _serialise_content(response.content)
                    history.append({"role": "assistant", "content": assistant_content})

                    # Heavy model might also call tools
                    for block in response.content:
                        if block.type == "tool_use":
                            yield {"type": "tool_start", "name": block.name, "input": block.input}
                            result_text = execute_tool(case_id, block.name, block.input, user_permissions=user_permissions)
                            tool_calls_log.append({"tool": block.name, "input": block.input, "result": result_text})
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": result_text,
                            })
                            yield {"type": "tool_result", "name": block.name, "result": result_text[:500]}
                    if tool_results:
                        history.append({"role": "user", "content": tool_results})
                        continue
                break

            history.append({"role": "user", "content": tool_results})

        # Final reply
        reply_text = _extract_text(response.content) if response else ""
        timeline.append(case_id, "action_done", {
            "action": "chat",
            "message": reply_text[:500] if reply_text else "Chat response",
        })
        save_history(case_id, history, user_email)

        yield {"type": "done", "reply": reply_text, "tool_calls": tool_calls_log}

    except Exception as exc:
        from tools.common import log_error as _log_error
        _log_error(case_id, "chat_stream.error", str(exc), severity="error")
        yield {"type": "error", "message": str(exc)}


def session_chat_stream(session_id: str, user_message: str, *, model_override: str | None = None, user_permissions: list[str] | None = None):
    """Streaming version of ``session_chat()`` — yields SSE event dicts."""
    if not ANTHROPIC_KEY:
        yield {"type": "error", "message": "Chat requires an Anthropic API key."}
        return

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        system_prompt = build_session_prompt(session_id)

        if model_override and model_override in ("fast", "standard", "heavy"):
            import config.settings as _s
            _tier_map = {"fast": "SOCAI_MODEL_FAST", "standard": "SOCAI_MODEL_STANDARD", "heavy": "SOCAI_MODEL_HEAVY"}
            _routing_model = getattr(_s, _tier_map[model_override])
            _response_model = _routing_model
        else:
            _routing_model = get_model("chat_routing", "medium")
            _response_model = get_model("chat_response", "medium")

        history = _session_load_history(session_id)
        history.append({"role": "user", "content": user_message})

        tool_calls_log = []
        materialised_case_id = None
        response = None

        def _track_materialise(block_name, result_text):
            nonlocal materialised_case_id
            if block_name == "materialise_case":
                import re
                m = re.search(r"Case \*\*(\w+)\*\* created", result_text)
                if m:
                    materialised_case_id = m.group(1)

        for _turn in range(MAX_TURNS):
            _model = _routing_model if _turn < MAX_TURNS - 1 else _response_model

            gen = _stream_one_turn(client, _model, system_prompt, SESSION_TOOL_DEFS,
                                   _prepare_messages_for_api(history, _model), 4096)
            final_message = None
            try:
                while True:
                    evt = next(gen)
                    yield evt
            except StopIteration as si:
                final_message = si.value

            if final_message is None:
                yield {"type": "error", "message": "Stream ended without final message"}
                return

            response = final_message
            assistant_content = _serialise_content(response.content)
            history.append({"role": "assistant", "content": assistant_content})

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    yield {"type": "tool_start", "name": block.name, "input": block.input}
                    result_text = execute_session_tool(session_id, block.name, block.input, user_permissions=user_permissions)
                    tool_calls_log.append({"tool": block.name, "input": block.input, "result": result_text})
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_text,
                    })
                    _track_materialise(block.name, result_text)
                    yield {"type": "tool_result", "name": block.name, "result": result_text[:500]}

                    # Emit case_context_loaded event for UI banner
                    if block.name == "load_case_context" and "Loaded case" in result_text:
                        ctx = _session_load_context(session_id)
                        yield {
                            "type": "case_context_loaded",
                            "case_id": ctx.get("loaded_case_id", ""),
                            "title": ctx.get("loaded_case_title", ""),
                            "severity": ctx.get("loaded_case_severity", ""),
                        }

            if not tool_results:
                if _model == _routing_model and _routing_model != _response_model:
                    history.pop()
                    gen = _stream_one_turn(client, _response_model, system_prompt, SESSION_TOOL_DEFS,
                                           _prepare_messages_for_api(history, _model), 4096)
                    try:
                        while True:
                            evt = next(gen)
                            yield evt
                    except StopIteration as si:
                        final_message = si.value

                    if final_message is None:
                        yield {"type": "error", "message": "Stream ended without final message"}
                        return

                    response = final_message
                    assistant_content = _serialise_content(response.content)
                    history.append({"role": "assistant", "content": assistant_content})

                    for block in response.content:
                        if block.type == "tool_use":
                            yield {"type": "tool_start", "name": block.name, "input": block.input}
                            result_text = execute_session_tool(session_id, block.name, block.input, user_permissions=user_permissions)
                            tool_calls_log.append({"tool": block.name, "input": block.input, "result": result_text})
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": result_text,
                            })
                            _track_materialise(block.name, result_text)
                            yield {"type": "tool_result", "name": block.name, "result": result_text[:500]}
                    if tool_results:
                        history.append({"role": "user", "content": tool_results})
                        continue
                break

            history.append({"role": "user", "content": tool_results})

        reply_text = _extract_text(response.content) if response else ""
        _session_save_history(session_id, history)

        yield {"type": "done", "reply": reply_text, "tool_calls": tool_calls_log, "case_id": materialised_case_id}

    except Exception as exc:
        yield {"type": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Chat history display formatter
# ---------------------------------------------------------------------------

def get_display_history(case_id: str, user_email: str | None = None) -> list[dict]:
    """Return chat history in a display-friendly format for the UI."""
    history = load_history(case_id, user_email)
    display = []
    for msg in history:
        role = msg.get("role", "")
        content = msg.get("content", "")

        if role == "user":
            if isinstance(content, str):
                display.append({"role": "user", "content": content})
            elif isinstance(content, list):
                # Tool results — skip in display (shown inline with assistant)
                # But check for plain text too
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        continue  # Skip tool results in display
                    elif isinstance(block, dict) and block.get("type") == "text":
                        display.append({"role": "user", "content": block.get("text", "")})

        elif role == "assistant":
            text_parts = []
            tool_calls = []
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "text":
                            text_parts.append(block.get("text", ""))
                        elif block.get("type") == "tool_use":
                            tool_calls.append({
                                "name": block.get("name", ""),
                                "input": block.get("input", {}),
                            })

            if text_parts or tool_calls:
                entry = {"role": "assistant"}
                if text_parts:
                    entry["content"] = "\n".join(text_parts)
                if tool_calls:
                    entry["tool_calls"] = tool_calls

                # Find matching tool results in the next message
                idx = history.index(msg)
                if idx + 1 < len(history):
                    next_msg = history[idx + 1]
                    if next_msg.get("role") == "user" and isinstance(next_msg.get("content"), list):
                        results = []
                        for block in next_msg["content"]:
                            if isinstance(block, dict) and block.get("type") == "tool_result":
                                results.append(block.get("content", ""))
                        if results:
                            entry["tool_results"] = results

                display.append(entry)

    return display




# ---------------------------------------------------------------------------
# Session tool execution
# ---------------------------------------------------------------------------

def execute_session_tool(session_id: str, tool_name: str, tool_input: dict, *, user_permissions: list[str] | None = None) -> str:
    """Execute a session-scoped tool and return result as string."""
    try:
        result = _dispatch_session_tool(session_id, tool_name, tool_input, user_permissions=user_permissions or [])
        if isinstance(result, dict):
            msg = result.get("message") or result.get("_message", "")
            if msg:
                return msg
            return json.dumps(result, indent=2, default=str)[:8000]
        return str(result)[:8000]
    except Exception as exc:
        tb = traceback.format_exc()
        return f"Error running {tool_name}: {exc}"


def _session_ensure_backing_case(session_id: str) -> str:
    """Ensure a backing case exists for session artefact storage (web captures, etc.).

    Creates a case on first call and stores the ID in session context.
    Returns the case_id.
    """
    from api.sessions import load_context, save_context

    ctx = load_context(session_id)
    existing = ctx.get("backing_case_id")
    if existing and (CASES_DIR / existing).exists():
        return existing

    # Generate a new case ID
    from api.jobs import JobManager
    case_id = JobManager.next_case_id()

    # Minimal case creation — just enough for tools to write artefacts
    from tools.case_create import case_create
    case_create(case_id, title=f"Session {session_id[:8]} investigation", severity="medium")

    # Store in session context
    ctx["backing_case_id"] = case_id
    save_context(session_id, ctx)

    print(f"[session] Created backing case {case_id} for session {session_id[:8]}")
    return case_id


def _dispatch_session_tool(session_id: str, tool_name: str, tool_input: dict, *, user_permissions: list[str] | None = None) -> dict:
    """Route session tool calls."""
    perms = user_permissions or []

    if tool_name == "run_kql":
        if "sentinel:query" not in perms and "admin" not in perms:
            return {"_message": "Permission denied — Sentinel query execution requires admin privileges."}
        return _run_kql_tool(tool_input)

    if tool_name == "assess_landscape":
        from tools.case_landscape import assess_landscape
        result = assess_landscape(
            days=tool_input.get("days"),
            client=tool_input.get("client"),
        )
        return {"_message": result.get("summary", "No data."), **result}

    elif tool_name == "link_cases":
        from tools.case_links import link_cases
        result = link_cases(
            tool_input.get("case_a", ""),
            tool_input.get("case_b", ""),
            tool_input.get("link_type", "related"),
            canonical=tool_input.get("canonical"),
            reason=tool_input.get("reason", ""),
        )
        if result.get("status") == "ok":
            msg = f"Linked **{result['case_a']}** ↔ **{result['case_b']}** ({result['link_type']})"
            if result.get("canonical"):
                msg += f"\nCanonical case: **{result['canonical']}**"
        else:
            msg = result.get("reason", "Link failed.")
        return {"_message": msg, **result}

    elif tool_name == "merge_cases":
        from tools.case_links import merge_cases
        result = merge_cases(
            tool_input.get("source_ids", []),
            tool_input.get("target_id", ""),
        )
        if result.get("status") == "ok":
            msg = (f"Merged **{', '.join(result['sources'])}** → **{result['target']}**\n"
                   f"- Artefacts: {result['artefacts_merged']}\n"
                   f"- IOC types: {', '.join(result['ioc_types_merged']) or 'none'}\n"
                   f"- Findings: {result['findings_merged']}")
        else:
            msg = result.get("reason", "Merge failed.")
        return {"_message": msg, **result}

    elif tool_name == "recall_cases":
        from tools.recall import recall
        result = recall(
            iocs=tool_input.get("iocs", []),
            emails=tool_input.get("emails", []),
            keywords=tool_input.get("keywords", []),
        )
        return {"_message": result.get("summary", "No results."), **result}

    elif tool_name == "capture_urls":
        urls = tool_input.get("urls", [])
        if not urls:
            return {"_message": "No URLs provided."}

        # Ensure a backing case exists for artefact storage
        case_id = _session_ensure_backing_case(session_id)

        from api import actions
        result = actions.capture_urls(case_id, urls)

        # Save extracted URLs as IOCs in session context
        _session_add_iocs(session_id, {"urls": urls})

        captured = result.get("captured", 0) if isinstance(result, dict) else 0
        msg = f"Captured {captured} page(s) for case {case_id}."
        if isinstance(result, dict):
            result["_message"] = msg
            result["backing_case_id"] = case_id
        else:
            result = {"_message": msg, "backing_case_id": case_id}
        return result

    elif tool_name == "detect_phishing":
        ctx = _session_load_context(session_id)
        case_id = ctx.get("backing_case_id")
        if not case_id:
            return {"_message": "No URLs have been captured yet. Use capture_urls first."}

        from tools.detect_phishing_page import detect_phishing_page
        result = detect_phishing_page(case_id)

        # Record key findings in session context
        findings = result.get("findings", [])
        if findings:
            high = [f for f in findings if f.get("confidence") == "high"]
            medium = [f for f in findings if f.get("confidence") == "medium"]
            summary_parts = []
            if high:
                summary_parts.append(f"{len(high)} HIGH confidence")
            if medium:
                summary_parts.append(f"{len(medium)} MEDIUM confidence")
            _session_add_finding(
                session_id, "phishing_detection",
                f"Phishing signals: {', '.join(summary_parts) or 'none'}",
                detail="; ".join(
                    f"{f['brand']} on {f['hostname']} ({f['confidence']}, via {f.get('source', 'regex')})"
                    for f in findings
                ),
            )

        summary = result.get("summary", {})
        heuristic_count = summary.get("pages_with_heuristic_signals", 0)
        escalated = summary.get("pages_escalated_to_llm", 0)

        lines = [f"Scanned {result.get('scanned', 0)} page(s)."]
        if summary.get("high_confidence"):
            lines.append(f"**{summary['high_confidence']} HIGH confidence** phishing finding(s)")
        if summary.get("medium_confidence"):
            lines.append(f"**{summary['medium_confidence']} MEDIUM confidence** finding(s)")
        if summary.get("credential_harvest_pages"):
            lines.append(f"**{summary['credential_harvest_pages']}** credential harvest page(s)")
        if summary.get("suspicious_tls_certs"):
            lines.append(f"**{summary['suspicious_tls_certs']}** suspicious TLS certificate(s)")
        if heuristic_count:
            lines.append(f"**{heuristic_count}** page(s) with structural heuristic signals")
        if escalated:
            lines.append(f"**{escalated}** page(s) escalated to LLM analysis")
        if not any(summary.get(k) for k in ("high_confidence", "medium_confidence",
                                              "credential_harvest_pages", "suspicious_tls_certs")):
            if heuristic_count:
                lines.append("No definitive findings, but heuristic signals present — review recommended.")
            else:
                lines.append("No phishing signals detected.")

        result["_message"] = "\n".join(lines)
        return result

    elif tool_name == "analyse_telemetry":
        filename = tool_input.get("filename", "")
        if not filename:
            return {"_message": "No filename provided. Specify which uploaded file to analyse."}
        file_path = SESSIONS_DIR / session_id / "uploads" / filename
        if not file_path.exists():
            # Try case-insensitive match
            uploads = _session_upload_dir(session_id)
            for f in uploads.iterdir():
                if f.name.lower() == filename.lower():
                    file_path = f
                    break
            else:
                available = _session_list_uploads(session_id)
                return {"_message": f"File not found: {filename}. Available: {', '.join(available) or 'none'}"}

        from tools.telemetry_analysis import analyse_telemetry
        result = analyse_telemetry(str(file_path), session_id)

        # Save telemetry summary to session context
        if result.get("event_count", 0) > 0:
            _session_add_telemetry(session_id, {
                "source_file": result.get("source_file", filename),
                "event_count": result.get("event_count", 0),
                "platform": result.get("platform", "unknown"),
                "time_range": f"{result.get('time_range', {}).get('start', '?')} — {result.get('time_range', {}).get('end', '?')}",
                "computers": list(result.get("computers", {}).keys()),
                "users": list(result.get("users", {}).keys()),
                "top_tactics": list(result.get("tactics", {}).keys())[:5],
            })

            # Auto-extract IOCs from telemetry
            iocs_to_add = {}
            remote_ips = list(result.get("remote_ips", {}).keys())
            if remote_ips:
                iocs_to_add["ips"] = remote_ips
            domains = result.get("domains_queried", [])
            if domains:
                iocs_to_add["domains"] = domains
            if iocs_to_add:
                _session_add_iocs(session_id, iocs_to_add)

        return result

    elif tool_name == "read_uploaded_file":
        filename = tool_input.get("filename", "")
        offset = tool_input.get("offset", 0)
        limit = tool_input.get("limit", 200)
        if not filename:
            return {"_message": "No filename provided."}
        file_path = SESSIONS_DIR / session_id / "uploads" / filename
        if not file_path.exists():
            available = _session_list_uploads(session_id)
            return {"_message": f"File not found: {filename}. Available: {', '.join(available) or 'none'}"}
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").split("\n")
            total = len(lines)
            chunk = lines[offset:offset + limit]
            content = "\n".join(chunk)
            if len(content) > 15000:
                content = content[:15000] + "\n... [truncated]"
            return {"_message": f"[{filename} — lines {offset}-{offset+len(chunk)} of {total}]\n\n{content}"}
        except Exception as exc:
            return {"_message": f"Error reading {filename}: {exc}"}

    elif tool_name == "extract_iocs":
        text = tool_input.get("text", "")
        if not text:
            return {"_message": "No text provided."}
        from api.parse_input import parse_analyst_input
        parsed = parse_analyst_input(text)
        iocs = {}
        if parsed.get("urls"):
            iocs["urls"] = parsed["urls"]
        if parsed.get("ips"):
            iocs["ips"] = parsed["ips"]
        if parsed.get("hashes"):
            iocs["hashes"] = parsed["hashes"]
        if parsed.get("emails"):
            iocs["emails"] = parsed["emails"]
        if iocs:
            _session_add_iocs(session_id, iocs)
            parts = [f"{len(v)} {k}" for k, v in iocs.items()]
            return {"_message": f"IOCs extracted and saved: {', '.join(parts)}"}
        return {"_message": "No IOCs found in the provided text."}

    elif tool_name == "add_finding":
        ftype = tool_input.get("finding_type", "general")
        summary = tool_input.get("summary", "")
        detail = tool_input.get("detail", "")
        if not summary:
            return {"_message": "No summary provided for the finding."}
        _session_add_finding(session_id, ftype, summary, detail)
        return {"_message": f"Finding recorded: [{ftype}] {summary}"}

    elif tool_name == "materialise_case":
        title = tool_input.get("title", "Investigation")
        severity = tool_input.get("severity", "medium")
        disposition = tool_input.get("disposition", "")
        meta = _session_load_context(session_id)

        # Get user email from session meta
        from api.sessions import load_session
        smeta = load_session(session_id)
        analyst = smeta.get("user_email", "unknown") if smeta else "unknown"

        # Generate case ID
        from api.jobs import JobManager
        case_id = JobManager.next_case_id()

        from api.sessions import materialise
        result = materialise(session_id, case_id, title, severity, analyst, disposition)

        if disposition:
            _session_set_disposition(session_id, disposition)

        return {
            "_message": (
                f"Case **{case_id}** created from session.\n"
                f"- Title: {title}\n"
                f"- Severity: {severity}\n"
                f"- Disposition: {disposition}\n"
                f"- IOCs saved: {result.get('iocs_saved', False)}\n"
                f"- Findings: {result.get('findings_count', 0)}\n"
                f"- Uploads moved: {result.get('uploads_moved', 0)}"
            ),
            "case_id": case_id,
        }

    elif tool_name == "generate_fp_comment":
        template_name = tool_input.get("template", "")
        ctx = _session_load_context(session_id)
        return _generate_fp_comment_from_context(session_id, ctx, template_name)

    elif tool_name == "generate_mdr_report":
        ctx = _session_load_context(session_id)
        return _generate_mdr_report_from_context(session_id, ctx)

    elif tool_name == "enrich_iocs":
        # Create a temp case-like structure for enrichment, or enrich inline
        ctx = _session_load_context(session_id)
        iocs = ctx.get("iocs", {})
        if not any(iocs.get(t) for t in ("ips", "domains", "hashes", "urls")):
            return {"_message": "No IOCs to enrich. Extract IOCs from telemetry or text first."}
        return _enrich_session_iocs(session_id, iocs)

    elif tool_name == "triage_iocs":
        ctx = _session_load_context(session_id)
        iocs = ctx.get("iocs", {})
        urls = iocs.get("urls", [])
        ips = iocs.get("ips", [])
        domains = iocs.get("domains", [])
        all_iocs = urls + [f"https://{d}" for d in domains]
        if not all_iocs and not ips:
            return {"_message": "No IOCs to triage. Extract IOCs first."}
        # Use triage tool directly with IOC list
        try:
            from tools.triage import triage as _triage
            # Triage needs a case_id but we can pass a dummy and override
            result = _triage("SESSION", urls=all_iocs or None)
            lines = []
            mal = result.get("known_malicious", [])
            sus = result.get("known_suspicious", [])
            if mal:
                lines.append(f"**{len(mal)} known malicious** from prior cases")
            if sus:
                lines.append(f"**{len(sus)} known suspicious** from prior cases")
            if not mal and not sus:
                lines.append("No known malicious or suspicious IOCs in prior cases.")
            result["_message"] = "\n".join(lines)
            return result
        except Exception as exc:
            return {"_message": f"Triage error: {exc}"}

    # ------------------------------------------------------------------
    # Case-backed tools — delegate to case-mode functions via backing case
    # ------------------------------------------------------------------

    elif tool_name == "analyse_email":
        case_id = _session_ensure_backing_case(session_id)
        uploads_dir = SESSIONS_DIR / session_id / "uploads"
        eml_files = list(uploads_dir.glob("*.eml")) if uploads_dir.exists() else []
        if not eml_files:
            return {"_message": "No .eml files found. Upload an .eml file first."}
        from tools.analyse_email import analyse_email
        results = []
        for eml_path in eml_files:
            result = analyse_email(str(eml_path), case_id)
            results.append(result)
            # Record URLs from email as IOCs
            urls = result.get("urls_extracted", [])
            if urls:
                _session_add_iocs(session_id, {"urls": urls})
            # Record spoofing findings
            spoofing = result.get("spoofing_indicators", [])
            if spoofing:
                _session_add_finding(session_id, "email_analysis",
                                     f"Spoofing indicators in {eml_path.name}",
                                     detail="; ".join(str(s) for s in spoofing[:5]))
        return {
            "_message": f"Analysed {len(eml_files)} .eml file(s) for case {case_id}.",
            "results": results,
        }

    elif tool_name == "correlate":
        case_id = _session_ensure_backing_case(session_id)
        from tools.correlate import correlate
        result = correlate(case_id)
        return {"_message": f"Correlation complete for {case_id}.", **result}

    elif tool_name == "generate_report":
        case_id = _session_ensure_backing_case(session_id)
        close = tool_input.get("close_case", False)
        from tools.generate_report import generate_report
        result = generate_report(case_id, close_case=close)
        report_path = result.get("report_path", "")
        return {"_message": f"Report generated: {report_path}", **result}

    elif tool_name == "generate_executive_summary":
        case_id = _session_ensure_backing_case(session_id)
        from tools.executive_summary import generate_executive_summary
        result = generate_executive_summary(case_id)
        return {"_message": "Executive summary generated.", **result}

    elif tool_name == "generate_fp_ticket":
        case_id = _session_ensure_backing_case(session_id)
        alert_data = tool_input.get("alert_data", "")
        platform = tool_input.get("platform")
        if not alert_data:
            return {"_message": "No alert data provided. Paste the alert JSON in your message."}
        from tools.fp_ticket import generate_fp_ticket
        result = generate_fp_ticket(
            case_id, alert_text=alert_data, platform_override=platform,
        )
        return {"_message": "FP ticket generated.", **result}

    elif tool_name == "generate_queries":
        case_id = _session_ensure_backing_case(session_id)
        platforms = tool_input.get("platforms")
        from tools.generate_queries import generate_queries
        result = generate_queries(case_id, platforms=platforms)
        return {"_message": "SIEM queries generated.", **result}

    elif tool_name == "reconstruct_timeline":
        case_id = _session_ensure_backing_case(session_id)
        from tools.timeline_reconstruct import reconstruct_timeline
        result = reconstruct_timeline(case_id)
        return {"_message": "Timeline reconstructed.", **result}

    elif tool_name == "security_arch_review":
        case_id = _session_ensure_backing_case(session_id)
        from tools.security_arch_review import security_arch_review
        result = security_arch_review(case_id)
        return {"_message": "Security architecture review complete.", **result}

    elif tool_name == "run_full_pipeline":
        case_id = _session_ensure_backing_case(session_id)
        ctx = _session_load_context(session_id)
        urls = ctx.get("iocs", {}).get("urls", [])
        from agents.chief import ChiefAgent
        chief = ChiefAgent(case_id)
        result = chief.run(
            urls=urls,
            severity="medium",
        )
        return {"_message": f"Full pipeline complete for {case_id}.", **result}

    elif tool_name == "contextualise_cves":
        case_id = _session_ensure_backing_case(session_id)
        from tools.cve_contextualise import contextualise_cves
        result = contextualise_cves(case_id)
        return {"_message": "CVE contextualisation complete.", **result}

    elif tool_name == "analyse_pe_files":
        case_id = _session_ensure_backing_case(session_id)
        from tools.pe_analysis import analyse_pe_files
        result = analyse_pe_files(case_id)
        return {"_message": "PE analysis complete.", **result}

    elif tool_name == "correlate_event_logs":
        case_id = _session_ensure_backing_case(session_id)
        from tools.evtx_correlate import correlate_evtx
        result = correlate_evtx(case_id)
        return {"_message": "Event log correlation complete.", **result}

    elif tool_name == "yara_scan":
        case_id = _session_ensure_backing_case(session_id)
        generate_rules = tool_input.get("generate_rules", False)
        from tools.yara_scan import yara_scan
        result = yara_scan(case_id, generate_rules=generate_rules)
        return {"_message": "YARA scan complete.", **result}

    elif tool_name == "read_case_file":
        case_id = _session_ensure_backing_case(session_id)
        file_path = tool_input.get("file_path", "")
        if not file_path:
            return {"_message": "No file path provided."}
        full_path = CASES_DIR / case_id / file_path
        if not full_path.exists():
            return {"_message": f"File not found: {file_path}"}
        # Prevent path traversal
        try:
            full_path.resolve().relative_to((CASES_DIR / case_id).resolve())
        except ValueError:
            return {"_message": "Invalid file path."}
        try:
            content = full_path.read_text(errors="replace")
            if len(content) > 15000:
                content = content[:15000] + "\n... [truncated]"
            return {"_message": f"[{file_path}]\n\n{content}"}
        except Exception as exc:
            return {"_message": f"Error reading file: {exc}"}

    elif tool_name == "add_evidence":
        case_id = _session_ensure_backing_case(session_id)
        text = tool_input.get("text", "")
        if not text:
            return {"_message": "No text provided."}
        from api.parse_input import parse_analyst_input
        parsed = parse_analyst_input(text)
        iocs = {}
        if parsed.get("urls"):
            iocs["urls"] = parsed["urls"]
        if parsed.get("ips"):
            iocs["ips"] = parsed["ips"]
        if parsed.get("hashes"):
            iocs["hashes"] = parsed["hashes"]
        if parsed.get("emails"):
            iocs["emails"] = parsed["emails"]
        if iocs:
            _session_add_iocs(session_id, iocs)
            parts = [f"{len(v)} {k}" for k, v in iocs.items()]
            return {"_message": f"Evidence saved to {case_id}: {', '.join(parts)}"}
        return {"_message": "No IOCs found in the provided text."}

    elif tool_name == "campaign_cluster":
        case_id = _session_ensure_backing_case(session_id)
        from tools.campaign_cluster import campaign_cluster
        result = campaign_cluster(case_id)
        return {"_message": "Campaign clustering complete.", **result}

    elif tool_name == "load_case_context":
        target_case = tool_input.get("case_id", "").strip()
        if not target_case:
            return {"_message": "No case_id provided."}
        case_dir = CASES_DIR / target_case
        if not case_dir.exists():
            return {"_message": f"Case {target_case} not found."}

        from tools.common import load_json as _load_json
        meta = _load_json(case_dir / "case_meta.json") or {}
        iocs = _load_json(case_dir / "iocs" / "iocs.json") or {}
        verdicts = _load_json(case_dir / "artefacts" / "enrichment" / "verdict_summary.json") or {}
        session_ctx = _load_json(case_dir / "session_context.json") or {}

        # Store the loaded case in session context
        ctx = _session_load_context(session_id)
        ctx["loaded_case_id"] = target_case
        ctx["loaded_case_title"] = meta.get("title", "")
        ctx["loaded_case_severity"] = meta.get("severity", "")
        from api.sessions import save_context
        save_context(session_id, ctx)

        # Build summary for LLM
        ioc_summary_parts = []
        for ioc_type, vals in iocs.items():
            if isinstance(vals, list) and vals:
                ioc_summary_parts.append(f"{ioc_type}: {len(vals)}")

        return {
            "_message": (
                f"Loaded case **{target_case}** — {meta.get('title', 'Untitled')}\n"
                f"- Severity: {meta.get('severity', 'unknown')}\n"
                f"- Status: {meta.get('status', 'unknown')}\n"
                f"- Disposition: {meta.get('disposition', 'undetermined')}\n"
                f"- IOCs: {', '.join(ioc_summary_parts) or 'none'}\n"
                f"- Findings: {len(session_ctx.get('findings', []))}\n"
                f"- High priority verdicts: {len(verdicts.get('high_priority', []))}"
            ),
            "case_id": target_case,
            "title": meta.get("title", ""),
            "severity": meta.get("severity", ""),
            "_event": "case_context_loaded",
        }

    elif tool_name == "save_to_case":
        target_case = tool_input.get("case_id", "").strip()
        updates = tool_input.get("updates", {})
        if not target_case:
            return {"_message": "No case_id provided."}
        case_dir = CASES_DIR / target_case
        if not case_dir.exists():
            return {"_message": f"Case {target_case} not found."}

        from tools.common import load_json as _load_json, save_json as _save_json, write_artefact as _write_artefact
        saved = []

        # Save findings
        if updates.get("findings"):
            ctx_path = case_dir / "session_context.json"
            ctx = _load_json(ctx_path) or {}
            existing = ctx.get("findings", [])
            for f in updates["findings"]:
                existing.append({
                    "type": f.get("type", "general"),
                    "summary": f.get("summary", ""),
                    "detail": f.get("detail", ""),
                })
            ctx["findings"] = existing
            _save_json(ctx_path, ctx)
            saved.append(f"{len(updates['findings'])} finding(s)")

        # Save IOCs (merge into existing)
        if updates.get("iocs"):
            ioc_path = case_dir / "iocs" / "iocs.json"
            existing_iocs = _load_json(ioc_path) or {}
            for ioc_type, vals in updates["iocs"].items():
                if isinstance(vals, list):
                    existing_list = existing_iocs.get(ioc_type, [])
                    merged = list(set(existing_list + vals))
                    existing_iocs[ioc_type] = merged
            ioc_path.parent.mkdir(parents=True, exist_ok=True)
            _save_json(ioc_path, existing_iocs)
            saved.append("IOCs")

        # Update status/disposition in case_meta
        meta_path = case_dir / "case_meta.json"
        meta = _load_json(meta_path) or {}
        if updates.get("status"):
            meta["status"] = updates["status"]
            saved.append(f"status → {updates['status']}")
        if updates.get("disposition"):
            meta["disposition"] = updates["disposition"]
            saved.append(f"disposition → {updates['disposition']}")
        if updates.get("notes"):
            notes_list = meta.get("analyst_notes", [])
            if isinstance(notes_list, str):
                notes_list = [notes_list]
            notes_list.append(updates["notes"])
            meta["analyst_notes"] = notes_list
            saved.append("notes")
        if any(updates.get(k) for k in ("status", "disposition", "notes")):
            _save_json(meta_path, meta)

        return {"_message": f"Saved to **{target_case}**: {', '.join(saved) or 'nothing to save'}"}

    elif tool_name == "load_kql_playbook":
        return _handle_kql_playbook(tool_input)

    return {"_message": f"Unknown session tool: {tool_name}"}


def _enrich_session_iocs(session_id: str, iocs: dict) -> dict:
    """Enrich IOCs from session context using the real provider registry."""
    try:
        from tools.enrich import (
            PROVIDERS, _fn_provider_name, _cache_load, _cache_get,
            _cache_set, _cache_save, _cache_lock, _is_known_clean,
            _intezer_get_token, _intezer_lookup,
        )
        from config.settings import ENRICH_WORKERS, INTEZER_KEY
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import functools

        # Map session IOC keys to enrichment provider keys
        import re as _re
        _SESSION_TO_PROVIDER = {
            "ips": "ipv4", "domains": "domain", "urls": "url", "emails": "email",
        }
        def _hash_type(h: str) -> str:
            l = len(h)
            if l == 32: return "md5"
            if l == 40: return "sha1"
            if l == 64: return "sha256"
            return ""

        # Flatten IOCs from context into (type, value) pairs
        all_iocs: list[tuple[str, str]] = []
        for session_key, items in iocs.items():
            for item in (items or []):
                if session_key == "hashes":
                    ptype = _hash_type(item)
                    if not ptype:
                        continue
                else:
                    ptype = _SESSION_TO_PROVIDER.get(session_key, session_key)
                if ptype not in PROVIDERS:
                    continue
                if not _is_known_clean(item, ptype):
                    all_iocs.append((ptype, item))
        if not all_iocs:
            return {"_message": "No enrichable IOCs in session context."}
        if len(all_iocs) > 50:
            all_iocs = all_iocs[:50]

        # Pre-fetch Intezer token once
        intezer_token = _intezer_get_token() if INTEZER_KEY else None
        local_providers: dict[str, list] = {}
        for ioc_type, fns in PROVIDERS.items():
            local_providers[ioc_type] = [
                functools.partial(_intezer_lookup, _token=intezer_token)
                if (fn is _intezer_lookup and intezer_token) else fn
                for fn in fns
            ]

        # Split into cache hits and work tasks
        with _cache_lock:
            cache = _cache_load()
        cached_results: list[dict] = []
        work_tasks: list[tuple] = []
        for ioc_type, ioc_val in all_iocs:
            for fn in local_providers.get(ioc_type, []):
                pname = _fn_provider_name(fn)
                hit = _cache_get(cache, ioc_val, pname)
                if hit is not None:
                    cached_results.append(hit)
                else:
                    work_tasks.append((fn, ioc_val, ioc_type))

        # Run live lookups in parallel
        def _run(task):
            fn, ioc, ioc_type = task
            try:
                return fn(ioc, ioc_type)
            except Exception as exc:
                return {"ioc": ioc, "provider": _fn_provider_name(fn),
                        "error": str(exc), "status": "error"}

        live_results: list[dict] = []
        if work_tasks:
            with ThreadPoolExecutor(max_workers=min(ENRICH_WORKERS, len(work_tasks))) as pool:
                for res in pool.map(_run, work_tasks):
                    live_results.append(res)

        # Update cache with successful results
        if live_results:
            with _cache_lock:
                fresh = _cache_load()
                for res in live_results:
                    if res.get("status") == "ok" and "error" not in res:
                        _cache_set(fresh, res.get("ioc", ""), res.get("provider", ""), res)
                _cache_save(fresh)

        all_results = cached_results + live_results

        # Save enrichment to session artefacts
        from api.sessions import SESSIONS_DIR
        enrich_path = SESSIONS_DIR / session_id / "artefacts" / "enrichment.json"
        enrich_path.parent.mkdir(parents=True, exist_ok=True)
        import json as _json
        enrich_path.write_text(_json.dumps(all_results, indent=2, default=str))

        # Summarise verdicts
        malicious, suspicious, clean, errors = [], [], [], []
        for r in all_results:
            ioc_val = r.get("ioc", "")
            verdict = r.get("verdict", r.get("status", ""))
            if r.get("error"):
                errors.append(r.get("provider", "unknown"))
            elif verdict == "malicious" and ioc_val not in malicious:
                malicious.append(ioc_val)
            elif verdict == "suspicious" and ioc_val not in suspicious:
                suspicious.append(ioc_val)
            elif ioc_val not in clean:
                clean.append(ioc_val)

        # Update session context with enrichment findings
        if malicious:
            _session_add_finding(session_id, "enrichment",
                                 f"{len(malicious)} malicious IOC(s): {', '.join(malicious[:10])}")
        if suspicious:
            _session_add_finding(session_id, "enrichment",
                                 f"{len(suspicious)} suspicious IOC(s): {', '.join(suspicious[:10])}")

        lines = [f"Enriched {len(all_iocs)} IOC(s) across {len(all_results)} provider lookups "
                 f"({len(cached_results)} cached, {len(live_results)} live)."]
        if malicious:
            lines.append(f"**{len(malicious)} malicious:** {', '.join(malicious[:5])}")
        if suspicious:
            lines.append(f"**{len(suspicious)} suspicious:** {', '.join(suspicious[:5])}")
        if not malicious and not suspicious:
            lines.append("No malicious or suspicious IOCs detected.")
        if errors:
            unique_errs = list(set(errors))
            lines.append(f"Provider errors: {', '.join(unique_errs[:5])}")

        return {"_message": "\n".join(lines), "enriched": len(all_iocs),
                "malicious": malicious, "suspicious": suspicious,
                "total_lookups": len(all_results), "errors": len(errors)}

    except Exception as exc:
        return {"_message": f"Enrichment error: {exc}"}


# ---------------------------------------------------------------------------
# FP comment generation from session context
# ---------------------------------------------------------------------------

def _generate_fp_comment_from_context(session_id: str, ctx: dict, template_name: str = "") -> dict:
    """Generate an FP comment using LLM + accumulated session context."""
    if not ANTHROPIC_KEY:
        return {"_message": "FP comment generation requires an Anthropic API key."}

    # Load template if configured
    template_text = _load_fp_template(template_name)

    # Build context for LLM
    findings_text = ""
    for f in ctx.get("findings", []):
        findings_text += f"\n- [{f.get('type', '?')}] {f.get('summary', '')}"
        if f.get("detail"):
            findings_text += f"\n  {f['detail']}"

    telemetry_text = ""
    for t in ctx.get("telemetry_summaries", []):
        telemetry_text += f"\n- {t.get('source_file', '?')}: {t.get('event_count', '?')} events"
        telemetry_text += f" (platform: {t.get('platform', '?')})"
        if t.get("computers"):
            telemetry_text += f", hosts: {', '.join(t['computers'])}"
        if t.get("users"):
            telemetry_text += f", users: {', '.join(t['users'])}"

    iocs_text = ""
    for itype, items in ctx.get("iocs", {}).items():
        if items:
            iocs_text += f"\n{itype}: {', '.join(items[:20])}"

    system = f"""You are a SOC analyst generating a False Positive closure comment.
Based on the investigation context below, generate a professional, structured FP closure comment.

{f"Use this template format:{chr(10)}{template_text}" if template_text else ""}

The comment should include:
1. Disposition line (False Positive + category)
2. Summary (1-2 sentences)
3. Analysis (evidence-based, citing specific IOCs, processes, domains)
4. Hashes verified (if any)
5. Recommendation (prevent recurrence)

INVESTIGATION CONTEXT:
Findings:{findings_text or " None recorded"}
Telemetry:{telemetry_text or " None analysed"}
IOCs:{iocs_text or " None collected"}
Disposition: {ctx.get('disposition', 'false_positive')}"""

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        response = client.messages.create(
            model=get_model("fp_ticket", "medium"),
            system=[{"type": "text", "text": system}],
            messages=[{"role": "user", "content": "Generate the FP closure comment now."}],
            max_tokens=2000,
        )
        comment = _extract_text(response.content)

        # Save to session artefacts
        art_dir = SESSIONS_DIR / session_id / "artefacts" / "fp_comms"
        art_dir.mkdir(parents=True, exist_ok=True)
        (art_dir / "fp_comment.md").write_text(comment)

        return {"_message": comment}
    except Exception as exc:
        return {"_message": f"Error generating FP comment: {exc}"}


def _load_fp_template(template_name: str) -> str:
    """Load an FP comment template from config/fp_templates/."""
    templates_dir = Path(__file__).resolve().parent.parent / "config" / "fp_templates"
    if not templates_dir.exists():
        return ""

    if template_name:
        # Direct name match
        for ext in (".md", ".txt", ""):
            path = templates_dir / f"{template_name}{ext}"
            if path.exists():
                return path.read_text(encoding="utf-8", errors="replace")
        return ""

    # Auto-detect: use default.md if it exists
    default = templates_dir / "default.md"
    if default.exists():
        return default.read_text(encoding="utf-8", errors="replace")
    return ""


# ---------------------------------------------------------------------------
# MDR report generation from session context
# ---------------------------------------------------------------------------

def _generate_mdr_report_from_context(session_id: str, ctx: dict) -> dict:
    """Generate an MDR-style report using the Gold MDR/XDR Analyst Instruction Set.

    Uses the same system prompt as the CLI's generate_mdr_report tool so that
    web-UI and CLI reports are structurally identical.
    """
    if not ANTHROPIC_KEY:
        return {"_message": "MDR report generation requires an Anthropic API key."}

    from tools.generate_mdr_report import _SYSTEM_PROMPT as MDR_SYSTEM_PROMPT

    # --- Build rich investigation context from session data ----------------

    parts: list[str] = ["# Investigation Context\n"]

    # Findings
    findings = ctx.get("findings", [])
    if findings:
        parts.append("## Findings")
        for f in findings:
            parts.append(f"- [{f.get('type', '?')}] {f.get('summary', '')}")
            if f.get("detail"):
                parts.append(f"  {f['detail']}")
        parts.append("")

    # Telemetry summaries
    telemetry = ctx.get("telemetry_summaries", [])
    if telemetry:
        parts.append("## Telemetry Summaries")
        for t in telemetry:
            line = f"- {t.get('source_file', '?')}: {t.get('event_count', '?')} events"
            line += f" (platform: {t.get('platform', '?')})"
            if t.get("computers"):
                line += f", hosts: {', '.join(t['computers'])}"
            if t.get("users"):
                line += f", users: {', '.join(t['users'])}"
            if t.get("top_tactics"):
                line += f", tactics: {', '.join(t['top_tactics'])}"
            parts.append(line)
        parts.append("")

    # IOCs
    iocs = ctx.get("iocs", {})
    if any(iocs.get(t) for t in ("ips", "domains", "hashes", "urls")):
        parts.append("## Extracted IOCs")
        for itype, items in iocs.items():
            if items:
                parts.append(f"### {itype.upper()} ({len(items)})")
                for v in items[:50]:
                    parts.append(f"  - {v}")
        parts.append("")

    # Disposition
    disposition = ctx.get("disposition", "unknown")
    parts.append(f"## Disposition: {disposition}\n")

    # Conversation history — includes KQL results, analyst observations, etc.
    history = _session_load_history(session_id)
    if history:
        # Extract assistant and tool_result messages for evidence context
        evidence_lines: list[str] = []
        for msg in history:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "assistant" and isinstance(content, str) and content.strip():
                evidence_lines.append(content.strip())
            elif role == "user" and isinstance(content, list):
                # tool_result blocks
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        tr_content = block.get("content", "")
                        if isinstance(tr_content, str) and tr_content.strip():
                            evidence_lines.append(tr_content.strip())
        if evidence_lines:
            evidence_text = "\n\n---\n\n".join(evidence_lines)
            # Truncate to avoid token overflow
            if len(evidence_text) > 12000:
                evidence_text = evidence_text[-12000:]
                evidence_text = "...[earlier context truncated]...\n\n" + evidence_text
            parts.append("## Investigation Evidence (from session)")
            parts.append(evidence_text)
            parts.append("")

    context_block = "\n".join(parts)

    user_content = (
        "Please produce an MDR-style incident report for the following investigation, "
        "following the Gold MDR/XDR Analyst Instruction Set exactly.\n\n"
        f"{context_block}"
    )

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        response = client.messages.create(
            model=get_model("mdr_report", "medium"),
            system=[{"type": "text", "text": MDR_SYSTEM_PROMPT}],
            messages=[{"role": "user", "content": user_content}],
            max_tokens=8192,
        )
        report = _extract_text(response.content)

        # Save to session artefacts
        art_dir = SESSIONS_DIR / session_id / "artefacts" / "reports"
        art_dir.mkdir(parents=True, exist_ok=True)
        (art_dir / "mdr_report.md").write_text(report)

        # If session has been materialised, also save to the case directory
        from api.sessions import load_session as _load_session_meta
        smeta = _load_session_meta(session_id)
        linked_case = smeta.get("case_id") if smeta else None
        if linked_case:
            case_report_dir = CASES_DIR / linked_case / "reports"
            case_report_dir.mkdir(parents=True, exist_ok=True)
            (case_report_dir / "mdr_report.md").write_text(report)

        return {"_message": report}
    except Exception as exc:
        return {"_message": f"Error generating MDR report: {exc}"}


# ---------------------------------------------------------------------------
# Session chat function — multi-turn tool loop (mirrors case chat)
# ---------------------------------------------------------------------------

def session_chat(session_id: str, user_message: str, *, model_override: str | None = None, user_permissions: list[str] | None = None) -> dict:
    """
    Process a user message in a session-mode investigation chat.

    Returns:
        {"reply": str, "tool_calls": list[dict], "history": list[dict],
         "case_id": str|None}
    """
    if not ANTHROPIC_KEY:
        return {
            "reply": "Chat requires an Anthropic API key. Set ANTHROPIC_API_KEY in .env.",
            "tool_calls": [],
            "history": [],
            "case_id": None,
        }

    return _session_chat_inner(session_id, user_message,
                               model_override=model_override,
                               user_permissions=user_permissions)


def _session_chat_inner(session_id: str, user_message: str, *, model_override: str | None = None, user_permissions: list[str] | None = None) -> dict:
    """Inner session chat implementation — always runs inside force_fast_model context."""
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    system_prompt = build_session_prompt(session_id)

    # Two-tier model: fast for routing (tool selection), heavy for final response
    if model_override and model_override in ("fast", "standard", "heavy"):
        import config.settings as _s
        _tier_map = {"fast": "SOCAI_MODEL_FAST", "standard": "SOCAI_MODEL_STANDARD", "heavy": "SOCAI_MODEL_HEAVY"}
        _routing_model = getattr(_s, _tier_map[model_override])
        _response_model = _routing_model
    else:
        _routing_model = get_model("chat_routing", "medium")
        _response_model = get_model("chat_response", "medium")

    history = _session_load_history(session_id)

    # Append user message
    history.append({"role": "user", "content": user_message})

    tool_calls_log = []
    materialised_case_id = None

    def _track_materialise(block_name, result_text):
        """Check if a materialise_case tool produced a case ID."""
        nonlocal materialised_case_id
        if block_name == "materialise_case":
            try:
                import re
                m = re.search(r"Case \*\*(\w+)\*\* created", result_text)
                if m:
                    materialised_case_id = m.group(1)
            except Exception:
                pass

    def _process_tool_calls(resp):
        """Execute tool calls from a response, return tool_results list."""
        results = []
        for block in resp.content:
            if block.type == "tool_use":
                result_text = execute_session_tool(session_id, block.name, block.input, user_permissions=user_permissions)
                tool_calls_log.append({
                    "tool": block.name,
                    "input": block.input,
                    "result": result_text,
                })
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text,
                })
                _track_materialise(block.name, result_text)
        return results

    # Multi-turn loop: fast model routes, heavy model responds
    for _turn in range(MAX_TURNS):
        _model = _routing_model if _turn < MAX_TURNS - 1 else _response_model
        try:
            response = client.messages.create(
                model=_model,
                system=system_prompt,
                tools=SESSION_TOOL_DEFS,
                tool_choice={"type": "auto"},
                messages=_prepare_messages_for_api(history, _model),
                max_tokens=4096,
            )
        except Exception as exc:
            return {
                "reply": f"I encountered an error calling the AI model: {exc}",
                "tool_calls": tool_calls_log,
                "history": history,
                "case_id": None,
            }

        assistant_content = _serialise_content(response.content)
        history.append({"role": "assistant", "content": assistant_content})

        tool_results = _process_tool_calls(response)

        if not tool_results:
            # No tools — if fast model responded, re-generate with heavy
            if _model == _routing_model and _routing_model != _response_model:
                history.pop()  # remove fast model's response
                try:
                    response = client.messages.create(
                        model=_response_model,
                        system=system_prompt,
                        tools=SESSION_TOOL_DEFS,
                        tool_choice={"type": "auto"},
                        messages=_prepare_messages_for_api(history, _model),
                        max_tokens=4096,
                    )
                except Exception as exc:
                    return {
                        "reply": f"I encountered an error calling the AI model: {exc}",
                        "tool_calls": tool_calls_log,
                        "history": history,
                        "case_id": None,
                    }
                assistant_content = _serialise_content(response.content)
                history.append({"role": "assistant", "content": assistant_content})

                # Heavy model might also call tools
                tool_results = _process_tool_calls(response)
                if tool_results:
                    history.append({"role": "user", "content": tool_results})
                    continue
            break

        history.append({"role": "user", "content": tool_results})

    reply = _extract_text(response.content)

    # Save history
    _session_save_history(session_id, history)

    return {
        "reply": reply,
        "tool_calls": tool_calls_log,
        "history": history,
        "case_id": materialised_case_id,
    }


def get_session_display_history(session_id: str) -> list[dict]:
    """Return session chat history in display-friendly format."""
    history = _session_load_history(session_id)
    # Reuse the same formatter logic
    display = []
    for i, msg in enumerate(history):
        role = msg.get("role", "")
        content = msg.get("content", "")

        if role == "user":
            if isinstance(content, str):
                display.append({"role": "user", "content": content})
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        continue
                    elif isinstance(block, dict) and block.get("type") == "text":
                        display.append({"role": "user", "content": block.get("text", "")})

        elif role == "assistant":
            text_parts = []
            tool_calls = []
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "text":
                            text_parts.append(block.get("text", ""))
                        elif block.get("type") == "tool_use":
                            tool_calls.append({
                                "name": block.get("name", ""),
                                "input": block.get("input", {}),
                            })

            if text_parts or tool_calls:
                entry = {"role": "assistant"}
                if text_parts:
                    entry["content"] = "\n".join(text_parts)
                if tool_calls:
                    entry["tool_calls"] = tool_calls

                if i + 1 < len(history):
                    next_msg = history[i + 1]
                    if next_msg.get("role") == "user" and isinstance(next_msg.get("content"), list):
                        results = []
                        for block in next_msg["content"]:
                            if isinstance(block, dict) and block.get("type") == "tool_result":
                                results.append(block.get("content", ""))
                        if results:
                            entry["tool_results"] = results

                display.append(entry)

    return display
