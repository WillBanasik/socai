"""MCP tool wrappers — expose socai investigation tools with RBAC.

Each tool is registered on a ``FastMCP`` instance via ``register_tools(mcp)``.
All tools validate permissions using ``_require_scope()`` before delegating to
the existing action / tool layer.

Tools are organised in three tiers:
  Tier 1 — Core Investigation
  Tier 2 — Extended Analysis
  Tier 3 — Advanced / Restricted

Deliverable tools (``prepare_mdr_report``, ``prepare_pup_report``,
``prepare_closure_comment``, ``prepare_fp_tuning_ticket``) accept an optional
``case_id`` — if omitted, ``_ensure_case()`` auto-creates and promotes a case.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from mcp_server.auth import _require_scope

# ---------------------------------------------------------------------------
# Boundary stubs — client and case boundaries have been removed.
#
# RBAC (per-tool scopes) and filesystem isolation (cases/<ID>/) provide
# sufficient access control.  The in-process boundary enforcement caused
# friction (stale locks across sessions, blocking legitimate multi-case
# workflows) without adding real security value.
#
# The function signatures are kept as no-ops so that the ~50 call sites
# throughout this file don't need to be touched.
# ---------------------------------------------------------------------------

def _reset_boundaries(caller: str | None = None) -> None:  # noqa: ARG001
    """No-op — boundaries removed."""

def _check_client_boundary(case_id: str) -> None:  # noqa: ARG001
    """No-op — boundaries removed."""

def _set_client_boundary(client_name: str) -> None:  # noqa: ARG001
    """No-op — boundaries removed."""

def _check_workspace_boundary(workspace_id: str) -> None:  # noqa: ARG001
    """No-op — boundaries removed."""


# ---------------------------------------------------------------------------
# Toolset profiles — modular tool groups loaded per investigation type.
#
# Every tool is registered once at startup (cheap — just a JSON schema), then
# register_tools() prunes the live tool list down to the active profile
# (SOCAI_MCP_TOOLSETS, default "all" — every toolset loaded up front, which is
# what Claude Desktop requires since its tool-search indexes session-start
# tools only). When the profile is narrower than "all", specialist groups can
# still be added mid-session via the load_toolset tool, which restores them
# from _ALL_TOOLS and pushes a tools/list_changed notification — useful for
# transports/clients that honour the notification.
#
# "core" is always present: case management, enrichment/triage, all log
# hunting (KQL/Defender/Falcon), recall, GeoIP, coverage, reporting/close-out,
# plus the two meta-tools. classify_attack recommends a specialist group; the
# common log-based investigations (account compromise, priv-esc, exfil,
# lateral movement, PUP, generic) need core alone.
#
# INVARIANT: every registered tool must appear in exactly one toolset.
# register_tools() folds any unassigned tool into core as a safety net.
# ---------------------------------------------------------------------------

TOOLSETS: dict[str, set[str]] = {
    "core": {
        # meta
        "load_toolset", "list_toolsets",
        # case management
        "new_investigation", "lookup_client", "list_clients",
        "update_client_knowledge", "list_cases", "case_summary", "read_report",
        "read_case_file", "list_case_files", "create_case", "promote_case",
        "discard_case", "close_case", "add_evidence", "add_finding",
        "link_cases", "merge_cases",
        # enrichment / triage
        "enrich_iocs", "quick_enrich", "import_enrichment",
        "extract_iocs_from_text", "triage_iocs", "score_ioc_verdicts",
        "classify_attack", "plan_investigation",
        # cross-cutting triage (referenced by phishing AND malware sequences)
        "capture_urls", "xposed_breach_check",
        # correlation / recall
        "correlate", "reconstruct_timeline", "campaign_cluster", "recall_cases",
        "recall_semantic", "get_client_baseline", "geoip_lookup",
        # log hunting
        "run_kql", "run_kql_batch", "run_defender_kql", "run_falcon_cql",
        "query_falcon_detections", "query_falcon_hosts", "query_falcon_incidents",
        "eql_entity_context", "eql_query", "eql_posture_context",
        "load_kql_playbook", "load_cql_playbook", "generate_sentinel_query",
        "generate_queries", "load_ngsiem_reference", "parse_logs",
        "detect_anomalies",
        # coverage
        "check_log_coverage", "can_investigate_attack", "refresh_log_coverage",
        # reporting / close-out
        "generate_report", "prepare_mdr_report", "prepare_pup_report",
        "prepare_executive_summary", "load_report_template", "save_report",
        "generate_weekly", "response_actions", "prepare_closure_comment",
        "prepare_fp_tuning_ticket",
    },
    "phishing": {
        "detect_phishing", "analyse_email", "start_browser_session",
        "stop_browser_session", "list_browser_sessions",
        "read_browser_session_file", "list_browser_session_files",
        "import_browser_session",
    },
    "malware": {
        "analyse_file", "prepare_file_upload", "upload_file_content",
        "sandbox_api_lookup", "start_sandbox_session", "stop_sandbox_session",
        "list_sandbox_sessions", "yara_scan",
    },
    "forensics": {
        "correlate_evtx", "ingest_velociraptor", "ingest_mde_package",
        "memory_dump_guide", "analyse_memory_dump", "analyse_memory_volatility",
    },
    "intel": {
        "query_opencti", "search_confluence", "assess_landscape",
        "search_threat_articles", "check_article_dedup", "generate_threat_article",
        "save_threat_article", "post_opencti_report", "generate_opencti_package",
        "web_search", "query_cyberint_alerts", "cyberint_alert_artefact",
        "cyberint_metadata", "security_arch_review", "contextualise_cves",
    },
    "darkweb": {
        "parse_stealer_logs_tool", "darkweb_exposure_summary",
        "ahmia_darkweb_search", "intelx_search_tool",
        "run_client_exposure_test", "get_client_exposure_report",
    },
    "analysis": {
        "generate_investigation_matrix", "review_report_quality",
        "run_determination", "list_followups", "execute_followup",
    },
    "admin": {
        "rebuild_case_memory", "rebuild_client_baseline", "refresh_geoip",
        "audit_user_activity",
    },
}

_TOOLSET_DESCRIPTIONS: dict[str, str] = {
    "core": "Always loaded — case management, enrichment/triage, log hunting (KQL/Defender/Falcon), recall, reporting and close-out.",
    "phishing": "Email/URL investigation — phishing detection, email parsing, browser-based page-capture sessions.",
    "malware": "File/payload analysis — static file analysis, file upload, sandbox detonation sessions, YARA.",
    "forensics": "Host DFIR — EVTX correlation, Velociraptor/MDE package ingest, memory-dump analysis (incl. Volatility3).",
    "intel": "Threat intelligence & OSINT — OpenCTI, threat articles (published ET/EV archive on Confluence), Cyberint, CVE context, security architecture review.",
    "darkweb": "Dark-web & exposure — stealer-log/breach parsing, Ahmia/IntelX search, client exposure testing.",
    "analysis": "Deep analytical rigour — investigation matrix, report quality gate, determination analysis, follow-up proposals.",
    "admin": "Maintenance — rebuild case-memory/baseline indexes, refresh GeoIP, audit user activity.",
}

# Snapshot of every registered tool (name -> Tool object), populated by
# register_tools(). load_toolset restores pruned tools from here.
_ALL_TOOLS: dict = {}


# Bounded concurrency for speculative (advisory) enrichment. Prevents a bulk
# evidence paste from fanning out dozens of simultaneous TI-provider calls.
import threading as _spec_thr

_SPEC_ENRICH_MAX_CONCURRENT = 3
_spec_enrich_slots = _spec_thr.Semaphore(_SPEC_ENRICH_MAX_CONCURRENT)


def _speculative_enrich_bg(
    text: str,
    *,
    extra_iocs: list[str] | None = None,
    thread_name: str = "spec_enrich",
) -> None:
    """Extract IOCs from *text* and pre-warm enrichment cache in a background thread.

    Advisory only — failures are logged but never block the caller. Capped
    at ``_SPEC_ENRICH_MAX_CONCURRENT`` concurrent threads; over-budget calls
    are dropped silently (the next real enrichment will fetch as normal).
    """
    try:
        from tools.extract_iocs import _extract_from_text

        extracted = _extract_from_text(text)
        raw_iocs: list[str] = []
        for ioc_type in ("ipv4", "domain", "url", "sha256", "sha1", "md5"):
            raw_iocs.extend(extracted.get(ioc_type, set()))
        if extra_iocs:
            raw_iocs.extend(extra_iocs)
        raw_iocs = list(dict.fromkeys(raw_iocs))[:20]  # dedup, cap at 20
        if not raw_iocs:
            return

        if not _spec_enrich_slots.acquire(blocking=False):
            return  # pool saturated — drop; speculative only

        def _bg():
            try:
                from tools.enrich import quick_enrich
                quick_enrich(raw_iocs, depth="fast")
            except Exception as exc:
                from tools.common import log_error
                log_error("", "speculative_enrich", str(exc), severity="info")
            finally:
                _spec_enrich_slots.release()

        _spec_thr.Thread(target=_bg, daemon=True, name=thread_name).start()
    except Exception:
        pass  # advisory — never block caller


def _resolve_workspace_code_from_id(workspace_id: str) -> str:
    """Reverse-lookup workspace code from GUID for schema validation."""
    try:
        from config.sentinel_schema import resolve_workspace_code
        return resolve_workspace_code(workspace_id)
    except Exception:
        return ""


def _validate_kql_schema(query: str, workspace_id: str = "") -> list[str]:
    """Pre-flight schema validation for a KQL query.  Returns warning strings."""
    try:
        from config.sentinel_schema import extract_tables_from_kql, validate_tables, has_registry
        if not has_registry():
            return []
        tables = extract_tables_from_kql(query)
        if not tables:
            return []
        ws_code = _resolve_workspace_code_from_id(workspace_id) if workspace_id else ""
        validation = validate_tables(list(tables), workspace=ws_code)
        return validation.get("warnings", [])
    except Exception:
        return []


def _workspace_resolution_hint(case_id: str = "") -> dict:
    """Build an error payload for failed KQL workspace resolution.

    Lists which clients have a Sentinel workspace configured, and which don't,
    so the agent can reason about why the resolve failed instead of just
    blindly retrying with a different workspace string.
    """
    from config.settings import CLIENT_ENTITIES, CASES_DIR
    from tools.common import load_json

    configured: list[str] = []
    unconfigured: list[str] = []
    try:
        entities = load_json(CLIENT_ENTITIES).get("clients", [])
        for ent in entities:
            name = ent.get("name", "")
            ws = (ent.get("platforms", {}) or {}).get("sentinel", {}).get("workspace_id") \
                or ent.get("workspace_id")
            if ws:
                configured.append(name)
            else:
                unconfigured.append(name)
    except Exception:
        pass

    case_client = ""
    if case_id:
        try:
            meta = load_json(CASES_DIR / case_id / "case_meta.json")
            case_client = (meta.get("client") or "").strip()
        except Exception:
            pass

    hint_lines = []
    if case_client and case_client in unconfigured:
        hint_lines.append(
            f"Case client {case_client!r} has no Sentinel workspace_id in "
            "client_entities.json — populate it or pass workspace= explicitly."
        )
    elif case_client and case_client not in configured:
        hint_lines.append(
            f"Case client {case_client!r} is not in the client registry."
        )
    hint_lines.append(
        "Pass workspace=<name|GUID> explicitly, or run from a case whose client "
        "has a configured Sentinel workspace. There is no default workspace — "
        "an unscoped query is refused so it cannot hit the wrong client's tenant."
    )

    return {
        "error": "Could not resolve Sentinel workspace.",
        "case_client": case_client or None,
        "clients_with_workspace": configured,
        "clients_without_workspace": unconfigured,
        "hint": " ".join(hint_lines),
    }


def _ensure_case(
    case_id: str,
    *,
    title: str = "",
    severity: str = "medium",
    client: str = "",
    tags: list[str] | None = None,
    disposition: str = "",
) -> str:
    """Return *case_id*, creating + promoting the case if it doesn't exist.

    Deliverable tools call this instead of requiring ``case_id`` upfront.
    If ``case_id`` is empty, a new case is auto-created and promoted to
    active status so the deliverable can proceed immediately.

    If ``case_id`` is provided but the case doesn't exist, raises
    ``ToolError`` — callers should not silently get a different case.
    """
    from config.settings import CASES_DIR, DEFAULT_CLIENT
    from tools.case_create import case_create as _create, next_case_id
    from tools.index_case import promote_case as _promote

    def _do_promote(cid: str) -> None:
        result = _promote(cid, disposition=disposition or None)
        if isinstance(result, dict) and "error" in result:
            raise ToolError(result["error"])

    # Resolve: if a case_id is given, it must exist
    if case_id:
        meta_path = CASES_DIR / case_id / "case_meta.json"
        if not meta_path.exists():
            raise ToolError(
                f"Case {case_id} does not exist. Omit case_id to auto-create."
            )
        from tools.common import load_json
        meta = load_json(meta_path)
        current_status = meta.get("status", "")
        if current_status in ("discarded", "closed", "archived"):
            raise ToolError(
                f"Case {case_id} is {current_status}. Cannot generate "
                f"deliverables for a {current_status} case."
            )
        if current_status == "triage":
            _do_promote(case_id)
        return case_id

    # No case_id — auto-create; fall back to DEFAULT_CLIENT
    client = client or DEFAULT_CLIENT
    if not client:
        raise ToolError(
            "Client name is required when auto-creating a case. "
            "Specify the client explicitly, or call create_case with "
            "a client name before using deliverable tools."
        )
    case_id = next_case_id()
    _create(
        case_id,
        title=title or "Auto-created at deliverable time",
        severity=severity,
        client=client,
        tags=tags or [],
    )
    _do_promote(case_id)
    return case_id


def _json(obj: object) -> str:
    """Serialise *obj* to a compact JSON string.

    Raises ``ToolError`` when the result is a top-level error dict so that
    MCP clients receive ``isError: true`` instead of a misleading success.
    """
    if isinstance(obj, dict):
        # {"status": "error", "reason": "..."}
        if obj.get("status") == "error":
            raise ToolError(obj.get("reason") or obj.get("error") or "Unknown error")
        # {"error": "...", maybe "case_id"/"path"}  (small error-only dicts)
        if "error" in obj and isinstance(obj["error"], str) and len(obj) <= 3:
            raise ToolError(obj["error"])
    return json.dumps(obj, indent=2, default=str)


def _pop_message(result: dict) -> dict:
    """Strip the internal ``_message`` key used by actions.py wrappers."""
    if isinstance(result, dict):
        result.pop("_message", None)
    return result


# ---------------------------------------------------------------------------
# Tier 1 — Core Investigation tools
# ---------------------------------------------------------------------------

def _register_tier1(mcp: FastMCP) -> None:

    @mcp.tool(title="Start New Investigation")
    async def new_investigation() -> str:
        """Use when the analyst says "new case", "start fresh", or "different investigation".

        This is a semantic marker — it signals that the analyst is starting a
        fresh investigation context.  Clears tool-sequence session tracking
        for this caller so the next case gets a fresh session ID.
        """
        _require_scope("investigations:read")
        from mcp_server.auth import _get_caller_email
        from mcp_server.usage import _sessions, _session_lock
        caller = _get_caller_email()
        with _session_lock:
            to_remove = [k for k, v in _sessions.items() if v["caller"] == caller]
            for k in to_remove:
                del _sessions[k]
        return _json({
            "status": "ok",
            "message": "Ready for a new investigation.",
        })

    @mcp.tool(title="Look Up Client", annotations={"readOnlyHint": True})
    def lookup_client(client_name: str) -> str:
        """Resolve a client and return their registered security platforms, workspace IDs,
        knowledge base, response playbook, and Sentinel reference.
        """
        _require_scope("investigations:read")

        from tools.common import get_client_config
        # Normalise input: lowercase, strip, and collapse whitespace/hyphens to
        # underscores so "Heidelberg Materials" and "heidelberg-materials" both
        # resolve to the canonical name "heidelberg_materials" without needing
        # the alias fallback path below.
        normalised = client_name.strip().lower().replace(" ", "_").replace("-", "_")
        cfg = get_client_config(client_name) or get_client_config(normalised)
        if not cfg:
            # Fuzzy matching: try substring and domain patterns
            from config.settings import CLIENT_ENTITIES
            from tools.common import load_json
            try:
                entities = load_json(CLIENT_ENTITIES).get("clients", [])
            except Exception:
                entities = []

            query = client_name.lower().strip()
            suggestions = []
            # Exact alias match only — no fuzzy/substring matching. Fuzzy
            # matching caused spurious hits (e.g. any 3-char substring
            # collisions). Aliases must be declared explicitly in
            # client_entities.json (e.g. "perf" → performanta, "hbm" →
            # heidelberg_materials).
            for ent in entities:
                aliases = {a.lower().strip() for a in ent.get("aliases", [])}
                if query in aliases:
                    suggestions.append(ent.get("name", ""))

            if len(suggestions) == 1:
                # Single match — auto-resolve
                cfg = get_client_config(suggestions[0])
            elif len(suggestions) > 1:
                # Ambiguous alias (e.g. "tsogo" maps to BOTH Southern Sun
                # Hotels and Tsogo Sun Gaming). Do NOT auto-resolve — gate and
                # surface each candidate's `disambiguation` facts so the caller
                # can confirm which client is meant, then retry with the exact
                # name. This is intentional: see the shared-alias notes in
                # client_entities.json.
                candidates = []
                for name in suggestions:
                    c = get_client_config(name) or {}
                    candidates.append({
                        "name": name,
                        "disambiguation": c.get("disambiguation", ""),
                    })
                return _json({
                    "status": "ambiguous_client",
                    "query": client_name,
                    "candidates": candidates,
                    "_hint": (
                        f"{client_name!r} is ambiguous — it matches multiple "
                        "clients. Do NOT pick one arbitrarily. Use the "
                        "`disambiguation` facts on each candidate (and the "
                        "originating Falcon CID / Encore client, which are "
                        "authoritative) to confirm which client this is, then "
                        "call lookup_client again with the exact name. If you "
                        "cannot tell, ask the analyst."
                    ),
                })
            else:
                return _json({
                    "error": f"Client {client_name!r} not found.",
                    "suggestions": [],
                    "_hint": (
                        "Do NOT retry with guessed spellings — each failed call "
                        "adds context overhead. Read the socai://clients resource "
                        "for the authoritative client list, or ask the analyst "
                        "to confirm the client name."
                    ),
                })

        # Include platforms and any response playbook
        platforms = cfg.get("platforms", {})
        if not platforms and cfg.get("workspace_id"):
            platforms = {"sentinel": {"workspace_id": cfg["workspace_id"]}}

        result = {
            "name": cfg.get("name", ""),
            "platforms": platforms,
            "platform_list": list(platforms.keys()),
        }

        from mcp_server.resources import _resolve_client_playbook, _resolve_client_knowledge
        from config.settings import CLIENT_PLAYBOOKS_DIR as CLIENTS_DIR
        import json as _json_mod

        kb_path = _resolve_client_knowledge(cfg["name"])
        if kb_path:
            result["knowledge_base"] = kb_path.read_text(encoding="utf-8")
        else:
            result["knowledge_base"] = None

        pb_path = _resolve_client_playbook(cfg["name"])
        if pb_path:
            try:
                result["response_playbook"] = _json_mod.loads(pb_path.read_text(encoding="utf-8"))
            except Exception:
                result["response_playbook"] = pb_path.read_text(encoding="utf-8")
        else:
            result["response_playbook"] = None

        sentinel_path = CLIENTS_DIR / cfg["name"] / "sentinel.md"
        if sentinel_path.exists():
            result["sentinel_reference"] = sentinel_path.read_text(encoding="utf-8")
        else:
            result["sentinel_reference"] = None

        return _json(result)

    @mcp.tool(title="List Clients", annotations={"readOnlyHint": True})
    def list_clients() -> str:
        """List all registered clients with their names, aliases, and configured platforms.
        Cheap (no knowledge/playbook payload) — use before ``lookup_client`` to discover client names.
        """
        _require_scope("investigations:read")

        from config.settings import CLIENT_ENTITIES
        from tools.common import load_json

        if not CLIENT_ENTITIES.exists():
            return _json({"clients": [], "count": 0})

        entities = load_json(CLIENT_ENTITIES).get("clients", [])
        summary = []
        for ent in entities:
            platforms = ent.get("platforms", {})
            if not platforms and ent.get("workspace_id"):
                platforms = {"sentinel": {"workspace_id": ent["workspace_id"]}}
            summary.append({
                "name": ent.get("name", ""),
                "aliases": ent.get("aliases", []),
                "platforms": list(platforms.keys()) if platforms else [],
            })
        summary.sort(key=lambda c: c["name"])
        return _json({"clients": summary, "count": len(summary)})

    @mcp.tool(title="Update Client Knowledge Base")
    async def update_client_knowledge(
        client_name: str,
        section: str,
        content: str,
    ) -> str:
        """Update a section of the client knowledge base with persistent findings
        (network ranges, FP patterns, security stack, identity infrastructure, etc.).

        ``section``: heading to update (e.g. "Network Topology", "Known Legitimate Software & Services").
        ``content``: markdown replacing existing section body up to the next ``---`` divider.
        """
        _require_scope("investigations:submit")

        from mcp_server.resources import _resolve_client_knowledge
        from tools.common import audit

        path = _resolve_client_knowledge(client_name)
        if not path:
            # Create the knowledge base file for this client
            from config.settings import CLIENT_PLAYBOOKS_DIR as CLIENTS_DIR
            from tools.common import get_client_config
            cfg = get_client_config(client_name)
            resolved_name = cfg.get("name", client_name) if cfg else client_name
            kb_dir = CLIENTS_DIR / resolved_name.lower().replace(" ", "_")
            kb_dir.mkdir(parents=True, exist_ok=True)
            path = kb_dir / "knowledge.md"
            template = (
                f"# {resolved_name} — Client Knowledge Base\n\n"
                f"> Auto-created by update_client_knowledge.\n\n"
                f"---\n\n"
                f"## {section}\n\n"
                f"{content.strip()}\n\n"
                f"---\n"
            )
            path.write_text(template, encoding="utf-8")
            audit("update_client_knowledge",
                  str(path), extra={"client": client_name, "section": section,
                                    "action": "created"})
            return _json({
                "status": "ok",
                "client": resolved_name,
                "section": section,
                "path": str(path),
                "created": True,
            })

        text = path.read_text(encoding="utf-8")

        # Find the section heading and replace content up to next ---
        import re
        heading_pattern = re.compile(
            rf"(## {re.escape(section)}\s*\n)"  # heading line
            rf"(.*?)"                             # section body
            rf"(\n---|\Z)",                       # next divider or end
            re.DOTALL,
        )
        match = heading_pattern.search(text)
        if match:
            # Update existing section
            updated = (
                text[:match.start()]
                + match.group(1)  # keep heading
                + "\n" + content.strip() + "\n"
                + match.group(3)  # keep divider
                + text[match.end():]
            )
        else:
            # Append new section at end of file
            updated = text.rstrip() + f"\n\n---\n\n## {section}\n\n{content.strip()}\n\n---\n"

        path.write_text(updated, encoding="utf-8")
        audit("update_client_knowledge",
              str(path), extra={"client": client_name, "section": section})

        return _json({
            "status": "ok",
            "client": client_name,
            "section": section,
            "path": str(path),
        })

    @mcp.tool(title="List Cases", annotations={"readOnlyHint": True})
    def list_cases(status: str = "active,closed") -> str:
        """Return cases filtered by status (default ``"active,closed"``).
        Pass ``"triage"``, ``"all"``, or any comma-separated combination.

        For searching prior cases by IOC or keyword use ``recall_cases`` instead.
        """
        _require_scope("investigations:read")

        from config.settings import REGISTRY_FILE
        from tools.common import load_json

        if not REGISTRY_FILE.exists():
            return _json({"cases": {}, "message": "No registry found."})

        registry = load_json(REGISTRY_FILE)

        # Filter by status
        if status and status.strip().lower() not in ("all", ""):
            allowed = {s.strip().lower() for s in status.split(",")}
            # Map legacy "open" to "active" for filtering
            if "open" in allowed:
                allowed.add("active")
            filtered = {}
            for cid, entry in registry.get("cases", {}).items():
                case_status = (entry.get("status") or "").lower()
                # Legacy "open" cases match "active" filter
                if case_status == "open" and "active" in allowed:
                    filtered[cid] = entry
                elif case_status in allowed:
                    filtered[cid] = entry
            registry = {**registry, "cases": filtered}

        return _json(registry)

    @mcp.tool(title="Full Case Summary", annotations={"readOnlyHint": True})
    def case_summary(case_id: str) -> str:
        """Return a full case overview in one call: metadata, IOCs with verdicts, enrichment stats,
        response actions, correlation hits, campaign links, analyst notes, timeline count, and errors.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from config.settings import CASES_DIR
        from tools.common import load_json

        case_dir = CASES_DIR / case_id
        meta_path = case_dir / "case_meta.json"
        if not meta_path.exists():
            return _json({"error": f"Case {case_id!r} not found."})

        def _load(rel: str) -> dict | list | None:
            p = case_dir / rel
            if not p.exists():
                return None
            try:
                return load_json(p)
            except Exception:
                return None

        def _read_text(rel: str, limit: int = 8000) -> str | None:
            p = case_dir / rel
            if not p.exists():
                return None
            try:
                t = p.read_text(encoding="utf-8", errors="replace")
                return t[:limit] + "\n\n... [truncated]" if len(t) > limit else t
            except Exception:
                return None

        meta = load_json(meta_path)

        # IOCs
        iocs_data = _load("iocs/iocs.json")
        ioc_summary: dict = {}
        if iocs_data:
            raw = iocs_data.get("iocs", {})
            for ioc_type, vals in raw.items():
                if vals:
                    ioc_summary[ioc_type] = {"count": len(vals), "values": vals[:20]}

        # Verdict summary
        verdict = _load("artefacts/enrichment/verdict_summary.json")
        verdict_highlights: dict = {}
        if verdict:
            verdict_highlights["malicious"] = verdict.get("high_priority", [])
            verdict_highlights["suspicious"] = verdict.get("needs_review", [])
            verdict_highlights["clean_count"] = len(verdict.get("clean", []))
            verdict_highlights["total_scored"] = verdict.get("ioc_count", 0)
            # Per-IOC detail for malicious/suspicious only
            per_ioc = verdict.get("iocs", {})
            detail = {}
            for ioc_val in (verdict_highlights["malicious"] + verdict_highlights["suspicious"]):
                info = per_ioc.get(ioc_val)
                if info:
                    detail[ioc_val] = {
                        "type": info.get("ioc_type"),
                        "verdict": info.get("verdict"),
                        "confidence": info.get("confidence"),
                        "providers": info.get("providers", {}),
                    }
            if detail:
                verdict_highlights["detail"] = detail

        # Enrichment stats
        enrichment = _load("artefacts/enrichment/enrichment.json")
        enrichment_stats: dict = {}
        if enrichment:
            enrichment_stats["total_lookups"] = enrichment.get("total_lookups", 0)
            enrichment_stats["live_lookups"] = enrichment.get("live_lookups", enrichment.get("live_calls", 0))
            enrichment_stats["cache_hits"] = enrichment.get("cache_hits", 0)
            raw_results = enrichment.get("results", [])
            if isinstance(raw_results, list):
                enrichment_stats["providers_used"] = sorted({
                    r.get("provider") for r in raw_results
                    if isinstance(r, dict) and r.get("provider")
                })
            elif isinstance(raw_results, dict):
                enrichment_stats["providers_used"] = sorted({
                    r.get("provider") for per_ioc in raw_results.values()
                    if isinstance(per_ioc, list) for r in per_ioc
                    if isinstance(r, dict) and r.get("provider")
                })

        # Response actions
        actions = _load("artefacts/response_actions/response_actions.json")
        response_summary: dict = {}
        if actions and actions.get("status") == "ok":
            response_summary["priority"] = actions.get("priority")
            response_summary["priority_source"] = actions.get("priority_source")
            esc = actions.get("escalation", {})
            response_summary["contact_process"] = esc.get("contact_process")
            response_summary["permitted_actions"] = esc.get("permitted_actions", [])
            response_summary["containment_capabilities"] = actions.get("containment_capabilities", [])
            response_summary["remediation_actions"] = actions.get("remediation_actions", [])
            response_summary["crown_jewel_match"] = actions.get("crown_jewel_match", False)

        # Correlation
        correlation = _load("artefacts/correlation/correlation.json")
        correlation_summary: dict = {}
        if correlation:
            correlation_summary["hit_summary"] = correlation.get("hit_summary", {})
            correlation_summary["timeline_events"] = correlation.get("timeline_events", 0)

        # Campaign links
        campaign = _load("artefacts/campaign/campaign_links.json")

        # Analyst notes
        analyst_notes = _read_text("notes/analyst_input.md", limit=4000)

        # Timeline
        timeline = _load("timeline.json")

        # Error log (case-specific entries — JSONL format)
        # Group duplicate errors by (severity, step, error) to avoid emitting
        # the same noise warning 90+ times in the per-turn payload. Full raw
        # entries persist on disk and can be read via `python3 socai.py errors`.
        errors_total = 0
        errors_by_severity: dict[str, int] = {}
        error_groups: dict[tuple, dict] = {}
        try:
            from config.settings import ERROR_LOG
            if ERROR_LOG.exists():
                for line in ERROR_LOG.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if entry.get("case_id") != case_id:
                        continue
                    errors_total += 1
                    sev = entry.get("severity", "error")
                    errors_by_severity[sev] = errors_by_severity.get(sev, 0) + 1
                    key = (sev, entry.get("step", ""), entry.get("error", ""))
                    g = error_groups.get(key)
                    if g is None:
                        error_groups[key] = {
                            "severity": sev,
                            "step": entry.get("step", ""),
                            "error": entry.get("error", ""),
                            "count": 1,
                            "first_ts": entry.get("ts"),
                            "last_ts": entry.get("ts"),
                            "sample_context": entry.get("context"),
                        }
                    else:
                        g["count"] += 1
                        g["last_ts"] = entry.get("ts") or g["last_ts"]
        except Exception:
            pass

        # Top groups by count (relevance-ranked, capped)
        ERROR_GROUPS_CAP = 10
        top_groups = sorted(error_groups.values(), key=lambda x: -x["count"])
        errors_summary = {
            "total": errors_total,
            "by_severity": errors_by_severity,
            "distinct_groups": len(error_groups),
            "top_groups": top_groups[:ERROR_GROUPS_CAP],
        }
        if len(error_groups) > ERROR_GROUPS_CAP:
            errors_summary["_truncated"] = (
                f"Showing top {ERROR_GROUPS_CAP} of {len(error_groups)} distinct error groups. "
                f"Run `python3 socai.py errors` for the full log."
            )

        summary = {
            "case_id": case_id,
            "metadata": {
                "title": meta.get("title"),
                "status": meta.get("status"),
                "disposition": meta.get("disposition"),
                "severity": meta.get("severity"),
                "attack_type": meta.get("attack_type"),
                "attack_type_confidence": meta.get("attack_type_confidence"),
                "client": meta.get("client"),
                "analyst": meta.get("analyst"),
                "created_at": meta.get("created_at"),
                "updated_at": meta.get("updated_at"),
                "report_exists": any(
                    (case_dir / "reports" / f).exists()
                    for f in ("mdr_report.html", "pup_report.html", "investigation_report.html")
                ),
            },
            "iocs": ioc_summary,
            "verdicts": verdict_highlights,
            "enrichment": enrichment_stats,
            "response_actions": response_summary,
            "correlation": correlation_summary,
            "campaign": campaign if campaign else {},
            "analyst_notes": analyst_notes,
            "timeline_events": len(timeline) if isinstance(timeline, list) else 0,
            "errors": errors_summary,
            "_hint": (
                "This is the full case summary. Use read_report to view the "
                "investigation narrative (read-only), or read_case_file for "
                "specific artefacts. Use close_case to close the investigation. "
                "Full raw error log: `python3 socai.py errors`."
            ),
        }

        return _json(summary)

    @mcp.tool(title="Read Investigation Report", annotations={"readOnlyHint": True})
    def read_report(case_id: str) -> str:
        """Return the full investigation report for a case. Read-only — does NOT close the case.
        Use ``close_case`` explicitly when complete. For a quick overview use ``case_summary``.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from config.settings import CASES_DIR

        reports_dir = CASES_DIR / case_id / "reports"
        report_path = None
        for candidate in [
            reports_dir / "mdr_report.md",
            reports_dir / "pup_report.md",
            reports_dir / "investigation_report.md",
            # Legacy HTML reports (pre-markdown migration)
            reports_dir / "mdr_report.html",
            reports_dir / "pup_report.html",
            reports_dir / "investigation_report.html",
        ]:
            if candidate.exists():
                report_path = candidate
                break
        if report_path is None:
            return f"No report found for case {case_id!r}. Use the write_mdr_report or write_pup_report MCP prompt first."

        return report_path.read_text(encoding="utf-8")

    @mcp.tool(title="Read Case File", annotations={"readOnlyHint": True})
    def read_case_file(case_id: str, file_path: str):
        # Return type intentionally untyped: this tool returns a string for text
        # files and an Image object for screenshots; declaring `-> str` causes
        # Pydantic output validation to reject the Image branch.
        """Use when you need to read a specific artefact file from a case — e.g.
        raw enrichment JSON, IOC lists, captured HTML, phishing detection results,
        screenshots, or any other file produced by the pipeline.

        Takes a relative path within the case directory. Common paths include:
        ``iocs/iocs.json``, ``artefacts/enrichment/enrichment.json``,
        ``artefacts/enrichment/verdict_summary.json``,
        ``artefacts/phishing/detection.json``, ``artefacts/captures/*.html``,
        ``artefacts/web/*/screenshot.png``, ``notes/analyst_input.md``,
        ``reports/mdr_report.html``, ``reports/pup_report.html``.

        **Image files** (PNG, JPG, GIF, WebP) are returned as rendered images
        that display directly in chat. Use this to view screenshots from web
        captures, browser sessions, or sandbox detonations.

        For the investigation report specifically, prefer ``read_report`` (which
        also handles auto-close). For a full case overview, use ``case_summary``.

        Parameters
        ----------
        case_id : str
            Case identifier.
        file_path : str
            Relative path within the case directory (e.g. "artefacts/iocs.json").
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from config.settings import CASES_DIR

        import re as _re
        if not _re.match(r"^[A-Za-z0-9_-]+$", case_id):
            return _json({"error": "Invalid case_id."})

        clean = Path(file_path).as_posix()
        if ".." in clean or clean.startswith("/"):
            return _json({"error": "Directory traversal not allowed."})

        full_path = CASES_DIR / case_id / clean
        # Ensure resolved path stays inside the case directory
        try:
            full_path.resolve().relative_to((CASES_DIR / case_id).resolve())
        except ValueError:
            return _json({"error": "Directory traversal not allowed."})
        if not full_path.exists():
            # Try alternate locations
            for alt in [
                CASES_DIR / case_id / "artefacts" / clean,
                CASES_DIR / case_id / "artefacts" / "reports" / Path(clean).name,
            ]:
                if alt.exists():
                    full_path = alt
                    break
            else:
                return _json({"error": f"File not found: {file_path}"})

        # Image files → return as rendered image via MCP ImageContent
        _IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
        if full_path.suffix.lower() in _IMAGE_SUFFIXES:
            from mcp.server.fastmcp.utilities.types import Image
            max_image_bytes = 10 * 1024 * 1024  # 10 MB safety cap
            if full_path.stat().st_size > max_image_bytes:
                return _json({"error": f"Image too large ({full_path.stat().st_size} bytes). Max 10 MB."})
            return Image(path=full_path)

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            if len(content) > 50000:
                content = content[:50000] + "\n\n... [truncated]"
            return content
        except Exception as exc:
            return _json({"error": f"Error reading {file_path}: {exc}"})

    @mcp.tool(title="List Case Files", annotations={"readOnlyHint": True})
    def list_case_files(case_id: str, subpath: str = "") -> str:
        """List all files in a case directory (or subdirectory) with sizes.
        Pass ``subpath`` to scope to a subdirectory. Use returned paths with ``read_case_file``.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from config.settings import CASES_DIR
        import re as _re

        if not _re.match(r"^[A-Za-z0-9_-]+$", case_id):
            return _json({"error": "Invalid case_id."})

        case_dir = CASES_DIR / case_id
        if not case_dir.is_dir():
            return _json({"error": f"Case not found: {case_id}"})

        target = case_dir
        if subpath:
            clean = Path(subpath).as_posix()
            if ".." in clean or clean.startswith("/"):
                return _json({"error": "Directory traversal not allowed."})
            target = case_dir / clean
            try:
                target.resolve().relative_to(case_dir.resolve())
            except ValueError:
                return _json({"error": "Directory traversal not allowed."})
            if not target.is_dir():
                return _json({"error": f"Directory not found: {subpath}"})

        files = []
        for p in sorted(target.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(case_dir).as_posix()
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            files.append({"path": rel, "size": size})

        return _json({
            "case_id": case_id,
            "root": subpath or ".",
            "file_count": len(files),
            "files": files,
        })

    @mcp.tool(title="Create Case")
    async def create_case(
        title: str,
        severity: str = "medium",
        analyst: str = "unassigned",
        tags: list[str] | None = None,
        client_name: str = "",
        classification: str = "",
        plan: str = "",
        enrichment_id: str = "",
    ) -> str:
        """Create a new case (triage status, auto-assigned ID). Deliverable tools auto-create
        cases — use this when you need a case before the deliverable step.

        Typical flow: ``quick_enrich`` → IOCs malicious → create case with ``enrichment_id``
        (auto-imports results). ``client_name`` is required.
        """
        _require_scope("investigations:submit")

        if not client_name:
            raise ToolError(
                "Client name is required. Specify the client to ensure "
                "correct data segregation. Use lookup_client to find the "
                "registered client name."
            )

        _set_client_boundary(client_name)

        from tools.case_create import case_create as _create, next_case_id
        case_id = next_case_id()

        result = _create(
            case_id, title=title, severity=severity,
            analyst=analyst, tags=tags or [], client=client_name,
        )

        # Save classification and plan as notes
        if classification:
            result["attack_type"] = classification
            from config.settings import CASES_DIR
            from tools.common import save_json, load_json
            meta_path = CASES_DIR / case_id / "case_meta.json"
            meta = load_json(meta_path)
            meta["attack_type"] = classification
            save_json(meta_path, meta)

        if plan:
            from config.settings import CASES_DIR
            notes_dir = CASES_DIR / case_id / "notes"
            notes_dir.mkdir(parents=True, exist_ok=True)
            (notes_dir / "analyst_input.md").write_text(f"## Investigation Plan\n\n{plan}\n")

        # Auto-import quick_enrich results if enrichment_id provided
        if enrichment_id:
            try:
                from tools.enrich import import_enrichment as _import_enrich
                import_result = await asyncio.to_thread(
                    lambda: _import_enrich(enrichment_id, case_id)
                )
                result["imported_enrichment"] = import_result
            except Exception as exc:
                result["imported_enrichment"] = {
                    "error": f"Auto-import failed: {exc}",
                    "enrichment_id": enrichment_id,
                }

        return _json(result)

    @mcp.tool(title="Promote Case")
    def promote_case(
        case_id: str,
        title: str | None = None,
        severity: str | None = None,
        disposition: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Promote a case from triage to active status. Only triage cases can be promoted.
        Optionally update title, severity, disposition, or tags at promotion time.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.index_case import promote_case as _promote
        return _json(_promote(case_id, title=title, severity=severity,
                              disposition=disposition, tags=tags))

    @mcp.tool(title="Discard Case")
    def discard_case(
        case_id: str,
        reason: str = "",
    ) -> str:
        """Discard a triage case (known FP, duplicate, out of scope). Only triage cases can be discarded;
        use ``close_case`` for active or closed cases. ``reason`` is saved to metadata.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.index_case import discard_case as _discard
        return _json(_discard(case_id, reason=reason))

    @mcp.tool(title="Close Case")
    def close_case(
        case_id: str,
        disposition: str = "resolved",
    ) -> str:
        """Close a case and set its disposition. Idempotent — safe to call on already-closed cases.

        Disposition values: ``true_positive``, ``benign_positive``, ``false_positive``,
        ``benign``, ``pup_pua``, ``inconclusive``, ``resolved`` (default).
        Use ``benign_positive`` when the alert fired correctly but activity was authorised.
        """
        _require_scope("investigations:submit")
        # No boundary check — close_case is administrative (bulk close across cases)

        # Idempotent: if already closed, return a warning instead of double-closing
        from config.settings import CASES_DIR
        from tools.common import load_json
        meta_path = CASES_DIR / case_id / "case_meta.json"
        if meta_path.exists():
            meta = load_json(meta_path)
            if meta.get("status") == "closed":
                return _json({
                    "status": "already_closed",
                    "case_id": case_id,
                    "disposition": meta.get("disposition", "unknown"),
                    "message": (
                        f"Case {case_id} is already closed with disposition "
                        f"{meta.get('disposition', 'unknown')!r}. No action taken."
                    ),
                })

        from tools.index_case import index_case
        return _json(index_case(case_id, status="closed", disposition=disposition))

    @mcp.tool(title="Add Evidence")
    async def add_evidence(case_id: str, text: str) -> str:
        """Attach raw alert data, IOC lists, or analyst notes to a case. Extracts and
        merges IOCs into the case IOC set. Follow with ``enrich_iocs``.

        For NEW alerts on the same user/host, open a NEW case — never add to an old case.
        For analytical conclusions use ``add_finding`` instead of this tool.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.add_evidence(case_id, text)
        )

        # Speculative enrichment — pre-warm cache with IOCs from evidence text
        _speculative_enrich_bg(text, thread_name=f"spec_enrich_evidence_{case_id}")

        return _json(_pop_message(result))

    @mcp.tool(title="Record Analytical Finding")
    def add_finding(
        case_id: str,
        finding_type: str,
        summary: str,
        detail: str = "",
    ) -> str:
        """Record an analytical conclusion against a case. Use for structured findings, not raw data.

        ``add_evidence`` is for raw input; this tool is for conclusions drawn from evidence.
        Auto-promotes triage → active on first finding.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from config.settings import CASES_DIR
        from tools.common import load_json, utcnow

        case_dir = CASES_DIR / case_id

        # Auto-promote triage → active on first finding
        promoted = False
        meta_path = case_dir / "case_meta.json"
        if meta_path.exists():
            meta = load_json(meta_path)
            if meta.get("status") in ("triage", "open"):
                from tools.index_case import promote_case
                promote_case(case_id)
                promoted = True

        notes_dir = case_dir / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)

        # Append to analyst_input.md so report generation picks it up
        from tools.common import write_artefact

        notes_path = notes_dir / "analyst_input.md"
        existing = notes_path.read_text(errors="replace") if notes_path.exists() else ""
        entry = f"\n\n---\n\n**Finding ({finding_type}):** {summary}"
        if detail:
            entry += f"\n\n{detail}"
        write_artefact(notes_path, existing + entry + "\n")

        result = {
            "case_id": case_id,
            "finding_type": finding_type,
            "summary": summary,
            "recorded_at": utcnow(),
        }
        if promoted:
            result["auto_promoted"] = "triage → active"
        return _json(result)

    @mcp.tool(title="Enrich IOCs")
    async def enrich_iocs(
        case_id: str,
        include_private: bool = False,
        depth: str = "auto",
    ) -> str:
        """Extract and enrich all IOCs in a case against tiered threat intel providers.
        Triage + client baseline pre-filter saves API quota. Safe to re-run.

        ``depth``: ``"auto"`` (smart), ``"fast"`` (Tier 1 only), ``"full"`` (all tiers). See ``socai://enrichment-depths``.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)
        if depth not in ("auto", "fast", "full"):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(f"Invalid depth '{depth}'. Must be 'auto', 'fast', or 'full'.")

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.extract_and_enrich(
                case_id, include_private=include_private, depth=depth,
            )
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Generate Investigation Report")
    async def generate_report(case_id: str, close_case: bool = False) -> str:
        """Generate the internal investigation narrative (findings, IOC analysis, verdicts, attack chain).
        For the client-facing deliverable use ``prepare_mdr_report``; for PUP use ``prepare_pup_report``.

        Requires enrichment to have run first. Pass ``close_case=True`` to close on completion.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        # Guard: if close_case=True, auto-promote triage → active
        if close_case:
            from config.settings import CASES_DIR
            from tools.common import load_json
            meta_path = CASES_DIR / case_id / "case_meta.json"
            if meta_path.exists():
                meta = load_json(meta_path)
                if meta.get("status") == "triage":
                    from tools.index_case import promote_case as _promote
                    result = _promote(case_id)
                    if isinstance(result, dict) and "error" in result:
                        raise ToolError(result["error"])

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.generate_report(case_id, close_case=close_case)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Prepare MDR Report")
    async def prepare_mdr_report(case_id: str = "") -> str:
        """Prepare the primary client-facing MDR deliverable. Use the ``write_mdr_report`` prompt
        to generate the report, then call ``save_report(report_type="mdr_report")`` to persist it.

        ``case_id`` optional — auto-created and promoted if empty.
        """
        _require_scope("investigations:submit")

        case_id = _ensure_case(case_id)
        _check_client_boundary(case_id)

        return _json({
            "status": "use_prompt",
            "case_id": case_id,
            "prompt": "write_mdr_report",
            "save_tool": "save_report",
            "save_args": {"report_type": "mdr_report"},
            "message": (
                f"Case {case_id} is ready. Use the write_mdr_report prompt "
                f"to generate the report, then call save_report with "
                f'report_type="mdr_report" to persist it.'
            ),
        })

    @mcp.tool(title="Prepare PUP/PUA Report")
    async def prepare_pup_report(case_id: str = "") -> str:
        """Prepare a PUP/PUA report. Use the ``write_pup_report`` prompt to generate the report,
        then call ``save_report(report_type="pup_report")`` to persist it.
        ``case_id`` optional — auto-created if empty.
        """
        _require_scope("investigations:submit")

        case_id = _ensure_case(case_id, disposition="pup_pua")
        _check_client_boundary(case_id)

        return _json({
            "status": "use_prompt",
            "case_id": case_id,
            "prompt": "write_pup_report",
            "save_tool": "save_report",
            "save_args": {"report_type": "pup_report"},
            "message": (
                f"Case {case_id} is ready. Use the write_pup_report prompt "
                f"to generate the report, then call save_report with "
                f'report_type="pup_report" to persist it.'
            ),
        })

    @mcp.tool(title="Load Report Template")
    def load_report_template(template: str) -> str:
        """Return the markdown skeleton and analyst instructions for a report template.
        Use when ``prepare_mdr_report``/``prepare_pup_report`` is unavailable (e.g. case is closed).
        ``template``: ``"mdr_report"`` or ``"pup_report"``.
        """
        _require_scope("investigations:read")

        if template == "mdr_report":
            from tools.generate_mdr_report import _SYSTEM_PROMPT

            md_skeleton = (
                "# MDR Incident Report — {case_id}\n\n"
                "**Generated:** {timestamp}  \n"
                "**Analyst:** {analyst}  \n"
                "**Client:** {client}  \n"
                "**Severity:** {severity}\n\n"
                "---\n\n"
                "## Executive Summary\n\n"
                "[One paragraph: what was detected, by which platform, users/hosts "
                "involved, overall assessment, confidence level, evidence gaps.]\n\n"
                "## Technical Analysis\n\n"
                "[Chronological technical narrative: timestamps, processes, IOCs "
                "inline, enrichment verdicts. Mark gaps as UNKNOWN.]\n\n"
                "## Plain-Language Risk Explanation\n\n"
                "[Non-technical: what happened, business impact, what could happen "
                "if no action.]\n\n"
                "## What Was NOT Observed\n\n"
                "- [Tailored list of notable absences relevant to this detection type]\n\n"
                "## Recommendations\n\n"
                "### SOC-Executed Containment\n\n"
                "- [Reference Approved Response Actions and containment capabilities]\n\n"
                "### Client-Responsible Remediation\n\n"
                "- [Specific actions the client must take — name the user, host, or IOC]\n"
            )

            return (
                "# MDR Report Template\n\n"
                "## How to Use\n\n"
                "1. Produce the report as **markdown** using the skeleton below\n"
                "2. Fill in each section with investigation findings\n"
                "3. Call `save_report` with `report_type=\"mdr_report\"` and the full markdown as `report_text`\n\n"
                "The Claude Desktop visualiser renders the markdown directly — "
                "no HTML, no inline styles required.\n\n"
                "---\n\n"
                "## Analyst Instructions (Gold MDR / XDR Instruction Set)\n\n"
                f"{_SYSTEM_PROMPT}\n\n"
                "---\n\n"
                "## Markdown Skeleton\n\n"
                "Use this exact structure. Replace placeholder text with actual findings.\n\n"
                "```markdown\n"
                f"{md_skeleton}"
                "```\n"
            )

        if template == "pup_report":
            md_skeleton = (
                "# PUP/PUA Report — {case_id}\n\n"
                "**Generated:** {timestamp}  \n"
                "**Analyst:** {analyst}  \n"
                "**Client:** {client}\n\n"
                "---\n\n"
                "## Summary\n\n"
                "[One line: hostname, username, software name, PUP category, "
                "detection platform.]\n\n"
                "## Path & File Details\n\n"
                "- **File name:** [name]\n"
                "- **File path:** [full path on disk]\n"
                "- **SHA256:** [hash if available]\n"
                "- **Publisher / signer:** [if known]\n"
                "- **Detection name:** [EDR/AV signature or heuristic label]\n"
                "- **Category:** [adware / browser hijacker / bundleware / toolbar / "
                "crypto miner / system optimiser / other]\n\n"
                "## Access Vector\n\n"
                "[How the software arrived: user-installed, bundled with legitimate "
                "software, drive-by download, group policy, unknown. Include evidence "
                "— process tree, parent process, download source URL, installer name.]\n\n"
                "## Actions Taken\n\n"
                "- [What the SOC/EDR has already done: quarantined, blocked, alerted "
                "only. Include timestamps.]\n\n"
                "## Recommendations\n\n"
                "- Confirm whether this application is approved for use on corporate machines\n"
                "- [If not approved: removal steps — uninstall, EDR quarantine, manual cleanup]\n"
                "- [Prevention: block publisher hash, restrict user installs, browser policy]\n"
            )

            instructions = (
                "# PUP/PUA Report Instructions\n\n"
                "## Tone\n\n"
                "PUP/PUA reports are **not incident reports**. The tone is "
                "\"unwanted software found, recommended action required\" — not "
                "\"attack detected/blocked\". Use **UK English** and a professional SOC tone.\n\n"
                "## Rules\n\n"
                "- Every finding must be provable with supplied data\n"
                "- PUP ≠ malware — be precise about what it does vs. what it could do\n"
                "- If the access vector is unknown, say so — do not speculate\n"
                "- The default recommendation is always: "
                "\"confirm whether this application is approved for use on corporate machines\"\n"
                "- Only include IOCs that are directly observed (file hashes, paths, domains contacted)\n"
                "- Classify findings: CONFIRMED = data proves it, "
                "ASSESSED = inference, UNKNOWN = no data\n"
            )

            return (
                "# PUP/PUA Report Template\n\n"
                "## How to Use\n\n"
                "1. Produce the report as **markdown** using the skeleton below\n"
                "2. Fill in each section with investigation findings\n"
                "3. Call `save_report` with `report_type=\"pup_report\"` and the full markdown as `report_text`\n\n"
                "---\n\n"
                f"{instructions}\n"
                "---\n\n"
                "## Markdown Skeleton\n\n"
                "Use this exact structure. Replace placeholder text with actual findings.\n\n"
                "```markdown\n"
                f"{md_skeleton}"
                "```\n"
            )

        raise ToolError(
            f"Unknown template {template!r}. Valid values: mdr_report, pup_report."
        )

    @mcp.tool(title="Generate Hunt Queries")
    async def generate_queries(
        case_id: str,
        platforms: list[str] | None = None,
        tables: list[str] | None = None,
    ) -> str:
        """Generate ready-to-run hunt queries (KQL, Splunk SPL, LogScale CQL) from case IOCs
        and attack patterns. Requires enrichment to have run first.

        For ad-hoc LogScale/CQL queries without a case, call ``load_ngsiem_reference`` instead
        and write conversationally. Platforms default to all; pass ``tables`` to scope KQL.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.generate_queries(case_id, platforms=platforms, tables=tables)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Load NGSIEM Reference", annotations={"readOnlyHint": True})
    def load_ngsiem_reference(
        sections: list[str] | None = None,
    ) -> str:
        """Load CQL/LogScale/NGSIEM/CrowdStrike/Falcon syntax reference.
        Call BEFORE writing any such query.

        ``sections`` defaults to ``["rules", "syntax"]``. Other options:
        ``"columns"`` (per-connector field schemas), ``"grammar"`` (all
        194 CQL function signatures — 57 KB, request only when needed).
        Unknown section names return the valid list in the response.
        """
        _require_scope("sentinel:query")

        import pathlib
        base = pathlib.Path(__file__).resolve().parent.parent / "config"

        section_map = {
            "rules":   base / "ngsiem" / "ngsiem_rules.md",
            "columns": base / "ngsiem" / "ngsiem_columns.yaml",
            "grammar": base / "ngsiem" / "cql_grammar.json",
            "syntax":  base / "logscale_syntax.md",
        }

        if sections is None:
            sections = ["rules", "syntax"]

        parts = []
        for s in sections:
            path = section_map.get(s)
            if path and path.exists():
                parts.append(f"--- {s.upper()} ---\n\n{path.read_text(encoding='utf-8')}")
            elif path:
                parts.append(f"--- {s.upper()} --- (file not found)")
            else:
                valid = ", ".join(f'"{k}"' for k in section_map)
                parts.append(f"--- {s.upper()} --- (unknown section; valid: {valid})")

        return "\n\n".join(parts)

    @mcp.tool(title="Classify Attack Type", annotations={"readOnlyHint": True})
    def classify_attack(
        title: str = "",
        notes: str = "",
        tags: list[str] | None = None,
        urls: list[str] | None = None,
        file_names: list[str] | None = None,
        eml_provided: bool = False,
        logs_provided: bool = False,
    ) -> str:
        """Classify alert into attack_type (phishing, malware, ransomware,
        account_compromise, credential_access, privilege_escalation,
        data_exfiltration, insider_threat, lateral_movement,
        command_and_control, reconnaissance, persistence, defence_evasion,
        web_shell, oauth_consent, pup_pua, generic) and return ordered tool
        sequence + skip profile + the matching KQL/CQL playbook. Deterministic
        keyword/shape match, no LLM, no case required. Call EARLY to
        decide the investigation path.

        See ``plan_investigation`` for the same classification plus a
        numbered step-by-step plan with client identification.
        """
        _require_scope("investigations:read")

        from tools.classify_attack import classify_attack_type, PIPELINE_PROFILES

        result = classify_attack_type(
            title=title,
            analyst_notes=notes,
            tags=tags,
            urls=urls or (file_names if file_names else None),
            eml_paths=["provided.eml"] if eml_provided else None,
            zip_path="provided.zip" if file_names else None,
            log_paths=["provided.log"] if logs_provided else None,
        )

        attack_type = result["attack_type"]

        # Build recommended tool sequence per attack type.
        # Every sequence is prefixed with lookup_client → add_evidence so the
        # LLM always identifies the client and registers the alert first.
        _prefix = [
            {"tool": "lookup_client", "reason": "Identify client and confirm platform scope", "phase": "setup"},
            {"tool": "add_evidence", "reason": "Register raw alert data in the case", "phase": "setup"},
        ]
        # KQL playbook two-step: load_kql_playbook → run_kql per stage.
        # Playbooks are curated, stage-ordered query sets — always prefer
        # them over ad-hoc KQL.  The LLM must load the playbook first to
        # get the parameterised queries, then execute each stage with run_kql.
        def _kql(playbook_id: str, description: str) -> list[dict]:
            return [
                {"tool": "load_kql_playbook", "reason": f"Load the '{playbook_id}' playbook — contains optimised, multi-stage KQL queries for {description}", "playbook": playbook_id, "condition": "if Sentinel access (Advanced Hunting tables)"},
                {"tool": "run_kql_batch", "reason": "Execute independent playbook stages in parallel via run_kql_batch for speed — only use sequential run_kql when one stage's results inform the next", "depends_on": "load_kql_playbook", "condition": "if Sentinel access (Advanced Hunting tables)"},
            ]

        # Sentinel composite queries — single-execution full-picture queries
        # using Sentinel-native tables (OfficeActivity, SigninLogs, SecurityAlert).
        # Preferred over multi-stage playbooks when the environment only has
        # Sentinel-native tables rather than Advanced Hunting tables.
        def _composite(scenario: str, description: str) -> list[dict]:
            return [
                {"tool": "generate_sentinel_query", "reason": f"Generate composite '{scenario}' query — single-execution full-picture query for {description}", "scenario": scenario, "condition": "if Sentinel access (Sentinel-native tables)"},
                {"tool": "run_kql", "reason": "Execute the composite query — returns all investigation sections in one pass", "depends_on": "generate_sentinel_query", "condition": "if Sentinel access (Sentinel-native tables)"},
            ]

        tool_sequences = {
            "phishing": _prefix + [
                {"tool": "capture_urls", "reason": "Capture suspicious pages and auto-detect phishing (detect_phishing=True by default)"},
                {"tool": "analyse_email", "reason": "Parse .eml headers and content", "condition": "if .eml available"},
                {"tool": "enrich_iocs", "reason": "Enrich all extracted IOCs"},
                {"tool": "xposed_breach_check", "reason": "Check if targeted user email has prior breach exposure", "condition": "if recipient email available"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
            ] + _kql("phishing", "email delivery, URL clicks, credential harvest")
              + _kql("bec", "BEC lifecycle — persistence hunt, attacker email activity, tenant IP sweep, MDO block actions")
              + _composite("email-threat-zap", "email threats, ZAP, post-delivery activity") + [
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "malware": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich file hashes, IPs, domains"},
                {"tool": "capture_urls", "reason": "Capture any delivery URLs", "condition": "if URLs present"},
                {"tool": "start_sandbox_session", "reason": "Dynamic analysis of suspicious files", "condition": "if file available"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
            ] + _kql("malware-execution", "process tree, file events, persistence") + [
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment and remediation guidance"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "account_compromise": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich IPs, domains from sign-in data"},
                {"tool": "xposed_breach_check", "reason": "Check if user email appears in historical data breaches", "condition": "if user email available"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("account-compromise", "sign-ins, MFA, post-compromise audit")
              + _kql("bec", "BEC lifecycle — persistence hunt, attacker email activity, tenant IP sweep, MDO block actions")
              + _composite("suspicious-signin", "sign-ins, MFA, post-auth activity, alerts") + [
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment and remediation guidance"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "privilege_escalation": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich actor and target identities"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("privilege-escalation", "role changes, actor legitimacy")
              + _composite("oauth-consent-grant", "OAuth consent, app role assignments, post-consent activity") + [
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment and remediation guidance"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "data_exfiltration": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich IPs, domains from DLP/activity data"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("data-exfiltration", "volume anomalies, cloud access, network transfers")
              + _composite("dlp-exfiltration", "DLP alerts, bulk downloads, external sharing") + [
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment and remediation guidance"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "lateral_movement": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich IPs, hostnames, hashes from movement indicators"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("lateral-movement", "RDP/SMB pivots, credential access, blast radius")
              + _composite("suspicious-signin", "sign-ins, lateral movement indicators, alerts") + [
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment and remediation guidance (host isolation, credential reset)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "command_and_control": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich candidate C2 IPs/domains surfaced by the behavioural hunt"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations / known C2 infrastructure"},
            ] + _kql("command-and-control", "beaconing, DNS tunnelling, long-haul sessions, LOLBin callbacks") + [
                {"tool": "correlate", "reason": "Cross-reference candidate C2 destinations across artefacts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment and remediation guidance (block C2, isolate host)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "reconnaissance": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich scanning/spraying source IPs and ASNs"},
                {"tool": "recall_cases", "reason": "Check for prior recon from the same source"},
            ] + _kql("reconnaissance", "credential spray/stuffing, port/service scanning, DNS enumeration") + [
                {"tool": "correlate", "reason": "Cross-reference source IPs across artefacts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment guidance (block source, enforce MFA / smart lockout)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "ransomware": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich file hashes, ransom-note IOCs, C2 IPs"},
                {"tool": "recall_cases", "reason": "Check for prior related cases / same ransomware family"},
            ] + _kql("ransomware", "recovery tampering, mass file modification, ransom notes, impact detections") + [
                {"tool": "correlate", "reason": "Cross-reference encryption tooling and impacted hosts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment (isolate hosts, disable accounts, preserve for recovery)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "credential_access": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich actor/source identities and hosts"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("credential-access", "LSASS dumping, Kerberoasting/AS-REP, DCSync, credential-theft detections") + [
                {"tool": "correlate", "reason": "Cross-reference credential-theft tradecraft across hosts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment (reset credentials, KRBTGT double-reset, isolate hosts)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "persistence": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich persistence-related hashes, paths, domains"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("persistence", "scheduled tasks, Run keys, services, WMI subscriptions, startup folder") + [
                {"tool": "correlate", "reason": "Cross-reference persistence mechanisms across hosts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment (remove persistence, isolate host)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "defence_evasion": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich tooling hashes and source identities"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("defence-evasion", "log clearing, EDR/AV tamper, defensive-tool kills, detections") + [
                {"tool": "correlate", "reason": "Cross-reference tamper activity across hosts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment (re-enable protection, isolate host, investigate blind spot)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "web_shell": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich source IPs and dropped-file hashes"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("web-shell", "web-server spawned shells, web-shell drops, post-exploitation") + [
                {"tool": "correlate", "reason": "Cross-reference web-shell activity and egress"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment (remove web shell, patch app, isolate server)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "oauth_consent": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich consent IP and app/SP identifiers"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations / same app"},
            ] + _kql("oauth-consent", "consent grants, SP sign-ins, app data access, IP tenant sweep")
              + _composite("oauth-consent-grant", "OAuth consent, app role assignments, post-consent activity") + [
                {"tool": "correlate", "reason": "Cross-reference the app/SP across accounts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment (revoke consent, disable app/SP, revoke tokens)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "insider_threat": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich egress destinations and devices"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("insider-data-staging", "bulk cloud pull, local archiving, removable media, egress")
              + _composite("dlp-exfiltration", "DLP alerts, bulk downloads, external sharing") + [
                {"tool": "correlate", "reason": "Cross-reference staging and egress activity"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment guidance (preserve evidence, HR/legal coordination, restrict access)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "pup_pua": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich file hashes and domains"},
                {"tool": "prepare_pup_report", "reason": "Prepare PUP/PUA report"},
            ],
            "generic": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich all extracted IOCs"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
                {"tool": "capture_urls", "reason": "Capture any suspicious URLs", "condition": "if URLs present"},
                {"tool": "detect_phishing", "reason": "Check for brand impersonation", "depends_on": "capture_urls", "condition": "if URLs captured"},
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
                {"tool": "run_kql", "reason": "Ad-hoc KQL queries — no standard playbook for generic; write queries based on available IOCs", "condition": "if Sentinel access"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "prepare_mdr_report", "reason": "Prepare client-facing MDR deliverable"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
        }

        # Map attack types to their KQL playbook ID (None = no standard playbook)
        _playbook_map = {
            "phishing": "phishing",
            "malware": "malware-execution",
            "account_compromise": "account-compromise",
            "privilege_escalation": "privilege-escalation",
            "data_exfiltration": "data-exfiltration",
            "lateral_movement": "lateral-movement",
            "command_and_control": "command-and-control",
            "reconnaissance": "reconnaissance",
            "ransomware": "ransomware",
            "credential_access": "credential-access",
            "persistence": "persistence",
            "defence_evasion": "defence-evasion",
            "web_shell": "web-shell",
            "oauth_consent": "oauth-consent",
            "insider_threat": "insider-data-staging",
        }

        # Map attack types to composite Sentinel query scenarios.
        # These are single-execution full-picture queries using Sentinel-native
        # tables (OfficeActivity, SigninLogs, SecurityAlert, AlertEvidence).
        _composite_map = {
            "phishing": ["email-threat-zap", "inbox-rule-bec"],
            "account_compromise": ["suspicious-signin", "mailbox-permission-change", "inbox-rule-bec"],
            "privilege_escalation": ["suspicious-signin", "oauth-consent-grant"],
            "data_exfiltration": ["dlp-exfiltration"],
            "lateral_movement": ["suspicious-signin"],
            "oauth_consent": ["oauth-consent-grant"],
            "insider_threat": ["dlp-exfiltration"],
        }

        profile = PIPELINE_PROFILES.get(attack_type, PIPELINE_PROFILES["generic"])
        result["recommended_tools"] = tool_sequences.get(attack_type, tool_sequences["generic"])

        # Top-level playbook directive — makes it unmissable
        playbook_id = _playbook_map.get(attack_type)
        if playbook_id:
            result["kql_playbook"] = {
                "id": playbook_id,
                "instruction": (
                    f"A curated KQL playbook exists for this attack type. "
                    f"You MUST call load_kql_playbook('{playbook_id}') to load it, "
                    f"then execute each stage sequentially with run_kql. "
                    f"Do NOT write ad-hoc KQL — the playbook queries are optimised "
                    f"to get the most relevant data in the fewest queries."
                ),
            }
        else:
            result["kql_playbook"] = None

        # CQL playbook directive (LogScale / NGSIEM alternative)
        _cql_playbook_map = {
            "malware": "malware-execution",
            "lateral_movement": "lateral-movement",
            "account_compromise": "account-compromise",
            # C2 is fully portable to LogScale; reconnaissance covers Stages 1-2
            # on LogScale (Stage 3 authoritative-DNS enumeration is Sentinel-only).
            "command_and_control": "command-and-control",
            "reconnaissance": "reconnaissance",
            # New playbooks all ship Sentinel KQL + NGSIEM CQL. Email-backed
            # types (oauth_consent, insider_threat) need the M365/Defender
            # forwarding connector on LogScale; endpoint types ride Falcon native.
            "ransomware": "ransomware",
            "credential_access": "credential-access",
            "persistence": "persistence",
            "defence_evasion": "defence-evasion",
            "web_shell": "web-shell",
            "oauth_consent": "oauth-consent",
            "insider_threat": "insider-data-staging",
        }
        cql_playbook_id = _cql_playbook_map.get(attack_type)
        if cql_playbook_id:
            result["cql_playbook"] = {
                "id": cql_playbook_id,
                "instruction": (
                    f"A CQL playbook exists for this attack type. "
                    f"If the client uses CrowdStrike LogScale/NGSIEM (not Sentinel), "
                    f"call load_cql_playbook('{cql_playbook_id}') instead of load_kql_playbook. "
                    f"Check lookup_client platform list for 'ngsiem' or 'crowdstrike'."
                ),
            }
        else:
            result["cql_playbook"] = None

        # Sentinel composite queries — single-execution full-picture queries
        composite_scenarios = _composite_map.get(attack_type, [])
        if composite_scenarios:
            result["sentinel_composite_queries"] = {
                "scenarios": composite_scenarios,
                "instruction": (
                    f"Composite Sentinel queries are available for this attack type. "
                    f"Call generate_sentinel_query(scenario='{composite_scenarios[0]}', upn=...) "
                    f"to get a single ready-to-run query covering the full investigation picture. "
                    f"Use these for Sentinel-native environments instead of multi-stage playbooks."
                ),
            }
        else:
            result["sentinel_composite_queries"] = None

        result["routing_note"] = (
            "Follow the recommended_tools list in order. Do not skip steps unless a condition is unmet. "
            "When a KQL playbook is specified, always use it — do not substitute ad-hoc queries. "
            "For Sentinel-native environments, prefer generate_sentinel_query for full-picture queries."
        )
        result["skip_steps"] = sorted(profile.get("skip", set()))
        result["profile_description"] = profile.get("description", "")
        # Serialise sets for JSON output
        result["profile"] = {
            "skip": sorted(profile.get("skip", set())),
            "description": profile.get("description", ""),
        }

        # Specialist toolset routing — most tools load on demand, not at
        # startup. Tell the LLM which group (if any) to load for this type so
        # the right tools appear without bloating every session's context.
        from tools.classify_attack import ATTACK_TYPE_TOOLSETS
        rec_toolsets = ATTACK_TYPE_TOOLSETS.get(attack_type, [])
        result["recommended_toolsets"] = rec_toolsets
        if rec_toolsets:
            result["toolset_instruction"] = (
                f"Specialist tools for '{attack_type}' are NOT loaded yet. "
                f"Call load_toolset('{rec_toolsets[0]}') now so they become "
                f"callable, then follow recommended_tools."
            )
        else:
            result["toolset_instruction"] = (
                "The always-on core toolset covers this investigation type. "
                "If you later need a capability that isn't available (sandbox, "
                "OpenCTI, memory forensics, dark-web), call list_toolsets then "
                "load_toolset(<group>)."
            )

        # Speculative enrichment — pre-warm cache with IOCs from alert text
        _speculative_enrich_bg(
            f"{title}\n{notes}", extra_iocs=urls,
            thread_name="spec_enrich_classify",
        )

        return _json(result)

    @mcp.tool(title="Plan Investigation", annotations={"readOnlyHint": True})
    def plan_investigation(
        title: str = "",
        notes: str = "",
        tags: list[str] | None = None,
        urls: list[str] | None = None,
        file_names: list[str] | None = None,
        eml_provided: bool = False,
        logs_provided: bool = False,
        client_name: str = "",
        severity: str = "",
    ) -> str:
        """Use at the START of an interactive investigation. Classifies the
        attack type (see ``classify_attack``) and returns a numbered,
        phased investigation plan: client identification, intake, recall,
        enrichment, attack-specific evidence, reporting. Advisory only —
        execute steps by calling each tool.
        """
        _require_scope("investigations:read")

        from tools.classify_attack import classify_attack_type, PIPELINE_PROFILES

        result = classify_attack_type(
            title=title,
            analyst_notes=notes,
            tags=tags,
            urls=urls,
            eml_paths=["provided.eml"] if eml_provided else None,
            zip_path="provided.zip" if file_names else None,
            log_paths=["provided.log"] if logs_provided else None,
        )

        attack_type = result["attack_type"]
        profile = PIPELINE_PROFILES.get(attack_type, PIPELINE_PROFILES["generic"])

        # Build the investigation plan
        plan_steps = []
        step_num = 0

        # Phase 0 — Client identification (always)
        step_num += 1
        if client_name:
            plan_steps.append({
                "step": step_num,
                "phase": "Client Identification",
                "action": f"Call `lookup_client` to validate '{client_name}' and confirm available platforms.",
                "tool": "lookup_client",
                "reason": "Establishes platform scope (Sentinel workspace, XDR tenant, etc.)",
            })
        else:
            plan_steps.append({
                "step": step_num,
                "phase": "Client Identification",
                "action": "Identify the client from alert data, then call `lookup_client` to validate.",
                "tool": "lookup_client",
                "reason": "MANDATORY — no investigation proceeds without confirmed client.",
            })

        # Phase 1 — Intake
        step_num += 1
        plan_steps.append({
            "step": step_num,
            "phase": "Intake & Classification",
            "action": "Call `add_evidence` with the raw alert/incident data to register it in the case.",
            "tool": "add_evidence",
            "reason": "Extracts IOCs and saves raw evidence to the case.",
        })

        # Phase 2 — Recall & Enrich (always)
        step_num += 1
        plan_steps.append({
            "step": step_num,
            "phase": "Recall & Enrichment",
            "action": "Call `recall_cases` with extracted IOCs to check for prior investigations.",
            "tool": "recall_cases",
            "reason": "Identifies overlap with existing cases — may shortcut the investigation.",
        })
        step_num += 1
        plan_steps.append({
            "step": step_num,
            "phase": "Recall & Enrichment",
            "action": "Call `enrich_iocs` to run IOC extraction, enrichment, and scoring.",
            "tool": "enrich_iocs",
            "reason": "Queries VirusTotal, AbuseIPDB, URLhaus, ThreatFox, and other providers.",
        })

        # Phase 3 — Evidence collection (attack-type specific)
        skip = profile.get("skip", set())

        if urls and "domain_investigate" not in skip:
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Evidence Collection",
                "action": "Call `capture_urls` to screenshot and capture page source.",
                "tool": "capture_urls",
                "reason": "Collects web evidence for analysis.",
            })

        if urls and "detect_phishing_page" not in skip:
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Evidence Collection",
                "action": "Call `detect_phishing` on captured pages.",
                "tool": "detect_phishing",
                "depends_on": "capture_urls",
                "reason": "Checks for brand impersonation and credential harvesting.",
            })

        if eml_provided:
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Evidence Collection",
                "action": "Call `analyse_email` to parse .eml headers and content.",
                "tool": "analyse_email",
                "reason": "Analyses SPF/DKIM/DMARC, sender reputation, embedded URLs.",
            })

        if "sandbox_analyse" not in skip and (file_names or (urls and attack_type == "malware")):
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Evidence Collection",
                "action": "Consider `start_sandbox_session` for dynamic file analysis.",
                "tool": "start_sandbox_session",
                "reason": "Detonates suspicious files in an isolated container.",
                "optional": True,
            })

        # KQL playbook
        kql_playbooks = {
            "phishing": "phishing",
            "malware": "malware-execution",
            "account_compromise": "account-compromise",
            "privilege_escalation": "privilege-escalation",
            "data_exfiltration": "data-exfiltration",
            "lateral_movement": "lateral-movement",
            "command_and_control": "command-and-control",
            "reconnaissance": "reconnaissance",
        }
        if attack_type in kql_playbooks:
            step_num += 1
            pb_id = kql_playbooks[attack_type]
            plan_steps.append({
                "step": step_num,
                "phase": "Evidence Collection",
                "action": f"Load `{pb_id}` KQL playbook via `load_kql_playbook`, then execute stages with `run_kql`.",
                "tool": "run_kql",
                "condition": "Only if client has Sentinel access (check lookup_client result).",
                "reason": f"Structured {attack_type.replace('_', ' ')} investigation queries.",
            })

        # Phase 4 — Analysis
        step_num += 1
        plan_steps.append({
            "step": step_num,
            "phase": "Analysis",
            "action": "Call `correlate` to cross-reference IOCs across all case artefacts.",
            "tool": "correlate",
            "reason": "Identifies connections between evidence sources.",
        })

        # Phase 5 — Output
        step_num += 1
        plan_steps.append({
            "step": step_num,
            "phase": "Output",
            "action": "Call `generate_report` to produce the investigation narrative.",
            "tool": "generate_report",
            "reason": "Creates the detailed investigation report.",
        })

        if attack_type == "pup_pua":
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Output",
                "action": "Call `prepare_pup_report` for the PUP/PUA deliverable.",
                "tool": "prepare_pup_report",
                "reason": "Lightweight report for unwanted software detections.",
            })
        else:
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Output",
                "action": "Call `prepare_mdr_report` for the client-facing MDR deliverable.",
                "tool": "prepare_mdr_report",
                "reason": "Structured report for the client.",
            })
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Output",
                "action": "Call `response_actions` for containment and remediation guidance.",
                "tool": "response_actions",
                "reason": "Advisory response plan based on case findings and client platforms.",
            })
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Output",
                "action": "Call `generate_queries` for SIEM hunt queries.",
                "tool": "generate_queries",
                "reason": "Ready-to-run threat hunting queries for the client.",
            })

        # Build skipped steps explanation
        skipped = []
        skip_explanations = {
            "sandbox_analyse": "Cloud sandbox analysis — not relevant for this attack type",
            "sandbox_detonate": "Local sandbox detonation — not relevant for this attack type",
            "static_file_analyse": "Static file analysis — not relevant (no file artefact for this attack type)",
            "analyse_file": "File analysis — not relevant (no file artefact for this attack type)",
            "analyse_email": "Email analysis — not relevant (no email artefact for this attack type)",
            "detect_phishing_page": "Phishing detection — not relevant (not a phishing investigation)",
            "recursive_capture": "Recursive URL crawling — not relevant for this attack type",
            "domain_investigate": "Web capture — not relevant (no URL-based evidence expected)",
            "log_correlate": "Log correlation — skipped per profile",
            "plan": "Planning step — skipped per profile",
            "correlate": "Artefact correlation — skipped per profile",
            "anomaly_detection": "Anomaly detection — skipped per profile",
            "campaign_cluster": "Campaign clustering — skipped per profile",
            "response_actions": "Response actions — skipped per profile",
            "report": "Report generation — skipped per profile (PUP report used instead)",
            "query_gen": "Hunt query generation — skipped per profile",
            "security_arch": "Security architecture review — skipped per profile",
        }
        for s in sorted(skip):
            skipped.append({"step": s, "reason": skip_explanations.get(s, "Skipped per attack-type profile")})

        return _json({
            "attack_type": result["attack_type"],
            "confidence": result["confidence"],
            "signals": result["signals"],
            "severity": severity or "auto-detect from alert data",
            "client": client_name or "MUST BE IDENTIFIED — call lookup_client first",
            "plan": plan_steps,
            "skipped_steps": skipped,
            "profile_description": profile.get("description", ""),
            "note": "This plan is advisory. Execute each step by calling the listed tool.",
        })

    @mcp.tool(title="Quick IOC Enrichment", annotations={"readOnlyHint": True})
    async def quick_enrich(
        iocs: list[str],
        depth: str = "auto",
    ) -> str:
        """Fast, ad-hoc IOC lookup — no case required. Auto-detects IOC type.
        Returns per-IOC verdicts + full per-provider rows + an ``enrichment_id`` importable via ``import_enrichment``.
        ``depth``: ``"auto"`` | ``"fast"`` | ``"full"``. See ``socai://enrichment-depths``.
        """
        _require_scope("investigations:read")

        if depth not in ("auto", "fast", "full"):
            from mcp.server.fastmcp.exceptions import ToolError
            raise ToolError(f"Invalid depth '{depth}'. Must be 'auto', 'fast', or 'full'.")

        from tools.enrich import quick_enrich as _quick_enrich

        result = await asyncio.to_thread(
            lambda: _quick_enrich(iocs, depth=depth)
        )
        return _json(result)


    @mcp.tool(title="Import Enrichment into Case")
    async def import_enrichment(
        enrichment_id: str,
        case_id: str,
    ) -> str:
        """Import a prior ``quick_enrich`` result into a case without re-querying providers.
        Copies enrichment data, writes IOCs, scores verdicts, and updates the shared IOC index.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.enrich import import_enrichment as _import

        result = await asyncio.to_thread(
            lambda: _import(enrichment_id, case_id)
        )
        return _json(result)

    @mcp.tool(title="Query OpenCTI", annotations={"readOnlyHint": True, "openWorldHint": True})
    async def query_opencti(
        query: str = "",
        query_type: str = "auto",
        report_id: str = "",
    ) -> str:
        """Query the internal OpenCTI instance for threat actors, malware, campaigns,
        attack patterns, IOCs, CVEs, or reports. For routine IOC enrichment prefer
        ``quick_enrich``/``enrich_iocs`` which call OpenCTI automatically.

        Pass ``report_id`` to fetch a full STIX report bundle. ``query_type`` auto-detects
        IOCs/CVEs; use ``"threat_actor"``, ``"malware"``, ``"campaign"``, ``"report"`` for keyword search.
        """
        _require_scope("investigations:read")

        from tools.enrich import _opencti_lookup, _detect_ioc_type
        from config.settings import OPENCTI_KEY, OPENCTI_URL

        if not OPENCTI_KEY:
            return _json({"status": "error",
                          "message": "OpenCTI not configured (SOCAI_OPENCTI_KEY not set)"})

        if report_id:
            result = await asyncio.to_thread(
                lambda: _opencti_report_detail(report_id, OPENCTI_KEY, OPENCTI_URL)
            )
        else:
            if not query:
                return _json({"status": "error",
                              "message": "Either query or report_id must be provided"})
            result = await asyncio.to_thread(
                lambda: _query_opencti_inner(query, query_type, _opencti_lookup,
                                             _detect_ioc_type, OPENCTI_KEY, OPENCTI_URL)
            )
        return _json(result)

    @mcp.tool(title="Extract IOCs from Text", annotations={"readOnlyHint": True})
    def extract_iocs_from_text(text: str, include_private: bool = False) -> str:
        """Extract IOCs (IPs, domains, URLs, hashes, emails, CVEs) from raw text. No case required.
        Feed output into ``quick_enrich`` for reputation data. ``include_private`` includes RFC-1918 IPs.
        """
        _require_scope("investigations:read")

        from tools.extract_iocs import _extract_from_text
        raw = _extract_from_text(text, include_private=include_private)
        # Convert sets to sorted lists for JSON serialisation
        result = {k: sorted(v) for k, v in raw.items()}
        total = sum(len(v) for v in result.values())
        return _json({"status": "ok", "total_iocs": total, "iocs": result})

    @mcp.tool(title="Search Confluence", annotations={"readOnlyHint": True, "openWorldHint": True})
    async def search_confluence(
        query: str = "",
        page_id: str = "",
        limit: int = 15,
    ) -> str:
        """Browse or search **published ET/EV threat articles** on the team Confluence space.

        Confluence is exclusively the archive of published threat articles (ET/EV).
        It is **not** a SOC knowledge base — do not use for processes, policies,
        runbooks, escalation matrices, or shift handover. Those live in
        ``socai://`` resources and client playbooks.

        Modes: browse (no args) → recent pages; search (query) → title match; read (page_id) → full body.
        """
        _require_scope("investigations:read")

        from tools.confluence_read import (
            _is_configured,
            get_page,
            list_pages,
            search_pages,
        )

        if not _is_configured():
            raise ToolError(
                "Confluence not configured. Set CONFLUENCE_URL, CONFLUENCE_CLOUD_ID, "
                "CONFLUENCE_EMAIL, CONFLUENCE_API_TOKEN, and CONFLUENCE_SPACE_KEY."
            )

        # Mode: read a specific page
        if page_id:
            result = await asyncio.to_thread(get_page, page_id)
            if not result:
                raise ToolError(f"Page {page_id} not found or not accessible.")
            # Cap body at ~8 KB to keep context manageable. ET/EV articles can
            # be >100 KB of raw HTML; full content is rarely needed once IOCs
            # and the summary are visible.
            MAX_BODY_CHARS = 8000
            body = result.get("body") or ""
            if len(body) > MAX_BODY_CHARS:
                result["body"] = body[:MAX_BODY_CHARS]
                result["_body_truncated"] = True
                result["_body_full_length"] = len(body)
                result["_hint"] = (
                    f"Page body truncated to {MAX_BODY_CHARS} of {len(body)} chars. "
                    "Full content is rarely needed — ask the analyst to open the "
                    "Confluence URL directly if deeper context is required."
                )
            return _json({"status": "ok", "mode": "read", "page": result})

        # Mode: search by title
        if query:
            pages = await asyncio.to_thread(search_pages, query, limit)
            if not pages:
                return _json({
                    "status": "no_matches",
                    "mode": "search",
                    "query": query,
                    "results": 0,
                    "pages": [],
                    "_hint": (
                        "No pages match this title query. Do NOT reformulate "
                        "and retry — the ET/EV corpus genuinely has no entry. "
                        "For SOC process/runbook questions use socai:// "
                        "resources (incident-handling, service-requests, "
                        "critical-incident-management). For external threat "
                        "intel use search_threat_articles or web_search."
                    ),
                })
            return _json({
                "status": "ok",
                "mode": "search",
                "query": query,
                "results": len(pages),
                "pages": pages,
                "_hint": (
                    "To read the full content of a page, call search_confluence "
                    "again with the page_id from the results above."
                ),
            })

        # Mode: browse recent pages
        result = await asyncio.to_thread(list_pages, limit)
        pages = result.get("pages", [])
        if not pages:
            return _json({
                "status": "no_matches",
                "mode": "browse",
                "results": 0,
                "pages": [],
                "_hint": (
                    "Confluence space returned no pages — check CONFLUENCE_SPACE_KEY "
                    "and token scopes. Do not retry this tool."
                ),
            })
        return _json({
            "status": "ok",
            "mode": "browse",
            "results": len(pages),
            "pages": pages,
            "next_cursor": result.get("next_cursor"),
            "_hint": (
                "To read the full content of a page, call search_confluence "
                "again with the page_id from the results above."
            ),
        })


def _opencti_report_detail(
    report_id: str,
    opencti_key: str,
    opencti_url: str,
) -> dict:
    """Fetch a full OpenCTI report with contained STIX objects and metadata."""
    import requests as _requests

    headers = {"Authorization": f"Bearer {opencti_key}", "Content-Type": "application/json"}
    graphql_url = f"{opencti_url}/graphql"

    gql = """
    query GetReport($id: String!) {
      report(id: $id) {
        id
        entity_type
        name
        description
        published
        report_types
        confidence
        created_at
        createdBy { name }
        objectMarking { definition }
        externalReferences {
          edges { node { url source_name description } }
        }
        objects(first: 500) {
          edges {
            node {
              ... on StixDomainObject {
                id
                entity_type
                ... on Indicator {
                  name
                  pattern
                  valid_from
                  valid_until
                  description
                }
                ... on ThreatActorGroup { name description aliases }
                ... on ThreatActorIndividual { name description aliases }
                ... on Malware { name description is_family malware_types }
                ... on AttackPattern { name description x_mitre_id }
                ... on Vulnerability { name description }
                ... on Campaign { name description first_seen last_seen }
                ... on Infrastructure { name description }
                ... on IntrusionSet { name description }
                ... on Report { name }
              }
              ... on StixCyberObservable {
                id
                entity_type
                observable_value
              }
            }
          }
        }
      }
    }
    """

    try:
        resp = _requests.post(
            graphql_url, headers=headers,
            json={"query": gql, "variables": {"id": report_id}},
            timeout=20,
        )
        resp.raise_for_status()
    except Exception as exc:
        return {"provider": "opencti", "status": "error",
                "report_id": report_id, "error": str(exc)}

    data = resp.json()
    if data.get("errors"):
        return {"provider": "opencti", "status": "api_error",
                "report_id": report_id,
                "message": data["errors"][0].get("message")}

    report = data.get("data", {}).get("report")
    if not report:
        return {"provider": "opencti", "status": "not_found",
                "report_id": report_id, "message": "Report not found"}

    # Build result
    result = {
        "id": report.get("id"),
        "type": report.get("entity_type"),
        "name": report.get("name"),
        "description": report.get("description"),
        "published": report.get("published"),
        "created_at": report.get("created_at"),
        "report_types": report.get("report_types"),
        "confidence": report.get("confidence"),
        "created_by": report.get("createdBy", {}).get("name") if report.get("createdBy") else None,
        "markings": [m.get("definition") for m in (report.get("objectMarking") or [])],
        "opencti_link": f"{opencti_url}/dashboard/analyses/reports/{report.get('id')}",
    }

    # External references
    ext_refs = []
    for edge in (report.get("externalReferences") or {}).get("edges", []):
        node = edge.get("node", {})
        ref = {}
        if node.get("source_name"):
            ref["source_name"] = node["source_name"]
        if node.get("url"):
            ref["url"] = node["url"]
        if node.get("description"):
            ref["description"] = node["description"]
        if ref:
            ext_refs.append(ref)
    if ext_refs:
        result["external_references"] = ext_refs

    # Contained STIX objects — grouped by type
    objects_by_type: dict[str, list] = {}
    for edge in (report.get("objects") or {}).get("edges", []):
        node = edge.get("node", {})
        etype = node.get("entity_type", "unknown")

        obj: dict = {"id": node.get("id"), "type": etype}

        # StixCyberObservable
        if node.get("observable_value"):
            obj["value"] = node["observable_value"]
        # StixDomainObject fields
        if node.get("name"):
            obj["name"] = node["name"]
        if node.get("description"):
            obj["description"] = node["description"][:2000]
        if node.get("pattern"):
            obj["pattern"] = node["pattern"]
        if node.get("valid_from"):
            obj["valid_from"] = node["valid_from"]
        if node.get("valid_until"):
            obj["valid_until"] = node["valid_until"]
        if node.get("aliases"):
            obj["aliases"] = node["aliases"]
        if node.get("x_mitre_id"):
            obj["mitre_id"] = node["x_mitre_id"]
        if node.get("is_family") is not None:
            obj["is_family"] = node["is_family"]
        if node.get("malware_types"):
            obj["malware_types"] = node["malware_types"]
        if node.get("first_seen"):
            obj["first_seen"] = node["first_seen"]
        if node.get("last_seen"):
            obj["last_seen"] = node["last_seen"]

        objects_by_type.setdefault(etype, []).append(obj)

    if objects_by_type:
        result["objects"] = objects_by_type
        result["object_counts"] = {k: len(v) for k, v in objects_by_type.items()}
        result["total_objects"] = sum(len(v) for v in objects_by_type.values())

    return {
        "provider": "opencti",
        "status": "ok",
        "query_type": "report_detail",
        "report_id": report_id,
        "report": result,
    }


def _query_opencti_inner(
    query: str,
    query_type: str,
    _opencti_lookup,
    _detect_ioc_type,
    opencti_key: str,
    opencti_url: str,
) -> dict:
    """Synchronous inner logic for query_opencti tool."""
    import requests as _requests

    # Auto-detect query type
    if query_type == "auto":
        ioc_type = _detect_ioc_type(query)
        if ioc_type:
            query_type = "ioc"
        elif query.upper().startswith("CVE-"):
            query_type = "cve"
        else:
            query_type = "search"

    # IOC lookup — delegate to existing provider function
    if query_type == "ioc":
        ioc_type = _detect_ioc_type(query)
        if not ioc_type:
            return {"status": "error", "message": f"Could not detect IOC type for: {query}"}
        return _opencti_lookup(query, ioc_type)

    # CVE lookup — delegate to existing provider function
    if query_type == "cve":
        return _opencti_lookup(query.upper(), "cve")

    # Keyword search — threat actors, malware, campaigns, reports, attack patterns
    entity_map = {
        "threat_actor": ("threatActors", "ThreatActor"),
        "malware": ("malwares", "Malware"),
        "campaign": ("campaigns", "Campaign"),
        "report": ("reports", "Report"),
        "attack_pattern": ("attackPatterns", "AttackPattern"),
        "search": None,  # broad search across all types
    }

    headers = {"Authorization": f"Bearer {opencti_key}", "Content-Type": "application/json"}
    graphql_url = f"{opencti_url}/graphql"

    if query_type in entity_map and entity_map[query_type]:
        collection, _ = entity_map[query_type]
        gql = """{
          %s(search: "%s", first: 10, orderBy: created_at, orderMode: desc) {
            edges { node { id entity_type name description created_at } }
          }
        }""" % (collection, query.replace('"', '\\"'))
    else:
        # Broad search across STIX domain objects
        gql = """{
          stixDomainObjects(search: "%s", first: 15, orderBy: created_at, orderMode: desc) {
            edges {
              node {
                id
                entity_type
                ... on ThreatActorGroup  { name description }
                ... on ThreatActorIndividual { name description }
                ... on Malware           { name description malware_types }
                ... on Campaign          { name description }
                ... on Report            { name description published }
                ... on IntrusionSet      { name description }
                ... on AttackPattern     { name description x_mitre_id }
                ... on Vulnerability     { name description }
                created_at
              }
            }
          }
        }""" % query.replace('"', '\\"')

    try:
        resp = _requests.post(graphql_url, headers=headers, json={"query": gql}, timeout=15)
        resp.raise_for_status()
    except Exception as exc:
        return {"provider": "opencti", "status": "error", "query": query, "error": str(exc)}

    data = resp.json()
    if data.get("errors"):
        return {"provider": "opencti", "status": "api_error", "query": query,
                "message": data["errors"][0].get("message")}

    # Extract results from whichever collection was queried
    results = []
    for key in ("stixDomainObjects", "threatActors", "malwares", "campaigns",
                "reports", "attackPatterns"):
        edges = data.get("data", {}).get(key, {}).get("edges", [])
        if edges:
            for e in edges:
                node = e["node"]
                entry = {
                    "id": node.get("id"),
                    "type": node.get("entity_type"),
                    "name": node.get("name"),
                    "created_at": node.get("created_at"),
                }
                if node.get("description"):
                    entry["description"] = node["description"][:2000]
                if node.get("x_mitre_id"):
                    entry["mitre_id"] = node["x_mitre_id"]
                if node.get("malware_types"):
                    entry["malware_types"] = node["malware_types"]
                if node.get("published"):
                    entry["published"] = node["published"]
                # Build direct link
                path_map = {
                    "Threat-Actor-Group": "threats/threat_actors_group",
                    "Threat-Actor-Individual": "threats/threat_actors_individual",
                    "Malware": "arsenal/malwares",
                    "Campaign": "threats/campaigns",
                    "Report": "analyses/reports",
                    "Intrusion-Set": "threats/intrusion_sets",
                    "Attack-Pattern": "techniques/attack_patterns",
                    "Vulnerability": "arsenal/vulnerabilities",
                }
                etype = node.get("entity_type", "")
                if etype in path_map:
                    entry["opencti_link"] = f"{opencti_url}/dashboard/{path_map[etype]}/{node['id']}"
                results.append(entry)
            break

    return {
        "provider": "opencti",
        "status": "ok",
        "query": query,
        "query_type": query_type,
        "result_count": len(results),
        "results": results,
    }


# ---------------------------------------------------------------------------
# Tier 2 — Extended Analysis (26 tools)
# ---------------------------------------------------------------------------

def _register_tier2(mcp: FastMCP) -> None:

    @mcp.tool(title="Capture URLs")
    async def capture_urls(
        case_id: str,
        urls: list[str],
        detect_phishing: bool = True,
    ) -> str:
        """Capture screenshots, HTML source, headers, and redirect chain for each URL.
        Phishing detection runs automatically after capture (set ``detect_phishing=False`` to skip).

        View screenshots via ``read_case_file`` — images render inline in chat.
        Use ``start_browser_session`` when Cloudflare/CAPTCHA blocks automation.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.capture_urls(case_id, urls)
        )

        if detect_phishing:
            try:
                phishing_result = await asyncio.to_thread(
                    lambda: actions.detect_phishing(case_id)
                )
                result["phishing_detection"] = phishing_result
            except Exception:
                result["phishing_detection"] = {"error": "Phishing detection failed — run detect_phishing separately"}

        return _json(_pop_message(result))

    @mcp.tool(title="Detect Phishing")
    async def detect_phishing(case_id: str) -> str:
        """Analyse captured page content for brand impersonation, fake login forms, and phishing kit signatures.
        Prerequisite: ``capture_urls`` must have run first.

        Parameters
        ----------
        case_id : str
            Case identifier. URLs must have been captured first.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.detect_phishing(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Analyse Email")
    async def analyse_email(case_id: str) -> str:
        """Analyse .eml files from the case ``uploads/`` directory: SPF/DKIM/DMARC,
        header anomalies, reply-to mismatches, URLs, attachments, BEC patterns.

        Upload .eml files to the case first; returns error if none found.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from config.settings import CASES_DIR
        from api import actions

        eml_dir = CASES_DIR / case_id / "uploads"
        eml_paths = [str(f) for f in eml_dir.glob("*.eml")] if eml_dir.exists() else []
        if not eml_paths:
            return _json({"error": "No .eml files found in uploads."})

        result = await asyncio.to_thread(
            lambda: actions.analyse_email(case_id, eml_paths)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Correlate IOCs Across Artefacts")
    async def correlate(case_id: str) -> str:
        """Cross-reference IOCs across all case artefacts (enrichment, captured pages, email headers,
        logs) to find shared infrastructure and attack chain links. Returns every raw match.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.correlate(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Reconstruct Forensic Timeline", annotations={"readOnlyHint": True})
    async def reconstruct_timeline(case_id: str) -> str:
        """Extract timestamped events from all case artefacts and assemble a chronological
        forensic timeline (initial access → execution → persistence → exfiltration).
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.reconstruct_timeline(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Cluster Campaign Overlaps", annotations={"readOnlyHint": True})
    async def campaign_cluster(case_id: str) -> str:
        """Bulk-compare all IOCs in a case against every other case to find shared infrastructure
        and campaign clusters. Use ``recall_cases`` for targeted IOC/keyword search instead.
        """
        _require_scope("campaigns:read")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.run_campaign_cluster(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Recall Prior Cases", annotations={"readOnlyHint": True})
    def recall_cases(
        iocs: list[str] | None = None,
        emails: list[str] | None = None,
        keywords: list[str] | None = None,
    ) -> str:
        """Search all prior investigations for overlapping IOCs, emails, or keywords.
        Use during every investigation to check whether entities appeared in prior cases.

        Note overlaps in your analysis but keep evidence in the current case — never merge.
        Use ``campaign_cluster`` for automated bulk IOC comparison across all cases.
        Returns full prior-case report excerpts.
        """
        _require_scope("investigations:read")

        # Client boundary filtering is a no-op now
        active_client = ""

        from tools.recall import recall
        result = recall(
            iocs=iocs or [],
            emails=emails or [],
            keywords=keywords or [],
            caller_client=active_client,
        )
        if isinstance(result, dict):
            result["_hint"] = (
                "Note any overlapping IOCs or users in your analysis, but do NOT "
                "merge cases or add evidence to prior cases. One alert = one case. "
                "Consider whether overlap indicates a campaign or coincidence."
            )
        return _json(result)

    @mcp.tool(title="Assess Threat Landscape", annotations={"readOnlyHint": True})
    def assess_landscape(
        days: int | None = None,
        client_name: str | None = None,
    ) -> str:
        """Analyse recent cases to produce a threat landscape assessment: attack type distribution,
        severity trends, top-targeted clients, and active campaigns.

        Optionally filter by ``client_name`` or set a ``days`` lookback window.
        """
        _require_scope("campaigns:read")

        from tools.case_landscape import assess_landscape as _assess
        return _json(_assess(days=days, client=client_name))

    @mcp.tool(title="Search Threat Articles", annotations={"readOnlyHint": True})
    def search_threat_articles(
        days: int = 7,
        count: int = 20,
        category: str | None = None,
    ) -> str:
        """Search threat intel feeds for recent ET/EV article candidates, de-duplicated
        against published articles. Returns a ranked list for analyst review.

        After selecting, call ``generate_threat_article`` to produce write-ups.
        ``category``: ``"ET"`` or ``"EV"``; ``days``: lookback window; ``count``: max candidates.
        """
        _require_scope("campaigns:read")

        from tools.threat_articles import fetch_candidates
        candidates = fetch_candidates(days=days, max_candidates=count, category=category)
        return _json({"candidates": candidates, "count": len(candidates)})

    @mcp.tool(title="Check Article Dedup", annotations={"readOnlyHint": True})
    def check_article_dedup(title: str) -> str:
        """Check if a proposed article topic is already covered in the local index,
        Confluence, or OpenCTI before writing it. Returns match details.
        """
        _require_scope("campaigns:read")

        from tools.threat_articles import check_topic_dedup
        result = check_topic_dedup(title)
        if not result["is_duplicate"]:
            result["message"] = "No duplicates found. Safe to write this article."
        else:
            result["message"] = (
                "Duplicate(s) detected. Review the matches below. "
                "If you still want to proceed, use force=True when calling "
                "save_threat_article."
            )
        return _json(result)

    @mcp.tool(title="Generate Threat Article")
    async def generate_threat_article(
        candidate_urls: list[str],
        analyst: str = "mcp",
        case_id: str | None = None,
    ) -> str:
        """Prepare a threat article write-up. Use the ``write_threat_article`` prompt
        to write the article, then call ``save_threat_article`` to persist it.
        """
        _require_scope("investigations:submit")
        if case_id:
            _check_client_boundary(case_id)

        return _json({
            "status": "use_prompt",
            "prompt": "write_threat_article",
            "save_tool": "save_threat_article",
            "candidate_urls": candidate_urls,
            "analyst": analyst,
            "case_id": case_id,
            "message": (
                "Use the write_threat_article prompt to generate the article, "
                "then call save_threat_article to persist it."
            ),
        })

    @mcp.tool(title="Save Threat Article")
    async def save_threat_article(
        article_text: str,
        title: str,
        category: str = "ET",
        source_urls: list[str] | None = None,
        analyst: str = "mcp",
        case_id: str | None = None,
        force: bool = False,
    ) -> str:
        """Persist a threat article (from ``write_threat_article`` prompt) to disk with dedup check.

        Checks for duplicates across local index, Confluence, and OpenCTI before saving.
        Use ``force=True`` to override. Category: ``"ET"`` (Emerging Threat) or ``"EV"`` (Emerging Vulnerability).
        """
        _require_scope("investigations:submit")
        if case_id:
            _check_client_boundary(case_id)

        from tools.threat_articles import save_article
        result = await asyncio.to_thread(
            lambda: save_article(
                article_text=article_text,
                title=title,
                category=category,
                source_urls=source_urls or [],
                analyst=analyst,
                case_id=case_id,
                force=force,
            )
        )

        if result.get("status") == "duplicate_warning":
            result["_hint"] = (
                "To save this article despite the duplicate warning, "
                "call save_threat_article again with force=True."
            )
            return _json(result)

        # Reload the persisted article so Claude Desktop can render it as a
        # markdown artifact in the visualiser. The .md file is the analyst's
        # copy-paste source for the customer deliverable / Confluence post.
        try:
            from pathlib import Path as _Path
            ap = _Path(result.get("article_path", ""))
            if ap.is_file():
                result["article_md"] = ap.read_text(encoding="utf-8")
                result["display_hint"] = (
                    "Render `article_md` as a markdown artifact so Claude Desktop "
                    "opens it in the visualiser (Artifacts side panel). Do not "
                    "paste the raw markdown into the chat body."
                )
        except Exception as exc:
            from tools.common import log_error
            import traceback as _tb
            log_error(case_id or "", "save_threat_article.read_back", str(exc),
                      severity="warning", traceback=_tb.format_exc())

        from config.settings import OPENCTI_PUBLISH_ENABLED
        if OPENCTI_PUBLISH_ENABLED:
            result["_next_step"] = (
                "To prepare this article for OpenCTI posting, call "
                "generate_opencti_package with article_id="
                f"'{result.get('article_id', '')}'. This generates an HTML file "
                "with labelled sections for report metadata, observable blocklists, "
                "STIX indicators, and KQL/LogScale hunt queries."
            )
        return _json(result)

    @mcp.tool(title="Publish Article to OpenCTI")
    async def post_opencti_report(
        article_id: str,
        force: bool = False,
    ) -> str:
        """Publish a saved threat article to OpenCTI as a STIX 2.1 bundle.
        Dedup checks by title before posting — use ``force=True`` to override.

        Requires ``SOCAI_OPENCTI_PUBLISH=1``. Writes back the OpenCTI report ID to the manifest.
        """
        _require_scope("investigations:submit")

        from tools.opencti_publish import publish_report
        result = await asyncio.to_thread(
            lambda: publish_report(article_id, force=force)
        )
        return _json(result)

    @mcp.tool(title="Generate OpenCTI Posting Package")
    async def generate_opencti_package(
        article_id: str,
    ) -> str:
        """Generate an HTML posting package for an article: STIX 2.1 bundle, IOC indicators,
        KQL + LogScale hunt queries, labelled sections for pasting into OpenCTI.

        HTML saved alongside the article. Pass ``article_id`` (e.g. ``ART-20260327-0001``).
        """
        _require_scope("investigations:read")

        from tools.opencti_publish import generate_posting_package
        result = await asyncio.to_thread(
            lambda: generate_posting_package(article_id)
        )
        return _json(result)

    @mcp.tool(title="Web Search (OSINT)", annotations={"readOnlyHint": True})
    def web_search(query: str, max_results: int = 10) -> str:
        """OSINT web search via Brave Search API or DuckDuckGo fallback. Use only when
        structured tools (``enrich_iocs``, ``contextualise_cves``) return insufficient data.
        """
        _require_scope("investigations:submit")

        from tools.web_search import web_search as _ws
        return _json(_ws(query, max_results=max_results))

    @mcp.tool(title="Prepare Executive Summary")
    async def prepare_executive_summary(case_id: str) -> str:
        """Prepare a non-technical executive summary. Use the ``write_executive_summary`` prompt
        to write it, then call ``save_report(report_type="executive_summary")`` to persist it.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        return _json({
            "status": "use_prompt",
            "case_id": case_id,
            "prompt": "write_executive_summary",
            "save_tool": "save_report",
            "save_args": {"report_type": "executive_summary"},
            "message": (
                f"Use the write_executive_summary prompt to generate the "
                f"summary for {case_id}, then call save_report with "
                f'report_type="executive_summary" to persist it.'
            ),
        })

    @mcp.tool(title="Parse Log Files")
    async def parse_logs(case_id: str) -> str:
        """Parse CSV/JSON/JSONL log files from case ``uploads/`` and extract structured entities
        (timestamps, IPs, usernames, process names, command lines, Event IDs).

        Follow with ``detect_anomalies`` for behavioural detection or ``correlate_evtx`` for event chains.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.parse_logs_action(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Detect Anomalies", annotations={"readOnlyHint": True})
    async def detect_anomalies(case_id: str) -> str:
        """Run six behavioural anomaly detectors on parsed log data: temporal (OOH logins),
        impossible travel, brute force, first-seen entities, volume spikes, lateral movement.

        Requires ``parse_logs``, ``ingest_velociraptor``, or ``ingest_mde_package`` first.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.detect_anomalies_action(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Correlate EVTX Attack Chains")
    async def correlate_evtx(case_id: str) -> str:
        """Correlate parsed Windows Event Log data to detect multi-step attack chains:
        brute force→success, lateral movement, persistence, privilege escalation,
        account manipulation, Kerberos abuse, Pass-the-Hash.

        Requires ``parse_logs``, ``ingest_velociraptor``, or ``ingest_mde_package`` first.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.correlate_event_logs(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Triage IOCs", annotations={"readOnlyHint": True})
    async def triage_iocs(case_id: str, urls: list[str] | None = None,
                          severity: str = "medium") -> str:
        """Fast pre-pipeline IOC triage against the cross-case IOC index and enrichment cache.
        Returns known-malicious/suspicious hits and severity escalation recommendations.

        Much faster than ``enrich_iocs`` — use this first to decide whether full enrichment is needed.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from tools.triage import triage as _triage
        result = await asyncio.to_thread(
            lambda: _triage(case_id, urls=urls, severity=severity)
        )
        return _json(result)

    @mcp.tool(title="Score Verdicts", annotations={"readOnlyHint": True})
    async def score_ioc_verdicts(case_id: str) -> str:
        """Compute composite verdicts (malicious/suspicious/clean/unknown + confidence)
        for all enriched IOCs and update the cross-case IOC index.

        Requires ``enrich_iocs`` to have run first.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from tools.score_verdicts import score_verdicts, update_ioc_index

        def _run():
            result = score_verdicts(case_id)
            update_ioc_index(case_id)
            return result

        result = await asyncio.to_thread(_run)
        if isinstance(result, dict):
            result["_hint"] = (
                "Verdicts are signals, not conclusions. Consider what the "
                "sessions actually did before determining disposition. A "
                "malicious IP with benign activity may indicate VPN usage, "
                "not compromise. Verify session behaviour before closing."
            )
        return _json(result)

    @mcp.tool(title="Analyse File (Tiered)", annotations={"readOnlyHint": True})
    async def analyse_file(
        file_path: str,
        case_id: str,
        depth: str = "auto",
        run_yara: str = "auto",
    ) -> str:
        """Tiered static file analysis. Tier 1: magic, hash, entropy, strings, reputation.
        Tier 2 (auto/full): PE, Office macros, PDF JS, LNK, OneNote, MSI, Mach-O. Tier 3: YARA + sandbox suggestion.

        ``depth``: ``"fast"`` | ``"auto"`` | ``"full"``. ``run_yara``: ``"true"|"false"|"auto"``.
        File must be on the MCP server filesystem (use ``prepare_file_upload`` to ship it).
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from tools.file_analyse import file_analyse
        result = await asyncio.to_thread(
            lambda: file_analyse(file_path, case_id, depth=depth, run_yara=run_yara)
        )
        return _json(result)

    @mcp.tool(title="Prepare File Upload")
    async def prepare_file_upload(case_id: str, filename: str) -> str:
        """Mint a signed upload URL for shipping a file from another sandbox to the MCP server.
        Only needed after ``triage_file`` identifies a need for server-side tools (YARA, deep PE, sandbox).

        Token is (case_id, filename)-scoped with short TTL; capped at ``SOCAI_MCP_UPLOAD_MAX_BYTES``.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from mcp_server.uploads_http import (
            build_upload_url,
            expected_artefact_path,
            mint_upload_token,
            sanitise_filename,
        )
        from mcp_server.auth import _get_caller_email
        from mcp_server.config import (
            MCP_UPLOAD_MAX_BYTES,
            MCP_UPLOAD_TOKEN_TTL_SECONDS,
        )

        safe = sanitise_filename(filename)
        if safe is None:
            return _json({
                "status": "error",
                "error": "filename sanitised to empty — provide a name with "
                         "at least one [A-Za-z0-9] character",
            })

        token = mint_upload_token(
            case_id=case_id,
            filename=safe,
            caller_email=_get_caller_email(),
        )
        url = build_upload_url(case_id=case_id, filename=safe, token=token)
        path = expected_artefact_path(case_id=case_id, filename=safe)

        return _json({
            "status": "ok",
            "case_id": case_id,
            "filename": safe,
            "upload_url": url,
            "artefact_path": str(path),
            "max_bytes": MCP_UPLOAD_MAX_BYTES,
            "ttl_seconds": MCP_UPLOAD_TOKEN_TTL_SECONDS,
            "curl_example": (
                f'curl -X POST --data-binary @<local-file> "{url}"'
            ),
            "fallback": (
                "If the calling sandbox has no network path to the MCP "
                "server (e.g. host.docker.internal does not resolve), use "
                "upload_file_content instead — it ships bytes in-band over "
                "the MCP transport itself."
            ),
            "next_step": (
                f"After upload, call analyse_file(file_path='{path}', "
                f"case_id='{case_id}')."
            ),
        })

    @mcp.tool(title="Upload File Content (in-band)")
    async def upload_file_content(
        case_id: str,
        filename: str,
        content_b64: str,
    ) -> str:
        """Last-resort fallback: ship file bytes as base64 in-band (heavy context cost).
        Use only when ``triage_file`` requires server tools AND the sandbox cannot reach the HTTP endpoint.
        Cap: ``SOCAI_MCP_INBAND_UPLOAD_MAX_BYTES`` (default 2 MB). Returns ``path`` for ``analyse_file``.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from mcp_server.uploads_http import sanitise_filename, store_inband_upload
        from mcp_server.config import MCP_INBAND_UPLOAD_MAX_BYTES
        from mcp_server.logging_config import mcp_log

        safe = sanitise_filename(filename)
        if safe is None:
            return _json({
                "status": "error",
                "error": "filename sanitised to empty — provide a name with "
                         "at least one [A-Za-z0-9] character",
            })

        result = await asyncio.to_thread(
            store_inband_upload,
            case_id=case_id, filename=safe, content_b64=content_b64,
            max_bytes=MCP_INBAND_UPLOAD_MAX_BYTES,
        )
        if result.get("status") == "ok":
            mcp_log("upload_stored_inband",
                    case_id=case_id, filename=safe,
                    bytes=result["bytes"], sha256=result["sha256"])
        return _json(result)

    @mcp.tool(title="Sandbox API Lookup", annotations={"readOnlyHint": True, "openWorldHint": True})
    async def sandbox_api_lookup(case_id: str) -> str:
        """Query Hybrid Analysis, Any.Run, and Joe Sandbox for existing reports by SHA256.
        API lookup of prior detonations only — for live detonation use ``start_sandbox_session``.

        Requires ``analyse_file`` to have run first to produce SHA256 hashes.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from tools.sandbox_analyse import sandbox_analyse
        result = await asyncio.to_thread(lambda: sandbox_analyse(case_id))
        return _json(result)

    # -- Cyberint CTI (read-only) ------------------------------------------

    @mcp.tool(title="Query Cyberint Alerts", annotations={"readOnlyHint": True, "openWorldHint": True})
    async def query_cyberint_alerts(
        alert_ref_id: str = "",
        severity: str = "",
        status: str = "",
        category: str = "",
        environment: str = "",
        created_from: str = "",
        created_to: str = "",
        page: int = 1,
        size: int = 10,
    ) -> str:
        """Query Cyberint CTI alerts (brand impersonation, data leaks, phishing kits, credential exposure).

        Pass ``alert_ref_id`` for a single alert detail, or use filters (severity, status, category,
        environment, created_from/to, page, size) for a paginated list.
        """
        _require_scope("investigations:read")

        from tools.cyberint_read import _is_configured, get_alert, list_alerts

        if not _is_configured():
            raise ToolError(
                "Cyberint not configured. Set CYBERINT_API_KEY and "
                "CYBERINT_API_URL in .env."
            )

        # Single alert mode
        if alert_ref_id:
            result = await asyncio.to_thread(get_alert, alert_ref_id)
            if not result:
                raise ToolError(f"Alert {alert_ref_id} not found or not accessible.")
            return _json({"status": "ok", "mode": "detail", "alert": result})

        # Filtered list mode
        result = await asyncio.to_thread(
            lambda: list_alerts(
                page=page, size=size,
                severity=severity or None,
                status=status or None,
                category=category or None,
                environment=environment or None,
                created_from=created_from or None,
                created_to=created_to or None,
            )
        )
        if not result:
            raise ToolError("Cyberint alert query failed — check logs.")
        return _json({
            "status": "ok",
            "mode": "list",
            "total": result.get("total", 0),
            "page": page,
            "size": size,
            "alerts": result.get("alerts", []),
        })

    @mcp.tool(title="Cyberint Alert Artefact", annotations={"readOnlyHint": True, "openWorldHint": True})
    async def cyberint_alert_artefact(
        alert_ref_id: str,
        attachment_id: str = "",
        indicator_id: str = "",
        analysis_report: bool = False,
        risk_environment: str = "",
    ) -> str:
        """Retrieve a Cyberint alert artefact. Exactly one mode at a time:
        ``attachment_id`` → download URL; ``indicator_id`` → indicator detail;
        ``analysis_report=True`` → report URL; ``risk_environment`` → risk scores (no alert_ref_id needed).
        """
        _require_scope("investigations:read")

        from tools.cyberint_read import (
            _is_configured,
            get_alert_analysis_report,
            get_alert_attachment,
            get_alert_indicator,
            get_risk_scores,
        )

        if not _is_configured():
            raise ToolError(
                "Cyberint not configured. Set CYBERINT_API_KEY and "
                "CYBERINT_API_URL in .env."
            )

        # Risk scores mode (no alert_ref_id needed)
        if risk_environment:
            result = await asyncio.to_thread(get_risk_scores, risk_environment)
            if not result:
                raise ToolError(f"Risk scores for '{risk_environment}' not found.")
            return _json({"status": "ok", "mode": "risk_scores",
                          "environment": risk_environment, "scores": result})

        if not alert_ref_id:
            raise ToolError("alert_ref_id is required for attachment, indicator, and report modes.")

        if attachment_id:
            url = await asyncio.to_thread(
                get_alert_attachment, alert_ref_id, attachment_id)
            if not url:
                raise ToolError(f"Attachment {attachment_id} not found on alert {alert_ref_id}.")
            return _json({"status": "ok", "mode": "attachment",
                          "download_url": url})

        if indicator_id:
            result = await asyncio.to_thread(
                get_alert_indicator, alert_ref_id, indicator_id)
            if not result:
                raise ToolError(f"Indicator {indicator_id} not found on alert {alert_ref_id}.")
            return _json({"status": "ok", "mode": "indicator",
                          "indicator": result})

        if analysis_report:
            url = await asyncio.to_thread(
                get_alert_analysis_report, alert_ref_id)
            if not url:
                raise ToolError(f"Analysis report not found for alert {alert_ref_id}.")
            return _json({"status": "ok", "mode": "analysis_report",
                          "report_url": url})

        raise ToolError(
            "Specify exactly one of: attachment_id, indicator_id, "
            "analysis_report=True, or risk_environment."
        )

    @mcp.tool(title="Cyberint Metadata", annotations={"readOnlyHint": True, "openWorldHint": True})
    async def cyberint_metadata() -> str:
        """Use when the analyst asks "what categories does Cyberint have?",
        "show me Cyberint metadata", or needs to understand the available
        alert types, severities, statuses, or categories before querying.

        Returns the Cyberint alert catalog metadata — no parameters needed.
        """
        _require_scope("investigations:read")

        from tools.cyberint_read import _is_configured, get_alert_metadata

        if not _is_configured():
            raise ToolError(
                "Cyberint not configured. Set CYBERINT_API_KEY and "
                "CYBERINT_API_URL in .env."
            )

        result = await asyncio.to_thread(get_alert_metadata)
        if not result:
            raise ToolError("Failed to retrieve Cyberint metadata — check logs.")
        return _json({"status": "ok", "metadata": result})


# ---------------------------------------------------------------------------
# Tier 2b — Rumsfeld Investigation Pipeline (5 tools)
# ---------------------------------------------------------------------------

def _register_tier2_rumsfeld(mcp: FastMCP) -> None:

    @mcp.tool(title="Generate Investigation Matrix")
    async def generate_investigation_matrix(case_id: str) -> str:
        """Generate a structured investigation reasoning matrix for a case.

        **How to use:** Select the ``build_investigation_matrix`` prompt,
        produce the matrix (known_knowns, known_unknowns, hypotheses),
        then call ``add_finding`` with your conclusions
        to persist it.

        Returns guidance on how to generate the matrix.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        return _json({
            "status": "use_prompt",
            "case_id": case_id,
            "prompt": "build_investigation_matrix",
            "save_tool": "add_finding",
            "message": (
                f"Use the build_investigation_matrix prompt to generate the "
                f"matrix for {case_id}, then call add_finding with "
                f'analysis_type="investigation_matrix" to persist it.'
            ),
        })

    @mcp.tool(title="Review Report Quality")
    async def review_report_quality(case_id: str) -> str:
        """Run the analytical standards quality gate on a case report.

        Returns deterministic checks for: confirmed claims without evidence,
        causal language without data links, speculative language, and
        matrix coverage gaps.

        For a full LLM-assisted review, use the ``review_report`` prompt.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from tools.report_quality_gate import review_report
        result = await asyncio.to_thread(lambda: review_report(case_id))
        return _json(result or {"status": "no_report", "case_id": case_id})

    @mcp.tool(title="Run Determination Analysis")
    async def run_determination(case_id: str) -> str:
        """Run evidence-chain determination analysis.

        **How to use:** Select the ``run_determination`` prompt to get the
        instructions and case evidence, produce the disposition proposal,
        then call ``add_finding`` with your conclusion
        to persist it, or call ``add_finding`` with your conclusion.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        return _json({
            "status": "use_prompt",
            "case_id": case_id,
            "prompt": "run_determination",
            "save_tool": "add_finding",
            "message": (
                f"Use the run_determination prompt to analyse evidence for "
                f"{case_id}, then call add_finding with "
                f'analysis_type="determination" to persist the result.'
            ),
        })

    @mcp.tool(title="List Follow-up Proposals")
    async def list_followups(case_id: str) -> str:
        """List follow-up investigation proposals for a case.

        After the Rumsfeld pipeline runs, it generates proposals for
        closing evidence gaps. Use this to review them before approving.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from api.actions import list_followup_proposals as _list
        result = await asyncio.to_thread(lambda: _list(case_id))
        return _json(result)

    @mcp.tool(title="Execute Follow-up Proposal")
    async def execute_followup(case_id: str, proposal_id: str) -> str:
        """Execute an approved follow-up investigation proposal.
        Review proposals via ``list_followups`` before calling.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api.actions import execute_followup_proposal as _exec
        result = await asyncio.to_thread(lambda: _exec(case_id, proposal_id))
        return _json(result)


# ---------------------------------------------------------------------------
# Tier 3 — Advanced / Restricted (31 tools)
# ---------------------------------------------------------------------------

def _register_tier3(mcp: FastMCP) -> None:

    @mcp.tool(title="Run KQL Query")
    async def run_kql(
        query: str,
        workspace: str = "",
        max_rows: int = 50,
    ) -> str:
        """Execute a read-only KQL query against Azure Sentinel. Build the query yourself —
        do not ask the analyst to write KQL. ``| take`` row limit auto-appended (default 50, max 1000).

        Use ``lookup_client`` to resolve the workspace first. For guided multi-stage
        investigations use ``load_kql_playbook`` instead. See ``socai://sentinel-queries`` for table list.
        """
        _require_scope("sentinel:query")

        from tools.sentinel_queries import resolve_kql_workspace as _resolve_kql_workspace
        from scripts.run_kql import run_kql as _run_kql

        query = query.strip()
        if not query:
            return _json({"error": "No KQL query provided."})

        ws_id = _resolve_kql_workspace(workspace.strip())
        if not ws_id:
            return _json(_workspace_resolution_hint())

        # Enforce client boundary — resolve workspace back to owning client
        _check_workspace_boundary(ws_id)

        limit = max(1, min(int(max_rows), 1000))

        q = query.rstrip().rstrip(";")
        if "| take " not in q.lower() and "| limit " not in q.lower():
            q += f"\n| take {limit}"

        schema_warnings = _validate_kql_schema(q, ws_id)

        rows = await asyncio.to_thread(lambda: _run_kql(ws_id, q, timeout=60))
        if rows is None:
            err: dict = {
                "error": "Query execution failed.",
                "workspace": ws_id,
            }
            if schema_warnings:
                err["schema_warnings"] = schema_warnings
                err["hint"] = (
                    "Schema pre-check flagged unknown or unavailable tables — "
                    "likely cause of the failure. Check the workspace's "
                    "available tables via socai://sentinel-queries."
                )
            return _json(err)
        result = {
            "workspace": ws_id,
            "workspace_code": _resolve_workspace_code_from_id(ws_id) or None,
            "rows": rows[:limit],
            "row_count": len(rows),
            "truncated": len(rows) > limit,
        }
        if len(rows) > 500:
            result["_hint"] = (
                f"{len(rows)} rows returned — at this volume the context cost is "
                "significant. For pattern analysis prefer `| summarize Count=count() "
                "by Field` or `| summarize` with a time bucket; use raw rows only "
                "when inspecting specific events."
            )
        if schema_warnings:
            result["schema_warnings"] = schema_warnings
        return _json(result)

    @mcp.tool(title="Run Defender XDR Advanced Hunting Query")
    async def run_defender_kql(
        client: str,
        query: str,
        max_rows: int = 50,
    ) -> str:
        """Query Defender XDR Advanced Hunting (Device*, Email*, Identity*, CloudApp* tables)
        for a client. Covers high-volume device telemetry not streamed to Sentinel.

        Requires ``platforms.defender_xdr.api_enabled=true`` in client_entities.json.
        ``| take`` auto-appended; Defender caps at 10,000 rows / 30s.
        """
        _require_scope("defender_xdr:query")

        from tools.defender_hunting import (
            DefenderHuntingError,
            DefenderNotConfigured,
            run_defender_kql as _run_defender_kql,
        )

        query = query.strip()
        if not query:
            return _json({"error": "No KQL query provided."})
        if not client.strip():
            return _json({"error": "client is required."})

        limit = max(1, min(int(max_rows), 1000))
        q = query.rstrip().rstrip(";")
        if "| take " not in q.lower() and "| limit " not in q.lower():
            q += f"\n| take {limit}"

        try:
            result = await asyncio.to_thread(lambda: _run_defender_kql(client, q, timeout=30))
        except DefenderNotConfigured as exc:
            return _json({
                "error": "Defender XDR not configured for this client.",
                "detail": str(exc),
                "hint": "Set platforms.defender_xdr.api_enabled=true and tenant_id in client_entities.json, and ensure SOCAI_DEFENDER_APP_CLIENT_ID/SECRET are set.",
            })
        except DefenderHuntingError as exc:
            return _json({"error": "Defender XDR query failed.", "detail": str(exc)})

        rows = result["rows"]
        out: dict = {
            "rows": rows[:limit],
            "row_count": len(rows),
            "truncated": len(rows) > limit,
            "elapsed_ms": result["stats"]["elapsed_ms"],
        }
        if len(rows) > 500:
            out["_hint"] = (
                f"{len(rows)} rows returned — at this volume the context cost is "
                "significant. Prefer `| summarize Count=count() by Field` or "
                "time-bucketed summaries; use raw rows only when inspecting specific events."
            )
        return _json(out)

    @mcp.tool(title="Run CrowdStrike Falcon NG-SIEM Query")
    async def run_falcon_cql(
        client: str,
        cql: str,
        repo: str = "",
        max_rows: int = 50,
    ) -> str:
        """Execute a read-only CQL query against the client's Falcon NG-SIEM (LogScale) repository.

        Requires ``platforms.crowdstrike.api_enabled=true`` in client_entities.json.
        ``repo`` defaults to ``platforms.crowdstrike.ngsiem_repo``. Max 1000 rows.
        """
        _require_scope("crowdstrike:query")

        from tools.crowdstrike import (
            FalconError,
            FalconNotConfigured,
            run_falcon_cql as _run_falcon_cql,
        )

        cql = cql.strip()
        if not cql:
            return _json({"error": "No CQL query provided."})
        if not client.strip():
            return _json({"error": "client is required."})

        limit = max(1, min(int(max_rows), 1000))
        try:
            result = await asyncio.to_thread(
                lambda: _run_falcon_cql(client, cql, repo=(repo or None), timeout=30)
            )
        except FalconNotConfigured as exc:
            return _json({
                "error": "CrowdStrike not configured for this client.",
                "detail": str(exc),
                "hint": "Set platforms.crowdstrike.api_enabled=true + falcon_region + ngsiem_repo, and SOCAI_CROWDSTRIKE_<CLIENT>_CLIENT_ID/SECRET env vars.",
            })
        except FalconError as exc:
            return _json({"error": "CrowdStrike NG-SIEM query failed.", "detail": str(exc)})

        rows = result.get("rows") or []
        out: dict = {
            "rows": rows[:limit],
            "row_count": len(rows),
            "truncated": len(rows) > limit,
            "elapsed_ms": result["stats"]["elapsed_ms"],
        }
        if len(rows) > 500:
            out["_hint"] = (
                f"{len(rows)} rows returned — high context cost. Prefer "
                "`groupBy()` aggregations or time-bucketed summaries."
            )
        return _json(out)

    @mcp.tool(title="Encore EQL Entity Context", annotations={"readOnlyHint": True})
    async def eql_entity_context(
        case_id: str,
        user: str = "",
        host: str = "",
        ip: str = "",
        depth: str = "auto",
    ) -> str:
        """Pull recent identity / device / detection / exposure context for a user, host, or IP
        from Encore EQL — call during the baseline step when an alert names an entity.

        Case-scoped: the query is pinned to the Encore client mapped to this case's client
        (``platforms.encore.internal_client_id``); a caller cannot target another client.
        Results are written as a case artefact and summarised into the evidence chain.
        Coverage varies per client and SignInAudits is a rolling ~7-day window —
        an empty result means "not ingested for this client", NOT "clean".
        """
        _require_scope("investigations:read")
        from tools.eql import EqlError, EqlNotConfigured, entity_context as _entity_context

        if not case_id.strip():
            return _json({"error": "case_id is required."})
        if not (user.strip() or host.strip() or ip.strip()):
            return _json({"error": "Provide at least one of user, host, ip."})
        try:
            result = await asyncio.to_thread(
                lambda: _entity_context(case_id, user=user or None, host=host or None,
                                        ip=ip or None, depth=depth)
            )
        except EqlNotConfigured as exc:
            return _json({
                "error": "Encore EQL not enabled for this case's client.",
                "detail": str(exc),
                "hint": "Set platforms.encore.internal_client_id (+ access) in client_entities.json.",
            })
        except EqlError as exc:
            return _json({"error": "Encore EQL entity-context lookup failed.", "detail": str(exc)})
        return _json(result)

    @mcp.tool(title="Encore EQL Query", annotations={"readOnlyHint": True})
    async def eql_query(case_id: str, eql: str) -> str:
        """Run a raw read-only EQL query, pinned to this case's Encore client (escape hatch).

        EQL is NOT SQL/Elasticsearch: ``<Table> WHERE <col> = "v" SELECT <c1>, <c2>`` —
        no pipes, FROM, LIMIT, or single quotes. Prefer ``eql_entity_context`` for the
        common identity/host lookups. Same scope gate: the query cannot leave the case's client.
        """
        _require_scope("investigations:read")
        from tools.eql import EqlError, EqlNotConfigured, run_eql_for_case as _run_eql_for_case

        if not case_id.strip():
            return _json({"error": "case_id is required."})
        if not eql.strip():
            return _json({"error": "eql query is required."})
        try:
            result = await asyncio.to_thread(lambda: _run_eql_for_case(case_id, eql.strip()))
        except EqlNotConfigured as exc:
            return _json({
                "error": "Encore EQL not enabled for this case's client.",
                "detail": str(exc),
                "hint": "Set platforms.encore.internal_client_id (+ access) in client_entities.json.",
            })
        except EqlError as exc:
            return _json({"error": "Encore EQL query failed.", "detail": str(exc)})
        return _json(result)

    @mcp.tool(title="Encore EQL Posture Baseline", annotations={"readOnlyHint": True})
    async def eql_posture_context(case_id: str, depth: str = "auto") -> str:
        """Pull the client's preventative-control / best-practice configuration baseline from Encore EQL.

        Client-wide (NOT entity-scoped) — the input for a security architecture review.
        Runs a curated set covering Secure Score, identity/MFA coverage, privileged-role
        assignments, app-credential hygiene, device/encryption compliance, Defender config
        recommendations, vulnerability exposure, and security-awareness training. Pair with
        ``eql_entity_context`` for the specific user/host/IP named in the incident.

        Case-scoped: pinned to this case's Encore client (``platforms.encore.internal_client_id``);
        results are written as a case artefact and summarised into the evidence chain. Snapshot
        tables are ordered newest-first; an empty result means "not ingested for this client",
        NOT "compliant".
        """
        _require_scope("investigations:read")
        from tools.eql import EqlError, EqlNotConfigured, posture_context as _posture_context

        if not case_id.strip():
            return _json({"error": "case_id is required."})
        try:
            result = await asyncio.to_thread(lambda: _posture_context(case_id, depth=depth))
        except EqlNotConfigured as exc:
            return _json({
                "error": "Encore EQL not enabled for this case's client.",
                "detail": str(exc),
                "hint": "Set platforms.encore.internal_client_id (+ access) in client_entities.json.",
            })
        except EqlError as exc:
            return _json({"error": "Encore EQL posture lookup failed.", "detail": str(exc)})
        return _json(result)

    @mcp.tool(title="Query CrowdStrike Falcon Detections")
    async def query_falcon_detections(client: str, filter_fql: str = "", limit: int = 50) -> str:
        """Use when the analyst asks for Falcon detections / alerts.

        Returns detection summary objects from CrowdStrike Falcon. ``filter_fql``
        is a Falcon FQL filter, e.g. ``status:'new'+max_severity_displayname:'High'``.
        """
        _require_scope("crowdstrike:query")
        from tools.crowdstrike import FalconError, FalconNotConfigured, query_detections
        try:
            result = await asyncio.to_thread(
                lambda: query_detections(client, filter_=(filter_fql or None), limit=limit)
            )
        except FalconNotConfigured as exc:
            return _json({"error": "CrowdStrike not configured.", "detail": str(exc)})
        except FalconError as exc:
            return _json({"error": "Falcon API call failed.", "detail": str(exc)})
        return _json(result)

    @mcp.tool(title="Query CrowdStrike Falcon Hosts")
    async def query_falcon_hosts(client: str, filter_fql: str = "", limit: int = 50) -> str:
        """Use when the analyst asks for a host's Falcon details. Returns host
        inventory records. ``filter_fql`` FQL, e.g. ``hostname:'host-1'``."""
        _require_scope("crowdstrike:query")
        from tools.crowdstrike import FalconError, FalconNotConfigured, query_hosts
        try:
            result = await asyncio.to_thread(
                lambda: query_hosts(client, filter_=(filter_fql or None), limit=limit)
            )
        except FalconNotConfigured as exc:
            return _json({"error": "CrowdStrike not configured.", "detail": str(exc)})
        except FalconError as exc:
            return _json({"error": "Falcon API call failed.", "detail": str(exc)})
        return _json(result)

    @mcp.tool(title="Query CrowdStrike Falcon Incidents")
    async def query_falcon_incidents(client: str, filter_fql: str = "", limit: int = 50) -> str:
        """Use when the analyst asks for Falcon incidents. Returns incident
        records. ``filter_fql`` FQL, e.g. ``status:20``."""
        _require_scope("crowdstrike:query")
        from tools.crowdstrike import FalconError, FalconNotConfigured, query_incidents
        try:
            result = await asyncio.to_thread(
                lambda: query_incidents(client, filter_=(filter_fql or None), limit=limit)
            )
        except FalconNotConfigured as exc:
            return _json({"error": "CrowdStrike not configured.", "detail": str(exc)})
        except FalconError as exc:
            return _json({"error": "Falcon API call failed.", "detail": str(exc)})
        return _json(result)

    @mcp.tool(title="Load KQL Playbook", annotations={"readOnlyHint": True})
    def load_kql_playbook(
        playbook_id: str | None = None,
        stage: int | None = None,
        params: dict | None = None,
    ) -> str:
        """Load a parameterised KQL investigation playbook for Sentinel.

        No args → list available playbooks. With ``playbook_id`` → show stages and parameters.
        With ``playbook_id`` + ``stage`` + ``params`` → render ready-to-run KQL for ``run_kql``.
        """
        _require_scope("sentinel:query")

        from tools.playbooks import (
            list_playbooks_unified,
            load_playbook_for_platform,
            render_stage_for_platform,
        )

        if not playbook_id:
            return _json({"playbooks": list_playbooks_unified()})

        pb = load_playbook_for_platform(playbook_id, "sentinel")
        if "error" in pb:
            return _json(pb)

        if stage is None:
            return _json(pb)

        rendered = render_stage_for_platform(playbook_id, stage, params or {}, "sentinel")
        if isinstance(rendered, dict):
            return _json(rendered)
        result = {"query": rendered, "language": "kql"}
        try:
            from tools.kql_playbooks import validate_playbook_tables
            from config.sentinel_schema import has_registry
            if has_registry() and pb.get("tables"):
                validation = validate_playbook_tables(pb)
                if validation.get("warnings"):
                    result["schema_warnings"] = validation["warnings"]
        except Exception:
            pass
        return _json(result)

    @mcp.tool(title="Load CQL Playbook", annotations={"readOnlyHint": True})
    def load_cql_playbook(
        playbook_id: str | None = None,
        stage: int | None = None,
        sub_query: int | None = None,
        params: dict | None = None,
    ) -> str:
        """Load a parameterised CQL investigation playbook for CrowdStrike LogScale/NGSIEM.

        No args → list available playbooks. With ``playbook_id`` → stages/params.
        With ``playbook_id`` + ``stage`` + ``params`` → rendered CQL. ``sub_query`` (0-based) for single sub-query.
        """
        _require_scope("investigations:read")

        from tools.playbooks import (
            list_playbooks_unified,
            load_playbook_for_platform,
            render_stage_for_platform,
        )

        if not playbook_id:
            return _json({"playbooks": list_playbooks_unified()})

        pb = load_playbook_for_platform(playbook_id, "logscale")
        if "error" in pb:
            # Legacy CQL playbooks (config/cql_playbooks/<id>.cql) may still
            # exist outside the unified loader; fall back when available.
            try:
                from tools.cql_playbooks import (
                    load_playbook as _legacy_load,
                    render_stage as _legacy_render,
                    render_sub_query as _legacy_render_sub,
                )
                legacy_pb = _legacy_load(playbook_id)
                if legacy_pb:
                    if stage is None:
                        return _json(legacy_pb)
                    if sub_query is not None:
                        rendered = _legacy_render_sub(legacy_pb, stage, sub_query, params or {})
                    else:
                        rendered = _legacy_render(legacy_pb, stage, params or {})
                    if rendered:
                        return _json({"query": rendered, "language": "cql"})
            except Exception:
                pass
            return _json(pb)

        if stage is None:
            return _json(pb)

        rendered = render_stage_for_platform(playbook_id, stage, params or {}, "logscale")
        if isinstance(rendered, dict):
            return _json(rendered)
        return _json({"query": rendered, "language": "cql"})

    @mcp.tool(title="Generate Sentinel Composite Query", annotations={"readOnlyHint": True})
    def generate_sentinel_query(
        scenario: str = "",
        upn: str = "",
        ip: str = "",
        object_id: str = "",
        mailbox_id: str = "",
        additional_upns: str = "",
        lookback_hours: int = 24,
    ) -> str:
        """Render a composite Sentinel KQL query (multiple ``let`` blocks unioned) for a full scenario.
        Empty ``scenario`` lists available options. ``upn`` required for all scenarios.
        Sentinel-native tables only (OfficeActivity, SigninLogs, SecurityAlert). Pass result to ``run_kql``.
        """
        _require_scope("sentinel:query")

        from tools.sentinel_queries import list_scenarios, render_query

        if not scenario or not scenario.strip():
            return _json({"scenarios": list_scenarios()})

        if not upn or not upn.strip():
            return _json({"error": "upn is required for all scenarios."})

        result = render_query(
            scenario.strip().lower(),
            upn=upn.strip(),
            ip=ip.strip(),
            object_id=object_id.strip(),
            mailbox_id=mailbox_id.strip(),
            additional_upns=additional_upns.strip(),
            lookback_hours=max(1, min(int(lookback_hours), 720)),
        )
        return _json(result)

    @mcp.tool(title="Run KQL Batch", annotations={"openWorldHint": True})
    async def run_kql_batch(
        queries: list[str],
        workspace: str = "",
        case_id: str = "",
        max_rows: int = 1000,
    ) -> str:
        """Execute multiple KQL queries concurrently against a Sentinel workspace.
        Returns all results in roughly the time of the slowest single query.

        Typical use: call ``generate_sentinel_query`` for each scenario, collect the queries,
        then pass them all here. ``workspace`` auto-resolved from case client if omitted.
        """
        _require_scope("sentinel:query")
        if case_id:
            _check_client_boundary(case_id)

        from tools.sentinel_queries import resolve_kql_workspace

        ws_id = resolve_kql_workspace(workspace, case_id=case_id or None)
        if not ws_id:
            return _json(_workspace_resolution_hint(case_id=case_id))

        if case_id:
            _check_workspace_boundary(ws_id)

        if not queries:
            return _json({"error": "No queries provided."})

        from concurrent.futures import ThreadPoolExecutor, as_completed

        limit = max(1, min(int(max_rows), 1000))

        def _run_one(query: str) -> dict:
            try:
                from scripts.run_kql import run_kql
                q = query.rstrip().rstrip(";")
                if "| take " not in q.lower() and "| limit " not in q.lower():
                    q += f"\n| take {limit}"
                warnings = _validate_kql_schema(q, ws_id)
                rows = run_kql(ws_id, q)
                r: dict = {"query": query[:200], "row_count": len(rows), "rows": rows}
                if warnings:
                    r["schema_warnings"] = warnings
                return r
            except Exception as exc:
                return {"query": query[:200], "error": str(exc), "row_count": 0, "rows": []}

        results = []
        max_workers = min(8, len(queries))
        loop = asyncio.get_running_loop()

        def _batch():
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futs = {executor.submit(_run_one, q): i for i, q in enumerate(queries)}
                ordered = [None] * len(queries)
                for fut in as_completed(futs):
                    idx = futs[fut]
                    ordered[idx] = fut.result()
                return ordered

        results = await loop.run_in_executor(None, _batch)
        total_rows = sum(r["row_count"] for r in results if r)
        return _json({
            "workspace": ws_id,
            "workspace_code": _resolve_workspace_code_from_id(ws_id) or None,
            "query_count": len(queries),
            "total_rows": total_rows,
            "results": results,
        })

    @mcp.tool(title="Security Architecture Review")
    async def security_arch_review(case_id: str) -> str:
        """Prepare a security architecture review. Use the ``write_security_arch_review`` prompt
        to write it, then call ``save_report(report_type="security_arch_review")`` to persist it.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        return _json({
            "status": "use_prompt",
            "case_id": case_id,
            "prompt": "write_security_arch_review",
            "save_tool": "save_report",
            "save_args": {"report_type": "security_arch_review"},
            "message": (
                f"Use the write_security_arch_review prompt to generate the "
                f"review for {case_id}, then call save_report with "
                f'report_type="security_arch_review" to persist it.'
            ),
        })

    @mcp.tool(title="Contextualise CVEs", annotations={"readOnlyHint": True})
    async def contextualise_cves(case_id: str) -> str:
        """Look up case CVEs against NVD (severity/vector), EPSS (exploitation probability),
        and CISA KEV (known exploited). For general vulnerability research use ``web_search``.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.contextualise_cves(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Ingest Velociraptor Collection")
    async def ingest_velociraptor(case_id: str, run_analysis: bool = True) -> str:
        """Ingest and normalise a Velociraptor offline collector (ZIP, VQL JSON, or result dir).
        Parses EVTX, autoruns, netstat, processes, services, prefetch, shimcache, MFT, USN.

        ``run_analysis=True`` (default) auto-extracts IOCs, enriches, and correlates after ingest.
        For MDE packages use ``ingest_mde_package`` instead.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.ingest_velociraptor(case_id, run_analysis=run_analysis)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Ingest MDE Investigation Package")
    async def ingest_mde_package(case_id: str, run_analysis: bool = True) -> str:
        """Ingest and normalise an MDE investigation package ZIP using 13 specialised normalisers.
        Alternative to ``ingest_velociraptor`` for MDE endpoint data.
        ``run_analysis=True`` (default) auto-extracts IOCs, enriches, and correlates after ingest.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.ingest_mde_package(case_id, run_analysis=run_analysis)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Generate Weekly Report", annotations={"readOnlyHint": True})
    async def generate_weekly(
        year: int | None = None,
        week: int | None = None,
        include_open: bool = False,
    ) -> str:
        """Generate a weekly SOC report for an ISO week (case count, severity, disposition,
        attack type distribution). Defaults to the current week.

        Pass ``year`` and ``week`` for historical reports; ``include_open=True`` to include open cases.
        """
        _require_scope("investigations:read")

        from tools.generate_weekly_report import generate_weekly_report
        result = await asyncio.to_thread(
            lambda: generate_weekly_report(year=year, week=week, include_open=include_open)
        )
        return _json(result)

    @mcp.tool(title="Save Report")
    async def save_report(
        case_id: str,
        report_type: str,
        report_text: str,
        disposition: str | None = None,
    ) -> str:
        """Persist a locally-generated **markdown** report with defanging, audit, and auto-close.
        Call after the matching ``write_*`` prompt. ``report_type``: ``mdr_report`` | ``pup_report`` |
        ``closure_comment`` | ``fp_tuning_ticket`` | ``executive_summary`` | ``security_arch_review``.
        For ``closure_comment`` (BP/FP/Undetermined) pass ``disposition`` explicitly
        (``benign_positive`` / ``false_positive`` / ``inconclusive``). ``report_text`` must be
        markdown. On success, render ``report_md`` as a markdown artifact so Claude Desktop opens
        it in the visualiser (Artifacts side panel) for analyst review.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.save_report import save_report_to_case
        result = await asyncio.to_thread(
            lambda: save_report_to_case(
                case_id=case_id,
                report_type=report_type,
                report_text=report_text,
                disposition=disposition,
            )
        )

        # Reload the persisted file and return its contents so the analyst
        # sees the (defanged, header-prefixed) report rendered in the Desktop
        # visualiser as a markdown artifact. The .md file on disk is the
        # copy-paste source for the customer deliverable.
        if isinstance(result, dict) and result.get("status") == "ok":
            try:
                from pathlib import Path as _Path
                rp = _Path(result.get("report_path", ""))
                if rp.is_file():
                    result["report_md"] = rp.read_text(encoding="utf-8")
                    result["display_hint"] = (
                        "Render `report_md` as a markdown artifact so Claude "
                        "Desktop opens it in the visualiser (Artifacts side "
                        "panel). Do not paste the raw markdown into the chat body."
                    )
            except Exception as exc:
                from tools.common import log_error
                import traceback as _tb
                log_error(case_id, "save_report.read_back", str(exc),
                          severity="warning", traceback=_tb.format_exc(),
                          context={"report_type": report_type})

        return _json(result)

    @mcp.tool(title="Link Related Cases")
    def link_cases(
        case_a: str,
        case_b: str,
        link_type: str = "related",
        canonical: str | None = None,
        reason: str = "",
    ) -> str:
        """Create a bidirectional link between two cases (related, duplicate, parent-child).

        Use for non-destructive case association. For moving artefacts into one case use ``merge_cases``.
        ``canonical`` sets the primary case ID; ``reason`` is saved to metadata.
        """
        _require_scope("investigations:submit")

        from tools.case_links import link_cases as _link
        return _json(_link(case_a, case_b, link_type, canonical=canonical, reason=reason))

    @mcp.tool(title="Merge Duplicate Cases", annotations={"destructiveHint": True})
    def merge_cases(source_ids: list[str], target_id: str) -> str:
        """Destructive: move all artefacts and IOCs from source cases into the target case.
        Source cases are marked as merged. Cannot be easily undone.

        For non-destructive association use ``link_cases`` instead.
        """
        _require_scope("admin")

        from tools.case_links import merge_cases as _merge
        return _json(_merge(source_ids, target_id))

    @mcp.tool(title="Recommend Response Actions")
    async def response_actions(case_id: str) -> str:
        """Generate an advisory response action plan (containment, remediation, permitted actions,
        escalation contacts) based on case findings and client playbook. Advisory only — does not execute.

        Best called after enrichment and correlation are complete.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.response_actions import generate_response_actions
        result = await asyncio.to_thread(lambda: generate_response_actions(case_id))
        return _json(result)

    @mcp.tool(title="Prepare Closure Comment")
    async def prepare_closure_comment(
        classification: str,
        alert_data: str = "",
        case_id: str = "",
        platform: str | None = None,
        query_text: str | None = None,
    ) -> str:
        """Prepare a two-sentence incident closure comment for any non-TP disposition.

        ``classification``: one of ``bp_suspicious_but_expected``,
        ``bp_suspicious_not_malicious``, ``fp_incorrect_logic``,
        ``fp_inaccurate_data``, ``undetermined`` (Sentinel-aligned).
        Use the ``write_closure_comment`` prompt to write the comment, then call
        ``save_report(report_type="closure_comment", disposition=<...>)`` to persist it.

        ``case_id`` optional — auto-created if empty. ``alert_data`` stored as evidence.
        """
        _require_scope("investigations:submit")

        from tools.closure_comment import CLASSIFICATIONS
        if classification not in CLASSIFICATIONS:
            return _json({
                "status": "error",
                "reason": f"Unknown classification {classification!r}.",
                "valid_classifications": list(CLASSIFICATIONS),
            })

        cfg = CLASSIFICATIONS[classification]
        case_id = _ensure_case(case_id, disposition=cfg["disposition"])
        _check_client_boundary(case_id)

        # Store alert as evidence so the prompt can access it
        if alert_data:
            try:
                from api import actions
                actions.add_evidence(case_id, alert_data)
            except Exception:
                pass  # best-effort

        return _json({
            "status": "use_prompt",
            "case_id": case_id,
            "classification": classification,
            "label": cfg["label"],
            "disposition": cfg["disposition"],
            "prompt": "write_closure_comment",
            "save_tool": "save_report",
            "save_args": {
                "report_type": "closure_comment",
                "disposition": cfg["disposition"],
            },
            "message": (
                f"Case {case_id} is ready ({cfg['label']}). Use the "
                f"write_closure_comment prompt with classification="
                f'"{classification}" to generate the closure comment, then '
                f'call save_report with report_type="closure_comment" and '
                f'disposition="{cfg["disposition"]}" to persist it.'
            ),
        })

    @mcp.tool(title="Prepare SIEM Tuning Ticket")
    async def prepare_fp_tuning_ticket(
        alert_data: str,
        case_id: str = "",
        platform: str | None = None,
        query_text: str | None = None,
    ) -> str:
        """Prepare a SIEM tuning ticket. Use the ``write_fp_tuning`` prompt to write the
        tuning ticket, then call ``save_report(report_type="fp_tuning_ticket")`` to persist it.

        ``case_id`` optional — auto-created if empty. ``alert_data`` stored as evidence for the prompt.
        """
        _require_scope("investigations:submit")

        case_id = _ensure_case(case_id)
        _check_client_boundary(case_id)

        # Store alert as evidence so the prompt can access it
        try:
            from api import actions
            actions.add_evidence(case_id, alert_data)
        except Exception:
            pass  # best-effort

        return _json({
            "status": "use_prompt",
            "case_id": case_id,
            "prompt": "write_fp_tuning",
            "save_tool": "save_report",
            "save_args": {"report_type": "fp_tuning_ticket"},
            "message": (
                f"Case {case_id} is ready with alert evidence. Use the "
                f"write_fp_tuning prompt to generate the tuning ticket, then "
                f'call save_report with report_type="fp_tuning_ticket" to persist it.'
            ),
        })

    @mcp.tool(title="Start Sandbox Detonation", annotations={"destructiveHint": True})
    async def start_sandbox_session(
        sample_path: str,
        case_id: str,
        timeout: int = 120,
        network_mode: str = "monitor",
        interactive: bool = False,
    ) -> str:
        """Detonate a sample in an isolated Docker container (strace + tcpdump + honeypot C2 trap).
        Supports ELF, scripts, PE via Wine. Destructive — executes real malware.

        Use ``network_mode="isolate"`` to block outbound access. Set ``interactive=True`` for a shell.
        Call ``stop_sandbox_session`` when done to collect strace logs, pcap, and filesystem diff.
        """
        _require_scope("admin")
        _check_client_boundary(case_id)

        from tools.sandbox_session import start_session
        result = await asyncio.to_thread(
            lambda: start_session(
                sample_path, case_id,
                timeout=timeout,
                network_mode=network_mode,
                interactive=interactive,
            )
        )
        return _json(result)

    @mcp.tool(title="Stop Sandbox Session", annotations={"destructiveHint": True})
    def stop_sandbox_session(session_id: str) -> str:
        """Use to stop a running sandbox detonation and collect the analysis artefacts
        (strace logs, pcap, filesystem diff). Call this after ``start_sandbox_session``
        when the detonation has run long enough or the timeout has elapsed.

        Parameters
        ----------
        session_id : str
            Sandbox session ID.
        """
        _require_scope("admin")

        from tools.sandbox_session import stop_session
        return _json(stop_session(session_id))

    @mcp.tool(title="List Sandbox Sessions", annotations={"readOnlyHint": True})
    def list_sandbox_sessions() -> str:
        """Use to check on running sandbox detonations or review recent sessions.
        Returns all active and recently completed sandbox sessions with their
        status, sample details, and case associations."""
        _require_scope("admin")

        from tools.sandbox_session import list_sessions
        return _json({"sessions": list_sessions()})

    @mcp.tool(title="Start Disposable Browser Session", annotations={"destructiveHint": True})
    async def start_browser_session(url: str, case_id: str = "") -> str:
        """Start a disposable Docker Chrome session with passive tcpdump capture and a noVNC URL
        for manual browser interaction. Use when ``capture_urls`` fails due to Cloudflare/CAPTCHA.

        Artefacts stored caseless unless ``case_id`` provided. Call ``stop_browser_session`` when done.
        """
        _require_scope("admin")
        if case_id:
            _check_client_boundary(case_id)

        from tools.browser_session import start_session
        result = await asyncio.to_thread(lambda: start_session(url, case_id))
        return _json(result)

    @mcp.tool(title="Stop Browser Session", annotations={"destructiveHint": True})
    def stop_browser_session(session_id: str) -> str:
        """Use to stop a running disposable browser session and collect network
        artefacts (pcap, parsed DNS/TCP/HTTP/TLS, entities). Call this after
        the analyst has finished interacting with the page via noVNC.

        Parameters
        ----------
        session_id : str
            Browser session ID.
        """
        _require_scope("admin")

        from tools.browser_session import stop_session
        return _json(stop_session(session_id))

    @mcp.tool(title="List Browser Sessions", annotations={"readOnlyHint": True})
    def list_browser_sessions() -> str:
        """Use to check on running disposable browser sessions or review recent
        ones. Returns all active and recently completed browser sessions with
        their status, URL, and case associations."""
        _require_scope("admin")

        from tools.browser_session import list_sessions
        return _json({"sessions": list_sessions()})

    @mcp.tool(title="Read Browser Session File", annotations={"readOnlyHint": True})
    def read_browser_session_file(session_id: str, file_path: str) -> str:
        """Read an artefact file from a caseless browser session. For sessions attached to a case
        use ``read_case_file`` instead. Image files render inline in chat.

        Common paths: ``artefacts/session_manifest.json``, ``artefacts/network_log.json``,
        ``artefacts/screenshot_final.png``.
        """
        _require_scope("admin")

        import re as _re
        if not _re.match(r"^[a-f0-9]{8,40}$", session_id):
            return _json({"error": "Invalid session_id."})

        from tools.browser_session import SESSIONS_DIR
        session_dir = SESSIONS_DIR / session_id
        if not session_dir.is_dir():
            return _json({"error": f"Session not found: {session_id}"})

        clean = Path(file_path).as_posix()
        if ".." in clean or clean.startswith("/"):
            return _json({"error": "Directory traversal not allowed."})

        full_path = session_dir / clean
        try:
            full_path.resolve().relative_to(session_dir.resolve())
        except ValueError:
            return _json({"error": "Directory traversal not allowed."})
        if not full_path.exists():
            return _json({"error": f"File not found: {file_path}"})

        _IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
        if full_path.suffix.lower() in _IMAGE_SUFFIXES:
            from mcp.server.fastmcp.utilities.types import Image
            max_image_bytes = 10 * 1024 * 1024
            if full_path.stat().st_size > max_image_bytes:
                return _json({"error": f"Image too large ({full_path.stat().st_size} bytes). Max 10 MB."})
            return Image(path=full_path)

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            if len(content) > 50000:
                content = content[:50000] + "\n\n... [truncated]"
            return content
        except Exception as exc:
            return _json({"error": f"Error reading {file_path}: {exc}"})

    @mcp.tool(title="List Browser Session Files", annotations={"readOnlyHint": True})
    def list_browser_session_files(session_id: str) -> str:
        """Use to discover what artefact files exist in a browser session
        directory.  Returns file paths and sizes.  Use the returned paths
        with ``read_browser_session_file`` to read individual files.

        Parameters
        ----------
        session_id : str
            Browser session identifier.
        """
        _require_scope("admin")

        import re as _re
        if not _re.match(r"^[a-f0-9]{8,40}$", session_id):
            return _json({"error": "Invalid session_id."})

        from tools.browser_session import SESSIONS_DIR
        session_dir = SESSIONS_DIR / session_id
        if not session_dir.is_dir():
            return _json({"error": f"Session not found: {session_id}"})

        files = []
        for p in sorted(session_dir.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(session_dir).as_posix()
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            files.append({"path": rel, "size": size})

        return _json({
            "session_id": session_id,
            "file_count": len(files),
            "files": files,
        })

    @mcp.tool(title="Import Browser Session")
    def import_browser_session(session_id: str, case_id: str) -> str:
        """Copy all artefacts from a caseless browser session into a case directory.
        Only works for sessions started without a ``case_id``; already-attached sessions are rejected.
        """
        _require_scope("admin")
        _check_client_boundary(case_id)

        from tools.browser_session import import_session
        return _json(import_session(session_id, case_id))

    @mcp.tool(title="YARA Scan")
    async def yara_scan(case_id: str, generate_rules: bool = False) -> str:
        """Scan case artefacts against YARA rules: built-in (PE, PowerShell, C2, RAT),
        custom rules from ``config/yara_rules/``, and optionally LLM-generated rules.

        Requires ``yara-python``. Set ``generate_rules=True`` to create custom rules from PE analysis.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.yara_scan_action(case_id, generate_rules=generate_rules)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Generate Memory Dump Guidance")
    async def memory_dump_guide(
        case_id: str,
        process_name: str = "",
        pid: str = "",
        alert_title: str = "",
        hostname: str = "",
    ) -> str:
        """Generate step-by-step instructions for collecting a process memory dump via
        MDE Live Response (ProcDump, built-in memdump, or investigation package).
        After collecting the dump, call ``analyse_memory_dump`` to process it.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.memory_dump_guide(
                case_id,
                process_name=process_name,
                pid=pid,
                alert_title=alert_title,
                hostname=hostname,
            )
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Analyse Memory Dump")
    async def analyse_memory_dump(case_id: str, run_analysis: bool = True) -> str:
        """Analyse process memory dump files (.dmp, .dump, .raw, .bin) from case uploads:
        string extraction, IOC extraction, DLL analysis, injection/shellcode pattern detection,
        embedded PE detection, and risk scoring.

        Upload .dmp files to ``uploads/`` first. ``run_analysis=True`` auto-enriches IOCs after.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.analyse_memory_dump_action(case_id, run_analysis=run_analysis)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Analyse Memory Dump (Volatility3)")
    async def analyse_memory_volatility(
        case_id: str,
        full: bool = False,
        per_plugin_timeout_seconds: int = 600,
    ) -> str:
        """Volatility3 deep memory-dump analysis: pslist, psscan, netscan,
        cmdline, malfind, svcscan. Auto-detects Windows/Linux/macOS.

        Run after ``analyse_memory_dump`` when string findings warrant deep
        process / network / injection inspection. Set ``full=True`` to also
        run DllList / Modules (much slower). Requires Volatility3 on PATH.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.analyse_memory_volatility_action(
                case_id, full=full,
                per_plugin_timeout_seconds=per_plugin_timeout_seconds,
            )
        )
        return _json(_pop_message(result))

    # Format-specific specialist analysers (analyse_pe / office / pdf / lnk /
    # onenote / macho / disk_image / msi) are no longer registered as
    # individual MCP tools. They remain importable Python entry points used
    # by the unified ``analyse_file`` dispatcher (see tools/file_analyse.py),
    # which auto-routes by magic-byte detection and tiers the work by signal.


# ---------------------------------------------------------------------------
# Intelligence tier — semantic memory, baselines, GeoIP
# ---------------------------------------------------------------------------

def _register_intelligence(mcp: FastMCP) -> None:

    @mcp.tool(title="Semantic Case Recall", annotations={"readOnlyHint": True})
    async def recall_semantic(
        query: Annotated[str, "Natural-language description of what you're looking for "
                              "(e.g. 'DocuSign phishing credential harvest' or "
                              "'account takeover Egypt sign-in')."],
        top_k: Annotated[int, "Maximum results to return (default 5)."] = 5,
        client_filter: Annotated[str, "Restrict results to a specific client (optional)."] = "",
    ) -> str:
        """Use when you want to find prior cases similar to the current investigation
        by *meaning* rather than exact IOC match.

        Unlike ``recall_cases`` (exact IOC/keyword lookup), this tool uses BM25
        ranked text search over case titles, tags, IOCs, report excerpts, and
        analyst notes — so it surfaces cases with similar *context* even when no
        single IOC overlaps.

        Best for:
        - "Have we seen DocuSign phishing before?"
        - "Any prior account compromises from unfamiliar countries?"
        - "Similar malware dropper via macro?"

        Call ``recall_cases`` first for exact IOC matches, then call this for
        broader thematic context.

        Parameters
        ----------
        query : str
            Natural-language description of the investigation type.
        top_k : int
            Max results (default 5).
        client_filter : str
            Optional client name to scope results.
        """
        _require_scope("investigations:read")

        result = await asyncio.to_thread(
            lambda: __import__("tools.case_memory", fromlist=["search_case_memory"])
                        .search_case_memory(query, top_k=top_k, client_filter=client_filter)
        )
        return _json(result)

    @mcp.tool(title="Rebuild Case Memory Index")
    async def rebuild_case_memory() -> str:
        """Use to manually refresh the semantic case memory index.

        The index is rebuilt automatically every 6 hours by the background
        scheduler. Call this if you've just closed several cases and want
        them immediately searchable via ``recall_semantic``.

        Returns the number of cases indexed and the file path.
        """
        _require_scope("investigations:read")

        result = await asyncio.to_thread(
            lambda: __import__("tools.case_memory", fromlist=["build_case_memory_index"])
                        .build_case_memory_index()
        )
        return _json(result)

    @mcp.tool(title="Get Client Baseline", annotations={"readOnlyHint": True})
    async def get_client_baseline(
        client_name: Annotated[str, "Client name to retrieve baseline for."],
    ) -> str:
        """Return the behavioural baseline for a client: IOC recurrence, attack type distribution,
        severity breakdown, known-clean IOCs, and confirmed malicious IOCs from prior cases.

        Built from case history; rebuilt every 24h by the scheduler or on demand via ``rebuild_client_baseline``.
        """
        _require_scope("investigations:read")

        result = await asyncio.to_thread(
            lambda: __import__("tools.client_baseline", fromlist=["get_client_baseline"])
                        .get_client_baseline(client_name)
        )
        return _json(result)

    @mcp.tool(title="Rebuild Client Baseline")
    async def rebuild_client_baseline(
        client_name: Annotated[str, "Client name to rebuild baseline for."],
    ) -> str:
        """Force-rebuild the behavioural baseline for a client from all historical cases.
        Auto-rebuilt every 24h by the scheduler — call this after closing a significant batch of new cases.
        """
        _require_scope("investigations:submit")

        result = await asyncio.to_thread(
            lambda: __import__("tools.client_baseline", fromlist=["build_client_baseline"])
                        .build_client_baseline(client_name)
        )
        return _json(result)

    @mcp.tool(title="GeoIP Lookup", annotations={"readOnlyHint": True})
    async def geoip_lookup(
        ip: Annotated[str, "IPv4 or IPv6 address to geolocate."],
    ) -> str:
        """Geolocate an IP address using the local MaxMind GeoLite2-City database (offline, no API quota).
        Returns country, city, lat/lon, timezone. Requires ``MAXMIND_LICENSE_KEY`` and ``geoip2``.
        """
        _require_scope("investigations:read")

        result = await asyncio.to_thread(
            lambda: __import__("tools.geoip", fromlist=["lookup_ip"])
                        .lookup_ip(ip)
        )
        return _json(result)

    @mcp.tool(title="Refresh GeoIP Database")
    async def refresh_geoip(
        force: Annotated[bool, "Re-download even if recently updated."] = False,
    ) -> str:
        """Download or update the local MaxMind GeoLite2-City database (~70 MB).
        Auto-refreshed every 7 days by the scheduler. Requires ``MAXMIND_LICENSE_KEY``.
        """
        _require_scope("admin")

        result = await asyncio.to_thread(
            lambda: __import__("tools.geoip", fromlist=["refresh_geoip_db"])
                        .refresh_geoip_db(force=force)
        )
        return _json(result)


# ---------------------------------------------------------------------------
# Dark web intelligence
# ---------------------------------------------------------------------------

def _register_darkweb(mcp: FastMCP) -> None:

    @mcp.tool(title="Breach Exposure Check (XposedOrNot)",
              annotations={"readOnlyHint": False, "openWorldHint": True})
    async def xposed_breach_check(
        query: Annotated[str, "Email address or domain to check for breach exposure."],
        query_type: Annotated[str, "One of: 'email', 'domain'. "
                                   "Default 'auto' detects from value."] = "auto",
        case_id: Annotated[str, "Case ID to save results to (optional)."] = "",
    ) -> str:
        """Check email or domain breach exposure via XposedOrNot (breach names, risk scores,
        exposed data types, paste exposure). Email lookups are keyless; domain lookups require
        ``XPOSEDORNOT_API_KEY``. ``query_type``: ``"auto"`` | ``"email"`` | ``"domain"``.
        """
        _require_scope("investigations:read")
        if case_id:
            _check_client_boundary(case_id)

        from tools.darkweb import (
            _detect_type,
            xposedornot_domain_check,
            xposedornot_email_check,
        )

        qtype = query_type if query_type != "auto" else _detect_type(query)

        if qtype == "email":
            result = await asyncio.to_thread(
                lambda: xposedornot_email_check(query, case_id=case_id)
            )
        elif qtype == "domain":
            result = await asyncio.to_thread(
                lambda: xposedornot_domain_check(query, case_id=case_id)
            )
        else:
            raise ToolError(f"XposedOrNot supports email and domain lookups. "
                            f"Got type '{qtype}' for '{query}'.")
        return _json(result)

    @mcp.tool(title="Parse Stealer Logs")
    async def parse_stealer_logs_tool(
        case_id: Annotated[str, "Case ID containing stealer log archives."],
        archive_path: Annotated[str, "Path to archive within case dir (optional -- "
                                      "auto-discovers .rar/.zip/.7z if empty)."] = "",
    ) -> str:
        """Parse infostealer log archives (.rar/.zip/.7z) via lexfo/stealer-parser.
        Extracts browser credentials (REDACTED), cookies, autofill, history, system info, and stealer family.

        Requires ``stealer-parser`` package. ``archive_path`` defaults to auto-scan of case artefacts.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.darkweb import parse_stealer_logs

        result = await asyncio.to_thread(
            lambda: parse_stealer_logs(case_id, archive_path=archive_path)
        )
        return _json(result)

    @mcp.tool(title="Dark Web Exposure Summary")
    async def darkweb_exposure_summary(
        case_id: Annotated[str, "Case ID to assess dark web exposure for."],
        emails: Annotated[str, "Comma-separated email addresses to check "
                                "(optional -- auto-extracts from case IOCs if empty)."] = "",
        domains: Annotated[str, "Comma-separated domains to check (optional)."] = "",
        ips: Annotated[str, "Comma-separated IPs to check (optional)."] = "",
    ) -> str:
        """Aggregate dark web / breach exposure for a case across
        XposedOrNot. If ``emails`` / ``domains`` / ``ips`` are empty,
        auto-extracts indicators from ``iocs.json``. Saved to
        ``cases/<case_id>/artefacts/darkweb/darkweb_summary.json``.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.darkweb import darkweb_summary

        email_list = [e.strip() for e in emails.split(",") if e.strip()] if emails else None
        domain_list = [d.strip() for d in domains.split(",") if d.strip()] if domains else None
        ip_list = [i.strip() for i in ips.split(",") if i.strip()] if ips else None

        result = await asyncio.to_thread(
            lambda: darkweb_summary(case_id, emails=email_list,
                                    domains=domain_list, ips=ip_list)
        )
        return _json(result)

    @mcp.tool(title="Dark Web Search (Ahmia)",
              annotations={"readOnlyHint": False, "openWorldHint": True})
    async def ahmia_darkweb_search(
        query: Annotated[str, "Search term — email, domain, username, keyword, "
                              "or any text to search for on indexed .onion sites."],
        max_results: Annotated[int, "Maximum results to return (default 20)."] = 20,
        case_id: Annotated[str, "Case ID to save results to (optional)."] = "",
    ) -> str:
        """Search indexed .onion sites via Ahmia. With
        ``SOCAI_OPSEC_PROXY`` (Tor SOCKS5) does full content search;
        without proxy, greps Ahmia's domain list for known .onion
        addresses. No API key required.
        """
        _require_scope("investigations:read")
        if case_id:
            _check_client_boundary(case_id)

        from tools.darkweb import ahmia_search

        result = await asyncio.to_thread(
            lambda: ahmia_search(query, max_results=max_results, case_id=case_id)
        )
        return _json(result)

    @mcp.tool(title="Intelligence X Search",
              annotations={"readOnlyHint": False, "openWorldHint": True})
    async def intelx_search_tool(
        query: Annotated[str, "Strong selector — email, domain, IP, URL, "
                              "phone number, Bitcoin address, etc."],
        max_results: Annotated[int, "Maximum results to return (default 20)."] = 20,
        buckets: Annotated[str, "Comma-separated data sources to search: "
                                "'pastes', 'darknet', 'leaks', 'documents'. "
                                "Empty searches all."] = "",
        case_id: Annotated[str, "Case ID to save results to (optional)."] = "",
    ) -> str:
        """Search Intelligence X (dark web, pastes, leaks, documents) by
        strong selector. Set ``INTELX_API_KEY`` for full results; falls
        back to limited public API otherwise. Credentials in results are
        auto-redacted.
        """
        _require_scope("investigations:read")
        if case_id:
            _check_client_boundary(case_id)

        from tools.darkweb import intelx_search

        bucket_list = [b.strip() for b in buckets.split(",") if b.strip()] if buckets else None

        result = await asyncio.to_thread(
            lambda: intelx_search(query, max_results=max_results,
                                  buckets=bucket_list, case_id=case_id)
        )
        return _json(result)


# ---------------------------------------------------------------------------
# Log source coverage tools
# ---------------------------------------------------------------------------

def _register_coverage(mcp: FastMCP) -> None:

    @mcp.tool(title="Check Log Coverage", annotations={"readOnlyHint": True})
    async def check_log_coverage(
        client_name: Annotated[str, "Client name (case-insensitive)."],
    ) -> str:
        """Return coverage scores by domain (identity, endpoint, email, etc.), gaps, and health issues.
        Auto-collects from Sentinel if data is older than 24 hours.
        """
        _require_scope("investigations:read")

        from tools.log_coverage import get_coverage
        cov = await asyncio.to_thread(lambda: get_coverage(client_name))

        if not isinstance(cov, dict) or "scores" not in cov:
            return _json(cov)

        # Return a focused summary (full data is large)
        return _json({
            "client": cov.get("client"),
            "collected_at": cov.get("collected_at"),
            "scores": cov.get("scores"),
            "gaps": cov.get("gaps", []),
            "health_issues": cov.get("health_issues", []),
            "source_count": cov.get("source_count", 0),
        })

    @mcp.tool(title="Check Investigation Capability", annotations={"readOnlyHint": True})
    async def can_investigate_attack(
        client_name: Annotated[str, "Client name."],
        attack_type: Annotated[str, "Attack type from classify_attack (phishing, malware, "
                                    "account_compromise, privilege_escalation, "
                                    "data_exfiltration, lateral_movement, pup_pua, generic)."] = "generic",
    ) -> str:
        """Check whether the client has sufficient log coverage for a given attack type.
        Returns available/missing coverage domains and investigation limitations.
        """
        _require_scope("investigations:read")

        from tools.log_coverage import can_investigate
        result = await asyncio.to_thread(lambda: can_investigate(client_name, attack_type))
        return _json(result)

    @mcp.tool(title="Refresh Log Coverage")
    async def refresh_log_coverage(
        client_name: Annotated[str, "Client name."],
        full: Annotated[bool, "Include 365-day retention analysis (slower)."] = False,
    ) -> str:
        """Force a fresh log source collection for a client. Use when coverage data is stale
        or after new log sources are onboarded. ``full=True`` includes retention analysis.
        """
        _require_scope("investigations:submit")

        from tools.log_coverage import collect_log_sources
        result = await asyncio.to_thread(lambda: collect_log_sources(client_name, full=full))
        return _json(result)


# ---------------------------------------------------------------------------
# Exposure testing tools
# ---------------------------------------------------------------------------

def _register_exposure(mcp: FastMCP) -> None:

    @mcp.tool(title="Run Exposure Test")
    async def run_client_exposure_test(
        client_name: Annotated[str, "Client name."],
        domains: Annotated[str, "Comma-separated domains to test (auto-detected if empty)."] = "",
        include_typosquats: Annotated[bool, "Include typosquat detection (can be slow)."] = True,
    ) -> str:
        """Run an external attack surface assessment for a client.

        Discovers the client's web-facing footprint via DNS enumeration,
        certificate transparency, subdomain discovery, and OSINT enrichment.
        Assesses email security (SPF/DMARC/DKIM), service exposure, credential
        leaks, and typosquat domains.

        Parameters
        ----------
        client_name : str
            Client name.
        domains : str
            Comma-separated domains (auto-detected from knowledge.md if empty).
        include_typosquats : bool
            Include typosquat detection (default: True).
        """
        _require_scope("investigations:submit")

        from tools.exposure_test import run_exposure_test
        domain_list = [d.strip() for d in domains.split(",") if d.strip()] or None
        result = await asyncio.to_thread(
            lambda: run_exposure_test(client_name, domains=domain_list,
                                      include_typosquats=include_typosquats)
        )
        return _json(result)

    @mcp.tool(title="Get Exposure Report", annotations={"readOnlyHint": True})
    async def get_client_exposure_report(
        client_name: Annotated[str, "Client name."],
    ) -> str:
        """Return the latest exposure test results for a client: scores, findings,
        subdomain map, email security posture, and typosquat data.
        """
        _require_scope("investigations:read")

        from tools.exposure_test import get_exposure_report
        data = await asyncio.to_thread(lambda: get_exposure_report(client_name))

        if not isinstance(data, dict) or "scores" not in data:
            return _json(data)

        return _json({
            "client": data.get("client"),
            "tested_at": data.get("tested_at"),
            "domains_tested": data.get("domains_tested"),
            "scores": data.get("scores"),
            "findings": data.get("findings"),
            "summary": data.get("summary"),
        })


def _register_audit(mcp: FastMCP) -> None:
    """User-activity audit tooling — read-only views over the MCP server log."""

    @mcp.tool(title="Audit User Activity", annotations={"readOnlyHint": True})
    async def audit_user_activity(
        user: Annotated[str, "Filter to a single caller email. Empty = all users."] = "",
        since: Annotated[str, "ISO date or timestamp (inclusive lower bound). Empty = unbounded."] = "",
        until: Annotated[str, "ISO date or timestamp (exclusive upper bound). Empty = unbounded."] = "",
        errors_only: Annotated[bool, "Only return failed calls."] = False,
        max_events: Annotated[int, "Cap on events scanned. Default 2000."] = 2000,
    ) -> str:
        """Audit MCP tool activity from the server log: who called what, when,
        and which calls failed or ran slow.

        Returns per-user breakdown (calls / successes / failures / top tools /
        cases touched), every failed call with the error message, and any calls
        exceeding 30s. Use when the analyst asks "what did <user> do yesterday?",
        "show me errors from last week", or "any slow tools recently?".

        Read-only — pulls from ``registry/mcp_server.jsonl``.
        """
        _require_scope("investigations:read")

        from tools.audit_user import audit_user
        report = await asyncio.to_thread(
            lambda: audit_user(
                user=user or None,
                since=since or None,
                until=until or None,
                errors_only=errors_only,
                max_events=max_events,
            )
        )
        return _json(report)


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def _register_meta(mcp: FastMCP) -> None:
    """Meta-tools for on-demand toolset loading. Always part of core."""

    @mcp.tool(title="List Toolsets", annotations={"readOnlyHint": True})
    def list_toolsets() -> str:
        """List the available tool groups and which are currently loaded.

        Core is always loaded; specialist groups load on demand via
        load_toolset. Call this when you need a capability (sandbox, OpenCTI,
        memory forensics, dark-web, etc.) that isn't currently available.
        """
        _require_scope("investigations:read")
        live = set(mcp._tool_manager._tools)
        out = {
            ts_name: {
                "loaded": names.issubset(live),
                "description": _TOOLSET_DESCRIPTIONS.get(ts_name, ""),
                "tools": sorted(names),
            }
            for ts_name, names in TOOLSETS.items()
        }
        return _json({
            "toolsets": out,
            "hint": "Call load_toolset('<name>') to make a group's tools callable.",
        })

    @mcp.tool(title="Load Toolset")
    async def load_toolset(name: str, ctx: Context) -> str:
        """Load a specialist tool group so its tools become callable this session.

        name: one of phishing, malware, forensics, intel, darkweb, analysis,
        admin (see list_toolsets). classify_attack recommends the right group.
        Idempotent — returns the tools now available.
        """
        _require_scope("investigations:read")
        key = (name or "").strip().lower()
        if key not in TOOLSETS:
            return _json({
                "status": "error",
                "reason": f"unknown toolset '{name}' — choose from {sorted(TOOLSETS)}",
            })
        mgr = mcp._tool_manager
        newly: list[str] = []
        for tname in sorted(TOOLSETS[key]):
            if tname not in mgr._tools and tname in _ALL_TOOLS:
                mgr._tools[tname] = _ALL_TOOLS[tname]
                newly.append(tname)
        notified = False
        if newly:
            try:
                await ctx.session.send_tool_list_changed()
                notified = True
            except Exception as exc:  # noqa: BLE001
                from mcp_server.logging_config import mcp_log
                mcp_log("toolset_notify_failed", toolset=key, error=str(exc))
        return _json({
            "status": "ok",
            "toolset": key,
            "newly_loaded": newly,
            "newly_available_count": len(newly),
            "list_changed_notified": notified,
            "already_loaded": not newly,
            "tools": sorted(TOOLSETS[key]),
        })


def register_tools(mcp: FastMCP) -> None:
    """Register every MCP tool, then prune to the active toolset profile.

    All tools register once (cheap — just a JSON schema), get snapshotted into
    ``_ALL_TOOLS``. The active profile is ``SOCAI_MCP_TOOLSETS`` (default
    ``all`` — every tool stays live up front, which is what Claude Desktop
    needs). If a narrower profile is set, tools outside it are pruned from
    the live list and can be restored mid-session via ``load_toolset`` for
    clients that honour ``tools/list_changed``.
    """
    _register_meta(mcp)
    _register_tier1(mcp)
    _register_tier2(mcp)
    _register_tier2_rumsfeld(mcp)
    _register_tier3(mcp)
    _register_intelligence(mcp)
    _register_darkweb(mcp)
    _register_coverage(mcp)
    _register_exposure(mcp)
    _register_audit(mcp)

    # Snapshot every registered tool, then prune to the active profile.
    from mcp_server.config import MCP_TOOLSETS
    from mcp_server.logging_config import mcp_log

    _ALL_TOOLS.clear()
    _ALL_TOOLS.update(mcp._tool_manager._tools)

    # Safety net: any tool not assigned to a toolset stays in core, so a
    # mapping gap can never make a tool permanently unreachable.
    assigned = set().union(*TOOLSETS.values())
    unassigned = set(_ALL_TOOLS) - assigned
    if unassigned:
        TOOLSETS["core"] |= unassigned
        mcp_log("toolset_unassigned", tools=sorted(unassigned), note="folded into core")

    requested = {t.strip().lower() for t in MCP_TOOLSETS.split(",") if t.strip()}
    if requested & {"all", "full"}:
        mcp_log("tools_active", profile="all", loaded=len(_ALL_TOOLS), total=len(_ALL_TOOLS))
        return

    active = {"core"} | (requested & set(TOOLSETS))
    keep: set[str] = set()
    for ts_name in active:
        keep |= TOOLSETS[ts_name]
    for tname in list(mcp._tool_manager._tools):
        if tname not in keep:
            del mcp._tool_manager._tools[tname]

    mcp_log("tools_active", profile=",".join(sorted(active)),
            loaded=len(mcp._tool_manager._tools), total=len(_ALL_TOOLS))
