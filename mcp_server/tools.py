"""MCP tool wrappers — expose socai investigation tools with RBAC.

Each tool is registered on a ``FastMCP`` instance via ``register_tools(mcp)``.
All tools validate permissions using ``_require_scope()`` before delegating to
the existing action / tool layer.

Tools are organised in three tiers:
  Tier 1 (18) — Core Investigation   (Phase 1)
  Tier 2 (12) — Extended Analysis    (Phase 2)
  Tier 3 (19) — Advanced / Restricted (Phase 3)
"""
from __future__ import annotations

import asyncio
import json
from functools import partial
from pathlib import Path
from typing import Annotated

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from mcp_server.auth import _get_caller_email, _get_caller_scopes, _require_scope

# ---------------------------------------------------------------------------
# Conversation boundary enforcement — prevents cross-client and cross-case
# data mixing within a single chat session.
# ---------------------------------------------------------------------------

# Per-user active context.  Set on the first case-touching tool call in a
# conversation; any subsequent call that references a different client or
# case is rejected with a clear instruction to start a new chat.
_active_client: dict[str, str] = {}   # user_email → client_name
_active_case: dict[str, str] = {}     # user_email → case_id


def _reset_boundaries(caller: str | None = None) -> None:
    """Clear boundary state for a user, allowing a new investigation to begin.

    Called explicitly via the ``new_investigation`` tool or internally when
    creating a brand-new case.
    """
    user = caller or _get_caller_email()
    if not user:
        return
    _active_case.pop(user, None)
    _active_client.pop(user, None)


def _check_client_boundary(case_id: str) -> None:
    """Verify the case's client matches the active client for this user.

    Raises ``ToolError`` if the analyst is switching to a different client
    mid-conversation, instructing them to start a new chat session.
    """
    caller = _get_caller_email()
    if not caller:
        return  # no auth — skip enforcement

    # ── Case boundary ──────────────────────────────────────────────────
    prev_case = _active_case.get(caller)
    if prev_case is None:
        _active_case[caller] = case_id
    elif prev_case != case_id:
        raise ToolError(
            f"CASE BOUNDARY: This conversation is scoped to case {prev_case}. "
            f"You are now referencing case {case_id}. "
            f"Please start a NEW chat session for each investigation — "
            f"mixing cases in one conversation risks context contamination."
        )

    # ── Client boundary ────────────────────────────────────────────────
    from config.settings import CASES_DIR
    meta_path = CASES_DIR / case_id / "case_meta.json"
    if not meta_path.exists():
        return  # case doesn't exist yet — will be checked on creation

    try:
        meta = json.loads(meta_path.read_text())
    except Exception:
        return
    case_client = (meta.get("client") or "").strip().lower()
    if not case_client:
        return  # no client set on case — skip

    prev = _active_client.get(caller)
    if prev is None:
        _active_client[caller] = case_client
        return

    if prev != case_client:
        raise ToolError(
            f"CLIENT BOUNDARY: This conversation is scoped to client '{prev}'. "
            f"Case {case_id} belongs to client '{case_client}'. "
            f"You must start a NEW chat session to investigate a different client's data. "
            f"Client data must never be mixed in the same conversation."
        )


def _set_client_boundary(client_name: str) -> None:
    """Explicitly set the active client for the current user (e.g. on case creation)."""
    caller = _get_caller_email()
    if not caller or not client_name:
        return
    client_lower = client_name.strip().lower()
    prev = _active_client.get(caller)
    if prev is not None and prev != client_lower:
        raise ToolError(
            f"CLIENT BOUNDARY: This conversation is scoped to client '{prev}'. "
            f"You are attempting to create a case for client '{client_name}'. "
            f"You must start a NEW chat session to work with a different client."
        )
    _active_client[caller] = client_lower


def _check_workspace_boundary(workspace_id: str) -> None:
    """Verify the workspace belongs to the active client (if one is set).

    Looks up which client owns *workspace_id* in the client registry and
    checks against ``_active_client``.  Raises ``ToolError`` on mismatch.
    """
    caller = _get_caller_email()
    if not caller:
        return

    from config.settings import CLIENT_ENTITIES
    from tools.common import load_json
    try:
        entities = load_json(CLIENT_ENTITIES).get("clients", [])
    except Exception:
        return

    # Resolve workspace → owning client
    ws_lower = workspace_id.strip().lower()
    owner = ""
    owner_display = ""
    for ent in entities:
        platforms = ent.get("platforms", {})
        if not platforms and ent.get("workspace_id"):
            platforms = {"sentinel": {"workspace_id": ent["workspace_id"]}}
        sentinel_ws = (platforms.get("sentinel", {}).get("workspace_id") or "").lower()
        if sentinel_ws == ws_lower:
            owner = ent.get("name", "").strip().lower()
            owner_display = ent.get("name", "")
            break

    prev = _active_client.get(caller)
    if prev is None:
        # First query — lock to the workspace's owning client
        if owner:
            _active_client[caller] = owner
        return

    if owner and owner != prev:
        raise ToolError(
            f"CLIENT BOUNDARY: This conversation is scoped to client '{prev}'. "
            f"Workspace {workspace_id} belongs to client '{owner_display}'. "
            f"You must start a NEW chat session to query a different client's data."
        )


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
# Tier 1 — Core Investigation (18 tools)
# ---------------------------------------------------------------------------

def _register_tier1(mcp: FastMCP) -> None:

    @mcp.tool(title="Start New Investigation")
    async def new_investigation() -> str:
        """Use when the analyst says "new case", "start fresh", "different investigation",
        or "switch case". Resets the conversation so a new case and client can be worked on.

        Every conversation is locked to one case and one client for data isolation.
        If an analyst needs to work on a different case or client, this tool must be
        called first — otherwise the boundary check will reject the request and ask
        the analyst to start a new chat.

        Does not delete any data — it only clears the conversation-level lock.
        """
        caller = _get_caller_email()
        prev_case = _active_case.get(caller)
        _reset_boundaries(caller)
        if prev_case:
            return _json({
                "status": "ok",
                "message": f"Boundaries cleared (was scoped to {prev_case}). Ready for a new investigation.",
            })
        return _json({
            "status": "ok",
            "message": "Ready for a new investigation.",
        })

    @mcp.tool(title="Run Full Investigation", annotations={"openWorldHint": True})
    async def investigate(
        case_id: str,
        title: str = "",
        severity: str = "medium",
        analyst: str = "unassigned",
        urls: list[str] | None = None,
        zip_path: str | None = None,
        zip_pass: str | None = None,
        log_paths: list[str] | None = None,
        eml_paths: list[str] | None = None,
        tags: list[str] | None = None,
        close_case: bool = False,
        include_private_ips: bool = False,
        detonate: bool = False,
        analyst_notes: str | None = None,
        wait: bool = False,
        ctx: Context | None = None,
    ) -> str:
        """Use when the analyst says "investigate this case", "run the full pipeline",
        or provides a case ID with alert details, URLs, files, or logs to analyse.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Runs the complete investigation pipeline: IOC extraction, enrichment,
        correlation, phishing detection, report generation, and response actions.
        This is the heavyweight option — takes 2-10 minutes. For a quick look at
        a single URL, domain, or file, prefer the ``quick_investigate_*`` tools instead.

        By default runs in the background (fire-and-forget) and returns a case_id
        immediately. Poll progress with ``get_case`` every 30 seconds until
        ``pipeline_complete`` is true, then call ``read_report`` to retrieve findings.
        Set ``wait=True`` to block until the pipeline finishes (useful for scripted flows).

        Parameters
        ----------
        case_id : str
            Unique case identifier, e.g. "IV_CASE_001".
        title : str
            Human-readable case title.
        severity : str
            One of: low, medium, high, critical.
        analyst : str
            Analyst name or ID.
        urls : list[str]
            URLs to capture and investigate.
        zip_path : str
            Absolute path to a ZIP archive.
        zip_pass : str
            Password for the ZIP archive.
        log_paths : list[str]
            Absolute paths to log files.
        eml_paths : list[str]
            Absolute paths to .eml files.
        tags : list[str]
            Free-form tags for the case.
        close_case : bool
            Mark the case as closed after pipeline completes.
        include_private_ips : bool
            Include RFC-1918 IPs in IOC extraction.
        detonate : bool
            Submit file hashes to sandbox for live detonation.
        analyst_notes : str
            Freeform analyst context, observations, or IOCs to attach to the
            case. Saved to ``notes/analyst_input.md`` before the pipeline runs
            so downstream tools (report generation, security architecture
            review) can reference it.
        wait : bool
            If True, block until pipeline completes (with progress). Default
            is False (fire-and-forget, returns job_id immediately).
        """
        _require_scope("investigations:submit")

        # Auto-reset boundaries when creating a brand-new case so that
        # a new conversation isn't blocked by stale state from a prior one.
        from config.settings import CASES_DIR
        if not (CASES_DIR / case_id).exists():
            _reset_boundaries()

        _check_client_boundary(case_id)

        from agents.chief import ChiefAgent

        kwargs = dict(
            title=title or f"Investigation {case_id}",
            severity=severity,
            analyst=analyst,
            tags=tags or [],
            urls=urls or [],
            zip_path=zip_path,
            zip_pass=zip_pass,
            log_paths=log_paths or [],
            eml_paths=eml_paths or [],
            close_case=close_case,
            include_private_ips=include_private_ips,
            detonate=detonate,
            analyst_notes=analyst_notes,
        )

        if wait:
            # Inline — run in thread pool so we don't block the event loop
            result = await asyncio.to_thread(
                lambda: ChiefAgent(case_id).run(**kwargs)
            )
            return _json(result)

        # Fire-and-forget — schedule in background, return immediately
        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, lambda: ChiefAgent(case_id).run(**kwargs))
        return _json({
            "status": "submitted",
            "case_id": case_id,
            "message": f"Investigation {case_id} submitted. Poll get_case for status.",
        })

    @mcp.tool(title="Quick Investigate URL", annotations={"openWorldHint": True})
    async def quick_investigate_url(
        url: str,
        severity: str = "medium",
        analyst: str = "unassigned",
        tags: list[str] | None = None,
        wait: bool = False,
    ) -> str:
        """Use when the analyst says "check this URL", "investigate this link",
        or pastes a URL to analyse. Auto-generates a case ID and runs the full
        investigation pipeline — no need to create a case first.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        This is the quick-run entry point for URL-based investigations (phishing
        links, suspicious redirects, credential harvesting pages, etc.).
        For domain-only investigations (no specific URL path), use
        ``quick_investigate_domain`` instead.

        Takes 2-10 minutes. Returns the case_id immediately by default.
        **After calling this tool:**
        1. Poll ``get_case(case_id)`` every 30s until ``pipeline_complete`` is true
        2. Call ``read_report(case_id)`` to retrieve the investigation narrative
        3. Summarise the findings for the analyst
        4. Call ``close_case(case_id, disposition)`` to close the investigation

        Parameters
        ----------
        url : str
            The URL to investigate.
        severity : str
            One of: low, medium, high, critical.
        analyst : str
            Analyst name or ID.
        tags : list[str]
            Free-form tags.
        wait : bool
            If True, block until pipeline completes. Default False (fire-and-forget).
        """
        _require_scope("investigations:submit")
        _reset_boundaries()  # always a new case

        from api.jobs import JobManager
        from agents.chief import ChiefAgent

        case_id = JobManager.next_case_id()
        _active_case[_get_caller_email()] = case_id

        def _run():
            return ChiefAgent(case_id).run(
                title=f"URL investigation: {url}",
                severity=severity,
                analyst=analyst,
                tags=tags or [],
                urls=[url],
            )

        if wait:
            result = await asyncio.to_thread(_run)
            return _json({"case_id": case_id, **result})

        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, _run)
        return _json({
            "status": "submitted",
            "case_id": case_id,
            "message": f"Investigation {case_id} submitted. Use get_case('{case_id}') to poll for results.",
        })

    @mcp.tool(title="Quick Investigate Domain", annotations={"openWorldHint": True})
    async def quick_investigate_domain(
        domain: str,
        severity: str = "medium",
        analyst: str = "unassigned",
        tags: list[str] | None = None,
        wait: bool = False,
    ) -> str:
        """Use when the analyst says "look up this domain", "investigate this domain",
        or provides a bare domain name (no URL path). Auto-generates a case ID and
        runs the full investigation pipeline.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        This is the quick-run entry point for domain-based investigations. The domain
        is automatically prefixed with ``https://`` for web capture. If the analyst
        provides a full URL with a path, use ``quick_investigate_url`` instead.

        Takes 2-10 minutes. Returns the case_id immediately by default.
        **After calling this tool:**
        1. Poll ``get_case(case_id)`` every 30s until ``pipeline_complete`` is true
        2. Call ``read_report(case_id)`` to retrieve the investigation narrative
        3. Summarise the findings for the analyst
        4. Call ``close_case(case_id, disposition)`` to close the investigation

        Parameters
        ----------
        domain : str
            Domain to investigate (e.g. "evil-domain.com").
        severity : str
            One of: low, medium, high, critical.
        analyst : str
            Analyst name or ID.
        tags : list[str]
            Free-form tags.
        wait : bool
            If True, block until pipeline completes. Default False (fire-and-forget).
        """
        _require_scope("investigations:submit")
        _reset_boundaries()  # always a new case

        from api.jobs import JobManager
        from agents.chief import ChiefAgent

        case_id = JobManager.next_case_id()
        _active_case[_get_caller_email()] = case_id
        url = f"https://{domain}" if not domain.startswith("http") else domain

        def _run():
            return ChiefAgent(case_id).run(
                title=f"Domain investigation: {domain}",
                severity=severity,
                analyst=analyst,
                tags=tags or [],
                urls=[url],
            )

        if wait:
            result = await asyncio.to_thread(_run)
            return _json({"case_id": case_id, **result})

        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, _run)
        return _json({
            "status": "submitted",
            "case_id": case_id,
            "message": f"Investigation {case_id} submitted. Use get_case('{case_id}') to poll for results.",
        })

    @mcp.tool(title="Quick Investigate File", annotations={"openWorldHint": True})
    async def quick_investigate_file(
        file_path: str,
        severity: str = "medium",
        analyst: str = "unassigned",
        zip_pass: str | None = None,
        tags: list[str] | None = None,
        wait: bool = False,
    ) -> str:
        """Use when the analyst says "analyse this file", "check this sample",
        "investigate this attachment", or provides a file path (ZIP, EXE, DLL,
        script, etc.). Auto-generates a case ID and runs the full investigation
        pipeline — no need to create a case first.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        This is the quick-run entry point for file/malware-based investigations.
        Supports password-protected ZIP archives (provide ``zip_pass``).
        For URL- or domain-based investigations, use the corresponding
        ``quick_investigate_url`` or ``quick_investigate_domain`` tools instead.

        Takes 2-10 minutes. Returns the case_id immediately by default.
        **After calling this tool:**
        1. Poll ``get_case(case_id)`` every 30s until ``pipeline_complete`` is true
        2. Call ``read_report(case_id)`` to retrieve the investigation narrative
        3. Summarise the findings for the analyst
        4. Call ``close_case(case_id, disposition)`` to close the investigation

        Parameters
        ----------
        file_path : str
            Absolute path to the file or ZIP archive.
        severity : str
            One of: low, medium, high, critical.
        analyst : str
            Analyst name or ID.
        zip_pass : str
            Password for the ZIP archive.
        tags : list[str]
            Free-form tags.
        wait : bool
            If True, block until pipeline completes. Default False (fire-and-forget).
        """
        _require_scope("investigations:submit")
        _reset_boundaries()  # always a new case

        from api.jobs import JobManager
        from agents.chief import ChiefAgent

        case_id = JobManager.next_case_id()
        _active_case[_get_caller_email()] = case_id
        fname = Path(file_path).name

        def _run():
            return ChiefAgent(case_id).run(
                title=f"File investigation: {fname}",
                severity=severity,
                analyst=analyst,
                tags=tags or [],
                zip_path=file_path,
                zip_pass=zip_pass,
            )

        if wait:
            result = await asyncio.to_thread(_run)
            return _json({"case_id": case_id, **result})

        loop = asyncio.get_running_loop()
        loop.run_in_executor(None, _run)
        return _json({
            "status": "submitted",
            "case_id": case_id,
            "message": f"Investigation {case_id} submitted. Use get_case('{case_id}') to poll for results.",
        })

    @mcp.tool(title="Look Up Client", annotations={"readOnlyHint": True})
    def lookup_client(client_name: str) -> str:
        """Use when the analyst mentions a client name, asks "which platforms does
        this client have?", or when you need to confirm which Sentinel workspace,
        XDR tenant, or CrowdStrike CID belongs to a client before running queries.

        Returns the client's registered security platforms and whether a response
        playbook exists. Also locks the conversation to this client — all subsequent
        tool calls will be scoped to this client's data only.

        Call this early in an investigation to establish the client context, especially
        before using ``run_kql`` (which needs the correct workspace).

        Parameters
        ----------
        client_name : str
            Client name to look up (case-insensitive).
        """
        _require_scope("investigations:read")

        from tools.common import get_client_config
        cfg = get_client_config(client_name)
        if not cfg:
            # If a client boundary is already set, warn about scope
            caller = _get_caller_email()
            prev = _active_client.get(caller, "") if caller else ""
            if prev:
                raise ToolError(
                    f"CLIENT BOUNDARY: This conversation is scoped to client '{prev}'. "
                    f"Client {client_name!r} is not recognised — you may be attempting "
                    f"to switch clients. Please start a NEW chat session for a different client."
                )
            # No boundary set — just report not found
            from config.settings import CLIENT_ENTITIES
            from tools.common import load_json
            try:
                entities = load_json(CLIENT_ENTITIES).get("clients", [])
                names = [e.get("name", "") for e in entities]
            except Exception:
                names = []
            return _json({
                "error": f"Client {client_name!r} not found.",
                "available_clients": names,
            })

        # Lock the conversation to this client (raises ToolError on mismatch)
        _set_client_boundary(cfg.get("name", client_name))

        # Include platforms and any response playbook
        platforms = cfg.get("platforms", {})
        if not platforms and cfg.get("workspace_id"):
            platforms = {"sentinel": {"workspace_id": cfg["workspace_id"]}}

        result = {
            "name": cfg.get("name", ""),
            "platforms": platforms,
            "platform_list": list(platforms.keys()),
        }
        # Check for response playbook
        from pathlib import Path
        playbook_path = Path(__file__).resolve().parent.parent / "config" / "clients" / f"{cfg['name']}.json"
        result["has_response_playbook"] = playbook_path.exists()

        return _json(result)

    @mcp.tool(title="List Cases", annotations={"readOnlyHint": True})
    def list_cases() -> str:
        """Use when the analyst asks "show me recent cases", "what's open?",
        "list my cases", or "what investigations do we have?".

        Returns all cases from the registry with their status, severity, and
        disposition. When the analyst asks for "recent" or "current" cases,
        prefer filtering the results to show **open cases** unless they
        explicitly ask for all or closed cases.

        For searching prior cases by IOC, email, or keyword, use ``recall_cases``
        instead."""
        _require_scope("investigations:read")

        from config.settings import REGISTRY_FILE
        from tools.common import load_json

        if not REGISTRY_FILE.exists():
            return _json({"cases": {}, "message": "No registry found."})
        return _json(load_json(REGISTRY_FILE))

    @mcp.tool(title="Get Case Status", annotations={"readOnlyHint": True})
    def get_case(case_id: str) -> str:
        """Use to check on a running investigation or retrieve basic case metadata.
        This is the lightweight polling tool — call it every 30 seconds after
        submitting an investigation until ``pipeline_complete`` is true.

        Returns case metadata (title, severity, status, disposition, timestamps).
        Does NOT include IOCs, verdicts, or enrichment data — for a complete
        picture, use ``case_summary`` instead.

        **Polling workflow:** after ``investigate`` or ``quick_investigate_*``,
        poll this tool every 30s. When ``pipeline_complete`` is true, call
        ``read_report`` to get findings, summarise for the analyst, then
        ``close_case`` to close.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "IV_CASE_001".
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from config.settings import CASES_DIR
        from tools.common import load_json

        meta_path = CASES_DIR / case_id / "case_meta.json"
        if not meta_path.exists():
            return _json({"error": f"Case {case_id!r} not found. Investigation may still be initialising — retry in 15 seconds."})
        meta = load_json(meta_path)

        # Add pipeline_complete flag for polling clients
        report_exists = (CASES_DIR / case_id / "reports" / "investigation_report.md").exists()
        meta["pipeline_complete"] = report_exists
        if not report_exists:
            meta["_hint"] = "Pipeline still running. Call get_case again in 30 seconds."
        elif meta.get("status") == "open":
            meta["_hint"] = (
                "Pipeline complete. Read the report with read_report "
                "and summarise the findings for the user. "
                "The case will be auto-closed when you read the report."
            )

        return _json(meta)

    @mcp.tool(title="Full Case Summary", annotations={"readOnlyHint": True})
    def case_summary(case_id: str) -> str:
        """Use when the analyst says "summarise this case", "what do we know about
        this case?", "give me an overview", or when you need to review or resume
        an existing investigation.

        Returns everything in one call: metadata, IOCs with verdicts, enrichment
        stats, response actions, correlation hits, campaign links, analyst notes,
        timeline event count, and any errors. This is the go-to tool for getting
        a full picture of a case without calling multiple tools.

        **Prefer this over ``get_case``** unless you are only polling for pipeline
        completion. ``get_case`` returns metadata only; this returns the full
        investigative context.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "IV_CASE_004".
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

        # Pipeline status
        report_exists = (case_dir / "reports" / "investigation_report.md").exists()
        meta["pipeline_complete"] = report_exists

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
                    p for per_ioc in raw_results.values()
                    if isinstance(per_ioc, dict) for p in per_ioc
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

        # Error log (case-specific entries)
        errors: list = []
        try:
            from config.settings import ERROR_LOG
            if ERROR_LOG.exists():
                all_errors = load_json(ERROR_LOG)
                errors = [e for e in all_errors if e.get("case_id") == case_id]
        except Exception:
            pass

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
                "pipeline_complete": meta.get("pipeline_complete"),
            },
            "iocs": ioc_summary,
            "verdicts": verdict_highlights,
            "enrichment": enrichment_stats,
            "response_actions": response_summary,
            "correlation": correlation_summary,
            "campaign": campaign if campaign else {},
            "analyst_notes": analyst_notes,
            "timeline_events": len(timeline) if isinstance(timeline, list) else 0,
            "errors": errors,
            "_hint": (
                "This is the full case summary. Use read_report to get the "
                "investigation narrative, or read_case_file for specific artefacts."
            ),
        }

        return _json(summary)

    @mcp.tool(title="Read Investigation Report", annotations={"readOnlyHint": True})
    def read_report(case_id: str) -> str:
        """Use when the analyst says "show me the report", "what did the investigation
        find?", or after a pipeline completes and you need to present findings.

        Returns the full investigation report in Markdown. This is the detailed
        narrative produced by the pipeline — findings, IOC analysis, verdicts,
        attack chain, and recommendations.

        **Side effect:** auto-closes the case (disposition: "resolved") if it is
        still open. This is by design — reading the report is the final deliverable
        collection step. If you only need a quick overview without closing, use
        ``case_summary`` instead.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "IV_CASE_001".
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from config.settings import CASES_DIR
        from tools.common import load_json

        report_path = CASES_DIR / case_id / "reports" / "investigation_report.md"
        if not report_path.exists():
            return f"No report found for case {case_id!r}. Run investigate or generate_report first."

        # Auto-close: if the report exists and case is still open, close it
        meta_path = CASES_DIR / case_id / "case_meta.json"
        if meta_path.exists():
            meta = load_json(meta_path)
            if meta.get("status") == "open":
                from tools.index_case import index_case
                index_case(case_id, status="closed", disposition="resolved")

        return report_path.read_text(encoding="utf-8")

    @mcp.tool(title="Read Case File", annotations={"readOnlyHint": True})
    def read_case_file(case_id: str, file_path: str) -> str:
        """Use when you need to read a specific artefact file from a case — e.g.
        raw enrichment JSON, IOC lists, captured HTML, phishing detection results,
        or any other file produced by the pipeline.

        Takes a relative path within the case directory. Common paths include:
        ``iocs/iocs.json``, ``artefacts/enrichment/enrichment.json``,
        ``artefacts/enrichment/verdict_summary.json``,
        ``artefacts/phishing/detection.json``, ``artefacts/captures/*.html``,
        ``notes/analyst_input.md``, ``reports/investigation_report.md``.

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

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            if len(content) > 50000:
                content = content[:50000] + "\n\n... [truncated]"
            return content
        except Exception as exc:
            return _json({"error": f"Error reading {file_path}: {exc}"})

    @mcp.tool(title="Close Case")
    def close_case(
        case_id: str,
        disposition: str = "resolved",
    ) -> str:
        """Use when the analyst says "close this case", "mark as false positive",
        "this is a true positive", or after you have summarised the findings and
        the investigation is complete.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        This is the final step of the standard workflow: investigate -> poll ->
        read_report -> summarise -> **close_case**. Note that ``read_report``
        auto-closes with disposition "resolved", so you only need this tool
        explicitly when the analyst wants a specific disposition (e.g. "false_positive",
        "true_positive", "benign", "inconclusive").

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "IV_CASE_001".
        disposition : str
            Closing disposition. One of: "true_positive", "false_positive",
            "benign", "inconclusive", "resolved". Default "resolved".
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.index_case import index_case
        return _json(index_case(case_id, status="closed", disposition=disposition))

    @mcp.tool(title="Add Evidence")
    async def add_evidence(case_id: str, text: str) -> str:
        """Use when the analyst pastes in raw alert data, IOC lists, log snippets,
        or contextual notes that should be attached to an existing case. Trigger
        phrases: "here's the alert", "add these IOCs", "paste this into the case",
        "here's more context".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Parses the text for IOCs (URLs, IPs, domains, hashes, emails, CVEs) and
        saves both the raw text and extracted IOCs to the case. The extracted IOCs
        are merged into the case IOC set.

        **Difference from ``add_finding``:** this tool is for raw input data
        (alert JSON, IOC lists, analyst notes). ``add_finding`` is for recording
        your analytical conclusions (e.g. "this is credential phishing targeting
        the finance team"). Use ``add_evidence`` to feed data in, use ``add_finding``
        to record what you concluded from it.

        **Follow-up:** call ``enrich_iocs`` after adding evidence to enrich any
        newly added IOCs.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "IV_CASE_001".
        text : str
            Freeform analyst input — paste alert text, IOC lists, contextual
            notes, or any observations relevant to the investigation.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.add_evidence(case_id, text)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Record Analytical Finding")
    def add_finding(
        case_id: str,
        finding_type: str,
        summary: str,
        detail: str = "",
    ) -> str:
        """Use when you (or the analyst) have reached an analytical conclusion
        and want to record it against the case. Trigger phrases: "record this
        finding", "note that this is phishing", "mark as false positive",
        "key finding: lateral movement via RDP".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Findings are structured conclusions — not raw data. They are saved to
        the case notes and referenced during report generation.

        **Difference from ``add_evidence``:** ``add_evidence`` is for raw input
        (alert text, IOC lists, log snippets). ``add_finding`` is for analytical
        conclusions you have drawn from the evidence. Example: after reviewing
        enrichment results showing a domain is a known credential harvester,
        record that as a finding here.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "IV_CASE_001".
        finding_type : str
            Category of finding, e.g. "phishing", "malware", "credential_access",
            "lateral_movement", "exfiltration", "benign", "false_positive".
        summary : str
            One-line summary of the finding.
        detail : str
            Extended detail, evidence references, or analyst reasoning.
        """
        _require_scope("investigations:submit")

        from config.settings import CASES_DIR
        from tools.common import utcnow

        case_dir = CASES_DIR / case_id
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

        return _json({
            "case_id": case_id,
            "finding_type": finding_type,
            "summary": summary,
            "recorded_at": utcnow(),
        })

    @mcp.tool(title="Enrich IOCs")
    async def enrich_iocs(case_id: str, include_private: bool = False) -> str:
        """Use when the analyst says "enrich these IOCs", "look up this IP/domain/hash",
        "what do we know about these indicators?", or after adding new evidence to a
        case that introduced new IOCs.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Extracts all IOCs from case artefacts (URLs, IPs, domains, hashes, emails,
        CVEs), then enriches them against multiple threat intelligence sources:
        VirusTotal, AbuseIPDB, URLhaus, ThreatFox, OpenCTI, Shodan, GreyNoise,
        URLScan, MalwareBazaar, Intezer, Censys, OTX, Hybrid Analysis, WhoisXML,
        and ProxyCheck. Produces a scored verdict (malicious/suspicious/clean) for
        each IOC.

        This tool re-runs extraction and enrichment from scratch — safe to call
        multiple times as new evidence is added. Results are saved to the case
        and used by report generation and correlation tools.

        Parameters
        ----------
        case_id : str
            Case identifier.
        include_private : bool
            Include RFC-1918 IPs.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.extract_and_enrich(case_id, include_private=include_private)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Generate Investigation Report")
    async def generate_report(case_id: str, close_case: bool = False) -> str:
        """Use when the analyst says "write the report", "generate the investigation
        report", or "regenerate the report" for a case that has been through
        enrichment and analysis.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Produces the main investigation Markdown report — the detailed narrative
        covering findings, IOC analysis, verdicts, attack chain reconstruction,
        and recommendations. This is the internal/technical report.

        **Choosing the right report tool:**
        - ``generate_report`` — internal investigation narrative (this tool)
        - ``generate_mdr_report`` — structured client-facing MDR deliverable
        - ``generate_pup_report`` — lightweight report for PUP/PUA detections only
        - ``generate_executive_summary`` — non-technical summary for leadership

        Prerequisites: the case should have IOCs extracted and enriched first.
        If not, the report will have limited content.

        Parameters
        ----------
        case_id : str
            Case identifier.
        close_case : bool
            Mark the case as closed after report generation.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.generate_report(case_id, close_case=close_case)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Generate MDR Report")
    async def generate_mdr_report(case_id: str) -> str:
        """Use when the analyst says "write the MDR report", "client report",
        "generate the deliverable", or needs the structured client-facing report
        for a completed investigation.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Produces the formal Managed Detection & Response report — the primary
        deliverable sent to the client. Includes executive summary, detailed
        findings, IOC table, response recommendations, and next steps.

        **Auto-closes the case** on generation (preserves existing disposition).
        This is by design — the MDR report is the final deliverable.

        **Choosing the right report tool:**
        - ``generate_mdr_report`` — client-facing MDR deliverable (this tool)
        - ``generate_report`` — internal investigation narrative
        - ``generate_pup_report`` — use instead when the detection is PUP/PUA
          (adware, bundleware, toolbars), not a real threat
        - ``generate_executive_summary`` — non-technical summary for leadership

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.generate_mdr_report import generate_mdr_report as _mdr
        result = await asyncio.to_thread(lambda: _mdr(case_id))
        return _json(result)

    @mcp.tool(title="Generate PUP/PUA Report")
    async def generate_pup_report(case_id: str) -> str:
        """Use when the analyst says "this is just a PUP", "adware report",
        "unwanted software", or when the detection is a Potentially Unwanted
        Program/Application — not a real compromise or targeted attack.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Produces a lightweight PUP/PUA-specific report covering: software
        identification, installation scope, risk assessment, and removal steps.
        Skips attack-chain analysis since there is no actual attack.

        **Auto-closes the case** with disposition "pup_pua".

        **When to use this vs ``generate_mdr_report``:** if the detection is
        adware, bundleware, browser hijackers, toolbars, crypto miners (non-malicious),
        or similar unwanted-but-not-malicious software, use this tool.
        If it is an actual compromise, targeted attack, or malicious activity,
        use ``generate_mdr_report`` instead.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.generate_pup_report import generate_pup_report as _pup
        result = await asyncio.to_thread(lambda: _pup(case_id))
        return _json(result)

    @mcp.tool(title="Generate Hunt Queries")
    async def generate_queries(
        case_id: str,
        platforms: list[str] | None = None,
        tables: list[str] | None = None,
    ) -> str:
        """Use when the analyst says "give me hunt queries", "detection rules",
        "SIEM queries", "KQL for this", "Splunk queries", or "how do I hunt for
        this in our logs?".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Generates ready-to-run threat hunting queries based on the case's IOCs
        and observed attack patterns. Supports KQL (Azure Sentinel), Splunk SPL,
        and LogScale (CrowdStrike). Queries are tailored to the specific threat
        — e.g. phishing IOCs produce email and proxy queries, malware IOCs
        produce process and file event queries.

        Prerequisites: the case must have IOCs (run ``enrich_iocs`` first or
        ensure the pipeline has completed).

        Parameters
        ----------
        case_id : str
            Case identifier.
        platforms : list[str]
            SIEM platforms: "kql", "splunk", "logscale". Defaults to all.
        tables : list[str]
            Confirmed KQL tables to scope queries to.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.generate_queries(case_id, platforms=platforms, tables=tables)
        )
        return _json(_pop_message(result))

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
        """Use EARLY in any interactive investigation — before deciding which
        tools to call.  Trigger phrases: "what type of attack is this?",
        "classify this alert", "what should I investigate?", or simply when
        you have alert details and need to decide the investigation path.

        Runs deterministic keyword + input-shape classification (no LLM call,
        instant) and returns:

        - **attack_type** — phishing, malware, account_compromise,
          privilege_escalation, pup_pua, or generic
        - **confidence** — high / medium / low
        - **signals** — human-readable reasons for the classification
        - **profile** — which pipeline steps to run and which to skip
        - **recommended_tools** — ordered list of MCP tools to call for this
          attack type, with dependencies noted

        Does NOT require a case — works on raw alert text alone.  Call this
        before creating a case to inform your investigation strategy.

        Parameters
        ----------
        title : str
            Alert or incident title.
        notes : str
            Analyst notes, alert description, or raw alert text.
        tags : list[str]
            Tags from the alert (e.g. MITRE technique IDs).
        urls : list[str]
            URLs present in the alert (used as input-shape signal).
        file_names : list[str]
            File names / paths from the alert (used as input-shape signal).
        eml_provided : bool
            True if .eml files are available.
        logs_provided : bool
            True if log files are available.
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
                {"tool": "run_kql", "reason": "Execute each playbook stage in order — check Stage 1 results before proceeding to Stage 2", "depends_on": "load_kql_playbook", "condition": "if Sentinel access (Advanced Hunting tables)"},
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
                {"tool": "capture_urls", "reason": "Capture suspicious pages for analysis"},
                {"tool": "detect_phishing", "reason": "Check for brand impersonation", "depends_on": "capture_urls"},
                {"tool": "analyse_email", "reason": "Parse .eml headers and content", "condition": "if .eml available"},
                {"tool": "enrich_iocs", "reason": "Enrich all extracted IOCs"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
            ] + _kql("phishing", "email delivery, URL clicks, credential harvest")
              + _composite("email-threat-zap", "email threats, ZAP, post-delivery activity") + [
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "generate_mdr_report", "reason": "Generate client-facing MDR deliverable"},
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
                {"tool": "generate_mdr_report", "reason": "Generate client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment and remediation guidance"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "account_compromise": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich IPs, domains from sign-in data"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
            ] + _kql("account-compromise", "sign-ins, MFA, post-compromise audit")
              + _composite("suspicious-signin", "sign-ins, MFA, post-auth activity, alerts") + [
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "generate_mdr_report", "reason": "Generate client-facing MDR deliverable"},
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
                {"tool": "generate_mdr_report", "reason": "Generate client-facing MDR deliverable"},
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
                {"tool": "generate_mdr_report", "reason": "Generate client-facing MDR deliverable"},
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
                {"tool": "generate_mdr_report", "reason": "Generate client-facing MDR deliverable"},
                {"tool": "response_actions", "reason": "Containment and remediation guidance (host isolation, credential reset)"},
                {"tool": "generate_queries", "reason": "Generate SIEM hunt queries"},
            ],
            "pup_pua": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich file hashes and domains"},
                {"tool": "generate_pup_report", "reason": "Generate PUP/PUA report (auto-closes case)"},
            ],
            "generic": _prefix + [
                {"tool": "enrich_iocs", "reason": "Enrich all extracted IOCs"},
                {"tool": "recall_cases", "reason": "Check for prior related investigations"},
                {"tool": "capture_urls", "reason": "Capture any suspicious URLs", "condition": "if URLs present"},
                {"tool": "detect_phishing", "reason": "Check for brand impersonation", "depends_on": "capture_urls", "condition": "if URLs captured"},
                {"tool": "correlate", "reason": "Cross-reference IOCs across artefacts"},
                {"tool": "run_kql", "reason": "Ad-hoc KQL queries — no standard playbook for generic; write queries based on available IOCs", "condition": "if Sentinel access"},
                {"tool": "generate_report", "reason": "Generate investigation narrative"},
                {"tool": "generate_mdr_report", "reason": "Generate client-facing MDR deliverable"},
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
        client: str = "",
        severity: str = "",
    ) -> str:
        """Use at the START of an interactive investigation to get a complete,
        ordered plan.  Trigger phrases: "how should I investigate this?",
        "what's the plan?", "walk me through this", or anytime you receive
        alert details and need to decide the investigation approach.

        Classifies the attack type, then returns a step-by-step investigation
        plan tailored to the alert:

        - Ordered tool calls with reasons and dependencies
        - Steps to skip (and why) based on the attack profile
        - Recommended KQL playbook (if Sentinel access is available)
        - Guidance on which report tool to use at the end

        Does NOT execute anything — purely advisory.  Present the plan to the
        analyst, then execute the steps by calling the individual tools.

        For automated end-to-end execution, use ``investigate`` instead.

        Parameters
        ----------
        title : str
            Alert or incident title.
        notes : str
            Analyst notes, alert description, or raw alert text.
        tags : list[str]
            Tags from the alert (e.g. MITRE technique IDs).
        urls : list[str]
            URLs present in the alert.
        file_names : list[str]
            File names / paths from the alert.
        eml_provided : bool
            True if .eml files are available.
        logs_provided : bool
            True if log files are available.
        client : str
            Client name (if known).
        severity : str
            Alert severity (low, medium, high, critical).
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
        if client:
            plan_steps.append({
                "step": step_num,
                "phase": "Client Identification",
                "action": f"Call `lookup_client` to validate '{client}' and confirm available platforms.",
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
                "action": "Call `generate_pup_report` for the PUP/PUA deliverable (auto-closes case).",
                "tool": "generate_pup_report",
                "reason": "Lightweight report for unwanted software detections.",
            })
        else:
            step_num += 1
            plan_steps.append({
                "step": step_num,
                "phase": "Output",
                "action": "Call `generate_mdr_report` for the client-facing MDR deliverable (auto-closes case).",
                "tool": "generate_mdr_report",
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
            "client": client or "MUST BE IDENTIFIED — call lookup_client first",
            "plan": plan_steps,
            "skipped_steps": skipped,
            "profile_description": profile.get("description", ""),
            "note": "This plan is advisory. Execute each step by calling the listed tool. "
                    "For fully automated execution, use the `investigate` tool instead.",
        })


# ---------------------------------------------------------------------------
# Tier 2 — Extended Analysis (12 tools)
# ---------------------------------------------------------------------------

def _register_tier2(mcp: FastMCP) -> None:

    @mcp.tool(title="Capture URLs")
    async def capture_urls(case_id: str, urls: list[str]) -> str:
        """Use when the analyst says "capture this page", "screenshot this URL",
        "grab the page source", or when you need to collect web evidence before
        running phishing detection.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Visits each URL and captures: screenshot, full HTML source, HTTP response
        headers, and redirect chain. All artefacts are saved to the case directory.

        **This tool is a prerequisite for ``detect_phishing``** — phishing detection
        analyses the captured page content, so you must capture URLs first.

        If the target site blocks automated browsers (Cloudflare, CAPTCHA), use
        ``start_browser_session`` instead for manual interaction via a disposable
        Docker-based Chrome session.

        Parameters
        ----------
        case_id : str
            Case identifier.
        urls : list[str]
            URLs to capture.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.capture_urls(case_id, urls)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Detect Phishing")
    async def detect_phishing(case_id: str) -> str:
        """Use when the analyst says "is this phishing?", "check for brand
        impersonation", "does this look like a fake login page?", or after
        capturing URLs that may be credential harvesting pages.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Analyses captured page content (HTML, screenshots) for brand impersonation
        indicators — fake login forms, spoofed logos, credential harvesting patterns,
        and known phishing kit signatures.

        **Prerequisite: ``capture_urls`` must be called first.** This tool analyses
        the already-captured page data; it does not visit URLs itself. If no
        captures exist, it will fail.

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
        """Use when the analyst says "analyse this email", "check this phishing email",
        "is this BEC?", "check the headers", or provides .eml files for analysis.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Parses .eml files from the case uploads directory and analyses: sender
        authentication (SPF, DKIM, DMARC), header anomalies, reply-to mismatches,
        embedded URLs, attachments, impersonation indicators, and BEC (Business
        Email Compromise) patterns.

        Upload .eml files to the case's ``uploads/`` directory before calling this
        tool. If no .eml files are found, it will return an error.

        Parameters
        ----------
        case_id : str
            Case identifier. Upload .eml files to the case first.
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
        """Use when the analyst says "correlate the IOCs", "cross-reference the
        indicators", "connect the dots", or when you want to find relationships
        between IOCs across different data sources within the case.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Cross-references IOCs from enrichment results, captured pages, email
        headers, log files, and other case artefacts to identify shared
        infrastructure (e.g. an IP hosting multiple malicious domains, a URL
        found in both email and proxy logs, a hash seen across multiple hosts).

        Useful after enrichment to build a more complete picture of the threat
        actor's infrastructure and identify attack chain links.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.correlate(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Reconstruct Forensic Timeline", annotations={"readOnlyHint": True})
    async def reconstruct_timeline(case_id: str) -> str:
        """Use when the analyst says "build a timeline", "what happened in order?",
        "sequence of events", or "reconstruct the attack chain".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Extracts timestamped events from all case artefacts (email headers, web
        captures, log entries, enrichment data, Velociraptor/MDE ingest) and
        assembles them into a chronological forensic timeline.

        Useful for understanding the attack sequence: initial access -> execution ->
        persistence -> lateral movement -> exfiltration. Particularly valuable for
        complex incidents with multiple data sources where the order of events
        matters for establishing causation.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.reconstruct_timeline(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Cluster Campaign Overlaps", annotations={"readOnlyHint": True})
    async def campaign_cluster(case_id: str) -> str:
        """Use when the analyst says "is this part of a campaign?", "are there related
        incidents?", "link to other cases", "same threat actor?", or when you want
        to check if the current case's IOCs overlap with other investigations.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Compares the current case's IOCs against all other cases in the registry
        to find shared infrastructure — domains, IPs, hashes, or email addresses
        that appear across multiple investigations. Groups related cases into
        campaign clusters.

        This is different from ``recall_cases`` (which searches by specific IOCs
        or keywords). Campaign clustering performs an automated bulk comparison
        of all IOCs in the current case against all other cases.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("campaigns:read")

        from api import actions
        result = await asyncio.to_thread(lambda: actions.run_campaign_cluster(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Recall Prior Cases", annotations={"readOnlyHint": True})
    def recall_cases(
        iocs: list[str] | None = None,
        emails: list[str] | None = None,
        keywords: list[str] | None = None,
    ) -> str:
        """Use when the analyst says "have we seen this before?", "prior art",
        "similar incidents", "search old cases for this IOC", "any history on
        this domain/IP/hash?", or "check previous investigations".

        Searches all prior investigations by IOC values, email addresses, or
        free-text keywords. Returns matching cases with their status, severity,
        and relevant IOC overlap.

        **Data isolation rules apply:** global IOCs (public IPs, domains, hashes,
        CVEs) are searched across all clients, but cross-client matches only
        show IOC overlap and verdict — no case details are exposed. Client-scoped
        IOCs (internal hostnames, private IPs) are only searched within the
        active client's cases.

        This is different from ``campaign_cluster`` (which automatically compares
        all IOCs in a case against all other cases). Use ``recall_cases`` when
        you have specific IOCs or keywords to search for.

        Parameters
        ----------
        iocs : list[str]
            IOC values to search for.
        emails : list[str]
            Email addresses to search for.
        keywords : list[str]
            Free-text keywords.
        """
        _require_scope("investigations:read")

        # Pass the active client for tier-aware filtering
        caller = _get_caller_email()
        active_client = _active_client.get(caller, "") if caller else ""

        from tools.recall import recall
        result = recall(
            iocs=iocs or [],
            emails=emails or [],
            keywords=keywords or [],
            caller_client=active_client,
        )
        return _json(result)

    @mcp.tool(title="Assess Threat Landscape", annotations={"readOnlyHint": True})
    def assess_landscape(
        days: int | None = None,
        client: str | None = None,
    ) -> str:
        """Use when the analyst says "what's trending?", "threat summary",
        "how are we doing?", "show me the landscape", "weekly overview",
        or "what attack types are we seeing?".

        Analyses recent cases to produce a threat landscape assessment:
        attack type distribution, severity trends, common IOC patterns,
        top-targeted clients, and active campaigns. Provides a high-level
        view of the SOC's current workload and threat environment.

        Optionally filter by client or adjust the lookback window.

        Parameters
        ----------
        days : int
            Lookback window in days.
        client : str
            Filter by client name.
        """
        _require_scope("campaigns:read")

        from tools.case_landscape import assess_landscape as _assess
        return _json(_assess(days=days, client=client))

    @mcp.tool(title="Search Threat Articles", annotations={"readOnlyHint": True})
    def search_threat_articles(
        days: int = 7,
        count: int = 20,
        category: str | None = None,
    ) -> str:
        """Use when the analyst says "find threat articles", "what's new in threat
        intel?", "articles for the monthly report", or needs to discover recent
        threat intelligence articles for ET (Emerging Threats) or EV (Emerging
        Vulnerabilities) monthly reporting.

        Searches threat intelligence feeds for recent article candidates, clusters
        them by topic, and de-duplicates against previously published articles.
        Returns a ranked list of candidates for the analyst to review and select.

        After selecting candidates, use ``generate_threat_article`` to produce
        the write-ups.

        Parameters
        ----------
        days : int
            Lookback window.
        count : int
            Maximum number of candidates.
        category : str
            Filter by category (ET or EV).
        """
        _require_scope("campaigns:read")

        from tools.threat_articles import fetch_candidates
        candidates = fetch_candidates(days=days, max_candidates=count, category=category)
        return _json({"candidates": candidates, "count": len(candidates)})

    @mcp.tool(title="Generate Threat Article")
    async def generate_threat_article(
        candidate_urls: list[str],
        analyst: str = "mcp",
        case_id: str | None = None,
    ) -> str:
        """Use after ``search_threat_articles`` when the analyst has selected which
        articles to write up. Trigger phrases: "write up these articles",
        "generate the threat articles", "publish articles 1, 3, 5".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Takes the source URLs of selected threat intelligence articles, fetches
        their content, and generates structured write-ups suitable for monthly
        ET/EV reporting. Each article includes a summary, key findings, IOCs,
        and analyst attribution.

        Parameters
        ----------
        candidate_urls : list[str]
            URLs of the threat articles to write up.
        analyst : str
            Analyst name for attribution.
        case_id : str
            Optional case ID to associate with.
        """
        _require_scope("investigations:submit")

        from tools.threat_articles import generate_articles
        # Build candidate dicts from URLs
        candidates = [{"url": u, "title": u, "id": u} for u in candidate_urls]
        result = await asyncio.to_thread(
            lambda: generate_articles(candidates, analyst=analyst, case_id=case_id)
        )
        return _json({"articles": result, "count": len(result) if result else 0})

    @mcp.tool(title="Web Search (OSINT)", annotations={"readOnlyHint": True})
    def web_search(query: str, max_results: int = 10) -> str:
        """Use when structured enrichment APIs lack data and you need to search the
        open web for context on a threat, IOC, vulnerability, or threat actor.
        Trigger phrases: "search for this", "look this up", "what is this malware
        family?", "find more context on this CVE".

        Performs an OSINT web search via Brave Search API (if configured) or
        DuckDuckGo (free fallback). Returns titles, URLs, and snippets.

        This is a supplementary tool — prefer ``enrich_iocs`` for IOC lookups
        and ``contextualise_cves`` for CVE context. Use ``web_search`` when those
        tools return insufficient data or for general threat intelligence queries.

        Parameters
        ----------
        query : str
            Search query.
        max_results : int
            Maximum number of results.
        """
        _require_scope("investigations:submit")

        from tools.web_search import web_search as _ws
        return _json(_ws(query, max_results=max_results))

    @mcp.tool(title="Generate Executive Summary")
    async def generate_executive_summary(case_id: str) -> str:
        """Use when the analyst says "exec summary", "summary for management",
        "leadership briefing", or "non-technical summary".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Produces a concise, non-technical executive summary suitable for
        senior leadership, client executives, or stakeholders who do not
        need the full technical detail. Covers: what happened, business
        impact, current status, and recommended next steps.

        **Choosing the right report tool:**
        - ``generate_executive_summary`` — non-technical leadership briefing (this tool)
        - ``generate_mdr_report`` — full client-facing MDR deliverable
        - ``generate_report`` — internal technical investigation narrative
        - ``generate_pup_report`` — lightweight PUP/PUA report

        Prerequisites: the investigation should be substantially complete
        (enrichment, analysis, and ideally the main report generated first).

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.generate_exec_summary(case_id))
        return _json(_pop_message(result))


# ---------------------------------------------------------------------------
# Tier 3 — Advanced / Restricted (18 tools)
# ---------------------------------------------------------------------------

def _register_tier3(mcp: FastMCP) -> None:

    @mcp.tool(title="Run KQL Query")
    async def run_kql(
        query: str,
        workspace: str = "",
        max_rows: int = 50,
    ) -> str:
        """Use when the analyst asks to query Sentinel, check sign-in logs, look
        up alerts, search device events, investigate email activity, or run any
        KQL query. Trigger phrases: "check Sentinel", "query the logs",
        "any alerts for this user?", "sign-in history", "device events",
        "email events for this sender".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Executes a read-only KQL query against Azure Sentinel. You should build
        the KQL query yourself based on the analyst's request — do not ask the
        analyst to write KQL.

        Common tables: SecurityIncident, SecurityAlert, SigninLogs,
        AADNonInteractiveUserSignInLogs, DeviceProcessEvents,
        DeviceNetworkEvents, DeviceFileEvents, EmailEvents, EmailUrlInfo,
        IdentityLogonEvents, AuditLogs, OfficeActivity, ThreatIntelligenceIndicator.

        A ``| take`` row limit is automatically appended if the query does not
        already contain one. Default 50 rows; increase ``max_rows`` (up to 1000)
        for pattern analysis that needs more data. Use ``lookup_client`` first
        to resolve the correct workspace if needed. For guided multi-stage
        investigations, see ``load_kql_playbook``.

        Parameters
        ----------
        query : str
            KQL query string.
        workspace : str
            Workspace name or GUID. Falls back to SOCAI_SENTINEL_WORKSPACE env var.
        max_rows : int
            Maximum rows to return (1–1000, default 50). Use higher values for
            pattern analysis (e.g. logon burst detection, timeline reconstruction).
        """
        _require_scope("sentinel:query")

        from tools.sentinel_queries import resolve_kql_workspace as _resolve_kql_workspace
        from scripts.run_kql import run_kql as _run_kql

        query = query.strip()
        if not query:
            return _json({"error": "No KQL query provided."})

        ws_id = _resolve_kql_workspace(workspace.strip())
        if not ws_id:
            return _json({"error": "No workspace resolved. Pass workspace explicitly or set SOCAI_SENTINEL_WORKSPACE."})

        # Enforce client boundary — resolve workspace back to owning client
        _check_workspace_boundary(ws_id)

        limit = max(1, min(int(max_rows), 1000))

        q = query.rstrip().rstrip(";")
        if "| take " not in q.lower() and "| limit " not in q.lower():
            q += f"\n| take {limit}"

        rows = await asyncio.to_thread(lambda: _run_kql(ws_id, q, timeout=60))
        if rows is None:
            return _json({"error": "Query execution failed."})
        return _json({"rows": rows[:limit], "row_count": len(rows), "truncated": len(rows) > limit})

    @mcp.tool(title="Load KQL Playbook", annotations={"readOnlyHint": True})
    def load_kql_playbook(
        playbook_id: str | None = None,
        stage: int | None = None,
        params: dict | None = None,
    ) -> str:
        """Use when the analyst says "run the phishing playbook", "guided investigation",
        "step-by-step KQL", or when you want to follow a structured multi-stage
        Sentinel investigation rather than writing ad-hoc KQL.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Playbooks are pre-built, parameterised KQL investigation workflows — each
        playbook has multiple stages that progressively narrow the investigation.
        For example, the phishing playbook starts with email delivery, then checks
        URL clicks, then device activity.

        **Usage pattern:**
        1. Call with no arguments to list available playbooks
        2. Call with ``playbook_id`` to see its stages and required parameters
        3. Call with ``playbook_id`` + ``stage`` + ``params`` to render ready-to-run KQL
        4. Pass the rendered KQL to ``run_kql`` to execute

        Parameters
        ----------
        playbook_id : str
            Playbook identifier (e.g. "phishing").
        stage : int
            1-based stage number.
        params : dict
            Parameter substitutions for template rendering.
        """
        _require_scope("sentinel:query")

        from tools.kql_playbooks import list_playbooks, load_playbook, render_stage

        if not playbook_id:
            return _json({"playbooks": list_playbooks()})

        pb = load_playbook(playbook_id)
        if not pb:
            return _json({"error": f"Playbook {playbook_id!r} not found."})

        if stage is None:
            return _json(pb)

        rendered = render_stage(pb, stage, params or {})
        return rendered if rendered else _json({"error": f"Stage {stage} not found."})

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
        """Use when the analyst needs a **single ready-to-run Sentinel KQL query**
        that covers an entire investigation scenario in one execution.  Unlike
        ``load_kql_playbook`` (multi-stage, one query at a time), this returns a
        composite query with multiple ``let`` sections unioned together — run it
        once and get the full picture.

        Trigger phrases: "composite query for mailbox changes", "full picture
        query", "catch-all query for this sign-in", "BEC query", "DLP query",
        "OAuth consent query", "generate Sentinel query".

        **Available scenarios:**
        - ``mailbox-permission-change`` — delegation, FullAccess, SendAs changes
        - ``suspicious-signin`` — risky sign-ins, location anomalies, MFA bypass
        - ``inbox-rule-bec`` — inbox rules, mail forwarding, BEC indicators
        - ``email-threat-zap`` — email threats, ZAP actions, post-delivery activity
        - ``dlp-exfiltration`` — DLP alerts, bulk downloads, external sharing
        - ``oauth-consent-grant`` — OAuth consent, app role assignments, post-consent activity

        Call with no ``scenario`` to list available scenarios.

        Uses only Sentinel-native tables (OfficeActivity, SigninLogs,
        SecurityAlert, AlertEvidence).  Pass the returned query directly
        to ``run_kql`` for execution.

        Parameters
        ----------
        scenario : str
            Scenario identifier (e.g. "suspicious-signin").  Empty to list all.
        upn : str
            Primary target User Principal Name (required for all scenarios).
        ip : str
            Optional suspicious IP address.
        object_id : str
            Optional Azure AD object ID.
        mailbox_id : str
            Optional mailbox GUID (OfficeObjectId from OfficeActivity).
        additional_upns : str
            Comma-separated additional UPNs to include in query scope.
        lookback_hours : int
            Lookback window in hours (default 24, max 720).
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

    @mcp.tool(title="Security Architecture Review")
    async def security_arch_review(case_id: str) -> str:
        """Use when the analyst says "what security gaps does this reveal?",
        "architecture review", "what controls failed?", "how could this have
        been prevented?", or "security recommendations".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Analyses the case findings to identify security architecture gaps and
        control failures that allowed the incident to occur. Produces
        recommendations for preventive controls, detection improvements,
        and architectural changes specific to the client's environment.

        Prerequisites: the investigation should be substantially complete
        (enrichment, correlation, and ideally the main report generated).

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.security_arch_review(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Contextualise CVEs", annotations={"readOnlyHint": True})
    async def contextualise_cves(case_id: str) -> str:
        """Use when the analyst says "check these CVEs", "are any of these
        exploited?", "CVE context", "vulnerability details", or when the
        case contains CVE identifiers that need contextualisation.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Looks up CVEs found in the case artefacts against NVD (severity, vector,
        description), EPSS (exploitation probability score), and CISA KEV
        (Known Exploited Vulnerabilities catalogue). Helps prioritise which
        vulnerabilities are actively exploited in the wild vs theoretical risks.

        For general vulnerability research not tied to a case, use ``web_search``
        instead.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:read")

        from api import actions
        result = await asyncio.to_thread(lambda: actions.contextualise_cves(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Ingest Velociraptor Collection")
    async def ingest_velociraptor(case_id: str, run_analysis: bool = True) -> str:
        """Use when the analyst says "ingest the Velociraptor collection",
        "process the offline collector", or when Velociraptor artefacts
        (offline collector ZIP, VQL JSON exports, or result directories)
        have been uploaded to the case.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Parses and normalises Velociraptor data: EVTX logs, autoruns,
        netstat, running processes, services, scheduled tasks, prefetch,
        shimcache, amcache, MFT, and USN journal entries.

        Set ``run_analysis=True`` (default) to automatically extract IOCs,
        enrich, and correlate after ingest. Set ``run_analysis=False`` if
        you want to review the raw normalised data first.

        For MDE investigation packages, use ``ingest_mde_package`` instead.

        Parameters
        ----------
        case_id : str
            Case identifier.
        run_analysis : bool
            Run analysis pipeline after ingest (extract, enrich, correlate).
        """
        _require_scope("investigations:submit")

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.ingest_velociraptor(case_id, run_analysis=run_analysis)
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Ingest MDE Investigation Package")
    async def ingest_mde_package(case_id: str, run_analysis: bool = True) -> str:
        """Use when the analyst says "ingest the MDE package", "process the Defender
        investigation package", or when a Microsoft Defender for Endpoint
        investigation package ZIP has been uploaded to the case.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Parses and normalises MDE investigation package data using 13 specialised
        normalisers. This is the alternative to ``ingest_velociraptor`` when the
        endpoint data comes from MDE rather than Velociraptor.

        Set ``run_analysis=True`` (default) to automatically extract IOCs,
        enrich, and correlate after ingest. Set ``run_analysis=False`` to
        review raw normalised data first.

        For Velociraptor collections, use ``ingest_velociraptor`` instead.

        Parameters
        ----------
        case_id : str
            Case identifier.
        run_analysis : bool
            Run analysis pipeline after ingest.
        """
        _require_scope("investigations:submit")

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
        """Use when the analyst says "weekly report", "SOC rollup", "weekly summary",
        or "what happened this week?".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Generates a weekly SOC report summarising all cases for the specified
        ISO week: case count by severity and disposition, notable incidents,
        attack type distribution, and operational metrics.

        Defaults to the current week. Use ``year`` and ``week`` to generate
        historical reports. Set ``include_open=True`` to include cases that
        are still open (by default only closed cases are included).

        Parameters
        ----------
        year : int
            ISO year. Defaults to current.
        week : int
            ISO week number. Defaults to current.
        include_open : bool
            Include open cases.
        """
        _require_scope("investigations:read")

        from tools.generate_weekly_report import generate_weekly_report
        result = await asyncio.to_thread(
            lambda: generate_weekly_report(year=year, week=week, include_open=include_open)
        )
        return _json(result)

    @mcp.tool(title="Link Related Cases")
    def link_cases(
        case_a: str,
        case_b: str,
        link_type: str = "related",
        canonical: str | None = None,
        reason: str = "",
    ) -> str:
        """Use when the analyst says "link these cases", "these are related",
        "this is a duplicate of", or "mark as parent case".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Creates a bidirectional link between two cases. Use this when
        investigations share IOCs, involve the same threat actor, or are
        different phases of the same incident. Linked cases are referenced
        in reports and campaign clustering.

        For merging cases (moving artefacts into one), use ``merge_cases`` instead.

        Parameters
        ----------
        case_a : str
            First case ID.
        case_b : str
            Second case ID.
        link_type : str
            Link type: "related", "duplicate", "parent-child".
        canonical : str
            Canonical (primary) case ID.
        reason : str
            Reason for linking.
        """
        _require_scope("investigations:submit")

        from tools.case_links import link_cases as _link
        return _json(_link(case_a, case_b, link_type, canonical=canonical, reason=reason))

    @mcp.tool(title="Merge Duplicate Cases", annotations={"destructiveHint": True})
    def merge_cases(source_ids: list[str], target_id: str) -> str:
        """Use when the analyst says "merge these cases", "combine into one case",
        or when duplicate investigations need to be consolidated.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        **Destructive operation:** moves all artefacts and IOCs from source cases
        into the target case. Source cases are marked as merged. This cannot be
        easily undone.

        For non-destructive linking (keeping cases separate but noting the
        relationship), use ``link_cases`` instead.

        Parameters
        ----------
        source_ids : list[str]
            Case IDs to merge from.
        target_id : str
            Case ID to merge into.
        """
        _require_scope("admin")

        from tools.case_links import merge_cases as _merge
        return _json(_merge(source_ids, target_id))

    @mcp.tool(title="Recommend Response Actions")
    async def response_actions(case_id: str) -> str:
        """Use when the analyst says "what should we do?", "containment steps",
        "remediation plan", "response actions", "how do we respond?", or
        "next steps for containment".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Generates an advisory response action plan based on the case findings,
        client's platform capabilities, and escalation playbook. Includes
        containment actions, remediation steps, permitted actions per the
        client agreement, and escalation contact details.

        **Advisory only** — this tool recommends actions but does not execute
        anything. The analyst must carry out the recommended actions manually
        or via the appropriate platform.

        Prerequisites: the case should have enrichment and ideally correlation
        completed so the response plan is informed by verdicts.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.response_actions import generate_response_actions
        result = await asyncio.to_thread(lambda: generate_response_actions(case_id))
        return _json(result)

    @mcp.tool(title="Generate False Positive Ticket")
    async def generate_fp_ticket(
        case_id: str,
        alert_data: str,
        platform: str | None = None,
        query_text: str | None = None,
    ) -> str:
        """Use when the analyst says "this is a false positive", "suppress this alert",
        "FP ticket", "tuning request", or when an alert has been determined to be
        a false positive and needs a suppression/tuning ticket.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Generates a structured false-positive suppression ticket with: alert details,
        analyst justification, recommended suppression logic, and platform-specific
        tuning guidance. The ticket can be used to request rule tuning from the
        detection engineering team.

        **Auto-closes the case** with disposition "false_positive".

        Provide the raw alert JSON in ``alert_data``. The detection platform is
        auto-detected from the alert data but can be overridden with ``platform``.

        Parameters
        ----------
        case_id : str
            Case identifier.
        alert_data : str
            Raw alert JSON.
        platform : str
            Detection platform (auto-detected if omitted).
        query_text : str
            Original detection query text.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.generate_fp_ticket(
                case_id, alert_data=alert_data,
                platform=platform, query_text=query_text,
            )
        )
        return _json(_pop_message(result))

    @mcp.tool(title="Generate SIEM Tuning Ticket")
    async def generate_fp_tuning_ticket(
        case_id: str,
        alert_data: str,
        platform: str | None = None,
        query_text: str | None = None,
    ) -> str:
        """Use when the analyst says "tuning ticket", "SIEM engineering ticket",
        "detection engineering handoff", "rule tuning", or "fix the detection".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Generates a structured SIEM engineering tuning ticket with: detection rule
        identification, original query, false positive evidence, root cause analysis,
        proposed tuning (before/after query modifications), impact assessment, and
        recurrence data from prior cases.

        This is the engineering handoff document — it gives detection engineers
        everything they need to modify the rule. Use this AFTER or alongside
        ``generate_fp_ticket`` (which produces the analyst closure comment).

        **Does NOT auto-close the case** — the analyst may want both an FP closure
        comment and a tuning ticket.

        Parameters
        ----------
        case_id : str
            Case identifier.
        alert_data : str
            Raw alert JSON.
        platform : str
            Detection platform (auto-detected if omitted).
        query_text : str
            Original detection query text.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.fp_tuning_ticket import fp_tuning_ticket
        result = await asyncio.to_thread(
            lambda: fp_tuning_ticket(
                case_id, alert_data=alert_data,
                platform=platform, query_text=query_text,
            )
        )
        return _json(result)

    @mcp.tool(title="Start Sandbox Detonation", annotations={"destructiveHint": True})
    async def start_sandbox_session(
        sample_path: str,
        case_id: str,
        timeout: int = 120,
        network_mode: str = "monitor",
        interactive: bool = False,
    ) -> str:
        """Use when the analyst says "detonate this sample", "run it in a sandbox",
        "dynamic analysis", "execute the malware", or "sandbox this file".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Starts a containerised sandbox session for dynamic malware analysis.
        The sample is executed in an isolated Docker container under strace
        (syscall tracing) and tcpdump (network capture). Supports ELF binaries,
        scripts, and PE files (via Wine). Honeypot DNS/HTTP services catch
        C2 callbacks.

        **Destructive/dangerous:** executes actual malware. Use ``network_mode="isolate"``
        to prevent outbound network access. Use ``interactive=True`` for a shell
        session to manually interact with the sample.

        After detonation, call ``stop_sandbox_session`` to collect artefacts
        (strace logs, pcap, filesystem changes).

        Parameters
        ----------
        sample_path : str
            Absolute path to sample file.
        case_id : str
            Case identifier for artefact storage.
        timeout : int
            Execution timeout in seconds.
        network_mode : str
            "monitor" (default) or "isolate".
        interactive : bool
            Enable interactive shell mode.
        """
        _require_scope("admin")

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

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

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
    async def start_browser_session(url: str, case_id: str) -> str:
        """Use when the analyst says "open this in a browser", "I need to interact
        with the page", "Cloudflare is blocking", "CAPTCHA", or when automated
        URL capture (``capture_urls``) fails due to bot protection.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Starts a disposable Docker-based Chrome session with CDP (Chrome DevTools
        Protocol) network monitoring. Returns a noVNC URL for the analyst to
        visually interact with the page — useful for bypassing Cloudflare,
        solving CAPTCHAs, or navigating multi-step phishing flows.

        All network traffic is captured automatically. Call ``stop_browser_session``
        when done to collect the artefacts.

        Parameters
        ----------
        url : str
            URL to load in the browser.
        case_id : str
            Case identifier for artefact storage.
        """
        _require_scope("admin")

        from tools.browser_session import start_session
        result = await asyncio.to_thread(lambda: start_session(url, case_id))
        return _json(result)

    @mcp.tool(title="Stop Browser Session", annotations={"destructiveHint": True})
    def stop_browser_session(session_id: str) -> str:
        """Use to stop a running disposable browser session and collect network
        artefacts (captured requests, responses, redirects). Call this after
        the analyst has finished interacting with the page via noVNC.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

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


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_tools(mcp: FastMCP) -> None:
    """Register all MCP tool handlers on the given FastMCP instance."""
    _register_tier1(mcp)
    _register_tier2(mcp)
    _register_tier3(mcp)
