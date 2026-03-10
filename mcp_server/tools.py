"""MCP tool wrappers — expose socai investigation tools with RBAC.

Each tool is registered on a ``FastMCP`` instance via ``register_tools(mcp)``.
All tools validate permissions using ``_require_scope()`` before delegating to
the existing action / tool layer.

Tools are organised in three tiers:
  Tier 1 (15) — Core Investigation   (Phase 1)
  Tier 2 (12) — Extended Analysis    (Phase 2)
  Tier 3 (17) — Advanced / Restricted (Phase 3)
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


def _check_client_boundary(case_id: str) -> None:
    """Verify the case's client matches the active client for this user.

    Raises ``ToolError`` if the analyst is switching to a different client
    mid-conversation, instructing them to start a new chat session.
    """
    caller = _get_caller_email()
    if not caller:
        return  # stdio / no auth — skip enforcement

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
# Tier 1 — Core Investigation (15 tools)
# ---------------------------------------------------------------------------

def _register_tier1(mcp: FastMCP) -> None:

    @mcp.tool(annotations={"openWorldHint": True})
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
        """Run the full SOC investigation pipeline (16 steps).

        Long-running (2-10 min). By default returns a job_id for polling via
        ``get_case``. Set ``wait=True`` to block and receive progress updates.

        Parameters
        ----------
        case_id : str
            Unique case identifier, e.g. "C001".
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

    @mcp.tool(annotations={"openWorldHint": True})
    async def quick_investigate_url(
        url: str,
        severity: str = "medium",
        analyst: str = "unassigned",
        tags: list[str] | None = None,
        wait: bool = False,
    ) -> str:
        """Quick investigation of a URL — auto-generates case ID, runs pipeline.

        Long-running (2-10 min). Returns immediately with the case_id by default.

        **Full workflow after calling this tool:**
        1. Call ``get_case(case_id)`` every 30s until ``pipeline_complete`` is true
        2. Call ``read_report(case_id)`` to read the investigation report
        3. Summarise the findings for the user
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

        from api.jobs import JobManager
        from agents.chief import ChiefAgent

        case_id = JobManager.next_case_id()

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

    @mcp.tool(annotations={"openWorldHint": True})
    async def quick_investigate_domain(
        domain: str,
        severity: str = "medium",
        analyst: str = "unassigned",
        tags: list[str] | None = None,
        wait: bool = False,
    ) -> str:
        """Quick investigation of a domain — prefixes https://, auto-generates case ID.

        Long-running (2-10 min). Returns immediately with the case_id by default.

        **Full workflow after calling this tool:**
        1. Call ``get_case(case_id)`` every 30s until ``pipeline_complete`` is true
        2. Call ``read_report(case_id)`` to read the investigation report
        3. Summarise the findings for the user
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

        from api.jobs import JobManager
        from agents.chief import ChiefAgent

        case_id = JobManager.next_case_id()
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

    @mcp.tool(annotations={"openWorldHint": True})
    async def quick_investigate_file(
        file_path: str,
        severity: str = "medium",
        analyst: str = "unassigned",
        zip_pass: str | None = None,
        tags: list[str] | None = None,
        wait: bool = False,
    ) -> str:
        """Quick investigation of a file — auto-generates case ID, runs pipeline.

        Long-running (2-10 min). Returns immediately with the case_id by default.

        **Full workflow after calling this tool:**
        1. Call ``get_case(case_id)`` every 30s until ``pipeline_complete`` is true
        2. Call ``read_report(case_id)`` to read the investigation report
        3. Summarise the findings for the user
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

        from api.jobs import JobManager
        from agents.chief import ChiefAgent

        case_id = JobManager.next_case_id()
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

    @mcp.tool(annotations={"readOnlyHint": True})
    def lookup_client(client_name: str) -> str:
        """Look up a client's configuration and platform scope.

        Returns the client's available security platforms (Sentinel workspace,
        XDR tenant, CrowdStrike CID, Encore) and escalation playbook.
        Use this to confirm which client an incident belongs to and which
        platforms you have access to for that client.

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

    @mcp.tool(annotations={"readOnlyHint": True})
    def list_cases() -> str:
        """List all registered SOC cases from the case registry."""
        _require_scope("investigations:read")

        from config.settings import REGISTRY_FILE
        from tools.common import load_json

        if not REGISTRY_FILE.exists():
            return _json({"cases": {}, "message": "No registry found."})
        return _json(load_json(REGISTRY_FILE))

    @mcp.tool(annotations={"readOnlyHint": True})
    def get_case(case_id: str) -> str:
        """Retrieve metadata for a specific case.

        Use this to poll for investigation progress after submitting via
        ``investigate``, ``quick_investigate_url``, ``quick_investigate_domain``,
        or ``quick_investigate_file``. The investigation is complete when
        ``pipeline_complete`` is true or ``report_path`` is present. If
        still running, wait 30 seconds then poll again.

        **Once ``pipeline_complete`` is true and status is "open", you should
        read the report with ``read_report``, summarise the findings for the
        user, and then call ``close_case`` to close the investigation.**

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "C001".
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

    @mcp.tool()
    def read_report(case_id: str) -> str:
        """Read the investigation Markdown report for a case.

        Also auto-closes the case if the pipeline is complete and the case
        is still open (disposition: "resolved").

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "C001".
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

    @mcp.tool(annotations={"readOnlyHint": True})
    def read_case_file(case_id: str, file_path: str) -> str:
        """Read any artefact file from a case directory by relative path.

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

    @mcp.tool()
    def close_case(
        case_id: str,
        disposition: str = "resolved",
    ) -> str:
        """Close an investigation case. Call this after the pipeline completes
        and you have reviewed / summarised the findings for the user.

        This is the normal final step of every investigation workflow:
        investigate → poll get_case → read_report → summarise → **close_case**.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "C001".
        disposition : str
            Closing disposition. One of: "true_positive", "false_positive",
            "benign", "inconclusive", "resolved". Default "resolved".
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from tools.index_case import index_case
        return _json(index_case(case_id, status="closed", disposition=disposition))

    @mcp.tool()
    async def add_evidence(case_id: str, text: str) -> str:
        """Add analyst input, observations, or IOCs to an existing case.

        Parses the text for IOCs (URLs, IPs, hashes, emails, CVEs), appends
        it to the case's ``notes/analyst_input.md``, and returns what was
        extracted. Follow up with ``enrich_iocs`` to enrich newly added IOCs.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "C001".
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

    @mcp.tool()
    def add_finding(
        case_id: str,
        finding_type: str,
        summary: str,
        detail: str = "",
    ) -> str:
        """Record a key investigation finding against a case.

        Use this to capture important observations, conclusions, or interim
        results during an investigation. Findings are appended to the case
        notes and referenced in report generation.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "C001".
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

    @mcp.tool()
    async def enrich_iocs(case_id: str, include_private: bool = False) -> str:
        """Re-run IOC extraction, enrichment, and scoring for a case.

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

    @mcp.tool()
    async def generate_report(case_id: str, close_case: bool = False) -> str:
        """Generate or regenerate the investigation report for a case.

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

    @mcp.tool()
    async def generate_mdr_report(case_id: str) -> str:
        """Generate a structured MDR (Managed Detection & Response) report.

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

    @mcp.tool()
    async def generate_pup_report(case_id: str) -> str:
        """Generate a PUP/PUA (Potentially Unwanted Program/Application) report.

        Use instead of generate_mdr_report when the detection is unwanted software
        (adware, bundleware, browser hijacker, toolbar, etc.) rather than an active
        compromise or targeted attack.

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

    @mcp.tool()
    async def generate_queries(
        case_id: str,
        platforms: list[str] | None = None,
        tables: list[str] | None = None,
    ) -> str:
        """Generate SIEM hunt queries from case IOCs and threat patterns.

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


# ---------------------------------------------------------------------------
# Tier 2 — Extended Analysis (12 tools)
# ---------------------------------------------------------------------------

def _register_tier2(mcp: FastMCP) -> None:

    @mcp.tool()
    async def capture_urls(case_id: str, urls: list[str]) -> str:
        """Capture web pages (screenshots, HTML, headers, redirects).

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

    @mcp.tool()
    async def detect_phishing(case_id: str) -> str:
        """Run brand-impersonation detection on captured pages.

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

    @mcp.tool()
    async def analyse_email(case_id: str) -> str:
        """Analyse .eml email files in the case uploads directory.

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

    @mcp.tool()
    async def correlate(case_id: str) -> str:
        """Cross-reference IOCs across case artefacts for correlation hits.

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

    @mcp.tool(annotations={"readOnlyHint": True})
    async def reconstruct_timeline(case_id: str) -> str:
        """Reconstruct forensic timeline from all case artefacts.

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

    @mcp.tool(annotations={"readOnlyHint": True})
    async def campaign_cluster(case_id: str) -> str:
        """Run cross-case campaign clustering for a case's IOCs.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("campaigns:read")

        from api import actions
        result = await asyncio.to_thread(lambda: actions.run_campaign_cluster(case_id))
        return _json(_pop_message(result))

    @mcp.tool(annotations={"readOnlyHint": True})
    def recall_cases(
        iocs: list[str] | None = None,
        emails: list[str] | None = None,
        keywords: list[str] | None = None,
    ) -> str:
        """Search prior investigations by IOCs, emails, or keywords.

        Cross-case search respects the data hierarchy:
        - **Global IOCs** (public IPs, domains, hashes, CVEs) are searched
          across ALL clients.  Cross-client matches show IOC overlap and
          verdict only — no case details are exposed.
        - **Client-scoped IOCs** (internal hostnames, private IPs) are only
          searched within the active client's cases.
        - **Case details** (findings, reports, timeline) are only returned
          for same-client cases.

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

    @mcp.tool(annotations={"readOnlyHint": True})
    def assess_landscape(
        days: int | None = None,
        client: str | None = None,
    ) -> str:
        """Assess the current threat landscape across recent cases.

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

    @mcp.tool(annotations={"readOnlyHint": True})
    def search_threat_articles(
        days: int = 7,
        count: int = 20,
        category: str | None = None,
    ) -> str:
        """Search for recent threat article candidates for monthly reporting.

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

    @mcp.tool()
    async def generate_threat_article(
        candidate_urls: list[str],
        analyst: str = "mcp",
        case_id: str | None = None,
    ) -> str:
        """Generate threat articles from candidate URLs.

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

    @mcp.tool(annotations={"readOnlyHint": True})
    def web_search(query: str, max_results: int = 10) -> str:
        """OSINT web search fallback (Brave Search API or DuckDuckGo).

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

    @mcp.tool()
    async def generate_executive_summary(case_id: str) -> str:
        """Generate an executive summary for leadership.

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
# Tier 3 — Advanced / Restricted (17 tools)
# ---------------------------------------------------------------------------

def _register_tier3(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_kql(
        query: str,
        workspace: str = "",
    ) -> str:
        """Execute a read-only KQL query against Azure Sentinel.

        A ``| take 50`` row limit is enforced for safety.

        Parameters
        ----------
        query : str
            KQL query string.
        workspace : str
            Workspace name or GUID. Falls back to SOCAI_SENTINEL_WORKSPACE env var.
        """
        _require_scope("sentinel:query")

        from api.chat import _resolve_kql_workspace
        from scripts.run_kql import run_kql as _run_kql

        query = query.strip()
        if not query:
            return _json({"error": "No KQL query provided."})

        ws_id = _resolve_kql_workspace(workspace.strip())
        if not ws_id:
            return _json({"error": "No workspace resolved. Pass workspace explicitly or set SOCAI_SENTINEL_WORKSPACE."})

        # Enforce client boundary — resolve workspace back to owning client
        _check_workspace_boundary(ws_id)

        q = query.rstrip().rstrip(";")
        if "| take " not in q.lower() and "| limit " not in q.lower():
            q += "\n| take 50"

        rows = await asyncio.to_thread(lambda: _run_kql(ws_id, q, timeout=60))
        if rows is None:
            return _json({"error": "Query execution failed."})
        return _json({"rows": rows[:50], "row_count": len(rows)})

    @mcp.tool(annotations={"readOnlyHint": True})
    def load_kql_playbook(
        playbook_id: str | None = None,
        stage: int | None = None,
        params: dict | None = None,
    ) -> str:
        """Load parameterised KQL investigation playbooks.

        Call without arguments to list all playbooks. With ``playbook_id`` to
        see stages. With ``playbook_id`` + ``stage`` + ``params`` to render
        ready-to-run KQL.

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

    @mcp.tool()
    async def security_arch_review(case_id: str) -> str:
        """Run an LLM-based security architecture review.

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

    @mcp.tool(annotations={"readOnlyHint": True})
    async def contextualise_cves(case_id: str) -> str:
        """Contextualise CVEs found in case artefacts (NVD, EPSS, CISA KEV).

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:read")

        from api import actions
        result = await asyncio.to_thread(lambda: actions.contextualise_cves(case_id))
        return _json(_pop_message(result))

    @mcp.tool()
    async def ingest_velociraptor(case_id: str, run_analysis: bool = True) -> str:
        """Ingest Velociraptor collection data from case uploads.

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

    @mcp.tool()
    async def ingest_mde_package(case_id: str, run_analysis: bool = True) -> str:
        """Ingest MDE investigation package from case uploads.

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

    @mcp.tool(annotations={"readOnlyHint": True})
    async def generate_weekly(
        year: int | None = None,
        week: int | None = None,
        include_open: bool = False,
    ) -> str:
        """Generate a weekly SOC rollup report.

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

    @mcp.tool()
    def link_cases(
        case_a: str,
        case_b: str,
        link_type: str = "related",
        canonical: str | None = None,
        reason: str = "",
    ) -> str:
        """Link two related cases.

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

    @mcp.tool(annotations={"destructiveHint": True})
    def merge_cases(source_ids: list[str], target_id: str) -> str:
        """Merge multiple source cases into a target case.

        Destructive — moves artefacts and IOCs from sources into target.

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

    @mcp.tool()
    async def response_actions(case_id: str) -> str:
        """Generate advisory response action plan (no execution).

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

    @mcp.tool()
    async def generate_fp_ticket(
        case_id: str,
        alert_data: str,
        platform: str | None = None,
        query_text: str | None = None,
    ) -> str:
        """Generate a false-positive suppression ticket.

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

    @mcp.tool(annotations={"destructiveHint": True})
    async def start_sandbox_session(
        sample_path: str,
        case_id: str,
        timeout: int = 120,
        network_mode: str = "monitor",
        interactive: bool = False,
    ) -> str:
        """Start a containerised sandbox session for dynamic malware analysis.

        Executes ELF/scripts/PE (via Wine) under strace with tcpdump monitoring.

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

    @mcp.tool(annotations={"destructiveHint": True})
    def stop_sandbox_session(session_id: str) -> str:
        """Stop a running sandbox session and collect artefacts.

        Parameters
        ----------
        session_id : str
            Sandbox session ID.
        """
        _require_scope("admin")

        from tools.sandbox_session import stop_session
        return _json(stop_session(session_id))

    @mcp.tool(annotations={"readOnlyHint": True})
    def list_sandbox_sessions() -> str:
        """List all active and recent sandbox sessions."""
        _require_scope("admin")

        from tools.sandbox_session import list_sessions
        return _json({"sessions": list_sessions()})

    @mcp.tool(annotations={"destructiveHint": True})
    async def start_browser_session(url: str, case_id: str) -> str:
        """Start a disposable Docker-based Chrome session with CDP monitoring.

        Returns a noVNC URL for visual interaction.

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

    @mcp.tool(annotations={"destructiveHint": True})
    def stop_browser_session(session_id: str) -> str:
        """Stop a browser session and collect network artefacts.

        Parameters
        ----------
        session_id : str
            Browser session ID.
        """
        _require_scope("admin")

        from tools.browser_session import stop_session
        return _json(stop_session(session_id))

    @mcp.tool(annotations={"readOnlyHint": True})
    def list_browser_sessions() -> str:
        """List all active and recent browser sessions."""
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
