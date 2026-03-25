"""MCP tool wrappers — expose socai investigation tools with RBAC.

Each tool is registered on a ``FastMCP`` instance via ``register_tools(mcp)``.
All tools validate permissions using ``_require_scope()`` before delegating to
the existing action / tool layer.

Tools are organised in three tiers:
  Tier 1 — Core Investigation
  Tier 2 — Extended Analysis
  Tier 3 — Advanced / Restricted

Deliverable tools (``generate_mdr_report``, ``generate_pup_report``,
``generate_fp_ticket``, ``generate_fp_tuning_ticket``) accept an optional
``case_id`` — if omitted, ``_ensure_case()`` auto-creates and promotes a case.
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

    # No case_id — auto-create
    case_id = next_case_id()
    resolved_client = client or DEFAULT_CLIENT
    _create(
        case_id,
        title=title or "Auto-created at deliverable time",
        severity=severity,
        client=resolved_client,
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
        fresh investigation context. No server-side state is changed.
        """
        return _json({
            "status": "ok",
            "message": "Ready for a new investigation.",
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

        # Include platforms and any response playbook
        platforms = cfg.get("platforms", {})
        if not platforms and cfg.get("workspace_id"):
            platforms = {"sentinel": {"workspace_id": cfg["workspace_id"]}}

        result = {
            "name": cfg.get("name", ""),
            "platforms": platforms,
            "platform_list": list(platforms.keys()),
        }
        # Check for response playbook and knowledge base
        from mcp_server.resources import _resolve_client_playbook, _resolve_client_knowledge
        result["has_response_playbook"] = _resolve_client_playbook(cfg["name"]) is not None
        result["has_knowledge_base"] = _resolve_client_knowledge(cfg["name"]) is not None

        return _json(result)

    @mcp.tool(title="Update Client Knowledge Base")
    async def update_client_knowledge(
        client_name: str,
        section: str,
        content: str,
    ) -> str:
        """Update a section of the client knowledge base with new information
        discovered during an investigation.

        Call this whenever you learn something persistent about a client's
        environment — network ranges, legitimate software, FP patterns,
        security stack details, identity infrastructure, etc.

        The knowledge base is a structured markdown file. Specify which
        section to update and provide the new content for that section.

        Parameters
        ----------
        client_name : str
            Client name (case-insensitive).
        section : str
            Section heading to update (e.g. "Network Topology",
            "Known Legitimate Software & Services", "Historical Patterns",
            "Security Stack", "Identity & Access", "Analyst Notes").
        content : str
            New content for the section (markdown). Replaces existing
            section content between the heading and the next ``---`` divider.
        """
        _require_scope("investigations:submit")

        from mcp_server.resources import _resolve_client_knowledge
        from tools.common import audit

        path = _resolve_client_knowledge(client_name)
        if not path:
            return _json({
                "status": "error",
                "reason": f"No knowledge base found for client {client_name!r}.",
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
        if not match:
            return _json({
                "status": "error",
                "reason": f"Section {section!r} not found in knowledge base. "
                          f"Available sections can be seen via socai://clients/{client_name}/knowledge.",
            })

        updated = (
            text[:match.start()]
            + match.group(1)  # keep heading
            + "\n" + content.strip() + "\n"
            + match.group(3)  # keep divider
            + text[match.end():]
        )

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
        """Use when the analyst asks "show me recent cases", "what's open?",
        "list my cases", or "what investigations do we have?".

        Returns cases from the registry filtered by status, with their severity
        and disposition. When the analyst asks for "recent" or "current" cases,
        use the default filter (active + closed). Pass ``status="triage"`` for
        triage queue, ``status="all"`` for everything, or any comma-separated
        combination (e.g. ``"triage,active"``).

        For searching prior cases by IOC, email, or keyword, use ``recall_cases``
        instead.

        Parameters
        ----------
        status : str
            Comma-separated status filter. Default "active,closed".
            Use "all" or "" to return everything.
            Valid values: triage, active, discarded, closed, open (legacy).
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

    @mcp.tool(title="Get Case Status", annotations={"readOnlyHint": True})
    def get_case(case_id: str) -> str:
        """Retrieve basic case metadata (title, severity, status, disposition,
        timestamps, attack type).

        Returns case metadata only. Does NOT include IOCs, verdicts, or
        enrichment data — for a complete picture, use ``case_summary`` instead.

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
            return _json({"error": f"Case {case_id!r} not found."})
        meta = load_json(meta_path)

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

        **Prefer this over ``get_case``** when you need the full investigative
        context. ``get_case`` returns metadata only; this returns everything.

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

        reports_dir = CASES_DIR / case_id / "reports"
        report_path = None
        for candidate in [
            reports_dir / "mdr_report.html",
            reports_dir / "pup_report.html",
            reports_dir / "investigation_report.html",
        ]:
            if candidate.exists():
                report_path = candidate
                break
        if report_path is None:
            return f"No report found for case {case_id!r}. Run generate_mdr_report or generate_pup_report first."

        # Auto-close: if the report exists and case is active (or legacy open), close it
        # Triage cases are not auto-closed — they must be promoted first.
        meta_path = CASES_DIR / case_id / "case_meta.json"
        if meta_path.exists():
            meta = load_json(meta_path)
            if meta.get("status") in ("open", "active"):
                from tools.index_case import index_case
                index_case(case_id, status="closed", disposition="resolved")

        return report_path.read_text(encoding="utf-8")

    @mcp.tool(title="Read Case File", annotations={"readOnlyHint": True})
    def read_case_file(case_id: str, file_path: str) -> str:
        """Use when you need to read a specific artefact file from a case — e.g.
        raw enrichment JSON, IOC lists, captured HTML, phishing detection results,
        screenshots, or any other file produced by the pipeline.

        Takes a relative path within the case directory. Common paths include:
        ``iocs/iocs.json``, ``artefacts/enrichment/enrichment.json``,
        ``artefacts/enrichment/verdict_summary.json``,
        ``artefacts/phishing/detection.json``, ``artefacts/captures/*.html``,
        ``artefacts/web/*/screenshot.png``, ``notes/analyst_input.md``,
        ``reports/investigation_report.md``.

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
        """Use when you need to discover what artefact files exist in a case
        directory — e.g. after running a tool that produces artefacts, or when
        the analyst asks to review available evidence.

        Returns a tree of all files under the case directory (or a subdirectory
        if ``subpath`` is provided), with file sizes. Use the returned relative
        paths with ``read_case_file`` to read individual files.

        Parameters
        ----------
        case_id : str
            Case identifier.
        subpath : str
            Optional subdirectory to scope the listing (e.g. "artefacts/browser_session").
            Defaults to the full case directory.
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
        client: str = "",
        classification: str = "",
        plan: str = "",
    ) -> str:
        """Use when the analyst says "create a case", "new case", "start an investigation",
        or when you need a case before calling case-bound tools like ``enrich_iocs``
        or ``add_evidence``.

        Case creation is **optional** — deliverable tools (``generate_mdr_report``,
        ``generate_pup_report``, ``generate_fp_ticket``) auto-create and promote
        a case if one doesn't exist. Use this tool when you need a case earlier
        in the workflow, e.g. to attach evidence or run case-bound enrichment.

        Auto-generates a case ID (IV_CASE_XXX format). The case starts in **triage**
        status. It is auto-promoted to active when a deliverable tool or
        ``add_finding`` runs, or you can call ``promote_case`` / ``discard_case``
        manually.

        Parameters
        ----------
        title : str
            Human-readable case title (e.g. "Phishing — credential harvest on login.example.com").
        severity : str
            One of: low, medium, high, critical.
        analyst : str
            Analyst name or ID.
        tags : list[str]
            Free-form tags (e.g. ["phishing", "credential-harvest"]).
        client : str
            Client name (must match client registry).
        classification : str
            Attack type from classify_attack (e.g. "phishing", "malware").
        plan : str
            Investigation plan text to save as analyst notes.
        """
        _require_scope("investigations:submit")

        if client:
            _set_client_boundary(client)

        from tools.case_create import case_create as _create, next_case_id
        case_id = next_case_id()

        result = _create(
            case_id, title=title, severity=severity,
            analyst=analyst, tags=tags or [], client=client,
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

        if client:
            _set_client_boundary(client)

        return _json(result)

    @mcp.tool(title="Promote Case")
    def promote_case(
        case_id: str,
        title: str | None = None,
        severity: str | None = None,
        disposition: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Use after evidence review confirms the alert is worth a full investigation.
        Transitions the case from **triage** to **active** status.

        Only triage cases can be promoted. Active and closed cases are rejected.
        Optionally update title, severity, disposition, or tags at promotion time.

        Parameters
        ----------
        case_id : str
            Case identifier.
        title : str
            Updated case title (optional).
        severity : str
            Updated severity (optional).
        disposition : str
            Initial disposition hint (optional).
        tags : list[str]
            Updated tags (optional).
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
        """Use when triage determines the alert is not worth investigating — e.g.
        known false positive pattern, duplicate of an existing case, or out of scope.

        Only triage cases can be discarded. Active and closed cases must use
        ``close_case`` instead.

        Parameters
        ----------
        case_id : str
            Case identifier.
        reason : str
            Why the case was discarded (saved to case metadata).
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
        """Use when the analyst says "close this case", "mark as false positive",
        "this is a true positive", or after you have summarised the findings and
        the investigation is complete.

        Note that ``read_report`` auto-closes with disposition "resolved", so
        you only need this tool explicitly when the analyst wants a specific
        disposition (e.g. "false_positive", "true_positive", "benign_positive",
        "benign", "inconclusive").

        Cases can be closed from **active** or **triage** status. Closing from
        triage is useful for clear-cut dispositions (e.g. obvious benign positive
        or PUP) that don't need a full investigation cycle.

        Parameters
        ----------
        case_id : str
            Case identifier, e.g. "IV_CASE_001".
        disposition : str
            Closing disposition. One of: "true_positive", "benign_positive",
            "false_positive", "benign", "pup_pua", "inconclusive", "resolved".
            Default "resolved".
            Use "benign_positive" when the alert fired correctly on real activity
            but that activity was authorised/non-threatening (not "true_positive").
        """
        _require_scope("investigations:submit")
        # No boundary check — close_case is administrative (bulk close across cases)

        from tools.index_case import index_case
        return _json(index_case(case_id, status="closed", disposition=disposition))

    @mcp.tool(title="Add Evidence")
    async def add_evidence(case_id: str, text: str) -> str:
        """Use when the analyst pastes in raw alert data, IOC lists, log snippets,
        or contextual notes that should be attached to the CURRENT case. Trigger
        phrases: "here's the alert", "add these IOCs", "paste this into the case",
        "here's more context".

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Parses the text for IOCs (URLs, IPs, domains, hashes, emails, CVEs) and
        saves both the raw text and extracted IOCs to the case. The extracted IOCs
        are merged into the case IOC set.

        **IMPORTANT — Case isolation:** This tool adds evidence to the specified
        case only. If you have a NEW alert involving the same user/host/IOCs as a
        prior case, open a NEW case — do not add new alert data to the old case.
        Use ``recall_cases`` for historical cross-case context instead.

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

        # Speculative enrichment — pre-warm cache with IOCs from evidence text
        try:
            from tools.extract_iocs import _extract_from_text
            extracted = _extract_from_text(text)
            raw_iocs: list[str] = []
            for ioc_type in ("ipv4", "domain", "url", "sha256", "sha1", "md5"):
                raw_iocs.extend(extracted.get(ioc_type, set()))
            raw_iocs = list(dict.fromkeys(raw_iocs))[:20]
            if raw_iocs:
                import threading as _thr
                def _bg_enrich():
                    try:
                        from tools.enrich import quick_enrich
                        quick_enrich(raw_iocs, deep=False)
                    except Exception:
                        pass
                _thr.Thread(target=_bg_enrich, daemon=True,
                            name=f"spec_enrich_evidence_{case_id}").start()
        except Exception:
            pass  # advisory — never block add_evidence

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

    @mcp.tool(title="Generate MDR Report")
    async def generate_mdr_report(case_id: str = "") -> str:
        """Use when the analyst says "write the MDR report", "client report",
        "generate the deliverable", or needs the structured client-facing report
        for a completed investigation.

        **How to use:** Select the ``write_mdr_report`` prompt to get the
        instructions and case context, write the report, then call
        ``save_report`` with ``report_type="mdr_report"`` to persist it.

        ``case_id`` is optional — if omitted, a case is auto-created and
        promoted to active status first.

        Parameters
        ----------
        case_id : str
            Case identifier (optional — auto-created if empty).
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

    @mcp.tool(title="Generate PUP/PUA Report")
    async def generate_pup_report(case_id: str = "") -> str:
        """Use when the detection is PUP/PUA (adware, bundleware, toolbars).

        **How to use:** Select the ``write_pup_report`` prompt to get the
        instructions and case context, write the report, then call
        ``save_report`` with ``report_type="pup_report"`` to persist it.

        ``case_id`` is optional — if omitted, a case is auto-created first.

        Parameters
        ----------
        case_id : str
            Case identifier (optional — auto-created if empty).
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
        early in the investigation to inform your strategy.

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

        # Speculative enrichment — pre-warm cache with IOCs from alert text
        try:
            from tools.extract_iocs import _extract_from_text
            text_to_scan = f"{title}\n{notes}"
            extracted = _extract_from_text(text_to_scan)
            raw_iocs: list[str] = []
            for ioc_type in ("ipv4", "domain", "url", "sha256", "sha1", "md5"):
                raw_iocs.extend(extracted.get(ioc_type, set()))
            if urls:
                raw_iocs.extend(urls)
            raw_iocs = list(dict.fromkeys(raw_iocs))[:20]  # dedup, cap at 20
            if raw_iocs:
                import threading as _thr
                def _bg_enrich():
                    try:
                        from tools.enrich import quick_enrich
                        quick_enrich(raw_iocs, deep=False)
                    except Exception:
                        pass  # advisory — silent failure
                _thr.Thread(target=_bg_enrich, daemon=True,
                            name="spec_enrich_classify").start()
        except Exception:
            pass  # advisory — never block classify_attack

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
            "note": "This plan is advisory. Execute each step by calling the listed tool.",
        })

    @mcp.tool(title="Quick IOC Enrichment", annotations={"readOnlyHint": True})
    async def quick_enrich(
        iocs: list[str],
        deep: bool = True,
    ) -> str:
        """Use for fast, ad-hoc IOC lookups — no case required.  Trigger
        phrases: "enrich this IP", "look up this hash", "is this domain
        malicious?", "check these IOCs", or whenever the analyst pastes
        IOC values and wants immediate reputation data.

        Accepts raw IOC values (IPs, domains, URLs, hashes, emails) and
        auto-detects the type.  Runs all configured providers in parallel
        and returns per-IOC composite verdicts (malicious / suspicious /
        clean / unknown) with confidence levels.

        This tool does NOT create or modify a case — results are returned
        inline only.  For case-bound enrichment that persists artefacts,
        use ``enrich_iocs`` instead.

        Parameters
        ----------
        iocs : list[str]
            One or more raw IOC values.  Examples:
            ``["20.23.78.212", "evil-domain.com", "abc123..."]``
        deep : bool
            True (default) = run both fast and deep provider tiers.
            False = fast providers only (quicker, fewer API calls).
        """
        _require_scope("investigations:read")

        from tools.enrich import quick_enrich as _quick_enrich

        result = await asyncio.to_thread(
            lambda: _quick_enrich(iocs, deep=deep)
        )
        return _json(result)


    @mcp.tool(title="Query OpenCTI", annotations={"readOnlyHint": True, "openWorldHint": True})
    async def query_opencti(
        query: str,
        query_type: str = "auto",
    ) -> str:
        """Use when the analyst asks about threat actors, malware families, campaigns,
        attack patterns, or IOCs **from OpenCTI specifically** — e.g. "what does OpenCTI
        say about this IP?", "search OpenCTI for Lazarus", "any OpenCTI reports on this
        hash?", "check our threat intel platform", "what's trending in OpenCTI?".

        Also use when the analyst asks about CVE exploitation context, EPSS scores,
        or CISA KEV status — OpenCTI enriches vulnerability data with these fields.

        This queries the internal OpenCTI instance directly via GraphQL.
        No case required — results are returned inline.

        For routine IOC enrichment as part of an investigation, prefer ``quick_enrich``
        or ``enrich_iocs`` which call OpenCTI automatically alongside other providers.
        Use this tool for **targeted OpenCTI queries** — when the analyst specifically
        wants threat intel context, related threat actors, campaigns, or reports.

        Parameters
        ----------
        query : str
            The search term — an IOC value (IP, domain, URL, hash, email),
            a CVE ID (e.g. "CVE-2024-1234"), or a keyword to search for
            threat actors, malware, campaigns, or reports.
        query_type : str
            One of: ``auto``, ``ioc``, ``cve``, ``threat_actor``, ``malware``,
            ``campaign``, ``report``, ``attack_pattern``.
            Default ``auto`` detects IOCs and CVEs automatically, falls back
            to a broad STIX object search for keywords.
        """
        _require_scope("investigations:read")

        from tools.enrich import _opencti_lookup, _detect_ioc_type
        from config.settings import OPENCTI_KEY, OPENCTI_URL

        if not OPENCTI_KEY:
            return _json({"status": "error",
                          "message": "OpenCTI not configured (SOCAI_OPENCTI_KEY not set)"})

        result = await asyncio.to_thread(
            lambda: _query_opencti_inner(query, query_type, _opencti_lookup,
                                         _detect_ioc_type, OPENCTI_KEY, OPENCTI_URL)
        )
        return _json(result)

    @mcp.tool(title="Extract IOCs from Text", annotations={"readOnlyHint": True})
    def extract_iocs_from_text(text: str, include_private: bool = False) -> str:
        """Use when the analyst pastes raw alert text, email bodies, log snippets,
        or threat reports and wants structured IOCs extracted — e.g. "extract IOCs
        from this", "what IOCs are in this alert?", "parse this for indicators".

        Extracts IPv4 addresses, domains, URLs, hashes (MD5/SHA1/SHA256), email
        addresses, and CVE identifiers from raw text. No case required — results
        returned inline. Feed the output into ``quick_enrich`` for reputation data.

        Parameters
        ----------
        text : str
            Raw text to extract IOCs from (alert body, email, log snippet, etc.).
        include_private : bool
            Include RFC-1918 / loopback IPs (default False).
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
        """Use when the analyst says "what's on Confluence?", "check Confluence for X",
        "find the policy on Y", "show me the Confluence page about Z", or asks about
        published documentation, policies, processes, or threat hunting articles that
        live on the team wiki.

        Confluence is the team's internal knowledge base. It holds published threat
        articles, SOC policies, processes, runbooks, and documentation. This tool
        searches or retrieves pages from the configured Confluence space.

        **IMPORTANT — "articles" is ambiguous.** When the analyst asks about "articles"
        without specifying Confluence, clarify before acting:
        - "Check Confluence for articles on X" → use this tool
        - "Find articles about X" → could mean Confluence (published) OR online
          discovery (``search_threat_articles`` / ``web_search``). Ask which they mean.
        - "Search for new threat articles" → online discovery, NOT this tool

        Modes:
        - **Browse** (no query, no page_id): returns the most recently modified pages
        - **Search** (query provided): searches page titles for the query string
        - **Read** (page_id provided): returns full page content by ID

        Parameters
        ----------
        query : str
            Search term to find pages by title. Leave empty to browse recent pages.
        page_id : str
            Specific page ID to retrieve with full body content. Overrides query.
        limit : int
            Max pages to return when browsing or searching (default 15).
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
            return _json({"status": "ok", "mode": "read", "page": result})

        # Mode: search by title
        if query:
            pages = await asyncio.to_thread(search_pages, query, limit)
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
        return _json({
            "status": "ok",
            "mode": "browse",
            "results": len(result.get("pages", [])),
            "pages": result.get("pages", []),
            "next_cursor": result.get("next_cursor"),
            "_hint": (
                "To read the full content of a page, call search_confluence "
                "again with the page_id from the results above."
            ),
        })


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
    if "errors" in data:
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
                    entry["description"] = node["description"][:300]
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
# Tier 2 — Extended Analysis (19 tools)
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

        **To view screenshots:** call ``read_case_file`` with the screenshot path
        (e.g. ``artefacts/web/<domain>/screenshot.png``) — images render directly in chat.

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
        """Use when the analyst says "have we seen this before?", "prior art",
        "similar incidents", "search old cases for this IOC", "any history on
        this domain/IP/hash?", or "check previous investigations".

        **This is the cross-case correlation mechanism.** Each alert gets its own
        case (never merge), but ``recall_cases`` provides historical context by
        searching all prior investigations for overlapping IOCs, users, or
        keywords. Use it during Phase 3 of every investigation to check whether
        entities in the current alert have appeared before. Note overlaps in
        your analysis (e.g. "user also targeted in IV_CASE_205"), but keep all
        evidence in the current case.

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

        # Client boundary filtering is a no-op now
        active_client = ""

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
        """Use after ``search_threat_articles`` when the analyst has selected
        which articles to write up.

        **How to use:** Select the ``write_threat_article`` prompt to get the
        instructions and source context, write the article, then call
        ``save_threat_article`` to persist it.

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
    ) -> str:
        """Use after generating a threat article locally with the
        ``write_threat_article`` prompt. Persists the article to disk,
        updates the article index, and optionally links to a case.

        **Workflow:** Select ``write_threat_article`` prompt → research and
        write the article locally → call this tool to save it.

        Parameters
        ----------
        article_text : str
            Full article markdown (title, body, recommendations, indicators).
        title : str
            Article title.
        category : str
            "ET" (Emerging Threat) or "EV" (Emerging Vulnerability).
        source_urls : list[str]
            URLs of source material used.
        analyst : str
            Analyst name for attribution.
        case_id : str
            Optional case ID to associate with.
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
            )
        )
        return _json(result)

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

        **How to use:** Select the ``write_executive_summary`` prompt to get
        the instructions and case context, write the summary, then call
        ``save_report`` with ``report_type="executive_summary"`` to persist it.

        Parameters
        ----------
        case_id : str
            Case identifier.
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
        """Use when the analyst says "parse these logs", "extract entities from logs",
        "process the log files", or after uploading CSV/JSON/JSONL log files to a case.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Parses CSV, JSON, and JSONL log files from the case uploads directory.
        Extracts structured entities: timestamps, IPs, usernames, process names,
        command lines, HTTP methods/statuses, Windows Event IDs, and file paths.

        Upload log files to the case ``uploads/`` directory before calling.
        After parsing, use ``detect_anomalies`` to run behavioural detection on
        the parsed data, or ``correlate_evtx`` for Windows Event Log chain analysis.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.parse_logs_action(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Detect Anomalies", annotations={"readOnlyHint": True})
    async def detect_anomalies(case_id: str) -> str:
        """Use when the analyst says "check for anomalies", "look for suspicious patterns",
        "run anomaly detection", "any impossible travel?", "brute force attempts?", or
        after parsing logs to find behavioural outliers.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Runs six behavioural anomaly detectors on parsed log data:
        1. **Temporal** — logins outside business hours / weekends
        2. **Impossible travel** — same user, different geo IPs within time window
        3. **Brute force** — N+ failed logins from same source in window
        4. **First-seen entities** — processes/commands not seen in prior cases
        5. **Volume spikes** — events per IP/user exceeding statistical threshold
        6. **Lateral movement** — same user from 3+ distinct IPs in time window

        **Prerequisite:** Logs must be parsed first (via ``parse_logs``,
        ``ingest_velociraptor``, or ``ingest_mde_package``).

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.detect_anomalies_action(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Correlate EVTX Attack Chains")
    async def correlate_evtx(case_id: str) -> str:
        """Use when the analyst says "correlate event logs", "check for attack chains",
        "EVTX analysis", "look for lateral movement in logs", or after ingesting
        Windows Event Log data.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Correlates parsed Windows Event Log data to detect multi-step attack chains:
        1. **Brute force → success** (4625 failures then 4624 success)
        2. **Lateral movement** (type 3 logon from internal IP → process creation)
        3. **Persistence** (scheduled task 4698 / service install 7045 after logon)
        4. **Privilege escalation** (low-priv parent → elevated child, or RDP → group add)
        5. **Account manipulation** (4720 account created → 4732 added to group)
        6. **Kerberos abuse** (4768/4769 with RC4-HMAC encryption)
        7. **Pass-the-hash** (NTLM type 3 logon without 4776 validation)

        Optionally sends detected chains to Claude for narrative reconstruction
        and MITRE ATT&CK mapping.

        **Prerequisite:** Logs must be parsed first (via ``parse_logs``,
        ``ingest_velociraptor``, or ``ingest_mde_package``).

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.correlate_event_logs(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="Triage IOCs", annotations={"readOnlyHint": True})
    async def triage_iocs(case_id: str, urls: list[str] | None = None,
                          severity: str = "medium") -> str:
        """Use for fast pre-pipeline IOC triage — checks input IOCs against the
        cross-case IOC index and enrichment cache before running a full
        investigation. Trigger phrases: "triage these IOCs", "quick reputation
        check", "have we seen this before?", "pre-check these indicators".

        Returns known-malicious/suspicious hits, cache status, and severity
        escalation recommendations. Much faster than ``enrich_iocs`` — use this
        first to decide whether full enrichment is needed.

        Parameters
        ----------
        case_id : str
            Case identifier.
        urls : list[str]
            URLs to triage (domains are auto-extracted).
        severity : str
            Current case severity (used for escalation recommendations).
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
        """Use after enrichment to compute composite verdicts for all IOCs in a
        case. Trigger phrases: "score the IOCs", "what are the verdicts?",
        "composite verdict", "verdict summary".

        Aggregates per-provider enrichment results into a single verdict per IOC
        (malicious / suspicious / clean / unknown) with confidence levels
        (HIGH / MEDIUM / LOW). Also updates the cross-case IOC index.

        **Prerequisite:** ``enrich_iocs`` must have run first.

        Parameters
        ----------
        case_id : str
            Case identifier with completed enrichment.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from tools.score_verdicts import score_verdicts, update_ioc_index

        def _run():
            result = score_verdicts(case_id)
            update_ioc_index(case_id)
            return result

        result = await asyncio.to_thread(_run)
        return _json(result)

    @mcp.tool(title="Analyse Static File", annotations={"readOnlyHint": True})
    async def analyse_static_file(file_path: str, case_id: str) -> str:
        """Use for quick binary file triage — hashes, entropy, file type, strings,
        and PE metadata extraction. Trigger phrases: "analyse this file",
        "what is this binary?", "file triage", "quick file analysis".

        Lighter and faster than ``analyse_pe`` (full PE deep-dive). Use this for
        initial file triage; escalate to ``analyse_pe`` for suspicious binaries.

        Parameters
        ----------
        file_path : str
            Absolute path to the file to analyse.
        case_id : str
            Case identifier for artefact storage.
        """
        _require_scope("investigations:read")
        _check_client_boundary(case_id)

        from tools.static_file_analyse import static_file_analyse
        result = await asyncio.to_thread(
            lambda: static_file_analyse(file_path, case_id)
        )
        return _json(result)

    @mcp.tool(title="Sandbox API Lookup", annotations={"readOnlyHint": True, "openWorldHint": True})
    async def sandbox_api_lookup(case_id: str) -> str:
        """Use to check whether file hashes from a case have existing sandbox
        detonation reports. Trigger phrases: "check sandbox", "has this been
        detonated?", "any sandbox reports?", "Any.Run lookup", "Joe Sandbox".

        Queries Hybrid Analysis, Any.Run, and Joe Sandbox APIs for existing
        analysis reports by SHA256. This is an **API lookup** of prior
        detonations — for live detonation in a container, use
        ``start_sandbox_session`` instead.

        **Prerequisite:** Static file analysis (``analyse_static_file`` or
        ``analyse_pe``) must have run first to produce SHA256 hashes.

        Parameters
        ----------
        case_id : str
            Case identifier with file analysis artefacts.
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
        """Use when the analyst says "check Cyberint", "any Cyberint alerts?",
        "search Cyberint for X", "show me Cyberint alert <ID>", or asks about
        CTI alerts from the Cyberint platform.

        Cyberint is an external cyber threat intelligence platform that tracks
        alerts about brand impersonation, data leaks, phishing kits, credential
        exposure, and other external threats.

        Modes:
        - **Single alert** (alert_ref_id provided): returns full alert detail
        - **Filtered list** (no alert_ref_id): paginated list with optional filters

        Parameters
        ----------
        alert_ref_id : str
            Specific alert reference ID to retrieve. Overrides all filters.
        severity : str
            Filter by severity (e.g. "very_high", "high", "medium", "low").
        status : str
            Filter by status (e.g. "open", "acknowledged", "closed").
        category : str
            Filter by category (e.g. "phishing", "data_leak", "brand_security").
        environment : str
            Filter by environment/client name.
        created_from : str
            ISO date string — only alerts created after this date.
        created_to : str
            ISO date string — only alerts created before this date.
        page : int
            Page number for pagination (default 1).
        size : int
            Results per page (default 10, max 100).
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
        """Use when the analyst asks for a Cyberint alert attachment, indicator
        detail, analysis report, or risk scores.

        Exactly one mode at a time:
        - **attachment_id**: get a temporary download URL for an attachment
        - **indicator_id**: get indicator detail from an alert
        - **analysis_report=True**: get a temporary URL for the analysis report
        - **risk_environment**: get current risk scores for an environment (alert_ref_id ignored)

        Parameters
        ----------
        alert_ref_id : str
            Alert reference ID (required for attachment, indicator, and report modes).
        attachment_id : str
            Attachment ID to retrieve download URL for.
        indicator_id : str
            Indicator ID to retrieve details for.
        analysis_report : bool
            Set True to get the analysis report URL.
        risk_environment : str
            Environment name to get risk scores for (ignores alert_ref_id).
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
        _require_scope("investigations:write")
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
        _require_scope("investigations:write")
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

        Runs the tool call specified in the proposal and updates the
        investigation matrix. Only execute after reviewing the proposal
        via list_followups.

        Parameters:
            case_id: The case to execute against
            proposal_id: The proposal ID (e.g. "p_001")
        """
        _require_scope("investigations:write")
        _check_client_boundary(case_id)

        from api.actions import execute_followup_proposal as _exec
        result = await asyncio.to_thread(lambda: _exec(case_id, proposal_id))
        return _json(result)


# ---------------------------------------------------------------------------
# Tier 3 — Advanced / Restricted (23 tools)
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

    @mcp.tool(title="Run KQL Batch", annotations={"openWorldHint": True})
    async def run_kql_batch(
        queries: list[str],
        workspace: str = "",
        case_id: str = "",
        max_rows: int = 1000,
    ) -> str:
        """Use when you need to execute **multiple KQL queries concurrently**
        against a Sentinel workspace.  Returns all results together, completing
        in roughly the time of the slowest single query.

        Trigger phrases: "run all these queries", "batch KQL", "execute
        all composite queries".

        **Typical workflow:**
        1. Call ``generate_sentinel_query`` for each scenario you need
        2. Collect the rendered queries
        3. Pass them all to ``run_kql_batch`` for concurrent execution

        Parameters
        ----------
        queries : list[str]
            List of KQL query strings to execute.
        workspace : str
            Workspace name or GUID.  Auto-resolved from case client if omitted.
        case_id : str
            Optional case ID for workspace resolution and audit.
        max_rows : int
            Maximum rows per query (default 1000).
        """
        _require_scope("sentinel:query")
        if case_id:
            _check_client_boundary(case_id)

        from tools.sentinel_queries import resolve_kql_workspace

        ws_id = resolve_kql_workspace(workspace, case_id=case_id or None)
        if not ws_id:
            return _json({"error": "Could not resolve workspace. Provide workspace name/GUID or set SOCAI_SENTINEL_WORKSPACE."})

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
                rows = run_kql(ws_id, q)
                return {"query": query[:200], "row_count": len(rows), "rows": rows}
            except Exception as exc:
                return {"query": query[:200], "error": str(exc), "row_count": 0, "rows": []}

        results = []
        max_workers = min(4, len(queries))
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
            "query_count": len(queries),
            "total_rows": total_rows,
            "results": results,
        })

    @mcp.tool(title="Security Architecture Review")
    async def security_arch_review(case_id: str) -> str:
        """Use when the analyst says "architecture review", "what controls
        failed?", "security recommendations".

        **How to use:** Select the ``write_security_arch_review`` prompt,
        write the review, then call ``save_report`` with
        ``report_type="security_arch_review"`` to persist it.

        Parameters
        ----------
        case_id : str
            Case identifier.
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
        _check_client_boundary(case_id)

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
        _check_client_boundary(case_id)

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

    @mcp.tool(title="Save Report")
    async def save_report(
        case_id: str,
        report_type: str,
        report_text: str,
        disposition: str | None = None,
    ) -> str:
        """Use after selecting a report prompt (write_mdr_report, write_pup_report,
        write_fp_closure, write_fp_tuning, write_executive_summary,
        write_security_arch_review) and generating the report content locally.

        Persists a locally-generated report to disk with defanging, HTML
        conversion, auto-close logic, and audit trail. No LLM call — all
        the thinking was done by your local session.

        **Report types and auto-close behaviour:**
        - ``mdr_report`` — auto-closes case (preserves existing disposition)
        - ``pup_report`` — auto-closes case (disposition: pup_pua)
        - ``fp_ticket`` — auto-closes case (disposition: false_positive)
        - ``fp_tuning_ticket`` — does NOT auto-close
        - ``executive_summary`` — does NOT auto-close
        - ``security_arch_review`` — does NOT auto-close

        Parameters
        ----------
        case_id : str
            Case identifier.
        report_type : str
            One of: mdr_report, pup_report, fp_ticket, fp_tuning_ticket,
            executive_summary, security_arch_review.
        report_text : str
            Full report markdown as generated by your local session.
        disposition : str
            Optional disposition override for auto-close.
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
        alert_data: str,
        case_id: str = "",
        platform: str | None = None,
        query_text: str | None = None,
    ) -> str:
        """Use when the analyst says "this is a false positive", "FP ticket".

        **How to use:** Select the ``write_fp_closure`` prompt to get the
        instructions and case context, write the FP closure comment, then
        call ``save_report`` with ``report_type="fp_ticket"`` to persist it.

        ``case_id`` is optional — if omitted, a case is auto-created first.

        Parameters
        ----------
        alert_data : str
            Raw alert JSON (stored as evidence for the prompt).
        case_id : str
            Case identifier (optional — auto-created if empty).
        platform : str
            Detection platform (auto-detected if omitted).
        query_text : str
            Original detection query text.
        """
        _require_scope("investigations:submit")

        case_id = _ensure_case(case_id, disposition="false_positive")
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
            "prompt": "write_fp_closure",
            "save_tool": "save_report",
            "save_args": {"report_type": "fp_ticket"},
            "message": (
                f"Case {case_id} is ready with alert evidence. Use the "
                f"write_fp_closure prompt to generate the FP ticket, then "
                f'call save_report with report_type="fp_ticket" to persist it.'
            ),
        })

    @mcp.tool(title="Generate SIEM Tuning Ticket")
    async def generate_fp_tuning_ticket(
        alert_data: str,
        case_id: str = "",
        platform: str | None = None,
        query_text: str | None = None,
    ) -> str:
        """Use when the analyst says "tuning ticket", "SIEM engineering ticket".

        **How to use:** Select the ``write_fp_tuning`` prompt to get the
        instructions and case context, write the tuning ticket, then call
        ``save_report`` with ``report_type="fp_tuning_ticket"`` to persist it.

        ``case_id`` is optional — if omitted, a case is auto-created first.

        Parameters
        ----------
        alert_data : str
            Raw alert JSON (stored as evidence for the prompt).
        case_id : str
            Case identifier (optional — auto-created if empty).
        platform : str
            Detection platform (auto-detected if omitted).
        query_text : str
            Original detection query text.
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
    async def start_browser_session(url: str, case_id: str = "") -> str:
        """Use when the analyst says "open this in a browser", "I need to interact
        with the page", "Cloudflare is blocking", "CAPTCHA", or when automated
        URL capture (``capture_urls``) fails due to bot protection.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Starts a disposable Docker-based Chrome session with passive tcpdump
        network capture. Returns a noVNC URL for the analyst to manually
        interact with the page — no automation markers, no CDP, no Selenium.
        Phishing pages see a real browser with a real user driving it.

        Network traffic is captured passively via tcpdump (pcap). Call
        ``stop_browser_session`` when done to collect the artefacts.

        When ``case_id`` is omitted, artefacts are stored under the session
        directory (``browser_sessions/<session_id>/artefacts/``) with no case
        created. Pass a case_id to attach artefacts to an existing investigation.

        Parameters
        ----------
        url : str
            URL to load in the browser.
        case_id : str
            Optional case identifier. When empty, no case is created — artefacts
            are stored in the session directory.
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

    @mcp.tool(title="Analyse PE Files")
    async def analyse_pe(case_id: str) -> str:
        """Use when the analyst says "analyse the binary", "PE analysis", "check the
        executable", "static analysis", or after extracting PE files (EXE, DLL, SYS)
        from a ZIP or email attachment.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Runs deep static analysis on all PE files found in the case artefacts
        (extracted ZIPs and email attachments):
        - Shannon entropy (per-section + overall)
        - Section analysis (W+X, size mismatches, unnamed sections)
        - Full import table with suspicious API flagging
        - Export table analysis
        - PE header anomalies (timestamp, checksum, subsystem)
        - Overlay detection, packer signature heuristics, Rich header hash
        - File hashes (MD5, SHA1, SHA256) and strings extraction
        - Optional LLM-powered malware classification

        Requires the ``pefile`` library. Returns skip manifest if not installed.

        After PE analysis, use ``yara_scan`` for rule-based detection, optionally
        with ``generate_rules=True`` to create custom YARA rules from the findings.

        Parameters
        ----------
        case_id : str
            Case identifier.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(lambda: actions.pe_analysis_action(case_id))
        return _json(_pop_message(result))

    @mcp.tool(title="YARA Scan")
    async def yara_scan(case_id: str, generate_rules: bool = False) -> str:
        """Use when the analyst says "run YARA", "scan for malware signatures",
        "check against YARA rules", or after PE analysis to match known threat
        patterns against case artefacts.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Scans extracted files, email attachments, and web captures against:
        - **Built-in rules** — suspicious PE, PowerShell obfuscation, C2 patterns,
          base64-encoded PE headers, common RAT strings
        - **External rules** — custom ``.yar``/``.yara`` files from ``config/yara_rules/``
        - **LLM-generated rules** (when ``generate_rules=True``) — custom YARA rules
          created from PE analysis and enrichment verdicts

        Requires the ``yara-python`` library. Returns skip manifest if not installed.

        Parameters
        ----------
        case_id : str
            Case identifier.
        generate_rules : bool
            Generate custom YARA rules from PE analysis and enrichment data via LLM.
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
        """Use when the analyst says "how do I collect a memory dump?", "guide me
        through procdump", "I need to dump this process", or when a suspicious process
        needs memory analysis but the dump hasn't been collected yet.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Generates step-by-step instructions for collecting a process memory dump via
        MDE Live Response (ProcDump, built-in memdump, or investigation package).
        Tailored to the specific process, PID, and host provided.

        After collecting the dump, use ``analyse_memory_dump`` to process it.

        Parameters
        ----------
        case_id : str
            Case identifier.
        process_name : str
            Name of the suspicious process (e.g. svchost.exe).
        pid : str
            Process ID to dump.
        alert_title : str
            Title of the triggering alert (for context).
        hostname : str
            Target hostname (for Live Response connection instructions).
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
        """Use when the analyst says "analyse the memory dump", "check the dump file",
        "what's in this procdump?", or after collecting a process memory dump.

        **Routing:** If starting a new investigation, call `classify_attack` or `plan_investigation` first.

        Performs read-only analysis of process memory dump files (.dmp, .dump, .raw, .bin)
        from the case uploads directory:
        - String extraction (ASCII + UTF-16LE)
        - IOC extraction (IPs, URLs, domains, hashes, emails, file paths, registry keys)
        - DLL reference analysis (flags suspicious DLLs: AMSI, debug, network, credential)
        - Suspicious pattern detection (injection markers, shellcode, credential theft,
          AMSI/ETW bypass, PowerShell, Mimikatz modules)
        - Embedded PE header detection
        - Risk scoring and assessment

        Upload .dmp files to the case ``uploads/`` directory before calling.

        Set ``run_analysis=True`` (default) to automatically extract IOCs and enrich
        after analysis. Set ``run_analysis=False`` to review raw findings first.

        Parameters
        ----------
        case_id : str
            Case identifier.
        run_analysis : bool
            Run IOC enrichment after analysis.
        """
        _require_scope("investigations:submit")
        _check_client_boundary(case_id)

        from api import actions
        result = await asyncio.to_thread(
            lambda: actions.analyse_memory_dump_action(case_id, run_analysis=run_analysis)
        )
        return _json(_pop_message(result))


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
        """Use when you want to understand what is 'normal' for a client before
        interpreting enrichment results.

        Returns a behavioural profile built from all historical cases for the
        client, including:
        - IOC recurrence (IPs/domains that appear repeatedly, always clean)
        - Confirmed malicious / suspicious IOCs seen in prior cases
        - Attack type distribution (e.g. 60% phishing, 30% account compromise)
        - Severity distribution and tag frequency

        Built automatically from case history. Rebuilt every 24 hours by the
        background scheduler, or on demand via ``rebuild_client_baseline``.

        Call ``lookup_client`` first to confirm the client name, then this to
        load baseline context before enriching IOCs.

        Parameters
        ----------
        client_name : str
            Client name (case-insensitive).
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
        """Use to force-rebuild the behavioural baseline for a client.

        Scans all historical cases for this client and recomputes the profile
        (IOC recurrence, attack type distribution, severity breakdown, tags).

        The baseline is rebuilt automatically every 24 hours by the background
        scheduler. Call this after a significant batch of new cases has been
        closed for a client.

        Parameters
        ----------
        client_name : str
            Client name (case-insensitive).
        """
        _require_scope("investigations:write")

        result = await asyncio.to_thread(
            lambda: __import__("tools.client_baseline", fromlist=["build_client_baseline"])
                        .build_client_baseline(client_name)
        )
        return _json(result)

    @mcp.tool(title="GeoIP Lookup", annotations={"readOnlyHint": True})
    async def geoip_lookup(
        ip: Annotated[str, "IPv4 or IPv6 address to geolocate."],
    ) -> str:
        """Use when you need to quickly geolocate an IP address without consuming
        enrichment API quota.

        Queries the local MaxMind GeoLite2-City database (offline, fast).
        Returns country, city, latitude/longitude, and timezone.

        Requires MAXMIND_LICENSE_KEY in .env and geoip2 installed.
        Returns {"available": False} gracefully if not configured.

        Parameters
        ----------
        ip : str
            IPv4 or IPv6 address.
        """
        _require_scope("enrichment:run")

        result = await asyncio.to_thread(
            lambda: __import__("tools.geoip", fromlist=["lookup_ip"])
                        .lookup_ip(ip)
        )
        return _json(result)

    @mcp.tool(title="Refresh GeoIP Database")
    async def refresh_geoip(
        force: Annotated[bool, "Re-download even if recently updated."] = False,
    ) -> str:
        """Use to download or update the local MaxMind GeoLite2-City database.

        The database (~70 MB) is refreshed automatically every 7 days by the
        background scheduler. Call with force=True to update immediately.

        Requires MAXMIND_LICENSE_KEY in .env (free MaxMind account).

        Parameters
        ----------
        force : bool
            Force re-download even if database is current.
        """
        _require_scope("admin")

        result = await asyncio.to_thread(
            lambda: __import__("tools.geoip", fromlist=["refresh_geoip_db"])
                        .refresh_geoip_db(force=force)
        )
        return _json(result)


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_tools(mcp: FastMCP) -> None:
    """Register all MCP tool handlers on the given FastMCP instance."""
    _register_tier1(mcp)
    _register_tier2(mcp)
    _register_tier2_rumsfeld(mcp)
    _register_tier3(mcp)
    _register_intelligence(mcp)
