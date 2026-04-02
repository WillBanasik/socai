"""MCP resource implementations — read-only data endpoints.

Resources expose case data, playbooks, and threat intelligence as structured
content that MCP clients can read without invoking tool actions.
"""
from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from mcp_server.auth import _require_scope


def _json(obj: object) -> str:
    return json.dumps(obj, indent=2, default=str)


def _resolve_client_playbook(client_name: str) -> Path | None:
    """Find the playbook JSON for a client (directory or flat layout)."""
    from config.settings import CLIENT_PLAYBOOKS_DIR as CLIENTS_DIR
    from tools.common import load_json

    # New layout: config/clients/<name>/playbook.json
    candidates = [
        CLIENTS_DIR / client_name / "playbook.json",
        CLIENTS_DIR / client_name.lower().replace(" ", "_") / "playbook.json",
        # Legacy flat layout: config/clients/<name>.json
        CLIENTS_DIR / f"{client_name}.json",
        CLIENTS_DIR / f"{client_name.lower().replace(' ', '_')}.json",
    ]
    for p in candidates:
        if p.exists():
            return p

    # Search by client_name field inside JSON files
    for p in CLIENTS_DIR.rglob("*.json"):
        try:
            data = load_json(p)
            if data.get("client_name", "").lower() == client_name.lower():
                return p
        except Exception:
            continue
    return None


def _resolve_client_knowledge(client_name: str) -> Path | None:
    """Find the knowledge base markdown for a client."""
    from config.settings import CLIENT_PLAYBOOKS_DIR as CLIENTS_DIR

    candidates = [
        CLIENTS_DIR / client_name / "knowledge.md",
        CLIENTS_DIR / client_name.lower().replace(" ", "_") / "knowledge.md",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def register_resources(mcp: FastMCP) -> None:
    """Register all MCP resource handlers."""

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    @mcp.resource("socai://cases")
    def list_all_cases() -> str:
        """All cases from the registry."""
        _require_scope("investigations:read")

        from config.settings import REGISTRY_FILE
        from tools.common import load_json

        if not REGISTRY_FILE.exists():
            return _json({"cases": {}})
        return _json(load_json(REGISTRY_FILE))

    @mcp.resource("socai://cases/{case_id}/meta")
    def case_meta(case_id: str) -> str:
        """Case metadata JSON."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "case_meta.json"
        if not path.exists():
            return _json({"error": f"Case {case_id!r} not found."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/report")
    def case_report(case_id: str) -> str:
        """Investigation report markdown."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR

        path = CASES_DIR / case_id / "reports" / "investigation_report.md"
        if not path.exists():
            return f"No report found for case {case_id!r}."
        return path.read_text(encoding="utf-8")

    @mcp.resource("socai://cases/{case_id}/iocs")
    def case_iocs(case_id: str) -> str:
        """Extracted IOCs JSON."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "iocs" / "iocs.json"
        if not path.exists():
            return _json({"error": "No IOCs found.", "iocs": {}})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/verdicts")
    def case_verdicts(case_id: str) -> str:
        """Verdict summary JSON."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "enrichment" / "verdict_summary.json"
        if not path.exists():
            return _json({"error": "No verdicts found."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/enrichment")
    def case_enrichment(case_id: str) -> str:
        """Enrichment data JSON."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "enrichment" / "enrichment.json"
        if not path.exists():
            return _json({"error": "No enrichment data found."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/timeline")
    def case_timeline(case_id: str) -> str:
        """Timeline events JSON."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "timeline" / "timeline.json"
        if not path.exists():
            return _json({"error": "No timeline data found."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/notes")
    def case_notes(case_id: str) -> str:
        """Analyst notes (free-text investigation context)."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR

        path = CASES_DIR / case_id / "notes" / "analyst_input.md"
        if not path.exists():
            return f"No analyst notes found for case {case_id!r}."
        return path.read_text(encoding="utf-8")

    @mcp.resource("socai://cases/{case_id}/response-actions")
    def case_response_actions(case_id: str) -> str:
        """Response actions JSON (client-specific containment/remediation plan)."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "response_actions" / "response_actions.json"
        if not path.exists():
            return _json({"error": "No response actions found."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/fp-ticket")
    def case_fp_ticket(case_id: str) -> str:
        """Existing FP closure comment (if generated)."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR

        path = CASES_DIR / case_id / "artefacts" / "fp_comms" / "fp_ticket.md"
        if not path.exists():
            return f"No FP ticket found for case {case_id!r}."
        return path.read_text(encoding="utf-8")

    @mcp.resource("socai://cases/{case_id}/evidence")
    def case_evidence(case_id: str) -> str:
        """Raw evidence files added to the case.

        Contains alerts, log snippets, and other raw data added via
        ``add_evidence``. Read this to see all raw input data for a case
        in a single call instead of multiple ``read_case_file`` invocations.
        """
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        evidence_dir = CASES_DIR / case_id / "evidence"
        if not evidence_dir.is_dir():
            return _json({"error": "No evidence directory found.", "evidence": []})

        evidence = []
        for path in sorted(evidence_dir.iterdir()):
            if path.is_file():
                try:
                    if path.suffix == ".json":
                        evidence.append({
                            "filename": path.name,
                            "type": "json",
                            "data": load_json(path),
                        })
                    else:
                        text = path.read_text(encoding="utf-8", errors="replace")
                        if len(text) > 10000:
                            text = text[:10000] + "\n[...truncated...]"
                        evidence.append({
                            "filename": path.name,
                            "type": "text",
                            "data": text,
                        })
                except Exception:
                    evidence.append({
                        "filename": path.name,
                        "type": "error",
                        "data": "Failed to read file.",
                    })

        return _json({"evidence": evidence, "count": len(evidence)})

    @mcp.resource("socai://cases/{case_id}/findings")
    def case_findings(case_id: str) -> str:
        """Analytical findings recorded via ``add_finding``.

        Contains all analyst conclusions, determinations, and observations
        recorded during the investigation.
        """
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        findings_path = CASES_DIR / case_id / "artefacts" / "findings.json"
        if not findings_path.exists():
            return _json({"findings": [], "count": 0})
        data = load_json(findings_path)
        findings = data if isinstance(data, list) else data.get("findings", [])
        return _json({"findings": findings, "count": len(findings)})

    @mcp.resource("socai://cases/{case_id}/full")
    def case_full(case_id: str) -> str:
        """Complete case bundle — meta, IOCs, enrichment, verdicts, timeline,
        findings, and evidence in a single read.

        Use this instead of making 5-6 separate resource reads or tool calls
        to assemble case context. Truncates large sections to stay within
        reasonable size limits.
        """
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        case_dir = CASES_DIR / case_id
        if not case_dir.is_dir():
            return _json({"error": f"Case {case_id!r} not found."})

        def _load(rel_path: str, default=None):
            path = case_dir / rel_path
            if not path.exists():
                return default
            try:
                if path.suffix == ".json":
                    return load_json(path)
                return path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return default

        def _truncate_json(obj, max_chars: int = 8000):
            import json as _json_mod
            text = _json_mod.dumps(obj, indent=2, default=str)
            if len(text) > max_chars:
                return _json_mod.loads(_json_mod.dumps(obj, default=str))  # ensure serialisable
            return obj

        bundle = {
            "case_id": case_id,
            "meta": _load("case_meta.json", {}),
            "iocs": _load("iocs/iocs.json", {}),
            "verdicts": _load("artefacts/enrichment/verdict_summary.json", {}),
            "enrichment_stats": (_load("artefacts/enrichment/enrichment.json", {}) or {}).get("stats", {}),
            "timeline": _load("artefacts/timeline/timeline.json", []),
            "findings": _load("artefacts/findings.json", []),
        }

        # Include evidence filenames (not full content — too large)
        evidence_dir = case_dir / "evidence"
        if evidence_dir.is_dir():
            bundle["evidence_files"] = sorted(p.name for p in evidence_dir.iterdir() if p.is_file())
        else:
            bundle["evidence_files"] = []

        # Include report existence flags
        reports_dir = case_dir / "reports"
        if reports_dir.is_dir():
            bundle["reports"] = sorted(p.name for p in reports_dir.iterdir() if p.is_file())
        else:
            bundle["reports"] = []

        # Analyst notes (truncated)
        notes = _load("notes/analyst_input.md")
        if notes and len(notes) > 2000:
            notes = notes[:2000] + "\n[...truncated...]"
        bundle["notes"] = notes

        return _json(bundle)

    # ------------------------------------------------------------------
    # Rumsfeld Investigation Analysis
    # ------------------------------------------------------------------

    @mcp.resource("socai://cases/{case_id}/matrix")
    def case_matrix(case_id: str) -> str:
        """Investigation reasoning matrix (Rumsfeld method).

        Contains known_knowns (facts with evidence), known_unknowns
        (evidence gaps), and hypotheses (testable claims).
        """
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "analysis" / "investigation_matrix.json"
        if not path.exists():
            return _json({"error": "No investigation matrix found. Run generate_investigation_matrix first."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/determination")
    def case_determination(case_id: str) -> str:
        """Evidence-chain determination analysis."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "analysis" / "determination.json"
        if not path.exists():
            return _json({"error": "No determination found. Run run_determination first."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/quality-gate")
    def case_quality_gate(case_id: str) -> str:
        """Report quality gate review results."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "analysis" / "report_review.json"
        if not path.exists():
            return _json({"error": "No quality gate review found. Run review_report_quality first."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/followups")
    def case_followups(case_id: str) -> str:
        """Follow-up investigation proposals."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "analysis" / "followup_proposals.json"
        if not path.exists():
            return _json({"proposals": [], "message": "No follow-up proposals found."})
        return _json(load_json(path))

    # ------------------------------------------------------------------
    # Client Registry
    # ------------------------------------------------------------------

    @mcp.resource("socai://clients")
    def list_clients() -> str:
        """Client registry with platform scope (Sentinel, XDR, CrowdStrike, Encore).

        Use this to identify which client a case belongs to and which
        security platforms are available for that client.
        """
        _require_scope("investigations:read")

        from config.settings import CLIENT_ENTITIES
        from tools.common import load_json

        if not CLIENT_ENTITIES.exists():
            return _json({"clients": []})
        entities = load_json(CLIENT_ENTITIES).get("clients", [])
        # Return name + platforms only (strip alias for non-admin)
        summary = []
        for ent in entities:
            item = {"name": ent.get("name", "")}
            platforms = ent.get("platforms", {})
            if not platforms and ent.get("workspace_id"):
                platforms = {"sentinel": {"workspace_id": ent["workspace_id"]}}
            item["platforms"] = list(platforms.keys()) if platforms else []
            summary.append(item)
        return _json({"clients": summary})

    @mcp.resource("socai://clients/{client_name}")
    def client_detail(client_name: str) -> str:
        """Full client configuration including platform access scope."""
        _require_scope("investigations:read")

        from tools.common import get_client_config
        cfg = get_client_config(client_name)
        if not cfg:
            return _json({"error": f"Client {client_name!r} not found in registry."})
        return _json(cfg)

    # ------------------------------------------------------------------
    # KQL Playbooks
    # ------------------------------------------------------------------

    @mcp.resource("socai://playbooks")
    def list_playbooks() -> str:
        """List of all KQL investigation playbooks."""
        _require_scope("sentinel:query")

        from tools.kql_playbooks import list_playbooks as _list
        return _json({"playbooks": _list()})

    @mcp.resource("socai://playbooks/{playbook_id}")
    def get_playbook(playbook_id: str) -> str:
        """Full playbook with all stages."""
        _require_scope("sentinel:query")

        from tools.kql_playbooks import load_playbook
        pb = load_playbook(playbook_id)
        if not pb:
            return _json({"error": f"Playbook {playbook_id!r} not found."})
        return _json(pb)

    # ------------------------------------------------------------------
    # Sentinel Composite Queries
    # ------------------------------------------------------------------

    @mcp.resource("socai://sentinel-queries")
    def list_sentinel_queries() -> str:
        """List of all Sentinel composite query scenarios.

        Composite queries are single-execution full-picture queries using
        Sentinel-native tables (OfficeActivity, SigninLogs, SecurityAlert).
        Use generate_sentinel_query tool to hydrate them with parameters.
        """
        _require_scope("sentinel:query")

        from tools.sentinel_queries import list_scenarios
        return _json({"scenarios": list_scenarios()})

    # ------------------------------------------------------------------
    # LogScale Syntax Reference
    # ------------------------------------------------------------------

    @mcp.resource("socai://logscale-syntax")
    def logscale_syntax() -> str:
        """CrowdStrike LogScale (Humio) query language reference.

        Complete syntax reference for generating LogScale queries —
        operators, functions, field conventions, CrowdStrike Falcon
        sensor fields, and critical pitfalls.  Consult this before
        writing or reviewing any LogScale query.
        """
        _require_scope("sentinel:query")

        import pathlib
        ref_path = pathlib.Path(__file__).resolve().parent.parent / "config" / "logscale_syntax.md"
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8")
        return "LogScale syntax reference not found."

    # ------------------------------------------------------------------
    # SOC Process Documentation
    # ------------------------------------------------------------------

    @mcp.resource("socai://incident-handling")
    def incident_handling() -> str:
        """Incident handling process — role priorities, SOAR queue workflow, and escalation rules.

        Covers analyst role levels (L1-L3), priority ceilings per role,
        alert sorting criteria, SOAR filter usage, and morning clean-up procedure.
        Read this to understand queue management and escalation paths.
        """
        _require_scope("investigations:read")

        import pathlib
        doc_path = pathlib.Path(__file__).resolve().parent.parent / "docs" / "incident-handling.md"
        if doc_path.exists():
            return doc_path.read_text(encoding="utf-8")
        return "Incident handling documentation not found."

    @mcp.resource("socai://service-requests")
    def service_requests() -> str:
        """Service request process — SD queue monitoring, ticket handling, and Teams escalation.

        Covers Service Desk queues to monitor, ticket lifecycle (security incident,
        request, auto-reply), merging tickets safely, blueprint usage, closure notices,
        and Teams channel responsibilities.
        """
        _require_scope("investigations:read")

        import pathlib
        doc_path = pathlib.Path(__file__).resolve().parent.parent / "docs" / "service-requests.md"
        if doc_path.exists():
            return doc_path.read_text(encoding="utf-8")
        return "Service requests documentation not found."

    @mcp.resource("socai://time-tracking")
    def time_tracking() -> str:
        """Time tracking process — Kantata project categories, overtime logging, and on-call hours.

        Covers XDR team time entry categories, overtime multipliers (1.5x/2x),
        on-call day logging, ad-hoc overtime approval template, and leave logging.
        """
        _require_scope("investigations:read")

        import pathlib
        doc_path = pathlib.Path(__file__).resolve().parent.parent / "docs" / "time-tracking.md"
        if doc_path.exists():
            return doc_path.read_text(encoding="utf-8")
        return "Time tracking documentation not found."

    @mcp.resource("socai://critical-incident-management")
    def critical_incident_management() -> str:
        """Critical/High incident management — P1/P2 checklists, war rooms, and escalation.

        Covers manager and analyst checklists for P1/P2 incidents, client call guidelines,
        P1 classification criteria, technical report structure (initial access, compromised
        assets, lateral movement, exfiltration, containment), and IR activation criteria.
        """
        _require_scope("investigations:read")

        import pathlib
        doc_path = pathlib.Path(__file__).resolve().parent.parent / "docs" / "critical-incident-management.md"
        if doc_path.exists():
            return doc_path.read_text(encoding="utf-8")
        return "Critical incident management documentation not found."

    # ------------------------------------------------------------------
    # NGSIEM / LogScale Detection References
    # ------------------------------------------------------------------

    @mcp.resource("socai://ngsiem-rules")
    def ngsiem_rules() -> str:
        """NGSIEM (LogScale/CQL) detection rule authoring rules.

        Syntax conventions, proven query patterns, anti-patterns, ECS field
        naming, log source tag mapping (#Vendor + #event.module), pipeline
        structure, DaC template fields, and worked examples (Kerberoasting,
        port scan, AWS IAM escalation).  Read this before writing or
        reviewing any NGSIEM detection rule.
        """
        _require_scope("sentinel:query")

        import pathlib
        ref_path = pathlib.Path(__file__).resolve().parent.parent / "config" / "ngsiem" / "ngsiem_rules.md"
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8")
        return "NGSIEM rules reference not found."

    @mcp.resource("socai://ngsiem-columns")
    def ngsiem_columns() -> str:
        """NGSIEM field schema per connector / data source.

        Lists every field (ECS + vendor-specific) available per log source:
        Fortinet FortiGate, Azure AD sign-in, ClearPass, Windows events,
        Check Point, Cribl, DNS, and more.  Includes common metadata,
        tag fields, and discovery queries.  Use this to pick the correct
        field names when building LogScale queries.
        """
        _require_scope("sentinel:query")

        import pathlib
        ref_path = pathlib.Path(__file__).resolve().parent.parent / "config" / "ngsiem" / "ngsiem_columns.yaml"
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8")
        return "NGSIEM columns schema not found."

    @mcp.resource("socai://cql-grammar")
    def cql_grammar() -> str:
        """Complete CQL function grammar — 194 functions across 12 categories.

        Every LogScale/CQL function with label, description, documentation,
        and insert-text snippet.  Categories: aggregate, filtering, time,
        transformation, parsing, array, math, text, network, encoding,
        flow, lookup.  Use this as the authoritative function reference
        when writing or reviewing CQL queries.
        """
        _require_scope("sentinel:query")

        import pathlib
        ref_path = pathlib.Path(__file__).resolve().parent.parent / "config" / "ngsiem" / "cql_grammar.json"
        if ref_path.exists():
            return ref_path.read_text(encoding="utf-8")
        return "CQL grammar reference not found."

    # ------------------------------------------------------------------
    # Client Response Playbooks
    # ------------------------------------------------------------------

    @mcp.resource("socai://clients/{client_name}/playbook")
    def client_playbook(client_name: str) -> str:
        """Client-specific response playbook: escalation matrix, containment
        capabilities, remediation actions, crown jewels, and contact procedures.

        Use this to understand what response actions are available for a client
        BEFORE calling ``response_actions``.  Tells you:
        - What containment actions the SOC can take (EDR isolate, password reset, etc.)
        - What remediation actions the client owns (email purge, network blocklist, etc.)
        - Escalation matrix by priority and asset type (when to phone, when to ticket)
        - Crown jewel hosts that trigger P1 escalation if compromised
        """
        _require_scope("investigations:read")

        path = _resolve_client_playbook(client_name)
        if not path:
            return _json({"error": f"No response playbook found for client {client_name!r}."})

        from tools.common import load_json
        data = load_json(path)
        playbook = {
            "client_name": data.get("client_name", client_name),
            "escalation_matrix": data.get("escalation_matrix", []),
            "containment_capabilities": data.get("containment_capabilities", []),
            "remediation_actions": data.get("remediation_actions", []),
            "crown_jewels": data.get("crown_jewels", {}),
            "contacts": data.get("contacts", []),
            "response_notes": [
                r.get("action_to_be_taken", "")
                for r in data.get("response", [])
                if r.get("action_to_be_taken")
            ],
        }
        # Include environment-specific fields if present
        if "environments" in data:
            playbook["environments"] = data["environments"]
        if "escalation_matrix_ot" in data:
            playbook["escalation_matrix_ot"] = data["escalation_matrix_ot"]
        return _json(playbook)

    @mcp.resource("socai://clients/{client_name}/knowledge")
    def client_knowledge(client_name: str) -> str:
        """Client knowledge base — persistent context about the client's
        environment, security stack, identity infrastructure, network
        topology, known legitimate software, historical patterns, and
        analyst notes.

        Read this at the start of every investigation to have instant
        context without needing to ask. The knowledge base is a markdown
        file maintained by analysts and updated as investigations reveal
        new information about the client.
        """
        _require_scope("investigations:read")

        path = _resolve_client_knowledge(client_name)
        if not path:
            return _json({"error": f"No knowledge base found for client {client_name!r}."})

        return path.read_text(encoding="utf-8")

    @mcp.resource("socai://clients/{client_name}/sentinel")
    def client_sentinel(client_name: str) -> str:
        """Sentinel workspace reference for a client — workspace ID,
        available tables with descriptions, and key query patterns.

        Read this before building KQL queries to know which tables
        exist and what fields to use.
        """
        _require_scope("investigations:read")

        from config.settings import CLIENT_PLAYBOOKS_DIR as CLIENTS_DIR
        candidates = [
            CLIENTS_DIR / client_name / "sentinel.md",
            CLIENTS_DIR / client_name.lower().replace(" ", "_") / "sentinel.md",
        ]
        for p in candidates:
            if p.exists():
                return p.read_text(encoding="utf-8")
        return _json({"error": f"No Sentinel reference found for client {client_name!r}."})

    # ------------------------------------------------------------------
    # Pipeline Profiles (Attack-Type Routing)
    # ------------------------------------------------------------------

    @mcp.resource("socai://pipeline-profiles")
    def pipeline_profiles() -> str:
        """Attack-type pipeline profiles — which investigation steps to run
        or skip for each attack type.

        Each profile includes:
        - **skip** — steps excluded for this attack type
        - **description** — what the investigation focuses on

        Attack types: phishing, malware, account_compromise,
        privilege_escalation, pup_pua, generic.

        The LLM should read this to understand investigation routing.
        Use ``classify_attack`` or ``plan_investigation`` tools for
        per-case classification.
        """
        _require_scope("investigations:read")

        from tools.classify_attack import PIPELINE_PROFILES, ATTACK_TYPES

        profiles = {}
        for at in ATTACK_TYPES:
            profile = PIPELINE_PROFILES.get(at, {})
            profiles[at] = {
                "skip": sorted(profile.get("skip", set())),
                "description": profile.get("description", ""),
            }
        return _json({"profiles": profiles, "attack_types": list(ATTACK_TYPES)})

    # ------------------------------------------------------------------
    # Enrichment Provider Configuration
    # ------------------------------------------------------------------

    @mcp.resource("socai://enrichment-providers")
    def enrichment_providers() -> str:
        """Configured enrichment providers and their availability.

        Shows which threat intelligence providers are configured (have API
        keys) and available for use. Read this to understand what enrichment
        sources are available before running ``enrich_iocs``.
        """
        _require_scope("investigations:read")

        import os

        providers = {
            "ip": {
                "tier1_fast": [
                    {"name": "AbuseIPDB", "configured": bool(os.environ.get("ABUSEIPDB_KEY"))},
                    {"name": "URLhaus", "configured": True},  # No key required
                    {"name": "ThreatFox", "configured": True},  # No key required
                    {"name": "OpenCTI", "configured": bool(os.environ.get("OPENCTI_URL") and os.environ.get("OPENCTI_TOKEN"))},
                    {"name": "WhoisXML (ASN)", "configured": bool(os.environ.get("WHOISXML_KEY"))},
                ],
                "tier2_deep": [
                    {"name": "VirusTotal", "configured": bool(os.environ.get("VT_API_KEY"))},
                    {"name": "Shodan", "configured": bool(os.environ.get("SHODAN_KEY"))},
                    {"name": "GreyNoise", "configured": bool(os.environ.get("GREYNOISE_KEY"))},
                    {"name": "ProxyCheck", "configured": bool(os.environ.get("PROXYCHECK_KEY"))},
                    {"name": "Censys", "configured": bool(os.environ.get("CENSYS_API_ID") and os.environ.get("CENSYS_API_SECRET"))},
                    {"name": "OTX", "configured": bool(os.environ.get("OTX_KEY"))},
                ],
            },
            "domain": {
                "tier1_fast": [
                    {"name": "URLhaus", "configured": True},
                    {"name": "ThreatFox", "configured": True},
                    {"name": "OpenCTI", "configured": bool(os.environ.get("OPENCTI_URL") and os.environ.get("OPENCTI_TOKEN"))},
                    {"name": "WhoisXML", "configured": bool(os.environ.get("WHOISXML_KEY"))},
                ],
                "tier2_deep": [
                    {"name": "VirusTotal", "configured": bool(os.environ.get("VT_API_KEY"))},
                    {"name": "urlscan.io", "configured": bool(os.environ.get("URLSCAN_KEY"))},
                    {"name": "Censys", "configured": bool(os.environ.get("CENSYS_API_ID") and os.environ.get("CENSYS_API_SECRET"))},
                    {"name": "OTX", "configured": bool(os.environ.get("OTX_KEY"))},
                ],
            },
            "url": {
                "tier1_fast": [
                    {"name": "URLhaus", "configured": True},
                    {"name": "ThreatFox", "configured": True},
                    {"name": "OpenCTI", "configured": bool(os.environ.get("OPENCTI_URL") and os.environ.get("OPENCTI_TOKEN"))},
                ],
                "tier2_deep": [
                    {"name": "VirusTotal", "configured": bool(os.environ.get("VT_API_KEY"))},
                    {"name": "urlscan.io", "configured": bool(os.environ.get("URLSCAN_KEY"))},
                    {"name": "OTX", "configured": bool(os.environ.get("OTX_KEY"))},
                ],
            },
            "hash": {
                "tier1_fast": [
                    {"name": "MalwareBazaar", "configured": True},
                    {"name": "ThreatFox", "configured": True},
                    {"name": "OpenCTI", "configured": bool(os.environ.get("OPENCTI_URL") and os.environ.get("OPENCTI_TOKEN"))},
                ],
                "tier2_deep": [
                    {"name": "VirusTotal", "configured": bool(os.environ.get("VT_API_KEY"))},
                    {"name": "Intezer", "configured": bool(os.environ.get("INTEZER_KEY"))},
                    {"name": "OTX", "configured": bool(os.environ.get("OTX_KEY"))},
                ],
            },
        }

        # Summary counts
        total = 0
        configured = 0
        for ioc_type_providers in providers.values():
            for tier_providers in ioc_type_providers.values():
                for p in tier_providers:
                    total += 1
                    if p["configured"]:
                        configured += 1

        return _json({
            "providers": providers,
            "summary": {
                "total_provider_slots": total,
                "configured": configured,
                "unconfigured": total - configured,
            },
            "enrichment_director": "deterministic",
            "tier_escalation": (
                "Tier 1 (fast/free) runs on all IOCs. Tier 2 (deep) runs only on "
                "IOCs where Tier 1 returns suspicious/malicious signals, ambiguous "
                "results, or no data."
            ),
        })

    # ------------------------------------------------------------------
    # IOC Index
    # ------------------------------------------------------------------

    @mcp.resource("socai://ioc-index/stats")
    def ioc_index_stats() -> str:
        """IOC index summary with tier breakdown and top recurring indicators."""
        _require_scope("investigations:read")

        from config.settings import IOC_INDEX_FILE
        from tools.common import load_json

        if not IOC_INDEX_FILE.exists():
            return _json({"total": 0, "tiers": {}, "top_recurring": []})

        index = load_json(IOC_INDEX_FILE)
        tiers: dict[str, int] = {"global": 0, "client": 0}
        by_type: dict[str, int] = {}
        by_verdict: dict[str, int] = {}
        recurring: list[dict] = []

        for ioc, entry in index.items():
            tier = entry.get("tier", "global")
            tiers[tier] = tiers.get(tier, 0) + 1
            ioc_type = entry.get("ioc_type", "unknown")
            by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
            verdict = entry.get("verdict", "unknown")
            by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
            cases = entry.get("cases", [])
            if len(cases) > 1:
                recurring.append({
                    "ioc": ioc,
                    "type": ioc_type,
                    "tier": tier,
                    "verdict": verdict,
                    "case_count": len(cases),
                })

        recurring.sort(key=lambda r: r["case_count"], reverse=True)

        return _json({
            "total": len(index),
            "tiers": tiers,
            "by_type": by_type,
            "by_verdict": by_verdict,
            "recurring_count": len(recurring),
            "top_recurring": recurring[:20],
        })

    # ------------------------------------------------------------------
    # Threat Articles
    # ------------------------------------------------------------------

    @mcp.resource("socai://articles")
    def threat_article_index() -> str:
        """Threat article index."""
        _require_scope("campaigns:read")

        from tools.threat_articles import list_articles
        articles = list_articles()
        return _json({"articles": articles, "count": len(articles)})

    @mcp.resource("socai://landscape")
    def threat_landscape() -> str:
        """Threat landscape summary across recent cases."""
        _require_scope("campaigns:read")

        from tools.case_landscape import assess_landscape
        return _json(assess_landscape())

    # ------------------------------------------------------------------
    # Analyst Role
    # ------------------------------------------------------------------

    @mcp.resource("socai://role")
    def analyst_role() -> str:
        """Current analyst's role, permissions, and behavioural instructions.

        Read this resource at session start to adapt tone, explanation depth,
        and response style to the analyst's experience level.

        Roles: junior_mdr (learning, needs guidance), mdr_analyst (standard),
        senior_analyst (peer-level, deep IR).
        """
        from mcp_server.auth import (
            _get_caller_email, _get_caller_role,
            _get_role_instructions, _get_role_guidance,
        )
        from api.auth import get_role

        role_name = _get_caller_role()
        role_def = get_role(role_name) or {}

        return _json({
            "analyst": _get_caller_email(),
            "role": role_name,
            "title": role_def.get("title", role_name),
            "severity_ceiling": role_def.get("severity_ceiling", "critical"),
            "response_authority": role_def.get("response_authority", "containment"),
            "guidance": _get_role_guidance(),
            "instructions": _get_role_instructions(),
        })

    # ------------------------------------------------------------------
    # Capabilities overview
    # ------------------------------------------------------------------

    @mcp.resource("socai://capabilities")
    def capabilities_overview() -> str:
        """Complete capability map for the local Claude Desktop agent.

        Read this FIRST in every session to understand what you can do,
        what persists to disk, and how workflows are structured.
        """
        return _json({
            "architecture": {
                "model": "Centralised tools + local agent",
                "server": "MCP server — stateless data tools, enrichment, SIEM queries, persistence. No LLM reasoning.",
                "agent": "Local Claude Desktop — all analysis, reasoning, report writing. Drives investigation via tools and prompts.",
                "persistence": "Only essential artefacts saved to disk: case meta, IOCs, enrichment verdicts, final HTML reports, web captures, email evidence, sandbox telemetry, forensic data.",
            },
            "start_here": (
                "1. Read socai://role for your analyst permissions.\n"
                "2. Call lookup_client — returns platforms PLUS full knowledge base, response playbook, and Sentinel reference. Read and internalise before proceeding.\n"
                "3. Call classify_attack or plan_investigation with alert data.\n"
                "4. Follow the returned plan, calling tools step by step.\n"
                "5. When ready to deliver, use a write_* prompt then save_report."
            ),
            "tools": {
                "data_gathering": {
                    "description": "Tools that collect, extract, and enrich data. Call these to build your evidence base.",
                    "tools": {
                        "enrich_iocs": "Enrich IOCs against 15+ TI providers (VT, AbuseIPDB, Shodan, etc.). Saves IOCs + verdicts to disk.",
                        "quick_enrich": "Fast IOC enrichment without a case. Returns results only.",
                        "extract_iocs_from_text": "Regex IOC extraction from raw text. No case needed.",
                        "capture_urls": "Headless browser capture — screenshots, HTML, redirects. Saves to disk as evidence.",
                        "detect_phishing": "Tier 1 (brand regex) + Tier 2 (heuristic scoring) phishing detection. Returns verdict.",
                        "analyse_email": "Parse .eml files — headers, auth, URLs, attachments. Saves to disk as evidence.",
                        "correlate": "Cross-reference IOCs against parsed logs. Returns correlation data (not saved).",
                        "detect_anomalies": "Behavioural anomaly detection in parsed logs. Returns findings (not saved).",
                        "reconstruct_timeline": "Assemble forensic timeline from all artefacts. Returns events (not saved).",
                        "correlate_evtx": "Windows event log attack chain detection. Returns chains (not saved).",
                        "contextualise_cves": "NVD/EPSS/KEV lookups for CVEs. Returns context (not saved).",
                        "parse_logs": "Parse CSV/JSON/JSONL log files. Saves parsed output to disk.",
                        "analyse_pe": "Deep PE file analysis — imports, entropy, packers. Saves to disk.",
                        "yara_scan": "YARA rule scanning against case files. Saves results to disk.",
                        "sandbox_lookup": "Query sandbox providers (VT, Joe, Triage) for file hashes.",
                    },
                },
                "siem_and_queries": {
                    "description": "Query SIEM platforms and generate hunt queries.",
                    "tools": {
                        "lookup_client": "Identify client, confirm SIEM platforms and workspace IDs. Returns full knowledge base, response playbook, and Sentinel reference inline. Call FIRST.",
                        "run_kql": "Execute KQL query against Azure Sentinel. Read-only.",
                        "run_kql_batch": "Execute multiple KQL queries in parallel.",
                        "load_kql_playbook": "Load a KQL investigation playbook template.",
                        "generate_sentinel_query": "Generate composite Sentinel queries from scenario templates.",
                        "generate_queries": "Generate hunt queries for KQL/Splunk/LogScale from case IOCs. Now includes contextual queries (process tree, DNS, network, file writes, detections) when case has CrowdStrike pivot data.",
                        "load_ngsiem_reference": "Load CQL/LogScale syntax reference material. Call BEFORE writing any CrowdStrike/NGSIEM query. Sections: rules, columns, grammar, syntax. No case required.",
                    },
                },
                "case_management": {
                    "description": "Create, read, update, and close cases. These manage the persistent case record.",
                    "tools": {
                        "create_case": "Create a new case with title, severity, client, tags.",
                        "promote_case": "Promote triage case to active investigation.",
                        "discard_case": "Discard a triage case (noise/duplicate).",
                        "close_case": "Close a case with disposition.",
                        "list_cases": "List all registered cases with status/severity filters.",
                        "get_case": "Read case metadata.",
                        "case_summary": "Compact case summary with IOC/verdict/finding counts.",
                        "read_report": "Read the final HTML report for a case.",
                        "read_case_file": "Read any file from a case directory.",
                        "list_case_files": "List all files in a case directory.",
                        "add_evidence": "Attach raw evidence (alert JSON, IOC lists, notes) to a case.",
                        "add_finding": "Record an analytical conclusion against a case.",
                        "link_cases": "Create bidirectional link between related cases.",
                        "merge_cases": "Merge IOCs and evidence from one case into another.",
                        "new_investigation": "Semantic marker — signals a fresh investigation context.",
                    },
                },
                "report_delivery": {
                    "description": "These tools trigger the prompt+save workflow for deliverables. They auto-create cases if needed.",
                    "tools": {
                        "prepare_mdr_report": "Loads context for write_mdr_report prompt → save_report. Primary client deliverable.",
                        "prepare_pup_report": "Loads context for write_pup_report prompt → save_report.",
                        "prepare_executive_summary": "Loads context for write_executive_summary prompt → save_report.",
                        "prepare_fp_ticket": "Loads context for write_fp_closure prompt → save_report.",
                        "prepare_fp_tuning_ticket": "Loads context for write_fp_tuning prompt → save_report.",
                        "security_arch_review": "Redirects to write_security_arch_review prompt → save_report.",
                        "save_report": "Persist a locally-written report as HTML. Handles defanging, auto-close, audit.",
                        "save_threat_article": "Persist a threat intelligence article to the article registry.",
                    },
                },
                "cross_case_intelligence": {
                    "description": "Search across cases and threat intelligence.",
                    "tools": {
                        "recall_cases": "BM25 semantic search across all historical cases. Call before enrichment.",
                        "campaign_cluster": "Find IOC overlap across cases. Returns campaign links (not saved per-case).",
                        "assess_landscape": "Holistic threat landscape across recent cases.",
                        "search_threat_articles": "Search existing threat articles by keyword.",
                        "web_search": "OSINT web search (Brave/DuckDuckGo). Last resort after system tools.",
                    },
                },
                "dynamic_analysis": {
                    "description": "Sandbox detonation and disposable browser sessions.",
                    "tools": {
                        "start_sandbox_session": "Detonate a sample in an isolated sandbox.",
                        "stop_sandbox_session": "Stop sandbox and collect telemetry.",
                        "start_browser_session": "Browse a URL in a disposable browser.",
                        "stop_browser_session": "Stop browser and collect artefacts.",
                    },
                },
                "forensic_ingestion": {
                    "description": "Ingest endpoint forensic packages.",
                    "tools": {
                        "ingest_velociraptor": "Ingest Velociraptor collection ZIP. Parses artefacts, extracts entities.",
                        "ingest_mde_package": "Ingest MDE investigation package. Parses logs, EVTX, prefetch.",
                    },
                },
                "soc_processes": {
                    "description": "SOC operational processes and policies. Use lookup_soc_process for ALL process/policy questions — NOT search_confluence.",
                    "tools": {
                        "lookup_soc_process": "Look up SOC processes: incident handling, P1/P2 critical incidents, service desk, time tracking. Accepts topic name or keywords (e.g. 'p1', 'escalation', 'overtime').",
                    },
                },
                "dark_web_intelligence": {
                    "description": "Check dark web sources for credential theft, breach exposure, infostealer data, and dark web mentions. Use during account compromise, credential theft, or when assessing user/domain exposure.",
                    "tools": {
                        "hudsonrock_lookup": "Check infostealer exposure for email/domain/IP — was credential harvested by malware? (Hudson Rock Cavalier)",
                        "xposed_breach_check": "Check historical breach databases — which breaches was this email/domain in? (XposedOrNot)",
                        "ahmia_darkweb_search": "Search indexed .onion sites for keywords, IOCs, or threat actor references (Ahmia.fi, Tor required for full search).",
                        "intelx_search": "Search dark web, paste sites, data leaks, and documents for a specific indicator (Intelligence X).",
                        "parse_stealer_logs": "Parse infostealer log archives (.rar/.zip/.7z) into structured data with credential redaction.",
                        "darkweb_exposure_summary": "Aggregate all dark web exposure data for a case — runs Hudson Rock + XposedOrNot for all case indicators.",
                    },
                },
            },
            "prompts": {
                "description": "Prompts load system instructions + case context into your session. You do the reasoning, then call a save tool.",
                "guided_workflows": {
                    "hitl_investigation": "Full HITL workflow — intake to delivery with analyst checkpoints.",
                    "triage_alert": "Structured alert triage: classify, extract, enrich, verdict.",
                    "kql_investigation": "Multi-stage KQL playbook (phishing, account-compromise, malware, priv-esc, exfil, lateral-movement, ioc-hunt).",
                    "write_fp_ticket": "FP analysis and suppression workflow.",
                    "user_security_check": "Broad-scope user account security review.",
                },
                "report_writing": {
                    "write_mdr_report": "Gold MDR/XDR Analyst Instruction Set + case data → write report → save_report(type=mdr_report).",
                    "write_pup_report": "PUP/PUA report → save_report(type=pup_report).",
                    "write_fp_closure": "2-sentence FP closure comment → save_report(type=fp_ticket).",
                    "write_fp_tuning": "SIEM engineering tuning ticket → save_report(type=fp_tuning_ticket).",
                    "write_executive_summary": "Non-technical RAG-rated summary → save_report(type=executive_summary).",
                    "write_security_arch_review": "Security architecture gaps and recommendations → save_report(type=security_arch_review).",
                    "write_threat_article": "Threat intelligence article → save_threat_article.",
                    "write_response_plan": "Containment/response plan from client playbook.",
                },
                "analysis": {
                    "run_determination": "Evidence-chain disposition analysis (TP/BP/FP) → add_finding.",
                    "build_investigation_matrix": "Rumsfeld matrix: known knowns, unknowns, hypotheses → add_finding.",
                    "review_report": "Analytical standards quality gate.",
                    "write_timeline": "Forensic timeline narrative.",
                    "write_evtx_analysis": "Windows event log attack chain narrative.",
                    "write_phishing_verdict": "Phishing page assessment.",
                    "write_pe_verdict": "PE binary malware assessment.",
                    "write_cve_context": "CVE contextualisation.",
                },
            },
            "resources": {
                "description": "Read-only data URIs. Use these to inspect case state without calling tools.",
                "case_data": {
                    "socai://cases": "Full case registry (all cases with status/severity).",
                    "socai://cases/{id}/meta": "Case metadata (title, severity, client, disposition).",
                    "socai://cases/{id}/iocs": "Extracted IOCs.",
                    "socai://cases/{id}/verdicts": "Verdict summary (malicious/suspicious/clean).",
                    "socai://cases/{id}/enrichment": "Full enrichment data from all providers.",
                    "socai://cases/{id}/report": "Final HTML report.",
                    "socai://cases/{id}/full": "Complete case bundle.",
                },
                "client_and_config": {
                    "socai://clients": "Client registry.",
                    "socai://clients/{client_name}": "Full client config.",
                    "socai://clients/{client_name}/playbook": "Client response playbook.",
                    "socai://clients/{client_name}/knowledge": "Client knowledge base — environment, security stack, network, identity, historical patterns.",
                    "socai://clients/{client_name}/sentinel": "Sentinel workspace reference — workspace ID, available tables, key query patterns.",
                    "socai://playbooks": "KQL playbook index.",
                    "socai://sentinel-queries": "Composite Sentinel query scenarios.",
                    "socai://logscale-syntax": "LogScale (Humio) query language reference — operators, functions, pitfalls.",
                    "socai://ngsiem-rules": "NGSIEM detection rule authoring — syntax conventions, patterns, anti-patterns, log source tags.",
                    "socai://ngsiem-columns": "NGSIEM field schema per connector — ECS + vendor fields for each data source.",
                    "socai://cql-grammar": "Complete CQL function grammar — 194 functions with signatures and docs.",
                    "socai://enrichment-providers": "Available enrichment providers.",
                },
                "intelligence": {
                    "socai://ioc-index/stats": "IOC index — recurring indicators across cases.",
                    "socai://articles": "Threat article index.",
                    "socai://landscape": "Cross-case threat landscape.",
                },
                "soc_processes": {
                    "_routing": "ALWAYS check these local resources FIRST for any SOC process, policy, escalation, or P1/P2 question. Only use search_confluence if the topic is not covered here.",
                    "socai://incident-handling": "Role priorities (L1-L3), SOAR queue workflow, alert sorting, escalation rules.",
                    "socai://service-requests": "Service Desk queues, ticket lifecycle, merging, blueprint, Teams channels.",
                    "socai://time-tracking": "Kantata time categories, overtime logging (1.5x/2x), on-call hours.",
                    "socai://critical-incident-management": "P1/P2 checklists, war rooms, P1 classification, IR activation, technical report structure.",
                },
                "meta": {
                    "socai://capabilities": "This capability map.",
                    "socai://role": "Your analyst role and permissions.",
                },
            },
            "what_persists_to_disk": [
                "case_meta.json — case identity, severity, client, disposition, timestamps",
                "iocs/iocs.json — extracted IOCs",
                "enrichment/enrichment.json + verdict_summary.json — provider verdicts",
                "Final HTML reports (via save_report) — MDR, PUP, FP, exec summary, sec arch",
                "Web captures — screenshots, HTML, redirect chains (evidence)",
                "Email analysis + attachments (evidence)",
                "Sandbox telemetry — process trees, network capture, filesystem changes",
                "Forensic data — PE analysis, YARA results, MDE/Velociraptor ingests, parsed logs",
                "Registry indexes — case index, IOC index, campaign registry, baselines",
            ],
            "what_does_NOT_persist": [
                "Anomaly reports, correlation, timeline reconstruction, EVTX chains",
                "Hunt queries, triage summaries, CVE context, response action plans",
                "Investigation matrix, determination, quality gate, follow-up proposals",
                "These are computed on demand and returned in-memory to the agent.",
            ],
            "boundaries": [
                "The server has NO LLM — all reasoning is done by you (the local agent).",
                "SIEM queries are READ-ONLY — you cannot write to Sentinel.",
                "Containment actions are RECOMMENDATIONS only — you cannot execute containment.",
                "Reports are HTML-only — no markdown file output.",
                "One alert = one case. Never append to existing cases.",
            ],
            "common_workflows": {
                "phishing": "lookup_client → classify_attack → add_evidence → enrich_iocs → capture_urls → detect_phishing → analyse_email → kql_investigation(playbook=phishing) → write_mdr_report prompt → save_report",
                "malware": "lookup_client → classify_attack → add_evidence → enrich_iocs → analyse_pe → yara_scan → start_sandbox_session → kql_investigation(playbook=malware-execution) → write_mdr_report prompt → save_report",
                "account_compromise": "lookup_client → classify_attack → add_evidence → enrich_iocs → kql_investigation(playbook=account-compromise) → detect_anomalies → write_mdr_report prompt → save_report",
                "false_positive": "add_evidence → enrich_iocs → write_fp_closure prompt → save_report(type=fp_ticket) → optionally write_fp_tuning prompt → save_report(type=fp_tuning_ticket)",
                "pup_pua": "classify_attack → enrich_iocs → write_pup_report prompt → save_report(type=pup_report)",
            },
        })
