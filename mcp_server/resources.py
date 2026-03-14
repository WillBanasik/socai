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

        path = CASES_DIR / case_id / "artefacts" / "iocs.json"
        if not path.exists():
            return _json({"error": "No IOCs found.", "iocs": {}})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/verdicts")
    def case_verdicts(case_id: str) -> str:
        """Verdict summary JSON."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "verdicts.json"
        if not path.exists():
            return _json({"error": "No verdicts found."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/enrichment")
    def case_enrichment(case_id: str) -> str:
        """Enrichment data JSON."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "enrichment.json"
        if not path.exists():
            return _json({"error": "No enrichment data found."})
        return _json(load_json(path))

    @mcp.resource("socai://cases/{case_id}/timeline")
    def case_timeline(case_id: str) -> str:
        """Timeline events JSON."""
        _require_scope("investigations:read")

        from config.settings import CASES_DIR
        from tools.common import load_json

        path = CASES_DIR / case_id / "artefacts" / "timeline.json"
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

        from config.settings import CLIENT_PLAYBOOKS_DIR as CLIENTS_DIR
        from tools.common import load_json

        # Try exact name, then lowercase
        path = CLIENTS_DIR / f"{client_name}.json"
        if not path.exists():
            path = CLIENTS_DIR / f"{client_name.lower().replace(' ', '_')}.json"
        if not path.exists():
            # Search by client_name field inside JSON files
            for p in CLIENTS_DIR.glob("*.json"):
                try:
                    data = load_json(p)
                    if data.get("client_name", "").lower() == client_name.lower():
                        path = p
                        break
                except Exception:
                    continue
            else:
                return _json({"error": f"No response playbook found for client {client_name!r}."})

        data = load_json(path)
        # Return the response-relevant sections (strip raw contacts for privacy)
        playbook = {
            "client_name": data.get("client_name", client_name),
            "escalation_matrix": data.get("escalation_matrix", []),
            "containment_capabilities": data.get("containment_capabilities", []),
            "remediation_actions": data.get("remediation_actions", []),
            "crown_jewels": data.get("crown_jewels", {}),
            "response_notes": [
                r.get("action_to_be_taken", "")
                for r in data.get("response", [])
                if r.get("action_to_be_taken")
            ],
        }
        return _json(playbook)

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
        """Structured overview of all SOCAI tools, prompts, and resources.

        Read this resource to answer "what can you do?" in a single call
        instead of enumerating tool schemas.
        """
        return _json({
            "platform": "SOCAI — SOC Investigation Platform",
            "start_here": (
                "Call classify_attack or plan_investigation with alert data to get "
                "an attack-type classification and step-by-step tool sequence. "
                "Follow the returned plan."
            ),
            "tools": {
                "total": 77,
                "categories": {
                    "investigation_and_triage": {
                        "description": "Classify alerts and plan investigations",
                        "tools": [
                            "classify_attack", "plan_investigation",
                            "create_case", "promote_case", "discard_case",
                            "quick_enrich",
                        ],
                    },
                    "case_management": {
                        "description": "Create, read, update, close, link, and merge cases",
                        "tools": [
                            "list_cases", "get_case", "case_summary", "read_report",
                            "read_case_file", "new_investigation", "close_case",
                            "link_cases", "merge_cases", "add_evidence", "add_finding",
                        ],
                    },
                    "enrichment_and_analysis": {
                        "description": "Enrich IOCs, correlate across cases, check CVEs, and search OSINT",
                        "tools": [
                            "enrich_iocs", "correlate", "contextualise_cves",
                            "recall_cases", "campaign_cluster", "web_search",
                        ],
                    },
                    "email_and_phishing": {
                        "description": "Parse emails, capture URLs, and detect phishing pages",
                        "tools": ["analyse_email", "capture_urls", "detect_phishing"],
                    },
                    "log_analysis_and_forensics": {
                        "description": "Parse logs, detect anomalies, correlate Windows event logs, and reconstruct timelines",
                        "tools": [
                            "parse_logs", "detect_anomalies", "correlate_evtx",
                            "reconstruct_timeline",
                        ],
                    },
                    "binary_and_memory_analysis": {
                        "description": "Static PE analysis, YARA scanning, and process memory dump analysis",
                        "tools": [
                            "analyse_pe", "yara_scan",
                            "memory_dump_guide", "analyse_memory_dump",
                        ],
                    },
                    "siem_and_endpoint": {
                        "description": "Query Sentinel, load KQL playbooks, generate hunt queries, ingest endpoint packages",
                        "tools": [
                            "lookup_client", "run_kql", "load_kql_playbook",
                            "generate_sentinel_query", "generate_queries",
                            "ingest_velociraptor", "ingest_mde_package",
                        ],
                    },
                    "dynamic_analysis": {
                        "description": "Detonate malware in sandboxes and browse suspicious sites in disposable browsers",
                        "tools": [
                            "start_sandbox_session", "stop_sandbox_session",
                            "list_sandbox_sessions", "start_browser_session",
                            "stop_browser_session", "list_browser_sessions",
                        ],
                    },
                    "reporting": {
                        "description": "Generate investigation reports, MDR deliverables, executive summaries, and response guidance",
                        "tools": [
                            "generate_report", "generate_mdr_report", "generate_pup_report",
                            "generate_executive_summary", "generate_weekly",
                            "generate_fp_ticket", "generate_fp_tuning_ticket",
                            "security_arch_review", "response_actions",
                        ],
                    },
                    "threat_intelligence": {
                        "description": "Assess threat landscape, search and generate threat articles",
                        "tools": [
                            "assess_landscape", "search_threat_articles",
                            "generate_threat_article",
                        ],
                    },
                },
            },
            "prompts": {
                "total": 16,
                "items": [
                    {
                        "name": "hitl_investigation",
                        "description": "HITL investigation workflow — analyst-controlled checkpoints from intake to delivery.",
                    },
                    {
                        "name": "triage_alert",
                        "description": "Structured alert triage: classify, extract IOCs, enrich, verdict, next steps.",
                    },
                    {
                        "name": "write_fp_ticket",
                        "description": "False-positive analysis and suppression ticket generation.",
                    },
                    {
                        "name": "kql_investigation",
                        "description": "Unified KQL playbook prompt. Select a playbook: phishing, account-compromise, malware-execution, privilege-escalation, data-exfiltration, lateral-movement, or ioc-hunt.",
                    },
                    {
                        "name": "user_security_check",
                        "description": "Broad-scope security review of a specific user account.",
                    },
                    {
                        "name": "write_mdr_report",
                        "description": "Client-side MDR report generation — loads Gold Analyst Instruction Set + case data into local session.",
                    },
                    {
                        "name": "write_pup_report",
                        "description": "Client-side PUP/PUA report generation.",
                    },
                    {
                        "name": "write_fp_closure",
                        "description": "Client-side FP closure comment generation.",
                    },
                    {
                        "name": "write_fp_tuning",
                        "description": "Client-side SIEM engineering tuning ticket generation.",
                    },
                    {
                        "name": "write_executive_summary",
                        "description": "Client-side executive summary generation (RAG rated, non-technical).",
                    },
                    {
                        "name": "write_security_arch_review",
                        "description": "Client-side security architecture review generation.",
                    },
                    {
                        "name": "write_threat_article",
                        "description": "Client-side threat article generation — local web search, research, and writing.",
                    },
                    {
                        "name": "write_response_plan",
                        "description": "Client-side containment/response plan from client playbook.",
                    },
                    {
                        "name": "run_determination",
                        "description": "Client-side evidence-chain disposition analysis (TP/BP/FP determination).",
                    },
                    {
                        "name": "build_investigation_matrix",
                        "description": "Client-side Rumsfeld investigation matrix (known knowns, known unknowns, hypotheses).",
                    },
                    {
                        "name": "review_report",
                        "description": "Client-side report quality gate review (unconfirmed claims, speculation, gaps).",
                    },
                ],
            },
            "resources": {
                "total": 26,
                "uris": [
                    {"uri": "socai://capabilities", "description": "This overview"},
                    {"uri": "socai://role", "description": "Current analyst role, permissions, and behavioural instructions"},
                    {"uri": "socai://cases", "description": "Full case registry"},
                    {"uri": "socai://cases/{case_id}/meta", "description": "Case metadata"},
                    {"uri": "socai://cases/{case_id}/report", "description": "Investigation report markdown"},
                    {"uri": "socai://cases/{case_id}/iocs", "description": "Extracted IOCs"},
                    {"uri": "socai://cases/{case_id}/verdicts", "description": "Verdict summary"},
                    {"uri": "socai://cases/{case_id}/enrichment", "description": "Enrichment data"},
                    {"uri": "socai://cases/{case_id}/timeline", "description": "Timeline events"},
                    {"uri": "socai://cases/{case_id}/notes", "description": "Analyst notes"},
                    {"uri": "socai://cases/{case_id}/response-actions", "description": "Client response actions and containment plan"},
                    {"uri": "socai://cases/{case_id}/fp-ticket", "description": "Existing FP closure comment"},
                    {"uri": "socai://cases/{case_id}/matrix", "description": "Investigation reasoning matrix (Rumsfeld method)"},
                    {"uri": "socai://cases/{case_id}/determination", "description": "Evidence-chain determination analysis"},
                    {"uri": "socai://cases/{case_id}/quality-gate", "description": "Report quality gate review results"},
                    {"uri": "socai://cases/{case_id}/followups", "description": "Follow-up investigation proposals"},
                    {"uri": "socai://clients", "description": "Client registry with platform scope"},
                    {"uri": "socai://clients/{name}", "description": "Full client configuration"},
                    {"uri": "socai://clients/{name}/playbook", "description": "Client response playbook"},
                    {"uri": "socai://playbooks", "description": "KQL playbook index"},
                    {"uri": "socai://playbooks/{id}", "description": "Full KQL playbook with stages"},
                    {"uri": "socai://sentinel-queries", "description": "Sentinel composite query scenarios"},
                    {"uri": "socai://pipeline-profiles", "description": "Attack-type routing profiles"},
                    {"uri": "socai://ioc-index/stats", "description": "IOC index summary with recurring indicators"},
                    {"uri": "socai://articles", "description": "Threat article index"},
                    {"uri": "socai://landscape", "description": "Threat landscape across recent cases"},
                ],
            },
            "common_workflows": {
                "phishing": "lookup_client → classify_attack → add_evidence → enrich_iocs → capture_urls → detect_phishing → analyse_email → run_kql → generate_mdr_report",
                "malware": "lookup_client → classify_attack → add_evidence → enrich_iocs → analyse_pe → yara_scan → start_sandbox_session → run_kql → generate_mdr_report",
                "account_compromise": "lookup_client → classify_attack → add_evidence → enrich_iocs → run_kql → detect_anomalies → correlate_evtx → generate_mdr_report",
                "endpoint_forensics": "lookup_client → classify_attack → ingest_velociraptor (or ingest_mde_package) → parse_logs → detect_anomalies → correlate_evtx → enrich_iocs → generate_mdr_report",
                "memory_forensics": "lookup_client → classify_attack → memory_dump_guide → analyse_memory_dump → enrich_iocs → generate_mdr_report",
                "false_positive": "add_evidence → enrich_iocs → generate_fp_ticket → generate_fp_tuning_ticket (if tuning needed)",
                "pup_pua": "classify_attack → enrich_iocs → generate_pup_report",
            },
            "rules": [
                "Always identify the client (lookup_client) before running SIEM queries.",
                "Always call recall_cases before enrichment to check prior investigations.",
                "Reports auto-close cases: generate_mdr_report, generate_pup_report, generate_fp_ticket.",
                "Every finding must be provable with data — never speculate or fill evidence gaps.",
            ],
        })
