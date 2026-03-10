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
