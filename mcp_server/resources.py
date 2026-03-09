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
