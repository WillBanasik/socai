"""socai MCP server — HTTPS SSE transport with JWT RBAC.

Standalone process on port 8001. Shares filesystem state (cases/, registry/)
with the CLI. Stateless against the same data.

Usage::

    # SSE transport (default)
    python -m mcp_server

    # Streamable HTTP
    SOCAI_MCP_TRANSPORT=streamable-http python -m mcp_server

    # stdio (Claude Desktop backward compat — no auth)
    SOCAI_MCP_TRANSPORT=stdio python -m mcp_server

    # Custom port / host
    SOCAI_MCP_PORT=9001 SOCAI_MCP_HOST=127.0.0.1 python -m mcp_server

Environment variables:

    SOCAI_MCP_PORT          Port (default: 8001)
    SOCAI_MCP_HOST          Bind address (default: 0.0.0.0)
    SOCAI_MCP_TRANSPORT     "sse" (default), "streamable-http", or "stdio"
    SOCAI_MCP_AUTH          "local" (default) or "entra_id" (future)
    SOCAI_MCP_MOUNT_PATH    Mount path (default: "/")
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is on sys.path (same pattern as socai.py)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server.fastmcp import FastMCP

from mcp_server.config import MCP_HOST, MCP_PORT, MCP_TRANSPORT, MCP_AUTH_MODE, MCP_MOUNT_PATH
from mcp_server.auth import SocaiTokenVerifier
from mcp_server.tools import register_tools
from mcp_server.resources import register_resources
from mcp_server.prompts import register_prompts


def _build_auth_settings():
    """Build MCP AuthSettings for the configured auth mode."""
    from mcp.server.fastmcp.server import AuthSettings

    if MCP_AUTH_MODE == "entra_id":
        raise NotImplementedError(
            "Entra ID auth not yet implemented. Set SOCAI_MCP_AUTH=local."
        )

    return AuthSettings(
        issuer_url=f"http://{MCP_HOST}:{MCP_PORT}",
        resource_server_url=f"http://{MCP_HOST}:{MCP_PORT}",
        required_scopes=[],  # Per-tool RBAC, not transport-level scopes
    )


_SERVER_INSTRUCTIONS = """\
SOCAI — SOC Investigation Platform
52 tools · 18 resources · 5 prompts for security operations.

## Start Here

1. Call `classify_attack` or `plan_investigation` with the alert data — returns attack type and a step-by-step tool sequence.
2. Follow the returned plan. It tells you which tools to call, in what order, and what to skip.

## Guided Workflows (Prompts)

Analysts select these from the Claude Desktop prompt picker for structured workflows:

- `investigate_incident` — **primary workflow**: end-to-end from raw alert to MDR report or FP closure.
- `triage_alert` — structured alert triage (classify → enrich → verdict → next steps).
- `write_fp_ticket` — false-positive analysis and suppression ticket generation.
- `kql_investigation` — unified KQL playbook prompt. Select a playbook ID: `phishing`, `account-compromise`, `malware-execution`, `privilege-escalation`, `data-exfiltration`, `lateral-movement`, or `ioc-hunt`.

## Tool Categories

| Category | Tools |
|----------|-------|
| Investigation & Triage | classify_attack, plan_investigation, investigate, quick_investigate_url, quick_investigate_domain, quick_investigate_file |
| Case Management | list_cases, get_case, case_summary, read_report, read_case_file, new_investigation, close_case, link_cases, merge_cases, add_evidence, add_finding |
| Enrichment & Analysis | enrich_iocs, correlate, contextualise_cves, recall_cases, campaign_cluster, web_search |
| Email & Phishing | analyse_email, capture_urls, detect_phishing |
| SIEM & Endpoint | lookup_client, run_kql, load_kql_playbook, generate_sentinel_query, generate_queries, ingest_velociraptor, ingest_mde_package |
| Dynamic Analysis | start_sandbox_session, stop_sandbox_session, list_sandbox_sessions, start_browser_session, stop_browser_session, list_browser_sessions |
| Reporting | generate_report, generate_mdr_report, generate_pup_report, generate_executive_summary, generate_weekly, generate_fp_ticket, generate_fp_tuning_ticket, reconstruct_timeline, security_arch_review, response_actions |
| Threat Intelligence | assess_landscape, search_threat_articles, generate_threat_article |

## Data Resources (socai:// URIs)

Read case data, client config, playbooks, and threat intel without invoking tools:

- `socai://cases` — full case registry
- `socai://cases/{case_id}/meta`, `/report`, `/iocs`, `/verdicts`, `/enrichment`, `/timeline`
- `socai://clients` — client registry; `socai://clients/{name}` — full config; `socai://clients/{name}/playbook` — response playbook
- `socai://playbooks` — KQL playbook index; `socai://playbooks/{id}` — full playbook
- `socai://sentinel-queries` — Sentinel composite query scenarios (single-execution full-picture queries)
- `socai://pipeline-profiles` — attack-type routing profiles
- `socai://ioc-index/stats` — IOC index summary with recurring indicators
- `socai://articles` — threat article index
- `socai://landscape` — threat landscape across recent cases
- `socai://capabilities` — structured overview of all tools, prompts, and resources (read this to answer "what can you do?")

## When Alert Data is Pasted

When the analyst pastes raw alert data (JSON, email headers, log snippets):
1. Do NOT jump to enrich_iocs, capture_urls, run_kql, or any analysis tool.
2. FIRST call `classify_attack` with the alert title and any descriptive text.
3. The result tells you the attack type and exactly which tools to call in order.
4. For a full step-by-step plan with phases and dependencies, call `plan_investigation` instead.

## Common Workflows

Every workflow starts with classification. The `classify_attack` result includes the recommended tool sequence for the attack type:

- **Phishing:** lookup_client → classify_attack → add_evidence → enrich_iocs → capture_urls → detect_phishing → analyse_email → run_kql (phishing playbook) → generate_mdr_report
- **Malware:** lookup_client → classify_attack → add_evidence → enrich_iocs → start_sandbox_session → run_kql (malware-execution playbook) → generate_mdr_report
- **Account Compromise:** lookup_client → classify_attack → add_evidence → enrich_iocs → generate_sentinel_query (suspicious-signin / mailbox-permission-change) → run_kql → generate_mdr_report
- **False Positive:** add_evidence → enrich_iocs → generate_fp_ticket → generate_fp_tuning_ticket (if tuning needed)
- **PUP/PUA:** classify_attack → enrich_iocs → generate_pup_report

## Do NOT

- Call enrich_iocs, capture_urls, run_kql, or any analysis tool before classifying the attack type.
- Call run_kql without first confirming the client via lookup_client.
- Call generate_mdr_report before the investigation is complete.
- Skip classification — even if the attack type seems obvious from the alert title.

## Rules

- Always identify the client before running queries (`lookup_client`).
- Always call `recall_cases` before enrichment to check prior investigations.
- Reports auto-close cases: `generate_mdr_report`, `generate_pup_report`, `generate_fp_ticket`.
- Analytical standards: every finding must be provable with data. Never speculate or fill evidence gaps.
- Language: "Confirmed" = data proves it. "Assessed" = inference. "Unknown" = no data.
"""


def create_mcp_server(*, transport: str = MCP_TRANSPORT) -> FastMCP:
    """Create and configure the FastMCP server instance.

    Parameters
    ----------
    transport : str
        Transport mode. For ``"stdio"`` auth is skipped (local trust model).
        For ``"sse"`` or ``"streamable-http"`` JWT auth is enabled.
    """
    from mcp.server.fastmcp.server import TransportSecuritySettings

    # stdio = no auth (Claude Desktop local trust model)
    is_network = transport in ("sse", "streamable-http")

    auth_settings = _build_auth_settings() if is_network else None
    token_verifier = SocaiTokenVerifier() if is_network else None

    # For 0.0.0.0 binding, disable DNS rebinding protection (production
    # uses a reverse proxy that terminates TLS and handles origin checks).
    transport_security = None
    if is_network and MCP_HOST == "0.0.0.0":
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        )

    server = FastMCP(
        name="socai",
        instructions=_SERVER_INSTRUCTIONS,
        host=MCP_HOST,
        port=MCP_PORT,
        mount_path=MCP_MOUNT_PATH,
        auth=auth_settings,
        token_verifier=token_verifier,
        transport_security=transport_security,
        log_level="INFO",
    )

    register_tools(server)
    register_resources(server)
    register_prompts(server)

    from mcp_server.usage import install_usage_watcher
    install_usage_watcher(server)

    return server


def main() -> None:
    """Entry point for ``python -m mcp_server``."""
    transport = MCP_TRANSPORT
    if transport not in ("sse", "streamable-http", "stdio"):
        print(f"Unknown transport {transport!r}, falling back to 'sse'")
        transport = "sse"

    # Create server with transport-appropriate auth settings
    server = create_mcp_server(transport=transport)

    if transport == "stdio":
        print("socai MCP server (stdio, no auth)", file=sys.stderr)
    else:
        print(f"socai MCP server starting on {MCP_HOST}:{MCP_PORT} ({transport})")

    server.run(transport=transport, mount_path=MCP_MOUNT_PATH)


if __name__ == "__main__":
    main()
