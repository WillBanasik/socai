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

import os
import signal
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure repo root is on sys.path (same pattern as socai.py)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server.fastmcp import FastMCP

from mcp_server.config import MCP_HOST, MCP_PORT, MCP_TRANSPORT, MCP_AUTH_MODE, MCP_MOUNT_PATH
from mcp_server.auth import SocaiTokenVerifier
from mcp_server.tools import register_tools
from mcp_server.resources import register_resources
from mcp_server.prompts import register_prompts
from mcp_server.logging_config import setup_mcp_logger, mcp_log

from config.settings import MCP_SERVER_PID
from tools.common import utcnow

_server_start_time: float = 0.0


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
48 tools · 18 resources · 5 prompts for security operations.

## Start Here

This is a human-in-the-loop (HITL) platform. The analyst drives the investigation
by calling tools step by step. There is no autonomous pipeline.

1. Call `classify_attack` or `plan_investigation` with the alert data — returns attack type and a step-by-step tool sequence.
2. Follow the returned plan. It tells you which tools to call, in what order, and what to skip.
3. Execute each step, present findings to the analyst, and proceed on their direction.

## Guided Workflows (Prompts)

Analysts select these from the Claude Desktop prompt picker for structured workflows:

- `hitl_investigation` — **primary workflow**: guided step-by-step from raw alert to MDR report or FP closure.
- `triage_alert` — structured alert triage (classify → enrich → verdict → next steps).
- `write_fp_ticket` — false-positive analysis and suppression ticket generation.
- `kql_investigation` — unified KQL playbook prompt. Select a playbook ID: `phishing`, `account-compromise`, `malware-execution`, `privilege-escalation`, `data-exfiltration`, `lateral-movement`, or `ioc-hunt`.

## Tool Categories

| Category | Tools |
|----------|-------|
| Investigation & Triage | classify_attack, plan_investigation |
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

Every workflow starts with classification. The `classify_attack` result includes the recommended tool sequence for the attack type. Execute each step and present findings before proceeding:

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


# ---------------------------------------------------------------------------
# PID file management
# ---------------------------------------------------------------------------

def _write_pid() -> None:
    """Write current PID to file for crash detection on next startup."""
    MCP_SERVER_PID.parent.mkdir(parents=True, exist_ok=True)
    MCP_SERVER_PID.write_text(str(os.getpid()))


def _check_stale_pid() -> None:
    """Check for stale PID file from a previous unclean shutdown."""
    if not MCP_SERVER_PID.exists():
        return
    try:
        stale_pid = int(MCP_SERVER_PID.read_text().strip())
    except (ValueError, OSError):
        return
    # Check if the stale PID is still running
    try:
        os.kill(stale_pid, 0)
        mcp_log("server_recovery", stale_pid=stale_pid,
                note="previous instance still running or PID reused")
    except OSError:
        mcp_log("server_recovery", stale_pid=stale_pid,
                note="previous instance did not shut down cleanly")


def _remove_pid() -> None:
    """Remove PID file on clean shutdown."""
    try:
        MCP_SERVER_PID.unlink(missing_ok=True)
    except OSError:
        pass


def _reap_orphaned_browsers() -> None:
    """Kill any orphaned Playwright/Chromium processes from a previous run.

    On unclean shutdown the pooled browser's atexit handler may not fire,
    leaving chromium-headless-shell processes consuming ~400 MB each.
    This runs at startup to reclaim those resources.
    """
    try:
        result = subprocess.run(
            ["pgrep", "-f", "chromium_headless_shell.*playwright"],
            capture_output=True, text=True, timeout=5,
        )
        pids = result.stdout.strip().splitlines()
        if not pids:
            return
        my_pid = str(os.getpid())
        for pid in pids:
            pid = pid.strip()
            if pid and pid != my_pid:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except (OSError, ValueError):
                    pass
        mcp_log("browser_orphan_cleanup", killed=len(pids))
        print(f"[server] Cleaned up {len(pids)} orphaned Chromium process(es)")
    except Exception:
        pass  # pgrep not available or no matches — fine


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown hooks)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _socai_lifespan(server: FastMCP):
    """Log server startup and shutdown events."""
    global _server_start_time
    _server_start_time = time.monotonic()

    _check_stale_pid()
    _reap_orphaned_browsers()
    _write_pid()

    tool_count = len(server._tool_manager._tools) if hasattr(server, "_tool_manager") else 0
    mcp_log("server_start",
            transport=MCP_TRANSPORT, host=MCP_HOST, port=MCP_PORT,
            pid=os.getpid(), tool_count=tool_count)
    try:
        yield {}
    finally:
        uptime_s = int(time.monotonic() - _server_start_time)
        mcp_log("server_stop", reason="shutdown", pid=os.getpid(), uptime_s=uptime_s)
        _remove_pid()


# ---------------------------------------------------------------------------
# Signal handlers
# ---------------------------------------------------------------------------

def _install_signal_handlers() -> None:
    """Install signal handlers that log before the default handler fires."""
    _original_handlers: dict[int, Any] = {}

    def _handler(signum: int, frame) -> None:
        uptime_s = int(time.monotonic() - _server_start_time) if _server_start_time else 0
        sig_name = signal.Signals(signum).name
        mcp_log("server_signal", signal=sig_name, pid=os.getpid(), uptime_s=uptime_s)
        _remove_pid()
        # Restore and re-raise the original handler
        orig = _original_handlers.get(signum, signal.SIG_DFL)
        signal.signal(signum, orig)
        if callable(orig):
            orig(signum, frame)
        else:
            raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT):
        _original_handlers[sig] = signal.getsignal(sig)
        signal.signal(sig, _handler)


# ---------------------------------------------------------------------------
# Unhandled exception hook
# ---------------------------------------------------------------------------

def _install_excepthook() -> None:
    """Log unhandled exceptions before Python exits."""
    _original_hook = sys.excepthook

    def _hook(exc_type, exc_value, exc_tb):
        import traceback as tb_mod
        tb_str = "".join(tb_mod.format_exception(exc_type, exc_value, exc_tb))
        mcp_log("server_crash", error=str(exc_value), traceback=tb_str[:4000],
                pid=os.getpid())
        _remove_pid()
        _original_hook(exc_type, exc_value, exc_tb)

    sys.excepthook = _hook


# ---------------------------------------------------------------------------
# SSE connection logging middleware
# ---------------------------------------------------------------------------

def _extract_caller_from_headers(headers: dict[bytes, bytes]) -> str | None:
    """Extract the caller email from a raw Authorization header.

    Uses unverified JWT decoding — the auth middleware handles full
    validation later.  Returns ``None`` if no token or decoding fails.
    """
    auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="replace")
    if not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header[7:].strip()
    try:
        from jose import jwt as jose_jwt
        claims = jose_jwt.get_unverified_claims(token)
        return claims.get("sub")
    except Exception:
        return None


def _install_connection_logging(server: FastMCP) -> None:
    """Patch sse_app to add connection lifecycle logging.

    Wraps the Starlette ASGI app returned by ``server.sse_app()`` with
    middleware that logs SSE connect/disconnect events.
    """
    original_sse_app = server.sse_app

    def patched_sse_app(*args, **kwargs):
        app = original_sse_app(*args, **kwargs)

        from starlette.middleware import Middleware
        from starlette.types import ASGIApp, Receive, Scope, Send

        class ConnectionLoggingMiddleware:
            def __init__(self, app: ASGIApp) -> None:
                self.app = app

            async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
                if scope["type"] != "http":
                    await self.app(scope, receive, send)
                    return

                path = scope.get("path", "")
                if "/sse" not in path and "/messages" not in path:
                    await self.app(scope, receive, send)
                    return

                # Extract connection info
                headers = dict(scope.get("headers", []))
                client = scope.get("client")
                ip = client[0] if client else "unknown"
                ua = headers.get(b"user-agent", b"").decode("utf-8", errors="replace")

                if "/sse" in path:
                    t0 = time.monotonic()

                    mcp_log("sse_connect", ip=ip, user_agent=ua[:200], path=path)
                    try:
                        await self.app(scope, receive, send)
                    finally:
                        duration_s = int(time.monotonic() - t0)
                        mcp_log("sse_disconnect", ip=ip, duration_s=duration_s)
                else:
                    await self.app(scope, receive, send)

        # Wrap the app with our middleware
        return ConnectionLoggingMiddleware(app)

    server.sse_app = patched_sse_app


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------

def create_mcp_server(*, transport: str = MCP_TRANSPORT) -> FastMCP:
    """Create and configure the FastMCP server instance.

    Parameters
    ----------
    transport : str
        Transport mode. For ``"stdio"`` auth is skipped (local trust model).
        For ``"sse"`` or ``"streamable-http"`` JWT auth is enabled.
    """
    from mcp.server.fastmcp.server import TransportSecuritySettings

    # Initialise structured logging first
    setup_mcp_logger()

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

    # Install SSE connection tracking for network transports
    if is_network and transport == "sse":
        try:
            _install_connection_logging(server)
        except Exception:
            mcp_log("sse_middleware_skip", note="could not install connection logging")

    return server


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point for ``python -m mcp_server``."""
    global _server_start_time
    _server_start_time = time.monotonic()

    setup_mcp_logger()
    _install_signal_handlers()
    _install_excepthook()

    transport = MCP_TRANSPORT
    if transport not in ("sse", "streamable-http", "stdio"):
        print(f"Unknown transport {transport!r}, falling back to 'sse'")
        transport = "sse"

    # Create server with transport-appropriate auth settings
    server = create_mcp_server(transport=transport)

    _check_stale_pid()
    _reap_orphaned_browsers()
    _write_pid()

    tool_count = len(server._tool_manager._tools) if hasattr(server, "_tool_manager") else 0
    mcp_log("server_start",
            transport=transport, host=MCP_HOST, port=MCP_PORT,
            pid=os.getpid(), tool_count=tool_count)

    if transport == "stdio":
        print("socai MCP server (stdio, no auth)", file=sys.stderr)
    else:
        print(f"socai MCP server starting on {MCP_HOST}:{MCP_PORT} ({transport})")

    try:
        server.run(transport=transport, mount_path=MCP_MOUNT_PATH)
    finally:
        uptime_s = int(time.monotonic() - _server_start_time) if _server_start_time else 0
        mcp_log("server_stop", reason="shutdown", pid=os.getpid(), uptime_s=uptime_s)
        _remove_pid()


if __name__ == "__main__":
    main()
