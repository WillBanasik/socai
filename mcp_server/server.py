"""socai MCP server — HTTPS SSE transport with JWT RBAC.

Separate process on port 8001. Shares filesystem state (cases/, registry/)
with the web UI on port 8000. Both are stateless against the same data.

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
        instructions=(
            "socai SOC investigation platform. Use tools to run investigations, "
            "read case data, generate reports, and hunt for threats."
        ),
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
