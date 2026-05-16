"""Environment-based configuration for the socai MCP server."""
from __future__ import annotations

import os

MCP_HOST = os.getenv("SOCAI_MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("SOCAI_MCP_PORT", "8001"))
MCP_TRANSPORT: str = os.getenv("SOCAI_MCP_TRANSPORT", "sse")
MCP_AUTH_MODE: str = os.getenv("SOCAI_MCP_AUTH", "local")
MCP_MOUNT_PATH: str = os.getenv("SOCAI_MCP_MOUNT_PATH", "/")

# Public origin used to build clickable links returned by tools (e.g. report URLs).
# Production must override with the public Azure URL.
# 127.0.0.1 is the WSL2-friendly default for local dev — Windows Edge resolves it
# correctly whereas "localhost" can fall back to IPv6 and miss the WSL2 listener.
_DEFAULT_PUBLIC_HOST = "127.0.0.1" if MCP_HOST in ("0.0.0.0", "::") else MCP_HOST
MCP_PUBLIC_BASE_URL: str = os.getenv(
    "SOCAI_MCP_PUBLIC_BASE_URL",
    f"http://{_DEFAULT_PUBLIC_HOST}:{MCP_PORT}",
).rstrip("/")

# How long a one-click report link stays valid. Long enough for the analyst to
# open + re-open across a shift, short enough that a leaked URL has limited blast.
MCP_REPORT_TOKEN_TTL_SECONDS: int = int(
    os.getenv("SOCAI_MCP_REPORT_TOKEN_TTL_SECONDS", str(8 * 3600))
)
