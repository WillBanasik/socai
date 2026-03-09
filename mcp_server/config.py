"""Environment-based configuration for the socai MCP server."""
from __future__ import annotations

import os

MCP_HOST = os.getenv("SOCAI_MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("SOCAI_MCP_PORT", "8001"))
MCP_TRANSPORT: str = os.getenv("SOCAI_MCP_TRANSPORT", "sse")
MCP_AUTH_MODE: str = os.getenv("SOCAI_MCP_AUTH", "local")
MCP_MOUNT_PATH: str = os.getenv("SOCAI_MCP_MOUNT_PATH", "/")
