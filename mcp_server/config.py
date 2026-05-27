"""Environment-based configuration for the socai MCP server."""
from __future__ import annotations

import os

MCP_HOST = os.getenv("SOCAI_MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("SOCAI_MCP_PORT", "8001"))
MCP_TRANSPORT: str = os.getenv("SOCAI_MCP_TRANSPORT", "sse")
MCP_AUTH_MODE: str = os.getenv("SOCAI_MCP_AUTH", "local")
MCP_MOUNT_PATH: str = os.getenv("SOCAI_MCP_MOUNT_PATH", "/")

# Tool profile — which toolsets register at startup (comma-separated).
# "core" is always included and covers the common log/case path. Specialist
# groups (phishing, malware, forensics, intel, darkweb, analysis, admin) load
# on demand via the load_toolset tool, which pushes a tools/list_changed
# notification so the client picks them up mid-session. "all" (or "full")
# registers every toolset up front — legacy behaviour / dynamic-load fallback.
MCP_TOOLSETS: str = os.getenv("SOCAI_MCP_TOOLSETS", "core")

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

# Upload endpoint — used by Claude Desktop's bash sandbox to ship a sample into
# the MCP server's filesystem before calling analyse_file.
# TTL is short because the upload URL is single-purpose (one-shot transfer).
MCP_UPLOAD_TOKEN_TTL_SECONDS: int = int(
    os.getenv("SOCAI_MCP_UPLOAD_TOKEN_TTL_SECONDS", str(15 * 60))
)
# Hard cap on uploaded sample size (bytes). 100 MB covers typical PDFs, Office
# docs, and PE binaries while keeping memory usage bounded.
MCP_UPLOAD_MAX_BYTES: int = int(
    os.getenv("SOCAI_MCP_UPLOAD_MAX_BYTES", str(100 * 1024 * 1024))
)
# Separate, smaller cap for in-band base64 uploads — these ride the MCP
# JSON-RPC transport itself, so every uploaded byte lands in the analyst's
# chat transcript and persists in the LLM's context window for the rest of
# the session. A 2 MB raw cap (~2.7 MB base64) keeps a single upload under
# ~700 K tokens, which a Claude Desktop chat can absorb. Anything larger
# must use the HTTP upload endpoint (prepare_file_upload + curl).
MCP_INBAND_UPLOAD_MAX_BYTES: int = int(
    os.getenv("SOCAI_MCP_INBAND_UPLOAD_MAX_BYTES", str(2 * 1024 * 1024))
)
