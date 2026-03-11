"""MCP usage watcher — logs every tool invocation to JSONL + live stderr output.

Monkey-patches ``ToolManager.call_tool`` so that **zero** changes are needed in
the tool definitions in ``tools.py``.

Usage::

    from mcp_server.usage import install_usage_watcher
    install_usage_watcher(server)
"""
from __future__ import annotations

import json
import sys
import threading
import time
from typing import Any, Sequence

from mcp.server.fastmcp import FastMCP

from config.settings import MCP_USAGE_LOG
from tools.common import utcnow

_usage_lock = threading.Lock()

# Fields to strip from logged params (secrets / large blobs)
_SENSITIVE_KEYS = frozenset({"zip_pass", "password", "token", "secret", "api_key"})


def _sanitise_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """Return a copy of *params* with sensitive fields redacted."""
    if not params:
        return {}
    out: dict[str, Any] = {}
    for k, v in params.items():
        if k in _SENSITIVE_KEYS:
            out[k] = "***"
        else:
            out[k] = v
    return out


def log_mcp_call(
    caller: str,
    tool: str,
    params: dict[str, Any] | None,
    duration_ms: int,
    success: bool,
    error: str | None,
) -> None:
    """Append a single usage record to the JSONL log."""
    record = {
        "ts": utcnow(),
        "caller": caller,
        "tool": tool,
        "params": _sanitise_params(params),
        "duration_ms": duration_ms,
        "success": success,
        "error": error,
    }
    MCP_USAGE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with _usage_lock:
        with open(MCP_USAGE_LOG, "a") as fh:
            fh.write(json.dumps(record) + "\n")


def _emit_live(
    status: str,
    tool: str,
    caller: str,
    detail: str = "",
    duration_ms: int | None = None,
) -> None:
    """Print a status line to stderr for live tailing."""
    dur = f" {duration_ms}ms" if duration_ms is not None else ""
    det = f" — {detail}" if detail else ""
    print(f"[MCP {status:<4}] {tool}{dur} caller={caller}{det}", file=sys.stderr)


def install_usage_watcher(server: FastMCP) -> None:
    """Wrap ``ToolManager.call_tool`` to log every invocation.

    The MCP low-level protocol handler dispatches tool calls via
    ``server._tool_manager.call_tool``, bypassing ``FastMCP.call_tool``.
    We patch at the ToolManager level so the watcher actually fires.
    """
    tm = server._tool_manager
    original = tm.call_tool

    async def _watched(name: str, arguments: dict[str, Any], **kwargs: Any) -> Any:
        caller = "local"  # future: extract from auth context
        case_id = (arguments or {}).get("case_id", "")
        detail = f"case_id={case_id}" if case_id else ""
        _emit_live("CALL", name, caller, detail)

        t0 = time.monotonic()
        try:
            result = await original(name, arguments, **kwargs)
            duration_ms = int((time.monotonic() - t0) * 1000)
            log_mcp_call(caller, name, arguments, duration_ms, True, None)
            _emit_live("OK  ", name, caller, duration_ms=duration_ms)
            return result
        except Exception as exc:
            duration_ms = int((time.monotonic() - t0) * 1000)
            err_msg = str(exc)[:500]
            log_mcp_call(caller, name, arguments, duration_ms, False, err_msg)
            _emit_live("ERR ", name, caller, err_msg[:120], duration_ms)
            raise

    tm.call_tool = _watched  # type: ignore[assignment]
