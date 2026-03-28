"""Health check endpoint for the socai MCP server.

Exposes ``/healthz`` as a lightweight liveness probe that checks:
- Process is responsive (implicit)
- Background scheduler thread is alive
- Filesystem is writable (canary write to registry/)
- Uptime

Works as ASGI middleware: intercepts ``/healthz`` before the request
reaches the MCP transport layer.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from mcp_server.config import MCP_HOST, MCP_PORT


# Set by server.py at startup
_server_start_time: float = 0.0

_CANARY = Path(__file__).resolve().parent.parent / "registry" / ".health_canary"


def _check_scheduler() -> tuple[bool, str]:
    """Check if the background scheduler thread is alive."""
    try:
        from tools.scheduler import _scheduler_thread
        if _scheduler_thread is None:
            return False, "scheduler not started"
        if not _scheduler_thread.is_alive():
            return False, "scheduler thread dead"
        return True, "alive"
    except Exception as exc:
        return False, str(exc)


def _check_filesystem() -> tuple[bool, str]:
    """Check filesystem is writable via a canary file."""
    try:
        _CANARY.parent.mkdir(parents=True, exist_ok=True)
        _CANARY.write_text(str(time.time()))
        _CANARY.unlink(missing_ok=True)
        return True, "writable"
    except Exception as exc:
        return False, str(exc)


def health_response() -> tuple[int, dict]:
    """Build the health check response.

    Returns (http_status, body_dict).
    """
    sched_ok, sched_detail = _check_scheduler()
    fs_ok, fs_detail = _check_filesystem()

    uptime_s = int(time.monotonic() - _server_start_time) if _server_start_time else 0
    healthy = sched_ok and fs_ok

    body = {
        "status": "ok" if healthy else "degraded",
        "pid": os.getpid(),
        "uptime_s": uptime_s,
        "checks": {
            "scheduler": {"ok": sched_ok, "detail": sched_detail},
            "filesystem": {"ok": fs_ok, "detail": fs_detail},
        },
    }
    return (200 if healthy else 503, body)


class HealthMiddleware:
    """ASGI middleware that intercepts ``/healthz`` requests."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http" and scope.get("path") == "/healthz":
            status, body = health_response()
            payload = json.dumps(body).encode()

            await send({
                "type": "http.response.start",
                "status": status,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(payload)).encode()],
                    [b"cache-control", b"no-cache"],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": payload,
            })
            return

        await self.app(scope, receive, send)
