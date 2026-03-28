"""Systemd watchdog integration for the socai MCP server.

Sends ``WATCHDOG=1`` to the systemd notify socket at half the configured
watchdog interval. Only activates when ``WATCHDOG_USEC`` is set by systemd
(i.e. ``WatchdogSec=`` is configured in the unit file).

Uses the raw ``$NOTIFY_SOCKET`` Unix datagram protocol — no ``systemd``
Python package required.

Usage::

    # In an async context (server lifespan):
    task = asyncio.create_task(watchdog_loop())
    ...
    task.cancel()

    # Or call sd_notify directly:
    sd_notify("READY=1")
"""
from __future__ import annotations

import asyncio
import os
import socket


def sd_notify(state: str) -> bool:
    """Send a notification to the systemd notify socket.

    Returns True if the message was sent, False if the socket is not
    available (not running under systemd, or no WatchdogSec configured).
    """
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    # Abstract socket: starts with @
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.sendto(state.encode(), addr)
        sock.close()
        return True
    except Exception:
        return False


def watchdog_interval_s() -> float | None:
    """Return the recommended watchdog ping interval in seconds, or None.

    systemd sets ``WATCHDOG_USEC``; we ping at half that interval to give
    ourselves margin.
    """
    usec = os.environ.get("WATCHDOG_USEC")
    if not usec:
        return None
    try:
        return int(usec) / 1_000_000 / 2
    except (ValueError, ZeroDivisionError):
        return None


async def watchdog_loop() -> None:
    """Async loop that pings the systemd watchdog.

    Runs forever (cancel to stop). No-ops silently if not under systemd.
    """
    interval = watchdog_interval_s()
    if interval is None:
        return  # Not under systemd watchdog — nothing to do

    from mcp_server.health import health_response

    while True:
        # Only ping if health checks pass — lets systemd restart on hang
        status, _ = health_response()
        if status == 200:
            sd_notify("WATCHDOG=1")
        await asyncio.sleep(interval)
