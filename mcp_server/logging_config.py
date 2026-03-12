"""Structured JSONL logging for the MCP server.

Single source of truth for all MCP server debug logging. All events go to
``registry/mcp_server.jsonl`` with automatic rotation (10 MB x 3 backups).

Usage::

    from mcp_server.logging_config import mcp_log, setup_mcp_logger

    setup_mcp_logger()                        # call once at startup
    mcp_log("server_start", port=8001)        # structured event
    mcp_log("tool_call", tool="enrich_iocs")  # ...
"""
from __future__ import annotations

import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from typing import Any

from config.settings import MCP_SERVER_LOG, MCP_LOG_LEVEL
from tools.common import utcnow

_logger: logging.Logger | None = None


class _JsonFormatter(logging.Formatter):
    """Passes pre-formatted JSON strings through unchanged."""

    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


def setup_mcp_logger() -> None:
    """Initialise the rotating JSONL logger. Call once at server startup."""
    global _logger
    if _logger is not None:
        return

    MCP_SERVER_LOG.parent.mkdir(parents=True, exist_ok=True)

    _logger = logging.getLogger("socai.mcp.events")
    _logger.setLevel(getattr(logging, MCP_LOG_LEVEL.upper(), logging.INFO))
    _logger.propagate = False

    # Rotating file handler: 10 MB per file, 3 backups (~40 MB total)
    fh = RotatingFileHandler(
        str(MCP_SERVER_LOG),
        maxBytes=10_485_760,
        backupCount=3,
        encoding="utf-8",
    )
    fh.setFormatter(_JsonFormatter())
    _logger.addHandler(fh)

    # Also emit to stderr for live tailing
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(_JsonFormatter())
    sh.setLevel(logging.DEBUG)
    _logger.addHandler(sh)


def mcp_log(event: str, level: int = logging.INFO, **fields: Any) -> None:
    """Write a structured event to the MCP server log.

    Parameters
    ----------
    event : str
        Event name (e.g. ``"server_start"``, ``"tool_call"``).
    level : int
        Python logging level. Defaults to INFO.
    **fields
        Arbitrary key-value pairs included in the JSON record.
    """
    if _logger is None:
        # Logger not yet initialised — best-effort stderr
        print(json.dumps({"ts": utcnow(), "event": event, **fields}), file=sys.stderr)
        return

    record = {"ts": utcnow(), "event": event}
    record.update(fields)

    # Ensure all values are JSON-serialisable
    try:
        line = json.dumps(record, default=str)
    except (TypeError, ValueError):
        line = json.dumps({"ts": utcnow(), "event": event, "error": "unserializable fields"})

    _logger.log(level, line)
