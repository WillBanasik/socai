"""Session-wide pytest fixtures.

Redirects every registry log path to a per-session temp directory so test runs
don't pollute or destroy real ``registry/`` data. Without this:

- Import-failure tests (``test_run_task_exception``, ``test_lookup_no_geoip2_package``,
  ``test_extract_no_stealer_parser``) leave warnings in ``registry/error_log.jsonl``.
- ``tests/test_mcp_usage.py``'s autouse fixture **unlinks** the production
  ``mcp_usage.jsonl`` before each test — wiping accumulated usage history.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def _isolate_registry_logs():
    tmp = tempfile.mkdtemp(prefix="socai-tests-")
    tmp_path = Path(tmp)

    from config import settings as _settings
    from tools import common as _common

    saved = {
        "audit": (_settings.AUDIT_LOG, _common.AUDIT_LOG),
        "error": (_settings.ERROR_LOG, _common.ERROR_LOG),
        "metrics": _settings.METRICS_LOG,
        "mcp_usage": _settings.MCP_USAGE_LOG,
        "mcp_server": _settings.MCP_SERVER_LOG,
    }

    new_audit = tmp_path / "audit.log"
    new_error = tmp_path / "error_log.jsonl"
    new_metrics = tmp_path / "metrics.jsonl"
    new_mcp_usage = tmp_path / "mcp_usage.jsonl"
    new_mcp_server = tmp_path / "mcp_server.jsonl"

    _settings.AUDIT_LOG = new_audit
    _settings.ERROR_LOG = new_error
    _settings.METRICS_LOG = new_metrics
    _settings.MCP_USAGE_LOG = new_mcp_usage
    _settings.MCP_SERVER_LOG = new_mcp_server
    _common.AUDIT_LOG = new_audit
    _common.ERROR_LOG = new_error

    # Re-patch modules that imported these paths at load time. ANY module that
    # does `from config.settings import MCP_USAGE_LOG / METRICS_LOG` holds its
    # own reference and MUST be listed here, or tests touch the real registry/
    # files (a missing entry here once deleted production mcp_usage.jsonl).
    import importlib
    repatch = {
        "MCP_USAGE_LOG": new_mcp_usage,
        "METRICS_LOG": new_metrics,
    }
    for mod_name in ("mcp_server.usage", "tests.test_mcp_usage",
                     "scripts.token_cost_report", "tests.test_token_cost_report",
                     "scripts.workflow_report"):
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:
            continue
        for attr, new_val in repatch.items():
            if hasattr(mod, attr):
                setattr(mod, attr, new_val)

    yield

    _settings.AUDIT_LOG, _common.AUDIT_LOG = saved["audit"]
    _settings.ERROR_LOG, _common.ERROR_LOG = saved["error"]
    _settings.METRICS_LOG = saved["metrics"]
    _settings.MCP_USAGE_LOG = saved["mcp_usage"]
    _settings.MCP_SERVER_LOG = saved["mcp_server"]
