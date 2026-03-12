"""
Tests for MCP usage watcher: logging, sanitisation, assessment, and install.

Run with:  cd socai && python -m pytest tests/test_mcp_usage.py -v
"""
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import MCP_USAGE_LOG


@pytest.fixture(autouse=True)
def cleanup_usage_log():
    """Remove the usage log before and after each test."""
    if MCP_USAGE_LOG.exists():
        MCP_USAGE_LOG.unlink()
    yield
    if MCP_USAGE_LOG.exists():
        MCP_USAGE_LOG.unlink()


# ---------------------------------------------------------------------------
# log_mcp_call
# ---------------------------------------------------------------------------

class TestLogMcpCall:
    def test_writes_jsonl(self):
        from mcp_server.usage import log_mcp_call

        log_mcp_call("local", "enrich_iocs", {"case_id": "IV_CASE_001"},
                      duration_ms=1234, success=True, error=None)

        assert MCP_USAGE_LOG.exists()
        lines = MCP_USAGE_LOG.read_text().strip().splitlines()
        assert len(lines) == 1

        rec = json.loads(lines[0])
        assert rec["caller"] == "local"
        assert rec["tool"] == "enrich_iocs"
        assert rec["params"]["case_id"] == "IV_CASE_001"
        assert rec["duration_ms"] == 1234
        assert rec["success"] is True
        assert rec["error"] is None
        assert "ts" in rec

    def test_sanitises_secrets(self):
        from mcp_server.usage import log_mcp_call

        log_mcp_call("local", "enrich_iocs",
                      {"case_id": "IV_CASE_001", "zip_pass": "infected",
                       "password": "hunter2", "normal": "ok"},
                      duration_ms=100, success=True, error=None)

        rec = json.loads(MCP_USAGE_LOG.read_text().strip())
        assert rec["params"]["zip_pass"] == "***"
        assert rec["params"]["password"] == "***"
        assert rec["params"]["normal"] == "ok"

    def test_handles_none_params(self):
        from mcp_server.usage import log_mcp_call

        log_mcp_call("local", "list_cases", None,
                      duration_ms=50, success=True, error=None)

        rec = json.loads(MCP_USAGE_LOG.read_text().strip())
        assert rec["params"] == {}


# ---------------------------------------------------------------------------
# assess_mcp_usage
# ---------------------------------------------------------------------------

class TestAssessMcpUsage:
    def test_empty_log(self):
        from tools.mcp_usage import assess_mcp_usage

        result = assess_mcp_usage(json_output=True)
        assert result["status"] == "empty"
        assert result["total_calls"] == 0

    def test_aggregation(self):
        from mcp_server.usage import log_mcp_call
        from tools.mcp_usage import assess_mcp_usage

        # Write synthetic records
        log_mcp_call("local", "enrich_iocs", {"case_id": "C001"},
                      200, True, None)
        log_mcp_call("local", "enrich_iocs", {"case_id": "C002"},
                      300, True, None)
        log_mcp_call("local", "enrich_iocs", {"case_id": "C003"},
                      100, False, "Case not found")
        log_mcp_call("remote", "get_case", {"case_id": "C001"},
                      50, True, None)

        result = assess_mcp_usage(json_output=True)

        assert result["status"] == "ok"
        assert result["total_calls"] == 4
        assert result["total_success"] == 3
        assert result["total_failure"] == 1
        assert result["error_rate_pct"] == 25.0
        assert result["unique_tools"] == 2
        assert result["unique_callers"] == 2

        # enrich_iocs should be first (3 calls)
        top = result["top_tools"]
        assert top[0]["tool"] == "enrich_iocs"
        assert top[0]["calls"] == 3
        assert top[0]["failure"] == 1

    def test_caller_filter(self):
        from mcp_server.usage import log_mcp_call
        from tools.mcp_usage import assess_mcp_usage

        log_mcp_call("local", "enrich_iocs", {}, 100, True, None)
        log_mcp_call("remote", "get_case", {}, 50, True, None)

        result = assess_mcp_usage(caller_filter="remote", json_output=True)
        assert result["total_calls"] == 1
        assert result["top_tools"][0]["tool"] == "get_case"

    def test_tool_filter(self):
        from mcp_server.usage import log_mcp_call
        from tools.mcp_usage import assess_mcp_usage

        log_mcp_call("local", "enrich_iocs", {}, 100, True, None)
        log_mcp_call("local", "get_case", {}, 50, True, None)

        result = assess_mcp_usage(tool_filter="get_case", json_output=True)
        assert result["total_calls"] == 1


# ---------------------------------------------------------------------------
# clear_mcp_usage_log
# ---------------------------------------------------------------------------

class TestClearUsageLog:
    def test_clear(self):
        from mcp_server.usage import log_mcp_call
        from tools.mcp_usage import clear_mcp_usage_log

        log_mcp_call("local", "enrich_iocs", {}, 100, True, None)
        log_mcp_call("local", "get_case", {}, 50, True, None)

        result = clear_mcp_usage_log()
        assert result["cleared"] == 2
        assert not MCP_USAGE_LOG.exists()

    def test_clear_missing_log(self):
        from tools.mcp_usage import clear_mcp_usage_log

        result = clear_mcp_usage_log()
        assert result["cleared"] == 0


# ---------------------------------------------------------------------------
# install_usage_watcher
# ---------------------------------------------------------------------------

class TestInstallWatcher:
    def test_wraps_tool_manager(self):
        from mcp_server.usage import install_usage_watcher

        server = MagicMock()
        tm = server._tool_manager
        original = tm.call_tool

        install_usage_watcher(server)

        # _tool_manager.call_tool should now be replaced with the wrapper
        assert tm.call_tool is not original
        assert callable(tm.call_tool)

    def test_wrapper_logs_success(self):
        import asyncio
        from mcp_server.usage import install_usage_watcher

        server = MagicMock()
        server._tool_manager.call_tool = AsyncMock(return_value=[{"type": "text", "text": "ok"}])

        install_usage_watcher(server)

        result = asyncio.run(server._tool_manager.call_tool("get_case", {"case_id": "C001"}))
        assert result == [{"type": "text", "text": "ok"}]

        # Verify a record was written
        assert MCP_USAGE_LOG.exists()
        rec = json.loads(MCP_USAGE_LOG.read_text().strip())
        assert rec["tool"] == "get_case"
        assert rec["success"] is True

    def test_wrapper_logs_failure(self):
        import asyncio
        from mcp_server.usage import install_usage_watcher

        server = MagicMock()
        server._tool_manager.call_tool = AsyncMock(side_effect=ValueError("boom"))

        install_usage_watcher(server)

        with pytest.raises(ValueError, match="boom"):
            asyncio.run(server._tool_manager.call_tool("enrich_iocs", {"case_id": "C001"}))

        rec = json.loads(MCP_USAGE_LOG.read_text().strip())
        assert rec["tool"] == "enrich_iocs"
        assert rec["success"] is False
        assert "boom" in rec["error"]
