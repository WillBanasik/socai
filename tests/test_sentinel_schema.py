"""
Tests for Sentinel schema validation API.

Run with:  cd socai && python -m pytest tests/test_sentinel_schema.py -v
"""
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.sentinel_schema import (
    extract_tables_from_kql,
    validate_tables,
    get_table_schema_summary,
    get_workspace_tables,
    resolve_workspace_code,
    has_registry,
    _load_registry,
    _load_workspace_tables,
)


# ---------------------------------------------------------------------------
# extract_tables_from_kql
# ---------------------------------------------------------------------------

class TestExtractTablesFromKql:
    def test_bare_table_with_pipe(self):
        kql = "SigninLogs\n| where TimeGenerated > ago(7d)"
        tables = extract_tables_from_kql(kql)
        assert "SigninLogs" in tables

    def test_single_line_table_pipe(self):
        kql = "SigninLogs | where TimeGenerated > ago(7d)"
        tables = extract_tables_from_kql(kql)
        assert "SigninLogs" in tables

    def test_let_assignment(self):
        kql = 'let InteractiveSignIns = SigninLogs\n| where TimeGenerated > ago(7d)'
        tables = extract_tables_from_kql(kql)
        assert "SigninLogs" in tables
        # Variable name should NOT be in results (not a real table)
        assert "InteractiveSignIns" not in tables

    def test_multiple_tables(self):
        kql = (
            'let A = SigninLogs\n| where foo = "bar";\n'
            'let B = OfficeActivity\n| where baz = "qux";\n'
            'SecurityAlert\n| where TimeGenerated > ago(7d)'
        )
        tables = extract_tables_from_kql(kql)
        assert "SigninLogs" in tables
        assert "OfficeActivity" in tables
        assert "SecurityAlert" in tables

    def test_join_subquery(self):
        kql = (
            "EmailEvents\n| join kind=leftouter (\n"
            "    EmailAttachmentInfo\n"
            "    | where SHA256 != \"\"\n"
            ") on NetworkMessageId"
        )
        tables = extract_tables_from_kql(kql)
        assert "EmailEvents" in tables
        assert "EmailAttachmentInfo" in tables

    def test_excludes_kql_keywords(self):
        kql = "SigninLogs\n| where true\n| extend foo = \"bar\""
        tables = extract_tables_from_kql(kql)
        assert "true" not in tables
        assert "where" not in tables
        assert "extend" not in tables

    def test_empty_query(self):
        assert extract_tables_from_kql("") == set()

    def test_real_composite_query(self):
        """Test against a realistic composite query snippet."""
        kql = """let TargetUPN = "user@example.com";
let InteractiveSignIns = SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName == TargetUPN
| project TimeGenerated, UserPrincipalName, IPAddress;
let PostAuthExchange = OfficeActivity
| where OfficeWorkload == "Exchange"
| project TimeGenerated, Operation, UserId;
let Alerts = SecurityAlert
| where Entities has TargetUPN
| project TimeGenerated, AlertName;
union isfuzzy=true
    (InteractiveSignIns),
    (PostAuthExchange),
    (Alerts)
| sort by TimeGenerated asc"""
        tables = extract_tables_from_kql(kql)
        assert "SigninLogs" in tables
        assert "OfficeActivity" in tables
        assert "SecurityAlert" in tables
        # Variables should be excluded
        assert "InteractiveSignIns" not in tables
        assert "PostAuthExchange" not in tables
        assert "Alerts" not in tables


# ---------------------------------------------------------------------------
# validate_tables
# ---------------------------------------------------------------------------

class TestValidateTables:
    def test_valid_tables(self):
        if not has_registry():
            pytest.skip("No schema registry")
        result = validate_tables(["SigninLogs", "SecurityAlert"])
        assert result["valid"] is True
        assert result["unknown_tables"] == []
        assert result["missing_tables"] == []

    def test_unknown_table(self):
        if not has_registry():
            pytest.skip("No schema registry")
        result = validate_tables(["SigninLogs", "CompletelyFakeTable"])
        assert result["valid"] is True  # Always non-blocking
        assert "CompletelyFakeTable" in result["unknown_tables"]
        assert any("CompletelyFakeTable" in w for w in result["warnings"])

    def test_empty_table_list(self):
        result = validate_tables([])
        assert result["valid"] is True
        assert result["warnings"] == []

    def test_workspace_scoped_validation(self):
        if not has_registry():
            pytest.skip("No schema registry")
        ws = _load_workspace_tables()
        if not ws:
            pytest.skip("No workspace_tables.json")
        # Pick first workspace
        ws_code = next(iter(ws))
        ws_tables = set(ws[ws_code].get("tables", []))
        if not ws_tables:
            pytest.skip("Empty workspace")
        # Find a table in registry but not in this workspace
        all_tables = set(_load_registry().keys())
        missing = all_tables - ws_tables
        if not missing:
            pytest.skip("All tables present in workspace")
        test_table = next(iter(missing))
        result = validate_tables([test_table], workspace=ws_code)
        assert test_table in result["missing_tables"]

    def test_graceful_without_registry(self):
        with patch("config.sentinel_schema._registry", {}):
            with patch("config.sentinel_schema._SCHEMA_PATH",
                       Path("/nonexistent/path.json")):
                # Force reload
                import config.sentinel_schema as mod
                old = mod._registry
                mod._registry = None
                try:
                    result = validate_tables(["SigninLogs"])
                    assert result["valid"] is True
                    assert any("registry" in w.lower() for w in result["warnings"])
                finally:
                    mod._registry = old


# ---------------------------------------------------------------------------
# get_table_schema_summary
# ---------------------------------------------------------------------------

class TestGetTableSchemaSummary:
    def test_known_table(self):
        if not has_registry():
            pytest.skip("No schema registry")
        summary = get_table_schema_summary("SigninLogs")
        assert "SigninLogs" in summary
        assert "TimeGenerated" in summary
        assert "DateTime" in summary

    def test_unknown_table(self):
        summary = get_table_schema_summary("CompletelyFakeTable")
        assert summary == ""

    def test_max_columns_respected(self):
        if not has_registry():
            pytest.skip("No schema registry")
        summary = get_table_schema_summary("SigninLogs", max_columns=5)
        # Should have header + 5 columns + "more" line
        lines = summary.strip().split("\n")
        assert len(lines) == 7  # header + 5 cols + "+N more"
        assert "more columns" in lines[-1]

    def test_type_simplification(self):
        if not has_registry():
            pytest.skip("No schema registry")
        summary = get_table_schema_summary("SigninLogs")
        # Should use simplified types, not System.* prefixes
        assert "System.String" not in summary
        assert "String" in summary


# ---------------------------------------------------------------------------
# Workspace helpers
# ---------------------------------------------------------------------------

class TestWorkspaceHelpers:
    def test_get_workspace_tables_by_code(self):
        ws = _load_workspace_tables()
        if not ws:
            pytest.skip("No workspace_tables.json")
        code = next(iter(ws))
        tables = get_workspace_tables(code)
        assert isinstance(tables, set)
        assert len(tables) > 0

    def test_get_workspace_tables_by_guid(self):
        ws = _load_workspace_tables()
        if not ws:
            pytest.skip("No workspace_tables.json")
        code = next(iter(ws))
        guid = ws[code]["workspace_id"]
        tables = get_workspace_tables(guid)
        assert isinstance(tables, set)
        assert len(tables) > 0

    def test_get_workspace_tables_unknown(self):
        tables = get_workspace_tables("nonexistent-workspace")
        assert tables == set()

    def test_resolve_workspace_code(self):
        ws = _load_workspace_tables()
        if not ws:
            pytest.skip("No workspace_tables.json")
        code = next(iter(ws))
        guid = ws[code]["workspace_id"]
        assert resolve_workspace_code(guid) == code

    def test_resolve_workspace_code_unknown(self):
        assert resolve_workspace_code("00000000-0000-0000-0000-000000000000") == ""
