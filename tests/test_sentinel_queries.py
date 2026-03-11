"""
Tests for the Sentinel composite query generation system.

Run with:  cd socai && python -m pytest tests/test_sentinel_queries.py -v
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.sentinel_queries import (
    SENTINEL_QUERIES_DIR,
    list_scenarios,
    load_scenario,
    render_query,
)

EXPECTED_SCENARIOS = [
    "dlp-exfiltration",
    "email-threat-zap",
    "inbox-rule-bec",
    "mailbox-permission-change",
    "oauth-consent-grant",
    "suspicious-signin",
]


class TestListScenarios:
    def test_returns_all_scenarios(self):
        scenarios = list_scenarios()
        ids = [s["id"] for s in scenarios]
        for expected in EXPECTED_SCENARIOS:
            assert expected in ids, f"Missing scenario: {expected}"

    def test_scenario_has_required_fields(self):
        for s in list_scenarios():
            assert "id" in s
            assert "name" in s
            assert "description" in s
            assert "parameters" in s
            assert "tables" in s
            assert len(s["name"]) > 0
            assert len(s["description"]) > 0
            assert len(s["tables"]) > 0


class TestLoadScenario:
    def test_load_valid_scenario(self):
        for scenario_id in EXPECTED_SCENARIOS:
            result = load_scenario(scenario_id)
            assert result is not None, f"Failed to load: {scenario_id}"
            assert result["id"] == scenario_id
            assert "query_template" in result
            assert len(result["query_template"]) > 100

    def test_load_invalid_scenario(self):
        assert load_scenario("nonexistent-scenario") is None

    def test_query_template_has_union(self):
        for scenario_id in EXPECTED_SCENARIOS:
            result = load_scenario(scenario_id)
            assert "union isfuzzy=true" in result["query_template"], \
                f"{scenario_id} missing union"

    def test_query_template_has_sections(self):
        for scenario_id in EXPECTED_SCENARIOS:
            result = load_scenario(scenario_id)
            assert "Section" in result["query_template"], \
                f"{scenario_id} missing Section column"


class TestRenderQuery:
    def test_basic_render(self):
        result = render_query(
            "mailbox-permission-change",
            upn="test@example.com",
        )
        assert "error" not in result
        assert "query" in result
        assert "test@example.com" in result["query"]
        assert "{{upn}}" not in result["query"]

    def test_render_with_ip(self):
        result = render_query(
            "suspicious-signin",
            upn="user@domain.com",
            ip="10.0.0.1",
        )
        assert "10.0.0.1" in result["query"]
        assert "{{ip}}" not in result["query"]

    def test_render_with_additional_upns(self):
        result = render_query(
            "inbox-rule-bec",
            upn="primary@domain.com",
            additional_upns="secondary@domain.com, third@domain.com",
        )
        assert '"secondary@domain.com"' in result["query"]
        assert '"third@domain.com"' in result["query"]
        assert "{{additional_upns}}" not in result["query"]

    def test_render_with_object_id(self):
        result = render_query(
            "mailbox-permission-change",
            upn="admin@domain.com",
            object_id="756b7dcd-33a0-4cf9-8672-0923404417df",
        )
        assert "756b7dcd-33a0-4cf9-8672-0923404417df" in result["query"]

    def test_lookback_computation(self):
        result = render_query(
            "suspicious-signin",
            upn="user@domain.com",
            lookback_hours=48,
        )
        assert result["lookback_hours"] == 48
        assert "lookback_start" in result["parameters_used"]
        assert "lookback_end" in result["parameters_used"]

    def test_unknown_scenario_returns_error(self):
        result = render_query("nonexistent", upn="user@domain.com")
        assert "error" in result

    def test_no_unrendered_placeholders(self):
        for scenario_id in EXPECTED_SCENARIOS:
            result = render_query(
                scenario_id,
                upn="test@example.com",
                ip="192.168.1.1",
                object_id="test-object-id",
                mailbox_id="test-mailbox-id",
                additional_upns="extra@example.com",
            )
            query = result["query"]
            assert "{{" not in query, \
                f"{scenario_id} has unrendered placeholders"

    def test_result_metadata(self):
        result = render_query(
            "mailbox-permission-change",
            upn="admin@domain.com",
        )
        assert result["scenario"] == "mailbox-permission-change"
        assert "name" in result
        assert "description" in result
        assert "tables" in result
        assert isinstance(result["tables"], list)

    def test_empty_optional_params_produce_valid_kql(self):
        result = render_query(
            "suspicious-signin",
            upn="user@domain.com",
        )
        # With empty IP, isnotempty guard should be present
        assert "isnotempty(IncidentIP)" in result["query"]


class TestTemplateQuality:
    """Verify structural quality of all templates."""

    def test_all_templates_use_sentinel_tables_only(self):
        """Ensure no Advanced Hunting tables are referenced."""
        advanced_tables = [
            "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
            "DeviceLogonEvents", "DeviceEvents", "EmailEvents",
            "EmailAttachmentInfo", "EmailUrlInfo", "UrlClickEvents",
            "IdentityLogonEvents", "IdentityQueryEvents",
        ]
        for scenario_id in EXPECTED_SCENARIOS:
            result = load_scenario(scenario_id)
            for table in advanced_tables:
                assert table not in result["query_template"], \
                    f"{scenario_id} references Advanced Hunting table: {table}"

    def test_all_templates_have_sort(self):
        for scenario_id in EXPECTED_SCENARIOS:
            result = load_scenario(scenario_id)
            assert "sort by Section asc" in result["query_template"], \
                f"{scenario_id} missing final sort"

    def test_template_files_exist(self):
        for scenario_id in EXPECTED_SCENARIOS:
            path = SENTINEL_QUERIES_DIR / f"{scenario_id}.kql"
            assert path.exists(), f"Missing template file: {path}"
