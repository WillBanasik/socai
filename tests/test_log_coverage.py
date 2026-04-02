"""
Tests for log source coverage mapping.
Run with:  cd socai && python -m pytest tests/test_log_coverage.py -v
"""
import json
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import COVERAGE_DIR


@pytest.fixture(autouse=True)
def cleanup_coverage():
    """Remove test coverage data before and after each test."""
    test_file = COVERAGE_DIR / "test_client.json"
    test_html = COVERAGE_DIR / "test_client_coverage.html"

    def _rm():
        for f in (test_file, test_html):
            if f.exists():
                f.unlink()

    _rm()
    yield
    _rm()


# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_USAGE_ROWS = [
    {"DataType": "SigninLogs",                      "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 42.5,  "TotalMB": 1275.0, "DaysSeen": 28, "StaleDays": 0, "IsHealthy": True},
    {"DataType": "AADNonInteractiveUserSignInLogs", "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 80.0,  "TotalMB": 2400.0, "DaysSeen": 30, "StaleDays": 0, "IsHealthy": True},
    {"DataType": "AuditLogs",                       "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 15.0,  "TotalMB": 450.0,  "DaysSeen": 30, "StaleDays": 0, "IsHealthy": True},
    {"DataType": "DeviceProcessEvents",             "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 200.0, "TotalMB": 6000.0, "DaysSeen": 30, "StaleDays": 0, "IsHealthy": True},
    {"DataType": "DeviceFileEvents",                "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 150.0, "TotalMB": 4500.0, "DaysSeen": 30, "StaleDays": 0, "IsHealthy": True},
    {"DataType": "DeviceNetworkEvents",             "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 100.0, "TotalMB": 3000.0, "DaysSeen": 30, "StaleDays": 0, "IsHealthy": True},
    {"DataType": "EmailEvents",                     "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 25.0,  "TotalMB": 750.0,  "DaysSeen": 28, "StaleDays": 0, "IsHealthy": True},
    {"DataType": "SecurityAlert",                   "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 5.0,   "TotalMB": 150.0,  "DaysSeen": 20, "StaleDays": 0, "IsHealthy": True},
    {"DataType": "SecurityIncident",                "LastEvent": "2026-03-28T14:00:00Z", "DailyAvgMB": 2.0,   "TotalMB": 60.0,   "DaysSeen": 15, "StaleDays": 0, "IsHealthy": True},
    # Stale source
    {"DataType": "CommonSecurityLog",               "LastEvent": "2026-03-25T08:00:00Z", "DailyAvgMB": 30.0,  "TotalMB": 900.0,  "DaysSeen": 25, "StaleDays": 3, "IsHealthy": False},
    # Degraded source
    {"DataType": "AzureActivity",                   "LastEvent": "2026-03-15T08:00:00Z", "DailyAvgMB": 10.0,  "TotalMB": 300.0,  "DaysSeen": 10, "StaleDays": 13, "IsHealthy": False},
]

_MOCK_WORKSPACE_ID = "00000000-0000-0000-0000-000000000000"


def _mock_get_client_config(client):
    return {
        "name": "test_client",
        "platforms": {"sentinel": {"workspace_id": _MOCK_WORKSPACE_ID}},
    }


def _mock_run_kql(workspace_id, query, timeout=120, skip_validation=False):
    if "ago(365d)" in query:
        return []  # retention query not used in basic tests
    return _MOCK_USAGE_ROWS


# ---------------------------------------------------------------------------
# Health classification
# ---------------------------------------------------------------------------

def test_health_classification():
    from tools.log_coverage import _classify_health

    assert _classify_health(0, 28) == "healthy"
    assert _classify_health(1, 25) == "healthy"
    assert _classify_health(3, 20) == "stale"
    assert _classify_health(7, 10) == "stale"
    assert _classify_health(10, 20) == "degraded"
    assert _classify_health(31, 5) == "dead"


def test_health_weight():
    from tools.log_coverage import _health_weight

    assert _health_weight("healthy") == 1.0
    assert _health_weight("stale") == 0.5
    assert _health_weight("degraded") == 0.0
    assert _health_weight("dead") == 0.0


# ---------------------------------------------------------------------------
# Collection + graph building (mocked KQL)
# ---------------------------------------------------------------------------

@patch("tools.log_coverage._get_workspace_id", return_value=_MOCK_WORKSPACE_ID)
@patch("scripts.run_kql.run_kql", side_effect=_mock_run_kql)
def test_collect_and_build(mock_kql, mock_ws):
    from tools.log_coverage import collect_log_sources

    result = collect_log_sources("test_client")
    assert result["status"] == "ok"
    assert result["source_count"] == len(_MOCK_USAGE_ROWS)

    # Verify file was written
    cov_path = COVERAGE_DIR / "test_client.json"
    assert cov_path.exists()

    data = json.loads(cov_path.read_text())
    assert data["client"] == "test_client"
    assert data["scores"]["overall"] > 0
    assert "by_domain" in data["scores"]
    assert len(data["gaps"]) > 0  # missing enhanced tables at minimum


@patch("tools.log_coverage._get_workspace_id", return_value=_MOCK_WORKSPACE_ID)
@patch("scripts.run_kql.run_kql", side_effect=_mock_run_kql)
def test_scoring(mock_kql, mock_ws):
    from tools.log_coverage import collect_log_sources

    collect_log_sources("test_client")
    data = json.loads((COVERAGE_DIR / "test_client.json").read_text())
    scores = data["scores"]

    # Identity has all 3 required tables → should score well
    assert scores["by_domain"]["identity"] >= 0.65

    # Endpoint has all 3 required → should score well
    assert scores["by_domain"]["endpoint"] >= 0.65

    # Email has required → should score > 0
    assert scores["by_domain"]["email"] > 0

    # Device mgmt has no tables → should be 0
    assert scores["by_domain"]["device_mgmt"] == 0

    # Overall should be > 0 given good identity + endpoint
    assert scores["overall"] > 0.3


# ---------------------------------------------------------------------------
# Gap detection
# ---------------------------------------------------------------------------

@patch("tools.log_coverage._get_workspace_id", return_value=_MOCK_WORKSPACE_ID)
@patch("scripts.run_kql.run_kql", side_effect=_mock_run_kql)
def test_gap_detection(mock_kql, mock_ws):
    from tools.log_coverage import collect_log_sources

    collect_log_sources("test_client")
    data = json.loads((COVERAGE_DIR / "test_client.json").read_text())
    gaps = data["gaps"]

    # Should have gaps for missing required tables (CloudAppEvents, IntuneDevices)
    missing_required = [g for g in gaps if g["type"] == "missing_required"]
    assert len(missing_required) > 0

    # CloudAppEvents should be in the gaps
    gap_tables = [g["table"] for g in missing_required]
    assert "CloudAppEvents" in gap_tables
    assert "IntuneDevices" in gap_tables

    # Gaps should be sorted by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for i in range(len(gaps) - 1):
        assert sev_order.get(gaps[i]["severity"], 99) <= sev_order.get(gaps[i + 1]["severity"], 99)


# ---------------------------------------------------------------------------
# Health issues
# ---------------------------------------------------------------------------

@patch("tools.log_coverage._get_workspace_id", return_value=_MOCK_WORKSPACE_ID)
@patch("scripts.run_kql.run_kql", side_effect=_mock_run_kql)
def test_health_issues(mock_kql, mock_ws):
    from tools.log_coverage import collect_log_sources

    collect_log_sources("test_client")
    data = json.loads((COVERAGE_DIR / "test_client.json").read_text())
    health_issues = data.get("health_issues", [])

    # CommonSecurityLog is stale (3 days) but it's not a required table in network domain
    # Actually it IS required for network — so it should flag if stale
    # Let's check: CommonSecurityLog is stale (3d), it's required for network
    stale_tables = [h["table"] for h in health_issues if h["type"] == "stale"]
    # CommonSecurityLog should be flagged — it's stale and required for network
    assert "CommonSecurityLog" in stale_tables


# ---------------------------------------------------------------------------
# can_investigate
# ---------------------------------------------------------------------------

@patch("tools.log_coverage._get_workspace_id", return_value=_MOCK_WORKSPACE_ID)
@patch("scripts.run_kql.run_kql", side_effect=_mock_run_kql)
def test_can_investigate_account_compromise(mock_kql, mock_ws):
    from tools.log_coverage import collect_log_sources, can_investigate

    collect_log_sources("test_client")
    result = can_investigate("test_client", "account_compromise")

    # We have identity tables → should be able to investigate
    assert result["can_investigate"] is True
    assert result["coverage_level"] == "full"
    assert "identity" in result["available_domains"]


@patch("tools.log_coverage._get_workspace_id", return_value=_MOCK_WORKSPACE_ID)
@patch("scripts.run_kql.run_kql", side_effect=_mock_run_kql)
def test_can_investigate_data_exfil(mock_kql, mock_ws):
    from tools.log_coverage import collect_log_sources, can_investigate

    collect_log_sources("test_client")
    result = can_investigate("test_client", "data_exfiltration")

    # data_exfiltration requires endpoint + network
    # Endpoint is healthy, network (CommonSecurityLog) is stale but score >= 0.5
    assert result["attack_type"] == "data_exfiltration"
    assert "endpoint" in result["available_domains"]


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

@patch("tools.log_coverage._get_workspace_id", return_value=_MOCK_WORKSPACE_ID)
@patch("scripts.run_kql.run_kql", side_effect=_mock_run_kql)
def test_html_generation(mock_kql, mock_ws):
    from tools.log_coverage import collect_log_sources, generate_coverage_html

    collect_log_sources("test_client")
    result = generate_coverage_html("test_client")

    assert result["status"] == "ok"
    html_path = Path(result["path"])
    assert html_path.exists()

    content = html_path.read_text()
    assert "<!DOCTYPE html>" in content
    assert "Log Source Coverage" in content
    assert "test_client" in content
    assert "Identity" in content
    assert "Endpoint" in content


# ---------------------------------------------------------------------------
# History tracking
# ---------------------------------------------------------------------------

@patch("tools.log_coverage._get_workspace_id", return_value=_MOCK_WORKSPACE_ID)
@patch("scripts.run_kql.run_kql", side_effect=_mock_run_kql)
def test_history_tracking(mock_kql, mock_ws):
    from tools.log_coverage import collect_log_sources

    # Run twice to build history
    collect_log_sources("test_client")
    # Force a second collection by manipulating the timestamp
    cov_path = COVERAGE_DIR / "test_client.json"
    data = json.loads(cov_path.read_text())
    data["collected_at"] = "2026-03-27T00:00:00Z"  # make it look old
    cov_path.write_text(json.dumps(data))

    collect_log_sources("test_client")

    data = json.loads(cov_path.read_text())
    assert len(data["history"]) >= 2
    assert "overall" in data["history"][-1]
    assert "healthy_sources" in data["history"][-1]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_client():
    from tools.log_coverage import collect_log_sources

    result = collect_log_sources("")
    assert result["status"] == "error"


@patch("tools.log_coverage._get_workspace_id", return_value=None)
def test_no_workspace(mock_ws):
    from tools.log_coverage import collect_log_sources

    result = collect_log_sources("nonexistent_client")
    assert result["status"] == "error"
    assert "workspace" in result["reason"].lower()
