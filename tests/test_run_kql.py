"""Unit tests for ``scripts.run_kql.run_kql`` error handling.

Regression guard: a failed ``az`` query must raise ``KqlQueryError`` (carrying
the real az error) rather than return an empty list. Returning ``[]`` on failure
makes a bad-column/table/syntax query indistinguishable from a query that
legitimately matched zero rows — the "silent 0-row" trap.
"""
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from scripts.run_kql import KqlQueryError, run_kql


def _completed(returncode=0, stdout="", stderr=""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


@patch("scripts.run_kql.subprocess.run")
def test_success_returns_rows(mock_run):
    mock_run.return_value = _completed(0, json.dumps([{"A": 1}, {"A": 2}]))
    rows = run_kql("ws", "SecurityEvent | take 2", skip_validation=True)
    assert rows == [{"A": 1}, {"A": 2}]


@patch("scripts.run_kql.subprocess.run")
def test_empty_result_is_not_an_error(mock_run):
    # A genuine 0-row result must still come back as [] — not raise.
    mock_run.return_value = _completed(0, "[]")
    assert run_kql("ws", "SecurityEvent | where 1==0", skip_validation=True) == []


@patch("scripts.run_kql.subprocess.run")
def test_bad_column_raises_with_message(mock_run):
    mock_run.return_value = _completed(
        1,
        stderr="BadArgument: The name 'CreatedTimeUTC' does not refer to any known column",
    )
    with pytest.raises(KqlQueryError) as ei:
        run_kql("ws", "SecurityIncident | project CreatedTimeUTC", skip_validation=True)
    assert "CreatedTimeUTC" in str(ei.value)
    assert ei.value.kind == "error"


@patch("scripts.run_kql.subprocess.run")
def test_failure_falls_back_to_stdout_when_stderr_empty(mock_run):
    mock_run.return_value = _completed(1, stdout="SemanticError on stdout", stderr="")
    with pytest.raises(KqlQueryError) as ei:
        run_kql("ws", "SecurityEvent | bogus", skip_validation=True)
    assert "SemanticError on stdout" in str(ei.value)


@patch("scripts.run_kql.subprocess.run")
def test_timeout_raises(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="az", timeout=60)
    with pytest.raises(KqlQueryError) as ei:
        run_kql("ws", "SecurityEvent", timeout=60, skip_validation=True)
    assert ei.value.kind == "timeout"


@patch("scripts.run_kql.subprocess.run")
def test_invalid_json_raises(mock_run):
    mock_run.return_value = _completed(0, "not json at all")
    with pytest.raises(KqlQueryError) as ei:
        run_kql("ws", "SecurityEvent", skip_validation=True)
    assert ei.value.kind == "decode"


@patch("scripts.run_kql.subprocess.run")
def test_error_object_on_stdout_raises(mock_run):
    # az 200 carrying an error object instead of a row array.
    mock_run.return_value = _completed(
        0, json.dumps({"error": {"code": "BadArgument", "message": "bad query"}})
    )
    with pytest.raises(KqlQueryError):
        run_kql("ws", "SecurityEvent", skip_validation=True)
