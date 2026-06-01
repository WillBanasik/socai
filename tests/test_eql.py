"""
Tests for tools/eql.py — Encore EQL case-scoped entity context.

Mocks all outbound HTTP. No real ENCORE_EQL_TOKEN or gateway involved.
Focus: the token-scope gate (no HTTP when a client isn't mapped), happy-path
parsing, freshness/coverage stamping, and the evidence write.
"""
from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.eql as eql
from config.settings import CASES_DIR

TEST_CASE = "IV_CASE_000"


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or ""

    def json(self):
        return self._payload


def _eql_payload(rows: list[dict]) -> dict:
    return {"Data": rows, "ErrorMessages": [], "RowCount": len(rows)}


@pytest.fixture(autouse=True)
def _clear_token_cache():
    eql._token_cache.clear()
    yield
    eql._token_cache.clear()


@pytest.fixture(autouse=True)
def _seed_token():
    # Pre-seed a valid access token so no /auth/refresh call is made.
    eql._token_cache["access"] = ("fake-access-token", time.time() + 1800)


@pytest.fixture
def _case(tmp_path):
    """Create a minimal case with a client set, clean up after."""
    case_dir = CASES_DIR / TEST_CASE
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "case_meta.json").write_text(json.dumps({
        "case_id": TEST_CASE, "client": "performanta", "title": "test",
    }))
    yield case_dir
    if case_dir.exists():
        shutil.rmtree(case_dir)


def _mapped_config(client_name: str):
    if client_name.lower() == "performanta":
        return {"name": "performanta", "platforms": {
            "encore": {"internal_client_id": "uuid-perf-123", "access": "read"}}}
    if client_name.lower() == "noaccess":
        return {"name": "noaccess", "platforms": {
            "encore": {"internal_client_id": "uuid-x", "access": "none"}}}
    if client_name.lower() == "unmapped":
        return {"name": "unmapped", "platforms": {"sentinel": {"workspace_id": "x"}}}
    return None


# ---------------------------------------------------------------------------
# Scope gate
# ---------------------------------------------------------------------------

class TestScopeGate:
    def test_unmapped_client_refused_no_http(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        (_case / "case_meta.json").write_text(json.dumps({"client": "unmapped"}))
        post = MagicMock()
        with patch.object(eql.requests, "post", post):
            with pytest.raises(eql.EqlNotConfigured):
                eql.entity_context(TEST_CASE, user="alice@corp.com")
        post.assert_not_called()  # gate fires before any HTTP

    def test_no_read_access_refused(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        (_case / "case_meta.json").write_text(json.dumps({"client": "noaccess"}))
        with pytest.raises(eql.EqlNotConfigured):
            eql.entity_context(TEST_CASE, host="PC1")

    def test_is_eql_configured(self, monkeypatch):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        assert eql.is_eql_configured("performanta") is True
        assert eql.is_eql_configured("unmapped") is False
        assert eql.is_eql_configured("noaccess") is False

    def test_requires_an_entity(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        with pytest.raises(eql.EqlError):
            eql.entity_context(TEST_CASE)


# ---------------------------------------------------------------------------
# Entity context happy path
# ---------------------------------------------------------------------------

class TestEntityContext:
    def test_user_context_parsed_and_persisted(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        rows = [{"UserPrincipalName": "alice@corp.com", "CreatedDateTime": "2026-06-01T10:00:00Z",
                 "CountryName": "United Kingdom", "DaysSinceMostRecentData": 0}]
        with patch.object(eql.requests, "post", return_value=_FakeResponse(200, _eql_payload(rows))):
            out = eql.entity_context(TEST_CASE, user="alice@corp.com")

        assert out["client"] == "performanta"
        assert out["internal_client_id"] == "uuid-perf-123"
        # user has 4 curated queries
        assert len([q for q in out["queries"] if q["entity_type"] == "user"]) == 4
        first = out["queries"][0]
        assert first["row_count"] == 1
        assert first["coverage"] == "ok"
        assert first["freshness"]["latest_record"] == "2026-06-01T10:00:00Z"
        assert first["freshness"]["days_since_most_recent_data"] == 0
        # artefact written
        art = CASES_DIR / TEST_CASE / "artefacts" / "eql_context"
        assert art.exists() and any(art.iterdir())
        # evidence note appended
        assert (CASES_DIR / TEST_CASE / "notes" / "analyst_input.md").exists()

    def test_event_rows_capped_but_total_kept(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        many = [{"UserPrincipalName": "alice@corp.com",
                 "CreatedDateTime": f"2026-06-01T{h:02d}:00:00Z"} for h in range(24)] * 10  # 240 rows
        with patch.object(eql.requests, "post", return_value=_FakeResponse(200, _eql_payload(many))):
            out = eql.entity_context(TEST_CASE, user="alice@corp.com")
        q = out["queries"][0]
        assert q["row_count"] == 240            # true total preserved
        assert q["rows_returned"] == eql._MAX_ROWS_INLINE
        assert q["truncated"] is True
        assert len(q["rows"]) == eql._MAX_ROWS_INLINE
        # full set persisted to artefact
        art = next((CASES_DIR / TEST_CASE / "artefacts" / "eql_context").iterdir())
        assert len(json.loads(art.read_text())["queries"][0]["rows"]) == 240

    def test_empty_result_marked_no_data(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        with patch.object(eql.requests, "post", return_value=_FakeResponse(200, _eql_payload([]))):
            out = eql.entity_context(TEST_CASE, host="PC1")
        assert all(q["coverage"] == "no_data_for_client" for q in out["queries"])
        assert all(q["row_count"] == 0 for q in out["queries"])

    def test_query_pinned_to_internal_client_id(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        post = MagicMock(return_value=_FakeResponse(200, _eql_payload([])))
        with patch.object(eql.requests, "post", post):
            eql.entity_context(TEST_CASE, ip="1.2.3.4")
        # every call URL carries the mapped client id, never a caller value
        for call in post.call_args_list:
            url = call.args[0] if call.args else call.kwargs.get("url", "")
            assert "client=uuid-perf-123" in url

    def test_bad_table_does_not_sink_context(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        with patch.object(eql.requests, "post", return_value=_FakeResponse(500, text="boom")):
            out = eql.entity_context(TEST_CASE, user="bob@corp.com")
        # all queries errored but the call returned a structured result
        assert out["queries"]
        assert all(q["coverage"] == "query_error" for q in out["queries"])


# ---------------------------------------------------------------------------
# Raw query escape hatch
# ---------------------------------------------------------------------------

class TestRunEqlForCase:
    def test_raw_query_pinned_and_persisted(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        rows = [{"UserPrincipalName": "x", "CreatedDateTime": "2026-06-01T09:00:00Z"}]
        with patch.object(eql.requests, "post", return_value=_FakeResponse(200, _eql_payload(rows))):
            out = eql.run_eql_for_case(TEST_CASE, 'AzureActiveDirectory-Users SELECT UserPrincipalName')
        assert out["row_count"] == 1
        assert out["internal_client_id"] == "uuid-perf-123"
        assert out["freshness"]["latest_record"] == "2026-06-01T09:00:00Z"

    def test_raw_query_refused_when_unmapped(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        (_case / "case_meta.json").write_text(json.dumps({"client": "unmapped"}))
        post = MagicMock()
        with patch.object(eql.requests, "post", post):
            with pytest.raises(eql.EqlNotConfigured):
                eql.run_eql_for_case(TEST_CASE, "X SELECT Y")
        post.assert_not_called()


# ---------------------------------------------------------------------------
# Posture baseline (client-wide, for the security architecture review)
# ---------------------------------------------------------------------------

class TestPostureContext:
    def test_posture_pulls_all_domains_pinned(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        rows = [{"EntryDate": "2026-06-01T00:00:00", "CurrentScore": 1360}]
        post = MagicMock(return_value=_FakeResponse(200, _eql_payload(rows)))
        with patch.object(eql.requests, "post", post):
            out = eql.posture_context(TEST_CASE)

        assert out["client"] == "performanta"
        assert out["internal_client_id"] == "uuid-perf-123"
        # one domain entry per curated posture template
        assert len(out["domains"]) == len(eql.POSTURE_TEMPLATES)
        assert all(d["coverage"] == "ok" for d in out["domains"])
        # every query is client-wide (no WHERE) and pinned to the mapped id
        for d in out["domains"]:
            assert " WHERE " not in d["query"]
        for call in post.call_args_list:
            url = call.args[0] if call.args else call.kwargs.get("url", "")
            assert "client=uuid-perf-123" in url
        # full payload persisted as posture.json
        assert (CASES_DIR / TEST_CASE / "artefacts" / "eql_context" / "posture.json").exists()

    def test_posture_refused_when_unmapped_no_http(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        (_case / "case_meta.json").write_text(json.dumps({"client": "unmapped"}))
        post = MagicMock()
        with patch.object(eql.requests, "post", post):
            with pytest.raises(eql.EqlNotConfigured):
                eql.posture_context(TEST_CASE)
        post.assert_not_called()  # gate fires before any HTTP

    def test_posture_snapshot_rows_capped_total_kept(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        many = [{"EntryDate": f"2026-06-{d:02d}T00:00:00"} for d in range(1, 29)] * 5  # 140 rows
        with patch.object(eql.requests, "post", return_value=_FakeResponse(200, _eql_payload(many))):
            out = eql.posture_context(TEST_CASE)
        d0 = out["domains"][0]
        assert d0["row_count"] == 140                     # true total preserved
        assert d0["rows_returned"] == eql._MAX_ROWS_INLINE
        assert d0["truncated"] is True
        # full set persisted to the artefact
        art = json.loads((CASES_DIR / TEST_CASE / "artefacts" / "eql_context" / "posture.json").read_text())
        assert len(art["domains"][0]["rows"]) == 140

    def test_posture_bad_table_does_not_sink_pull(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        with patch.object(eql.requests, "post", return_value=_FakeResponse(500, text="boom")):
            out = eql.posture_context(TEST_CASE)
        assert out["domains"]
        assert all(d["coverage"] == "query_error" for d in out["domains"])
