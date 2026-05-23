"""
Tests for tools/crowdstrike.py — CrowdStrike Falcon platform wrapper.

Mocks all outbound HTTP. No real credentials or hosts involved.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.crowdstrike as cs


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or ""
        self.headers = headers or {}

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _clear_token_cache():
    cs._token_cache.clear()
    yield
    cs._token_cache.clear()


@pytest.fixture
def _fake_creds(monkeypatch):
    monkeypatch.setenv("SOCAI_CROWDSTRIKE_HEIDELBERG_MATERIALS_CLIENT_ID", "fake-cid")
    monkeypatch.setenv("SOCAI_CROWDSTRIKE_HEIDELBERG_MATERIALS_CLIENT_SECRET", "fake-sec")


@pytest.fixture
def _fake_client_config(monkeypatch):
    def fake_get(client_name: str):
        if client_name.lower() == "heidelberg_materials":
            return {
                "name": "heidelberg_materials",
                "platforms": {
                    "crowdstrike": {
                        "api_enabled": True,
                        "falcon_region": "eu-1",
                        "ngsiem_repo": "heidelberg-ngsiem-prod",
                    },
                },
            }
        if client_name.lower() == "pending_client":
            return {
                "name": "pending_client",
                "platforms": {"crowdstrike": {"api_enabled": False, "falcon_region": "", "ngsiem_repo": ""}},
            }
        if client_name.lower() == "bad_region":
            return {
                "name": "bad_region",
                "platforms": {"crowdstrike": {"api_enabled": True, "falcon_region": "atlantis", "ngsiem_repo": "x"}},
            }
        return None

    monkeypatch.setattr(cs, "get_client_config", fake_get)


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------

class TestResolveConfig:
    def test_resolves_enabled_client(self, _fake_client_config):
        cfg = cs._resolve_falcon_config("heidelberg_materials")
        assert cfg["host"] == "api.eu-1.crowdstrike.com"
        assert cfg["region"] == "eu-1"
        assert cfg["ngsiem_repo"] == "heidelberg-ngsiem-prod"

    def test_unknown_client_raises(self, _fake_client_config):
        with pytest.raises(cs.FalconNotConfigured):
            cs._resolve_falcon_config("nope")

    def test_disabled_client_raises(self, _fake_client_config):
        with pytest.raises(cs.FalconNotConfigured):
            cs._resolve_falcon_config("pending_client")

    def test_unknown_region_raises(self, _fake_client_config):
        with pytest.raises(cs.FalconNotConfigured):
            cs._resolve_falcon_config("bad_region")


class TestIsConfigured:
    def test_true_when_creds_and_config_present(self, _fake_creds, _fake_client_config):
        assert cs.is_falcon_configured("heidelberg_materials") is True

    def test_false_when_no_creds(self, monkeypatch, _fake_client_config):
        # No env vars set
        assert cs.is_falcon_configured("heidelberg_materials") is False

    def test_false_when_disabled(self, _fake_creds, _fake_client_config):
        assert cs.is_falcon_configured("pending_client") is False

    def test_false_when_unknown(self, _fake_creds, _fake_client_config):
        assert cs.is_falcon_configured("nope") is False


class TestEnvKey:
    def test_uppercases_and_sanitises(self):
        assert cs._env_key("alex_forbes") == "ALEX_FORBES"
        assert cs._env_key("se-first") == "SE_FIRST"
        assert cs._env_key("Cell C") == "CELL_C"


# ---------------------------------------------------------------------------
# Token acquisition + caching
# ---------------------------------------------------------------------------

class TestAcquireToken:
    def test_fetches_and_caches(self, _fake_creds, _fake_client_config):
        token_resp = _FakeResponse(200, {"access_token": "tok-a", "expires_in": 1799})
        with patch.object(cs.requests, "post", return_value=token_resp) as mock_post:
            h1, t1 = cs._acquire_token("heidelberg_materials")
            h2, t2 = cs._acquire_token("heidelberg_materials")
        assert (h1, h2) == ("api.eu-1.crowdstrike.com", "api.eu-1.crowdstrike.com")
        assert t1 == t2 == "tok-a"
        assert mock_post.call_count == 1

    def test_failure_raises(self, _fake_creds, _fake_client_config):
        resp = _FakeResponse(403, text='{"errors":[{"message":"invalid_client"}]}')
        with patch.object(cs.requests, "post", return_value=resp):
            with pytest.raises(cs.FalconError):
                cs._acquire_token("heidelberg_materials")


# ---------------------------------------------------------------------------
# NG-SIEM (CQL)
# ---------------------------------------------------------------------------

class TestRunFalconCql:
    def test_empty_query_raises(self, _fake_creds, _fake_client_config):
        with pytest.raises(cs.FalconError):
            cs.run_falcon_cql("heidelberg_materials", "")

    def test_not_configured_raises(self, _fake_creds, _fake_client_config):
        with pytest.raises(cs.FalconNotConfigured):
            cs.run_falcon_cql("pending_client", "* | head(1)")

    def test_happy_path(self, _fake_creds, _fake_client_config):
        cs._token_cache["heidelberg_materials@api.eu-1.crowdstrike.com"] = ("cached", time.time() + 1800)
        cql_resp = _FakeResponse(200, {
            "events": [{"@timestamp": "2026-05-23T00:00:00Z", "ProcessName": "powershell.exe"}],
            "metaData": {"eventCount": 1, "totalHits": 1},
        })
        with patch.object(cs.requests, "post", return_value=cql_resp):
            result = cs.run_falcon_cql("heidelberg_materials", "* | head(1)")
        assert result["stats"]["row_count"] == 1
        assert result["rows"][0]["ProcessName"] == "powershell.exe"

    def test_missing_repo_raises(self, _fake_creds, monkeypatch):
        def fake_get(client_name):
            return {
                "name": "heidelberg_materials",
                "platforms": {"crowdstrike": {"api_enabled": True, "falcon_region": "eu-1", "ngsiem_repo": ""}},
            }
        monkeypatch.setattr(cs, "get_client_config", fake_get)
        with pytest.raises(cs.FalconNotConfigured):
            cs.run_falcon_cql("heidelberg_materials", "* | head(1)")

    def test_401_clears_token(self, _fake_creds, _fake_client_config):
        cache_key = "heidelberg_materials@api.eu-1.crowdstrike.com"
        cs._token_cache[cache_key] = ("stale", time.time() + 1800)
        resp = _FakeResponse(401, text='{"errors":[{"message":"invalid token"}]}')
        with patch.object(cs.requests, "post", return_value=resp):
            with pytest.raises(cs.FalconError):
                cs.run_falcon_cql("heidelberg_materials", "* | head(1)")
        assert cache_key not in cs._token_cache

    def test_429_surfaces_retry_after(self, _fake_creds, _fake_client_config):
        cs._token_cache["heidelberg_materials@api.eu-1.crowdstrike.com"] = ("tok", time.time() + 1800)
        resp = _FakeResponse(429, text='{"errors":[]}', headers={"X-Ratelimit-Retryafter": "30"})
        with patch.object(cs.requests, "post", return_value=resp):
            with pytest.raises(cs.FalconError) as exc:
                cs.run_falcon_cql("heidelberg_materials", "* | head(1)")
        assert "429" in str(exc.value)
        assert "Retry-After=30" in str(exc.value)


# ---------------------------------------------------------------------------
# Classic Falcon API (detections / hosts / incidents)
# ---------------------------------------------------------------------------

class TestQueryPaged:
    def test_query_detections_two_step(self, _fake_creds, _fake_client_config):
        cs._token_cache["heidelberg_materials@api.eu-1.crowdstrike.com"] = ("tok", time.time() + 1800)

        ids_resp = _FakeResponse(200, {"resources": ["det-1", "det-2"], "errors": []})
        sums_resp = _FakeResponse(200, {
            "resources": [
                {"detection_id": "det-1", "severity": 70, "tactic": "Execution"},
                {"detection_id": "det-2", "severity": 50, "tactic": "Defense Evasion"},
            ],
            "errors": [],
        })

        with patch.object(cs.requests, "get", return_value=ids_resp) as mock_get, \
             patch.object(cs.requests, "post", return_value=sums_resp) as mock_post:
            result = cs.query_detections("heidelberg_materials", filter_="status:'new'", limit=10)

        assert mock_get.call_count == 1
        assert mock_post.call_count == 1
        assert result["stats"]["row_count"] == 2
        assert result["stats"]["id_count"] == 2
        assert result["rows"][0]["detection_id"] == "det-1"

    def test_empty_query_returns_zero_rows(self, _fake_creds, _fake_client_config):
        cs._token_cache["heidelberg_materials@api.eu-1.crowdstrike.com"] = ("tok", time.time() + 1800)
        ids_resp = _FakeResponse(200, {"resources": [], "errors": []})
        with patch.object(cs.requests, "get", return_value=ids_resp), \
             patch.object(cs.requests, "post") as mock_post:
            result = cs.query_hosts("heidelberg_materials", limit=10)
        assert result["stats"]["row_count"] == 0
        assert mock_post.call_count == 0  # short-circuited

    def test_403_raises(self, _fake_creds, _fake_client_config):
        cs._token_cache["heidelberg_materials@api.eu-1.crowdstrike.com"] = ("tok", time.time() + 1800)
        resp = _FakeResponse(403, text='{"errors":[{"message":"scope missing"}]}')
        with patch.object(cs.requests, "get", return_value=resp):
            with pytest.raises(cs.FalconError) as exc:
                cs.query_incidents("heidelberg_materials", limit=10)
        assert "403" in str(exc.value)
