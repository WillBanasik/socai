"""
Tests for tools/defender_hunting.py — Defender XDR Advanced Hunting wrapper.

Mocks all outbound HTTP. No real tokens or tenants involved.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.defender_hunting as dh


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
    dh._token_cache.clear()
    yield
    dh._token_cache.clear()


@pytest.fixture(autouse=True)
def _http_via_requests(monkeypatch):
    # Production issues HTTP through tools.common.get_session() (pooled); these
    # tests mock at the requests layer (patch.object(dh.requests, "post")).
    # Route get_session() back to the requests module so those patches intercept.
    monkeypatch.setattr(dh, "get_session", lambda: dh.requests)


@pytest.fixture
def _fake_creds(monkeypatch):
    monkeypatch.setenv("SOCAI_DEFENDER_APP_CLIENT_ID", "fake-client-id")
    monkeypatch.setenv("SOCAI_DEFENDER_APP_CLIENT_SECRET", "fake-secret")


@pytest.fixture
def _fake_client_config(monkeypatch):
    """Return a fake get_client_config that yields an enabled performanta entry."""
    def fake_get(client_name: str):
        if client_name.lower() == "performanta":
            return {
                "name": "performanta",
                "platforms": {
                    "defender_xdr": {
                        "api_enabled": True,
                        "tenant_id": "11111111-2222-3333-4444-555555555555",
                    },
                },
            }
        if client_name.lower() == "pending_client":
            return {
                "name": "pending_client",
                "platforms": {"defender_xdr": {"api_enabled": False, "tenant_id": ""}},
            }
        return None

    monkeypatch.setattr(dh, "get_client_config", fake_get)


class TestResolveTenant:
    def test_resolves_enabled_client(self, _fake_client_config):
        assert dh._resolve_tenant("performanta") == "11111111-2222-3333-4444-555555555555"

    def test_unknown_client_raises(self, _fake_client_config):
        with pytest.raises(dh.DefenderNotConfigured):
            dh._resolve_tenant("not-a-client")

    def test_disabled_client_raises(self, _fake_client_config):
        with pytest.raises(dh.DefenderNotConfigured):
            dh._resolve_tenant("pending_client")


class TestIsConfigured:
    def test_true_when_creds_and_config_present(self, _fake_creds, _fake_client_config):
        assert dh.is_defender_configured("performanta") is True

    def test_false_when_no_creds(self, monkeypatch, _fake_client_config):
        monkeypatch.delenv("SOCAI_DEFENDER_APP_CLIENT_ID", raising=False)
        monkeypatch.delenv("SOCAI_DEFENDER_APP_CLIENT_SECRET", raising=False)
        assert dh.is_defender_configured("performanta") is False

    def test_false_when_client_disabled(self, _fake_creds, _fake_client_config):
        assert dh.is_defender_configured("pending_client") is False

    def test_false_when_client_unknown(self, _fake_creds, _fake_client_config):
        assert dh.is_defender_configured("nope") is False


class TestAcquireToken:
    def test_fetches_and_caches(self, _fake_creds):
        token_resp = _FakeResponse(200, {"access_token": "tok-abc", "expires_in": 3600})
        with patch.object(dh.requests, "post", return_value=token_resp) as mock_post:
            t1 = dh._acquire_token("tenant-1")
            t2 = dh._acquire_token("tenant-1")
        assert t1 == t2 == "tok-abc"
        assert mock_post.call_count == 1  # cached on second call

    def test_refreshes_when_near_expiry(self, _fake_creds):
        # First token expires in 60s (safety margin is 120s → already expired)
        first = _FakeResponse(200, {"access_token": "old", "expires_in": 60})
        second = _FakeResponse(200, {"access_token": "new", "expires_in": 3600})
        with patch.object(dh.requests, "post", side_effect=[first, second]) as mock_post:
            t1 = dh._acquire_token("tenant-2")
            t2 = dh._acquire_token("tenant-2")
        assert t1 == "old"
        assert t2 == "new"
        assert mock_post.call_count == 2

    def test_failure_raises(self, _fake_creds):
        resp = _FakeResponse(401, text='{"error":"invalid_client"}')
        with patch.object(dh.requests, "post", return_value=resp):
            with pytest.raises(dh.DefenderHuntingError) as exc:
                dh._acquire_token("tenant-x")
        assert "401" in str(exc.value)


class TestRunDefenderKql:
    def test_empty_query_raises(self, _fake_creds, _fake_client_config):
        with pytest.raises(dh.DefenderHuntingError):
            dh.run_defender_kql("performanta", "")

    def test_not_configured_raises(self, _fake_creds, _fake_client_config):
        with pytest.raises(dh.DefenderNotConfigured):
            dh.run_defender_kql("pending_client", "DeviceEvents | take 1")

    def test_happy_path_returns_rows_and_schema(self, _fake_creds, _fake_client_config):
        # Prime token cache so only one HTTP call (the query) happens.
        dh._token_cache["11111111-2222-3333-4444-555555555555"] = ("cached-tok", time.time() + 3600)
        query_resp = _FakeResponse(200, {
            "Schema": [{"Name": "Timestamp", "Type": "DateTime"}, {"Name": "DeviceName", "Type": "String"}],
            "Results": [
                {"Timestamp": "2026-05-23T00:00:00Z", "DeviceName": "host-1"},
                {"Timestamp": "2026-05-23T00:01:00Z", "DeviceName": "host-2"},
            ],
        })
        with patch.object(dh.requests, "post", return_value=query_resp):
            result = dh.run_defender_kql("performanta", "DeviceEvents | take 2")
        assert result["stats"]["row_count"] == 2
        assert result["rows"][0]["DeviceName"] == "host-1"
        assert result["schema"][0]["Name"] == "Timestamp"

    def test_401_clears_token_cache_and_raises(self, _fake_creds, _fake_client_config):
        tenant = "11111111-2222-3333-4444-555555555555"
        dh._token_cache[tenant] = ("stale-tok", time.time() + 3600)
        resp = _FakeResponse(401, text='{"error":"InvalidAuthenticationToken"}')
        with patch.object(dh.requests, "post", return_value=resp):
            with pytest.raises(dh.DefenderHuntingError) as exc:
                dh.run_defender_kql("performanta", "DeviceEvents | take 1")
        assert "401" in str(exc.value)
        assert tenant not in dh._token_cache  # cleared

    def test_429_surfaces_retry_after(self, _fake_creds, _fake_client_config):
        dh._token_cache["11111111-2222-3333-4444-555555555555"] = ("tok", time.time() + 3600)
        resp = _FakeResponse(429, text='{"error":"too many requests"}', headers={"Retry-After": "60"})
        with patch.object(dh.requests, "post", return_value=resp):
            with pytest.raises(dh.DefenderHuntingError) as exc:
                dh.run_defender_kql("performanta", "DeviceEvents | take 1")
        assert "429" in str(exc.value)
        assert "Retry-After=60" in str(exc.value)

    def test_other_error_raises(self, _fake_creds, _fake_client_config):
        dh._token_cache["11111111-2222-3333-4444-555555555555"] = ("tok", time.time() + 3600)
        resp = _FakeResponse(400, text='{"error":"SemanticError: table not found"}')
        with patch.object(dh.requests, "post", return_value=resp):
            with pytest.raises(dh.DefenderHuntingError) as exc:
                dh.run_defender_kql("performanta", "BogusTable | take 1")
        assert "400" in str(exc.value)
