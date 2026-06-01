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


@pytest.fixture(autouse=True)
def _eql_http_via_requests(monkeypatch):
    # Production issues EQL HTTP through tools.common.get_session() (pooled).
    # These tests mock at the requests layer (patch.object(eql.requests,
    # "post", ...)), so route get_session() back to the requests module — its
    # module-level .post/.get are exactly what those patches replace.
    monkeypatch.setattr(eql, "get_session", lambda: eql.requests)


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
# Identity assessment — lean batch scoping (internal/external + devices)
# ---------------------------------------------------------------------------

def _identity_router(*responses_by_table):
    """Build a requests.post side_effect that returns rows by the table named in
    the EQL body. ``responses_by_table`` is a dict table-substr → rows-fn(value)."""
    routes = responses_by_table[0]

    def _side(*args, **kwargs):
        body = (kwargs.get("data") or b"").decode()
        for table_substr, rows in routes.items():
            if table_substr in body:
                out = rows(body) if callable(rows) else rows
                return _FakeResponse(200, _eql_payload(out))
        return _FakeResponse(200, _eql_payload([]))

    return _side


class TestIdentityAssessment:
    def test_classifies_internal_guest_and_missing(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)

        def _users(body):
            if "alice@corp.com" in body:
                return [{"UserPrincipalName": "alice@corp.com", "UserType": "Member",
                         "OnPremisesSamAccountName": "alice", "AccountEnabled": True}]
            if "guest_ext.com#EXT#@corp.com" in body or "carol@partner.com" in body:
                return [{"UserType": "Guest"}]
            return []  # ghost@corp.com → not in directory

        post = MagicMock(side_effect=_identity_router({
            "AzureActiveDirectory-Users": _users,
            "Intune-ManagedDevices": [{"ManagedDeviceName": "LAPTOP-A1",
                                       "DeviceComplianceStatus": "Compliant",
                                       "IsEncrypted": True, "LastCommsDate": "2026-06-01T08:00:00Z"}],
        }))
        with patch.object(eql.requests, "post", post):
            out = eql.identity_assessment(
                TEST_CASE,
                users=["alice@corp.com", "carol@partner.com", "ghost@corp.com"],
            )

        by_upn = {u["upn"]: u for u in out["users"]}
        assert by_upn["alice@corp.com"]["classification"] == "internal"
        assert by_upn["alice@corp.com"]["sync"] == "hybrid_on_prem"
        assert by_upn["alice@corp.com"]["device_count"] == 1
        assert by_upn["carol@partner.com"]["classification"] == "external_guest"
        assert by_upn["ghost@corp.com"]["classification"] == "not_in_directory"
        # device query fired ONLY for the internal user (1 user query each = 3,
        # plus 1 device query for alice = 4 total)
        assert out["summary"]["eql_queries_run"] == 4
        assert by_upn["carol@partner.com"].get("devices_skipped") == "external_guest"
        assert by_upn["ghost@corp.com"].get("devices_skipped") == "not_in_directory"
        # summary counts
        s = out["summary"]
        assert (s["users_internal"], s["users_external_guest"],
                s["users_not_in_directory"]) == (1, 1, 1)
        # artefact + evidence note written
        art = CASES_DIR / TEST_CASE / "artefacts" / "eql_context"
        assert art.exists() and any(art.glob("identity_assessment_*.json"))
        assert (CASES_DIR / TEST_CASE / "notes" / "analyst_input.md").exists()

    def test_soft_cap_lists_the_remainder(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        users = [f"u{i}@corp.com" for i in range(8)]
        post = MagicMock(return_value=_FakeResponse(200, _eql_payload([])))
        with patch.object(eql.requests, "post", post):
            out = eql.identity_assessment(TEST_CASE, users=users, cap=5)
        assert out["summary"]["users_assessed"] == 5
        assert out["summary"]["users_not_assessed_cap"] == 3
        assert out["not_assessed"]["users"] == users[5:]
        # all 5 are not-in-directory here, so NO device queries fire → exactly 5 calls
        assert post.call_count == 5

    def test_cap_is_raisable(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        users = [f"u{i}@corp.com" for i in range(8)]
        post = MagicMock(return_value=_FakeResponse(200, _eql_payload([])))
        with patch.object(eql.requests, "post", post):
            out = eql.identity_assessment(TEST_CASE, users=users, cap=10)
        assert out["summary"]["users_assessed"] == 8
        assert out["not_assessed"]["users"] == []

    def test_server_with_no_user_classified_and_admins_pulled(self, monkeypatch, _case):
        # A server / shared host that isn't assigned to one user: classify the ASSET
        # and surface who can operate it (local admins) — no `users` argument at all.
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        post = MagicMock(side_effect=_identity_router({
            "Baseline-Core": [{"HostName": "SRV-DB-02", "OperatingSystem": "Windows Server",
                               "ManagedInActiveDirectory": True,
                               "ManagedInDefenderForEndpoint": True,
                               "ManagedInMicrosoftIntune": False,
                               "LastSeen": "2026-05-31T00:00:00Z"}],
            "LateralMovement-LocalAdmins": [
                {"ComputerName": "SRV-DB-02", "AccountName": "CORP\\dbadmin", "AccountType": "User"},
                {"ComputerName": "SRV-DB-02", "AccountName": "CORP\\Domain Admins", "AccountType": "Group"},
            ],
        }))
        with patch.object(eql.requests, "post", post):
            out = eql.identity_assessment(TEST_CASE, hosts=["SRV-DB-02"])
        h = out["hosts"][0]
        assert h["classification"] == "managed_asset"
        assert h["is_managed"] is True
        assert h["managed_in"] == ["ad", "defender"]
        assert h["local_admin_count"] == 2
        assert {a["AccountName"] for a in h["local_admins"]} == {"CORP\\dbadmin", "CORP\\Domain Admins"}
        assert out["summary"]["hosts_managed"] == 1
        # 2 queries: Baseline-Core + LocalAdmins (no user queries at all)
        assert out["summary"]["eql_queries_run"] == 2

    def test_unknown_host_skips_admin_query(self, monkeypatch, _case):
        # No Baseline-Core record → not_in_directory → don't waste the admins query.
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        post = MagicMock(return_value=_FakeResponse(200, _eql_payload([])))
        with patch.object(eql.requests, "post", post):
            out = eql.identity_assessment(TEST_CASE, hosts=["MYSTERY-PC"])
        h = out["hosts"][0]
        assert h["classification"] == "not_in_directory"
        assert h.get("admins_skipped") == "not_in_directory"
        assert h["local_admin_count"] == 0
        assert out["summary"]["hosts_not_in_directory"] == 1
        assert post.call_count == 1   # only the Baseline-Core lookup, admins skipped

    def test_known_unmanaged_host(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        post = MagicMock(side_effect=_identity_router({
            "Baseline-Core": [{"HostName": "OLD-NAS", "OperatingSystem": "Linux"}],  # no ManagedIn*
            "LateralMovement-LocalAdmins": [],
        }))
        with patch.object(eql.requests, "post", post):
            out = eql.identity_assessment(TEST_CASE, hosts=["OLD-NAS"])
        h = out["hosts"][0]
        assert h["classification"] == "known_unmanaged"
        assert h["is_managed"] is False
        assert out["summary"]["hosts_known_unmanaged"] == 1
        assert out["summary"]["eql_queries_run"] == 2  # still pulls admins for a known host

    def test_domain_overlay_flags_mismatch(self, monkeypatch, _case):
        def _cfg(name):
            return {"name": "performanta", "platforms": {
                "encore": {"internal_client_id": "uuid-perf-123", "access": "read"}},
                "identity": {"internal_domains": ["corp.com"]}}
        monkeypatch.setattr(eql, "get_client_config", _cfg)

        def _users(body):
            # both Members, but bob is on an unexpected domain
            if "alice@corp.com" in body:
                return [{"UserPrincipalName": "alice@corp.com", "UserType": "Member"}]
            return [{"UserPrincipalName": "bob@other.com", "UserType": "Member"}]

        post = MagicMock(side_effect=_identity_router({
            "AzureActiveDirectory-Users": _users, "Intune-ManagedDevices": [],
        }))
        with patch.object(eql.requests, "post", post):
            out = eql.identity_assessment(TEST_CASE, users=["alice@corp.com", "bob@other.com"])
        by_upn = {u["upn"]: u for u in out["users"]}
        assert by_upn["alice@corp.com"]["domain_in_config"] is True
        assert by_upn["alice@corp.com"].get("domain_mismatch") is None
        assert by_upn["bob@other.com"]["domain_in_config"] is False
        assert by_upn["bob@other.com"]["domain_mismatch"] is True
        assert out["summary"]["users_domain_mismatch"] == 1
        assert out["internal_domains_configured"] == ["corp.com"]

    def test_pinned_to_client_id_and_refused_when_unmapped(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        post = MagicMock(return_value=_FakeResponse(200, _eql_payload([])))
        with patch.object(eql.requests, "post", post):
            eql.identity_assessment(TEST_CASE, users=["x@corp.com"])
        for call in post.call_args_list:
            url = call.args[0] if call.args else call.kwargs.get("url", "")
            assert "client=uuid-perf-123" in url
        # unmapped client → refused before any HTTP
        (_case / "case_meta.json").write_text(json.dumps({"client": "unmapped"}))
        post2 = MagicMock()
        with patch.object(eql.requests, "post", post2):
            with pytest.raises(eql.EqlNotConfigured):
                eql.identity_assessment(TEST_CASE, users=["x@corp.com"])
        post2.assert_not_called()

    def test_requires_an_entity(self, monkeypatch, _case):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        with pytest.raises(eql.EqlError):
            eql.identity_assessment(TEST_CASE)


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


# ---------------------------------------------------------------------------
# Caseless vulnerability hunt
# ---------------------------------------------------------------------------

class TestVulnHunt:
    def test_resolve_client_by_name_exact_and_gated(self, monkeypatch):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        assert eql.resolve_client_by_name("performanta") == ("performanta", "uuid-perf-123")
        # unmapped / no-access / unknown all refuse before any HTTP
        for bad in ("unmapped", "noaccess", "does-not-exist"):
            with pytest.raises(eql.EqlNotConfigured):
                eql.resolve_client_by_name(bad)
        with pytest.raises(eql.EqlNotConfigured):
            eql.resolve_client_by_name("")

    def test_build_vuln_query_where_and_order(self):
        tpl = {"table": "VulnerabilityPrioritization-Vulnerabilities", "order_by": "Epss",
               "where": 'Classification = "Actively Exploited"', "select": ["CVE", "Epss"]}
        q = eql._build_vuln_query(tpl)
        assert q == ('VulnerabilityPrioritization-Vulnerabilities WHERE '
                     'Classification = "Actively Exploited" SELECT CVE, Epss '
                     'ORDER BY Epss DESCENDING')
        # no-where, no-order template
        q2 = eql._build_vuln_query({"table": "T", "order_by": None, "select": ["A", "B"]})
        assert q2 == "T SELECT A, B"

    def test_vuln_hunt_runs_ranked_and_persists(self, monkeypatch, tmp_path):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        monkeypatch.setattr("config.settings.VULN_HUNT_DIR", tmp_path)
        hosts = [{"ComputerName": f"H{i}", "PrioritizationIndex": 3.4 - i * 0.01,
                  "HasActiveExploit": (i % 2 == 0), "IsRansomwareExploit": (i == 0),
                  "HasImminentThreats": True} for i in range(60)]
        post = MagicMock(return_value=_FakeResponse(200, _eql_payload(hosts)))
        with patch.object(eql.requests, "post", post):
            out = eql.vuln_hunt("performanta")

        assert out["hunt_id"].startswith("VH_")
        assert out["client"] == "performanta" and out["internal_client_id"] == "uuid-perf-123"
        assert len(out["domains"]) == len(eql.VULN_HUNT_TEMPLATES)
        # pinned to the mapped client id on every call
        for call in post.call_args_list:
            url = call.args[0] if call.args else call.kwargs.get("url", "")
            assert "client=uuid-perf-123" in url
        # summary computed on the (full) Hosts rows
        s = out["summary"]
        assert s["hosts_assessed"] == 60
        assert s["hosts_with_active_exploit"] == 30
        assert s["hosts_with_ransomware_exploit"] == 1
        # inline rows HEAD-capped (rank preserved — first row is the highest index)
        hosts_dom = next(d for d in out["domains"] if d["table"].endswith("-Hosts"))
        assert hosts_dom["rows_returned"] == eql._MAX_ROWS_INLINE
        assert hosts_dom["truncated"] is True
        assert hosts_dom["rows"][0]["ComputerName"] == "H0"   # not date-sorted
        # full payload persisted to the caseless store
        persisted = list(tmp_path.glob("VH_*.json"))
        assert len(persisted) == 1
        full = json.loads(persisted[0].read_text())
        assert len(full["domains"][0]["rows"]) == 60          # nothing dropped on disk

    def test_vuln_hunt_refused_when_unmapped_no_http(self, monkeypatch):
        monkeypatch.setattr(eql, "get_client_config", _mapped_config)
        post = MagicMock()
        with patch.object(eql.requests, "post", post):
            with pytest.raises(eql.EqlNotConfigured):
                eql.vuln_hunt("unmapped")
        post.assert_not_called()

    def test_import_vuln_hunt_round_trip(self, monkeypatch, tmp_path, _case):
        monkeypatch.setattr("config.settings.VULN_HUNT_DIR", tmp_path)
        hunt = {"hunt_id": "VH_TEST", "client": "performanta",
                "internal_client_id": "uuid-perf-123", "ts": "2026-06-01T00:00:00Z",
                "summary": {"hosts_assessed": 5, "hosts_with_active_exploit": 2,
                            "hosts_with_ransomware_exploit": 0, "actively_exploited_cves": 3,
                            "new_kevs_48h": 0},
                "domains": [], "_window_note": "n"}
        (tmp_path / "VH_TEST.json").write_text(json.dumps(hunt))

        res = eql.import_vuln_hunt("VH_TEST", TEST_CASE)
        assert res["status"] == "imported" and res["hunt_id"] == "VH_TEST"
        # artefact copied into the case + evidence note appended
        assert (CASES_DIR / TEST_CASE / "artefacts" / "eql_context" / "vuln_hunt_VH_TEST.json").exists()
        notes = (CASES_DIR / TEST_CASE / "notes" / "analyst_input.md").read_text()
        assert "vulnerability hunt" in notes.lower() and "VH_TEST" in notes
        # missing hunt → error, no raise
        assert "error" in eql.import_vuln_hunt("VH_NOPE", TEST_CASE)

    def test_vuln_hunt_report_context_reads_import(self, monkeypatch, tmp_path, _case):
        monkeypatch.setattr("config.settings.VULN_HUNT_DIR", tmp_path)
        hunt = {"hunt_id": "VH_CTX", "client": "performanta",
                "internal_client_id": "uuid-perf-123", "ts": "2026-06-01T00:00:00Z",
                "summary": {"hosts_assessed": 7, "hosts_with_active_exploit": 3,
                            "hosts_with_ransomware_exploit": 1, "hosts_with_imminent_threats": 4,
                            "actively_exploited_cves": 9, "new_kevs_48h": 2},
                "domains": [{"domain": "Exposed hosts", "table": "VulnerabilityPrioritization-Hosts",
                             "row_count": 1, "coverage": "ok",
                             "rows": [{"ComputerName": "WEB01", "MaxCVSS": 10,
                                       "HasActiveExploit": True}]}],
                "_window_note": "n"}
        (tmp_path / "VH_CTX.json").write_text(json.dumps(hunt))
        eql.import_vuln_hunt("VH_CTX", TEST_CASE)

        from tools.vuln_hunt_report import _build_context
        ctx = _build_context(TEST_CASE)
        assert "VH_CTX" in ctx          # hunt id surfaced
        assert "WEB01" in ctx           # host row surfaced
        assert "Actively-exploited CVEs: 9" in ctx   # summary line rendered


# ---------------------------------------------------------------------------
# Token cache — 401 eviction + retry
# ---------------------------------------------------------------------------

class TestTokenInvalidation:
    def test_run_eql_evicts_and_retries_on_401(self):
        """A cached token rejected with 401 (rotated/revoked server-side) is
        evicted and the query retried once with a freshly-minted token."""
        # _seed_token seeds 'fake-access-token'. Call 1: query -> 401.
        # Call 2: /auth/refresh -> new token. Call 3: query retry -> 200.
        q401 = _FakeResponse(401, text="token expired")
        refresh_ok = _FakeResponse(200, {"accessToken": "fresh-token"})
        q200 = _FakeResponse(200, _eql_payload([{"ComputerName": "WEB01"}]))
        post = MagicMock(side_effect=[q401, refresh_ok, q200])
        with patch.object(eql.requests, "post", post):
            out = eql.run_eql("uuid-perf-123", "FROM Devices")
        assert out["row_count"] == 1
        assert post.call_count == 3                       # 401, refresh, retry
        assert eql._token_cache["access"][0] == "fresh-token"  # re-minted

    def test_run_eql_no_retry_on_success(self):
        """Happy path makes exactly one query call and does not touch the token."""
        post = MagicMock(return_value=_FakeResponse(200, _eql_payload([])))
        with patch.object(eql.requests, "post", post):
            eql.run_eql("uuid-perf-123", "FROM Devices")
        assert post.call_count == 1
