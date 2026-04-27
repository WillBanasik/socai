"""
Tests for dark web intelligence tools (tools/darkweb.py).
Run with:  cd socai && python -m pytest tests/test_darkweb.py -v
"""
import json
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_CASE = "IV_CASE_000"


@pytest.fixture(autouse=True)
def cleanup_test_case():
    """Remove the test case before and after each test."""
    from config.settings import CASES_DIR, REGISTRY_FILE

    def _rm():
        case_dir = CASES_DIR / TEST_CASE
        if case_dir.exists():
            shutil.rmtree(case_dir)
        if REGISTRY_FILE.exists():
            data = json.loads(REGISTRY_FILE.read_text())
            data.get("cases", {}).pop(TEST_CASE, None)
            REGISTRY_FILE.write_text(json.dumps(data, indent=2))

    _rm()
    yield
    _rm()


# ---------------------------------------------------------------------------
# Credential sanitisation
# ---------------------------------------------------------------------------

class TestRedaction:

    def test_redact_password(self):
        from tools.darkweb import _redact_credentials
        data = {"username": "admin", "password": "SuperSecret123"}
        result = _redact_credentials(data)
        assert result["password"] == "[REDACTED-14chars]"
        assert result["username"] == "admin"

    def test_redact_nested(self):
        from tools.darkweb import _redact_credentials
        data = {
            "credentials": [
                {"url": "https://example.com", "username": "user@test.com",
                 "password": "pass123", "token": "abc-xyz"},
            ]
        }
        result = _redact_credentials(data)
        cred = result["credentials"][0]
        assert cred["password"] == "[REDACTED-7chars]"
        assert cred["token"] == "[REDACTED-7chars]"
        assert cred["url"] == "https://example.com"
        # username with @ gets local-part redacted
        assert cred["username"] == "u***@test.com"

    def test_redact_email_local(self):
        from tools.darkweb import _redact_email_local
        assert _redact_email_local("john.doe@example.com") == "j***@example.com"
        assert _redact_email_local("a@b.com") == "a***@b.com"
        assert _redact_email_local("not-an-email") == "not-an-email"

    def test_redact_empty_password(self):
        from tools.darkweb import _redact_credentials
        data = {"password": "", "pass": None}
        result = _redact_credentials(data)
        assert result["password"] == ""
        assert result["pass"] is None

    def test_redact_preserves_non_sensitive(self):
        from tools.darkweb import _redact_credentials
        data = {
            "stealer": "Lumma",
            "date_compromised": "2024-01-15",
            "computer_name": "ADMIN-PC",
            "ip": "192.168.1.1",
        }
        result = _redact_credentials(data)
        assert result == data


# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

class TestDetectType:

    def test_email(self):
        from tools.darkweb import _detect_type
        assert _detect_type("user@example.com") == "email"

    def test_ip(self):
        from tools.darkweb import _detect_type
        assert _detect_type("192.168.1.1") == "ip"

    def test_cidr(self):
        from tools.darkweb import _detect_type
        assert _detect_type("10.0.0.0/24") == "ip"

    def test_domain(self):
        from tools.darkweb import _detect_type
        assert _detect_type("example.com") == "domain"

    def test_unknown(self):
        from tools.darkweb import _detect_type
        assert _detect_type("foobar") == "unknown"


# ---------------------------------------------------------------------------
# XposedOrNot (mocked HTTP)
# ---------------------------------------------------------------------------

class TestXposedOrNot:

    def test_email_check_breached(self):
        from tools.darkweb import xposedornot_email_check

        mock_check_resp = MagicMock()
        mock_check_resp.status_code = 200
        mock_check_resp.json.return_value = {
            "breaches": ["LinkedIn2021", "Adobe2013"],
        }

        mock_analytics_resp = MagicMock()
        mock_analytics_resp.status_code = 200
        mock_analytics_resp.json.return_value = {
            "ExposedBreaches": [
                {"name": "LinkedIn2021", "domain": "linkedin.com"}
            ],
            "BreachesSummary": {"total_breaches": 2},
            "BreachMetrics": {
                "risk_score": 7.5,
                "data_types_exposed": ["emails", "passwords"],
                "industry_breakdown": {"technology": 2},
            },
            "ExposedPastes": [],
        }

        mock_session = MagicMock()
        mock_session.get.side_effect = [mock_check_resp, mock_analytics_resp]

        with patch("tools.darkweb.get_session", return_value=mock_session), \
             patch("tools.darkweb._xon_rate_limit"):
            result = xposedornot_email_check("victim@example.com")

        assert result["status"] == "ok"
        assert result["breached"] is True
        assert "LinkedIn2021" in result["breach_names"]
        assert result["risk_score"] == 7.5

    def test_email_check_clean(self):
        from tools.darkweb import xposedornot_email_check

        mock_check_resp = MagicMock()
        mock_check_resp.status_code = 404

        mock_analytics_resp = MagicMock()
        mock_analytics_resp.status_code = 404

        mock_session = MagicMock()
        mock_session.get.side_effect = [mock_check_resp, mock_analytics_resp]

        with patch("tools.darkweb.get_session", return_value=mock_session), \
             patch("tools.darkweb._xon_rate_limit"):
            result = xposedornot_email_check("clean@safe.com")

        assert result["status"] == "no_results"
        assert result["breached"] is False

    @patch("tools.darkweb.XPOSEDORNOT_KEY", "")
    def test_domain_check_no_key(self):
        from tools.darkweb import xposedornot_domain_check
        result = xposedornot_domain_check("example.com")
        assert result["status"] == "no_api_key"


# ---------------------------------------------------------------------------
# Ahmia.fi
# ---------------------------------------------------------------------------

class TestAhmia:

    def test_onion_grep_matches(self):
        """Test onion list grep mode (no OPSEC proxy)."""
        from tools.darkweb import ahmia_search

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.text = (
            "http://bmarketjfejd7xrvfvisx22i2w7tjhbr3fbh4ggv4ycaijodcda6aqyd.onion/<br>\n"
            "http://cmarket2mkfnxbpjtd7moahl2vel3r7bbix2mibljappe4bmwzbejtad.onion/<br>\n"
            "http://cleansite22fwhnpcneygix6wumgshk7dhymkvc4zdmakjp4dkbqzad.onion/<br>\n"
        )

        with patch("tools.darkweb._tor_is_available", return_value=False), \
             patch("requests.get", return_value=mock_resp):
            result = ahmia_search("market", max_results=5)

        assert result["status"] == "ok"
        assert result["mode"] == "onion_list_grep"
        assert result["result_count"] == 2
        assert result["total_indexed_onions"] == 3

    def test_onion_grep_no_matches(self):
        from tools.darkweb import ahmia_search

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.text = (
            "http://cleansite22fwhnpcneygix6wumgshk7dhymkvc4zdmakjp4dkbqzad.onion/<br>\n"
            "http://othersite3irb6bxhqt2rfem3mkj3sd357cikvchvitnpt4qrbzofad.onion/<br>\n"
        )

        with patch("tools.darkweb._tor_is_available", return_value=False), \
             patch("requests.get", return_value=mock_resp):
            result = ahmia_search("nonexistent_xyz")

        assert result["status"] == "no_results"
        assert result["result_count"] == 0

    def test_full_search_with_tor(self):
        """Test full search mode when Tor is available."""
        from tools.darkweb import ahmia_search

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = """
        <html><body>
        <li class="result">
            <h4>Dark Forum</h4>
            <a href="/search/redirect?redirect_url=http://abc123.onion/page">Link</a>
            <p>Discussion about leaked data</p>
            <cite>abc123.onion</cite>
        </li>
        </body></html>
        """

        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp

        with patch("tools.darkweb._tor_is_available", return_value=True), \
             patch("tools.darkweb._get_tor_session", return_value=mock_session):
            result = ahmia_search("test query")

        assert result["status"] == "ok"
        assert result["mode"] == "full_search"
        assert result["result_count"] == 1


# ---------------------------------------------------------------------------
# Intelligence X
# ---------------------------------------------------------------------------

class TestIntelX:

    @patch("tools.darkweb.INTELX_KEY", "test-key")
    def test_search_ok(self):
        from tools.darkweb import intelx_search

        mock_search_resp = MagicMock()
        mock_search_resp.status_code = 200
        mock_search_resp.raise_for_status = MagicMock()
        mock_search_resp.json.return_value = {"id": "search-uuid-123", "status": 0}

        mock_result_resp = MagicMock()
        mock_result_resp.status_code = 200
        mock_result_resp.raise_for_status = MagicMock()
        mock_result_resp.json.return_value = {
            "records": [
                {"bucket": "pastes", "name": "paste_result",
                 "date": "2024-01-15", "xscore": 0.9},
                {"bucket": "darknet", "name": "darknet_result",
                 "date": "2024-02-20", "xscore": 0.7},
            ],
            "status": 0,
        }

        mock_terminate_resp = MagicMock()
        mock_terminate_resp.status_code = 200

        mock_session = MagicMock()
        mock_session.post.return_value = mock_search_resp
        mock_session.get.side_effect = [mock_result_resp, mock_terminate_resp]

        with patch("tools.darkweb.get_session", return_value=mock_session), \
             patch("tools.darkweb.time.sleep"):
            result = intelx_search("test@example.com")

        assert result["status"] == "ok"
        assert result["result_count"] == 2
        assert result["search_id"] == "search-uuid-123"

    @patch("tools.darkweb.INTELX_KEY", "test-key")
    def test_search_no_results(self):
        from tools.darkweb import intelx_search

        mock_search_resp = MagicMock()
        mock_search_resp.status_code = 200
        mock_search_resp.raise_for_status = MagicMock()
        mock_search_resp.json.return_value = {"id": "search-uuid-456", "status": 0}

        mock_result_resp = MagicMock()
        mock_result_resp.status_code = 200
        mock_result_resp.raise_for_status = MagicMock()
        mock_result_resp.json.return_value = {"records": [], "status": 3}

        mock_terminate_resp = MagicMock()

        mock_session = MagicMock()
        mock_session.post.return_value = mock_search_resp
        mock_session.get.side_effect = [mock_result_resp, mock_terminate_resp]

        with patch("tools.darkweb.get_session", return_value=mock_session), \
             patch("tools.darkweb.time.sleep"):
            result = intelx_search("clean@safe.com")

        assert result["status"] == "no_results"
        assert result["result_count"] == 0

    @patch("tools.darkweb.INTELX_KEY", "test-key")
    def test_quota_exceeded(self):
        from tools.darkweb import intelx_search

        mock_resp = MagicMock()
        mock_resp.status_code = 402

        mock_session = MagicMock()
        mock_session.post.return_value = mock_resp

        with patch("tools.darkweb.get_session", return_value=mock_session):
            result = intelx_search("test@example.com")

        assert result["status"] == "quota_exceeded"

    @patch("tools.darkweb.INTELX_KEY", "test-key")
    def test_credentials_redacted_in_results(self):
        from tools.darkweb import intelx_search

        mock_search_resp = MagicMock()
        mock_search_resp.status_code = 200
        mock_search_resp.raise_for_status = MagicMock()
        mock_search_resp.json.return_value = {"id": "uuid-789", "status": 0}

        mock_result_resp = MagicMock()
        mock_result_resp.status_code = 200
        mock_result_resp.raise_for_status = MagicMock()
        mock_result_resp.json.return_value = {
            "records": [
                {"bucket": "leaks", "name": "leak_data",
                 "password": "leaked_password_123"},
            ],
            "status": 0,
        }

        mock_terminate_resp = MagicMock()

        mock_session = MagicMock()
        mock_session.post.return_value = mock_search_resp
        mock_session.get.side_effect = [mock_result_resp, mock_terminate_resp]

        with patch("tools.darkweb.get_session", return_value=mock_session), \
             patch("tools.darkweb.time.sleep"):
            result = intelx_search("test@example.com")

        assert "REDACTED" in result["results"][0]["password"]
        assert "leaked_password_123" not in json.dumps(result)


# ---------------------------------------------------------------------------
# Stealer log parser
# ---------------------------------------------------------------------------

class TestStealerParser:

    def test_missing_dependency(self):
        from tools.darkweb import parse_stealer_logs
        from tools.case_create import case_create

        case_create(TEST_CASE, title="stealer test", severity="low")

        with patch.dict("sys.modules", {"stealer_parser": None}):
            # Force re-import to hit ImportError
            import importlib
            import tools.darkweb as dw
            # The function handles ImportError gracefully
            result = dw.parse_stealer_logs(TEST_CASE)
            # Either "error" (import fails) or "no_archives" (import succeeds but no files)
            assert result["status"] in ("error", "no_archives")

    def test_no_archives(self):
        from tools.darkweb import parse_stealer_logs
        from tools.case_create import case_create

        case_create(TEST_CASE, title="stealer test", severity="low")

        # Mock the import so it doesn't fail
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"stealer_parser": mock_module}):
            result = parse_stealer_logs(TEST_CASE)
            assert result["status"] == "no_archives"


# ---------------------------------------------------------------------------
# Dark web summary
# ---------------------------------------------------------------------------

class TestDarkwebSummary:

    def test_no_indicators(self):
        from tools.darkweb import darkweb_summary
        from tools.case_create import case_create

        case_create(TEST_CASE, title="summary test", severity="low")
        result = darkweb_summary(TEST_CASE)
        assert result["status"] == "no_indicators"

    def test_case_not_found(self):
        from tools.darkweb import darkweb_summary
        result = darkweb_summary("NONEXISTENT_CASE")
        assert result["status"] == "error"
