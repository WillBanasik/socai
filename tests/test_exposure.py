"""
Tests for client exposure testing.
Run with:  cd socai && python -m pytest tests/test_exposure.py -v
"""
import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import EXPOSURE_DIR


@pytest.fixture(autouse=True)
def cleanup_exposure():
    """Remove test exposure data before and after each test."""
    test_file = EXPOSURE_DIR / "test_client.json"
    test_html = EXPOSURE_DIR / "test_client_exposure.html"

    def _rm():
        for f in (test_file, test_html):
            if f.exists():
                f.unlink()

    _rm()
    yield
    _rm()


# ---------------------------------------------------------------------------
# SPF parsing
# ---------------------------------------------------------------------------

def test_parse_spf_hard_fail():
    from tools.exposure_test import _parse_spf

    txt = ['v=spf1 ip4:1.2.3.4 include:_spf.google.com -all']
    result = _parse_spf(txt, "example.com", depth=3)  # depth=3 to skip recursive includes

    assert result["policy"] == "-all"
    assert "1.2.3.4" in result["authorised_ips"]
    assert "_spf.google.com" in result["includes"]


def test_parse_spf_soft_fail():
    from tools.exposure_test import _parse_spf

    txt = ['v=spf1 ip4:10.0.0.0/24 ~all']
    result = _parse_spf(txt, "example.com", depth=3)

    assert result["policy"] == "~all"
    assert "10.0.0.0/24" in result["authorised_networks"]


def test_parse_spf_missing():
    from tools.exposure_test import _parse_spf

    result = _parse_spf(["some random txt record"], "example.com")
    assert result["policy"] == "missing"


def test_parse_spf_pass_all():
    from tools.exposure_test import _parse_spf

    txt = ['v=spf1 +all']
    result = _parse_spf(txt, "example.com", depth=3)
    assert result["policy"] == "+all"


# ---------------------------------------------------------------------------
# DMARC parsing
# ---------------------------------------------------------------------------

def test_parse_dmarc_reject():
    from tools.exposure_test import _parse_dmarc

    with patch("tools.exposure_test._dns_query") as mock_dns:
        mock_dns.return_value = ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100']
        result = _parse_dmarc("example.com")

    assert result["policy"] == "reject"
    assert "mailto:dmarc@example.com" in result["rua"]
    assert result["pct"] == 100


def test_parse_dmarc_missing():
    from tools.exposure_test import _parse_dmarc

    with patch("tools.exposure_test._dns_query") as mock_dns:
        mock_dns.return_value = []
        result = _parse_dmarc("example.com")

    assert result["policy"] == "missing"


def test_parse_dmarc_none():
    from tools.exposure_test import _parse_dmarc

    with patch("tools.exposure_test._dns_query") as mock_dns:
        mock_dns.return_value = ['v=DMARC1; p=none; pct=50']
        result = _parse_dmarc("example.com")

    assert result["policy"] == "none"
    assert result["pct"] == 50


# ---------------------------------------------------------------------------
# Email security scoring
# ---------------------------------------------------------------------------

def test_email_security_good():
    from tools.exposure_test import assess_email_security

    dns_data = {
        "domain": "example.com",
        "spf": {"raw": "v=spf1 -all", "policy": "-all", "includes": [],
                "authorised_ips": [], "authorised_networks": [],
                "dns_lookups": 3, "over_limit": False},
        "dmarc": {"raw": "v=DMARC1; p=reject", "policy": "reject",
                  "subdomain_policy": "", "rua": ["mailto:d@example.com"],
                  "ruf": [], "pct": 100},
        "dkim_selectors": [{"selector": "selector1", "found": True}],
    }

    result = assess_email_security(dns_data)
    assert result["score"] >= 90
    assert len(result["findings"]) == 0


def test_email_security_bad():
    from tools.exposure_test import assess_email_security

    dns_data = {
        "domain": "example.com",
        "spf": {"raw": "", "policy": "missing", "includes": [],
                "authorised_ips": [], "authorised_networks": [],
                "dns_lookups": 0, "over_limit": False},
        "dmarc": {"raw": "", "policy": "missing", "subdomain_policy": "",
                  "rua": [], "ruf": [], "pct": 100},
        "dkim_selectors": [],
    }

    result = assess_email_security(dns_data)
    assert result["score"] <= 40
    critical = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(critical) >= 2  # missing SPF + missing DMARC


# ---------------------------------------------------------------------------
# Typosquat generation
# ---------------------------------------------------------------------------

def test_typosquat_generation():
    from tools.exposure_test import _generate_typosquats

    candidates = _generate_typosquats("example.com")

    # Should generate substantial candidates
    assert len(candidates) > 20

    # Should include different types
    types = {c["type"] for c in candidates}
    assert "omission" in types
    assert "transposition" in types
    assert "tld_swap" in types

    # Should not include the original domain
    domains = {c["domain"] for c in candidates}
    assert "example.com" not in domains

    # Cap at 250
    assert len(candidates) <= 250


def test_typosquat_omission():
    from tools.exposure_test import _generate_typosquats

    candidates = _generate_typosquats("test.com")
    omissions = [c for c in candidates if c["type"] == "omission"]
    omission_domains = {c["domain"] for c in omissions}

    assert "est.com" in omission_domains
    assert "tst.com" in omission_domains
    assert "tet.com" in omission_domains
    assert "tes.com" in omission_domains


def test_typosquat_tld_swap():
    from tools.exposure_test import _generate_typosquats

    candidates = _generate_typosquats("example.com")
    tld_swaps = [c for c in candidates if c["type"] == "tld_swap"]
    swap_domains = {c["domain"] for c in tld_swaps}

    assert "example.net" in swap_domains
    assert "example.org" in swap_domains
    assert "example.io" in swap_domains


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def test_scoring_no_findings():
    from tools.exposure_test import _calculate_scores

    scores = _calculate_scores([])
    assert scores["overall"] == 0
    assert all(v == 0 for v in scores["by_category"].values())


def test_scoring_critical_findings():
    from tools.exposure_test import _calculate_scores

    findings = [
        {"severity": "critical", "category": "email_security", "title": "No SPF"},
        {"severity": "critical", "category": "email_security", "title": "No DMARC"},
        {"severity": "high", "category": "service_exposure", "title": "RDP exposed"},
    ]

    scores = _calculate_scores(findings)
    assert scores["overall"] > 0
    assert scores["by_category"]["email_security"] > 0
    assert scores["by_category"]["service_exposure"] > 0
    assert scores["by_category"]["credential_exposure"] == 0


# ---------------------------------------------------------------------------
# Health weight / classification
# ---------------------------------------------------------------------------

def test_high_risk_ports():
    from tools.exposure_test import _HIGH_RISK_PORTS

    assert 3389 in _HIGH_RISK_PORTS  # RDP
    assert 445 in _HIGH_RISK_PORTS   # SMB
    assert 80 not in _HIGH_RISK_PORTS  # HTTP is not high risk


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

def test_extract_known_subdomains():
    from tools.exposure_test import _extract_known_subdomains

    knowledge = """
    # Infrastructure
    - portal.example.com — customer portal
    - api.example.com — REST API
    - staging.example.com — staging environment
    """

    subs = _extract_known_subdomains(knowledge, "example.com")
    assert "portal.example.com" in subs
    assert "api.example.com" in subs
    assert "staging.example.com" in subs


def test_extract_known_ips():
    from tools.exposure_test import _extract_known_ips

    knowledge = """
    - Primary: 1.2.3.4
    - Secondary: 10.0.0.1
    - CIDR: 192.168.1.0/24
    """

    ips = _extract_known_ips(knowledge)
    assert "1.2.3.4" in ips
    assert "10.0.0.1" in ips
    assert "192.168.1.0" in ips
