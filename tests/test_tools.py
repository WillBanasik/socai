"""
Minimal test suite for SOC-AI tool wrappers.
Run with:  cd socai && python -m pytest tests/ -v
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

# Ensure the repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).parent / "fixtures"
TEST_CASE = "IV_CASE_000"


@pytest.fixture(autouse=True)
def cleanup_test_case():
    """Remove the test case before and after each test."""
    from config.settings import CASES_DIR, REGISTRY_FILE

    def _rm():
        case_dir = CASES_DIR / TEST_CASE
        if case_dir.exists():
            shutil.rmtree(case_dir)
        # Remove from registry
        if REGISTRY_FILE.exists():
            data = json.loads(REGISTRY_FILE.read_text())
            data.get("cases", {}).pop(TEST_CASE, None)
            REGISTRY_FILE.write_text(json.dumps(data, indent=2))

    _rm()
    yield
    _rm()


# ---------------------------------------------------------------------------
# case_create
# ---------------------------------------------------------------------------

def test_case_create():
    from tools.case_create import case_create
    from config.settings import CASES_DIR

    meta = case_create(TEST_CASE, title="Unit test case", severity="low")
    assert meta["case_id"] == TEST_CASE
    assert meta["status"] == "triage"
    assert (CASES_DIR / TEST_CASE / "case_meta.json").exists()


# ---------------------------------------------------------------------------
# extract_iocs
# ---------------------------------------------------------------------------

def test_extract_iocs_from_text():
    from tools.case_create import case_create
    from tools.extract_iocs import extract_iocs
    from config.settings import CASES_DIR

    case_create(TEST_CASE)
    # Copy fixture into artefacts
    art_dir = CASES_DIR / TEST_CASE / "artefacts"
    art_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "sample_ioc_text.txt", art_dir / "sample_ioc_text.txt")

    result = extract_iocs(TEST_CASE)
    iocs = result["iocs"]

    assert "185.220.101.45" in iocs.get("ipv4", [])
    assert "91.199.212.52"  in iocs.get("ipv4", [])
    assert any("malware-delivery" in d for d in iocs.get("domain", []))
    assert "CVE-2024-21413" in iocs.get("cve", [])
    assert any("attacker@phishingops.ru" in e for e in iocs.get("email", []))

    iocs_path = CASES_DIR / TEST_CASE / "iocs" / "iocs.json"
    assert iocs_path.exists()


# ---------------------------------------------------------------------------
# parse_logs CSV
# ---------------------------------------------------------------------------

def test_parse_logs_csv():
    from tools.case_create import case_create
    from tools.parse_logs import parse_logs

    case_create(TEST_CASE)
    result = parse_logs(FIXTURES / "sample_proxy_log.csv", TEST_CASE)

    assert result["row_count"] == 6
    assert result["format"] == "csv"
    ips = result["entities"]["ips"]
    assert "185.220.101.45" in ips
    assert "91.199.212.52"  in ips


# ---------------------------------------------------------------------------
# parse_logs JSON
# ---------------------------------------------------------------------------

def test_parse_logs_json():
    from tools.case_create import case_create
    from tools.parse_logs import parse_logs

    case_create(TEST_CASE)
    result = parse_logs(FIXTURES / "sample_events.json", TEST_CASE)

    assert result["row_count"] == 4
    users = result["entities"]["users"]
    assert any("jsmith" in u for u in users)
    cmds = result["entities"]["commands"]
    assert any("powershell" in c.lower() for c in cmds)


# ---------------------------------------------------------------------------
# static_file_analyse
# ---------------------------------------------------------------------------

def test_static_file_analyse_text():
    from tools.case_create import case_create
    from tools.static_file_analyse import static_file_analyse

    case_create(TEST_CASE)
    result = static_file_analyse(FIXTURES / "sample_ioc_text.txt", TEST_CASE)

    assert result["file_type"] == "Plain text"
    assert result["hashes"]["sha256"]
    assert result["size_bytes"] > 0


# ---------------------------------------------------------------------------
# correlate (no log data – should not crash)
# ---------------------------------------------------------------------------

def test_correlate_no_logs():
    from tools.case_create import case_create
    from tools.extract_iocs import extract_iocs
    from tools.correlate import correlate
    from config.settings import CASES_DIR

    case_create(TEST_CASE)
    art_dir = CASES_DIR / TEST_CASE / "artefacts"
    art_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "sample_ioc_text.txt", art_dir / "sample_ioc_text.txt")
    extract_iocs(TEST_CASE)

    result = correlate(TEST_CASE)
    assert result["case_id"] == TEST_CASE
    # No logs, so no hits expected
    assert "ip_matches" not in result.get("hits", {})


# ---------------------------------------------------------------------------
# generate_report
# ---------------------------------------------------------------------------

def test_generate_report():
    from tools.case_create import case_create
    from tools.extract_iocs import extract_iocs
    from tools.generate_report import generate_report
    from config.settings import CASES_DIR

    case_create(TEST_CASE, title="Report generation test")
    art_dir = CASES_DIR / TEST_CASE / "artefacts"
    art_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "sample_ioc_text.txt", art_dir / "sample_ioc_text.txt")
    extract_iocs(TEST_CASE)

    result = generate_report(TEST_CASE)
    report_path = Path(result["report_path"])

    assert report_path.exists()
    content = report_path.read_text()
    assert "Executive Summary" in content
    assert "Technical Narrative" in content
    assert "Key IOCs" in content
    assert "Recommendations" in content
    assert "Confidence" in content
    assert "What Was NOT Observed" in content


# ---------------------------------------------------------------------------
# index_case
# ---------------------------------------------------------------------------

def test_index_case():
    from tools.case_create import case_create
    from tools.index_case import index_case
    from tools.common import load_json
    from config.settings import REGISTRY_FILE

    case_create(TEST_CASE)
    index_case(TEST_CASE, status="closed")

    registry = load_json(REGISTRY_FILE)
    assert registry["cases"][TEST_CASE]["status"] == "closed"


# ---------------------------------------------------------------------------
# analyse_email
# ---------------------------------------------------------------------------

def test_analyse_email():
    from tools.case_create import case_create
    from tools.analyse_email import analyse_email
    from config.settings import CASES_DIR

    case_create(TEST_CASE)
    result = analyse_email(FIXTURES / "sample_phishing.eml", TEST_CASE)

    assert result["status"] == "ok"
    assert result["case_id"] == TEST_CASE

    # Headers
    headers = result["headers"]
    assert "micros0ft-support.com" in headers["from"]
    assert headers["subject"]
    assert "totallylegit-support.net" in (headers.get("reply_to") or "")

    # Auth results
    auth = result["auth_results"]
    assert auth["spf"] == "fail"
    assert auth["dkim"] == "fail"
    assert auth["dmarc"] == "fail"

    # Spoofing
    signals = result["spoofing_signals"]
    assert len(signals) > 0
    signal_types = [s["type"] for s in signals]
    assert "reply_to_mismatch" in signal_types

    # URLs extracted
    assert len(result["urls"]) > 0
    assert any("micros0ft-verify" in u for u in result["urls"])

    # Attachments
    assert len(result["attachments"]) > 0
    assert any("security_update" in a["filename"] for a in result["attachments"])

    # Output file exists
    analysis_path = CASES_DIR / TEST_CASE / "artefacts" / "email" / "email_analysis.json"
    assert analysis_path.exists()


def test_analyse_email_spoofing_return_path():
    from tools.case_create import case_create
    from tools.analyse_email import analyse_email

    case_create(TEST_CASE)
    result = analyse_email(FIXTURES / "sample_phishing.eml", TEST_CASE)

    signals = result["spoofing_signals"]
    signal_types = [s["type"] for s in signals]
    # From domain (micros0ft-support.com) != Return-Path domain (evil-domain.com)
    assert "return_path_mismatch" in signal_types


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------

def test_triage_no_matches():
    from tools.case_create import case_create
    from tools.triage import triage
    from config.settings import CASES_DIR

    case_create(TEST_CASE)
    result = triage(TEST_CASE, urls=["https://example.com"], severity="medium")

    assert result["status"] == "ok"
    assert result["known_malicious"] == []
    assert result["known_suspicious"] == []
    assert result["escalate_severity"] is None

    triage_path = CASES_DIR / TEST_CASE / "artefacts" / "triage" / "triage_summary.json"
    assert triage_path.exists()


def test_triage_known_malicious():
    """Seed ioc_index with a malicious IOC and verify triage detects it."""
    from tools.case_create import case_create
    from tools.triage import triage
    from tools.common import save_json
    from config.settings import CASES_DIR, IOC_INDEX_FILE

    case_create(TEST_CASE)

    # Seed ioc_index with known malicious domain
    IOC_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    original = None
    if IOC_INDEX_FILE.exists():
        original = IOC_INDEX_FILE.read_text()

    try:
        save_json(IOC_INDEX_FILE, {
            "evil.example.com": {
                "type": "domain",
                "verdict": "malicious",
                "confidence": "HIGH",
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-03-01T00:00:00Z",
                "cases": ["C099"],
            }
        })

        result = triage(TEST_CASE, urls=["https://evil.example.com/phish"], severity="low")

        assert len(result["known_malicious"]) == 1
        assert result["known_malicious"][0]["ioc"] == "evil.example.com"
        assert result["escalate_severity"] == "high"
    finally:
        if original is not None:
            IOC_INDEX_FILE.write_text(original)
        elif IOC_INDEX_FILE.exists():
            IOC_INDEX_FILE.unlink()


# ---------------------------------------------------------------------------
# campaign_cluster
# ---------------------------------------------------------------------------

def test_campaign_cluster_finds_components():
    """Seed ioc_index with shared IOCs and verify campaigns are found."""
    from tools.case_create import case_create
    from tools.campaign_cluster import cluster_campaigns, CAMPAIGNS_FILE
    from tools.common import save_json
    from config.settings import IOC_INDEX_FILE

    case_create(TEST_CASE)

    # Seed ioc_index
    IOC_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    original = None
    if IOC_INDEX_FILE.exists():
        original = IOC_INDEX_FILE.read_text()

    try:
        save_json(IOC_INDEX_FILE, {
            "198.51.100.10": {
                "type": "ipv4", "verdict": "malicious", "confidence": "HIGH",
                "cases": ["C050", "C051"],
            },
            "evil.example.com": {
                "type": "domain", "verdict": "malicious", "confidence": "HIGH",
                "cases": ["C050", "C051"],
            },
            "unrelated.example.com": {
                "type": "domain", "verdict": "clean", "confidence": "HIGH",
                "cases": ["C099"],
            },
        })

        result = cluster_campaigns(case_id=TEST_CASE)

        assert result["status"] == "ok"
        assert result["total"] >= 1
        # Should find C050+C051 as a campaign
        camp = result["campaigns"][0]
        assert "C050" in camp["cases"]
        assert "C051" in camp["cases"]
        assert camp["shared_ioc_count"] >= 2
    finally:
        if original is not None:
            IOC_INDEX_FILE.write_text(original)
        elif IOC_INDEX_FILE.exists():
            IOC_INDEX_FILE.unlink()
        if CAMPAIGNS_FILE.exists():
            CAMPAIGNS_FILE.unlink()


def test_campaign_cluster_single_ioc_filtered():
    """A single shared IOC should not form a campaign (min 2)."""
    from tools.case_create import case_create
    from tools.campaign_cluster import cluster_campaigns, CAMPAIGNS_FILE
    from tools.common import save_json
    from config.settings import IOC_INDEX_FILE

    case_create(TEST_CASE)

    IOC_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    original = None
    if IOC_INDEX_FILE.exists():
        original = IOC_INDEX_FILE.read_text()

    try:
        save_json(IOC_INDEX_FILE, {
            "198.51.100.10": {
                "type": "ipv4", "verdict": "suspicious", "confidence": "LOW",
                "cases": ["C060", "C061"],
            },
        })

        result = cluster_campaigns()
        assert result["total"] == 0
    finally:
        if original is not None:
            IOC_INDEX_FILE.write_text(original)
        elif IOC_INDEX_FILE.exists():
            IOC_INDEX_FILE.unlink()
        if CAMPAIGNS_FILE.exists():
            CAMPAIGNS_FILE.unlink()


# ---------------------------------------------------------------------------
# sandbox_analyse
# ---------------------------------------------------------------------------

def test_sandbox_analyse_no_hashes():
    """Sandbox should handle gracefully when no analysis artefacts exist."""
    from tools.case_create import case_create
    from tools.sandbox_analyse import sandbox_analyse

    case_create(TEST_CASE)
    result = sandbox_analyse(TEST_CASE)

    assert result["status"] == "no_hashes"
    assert result["results"] == []


def test_sandbox_analyse_collects_hashes():
    """Verify hash collection from analysis artefacts."""
    from tools.case_create import case_create
    from tools.sandbox_analyse import _collect_hashes
    from tools.common import save_json
    from config.settings import CASES_DIR

    case_create(TEST_CASE)
    analysis_dir = CASES_DIR / TEST_CASE / "artefacts" / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    save_json(analysis_dir / "test_file.analysis.json", {
        "filename": "test.exe",
        "hashes": {"sha256": "abc123def456", "md5": "aaa"},
    })

    hashes = _collect_hashes(TEST_CASE)
    assert "abc123def456" in hashes


# ---------------------------------------------------------------------------
# detect_anomalies
# ---------------------------------------------------------------------------

def test_detect_anomalies_no_logs():
    """Should handle gracefully when no parsed logs exist."""
    from tools.case_create import case_create
    from tools.detect_anomalies import detect_anomalies

    case_create(TEST_CASE)
    result = detect_anomalies(TEST_CASE)

    assert result["status"] == "no_data"
    assert result["findings"] == []


def test_detect_anomalies_brute_force():
    """Verify brute force detection from fixture data."""
    from tools.case_create import case_create
    from tools.detect_anomalies import detect_anomalies
    from config.settings import CASES_DIR

    case_create(TEST_CASE)
    logs_dir = CASES_DIR / TEST_CASE / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "sample_anomaly_logs.json", logs_dir / "anomaly_test.parsed.json")

    result = detect_anomalies(TEST_CASE)

    assert result["status"] == "ok"
    assert result["total_findings"] > 0

    # Should detect brute force (5 failed logins from 198.51.100.99)
    types = [f["type"] for f in result["findings"]]
    assert "brute_force" in types

    # Output file exists
    anomaly_path = CASES_DIR / TEST_CASE / "artefacts" / "anomalies" / "anomaly_report.json"
    assert anomaly_path.exists()


def test_detect_anomalies_temporal():
    """Verify off-hours login detection."""
    from tools.case_create import case_create
    from tools.detect_anomalies import detect_anomalies
    from config.settings import CASES_DIR

    case_create(TEST_CASE)
    logs_dir = CASES_DIR / TEST_CASE / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "sample_anomaly_logs.json", logs_dir / "anomaly_test.parsed.json")

    result = detect_anomalies(TEST_CASE)
    types = [f["type"] for f in result["findings"]]
    # jsmith login at 02:30 UTC is off-hours
    assert "temporal_anomaly" in types


def test_detect_anomalies_lateral_movement():
    """Verify lateral movement detection (3+ IPs for same user)."""
    from tools.case_create import case_create
    from tools.detect_anomalies import detect_anomalies
    from config.settings import CASES_DIR

    case_create(TEST_CASE)
    logs_dir = CASES_DIR / TEST_CASE / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "sample_anomaly_logs.json", logs_dir / "anomaly_test.parsed.json")

    result = detect_anomalies(TEST_CASE)
    types = [f["type"] for f in result["findings"]]
    # lateral_user logs in from 10.0.0.1, 10.0.0.2, 10.0.0.3
    assert "lateral_movement" in types


# ---------------------------------------------------------------------------
# AliasMap — client domain aliasing
# ---------------------------------------------------------------------------

def test_alias_root_with_suffix():
    """Root + suffix: heidelbergmaterials.com -> stonebridge-materials.com."""
    from tools.common import AliasMap

    m = AliasMap()
    m.register_root("heidelberg", "stonebridge")
    assert m.alias_text("heidelbergmaterials.com") == "stonebridge-materials.com"


def test_alias_root_bare():
    """Bare root match: heidelberg.de -> stonebridge.de."""
    from tools.common import AliasMap

    m = AliasMap()
    m.register_root("heidelberg", "stonebridge")
    assert m.alias_text("heidelberg.de") == "stonebridge.de"


def test_alias_root_multiple_suffixes():
    """Multiple suffixes derive correctly from same root."""
    from tools.common import AliasMap

    m = AliasMap()
    m.register_root("heidelberg", "stonebridge")
    text = "heidelbergmaterials.com and heidelbergcement.ru"
    aliased = m.alias_text(text)
    assert "stonebridge-materials.com" in aliased
    assert "stonebridge-cement.ru" in aliased
    assert "heidelberg" not in aliased


def test_alias_exact_name():
    """Exact name replacement: example-client.com -> riverton.com."""
    from tools.common import AliasMap

    m = AliasMap()
    m.register_name("example-client", "riverton")
    assert m.alias_text("example-client.com") == "riverton.com"


def test_alias_preserves_tld():
    """TLD is preserved across .bg, .ru, .com."""
    from tools.common import AliasMap

    m = AliasMap()
    m.register_root("heidelberg", "stonebridge")
    assert m.alias_text("heidelbergmaterials.bg") == "stonebridge-materials.bg"
    assert m.alias_text("heidelbergcement.ru") == "stonebridge-cement.ru"
    assert m.alias_text("heidelberg.com") == "stonebridge.com"


def test_alias_preserves_subdomain():
    """Subdomains are preserved: mail.X -> mail.Y."""
    from tools.common import AliasMap

    m = AliasMap()
    m.register_root("heidelberg", "stonebridge")
    m.register_name("example-client", "riverton")
    assert m.alias_text("mail.heidelbergmaterials.com") == "mail.stonebridge-materials.com"
    assert m.alias_text("opencti.example.com") == "cti.riverton.com"


def test_dealias_round_trip():
    """dealias(alias(text)) == text for roots + names."""
    from tools.common import AliasMap

    m = AliasMap()
    m.register_root("heidelberg", "stonebridge")
    m.register_name("example-client", "riverton")
    m.register_name("tcw", "ashfield")
    original = (
        "mail.heidelbergmaterials.com and heidelbergcement.ru "
        "and opencti.example.com and tcw.com"
    )
    aliased = m.alias_text(original)
    assert "heidelberg" not in aliased
    assert "example-client" not in aliased
    assert "tcw" not in aliased
    restored = m.dealias_text(aliased)
    assert restored == original


def test_attacker_domains_untouched():
    """Non-client domains pass through unmodified."""
    from tools.common import AliasMap

    m = AliasMap()
    m.register_root("heidelberg", "stonebridge")
    m.register_name("example-client", "riverton")
    text = "evil-domain.net and phish.ru and heidelbergmaterials.com"
    aliased = m.alias_text(text)
    assert "evil-domain.net" in aliased
    assert "phish.ru" in aliased
    assert "heidelberg" not in aliased


def test_alias_disabled_default():
    """get_alias_map() returns None when SOCAI_ALIAS is unset."""
    import os
    from importlib import reload
    import config.settings as settings_mod
    import tools.common as common_mod

    old_val = os.environ.get("SOCAI_ALIAS")
    os.environ.pop("SOCAI_ALIAS", None)
    try:
        reload(settings_mod)
        common_mod._alias_map_singleton = None
        reload(common_mod)
        assert common_mod.get_alias_map() is None
    finally:
        if old_val is not None:
            os.environ["SOCAI_ALIAS"] = old_val
        else:
            os.environ.pop("SOCAI_ALIAS", None)
        reload(settings_mod)
        reload(common_mod)


def test_alias_persistence(tmp_path):
    """save + reload produces identical map."""
    from tools.common import AliasMap
    from config.settings import ALIAS_MAP_FILE

    m = AliasMap()
    m.register_root("heidelberg", "stonebridge")
    m.register_name("example-client", "riverton")
    m.save()

    m2 = AliasMap()
    m2.load()
    assert m2._roots == m._roots
    assert m2._names == m._names
    assert m2.alias_text("heidelbergmaterials.com") == "stonebridge-materials.com"
    assert m2.alias_text("example-client.com") == "riverton.com"

    # Cleanup
    if ALIAS_MAP_FILE.exists():
        ALIAS_MAP_FILE.unlink()


def test_register_from_config_unified(tmp_path, monkeypatch):
    """register_from_config reads unified clients list, skips EDIT_ME."""
    import json
    from tools.common import AliasMap
    import tools.common as common_mod

    cfg = tmp_path / "client_entities.json"
    cfg.write_text(json.dumps({
        "clients": [
            {"name": "acme", "alias": "oakdale", "root": True},
            {"name": "partner", "alias": "riverside"},
            {"name": "placeholder", "alias": "EDIT_ME"},
            {"name": "empty", "alias": ""},
        ]
    }))
    monkeypatch.setattr(common_mod, "CLIENT_ENTITIES", cfg)

    m = AliasMap()
    m.register_from_config()

    # Root registered
    assert m.alias_text("acmecorp.com") == "oakdale-corp.com"
    # Exact name registered
    assert m.alias_text("partner.com") == "riverside.com"
    # EDIT_ME and empty skipped
    assert m.alias_text("placeholder.com") == "placeholder.com"
    assert m.alias_text("empty.com") == "empty.com"


# ---------------------------------------------------------------------------
# response_actions
# ---------------------------------------------------------------------------

def test_response_actions_with_playbook():
    """Generate response actions with a client playbook and malicious IOCs."""
    from tools.case_create import case_create
    from tools.response_actions import generate_response_actions
    from tools.common import save_json
    from config.settings import CASES_DIR, CLIENT_PLAYBOOKS_DIR

    case_create(TEST_CASE, title="Test alert", severity="high", client="test_client")

    # Write mock verdict_summary with malicious IOCs
    verdict_dir = CASES_DIR / TEST_CASE / "artefacts" / "enrichment"
    verdict_dir.mkdir(parents=True, exist_ok=True)
    save_json(verdict_dir / "verdict_summary.json", {
        "high_priority": ["evil-domain.com", "1.2.3.4"],
        "needs_review": ["suspect-site.com"],
        "clean": ["example.com"],
        "ioc_count": 4,
    })

    # Write a test playbook
    CLIENT_PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
    playbook_path = CLIENT_PLAYBOOKS_DIR / "test_client.json"
    try:
        save_json(playbook_path, {
            "client_name": "test_client",
            "response": [
                {
                    "priority": "none",
                    "alert_name": "none",
                    "action_to_be_taken": "Default process.",
                    "contact_process": "Email security@test.com"
                }
            ],
            "crown_jewels": {"hosts": [], "default_action": "Escalate"},
            "contacts": [{"name": "Test Contact", "role": "CISO"}],
            "escalation_matrix": [
                {
                    "priority": "p2",
                    "activity_blocked": False,
                    "asset_type": "workstation",
                    "sd_ticket": "immediate",
                    "phone_call": True,
                    "response_action": "asset_containment",
                    "actions": [
                        "Raise immediate SD ticket.",
                        "Asset containment — isolate endpoint via EDR."
                    ]
                },
                {
                    "priority": "p2",
                    "activity_blocked": False,
                    "asset_type": "server/privileged",
                    "sd_ticket": "immediate",
                    "phone_call": True,
                    "response_action": "confirm_asset_containment",
                    "actions": [
                        "Raise immediate SD ticket.",
                        "Confirm asset containment — obtain client approval."
                    ]
                }
            ],
            "containment_capabilities": [
                {"technology": "Defender XDR", "actions": ["MDE Isolate Hosts"]}
            ],
            "remediation_actions": [
                {"technology": "Defender XDR", "owner": "client", "actions": ["Entra Disable User"]}
            ]
        })

        result = generate_response_actions(TEST_CASE)

        assert result["status"] == "ok"
        assert result["priority"] == "p2"  # high severity maps to p2
        assert result["client"] == "test_client"
        assert len(result["malicious_iocs"]) == 2
        assert len(result["suspicious_iocs"]) == 1
        assert result["escalation"]["contact_process"] == "Email security@test.com"
        assert len(result["escalation"]["permitted_actions"]) >= 1

        # Output files exist
        out_dir = CASES_DIR / TEST_CASE / "artefacts" / "response_actions"
        assert (out_dir / "response_actions.json").exists()
        assert (out_dir / "response_actions.md").exists()
    finally:
        if playbook_path.exists():
            playbook_path.unlink()


def test_response_actions_skip_clean():
    """Clean verdict (0 malicious, 0 suspicious) should skip."""
    from tools.case_create import case_create
    from tools.response_actions import generate_response_actions
    from tools.common import save_json
    from config.settings import CASES_DIR, CLIENT_PLAYBOOKS_DIR

    case_create(TEST_CASE, severity="medium", client="test_client")

    # Write clean verdict
    verdict_dir = CASES_DIR / TEST_CASE / "artefacts" / "enrichment"
    verdict_dir.mkdir(parents=True, exist_ok=True)
    save_json(verdict_dir / "verdict_summary.json", {
        "high_priority": [],
        "needs_review": [],
        "clean": ["example.com"],
        "ioc_count": 1,
    })

    # Write a minimal playbook
    CLIENT_PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
    playbook_path = CLIENT_PLAYBOOKS_DIR / "test_client.json"
    try:
        save_json(playbook_path, {
            "client_name": "test_client",
            "response": [],
            "crown_jewels": {"hosts": [], "default_action": ""},
            "contacts": [],
            "escalation_matrix": []
        })

        result = generate_response_actions(TEST_CASE)
        assert result["status"] == "skipped"
        assert "No malicious/suspicious IOCs" in result["reason"]
    finally:
        if playbook_path.exists():
            playbook_path.unlink()


def test_response_actions_no_playbook():
    """No client field on case should skip with appropriate reason."""
    from tools.case_create import case_create
    from tools.response_actions import generate_response_actions

    case_create(TEST_CASE, severity="medium")

    result = generate_response_actions(TEST_CASE)
    assert result["status"] == "skipped"
    assert "playbook" in result["reason"].lower() or "client" in result["reason"].lower()
