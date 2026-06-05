"""Regression tests for the investigate→friction→fix loop fixes.

2026-06-04 batch (P0/P1):
  - campaign_cluster: Microsoft 365 SaaS domains must be clustering noise
    (sharepointonline.com was anchoring a bogus cross-case campaign).
  - score_verdicts: ubiquitous-benign domains are forced clean so a single
    mis-flagging provider can't propagate "malicious" into the IOC index.
  - enrich: the OpenCTI provider must skip cleanly when OPENCTI_URL is unset
    (otherwise it POSTs to a scheme-less "/graphql" on every IOC).

2026-06-05 batch (P2/P3 quick wins):
  - enrich: client-owned domains (the case client's known_infrastructure) are
    skipped from enrichment, like the global known-clean set.
  - save_report: fp_tuning_ticket no longer hard-codes a false_positive
    disposition (it overrode Benign-Positive determinations on the BP+tuning path).
  - index_case: the registry entry retains client/tags/attack_type on re-index.
"""

import tools.enrich as enrich
from tools.campaign_cluster import _is_noise_ioc
from tools.score_verdicts import _is_force_clean, _composite_verdict


def test_microsoft_saas_domains_are_campaign_noise():
    for d in ("sharepointonline.com", "sharepoint.com", "microsoftonline.com",
              "aztecfseu.sharepoint.com"):
        assert _is_noise_ioc(d) is True, d
    # A genuine throwaway phishing domain must still be eligible to cluster.
    assert _is_noise_ioc("swift-track.info") is False


def test_ubiquitous_benign_domains_forced_clean():
    assert _is_force_clean("sharepointonline.com", "domain") is True
    assert _is_force_clean("login.microsoftonline.com", "domain") is True
    assert _is_force_clean("evil-phish.info", "domain") is False
    # Only applies to domains — never short-circuit IPs/hashes.
    assert _is_force_clean("8.8.8.8", "ipv4") is False


def test_composite_verdict_unchanged_for_real_iocs():
    # The force-clean override lives in score_verdicts(), NOT _composite_verdict;
    # the underlying "one credible malicious hit matters" rule must be intact.
    v, _ = _composite_verdict({"vt": "malicious", "a": "clean", "b": "clean", "c": "clean"})
    assert v == "malicious"


def test_opencti_skips_cleanly_without_url(monkeypatch):
    monkeypatch.setattr(enrich, "OPENCTI_KEY", "dummy")
    monkeypatch.setattr(enrich, "OPENCTI_URL", "")
    r = enrich._opencti_lookup("1.2.3.4", "ipv4")
    assert r["status"] == "not_configured"


# ---------------------------------------------------------------------------
# 2026-06-05 batch (P2/P3 quick wins)
# ---------------------------------------------------------------------------

def test_is_known_clean_skips_client_infrastructure():
    from tools.enrich import _is_known_clean
    infra = frozenset({"cellc.co.za", "essentra.com"})
    # Without the client-infra set, a client-owned domain is NOT skipped (the
    # pre-fix behaviour — client domains got enriched as if they were IOCs).
    assert _is_known_clean("contractor.cellc.co.za", "domain") is False
    # With it, the domain and its subdomains are treated as known-clean.
    assert _is_known_clean("cellc.co.za", "domain", infra) is True
    assert _is_known_clean("contractor.cellc.co.za", "domain", infra) is True
    assert _is_known_clean("https://portal.essentra.com/login", "url", infra) is True
    # A genuine external domain is still enriched even with the set present.
    assert _is_known_clean("swift-track.info", "domain", infra) is False
    # The global known-clean list still applies regardless of the extra set.
    assert _is_known_clean("login.microsoftonline.com", "domain") is True


def test_client_infra_domains_resolution(monkeypatch):
    monkeypatch.setattr(enrich, "get_client_config", lambda name: {
        "name": name,
        "known_infrastructure": ["cellc.co.za", "portal.example.com",
                                 "148.197.0.0/16"],
    })
    got = enrich._client_infra_domains({"client": "cell_c"})
    assert "cellc.co.za" in got
    assert "portal.example.com" in got
    # CIDR entries are excluded — this set is consulted for domain/url IOCs only.
    assert "148.197.0.0/16" not in got
    # Missing meta / missing client must never raise — return an empty set.
    assert enrich._client_infra_domains(None) == frozenset()
    assert enrich._client_infra_domains({}) == frozenset()
    # Unknown client (config lookup returns None) → empty set.
    monkeypatch.setattr(enrich, "get_client_config", lambda name: None)
    assert enrich._client_infra_domains({"client": "nope"}) == frozenset()


def test_fp_tuning_ticket_does_not_force_false_positive():
    # Regression: saving an fp_tuning_ticket with no disposition arg auto-closed
    # the case as false_positive, overriding a Benign-Positive determination.
    from tools.save_report import _REPORT_TYPES
    assert _REPORT_TYPES["fp_tuning_ticket"]["disposition"] is None


def test_index_case_registry_retains_client_and_tags():
    # Regression: index_case() dropped client/tags/attack_type from the registry
    # entry on re-index, so list_cases showed no client for ~92% of cases.
    import json as _json
    import shutil
    from config.settings import CASES_DIR, REGISTRY_FILE
    from tools.common import save_json, utcnow
    from tools.index_case import index_case

    case_id = "IV_CASE_FRICTION_IDX"
    case_dir = CASES_DIR / case_id

    def _cleanup():
        if case_dir.exists():
            shutil.rmtree(case_dir)
        if REGISTRY_FILE.exists():
            data = _json.loads(REGISTRY_FILE.read_text())
            data.get("cases", {}).pop(case_id, None)
            REGISTRY_FILE.write_text(_json.dumps(data, indent=2))

    _cleanup()
    try:
        save_json(case_dir / "case_meta.json", {
            "case_id": case_id,
            "title": "Friction idx test",
            "client": "essentra",
            "tags": ["phishing", "bp"],
            "attack_type": "phishing",
            "severity": "low",
            "status": "triage",
            "created_at": utcnow(),
        })
        index_case(case_id)  # no status → no metric / no case-memory upsert
        entry = _json.loads(REGISTRY_FILE.read_text())["cases"][case_id]
        assert entry["client"] == "essentra"
        assert entry["tags"] == ["phishing", "bp"]
        assert entry["attack_type"] == "phishing"
    finally:
        _cleanup()
