"""Regression tests for the 2026-06-04 investigate→friction→fix loop fixes.

Covers three tooling fixes surfaced by running real investigations:
  - campaign_cluster: Microsoft 365 SaaS domains must be clustering noise
    (sharepointonline.com was anchoring a bogus cross-case campaign).
  - score_verdicts: ubiquitous-benign domains are forced clean so a single
    mis-flagging provider can't propagate "malicious" into the IOC index.
  - enrich: the OpenCTI provider must skip cleanly when OPENCTI_URL is unset
    (otherwise it POSTs to a scheme-less "/graphql" on every IOC).
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
