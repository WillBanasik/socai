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

2026-06-05 batch (P2-5 blank dispositions):
  - index_case enforces the close invariant: a closed case with no disposition
    is floored to canonical "inconclusive".
  - save_report: mdr_report defaults to true_positive; closure_comment requires
    an explicit disposition (no silent blank close).
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


# ---------------------------------------------------------------------------
# 2026-06-05 batch (P2-5 blank dispositions)
# ---------------------------------------------------------------------------

import json as _json
import shutil as _shutil


def _scratch_case(case_id, meta):
    """Write a throwaway case_meta and return a (case_dir, cleanup) pair.
    conftest isolates the log paths but NOT cases/ or the registry, so the
    caller must clean up via try/finally."""
    from config.settings import CASES_DIR, REGISTRY_FILE
    from tools.common import save_json
    case_dir = CASES_DIR / case_id

    def _cleanup():
        if case_dir.exists():
            _shutil.rmtree(case_dir)
        if REGISTRY_FILE.exists():
            data = _json.loads(REGISTRY_FILE.read_text())
            data.get("cases", {}).pop(case_id, None)
            REGISTRY_FILE.write_text(_json.dumps(data, indent=2))

    _cleanup()
    save_json(case_dir / "case_meta.json", {"case_id": case_id, **meta})
    return case_dir, _cleanup


def test_index_case_floors_blank_disposition_on_close():
    from tools.common import utcnow
    from tools.index_case import index_case, CANONICAL_DISPOSITIONS
    case_dir, _cleanup = _scratch_case(
        "IV_CASE_FRICTION_DISP",
        {"title": "disp floor", "status": "active", "created_at": utcnow()},
    )
    try:
        # Close with NO disposition → floored to a canonical "inconclusive".
        meta = index_case("IV_CASE_FRICTION_DISP", status="closed")
        assert meta["disposition"] == "inconclusive"
        assert meta["disposition"] in CANONICAL_DISPOSITIONS
    finally:
        _cleanup()


def test_index_case_preserves_explicit_disposition():
    from tools.common import utcnow
    from tools.index_case import index_case
    case_dir, _cleanup = _scratch_case(
        "IV_CASE_FRICTION_DISP2",
        {"title": "disp explicit", "status": "active", "created_at": utcnow()},
    )
    try:
        meta = index_case("IV_CASE_FRICTION_DISP2", status="closed",
                          disposition="true_positive")
        assert meta["disposition"] == "true_positive"
    finally:
        _cleanup()


def test_mdr_report_defaults_to_true_positive():
    from tools.save_report import _REPORT_TYPES
    assert _REPORT_TYPES["mdr_report"]["disposition"] == "true_positive"


def test_mdr_report_requires_evidence_and_findings():
    # Analytical-Standards rule-9 gate: evidence-bearing deliverables refuse
    # to save when the case has no add_evidence/add_finding record.
    from tools.common import utcnow
    from tools.save_report import save_report_to_case
    case_id = "IV_CASE_FRICTION_RULE9"
    case_dir, _cleanup = _scratch_case(
        case_id,
        {"title": "rule9 gate", "status": "active", "created_at": utcnow()},
    )
    try:
        r = save_report_to_case(case_id, "mdr_report", "## MDR\n\nBody.")
        assert r["status"] == "error"
        assert "rule 9" in r["reason"]
        meta = _json.loads((case_dir / "case_meta.json").read_text())
        assert meta["status"] != "closed"

        # Backfilling the chain unblocks the save.
        notes_dir = case_dir / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        (notes_dir / "analyst_input.md").write_text(
            "KQL hit: 1 row\n\n---\n\n**Finding (verdict):** TP, backed above\n"
        )
        r2 = save_report_to_case(case_id, "mdr_report", "## MDR\n\nBody.")
        assert r2["status"] == "ok"
    finally:
        _cleanup()


def test_closure_comment_requires_disposition():
    from tools.common import utcnow
    from tools.save_report import save_report_to_case
    case_id = "IV_CASE_FRICTION_CLOSURE"
    case_dir, _cleanup = _scratch_case(
        case_id,
        {"title": "closure require", "status": "active", "created_at": utcnow()},
    )
    try:
        # No disposition + none already on the case → must error, not close blank.
        r = save_report_to_case(case_id, "closure_comment",
                                "BP: expected admin activity.", disposition=None)
        assert r["status"] == "error"
        assert "disposition" in r["reason"].lower()
        meta = _json.loads((case_dir / "case_meta.json").read_text())
        assert meta["status"] != "closed"
    finally:
        _cleanup()


def test_evidence_finding_counts():
    # Shared counter behind the rule-9 gate and the prepare_* early warning.
    from tools.common import utcnow
    from tools.save_report import evidence_finding_counts
    case_id = "IV_CASE_FRICTION_R9COUNTS"
    case_dir, _cleanup = _scratch_case(
        case_id,
        {"title": "r9 counts", "status": "active", "created_at": utcnow()},
    )
    try:
        assert evidence_finding_counts(case_id) == (0, 0)

        notes_dir = case_dir / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        (notes_dir / "analyst_input.md").write_text(
            "KQL hit: 1 row\n\n---\n\nEnrichment verdict: malicious"
            "\n\n---\n\n**Finding (verdict):** TP, backed above\n"
        )
        assert evidence_finding_counts(case_id) == (2, 1)
    finally:
        _cleanup()


def test_prepare_rule9_readiness_warns_then_clears():
    # The prepare_* payload surfaces a missing evidence/finding chain BEFORE
    # the report is written; the warning clears once the chain is backfilled.
    from tools.common import utcnow
    from mcp_server.tools import _rule9_readiness
    case_id = "IV_CASE_FRICTION_R9PREP"
    case_dir, _cleanup = _scratch_case(
        case_id,
        {"title": "r9 prep", "status": "active", "created_at": utcnow()},
    )
    try:
        out = _rule9_readiness(case_id)
        assert out["evidence_entries"] == 0
        assert out["finding_entries"] == 0
        assert "rule 9" in out["rule9_warning"]

        notes_dir = case_dir / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        (notes_dir / "analyst_input.md").write_text(
            "KQL hit: 1 row\n\n---\n\n**Finding (verdict):** TP, backed above\n"
        )
        out2 = _rule9_readiness(case_id)
        assert out2 == {"evidence_entries": 1, "finding_entries": 1}
    finally:
        _cleanup()


def test_save_report_returns_quality_warnings():
    # Non-blocking analytical-standards prose check at save time: causal and
    # speculative language is flagged in the manifest, never refused.
    from tools.common import utcnow
    from tools.save_report import save_report_to_case
    case_id = "IV_CASE_FRICTION_QWARN"
    case_dir, _cleanup = _scratch_case(
        case_id,
        {"title": "quality warnings", "status": "active", "created_at": utcnow()},
    )
    try:
        notes_dir = case_dir / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        (notes_dir / "analyst_input.md").write_text(
            "KQL hit: 1 row\n\n---\n\n**Finding (verdict):** TP, backed above\n"
        )
        r = save_report_to_case(
            case_id, "mdr_report",
            "## MDR\n\nThe phishing email likely led to execution on the host.",
        )
        assert r["status"] == "ok"
        assert r["quality_warning_count"] >= 2  # 'likely' + 'led to'
        rules = {f["rule"] for f in r["quality_warnings"]}
        assert "speculative_language" in rules
        assert "causal_claim" in rules

        # Clean text produces no flags — and still saves.
        r2 = save_report_to_case(
            case_id, "mdr_report",
            "## MDR\n\nConfirmed: hash 4f2a matched 62/70 VT engines.",
        )
        assert r2["status"] == "ok"
        assert r2["quality_warnings"] == []
        assert r2["quality_warning_count"] == 0
    finally:
        _cleanup()
