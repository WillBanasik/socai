"""Regression tests for the import_enrichment → update_ioc_index round-trip.

Covers two bugs:

  1. KeyError: 'malicious' in update_ioc_index when import_enrichment writes
     a slim verdict_summary.json missing the malicious/suspicious/clean/unknown
     count keys. Triggered on every create_case(enrichment_id=...) call where
     qe_verdicts is truthy.

  2. quick_enrich's verdict aggregator dropping infra_clean IPs (ASN
     pre-screen matches) because the asn_prescreen result has
     status="infra_clean" rather than status="ok". Per-IOC verdict surfaced
     as "unknown" with providers_checked=0 despite the tier-0 evidence.
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_CASE = "IV_CASE_000"
TEST_ENRICHMENT_ID = "QE_TEST_000000_000000"


@pytest.fixture(autouse=True)
def cleanup_test_state(monkeypatch, tmp_path):
    """Remove the test case and isolate the IOC index to a tmp path."""
    from config.settings import CASES_DIR, REGISTRY_FILE, QUICK_ENRICH_DIR
    import tools.score_verdicts as sv

    def _rm():
        case_dir = CASES_DIR / TEST_CASE
        if case_dir.exists():
            shutil.rmtree(case_dir)
        qe_path = QUICK_ENRICH_DIR / f"{TEST_ENRICHMENT_ID}.json"
        if qe_path.exists():
            qe_path.unlink()
        if REGISTRY_FILE.exists():
            data = json.loads(REGISTRY_FILE.read_text())
            data.get("cases", {}).pop(TEST_CASE, None)
            REGISTRY_FILE.write_text(json.dumps(data, indent=2))

    isolated_index = tmp_path / "ioc_index.json"
    monkeypatch.setattr(sv, "IOC_INDEX_FILE", isolated_index)

    _rm()
    yield
    _rm()


def _write_quick_enrich(verdicts: dict, depth: str = "auto") -> str:
    """Persist a fake quick_enrich output for import_enrichment to consume."""
    from config.settings import QUICK_ENRICH_DIR
    from tools.common import save_json

    QUICK_ENRICH_DIR.mkdir(parents=True, exist_ok=True)
    qe_path = QUICK_ENRICH_DIR / f"{TEST_ENRICHMENT_ID}.json"
    save_json(qe_path, {
        "enrichment_id": TEST_ENRICHMENT_ID,
        "depth": depth,
        "ioc_count": len(verdicts),
        "provider_calls": 0,
        "cache_hits": 0,
        "tiered_stats": {},
        "results": [],
        "verdicts": verdicts,
    })
    return TEST_ENRICHMENT_ID


def _make_verdict(ioc, ioc_type, verdict, providers=None, confidence="LOW"):
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "verdict": verdict,
        "confidence": confidence,
        "providers_checked": len(providers or {}),
        "provider_verdicts": providers or {},
    }


# ---------------------------------------------------------------------------
# Primary bug: import_enrichment → update_ioc_index must not KeyError
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario, verdicts", [
    ("all_unknown", {
        "1.2.3.4": _make_verdict("1.2.3.4", "ipv4", "unknown"),
        "evil.example": _make_verdict("evil.example", "domain", "unknown"),
    }),
    ("all_clean", {
        "1.2.3.4": _make_verdict("1.2.3.4", "ipv4", "clean",
                                  {"abuseipdb": "clean"}),
        "good.example": _make_verdict("good.example", "domain", "clean",
                                       {"whoisxml": "clean"}),
    }),
    ("clean_plus_unknown", {
        "deadbeef" * 8: _make_verdict("deadbeef" * 8, "sha256", "clean",
                                       {"otx": "clean"}),
        "user@example.com": _make_verdict("user@example.com", "email", "unknown"),
        "1.2.3.4": _make_verdict("1.2.3.4", "ipv4", "unknown"),
    }),
    ("clean_plus_malicious", {
        "1.2.3.4": _make_verdict("1.2.3.4", "ipv4", "clean",
                                  {"abuseipdb": "clean"}),
        "evil.example": _make_verdict("evil.example", "domain", "malicious",
                                       {"otx": "malicious", "vt": "malicious"}),
    }),
    ("all_four_verdicts", {
        "1.1.1.1": _make_verdict("1.1.1.1", "ipv4", "malicious",
                                  {"abuseipdb": "malicious"}),
        "2.2.2.2": _make_verdict("2.2.2.2", "ipv4", "suspicious",
                                  {"abuseipdb": "suspicious"}),
        "3.3.3.3": _make_verdict("3.3.3.3", "ipv4", "clean",
                                  {"abuseipdb": "clean"}),
        "4.4.4.4": _make_verdict("4.4.4.4", "ipv4", "unknown"),
    }),
])
def test_import_enrichment_round_trip(scenario, verdicts):
    """Round-trip every verdict mix without raising KeyError."""
    from tools.case_create import case_create
    from tools.enrich import import_enrichment
    from config.settings import CASES_DIR

    case_create(TEST_CASE, title=f"import test {scenario}", severity="low")
    enrichment_id = _write_quick_enrich(verdicts)

    result = import_enrichment(enrichment_id, TEST_CASE)

    assert "error" not in result, f"{scenario}: {result.get('error')}"
    assert result["status"] == "imported"
    assert result["enrichment_id"] == enrichment_id

    # verdict_summary.json must be readable and have the canonical shape
    verdict_path = CASES_DIR / TEST_CASE / "artefacts" / "enrichment" / "verdict_summary.json"
    assert verdict_path.exists()
    vs = json.loads(verdict_path.read_text())
    for ioc, score in vs["iocs"].items():
        for key in ("malicious", "suspicious", "clean", "unknown", "total_providers"):
            assert key in score, f"{scenario}: {ioc} missing key {key}"


def test_import_enrichment_empty_verdicts():
    """Empty verdicts dict should not crash — falls through to score_verdicts."""
    from tools.case_create import case_create
    from tools.enrich import import_enrichment

    case_create(TEST_CASE, title="import test empty", severity="low")
    enrichment_id = _write_quick_enrich({})

    result = import_enrichment(enrichment_id, TEST_CASE)
    # No verdicts → score_verdicts fallback path; no KeyError either way
    assert "error" not in result or "enrichment.json not found" in result.get("error", "")


def test_import_enrichment_ioc_index_aggregates_counts():
    """update_ioc_index must record per-verdict counts correctly."""
    from tools.case_create import case_create
    from tools.enrich import import_enrichment
    import tools.score_verdicts as sv

    case_create(TEST_CASE, title="ioc index counts", severity="low")
    verdicts = {
        "evil.example": _make_verdict(
            "evil.example", "domain", "malicious",
            {"otx": "malicious", "vt": "malicious", "urlhaus": "clean"},
        ),
    }
    enrichment_id = _write_quick_enrich(verdicts)
    import_enrichment(enrichment_id, TEST_CASE)

    index = json.loads(sv.IOC_INDEX_FILE.read_text())
    entry = index["evil.example"]
    assert entry["verdict"] == "malicious"
    assert entry["malicious"] == 2
    assert entry["clean"] == 1
    assert entry["suspicious"] == 0
    assert TEST_CASE in entry["cases"]


# ---------------------------------------------------------------------------
# Secondary bug: quick_enrich must surface infra_clean as a first-class verdict
# ---------------------------------------------------------------------------

def test_quick_enrich_surfaces_infra_clean_verdict(monkeypatch):
    """ASN pre-screen matches must produce verdict=infra_clean (not unknown)."""
    import tools.enrich as enr

    # Canned ASN data for a fake IP — _classify_ip_infra normally checks the
    # ASN owner string against a known list; stub it to flag this one as infra.
    fake_ip = "8.8.8.8"
    monkeypatch.setattr(enr, "_asn_lookup_bulk", lambda ips: {
        fake_ip: {"asn": "AS14618", "owner": "Amazon SES", "prefix": "8.8.8.0/24"},
    })
    monkeypatch.setattr(enr, "_classify_ip_infra", lambda ip, info: "aws_ses")

    # Stub provider calls so we don't hit the network for tier 1/2 work on
    # other IOCs in a hypothetical batch — here there's only one IP, and once
    # it lands in infra_ips it's removed from by_type so providers see nothing.
    monkeypatch.setattr(enr, "_run_tasks_parallel", lambda *a, **k: [])

    out = enr.quick_enrich([fake_ip], depth="auto")

    v = out["verdicts"][fake_ip]
    assert v["verdict"] == "infra_clean"
    assert v["providers_checked"] >= 1
    assert v["provider_verdicts"] == {"asn_prescreen": "infra_clean"}
    assert v.get("owner") == "aws_ses"


def test_quick_enrich_infra_clean_import_preserves_verdict(monkeypatch):
    """End-to-end: infra_clean IP from quick_enrich imports cleanly into a case."""
    from tools.case_create import case_create
    from tools.enrich import import_enrichment
    import tools.enrich as enr

    fake_ip = "9.9.9.9"
    monkeypatch.setattr(enr, "_asn_lookup_bulk", lambda ips: {
        fake_ip: {"asn": "AS14618", "owner": "Amazon SES", "prefix": "8.8.8.0/24"},
    })
    monkeypatch.setattr(enr, "_classify_ip_infra", lambda ip, info: "aws_ses")
    monkeypatch.setattr(enr, "_run_tasks_parallel", lambda *a, **k: [])

    qe_out = enr.quick_enrich([fake_ip], depth="auto")
    enrichment_id = qe_out["enrichment_id"]

    try:
        case_create(TEST_CASE, title="infra_clean import", severity="low")
        result = import_enrichment(enrichment_id, TEST_CASE)
        assert "error" not in result
        # infra_clean counts toward the clean bucket in import_enrichment
        assert result["clean"] >= 1
    finally:
        from config.settings import QUICK_ENRICH_DIR
        qe_path = QUICK_ENRICH_DIR / f"{enrichment_id}.json"
        if qe_path.exists():
            qe_path.unlink()
