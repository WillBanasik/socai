"""
Tests for the Rumsfeld investigation pipeline components:
  - investigation_matrix (generate, load, update, summary)
  - report_quality_gate (deterministic checks)
  - determination (compare_dispositions)
  - enrichment director (_apply_llm_escalation with director disabled)
  - RumsfeldAgent (gap analysis, proposals)

Run with:  cd socai && python -m pytest tests/test_rumsfeld.py -v

Note: LLM-dependent functions return None when ANTHROPIC_API_KEY is unset.
      Tests focus on deterministic logic, schema validation, and graceful
      degradation.
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

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
        if REGISTRY_FILE.exists():
            data = json.loads(REGISTRY_FILE.read_text())
            data.get("cases", {}).pop(TEST_CASE, None)
            REGISTRY_FILE.write_text(json.dumps(data, indent=2))

    _rm()
    yield
    _rm()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_case_with_artefacts():
    """Create a test case with IOCs and enrichment artefacts."""
    from config.settings import CASES_DIR
    from tools.case_create import case_create

    case_create(TEST_CASE, title="Test phishing case", severity="high")

    # Write IOCs
    iocs_dir = CASES_DIR / TEST_CASE / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)
    iocs_data = {
        "case_id": TEST_CASE,
        "iocs": {
            "ipv4": ["1.2.3.4", "5.6.7.8"],
            "domain": ["evil-phish.com"],
            "url": ["https://evil-phish.com/login"],
        },
    }
    (iocs_dir / "iocs.json").write_text(json.dumps(iocs_data, indent=2))

    # Write enrichment
    enrich_dir = CASES_DIR / TEST_CASE / "artefacts" / "enrichment"
    enrich_dir.mkdir(parents=True, exist_ok=True)
    enrichment = {
        "case_id": TEST_CASE,
        "results": [
            {"ioc": "1.2.3.4", "provider": "abuseipdb", "verdict": "malicious",
             "status": "ok", "total_reports": 15, "ioc_type": "ipv4"},
            {"ioc": "evil-phish.com", "provider": "urlhaus", "verdict": "malicious",
             "status": "ok", "malware": "phishing", "ioc_type": "domain"},
            {"ioc": "5.6.7.8", "provider": "abuseipdb", "verdict": "clean",
             "status": "ok", "total_reports": 0, "ioc_type": "ipv4"},
        ],
    }
    (enrich_dir / "enrichment.json").write_text(json.dumps(enrichment, indent=2))

    # Write verdicts
    verdicts = {
        "high_priority": [
            {"ioc": "1.2.3.4", "verdict": "malicious", "confidence": "high", "providers_checked": 3},
            {"ioc": "evil-phish.com", "verdict": "malicious", "confidence": "high", "providers_checked": 2},
        ],
        "needs_review": [],
        "clean": [
            {"ioc": "5.6.7.8", "verdict": "clean", "confidence": "medium", "providers_checked": 3},
        ],
        "unknown": [],
    }
    (enrich_dir / "verdict_summary.json").write_text(json.dumps(verdicts, indent=2))

    # Update metadata with attack type
    meta_path = CASES_DIR / TEST_CASE / "case_meta.json"
    meta = json.loads(meta_path.read_text())
    meta["attack_type"] = "phishing"
    meta["attack_type_confidence"] = "high"
    meta_path.write_text(json.dumps(meta, indent=2))

    return CASES_DIR / TEST_CASE


# ---------------------------------------------------------------------------
# investigation_matrix
# ---------------------------------------------------------------------------

def test_matrix_build_matrix():
    """Test _build_matrix normalisation."""
    from tools.investigation_matrix import _build_matrix

    parsed = {
        "known_knowns": [
            {"finding": "Email delivered", "evidence": "EML headers", "source_step": "email_analyse"},
        ],
        "known_unknowns": [
            {"question": "Did user click?", "required_evidence": "Proxy logs"},
        ],
        "hypotheses": [
            {"claim": "Credential harvesting", "supporting": ["Login form present"]},
        ],
    }

    matrix = _build_matrix(TEST_CASE, "phishing", parsed)

    assert matrix["version"] == 1
    assert matrix["case_id"] == TEST_CASE
    assert matrix["attack_type"] == "phishing"
    assert len(matrix["known_knowns"]) == 1
    assert matrix["known_knowns"][0]["id"] == "kk_001"
    assert matrix["known_knowns"][0]["confidence"] == "confirmed"
    assert len(matrix["known_unknowns"]) == 1
    assert matrix["known_unknowns"][0]["id"] == "ku_001"
    assert matrix["known_unknowns"][0]["resolution"] is None
    assert len(matrix["hypotheses"]) == 1
    assert matrix["hypotheses"][0]["id"] == "h_001"
    assert matrix["hypotheses"][0]["status"] == "unresolved"
    assert len(matrix["history"]) == 1


def test_matrix_load_nonexistent():
    """load_matrix returns None for nonexistent case."""
    from tools.investigation_matrix import load_matrix
    assert load_matrix("NONEXISTENT_CASE") is None


def test_matrix_update():
    """Test update_matrix merges findings correctly."""
    from config.settings import CASES_DIR
    from tools.investigation_matrix import _build_matrix, update_matrix
    from tools.common import save_json

    _create_case_with_artefacts()

    # Write an initial matrix
    initial = _build_matrix(TEST_CASE, "phishing", {
        "known_knowns": [{"finding": "Email delivered", "evidence": "EML headers"}],
        "known_unknowns": [{"question": "Did user click?"}],
        "hypotheses": [],
    })
    analysis_dir = CASES_DIR / TEST_CASE / "artefacts" / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    save_json(analysis_dir / "investigation_matrix.json", initial)

    # Update: resolve a known unknown
    updated = update_matrix(TEST_CASE, "log_correlate", {
        "resolve_unknowns": ["ku_001"],
    })

    assert updated is not None
    ku = updated["known_unknowns"][0]
    assert ku["resolution"] is not None
    assert ku["resolution"]["resolved_by"] == "log_correlate"
    assert len(updated["history"]) == 2


def test_matrix_summary():
    """Test get_matrix_summary returns compact format."""
    from config.settings import CASES_DIR
    from tools.investigation_matrix import _build_matrix, get_matrix_summary
    from tools.common import save_json

    _create_case_with_artefacts()

    matrix = _build_matrix(TEST_CASE, "phishing", {
        "known_knowns": [{"finding": "F1"}, {"finding": "F2"}],
        "known_unknowns": [{"question": "Q1"}],
        "hypotheses": [{"claim": "H1"}],
    })
    analysis_dir = CASES_DIR / TEST_CASE / "artefacts" / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    save_json(analysis_dir / "investigation_matrix.json", matrix)

    summary = get_matrix_summary(TEST_CASE)
    assert summary is not None
    assert summary["known_knowns"] == 2
    assert "0/1" in summary["known_unknowns"]
    assert "0/1" in summary["hypotheses"]


def test_matrix_generate_no_api_key(monkeypatch):
    """generate_matrix returns None gracefully when no API key."""
    monkeypatch.setattr("tools.investigation_matrix.ANTHROPIC_KEY", "")
    _create_case_with_artefacts()

    from tools.investigation_matrix import generate_matrix
    result = generate_matrix(TEST_CASE)
    assert result is None


# ---------------------------------------------------------------------------
# report_quality_gate
# ---------------------------------------------------------------------------

def test_quality_gate_confirmed_without_evidence():
    """Flag 'confirmed' claims not backed by matrix."""
    from tools.report_quality_gate import _check_confirmed_claims

    report = "The credential harvesting was confirmed during the investigation."
    matrix = {
        "known_knowns": [
            {"finding": "Email delivered to user", "confidence": "confirmed"},
        ],
    }

    flags = _check_confirmed_claims(report, matrix)
    assert len(flags) >= 1
    assert flags[0]["rule"] == "confirmed_without_evidence"


def test_quality_gate_causal_language():
    """Flag causal claims."""
    from tools.report_quality_gate import _check_causal_language

    report = "The phishing email led to the user downloading malware."
    flags = _check_causal_language(report)
    assert len(flags) >= 1
    assert flags[0]["rule"] == "causal_claim"


def test_quality_gate_speculation():
    """Flag speculative language."""
    from tools.report_quality_gate import _check_speculation

    report = "The attacker likely used a credential harvesting kit."
    flags = _check_speculation(report)
    assert len(flags) >= 1
    assert flags[0]["rule"] == "speculative_language"


def test_quality_gate_matrix_coverage():
    """Test coverage checking against matrix."""
    from tools.report_quality_gate import _check_matrix_coverage

    matrix = {
        "known_knowns": [
            {"id": "kk_001", "finding": "Email delivered to analyst user"},
            {"id": "kk_002", "finding": "Domain registered two days before incident"},
        ],
        "known_unknowns": [
            {"id": "ku_001", "question": "Did the user submit credentials on the form"},
        ],
    }

    report = "The email was delivered to the analyst user. The domain was registered two days before the incident."
    coverage = _check_matrix_coverage(report, matrix)
    assert coverage["known_knowns_addressed"] == 2
    assert coverage["known_knowns_total"] == 2


def test_quality_gate_no_matrix():
    """Coverage check returns zeros when no matrix."""
    from tools.report_quality_gate import _check_matrix_coverage

    coverage = _check_matrix_coverage("Some report text", None)
    assert coverage["known_knowns_total"] == 0


def test_quality_gate_review_no_report():
    """review_report returns None when no report exists."""
    from tools.case_create import case_create
    from tools.report_quality_gate import review_report

    case_create(TEST_CASE)
    result = review_report(TEST_CASE)
    assert result is None


# ---------------------------------------------------------------------------
# determination
# ---------------------------------------------------------------------------

def test_compare_dispositions_agree():
    """Compatible dispositions should agree."""
    from tools.determination import compare_dispositions

    result = compare_dispositions("benign_auto_closed", {
        "disposition": "benign", "confidence": "high",
    })
    assert result["agrees"] is True
    assert result["recommendation"] == "proceed"


def test_compare_dispositions_disagree_high():
    """High-confidence disagreement should flag for review."""
    from tools.determination import compare_dispositions

    result = compare_dispositions("benign_auto_closed", {
        "disposition": "true_positive", "confidence": "high",
    })
    assert result["agrees"] is False
    assert result["recommendation"] == "flag_for_review"


def test_compare_dispositions_disagree_low():
    """Low-confidence disagreement should log but not block."""
    from tools.determination import compare_dispositions

    result = compare_dispositions("benign_auto_closed", {
        "disposition": "true_positive", "confidence": "low",
    })
    assert result["agrees"] is False
    assert result["recommendation"] == "log_disagreement"


def test_compare_dispositions_inconclusive():
    """Inconclusive LLM is compatible with anything."""
    from tools.determination import compare_dispositions

    result = compare_dispositions("benign_auto_closed", {
        "disposition": "inconclusive", "confidence": "low",
    })
    assert result["agrees"] is True


def test_compare_dispositions_no_deterministic():
    """No deterministic disposition should always agree."""
    from tools.determination import compare_dispositions

    result = compare_dispositions(None, {
        "disposition": "true_positive", "confidence": "high",
    })
    assert result["agrees"] is True


def test_compare_fp_benign_compatible():
    """false_positive and benign are compatible."""
    from tools.determination import compare_dispositions

    result = compare_dispositions("false_positive", {
        "disposition": "benign", "confidence": "high",
    })
    assert result["agrees"] is True


def test_determination_no_api_key(monkeypatch):
    """llm_determine returns None gracefully when no API key."""
    monkeypatch.setattr("tools.determination.ANTHROPIC_KEY", "")
    _create_case_with_artefacts()

    from tools.determination import llm_determine
    result = llm_determine(TEST_CASE)
    assert result is None


# ---------------------------------------------------------------------------
# enrichment director
# ---------------------------------------------------------------------------

def test_enrich_director_disabled_by_default():
    """LLM enrichment director is a no-op when SOCAI_ENRICH_DIRECTOR != '1'."""
    from tools.enrich import _llm_enrichment_review

    result = _llm_enrichment_review(
        TEST_CASE,
        [{"ioc": "1.2.3.4", "verdict": "clean", "status": "ok", "ioc_type": "ipv4"}],
        "ipv4",
        ["1.2.3.4"],
    )
    assert result == {}


def test_apply_llm_escalation_noop():
    """_apply_llm_escalation returns unmodified list when director disabled."""
    from tools.enrich import _apply_llm_escalation

    original = ["1.2.3.4"]
    result = _apply_llm_escalation(
        TEST_CASE, list(original), ["1.2.3.4", "5.6.7.8"],
        [], "ipv4", None,
    )
    assert result == original


# ---------------------------------------------------------------------------
# RumsfeldAgent gap analysis
# ---------------------------------------------------------------------------

def test_analyse_gaps():
    """Test gap analysis identifies unresolved items."""
    from agents.rumsfeld import _analyse_gaps

    matrix = {
        "known_unknowns": [
            {"id": "ku_001", "question": "Did user click?", "priority": "high",
             "category": "user_action", "resolution": None},
            {"id": "ku_002", "question": "Was malware downloaded?", "priority": "medium",
             "category": "payload", "resolution": {"resolved_by": "enrich"}},
        ],
        "hypotheses": [
            {
                "id": "h_001", "claim": "Credential harvesting",
                "status": "unresolved",
                "disconfirming_checks": [
                    {"check": "POST to landing domain", "tool": "log_correlate", "result": None},
                    {"check": "Password change events", "tool": "sentinel_query", "result": "no_events"},
                ],
            },
        ],
    }

    gaps = _analyse_gaps(matrix)

    # Should find: 1 unresolved ku + 1 untested check (the one with result=None)
    assert len(gaps) == 2
    assert gaps[0]["type"] == "known_unknown"
    assert gaps[0]["id"] == "ku_001"
    assert gaps[1]["type"] == "untested_hypothesis_check"
    assert gaps[1]["hypothesis_id"] == "h_001"

    # Should be sorted by priority (both are high)
    assert all(g["priority"] == "high" for g in gaps)


def test_analyse_gaps_all_resolved():
    """No gaps when everything is resolved."""
    from agents.rumsfeld import _analyse_gaps

    matrix = {
        "known_unknowns": [
            {"id": "ku_001", "resolution": {"resolved_by": "enrich"}},
        ],
        "hypotheses": [
            {"id": "h_001", "status": "supported",
             "disconfirming_checks": [{"check": "x", "result": "confirmed"}]},
        ],
    }

    gaps = _analyse_gaps(matrix)
    assert len(gaps) == 0


def test_list_proposals_empty():
    """list_proposals returns empty list for case without proposals."""
    from tools.case_create import case_create
    from agents.rumsfeld import list_proposals

    case_create(TEST_CASE)
    assert list_proposals(TEST_CASE) == []


# ---------------------------------------------------------------------------
# JSON parsing helper
# ---------------------------------------------------------------------------

def test_parse_json_response_plain():
    """Parse plain JSON."""
    from tools.investigation_matrix import _parse_json_response

    raw = '{"known_knowns": [], "known_unknowns": [], "hypotheses": []}'
    result = _parse_json_response(raw)
    assert result is not None
    assert result["known_knowns"] == []


def test_parse_json_response_code_fence():
    """Parse JSON with code fences."""
    from tools.investigation_matrix import _parse_json_response

    raw = '```json\n{"known_knowns": [{"id": "kk_001"}]}\n```'
    result = _parse_json_response(raw)
    assert result is not None
    assert len(result["known_knowns"]) == 1


def test_parse_json_response_with_preamble():
    """Parse JSON with text before it."""
    from tools.investigation_matrix import _parse_json_response

    raw = 'Here is the matrix:\n{"known_knowns": [], "hypotheses": []}'
    result = _parse_json_response(raw)
    assert result is not None


def test_parse_json_response_invalid():
    """Invalid JSON returns None."""
    from tools.investigation_matrix import _parse_json_response

    result = _parse_json_response("This is not JSON at all")
    assert result is None
