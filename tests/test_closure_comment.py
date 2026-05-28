"""Tests for the closure_comment workflow (BP / FP / Undetermined)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest


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
# Classification map
# ---------------------------------------------------------------------------

def test_classifications_cover_sentinel_set():
    from tools.closure_comment import CLASSIFICATIONS

    expected = {
        "bp_suspicious_but_expected",
        "bp_suspicious_not_malicious",
        "fp_incorrect_logic",
        "fp_inaccurate_data",
        "undetermined",
    }
    assert set(CLASSIFICATIONS) == expected


def test_classification_dispositions_map_correctly():
    from tools.closure_comment import CLASSIFICATIONS

    assert CLASSIFICATIONS["bp_suspicious_but_expected"]["disposition"] == "benign_positive"
    assert CLASSIFICATIONS["bp_suspicious_not_malicious"]["disposition"] == "benign_positive"
    assert CLASSIFICATIONS["fp_incorrect_logic"]["disposition"] == "false_positive"
    assert CLASSIFICATIONS["fp_inaccurate_data"]["disposition"] == "false_positive"
    assert CLASSIFICATIONS["undetermined"]["disposition"] == "inconclusive"


def test_system_prompt_includes_classification_tone():
    from tools.closure_comment import _SYSTEM_PROMPT_FOR, CLASSIFICATIONS

    for clsf, cfg in CLASSIFICATIONS.items():
        prompt = _SYSTEM_PROMPT_FOR(clsf)
        # The classification-specific tone snippet must be embedded
        assert cfg["tone"][:40] in prompt


def test_system_prompt_rejects_unknown_classification():
    from tools.closure_comment import _SYSTEM_PROMPT_FOR

    with pytest.raises(ValueError):
        _SYSTEM_PROMPT_FOR("not_a_real_classification")


# ---------------------------------------------------------------------------
# save_report integration
# ---------------------------------------------------------------------------

def test_save_closure_comment_writes_md_and_auto_closes():
    from tools.case_create import case_create
    from tools.save_report import save_report_to_case
    from config.settings import CASES_DIR

    case_create(TEST_CASE, title="bp test", severity="low", client="Test Client")

    comment = "Activity confirmed as authorised admin scheduled task. No threat indicators present."
    result = save_report_to_case(
        case_id=TEST_CASE,
        report_type="closure_comment",
        report_text=comment,
        disposition="benign_positive",
    )

    assert result["status"] == "ok"
    assert result["auto_closed"] is True
    assert result["disposition"] == "benign_positive"

    md_path = Path(result["report_path"])
    assert md_path.suffix == ".md"
    assert md_path.exists()
    assert md_path.parent.name == "closure_comments"

    text = md_path.read_text(encoding="utf-8")
    # Header is prepended; body contains the comment
    assert comment in text
    assert "Closure Comment" in text

    # Case is closed in meta
    meta = json.loads((CASES_DIR / TEST_CASE / "case_meta.json").read_text())
    assert meta["status"] == "closed"
    assert meta["disposition"] == "benign_positive"


def test_save_closure_comment_with_fp_disposition():
    from tools.case_create import case_create
    from tools.save_report import save_report_to_case
    from config.settings import CASES_DIR

    case_create(TEST_CASE, title="fp test", severity="low", client="Test Client")

    result = save_report_to_case(
        case_id=TEST_CASE,
        report_type="closure_comment",
        report_text="Rule misfires on legitimate admin tool. Tuning recommended.",
        disposition="false_positive",
    )

    assert result["status"] == "ok"
    assert result["disposition"] == "false_positive"
    meta = json.loads((CASES_DIR / TEST_CASE / "case_meta.json").read_text())
    assert meta["disposition"] == "false_positive"


def test_save_closure_comment_undetermined_maps_to_inconclusive():
    from tools.case_create import case_create
    from tools.save_report import save_report_to_case
    from config.settings import CASES_DIR

    case_create(TEST_CASE, title="undetermined test", severity="low",
                client="Test Client")

    result = save_report_to_case(
        case_id=TEST_CASE,
        report_type="closure_comment",
        report_text="Insufficient logs to confirm or rule out. Retention has expired.",
        disposition="inconclusive",
    )

    assert result["status"] == "ok"
    meta = json.loads((CASES_DIR / TEST_CASE / "case_meta.json").read_text())
    assert meta["disposition"] == "inconclusive"


# ---------------------------------------------------------------------------
# Article markdown output
# ---------------------------------------------------------------------------

def test_save_article_writes_markdown_only(tmp_path, monkeypatch):
    from tools import threat_articles
    from config import settings

    # Point ARTICLES_DIR and the index at tmp_path so we don't touch the
    # real article registry.
    monkeypatch.setattr(threat_articles, "ARTICLES_DIR", tmp_path)
    monkeypatch.setattr(settings, "ARTICLES_DIR", tmp_path)
    monkeypatch.setattr(threat_articles, "ARTICLE_INDEX_FILE",
                        tmp_path / "article_index.json")
    monkeypatch.setattr(threat_articles, "check_topic_dedup",
                        lambda title: {"is_duplicate": False, "matches": []})

    article_text = "# Test Article\n\nBody paragraph.\n\n## Recommendations\n\n- Patch.\n"
    manifest = threat_articles.save_article(
        article_text=article_text,
        title="Unit test article",
        category="ET",
        analyst="pytest",
    )

    article_path = Path(manifest["article_path"])
    assert article_path.exists()
    assert article_path.suffix == ".md"
    # No companion HTML file should be written.
    assert not article_path.with_suffix(".html").exists()
    assert article_path.read_text(encoding="utf-8") == article_text
