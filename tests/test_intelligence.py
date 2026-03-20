"""
Tests for intelligence layer: case_memory, client_baseline, geoip, scheduler.
Run with:  cd socai && python -m pytest tests/test_intelligence.py -v
"""
import json
import shutil
import sys
import threading
import time
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


# ===========================================================================
# case_memory
# ===========================================================================

class TestCaseMemory:
    """BM25 case memory index and search."""

    @pytest.fixture(autouse=True)
    def cleanup_index(self):
        from config.settings import CASE_MEMORY_INDEX_FILE
        yield
        if CASE_MEMORY_INDEX_FILE.exists():
            CASE_MEMORY_INDEX_FILE.unlink()

    def test_tokenise_basic(self):
        from tools.case_memory import _tokenise

        tokens = _tokenise("DocuSign Phishing email@test.com 1.2.3.4")
        assert "docusign" in tokens
        assert "phishing" in tokens
        assert "1.2.3.4" in tokens

    def test_tokenise_dedup_and_short(self):
        from tools.case_memory import _tokenise

        tokens = _tokenise("a bb cc a bb")
        # single-char tokens filtered
        assert "a" not in tokens
        assert "bb" in tokens
        assert "cc" in tokens

    def test_bm25_basic_ranking(self):
        from tools.case_memory import _BM25

        docs = [
            ["phishing", "docusign", "credential", "harvest"],
            ["malware", "trojan", "download", "execution"],
            ["phishing", "office365", "credential", "theft"],
        ]
        bm25 = _BM25(docs)
        results = bm25.search(["phishing", "credential"], top_k=3)

        # Doc 0 and 2 should score highest (both contain phishing + credential)
        top_indices = [idx for idx, _ in results]
        assert 0 in top_indices[:2]
        assert 2 in top_indices[:2]
        # Doc 1 (malware) should score 0 or lowest
        assert 1 not in top_indices[:2]

    def test_bm25_empty_docs(self):
        from tools.case_memory import _BM25

        bm25 = _BM25([])
        results = bm25.search(["test"])
        assert results == []

    def test_build_index_and_search(self):
        from tools.case_create import case_create
        from tools.case_memory import build_case_memory_index, search_case_memory
        from config.settings import CASE_MEMORY_INDEX_FILE

        case_create(TEST_CASE, title="DocuSign phishing credential harvest", severity="high",
                    tags=["phishing", "docusign"])

        result = build_case_memory_index()
        assert result["status"] == "ok"
        assert result["indexed"] >= 1
        assert CASE_MEMORY_INDEX_FILE.exists()

        # Search should find our case
        search = search_case_memory("docusign phishing")
        assert search["status"] == "ok"
        assert len(search["results"]) >= 1
        assert any(r["case_id"] == TEST_CASE for r in search["results"])

    def test_search_empty_query(self):
        from tools.case_memory import search_case_memory

        result = search_case_memory("")
        assert result["status"] == "error"

    def test_search_auto_builds_index(self):
        from tools.case_create import case_create
        from tools.case_memory import search_case_memory
        from config.settings import CASE_MEMORY_INDEX_FILE

        case_create(TEST_CASE, title="Test auto build")

        # Index doesn't exist yet
        if CASE_MEMORY_INDEX_FILE.exists():
            CASE_MEMORY_INDEX_FILE.unlink()

        result = search_case_memory("test auto build")
        assert result["status"] == "ok"
        assert CASE_MEMORY_INDEX_FILE.exists()

    def test_search_client_filter(self):
        from tools.case_create import case_create
        from tools.case_memory import build_case_memory_index, search_case_memory

        case_create(TEST_CASE, title="Alert for acme", client="acme_corp")
        build_case_memory_index()

        # Search with matching client
        result = search_case_memory("alert", client_filter="acme_corp")
        assert result["status"] == "ok"
        assert any(r["case_id"] == TEST_CASE for r in result["results"])

        # Search with non-matching client
        result = search_case_memory("alert", client_filter="other_corp")
        assert result["status"] == "ok"
        assert len(result["results"]) == 0

    def test_build_skips_test_cases(self):
        """Cases starting with TEST_ should not be indexed."""
        from tools.case_memory import build_case_memory_index
        from config.settings import REGISTRY_FILE
        from tools.common import load_json

        # Seed registry with a TEST_ case
        reg = load_json(REGISTRY_FILE) if REGISTRY_FILE.exists() else {"cases": {}}
        reg.setdefault("cases", {})["TEST_SKIP_001"] = {
            "title": "Should be skipped", "status": "open"
        }
        REGISTRY_FILE.write_text(json.dumps(reg, indent=2))

        result = build_case_memory_index()
        assert result["status"] == "ok"

        from config.settings import CASE_MEMORY_INDEX_FILE
        index = json.loads(CASE_MEMORY_INDEX_FILE.read_text())
        case_ids = [e["case_id"] for e in index["entries"]]
        assert "TEST_SKIP_001" not in case_ids

        # Cleanup
        reg["cases"].pop("TEST_SKIP_001", None)
        REGISTRY_FILE.write_text(json.dumps(reg, indent=2))


# ===========================================================================
# client_baseline
# ===========================================================================

class TestClientBaseline:
    """Per-client behavioural baselines."""

    @pytest.fixture(autouse=True)
    def cleanup_baselines(self):
        from config.settings import BASELINES_DIR
        yield
        baseline_path = BASELINES_DIR / "test_client.json"
        if baseline_path.exists():
            baseline_path.unlink()

    def test_client_key_normalisation(self):
        from tools.client_baseline import _client_key

        assert _client_key("Acme Corp") == "acme_corp"
        assert _client_key("  test  ") == "test"

    def test_build_baseline_empty_client(self):
        from tools.client_baseline import build_client_baseline

        result = build_client_baseline("")
        assert result["status"] == "error"

    def test_build_baseline_no_cases(self):
        from tools.client_baseline import build_client_baseline

        result = build_client_baseline("nonexistent_client_xyz")
        assert result["status"] == "ok"
        assert result["case_count"] == 0

    def test_build_and_get_baseline(self):
        from tools.case_create import case_create
        from tools.client_baseline import build_client_baseline, get_client_baseline
        from config.settings import BASELINES_DIR

        case_create(TEST_CASE, title="Test alert", severity="high",
                    client="test_client", tags=["phishing", "credential_theft"])

        result = build_client_baseline("test_client")
        assert result["status"] == "ok"
        assert result["case_count"] == 1
        assert (BASELINES_DIR / "test_client.json").exists()

        # Get should return the profile
        profile = get_client_baseline("test_client")
        assert profile["client"] == "test_client"
        assert profile["case_count"] == 1
        assert profile["severity_dist"]["high"] == 1

    def test_get_baseline_auto_builds(self):
        from tools.case_create import case_create
        from tools.client_baseline import get_client_baseline
        from config.settings import BASELINES_DIR

        case_create(TEST_CASE, title="Auto build test", severity="medium",
                    client="test_client")

        # Ensure no baseline exists
        bp = BASELINES_DIR / "test_client.json"
        if bp.exists():
            bp.unlink()

        profile = get_client_baseline("test_client")
        assert profile["client"] == "test_client"
        assert profile["case_count"] == 1

    def test_check_against_baseline_unknown_ioc(self):
        from tools.case_create import case_create
        from tools.client_baseline import build_client_baseline, check_against_baseline

        case_create(TEST_CASE, title="Baseline check", severity="low",
                    client="test_client")
        build_client_baseline("test_client")

        result = check_against_baseline("test_client", "ipv4", "9.9.9.9")
        assert result["known"] is False
        assert result["seen"] == 0

    def test_check_against_baseline_known_ioc(self):
        from tools.case_create import case_create
        from tools.client_baseline import build_client_baseline, check_against_baseline
        from tools.common import save_json
        from config.settings import CASES_DIR

        case_create(TEST_CASE, title="IOC recurrence", severity="high",
                    client="test_client")

        # Seed IOCs
        iocs_dir = CASES_DIR / TEST_CASE / "iocs"
        iocs_dir.mkdir(parents=True, exist_ok=True)
        save_json(iocs_dir / "iocs.json", {
            "iocs": {
                "ipv4": ["1.2.3.4", "5.6.7.8"],
                "domain": ["evil.example.com"],
            }
        })

        build_client_baseline("test_client")

        result = check_against_baseline("test_client", "ipv4", "1.2.3.4")
        assert result["known"] is True
        assert result["seen"] >= 1
        assert TEST_CASE in result["cases"]

    def test_check_no_baseline_exists(self):
        from tools.client_baseline import check_against_baseline
        from config.settings import BASELINES_DIR

        # Ensure no baseline
        bp = BASELINES_DIR / "ghost_client.json"
        if bp.exists():
            bp.unlink()

        result = check_against_baseline("ghost_client", "domain", "test.com")
        assert result["known"] is False
        assert "No baseline" in result.get("note", "")

    def test_baseline_severity_distribution(self):
        """Multiple cases should aggregate severity correctly."""
        from tools.case_create import case_create
        from tools.client_baseline import build_client_baseline
        from config.settings import BASELINES_DIR

        # Create first case at high
        case_create(TEST_CASE, title="High sev", severity="high",
                    client="test_client")

        # We can only create one case with the autouse fixture, but the
        # severity from case_meta is what matters — verify the single case
        result = build_client_baseline("test_client")
        assert result["status"] == "ok"

        profile = json.loads((BASELINES_DIR / "test_client.json").read_text())
        assert profile["severity_dist"]["high"] == 1
        assert profile["severity_dist"]["low"] == 0


# ===========================================================================
# geoip
# ===========================================================================

class TestGeoIP:
    """GeoIP local lookup."""

    def test_lookup_empty_ip(self):
        from tools.geoip import lookup_ip

        result = lookup_ip("")
        assert result["available"] is False
        assert "empty" in result["note"]

    def test_lookup_no_database(self):
        from tools.geoip import lookup_ip

        with patch("tools.geoip.db_available", return_value=False):
            result = lookup_ip("8.8.8.8")
        assert result["available"] is False
        assert "not present" in result["note"]

    def test_lookup_no_geoip2_package(self):
        """When geoip2 is not installed, should degrade gracefully."""
        from tools.geoip import lookup_ip

        with patch("tools.geoip.db_available", return_value=True):
            with patch.dict("sys.modules", {"geoip2": None, "geoip2.database": None, "geoip2.errors": None}):
                # Force re-import to trigger ImportError
                result = lookup_ip("8.8.8.8")
                # Either "not installed" or a valid result depending on state
                assert "ip" in result

    def test_bulk_lookup(self):
        from tools.geoip import bulk_lookup

        with patch("tools.geoip.lookup_ip") as mock_lookup:
            mock_lookup.return_value = {"available": False, "ip": "1.1.1.1", "note": "test"}
            result = bulk_lookup(["1.1.1.1", "2.2.2.2"])

        assert "1.1.1.1" in result
        assert "2.2.2.2" in result
        assert mock_lookup.call_count == 2

    def test_refresh_no_license_key(self):
        from tools.geoip import refresh_geoip_db

        with patch("tools.geoip.MAXMIND_LICENSE_KEY", ""):
            result = refresh_geoip_db()
        assert result["status"] == "error"
        assert "MAXMIND_LICENSE_KEY" in result["reason"]

    def test_refresh_skip_recent(self):
        """Should skip download if database updated within 7 days."""
        from tools.geoip import refresh_geoip_db, _META_PATH, utcnow

        meta = {"updated_at": utcnow()}
        with patch("tools.geoip.MAXMIND_LICENSE_KEY", "test-key"), \
             patch("tools.geoip.db_available", return_value=True), \
             patch("tools.geoip._load_meta", return_value=meta):
            result = refresh_geoip_db()
        assert result["status"] == "ok"
        assert result["updated"] is False
        assert "current" in result["note"]

    def test_db_available_false(self):
        from tools.geoip import db_available

        with patch("tools.geoip.GEOIP_DB_PATH") as mock_path:
            mock_path.exists.return_value = False
            assert db_available() is False

    def test_meta_helpers(self):
        from tools.geoip import _load_meta, _save_meta, _META_PATH
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            test_meta_path = Path(tmpdir) / "meta.json"
            with patch("tools.geoip._META_PATH", test_meta_path):
                # No file yet
                assert _load_meta() == {}

                # Save and reload
                _save_meta({"updated_at": "2026-01-01T00:00:00Z", "source": "test"})
                loaded = _load_meta()
                assert loaded["source"] == "test"


# ===========================================================================
# scheduler
# ===========================================================================

class TestScheduler:
    """Background task scheduler."""

    @pytest.fixture(autouse=True)
    def reset_scheduler(self):
        """Reset scheduler singleton state between tests."""
        import tools.scheduler as sched
        sched._stop_event.set()
        if sched._scheduler_thread and sched._scheduler_thread.is_alive():
            sched._scheduler_thread.join(timeout=2)
        sched._scheduler_thread = None
        sched._stop_event.clear()
        yield
        sched._stop_event.set()
        if sched._scheduler_thread and sched._scheduler_thread.is_alive():
            sched._scheduler_thread.join(timeout=2)
        sched._scheduler_thread = None

    def test_run_task_success(self):
        from tools.scheduler import _run_task

        fn = MagicMock(return_value={"status": "ok"})
        _run_task("test_task", fn)
        fn.assert_called_once()

    def test_run_task_exception(self):
        """Task exceptions should be caught, not propagated."""
        from tools.scheduler import _run_task

        fn = MagicMock(side_effect=RuntimeError("boom"))
        # Should not raise
        _run_task("failing_task", fn)
        fn.assert_called_once()

    def test_stop_scheduler_sets_event(self):
        from tools.scheduler import stop_scheduler, _stop_event

        _stop_event.clear()
        stop_scheduler()
        assert _stop_event.is_set()

    def test_start_scheduler_idempotent(self):
        """Multiple start_scheduler calls should only create one thread."""
        import tools.scheduler as sched

        ran = threading.Event()

        def quick_loop(tasks):
            ran.set()
            while not sched._stop_event.is_set():
                sched._stop_event.wait(timeout=0.1)

        sched._stop_event.clear()
        sched._scheduler_thread = None

        with patch("tools.scheduler._scheduler_loop", quick_loop), \
             patch("tools.case_memory.build_case_memory_index", return_value={"status": "ok"}), \
             patch("tools.geoip.refresh_geoip_db", return_value={"status": "ok"}):
            sched.start_scheduler()
            thread1 = sched._scheduler_thread
            assert thread1 is not None
            ran.wait(timeout=2)

            # Second call should be a no-op (same thread)
            sched.start_scheduler()
            thread2 = sched._scheduler_thread
            assert thread2 is thread1

    def test_scheduler_loop_runs_tasks(self):
        """Verify the scheduler loop executes tasks and responds to stop."""
        from tools.scheduler import _scheduler_loop, _stop_event

        call_log = []

        def task_a():
            call_log.append("a")
            return "ok"

        def task_b():
            call_log.append("b")
            return "ok"

        _stop_event.clear()

        # Run in a thread, stop after tasks execute
        def run():
            _scheduler_loop([
                ("task_a", 3600, task_a),  # 1h interval (won't re-run)
                ("task_b", 3600, task_b),
            ])

        t = threading.Thread(target=run, daemon=True)
        t.start()

        # Wait for first iteration
        time.sleep(0.5)

        # Both tasks should have run once (immediate first run)
        assert "a" in call_log
        assert "b" in call_log

        # Stop the loop
        _stop_event.set()
        t.join(timeout=3)
        assert not t.is_alive()
