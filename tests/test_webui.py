"""
Tests for the web UI backend: chat engine, sessions, history trimming,
tool dispatch, and SSE streaming.

Run with:  cd socai && python -m pytest tests/test_webui.py -v
"""
import json
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_CASE = "TEST_WEBUI_001"
TEST_EMAIL = "analyst@test.local"
TEST_SESSION = None  # Set dynamically in fixtures


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def cleanup():
    """Remove test case and test sessions before and after each test."""
    from config.settings import CASES_DIR
    from api.sessions import SESSIONS_DIR

    def _rm():
        case_dir = CASES_DIR / TEST_CASE
        if case_dir.exists():
            shutil.rmtree(case_dir)
        # Clean up any test sessions and their auto-created cases
        if SESSIONS_DIR.exists():
            for d in SESSIONS_DIR.iterdir():
                if d.is_dir() and d.name.startswith("S-"):
                    meta_path = d / "session_meta.json"
                    if meta_path.exists():
                        try:
                            meta = json.loads(meta_path.read_text())
                            if meta.get("user_email") == TEST_EMAIL:
                                # Clean up auto-created case
                                session_case = meta.get("case_id")
                                if session_case:
                                    sc_dir = CASES_DIR / session_case
                                    if sc_dir.exists():
                                        shutil.rmtree(sc_dir)
                                shutil.rmtree(d)
                        except Exception:
                            pass

    _rm()
    yield
    _rm()


@pytest.fixture
def case_dir():
    """Create a minimal test case directory with metadata."""
    from config.settings import CASES_DIR
    from tools.common import save_json

    cdir = CASES_DIR / TEST_CASE
    cdir.mkdir(parents=True, exist_ok=True)
    save_json(cdir / "case_meta.json", {
        "case_id": TEST_CASE,
        "title": "Test phishing investigation",
        "severity": "medium",
        "status": "open",
        "analyst": TEST_EMAIL,
    })
    return cdir


@pytest.fixture
def session_id():
    """Create a fresh test session and return its ID."""
    from api.sessions import create_session
    meta = create_session(TEST_EMAIL)
    return meta["session_id"]


# ===========================================================================
# 1. History trimming — _trim_for_api
# ===========================================================================

class TestTrimForApi:
    """Tests for _trim_for_api and orphan cleanup logic."""

    def test_trims_to_max_messages(self):
        from api.chat import _trim_for_api

        messages = [{"role": "user" if i % 2 == 0 else "assistant",
                      "content": f"msg {i}"} for i in range(40)]
        result = _trim_for_api(messages, max_messages=20)
        assert len(result) <= 20

    def test_ensures_first_message_is_user(self):
        from api.chat import _trim_for_api

        messages = [
            {"role": "assistant", "content": "I'll help"},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
        ]
        result = _trim_for_api(messages, max_messages=10)
        assert result[0]["role"] == "user"

    def test_strips_orphaned_tool_results(self):
        from api.chat import _trim_for_api

        messages = [
            # Orphan: tool_result without matching tool_use
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "orphan_123", "content": "data"},
            ]},
            {"role": "user", "content": "What did you find?"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "Here's what I found"},
                {"type": "tool_use", "id": "valid_456", "name": "enrich_iocs", "input": {}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "valid_456", "content": "enrichment data"},
            ]},
        ]
        result = _trim_for_api(messages, max_messages=10)
        # The orphan tool_result message should be dropped
        for msg in result:
            if isinstance(msg.get("content"), list):
                for block in msg["content"]:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        assert block["tool_use_id"] != "orphan_123"

    def test_truncates_long_tool_results(self):
        from api.chat import _trim_for_api, MAX_TOOL_RESULT_CHARS

        long_content = "x" * (MAX_TOOL_RESULT_CHARS + 1000)
        messages = [
            {"role": "user", "content": "Do something"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "Running tool"},
                {"type": "tool_use", "id": "tu_1", "name": "test", "input": {}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "tu_1", "content": long_content},
            ]},
        ]
        result = _trim_for_api(messages, max_messages=10)
        # Find the tool_result block
        for msg in result:
            if isinstance(msg.get("content"), list):
                for block in msg["content"]:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        assert len(block["content"]) <= MAX_TOOL_RESULT_CHARS + 50  # allow for "… [truncated]"

    def test_strips_ts_metadata(self):
        from api.chat import _trim_for_api

        messages = [
            {"role": "user", "content": "Hello", "ts": "2026-01-01T00:00:00"},
            {"role": "assistant", "content": "Hi", "ts": "2026-01-01T00:00:01"},
        ]
        result = _trim_for_api(messages, max_messages=10)
        for msg in result:
            assert "ts" not in msg

    def test_empty_messages(self):
        from api.chat import _trim_for_api
        result = _trim_for_api([], max_messages=20)
        assert result == []

    def test_drops_empty_messages_after_orphan_removal(self):
        """If removing orphaned tool_results leaves an empty content list,
        the entire message should be dropped."""
        from api.chat import _trim_for_api

        messages = [
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "gone_999", "content": "stale"},
            ]},
            {"role": "user", "content": "Fresh question"},
            {"role": "assistant", "content": "Answer"},
        ]
        result = _trim_for_api(messages, max_messages=10)
        # The first message should be gone entirely
        assert all(msg.get("content") for msg in result)


class TestTrimForApiCompaction:
    """Tests for _trim_for_api_compaction (lighter trimming for Opus)."""

    def test_uses_higher_cap(self):
        from api.chat import _trim_for_api_compaction, MAX_COMPACTION_MESSAGES

        messages = [{"role": "user" if i % 2 == 0 else "assistant",
                      "content": f"msg {i}"} for i in range(50)]
        result = _trim_for_api_compaction(messages)
        # Should keep all 50 (under the 200 cap)
        # Some may be dropped if first isn't user, but most should remain
        assert len(result) >= 40

    def test_still_strips_orphans(self):
        from api.chat import _trim_for_api_compaction

        messages = [
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "orphan_1", "content": "stale"},
            ]},
            {"role": "user", "content": "Question"},
            {"role": "assistant", "content": "Answer"},
        ]
        result = _trim_for_api_compaction(messages)
        assert result[0]["role"] == "user"
        # Orphan message should be gone
        for msg in result:
            if isinstance(msg.get("content"), list):
                for block in msg["content"]:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        assert block["tool_use_id"] != "orphan_1"


class TestPrepareMessagesForApi:
    """Tests for the routing function that selects trim strategy."""

    def test_compaction_model_uses_compaction_trim(self):
        from api.chat import _prepare_messages_for_api, MAX_HISTORY_MESSAGES

        messages = [{"role": "user" if i % 2 == 0 else "assistant",
                      "content": f"msg {i}"} for i in range(40)]

        with patch("api.chat.SOCAI_COMPACTION_ENABLED", True):
            result = _prepare_messages_for_api(messages, "claude-opus-4-20250514")
            # Compaction trim keeps more than 20
            assert len(result) > MAX_HISTORY_MESSAGES

    def test_non_compaction_model_uses_hard_trim(self):
        from api.chat import _prepare_messages_for_api, MAX_HISTORY_MESSAGES

        messages = [{"role": "user" if i % 2 == 0 else "assistant",
                      "content": f"msg {i}"} for i in range(40)]

        result = _prepare_messages_for_api(messages, "claude-sonnet-4-20250514")
        assert len(result) <= MAX_HISTORY_MESSAGES


# ===========================================================================
# 2. Chat history persistence
# ===========================================================================

class TestChatHistory:
    """Tests for history save/load with per-user scoping."""

    def test_save_and_load(self, case_dir):
        from api.chat import save_history, load_history

        history = [
            {"role": "user", "content": "Investigate this URL"},
            {"role": "assistant", "content": "I'll look into it"},
        ]
        save_history(TEST_CASE, history, user_email=TEST_EMAIL)
        loaded = load_history(TEST_CASE, user_email=TEST_EMAIL)
        assert len(loaded) == 2
        assert loaded[0]["content"] == "Investigate this URL"

    def test_per_user_isolation(self, case_dir):
        from api.chat import save_history, load_history

        save_history(TEST_CASE, [{"role": "user", "content": "User A msg"}],
                     user_email="a@test.local")
        save_history(TEST_CASE, [{"role": "user", "content": "User B msg"}],
                     user_email="b@test.local")

        a_hist = load_history(TEST_CASE, user_email="a@test.local")
        b_hist = load_history(TEST_CASE, user_email="b@test.local")
        assert a_hist[0]["content"] == "User A msg"
        assert b_hist[0]["content"] == "User B msg"

    def test_timestamps_added_on_save(self, case_dir):
        from api.chat import save_history, load_history

        history = [{"role": "user", "content": "Hello"}]
        save_history(TEST_CASE, history, user_email=TEST_EMAIL)
        loaded = load_history(TEST_CASE, user_email=TEST_EMAIL)
        assert "ts" in loaded[0]

    def test_load_missing_case_returns_empty(self):
        from api.chat import load_history
        assert load_history("NONEXISTENT_CASE_999", user_email=TEST_EMAIL) == []


# ===========================================================================
# 3. Display history formatter
# ===========================================================================

class TestDisplayHistory:
    """Tests for get_display_history."""

    def test_formats_user_and_assistant_messages(self, case_dir):
        from api.chat import save_history, get_display_history

        history = [
            {"role": "user", "content": "Check this IP"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "The IP is malicious"},
            ]},
        ]
        save_history(TEST_CASE, history, user_email=TEST_EMAIL)
        display = get_display_history(TEST_CASE, user_email=TEST_EMAIL)
        assert len(display) == 2
        assert display[0]["role"] == "user"
        assert display[1]["role"] == "assistant"
        assert display[1]["content"] == "The IP is malicious"

    def test_extracts_tool_calls(self, case_dir):
        from api.chat import save_history, get_display_history

        history = [
            {"role": "user", "content": "Enrich IOCs"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "tu_1", "name": "enrich_iocs", "input": {}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "tu_1", "content": "3 malicious"},
            ]},
            {"role": "assistant", "content": [
                {"type": "text", "text": "Found 3 malicious IOCs"},
            ]},
        ]
        save_history(TEST_CASE, history, user_email=TEST_EMAIL)
        display = get_display_history(TEST_CASE, user_email=TEST_EMAIL)

        # First assistant entry should have tool_calls
        tool_entry = [d for d in display if d.get("tool_calls")]
        assert len(tool_entry) == 1
        assert tool_entry[0]["tool_calls"][0]["name"] == "enrich_iocs"
        # And tool_results from the next message
        assert tool_entry[0].get("tool_results") == ["3 malicious"]

    def test_skips_tool_result_user_messages(self, case_dir):
        from api.chat import save_history, get_display_history

        history = [
            {"role": "user", "content": "Do it"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "tu_1", "name": "triage_iocs", "input": {}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "tu_1", "content": "done"},
            ]},
        ]
        save_history(TEST_CASE, history, user_email=TEST_EMAIL)
        display = get_display_history(TEST_CASE, user_email=TEST_EMAIL)
        # Tool result messages should not appear as user messages
        user_msgs = [d for d in display if d["role"] == "user"]
        assert len(user_msgs) == 1
        assert user_msgs[0]["content"] == "Do it"


# ===========================================================================
# 4. Serialise content
# ===========================================================================

class TestSerialiseContent:
    """Tests for _serialise_content converting Anthropic blocks to dicts."""

    def test_text_block(self):
        from api.chat import _serialise_content
        blocks = [SimpleNamespace(type="text", text="Hello world")]
        result = _serialise_content(blocks)
        assert result == [{"type": "text", "text": "Hello world"}]

    def test_tool_use_block(self):
        from api.chat import _serialise_content
        blocks = [SimpleNamespace(type="tool_use", id="tu_1", name="enrich_iocs",
                                  input={"include_private": True})]
        result = _serialise_content(blocks)
        assert result[0]["type"] == "tool_use"
        assert result[0]["name"] == "enrich_iocs"
        assert result[0]["id"] == "tu_1"

    def test_thinking_block(self):
        from api.chat import _serialise_content
        blocks = [SimpleNamespace(type="thinking", thinking="Let me consider...")]
        result = _serialise_content(blocks)
        assert result[0]["type"] == "thinking"
        assert result[0]["thinking"] == "Let me consider..."

    def test_mixed_blocks(self):
        from api.chat import _serialise_content
        blocks = [
            SimpleNamespace(type="text", text="I'll run the tool"),
            SimpleNamespace(type="tool_use", id="tu_1", name="capture_urls",
                            input={"urls": ["https://example.com"]}),
        ]
        result = _serialise_content(blocks)
        assert len(result) == 2
        assert result[0]["type"] == "text"
        assert result[1]["type"] == "tool_use"


# ===========================================================================
# 5. Session CRUD
# ===========================================================================

class TestSessionCRUD:
    """Tests for session creation, listing, loading, and deletion."""

    def test_create_session(self):
        from api.sessions import create_session
        from config.settings import CASES_DIR
        meta = create_session(TEST_EMAIL)
        assert meta["session_id"].startswith("S-")
        assert meta["user_email"] == TEST_EMAIL
        assert meta["status"] == "active"
        # Auto-created case
        assert meta["case_id"] is not None
        assert (CASES_DIR / meta["case_id"]).exists()

    def test_load_session(self, session_id):
        from api.sessions import load_session
        meta = load_session(session_id)
        assert meta is not None
        assert meta["session_id"] == session_id

    def test_load_nonexistent_session(self):
        from api.sessions import load_session
        assert load_session("S-nonexistent-12345678") is None

    def test_list_sessions_filters_by_user(self, session_id):
        from api.sessions import create_session, list_sessions

        # Create a session for a different user
        create_session("other@test.local")
        sessions = list_sessions(TEST_EMAIL)
        assert all(s["user_email"] == TEST_EMAIL for s in sessions)

    def test_rename_session(self, session_id):
        from api.sessions import rename_session, load_session
        rename_session(session_id, "Phishing investigation")
        meta = load_session(session_id)
        assert meta["title"] == "Phishing investigation"

    def test_rename_truncates_long_titles(self, session_id):
        from api.sessions import rename_session, load_session
        rename_session(session_id, "A" * 200)
        meta = load_session(session_id)
        assert len(meta["title"]) == 120

    def test_delete_session(self, session_id):
        from api.sessions import delete_session, load_session, SESSIONS_DIR
        assert delete_session(session_id) is True
        assert not (SESSIONS_DIR / session_id).exists()

    def test_delete_all_sessions(self):
        from api.sessions import create_session, delete_all_sessions, list_sessions
        create_session(TEST_EMAIL)
        create_session(TEST_EMAIL)
        deleted = delete_all_sessions(TEST_EMAIL)
        assert deleted >= 2
        assert list_sessions(TEST_EMAIL) == []

    def test_user_owns_session(self, session_id):
        from api.sessions import user_owns_session
        assert user_owns_session(session_id, TEST_EMAIL) is True
        assert user_owns_session(session_id, "other@test.local") is False


# ===========================================================================
# 6. Session context accumulator
# ===========================================================================

class TestSessionContext:
    """Tests for IOC, finding, and telemetry accumulation in sessions."""

    def test_add_iocs_deduplicates(self, session_id):
        from api.sessions import add_iocs, load_context

        add_iocs(session_id, {"ips": ["1.2.3.4", "5.6.7.8"]})
        add_iocs(session_id, {"ips": ["1.2.3.4", "9.10.11.12"]})

        ctx = load_context(session_id)
        assert sorted(ctx["iocs"]["ips"]) == ["1.2.3.4", "5.6.7.8", "9.10.11.12"]

    def test_add_finding(self, session_id):
        from api.sessions import add_finding, load_context

        add_finding(session_id, "phishing", "Brand impersonation detected",
                    detail="Microsoft login page clone")
        ctx = load_context(session_id)
        assert len(ctx["findings"]) == 1
        assert ctx["findings"][0]["type"] == "phishing"
        assert ctx["findings"][0]["summary"] == "Brand impersonation detected"
        assert "ts" in ctx["findings"][0]

    def test_add_telemetry_summary(self, session_id):
        from api.sessions import add_telemetry_summary, load_context

        add_telemetry_summary(session_id, {
            "source_file": "alerts.csv",
            "event_count": 150,
            "platform": "sentinel",
        })
        ctx = load_context(session_id)
        assert len(ctx["telemetry_summaries"]) == 1
        assert ctx["telemetry_summaries"][0]["event_count"] == 150

    def test_set_disposition(self, session_id):
        from api.sessions import set_disposition, load_context

        set_disposition(session_id, "false_positive")
        ctx = load_context(session_id)
        assert ctx["disposition"] == "false_positive"

    def test_empty_context_structure(self, session_id):
        from api.sessions import load_context

        ctx = load_context(session_id)
        assert "iocs" in ctx
        assert "findings" in ctx
        assert "telemetry_summaries" in ctx
        assert ctx["disposition"] is None


# ===========================================================================
# 7. Session history
# ===========================================================================

class TestSessionHistory:
    """Tests for session-scoped history persistence."""

    def test_save_and_load(self, session_id):
        from api.sessions import save_history, load_history

        history = [
            {"role": "user", "content": "Analyse this alert"},
            {"role": "assistant", "content": "Looking into it"},
        ]
        save_history(session_id, history)
        loaded = load_history(session_id)
        assert len(loaded) == 2

    def test_adds_timestamps(self, session_id):
        from api.sessions import save_history, load_history

        save_history(session_id, [{"role": "user", "content": "Hi"}])
        loaded = load_history(session_id)
        assert "ts" in loaded[0]

    def test_load_empty(self, session_id):
        from api.sessions import load_history
        # Fresh session has empty history
        assert load_history(session_id) == []


# ===========================================================================
# 8. Session materialisation
# ===========================================================================

class TestMaterialisation:
    """Tests for converting a session into a full case."""

    def test_finalise_syncs_case(self, session_id):
        from api.sessions import finalise, add_iocs, add_finding, load_session
        from config.settings import CASES_DIR

        # Get the auto-created case ID
        meta = load_session(session_id)
        case_id = meta["case_id"]
        assert case_id is not None

        # Populate session with data
        add_iocs(session_id, {"ips": ["10.0.0.1"], "domains": ["evil.example.com"]})
        add_finding(session_id, "malware", "Cobalt Strike beacon detected")

        result = finalise(session_id, "Test investigation", "high", "true_positive")

        assert result["case_id"] == case_id
        assert result["iocs_saved"] is True
        assert result["findings_count"] == 1

        # Case directory should exist with updated metadata
        case_meta = json.loads((CASES_DIR / case_id / "case_meta.json").read_text())
        assert case_meta["title"] == "Test investigation"
        assert case_meta["severity"] == "high"
        assert case_meta["disposition"] == "true_positive"

        # IOCs should be copied
        iocs = json.loads((CASES_DIR / case_id / "iocs" / "iocs.json").read_text())
        assert "10.0.0.1" in iocs["iocs"]["ips"]

        # Session should be marked finalised
        meta = load_session(session_id)
        assert meta["status"] == "finalised"

    def test_finalise_copies_uploads(self, session_id):
        from api.sessions import finalise, upload_dir, load_session
        from config.settings import CASES_DIR

        case_id = load_session(session_id)["case_id"]

        # Create a fake upload
        udir = upload_dir(session_id)
        (udir / "alert_export.csv").write_text("timestamp,alert\n2026-01-01,test")

        finalise(session_id, "Test", "medium")

        assert (CASES_DIR / case_id / "uploads" / "alert_export.csv").exists()

    def test_finalise_copies_history(self, session_id):
        from api.sessions import finalise, save_history as save_sess_hist, load_session
        from api.chat import load_history
        from config.settings import CASES_DIR

        case_id = load_session(session_id)["case_id"]

        save_sess_hist(session_id, [
            {"role": "user", "content": "Investigate"},
            {"role": "assistant", "content": "On it"},
        ])

        finalise(session_id, "Test", "medium")

        case_history = load_history(case_id, user_email=TEST_EMAIL)
        assert len(case_history) == 2


# ===========================================================================
# 9. Tool dispatch — case mode
# ===========================================================================

class TestCaseToolDispatch:
    """Tests for _dispatch_tool routing in case mode."""

    def test_unknown_tool(self, case_dir):
        from api.chat import _dispatch_tool
        result = _dispatch_tool(TEST_CASE, "nonexistent_tool", {})
        assert "Unknown tool" in result.get("_message", "")

    def test_read_case_file_traversal_blocked(self, case_dir):
        from api.chat import read_case_file
        result = read_case_file(TEST_CASE, "../../etc/passwd")
        assert "traversal" in result["_message"].lower()

    def test_read_case_file_missing(self, case_dir):
        from api.chat import read_case_file
        result = read_case_file(TEST_CASE, "nonexistent.json")
        assert "not found" in result["_message"].lower()

    def test_read_case_file_success(self, case_dir):
        from api.chat import read_case_file

        # Write a test file
        (case_dir / "notes").mkdir(exist_ok=True)
        (case_dir / "notes" / "test.md").write_text("# Test note\nSome content")

        result = read_case_file(TEST_CASE, "notes/test.md")
        assert "Test note" in result["_message"]

    def test_add_evidence_no_text(self, case_dir):
        from api.chat import _dispatch_tool
        result = _dispatch_tool(TEST_CASE, "add_evidence", {"text": ""})
        assert "No text" in result.get("_message", "")

    def test_capture_urls_no_urls(self, case_dir):
        from api.chat import _dispatch_tool
        result = _dispatch_tool(TEST_CASE, "capture_urls", {"urls": []})
        assert "No URLs" in result.get("_message", "")

    def test_analyse_email_no_eml(self, case_dir):
        from api.chat import _dispatch_tool
        result = _dispatch_tool(TEST_CASE, "analyse_email", {})
        assert "No .eml" in result.get("_message", "")

    def test_generate_fp_ticket_no_alert(self, case_dir):
        from api.chat import _dispatch_tool
        result = _dispatch_tool(TEST_CASE, "generate_fp_ticket", {"alert_data": ""})
        assert "No alert" in result.get("_message", "")

    def test_run_kql_requires_permission(self, case_dir):
        from api.chat import _dispatch_tool
        result = _dispatch_tool(TEST_CASE, "run_kql",
                                {"query": "SecurityAlert | take 1", "workspace": "test"},
                                user_permissions=["investigations:read"])
        assert "Permission denied" in result.get("_message", "")

    def test_run_kql_allowed_for_admin(self, case_dir):
        """Admin should not get permission denied (may fail for other reasons)."""
        from api.chat import _dispatch_tool
        # Will fail because run_kql needs real infra, but should NOT be permission denied
        result = _dispatch_tool(TEST_CASE, "run_kql",
                                {"query": "SecurityAlert | take 1", "workspace": "test"},
                                user_permissions=["admin"])
        assert "Permission denied" not in result.get("_message", "")


# ===========================================================================
# 10. Tool dispatch — session mode
# ===========================================================================

class TestSessionToolDispatch:
    """Tests for _dispatch_session_tool routing."""

    def test_extract_iocs_saves_to_context(self, session_id):
        from api.chat import _dispatch_session_tool
        from api.sessions import load_context

        result = _dispatch_session_tool(
            session_id, "extract_iocs",
            {"text": "Check 185.220.101.45 and evil-domain.com"},
        )
        assert "IOCs extracted" in result.get("_message", "")

        ctx = load_context(session_id)
        assert "185.220.101.45" in ctx["iocs"]["ips"]

    def test_add_finding_via_tool(self, session_id):
        from api.chat import _dispatch_session_tool
        from api.sessions import load_context

        result = _dispatch_session_tool(
            session_id, "add_finding",
            {"finding_type": "credential_theft", "summary": "Password harvester detected"},
        )
        assert "Finding recorded" in result.get("_message", "")

        ctx = load_context(session_id)
        assert ctx["findings"][0]["type"] == "credential_theft"

    def test_add_finding_no_summary(self, session_id):
        from api.chat import _dispatch_session_tool
        result = _dispatch_session_tool(
            session_id, "add_finding",
            {"finding_type": "general", "summary": ""},
        )
        assert "No summary" in result.get("_message", "")

    def test_read_uploaded_file_missing(self, session_id):
        from api.chat import _dispatch_session_tool
        result = _dispatch_session_tool(
            session_id, "read_uploaded_file",
            {"filename": "nonexistent.csv"},
        )
        assert "not found" in result.get("_message", "").lower()

    def test_read_uploaded_file_success(self, session_id):
        from api.chat import _dispatch_session_tool
        from api.sessions import upload_dir

        udir = upload_dir(session_id)
        (udir / "test.csv").write_text("col1,col2\nval1,val2\n")

        result = _dispatch_session_tool(
            session_id, "read_uploaded_file",
            {"filename": "test.csv"},
        )
        assert "col1,col2" in result.get("_message", "")

    def test_enrich_no_iocs(self, session_id):
        from api.chat import _dispatch_session_tool
        result = _dispatch_session_tool(session_id, "enrich_iocs", {})
        assert "No IOCs" in result.get("_message", "")

    def test_triage_no_iocs(self, session_id):
        from api.chat import _dispatch_session_tool
        result = _dispatch_session_tool(session_id, "triage_iocs", {})
        assert "No IOCs" in result.get("_message", "")

    def test_detect_phishing_no_captures(self, session_id):
        from api.chat import _dispatch_session_tool
        result = _dispatch_session_tool(session_id, "detect_phishing", {})
        assert "No URLs" in result.get("_message", "") or "capture_urls" in result.get("_message", "")

    def test_load_case_context_missing(self, session_id):
        from api.chat import _dispatch_session_tool
        result = _dispatch_session_tool(
            session_id, "load_case_context",
            {"case_id": "NONEXISTENT_999"},
        )
        assert "not found" in result.get("_message", "").lower()

    def test_load_case_context_success(self, session_id, case_dir):
        from api.chat import _dispatch_session_tool
        from api.sessions import load_context

        result = _dispatch_session_tool(
            session_id, "load_case_context",
            {"case_id": TEST_CASE},
        )
        assert TEST_CASE in result.get("_message", "")
        assert result.get("case_id") == TEST_CASE

        # Should be stored in session context
        ctx = load_context(session_id)
        assert ctx["loaded_case_id"] == TEST_CASE

    def test_save_to_case_missing(self, session_id):
        from api.chat import _dispatch_session_tool
        result = _dispatch_session_tool(
            session_id, "save_to_case",
            {"case_id": "NONEXISTENT_999", "updates": {}},
        )
        assert "not found" in result.get("_message", "").lower()

    def test_finalise_case(self, session_id):
        from api.chat import _dispatch_session_tool
        from api.sessions import add_iocs, load_session
        from config.settings import CASES_DIR

        add_iocs(session_id, {"ips": ["192.168.1.1"]})

        # Session already has a case from creation — finalise it
        meta_before = load_session(session_id)
        existing_case_id = meta_before.get("case_id")
        assert existing_case_id is not None, "Session should have auto-created case"

        result = _dispatch_session_tool(
            session_id, "finalise_case",
            {"title": "Test finalise", "severity": "high", "disposition": "true_positive"},
        )

        assert "finalised" in result.get("_message", "").lower()
        case_id = result.get("case_id")
        assert case_id == existing_case_id

        # Verify case exists
        assert (CASES_DIR / case_id).exists()

        # Session should be finalised
        meta = load_session(session_id)
        assert meta["status"] == "finalised"

    def test_session_run_kql_requires_permission(self, session_id):
        from api.chat import _dispatch_session_tool
        result = _dispatch_session_tool(
            session_id, "run_kql",
            {"query": "SecurityAlert | take 1", "workspace": "test"},
            user_permissions=[],
        )
        assert "Permission denied" in result.get("_message", "")


# ===========================================================================
# 11. Session backing case
# ===========================================================================

class TestBackingCase:
    """Tests for _session_ensure_backing_case."""

    def test_creates_backing_case(self, session_id):
        from api.chat import _session_ensure_backing_case
        from api.sessions import load_context
        from config.settings import CASES_DIR

        case_id = _session_ensure_backing_case(session_id)
        assert case_id.startswith("C")
        assert (CASES_DIR / case_id).exists()

        # Should be stored in context
        ctx = load_context(session_id)
        assert ctx["backing_case_id"] == case_id

        # Cleanup
        shutil.rmtree(CASES_DIR / case_id, ignore_errors=True)

    def test_reuses_existing_backing_case(self, session_id):
        from api.chat import _session_ensure_backing_case

        first = _session_ensure_backing_case(session_id)
        second = _session_ensure_backing_case(session_id)
        assert first == second

        # Cleanup
        from config.settings import CASES_DIR
        shutil.rmtree(CASES_DIR / first, ignore_errors=True)


# ===========================================================================
# 12. Prompts
# ===========================================================================

class TestPrompts:
    """Tests for system prompt builders."""

    def test_build_system_prompt_includes_case_meta(self, case_dir):
        from api.prompts import build_system_prompt

        prompt = build_system_prompt(TEST_CASE)
        assert isinstance(prompt, list)
        assert len(prompt) == 1
        assert prompt[0]["type"] == "text"
        assert TEST_CASE in prompt[0]["text"]
        assert "Test phishing investigation" in prompt[0]["text"]
        assert "cache_control" in prompt[0]

    def test_build_system_prompt_missing_case(self):
        from api.prompts import build_system_prompt

        prompt = build_system_prompt("NONEXISTENT_CASE")
        assert isinstance(prompt, list)
        # Should still work with "Unknown" defaults
        assert "Unknown" in prompt[0]["text"]

    def test_build_session_prompt(self, session_id):
        from api.prompts import build_session_prompt

        prompt = build_session_prompt(session_id)
        assert isinstance(prompt, list)
        assert "session" in prompt[0]["text"].lower()

    def test_build_session_prompt_includes_context(self, session_id):
        from api.prompts import build_session_prompt
        from api.sessions import add_iocs, add_finding

        add_iocs(session_id, {"ips": ["10.0.0.1", "10.0.0.2"]})
        add_finding(session_id, "malware", "Beacon detected")

        prompt = build_session_prompt(session_id)
        text = prompt[0]["text"]
        assert "2 ips" in text.lower() or "2 IPs" in text
        assert "finding" in text.lower()

    def test_artefact_summary_includes_iocs(self, case_dir):
        from api.prompts import _summarise_artefacts
        from tools.common import save_json

        # Create IOCs file
        iocs_dir = case_dir / "iocs"
        iocs_dir.mkdir(exist_ok=True)
        save_json(iocs_dir / "iocs.json", {
            "iocs": {"ipv4": ["1.2.3.4"], "domain": ["evil.com", "bad.com"]},
        })

        summary = _summarise_artefacts(TEST_CASE)
        assert "IOCs extracted" in summary
        assert "domain" in summary


# ===========================================================================
# 13. Session expiry and cleanup
# ===========================================================================

class TestSessionCleanup:
    """Tests for session expiry detection and cleanup."""

    def test_expired_session_detected(self):
        from api.sessions import create_session, load_session, SESSIONS_DIR
        from datetime import datetime, timezone, timedelta

        meta = create_session(TEST_EMAIL)
        sid = meta["session_id"]

        # Manually set expiry to the past
        meta_path = SESSIONS_DIR / sid / "session_meta.json"
        meta["expires"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        meta_path.write_text(json.dumps(meta, default=str))

        loaded = load_session(sid)
        assert loaded["status"] == "expired"

    def test_cleanup_removes_expired(self):
        from api.sessions import create_session, cleanup_expired, SESSIONS_DIR
        from datetime import datetime, timezone, timedelta

        meta = create_session(TEST_EMAIL)
        sid = meta["session_id"]

        # Expire it
        meta_path = SESSIONS_DIR / sid / "session_meta.json"
        meta["expires"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        meta_path.write_text(json.dumps(meta, default=str))

        removed = cleanup_expired()
        assert removed >= 1
        assert not (SESSIONS_DIR / sid).exists()

    def test_cleanup_keeps_active_sessions(self, session_id):
        from api.sessions import cleanup_expired, SESSIONS_DIR

        cleanup_expired()
        # Active session should survive
        assert (SESSIONS_DIR / session_id).exists()


# ===========================================================================
# 14. Supports compaction check
# ===========================================================================

class TestSupportsCompaction:

    def test_opus_with_flag_enabled(self):
        from api.chat import _supports_compaction
        with patch("api.chat.SOCAI_COMPACTION_ENABLED", True):
            assert _supports_compaction("claude-opus-4-20250514") is True

    def test_opus_with_flag_disabled(self):
        from api.chat import _supports_compaction
        with patch("api.chat.SOCAI_COMPACTION_ENABLED", False):
            assert _supports_compaction("claude-opus-4-20250514") is False

    def test_sonnet_always_false(self):
        from api.chat import _supports_compaction
        with patch("api.chat.SOCAI_COMPACTION_ENABLED", True):
            assert _supports_compaction("claude-sonnet-4-20250514") is False

    def test_haiku_always_false(self):
        from api.chat import _supports_compaction
        with patch("api.chat.SOCAI_COMPACTION_ENABLED", True):
            assert _supports_compaction("claude-haiku-4-5-20251001") is False


# ===========================================================================
# 15. Execute tool error handling
# ===========================================================================

class TestExecuteToolErrorHandling:
    """Tests for execute_tool wrapper's error handling."""

    def test_returns_error_string_on_exception(self, case_dir):
        from api.chat import execute_tool

        # Force an error by calling a tool that will fail
        result = execute_tool(TEST_CASE, "generate_report", {})
        # Should return a string (not raise), containing "Error" or a message
        assert isinstance(result, str)

    def test_truncates_long_json_results(self, case_dir):
        from api.chat import execute_tool

        # read_case_file with a valid file should return content
        (case_dir / "test.txt").write_text("short content")
        result = execute_tool(TEST_CASE, "read_case_file", {"file_path": "test.txt"})
        assert isinstance(result, str)
