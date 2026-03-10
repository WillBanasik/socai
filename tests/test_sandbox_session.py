"""
Tests for tools/sandbox_session.py — sandbox detonation session management.

All tests use mocked Docker (no Docker required in CI).
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).parent / "fixtures"
TEST_CASE = "TEST_AUTOMATED_001"


@pytest.fixture(autouse=True)
def cleanup_test_case():
    """Remove the test case and sandbox sessions before and after each test."""
    from config.settings import CASES_DIR

    created_sessions: list[str] = []

    def _rm():
        case_dir = CASES_DIR / TEST_CASE
        if case_dir.exists():
            shutil.rmtree(case_dir, ignore_errors=True)
        # Clean sandbox session state (both hardcoded sbx_test_* and any created during test)
        from tools.sandbox_session import SESSIONS_DIR
        if SESSIONS_DIR.exists():
            for f in SESSIONS_DIR.glob("sbx_test_*"):
                f.unlink(missing_ok=True)
            for sid in created_sessions:
                (SESSIONS_DIR / f"{sid}.json").unlink(missing_ok=True)

    _rm()
    yield created_sessions
    _rm()


# ---------------------------------------------------------------------------
# Sample type detection
# ---------------------------------------------------------------------------

class TestDetectSampleType:
    def test_elf(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "sample"
        p.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert _detect_sample_type(p) == "elf"

    def test_pe(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "sample.exe"
        p.write_bytes(b"MZ" + b"\x00" * 100)
        assert _detect_sample_type(p) == "pe"

    def test_script_shebang(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "sample.sh"
        p.write_bytes(b"#!/bin/bash\necho hello")
        assert _detect_sample_type(p) == "script"

    def test_zip_archive(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "sample.zip"
        p.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        assert _detect_sample_type(p) == "archive_zip"

    def test_gzip_archive(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "sample.gz"
        p.write_bytes(b"\x1f\x8b" + b"\x00" * 100)
        assert _detect_sample_type(p) == "archive_gzip"

    def test_unknown_binary(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "sample.bin"
        p.write_bytes(b"\xDE\xAD\xBE\xEF" + b"\x00" * 100)
        assert _detect_sample_type(p) == "unknown"

    def test_extension_fallback_py(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "sample.py"
        p.write_text("import os\nos.system('echo pwned')")
        assert _detect_sample_type(p) == "script"

    def test_extension_fallback_exe(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "sample.exe"
        p.write_bytes(b"\x00" * 100)  # Not real PE magic but .exe extension
        assert _detect_sample_type(p) == "pe"

    def test_missing_file(self, tmp_path):
        from tools.sandbox_session import _detect_sample_type
        p = tmp_path / "nonexistent"
        assert _detect_sample_type(p) == "unknown"


class TestNeedsWine:
    def test_pe_needs_wine(self, tmp_path):
        from tools.sandbox_session import _needs_wine
        p = tmp_path / "malware.exe"
        p.write_bytes(b"MZ" + b"\x00" * 100)
        assert _needs_wine(p) is True

    def test_elf_no_wine(self, tmp_path):
        from tools.sandbox_session import _needs_wine
        p = tmp_path / "malware"
        p.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert _needs_wine(p) is False


# ---------------------------------------------------------------------------
# Session state round-trip
# ---------------------------------------------------------------------------

class TestSessionState:
    def test_save_and_load(self):
        from tools.sandbox_session import _save_session, _load_session, SESSIONS_DIR

        state = {
            "session_id": "sbx_test_roundtrip",
            "case_id": TEST_CASE,
            "status": "active",
            "sample_name": "test.elf",
        }
        _save_session(state)

        loaded = _load_session("sbx_test_roundtrip")
        assert loaded is not None
        assert loaded["session_id"] == "sbx_test_roundtrip"
        assert loaded["case_id"] == TEST_CASE
        assert loaded["status"] == "active"

        # Cleanup
        (SESSIONS_DIR / "sbx_test_roundtrip.json").unlink(missing_ok=True)

    def test_load_nonexistent(self):
        from tools.sandbox_session import _load_session
        assert _load_session("sbx_nonexistent_99999") is None


# ---------------------------------------------------------------------------
# Strace parsing (from monitor.py)
# ---------------------------------------------------------------------------

class TestStraceParsing:
    def test_parse_strace_basic(self, tmp_path):
        import docker.sandbox.monitor as monitor_mod
        orig = monitor_mod.TELEMETRY
        monitor_mod.TELEMETRY = tmp_path

        strace_log = tmp_path / "strace_raw.log"
        strace_log.write_text(
            '1234 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n'
            '1234 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0\n'
            '1234 clone(child_stack=NULL, flags=CLONE_VM) = 5678\n'
            '1234 read(3, "data", 4096) = 4\n'
        )
        output = tmp_path / "strace_parsed.jsonl"
        monitor_mod.parse_strace(strace_log, output)

        lines = output.read_text().strip().splitlines()
        records = [json.loads(l) for l in lines]

        # Should have openat (file), connect (network), clone (process)
        # read is "other" and not in the interesting set, so skipped
        assert len(records) == 3
        categories = {r["category"] for r in records}
        assert "file" in categories
        assert "network" in categories
        assert "process" in categories

        monitor_mod.TELEMETRY = orig

    def test_parse_strace_empty(self, tmp_path):
        import docker.sandbox.monitor as monitor_mod
        orig = monitor_mod.TELEMETRY
        monitor_mod.TELEMETRY = tmp_path

        strace_log = tmp_path / "strace_raw.log"
        strace_log.write_text("")
        output = tmp_path / "strace_parsed.jsonl"
        monitor_mod.parse_strace(strace_log, output)

        assert output.read_text() == ""

        monitor_mod.TELEMETRY = orig

    def test_parse_strace_missing_file(self, tmp_path):
        from docker.sandbox.monitor import parse_strace

        output = tmp_path / "strace_parsed.jsonl"
        parse_strace(tmp_path / "nonexistent.log", output)
        assert not output.exists()


# ---------------------------------------------------------------------------
# Filesystem diff logic (from monitor.py)
# ---------------------------------------------------------------------------

class TestSystemChanges:
    def test_detect_new_files(self, tmp_path):
        from docker.sandbox.monitor import detect_system_changes, TELEMETRY

        # Temporarily override TELEMETRY
        import docker.sandbox.monitor as monitor_mod
        orig = monitor_mod.TELEMETRY
        monitor_mod.TELEMETRY = tmp_path

        (tmp_path / "fs_before.txt").write_text("/sandbox/workspace/sample\n")
        (tmp_path / "fs_after.txt").write_text(
            "/sandbox/workspace/sample\n/sandbox/workspace/dropped.exe\n"
        )

        output = tmp_path / "system_changes.json"
        detect_system_changes(output)

        data = json.loads(output.read_text())
        assert "/sandbox/workspace/dropped.exe" in data["new_files"]

        monitor_mod.TELEMETRY = orig


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------

class TestEntityExtraction:
    def test_extract_strings_finds_ips_and_urls(self, tmp_path):
        from tools.sandbox_session import _extract_strings

        stdout_log = tmp_path / "stdout.log"
        stdout_log.write_text(
            "Connecting to 192.168.1.100:4444\n"
            "Downloading from https://evil.com/payload.bin\n"
            "Resolved c2.malware.net\n"
        )
        result = _extract_strings(tmp_path)
        assert "192.168.1.100" in result["ips"]
        assert any("evil.com" in u for u in result["urls"])
        assert "c2.malware.net" in result["domains"]

    def test_extract_dns_queries(self, tmp_path):
        from tools.sandbox_session import _extract_dns_queries

        # Write honeypot log
        hp_log = tmp_path / "honeypot_log.jsonl"
        hp_log.write_text(
            json.dumps({"type": "dns", "domain": "c2.evil.com", "ts": "2026-01-01T00:00:00Z"}) + "\n"
            + json.dumps({"type": "http", "path": "/beacon"}) + "\n"
        )

        # Write network parsed
        net_parsed = tmp_path / "network_parsed.json"
        net_parsed.write_text(json.dumps({
            "dns_queries": [{"query": "another.bad.net", "src": "10.0.0.1"}],
            "tcp_connections": [],
            "http_requests": [],
        }))

        queries = _extract_dns_queries(tmp_path)
        domains = {q["domain"] for q in queries}
        assert "c2.evil.com" in domains
        assert "another.bad.net" in domains


# ---------------------------------------------------------------------------
# Start session (mocked Docker)
# ---------------------------------------------------------------------------

class TestStartSession:
    @patch("tools.sandbox_session.subprocess.run")
    def test_start_session_success(self, mock_run, tmp_path, cleanup_test_case):
        from tools.sandbox_session import start_session

        sample = tmp_path / "test.elf"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 100)

        # Mock docker run
        mock_run.return_value = MagicMock(
            stdout="abc123def456\n",
            stderr="",
            returncode=0,
        )

        result = start_session(str(sample), TEST_CASE, timeout=30)

        assert result["status"] == "ok"
        assert result["session_id"].startswith("sbx_")
        assert result["sample_type"] == "elf"
        assert result["case_id"] == TEST_CASE

        # Track for cleanup
        cleanup_test_case.append(result["session_id"])

    def test_start_session_missing_sample(self):
        from tools.sandbox_session import start_session

        result = start_session("/nonexistent/path", TEST_CASE)
        assert result["status"] == "error"
        assert "not found" in result["reason"]


# ---------------------------------------------------------------------------
# Stop session (mocked Docker)
# ---------------------------------------------------------------------------

class TestStopSession:
    @patch("tools.sandbox_session._stop_container")
    @patch("tools.sandbox_session._copy_telemetry_from_container")
    def test_stop_session_success(self, mock_copy, mock_stop, tmp_path):
        from tools.sandbox_session import _save_session, stop_session
        from config.settings import CASES_DIR

        session_id = "sbx_test_stop_001"
        case_dir = CASES_DIR / TEST_CASE
        case_dir.mkdir(parents=True, exist_ok=True)

        _save_session({
            "session_id": session_id,
            "case_id": TEST_CASE,
            "status": "active",
            "sample_name": "test.elf",
            "sample_sha256": "abc123",
            "sample_type": "elf",
            "image": "socai-sandbox:latest",
            "network_mode": "monitor",
            "interactive": False,
            "timeout": 30,
            "started_at": "2026-01-01T00:00:00Z",
            "interactive_log": [],
        })

        # Mock telemetry copy to return empty (no telemetry in test)
        mock_copy.return_value = {}

        result = stop_session(session_id)
        assert result["status"] == "ok"
        assert result["session_id"] == session_id
        mock_stop.assert_called_once_with(session_id)

    def test_stop_nonexistent_session(self):
        from tools.sandbox_session import stop_session

        result = stop_session("sbx_nonexistent_99999")
        assert result["status"] == "error"
        assert "not found" in result["reason"]


# ---------------------------------------------------------------------------
# Exec in sandbox (mocked Docker)
# ---------------------------------------------------------------------------

class TestExecInSandbox:
    @patch("tools.sandbox_session._is_container_running", return_value=True)
    @patch("tools.sandbox_session.subprocess.run")
    def test_exec_success(self, mock_run, mock_running):
        from tools.sandbox_session import _save_session, exec_in_sandbox

        session_id = "sbx_test_exec_001"
        _save_session({
            "session_id": session_id,
            "case_id": TEST_CASE,
            "status": "active",
            "interactive": True,
            "interactive_log": [],
        })

        mock_run.return_value = MagicMock(
            stdout="root     1  0.0  0.0      0     0 ?        S    00:00   0:00 /sbin/init\n",
            stderr="",
            returncode=0,
        )

        result = exec_in_sandbox(session_id, "ps aux")
        assert result["status"] == "ok"
        assert "/sbin/init" in result["stdout"]

    def test_exec_non_interactive(self):
        from tools.sandbox_session import _save_session, exec_in_sandbox

        session_id = "sbx_test_exec_002"
        _save_session({
            "session_id": session_id,
            "case_id": TEST_CASE,
            "status": "active",
            "interactive": False,
        })

        result = exec_in_sandbox(session_id, "ls")
        assert result["status"] == "error"
        assert "interactive" in result["reason"].lower()

    def test_exec_inactive_session(self):
        from tools.sandbox_session import _save_session, exec_in_sandbox

        session_id = "sbx_test_exec_003"
        _save_session({
            "session_id": session_id,
            "case_id": TEST_CASE,
            "status": "completed",
            "interactive": True,
        })

        result = exec_in_sandbox(session_id, "ls")
        assert result["status"] == "error"
        assert "not active" in result["reason"].lower()


# ---------------------------------------------------------------------------
# List sessions
# ---------------------------------------------------------------------------

class TestListSessions:
    @patch("tools.sandbox_session._is_container_running", return_value=False)
    def test_list_empty(self, mock_running):
        from tools.sandbox_session import list_sessions
        # Should not crash with empty/nonexistent sessions dir
        sessions = list_sessions()
        assert isinstance(sessions, list)

    @patch("tools.sandbox_session._is_container_running", return_value=True)
    def test_list_with_sessions(self, mock_running):
        from tools.sandbox_session import _save_session, list_sessions

        _save_session({
            "session_id": "sbx_test_list_001",
            "case_id": TEST_CASE,
            "status": "active",
            "sample_name": "test.elf",
            "sample_type": "elf",
            "network_mode": "monitor",
            "started_at": "2026-01-01T00:00:00Z",
        })

        sessions = list_sessions()
        matching = [s for s in sessions if s["session_id"] == "sbx_test_list_001"]
        assert len(matching) == 1
        assert matching[0]["status"] == "active"


# ---------------------------------------------------------------------------
# Integration: artefact collection (mocked container, real file writes)
# ---------------------------------------------------------------------------

class TestArtefactCollection:
    def test_collect_artefacts_from_telemetry(self, tmp_path):
        from tools.sandbox_session import _collect_artefacts
        from config.settings import CASES_DIR

        case_dir = CASES_DIR / TEST_CASE
        case_dir.mkdir(parents=True, exist_ok=True)

        # Create mock telemetry
        telemetry_dir = tmp_path / "telemetry"
        telemetry_dir.mkdir()

        # Strace parsed JSONL
        (telemetry_dir / "strace_parsed.jsonl").write_text(
            json.dumps({"pid": 1, "syscall": "openat", "category": "file", "args": "/etc/passwd", "return": "3"}) + "\n"
        )

        # Network parsed
        (telemetry_dir / "network_parsed.json").write_text(json.dumps({
            "dns_queries": [{"query": "evil.com", "src": "10.0.0.1"}],
            "tcp_connections": [{"src_ip": "10.0.0.2", "src_port": 12345, "dst_ip": "1.2.3.4", "dst_port": 443}],
            "http_requests": [{"method": "GET", "path": "/beacon"}],
        }))

        # Honeypot log
        (telemetry_dir / "honeypot_log.jsonl").write_text(
            json.dumps({"type": "dns", "domain": "c2.evil.com", "ts": "2026-01-01T00:00:00Z"}) + "\n"
        )

        # Process tree
        (telemetry_dir / "process_tree.jsonl").write_text(
            json.dumps({"ts": "2026-01-01T00:00:00Z", "pid": 100, "ppid": 1, "exe": "/tmp/malware", "cmdline": "/tmp/malware"}) + "\n"
        )

        # System changes
        (telemetry_dir / "system_changes.json").write_text(json.dumps({
            "new_files": ["/sandbox/workspace/dropped.txt"],
            "modified_system_files": [],
            "crontab_changes": [],
            "user_changes": [],
        }))

        artefacts = _collect_artefacts("sbx_test_artefacts", TEST_CASE, telemetry_dir)

        assert "strace_log" in artefacts
        assert "network_log" in artefacts
        assert "honeypot_log" in artefacts
        assert "process_tree" in artefacts
        assert "filesystem_changes" in artefacts
        assert "dns_queries" in artefacts

        # Verify files exist on disk
        art_dir = CASES_DIR / TEST_CASE / "artefacts" / "sandbox_detonation"
        assert (art_dir / "strace_log.json").exists()
        assert (art_dir / "network_log.json").exists()
