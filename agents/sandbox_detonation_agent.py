"""
Sandbox Detonation Agent
------------------------
Thin orchestration agent for local malware sandbox detonation.
Starts a containerised sandbox session, waits for completion,
and collects artefacts.  Raw telemetry is saved for analyst review
via Claude Desktop agent — no embedded LLM call.

Used by chief.py step 6b when --detonate is set and cloud sandbox
lookups return no definitive results.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from config.settings import CASES_DIR
from tools.common import save_json, utcnow

logger = logging.getLogger("socai.sandbox_detonation")


class SandboxDetonationAgent(BaseAgent):
    name = "sandbox_detonation"

    def run(self, sample_path: str | None = None, **kwargs) -> dict:
        """Execute local sandbox detonation and analyse results.

        Parameters
        ----------
        sample_path : str | None
            Path to the sample to detonate. If None, attempts to locate
            the primary sample from the case's artefacts.
        """
        from tools.sandbox_session import (
            start_session,
            stop_session,
            wait_for_completion,
        )

        timeout = kwargs.get("timeout", 120)
        network_mode = kwargs.get("network_mode", "monitor")

        # Find sample
        if not sample_path:
            sample_path = self._find_primary_sample()
        if not sample_path or not Path(sample_path).exists():
            self._emit("skip", {"reason": "No sample found for detonation"})
            return {"status": "no_sample", "case_id": self.case_id}

        self._emit("starting", {
            "sample": str(sample_path),
            "timeout": timeout,
            "network_mode": network_mode,
        })

        # Start session
        result = start_session(
            sample_path,
            self.case_id,
            timeout=timeout,
            network_mode=network_mode,
            interactive=False,
        )

        if result.get("status") != "ok":
            self._emit("error", {"reason": result.get("reason", "start failed")})
            return {"status": "error", "reason": result.get("reason", "start failed")}

        session_id = result["session_id"]
        self._emit("executing", {"session_id": session_id})

        # Wait for completion
        completed = wait_for_completion(session_id)
        if not completed:
            logger.warning("Sandbox %s did not complete within timeout — force stopping", session_id)

        # Stop and collect artefacts
        stop_result = stop_session(session_id)

        if stop_result.get("status") != "ok":
            self._emit("error", {"reason": stop_result.get("reason", "stop failed")})
            return {"status": "error", "reason": stop_result.get("reason", "stop failed")}

        self._emit("collected", {
            "artefacts": len(stop_result.get("artefacts", {})),
            "duration": stop_result.get("duration_seconds", 0),
        })

        # Save raw telemetry summary for analyst review
        telemetry = self._collect_telemetry(stop_result)
        if telemetry:
            art_dir = CASES_DIR / self.case_id / "artefacts" / "sandbox_detonation"
            save_json(art_dir / "telemetry_summary.json", telemetry)

        self._emit("complete", {
            "session_id": session_id,
            "duration": stop_result.get("duration_seconds", 0),
            "entities": stop_result.get("entities_summary", {}),
        })

        return {
            "status": "ok",
            "case_id": self.case_id,
            "session_id": session_id,
            "duration_seconds": stop_result.get("duration_seconds", 0),
            "artefacts": stop_result.get("artefacts", {}),
            "entities_summary": stop_result.get("entities_summary", {}),
            "llm_analysis": "removed — review telemetry via Claude Desktop agent",
        }

    def _find_primary_sample(self) -> str | None:
        """Locate the most likely sample to detonate from case artefacts."""
        case_dir = CASES_DIR / self.case_id

        # Check extracted ZIP contents
        zip_dir = case_dir / "artefacts" / "zip"
        if zip_dir.exists():
            for f in sorted(zip_dir.rglob("*"), key=lambda p: p.stat().st_size, reverse=True):
                if f.is_file() and f.suffix.lower() in (
                    ".exe", ".dll", ".scr", ".elf", ".sh", ".py", ".ps1",
                    ".bat", ".vbs", ".js", ".bin", "",
                ):
                    return str(f)
            # If no known extension, take the largest file
            files = [f for f in zip_dir.rglob("*") if f.is_file()]
            if files:
                return str(max(files, key=lambda p: p.stat().st_size))

        # Check uploads directory
        uploads_dir = case_dir / "uploads"
        if uploads_dir.exists():
            for f in sorted(uploads_dir.rglob("*"), key=lambda p: p.stat().st_size, reverse=True):
                if f.is_file():
                    return str(f)

        return None

    def _collect_telemetry(self, stop_result: dict) -> dict | None:
        """Collect sandbox telemetry summaries for analyst review.

        Returns a dict of filename -> content for each telemetry artefact,
        or None if no artefacts exist.
        """
        art_dir = CASES_DIR / self.case_id / "artefacts" / "sandbox_detonation"
        if not art_dir.exists():
            return None

        telemetry_files = {}

        for filename in ["sandbox_manifest.json", "strace_log.json", "network_log.json",
                         "honeypot_log.json", "process_tree.json", "filesystem_changes.json",
                         "dns_queries.json", "strings_extracted.json"]:
            p = art_dir / filename
            if p.exists():
                try:
                    telemetry_files[filename] = json.loads(p.read_text(errors="replace"))
                except json.JSONDecodeError:
                    telemetry_files[filename] = p.read_text(errors="replace")

        if not telemetry_files:
            return None

        return {
            "collected_at": utcnow(),
            "case_id": self.case_id,
            "files": telemetry_files,
            "entities_summary": stop_result.get("entities_summary", {}),
            "duration_seconds": stop_result.get("duration_seconds", 0),
        }
