"""
Sandbox Detonation Agent
------------------------
Thin orchestration agent for local malware sandbox detonation.
Starts a containerised sandbox session, waits for completion,
collects artefacts, and triggers LLM analysis of telemetry.

Used by chief.py step 6b when --detonate is set and cloud sandbox
lookups return no definitive results.
"""
from __future__ import annotations

import json
import logging
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_model, log_error, save_json, utcnow

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

        # LLM analysis of telemetry
        analysis = self._analyse_telemetry(stop_result)
        if analysis:
            art_dir = CASES_DIR / self.case_id / "artefacts" / "sandbox_detonation"
            save_json(art_dir / "llm_analysis.json", analysis)

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
            "llm_analysis": analysis,
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

    def _analyse_telemetry(self, stop_result: dict) -> dict | None:
        """Use LLM to analyse collected sandbox telemetry."""
        if not ANTHROPIC_KEY:
            return None

        art_dir = CASES_DIR / self.case_id / "artefacts" / "sandbox_detonation"
        if not art_dir.exists():
            return None

        # Collect telemetry summaries for the LLM
        context_parts = []

        for filename in ["sandbox_manifest.json", "strace_log.json", "network_log.json",
                         "honeypot_log.json", "process_tree.json", "filesystem_changes.json",
                         "dns_queries.json", "strings_extracted.json"]:
            p = art_dir / filename
            if p.exists():
                text = p.read_text(errors="replace")
                # Truncate large files
                if len(text) > 10000:
                    text = text[:10000] + "\n... (truncated)"
                context_parts.append(f"=== {filename} ===\n{text}")

        if not context_parts:
            return None

        telemetry_text = "\n\n".join(context_parts)

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
            model = get_model("sandbox_detonation", stop_result.get("severity", "medium"))

            response = client.messages.create(
                model=model,
                max_tokens=4096,
                messages=[{
                    "role": "user",
                    "content": (
                        "Analyse the following malware sandbox detonation telemetry. "
                        "Provide:\n"
                        "1. **Behavioural summary** — what the sample did at runtime\n"
                        "2. **MITRE ATT&CK mapping** — TTPs observed (ID + name)\n"
                        "3. **IOC extraction** — C2 IPs/domains, dropped file hashes, "
                        "registry keys, mutexes\n"
                        "4. **Behavioural classification** — trojan, ransomware, worm, "
                        "RAT, downloader, etc.\n"
                        "5. **Risk score** — 0-100 with justification\n"
                        "6. **Recommended response actions**\n\n"
                        "Return valid JSON with keys: summary, mitre_ttps (array of "
                        "{id, name, evidence}), iocs (object with arrays: ips, domains, "
                        "urls, hashes, mutexes, registry_keys), classification, "
                        "risk_score (int), risk_justification, response_actions (array).\n\n"
                        f"Telemetry:\n{telemetry_text}"
                    ),
                }],
            )

            # Parse JSON from response
            response_text = response.content[0].text
            # Try to extract JSON from the response
            try:
                analysis = json.loads(response_text)
            except json.JSONDecodeError:
                # Try to find JSON block in markdown
                import re
                json_match = re.search(r"```(?:json)?\s*\n(.*?)\n```", response_text, re.DOTALL)
                if json_match:
                    analysis = json.loads(json_match.group(1))
                else:
                    analysis = {"raw_analysis": response_text}

            analysis["analysed_at"] = utcnow()
            analysis["model"] = model
            return analysis

        except Exception as exc:
            log_error(self.case_id, "sandbox_detonation.llm_analysis", str(exc),
                      severity="warning", traceback=traceback.format_exc())
            return None
