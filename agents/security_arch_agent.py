"""
Security Architecture Agent
----------------------------
Produces an LLM-assisted security architecture review for a completed
investigation, mapping observed threat activity to actionable control
recommendations across the Microsoft security stack and CrowdStrike Falcon.

Runs after ReportWriterAgent so the full investigation report is available
as context. Writes output to:
  cases/<case_id>/artefacts/security_architecture/security_arch_review.md

The agent is skipped gracefully (no error) when ANTHROPIC_API_KEY is not
configured or when no case artefacts are present.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.security_arch_review import security_arch_review


class SecurityArchAgent(BaseAgent):
    name = "security_arch"

    def run(self, **kwargs) -> dict:
        self._emit("starting_review", {})
        result = security_arch_review(self.case_id)

        status = result.get("status", "unknown")
        if status == "ok":
            self._emit("complete", {
                "review_path": result.get("review_path"),
                "tokens_in":   result.get("tokens_in", 0),
                "tokens_out":  result.get("tokens_out", 0),
            })
        else:
            self._emit("skipped", {"reason": result.get("reason", "")})

        return result
