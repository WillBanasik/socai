"""
FP Comms Agent
--------------
Thin wrapper around the fp_ticket tool.  Called via `socai.py fp-ticket`.

Generates a False Positive suppression ticket for a completed investigation,
with platform-specific recommendations for rule/policy tuning.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.fp_ticket import fp_ticket


class FPCommsAgent(BaseAgent):
    name = "fp_comms"

    def run(
        self,
        alert_data: str = "",
        query_text: str | None = None,
        platform: str | None = None,
        live_query: bool = False,
        **kwargs,
    ) -> dict:
        self._emit("starting_ticket", {
            "platform_override": platform or "auto",
            "live_query": live_query,
        })
        result = fp_ticket(
            self.case_id,
            alert_data=alert_data,
            query_text=query_text,
            platform=platform,
            live_query=live_query,
        )
        status = result.get("status", "unknown")
        if status == "ok":
            self._emit("complete", {"ticket_path": result.get("ticket_path")})
        elif status == "needs_clarification":
            self._emit("needs_clarification", {"question": result.get("question")})
        else:
            self._emit("skipped", {"reason": result.get("reason", "")})
        return result
