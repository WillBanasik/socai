"""
Response Actions Agent
-----------------------
Thin wrapper around the response_actions tool. Generates a client-specific
response plan based on investigation evidence and the client's approved
escalation matrix.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent


class ResponseActionsAgent(BaseAgent):
    name = "response_actions"

    def run(self, **kwargs) -> dict:
        from tools.response_actions import generate_response_actions

        self._emit("starting", {"case_id": self.case_id})
        result = generate_response_actions(self.case_id)
        self._emit("complete" if result.get("status") == "ok" else "skipped", result)
        return result
