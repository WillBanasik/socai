"""
Sandbox Agent
-------------
Queries sandbox APIs for dynamic analysis of file hashes.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.sandbox_analyse import sandbox_analyse


class SandboxAgent(BaseAgent):
    name = "sandbox"

    def run(self, detonate: bool = False, **kwargs) -> dict:
        self._emit("analysing", {"detonate": detonate})
        result = sandbox_analyse(self.case_id, detonate=detonate)
        self._emit("complete", {
            "hashes_checked": result.get("hashes_checked", 0),
            "ok_results": result.get("ok_results", 0),
            "sandbox_iocs": len(result.get("sandbox_iocs", [])),
        })
        return result
