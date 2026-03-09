"""
Log Correlator Agent
--------------------
Parses all submitted log files and runs correlation against IOCs.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.correlate import correlate
from tools.parse_logs import parse_logs


class LogCorrelatorAgent(BaseAgent):
    name = "log_correlator"

    def run(self, log_paths: list[str] | None = None, **kwargs) -> dict:
        parse_results = []
        for lp in (log_paths or []):
            self._emit("parsing_log", {"path": lp})
            res = parse_logs(lp, self.case_id)
            parse_results.append(res)

        self._emit("correlating", {})
        corr = correlate(self.case_id)

        self._emit("complete", {
            "logs_parsed": len(parse_results),
            "llm_insight": bool(corr.get("llm_insight")),
        })
        return {"log_parses": parse_results, "correlation": corr}
