"""
Report Writer Agent
--------------------
Triggers report generation and final case indexing.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.generate_report import generate_report
from tools.index_case import index_case


class ReportWriterAgent(BaseAgent):
    name = "report_writer"

    def run(self, close_case: bool = False, auto_disposition: str | None = None, **kwargs) -> dict:
        self._emit("generating_report", {})
        result = generate_report(self.case_id)

        final_status = "closed" if close_case else "open"
        self._emit("indexing_case", {"status": final_status})
        index_case(
            self.case_id,
            status=final_status,
            report_path=result["report_path"],
            disposition=auto_disposition,
        )

        self._emit("complete", {"report": result["report_path"]})
        return result
