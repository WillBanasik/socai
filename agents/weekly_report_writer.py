"""
Weekly Report Writer Agent
---------------------------
Generates the weekly rollup report on demand.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.generate_weekly_report import generate_weekly_report


class WeeklyReportWriterAgent(BaseAgent):
    name = "weekly_report_writer"

    def run(
        self,
        year: int | None = None,
        week: int | None = None,
        include_open: bool = False,
        **kwargs,
    ) -> dict:
        self._emit("generating", {"year": year, "week": week})
        result = generate_weekly_report(year, week, include_open)
        self._emit("complete", {"report": result.get("report_path")})
        return result
