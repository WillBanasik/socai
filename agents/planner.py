"""
Planner Agent
-------------
Inspects the case intake parameters and produces an ordered task plan
(which tools to run and in what order).  The Chief agent uses this plan.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent


class PlannerAgent(BaseAgent):
    name = "planner"

    def run(
        self,
        urls: list[str] | None = None,
        zip_path: str | None = None,
        zip_pass: str | None = None,
        log_paths: list[str] | None = None,
        **kwargs,
    ) -> dict:
        """
        Build a linear task list based on what inputs are provided.
        Returns a dict with 'steps' (ordered list of tool names and args).
        """
        steps: list[dict] = []

        # Always create the case first
        steps.append({"tool": "case_create", "args": {}})

        # Web captures
        for url in (urls or []):
            steps.append({"tool": "web_capture", "args": {"url": url}})

        # ZIP extraction
        if zip_path:
            steps.append({
                "tool": "extract_zip",
                "args": {"zip_path": zip_path, "password": zip_pass},
            })
            steps.append({"tool": "static_file_analyse", "args": {"source": "zip"}})

        # Log parsing
        for lp in (log_paths or []):
            steps.append({"tool": "parse_logs", "args": {"log_path": lp}})

        # Always extract IOCs and correlate
        steps.append({"tool": "extract_iocs", "args": {}})
        steps.append({"tool": "enrich",        "args": {}})
        steps.append({"tool": "correlate",     "args": {}})
        steps.append({"tool": "generate_report", "args": {}})
        steps.append({"tool": "index_case",    "args": {"status": "open"}})

        plan = {
            "case_id": self.case_id,
            "steps":   steps,
            "total":   len(steps),
        }
        self._emit("plan_created", {"steps": len(steps)})
        return plan
