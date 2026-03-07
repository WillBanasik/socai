"""
Query Gen Agent
---------------
Generates SIEM hunt queries from a case's IOCs and threat patterns
detected in the investigation report.

Supports KQL (Sentinel/Defender), Splunk SPL, and LogScale/Falcon.
Writes output to cases/<case_id>/artefacts/queries/hunt_queries.md
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.generate_queries import generate_queries


class QueryGenAgent(BaseAgent):
    name = "query_gen"

    def run(
        self,
        platforms: list[str] | None = None,
        tables: list[str] | None = None,
        **kwargs,
    ) -> dict:
        self._emit("generating", {"platforms": platforms, "tables": tables})
        result = generate_queries(self.case_id, platforms=platforms, tables=tables)
        self._emit("complete", {
            "query_path": result.get("query_path"),
            "patterns":   result.get("patterns", []),
            "ioc_counts": result.get("ioc_counts", {}),
        })
        return result
