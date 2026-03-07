"""
Triage Agent
------------
Pre-pipeline check of input IOCs against existing intelligence sources.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.triage import triage


class TriageAgent(BaseAgent):
    name = "triage"

    def run(self, urls: list[str] | None = None, severity: str = "medium", **kwargs) -> dict:
        self._emit("triaging", {"url_count": len(urls or [])})
        result = triage(self.case_id, urls=urls, severity=severity)
        self._emit("complete", {
            "malicious": len(result.get("known_malicious", [])),
            "suspicious": len(result.get("known_suspicious", [])),
            "skip_enrichment": len(result.get("skip_enrichment_iocs", [])),
            "escalate": result.get("escalate_severity"),
        })
        return result
