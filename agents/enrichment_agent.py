"""
Enrichment Agent
----------------
Runs the enrichment tool against extracted IOCs.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.enrich import enrich
from tools.extract_iocs import extract_iocs
from tools.score_verdicts import score_verdicts, update_ioc_index


class EnrichmentAgent(BaseAgent):
    name = "enrichment"

    def run(self, include_private: bool = False, skip_iocs: set[str] | None = None, **kwargs) -> dict:
        self._emit("extracting_iocs", {})
        ioc_result = extract_iocs(self.case_id, include_private=include_private)

        ioc_total = ioc_result.get("total", {})
        self._emit("enriching", {"ioc_count": sum(ioc_total.values()) if isinstance(ioc_total, dict) else ioc_total})
        enrich_result = enrich(self.case_id, skip_iocs=skip_iocs)

        self._emit("scoring_verdicts", {})
        verdict_result = score_verdicts(self.case_id)

        self._emit("updating_ioc_index", {})
        index_result = update_ioc_index(self.case_id)

        self._emit("complete", {
            "enrichments":    enrich_result.get("total_lookups", 0),
            "iocs_scored":    verdict_result.get("ioc_count", 0),
            "malicious":      len(verdict_result.get("high_priority", [])),
            "suspicious":     len(verdict_result.get("needs_review", [])),
            "recurring_iocs": index_result.get("recurring_iocs", 0),
        })
        return {
            "iocs":        ioc_result,
            "enrichment":  enrich_result,
            "verdicts":    verdict_result,
            "ioc_index":   index_result,
        }
