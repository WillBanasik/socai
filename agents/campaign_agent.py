"""
Campaign Agent
--------------
Groups cases sharing IOCs into campaigns using connected components.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.campaign_cluster import cluster_campaigns


class CampaignAgent(BaseAgent):
    name = "campaign"

    def run(self, **kwargs) -> dict:
        self._emit("clustering", {})
        result = cluster_campaigns(case_id=self.case_id)
        campaigns = result.get("campaigns", [])
        narratives = sum(1 for c in campaigns if c.get("narrative"))
        self._emit("complete", {
            "campaigns_found": result.get("total", 0),
            "llm_narratives": narratives,
        })
        return result
