"""
Domain Investigator Agent
--------------------------
Drives web capture for all URLs/domains in the case.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from config.settings import BROWSER_BACKEND
from tools.web_capture import web_capture, web_capture_batch


class DomainInvestigatorAgent(BaseAgent):
    name = "domain_investigator"

    def run(self, urls: list[str] | None = None, **kwargs) -> dict:
        urls = urls or []
        if not urls:
            return {"captures": []}

        self._emit("capturing", {"url_count": len(urls)})

        # Share one Playwright browser session across all URLs when possible
        if len(urls) > 1 and BROWSER_BACKEND == "playwright":
            results = web_capture_batch(urls, self.case_id)
        else:
            results = [web_capture(url, self.case_id) for url in urls]

        self._emit("complete", {"captured": len(results)})
        return {"captures": results}
