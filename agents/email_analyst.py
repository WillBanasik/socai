"""
Email Analyst Agent
-------------------
Parses .eml files, extracts URLs and attachments, and runs static analysis
on attachments.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.analyse_email import analyse_email
from tools.common import log_error


class EmailAnalystAgent(BaseAgent):
    name = "email_analyst"

    def run(self, eml_paths: list[str] | None = None, **kwargs) -> dict:
        if not eml_paths:
            return {"status": "no_input", "extracted_urls": [], "attachment_paths": []}

        all_urls: list[str] = []
        all_attachments: list[str] = []
        analyses: list[dict] = []

        for eml_path in eml_paths:
            self._emit("analysing_email", {"path": eml_path})
            result = analyse_email(eml_path, self.case_id)
            analyses.append(result)

            if result.get("status") == "ok":
                all_urls.extend(result.get("urls", []))
                for att in result.get("attachments", []):
                    all_attachments.append(att["path"])

        # Run static analysis on attachments
        if all_attachments:
            try:
                from tools.static_file_analyse import static_file_analyse
                for att_path in all_attachments:
                    self._emit("analysing_attachment", {"path": att_path})
                    try:
                        static_file_analyse(att_path, self.case_id)
                    except Exception as exc:
                        log_error(self.case_id, "email_analyst.static_analyse", str(exc),
                                  severity="warning", context={"attachment": att_path})
            except ImportError as exc:
                log_error(self.case_id, "email_analyst.import_static", str(exc),
                          severity="info", context={"reason": "static_file_analyse unavailable"})

        # Deduplicate URLs
        unique_urls = sorted(set(all_urls))

        self._emit("complete", {
            "emails_parsed": len(analyses),
            "urls_found": len(unique_urls),
            "attachments_found": len(all_attachments),
        })

        return {
            "status": "ok",
            "emails_parsed": len(analyses),
            "extracted_urls": unique_urls,
            "attachment_paths": all_attachments,
            "analyses": analyses,
        }
