"""
File Analyst Agent
-------------------
Drives ZIP extraction + static analysis for all files in a case.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from agents.base_agent import BaseAgent
from tools.extract_zip import extract_zip
from tools.static_file_analyse import static_file_analyse


class FileAnalystAgent(BaseAgent):
    name = "file_analyst"

    def run(
        self,
        zip_path: str | None = None,
        zip_pass: str | None = None,
        **kwargs,
    ) -> dict:
        results: dict = {"zip_manifest": None, "analyses": []}

        if zip_path:
            self._emit("extracting_zip", {"zip": zip_path})
            zm = extract_zip(zip_path, self.case_id, zip_pass)
            results["zip_manifest"] = zm

            # Analyse each extracted file
            zip_dir = CASES_DIR / self.case_id / "artefacts" / "zip"
            for extracted_file in zip_dir.rglob("*"):
                if extracted_file.is_file() and not extracted_file.name.endswith(
                    (".json", ".txt")
                ):
                    self._emit("analysing_file", {"file": str(extracted_file)})
                    an = static_file_analyse(extracted_file, self.case_id)
                    results["analyses"].append(an)

        self._emit("complete", {"analyses": len(results["analyses"])})
        return results
