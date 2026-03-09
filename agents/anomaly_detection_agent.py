"""
Anomaly Detection Agent
-----------------------
Runs behavioural anomaly detection on parsed log data.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from tools.detect_anomalies import detect_anomalies


class AnomalyDetectionAgent(BaseAgent):
    name = "anomaly_detection"

    def run(self, **kwargs) -> dict:
        self._emit("detecting", {})
        result = detect_anomalies(self.case_id)
        self._emit("complete", {
            "total_findings": result.get("total_findings", 0),
            "severity_counts": result.get("severity_counts", {}),
            "llm_context": bool(result.get("llm_context")),
        })
        return result
