"""
Base agent class.  All agents inherit from this.
"""
from __future__ import annotations

import json
import logging

from tools.common import audit

logger = logging.getLogger(__name__)


class BaseAgent:
    name: str = "base"

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.log = logging.getLogger(f"socai.{self.name}")

    def run(self, **kwargs) -> dict:
        raise NotImplementedError

    def _emit(self, event: str, data: dict) -> None:
        """Log a structured event for this agent."""
        self.log.info("%s | %s | %s", self.name, event, json.dumps(data))
        audit(f"{self.name}:{event}", path="", extra={"case_id": self.case_id, **data})
