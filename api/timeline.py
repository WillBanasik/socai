"""Case timeline — tracks analyst messages and action results."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from config.settings import CASES_DIR
from tools.common import utcnow

_lock = threading.Lock()


def _timeline_path(case_id: str) -> Path:
    return CASES_DIR / case_id / "timeline.json"


def _load(case_id: str) -> list[dict]:
    path = _timeline_path(case_id)
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)


def _save(case_id: str, entries: list[dict]) -> None:
    path = _timeline_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(entries, f, indent=2, default=str)


def append(case_id: str, entry_type: str, data: dict) -> dict:
    """
    Append an entry to the case timeline.

    entry_type: "analyst", "system", "action_start", "action_done", "action_error"
    """
    entry = {
        "ts": utcnow(),
        "type": entry_type,
        **data,
    }
    with _lock:
        entries = _load(case_id)
        entries.append(entry)
        _save(case_id, entries)
    return entry


def get_all(case_id: str) -> list[dict]:
    with _lock:
        return _load(case_id)
