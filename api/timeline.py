"""Case timeline — tracks analyst messages and action results.

Storage is JSONL (one JSON object per line) for append-only writes.
Reads parse all lines and return a list for backwards compatibility.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from config.settings import CASES_DIR
from tools.common import utcnow

_lock = threading.Lock()


def _timeline_path(case_id: str) -> Path:
    return CASES_DIR / case_id / "timeline.json"


def _migrate_if_needed(path: Path) -> None:
    """One-time migration: convert JSON array to JSONL if needed."""
    if not path.exists():
        return
    raw = path.read_text().strip()
    if not raw or not raw.startswith("["):
        return  # already JSONL or empty
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return
    if not isinstance(entries, list):
        return
    # Atomic rewrite as JSONL
    lines = [json.dumps(e, default=str) for e in entries]
    dir_fd = None
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".jsonl.tmp")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n" if lines else "")
        os.replace(tmp, path)
    except Exception:
        pass  # leave original intact on failure


def append(case_id: str, entry_type: str, data: dict) -> dict:
    """Append an entry to the case timeline (JSONL append-only)."""
    entry = {
        "ts": utcnow(),
        "type": entry_type,
        **data,
    }
    with _lock:
        path = _timeline_path(case_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        _migrate_if_needed(path)
        with open(path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    return entry


def get_all(case_id: str) -> list[dict]:
    """Read all timeline entries, returning a list for backwards compatibility."""
    with _lock:
        path = _timeline_path(case_id)
        if not path.exists():
            return []
        _migrate_if_needed(path)
        entries = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries
