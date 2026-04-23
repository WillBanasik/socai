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
from tools.common import log_error, utcnow

_lock = threading.Lock()


def _timeline_path(case_id: str) -> Path:
    return CASES_DIR / case_id / "timeline.json"


def _migrate_if_needed(path: Path) -> bool:
    """One-time migration: convert JSON array to JSONL if needed.

    Returns True if the file is safe to append to (either migrated
    successfully or was already JSONL). Returns False if migration was
    needed but failed — in which case the caller must NOT append, or the
    file will end up as a mix of JSON-array + JSONL lines that can't be parsed.
    """
    if not path.exists():
        return True
    raw = path.read_text().strip()
    if not raw or not raw.startswith("["):
        return True  # already JSONL or empty
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        log_error("", "timeline.migrate", str(exc), severity="error",
                  context={"path": str(path)})
        return False
    if not isinstance(entries, list):
        log_error("", "timeline.migrate",
                  "file starts with '[' but is not a JSON array",
                  severity="error", context={"path": str(path)})
        return False
    # Atomic rewrite as JSONL
    lines = [json.dumps(e, default=str) for e in entries]
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".jsonl.tmp")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n" if lines else "")
        os.replace(tmp, path)
        return True
    except Exception as exc:
        log_error("", "timeline.migrate", str(exc), severity="error",
                  traceback=True, context={"path": str(path)})
        return False


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
        if not _migrate_if_needed(path):
            # Migration failed — refuse to append so we don't corrupt the
            # file with mixed JSON-array + JSONL content.
            raise RuntimeError(
                f"Timeline file {path} needs migration but could not be "
                f"migrated; refusing to append. See error log."
            )
        with open(path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    return entry


def get_all(case_id: str) -> list[dict]:
    """Read all timeline entries, returning a list for backwards compatibility."""
    with _lock:
        path = _timeline_path(case_id)
        if not path.exists():
            return []
        migrated = _migrate_if_needed(path)
        text = path.read_text()
        if not migrated and text.strip().startswith("["):
            # Migration failed but the file is still a legacy JSON array;
            # fall back to reading it as a single JSON document.
            try:
                data = json.loads(text)
                return data if isinstance(data, list) else []
            except json.JSONDecodeError:
                return []
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries
