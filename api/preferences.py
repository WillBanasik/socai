"""Per-user preferences stored as JSON files.

Storage: config/preferences/<email_hash>.json

Preferences:
  - custom_instructions: str — injected into every system prompt
  - response_style: str — concise | detailed | formal
  - pinned_sessions: list[str] — session IDs pinned to top of sidebar
  - session_tags: dict[str, list[str]] — session_id → tags
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from config.settings import BASE_DIR

PREFS_DIR = BASE_DIR / "config" / "preferences"

_DEFAULTS = {
    "custom_instructions": "",
    "response_style": "concise",
    "pinned_sessions": [],
    "session_tags": {},
}

_VALID_STYLES = {"concise", "detailed", "formal"}


def _prefs_path(email: str) -> Path:
    h = hashlib.sha256(email.lower().strip().encode()).hexdigest()[:16]
    return PREFS_DIR / f"{h}.json"


def load_preferences(email: str) -> dict:
    """Load preferences for a user, returning defaults for missing keys."""
    path = _prefs_path(email)
    prefs = dict(_DEFAULTS)
    if path.exists():
        try:
            with open(path) as f:
                stored = json.load(f)
            if isinstance(stored, dict):
                prefs.update(stored)
        except Exception:
            pass
    return prefs


def save_preferences(email: str, updates: dict) -> dict:
    """Merge updates into existing preferences.  Returns the full prefs dict."""
    prefs = load_preferences(email)

    if "custom_instructions" in updates:
        val = str(updates["custom_instructions"]).strip()[:2000]
        prefs["custom_instructions"] = val

    if "response_style" in updates:
        val = str(updates["response_style"]).strip().lower()
        if val in _VALID_STYLES:
            prefs["response_style"] = val

    if "pinned_sessions" in updates:
        val = updates["pinned_sessions"]
        if isinstance(val, list):
            prefs["pinned_sessions"] = [str(s) for s in val][:50]

    if "session_tags" in updates:
        val = updates["session_tags"]
        if isinstance(val, dict):
            prefs["session_tags"] = {
                str(k): [str(t) for t in v][:10]
                for k, v in val.items()
            }

    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    with open(_prefs_path(email), "w") as f:
        json.dump(prefs, f, indent=2, default=str)

    return prefs


def pin_session(email: str, session_id: str) -> list[str]:
    """Pin a session.  Returns updated pinned list."""
    prefs = load_preferences(email)
    pinned = prefs.get("pinned_sessions", [])
    if session_id not in pinned:
        pinned.insert(0, session_id)
    return save_preferences(email, {"pinned_sessions": pinned})["pinned_sessions"]


def unpin_session(email: str, session_id: str) -> list[str]:
    """Unpin a session.  Returns updated pinned list."""
    prefs = load_preferences(email)
    pinned = [s for s in prefs.get("pinned_sessions", []) if s != session_id]
    return save_preferences(email, {"pinned_sessions": pinned})["pinned_sessions"]


def tag_session(email: str, session_id: str, tags: list[str]) -> dict:
    """Set tags on a session.  Returns updated session_tags dict."""
    prefs = load_preferences(email)
    session_tags = prefs.get("session_tags", {})
    if tags:
        session_tags[session_id] = tags[:10]
    else:
        session_tags.pop(session_id, None)
    return save_preferences(email, {"session_tags": session_tags})["session_tags"]


def search_sessions_index(email: str, query: str) -> list[str]:
    """Return session IDs matching query from the tags/pins index.

    This is a lightweight local search — the main search happens
    via the session context files on the API side.
    """
    prefs = load_preferences(email)
    q = query.lower().strip()
    if not q:
        return []
    matches = set()
    for sid, tags in prefs.get("session_tags", {}).items():
        if any(q in t.lower() for t in tags):
            matches.add(sid)
    return list(matches)
