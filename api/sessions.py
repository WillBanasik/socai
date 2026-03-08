"""
Session management for chat-first investigation flow.

Sessions are lightweight pre-case conversations where analysts can upload
telemetry, ask questions, and investigate interactively.  When the analyst
decides on a disposition (FP or malicious) the session is *materialised*
into a full case with IOCs, artefacts, and a generated report or FP comment.

Storage layout:
    sessions/<session_id>/
        session_meta.json   — {created, user_email, status, case_id, expires}
        history.json        — Anthropic-format conversation history
        context.json        — accumulated IOCs, findings, telemetry summaries
        uploads/            — analyst-uploaded files (CSV, JSON, EML, …)
        artefacts/          — tool outputs generated during session

Sessions auto-expire after 24 h if not materialised.
"""
from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from config.settings import BASE_DIR, CASES_DIR

SESSIONS_DIR = BASE_DIR / "sessions"
SESSION_TTL_HOURS = 24


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------

def create_session(user_email: str) -> dict:
    """Create a new investigation session. Returns session metadata."""
    sid = f"S-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    sdir = SESSIONS_DIR / sid
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "uploads").mkdir(exist_ok=True)

    meta = {
        "session_id": sid,
        "user_email": user_email,
        "status": "active",
        "case_id": None,
        "created": datetime.now(timezone.utc).isoformat(),
        "expires": (datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)).isoformat(),
    }
    _save_json(sdir / "session_meta.json", meta)
    _save_json(sdir / "context.json", _empty_context())
    _save_json(sdir / "history.json", [])
    return meta


def load_session(session_id: str) -> dict | None:
    """Load session metadata. Returns None if not found or expired."""
    path = SESSIONS_DIR / session_id / "session_meta.json"
    if not path.exists():
        return None
    meta = _load_json(path)
    if not meta:
        return None
    # Check expiry
    expires = meta.get("expires", "")
    if expires:
        try:
            exp_dt = datetime.fromisoformat(expires)
            if datetime.now(timezone.utc) > exp_dt and meta.get("status") == "active":
                meta["status"] = "expired"
                _save_json(path, meta)
        except (ValueError, TypeError):
            pass
    return meta


def list_sessions(user_email: str, *, include_all: bool = False) -> list[dict]:
    """List sessions for a user. By default only active sessions; set
    *include_all* to also return materialised/expired."""
    if not SESSIONS_DIR.exists():
        return []
    result = []
    for sdir in sorted(SESSIONS_DIR.iterdir(), reverse=True):
        if not sdir.is_dir():
            continue
        meta = load_session(sdir.name)
        if not meta:
            continue
        if meta.get("user_email", "").lower() != user_email.lower():
            continue
        if include_all or meta.get("status") == "active":
            result.append(meta)
    return result


def user_owns_session(session_id: str, user_email: str) -> bool:
    """Check if user owns a session."""
    meta = load_session(session_id)
    if not meta:
        return False
    return meta.get("user_email", "").lower() == user_email.lower()


def rename_session(session_id: str, title: str) -> dict | None:
    """Set a human-readable title on a session. Returns updated meta."""
    meta = load_session(session_id)
    if not meta:
        return None
    meta["title"] = title.strip()[:120]
    _save_json(SESSIONS_DIR / session_id / "session_meta.json", meta)
    return meta


def delete_all_sessions(user_email: str) -> int:
    """Delete all sessions for a user. Returns count deleted."""
    all_sessions = list_sessions(user_email, include_all=True)
    count = 0
    for s in all_sessions:
        if delete_session(s["session_id"]):
            count += 1
    return count


def cleanup_user_sessions(user_email: str) -> int:
    """Delete all non-materialised sessions for a user (logout cleanup).
    Materialised sessions are preserved as they are linked to cases.
    Returns count deleted."""
    all_sessions = list_sessions(user_email, include_all=True)
    count = 0
    for s in all_sessions:
        if s.get("status") != "materialised":
            if delete_session(s["session_id"]):
                count += 1
    return count


def delete_session(session_id: str) -> bool:
    """Delete a session and all its artefacts. Returns True if deleted."""
    sdir = SESSIONS_DIR / session_id
    if not sdir.exists():
        return False
    shutil.rmtree(str(sdir), ignore_errors=True)
    return True


# ---------------------------------------------------------------------------
# History persistence (mirrors chat.py pattern)
# ---------------------------------------------------------------------------

def load_history(session_id: str) -> list[dict]:
    path = SESSIONS_DIR / session_id / "history.json"
    if not path.exists():
        return []
    return _load_json(path) or []


def save_history(session_id: str, history: list[dict]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for msg in history:
        if "ts" not in msg:
            msg["ts"] = now
    path = SESSIONS_DIR / session_id / "history.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    _save_json(path, history)


# ---------------------------------------------------------------------------
# Investigation context accumulator
# ---------------------------------------------------------------------------

def _empty_context() -> dict:
    return {
        "iocs": {"ips": [], "domains": [], "hashes": [], "urls": [], "emails": []},
        "findings": [],
        "telemetry_summaries": [],
        "files_analysed": [],
        "disposition": None,
    }


def load_context(session_id: str) -> dict:
    path = SESSIONS_DIR / session_id / "context.json"
    if not path.exists():
        return _empty_context()
    return _load_json(path) or _empty_context()


def save_context(session_id: str, context: dict) -> None:
    path = SESSIONS_DIR / session_id / "context.json"
    _save_json(path, context)


def add_iocs(session_id: str, iocs: dict) -> None:
    """Merge new IOCs into session context (deduplicated)."""
    ctx = load_context(session_id)
    for ioc_type in ("ips", "domains", "hashes", "urls", "emails"):
        new = iocs.get(ioc_type) or []
        if new:
            existing = set(ctx["iocs"].get(ioc_type, []))
            existing.update(new)
            ctx["iocs"][ioc_type] = sorted(existing)
    save_context(session_id, ctx)


def add_finding(session_id: str, finding_type: str, summary: str, detail: str = "") -> None:
    """Append a structured finding to the session context."""
    ctx = load_context(session_id)
    ctx["findings"].append({
        "type": finding_type,
        "summary": summary,
        "detail": detail,
        "ts": datetime.now(timezone.utc).isoformat(),
    })
    save_context(session_id, ctx)


def add_telemetry_summary(session_id: str, summary: dict) -> None:
    """Append a parsed telemetry summary."""
    ctx = load_context(session_id)
    ctx["telemetry_summaries"].append(summary)
    save_context(session_id, ctx)


def set_disposition(session_id: str, disposition: str) -> None:
    """Set session disposition (false_positive, true_positive, etc.)."""
    ctx = load_context(session_id)
    ctx["disposition"] = disposition
    save_context(session_id, ctx)


# ---------------------------------------------------------------------------
# File uploads
# ---------------------------------------------------------------------------

def upload_dir(session_id: str) -> Path:
    d = SESSIONS_DIR / session_id / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_uploads(session_id: str) -> list[str]:
    d = SESSIONS_DIR / session_id / "uploads"
    if not d.exists():
        return []
    return [f.name for f in sorted(d.iterdir()) if f.is_file()]


# ---------------------------------------------------------------------------
# Materialisation — session → case
# ---------------------------------------------------------------------------

def materialise(session_id: str, case_id: str, title: str, severity: str,
                analyst: str, disposition: str = "") -> dict:
    """
    Convert a session into a full case.

    1. Create case directory and metadata
    2. Move uploads and artefacts to case dir
    3. Copy conversation history
    4. Save IOCs from accumulated context
    5. Update session metadata with case_id link
    """
    from api import actions

    sdir = SESSIONS_DIR / session_id
    cdir = CASES_DIR / case_id

    # 1. Create the case
    actions.create_case(case_id, title, severity, analyst)

    # 2. Move uploads
    src_uploads = sdir / "uploads"
    dst_uploads = cdir / "uploads"
    if src_uploads.exists() and any(src_uploads.iterdir()):
        dst_uploads.mkdir(parents=True, exist_ok=True)
        for f in src_uploads.iterdir():
            if f.is_file():
                shutil.copy2(str(f), str(dst_uploads / f.name))

    # 3. Move session artefacts
    src_artefacts = sdir / "artefacts"
    if src_artefacts.exists():
        dst_artefacts = cdir / "artefacts"
        dst_artefacts.mkdir(parents=True, exist_ok=True)
        for item in src_artefacts.iterdir():
            dest = dst_artefacts / item.name
            if item.is_dir():
                shutil.copytree(str(item), str(dest), dirs_exist_ok=True)
            else:
                shutil.copy2(str(item), str(dest))

    # 4. Save IOCs from context
    ctx = load_context(session_id)
    iocs = ctx.get("iocs", {})
    has_iocs = any(iocs.get(t) for t in ("ips", "domains", "hashes", "urls", "emails"))
    if has_iocs:
        iocs_dir = cdir / "iocs"
        iocs_dir.mkdir(parents=True, exist_ok=True)
        _save_json(iocs_dir / "iocs.json", {"iocs": iocs, "source": "session_context"})

    # 5. Copy history to case chat history
    history = load_history(session_id)
    if history:
        from api.chat import save_history as save_case_history
        save_case_history(case_id, history, user_email=analyst)

    # 6. Save context and findings as analyst notes
    findings = ctx.get("findings", [])
    telemetry = ctx.get("telemetry_summaries", [])
    if findings or telemetry:
        notes_dir = cdir / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        lines = ["# Investigation Session Context\n"]
        if findings:
            lines.append("## Key Findings\n")
            for f in findings:
                lines.append(f"- **{f.get('type', 'finding')}**: {f.get('summary', '')}")
                if f.get("detail"):
                    lines.append(f"  {f['detail']}")
            lines.append("")
        if telemetry:
            lines.append("## Telemetry Analysis\n")
            for t in telemetry:
                lines.append(f"- **{t.get('source_file', 'telemetry')}**: "
                             f"{t.get('event_count', '?')} events, "
                             f"{t.get('time_range', 'unknown time range')}")
            lines.append("")
        (notes_dir / "session_context.md").write_text("\n".join(lines))

    # 7. Save full context.json to case for reference
    _save_json(cdir / "session_context.json", ctx)

    # 8. Update session metadata
    meta = load_session(session_id)
    if meta:
        meta["status"] = "materialised"
        meta["case_id"] = case_id
        meta["materialised_at"] = datetime.now(timezone.utc).isoformat()
        # Auto-title with case ID + brief description
        if not meta.get("title"):
            short = (title[:60].rsplit(" ", 1)[0]) if len(title) > 60 else title
            meta["title"] = f"{case_id} — {short}" if short else case_id
        _save_json(sdir / "session_meta.json", meta)

    # 9. Set disposition on case meta if provided
    if disposition:
        case_meta_path = cdir / "case_meta.json"
        if case_meta_path.exists():
            cmeta = _load_json(case_meta_path)
            if cmeta:
                cmeta["disposition"] = disposition
                _save_json(case_meta_path, cmeta)

    return {
        "case_id": case_id,
        "session_id": session_id,
        "iocs_saved": has_iocs,
        "findings_count": len(findings),
        "uploads_moved": len(list_uploads(session_id)),
    }


# ---------------------------------------------------------------------------
# Cleanup — expire old sessions
# ---------------------------------------------------------------------------

def cleanup_empty(*, user_email: str | None = None) -> int:
    """Delete active sessions with no chat history and no uploads.
    If *user_email* is provided, only clean that user's sessions.
    Returns count removed."""
    if not SESSIONS_DIR.exists():
        return 0
    removed = 0
    for sdir in SESSIONS_DIR.iterdir():
        if not sdir.is_dir():
            continue
        meta_path = sdir / "session_meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = _load_json(meta_path)
            if not meta or meta.get("status") != "active":
                continue
            if user_email and meta.get("user_email", "").lower() != user_email.lower():
                continue
            history = _load_json(sdir / "history.json") if (sdir / "history.json").exists() else []
            if history:
                continue
            uploads_dir = sdir / "uploads"
            has_uploads = uploads_dir.exists() and any(uploads_dir.iterdir())
            if has_uploads:
                continue
            shutil.rmtree(str(sdir), ignore_errors=True)
            removed += 1
        except Exception:
            continue
    return removed


def cleanup_expired() -> int:
    """Delete expired sessions. Returns count of sessions removed."""
    if not SESSIONS_DIR.exists():
        return 0
    removed = 0
    now = datetime.now(timezone.utc)
    for sdir in SESSIONS_DIR.iterdir():
        if not sdir.is_dir():
            continue
        meta_path = sdir / "session_meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = _load_json(meta_path)
            if not meta:
                continue
            if meta.get("status") == "materialised":
                # Keep materialised sessions for audit trail (24h after materialisation)
                mat_at = meta.get("materialised_at", meta.get("created", ""))
                if mat_at:
                    mat_dt = datetime.fromisoformat(mat_at)
                    if now - mat_dt > timedelta(hours=SESSION_TTL_HOURS):
                        shutil.rmtree(str(sdir), ignore_errors=True)
                        removed += 1
                continue
            expires = meta.get("expires", "")
            if expires:
                exp_dt = datetime.fromisoformat(expires)
                if now > exp_dt:
                    shutil.rmtree(str(sdir), ignore_errors=True)
                    removed += 1
        except Exception:
            continue
    return removed


# ---------------------------------------------------------------------------
# JSON helpers (avoid circular imports with tools.common)
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict | list | None:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
