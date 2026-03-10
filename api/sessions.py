"""
Session management for chat-first investigation flow.

Every session auto-creates a case at start — no deferred materialisation.
This ensures all investigations have an audit trail and a case ID for
cross-platform linking (SOAR, service desk).

When the analyst reaches a disposition, the session is *finalised* — context,
IOCs, findings, and uploads are synced to the case, and the case metadata is
updated with title, severity, and disposition.

Storage layout:
    sessions/<session_id>/
        session_meta.json   — {created, user_email, status, case_id, expires}
        history.json        — Anthropic-format conversation history
        context.json        — accumulated IOCs, findings, telemetry summaries
        uploads/            — analyst-uploaded files (CSV, JSON, EML, …)
        artefacts/          — tool outputs generated during session

Sessions auto-expire after 24 h if not finalised.
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

def create_session(user_email: str, *, reference_id: str = "") -> dict:
    """Create a new investigation session with an automatic backing case.

    Every session gets a case from the start — no deferred materialisation.
    The case is immediately available for artefact storage, audit trails, and
    cross-platform ID linking (SOAR / service desk).

    Args:
        user_email: Analyst email address.
        reference_id: Optional external ticket/incident ID (e.g. service desk).
    """
    sid = f"S-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    sdir = SESSIONS_DIR / sid
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "uploads").mkdir(exist_ok=True)

    # Auto-create a case immediately
    from api.jobs import JobManager
    case_id = JobManager.next_case_id()
    from tools.case_create import case_create as _case_create
    _case_create(
        case_id,
        title=f"Session {sid[:20]} investigation",
        severity="medium",
        analyst=user_email,
        reference_id=reference_id,
    )

    meta = {
        "session_id": sid,
        "user_email": user_email,
        "status": "active",
        "case_id": case_id,
        "reference_id": reference_id or None,
        "created": datetime.now(timezone.utc).isoformat(),
        "expires": (datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)).isoformat(),
    }
    _save_json(sdir / "session_meta.json", meta)

    _save_json(sdir / "context.json", _empty_context(case_id))
    _save_json(sdir / "history.json", [])

    print(f"[session] Created session {sid} with case {case_id}")
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
    """Delete all non-finalised sessions for a user (logout cleanup).
    Finalised/materialised sessions are preserved as they are linked to cases.
    Returns count deleted."""
    all_sessions = list_sessions(user_email, include_all=True)
    count = 0
    for s in all_sessions:
        if s.get("status") not in ("materialised", "finalised"):
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
# Investigation context — threaded partitions
# ---------------------------------------------------------------------------

def _empty_thread(thread_id: str = "1", label: str = "Initial investigation") -> dict:
    return {
        "id": thread_id,
        "label": label,
        "created": datetime.now(timezone.utc).isoformat(),
        "iocs": {"ips": [], "domains": [], "hashes": [], "urls": [], "emails": []},
        "findings": [],
        "telemetry_summaries": [],
        "files_analysed": [],
        "disposition": None,
    }


def _empty_context(case_id: str | None = None) -> dict:
    thread = _empty_thread()
    return {
        "active_thread_id": "1",
        "threads": {"1": thread},
        "backing_case_id": case_id,
        "disposition": None,
    }


def _migrate_context(ctx: dict) -> dict:
    """Migrate old flat context to threaded format (backwards compat)."""
    if "threads" in ctx:
        return ctx
    thread = {
        "id": "1",
        "label": "Initial investigation",
        "created": datetime.now(timezone.utc).isoformat(),
        "iocs": ctx.get("iocs", {"ips": [], "domains": [], "hashes": [], "urls": [], "emails": []}),
        "findings": ctx.get("findings", []),
        "telemetry_summaries": ctx.get("telemetry_summaries", []),
        "files_analysed": ctx.get("files_analysed", []),
        "disposition": ctx.get("disposition"),
    }
    # Preserve per-thread extras from old format
    for k in ("loaded_case_id", "loaded_case_title", "loaded_case_severity"):
        if k in ctx:
            thread[k] = ctx[k]
    return {
        "active_thread_id": "1",
        "threads": {"1": thread},
        "backing_case_id": ctx.get("backing_case_id"),
        "disposition": ctx.get("disposition"),
    }


def get_active_thread(ctx: dict) -> dict:
    """Get the active thread from a full context."""
    tid = ctx.get("active_thread_id", "1")
    threads = ctx.get("threads", {})
    if tid in threads:
        return threads[tid]
    if threads:
        return next(iter(threads.values()))
    return _empty_thread()


def load_full_context(session_id: str) -> dict:
    """Load the full threaded context structure."""
    path = SESSIONS_DIR / session_id / "context.json"
    if not path.exists():
        return _empty_context()
    ctx = _load_json(path) or _empty_context()
    return _migrate_context(ctx)


def load_context(session_id: str) -> dict:
    """Load context scoped to the active thread (flat format for tool compat).

    Returns the active thread's IOCs/findings/telemetry plus session-global
    extras like ``backing_case_id``.  Read-only view — use
    ``load_full_context`` + ``save_context`` for writes.
    """
    full = load_full_context(session_id)
    thread = get_active_thread(full)
    result = {
        "iocs": thread.get("iocs", {"ips": [], "domains": [], "hashes": [], "urls": [], "emails": []}),
        "findings": thread.get("findings", []),
        "telemetry_summaries": thread.get("telemetry_summaries", []),
        "files_analysed": thread.get("files_analysed", []),
        "disposition": thread.get("disposition"),
        # Session-global
        "backing_case_id": full.get("backing_case_id"),
        # Active thread info
        "active_thread_id": full.get("active_thread_id", "1"),
        "active_thread_label": thread.get("label", ""),
    }
    # Per-thread extras (loaded case context, etc.)
    for k in ("loaded_case_id", "loaded_case_title", "loaded_case_severity"):
        if k in thread:
            result[k] = thread[k]
    return result


def save_context(session_id: str, context: dict) -> None:
    """Save context.  Expects the full threaded structure."""
    path = SESSIONS_DIR / session_id / "context.json"
    _save_json(path, context)


def get_active_thread_id(session_id: str) -> str:
    """Return the active thread ID for a session."""
    full = load_full_context(session_id)
    return full.get("active_thread_id", "1")


def add_iocs(session_id: str, iocs: dict) -> None:
    """Merge new IOCs into the active thread (deduplicated)."""
    full = load_full_context(session_id)
    thread = get_active_thread(full)
    for ioc_type in ("ips", "domains", "hashes", "urls", "emails"):
        new = iocs.get(ioc_type) or []
        if new:
            existing = set(thread["iocs"].get(ioc_type, []))
            existing.update(new)
            thread["iocs"][ioc_type] = sorted(existing)
    save_context(session_id, full)


def add_finding(session_id: str, finding_type: str, summary: str, detail: str = "") -> None:
    """Append a structured finding to the active thread."""
    full = load_full_context(session_id)
    thread = get_active_thread(full)
    thread["findings"].append({
        "type": finding_type,
        "summary": summary,
        "detail": detail,
        "ts": datetime.now(timezone.utc).isoformat(),
    })
    save_context(session_id, full)


def add_telemetry_summary(session_id: str, summary: dict) -> None:
    """Append a parsed telemetry summary to the active thread."""
    full = load_full_context(session_id)
    thread = get_active_thread(full)
    thread["telemetry_summaries"].append(summary)
    save_context(session_id, full)


def set_disposition(session_id: str, disposition: str) -> None:
    """Set disposition on the active thread."""
    full = load_full_context(session_id)
    thread = get_active_thread(full)
    thread["disposition"] = disposition
    save_context(session_id, full)


# ---------------------------------------------------------------------------
# Thread management
# ---------------------------------------------------------------------------

def create_thread(session_id: str, label: str = "") -> dict:
    """Create a new investigation thread and set it active.  Returns thread info."""
    full = load_full_context(session_id)
    threads = full.get("threads", {})
    next_id = str(max(int(k) for k in threads) + 1) if threads else "1"
    thread = _empty_thread(next_id, label or f"Thread {next_id}")
    threads[next_id] = thread
    full["threads"] = threads
    full["active_thread_id"] = next_id
    save_context(session_id, full)
    return thread_summary(thread, active=True)


def switch_thread(session_id: str, thread_id: str) -> dict | None:
    """Switch the active thread.  Returns thread summary or None if not found."""
    full = load_full_context(session_id)
    threads = full.get("threads", {})
    if thread_id not in threads:
        return None
    full["active_thread_id"] = thread_id
    save_context(session_id, full)
    return thread_summary(threads[thread_id], active=True)


def list_threads(session_id: str) -> list[dict]:
    """Return summary info for all threads in a session."""
    full = load_full_context(session_id)
    active_tid = full.get("active_thread_id", "1")
    threads = full.get("threads", {})
    result = []
    for tid in sorted(threads, key=lambda k: int(k)):
        t = threads[tid]
        result.append(thread_summary(t, active=(tid == active_tid)))
    return result


def thread_summary(thread: dict, *, active: bool = False) -> dict:
    """Build a compact summary dict for a single thread."""
    iocs = thread.get("iocs", {})
    ioc_count = sum(len(v) for v in iocs.values() if isinstance(v, list))
    return {
        "id": thread["id"],
        "label": thread.get("label", ""),
        "created": thread.get("created", ""),
        "active": active,
        "ioc_count": ioc_count,
        "finding_count": len(thread.get("findings", [])),
        "telemetry_count": len(thread.get("telemetry_summaries", [])),
        "disposition": thread.get("disposition"),
    }


def get_merged_context(session_id: str) -> dict:
    """Merge all threads into a single flat context (for materialisation)."""
    full = load_full_context(session_id)
    merged_iocs: dict[str, set] = {t: set() for t in ("ips", "domains", "hashes", "urls", "emails")}
    merged_findings: list[dict] = []
    merged_telemetry: list[dict] = []
    merged_files: list[str] = []

    for thread in full.get("threads", {}).values():
        for ioc_type in merged_iocs:
            for val in thread.get("iocs", {}).get(ioc_type, []):
                merged_iocs[ioc_type].add(val)
        merged_findings.extend(thread.get("findings", []))
        merged_telemetry.extend(thread.get("telemetry_summaries", []))
        merged_files.extend(thread.get("files_analysed", []))

    return {
        "iocs": {t: sorted(v) for t, v in merged_iocs.items()},
        "findings": merged_findings,
        "telemetry_summaries": merged_telemetry,
        "files_analysed": merged_files,
        "disposition": full.get("disposition"),
        "backing_case_id": full.get("backing_case_id"),
    }


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

def finalise(session_id: str, title: str, severity: str,
             disposition: str = "") -> dict:
    """
    Finalise a session's case — sync context, set disposition, update metadata.

    The case already exists (created at session start).  This function:
    1. Update case metadata (title, severity, disposition)
    2. Sync uploads and session artefacts to case dir
    3. Copy conversation history
    4. Save IOCs from accumulated context
    5. Save findings/telemetry as analyst notes
    6. Mark session as finalised
    """
    meta = load_session(session_id)
    if not meta:
        raise ValueError(f"Session {session_id} not found")
    case_id = meta.get("case_id")
    if not case_id:
        raise ValueError(f"Session {session_id} has no case_id")

    sdir = SESSIONS_DIR / session_id
    cdir = CASES_DIR / case_id

    # 1. Update case metadata
    case_meta_path = cdir / "case_meta.json"
    if case_meta_path.exists():
        cmeta = _load_json(case_meta_path) or {}
        if title:
            cmeta["title"] = title
        if severity:
            cmeta["severity"] = severity
        if disposition:
            cmeta["disposition"] = disposition
        cmeta["updated_at"] = datetime.now(timezone.utc).isoformat()
        _save_json(case_meta_path, cmeta)

    # 2. Sync uploads
    src_uploads = sdir / "uploads"
    dst_uploads = cdir / "uploads"
    if src_uploads.exists() and any(src_uploads.iterdir()):
        dst_uploads.mkdir(parents=True, exist_ok=True)
        for f in src_uploads.iterdir():
            if f.is_file():
                shutil.copy2(str(f), str(dst_uploads / f.name))

    # 3. Sync session artefacts
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

    # 4. Save IOCs from context (merged across all threads)
    ctx = get_merged_context(session_id)
    iocs = ctx.get("iocs", {})
    has_iocs = any(iocs.get(t) for t in ("ips", "domains", "hashes", "urls", "emails"))
    if has_iocs:
        iocs_dir = cdir / "iocs"
        iocs_dir.mkdir(parents=True, exist_ok=True)
        _save_json(iocs_dir / "iocs.json", {"iocs": iocs, "source": "session_context"})

    # 5. Copy history to case chat history
    history = load_history(session_id)
    analyst = meta.get("user_email", "unknown")
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

    # 8. Mark session as finalised
    meta["status"] = "finalised"
    meta["finalised_at"] = datetime.now(timezone.utc).isoformat()
    if not meta.get("title"):
        short = (title[:60].rsplit(" ", 1)[0]) if len(title) > 60 else title
        meta["title"] = f"{case_id} — {short}" if short else case_id
    _save_json(sdir / "session_meta.json", meta)

    return {
        "case_id": case_id,
        "session_id": session_id,
        "iocs_saved": has_iocs,
        "findings_count": len(findings),
        "uploads_synced": len(list_uploads(session_id)),
    }


def materialise(session_id: str, case_id: str, title: str, severity: str,
                analyst: str, disposition: str = "") -> dict:
    """Legacy wrapper — delegates to finalise().

    Kept for backwards compatibility with any callers that pass case_id explicitly.
    The case_id arg is ignored since the session already owns a case.
    """
    return finalise(session_id, title, severity, disposition)


# ---------------------------------------------------------------------------
# Cleanup — expire old sessions
# ---------------------------------------------------------------------------

def cleanup_empty(*, user_email: str | None = None) -> int:
    """Delete active sessions with no chat history and no uploads.
    Also removes the auto-created case if it's empty.
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
            # Also clean up the auto-created case if it's empty
            case_id = meta.get("case_id")
            if case_id:
                case_dir = CASES_DIR / case_id
                if case_dir.exists():
                    # Only remove if the case has no artefacts/iocs/reports
                    has_content = any(
                        (case_dir / sub).exists() and any((case_dir / sub).iterdir())
                        for sub in ("artefacts", "iocs", "reports", "notes")
                    )
                    if not has_content:
                        shutil.rmtree(str(case_dir), ignore_errors=True)
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
            if meta.get("status") in ("materialised", "finalised"):
                # Keep finalised sessions for audit trail (24h after finalisation)
                mat_at = meta.get("finalised_at", meta.get("materialised_at", meta.get("created", "")))
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
