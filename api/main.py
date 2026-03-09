"""FastAPI application for the socai REST API."""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# Ensure repo root is on sys.path so "from config…" / "from tools…" works
_repo_root = Path(__file__).resolve().parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from api.auth import (
    create_access_token,
    get_current_user,
    load_users,
    require_permission,
    verify_password,
    _resolve_permissions,
)
from api import actions, chat, preferences, sessions, timeline
from api.jobs import JobManager
from api.parse_input import build_title, parse_analyst_input, refang
from api.schemas import (
    CaseBrowseItem,
    CaseDetail,
    CaseSummary,
    InvestigationRequest,
    JobStatus,
    LoginRequest,
    TokenResponse,
    UserInfo,
)
from config.settings import BASE_DIR, CASES_DIR, CORS_ORIGINS, REGISTRY_FILE

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

job_manager: JobManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global job_manager
    job_manager = JobManager(max_workers=2)
    # Clean up expired and empty sessions on startup
    try:
        import logging
        _log = logging.getLogger("socai")
        removed_expired = sessions.cleanup_expired()
        removed_empty = sessions.cleanup_empty()
        if removed_expired:
            _log.info(f"Cleaned up {removed_expired} expired session(s)")
        if removed_empty:
            _log.info(f"Cleaned up {removed_empty} empty session(s)")
    except Exception:
        pass
    yield
    # Clean up empty sessions on shutdown
    try:
        sessions.cleanup_empty()
    except Exception:
        pass
    job_manager.shutdown()


app = FastAPI(title="socai", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Static UI files
# ---------------------------------------------------------------------------

_ui_dir = Path(__file__).resolve().parent.parent / "ui"
_new_ui = Path(__file__).resolve().parent.parent / "ui-dist"


@app.get("/", include_in_schema=False)
async def root():
    if _new_ui.exists() and (_new_ui / "index.html").exists():
        return FileResponse(_new_ui / "index.html")
    return FileResponse(_ui_dir / "index.html")


# Mount static after the root route so index.html is served at /
app.mount("/ui", StaticFiles(directory=str(_ui_dir)), name="ui")

# New Svelte UI static assets + SPA fallback
if _new_ui.exists() and (_new_ui / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(_new_ui / "assets")), name="new-ui-assets")


# ---------------------------------------------------------------------------
# Case artefact serving
# ---------------------------------------------------------------------------

@app.get("/api/cases/{case_id}/artefacts/{path:path}", include_in_schema=False)
async def serve_artefact(
    case_id: str,
    path: str,
    user: Annotated[dict, Depends(get_current_user)],
):
    """Serve a file from a case's artefacts directory."""
    safe_path = Path(path)
    # Block path traversal
    if ".." in safe_path.parts:
        raise HTTPException(status_code=400, detail="Invalid path")
    full = CASES_DIR / case_id / "artefacts" / safe_path
    if not full.exists() or not full.is_file():
        raise HTTPException(status_code=404, detail="Artefact not found")
    return FileResponse(full)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    users = load_users()
    user = users.get(req.email)
    if not user or not user.get("active", False):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    permissions = _resolve_permissions(user)
    token = create_access_token(req.email, user["role"], permissions)
    # Clean up empty sessions for this user on login
    try:
        sessions.cleanup_empty(user_email=req.email)
    except Exception:
        pass
    return TokenResponse(access_token=token)


@app.get("/api/auth/me", response_model=UserInfo)
async def me(user: Annotated[dict, Depends(get_current_user)]):
    return UserInfo(
        email=user["sub"],
        role=user["role"],
        permissions=user["permissions"],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json_safe(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _case_meta(case_id: str) -> dict | None:
    return _load_json_safe(CASES_DIR / case_id / "case_meta.json")


def _refang_url(url: str) -> str:
    """Undo common IOC defanging so the pipeline receives valid URLs."""
    url = url.replace("hxxps://", "https://").replace("hxxp://", "http://")
    url = url.replace("[.]", ".").replace("[:]", ":")
    return url


def _case_has_malicious(case_id: str) -> bool:
    """Return True if the case has confirmed malicious findings."""
    verdicts = _load_json_safe(
        CASES_DIR / case_id / "artefacts" / "enrichment" / "verdict_summary.json"
    )
    if verdicts and verdicts.get("high_priority"):
        return True
    meta = _case_meta(case_id) or {}
    disposition = meta.get("disposition", "")
    if disposition and "malicious" in disposition:
        return True
    return False


def _user_can_access_case(case_id: str, user: dict) -> bool:
    """Check if a user can access a case.

    Rules:
      - admin permission → always
      - case analyst matches user email → always (owner)
      - case has malicious findings → visible to all authenticated users
      - otherwise → denied
    """
    perms = user.get("permissions", [])
    if "admin" in perms:
        return True
    meta = _case_meta(case_id) or {}
    if meta.get("analyst", "").lower() == user.get("sub", "").lower():
        return True
    if _case_has_malicious(case_id):
        return True
    return False


# ---------------------------------------------------------------------------
# Investigation routes
# ---------------------------------------------------------------------------

_inv_read = Depends(require_permission("investigations:read"))
_inv_submit = Depends(require_permission("investigations:submit"))


def _save_upload(upload: UploadFile, dest_dir: Path) -> str:
    """Save an uploaded file to dest_dir and return its path."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / upload.filename
    with open(dest, "wb") as f:
        shutil.copyfileobj(upload.file, f)
    return str(dest)


@app.post("/api/parse")
async def parse_input(
    user: Annotated[dict, _inv_submit],
    text: str = Form(""),
):
    """Live-parse freeform analyst input and return extracted IOCs."""
    parsed = parse_analyst_input(text)
    parsed["title"] = build_title(parsed, text)
    return parsed


# ---------------------------------------------------------------------------
# Case creation (interactive mode — creates case, does NOT run pipeline)
# ---------------------------------------------------------------------------

@app.post("/api/cases")
async def create_case(
    user: Annotated[dict, _inv_submit],
    text: str = Form(""),
    severity: str = Form(""),
    title: str = Form(""),
    zip_file: UploadFile | None = File(None),
    eml_files: list[UploadFile] | None = File(None),
):
    """Create a new case from analyst input. Does NOT auto-run the pipeline."""
    parsed = parse_analyst_input(text)
    case_id = job_manager.next_case_id()
    upload_dir = CASES_DIR / case_id / "uploads"

    final_severity = severity or parsed["severity"]
    final_title = title or build_title(parsed, text)
    analyst_notes = text.strip() if text.strip() else None

    result = actions.create_case(
        case_id, final_title, final_severity, user["sub"],
        analyst_notes=analyst_notes,
    )

    # Save uploaded files
    eml_saved = []
    if zip_file and zip_file.filename:
        _save_upload(zip_file, upload_dir)
        timeline.append(case_id, "system", {"message": f"ZIP uploaded: {zip_file.filename}"})
    if eml_files:
        for f in eml_files:
            if f.filename:
                _save_upload(f, upload_dir)
                eml_saved.append(f.filename)
        if eml_saved:
            timeline.append(case_id, "system", {"message": f"EML uploaded: {', '.join(eml_saved)}"})

    return {
        "case_id": case_id,
        "title": final_title,
        "severity": final_severity,
        "parsed": parsed,
    }


# ---------------------------------------------------------------------------
# Interactive action routes — analyst triggers steps on demand
# ---------------------------------------------------------------------------

@app.post("/api/cases/{case_id}/message")
async def add_message(
    case_id: str,
    user: Annotated[dict, _inv_submit],
    text: str = Form(""),
    zip_file: UploadFile | None = File(None),
    eml_files: list[UploadFile] | None = File(None),
):
    """Add more evidence/context to an existing case."""
    if not (CASES_DIR / case_id).exists():
        raise HTTPException(status_code=404, detail="Case not found")
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")

    upload_dir = CASES_DIR / case_id / "uploads"

    # Save any uploaded files
    if zip_file and zip_file.filename:
        _save_upload(zip_file, upload_dir)
        timeline.append(case_id, "system", {"message": f"ZIP uploaded: {zip_file.filename}"})
    if eml_files:
        for f in eml_files:
            if f.filename:
                _save_upload(f, upload_dir)
                timeline.append(case_id, "system", {"message": f"EML uploaded: {f.filename}"})

    if text.strip():
        parsed = actions.add_evidence(case_id, text.strip())
        return {"status": "ok", "parsed": parsed}

    return {"status": "ok"}


@app.get("/api/cases/{case_id}/timeline")
async def get_timeline(case_id: str, user: Annotated[dict, _inv_read]):
    """Get the full case timeline."""
    if not (CASES_DIR / case_id).exists():
        raise HTTPException(status_code=404, detail="Case not found")
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    return timeline.get_all(case_id)


def _action_to_message(
    action: str,
    text: str,
    parsed: dict,
    platform: str,
    tables: str,
    close_case: bool,
    case_id: str,
) -> str:
    """Translate a REST API action + parameters into a natural language message
    for Chief to interpret and dispatch via the chat tool loop."""

    if action == "capture":
        urls = parsed.get("urls") or []
        if not urls:
            return ""  # caller raises 400
        return f"Capture and investigate these URLs: {', '.join(urls)}"

    elif action == "triage":
        urls = parsed.get("urls")
        if urls:
            return f"Triage these IOCs against prior intelligence: {', '.join(urls)}"
        return "Triage all IOCs in this case against the intelligence index."

    elif action == "enrich":
        return "Extract all IOCs from the case artefacts and enrich them with threat intelligence."

    elif action == "phishing":
        return "Scan all captured pages for phishing indicators and brand impersonation."

    elif action == "correlate":
        return "Run IOC correlation across all case artefacts."

    elif action == "email":
        return "Analyse the uploaded .eml email files for this case."

    elif action == "report":
        msg = "Generate the investigation report for this case."
        if close_case:
            msg += " Close the case when done."
        return msg

    elif action == "fp-ticket":
        plat_hint = f" Platform: {platform}." if platform else ""
        return f"Generate a false positive suppression ticket for this alert.{plat_hint}\n\nAlert data:\n{text.strip()}"

    elif action == "queries":
        parts = ["Generate SIEM hunt queries for this case."]
        if platform:
            parts.append(f"Platforms: {platform}.")
        if tables:
            parts.append(f"Tables: {tables}.")
        return " ".join(parts)

    elif action == "campaigns":
        return "Run campaign clustering to find cases sharing IOCs with this investigation."

    elif action == "security-arch":
        return "Run a security architecture review for this case."

    elif action == "sandbox":
        return "Query sandbox APIs for file hashes found in this case."

    elif action == "timeline":
        return "Reconstruct a forensic timeline from all case artefacts."

    elif action == "pe-analysis":
        return "Run deep PE file analysis on any executables in this case."

    elif action == "yara":
        return "Run YARA scanning against case files."

    elif action == "evtx":
        return "Correlate Windows Event Logs for attack chain detection."

    elif action == "cve-context":
        return "Contextualise any CVEs found in this case."

    elif action == "exec-summary":
        return "Generate an executive summary for this case."

    return ""


@app.post("/api/cases/{case_id}/actions/{action}")
async def run_action(
    case_id: str,
    action: str,
    user: Annotated[dict, _inv_submit],
    text: str = Form(""),
    platform: str = Form(""),
    tables: str = Form(""),
    close_case: bool = Form(False),
):
    """Route an action through Chief (LLM chat) — Chief always decides how to
    handle and investigate. The action name and parameters are translated into
    a natural language instruction for the chat engine."""
    if not (CASES_DIR / case_id).exists():
        raise HTTPException(status_code=404, detail="Case not found")
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")

    parsed = parse_analyst_input(text) if text.strip() else {}

    # "auto" still runs the full ChiefAgent pipeline in background
    if action == "auto":
        urls = parsed.get("urls")
        upload_dir = CASES_DIR / case_id / "uploads"
        zip_files = list(upload_dir.glob("*.zip")) if upload_dir.exists() else []
        eml_files = list(upload_dir.glob("*.eml")) if upload_dir.exists() else []
        kwargs = {
            "title": _case_meta(case_id).get("title", "") if _case_meta(case_id) else "",
            "severity": _case_meta(case_id).get("severity", "medium") if _case_meta(case_id) else "medium",
            "analyst": user["sub"],
            "urls": urls,
            "zip_path": str(zip_files[0]) if zip_files else None,
            "eml_paths": [str(f) for f in eml_files] if eml_files else None,
            "analyst_notes": text.strip() or None,
        }
        job = job_manager.submit(case_id, kwargs)
        return {"status": "ok", "action": "auto", "job_status": job.status, "case_id": case_id}

    # Translate action to a message for Chief
    message = _action_to_message(action, text, parsed, platform, tables, close_case, case_id)
    if not message:
        if action == "capture":
            raise HTTPException(status_code=400, detail="No URLs found in input")
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")

    # Route through Chief via the chat engine
    email = user.get("sub", "")
    result = chat.chat(case_id, message, user_email=email)

    return {
        "reply": result["reply"],
        "tool_calls": result["tool_calls"],
    }


# ---------------------------------------------------------------------------
# LLM Chat routes
# ---------------------------------------------------------------------------

def _resolve_or_create_case(user: dict, case_id: str | None = None) -> str:
    """Resolve an existing case or auto-create a new one for the user.

    Priority:
      1. Explicit case_id (if provided and accessible)
      2. User's most recent open case
      3. Create a new case
    """
    email = user.get("sub", "")

    if case_id and (CASES_DIR / case_id).exists():
        if _user_can_access_case(case_id, user):
            return case_id

    # Find user's most recent open case
    registry = _load_json_safe(REGISTRY_FILE) or {}
    cases = registry.get("cases", {})
    for cid in sorted(cases.keys(), reverse=True):
        meta = _case_meta(cid) or {}
        if meta.get("analyst", "").lower() == email.lower() and meta.get("status") == "open":
            return cid

    # Create a new case
    new_id = job_manager.next_case_id()
    actions.create_case(new_id, "Investigation", "medium", email)
    return new_id


@app.post("/api/chat")
async def global_chat(
    user: Annotated[dict, _inv_submit],
    message: str = Form(""),
    case_id: str = Form(""),
):
    """Main chat endpoint — auto-resolves or creates a case.
    This is the primary entry point for the UI."""
    if not message.strip():
        raise HTTPException(status_code=400, detail="Message is empty")

    resolved_id = _resolve_or_create_case(user, case_id.strip() or None)

    email = user.get("sub", "")
    perms = user.get("permissions", [])
    result = chat.chat(resolved_id, message.strip(), user_email=email, user_permissions=perms)
    return {
        "case_id": resolved_id,
        "reply": result["reply"],
        "tool_calls": result["tool_calls"],
    }


@app.post("/api/cases/{case_id}/chat")
async def case_chat(
    case_id: str,
    user: Annotated[dict, _inv_submit],
    message: str = Form(""),
):
    """Send a message to the LLM chat for a specific case."""
    if not (CASES_DIR / case_id).exists():
        raise HTTPException(status_code=404, detail="Case not found")
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    if not message.strip():
        raise HTTPException(status_code=400, detail="Message is empty")

    email = user.get("sub", "")
    perms = user.get("permissions", [])
    result = chat.chat(case_id, message.strip(), user_email=email, user_permissions=perms)
    return {
        "case_id": case_id,
        "reply": result["reply"],
        "tool_calls": result["tool_calls"],
    }


# ---------------------------------------------------------------------------
# Streaming LLM Chat routes (SSE)
# ---------------------------------------------------------------------------

def _sse_generator(event_gen):
    """Wrap an event generator as SSE text lines."""
    for evt in event_gen:
        yield f"data: {json.dumps(evt, default=str)}\n\n"


@app.post("/api/chat/stream")
async def global_chat_stream(
    user: Annotated[dict, _inv_submit],
    message: str = Form(""),
    case_id: str = Form(""),
):
    """Streaming version of /api/chat — returns SSE events."""
    if not message.strip():
        raise HTTPException(status_code=400, detail="Message is empty")

    resolved_id = _resolve_or_create_case(user, case_id.strip() or None)

    email = user.get("sub", "")
    perms = user.get("permissions", [])

    gen = chat.chat_stream(resolved_id, message.strip(),
                           user_email=email, user_permissions=perms)
    return StreamingResponse(_sse_generator(gen), media_type="text/event-stream",
                             headers={"X-Case-Id": resolved_id})


@app.post("/api/cases/{case_id}/chat/stream")
async def case_chat_stream(
    case_id: str,
    user: Annotated[dict, _inv_submit],
    message: str = Form(""),
):
    """Streaming version of /api/cases/{case_id}/chat — returns SSE events."""
    if not (CASES_DIR / case_id).exists():
        raise HTTPException(status_code=404, detail="Case not found")
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    if not message.strip():
        raise HTTPException(status_code=400, detail="Message is empty")

    email = user.get("sub", "")
    perms = user.get("permissions", [])

    gen = chat.chat_stream(case_id, message.strip(),
                           user_email=email, user_permissions=perms)
    return StreamingResponse(_sse_generator(gen), media_type="text/event-stream")


@app.post("/api/sessions/{session_id}/chat/stream")
async def session_chat_stream_endpoint(
    session_id: str,
    user: Annotated[dict, _inv_submit],
    message: str = Form(""),
):
    """Streaming version of /api/sessions/{session_id}/chat — returns SSE events."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if meta.get("status") != "active":
        raise HTTPException(status_code=400, detail=f"Session is {meta.get('status', 'inactive')}")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    if not message.strip():
        raise HTTPException(status_code=400, detail="Message is empty")

    perms = user.get("permissions", [])

    gen = chat.session_chat_stream(session_id, message.strip(),
                                    user_permissions=perms, user_email=user["sub"])
    return StreamingResponse(_sse_generator(gen), media_type="text/event-stream")


@app.get("/api/chat/history")
async def global_chat_history(user: Annotated[dict, _inv_read], case_id: str = ""):
    """Get chat history for user's active case."""
    if not case_id:
        # Find most recent open case for this user
        email = user.get("sub", "")
        registry = _load_json_safe(REGISTRY_FILE) or {}
        cases = registry.get("cases", {})
        for cid in sorted(cases.keys(), reverse=True):
            meta = _case_meta(cid) or {}
            if meta.get("analyst", "").lower() == email.lower() and meta.get("status") == "open":
                case_id = cid
                break
    if not case_id:
        return {"case_id": None, "history": []}
    if not (CASES_DIR / case_id).exists():
        return {"case_id": None, "history": []}
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    email = user.get("sub", "")
    history = chat.get_display_history(case_id, user_email=email)
    return {"case_id": case_id, "history": history}


@app.get("/api/cases/{case_id}/chat-history")
async def case_chat_history(case_id: str, user: Annotated[dict, _inv_read]):
    """Get display-friendly chat history for a case (per-user)."""
    if not (CASES_DIR / case_id).exists():
        raise HTTPException(status_code=404, detail="Case not found")
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    email = user.get("sub", "")
    return chat.get_display_history(case_id, user_email=email)


# ---------------------------------------------------------------------------
# Session routes — chat-first investigation flow
# ---------------------------------------------------------------------------

@app.post("/api/sessions")
async def create_session(user: Annotated[dict, _inv_submit]):
    """Create a new investigation session (pre-case)."""
    meta = sessions.create_session(user["sub"])
    return meta


@app.get("/api/sessions")
async def list_sessions(user: Annotated[dict, _inv_read], all: bool = False):
    """List sessions for the current user. ?all=true includes materialised."""
    result = sessions.list_sessions(user["sub"], include_all=all)
    # Enrich with case title when a backing case exists
    for s in result:
        cid = s.get("case_id")
        if cid:
            meta_path = CASES_DIR / cid / "case_meta.json"
            if meta_path.exists():
                try:
                    cm = json.loads(meta_path.read_text())
                    s["case_title"] = cm.get("title", "")
                except Exception:
                    pass
    return result


@app.get("/api/sessions/search")
async def search_sessions(user: Annotated[dict, _inv_read], q: str = ""):
    """Search across session titles, IOCs, and findings."""
    query = q.strip().lower()
    if not query:
        return []

    all_sessions = sessions.list_sessions(user["sub"], include_all=True)
    results = []

    for s in all_sessions:
        sid = s["session_id"]
        score = 0
        match_fields: list[str] = []

        # Match title
        title = (s.get("title") or "").lower()
        if query in title:
            score += 10
            match_fields.append("title")

        # Match session ID
        if query in sid.lower():
            score += 5
            match_fields.append("session_id")

        # Match IOCs and findings from context
        try:
            ctx = sessions.load_full_context(sid)
            for thread in ctx.get("threads", {}).values():
                iocs = thread.get("iocs", {})
                for ioc_type, vals in iocs.items():
                    if isinstance(vals, list):
                        for v in vals:
                            if query in v.lower():
                                score += 8
                                match_fields.append(f"ioc:{ioc_type}")
                                break

                for finding in thread.get("findings", []):
                    summary = (finding.get("summary") or "").lower()
                    if query in summary:
                        score += 6
                        match_fields.append("finding")
                        break

                label = (thread.get("label") or "").lower()
                if query in label:
                    score += 4
                    match_fields.append("thread_label")
        except Exception:
            pass

        # Match tags from preferences
        prefs = preferences.load_preferences(user["sub"])
        session_tags = prefs.get("session_tags", {}).get(sid, [])
        if any(query in t.lower() for t in session_tags):
            score += 7
            match_fields.append("tag")

        if score > 0:
            results.append({
                **s,
                "score": score,
                "match_fields": list(set(match_fields)),
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:20]


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str, user: Annotated[dict, _inv_read]):
    """Get session metadata."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    meta["uploads"] = sessions.list_uploads(session_id)
    return meta


@app.patch("/api/sessions/{session_id}")
async def rename_session(session_id: str, request: Request, user: Annotated[dict, _inv_submit]):
    """Rename a session (set a human-readable title)."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    body = await request.json()
    title = body.get("title", "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")
    updated = sessions.rename_session(session_id, title)
    return updated


@app.delete("/api/sessions")
async def delete_all_sessions(user: Annotated[dict, _inv_submit]):
    """Delete all sessions for the current user."""
    count = sessions.delete_all_sessions(user["sub"])
    return {"deleted": count}


@app.post("/api/sessions/cleanup")
async def cleanup_user_sessions(user: Annotated[dict, _inv_submit]):
    """Delete all non-materialised sessions (logout cleanup).
    Materialised sessions are preserved as they are linked to cases."""
    count = sessions.cleanup_user_sessions(user["sub"])
    return {"deleted": count}


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str, user: Annotated[dict, _inv_submit]):
    """Delete a session and all its artefacts."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    sessions.delete_session(session_id)
    return {"deleted": True, "session_id": session_id}


@app.post("/api/sessions/{session_id}/chat")
async def session_chat(
    session_id: str,
    user: Annotated[dict, _inv_submit],
    message: str = Form(""),
):
    """Send a message in session-mode investigation chat."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if meta.get("status") != "active":
        raise HTTPException(status_code=400, detail=f"Session is {meta.get('status', 'inactive')}")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    if not message.strip():
        raise HTTPException(status_code=400, detail="Message is empty")

    perms = user.get("permissions", [])
    result = chat.session_chat(
        session_id, message.strip(),
        user_permissions=perms,
    )
    return {
        "session_id": session_id,
        "reply": result["reply"],
        "tool_calls": result["tool_calls"],
        "case_id": result.get("case_id"),
    }


@app.post("/api/sessions/{session_id}/upload")
async def session_upload(
    session_id: str,
    user: Annotated[dict, _inv_submit],
    files: list[UploadFile] = File(...),
):
    """Upload files to a session for analysis."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if meta.get("status") != "active":
        raise HTTPException(status_code=400, detail=f"Session is {meta.get('status', 'inactive')}")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")

    dest_dir = sessions.upload_dir(session_id)
    saved = []
    for f in files:
        if f.filename:
            _save_upload(f, dest_dir)
            saved.append(f.filename)

    return {"status": "ok", "files_uploaded": saved}


@app.get("/api/sessions/{session_id}/history")
async def session_history(session_id: str, user: Annotated[dict, _inv_read], thread: str = ""):
    """Get display-friendly chat history for a session.

    Pass ``?thread=<id>`` to get a specific thread's history,
    ``?thread=all`` for everything, or omit for the active thread.
    """
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    tid = thread.strip() or None
    return chat.get_session_display_history(session_id, thread_id=tid)


@app.get("/api/sessions/{session_id}/context")
async def session_context(session_id: str, user: Annotated[dict, _inv_read]):
    """Get session investigation context (IOCs, findings, telemetry)."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    return sessions.load_context(session_id)


@app.get("/api/sessions/{session_id}/threads")
async def session_threads(session_id: str, user: Annotated[dict, _inv_read]):
    """List all investigation threads in a session."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    return sessions.list_threads(session_id)


@app.post("/api/sessions/{session_id}/pivot")
async def session_pivot(session_id: str, user: Annotated[dict, _inv_submit]):
    """Create a new investigation thread and set it active."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if meta.get("status") != "active":
        raise HTTPException(status_code=400, detail=f"Session is {meta.get('status', 'inactive')}")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    return sessions.create_thread(session_id, "")


@app.post("/api/sessions/{session_id}/pivot-with-label")
async def session_pivot_with_label(
    session_id: str,
    user: Annotated[dict, _inv_submit],
    label: str = Form(""),
):
    """Create a new investigation thread with a label and set it active."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if meta.get("status") != "active":
        raise HTTPException(status_code=400, detail=f"Session is {meta.get('status', 'inactive')}")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    return sessions.create_thread(session_id, label.strip())


@app.post("/api/sessions/{session_id}/threads/{thread_id}/activate")
async def session_activate_thread(session_id: str, thread_id: str, user: Annotated[dict, _inv_submit]):
    """Switch the active investigation thread."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if meta.get("status") != "active":
        raise HTTPException(status_code=400, detail=f"Session is {meta.get('status', 'inactive')}")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")
    result = sessions.switch_thread(session_id, thread_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Thread {thread_id} not found")
    return result


@app.post("/api/sessions/{session_id}/materialise")
async def materialise_session(
    session_id: str,
    user: Annotated[dict, _inv_submit],
    title: str = Form("Investigation"),
    severity: str = Form("medium"),
    disposition: str = Form(""),
):
    """Manually materialise a session into a case (alternative to LLM-driven materialisation)."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if meta.get("status") != "active":
        raise HTTPException(status_code=400, detail=f"Session is {meta.get('status', 'inactive')}")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")

    case_id = job_manager.next_case_id()
    result = sessions.materialise(session_id, case_id, title, severity, user["sub"], disposition)
    return result


# ---------------------------------------------------------------------------
# User preferences
# ---------------------------------------------------------------------------

@app.get("/api/preferences")
async def get_preferences(user: Annotated[dict, _inv_read]):
    """Get the current user's preferences."""
    return preferences.load_preferences(user["sub"])


@app.put("/api/preferences")
async def update_preferences(request: Request, user: Annotated[dict, _inv_submit]):
    """Update the current user's preferences (partial merge)."""
    body = await request.json()
    return preferences.save_preferences(user["sub"], body)


@app.post("/api/preferences/pin/{session_id}")
async def pin_session(session_id: str, user: Annotated[dict, _inv_submit]):
    """Pin a session to the top of the sidebar."""
    pinned = preferences.pin_session(user["sub"], session_id)
    return {"pinned_sessions": pinned}


@app.delete("/api/preferences/pin/{session_id}")
async def unpin_session(session_id: str, user: Annotated[dict, _inv_submit]):
    """Unpin a session."""
    pinned = preferences.unpin_session(user["sub"], session_id)
    return {"pinned_sessions": pinned}


@app.put("/api/preferences/tags/{session_id}")
async def tag_session(session_id: str, request: Request, user: Annotated[dict, _inv_submit]):
    """Set tags on a session."""
    body = await request.json()
    tags = body.get("tags", [])
    result = preferences.tag_session(user["sub"], session_id, tags)
    return {"session_tags": result}


@app.get("/api/sessions/{session_id}/export")
async def export_session(session_id: str, user: Annotated[dict, _inv_read]):
    """Export a session's chat history as Markdown."""
    meta = sessions.load_session(session_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    if not sessions.user_owns_session(session_id, user["sub"]):
        raise HTTPException(status_code=403, detail="Access denied")

    history = sessions.load_history(session_id)
    ctx = sessions.load_context(session_id)

    title = meta.get("title") or "Investigation Session"
    created = meta.get("created", "")
    status_val = meta.get("status", "")

    lines = [
        f"# {title}",
        f"",
        f"**Session:** `{session_id}`  ",
        f"**Created:** {created}  ",
        f"**Status:** {status_val}  ",
        f"",
    ]

    # IOC summary
    iocs = ctx.get("iocs", {})
    ioc_parts = []
    for ioc_type in ("ips", "domains", "hashes", "urls", "emails"):
        items = iocs.get(ioc_type, [])
        if items:
            ioc_parts.append(f"{len(items)} {ioc_type}")
    if ioc_parts:
        lines.append(f"**IOCs:** {', '.join(ioc_parts)}")
        lines.append("")

    # Findings
    findings = ctx.get("findings", [])
    if findings:
        lines.append("## Key Findings")
        lines.append("")
        for f in findings:
            lines.append(f"- **{f.get('type', 'finding')}**: {f.get('summary', '')}")
        lines.append("")

    # Conversation
    lines.append("## Conversation")
    lines.append("")
    for msg in history:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")
        if isinstance(content, list):
            # Tool result blocks
            parts = []
            for item in content:
                if isinstance(item, dict):
                    parts.append(item.get("content", str(item)))
                else:
                    parts.append(str(item))
            content = "\n".join(parts)

        if role == "user":
            lines.append(f"### Analyst")
            lines.append(f"")
            lines.append(content)
            lines.append("")
        elif role == "assistant":
            lines.append(f"### Chief")
            lines.append(f"")
            lines.append(content)
            lines.append("")

    md = "\n".join(lines)
    return PlainTextResponse(
        content=md,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="{session_id}.md"',
        },
    )


# ---------------------------------------------------------------------------
# Browse / landscape / context-summary endpoints
# ---------------------------------------------------------------------------

@app.get("/api/investigations/browse", response_model=list[CaseBrowseItem])
async def browse_investigations(
    user: Annotated[dict, _inv_read],
    status: str = "",
    severity: str = "",
    q: str = "",
):
    """Enriched case list for the browse page — includes disposition, IOC totals, links."""
    registry = _load_json_safe(REGISTRY_FILE)
    if not registry:
        return []
    cases = registry.get("cases", {})
    link_index = _load_json_safe(BASE_DIR / "registry" / "link_index.json") or {}
    result = []
    q_lower = q.strip().lower()
    for cid, info in sorted(cases.items(), reverse=True):
        if not _user_can_access_case(cid, user):
            continue
        meta = _case_meta(cid) or {}
        case_status = meta.get("status", info.get("status", ""))
        case_severity = info.get("severity", meta.get("severity", ""))
        case_disposition = meta.get("disposition", "undetermined")

        # Apply filters
        if status and case_status != status:
            continue
        if severity and case_severity != severity:
            continue
        if q_lower:
            title = info.get("title", meta.get("title", "")).lower()
            if q_lower not in title and q_lower not in cid.lower():
                continue

        # IOC totals
        ioc_data = _load_json_safe(CASES_DIR / cid / "iocs" / "iocs.json")
        ioc_totals = {}
        if isinstance(ioc_data, dict):
            for ioc_type, vals in ioc_data.items():
                if isinstance(vals, list) and vals:
                    ioc_totals[ioc_type] = len(vals)

        # Link count
        link_count = len(link_index.get(cid, []))

        # External refs
        external_refs = {}
        if meta.get("zoho_ticket"):
            external_refs["zoho_ticket"] = meta["zoho_ticket"]
        if meta.get("external_ref"):
            external_refs["external_ref"] = meta["external_ref"]

        result.append(CaseBrowseItem(
            case_id=cid,
            title=info.get("title", meta.get("title", "")),
            severity=case_severity,
            status=case_status,
            created=info.get("created", meta.get("created_at", "")),
            disposition=case_disposition,
            ioc_totals=ioc_totals,
            link_count=link_count,
            external_refs=external_refs,
        ))
    return result


@app.get("/api/landscape")
async def get_landscape(
    user: Annotated[dict, _inv_read],
    days: int | None = None,
    client: str = "",
):
    """Return landscape assessment data for the dashboard."""
    import time
    landscape_path = BASE_DIR / "registry" / "landscape.json"
    cached = _load_json_safe(landscape_path)

    # Use cache if fresh (< 1 hour)
    if cached and not days and not client:
        generated = cached.get("generated_at", "")
        if generated:
            try:
                from datetime import datetime, timezone
                gen_dt = datetime.fromisoformat(generated.replace("Z", "+00:00"))
                age_secs = (datetime.now(timezone.utc) - gen_dt).total_seconds()
                if age_secs < 3600:
                    return cached
            except Exception:
                pass

    # Regenerate
    from tools.case_landscape import assess_landscape
    kwargs = {}
    if days:
        kwargs["days"] = days
    if client:
        kwargs["client"] = client
    result = assess_landscape(**kwargs)
    return result


@app.get("/api/investigations/{case_id}/context-summary")
async def case_context_summary(case_id: str, user: Annotated[dict, _inv_read]):
    """Compact context bundle for loading a case into a chat session."""
    if not (CASES_DIR / case_id).exists():
        raise HTTPException(status_code=404, detail="Case not found")
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")

    meta = _case_meta(case_id) or {}
    iocs = _load_json_safe(CASES_DIR / case_id / "iocs" / "iocs.json") or {}
    verdicts = _load_json_safe(
        CASES_DIR / case_id / "artefacts" / "enrichment" / "verdict_summary.json"
    ) or {}
    session_ctx = _load_json_safe(CASES_DIR / case_id / "session_context.json") or {}

    # Get latest report excerpt
    report_excerpt = ""
    report_dir = CASES_DIR / case_id / "reports"
    if not report_dir.exists():
        report_dir = CASES_DIR / case_id / "artefacts" / "reports"
    if report_dir.exists():
        md_files = sorted(report_dir.glob("*.md"))
        if md_files:
            text = md_files[0].read_text(encoding="utf-8", errors="replace")
            report_excerpt = text[:3000]

    # Extract standardised investigation log and KQL queries from chat history.
    # User messages are replaced by structured tool-action entries;
    # assistant analysis text is kept as-is (already standardised LLM language).
    _TOOL_ACTIONS = {
        "extract_iocs": "Extracted IOCs from provided data",
        "triage_iocs": "Triaged IOCs against prior case intelligence",
        "enrich_iocs": "Enriched IOCs against threat intelligence providers",
        "detect_phishing": "Ran phishing detection analysis",
        "capture_urls": "Captured and screenshotted URLs",
        "correlate": "Correlated findings across case artefacts",
        "analyse_email": "Analysed email headers and content",
        "generate_report": "Generated investigation report",
        "generate_mdr_report": "Generated MDR report",
        "generate_fp_ticket": "Generated false positive ticket",
        "generate_queries": "Generated detection/hunting queries",
        "campaign_cluster": "Clustered related campaigns",
        "security_arch_review": "Performed security architecture review",
        "reconstruct_timeline": "Reconstructed attack timeline",
        "analyse_pe_files": "Analysed PE file artefacts",
        "yara_scan": "Ran YARA rule scan",
        "correlate_event_logs": "Correlated event log entries",
        "contextualise_cves": "Contextualised CVE vulnerabilities",
        "generate_executive_summary": "Generated executive summary",
        "add_evidence": "Added evidence to the case",
        "read_case_file": "Read case artefact file",
        "run_full_pipeline": "Ran full investigation pipeline",
        "run_kql": "Executed KQL query",
        "load_kql_playbook": "Loaded KQL playbook",
        "assess_landscape": "Assessed threat landscape across cases",
        "link_cases": "Linked related cases",
        "recall_cases": "Searched prior case intelligence",
        "analyse_telemetry": "Analysed telemetry data",
        "add_finding": "Recorded investigation finding",
        "materialise_case": "Materialised session into a case",
        "load_case_context": "Loaded case context into session",
        "save_to_case": "Saved updates back to case",
    }

    investigation_log = []
    kql_queries = []
    case_dir = CASES_DIR / case_id
    for chat_file in sorted(case_dir.glob("chat_history_*.json")):
        try:
            with open(chat_file, encoding="utf-8") as f:
                messages = json.load(f)
        except Exception:
            continue

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            msg_ts = msg.get("ts", "")

            # Skip user messages — replaced by tool-action entries below
            if role == "user":
                continue

            if role != "assistant":
                continue

            # Process assistant message blocks
            blocks = (
                [{"type": "text", "text": content}]
                if isinstance(content, str)
                else content if isinstance(content, list) else []
            )

            for block in blocks:
                btype = block.get("type", "")

                if btype == "text" and block.get("text", "").strip():
                    investigation_log.append({
                        "type": "analysis",
                        "text": block["text"][:500],
                        "ts": msg_ts,
                    })

                elif btype == "tool_use":
                    tool_name = block.get("name", "")
                    inp = block.get("input", {})
                    action = _TOOL_ACTIONS.get(tool_name, f"Ran {tool_name}")

                    # Add context from tool inputs where useful
                    detail_parts = []
                    if tool_name == "run_kql":
                        ws = inp.get("workspace", "")
                        if ws:
                            detail_parts.append(f"workspace: {ws}")
                        kql_queries.append({
                            "source": "executed",
                            "query": inp.get("query", ""),
                            "workspace": ws,
                        })
                    elif tool_name == "enrich_iocs":
                        pass  # action text is sufficient
                    elif tool_name == "read_case_file":
                        fp = inp.get("file_path", "")
                        if fp:
                            detail_parts.append(fp)
                    elif tool_name == "load_kql_playbook":
                        pb = inp.get("playbook", inp.get("name", ""))
                        if pb:
                            detail_parts.append(pb)

                    detail = " — ".join(detail_parts) if detail_parts else ""
                    investigation_log.append({
                        "type": "action",
                        "tool": tool_name,
                        "text": action + (f" ({detail})" if detail else ""),
                        "ts": msg_ts,
                    })

        # Extract KQL code blocks from assistant text
        for msg in messages:
            if msg.get("role") != "assistant":
                continue
            content = msg.get("content", [])
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text = "\n".join(
                    b.get("text", "") for b in content if b.get("type") == "text"
                )
            else:
                continue
            for match in re.finditer(r"```kql\n(.*?)```", text, re.DOTALL):
                q = match.group(1).strip()
                if q and not any(
                    existing["query"].strip() == q for existing in kql_queries
                ):
                    kql_queries.append({
                        "source": "suggested",
                        "query": q,
                        "workspace": "",
                    })

    return {
        "case_id": case_id,
        "title": meta.get("title", ""),
        "severity": meta.get("severity", ""),
        "status": meta.get("status", ""),
        "disposition": meta.get("disposition", "undetermined"),
        "analyst": meta.get("analyst", ""),
        "created": meta.get("created", ""),
        "iocs": iocs,
        "verdicts": verdicts,
        "findings": session_ctx.get("findings", []),
        "report_excerpt": report_excerpt,
        "investigation_log": investigation_log,
        "kql_queries": kql_queries,
    }


# ---------------------------------------------------------------------------
# OpenCTI dashboard endpoints
# ---------------------------------------------------------------------------

from api.opencti import (
    fetch_recent_reports as _cti_reports,
    batch_ioc_xref as _cti_xref,
    fetch_trending_indicators as _cti_trending,
    fetch_attack_heatmap as _cti_heatmap,
    fetch_watchlist_activity as _cti_watchlist_activity,
    get_watchlist as _cti_get_watchlist,
    add_to_watchlist as _cti_add_watch,
    remove_from_watchlist as _cti_remove_watch,
    fetch_ioc_decay as _cti_ioc_decay,
)


@app.get("/api/cti/feed")
async def cti_feed(
    user: Annotated[dict, _inv_read],
    days: int = 30,
    sector: str | None = None,
    limit: int = 20,
):
    """Recent reports and threat actor activity from OpenCTI."""
    return _cti_reports(days=days, sector=sector, limit=limit)


@app.get("/api/cti/ioc-xref")
async def cti_ioc_xref(user: Annotated[dict, _inv_read]):
    """Cross-reference open case IOCs against OpenCTI."""
    all_iocs: list[dict] = []
    seen: set[str] = set()
    registry = _load_json_safe(REGISTRY_FILE) or {}
    cases = registry.get("cases", registry) if isinstance(registry, dict) else {}
    for case_id, info in cases.items():
        meta = _case_meta(case_id) or {}
        if meta.get("status", info.get("status", "")) == "closed":
            continue
        ioc_data = _load_json_safe(CASES_DIR / case_id / "iocs" / "iocs.json") or {}
        iocs_dict = ioc_data.get("iocs", ioc_data)
        for ioc_type, values in iocs_dict.items():
            if not isinstance(values, list):
                continue
            for v in values:
                val = v if isinstance(v, str) else (v.get("value", "") if isinstance(v, dict) else "")
                if val and val not in seen:
                    seen.add(val)
                    all_iocs.append({"value": val, "type": ioc_type, "case_id": case_id})

    return _cti_xref(all_iocs[:100])


@app.get("/api/cti/trending")
async def cti_trending(
    user: Annotated[dict, _inv_read],
    days: int = 7,
    limit: int = 20,
):
    """Trending high-score indicators from OpenCTI."""
    return _cti_trending(days=days, limit=limit)


@app.get("/api/cti/attack-heatmap")
async def cti_attack_heatmap(user: Annotated[dict, _inv_read]):
    """MITRE ATT&CK technique heatmap from OpenCTI."""
    return _cti_heatmap()


@app.get("/api/cti/watchlist")
async def cti_watchlist(
    user: Annotated[dict, _inv_read],
    days: int = 30,
):
    """Threat actor watchlist with recent activity."""
    return {
        "watchlist": _cti_get_watchlist(),
        "activity": _cti_watchlist_activity(days=days),
    }


@app.post("/api/cti/watchlist")
async def cti_watchlist_add(
    user: Annotated[dict, _inv_read],
    name: str = Form(...),
):
    """Add a threat actor to the watchlist."""
    email = user.get("email", "")
    entries = _cti_add_watch(name, added_by=email)
    return {"watchlist": entries}


@app.delete("/api/cti/watchlist")
async def cti_watchlist_remove(
    user: Annotated[dict, _inv_read],
    name: str = "",
):
    """Remove a threat actor from the watchlist."""
    entries = _cti_remove_watch(name)
    return {"watchlist": entries}


@app.get("/api/cti/ioc-decay")
async def cti_ioc_decay(user: Annotated[dict, _inv_read]):
    """IOC decay/ageing — check validity of case IOCs in OpenCTI."""
    all_values: list[str] = []
    seen: set[str] = set()
    registry = _load_json_safe(REGISTRY_FILE) or {}
    cases_map = registry.get("cases", registry) if isinstance(registry, dict) else {}
    for cid, info in cases_map.items():
        meta = _case_meta(cid) or {}
        if meta.get("status", info.get("status", "")) == "closed":
            continue
        ioc_data = _load_json_safe(CASES_DIR / cid / "iocs" / "iocs.json") or {}
        iocs_dict = ioc_data.get("iocs", ioc_data)
        for ioc_type, values in iocs_dict.items():
            if not isinstance(values, list):
                continue
            for v in values:
                val = v if isinstance(v, str) else (v.get("value", "") if isinstance(v, dict) else "")
                if val and val not in seen:
                    seen.add(val)
                    all_values.append(val)

    results = _cti_ioc_decay(all_values[:100])
    active = sum(1 for r in results if r.get("status") == "active")
    expired = sum(1 for r in results if r.get("status") == "expired")
    revoked = sum(1 for r in results if r.get("status") == "revoked")
    not_found = sum(1 for r in results if r.get("status") == "not_found")
    return {
        "summary": {
            "active": active,
            "expired": expired,
            "revoked": revoked,
            "not_in_cti": not_found,
            "total": len(results),
        },
        "indicators": results,
    }


# ---------------------------------------------------------------------------
# Legacy investigation submit (still works for backward compat)
# ---------------------------------------------------------------------------

@app.post("/api/investigations", response_model=JobStatus)
async def submit_investigation(
    user: Annotated[dict, _inv_submit],
    text: str = Form(""),
    severity: str = Form(""),
    title: str = Form(""),
    zip_pass: str = Form(""),
    detonate: bool = Form(False),
    close_case: bool = Form(False),
    include_private_ips: bool = Form(False),
    zip_file: UploadFile | None = File(None),
    eml_files: list[UploadFile] | None = File(None),
):
    parsed = parse_analyst_input(text)
    case_id = job_manager.next_case_id()
    upload_dir = CASES_DIR / case_id / "uploads"

    zip_path = None
    if zip_file and zip_file.filename:
        zip_path = _save_upload(zip_file, upload_dir)

    eml_paths = None
    if eml_files:
        eml_paths = [_save_upload(f, upload_dir) for f in eml_files if f.filename]
        if not eml_paths:
            eml_paths = None

    final_severity = severity or parsed["severity"]
    final_title = title or build_title(parsed, text)
    analyst_notes = text.strip() if text.strip() else None

    kwargs = {
        "title": final_title,
        "severity": final_severity,
        "analyst": user["sub"],
        "urls": parsed.get("urls"),
        "zip_path": zip_path,
        "zip_pass": zip_pass or None,
        "eml_paths": eml_paths,
        "analyst_notes": analyst_notes,
        "detonate": detonate,
        "close_case": close_case,
        "include_private_ips": include_private_ips,
    }
    job = job_manager.submit(case_id, kwargs)
    return JobStatus(case_id=job.case_id, status=job.status)


@app.get("/api/investigations", response_model=list[CaseSummary])
async def list_investigations(user: Annotated[dict, _inv_read]):
    registry = _load_json_safe(REGISTRY_FILE)
    if not registry:
        return []
    cases = registry.get("cases", {})
    result = []
    for cid, info in sorted(cases.items(), reverse=True):
        if not _user_can_access_case(cid, user):
            continue
        meta = _case_meta(cid) or {}
        result.append(CaseSummary(
            case_id=cid,
            title=info.get("title", meta.get("title", "")),
            severity=info.get("severity", meta.get("severity", "")),
            status=meta.get("status", info.get("status", "")),
            created=info.get("created", meta.get("created_at", "")),
        ))
    return result


@app.get("/api/investigations/{case_id}", response_model=CaseDetail)
async def get_investigation(case_id: str, user: Annotated[dict, _inv_read]):
    meta = _case_meta(case_id)
    if not meta:
        registry = _load_json_safe(REGISTRY_FILE) or {}
        info = registry.get("cases", {}).get(case_id)
        if not info:
            raise HTTPException(status_code=404, detail="Case not found")
        if not _user_can_access_case(case_id, user):
            raise HTTPException(status_code=403, detail="Access denied")
        return CaseDetail(case_id=case_id, title=info.get("title", ""), severity=info.get("severity", ""))
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    return CaseDetail(
        case_id=case_id,
        title=meta.get("title", ""),
        severity=meta.get("severity", ""),
        status=meta.get("status", ""),
        created=meta.get("created", ""),
        report_path=meta.get("report_path"),
        ioc_totals=meta.get("ioc_totals"),
        disposition=meta.get("disposition"),
    )


@app.get("/api/investigations/{case_id}/status", response_model=JobStatus)
async def investigation_status(case_id: str, user: Annotated[dict, _inv_read]):
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    job = job_manager.get(case_id)
    if not job:
        meta = _case_meta(case_id)
        if meta:
            return JobStatus(case_id=case_id, status="complete")
        raise HTTPException(status_code=404, detail="Case not found")
    return JobStatus(case_id=job.case_id, status=job.status, error=job.error)


@app.get("/api/investigations/{case_id}/report")
async def investigation_report(case_id: str, user: Annotated[dict, _inv_read]):
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    report_dir = CASES_DIR / case_id / "reports"
    if not report_dir.exists():
        report_dir = CASES_DIR / case_id / "artefacts" / "reports"
    if not report_dir.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    md_files = sorted(report_dir.glob("*.md"))
    if not md_files:
        raise HTTPException(status_code=404, detail="Report not found")
    content = md_files[0].read_text(encoding="utf-8", errors="replace")
    return PlainTextResponse(content, media_type="text/markdown")


@app.get("/api/investigations/{case_id}/iocs")
async def investigation_iocs(case_id: str, user: Annotated[dict, _inv_read]):
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    data = _load_json_safe(CASES_DIR / case_id / "iocs" / "iocs.json")
    if data is None:
        raise HTTPException(status_code=404, detail="IOCs not found")
    return data


@app.get("/api/investigations/{case_id}/verdicts")
async def investigation_verdicts(case_id: str, user: Annotated[dict, _inv_read]):
    if not _user_can_access_case(case_id, user):
        raise HTTPException(status_code=403, detail="Access denied")
    data = _load_json_safe(
        CASES_DIR / case_id / "artefacts" / "enrichment" / "verdict_summary.json"
    )
    if data is None:
        raise HTTPException(status_code=404, detail="Verdicts not found")
    return data


# ---------------------------------------------------------------------------
# Registry routes
# ---------------------------------------------------------------------------

@app.get("/api/campaigns")
async def campaigns(user: Annotated[dict, Depends(require_permission("campaigns:read"))]):
    data = _load_json_safe(BASE_DIR / "registry" / "campaigns.json")
    if data is None:
        return {"campaigns": []}
    return data


@app.get("/api/ioc-index")
async def ioc_index(user: Annotated[dict, Depends(require_permission("ioc_index:read"))]):
    data = _load_json_safe(BASE_DIR / "registry" / "ioc_index.json")
    if data is None:
        return {}
    return data


# ---------------------------------------------------------------------------
# SPA fallback — serve ui-dist/index.html for all non-API, non-UI routes
# Must be defined LAST so it doesn't shadow any API routes.
# ---------------------------------------------------------------------------

if _new_ui.exists() and (_new_ui / "index.html").exists():
    @app.get("/{path:path}", include_in_schema=False)
    async def spa_fallback(path: str):
        if path.startswith("api/") or path.startswith("ui/"):
            raise HTTPException(status_code=404)
        return FileResponse(_new_ui / "index.html")
