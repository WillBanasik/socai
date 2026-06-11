"""Sample-upload HTTP endpoint for cross-sandbox file transfer.

Claude Desktop's bash sandbox has its own filesystem; the MCP server runs on
the WSL/host filesystem. ``analyse_file`` is path-based, so a file
sitting in ``/home/claude/...`` inside the bash sandbox is invisible to it.

This middleware closes that gap. The analyst (or the model on their behalf)
calls ``prepare_file_upload`` to mint a signed upload URL, then ``curl``s the
sample to::

    POST /cases/<case_id>/uploads?token=<jwt>&filename=<safe-name>

The server writes the bytes to
``cases/<case_id>/artefacts/uploads/<filename>`` and returns the absolute
path + SHA-256. The analyst then passes that path straight into
``analyse_file``.

Auth & safety:
  - JWT bound to (case_id, filename), audience ``socai-upload``, short TTL.
  - Filename is sanitised to ``[A-Za-z0-9._-]`` and forced under the case dir
    (path-escape attempts → 400).
  - Body capped at ``MCP_UPLOAD_MAX_BYTES`` — oversized requests are rejected
    mid-stream rather than buffered.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import quote, parse_qs

from jose import JWTError, jwt

from api.auth import JWT_ALGORITHM, JWT_SECRET
from config.settings import CASES_DIR
from mcp_server.config import (
    MCP_PUBLIC_BASE_URL,
    MCP_UPLOAD_MAX_BYTES,
    MCP_UPLOAD_TOKEN_TTL_SECONDS,
)
from mcp_server.logging_config import mcp_log


UPLOAD_AUDIENCE = "socai-upload"
_ROUTE_PREFIX = "/cases/"
_ROUTE_SUFFIX = "/uploads"
_UPLOAD_SUBDIR = "artefacts/uploads"
_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def validate_case_id(case_id: str) -> bool:
    """True when ``case_id`` is a plain identifier that cannot escape
    ``CASES_DIR`` (no separators, no ``..``). Mirrors the read-side gate in
    ``read_case_file``/``list_case_files`` — the upload path must be at least
    as strict, since it *writes*."""
    return bool(case_id) and bool(_CASE_ID_RE.match(case_id))


# ---------------------------------------------------------------------------
# Filename hygiene
# ---------------------------------------------------------------------------

def sanitise_filename(name: str) -> str | None:
    """Strip path components and unsafe chars from a user-supplied filename.

    Returns the sanitised name, or ``None`` if nothing usable remains.
    """
    if not name:
        return None
    # Drop any directory component the client tried to smuggle in.
    base = Path(name).name
    # Remove leading dots so we never write a hidden / dotfile.
    base = base.lstrip(".")
    if not base:
        return None
    cleaned = _FILENAME_RE.sub("_", base)
    cleaned = cleaned.strip("._")
    if not cleaned:
        return None
    # Cap length — long filenames bloat artefact listings and some FSes choke.
    return cleaned[:200]


# ---------------------------------------------------------------------------
# Token minting
# ---------------------------------------------------------------------------

def mint_upload_token(
    *,
    case_id: str,
    filename: str,
    caller_email: str,
    ttl_seconds: int | None = None,
) -> str:
    """Mint a short-lived JWT granting one-shot write access for a single file."""
    ttl = ttl_seconds if ttl_seconds is not None else MCP_UPLOAD_TOKEN_TTL_SECONDS
    now = int(time.time())
    payload = {
        "sub": caller_email or "local",
        "case_id": case_id,
        "filename": filename,
        "aud": UPLOAD_AUDIENCE,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def build_upload_url(*, case_id: str, filename: str, token: str) -> str:
    """Build the absolute URL the caller should POST the file body to."""
    return (
        f"{MCP_PUBLIC_BASE_URL}{_ROUTE_PREFIX}{quote(case_id)}{_ROUTE_SUFFIX}"
        f"?token={quote(token)}&filename={quote(filename)}"
    )


def expected_artefact_path(*, case_id: str, filename: str) -> Path:
    """Where the upload will land — returned to callers so they can chain into
    ``analyse_file`` without waiting for the upload response."""
    return CASES_DIR / case_id / _UPLOAD_SUBDIR / filename


# ---------------------------------------------------------------------------
# In-band write helper (used by the upload_file_content MCP tool)
# ---------------------------------------------------------------------------

def store_inband_upload(
    *, case_id: str, filename: str, content_b64: str, max_bytes: int,
) -> dict:
    """Decode a base64 payload and write it to the canonical upload path.

    Used when the calling sandbox has no network path to the HTTP endpoint
    (e.g. Claude Desktop's bash container) and therefore ships bytes inside
    the MCP transport itself.

    Returns a result dict shaped like the HTTP endpoint's 201 response on
    success, or ``{"status": "error", "error": "..."}`` on any failure.
    Caller is responsible for filename sanitisation (so the same ``filename``
    can be reused in logging and the returned ``path``).
    """
    import base64
    import binascii
    import hashlib

    if not validate_case_id(case_id):
        return {"status": "error",
                "error": "Invalid case_id (must match [A-Za-z0-9_-]+)"}

    if not content_b64:
        return {"status": "error", "error": "content_b64 is empty"}

    try:
        data = base64.b64decode(content_b64, validate=False)
    except (binascii.Error, ValueError) as exc:
        return {"status": "error", "error": f"invalid base64: {exc}"}

    if not data:
        return {"status": "error", "error": "decoded content is empty"}

    if len(data) > max_bytes:
        return {
            "status": "error",
            "error": (
                f"file exceeds in-band cap "
                f"({len(data)} > {max_bytes} bytes). Use prepare_file_upload "
                f"+ HTTP for larger samples."
            ),
        }

    target = expected_artefact_path(case_id=case_id, filename=filename)
    case_dir = (CASES_DIR / case_id).resolve()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"status": "error", "error": f"could not create upload dir: {exc}"}

    # Resolve after mkdir so symlink games can't redirect us mid-flight.
    try:
        target.parent.resolve().relative_to(case_dir)
    except ValueError:
        return {"status": "error", "error": "target path escapes case dir"}

    tmp = target.with_suffix(target.suffix + ".part")
    try:
        tmp.write_bytes(data)
        tmp.replace(target)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        return {"status": "error", "error": f"write failed: {exc}"}

    sha256 = hashlib.sha256(data).hexdigest()
    return {
        "status": "ok",
        "case_id": case_id,
        "filename": filename,
        "path": str(target),
        "bytes": len(data),
        "sha256": sha256,
        "next_step": (
            f"Call analyse_file(file_path='{target}', "
            f"case_id='{case_id}') to triage the sample."
        ),
    }


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------

async def _send_json(send, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            [b"content-type", b"application/json"],
            [b"content-length", str(len(body)).encode()],
            [b"cache-control", b"no-store"],
        ],
    })
    await send({"type": "http.response.body", "body": body})


def _parse_route(path: str) -> str | None:
    """Parse ``/cases/<id>/uploads`` → case_id."""
    if not path.startswith(_ROUTE_PREFIX) or not path.endswith(_ROUTE_SUFFIX):
        return None
    middle = path[len(_ROUTE_PREFIX):-len(_ROUTE_SUFFIX)]
    if not middle or "/" in middle:
        return None
    return middle


def _extract_query(scope) -> dict[str, str]:
    raw = scope.get("query_string", b"")
    if not raw:
        return {}
    try:
        params = parse_qs(raw.decode("utf-8"))
    except Exception:
        return {}
    return {k: v[0] for k, v in params.items() if v}


class UploadsMiddleware:
    """ASGI middleware that handles ``POST /cases/<id>/uploads``."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        case_id = _parse_route(path)
        if case_id is None:
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "").upper()
        if method != "POST":
            await _send_json(send, 405, {"error": "Method not allowed; POST required"})
            return

        # _parse_route rejects "/" in the id, but "." / ".." still slip
        # through it — and the escape guard below derives its root from this
        # same untrusted id, so it can never catch that. Gate hard here.
        if not validate_case_id(case_id):
            mcp_log("upload_rejected", case_id=case_id,
                    reason="invalid case_id")
            await _send_json(send, 400,
                             {"error": "Invalid case_id (must match "
                                       "[A-Za-z0-9_-]+)"})
            return

        query = _extract_query(scope)
        token = query.get("token")
        raw_filename = query.get("filename") or ""

        if not token:
            await _send_json(send, 401, {"error": "Missing token"})
            return

        filename = sanitise_filename(raw_filename)
        if filename is None:
            await _send_json(send, 400, {"error": "Missing or unusable filename"})
            return

        try:
            claims = jwt.decode(
                token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                audience=UPLOAD_AUDIENCE,
            )
        except JWTError as exc:
            mcp_log("upload_token_invalid", reason=str(exc),
                    case_id=case_id, filename=filename)
            await _send_json(send, 401, {"error": "Invalid or expired token"})
            return

        if claims.get("case_id") != case_id or claims.get("filename") != filename:
            mcp_log("upload_token_mismatch",
                    case_id=case_id, filename=filename,
                    claim_case=claims.get("case_id"),
                    claim_filename=claims.get("filename"))
            await _send_json(send, 403,
                             {"error": "Token does not grant this case/filename"})
            return

        # Resolve target path and guard against escape via symlink / traversal.
        case_dir = (CASES_DIR / case_id).resolve()
        upload_dir = (case_dir / _UPLOAD_SUBDIR).resolve()
        try:
            upload_dir.relative_to(case_dir)
        except ValueError:
            await _send_json(send, 500, {"error": "Upload dir escapes case dir"})
            return
        upload_dir.mkdir(parents=True, exist_ok=True)
        target = (upload_dir / filename).resolve()
        try:
            target.relative_to(upload_dir)
        except ValueError:
            await _send_json(send, 400, {"error": "Filename escapes upload dir"})
            return

        # Stream the body to disk with a hard cap. Aborts cleanly if the client
        # tries to send more than MCP_UPLOAD_MAX_BYTES.
        total = 0
        sha = hashlib.sha256()
        tmp = target.with_suffix(target.suffix + ".part")
        try:
            with open(tmp, "wb") as fh:
                while True:
                    msg = await receive()
                    if msg["type"] == "http.disconnect":
                        raise ConnectionError("client disconnected mid-upload")
                    if msg["type"] != "http.request":
                        continue
                    chunk = msg.get("body", b"")
                    if chunk:
                        total += len(chunk)
                        if total > MCP_UPLOAD_MAX_BYTES:
                            raise ValueError(
                                f"upload exceeds {MCP_UPLOAD_MAX_BYTES} bytes"
                            )
                        sha.update(chunk)
                        fh.write(chunk)
                    if not msg.get("more_body", False):
                        break
            if total == 0:
                tmp.unlink(missing_ok=True)
                await _send_json(send, 400, {"error": "Empty body"})
                return
            tmp.replace(target)
        except ValueError as exc:
            tmp.unlink(missing_ok=True)
            mcp_log("upload_rejected", case_id=case_id, filename=filename,
                    reason=str(exc), bytes=total)
            await _send_json(send, 413, {"error": str(exc)})
            return
        except (OSError, ConnectionError) as exc:
            tmp.unlink(missing_ok=True)
            mcp_log("upload_failed", case_id=case_id, filename=filename,
                    error=str(exc), bytes=total)
            await _send_json(send, 500, {"error": "Upload failed", "detail": str(exc)})
            return

        sha256 = sha.hexdigest()
        mcp_log("upload_stored",
                case_id=case_id, filename=filename, bytes=total,
                sha256=sha256, caller=claims.get("sub"))

        await _send_json(send, 201, {
            "status": "ok",
            "case_id": case_id,
            "filename": filename,
            "path": str(target),
            "bytes": total,
            "sha256": sha256,
            "next_step": (
                f"Call analyse_file(file_path='{target}', "
                f"case_id='{case_id}') to triage the sample."
            ),
        })


def install_uploads_endpoint(server) -> None:
    """Wrap the FastMCP ASGI app builders so upload requests are served
    alongside MCP traffic on whichever network transport is active."""
    for attr in ("sse_app", "streamable_http_app"):
        original = getattr(server, attr, None)
        if original is None:
            continue

        def _make_patched(orig):
            def patched(*args, **kwargs):
                return UploadsMiddleware(orig(*args, **kwargs))
            return patched

        setattr(server, attr, _make_patched(original))
