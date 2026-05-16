"""One-click HTTP serving for saved reports.

Reports are persisted server-side by ``tools/save_report.py``. The analyst
should be able to open them in their browser with a single click from the
Claude Desktop tool response — no follow-up prompt, no filesystem MCP, no
manual URL construction.

The middleware exposes::

    GET /cases/<case_id>/reports/<report_type>?token=<signed>

The token is a short-lived JWT minted by ``mint_report_token()`` at
``save_report`` time. It binds the grantee (caller email), the resource
(case_id + report_type), and an expiry. Claims:

    sub        — caller email (audit trail)
    case_id    — bound case
    report_type — bound report kind (mdr_report, pup_report, …)
    aud        — "socai-report" (separates these tokens from API JWTs)
    exp        — Unix seconds

In stdio mode (local trust, no JWT auth on the MCP transport) the token is
still signed with the project's ``JWT_SECRET`` — the secret is always
present locally — so the same code path works in dev and prod.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import quote, parse_qs

from jose import JWTError, jwt

from api.auth import JWT_ALGORITHM, JWT_SECRET
from config.settings import CASES_DIR
from mcp_server.config import MCP_PUBLIC_BASE_URL, MCP_REPORT_TOKEN_TTL_SECONDS
from mcp_server.logging_config import mcp_log
from tools.save_report import _REPORT_TYPES


REPORT_AUDIENCE = "socai-report"
_ROUTE_PREFIX = "/cases/"
_ROUTE_INFIX = "/reports/"


# ---------------------------------------------------------------------------
# Token minting (called from the save_report tool wrapper)
# ---------------------------------------------------------------------------

def mint_report_token(
    *,
    case_id: str,
    report_type: str,
    caller_email: str,
    ttl_seconds: int | None = None,
) -> str:
    """Mint a short-lived JWT granting one-click read access to a single report."""
    ttl = ttl_seconds if ttl_seconds is not None else MCP_REPORT_TOKEN_TTL_SECONDS
    now = int(time.time())
    payload = {
        "sub": caller_email or "local",
        "case_id": case_id,
        "report_type": report_type,
        "aud": REPORT_AUDIENCE,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def build_report_url(*, case_id: str, report_type: str, token: str) -> str:
    """Build the absolute one-click URL for a saved report."""
    return (
        f"{MCP_PUBLIC_BASE_URL}{_ROUTE_PREFIX}{quote(case_id)}"
        f"{_ROUTE_INFIX}{quote(report_type)}?token={quote(token)}"
    )


# ---------------------------------------------------------------------------
# ASGI middleware
# ---------------------------------------------------------------------------

def _resolve_report_path(case_id: str, report_type: str) -> Path | None:
    """Resolve a (case_id, report_type) pair to the on-disk report file.

    Returns ``None`` if the report_type is unknown, the path escapes the
    case directory, or the file does not exist.
    """
    cfg = _REPORT_TYPES.get(report_type)
    if cfg is None:
        return None
    case_dir = (CASES_DIR / case_id).resolve()
    candidate = (case_dir / cfg["path"]).resolve()
    try:
        candidate.relative_to(case_dir)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


async def _send_error(send, status: int, message: str) -> None:
    body = json.dumps({"error": message}).encode()
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


async def _send_html(send, html_bytes: bytes) -> None:
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [
            [b"content-type", b"text/html; charset=utf-8"],
            [b"content-length", str(len(html_bytes)).encode()],
            [b"cache-control", b"private, no-store"],
            [b"content-disposition", b"inline"],
            [b"x-content-type-options", b"nosniff"],
            [b"referrer-policy", b"no-referrer"],
        ],
    })
    await send({"type": "http.response.body", "body": html_bytes})


def _parse_route(path: str) -> tuple[str, str] | None:
    """Parse ``/cases/<id>/reports/<type>`` → (case_id, report_type)."""
    if not path.startswith(_ROUTE_PREFIX):
        return None
    rest = path[len(_ROUTE_PREFIX):]
    if _ROUTE_INFIX.strip("/") not in rest:
        return None
    parts = rest.split("/", 2)
    if len(parts) != 3 or parts[1] != "reports":
        return None
    case_id, _, report_type = parts
    if not case_id or not report_type:
        return None
    return case_id, report_type


def _extract_token(scope) -> str | None:
    query = scope.get("query_string", b"")
    if not query:
        return None
    try:
        params = parse_qs(query.decode("utf-8"))
    except Exception:
        return None
    tokens = params.get("token") or []
    return tokens[0] if tokens else None


class ReportsMiddleware:
    """ASGI middleware that intercepts ``GET /cases/<id>/reports/<type>``."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        parsed = _parse_route(path)
        if parsed is None:
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        if method not in ("GET", "HEAD"):
            await _send_error(send, 405, "Method not allowed")
            return

        case_id, report_type = parsed

        token = _extract_token(scope)
        if not token:
            await _send_error(send, 401, "Missing token")
            return

        try:
            claims = jwt.decode(
                token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                audience=REPORT_AUDIENCE,
            )
        except JWTError as exc:
            mcp_log("report_token_invalid", reason=str(exc), case_id=case_id,
                    report_type=report_type)
            await _send_error(send, 401, "Invalid or expired token")
            return

        if claims.get("case_id") != case_id or claims.get("report_type") != report_type:
            mcp_log("report_token_mismatch", case_id=case_id, report_type=report_type,
                    claim_case=claims.get("case_id"),
                    claim_report=claims.get("report_type"))
            await _send_error(send, 403, "Token does not grant this resource")
            return

        report_path = _resolve_report_path(case_id, report_type)
        if report_path is None:
            await _send_error(send, 404, "Report not found")
            return

        try:
            html_bytes = report_path.read_bytes()
        except OSError as exc:
            mcp_log("report_read_error", path=str(report_path), error=str(exc))
            await _send_error(send, 500, "Failed to read report")
            return

        mcp_log("report_served",
                case_id=case_id, report_type=report_type,
                bytes=len(html_bytes), caller=claims.get("sub"))

        if method == "HEAD":
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    [b"content-type", b"text/html; charset=utf-8"],
                    [b"content-length", str(len(html_bytes)).encode()],
                ],
            })
            await send({"type": "http.response.body", "body": b""})
            return

        await _send_html(send, html_bytes)


def install_reports_endpoint(server) -> None:
    """Wrap the FastMCP ASGI app builders so report URLs are served alongside
    MCP traffic, regardless of which network transport is active."""
    for attr in ("sse_app", "streamable_http_app"):
        original = getattr(server, attr, None)
        if original is None:
            continue

        def _make_patched(orig):
            def patched(*args, **kwargs):
                return ReportsMiddleware(orig(*args, **kwargs))
            return patched

        setattr(server, attr, _make_patched(original))
