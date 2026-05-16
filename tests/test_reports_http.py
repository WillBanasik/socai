"""Tests for the one-click report URL feature.

Covers:
  - mint_report_token / build_report_url round-trip
  - ReportsMiddleware: happy path, missing token, wrong token, expired token,
    case_id mismatch, unknown report_type, path traversal, file missing,
    wrong HTTP method, unrelated paths pass through.
"""
import json
import shutil
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_CASE = "IV_CASE_000"


@pytest.fixture(autouse=True)
def cleanup_test_case():
    from config.settings import CASES_DIR, REGISTRY_FILE

    def _rm():
        case_dir = CASES_DIR / TEST_CASE
        if case_dir.exists():
            shutil.rmtree(case_dir)
        if REGISTRY_FILE.exists():
            data = json.loads(REGISTRY_FILE.read_text())
            data.get("cases", {}).pop(TEST_CASE, None)
            REGISTRY_FILE.write_text(json.dumps(data, indent=2))

    _rm()
    yield
    _rm()


# ---------------------------------------------------------------------------
# ASGI test harness
# ---------------------------------------------------------------------------

class _Collector:
    """Capture ASGI send events into a single response dict."""

    def __init__(self):
        self.status: int | None = None
        self.headers: list[tuple[bytes, bytes]] = []
        self.body: bytes = b""

    async def send(self, message):
        if message["type"] == "http.response.start":
            self.status = message["status"]
            self.headers = [tuple(h) for h in message["headers"]]
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


def _make_scope(path: str, query: str = "", method: str = "GET"):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query.encode(),
        "headers": [],
        "client": ("127.0.0.1", 0),
    }


def _drive(middleware, scope) -> _Collector:
    import asyncio
    collector = _Collector()
    asyncio.run(middleware(scope, _receive, collector.send))
    return collector


@pytest.fixture
def passthrough_middleware():
    from mcp_server.reports_http import ReportsMiddleware

    pass_state = {"called": False}

    async def inner_app(scope, receive, send):
        pass_state["called"] = True
        await send({
            "type": "http.response.start", "status": 200,
            "headers": [[b"content-type", b"text/plain"]],
        })
        await send({"type": "http.response.body", "body": b"inner"})

    return ReportsMiddleware(inner_app), pass_state


@pytest.fixture
def mdr_report_on_disk():
    from tools.case_create import case_create
    from tools.save_report import save_report_to_case

    case_create(TEST_CASE, title="report http test", severity="low",
                client="Test Client")
    html = "<!DOCTYPE html><html><body><h1>MDR — test</h1></body></html>"
    result = save_report_to_case(
        case_id=TEST_CASE, report_type="mdr_report", report_text=html,
    )
    assert result["status"] == "ok"
    return html


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def test_mint_and_build_url_round_trip():
    from mcp_server.reports_http import (
        mint_report_token, build_report_url, REPORT_AUDIENCE,
    )
    from api.auth import JWT_SECRET, JWT_ALGORITHM
    from jose import jwt

    token = mint_report_token(
        case_id="IV_CASE_001", report_type="mdr_report",
        caller_email="analyst@example.com",
    )
    claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                        audience=REPORT_AUDIENCE)
    assert claims["case_id"] == "IV_CASE_001"
    assert claims["report_type"] == "mdr_report"
    assert claims["sub"] == "analyst@example.com"
    assert claims["exp"] > claims["iat"]

    url = build_report_url(
        case_id="IV_CASE_001", report_type="mdr_report", token=token,
    )
    assert "/cases/IV_CASE_001/reports/mdr_report" in url
    assert "token=" in url


# ---------------------------------------------------------------------------
# Middleware: happy path
# ---------------------------------------------------------------------------

def test_middleware_serves_report_with_valid_token(passthrough_middleware,
                                                    mdr_report_on_disk):
    from mcp_server.reports_http import mint_report_token

    middleware, pass_state = passthrough_middleware
    token = mint_report_token(case_id=TEST_CASE, report_type="mdr_report",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query=f"token={token}")

    resp = _drive(middleware, scope)

    assert resp.status == 200
    assert pass_state["called"] is False  # intercepted, not passed through
    assert b"MDR \xe2\x80\x94 test" in resp.body  # em-dash UTF-8
    headers = {k.decode(): v.decode() for k, v in resp.headers}
    assert headers["content-type"].startswith("text/html")
    assert headers["content-disposition"] == "inline"


def test_middleware_head_request_returns_no_body(passthrough_middleware,
                                                  mdr_report_on_disk):
    from mcp_server.reports_http import mint_report_token

    middleware, _ = passthrough_middleware
    token = mint_report_token(case_id=TEST_CASE, report_type="mdr_report",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query=f"token={token}", method="HEAD")

    resp = _drive(middleware, scope)
    assert resp.status == 200
    assert resp.body == b""


# ---------------------------------------------------------------------------
# Middleware: auth + authorisation failures
# ---------------------------------------------------------------------------

def test_middleware_missing_token_returns_401(passthrough_middleware):
    middleware, _ = passthrough_middleware
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report")
    resp = _drive(middleware, scope)
    assert resp.status == 401


def test_middleware_garbage_token_returns_401(passthrough_middleware):
    middleware, _ = passthrough_middleware
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query="token=not-a-jwt")
    resp = _drive(middleware, scope)
    assert resp.status == 401


def test_middleware_expired_token_returns_401(passthrough_middleware,
                                               mdr_report_on_disk):
    from mcp_server.reports_http import mint_report_token

    middleware, _ = passthrough_middleware
    # Negative TTL → already-expired token
    token = mint_report_token(case_id=TEST_CASE, report_type="mdr_report",
                              caller_email="a@b.c", ttl_seconds=-60)
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query=f"token={token}")
    resp = _drive(middleware, scope)
    assert resp.status == 401


def test_middleware_token_bound_to_different_case_returns_403(
        passthrough_middleware, mdr_report_on_disk):
    from mcp_server.reports_http import mint_report_token

    middleware, _ = passthrough_middleware
    # Mint a token for a DIFFERENT case, try to use it on TEST_CASE
    token = mint_report_token(case_id="IV_CASE_999", report_type="mdr_report",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query=f"token={token}")
    resp = _drive(middleware, scope)
    assert resp.status == 403


def test_middleware_token_bound_to_different_report_type_returns_403(
        passthrough_middleware, mdr_report_on_disk):
    from mcp_server.reports_http import mint_report_token

    middleware, _ = passthrough_middleware
    token = mint_report_token(case_id=TEST_CASE, report_type="pup_report",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query=f"token={token}")
    resp = _drive(middleware, scope)
    assert resp.status == 403


def test_middleware_token_with_wrong_audience_returns_401(passthrough_middleware,
                                                          mdr_report_on_disk):
    from api.auth import JWT_SECRET, JWT_ALGORITHM
    from jose import jwt

    middleware, _ = passthrough_middleware
    # Mint a token with the API audience, not the report audience
    bad = jwt.encode(
        {"sub": "x", "case_id": TEST_CASE, "report_type": "mdr_report",
         "aud": "socai-api", "exp": int(time.time()) + 60},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query=f"token={bad}")
    resp = _drive(middleware, scope)
    assert resp.status == 401


# ---------------------------------------------------------------------------
# Middleware: resource resolution
# ---------------------------------------------------------------------------

def test_middleware_unknown_report_type_returns_404(passthrough_middleware,
                                                     mdr_report_on_disk):
    from mcp_server.reports_http import mint_report_token

    middleware, _ = passthrough_middleware
    token = mint_report_token(case_id=TEST_CASE, report_type="bogus_report",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/bogus_report",
                        query=f"token={token}")
    resp = _drive(middleware, scope)
    assert resp.status == 404


def test_middleware_report_not_yet_saved_returns_404(passthrough_middleware):
    from tools.case_create import case_create
    from mcp_server.reports_http import mint_report_token

    case_create(TEST_CASE, title="empty", severity="low",
                client="Test Client")
    middleware, _ = passthrough_middleware
    token = mint_report_token(case_id=TEST_CASE, report_type="mdr_report",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query=f"token={token}")
    resp = _drive(middleware, scope)
    assert resp.status == 404


def test_middleware_path_traversal_blocked(passthrough_middleware):
    from mcp_server.reports_http import _resolve_report_path
    # Direct resolver test — any report_type that's not in _REPORT_TYPES
    # cannot escape the case dir because the resolver returns None.
    assert _resolve_report_path("IV_CASE_000", "../../../etc/passwd") is None
    # And a route with literal slashes won't even parse:
    middleware, _ = passthrough_middleware
    scope = _make_scope("/cases/IV_CASE_000/reports/../mdr_report")
    resp = _drive(middleware, scope)
    # parse_route requires exactly 3 segments after /cases/ — extra slashes
    # mean it falls through to inner app (which would be the MCP app, 404).
    # Either way: we MUST NOT serve a 200.
    assert resp.status != 200


# ---------------------------------------------------------------------------
# Middleware: routing + method handling
# ---------------------------------------------------------------------------

def test_middleware_passes_through_unrelated_paths(passthrough_middleware):
    middleware, pass_state = passthrough_middleware
    scope = _make_scope("/sse")
    resp = _drive(middleware, scope)
    assert pass_state["called"] is True
    assert resp.body == b"inner"


def test_middleware_rejects_post(passthrough_middleware, mdr_report_on_disk):
    from mcp_server.reports_http import mint_report_token

    middleware, _ = passthrough_middleware
    token = mint_report_token(case_id=TEST_CASE, report_type="mdr_report",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query=f"token={token}", method="POST")
    resp = _drive(middleware, scope)
    assert resp.status == 405
