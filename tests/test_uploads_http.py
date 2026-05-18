"""Tests for the cross-sandbox upload endpoint.

Covers:
  - sanitise_filename: traversal, dotfiles, unsafe chars, length cap
  - mint_upload_token / build_upload_url round-trip
  - UploadsMiddleware: happy path, missing token, garbage token, expired,
    case mismatch, filename mismatch, wrong audience, oversize, empty body,
    method handling, unrelated path passthrough.
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
# ASGI test harness — supports POST bodies
# ---------------------------------------------------------------------------

class _Collector:
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


def _make_receiver(body: bytes, chunk_size: int = 64 * 1024):
    """ASGI receive() that streams ``body`` in chunks, then EOF."""
    chunks = [body[i:i + chunk_size] for i in range(0, len(body), chunk_size)] or [b""]
    idx = {"i": 0}

    async def receive():
        i = idx["i"]
        if i >= len(chunks):
            return {"type": "http.request", "body": b"", "more_body": False}
        chunk = chunks[i]
        idx["i"] += 1
        more = idx["i"] < len(chunks)
        return {"type": "http.request", "body": chunk, "more_body": more}

    return receive


def _make_scope(path: str, query: str = "", method: str = "POST"):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query.encode(),
        "headers": [],
        "client": ("127.0.0.1", 0),
    }


def _drive(middleware, scope, body: bytes = b"") -> _Collector:
    import asyncio
    collector = _Collector()
    asyncio.run(middleware(scope, _make_receiver(body), collector.send))
    return collector


def _decoded(resp: _Collector) -> dict:
    return json.loads(resp.body.decode())


@pytest.fixture
def passthrough_middleware():
    from mcp_server.uploads_http import UploadsMiddleware

    pass_state = {"called": False}

    async def inner_app(scope, receive, send):
        pass_state["called"] = True
        await send({
            "type": "http.response.start", "status": 200,
            "headers": [[b"content-type", b"text/plain"]],
        })
        await send({"type": "http.response.body", "body": b"inner"})

    return UploadsMiddleware(inner_app), pass_state


@pytest.fixture
def case_on_disk():
    from tools.case_create import case_create
    case_create(TEST_CASE, title="upload test", severity="low",
                client="Test Client")


# ---------------------------------------------------------------------------
# sanitise_filename
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("sample.pdf", "sample.pdf"),
    ("a/b/c.docx", "c.docx"),
    ("../../etc/passwd", "passwd"),
    ("/absolute/path/x.exe", "x.exe"),
    ("weird name with spaces!.bin", "weird_name_with_spaces_.bin"),
    (".hidden", "hidden"),
    ("..", None),
    ("....", None),
    ("", None),
    (None, None),
])
def test_sanitise_filename(raw, expected):
    from mcp_server.uploads_http import sanitise_filename
    assert sanitise_filename(raw) == expected


def test_sanitise_filename_length_capped():
    from mcp_server.uploads_http import sanitise_filename
    out = sanitise_filename("a" * 500 + ".bin")
    assert out is not None
    assert len(out) <= 200


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def test_mint_and_build_url_round_trip():
    from mcp_server.uploads_http import (
        mint_upload_token, build_upload_url, UPLOAD_AUDIENCE,
    )
    from api.auth import JWT_SECRET, JWT_ALGORITHM
    from jose import jwt

    token = mint_upload_token(
        case_id="IV_CASE_001", filename="sample.pdf",
        caller_email="analyst@example.com",
    )
    claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                        audience=UPLOAD_AUDIENCE)
    assert claims["case_id"] == "IV_CASE_001"
    assert claims["filename"] == "sample.pdf"
    assert claims["sub"] == "analyst@example.com"
    assert claims["exp"] > claims["iat"]

    url = build_upload_url(case_id="IV_CASE_001", filename="sample.pdf",
                           token=token)
    assert "/cases/IV_CASE_001/uploads" in url
    assert "token=" in url
    assert "filename=sample.pdf" in url


# ---------------------------------------------------------------------------
# Middleware: happy path
# ---------------------------------------------------------------------------

def test_middleware_stores_file_with_valid_token(passthrough_middleware,
                                                  case_on_disk):
    import hashlib
    from mcp_server.uploads_http import (
        mint_upload_token, expected_artefact_path,
    )

    middleware, pass_state = passthrough_middleware
    fname = "sample.pdf"
    body = b"%PDF-1.4\n" + b"X" * 1000
    expected_sha = hashlib.sha256(body).hexdigest()

    token = mint_upload_token(case_id=TEST_CASE, filename=fname,
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}&filename={fname}")
    resp = _drive(middleware, scope, body=body)

    assert pass_state["called"] is False
    assert resp.status == 201
    payload = _decoded(resp)
    assert payload["status"] == "ok"
    assert payload["bytes"] == len(body)
    assert payload["sha256"] == expected_sha

    on_disk = expected_artefact_path(case_id=TEST_CASE, filename=fname)
    assert on_disk.is_file()
    assert on_disk.read_bytes() == body
    # No leftover .part file
    assert not on_disk.with_suffix(on_disk.suffix + ".part").exists()


def test_middleware_sanitises_filename_in_storage(passthrough_middleware,
                                                    case_on_disk):
    from mcp_server.uploads_http import (
        mint_upload_token, expected_artefact_path, sanitise_filename,
    )

    middleware, _ = passthrough_middleware
    raw = "weird name!.bin"
    safe = sanitise_filename(raw)
    token = mint_upload_token(case_id=TEST_CASE, filename=safe,
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}&filename={safe}")
    resp = _drive(middleware, scope, body=b"abc")
    assert resp.status == 201

    on_disk = expected_artefact_path(case_id=TEST_CASE, filename=safe)
    assert on_disk.is_file()
    # Original (unsafe) name must NOT exist
    assert not (on_disk.parent / raw).exists()


# ---------------------------------------------------------------------------
# Middleware: auth + authorisation failures
# ---------------------------------------------------------------------------

def test_middleware_missing_token_returns_401(passthrough_middleware):
    middleware, _ = passthrough_middleware
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query="filename=x.pdf")
    resp = _drive(middleware, scope, body=b"data")
    assert resp.status == 401


def test_middleware_missing_filename_returns_400(passthrough_middleware):
    from mcp_server.uploads_http import mint_upload_token
    middleware, _ = passthrough_middleware
    token = mint_upload_token(case_id=TEST_CASE, filename="x.pdf",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}")
    resp = _drive(middleware, scope, body=b"data")
    assert resp.status == 400


def test_middleware_garbage_token_returns_401(passthrough_middleware):
    middleware, _ = passthrough_middleware
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query="token=not-a-jwt&filename=x.pdf")
    resp = _drive(middleware, scope, body=b"data")
    assert resp.status == 401


def test_middleware_expired_token_returns_401(passthrough_middleware,
                                                case_on_disk):
    from mcp_server.uploads_http import mint_upload_token
    middleware, _ = passthrough_middleware
    token = mint_upload_token(case_id=TEST_CASE, filename="x.pdf",
                              caller_email="a@b.c", ttl_seconds=-60)
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}&filename=x.pdf")
    resp = _drive(middleware, scope, body=b"data")
    assert resp.status == 401


def test_middleware_token_bound_to_different_case_returns_403(
        passthrough_middleware, case_on_disk):
    from mcp_server.uploads_http import mint_upload_token
    middleware, _ = passthrough_middleware
    token = mint_upload_token(case_id="IV_CASE_999", filename="x.pdf",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}&filename=x.pdf")
    resp = _drive(middleware, scope, body=b"data")
    assert resp.status == 403


def test_middleware_token_bound_to_different_filename_returns_403(
        passthrough_middleware, case_on_disk):
    from mcp_server.uploads_http import mint_upload_token
    middleware, _ = passthrough_middleware
    token = mint_upload_token(case_id=TEST_CASE, filename="benign.pdf",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}&filename=malicious.exe")
    resp = _drive(middleware, scope, body=b"data")
    assert resp.status == 403


def test_middleware_token_with_wrong_audience_returns_401(passthrough_middleware,
                                                           case_on_disk):
    from api.auth import JWT_SECRET, JWT_ALGORITHM
    from jose import jwt
    middleware, _ = passthrough_middleware
    bad = jwt.encode(
        {"sub": "x", "case_id": TEST_CASE, "filename": "x.pdf",
         "aud": "socai-report", "exp": int(time.time()) + 60},
        JWT_SECRET, algorithm=JWT_ALGORITHM,
    )
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={bad}&filename=x.pdf")
    resp = _drive(middleware, scope, body=b"data")
    assert resp.status == 401


# ---------------------------------------------------------------------------
# Middleware: body validation
# ---------------------------------------------------------------------------

def test_middleware_oversize_body_returns_413(passthrough_middleware,
                                                case_on_disk, monkeypatch):
    from mcp_server import uploads_http
    monkeypatch.setattr(uploads_http, "MCP_UPLOAD_MAX_BYTES", 100)

    from mcp_server.uploads_http import (
        mint_upload_token, expected_artefact_path,
    )
    middleware, _ = passthrough_middleware
    token = mint_upload_token(case_id=TEST_CASE, filename="big.bin",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}&filename=big.bin")
    resp = _drive(middleware, scope, body=b"X" * 500)
    assert resp.status == 413

    # No partial file left behind
    target = expected_artefact_path(case_id=TEST_CASE, filename="big.bin")
    assert not target.exists()
    assert not target.with_suffix(target.suffix + ".part").exists()


def test_middleware_empty_body_returns_400(passthrough_middleware, case_on_disk):
    from mcp_server.uploads_http import (
        mint_upload_token, expected_artefact_path,
    )
    middleware, _ = passthrough_middleware
    token = mint_upload_token(case_id=TEST_CASE, filename="empty.pdf",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}&filename=empty.pdf")
    resp = _drive(middleware, scope, body=b"")
    assert resp.status == 400

    target = expected_artefact_path(case_id=TEST_CASE, filename="empty.pdf")
    assert not target.exists()


# ---------------------------------------------------------------------------
# Middleware: routing + method handling
# ---------------------------------------------------------------------------

def test_middleware_rejects_get(passthrough_middleware, case_on_disk):
    from mcp_server.uploads_http import mint_upload_token
    middleware, _ = passthrough_middleware
    token = mint_upload_token(case_id=TEST_CASE, filename="x.pdf",
                              caller_email="a@b.c")
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads",
                        query=f"token={token}&filename=x.pdf", method="GET")
    resp = _drive(middleware, scope)
    assert resp.status == 405


def test_middleware_passes_through_unrelated_paths(passthrough_middleware):
    middleware, pass_state = passthrough_middleware
    scope = _make_scope("/sse", method="GET")
    resp = _drive(middleware, scope)
    assert pass_state["called"] is True
    assert resp.body == b"inner"


def test_middleware_passes_through_reports_path(passthrough_middleware):
    """The reports middleware owns /cases/<id>/reports/... — the uploads
    middleware must not intercept it."""
    middleware, pass_state = passthrough_middleware
    scope = _make_scope(f"/cases/{TEST_CASE}/reports/mdr_report",
                        query="token=x", method="GET")
    resp = _drive(middleware, scope)
    assert pass_state["called"] is True


def test_middleware_extra_path_segments_pass_through(passthrough_middleware):
    middleware, pass_state = passthrough_middleware
    scope = _make_scope(f"/cases/{TEST_CASE}/uploads/extra")
    resp = _drive(middleware, scope, body=b"data")
    # Falls through to inner app; either way must not be a 201 from us
    assert resp.status != 201


# ---------------------------------------------------------------------------
# In-band base64 upload (store_inband_upload) — used when the calling sandbox
# can't reach the HTTP endpoint over the network.
# ---------------------------------------------------------------------------

def test_inband_upload_writes_file(case_on_disk):
    import base64, hashlib
    from mcp_server.uploads_http import store_inband_upload, expected_artefact_path

    body = b"%PDF-1.4\n" + b"X" * 2048
    b64 = base64.b64encode(body).decode()
    result = store_inband_upload(
        case_id=TEST_CASE, filename="sample.pdf", content_b64=b64,
        max_bytes=1_000_000,
    )
    assert result["status"] == "ok"
    assert result["bytes"] == len(body)
    assert result["sha256"] == hashlib.sha256(body).hexdigest()

    on_disk = expected_artefact_path(case_id=TEST_CASE, filename="sample.pdf")
    assert on_disk.is_file()
    assert on_disk.read_bytes() == body
    # No leftover .part file
    assert not on_disk.with_suffix(on_disk.suffix + ".part").exists()


def test_inband_upload_tolerates_whitespace_in_b64(case_on_disk):
    """base64 with newlines (as produced by ``base64 file`` without -w0)
    must still decode — common case from copy/paste pipelines."""
    import base64
    from mcp_server.uploads_http import store_inband_upload

    body = b"hello world" * 100
    b64 = base64.b64encode(body).decode()
    # Inject newlines every 60 chars (matches GNU base64 default)
    chunked = "\n".join(b64[i:i+60] for i in range(0, len(b64), 60))
    result = store_inband_upload(
        case_id=TEST_CASE, filename="ws.bin", content_b64=chunked,
        max_bytes=1_000_000,
    )
    assert result["status"] == "ok"
    assert result["bytes"] == len(body)


def test_inband_upload_empty_content_rejected(case_on_disk):
    from mcp_server.uploads_http import store_inband_upload
    result = store_inband_upload(
        case_id=TEST_CASE, filename="x.bin", content_b64="",
        max_bytes=1_000_000,
    )
    assert result["status"] == "error"
    assert "empty" in result["error"].lower()


def test_inband_upload_invalid_base64_rejected(case_on_disk):
    from mcp_server.uploads_http import store_inband_upload
    result = store_inband_upload(
        case_id=TEST_CASE, filename="x.bin", content_b64="!!!not-base64!!!",
        max_bytes=1_000_000,
    )
    assert result["status"] == "error"
    # Either decoded to empty (lenient mode strips garbage) or returned a
    # base64 error — both are acceptable rejection paths.
    assert ("base64" in result["error"].lower()
            or "empty" in result["error"].lower())


def test_inband_upload_oversize_rejected(case_on_disk):
    import base64
    from mcp_server.uploads_http import store_inband_upload, expected_artefact_path

    body = b"X" * 500
    b64 = base64.b64encode(body).decode()
    result = store_inband_upload(
        case_id=TEST_CASE, filename="big.bin", content_b64=b64,
        max_bytes=100,
    )
    assert result["status"] == "error"
    assert "exceed" in result["error"].lower() or "cap" in result["error"].lower()

    # No partial / final file on disk
    target = expected_artefact_path(case_id=TEST_CASE, filename="big.bin")
    assert not target.exists()
    assert not target.with_suffix(target.suffix + ".part").exists()


def test_inband_upload_atomic_replace_overwrites_previous(case_on_disk):
    """Re-uploading the same filename replaces the bytes atomically — no
    half-written file, no .part leftover."""
    import base64
    from mcp_server.uploads_http import store_inband_upload, expected_artefact_path

    first = base64.b64encode(b"first version").decode()
    second = base64.b64encode(b"SECOND VERSION - replaced").decode()
    store_inband_upload(case_id=TEST_CASE, filename="x.bin",
                        content_b64=first, max_bytes=1_000_000)
    r2 = store_inband_upload(case_id=TEST_CASE, filename="x.bin",
                             content_b64=second, max_bytes=1_000_000)
    assert r2["status"] == "ok"
    on_disk = expected_artefact_path(case_id=TEST_CASE, filename="x.bin")
    assert on_disk.read_bytes() == b"SECOND VERSION - replaced"
    assert not on_disk.with_suffix(on_disk.suffix + ".part").exists()
