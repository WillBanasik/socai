"""Platform schema fetcher — pulls schemas from the external schema project.

In production, platform schemas (tables, columns, field types) are maintained
in a separate project so SOCAI doesn't have to ship them. This module:
  * Reads a manifest from SOCAI_SCHEMA_SOURCE_URL
  * Pulls each platform's schema and writes to ``config/schemas/<id>.json``
  * Honours ETag for incremental refresh
  * Falls back to cached copies on network failure
  * Refreshes periodically based on SOCAI_SCHEMA_REFRESH_HOURS

Public API
----------
ensure_schema(platform_id)    → Path to local cached schema (fetch if stale/missing)
refresh_all()                 → Pull every entry in the manifest. Returns summary dict.
get_schema(platform_id)       → Parsed JSON of the cached schema, or None.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import (
    SCHEMAS_DIR,
    SOCAI_SCHEMA_API_KEY,
    SOCAI_SCHEMA_REFRESH_HOURS,
    SOCAI_SCHEMA_SOURCE_URL,
)
from tools.common import log_error, utcnow

_etag_path = SCHEMAS_DIR / ".etags.json"
_lock = threading.Lock()
_last_refresh_ts: float = 0.0


def _load_etags() -> dict[str, str]:
    if not _etag_path.exists():
        return {}
    try:
        return json.loads(_etag_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_etags(etags: dict[str, str]) -> None:
    SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)
    _etag_path.write_text(json.dumps(etags, indent=2))


def _http_get(url: str, *, etag: str = "") -> tuple[int, dict[str, str], bytes]:
    """Tiny HTTP GET wrapper. Returns (status, headers, body)."""
    import requests
    headers: dict[str, str] = {"Accept": "application/json"}
    if SOCAI_SCHEMA_API_KEY:
        headers["Authorization"] = f"Bearer {SOCAI_SCHEMA_API_KEY}"
    if etag:
        headers["If-None-Match"] = etag
    resp = requests.get(url, headers=headers, timeout=30)
    return resp.status_code, dict(resp.headers), resp.content


def _fetch_manifest() -> dict[str, Any] | None:
    """GET the manifest. Returns parsed dict or None on failure."""
    if not SOCAI_SCHEMA_SOURCE_URL:
        return None
    try:
        status, _, body = _http_get(SOCAI_SCHEMA_SOURCE_URL)
        if status != 200:
            log_error("", "schema_fetcher.manifest",
                      f"Manifest GET returned {status}",
                      severity="warning",
                      context={"url": SOCAI_SCHEMA_SOURCE_URL})
            return None
        return json.loads(body.decode("utf-8"))
    except Exception as exc:
        log_error("", "schema_fetcher.manifest", str(exc),
                  severity="warning",
                  context={"url": SOCAI_SCHEMA_SOURCE_URL})
        return None


def _fetch_one(platform_id: str, entry: dict, etags: dict[str, str]) -> str:
    """Pull a single platform schema. Returns "fetched", "not_modified", "cached_fallback", or "error"."""
    url = entry.get("url", "")
    if not url:
        return "error"

    dest = SCHEMAS_DIR / f"{platform_id}.json"
    SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)

    try:
        status, headers, body = _http_get(url, etag=etags.get(platform_id, ""))
    except Exception as exc:
        log_error("", "schema_fetcher.fetch", f"{platform_id}: {exc}",
                  severity="warning", context={"url": url})
        return "cached_fallback" if dest.exists() else "error"

    if status == 304:
        return "not_modified"
    if status != 200:
        log_error("", "schema_fetcher.fetch",
                  f"{platform_id}: HTTP {status}",
                  severity="warning", context={"url": url})
        return "cached_fallback" if dest.exists() else "error"

    # Atomic write
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(body)
    tmp.replace(dest)

    new_etag = headers.get("ETag", "")
    if new_etag:
        etags[platform_id] = new_etag

    return "fetched"


def refresh_all() -> dict[str, Any]:
    """Pull every platform schema named in the manifest. Returns a status summary."""
    global _last_refresh_ts
    summary: dict[str, Any] = {
        "ts": utcnow(),
        "source": SOCAI_SCHEMA_SOURCE_URL or "(unconfigured)",
        "platforms": {},
        "manifest_ok": False,
    }

    if not SOCAI_SCHEMA_SOURCE_URL:
        summary["note"] = "SOCAI_SCHEMA_SOURCE_URL not configured — using locally cached schemas only"
        return summary

    with _lock:
        manifest = _fetch_manifest()
        if not manifest:
            summary["note"] = "Manifest fetch failed — falling back to cached schemas"
            return summary
        summary["manifest_ok"] = True

        etags = _load_etags()
        for platform_id, entry in manifest.items():
            if not isinstance(entry, dict):
                summary["platforms"][platform_id] = "skipped (manifest entry not a dict)"
                continue
            status = _fetch_one(platform_id, entry, etags)
            summary["platforms"][platform_id] = status

        _save_etags(etags)
        _last_refresh_ts = time.monotonic()

    return summary


def ensure_schema(platform_id: str) -> Path | None:
    """Return the local schema path for *platform_id*, refreshing if stale.

    If the file is missing and the source URL is configured, triggers a fetch.
    Returns None if the schema cannot be obtained.
    """
    dest = SCHEMAS_DIR / f"{platform_id}.json"
    if not dest.exists() and SOCAI_SCHEMA_SOURCE_URL:
        refresh_all()
    return dest if dest.exists() else None


def get_schema(platform_id: str) -> dict | None:
    """Return the parsed JSON of the cached schema, or None."""
    path = ensure_schema(platform_id)
    if path is None:
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log_error("", "schema_fetcher.parse", str(exc),
                  severity="warning", context={"platform": platform_id})
        return None


def maybe_periodic_refresh() -> str:
    """Trigger a refresh if SOCAI_SCHEMA_REFRESH_HOURS has elapsed. No-op if disabled
    or if the source URL is unconfigured. Returns a status string.
    """
    if SOCAI_SCHEMA_REFRESH_HOURS <= 0:
        return "disabled"
    if not SOCAI_SCHEMA_SOURCE_URL:
        return "no_source"
    if time.monotonic() - _last_refresh_ts < SOCAI_SCHEMA_REFRESH_HOURS * 3600:
        return "not_due"
    refresh_all()
    return "refreshed"
