"""
Read-only Confluence Cloud client — scoped to a single space.

Uses a scoped API token with read:page:confluence and read:space:confluence
permissions via the Atlassian Cloud REST API v2.
"""
from __future__ import annotations

import base64
from typing import Any

import requests

from config.settings import (
    CONFLUENCE_API_TOKEN,
    CONFLUENCE_CLOUD_ID,
    CONFLUENCE_EMAIL,
    CONFLUENCE_SPACE_KEY,
    CONFLUENCE_URL,
)
from tools.common import log_error

_TIMEOUT = 15


def _is_configured() -> bool:
    """Check all required Confluence settings are present."""
    return all([CONFLUENCE_URL, CONFLUENCE_CLOUD_ID, CONFLUENCE_EMAIL,
                CONFLUENCE_API_TOKEN, CONFLUENCE_SPACE_KEY])


def _base_url() -> str:
    """Scoped tokens use the Atlassian API gateway."""
    return f"https://api.atlassian.com/ex/confluence/{CONFLUENCE_CLOUD_ID}/wiki/api/v2"


def _auth_header() -> dict[str, str]:
    """Basic auth header for scoped API token."""
    creds = base64.b64encode(f"{CONFLUENCE_EMAIL}:{CONFLUENCE_API_TOKEN}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Accept": "application/json",
    }


def _get(path: str, params: dict | None = None) -> dict | list | None:
    """Make an authenticated GET request to Confluence API v2."""
    if not _is_configured():
        log_error("", "confluence_read", "Confluence not configured — check .env",
                  severity="warning")
        return None
    url = f"{_base_url()}{path}"
    try:
        resp = requests.get(url, headers=_auth_header(), params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        log_error("", "confluence_read.get", f"HTTP {exc.response.status_code}: {exc.response.text[:500]}",
                  severity="error", context={"url": url})
        return None
    except Exception as exc:
        log_error("", "confluence_read.get", str(exc), severity="error", context={"url": url})
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_space_id() -> str | None:
    """Resolve the configured space key to a space ID."""
    data = _get("/spaces", params={"keys": CONFLUENCE_SPACE_KEY})
    if not data:
        return None
    results = data.get("results", [])
    if results:
        return results[0].get("id")
    return None


def list_pages(
    limit: int = 25,
    cursor: str | None = None,
    title: str | None = None,
    sort: str = "-modified-date",
) -> dict[str, Any]:
    """List pages in the configured space.

    Returns {"pages": [...], "next_cursor": str | None}.
    """
    space_id = get_space_id()
    if not space_id:
        return {"pages": [], "next_cursor": None, "error": "Could not resolve space ID"}

    params: dict[str, Any] = {"limit": limit, "sort": sort}
    if cursor:
        params["cursor"] = cursor
    if title:
        params["title"] = title

    data = _get(f"/spaces/{space_id}/pages", params=params)
    if not data:
        return {"pages": [], "next_cursor": None}

    pages = []
    for p in data.get("results", []):
        pages.append({
            "id": p.get("id"),
            "title": p.get("title"),
            "status": p.get("status"),
            "created_at": p.get("createdAt"),
            "version": p.get("version", {}).get("number"),
        })

    # Pagination
    next_cursor = None
    links = data.get("_links", {})
    next_link = links.get("next", "")
    if "cursor=" in next_link:
        next_cursor = next_link.split("cursor=")[-1].split("&")[0]

    return {"pages": pages, "next_cursor": next_cursor}


def get_page(page_id: str, body_format: str = "storage") -> dict | None:
    """Get a single page by ID, including body content.

    body_format: "storage" (raw HTML), "atlas_doc_format" (ADF JSON), or "view" (rendered).
    """
    data = _get(f"/pages/{page_id}", params={"body-format": body_format})
    if not data:
        return None

    body_key = {
        "storage": "storage",
        "atlas_doc_format": "atlas_doc_format",
        "view": "view",
    }.get(body_format, "storage")

    body_obj = data.get("body", {}).get(body_key, {})

    return {
        "id": data.get("id"),
        "title": data.get("title"),
        "status": data.get("status"),
        "body": body_obj.get("value", ""),
        "version": data.get("version", {}).get("number"),
        "created_at": data.get("createdAt"),
        "space_id": data.get("spaceId"),
    }


def search_pages(query: str, limit: int = 10) -> list[dict]:
    """Search for pages by title within the configured space."""
    result = list_pages(limit=limit, title=query)
    return result.get("pages", [])


def get_page_by_title(title: str) -> dict | None:
    """Get a single page by exact title match."""
    pages = search_pages(title, limit=1)
    if pages:
        return get_page(pages[0]["id"])
    return None
