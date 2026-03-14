"""
Read-only Cyberint CTI alert query client.

Uses the Cyberint API v1 with cookie-based authentication (access_token).
Provides alert listing, detail retrieval, attachment/indicator lookups,
analysis reports, and risk scores.
"""
from __future__ import annotations

from typing import Any

import requests
from requests.exceptions import HTTPError

from config.settings import CYBERINT_API_KEY, CYBERINT_API_URL
from tools.common import get_session, log_error

_TIMEOUT = 20
_BASE_PATH = "/alert/api/v1"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _is_configured() -> bool:
    """Check that Cyberint API key and URL are present."""
    return bool(CYBERINT_API_KEY and CYBERINT_API_URL)


def _cookies() -> dict[str, str]:
    """Authentication cookies for Cyberint API."""
    return {"access_token": CYBERINT_API_KEY}


def _url(path: str) -> str:
    """Build full Cyberint API URL."""
    base = CYBERINT_API_URL.rstrip("/")
    return f"{base}{_BASE_PATH}{path}"


def _handle_auth_error(resp: requests.Response, step: str) -> None:
    """Log a clear message for auth failures."""
    if resp.status_code in (401, 403):
        log_error("", step,
                  f"HTTP {resp.status_code}: access_token cookie is expired or invalid. "
                  "Refresh CYBERINT_API_KEY in .env.",
                  severity="error", context={"url": resp.url})
    elif resp.status_code == 429:
        log_error("", step,
                  f"HTTP 429: Cyberint rate limit hit.",
                  severity="warning", context={"url": resp.url})


def _get(path: str, params: dict | None = None,
         *, allow_redirects: bool = True) -> dict | str | None:
    """Authenticated GET request to Cyberint API.

    When allow_redirects=False, returns the Location header (for
    attachment/report redirect endpoints) instead of following the redirect.
    """
    if not _is_configured():
        log_error("", "cyberint_read", "Cyberint not configured — check .env",
                  severity="warning")
        return None
    url = _url(path)
    try:
        resp = get_session().get(url, cookies=_cookies(), params=params,
                            timeout=_TIMEOUT, allow_redirects=allow_redirects)
        if not allow_redirects and resp.status_code == 302:
            return resp.headers.get("Location", "")
        _handle_auth_error(resp, "cyberint_read.get")
        resp.raise_for_status()
        return resp.json()
    except HTTPError as exc:
        _handle_auth_error(exc.response, "cyberint_read.get")
        log_error("", "cyberint_read.get",
                  f"HTTP {exc.response.status_code}: {exc.response.text[:500]}",
                  severity="error", context={"url": url})
        return None
    except Exception as exc:
        log_error("", "cyberint_read.get", str(exc),
                  severity="error", context={"url": url})
        return None


def _post(path: str, json_body: dict | None = None) -> dict | None:
    """Authenticated POST request to Cyberint API."""
    if not _is_configured():
        log_error("", "cyberint_read", "Cyberint not configured — check .env",
                  severity="warning")
        return None
    url = _url(path)
    try:
        resp = get_session().post(url, cookies=_cookies(), json=json_body,
                             timeout=_TIMEOUT)
        _handle_auth_error(resp, "cyberint_read.post")
        resp.raise_for_status()
        return resp.json()
    except HTTPError as exc:
        _handle_auth_error(exc.response, "cyberint_read.post")
        log_error("", "cyberint_read.post",
                  f"HTTP {exc.response.status_code}: {exc.response.text[:500]}",
                  severity="error", context={"url": url})
        return None
    except Exception as exc:
        log_error("", "cyberint_read.post", str(exc),
                  severity="error", context={"url": url})
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_alerts(
    page: int = 1,
    size: int = 10,
    *,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    environment: str | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
) -> dict[str, Any] | None:
    """List alerts with optional filters (POST /alerts).

    Returns {"alerts": [...], "total": int} or None on error.
    """
    filters: dict[str, list[str]] = {}
    if severity:
        filters["severity"] = [severity]
    if status:
        filters["status"] = [status]
    if category:
        filters["category"] = [category]
    if environment:
        filters["environment"] = [environment]

    body: dict[str, Any] = {
        "page": page,
        "size": max(size, 10),
        "filters": filters,
    }

    if created_from or created_to:
        date_range: dict[str, str] = {}
        if created_from:
            date_range["from"] = created_from
        if created_to:
            date_range["to"] = created_to
        body["created_date"] = date_range

    data = _post("/alerts", body)
    if not data:
        return None

    alerts = data.get("alerts", data.get("data", []))
    total = data.get("total", len(alerts))
    return {"alerts": alerts, "total": total}


def get_alert_metadata() -> dict | None:
    """Get alert catalog metadata (GET /alerts/metadata).

    Returns the metadata dict (categories, types, severities, etc.) or None.
    """
    return _get("/alerts/metadata")


def get_alert(ref_id: str) -> dict | None:
    """Get a single alert by reference ID (GET /alerts/{ref_id}).

    Returns the alert dict or None.
    """
    return _get(f"/alerts/{ref_id}")


def get_alert_attachment(ref_id: str, att_id: str) -> str | None:
    """Get a temporary download URL for an alert attachment.

    Uses allow_redirects=False to extract the Location header.
    Returns the URL string or None.
    """
    result = _get(f"/alerts/{ref_id}/attachments/{att_id}",
                  allow_redirects=False)
    if isinstance(result, str):
        return result or None
    return None


def get_alert_indicator(ref_id: str, ind_id: str) -> dict | None:
    """Get a specific indicator from an alert (GET /alerts/{ref_id}/indicators/{ind_id}).

    Returns the indicator dict or None.
    """
    return _get(f"/alerts/{ref_id}/indicators/{ind_id}")


def get_alert_analysis_report(ref_id: str) -> str | None:
    """Get a temporary URL for an alert's analysis report.

    Uses allow_redirects=False to extract the Location header.
    Returns the URL string or None.
    """
    result = _get(f"/alerts/{ref_id}/analysis_report",
                  allow_redirects=False)
    if isinstance(result, str):
        return result or None
    return None


def get_risk_scores(environment: str) -> dict | None:
    """Get current risk scores for an environment (GET /analytics/{env}/risks/current).

    Returns the risk scores dict or None.
    """
    return _get(f"/analytics/{environment}/risks/current")
