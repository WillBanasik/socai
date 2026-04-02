"""
tool: darkweb
-------------
Dark web intelligence lookups -- infostealer exposure (Hudson Rock Cavalier),
breach analytics (XposedOrNot), dark web search (Ahmia.fi), and deep/dark web
content search (Intelligence X).

Agent-invocable MCP tools (NOT automatic enrichment).  The Claude Desktop
agent decides when to invoke these during investigations.

Writes:
  cases/<case_id>/artefacts/darkweb/hudsonrock_results.json
  cases/<case_id>/artefacts/darkweb/xposedornot_results.json
  cases/<case_id>/artefacts/darkweb/ahmia_results.json
  cases/<case_id>/artefacts/darkweb/intelx_results.json
  cases/<case_id>/artefacts/darkweb/darkweb_summary.json
  cases/<case_id>/artefacts/darkweb/stealer_logs/
"""

from __future__ import annotations

import os
import re
import socket
import threading
import time
import traceback as tb
from pathlib import Path

from config.settings import CASES_DIR, HUDSONROCK_KEY, INTELX_KEY, XPOSEDORNOT_KEY
from tools.common import get_session, load_json, log_error, save_json, utcnow

# ---------------------------------------------------------------------------
# Credential sanitisation (MUST be applied before data leaves this module)
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = frozenset({
    "password", "pass", "cookie_value", "token", "session_token",
    "master_key", "encryption_key", "login_key", "credit_card",
    "cc_number", "secret",
})


def _redact_value(value: str) -> str:
    """Replace a sensitive value with a length-preserving placeholder."""
    if not value or not isinstance(value, str):
        return value
    return f"[REDACTED-{len(value)}chars]"


def _redact_email_local(email: str) -> str:
    """Truncate email local-part: 'john.doe@example.com' -> 'j***@example.com'."""
    if not isinstance(email, str) or "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    if len(local) <= 1:
        return f"{local}***@{domain}"
    return f"{local[0]}***@{domain}"


def _redact_credentials(data):
    """Recursively redact all sensitive fields in a response structure."""
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if k.lower() in _SENSITIVE_KEYS:
                result[k] = _redact_value(v) if isinstance(v, str) else v
            elif k.lower() in ("username", "login_email") and isinstance(v, str) and "@" in v:
                result[k] = _redact_email_local(v)
            else:
                result[k] = _redact_credentials(v)
        return result
    elif isinstance(data, list):
        return [_redact_credentials(item) for item in data]
    return data


# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _detect_type(value: str) -> str:
    """Auto-detect IOC type from value string."""
    value = value.strip()
    if _IPV4_RE.match(value) or "/" in value and _IPV4_RE.match(value.split("/")[0]):
        return "ip"
    if _EMAIL_RE.match(value):
        return "email"
    # Anything with a dot that isn't an IP or email is treated as a domain
    if "." in value and not value.startswith("http"):
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# Hudson Rock Cavalier API
# ---------------------------------------------------------------------------

_HR_BASE = "https://api.hudsonrock.com/json/v3"
_HR_TIMEOUT = 30


def _hr_headers() -> dict[str, str]:
    return {"api-key": HUDSONROCK_KEY, "Content-Type": "application/json"}


def _hr_is_configured() -> bool:
    return bool(HUDSONROCK_KEY)


def _hudsonrock_paginate(
    endpoint: str,
    payload: dict,
    *,
    max_pages: int = 5,
    case_id: str = "",
) -> list[dict]:
    """Follow cursor-based pagination for Hudson Rock endpoints."""
    all_data: list[dict] = []
    session = get_session()
    cursor = None

    for _ in range(max_pages):
        if cursor:
            payload["cursor"] = cursor
        try:
            resp = session.post(
                f"{_HR_BASE}/{endpoint}",
                headers=_hr_headers(),
                json=payload,
                timeout=_HR_TIMEOUT,
            )
            if resp.status_code == 429:
                log_error(case_id, "darkweb.hudsonrock", "Rate limited by Hudson Rock",
                          severity="warning")
                break
            resp.raise_for_status()
            body = resp.json()
        except Exception as exc:
            log_error(case_id, "darkweb.hudsonrock", str(exc),
                      severity="warning", traceback=tb.format_exc())
            break

        page_data = body.get("data", [])
        if isinstance(page_data, list):
            all_data.extend(page_data)
        elif isinstance(page_data, dict):
            all_data.append(page_data)

        cursor = body.get("nextCursor")
        if not cursor:
            break

    return all_data


def hudsonrock_email_search(
    emails: list[str],
    case_id: str = "",
) -> dict:
    """Search Hudson Rock for infostealer compromise data on email addresses.

    Parameters
    ----------
    emails : list[str]
        Up to 50 email addresses to search.
    case_id : str
        If provided, results are saved to case artefacts.

    Returns
    -------
    dict with source, status, results, compromised_count, total_queried, ts.
    Credentials are ALWAYS redacted before return.
    """
    if not _hr_is_configured():
        return {"source": "hudsonrock", "status": "no_api_key",
                "message": "HUDSONROCK_API_KEY not set", "ts": utcnow()}

    emails = emails[:50]
    payload = {"logins": emails}
    raw = _hudsonrock_paginate("search-by-login/emails", payload, case_id=case_id)

    # Redact IMMEDIATELY
    results = _redact_credentials(raw)

    out = {
        "source": "hudsonrock",
        "status": "ok" if results else "no_results",
        "query_type": "email",
        "queries": emails,
        "compromised_count": len(results),
        "total_queried": len(emails),
        "results": results,
        "ts": utcnow(),
    }

    if case_id:
        dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "hudsonrock_results.json"
        _merge_save(dest, out, case_id)

    return out


def hudsonrock_domain_search(
    domain: str,
    search_type: str = "overview",
    case_id: str = "",
) -> dict:
    """Search Hudson Rock for domain exposure data.

    Parameters
    ----------
    domain : str
        Domain to search (e.g. 'example.com').
    search_type : str
        'overview' for summary stats, 'detailed' for full breakdown.
    case_id : str
        If provided, results are saved to case artefacts.
    """
    if not _hr_is_configured():
        return {"source": "hudsonrock", "status": "no_api_key",
                "message": "HUDSONROCK_API_KEY not set", "ts": utcnow()}

    if search_type == "overview":
        endpoint = "search-by-domain/overview"
        payload = {"domains": [domain]}
    else:
        endpoint = "search-by-domain"
        payload = {"domains": [domain], "types": ["employees", "users", "third_parties"]}

    raw = _hudsonrock_paginate(endpoint, payload, case_id=case_id)
    results = _redact_credentials(raw)

    out = {
        "source": "hudsonrock",
        "status": "ok" if results else "no_results",
        "query_type": "domain",
        "query": domain,
        "search_type": search_type,
        "results": results,
        "ts": utcnow(),
    }

    if case_id:
        dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "hudsonrock_results.json"
        _merge_save(dest, out, case_id)

    return out


def hudsonrock_ip_search(
    ips: list[str],
    case_id: str = "",
) -> dict:
    """Search Hudson Rock for IP/CIDR infostealer data.

    Parameters
    ----------
    ips : list[str]
        Up to 50 IPs or a single CIDR range.
    case_id : str
        If provided, results are saved to case artefacts.
    """
    if not _hr_is_configured():
        return {"source": "hudsonrock", "status": "no_api_key",
                "message": "HUDSONROCK_API_KEY not set", "ts": utcnow()}

    ips = ips[:50]
    # Check if CIDR
    if len(ips) == 1 and "/" in ips[0]:
        payload = {"cidr": ips[0]}
    else:
        payload = {"ips": ips}

    raw = _hudsonrock_paginate("search-by-ip", payload, case_id=case_id)
    results = _redact_credentials(raw)

    out = {
        "source": "hudsonrock",
        "status": "ok" if results else "no_results",
        "query_type": "ip",
        "queries": ips,
        "compromised_count": len(results),
        "total_queried": len(ips),
        "results": results,
        "ts": utcnow(),
    }

    if case_id:
        dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "hudsonrock_results.json"
        _merge_save(dest, out, case_id)

    return out


# ---------------------------------------------------------------------------
# XposedOrNot API
# ---------------------------------------------------------------------------

_XON_BASE = "https://api.xposedornot.com"
_XON_TIMEOUT = 20

_xon_last_call: float = 0.0
_xon_lock = threading.Lock()


def _xon_rate_limit() -> None:
    """Enforce 1 req/sec for XposedOrNot free tier."""
    global _xon_last_call
    with _xon_lock:
        elapsed = time.monotonic() - _xon_last_call
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
        _xon_last_call = time.monotonic()


def xposedornot_email_check(
    email: str,
    case_id: str = "",
) -> dict:
    """Check if an email appears in known data breaches via XposedOrNot.

    Calls both /v1/check-email (basic) and /v1/breach-analytics (detailed).
    No API key required for email lookups.

    Parameters
    ----------
    email : str
        Email address to check.
    case_id : str
        If provided, results are saved to case artefacts.
    """
    session = get_session()
    breach_names: list[str] = []
    analytics: dict = {}

    # --- Basic breach check (keyless) ---
    _xon_rate_limit()
    try:
        resp = session.get(
            f"{_XON_BASE}/v1/check-email/{email}",
            timeout=_XON_TIMEOUT,
        )
        if resp.status_code == 200:
            body = resp.json()
            if body.get("breaches"):
                raw = body["breaches"]
                if isinstance(raw, list):
                    # API sometimes returns nested lists — flatten
                    breach_names = []
                    for item in raw:
                        if isinstance(item, list):
                            breach_names.extend(item)
                        else:
                            breach_names.append(item)
                else:
                    breach_names = []
        elif resp.status_code == 404:
            pass  # not found — no breaches
        elif resp.status_code == 429:
            log_error(case_id, "darkweb.xposedornot", "Rate limited",
                      severity="warning")
        else:
            resp.raise_for_status()
    except Exception as exc:
        log_error(case_id, "darkweb.xposedornot", str(exc),
                  severity="warning", traceback=tb.format_exc())

    # --- Detailed breach analytics (keyless) ---
    _xon_rate_limit()
    try:
        resp = session.get(
            f"{_XON_BASE}/v1/breach-analytics",
            params={"email": email},
            timeout=_XON_TIMEOUT,
        )
        if resp.status_code == 200:
            analytics = resp.json()
        elif resp.status_code == 404:
            pass
        elif resp.status_code == 429:
            log_error(case_id, "darkweb.xposedornot", "Rate limited (analytics)",
                      severity="warning")
    except Exception as exc:
        log_error(case_id, "darkweb.xposedornot", str(exc),
                  severity="warning", traceback=tb.format_exc())

    breaches_detail = analytics.get("ExposedBreaches", [])
    summary = analytics.get("BreachesSummary", {})
    metrics = analytics.get("BreachMetrics", {})
    pastes = analytics.get("ExposedPastes", [])

    out = {
        "source": "xposedornot",
        "status": "ok" if breach_names or breaches_detail else "no_results",
        "query_type": "email",
        "query": email,
        "breached": bool(breach_names or breaches_detail),
        "breach_count": len(breach_names) if breach_names else summary.get("total_breaches", 0),
        "breach_names": breach_names,
        "breaches_detail": breaches_detail,
        "risk_score": metrics.get("risk_score"),
        "exposed_data_types": metrics.get("data_types_exposed", []),
        "industry_breakdown": metrics.get("industry_breakdown", {}),
        "paste_count": len(pastes) if isinstance(pastes, list) else 0,
        "ts": utcnow(),
    }

    if case_id:
        dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "xposedornot_results.json"
        _merge_save(dest, out, case_id)

    return out


def xposedornot_domain_check(
    domain: str,
    case_id: str = "",
) -> dict:
    """Check domain breach exposure via XposedOrNot (requires API key).

    Parameters
    ----------
    domain : str
        Domain to check.
    case_id : str
        If provided, results are saved to case artefacts.
    """
    if not XPOSEDORNOT_KEY:
        return {"source": "xposedornot", "status": "no_api_key",
                "message": "XPOSEDORNOT_API_KEY not set (required for domain lookups)",
                "ts": utcnow()}

    session = get_session()
    _xon_rate_limit()

    try:
        resp = session.post(
            f"{_XON_BASE}/v1/domain-breaches/",
            headers={"x-api-key": XPOSEDORNOT_KEY, "Content-Type": "application/json"},
            json={"domain": domain},
            timeout=_XON_TIMEOUT,
        )
        if resp.status_code == 200:
            body = resp.json()
            return {
                "source": "xposedornot",
                "status": "ok",
                "query_type": "domain",
                "query": domain,
                "breached": True,
                "results": body,
                "ts": utcnow(),
            }
        elif resp.status_code == 404:
            return {
                "source": "xposedornot",
                "status": "no_results",
                "query_type": "domain",
                "query": domain,
                "breached": False,
                "ts": utcnow(),
            }
        elif resp.status_code == 429:
            log_error(case_id, "darkweb.xposedornot", "Rate limited (domain)",
                      severity="warning")
            return {"source": "xposedornot", "status": "rate_limited", "ts": utcnow()}
        else:
            resp.raise_for_status()
    except Exception as exc:
        log_error(case_id, "darkweb.xposedornot", str(exc),
                  severity="warning", traceback=tb.format_exc())
        return {"source": "xposedornot", "status": "error",
                "error": str(exc), "ts": utcnow()}

    return {"source": "xposedornot", "status": "error", "ts": utcnow()}


# ---------------------------------------------------------------------------
# Ahmia.fi — Tor hidden service search engine
# ---------------------------------------------------------------------------
#
# Ahmia's /search/ endpoint redirects non-Tor traffic to /.  Two modes:
#   1. Tor SOCKS5 proxy available (local Tor on 9050 or SOCAI_TOR_PROXY) →
#      full text search via the .onion address.
#   2. No Tor → fetch the /onions/ list (all indexed .onion domains)
#      and grep it locally for matches.

_AHMIA_BASE = "https://ahmia.fi"
_AHMIA_ONION = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
_AHMIA_TIMEOUT = 30

# Tor SOCKS5 proxy for .onion access (separate from OPSEC_PROXY)
_TOR_PROXY_DEFAULT = "socks5h://127.0.0.1:9050"

_tor_session_local = threading.local()


def _get_tor_session() -> "requests.Session":
    """Return a requests session routed through Tor SOCKS5."""
    import requests as _req

    session: _req.Session | None = getattr(_tor_session_local, "session", None)
    if session is not None:
        return session

    tor_proxy = os.environ.get("SOCAI_TOR_PROXY", _TOR_PROXY_DEFAULT)
    session = _req.Session()
    session.proxies = {"http": tor_proxy, "https": tor_proxy}
    _tor_session_local.session = session
    return session


def _tor_is_available() -> bool:
    """Check if Tor SOCKS5 proxy is reachable (TCP connect to port 9050)."""
    tor_proxy = os.environ.get("SOCAI_TOR_PROXY", _TOR_PROXY_DEFAULT)
    # Parse host:port from socks5h://host:port
    try:
        from urllib.parse import urlparse
        parsed = urlparse(tor_proxy)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 9050
    except Exception as exc:
        log_error("", "darkweb.tor_proxy_parse", str(exc),
                  severity="warning", traceback=True)
        host, port = "127.0.0.1", 9050

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception as exc:
        log_error("", "darkweb.tor_availability_check", str(exc),
                  severity="info", traceback=True)
        return False


def ahmia_search(
    query: str,
    max_results: int = 20,
    case_id: str = "",
) -> dict:
    """Search indexed .onion sites via Ahmia.fi.

    If Tor is available (local Tor service on port 9050 or SOCAI_TOR_PROXY),
    performs a full text search via the Ahmia .onion address.  Otherwise,
    fetches the full list of indexed .onion domains from the clearnet
    endpoint and filters locally.

    Parameters
    ----------
    query : str
        Search term — email, domain, username, keyword, .onion address, etc.
    max_results : int
        Maximum results to return (default 20).
    case_id : str
        If provided, results are saved to case artefacts.
    """
    # Try full search via Tor if available
    if _tor_is_available():
        result = _ahmia_full_search(query, max_results, case_id)
        if result["status"] != "error":
            return result
        # Fall through to onion list grep on error

    # Fallback: grep the /onions/ list
    return _ahmia_onion_grep(query, max_results, case_id)


def _ahmia_full_search(
    query: str,
    max_results: int,
    case_id: str,
) -> dict:
    """Full Ahmia search via Tor SOCKS5 proxy.

    Tries the .onion address first, then clearnet via Tor exit as fallback.
    """
    session = _get_tor_session()
    results: list[dict] = []

    # Try .onion first, then clearnet via Tor exit
    urls = [
        f"{_AHMIA_ONION}/search/",
        f"{_AHMIA_BASE}/search/",
    ]

    last_error = ""
    for url in urls:
        try:
            resp = session.get(
                url,
                params={"q": query},
                timeout=_AHMIA_TIMEOUT,
            )
            # 302 redirect to / means search blocked — try next URL
            if resp.status_code == 302:
                last_error = f"Redirected (search blocked) at {url}"
                continue
            resp.raise_for_status()

            content_type = resp.headers.get("Content-Type", "")
            if "json" in content_type:
                body = resp.json()
                if isinstance(body, dict) and "results" in body:
                    results = body["results"][:max_results]
                elif isinstance(body, list):
                    results = body[:max_results]
            else:
                results = _parse_ahmia_html(resp.text, max_results)

            # Got a real response — break out
            break

        except Exception as exc:
            last_error = str(exc)
            log_error(case_id, "darkweb.ahmia_full_search", str(exc),
                      severity="warning", traceback=True,
                      context={"url": url, "query": query})
            continue

    if not results and last_error:
        log_error(case_id, "darkweb.ahmia", last_error,
                  severity="warning")
        return {"source": "ahmia", "status": "error",
                "error": last_error, "ts": utcnow()}

    out = {
        "source": "ahmia",
        "status": "ok" if results else "no_results",
        "mode": "full_search",
        "query": query,
        "result_count": len(results),
        "results": results,
        "ts": utcnow(),
    }

    if case_id:
        dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "ahmia_results.json"
        _merge_save(dest, out, case_id)

    return out


def _ahmia_onion_grep(
    query: str,
    max_results: int,
    case_id: str,
) -> dict:
    """Fetch all indexed .onion domains from Ahmia and grep for matches."""
    import requests as _req

    # Ahmia drops connections from sessions with retry adapters.
    # Use a plain session with a browser UA.
    try:
        resp = _req.get(
            f"{_AHMIA_BASE}/onions/",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/120.0.0.0 Safari/537.36"},
            timeout=_AHMIA_TIMEOUT,
        )
        resp.raise_for_status()
        raw = resp.text
    except Exception as exc:
        log_error(case_id, "darkweb.ahmia", str(exc),
                  severity="warning", traceback=tb.format_exc())
        return {"source": "ahmia", "status": "error",
                "error": str(exc), "ts": utcnow()}

    # Extract all .onion URLs from the response
    onion_urls = re.findall(r"https?://[a-z2-7]{16,56}\.onion/?[^\s<\"]*", raw)

    # Filter by query (case-insensitive substring match)
    query_lower = query.lower()
    matches = [url for url in onion_urls if query_lower in url.lower()][:max_results]

    # If no direct URL matches, return the total count for context
    out = {
        "source": "ahmia",
        "status": "ok" if matches else "no_results",
        "mode": "onion_list_grep",
        "query": query,
        "note": ("Full text search requires SOCAI_OPSEC_PROXY with Tor SOCKS5. "
                 "This result only checks indexed .onion domain URLs."
                 if not matches else
                 "Matched from Ahmia's indexed .onion domain list. "
                 "For full text search, configure SOCAI_OPSEC_PROXY with Tor SOCKS5."),
        "total_indexed_onions": len(onion_urls),
        "result_count": len(matches),
        "results": [{"onion_url": url} for url in matches],
        "ts": utcnow(),
    }

    if case_id:
        dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "ahmia_results.json"
        _merge_save(dest, out, case_id)

    return out


def _parse_ahmia_html(html: str, max_results: int) -> list[dict]:
    """Parse Ahmia HTML search results into structured records."""
    try:
        from bs4 import BeautifulSoup
    except ImportError as exc:
        log_error("", "darkweb.ahmia_html_parse", str(exc),
                  severity="warning", traceback=True)
        return [{"note": "beautifulsoup4 required for HTML parsing"}]

    soup = BeautifulSoup(html, "html.parser")
    results: list[dict] = []

    for item in soup.select("li.result")[:max_results]:
        title_el = item.select_one("h4") or item.select_one("a")
        link_el = item.select_one("a[href]")
        desc_el = item.select_one("p") or item.select_one(".description")
        cite_el = item.select_one("cite")

        result = {}
        if title_el:
            result["title"] = title_el.get_text(strip=True)
        if link_el:
            href = link_el.get("href", "")
            # Ahmia proxies onion links — extract the redirect target
            if "redirect_url=" in href:
                from urllib.parse import parse_qs, urlparse
                parsed = urlparse(href)
                target = parse_qs(parsed.query).get("redirect_url", [""])[0]
                result["url"] = target or href
            else:
                result["url"] = href
        if desc_el:
            result["description"] = desc_el.get_text(strip=True)
        if cite_el:
            result["onion_url"] = cite_el.get_text(strip=True)

        if result:
            results.append(result)

    return results


# ---------------------------------------------------------------------------
# Intelligence X — deep/dark web content search
# ---------------------------------------------------------------------------

_INTELX_TIMEOUT = 30


def _intelx_base() -> str:
    """Return the correct IntelX API base URL based on key type."""
    if not INTELX_KEY:
        return "https://public.intelx.io"
    # Free keys use free.intelx.io, paid keys use 2.intelx.io
    # Default to free — paid users can override via env if needed
    return "https://free.intelx.io"


def _intelx_headers() -> dict[str, str]:
    return {"x-key": INTELX_KEY, "Content-Type": "application/json",
            "User-Agent": "socai/1.0"}


def intelx_search(
    query: str,
    max_results: int = 20,
    buckets: list[str] | None = None,
    timeout: int = 10,
    case_id: str = "",
) -> dict:
    """Search Intelligence X for dark web, paste, and leak data.

    IntelX search is async: submit a search, wait briefly, then retrieve
    results.  Requires INTELX_API_KEY for authenticated access (free tier
    available).  Falls back to public API (very limited) if no key is set.

    Parameters
    ----------
    query : str
        Strong selector — email, domain, IP, URL, phone number, etc.
    max_results : int
        Maximum results to return (default 20).
    buckets : list[str] | None
        Data sources to search.  Options: 'pastes', 'darknet', 'leaks',
        'documents'.  None searches all.
    timeout : int
        Search timeout in seconds (default 10).
    case_id : str
        If provided, results are saved to case artefacts.
    """
    base = _intelx_base()
    session = get_session()

    # --- Step 1: Submit search ---
    payload: dict = {
        "term": query,
        "maxresults": max_results,
        "timeout": timeout,
    }
    if buckets:
        payload["buckets"] = buckets

    try:
        resp = session.post(
            f"{base}/intelligent/search",
            headers=_intelx_headers(),
            json=payload,
            timeout=_INTELX_TIMEOUT,
        )
        if resp.status_code == 402:
            return {"source": "intelx", "status": "quota_exceeded",
                    "message": "IntelX API quota exceeded (free tier limit)",
                    "ts": utcnow()}
        resp.raise_for_status()
        search_resp = resp.json()
        search_id = search_resp.get("id")
        if not search_id:
            return {"source": "intelx", "status": "error",
                    "error": "No search ID returned", "ts": utcnow()}
    except Exception as exc:
        log_error(case_id, "darkweb.intelx", str(exc),
                  severity="warning", traceback=tb.format_exc())
        return {"source": "intelx", "status": "error",
                "error": str(exc), "ts": utcnow()}

    # --- Step 2: Wait briefly then retrieve results ---
    # IntelX docs recommend ~400ms wait before first poll
    time.sleep(0.5)

    records: list[dict] = []
    try:
        resp = session.get(
            f"{base}/intelligent/search/result",
            headers=_intelx_headers(),
            params={"id": search_id, "limit": max_results},
            timeout=_INTELX_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
        raw_records = body.get("records", [])

        # Status: 0=done, 1=partial results, 2=still searching, 3=no results
        search_status = body.get("status", 0)

        # If still searching, poll once more
        if search_status == 2 and not raw_records:
            time.sleep(1.0)
            resp = session.get(
                f"{base}/intelligent/search/result",
                headers=_intelx_headers(),
                params={"id": search_id, "limit": max_results},
                timeout=_INTELX_TIMEOUT,
            )
            resp.raise_for_status()
            body = resp.json()
            raw_records = body.get("records", [])

        # Redact any credentials in results
        records = _redact_credentials(raw_records) if raw_records else []

    except Exception as exc:
        log_error(case_id, "darkweb.intelx", str(exc),
                  severity="warning", traceback=tb.format_exc())
        return {"source": "intelx", "status": "error",
                "error": str(exc), "search_id": search_id, "ts": utcnow()}

    # --- Step 3: Terminate search to free server resources ---
    try:
        session.get(
            f"{base}/intelligent/search/terminate",
            headers=_intelx_headers(),
            params={"id": search_id},
            timeout=10,
        )
    except Exception as exc:
        log_error(case_id, "darkweb.intelx_terminate", str(exc),
                  severity="info", traceback=True)
        # best-effort cleanup

    out = {
        "source": "intelx",
        "status": "ok" if records else "no_results",
        "query": query,
        "search_id": search_id,
        "result_count": len(records),
        "results": records,
        "ts": utcnow(),
    }

    if case_id:
        dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "intelx_results.json"
        _merge_save(dest, out, case_id)

    return out


# ---------------------------------------------------------------------------
# Stealer log parser
# ---------------------------------------------------------------------------

def parse_stealer_logs(
    case_id: str,
    archive_path: str = "",
) -> dict:
    """Parse infostealer log archives using lexfo/stealer-parser.

    If archive_path is not provided, scans the case's artefacts directory
    for .rar/.zip/.7z files.

    Parameters
    ----------
    case_id : str
        Case identifier.
    archive_path : str
        Explicit path to archive.  If empty, auto-discovers.
    """
    try:
        from stealer_parser import StealerParser  # type: ignore[import-untyped]
    except ImportError as exc:
        log_error(case_id, "darkweb.stealer_parser_import", str(exc),
                  severity="warning", traceback=True)
        return {
            "status": "error",
            "message": "stealer-parser not installed. Run: pip install stealer-parser",
            "ts": utcnow(),
        }

    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        return {"status": "error", "message": f"Case {case_id} not found", "ts": utcnow()}

    # Discover archives
    archives: list[Path] = []
    if archive_path:
        p = Path(archive_path)
        if not p.is_absolute():
            p = case_dir / p
        if p.exists():
            archives.append(p)
        else:
            return {"status": "error", "message": f"Archive not found: {p}", "ts": utcnow()}
    else:
        for ext in ("*.rar", "*.zip", "*.7z"):
            archives.extend(case_dir.rglob(ext))

    if not archives:
        return {"status": "no_archives",
                "message": "No .rar/.zip/.7z archives found in case directory",
                "ts": utcnow()}

    parsed_results = []
    for archive in archives:
        try:
            parser = StealerParser(str(archive))
            result = parser.parse()
            # Redact credentials before storing
            redacted = _redact_credentials(result)
            parsed_results.append({
                "archive": archive.name,
                "data": redacted,
            })
        except Exception as exc:
            log_error(case_id, "darkweb.stealer_parser", str(exc),
                      severity="warning", traceback=tb.format_exc(),
                      context={"archive": str(archive)})
            parsed_results.append({
                "archive": archive.name,
                "error": str(exc),
            })

    out = {
        "status": "ok" if any("data" in r for r in parsed_results) else "error",
        "archives_processed": len(archives),
        "results": parsed_results,
        "ts": utcnow(),
    }

    dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "stealer_logs" / "parsed.json"
    save_json(dest, out)

    return out


# ---------------------------------------------------------------------------
# Aggregated dark web summary
# ---------------------------------------------------------------------------

def darkweb_summary(
    case_id: str,
    emails: list[str] | None = None,
    domains: list[str] | None = None,
    ips: list[str] | None = None,
) -> dict:
    """Produce an aggregated dark web exposure summary for a case.

    Calls Hudson Rock and XposedOrNot for all provided indicators,
    merges results, and saves a summary to the case.

    If no indicators are provided, extracts them from the case's iocs.json.
    """
    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        return {"status": "error", "message": f"Case {case_id} not found", "ts": utcnow()}

    # Auto-extract IOCs if none provided
    if not emails and not domains and not ips:
        iocs_path = case_dir / "artefacts" / "enrichment" / "iocs.json"
        if iocs_path.exists():
            try:
                iocs = load_json(iocs_path)
                emails = iocs.get("email", [])
                domains = iocs.get("domain", [])
                ips = iocs.get("ipv4", [])
            except Exception as exc:
                log_error(case_id, "darkweb.load_iocs", str(exc),
                          severity="warning", traceback=True)
        if not emails and not domains and not ips:
            return {"status": "no_indicators",
                    "message": "No indicators provided and none found in case IOCs",
                    "ts": utcnow()}

    emails = emails or []
    domains = domains or []
    ips = ips or []

    results: dict = {
        "case_id": case_id,
        "hudsonrock": {},
        "xposedornot": {},
        "summary": {},
        "ts": utcnow(),
    }

    # --- Hudson Rock ---
    hr_results: list[dict] = []
    if emails and _hr_is_configured():
        hr_results.append(hudsonrock_email_search(emails, case_id=case_id))
    if ips and _hr_is_configured():
        hr_results.append(hudsonrock_ip_search(ips, case_id=case_id))
    for domain in domains:
        if _hr_is_configured():
            hr_results.append(hudsonrock_domain_search(domain, case_id=case_id))
    results["hudsonrock"] = hr_results

    # --- XposedOrNot ---
    xon_results: list[dict] = []
    for email in emails:
        xon_results.append(xposedornot_email_check(email, case_id=case_id))
    for domain in domains:
        xon_results.append(xposedornot_domain_check(domain, case_id=case_id))
    results["xposedornot"] = xon_results

    # --- Summary ---
    hr_compromised = sum(
        r.get("compromised_count", 0) for r in hr_results if isinstance(r.get("compromised_count"), int)
    )
    xon_breached = sum(1 for r in xon_results if r.get("breached"))
    all_breach_names: set[str] = set()
    for r in xon_results:
        all_breach_names.update(r.get("breach_names", []))

    results["summary"] = {
        "total_indicators_checked": len(emails) + len(domains) + len(ips),
        "hudsonrock_compromised_records": hr_compromised,
        "xposedornot_breached_indicators": xon_breached,
        "unique_breaches": sorted(all_breach_names),
        "hudsonrock_configured": _hr_is_configured(),
        "xposedornot_configured": True,  # keyless for email
    }

    dest = CASES_DIR / case_id / "artefacts" / "darkweb" / "darkweb_summary.json"
    save_json(dest, results)

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _merge_save(dest: Path, new_data: dict, case_id: str) -> None:
    """Merge new results into existing artefact file (append to results list)."""
    try:
        if dest.exists():
            existing = load_json(dest)
            if isinstance(existing, list):
                existing.append(new_data)
                save_json(dest, existing)
            elif isinstance(existing, dict) and existing.get("source") == new_data.get("source"):
                # Same source, same query type — overwrite
                save_json(dest, new_data)
            else:
                save_json(dest, [existing, new_data])
        else:
            save_json(dest, new_data)
    except Exception as exc:
        log_error(case_id, "darkweb.save", str(exc),
                  severity="warning", traceback=tb.format_exc())
        save_json(dest, new_data)
