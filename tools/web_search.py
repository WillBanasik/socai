"""
tool: web_search
----------------
Web search fallback for OSINT enrichment.  When structured API providers
(VirusTotal, AbuseIPDB, Shodan, etc.) don't have data, the LLM can call
this tool to search the open web for threat intelligence context.

Backends (tried in order):
  1. Brave Search API  — if SOCAI_BRAVE_SEARCH_KEY is set (fast, reliable)
  2. DuckDuckGo HTML   — free fallback, no key required (requests + bs4)

Writes: nothing (stateless lookup, results returned to LLM context only)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import quote_plus

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BRAVE_SEARCH_KEY
from tools.common import get_opsec_session, log_error

_TIMEOUT = 15
_DEFAULT_MAX_RESULTS = 10
_MAX_RESULTS_CAP = 20

_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
# Brave Search API
# ---------------------------------------------------------------------------

def _brave_search(query: str, max_results: int) -> list[dict]:
    """Search via Brave Search API (requires key)."""
    resp = get_opsec_session().get(
        "https://api.search.brave.com/res/v1/web/search",
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": BRAVE_SEARCH_KEY,
        },
        params={"q": query, "count": min(max_results, _MAX_RESULTS_CAP)},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()

    results = []
    for item in data.get("web", {}).get("results", [])[:max_results]:
        results.append({
            "title": item.get("title", ""),
            "url": item.get("url", ""),
            "snippet": item.get("description", ""),
        })
    return results


# ---------------------------------------------------------------------------
# DuckDuckGo HTML fallback
# ---------------------------------------------------------------------------

def _ddg_search(query: str, max_results: int) -> list[dict]:
    """Search via DuckDuckGo HTML (no API key required)."""
    from bs4 import BeautifulSoup

    resp = get_opsec_session().get(
        "https://html.duckduckgo.com/html/",
        params={"q": query},
        headers={"User-Agent": _UA},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    results = []

    for result_div in soup.select(".result__body")[:max_results]:
        title_el = result_div.select_one(".result__a")
        snippet_el = result_div.select_one(".result__snippet")
        if not title_el:
            continue

        href = title_el.get("href", "")
        # DDG wraps URLs in a redirect — extract the real URL
        real_url = _extract_ddg_url(href)

        results.append({
            "title": title_el.get_text(strip=True),
            "url": real_url,
            "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
        })

    return results


def _extract_ddg_url(href: str) -> str:
    """Extract the real URL from a DuckDuckGo redirect link."""
    # DDG links look like: //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com&...
    from urllib.parse import parse_qs, urlparse
    parsed = urlparse(href)
    qs = parse_qs(parsed.query)
    if "uddg" in qs:
        return qs["uddg"][0]
    # Fallback: return as-is (may be a direct link)
    if href.startswith("//"):
        return "https:" + href
    return href


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def web_search(query: str, max_results: int = _DEFAULT_MAX_RESULTS) -> dict:
    """Search the web and return structured results.

    Parameters
    ----------
    query : str
        Search query string.
    max_results : int
        Maximum number of results to return (capped at 20).

    Returns
    -------
    dict
        ``{"status": "ok", "query": ..., "backend": ..., "result_count": ...,
        "results": [{"title", "url", "snippet"}, ...]}``
    """
    max_results = min(max_results, _MAX_RESULTS_CAP)

    # Try Brave first if configured
    if BRAVE_SEARCH_KEY:
        try:
            results = _brave_search(query, max_results)
            return {
                "status": "ok",
                "query": query,
                "backend": "brave",
                "result_count": len(results),
                "results": results,
            }
        except Exception as exc:
            log_error(None, "web_search", str(exc), severity="warning",
                      context={"backend": "brave", "query": query})
            # Fall through to DDG

    # DuckDuckGo fallback
    try:
        results = _ddg_search(query, max_results)
        return {
            "status": "ok",
            "query": query,
            "backend": "duckduckgo",
            "result_count": len(results),
            "results": results,
        }
    except Exception as exc:
        log_error(None, "web_search", str(exc), severity="error",
                  context={"backend": "duckduckgo", "query": query})
        return {
            "status": "error",
            "query": query,
            "reason": f"All search backends failed: {exc}",
            "results": [],
        }
