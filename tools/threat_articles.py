"""
Threat article discovery and persistence for monthly SOC reporting.

Article generation is now done by the local Claude Desktop agent using the
``write_threat_article`` MCP prompt, persisted via ``save_threat_article``.
Module retains ``_SYSTEM_PROMPT``, ``fetch_candidates()``, and ``save_article()``.
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from typing import Any

from tools.common import get_session

from config.settings import (
    ARTICLE_INDEX_FILE,
    ARTICLES_DIR,
    BASE_DIR,
    CAPTURE_UA,
    OPENCTI_KEY,
    OPENCTI_URL,
)
from tools.common import (
    defang_ioc,
    load_json,
    log_error,
    save_json,
    utcnow,
    write_artefact,
    write_report,
)

_SOURCES_FILE = BASE_DIR / "config" / "article_sources.json"
_REQUEST_TIMEOUT = 15
_MAX_BODY_CHARS = 3000  # truncate fetched article body to save tokens


# ---------------------------------------------------------------------------
# RSS fetching
# ---------------------------------------------------------------------------

def _load_sources() -> list[dict]:
    """Load RSS source config, falling back to empty list."""
    try:
        data = load_json(_SOURCES_FILE)
        return data.get("sources", [])
    except FileNotFoundError:
        return []


def _strip_html(html: str) -> str:
    """Crude HTML tag removal for RSS descriptions."""
    text = re.sub(r"<[^>]+>", " ", html)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _parse_rss(xml_text: str, source_name: str) -> list[dict]:
    """Parse RSS/Atom XML into normalised entry dicts."""
    entries: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return entries

    # RSS 2.0
    for item in root.iter("item"):
        title_el = item.find("title")
        link_el = item.find("link")
        desc_el = item.find("description")
        pub_el = item.find("pubDate")
        title = title_el.text.strip() if title_el is not None and title_el.text else ""
        link = link_el.text.strip() if link_el is not None and link_el.text else ""
        desc = _strip_html(desc_el.text) if desc_el is not None and desc_el.text else ""
        pub = pub_el.text.strip() if pub_el is not None and pub_el.text else ""
        if title and link:
            entries.append({
                "title": title,
                "url": link,
                "summary": desc[:500],
                "published": pub,
                "source_name": source_name,
            })

    # Atom
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//atom:entry", ns):
        title_el = entry.find("atom:title", ns)
        link_el = entry.find("atom:link[@rel='alternate']", ns)
        if link_el is None:
            link_el = entry.find("atom:link", ns)
        summary_el = entry.find("atom:summary", ns) or entry.find("atom:content", ns)
        updated_el = entry.find("atom:updated", ns) or entry.find("atom:published", ns)
        title = title_el.text.strip() if title_el is not None and title_el.text else ""
        link = link_el.get("href", "").strip() if link_el is not None else ""
        desc = _strip_html(summary_el.text) if summary_el is not None and summary_el.text else ""
        pub = updated_el.text.strip() if updated_el is not None and updated_el.text else ""
        if title and link:
            entries.append({
                "title": title,
                "url": link,
                "summary": desc[:500],
                "published": pub,
                "source_name": source_name,
            })

    return entries


def _fetch_feeds(days: int = 7, category: str | None = None) -> list[dict]:
    """Fetch and parse all configured RSS feeds, returning recent entries."""
    sources = _load_sources()
    if category:
        sources = [s for s in sources if category.upper() in s.get("categories", [])]

    all_entries: list[dict] = []
    headers = {"User-Agent": CAPTURE_UA}

    for src in sources:
        if src.get("type") != "rss":
            continue
        try:
            resp = get_session().get(src["url"], headers=headers, timeout=_REQUEST_TIMEOUT)
            resp.raise_for_status()
            entries = _parse_rss(resp.text, src["name"])
            all_entries.extend(entries)
        except Exception as exc:
            log_error("", "threat_articles.fetch_feed", str(exc),
                      severity="warning", context={"source": src["name"], "url": src["url"]})

    # Deduplicate by URL
    seen: set[str] = set()
    unique: list[dict] = []
    for e in all_entries:
        if e["url"] not in seen:
            seen.add(e["url"])
            unique.append(e)

    return unique


def _fetch_full_content(url: str) -> str:
    """Fetch full article text from a URL. Returns plain text, truncated."""
    headers = {"User-Agent": CAPTURE_UA}
    try:
        resp = get_session().get(url, headers=headers, timeout=_REQUEST_TIMEOUT)
        resp.raise_for_status()
        text = _strip_html(resp.text)
        return text[:_MAX_BODY_CHARS]
    except Exception as exc:
        log_error("", "threat_articles.fetch_content", str(exc),
                  severity="warning", context={"url": url})
        return ""


# ---------------------------------------------------------------------------
# Article index (dedup)
# ---------------------------------------------------------------------------

def _load_article_index() -> dict:
    """Load the article index from registry."""
    try:
        return load_json(ARTICLE_INDEX_FILE)
    except FileNotFoundError:
        return {"version": 1, "articles": []}


def _save_article_index(index: dict) -> None:
    """Persist article index."""
    save_json(ARTICLE_INDEX_FILE, index)


def _topic_fingerprint(title: str) -> str:
    """Deterministic fingerprint for dedup: normalised title hash."""
    normalised = re.sub(r"[^a-z0-9 ]", "", title.lower()).strip()
    return hashlib.sha256(normalised.encode()).hexdigest()[:16]


def _is_covered(fingerprint: str, index: dict) -> bool:
    """Check if a topic fingerprint already exists in the index."""
    existing = {a.get("fingerprint") for a in index.get("articles", [])}
    return fingerprint in existing


# ---------------------------------------------------------------------------
# Confluence dedup — check recent pages in the MDR1 space
# ---------------------------------------------------------------------------

_confluence_cache: list[dict] | None = None


def _fetch_confluence_pages(limit: int = 15) -> list[dict]:
    """Fetch recent page titles and IDs from Confluence for dedup.

    Cached for the lifetime of the process to avoid repeated API calls.
    Returns list of ``{"title": <lowercased>, "id": <page_id>}`` dicts.
    """
    global _confluence_cache
    if _confluence_cache is not None:
        return _confluence_cache

    try:
        from tools.confluence_read import _is_configured, list_pages
        if not _is_configured():
            _confluence_cache = []
            return _confluence_cache
        result = list_pages(limit=limit)
        _confluence_cache = [
            {"title": p["title"].lower(), "id": p.get("id", "")}
            for p in result.get("pages", [])
        ]
    except Exception as exc:
        log_error("", "threat_articles.confluence_dedup", str(exc),
                  severity="warning")
        _confluence_cache = []

    return _confluence_cache


def _fetch_confluence_titles(limit: int = 15) -> list[str]:
    """Return lowercased titles only (convenience wrapper)."""
    return [p["title"] for p in _fetch_confluence_pages(limit=limit)]


def _stem(word: str) -> str:
    """Crude suffix stripping for dedup matching."""
    for suffix in ("ation", "ting", "ing", "ment", "ies", "es", "ed", "ly", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[:-len(suffix)]
    return word


def _tokenise(text: str) -> set[str]:
    """Normalise text into a set of stemmed significant tokens."""
    words = re.sub(r"[^a-z0-9 ]", "", text.lower()).split()
    return {_stem(w) for w in words if len(w) > 3}


def _is_covered_confluence(title: str) -> bool:
    """Check if a topic is already covered by a recent Confluence page.

    Uses stemmed token-overlap matching — if >=40% of significant words
    in the candidate title appear in a Confluence page title, it's a match.
    """
    confluence_titles = _fetch_confluence_titles()
    if not confluence_titles:
        return False

    candidate_tokens = _tokenise(title)
    if not candidate_tokens:
        return False

    for ct in confluence_titles:
        page_tokens = _tokenise(ct)
        overlap = candidate_tokens & page_tokens
        if len(overlap) >= len(candidate_tokens) * 0.4:
            return True

    return False


# ---------------------------------------------------------------------------
# OpenCTI dedup — check existing reports in the CTI platform
# ---------------------------------------------------------------------------

_opencti_report_cache: list[str] | None = None


def _fetch_opencti_report_titles(limit: int = 30) -> list[str]:
    """Fetch recent report titles from OpenCTI for dedup.

    Cached for the lifetime of the process to avoid repeated API calls.
    Returns lowercased titles for fuzzy matching.
    """
    global _opencti_report_cache
    if _opencti_report_cache is not None:
        return _opencti_report_cache

    if not OPENCTI_KEY:
        _opencti_report_cache = []
        return _opencti_report_cache

    try:
        import requests as _requests
        gql = """{
          reports(first: %d, orderBy: created_at, orderMode: desc) {
            edges { node { name } }
          }
        }""" % limit
        headers = {"Authorization": f"Bearer {OPENCTI_KEY}",
                    "Content-Type": "application/json"}
        resp = _requests.post(
            f"{OPENCTI_URL}/graphql", headers=headers,
            json={"query": gql}, timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        edges = data.get("data", {}).get("reports", {}).get("edges", [])
        _opencti_report_cache = [e["node"]["name"].lower() for e in edges
                                  if e.get("node", {}).get("name")]
    except Exception as exc:
        log_error("", "threat_articles.opencti_dedup", str(exc),
                  severity="warning")
        _opencti_report_cache = []

    return _opencti_report_cache


def _is_covered_opencti(title: str) -> bool:
    """Check if a topic is already covered by an OpenCTI report.

    Uses the same stemmed token-overlap matching as Confluence dedup —
    if >=40% of significant words in the candidate title appear in an
    existing OpenCTI report title, it's a match.
    """
    report_titles = _fetch_opencti_report_titles()
    if not report_titles:
        return False

    candidate_tokens = _tokenise(title)
    if not candidate_tokens:
        return False

    for rt in report_titles:
        report_tokens = _tokenise(rt)
        overlap = candidate_tokens & report_tokens
        if len(overlap) >= len(candidate_tokens) * 0.4:
            return True

    return False


def _find_matching_title(candidate_title: str, cached_titles: list[str]) -> str | None:
    """Return the first cached title that fuzzy-matches the candidate, or None."""
    candidate_tokens = _tokenise(candidate_title)
    if not candidate_tokens:
        return None
    for ct in cached_titles:
        page_tokens = _tokenise(ct)
        overlap = candidate_tokens & page_tokens
        if len(overlap) >= len(candidate_tokens) * 0.4:
            return ct
    return None


def _find_matching_confluence_page(candidate_title: str) -> dict | None:
    """Return the first Confluence page that fuzzy-matches, with title and ID."""
    candidate_tokens = _tokenise(candidate_title)
    if not candidate_tokens:
        return None
    for page in _fetch_confluence_pages():
        page_tokens = _tokenise(page["title"])
        overlap = candidate_tokens & page_tokens
        if len(overlap) >= len(candidate_tokens) * 0.4:
            return page
    return None


def invalidate_dedup_caches() -> None:
    """Reset Confluence and OpenCTI dedup caches.

    Call after saving or publishing an article so that subsequent
    dedup checks within the same process see fresh data.
    """
    global _confluence_cache, _opencti_report_cache
    _confluence_cache = None
    _opencti_report_cache = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_topic_dedup(title: str) -> dict:
    """Check whether a topic title duplicates an existing article.

    Composes all three dedup stores:
      1. Local article index — exact fingerprint match
      2. Confluence — stemmed 40% token overlap
      3. OpenCTI — stemmed 40% token overlap

    Returns
    -------
    dict
        ``{"is_duplicate": False}`` if no match found, or
        ``{"is_duplicate": True, "matches": [...]}`` with detail on each
        store that matched.
    """
    matches: list[dict] = []

    # 1. Local index
    index = _load_article_index()
    fp = _topic_fingerprint(title)
    if _is_covered(fp, index):
        for a in index.get("articles", []):
            if a.get("fingerprint") == fp:
                matches.append({
                    "store": "local_index",
                    "matched_title": a.get("title", ""),
                    "article_id": a.get("article_id", ""),
                })
                break

    # 2. Confluence
    if _is_covered_confluence(title):
        page = _find_matching_confluence_page(title)
        match_entry: dict[str, str] = {
            "store": "confluence",
            "matched_title": page["title"] if page else "(title overlap detected)",
        }
        if page and page.get("id"):
            match_entry["page_id"] = page["id"]
        matches.append(match_entry)

    # 3. OpenCTI
    if _is_covered_opencti(title):
        matched = _find_matching_title(title, _fetch_opencti_report_titles())
        matches.append({
            "store": "opencti",
            "matched_title": matched or "(title overlap detected)",
        })

    if matches:
        return {
            "is_duplicate": True,
            "title": title,
            "matches": matches,
        }

    return {"is_duplicate": False, "title": title}


def fetch_candidates(
    days: int = 7,
    max_candidates: int = 20,
    category: str | None = None,
) -> list[dict]:
    """Fetch recent cybersecurity news, classify, and check for duplicates.

    Returns a list of candidate dicts ready for analyst selection.
    """
    entries = _fetch_feeds(days=days, category=category)
    index = _load_article_index()

    candidates: list[dict] = []
    for entry in entries:
        fp = _topic_fingerprint(entry["title"])
        in_opencti = _is_covered_opencti(entry["title"])
        already_covered = (_is_covered(fp, index)
                           or _is_covered_confluence(entry["title"])
                           or in_opencti)

        # Quick heuristic classification based on keywords
        title_lower = entry["title"].lower()
        summary_lower = entry.get("summary", "").lower()
        cve_match = re.search(r"cve-\d{4}-\d+", title_lower + " " + summary_lower)
        vuln_keywords = {"vulnerability", "vulnerabilities", "patch", "advisory",
                         "zero-day", "0-day", "exploit", "rce", "privilege escalation"}
        is_vuln = cve_match or any(kw in title_lower for kw in vuln_keywords)
        cat = "EV" if is_vuln else "ET"

        if category and cat != category.upper():
            continue

        candidates.append({
            "id": fp,
            "title": entry["title"],
            "category": cat,
            "source_name": entry["source_name"],
            "source_url": entry["url"],
            "published": entry.get("published", ""),
            "summary": entry.get("summary", ""),
            "already_covered": already_covered,
            "in_opencti": in_opencti,
        })

    # Sort: uncovered first, then by source diversity
    candidates.sort(key=lambda c: (c["already_covered"], c["source_name"]))

    return candidates[:max_candidates]


def generate_articles(
    candidates: list[dict],
    analyst: str = "unassigned",
    case_id: str | None = None,
) -> dict:
    """Stub — direct LLM generation removed.

    Use the ``write_threat_article`` MCP prompt to generate articles via
    the local Claude Desktop agent, then call ``save_threat_article``
    to persist them.
    """
    return {
        "status": "use_prompt",
        "prompt": "write_threat_article",
        "save_tool": "save_threat_article",
    }


def save_article(
    article_text: str,
    title: str,
    category: str = "ET",
    source_urls: list[str] | None = None,
    analyst: str = "unassigned",
    case_id: str | None = None,
    force: bool = False,
) -> dict:
    """Persist a threat article generated by the analyst's local Claude session.

    Parameters
    ----------
    article_text : str
        Full article markdown (title, body, recommendations, indicators).
    title : str
        Article title.
    category : str
        "ET" (Emerging Threat) or "EV" (Emerging Vulnerability).
    source_urls : list[str], optional
        URLs of the source material used.
    analyst : str
        Analyst name for attribution.
    case_id : str, optional
        Case ID to associate with.
    force : bool
        Override duplicate detection and save regardless. Default False.

    Returns
    -------
    dict
        Article manifest, or ``{"status": "duplicate_warning", ...}``
        if a duplicate is detected and *force* is False.
    """
    # Pre-save dedup gate
    if not force:
        dedup = check_topic_dedup(title)
        if dedup["is_duplicate"]:
            return {
                "status": "duplicate_warning",
                "title": title,
                "matches": dedup["matches"],
                "message": (
                    "This topic appears to already be covered. "
                    "Use force=True to save anyway."
                ),
            }

    now = datetime.fromisoformat(utcnow().replace("Z", "+00:00"))
    month_dir = now.strftime("%Y-%m")
    index = _load_article_index()

    seq = len(index.get("articles", [])) + 1
    art_id = f"ART-{now.strftime('%Y%m%d')}-{seq:04d}"

    # Write artefacts
    art_dir = ARTICLES_DIR / month_dir / art_id
    md_manifest = write_report(art_dir / "article.md", article_text, title=title)

    manifest = {
        "article_id": art_id,
        "title": title,
        "category": category.upper(),
        "analyst": analyst,
        "date": now.strftime("%Y-%m-%d"),
        "source_urls": source_urls or [],
        "fingerprint": _topic_fingerprint(title),
        "article_path": md_manifest["path"],
        "source": "claude_desktop",
        "confluence_page_id": None,
        "confluence_url": None,
        "published_at": None,
        "opencti_report_id": None,
        "opencti_url": None,
    }
    save_json(art_dir / "article_manifest.json", manifest)

    # Update index
    index.setdefault("articles", []).append(manifest)
    _save_article_index(index)

    # Also write to case if provided
    if case_id:
        from config.settings import CASES_DIR
        case_art_dir = CASES_DIR / case_id / "artefacts" / "articles"
        write_report(case_art_dir / f"{art_id}.md", article_text, title=title)

    invalidate_dedup_caches()
    return manifest


def list_articles(
    month: str | None = None,
    category: str | None = None,
) -> list[dict]:
    """List produced articles from the index, optionally filtered."""
    index = _load_article_index()
    articles = index.get("articles", [])

    if month:
        articles = [a for a in articles if a.get("date", "").startswith(month)]
    if category:
        articles = [a for a in articles if a.get("category") == category.upper()]

    return articles
