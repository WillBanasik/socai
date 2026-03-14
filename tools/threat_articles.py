"""
Threat article discovery and generation for monthly SOC reporting.

Fetches recent cybersecurity news from configured RSS feeds, clusters by topic,
and produces 60-second-read article summaries categorised as ET (Emerging Threat)
or EV (Emerging Vulnerability).
"""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from typing import Any

from tools.common import get_session

from config.article_prompts import (
    ARTICLE_SYSTEM_PROMPT,
    ARTICLE_USER_TEMPLATE,
    CLASSIFY_SYSTEM_PROMPT,
    CLUSTER_SYSTEM_PROMPT,
)
from config.settings import (
    ANTHROPIC_KEY,
    ARTICLE_INDEX_FILE,
    ARTICLES_DIR,
    BASE_DIR,
    CAPTURE_UA,
)
from tools.common import (
    defang_ioc,
    get_model,
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

_confluence_cache: list[str] | None = None


def _fetch_confluence_titles(limit: int = 15) -> list[str]:
    """Fetch recent page titles from Confluence for dedup.

    Cached for the lifetime of the process to avoid repeated API calls.
    Returns lowercased titles for fuzzy matching.
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
        _confluence_cache = [p["title"].lower() for p in result.get("pages", [])]
    except Exception as exc:
        log_error("", "threat_articles.confluence_dedup", str(exc),
                  severity="warning")
        _confluence_cache = []

    return _confluence_cache


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
# LLM helpers
# ---------------------------------------------------------------------------

def _llm_call(system: str, user_msg: str, max_tokens: int = 1024) -> str:
    """Simple single-turn LLM call. Returns text response."""
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    model = get_model("articles")
    resp = client.messages.create(
        model=model,
        system=system,
        messages=[{"role": "user", "content": user_msg}],
        max_tokens=max_tokens,
    )
    text = ""
    for block in resp.content:
        if getattr(block, "type", None) == "text":
            text += block.text
    return text.strip()


def _classify_article(title: str, summary: str) -> str:
    """Classify a single article as ET or EV using LLM."""
    user_msg = f"Title: {title}\nSummary: {summary}"
    result = _llm_call(CLASSIFY_SYSTEM_PROMPT, user_msg, max_tokens=10)
    return "EV" if "EV" in result.upper() else "ET"


def _cluster_candidates(candidates: list[dict]) -> list[dict]:
    """Group candidates by topic using LLM. Returns list of group dicts."""
    if len(candidates) <= 1:
        return [{"topic": c["title"], "indices": [i], "category": c.get("category", "ET")}
                for i, c in enumerate(candidates)]

    listing = "\n".join(
        f"[{i}] ({c.get('category', '?')}) {c['title']} — {c.get('summary', '')[:150]}"
        for i, c in enumerate(candidates)
    )
    user_msg = f"Articles:\n{listing}\n\nReturn JSON array of groups."
    raw = _llm_call(CLUSTER_SYSTEM_PROMPT, user_msg, max_tokens=2048)

    # Extract JSON from response
    try:
        match = re.search(r"\[.*\]", raw, re.DOTALL)
        if match:
            groups = json.loads(match.group())
            return groups
    except (json.JSONDecodeError, AttributeError):
        pass

    # Fallback: each candidate in its own group
    return [{"topic": c["title"], "indices": [i], "category": c.get("category", "ET")}
            for i, c in enumerate(candidates)]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

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
        already_covered = (_is_covered(fp, index)
                           or _is_covered_confluence(entry["title"]))

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
        })

    # Sort: uncovered first, then by source diversity
    candidates.sort(key=lambda c: (c["already_covered"], c["source_name"]))

    return candidates[:max_candidates]


def generate_articles(
    candidates: list[dict],
    analyst: str = "unassigned",
    case_id: str | None = None,
) -> list[dict]:
    """Generate article summaries for the given candidates.

    Each candidate (or group of candidates on the same topic) produces one
    article. Returns list of manifest dicts for written artefacts.
    """
    from tools.schemas import ArticleSummary
    from tools.structured_llm import structured_call

    # Cluster candidates by topic
    groups = _cluster_candidates(candidates)
    index = _load_article_index()
    results: list[dict] = []
    model = get_model("articles")
    now = datetime.fromisoformat(utcnow().replace("Z", "+00:00"))
    month_dir = now.strftime("%Y-%m")

    for group in groups:
        indices = group.get("indices", [])
        if not indices:
            continue

        group_candidates = [candidates[i] for i in indices if i < len(candidates)]
        if not group_candidates:
            continue

        cat = group.get("category", group_candidates[0].get("category", "ET"))
        topic_title = group.get("topic", group_candidates[0]["title"])

        # Fetch full content for each source
        source_texts: list[str] = []
        source_urls: list[str] = []
        for c in group_candidates:
            url = c.get("source_url", "")
            source_urls.append(url)
            full_text = _fetch_full_content(url)
            if full_text:
                source_texts.append(f"Source: {c['source_name']} ({url})\n{full_text}")
            else:
                # Fall back to RSS summary
                source_texts.append(
                    f"Source: {c['source_name']} ({url})\n{c.get('summary', 'No content available.')}"
                )

        sources_block = "\n\n---\n\n".join(source_texts)

        user_msg = ARTICLE_USER_TEMPLATE.format(
            category=cat,
            title=topic_title,
            sources=sources_block,
        )

        # Generate via structured output
        try:
            article, usage = structured_call(
                model=model,
                system=ARTICLE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
                output_schema=ArticleSummary,
                max_tokens=2048,
            )
        except Exception as exc:
            log_error("", "threat_articles.generate", str(exc),
                      severity="error", context={"topic": topic_title})
            continue

        if not article:
            log_error("", "threat_articles.generate", "LLM returned no result",
                      severity="warning", context={"topic": topic_title})
            continue

        # Build markdown output
        md_lines = [
            f"# {article.title}",
            "",
            f"**Category:** {article.category}",
            f"**Date:** {now.strftime('%Y-%m-%d')}",
            f"**Analyst:** {analyst}",
            f"**Sources:** {', '.join(source_urls)}",
            "",
            article.body,
            "",
            "## Recommendations",
            "",
            article.recommendations,
            "",
            "## Indicators",
            "",
        ]

        if article.cves:
            md_lines.append("**CVEs:**")
            for cve in article.cves:
                md_lines.append(f"- {cve}")
            md_lines.append("")

        if article.iocs:
            md_lines.append("**IOCs:**")
            for ioc in article.iocs:
                md_lines.append(f"- {ioc}")
            md_lines.append("")

        if not article.cves and not article.iocs:
            md_lines.append("No indicators identified in source material.")
            md_lines.append("")

        md_text = "\n".join(md_lines)

        # Generate article ID
        seq = len(index.get("articles", [])) + 1
        art_id = f"ART-{now.strftime('%Y%m%d')}-{seq:04d}"

        # Write artefacts
        art_dir = ARTICLES_DIR / month_dir / art_id
        md_manifest = write_report(art_dir / "article.md", md_text, title=article.title)

        manifest = {
            "article_id": art_id,
            "title": article.title,
            "category": article.category,
            "analyst": analyst,
            "date": now.strftime("%Y-%m-%d"),
            "source_urls": source_urls,
            "fingerprint": _topic_fingerprint(topic_title),
            "article_path": md_manifest["path"],
            "confluence_page_id": None,
            "confluence_url": None,
            "published_at": None,
        }
        save_json(art_dir / "article_manifest.json", manifest)

        # Update index
        index.setdefault("articles", []).append(manifest)

        # Also write to case if provided
        if case_id:
            from config.settings import CASES_DIR
            case_art_dir = CASES_DIR / case_id / "artefacts" / "articles"
            write_report(case_art_dir / f"{art_id}.md", md_text, title=article.title)

        results.append(manifest)

    # Persist updated index
    if results:
        _save_article_index(index)

    return results


def save_article(
    article_text: str,
    title: str,
    category: str = "ET",
    source_urls: list[str] | None = None,
    analyst: str = "unassigned",
    case_id: str | None = None,
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

    Returns
    -------
    dict
        Article manifest.
    """
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
