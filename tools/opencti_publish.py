"""
OpenCTI report publishing — build STIX 2.1 bundles from threat articles
and push them to OpenCTI via the bundleCreate GraphQL mutation.

Gated behind ``SOCAI_OPENCTI_PUBLISH=1``.  When disabled, all public
functions return early with a status message — safe to call unconditionally.

Workflow:
    1. ``check_before_publish(article_id)`` — dedup gate (title overlap)
    2. ``build_stix_bundle(manifest, article_text)`` — STIX 2.1 JSON bundle
    3. ``generate_posting_package(article_id)`` — HTML file with labelled
       sections for manual OpenCTI posting
    4. ``publish_report(article_id)`` — push bundle, write OpenCTI ID back
       to the article manifest (requires SOCAI_OPENCTI_PUBLISH=1)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.settings import (
    ARTICLE_INDEX_FILE,
    ARTICLES_DIR,
    OPENCTI_KEY,
    OPENCTI_PUBLISH_ENABLED,
    OPENCTI_URL,
)
from tools.common import load_json, log_error, save_json, utcnow


# ---------------------------------------------------------------------------
# STIX 2.1 helpers
# ---------------------------------------------------------------------------

def _stix_id(stype: str) -> str:
    """Generate a deterministic-format STIX ID."""
    return f"{stype}--{uuid.uuid4()}"


# Map extract_iocs keys to STIX Cyber Observable types
_IOC_TYPE_MAP: dict[str, tuple[str, str]] = {
    "ipv4":   ("ipv4-addr",    "value"),
    "domain": ("domain-name",  "value"),
    "url":    ("url",          "value"),
    "email":  ("email-addr",   "value"),
    "md5":    ("file",         "hashes.MD5"),
    "sha1":   ("file",         "hashes.SHA-1"),
    "sha256": ("file",         "hashes.SHA-256"),
}


# ---------------------------------------------------------------------------
# Hunt query generation (IOC → KQL / LogScale indicators)
# ---------------------------------------------------------------------------

def _generate_hunt_queries(iocs: dict[str, list], created: str,
                           title: str = "") -> list[dict]:
    """Generate STIX Indicator objects containing KQL and LogScale hunt queries.

    Each query is a STIX Indicator with a custom ``pattern_type`` (``kql`` or
    ``logscale``) so OpenCTI stores them as detection rules alongside the
    standard STIX-pattern IOC indicators.  Linked to their parent report via
    ``object_refs`` in the bundle.

    Naming convention: ``[HUNT] <article title> — <IOC type>`` to distinguish
    from standing detection queries (``[DEFENDER]`` / ``[SENTINEL]``).
    """
    from tools.generate_queries import (
        _build_kql_ipv4,
        _build_kql_domains,
        _build_kql_hashes,
        _build_kql_urls,
        _build_kql_emails,
        _build_logscale,
    )

    indicators: list[dict] = []

    # --- KQL queries ---
    kql_sections: list[tuple[str, str]] = []  # (description, query)

    if iocs.get("ipv4"):
        q = _build_kql_ipv4(iocs["ipv4"], tables=None)
        if q:
            kql_sections.append(("IPv4 hunt", q))

    if iocs.get("domain"):
        q = _build_kql_domains(iocs["domain"], tables=None)
        if q:
            kql_sections.append(("Domain hunt", q))

    hash_dict = {}
    for ht in ("sha256", "sha1", "md5"):
        if iocs.get(ht):
            hash_dict[ht] = iocs[ht]
    if hash_dict:
        q = _build_kql_hashes(hash_dict, tables=None)
        if q:
            kql_sections.append(("Hash hunt", q))

    if iocs.get("url"):
        q = _build_kql_urls(iocs["url"], tables=None)
        if q:
            kql_sections.append(("URL hunt", q))

    if iocs.get("email"):
        q = _build_kql_emails(iocs["email"], tables=None)
        if q:
            kql_sections.append(("Email hunt", q))

    # Short title for naming (truncate at 60 chars)
    short_title = title[:60].rstrip() if title else "Untitled"

    for desc, query_text in kql_sections:
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_id("indicator"),
            "created": created,
            "modified": created,
            "name": f"[HUNT] {short_title} \u2014 {desc}",
            "description": f"Sentinel/Defender KQL hunt query for {desc.lower()}, "
                           f"linked to report: {title}",
            "pattern": query_text,
            "pattern_type": "kql",
            "valid_from": created,
            "indicator_types": ["anomalous-activity"],
        })

    # --- LogScale queries ---
    logscale_text = _build_logscale(iocs)
    if logscale_text:
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_id("indicator"),
            "created": created,
            "modified": created,
            "name": f"[HUNT] {short_title} \u2014 LogScale IOC hunt",
            "description": f"CrowdStrike LogScale/NGSIEM hunt query for all IOC types, "
                           f"linked to report: {title}",
            "pattern": logscale_text,
            "pattern_type": "logscale",
            "valid_from": created,
            "indicator_types": ["anomalous-activity"],
        })

    return indicators


def _build_indicator(ioc_value: str, ioc_type: str, report_id: str,
                     created: str) -> dict | None:
    """Build a STIX 2.1 Indicator object from a raw IOC."""
    mapping = _IOC_TYPE_MAP.get(ioc_type)
    if not mapping:
        return None

    obs_type, obs_key = mapping

    # Build STIX pattern
    if obs_key.startswith("hashes."):
        hash_type = obs_key.split(".", 1)[1]
        pattern = f"[file:hashes.'{hash_type}' = '{ioc_value}']"
    else:
        pattern = f"[{obs_type}:{obs_key} = '{ioc_value}']"

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator"),
        "created": created,
        "modified": created,
        "name": ioc_value,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "indicator_types": ["malicious-activity"],
    }


def _build_observable(ioc_value: str, ioc_type: str, created: str) -> dict | None:
    """Build a STIX 2.1 SCO (observable) from a raw IOC."""
    mapping = _IOC_TYPE_MAP.get(ioc_type)
    if not mapping:
        return None

    obs_type, obs_key = mapping

    obj: dict[str, Any] = {
        "type": obs_type,
        "spec_version": "2.1",
        "id": _stix_id(obs_type),
    }

    if obs_key.startswith("hashes."):
        hash_type = obs_key.split(".", 1)[1]
        obj["hashes"] = {hash_type: ioc_value}
    else:
        obj["value"] = ioc_value

    return obj


# ---------------------------------------------------------------------------
# Bundle builder
# ---------------------------------------------------------------------------

def build_stix_bundle(
    manifest: dict,
    article_text: str,
) -> dict:
    """Build a STIX 2.1 bundle from an article manifest and its text.

    Returns a dict suitable for JSON serialisation and OpenCTI's
    ``bundleCreate`` mutation.  The bundle contains:

    - A ``report`` SDO (the article itself)
    - ``indicator`` SDOs for each extracted IOC (STIX patterns)
    - ``indicator`` SDOs for KQL hunt queries (pattern_type=kql)
    - ``indicator`` SDOs for LogScale hunt queries (pattern_type=logscale)
    - ``observed-data`` / SCO objects for each IOC
    - ``relationship`` SROs linking indicators to the report

    Parameters
    ----------
    manifest : dict
        Article manifest (from ``article_manifest.json``).
    article_text : str
        Full article markdown text.
    """
    from tools.extract_iocs import _extract_from_text

    created = datetime.fromisoformat(
        manifest.get("date", utcnow().split("T")[0]) + "T00:00:00+00:00"
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # --- Report SDO ---
    report_id = _stix_id("report")
    report_obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": created,
        "modified": created,
        "name": manifest.get("title", "Untitled"),
        "description": article_text,
        "published": created,
        "report_types": ["threat-report"],
        "object_refs": [],   # populated below
    }

    # Add external references (source URLs)
    ext_refs = []
    for url in manifest.get("source_urls", []):
        ext_refs.append({"source_name": "Source Article", "url": url})
    if ext_refs:
        report_obj["external_references"] = ext_refs

    # --- Extract IOCs from article text ---
    raw_iocs = _extract_from_text(article_text, include_private=False)

    objects: list[dict] = [report_obj]
    object_refs: list[str] = []

    for ioc_type, values in raw_iocs.items():
        if ioc_type == "cve":
            # CVEs become vulnerability objects
            for cve_id in values:
                vuln = {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": _stix_id("vulnerability"),
                    "created": created,
                    "modified": created,
                    "name": cve_id,
                }
                objects.append(vuln)
                object_refs.append(vuln["id"])
            continue

        for value in values:
            # Indicator (pattern-based)
            indicator = _build_indicator(value, ioc_type, report_id, created)
            if indicator:
                objects.append(indicator)
                object_refs.append(indicator["id"])

            # Observable (value-based)
            observable = _build_observable(value, ioc_type, created)
            if observable:
                objects.append(observable)
                object_refs.append(observable["id"])

            # Relationship: indicator → report
            if indicator:
                rel = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _stix_id("relationship"),
                    "created": created,
                    "modified": created,
                    "relationship_type": "object",
                    "source_ref": indicator["id"],
                    "target_ref": report_id,
                }
                objects.append(rel)

    # --- Hunt queries (KQL + LogScale indicators) ---
    hunt_indicators = _generate_hunt_queries(
        raw_iocs, created, title=manifest.get("title", ""))
    for hi in hunt_indicators:
        objects.append(hi)
        object_refs.append(hi["id"])

    report_obj["object_refs"] = object_refs

    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }


# ---------------------------------------------------------------------------
# Dedup check
# ---------------------------------------------------------------------------

def check_before_publish(article_id: str) -> dict:
    """Pre-publish dedup check for an article.

    Returns
    -------
    dict
        ``{"ok": True}`` if safe to publish, or
        ``{"ok": False, "reason": "..."}`` with details on why not.
    """
    index = load_json(ARTICLE_INDEX_FILE)
    manifest = None
    for a in index.get("articles", []):
        if a.get("article_id") == article_id:
            manifest = a
            break

    if not manifest:
        return {"ok": False, "reason": f"Article {article_id} not found in index"}

    # Already published?
    if manifest.get("opencti_report_id"):
        return {
            "ok": False,
            "reason": f"Already published as OpenCTI report {manifest['opencti_report_id']}",
            "opencti_url": manifest.get("opencti_url"),
        }

    # Title overlap with existing OpenCTI reports
    from tools.threat_articles import _is_covered_opencti
    if _is_covered_opencti(manifest.get("title", "")):
        return {
            "ok": False,
            "reason": "Similar report already exists in OpenCTI (title overlap)",
            "title": manifest.get("title"),
        }

    return {"ok": True, "article_id": article_id, "title": manifest.get("title")}


# ---------------------------------------------------------------------------
# Publish to OpenCTI
# ---------------------------------------------------------------------------

def publish_report(article_id: str, *, force: bool = False) -> dict:
    """Build a STIX bundle from an article and push it to OpenCTI.

    Gated behind ``SOCAI_OPENCTI_PUBLISH=1``.  Returns the OpenCTI
    report ID and URL on success, writes them back to the article manifest.

    Parameters
    ----------
    article_id : str
        Article ID (e.g. ``ART-20260324-0001``).
    force : bool
        Skip the dedup check (use with caution).
    """
    if not OPENCTI_PUBLISH_ENABLED:
        return {"status": "disabled",
                "message": "OpenCTI publishing disabled (set SOCAI_OPENCTI_PUBLISH=1)"}

    if not OPENCTI_KEY:
        return {"status": "error",
                "message": "OpenCTI not configured (OPENCTI_API_KEY not set)"}

    # Load article
    index = load_json(ARTICLE_INDEX_FILE)
    manifest = None
    manifest_idx = -1
    for i, a in enumerate(index.get("articles", [])):
        if a.get("article_id") == article_id:
            manifest = a
            manifest_idx = i
            break

    if not manifest:
        return {"status": "error", "message": f"Article {article_id} not found"}

    # Dedup gate
    if not force:
        check = check_before_publish(article_id)
        if not check.get("ok"):
            return {"status": "blocked", **check}

    # Load article text
    art_path = Path(manifest.get("article_path", ""))
    # article_path points to .md — but we may have .html only; try .md first
    if art_path.exists():
        article_text = art_path.read_text(encoding="utf-8")
    else:
        # Try HTML sibling
        html_path = art_path.with_suffix(".html")
        if html_path.exists():
            article_text = html_path.read_text(encoding="utf-8")
        else:
            return {"status": "error",
                    "message": f"Article file not found: {art_path}"}

    # Build STIX bundle
    bundle = build_stix_bundle(manifest, article_text)

    # Push to OpenCTI via bundleCreate mutation
    try:
        import requests as _requests

        gql = """
        mutation BundleCreate($input: String!) {
          stixBundleCreate(content: $input) {
            id
          }
        }
        """
        headers = {"Authorization": f"Bearer {OPENCTI_KEY}",
                    "Content-Type": "application/json"}
        payload = {
            "query": gql,
            "variables": {"input": json.dumps(bundle)},
        }

        resp = _requests.post(
            f"{OPENCTI_URL}/graphql", headers=headers,
            json=payload, timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        if "errors" in data:
            return {"status": "api_error", "article_id": article_id,
                    "message": data["errors"][0].get("message")}

        # Extract the created report ID from the bundle response
        # bundleCreate returns a list of created IDs
        bundle_result = data.get("data", {}).get("stixBundleCreate", {})
        opencti_id = bundle_result.get("id", "")

        # Find the report object ID — query for it by title
        report_url = f"{OPENCTI_URL}/dashboard/analyses/reports/{opencti_id}" if opencti_id else None

    except Exception as exc:
        log_error("", "opencti_publish.publish_report", str(exc),
                  severity="error", context={"article_id": article_id})
        return {"status": "error", "article_id": article_id, "error": str(exc)}

    # Write OpenCTI ID back to manifest
    manifest["opencti_report_id"] = opencti_id
    manifest["opencti_url"] = report_url
    manifest["published_at"] = utcnow()
    index["articles"][manifest_idx] = manifest
    save_json(ARTICLE_INDEX_FILE, index)

    # Also update the per-article manifest file
    art_dir = art_path.parent if art_path.exists() else None
    if art_dir:
        manifest_file = art_dir / "article_manifest.json"
        if manifest_file.exists():
            local_manifest = load_json(manifest_file)
            local_manifest["opencti_report_id"] = opencti_id
            local_manifest["opencti_url"] = report_url
            local_manifest["published_at"] = manifest["published_at"]
            save_json(manifest_file, local_manifest)

    return {
        "status": "ok",
        "article_id": article_id,
        "opencti_report_id": opencti_id,
        "opencti_url": report_url,
        "objects_in_bundle": len(bundle.get("objects", [])),
    }


# ---------------------------------------------------------------------------
# Posting package — HTML for manual OpenCTI entry
# ---------------------------------------------------------------------------

def generate_posting_package(article_id: str) -> dict:
    """Generate an HTML posting package for manual OpenCTI entry.

    Reads a saved article, builds the STIX bundle, and writes an HTML file
    with labelled sections for each piece of data that needs to go into
    OpenCTI (report description, observables, indicators, hunt queries).

    Parameters
    ----------
    article_id : str
        Article ID (e.g. ``ART-20260327-0001``).

    Returns
    -------
    dict
        Manifest with ``html_path`` and summary stats.
    """
    from html import escape as e

    # Load article from index
    index = load_json(ARTICLE_INDEX_FILE)
    manifest = None
    for a in index.get("articles", []):
        if a.get("article_id") == article_id:
            manifest = a
            break

    if not manifest:
        return {"status": "error", "message": f"Article {article_id} not found"}

    # Load article text
    art_path = Path(manifest.get("article_path", ""))
    if art_path.exists():
        article_text = art_path.read_text(encoding="utf-8")
    else:
        html_path = art_path.with_suffix(".html")
        if html_path.exists():
            article_text = html_path.read_text(encoding="utf-8")
        else:
            return {"status": "error", "message": f"Article file not found: {art_path}"}

    # Build bundle
    bundle = build_stix_bundle(manifest, article_text)

    # Categorise objects
    report_obj = None
    stix_indicators: list[dict] = []
    hunt_kql: list[dict] = []
    hunt_logscale: list[dict] = []
    vulnerabilities: list[dict] = []
    obs_by_type: dict[str, list] = {}

    for obj in bundle["objects"]:
        if obj["type"] == "report":
            report_obj = obj
        elif obj["type"] == "indicator":
            pt = obj.get("pattern_type", "")
            if pt == "kql":
                hunt_kql.append(obj)
            elif pt == "logscale":
                hunt_logscale.append(obj)
            elif pt == "stix":
                stix_indicators.append(obj)
        elif obj["type"] == "vulnerability":
            vulnerabilities.append(obj)
        elif obj["type"] in ("domain-name", "ipv4-addr", "url", "file", "email-addr"):
            obs_by_type.setdefault(obj["type"], []).append(obj)

    # Extract flat lists for blocklists
    domains = sorted(o.get("value", "") for o in obs_by_type.get("domain-name", []))
    ips = sorted(o.get("value", "") for o in obs_by_type.get("ipv4-addr", []))
    hashes: list[str] = []
    for f in obs_by_type.get("file", []):
        for algo, val in (f.get("hashes") or {}).items():
            hashes.append(f"{algo}: {val}")
    urls = sorted(o.get("value", "") for o in obs_by_type.get("url", []))
    emails = sorted(o.get("value", "") for o in obs_by_type.get("email-addr", []))

    # Build HTML
    title = manifest.get("title", "Untitled")
    category = manifest.get("category", "ET")
    date = manifest.get("date", "")
    source_url = (manifest.get("source_urls") or [""])[0]

    # IOC table rows
    ioc_rows = ""
    for ind in stix_indicators:
        ioc_rows += (f"<tr><td><code>{e(ind.get('name', ''))}</code></td>"
                     f"<td><code>{e(ind.get('pattern', ''))}</code></td></tr>\n")

    # Vulnerability rows
    vuln_rows = ""
    for v in vulnerabilities:
        vuln_rows += f"<tr><td><code>{e(v.get('name', ''))}</code></td></tr>\n"

    # KQL sections
    kql_html = ""
    for q in hunt_kql:
        kql_html += (f'<div class="query-block"><h4>{e(q["name"])}</h4>'
                     f'<p class="meta">{e(q.get("description", ""))}</p>'
                     f'<pre><code>{e(q["pattern"])}</code></pre></div>\n')

    # LogScale sections
    logscale_html = ""
    for q in hunt_logscale:
        logscale_html += (f'<div class="query-block"><h4>{e(q["name"])}</h4>'
                          f'<p class="meta">{e(q.get("description", ""))}</p>'
                          f'<pre><code>{e(q["pattern"])}</code></pre></div>\n')

    # Blocklists
    domain_block = "\n".join(domains) if domains else "None extracted"
    ip_block = "\n".join(ips) if ips else "None extracted"
    hash_block = "\n".join(hashes) if hashes else "None extracted"
    url_block = "\n".join(urls) if urls else "None extracted"
    email_block = "\n".join(emails) if emails else "None extracted"

    # Observable sections — only render non-empty types
    obs_sections = ""
    obs_items = [
        ("Domains", "Domain-Name", domains, domain_block),
        ("IP Addresses", "IPv4-Addr", ips, ip_block),
        ("Hashes", "StixFile", hashes, hash_block),
        ("URLs", "Url", urls, url_block),
        ("Email Addresses", "Email-Addr", emails, email_block),
    ]
    obs_num = 2
    for label, octi_type, items, block in obs_items:
        if not items or block == "None extracted":
            continue
        obs_sections += f"""
<h3>{obs_num}{'abcde'[obs_num-2]}. {label} ({len(items)})</h3>
<div class="section">
    <div class="section-header">
        <span class="paste-label">Create as Observables &rarr; {e(octi_type)} &amp; add to Report</span>
    </div>
    <pre><code>{e(block)}</code></pre>
</div>
"""

    # TOC entries for observable sections
    obs_toc = ""
    for label, _, items, block in obs_items:
        if items and block != "None extracted":
            obs_toc += (f'<li><a href="#{label.lower().replace(" ", "-")}">'
                        f'{label} ({len(items)})</a></li>\n')

    total_obs = len(domains) + len(ips) + len(hashes) + len(urls) + len(emails)

    bundle_json = json.dumps(bundle, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenCTI Posting Package — {e(title)}</title>
<style>
    :root {{
        --bg: #0d1117; --surface: #161b22; --border: #30363d;
        --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
        --green: #3fb950; --orange: #d29922; --red: #f85149;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
           background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1200px; margin: 0 auto; }}
    h1 {{ color: var(--accent); margin-bottom: 0.5rem; font-size: 1.5rem; }}
    h2 {{ color: var(--green); margin: 2rem 0 0.75rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); font-size: 1.2rem; }}
    h3 {{ color: var(--orange); margin: 1.5rem 0 0.5rem; font-size: 1.05rem; }}
    h4 {{ color: var(--text); margin: 1rem 0 0.25rem; font-size: 0.95rem; }}
    p {{ margin-bottom: 0.75rem; }}
    .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 0.5rem; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }}
    .badge-et {{ background: #f8514920; color: var(--red); border: 1px solid #f8514940; }}
    .badge-ev {{ background: #d2992220; color: var(--orange); border: 1px solid #d2992240; }}
    .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; margin-bottom: 1.5rem; }}
    .section-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }}
    .paste-label {{ color: var(--orange); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    pre {{ background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 1rem; overflow-x: auto;
           font-size: 0.8rem; line-height: 1.5; white-space: pre-wrap; word-break: break-all; }}
    code {{ font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: 0.85rem; }}
    th {{ text-align: left; padding: 0.5rem; background: var(--bg); color: var(--muted); border-bottom: 1px solid var(--border); }}
    td {{ padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
    tr:hover td {{ background: #1c2128; }}
    .query-block {{ margin-bottom: 1.5rem; }}
    .query-block h4 {{ margin-bottom: 0.25rem; }}
    ul {{ padding-left: 1.5rem; margin-bottom: 0.75rem; }}
    li {{ margin-bottom: 0.25rem; }}
    .copy-hint {{ color: var(--muted); font-size: 0.75rem; font-style: italic; }}
    .toc {{ list-style: none; padding: 0; }}
    .toc li {{ margin-bottom: 0.35rem; }}
    .toc a {{ color: var(--accent); text-decoration: none; }}
    .toc a:hover {{ text-decoration: underline; }}
    a {{ color: var(--accent); }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin-bottom: 1rem; }}
    .stat {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 0.75rem; text-align: center; }}
    .stat-num {{ font-size: 1.5rem; font-weight: 700; color: var(--accent); }}
    .stat-label {{ font-size: 0.75rem; color: var(--muted); }}
</style>
</head>
<body>

<h1>{e(title)}</h1>
<p class="meta">
    <span class="badge badge-{category.lower()}">{e(category)}</span>
    &nbsp; {e(date)} &nbsp;|&nbsp;
    {"Source: <a href='" + e(source_url) + "' target='_blank'>" + e(source_url[:60]) + "</a> &nbsp;|&nbsp; " if source_url else ""}
    Article ID: {e(article_id)}
</p>

<div class="stats">
    <div class="stat"><div class="stat-num">{total_obs}</div><div class="stat-label">Observables</div></div>
    <div class="stat"><div class="stat-num">{len(stix_indicators)}</div><div class="stat-label">STIX Indicators</div></div>
    <div class="stat"><div class="stat-num">{len(vulnerabilities)}</div><div class="stat-label">Vulnerabilities</div></div>
    <div class="stat"><div class="stat-num">{len(hunt_kql)}</div><div class="stat-label">KQL Queries</div></div>
    <div class="stat"><div class="stat-num">{len(hunt_logscale)}</div><div class="stat-label">LogScale Queries</div></div>
    <div class="stat"><div class="stat-num">{len(bundle["objects"])}</div><div class="stat-label">STIX Objects</div></div>
</div>

<h2>Contents</h2>
<ul class="toc">
    <li><a href="#report">1. Report Description &amp; Metadata</a></li>
    <li><a href="#observables">2. Observables (Blocklists)</a></li>
    {f'<li><a href="#vulnerabilities">3. Vulnerabilities ({len(vulnerabilities)})</a></li>' if vulnerabilities else ""}
    <li><a href="#stix-indicators">{"4" if vulnerabilities else "3"}. STIX IOC Indicators ({len(stix_indicators)})</a></li>
    {f'<li><a href="#kql">KQL Hunt Queries ({len(hunt_kql)})</a></li>' if hunt_kql else ""}
    {f'<li><a href="#logscale">LogScale Hunt Queries ({len(hunt_logscale)})</a></li>' if hunt_logscale else ""}
    <li><a href="#stix-bundle">Full STIX Bundle (JSON)</a></li>
</ul>

<h2 id="report">1. Report Description &amp; Metadata</h2>
<div class="section">
    <div class="section-header">
        <span class="paste-label">OpenCTI &rarr; Analyses &rarr; Reports &rarr; Create</span>
    </div>
    <h3>Metadata</h3>
    <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Name</td><td><code>{e(title)}</code></td></tr>
        <tr><td>Report type</td><td><code>threat-report</code></td></tr>
        <tr><td>Published</td><td><code>{e(date)}T00:00:00.000Z</code></td></tr>
        {f'<tr><td>External reference</td><td><a href="{e(source_url)}">{e(source_url)}</a></td></tr>' if source_url else ""}
        <tr><td>Confidence</td><td><code>75</code> (adjust as appropriate)</td></tr>
        <tr><td>Marking</td><td><code>TLP:CLEAR</code></td></tr>
    </table>
    <h3>Description</h3>
    <p class="copy-hint">Copy into the report description field.</p>
    <pre><code>{e(article_text.strip())}</code></pre>
</div>

<h2 id="observables">2. Observables</h2>
{obs_sections if obs_sections else '<div class="section"><p class="meta">No observables extracted from article.</p></div>'}

{"<h2 id='vulnerabilities'>3. Vulnerabilities</h2>" + '<div class="section"><div class="section-header"><span class="paste-label">Create as Vulnerability objects &amp; add to Report</span></div><table><tr><th>CVE</th></tr>' + vuln_rows + "</table></div>" if vulnerabilities else ""}

<h2 id="stix-indicators">STIX IOC Indicators</h2>
<div class="section">
    <div class="section-header">
        <span class="paste-label">Create as Indicators (pattern_type: stix) &amp; add to Report</span>
    </div>
    {f'<table><tr><th>Name</th><th>STIX Pattern</th></tr>{ioc_rows}</table>' if stix_indicators else '<p class="meta">No STIX IOC indicators extracted.</p>'}
</div>

{"<h2 id='kql'>KQL Hunt Queries (Sentinel / Defender)</h2>" + '<div class="section"><div class="section-header"><span class="paste-label">Create as Indicators (pattern_type: kql) &amp; add to Report</span></div>' + kql_html + "</div>" if hunt_kql else ""}

{"<h2 id='logscale'>LogScale Hunt Queries (NGSIEM / CrowdStrike)</h2>" + '<div class="section"><div class="section-header"><span class="paste-label">Create as Indicators (pattern_type: logscale) &amp; add to Report</span></div>' + logscale_html + "</div>" if hunt_logscale else ""}

<h2 id="stix-bundle">Full STIX Bundle (JSON)</h2>
<div class="section">
    <div class="section-header">
        <span class="paste-label">For bundleCreate automation</span>
    </div>
    <p class="copy-hint">{len(bundle["objects"])} objects. When <code>SOCAI_OPENCTI_PUBLISH=1</code> is enabled,
    <code>post_opencti_report</code> sends this automatically.</p>
    <details>
        <summary style="cursor:pointer; color: var(--accent);">Expand STIX bundle ({len(bundle_json):,} bytes)</summary>
        <pre><code>{e(bundle_json)}</code></pre>
    </details>
</div>

<p class="meta" style="margin-top: 2rem; text-align: center;">
    Generated by socai &mdash; {e(date)}
</p>

</body>
</html>"""

    # Write alongside article
    art_dir = art_path.parent if art_path.exists() else ARTICLES_DIR
    out_path = art_dir / f"opencti_package_{article_id}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")

    return {
        "status": "ok",
        "article_id": article_id,
        "html_path": str(out_path),
        "title": title,
        "observables": total_obs,
        "stix_indicators": len(stix_indicators),
        "vulnerabilities": len(vulnerabilities),
        "kql_queries": len(hunt_kql),
        "logscale_queries": len(hunt_logscale),
        "bundle_objects": len(bundle["objects"]),
    }
