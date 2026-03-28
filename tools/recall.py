"""
tool: recall
-------------
Search prior cases and cached intelligence for what is already known about
given IOCs, email addresses, or keywords.

Philosophy: Recall → Assess → Investigate
  1. Known knowns  — what we already have (prior cases, cached enrichments)
  2. Known unknowns — gaps identified from what we have
  3. Unknown unknowns — only then go searching (KQL, enrichment APIs)

Returns a structured summary of prior intelligence so the analyst (or LLM)
can decide whether a fresh investigation is actually needed.

Usage:
    from tools.recall import recall

    result = recall(
        iocs=["gamblingprice.com", "154.119.71.68"],
        emails=["user@example.com"],
        keywords=["keyword"],
    )
"""
from __future__ import annotations

import json
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import (
    CASES_DIR, ENRICH_CACHE_FILE, ENRICH_CACHE_TTL, IOC_INDEX_FILE, REGISTRY_FILE,
)
from tools.common import load_json, log_error
from tools.ioc_classify import TIER_CLIENT, TIER_GLOBAL, get_case_client

# Max artefact text to include per case to avoid blowing up context
_MAX_REPORT_CHARS = 6000
_MAX_CASES = 5


def _load_optional(path: Path) -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "recall.load_optional", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _extract_domains(urls: list[str]) -> list[str]:
    """Pull domains from URLs for IOC index lookup."""
    domains: set[str] = set()
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
            host = parsed.hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass
    return list(domains)


def recall(
    *,
    iocs: list[str] | None = None,
    emails: list[str] | None = None,
    keywords: list[str] | None = None,
    caller_client: str = "",
) -> dict:
    """
    Search prior cases and intelligence for what is already known.

    Args:
        iocs: IOC values to look up (IPs, domains, URLs, hashes)
        emails: Email addresses to search for in IOC index and case titles
        keywords: Free-text keywords to match against case titles
        caller_client: Lowercase client name of the caller.  When set,
            enforces the data hierarchy:
              - **Global IOCs** (public IPs, domains, hashes, CVEs): cross-
                client matches are returned, but case details (findings,
                reports) are redacted for other clients' cases.
              - **Client-scoped IOCs** (private IPs, bare hostnames): only
                same-client case matches are returned.
              - **Case details** (findings, report excerpts, timeline): only
                returned for same-client cases.

    Returns:
        {
            "status": "ok",
            "matches": int,
            "prior_cases": [...],      # matched cases with summaries
            "known_iocs": [...],       # IOCs found in index with verdicts
            "cached_enrichments": [...], # IOCs with fresh cache hits
            "gaps": [...],             # searched terms with no prior data
            "summary": str,            # human-readable summary
        }
    """
    iocs = iocs or []
    emails = emails or []
    keywords = keywords or []
    caller_client = caller_client.strip().lower()

    # Normalise: extract domains from any URLs in the IOC list
    url_domains = _extract_domains([i for i in iocs if "/" in i or "." in i])
    all_search_iocs = list(set(iocs + url_domains + emails))

    # Load intelligence sources
    ioc_index = _load_optional(IOC_INDEX_FILE) or {}
    case_index_data = _load_optional(REGISTRY_FILE) or {}
    case_registry = case_index_data.get("cases", case_index_data)
    enrich_cache = _load_optional(ENRICH_CACHE_FILE) or {}

    # --- 1. IOC index lookup (tier-aware) ---
    known_iocs: list[dict] = []
    matched_case_ids: set[str] = set()

    for ioc in all_search_iocs:
        entry = ioc_index.get(ioc)
        if entry:
            tier = entry.get("tier", TIER_GLOBAL)
            cases = entry.get("cases", [])
            case_clients = entry.get("case_clients", {})

            # Apply tier filtering when caller_client is set
            if caller_client:
                if tier == TIER_CLIENT:
                    # Client-scoped: only show cases belonging to same client
                    cases = [
                        c for c in cases
                        if case_clients.get(c, get_case_client(c)) == caller_client
                    ]
                    if not cases:
                        continue  # no same-client matches for this IOC
                # Global tier: all cases visible (but detail redaction happens later)

            matched_case_ids.update(cases)
            known_iocs.append({
                "ioc": ioc,
                "type": entry.get("ioc_type", "unknown"),
                "tier": tier,
                "verdict": entry.get("verdict", "unknown"),
                "malicious": entry.get("malicious", 0),
                "suspicious": entry.get("suspicious", 0),
                "clean": entry.get("clean", 0),
                "first_seen": entry.get("first_seen", ""),
                "last_seen": entry.get("last_seen", ""),
                "cases": cases,
            })

    # --- 2. Keyword / email search in case titles ---
    search_terms = [k.lower() for k in keywords + emails if k]
    for cid, cmeta in case_registry.items():
        if cid.startswith("TEST_"):
            continue
        title = (cmeta.get("title", "") or "").lower()
        for term in search_terms:
            if term in title:
                matched_case_ids.add(cid)
                break

    # --- 3. Enrichment cache lookup ---
    cached_enrichments: list[dict] = []
    cache_ttl = timedelta(hours=ENRICH_CACHE_TTL) if ENRICH_CACHE_TTL > 0 else None
    now = datetime.now(timezone.utc)

    for ioc in all_search_iocs:
        providers_hit: list[str] = []
        for cache_key, cached in enrich_cache.items():
            if not cache_key.endswith(f"|{ioc}"):
                continue
            if cached.get("status") != "ok":
                continue
            if cache_ttl:
                try:
                    cached_ts = datetime.fromisoformat(
                        cached.get("cached_at", "2000-01-01T00:00:00Z").replace("Z", "+00:00")
                    )
                    if now - cached_ts > cache_ttl:
                        continue
                except Exception:
                    continue
            provider = cache_key.split("|")[0] if "|" in cache_key else "unknown"
            providers_hit.append(provider)
        if providers_hit:
            cached_enrichments.append({
                "ioc": ioc,
                "providers": providers_hit,
                "provider_count": len(providers_hit),
            })

    # --- 4. Build case summaries for matched cases ---
    prior_cases: list[dict] = []
    # Sort by most recent first
    sorted_case_ids = sorted(
        matched_case_ids,
        key=lambda cid: case_registry.get(cid, {}).get("created_at", ""),
        reverse=True,
    )

    for cid in sorted_case_ids[:_MAX_CASES]:
        cmeta = case_registry.get(cid, {})
        case_dir = CASES_DIR / cid

        # Determine if this case belongs to the same client as the caller.
        # Cross-client cases get a redacted summary (IOC overlap + verdict
        # only) to prevent leaking internal investigation detail.
        case_client = get_case_client(cid)
        same_client = (
            not caller_client              # no boundary set — show everything
            or not case_client             # case has no client — show everything
            or case_client == caller_client
        )

        if same_client:
            # ── Full detail: same-client or no boundary ──────────────
            case_summary: dict = {
                "case_id": cid,
                "title": cmeta.get("title", "Unknown"),
                "severity": cmeta.get("severity", "unknown"),
                "status": cmeta.get("status", "unknown"),
                "created_at": cmeta.get("created_at", ""),
                "disposition": cmeta.get("disposition", ""),
            }

            # Load links and external refs
            meta_full = _load_optional(case_dir / "case_meta.json")
            if meta_full:
                links = meta_full.get("links", [])
                if links:
                    case_summary["links"] = links
                ext_refs = meta_full.get("external_refs", {})
                if ext_refs:
                    case_summary["external_refs"] = ext_refs
                if meta_full.get("canonical_case"):
                    case_summary["canonical_case"] = meta_full["canonical_case"]

            # Load IOCs
            iocs_data = _load_optional(case_dir / "iocs" / "iocs.json")
            if iocs_data:
                ioc_dict = iocs_data.get("iocs", {})
                case_summary["iocs"] = {
                    t: vals[:20] for t, vals in ioc_dict.items() if vals
                }

            # Load verdict summary
            verdict = _load_optional(
                case_dir / "artefacts" / "enrichment" / "verdict_summary.json"
            )
            if verdict:
                case_summary["verdicts"] = {
                    "malicious": verdict.get("high_priority", []),
                    "suspicious": verdict.get("needs_review", []),
                    "clean_count": len(verdict.get("clean", [])),
                }

            # Load findings from session context
            session_ctx = _load_optional(case_dir / "session_context.json")
            if session_ctx:
                findings = session_ctx.get("findings", [])
                if findings:
                    case_summary["findings"] = [
                        {"type": f.get("type", "?"), "summary": f.get("summary", "")}
                        for f in findings[:10]
                    ]

            # Load MDR report if available (prefer over pipeline report)
            mdr_path = case_dir / "reports" / "mdr_report.md"
            report_path = case_dir / "reports" / "investigation_report.md"
            rpath = mdr_path if mdr_path.exists() else (report_path if report_path.exists() else None)
            if rpath:
                try:
                    text = rpath.read_text(encoding="utf-8", errors="replace")
                    if len(text) > _MAX_REPORT_CHARS:
                        text = text[:_MAX_REPORT_CHARS] + "\n\n[...truncated...]"
                    case_summary["report_excerpt"] = text
                except Exception:
                    pass
        else:
            # ── Redacted: cross-client case ──────────────────────────
            # Only expose that an IOC overlap exists + verdict.  No title,
            # no findings, no report content, no internal references.
            case_summary = {
                "case_id": cid,
                "cross_client": True,
                "severity": cmeta.get("severity", "unknown"),
                "created_at": cmeta.get("created_at", ""),
                "disposition": cmeta.get("disposition", ""),
                "note": "Cross-client match — case details restricted.",
            }
            # Show only which searched IOCs matched this case
            if ioc_index:
                overlapping = []
                for ioc in all_search_iocs:
                    idx_entry = ioc_index.get(ioc, {})
                    if cid in idx_entry.get("cases", []):
                        overlapping.append({
                            "ioc": ioc,
                            "verdict": idx_entry.get("verdict", "unknown"),
                        })
                if overlapping:
                    case_summary["matched_iocs"] = overlapping

        prior_cases.append(case_summary)

    # --- 5. Identify gaps ---
    found_iocs = {ki["ioc"] for ki in known_iocs}
    found_cached = {ce["ioc"] for ce in cached_enrichments}
    gaps = [
        ioc for ioc in all_search_iocs
        if ioc not in found_iocs and ioc not in found_cached
    ]

    # --- 6. Build human-readable summary ---
    lines: list[str] = []
    same_client_cases = [pc for pc in prior_cases if not pc.get("cross_client")]
    cross_client_cases = [pc for pc in prior_cases if pc.get("cross_client")]

    if prior_cases:
        lines.append(f"**{len(prior_cases)} prior case(s) found** matching your search:")
        if cross_client_cases:
            lines.append(
                f"  ({len(cross_client_cases)} cross-client — details restricted, "
                f"IOC overlap only)"
            )
        for pc in prior_cases:
            if pc.get("cross_client"):
                matched = pc.get("matched_iocs", [])
                ioc_str = ", ".join(f"{m['ioc']} ({m['verdict']})" for m in matched[:5])
                lines.append(
                    f"- **{pc['case_id']}** — [cross-client] "
                    f"[{pc['severity'].upper()}] ({pc.get('disposition', '?')})"
                )
                if ioc_str:
                    lines.append(f"  Shared IOCs: {ioc_str}")
            else:
                lines.append(f"- **{pc['case_id']}** — {pc.get('title', '?')} [{pc['severity'].upper()}] ({pc.get('status', '?')})")
                if pc.get("verdicts"):
                    v = pc["verdicts"]
                    mal = v.get("malicious", [])
                    sus = v.get("suspicious", [])
                    if mal:
                        lines.append(f"  Malicious IOCs: {', '.join(mal[:5])}")
                    if sus:
                        lines.append(f"  Suspicious IOCs: {', '.join(sus[:5])}")
                if pc.get("findings"):
                    for f in pc["findings"][:3]:
                        lines.append(f"  Finding: [{f['type']}] {f['summary']}")
                if pc.get("links"):
                    linked_ids = [l["case_id"] for l in pc["links"]]
                    lines.append(f"  Linked to: {', '.join(linked_ids)}")
                if pc.get("canonical_case"):
                    lines.append(f"  **DUPLICATE** of canonical case {pc['canonical_case']}")
                if pc.get("external_refs"):
                    refs = [f"{k}={v}" for k, v in pc["external_refs"].items()]
                    lines.append(f"  External refs: {', '.join(refs)}")
    else:
        lines.append("No prior cases found matching these search terms.")

    if known_iocs:
        lines.append(f"\n**{len(known_iocs)} IOC(s) already in intelligence index:**")
        for ki in known_iocs:
            lines.append(f"- `{ki['ioc']}` — {ki['verdict'].upper()} (seen in {', '.join(ki['cases'][:3])})")

    if cached_enrichments:
        lines.append(f"\n**{len(cached_enrichments)} IOC(s) have cached enrichment data:**")
        for ce in cached_enrichments:
            lines.append(f"- `{ce['ioc']}` — {ce['provider_count']} providers ({', '.join(ce['providers'])})")

    if gaps:
        lines.append(f"\n**{len(gaps)} search term(s) have no prior data** (investigation needed):")
        for g in gaps:
            lines.append(f"- `{g}`")

    summary = "\n".join(lines)

    return {
        "status": "ok",
        "matches": len(prior_cases),
        "prior_cases": prior_cases,
        "known_iocs": known_iocs,
        "cached_enrichments": cached_enrichments,
        "gaps": gaps,
        "summary": summary,
    }
