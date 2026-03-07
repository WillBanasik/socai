"""
tool: case_landscape
---------------------
Holistic cross-case intelligence assessment.

Analyses the full case registry, IOC index, link graph, enrichment cache,
and campaign data to produce a structured landscape view:

  - Case statistics (volume, severity, disposition, status)
  - IOC intelligence (most seen, highest risk, cross-case overlap)
  - Link graph analysis (clusters, orphans, duplicates)
  - Targeted entities (repeat victims, most-hit clients)
  - Attack patterns (common tactics, infrastructure reuse)
  - Temporal trends (case velocity, spikes)
  - Gaps and recommendations

Designed for SOC leads and analysts who need to see the big picture
across all investigations — not just one case at a time.

Writes:
  registry/landscape.json  (structured data for dashboards / Zoho sync)

Usage:
    from tools.case_landscape import assess_landscape
    result = assess_landscape()           # full landscape
    result = assess_landscape(days=7)     # last 7 days only
    result = assess_landscape(client="example-client")  # scoped to client
"""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR, CASES_DIR, IOC_INDEX_FILE, REGISTRY_FILE
from tools.common import load_json, log_error, save_json, utcnow

LINKS_INDEX_FILE = BASE_DIR / "registry" / "case_links.json"
CAMPAIGNS_FILE = BASE_DIR / "registry" / "campaigns.json"
LANDSCAPE_FILE = BASE_DIR / "registry" / "landscape.json"


def _load_optional(path: Path) -> dict | list | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "case_landscape.load_optional", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def assess_landscape(
    *,
    days: int | None = None,
    client: str | None = None,
) -> dict:
    """
    Produce a holistic cross-case intelligence assessment.

    Args:
        days: Only include cases from the last N days (None = all time)
        client: Filter to cases matching this client name (substring match on title)

    Returns structured landscape dict with statistics, patterns, and recommendations.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days) if days else None

    # Load data sources
    case_index_data = _load_optional(REGISTRY_FILE) or {}
    case_registry = case_index_data.get("cases", case_index_data)
    ioc_index = _load_optional(IOC_INDEX_FILE) or {}
    links_index = _load_optional(LINKS_INDEX_FILE) or {}
    campaigns = _load_optional(CAMPAIGNS_FILE) or {}

    # Filter cases
    cases: dict[str, dict] = {}
    for cid, cmeta in case_registry.items():
        if cid.startswith("TEST_"):
            continue
        if cutoff:
            created = _parse_ts(cmeta.get("created_at", ""))
            if created and created < cutoff:
                continue
        if client:
            title = (cmeta.get("title", "") or "").lower()
            if client.lower() not in title:
                continue
        cases[cid] = cmeta

    if not cases:
        return {
            "status": "ok",
            "case_count": 0,
            "summary": "No cases found matching the given filters.",
            "ts": utcnow(),
        }

    # -----------------------------------------------------------------------
    # 1. Case statistics
    # -----------------------------------------------------------------------
    severity_counts = Counter(c.get("severity", "unknown") for c in cases.values())
    status_counts = Counter(c.get("status", "unknown") for c in cases.values())
    disposition_counts = Counter(
        c.get("disposition", "undetermined") or "undetermined"
        for c in cases.values()
    )

    # Cases by date (for velocity)
    cases_by_date: Counter = Counter()
    for cmeta in cases.values():
        created = _parse_ts(cmeta.get("created_at", ""))
        if created:
            cases_by_date[created.strftime("%Y-%m-%d")] += 1

    case_stats = {
        "total": len(cases),
        "by_severity": dict(severity_counts.most_common()),
        "by_status": dict(status_counts.most_common()),
        "by_disposition": dict(disposition_counts.most_common()),
        "by_date": dict(sorted(cases_by_date.items())),
    }

    # -----------------------------------------------------------------------
    # 2. IOC intelligence
    # -----------------------------------------------------------------------
    # Filter IOC index to IOCs that appear in our case set
    case_ids = set(cases.keys())
    ioc_stats: dict = {
        "total_indexed": len(ioc_index),
        "malicious": 0,
        "suspicious": 0,
        "clean": 0,
    }
    # IOCs appearing in most cases
    ioc_case_counts: list[tuple[str, int, str, str]] = []  # (ioc, case_count, type, verdict)
    # Most dangerous IOCs (malicious + multi-case)
    high_risk_iocs: list[dict] = []

    for ioc_val, entry in ioc_index.items():
        verdict = entry.get("verdict", "unknown").lower()
        if verdict == "malicious":
            ioc_stats["malicious"] += 1
        elif verdict == "suspicious":
            ioc_stats["suspicious"] += 1
        elif verdict == "clean":
            ioc_stats["clean"] += 1

        ioc_cases = set(entry.get("cases", []))
        overlap = ioc_cases & case_ids
        if overlap:
            ioc_case_counts.append((
                ioc_val,
                len(overlap),
                entry.get("ioc_type", "unknown"),
                verdict,
            ))
            if verdict in ("malicious", "suspicious") and len(overlap) >= 2:
                high_risk_iocs.append({
                    "ioc": ioc_val,
                    "type": entry.get("ioc_type", "unknown"),
                    "verdict": verdict,
                    "case_count": len(overlap),
                    "cases": sorted(overlap),
                })

    # Sort by case count descending
    ioc_case_counts.sort(key=lambda x: x[1], reverse=True)
    high_risk_iocs.sort(key=lambda x: x["case_count"], reverse=True)

    ioc_intelligence = {
        **ioc_stats,
        "most_seen": [
            {"ioc": i[0], "case_count": i[1], "type": i[2], "verdict": i[3]}
            for i in ioc_case_counts[:15]
        ],
        "high_risk_cross_case": high_risk_iocs[:10],
    }

    # -----------------------------------------------------------------------
    # 3. Link graph analysis
    # -----------------------------------------------------------------------
    linked_cases = set(links_index.keys()) & case_ids
    orphan_cases = case_ids - set(links_index.keys())
    duplicate_cases = {
        cid for cid, cmeta in cases.items()
        if cmeta.get("status") == "duplicate"
    }

    # Build clusters from link graph
    visited: set[str] = set()
    clusters: list[list[str]] = []
    for cid in linked_cases:
        if cid in visited:
            continue
        # BFS to find cluster
        cluster: list[str] = []
        queue = [cid]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            if current in case_ids:
                cluster.append(current)
            for entry in links_index.get(current, []):
                linked = entry["case_id"]
                if linked not in visited:
                    queue.append(linked)
        if len(cluster) >= 2:
            clusters.append(sorted(cluster))

    link_analysis = {
        "linked_cases": len(linked_cases),
        "orphan_cases": len(orphan_cases),
        "duplicate_cases": len(duplicate_cases),
        "clusters": [
            {"cases": c, "size": len(c)}
            for c in sorted(clusters, key=len, reverse=True)
        ],
        "orphan_ids": sorted(orphan_cases)[:20],
    }

    # -----------------------------------------------------------------------
    # 4. Targeted entities
    # -----------------------------------------------------------------------
    # Extract email targets from IOC index
    target_emails: Counter = Counter()
    target_domains: Counter = Counter()

    for ioc_val, entry in ioc_index.items():
        ioc_type = entry.get("ioc_type", "")
        ioc_cases = set(entry.get("cases", []))
        overlap = ioc_cases & case_ids
        if not overlap:
            continue
        if ioc_type == "email" and "@" in ioc_val:
            target_emails[ioc_val] += len(overlap)
            domain = ioc_val.split("@")[1].lower()
            target_domains[domain] += len(overlap)

    # Also scan case titles for client/org patterns
    title_words: Counter = Counter()
    for cmeta in cases.values():
        title = cmeta.get("title", "")
        # Extract likely org/client names (capitalised words, domain-like)
        for word in title.split():
            clean = word.strip("—–-(),.:;\"'")
            if len(clean) > 3 and clean[0].isupper():
                title_words[clean] += 1

    targeted_entities = {
        "repeat_targets": [
            {"email": e, "case_count": c}
            for e, c in target_emails.most_common(10) if c >= 2
        ],
        "targeted_domains": [
            {"domain": d, "case_count": c}
            for d, c in target_domains.most_common(10) if c >= 2
        ],
    }

    # -----------------------------------------------------------------------
    # 5. Attack patterns
    # -----------------------------------------------------------------------
    # IOC type distribution across cases
    ioc_type_counts: Counter = Counter()
    for entry in ioc_index.values():
        ioc_cases = set(entry.get("cases", []))
        if ioc_cases & case_ids:
            ioc_type_counts[entry.get("ioc_type", "unknown")] += 1

    # Verdict distribution
    verdict_counts: Counter = Counter()
    for entry in ioc_index.values():
        ioc_cases = set(entry.get("cases", []))
        if ioc_cases & case_ids:
            verdict_counts[entry.get("verdict", "unknown")] += 1

    attack_patterns = {
        "ioc_type_distribution": dict(ioc_type_counts.most_common()),
        "verdict_distribution": dict(verdict_counts.most_common()),
        "active_campaigns": len(campaigns.get("campaigns", [])) if isinstance(campaigns, dict) else 0,
    }

    # -----------------------------------------------------------------------
    # 6. Recommendations
    # -----------------------------------------------------------------------
    recommendations: list[str] = []

    # Unlinked cases that share IOCs
    unlinked_overlaps: list[dict] = []
    for ioc_info in high_risk_iocs:
        ioc_cases_set = set(ioc_info["cases"])
        for cid in ioc_cases_set:
            linked_to = {e["case_id"] for e in links_index.get(cid, [])}
            unlinked = ioc_cases_set - linked_to - {cid}
            if unlinked:
                unlinked_overlaps.append({
                    "ioc": ioc_info["ioc"],
                    "case": cid,
                    "should_link_to": sorted(unlinked),
                })

    if unlinked_overlaps:
        recommendations.append(
            f"{len(unlinked_overlaps)} case pair(s) share malicious/suspicious IOCs but are not linked. "
            f"Consider running link_cases or merge_cases."
        )

    if link_analysis["duplicate_cases"] > 0:
        recommendations.append(
            f"{link_analysis['duplicate_cases']} case(s) marked as duplicate. "
            f"Consider merging artefacts into canonical cases."
        )

    open_high = sum(
        1 for c in cases.values()
        if c.get("severity") in ("high", "critical") and c.get("status") == "open"
    )
    if open_high > 0:
        recommendations.append(
            f"{open_high} high/critical case(s) still open — prioritise for closure."
        )

    if len(orphan_cases) > len(cases) * 0.5:
        recommendations.append(
            f"{len(orphan_cases)}/{len(cases)} cases have no links. "
            f"Run campaign_cluster to identify shared infrastructure."
        )

    # -----------------------------------------------------------------------
    # 7. Build human-readable summary
    # -----------------------------------------------------------------------
    lines: list[str] = []
    period = f"last {days} days" if days else "all time"
    scope = f" (client: {client})" if client else ""
    lines.append(f"## Case Landscape — {period}{scope}\n")

    lines.append(f"**{case_stats['total']} cases** | "
                 f"{case_stats['by_severity'].get('critical', 0)} critical, "
                 f"{case_stats['by_severity'].get('high', 0)} high, "
                 f"{case_stats['by_severity'].get('medium', 0)} medium, "
                 f"{case_stats['by_severity'].get('low', 0)} low\n")

    lines.append(f"**Status:** {', '.join(f'{v} {k}' for k, v in case_stats['by_status'].items())}")
    lines.append(f"**Dispositions:** {', '.join(f'{v} {k}' for k, v in case_stats['by_disposition'].items())}\n")

    if ioc_intelligence["high_risk_cross_case"]:
        lines.append("### High-Risk IOCs (cross-case)")
        for hr in ioc_intelligence["high_risk_cross_case"][:5]:
            lines.append(f"- `{hr['ioc']}` ({hr['type']}) — {hr['verdict'].upper()}, "
                         f"seen in {hr['case_count']} cases: {', '.join(hr['cases'])}")
        lines.append("")

    if link_analysis["clusters"]:
        lines.append(f"### Case Clusters ({len(link_analysis['clusters'])})")
        for cl in link_analysis["clusters"][:5]:
            lines.append(f"- {', '.join(cl['cases'])} ({cl['size']} cases)")
        lines.append("")

    if targeted_entities["repeat_targets"]:
        lines.append("### Repeat Targets")
        for rt in targeted_entities["repeat_targets"][:5]:
            lines.append(f"- `{rt['email']}` — {rt['case_count']} cases")
        lines.append("")

    if unlinked_overlaps:
        lines.append("### Suggested Links")
        seen_pairs: set[frozenset] = set()
        for uo in unlinked_overlaps[:5]:
            for tgt in uo["should_link_to"]:
                pair = frozenset({uo["case"], tgt})
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    lines.append(f"- **{uo['case']}** ↔ **{tgt}** (shared IOC: `{uo['ioc']}`)")
        lines.append("")

    if recommendations:
        lines.append("### Recommendations")
        for r in recommendations:
            lines.append(f"- {r}")
        lines.append("")

    summary = "\n".join(lines)

    # -----------------------------------------------------------------------
    # Persist and return
    # -----------------------------------------------------------------------
    result = {
        "status": "ok",
        "case_count": len(cases),
        "period": period,
        "client_filter": client,
        "case_stats": case_stats,
        "ioc_intelligence": ioc_intelligence,
        "link_analysis": link_analysis,
        "targeted_entities": targeted_entities,
        "attack_patterns": attack_patterns,
        "unlinked_overlaps": unlinked_overlaps[:20],
        "recommendations": recommendations,
        "summary": summary,
        "ts": utcnow(),
    }

    save_json(LANDSCAPE_FILE, result)
    return result
