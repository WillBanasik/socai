"""
tool: log_coverage
------------------
Map client environments by log source — what Sentinel tables are active,
how healthy ingestion is, where visibility gaps exist.

Queries the Sentinel Usage table for each client workspace, maps discovered
tables against a coverage domain reference model, scores overall coverage,
detects gaps and health issues, and generates interactive HTML visualisations.

Writes:
  registry/coverage/{client_key}.json
  registry/coverage/{client_key}_coverage.html

Usage:
    from tools.log_coverage import get_coverage, can_investigate

    cov = get_coverage("performanta")
    result = can_investigate("performanta", "account_compromise")
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import COVERAGE_DIR, BASE_DIR
from tools.common import load_json, log_error, save_json, utcnow


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DOMAINS_FILE = BASE_DIR / "config" / "coverage_domains.json"

_USAGE_QUERY = """\
Usage
| where TimeGenerated > ago(30d)
| summarize
    LastEvent = max(TimeGenerated),
    DailyAvgMB = round(avg(Quantity), 2),
    TotalMB = round(sum(Quantity), 2),
    DaysSeen = dcount(bin(TimeGenerated, 1d))
    by DataType
| extend
    StaleDays = datetime_diff('day', now(), LastEvent),
    IsHealthy = iff(datetime_diff('day', now(), LastEvent) <= 1, true, false)
| order by DataType asc"""

_RETENTION_QUERY = """\
Usage
| where TimeGenerated > ago(365d)
| summarize EarliestEvent = min(TimeGenerated) by DataType
| extend RetentionDays = datetime_diff('day', now(), EarliestEvent)"""

# Max staleness thresholds (days)
_STALE_THRESHOLD = 1
_DEGRADED_THRESHOLD = 7
_DAYS_ACTIVE_HEALTHY = 25
_DAYS_ACTIVE_DEGRADED = 15

# History cap
_MAX_HISTORY = 90

# Attack type → required/helpful coverage domains
ATTACK_COVERAGE: dict[str, dict[str, list[str]]] = {
    "phishing":             {"required": ["email", "identity"],   "helpful": ["endpoint", "cloud_apps"]},
    "account_compromise":   {"required": ["identity"],            "helpful": ["cloud_apps", "email", "endpoint"]},
    "malware":              {"required": ["endpoint"],            "helpful": ["network", "email", "alerts"]},
    "lateral_movement":     {"required": ["endpoint", "identity"], "helpful": ["network"]},
    "privilege_escalation": {"required": ["identity", "endpoint"], "helpful": ["azure_infra"]},
    "data_exfiltration":    {"required": ["endpoint", "network"], "helpful": ["cloud_apps"]},
    "pup_pua":              {"required": ["endpoint"],            "helpful": ["alerts"]},
    "generic":              {"required": ["identity", "endpoint"], "helpful": ["email", "network", "cloud_apps", "alerts"]},
}


def _client_key(client: str) -> str:
    return client.strip().lower().replace(" ", "_")


def _load_domains() -> dict:
    """Load coverage domain reference model."""
    try:
        data = load_json(_DOMAINS_FILE)
        return data.get("domains", {})
    except Exception as exc:
        log_error("", "coverage.load_domains", str(exc), severity="error")
        return {}


def _get_workspace_id(client: str) -> str | None:
    """Resolve Sentinel workspace ID for a client."""
    try:
        from tools.common import get_client_config
        cfg = get_client_config(client)
        if not cfg:
            return None
        return (cfg.get("platforms", {}).get("sentinel", {}).get("workspace_id")
                or cfg.get("workspace_id")
                or None)
    except Exception as exc:
        log_error("", "coverage.get_workspace_id", str(exc),
                  severity="warning", traceback=True, context={"client": client})
        return None


def _classify_health(stale_days: int, days_active: int) -> str:
    """Classify a log source's health status."""
    if stale_days <= _STALE_THRESHOLD and days_active >= _DAYS_ACTIVE_HEALTHY:
        return "healthy"
    if stale_days <= _DEGRADED_THRESHOLD:
        return "stale"
    if stale_days <= 30:
        return "degraded"
    return "dead"


def _health_weight(health: str) -> float:
    """Numeric weight for scoring: healthy=1.0, stale=0.5, degraded/dead=0.0."""
    return {"healthy": 1.0, "stale": 0.5, "degraded": 0.0, "dead": 0.0}.get(health, 0.0)


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def collect_log_sources(client: str, *, full: bool = False) -> dict:
    """
    Discover log sources for a client by querying Sentinel Usage table.

    Args:
        client: Client name (case-insensitive).
        full:   If True, also run the 365-day retention query (slower).

    Returns:
        {"status": "ok", "client": str, "source_count": int, "path": str}
    """
    if not client.strip():
        return {"status": "error", "reason": "client name required"}

    workspace_id = _get_workspace_id(client)
    if not workspace_id:
        return {"status": "error", "reason": f"No Sentinel workspace found for client '{client}'"}

    # Import here to avoid circular dependency at module level
    from scripts.run_kql import run_kql

    rows = run_kql(workspace_id, _USAGE_QUERY, timeout=120, skip_validation=True)
    if not rows:
        return {"status": "error", "reason": "Usage query returned no data — check workspace connectivity and az login"}

    # Parse retention data if full mode
    retention_map: dict[str, int] = {}
    if full:
        ret_rows = run_kql(workspace_id, _RETENTION_QUERY, timeout=300, skip_validation=True)
        for row in ret_rows:
            table = row.get("DataType", "")
            days = row.get("RetentionDays")
            if table and days is not None:
                try:
                    retention_map[table] = int(float(days))
                except (ValueError, TypeError):
                    pass

    # Build source metadata
    sources = []
    for row in rows:
        table = row.get("DataType", "").strip()
        if not table:
            continue

        stale_days = 0
        try:
            stale_days = int(float(row.get("StaleDays", 0)))
        except (ValueError, TypeError):
            pass

        days_active = 0
        try:
            days_active = int(float(row.get("DaysSeen", 0)))
        except (ValueError, TypeError):
            pass

        sources.append({
            "table": table,
            "platform": "sentinel",
            "workspace_id": workspace_id,
            "last_event": row.get("LastEvent", ""),
            "daily_avg_mb": _safe_float(row.get("DailyAvgMB")),
            "total_mb_30d": _safe_float(row.get("TotalMB")),
            "days_active_30d": days_active,
            "stale_days": stale_days,
            "retention_days": retention_map.get(table),
            "health": _classify_health(stale_days, days_active),
        })

    # Check workspace_tables.json for tables that should exist but have no Usage data
    try:
        from config.sentinel_schema import get_workspace_tables, resolve_workspace_code
        code = resolve_workspace_code(workspace_id)
        if code:
            ws_tables = get_workspace_tables(code)
            active_tables = {s["table"] for s in sources}
            for table in sorted(ws_tables - active_tables):
                sources.append({
                    "table": table,
                    "platform": "sentinel",
                    "workspace_id": workspace_id,
                    "last_event": None,
                    "daily_avg_mb": 0.0,
                    "total_mb_30d": 0.0,
                    "days_active_30d": 0,
                    "stale_days": 999,
                    "retention_days": None,
                    "health": "dead",
                })
    except Exception as exc:
        log_error("", "coverage.collect.workspace_tables", str(exc),
                  severity="info", traceback=True, context={"client": client})
        pass  # Non-critical — workspace_tables may not exist

    # Save raw sources
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    ck = _client_key(client)
    out_path = COVERAGE_DIR / f"{ck}.json"

    # Preserve history from existing file
    history = []
    if out_path.exists():
        try:
            existing = load_json(out_path)
            history = existing.get("history", [])
        except Exception as exc:
            log_error("", "coverage.collect.load_existing", str(exc),
                      severity="warning", traceback=True, context={"path": str(out_path)})
            pass

    data = {
        "client": ck,
        "collected_at": utcnow(),
        "workspace_id": workspace_id,
        "source_count": len(sources),
        "sources": sources,
        "graph": {},
        "scores": {},
        "gaps": [],
        "history": history,
    }

    save_json(out_path, data)

    # Build coverage graph on top of collected sources
    build_result = build_coverage_graph(client)
    if build_result.get("status") != "ok":
        return build_result

    return {
        "status": "ok",
        "client": client,
        "source_count": len(sources),
        "path": str(out_path),
    }


def _safe_float(val, default: float = 0.0) -> float:
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Graph building & scoring
# ---------------------------------------------------------------------------

def build_coverage_graph(client: str) -> dict:
    """
    Build coverage graph from collected sources + reference model.

    Reads sources from registry/coverage/{client}.json, maps against
    coverage_domains.json, computes scores and gaps.

    Returns:
        {"status": "ok", "client": str, "overall_score": float,
         "gaps": list, "health_issues": list, "path": str}
    """
    ck = _client_key(client)
    cov_path = COVERAGE_DIR / f"{ck}.json"

    if not cov_path.exists():
        return {"status": "error", "reason": f"No coverage data for '{client}' — run collect_log_sources first"}

    data = load_json(cov_path)
    sources = data.get("sources", [])
    domains = _load_domains()

    if not domains:
        return {"status": "error", "reason": "Coverage domains reference model not found"}

    # Build lookup: table -> source metadata
    source_map: dict[str, dict] = {}
    for s in sources:
        source_map[s["table"]] = s

    # Build graph nodes and edges
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    domain_scores: dict[str, float] = {}
    gaps: list[dict] = []
    health_issues: list[dict] = []

    total_healthy = 0
    total_stale = 0
    total_degraded = 0
    total_dead = 0

    for s in sources:
        h = s.get("health", "dead")
        if h == "healthy":
            total_healthy += 1
        elif h == "stale":
            total_stale += 1
        elif h == "degraded":
            total_degraded += 1
        else:
            total_dead += 1

        nodes[f"src:{s['table']}"] = {
            "type": "log_source",
            "label": s["table"],
            "health": h,
            "daily_avg_mb": s.get("daily_avg_mb", 0),
            "last_event": s.get("last_event"),
            "stale_days": s.get("stale_days", 0),
        }

    for domain_key, domain_def in domains.items():
        required_tables = domain_def.get("required_tables", [])
        enhanced_tables = domain_def.get("enhanced_tables", [])
        weight = domain_def.get("weight", 1.0)

        req_present = 0.0
        enh_present = 0.0

        # Score required tables
        for table in required_tables:
            src = source_map.get(table)
            if src:
                hw = _health_weight(src.get("health", "dead"))
                req_present += hw
                edges.append({"from": f"src:{table}", "to": f"domain:{domain_key}", "type": "covers"})

                # Flag health issues for required tables
                h = src.get("health", "dead")
                if h in ("stale", "degraded"):
                    health_issues.append({
                        "type": h,
                        "domain": domain_key,
                        "table": table,
                        "last_event": src.get("last_event"),
                        "stale_days": src.get("stale_days", 0),
                        "severity": "critical" if h == "degraded" else "high",
                        "impact": f"{table} is {h} ({src.get('stale_days', '?')}d since last event). "
                                  f"Required for {domain_def.get('label', domain_key)} coverage.",
                        "recommendation": f"Check connector health for {table}.",
                    })
            else:
                gaps.append({
                    "type": "missing_required",
                    "domain": domain_key,
                    "table": table,
                    "severity": "high",
                    "impact": domain_def.get("gap_impact", f"No {table} data."),
                    "recommendation": f"Onboard {table} to gain {domain_def.get('label', domain_key)} visibility.",
                })

        # Score enhanced tables
        for table in enhanced_tables:
            src = source_map.get(table)
            if src:
                hw = _health_weight(src.get("health", "dead"))
                enh_present += hw
                edges.append({"from": f"src:{table}", "to": f"domain:{domain_key}", "type": "covers"})
            else:
                gaps.append({
                    "type": "missing_enhanced",
                    "domain": domain_key,
                    "table": table,
                    "severity": "medium",
                    "impact": f"Missing {table} — reduced depth in {domain_def.get('label', domain_key)}.",
                    "recommendation": f"Consider onboarding {table} for deeper {domain_def.get('label', domain_key)} telemetry.",
                })

        # Calculate domain score
        req_total = len(required_tables) or 1
        enh_total = len(enhanced_tables) or 1
        score = (req_present / req_total) * 0.7 + (enh_present / enh_total) * 0.3
        domain_scores[domain_key] = round(score, 3)

        nodes[f"domain:{domain_key}"] = {
            "type": "coverage_domain",
            "label": domain_def.get("label", domain_key),
            "score": domain_scores[domain_key],
            "weight": weight,
            "required_present": round(req_present, 1),
            "required_total": len(required_tables),
            "enhanced_present": round(enh_present, 1),
            "enhanced_total": len(enhanced_tables),
        }

    # Overall weighted score
    total_weight = sum(domains[d].get("weight", 1.0) for d in domains)
    overall = sum(domain_scores.get(d, 0) * domains[d].get("weight", 1.0) for d in domains)
    overall_score = round(overall / total_weight, 3) if total_weight else 0.0

    # Sort gaps by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    gaps.sort(key=lambda g: sev_order.get(g.get("severity", "low"), 99))
    health_issues.sort(key=lambda h: sev_order.get(h.get("severity", "low"), 99))

    scores = {
        "overall": overall_score,
        "by_domain": domain_scores,
        "healthy_sources": total_healthy,
        "stale_sources": total_stale,
        "degraded_sources": total_degraded,
        "dead_sources": total_dead,
        "total_sources": len(sources),
    }

    graph = {"nodes": nodes, "edges": edges}

    # Update history
    history = data.get("history", [])
    history.append({
        "collected_at": data.get("collected_at", utcnow()),
        "overall": overall_score,
        "healthy_sources": total_healthy,
        "total_sources": len(sources),
        "by_domain": dict(domain_scores),
    })
    if len(history) > _MAX_HISTORY:
        history = history[-_MAX_HISTORY:]

    # Save
    data["graph"] = graph
    data["scores"] = scores
    data["gaps"] = gaps
    data["health_issues"] = health_issues
    data["history"] = history

    out_path = COVERAGE_DIR / f"{ck}.json"
    save_json(out_path, data)

    return {
        "status": "ok",
        "client": client,
        "overall_score": overall_score,
        "gap_count": len(gaps),
        "health_issue_count": len(health_issues),
        "path": str(out_path),
    }


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------

def get_coverage(client: str) -> dict:
    """
    Return full coverage data for a client. Auto-collects if missing or stale (>24h).
    """
    ck = _client_key(client)
    cov_path = COVERAGE_DIR / f"{ck}.json"

    if cov_path.exists():
        try:
            data = load_json(cov_path)
            collected_at = data.get("collected_at", "")
            if collected_at:
                from datetime import datetime, timezone
                ts = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
                age_hours = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
                if age_hours < 24:
                    return data
        except Exception as exc:
            log_error("", "coverage.get_coverage.load_cached", str(exc),
                      severity="warning", traceback=True, context={"client": client, "path": str(cov_path)})
            pass

    # Auto-collect
    result = collect_log_sources(client)
    if result.get("status") != "ok":
        return result

    try:
        return load_json(cov_path)
    except Exception as exc:
        log_error("", "coverage.get_coverage.load_json", str(exc),
                  severity="error", traceback=True, context={"client": client, "path": str(cov_path)})
        return {"status": "error", "reason": str(exc)}


def check_gaps(client: str) -> list[dict]:
    """Return coverage gaps for a client."""
    cov = get_coverage(client)
    if isinstance(cov, dict) and "gaps" in cov:
        return cov["gaps"]
    return []


def check_source_health(client: str) -> list[dict]:
    """Return health issues (stale/degraded sources) for a client."""
    cov = get_coverage(client)
    if isinstance(cov, dict) and "health_issues" in cov:
        return cov["health_issues"]
    return []


def can_investigate(client: str, attack_type: str) -> dict:
    """
    Check whether we have sufficient log coverage to investigate a given
    attack type for this client.

    Args:
        client:      Client name.
        attack_type: One of ATTACK_TYPES from classify_attack.py.

    Returns:
        {
            "can_investigate": bool,
            "coverage_level": "full" | "partial" | "minimal" | "none",
            "required_domains": [...],
            "available_domains": [...],
            "missing_domains": [...],
            "helpful_domains": [...],
            "available_helpful": [...],
            "limitations": [str],
        }
    """
    cov = get_coverage(client)
    if not isinstance(cov, dict) or "scores" not in cov:
        return {
            "can_investigate": False,
            "coverage_level": "none",
            "limitations": [cov.get("reason", "Coverage data unavailable")],
        }

    mapping = ATTACK_COVERAGE.get(attack_type, ATTACK_COVERAGE.get("generic", {}))
    required = mapping.get("required", [])
    helpful = mapping.get("helpful", [])
    domain_scores = cov.get("scores", {}).get("by_domain", {})

    available = []
    missing = []
    limitations = []

    for d in required:
        score = domain_scores.get(d, 0)
        if score >= 0.5:
            available.append(d)
        else:
            missing.append(d)
            domains = _load_domains()
            label = domains.get(d, {}).get("label", d)
            impact = domains.get(d, {}).get("gap_impact", f"No {label} visibility.")
            limitations.append(impact)

    available_helpful = [d for d in helpful if domain_scores.get(d, 0) >= 0.5]

    if not missing:
        if len(available_helpful) == len(helpful):
            level = "full"
        else:
            level = "full"  # all required present, some helpful missing is still full
    elif len(available) > 0:
        level = "partial"
    else:
        level = "minimal"

    return {
        "can_investigate": len(missing) == 0,
        "coverage_level": level,
        "attack_type": attack_type,
        "required_domains": required,
        "available_domains": available,
        "missing_domains": missing,
        "helpful_domains": helpful,
        "available_helpful": available_helpful,
        "limitations": limitations,
    }


def compare_clients(*clients: str) -> dict:
    """
    Cross-client coverage comparison.

    Returns:
        {
            "comparison": [{client, overall, by_domain, healthy, total, gaps}],
            "weakest_domains": [(domain, [clients])],
        }
    """
    comparison = []
    domain_weakness: dict[str, list[str]] = {}

    for client in clients:
        cov = get_coverage(client)
        if not isinstance(cov, dict) or "scores" not in cov:
            comparison.append({"client": client, "error": cov.get("reason", "unavailable")})
            continue

        scores = cov["scores"]
        entry = {
            "client": client,
            "overall": scores.get("overall", 0),
            "by_domain": scores.get("by_domain", {}),
            "healthy_sources": scores.get("healthy_sources", 0),
            "total_sources": scores.get("total_sources", 0),
            "gap_count": len(cov.get("gaps", [])),
        }
        comparison.append(entry)

        # Track weak domains (score < 0.5)
        for domain, score in scores.get("by_domain", {}).items():
            if score < 0.5:
                domain_weakness.setdefault(domain, []).append(client)

    # Sort weakest domains by number of affected clients
    weakest = sorted(domain_weakness.items(), key=lambda x: len(x[1]), reverse=True)

    return {
        "status": "ok",
        "comparison": sorted(comparison, key=lambda x: x.get("overall", 0)),
        "weakest_domains": weakest,
    }


# ---------------------------------------------------------------------------
# HTML visualisation
# ---------------------------------------------------------------------------

def generate_coverage_html(client: str) -> dict:
    """
    Generate an interactive HTML coverage visualisation.

    Writes to registry/coverage/{client_key}_coverage.html.

    Returns:
        {"status": "ok", "path": str}
    """
    from tools.common import write_artefact

    cov = get_coverage(client)
    if not isinstance(cov, dict) or "scores" not in cov:
        return {"status": "error", "reason": cov.get("reason", "Coverage data unavailable")}

    ck = _client_key(client)
    html = _render_coverage_html(client, cov)
    out_path = COVERAGE_DIR / f"{ck}_coverage.html"

    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    manifest = write_artefact(out_path, html)
    manifest["html_path"] = str(out_path)

    return {"status": "ok", "path": str(out_path)}


def _render_coverage_html(client: str, cov: dict) -> str:
    """Build self-contained HTML string for coverage report."""
    scores = cov.get("scores", {})
    sources = cov.get("sources", [])
    gaps = cov.get("gaps", [])
    health_issues = cov.get("health_issues", [])
    history = cov.get("history", [])
    domains = _load_domains()
    domain_scores = scores.get("by_domain", {})

    overall = scores.get("overall", 0)
    overall_pct = int(overall * 100)

    # Colour for overall score
    if overall >= 0.75:
        score_colour = "#1e8b4c"
    elif overall >= 0.5:
        score_colour = "#f39c12"
    else:
        score_colour = "#c0392b"

    # Build domain heatmap rows
    heatmap_rows = ""
    for dk, ddef in domains.items():
        ds = domain_scores.get(dk, 0)
        ds_pct = int(ds * 100)
        if ds >= 0.75:
            ds_colour = "#1e8b4c"
        elif ds >= 0.5:
            ds_colour = "#f39c12"
        else:
            ds_colour = "#c0392b"

        # Table cells
        table_cells = ""
        source_map = {s["table"]: s for s in sources}
        for table in ddef.get("required_tables", []):
            src = source_map.get(table)
            if src:
                h = src.get("health", "dead")
                cell_colour = {"healthy": "#1e8b4c", "stale": "#f39c12", "degraded": "#c0392b", "dead": "#c0392b"}.get(h, "#555")
                label = f'{table}<br><span style="font-size:0.75em">{h} ({src.get("stale_days", "?")}d)</span>'
            else:
                cell_colour = "#333"
                label = f'{table}<br><span style="font-size:0.75em">missing</span>'
            table_cells += f'<td style="background:{cell_colour};padding:8px 10px;border-radius:4px;text-align:center;font-size:0.85em;border:1px solid #1e1e1e">{label}</td>'

        for table in ddef.get("enhanced_tables", []):
            src = source_map.get(table)
            if src:
                h = src.get("health", "dead")
                cell_colour = {"healthy": "#1e8b4c88", "stale": "#f39c1288", "degraded": "#c0392b88", "dead": "#c0392b88"}.get(h, "#333")
                label = f'{table}<br><span style="font-size:0.75em">{h}</span>'
            else:
                cell_colour = "#1a1a1a"
                label = f'{table}<br><span style="font-size:0.75em">--</span>'
            table_cells += f'<td style="background:{cell_colour};padding:8px 10px;border-radius:4px;text-align:center;font-size:0.8em;opacity:0.8;border:1px solid #1e1e1e">{label}</td>'

        heatmap_rows += f"""
        <tr>
          <td style="padding:10px;font-weight:bold;white-space:nowrap;vertical-align:top">
            {ddef.get("label", dk)}<br>
            <span style="color:{ds_colour};font-size:0.9em">{ds_pct}%</span>
          </td>
          {table_cells}
        </tr>"""

    # Build gap rows
    gap_rows = ""
    sev_colours = {"critical": "#c0392b", "high": "#e74c3c", "medium": "#f39c12", "low": "#58a6ff"}
    for g in gaps[:30]:
        sev = g.get("severity", "medium")
        gap_rows += f"""
        <tr>
          <td style="color:{sev_colours.get(sev, '#888')};font-weight:bold;text-transform:uppercase;padding:8px">{sev}</td>
          <td style="padding:8px">{g.get('domain', '')}</td>
          <td style="padding:8px;font-family:monospace">{g.get('table', '')}</td>
          <td style="padding:8px">{g.get('type', '').replace('_', ' ')}</td>
          <td style="padding:8px;font-size:0.9em">{g.get('recommendation', '')}</td>
        </tr>"""

    # Build health issue rows
    health_rows = ""
    for hi in health_issues[:20]:
        sev = hi.get("severity", "medium")
        health_rows += f"""
        <tr>
          <td style="color:{sev_colours.get(sev, '#888')};font-weight:bold;text-transform:uppercase;padding:8px">{sev}</td>
          <td style="padding:8px;font-family:monospace">{hi.get('table', '')}</td>
          <td style="padding:8px">{hi.get('type', '')}</td>
          <td style="padding:8px">{hi.get('stale_days', '?')}d</td>
          <td style="padding:8px;font-size:0.9em">{hi.get('impact', '')}</td>
        </tr>"""

    # History data for trend chart (JSON-safe)
    history_json = json.dumps(history[-60:], default=str)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log Source Coverage — {client}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; padding: 20px 30px; }}
  h1 {{ color: #58a6ff; margin-bottom: 8px; font-size: 1.6em; }}
  h2 {{ color: #58a6ff; margin: 30px 0 15px 0; font-size: 1.2em; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
  .meta {{ color: #8b949e; font-size: 0.9em; margin-bottom: 20px; }}
  .scorecard {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
  .score-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 20px; text-align: center; min-width: 140px; }}
  .score-big {{ font-size: 2.5em; font-weight: bold; }}
  .score-label {{ font-size: 0.85em; color: #8b949e; margin-top: 4px; }}
  .heatmap {{ overflow-x: auto; }}
  .heatmap table {{ border-collapse: separate; border-spacing: 4px; }}
  .heatmap th {{ text-align: left; padding: 8px; color: #8b949e; font-size: 0.8em; }}
  .gaps table, .health table {{ width: 100%; border-collapse: collapse; }}
  .gaps th, .health th {{ text-align: left; padding: 8px; color: #8b949e; font-size: 0.85em; border-bottom: 1px solid #21262d; }}
  .gaps tr:hover, .health tr:hover {{ background: #161b22; }}
  .legend {{ display: flex; gap: 15px; margin: 10px 0; font-size: 0.85em; color: #8b949e; }}
  .legend-item {{ display: flex; align-items: center; gap: 5px; }}
  .legend-dot {{ width: 12px; height: 12px; border-radius: 3px; }}
  canvas {{ max-width: 100%; margin: 10px 0; }}
</style>
</head>
<body>

<h1>Log Source Coverage</h1>
<div class="meta">{client} &mdash; collected {cov.get('collected_at', 'unknown')}</div>

<!-- Scorecard -->
<div class="scorecard">
  <div class="score-card">
    <div class="score-big" style="color:{score_colour}">{overall_pct}%</div>
    <div class="score-label">Overall Coverage</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#1e8b4c">{scores.get('healthy_sources', 0)}</div>
    <div class="score-label">Healthy Sources</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#f39c12">{scores.get('stale_sources', 0)}</div>
    <div class="score-label">Stale</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#c0392b">{scores.get('degraded_sources', 0) + scores.get('dead_sources', 0)}</div>
    <div class="score-label">Degraded / Dead</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#8b949e">{scores.get('total_sources', 0)}</div>
    <div class="score-label">Total Sources</div>
  </div>
</div>

<!-- Domain Heatmap -->
<h2>Coverage by Domain</h2>
<div class="legend">
  <div class="legend-item"><div class="legend-dot" style="background:#1e8b4c"></div> Healthy (required)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#1e8b4c88"></div> Healthy (enhanced)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#f39c12"></div> Stale</div>
  <div class="legend-item"><div class="legend-dot" style="background:#c0392b"></div> Degraded / Dead</div>
  <div class="legend-item"><div class="legend-dot" style="background:#333"></div> Missing (required)</div>
  <div class="legend-item"><div class="legend-dot" style="background:#1a1a1a"></div> Not onboarded (enhanced)</div>
</div>
<div class="heatmap">
  <table>
    <tr><th>Domain</th><th colspan="20">Tables</th></tr>
    {heatmap_rows}
  </table>
</div>

<!-- Gaps -->
<h2>Coverage Gaps ({len(gaps)})</h2>
<div class="gaps">
<table>
  <tr><th>Severity</th><th>Domain</th><th>Table</th><th>Type</th><th>Recommendation</th></tr>
  {gap_rows if gap_rows else '<tr><td colspan="5" style="padding:12px;color:#8b949e">No gaps detected</td></tr>'}
</table>
</div>

<!-- Health Issues -->
<h2>Health Issues ({len(health_issues)})</h2>
<div class="health">
<table>
  <tr><th>Severity</th><th>Table</th><th>Status</th><th>Stale</th><th>Impact</th></tr>
  {health_rows if health_rows else '<tr><td colspan="5" style="padding:12px;color:#8b949e">All sources healthy</td></tr>'}
</table>
</div>

<!-- Trend Chart -->
<h2>Coverage Trend</h2>
<canvas id="trendChart" height="80"></canvas>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>
const history = {history_json};
if (history.length > 1) {{
  const labels = history.map(h => h.collected_at ? h.collected_at.slice(0, 10) : '');
  const scores = history.map(h => Math.round((h.overall || 0) * 100));
  const healthy = history.map(h => h.healthy_sources || 0);
  const total = history.map(h => h.total_sources || 0);
  new Chart(document.getElementById('trendChart'), {{
    type: 'line',
    data: {{
      labels,
      datasets: [
        {{ label: 'Overall %', data: scores, borderColor: '#58a6ff', backgroundColor: '#58a6ff22', tension: 0.3, yAxisID: 'y' }},
        {{ label: 'Healthy', data: healthy, borderColor: '#1e8b4c', backgroundColor: '#1e8b4c22', tension: 0.3, yAxisID: 'y1' }},
        {{ label: 'Total', data: total, borderColor: '#8b949e', backgroundColor: '#8b949e22', tension: 0.3, yAxisID: 'y1' }},
      ]
    }},
    options: {{
      responsive: true,
      interaction: {{ mode: 'index', intersect: false }},
      plugins: {{ legend: {{ labels: {{ color: '#8b949e' }} }} }},
      scales: {{
        x: {{ ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }} }},
        y: {{ position: 'left', title: {{ display: true, text: 'Score %', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ color: '#21262d' }}, min: 0, max: 100 }},
        y1: {{ position: 'right', title: {{ display: true, text: 'Sources', color: '#8b949e' }}, ticks: {{ color: '#8b949e' }}, grid: {{ drawOnChartArea: false }} }},
      }}
    }}
  }});
}} else {{
  document.getElementById('trendChart').parentElement.innerHTML += '<p style="color:#8b949e;font-size:0.9em">Trend data will appear after multiple collection runs.</p>';
}}
</script>

</body>
</html>"""

    return html
