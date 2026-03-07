"""OpenCTI dashboard integration — GraphQL queries for threat intelligence panels."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests

from config.settings import OPENCTI_KEY, OPENCTI_URL

_HEADERS = {
    "Authorization": f"Bearer {OPENCTI_KEY}",
    "Content-Type": "application/json",
} if OPENCTI_KEY else {}

_GQL = f"{OPENCTI_URL}/graphql" if OPENCTI_URL else ""

_TIMEOUT = 20


def _available() -> bool:
    return bool(OPENCTI_KEY and OPENCTI_URL)


def _post(query: str, variables: dict | None = None) -> dict:
    """Execute a GraphQL query against OpenCTI."""
    payload: dict = {"query": query}
    if variables:
        payload["variables"] = variables
    resp = requests.post(_GQL, headers=_HEADERS, json=payload, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(data["errors"][0].get("message", "GraphQL error"))
    return data.get("data", {})


# ---------------------------------------------------------------------------
# 1. Live Threat Feed — recent reports with linked threat actors & malware
# ---------------------------------------------------------------------------

def fetch_recent_reports(days: int = 30, sector: str | None = None, limit: int = 20) -> list[dict]:
    """Fetch recent OpenCTI reports with linked entities."""
    if not _available():
        return []

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")

    filters = [
        '{ key: "published", values: ["%s"], operator: gte }' % since,
    ]
    if sector:
        filters.append(
            '{ key: "objectLabel", values: ["%s"], operator: eq }' % sector
        )
    filter_str = ", ".join(filters)

    query = """
    {
      reports(
        first: %d,
        orderBy: published,
        orderMode: desc,
        filters: {
          mode: and,
          filters: [%s],
          filterGroups: []
        }
      ) {
        edges {
          node {
            id
            name
            published
            description
            confidence
            objectLabel { value color }
            objectMarking { definition }
            createdBy { name }
            objects(first: 30) {
              edges {
                node {
                  __typename
                  ... on ThreatActorGroup { name }
                  ... on ThreatActorIndividual { name }
                  ... on IntrusionSet { name }
                  ... on Malware { name malware_types }
                  ... on Campaign { name }
                  ... on AttackPattern { name x_mitre_id }
                  ... on Vulnerability { name }
                  ... on Country { name }
                  ... on Sector { name }
                }
              }
            }
          }
        }
      }
    }
    """ % (limit, filter_str)

    try:
        data = _post(query)
    except Exception:
        return []

    results = []
    for edge in data.get("reports", {}).get("edges", []):
        node = edge["node"]
        # Categorise linked objects
        actors = []
        malware = []
        campaigns = []
        techniques = []
        sectors = []
        vulns = []
        for obj_edge in node.get("objects", {}).get("edges", []):
            obj = obj_edge["node"]
            otype = obj.get("__typename", "")
            name = obj.get("name", "")
            if not name:
                continue
            if otype in ("ThreatActorGroup", "ThreatActorIndividual", "IntrusionSet"):
                if name not in actors:
                    actors.append(name)
            elif otype == "Malware":
                if name not in malware:
                    malware.append(name)
            elif otype == "Campaign":
                if name not in campaigns:
                    campaigns.append(name)
            elif otype == "AttackPattern":
                mid = obj.get("x_mitre_id", "")
                entry = f"{mid} {name}" if mid else name
                if entry not in techniques:
                    techniques.append(entry)
            elif otype == "Sector":
                if name not in sectors:
                    sectors.append(name)
            elif otype == "Vulnerability":
                if name not in vulns:
                    vulns.append(name)

        labels = [lb.get("value", "") for lb in node.get("objectLabel", []) if lb.get("value")]
        markings = [m.get("definition", "") for m in node.get("objectMarking", []) if m.get("definition")]

        results.append({
            "id": node["id"],
            "name": node["name"],
            "published": node.get("published", ""),
            "description": (node.get("description") or "")[:200],
            "confidence": node.get("confidence"),
            "author": (node.get("createdBy") or {}).get("name", ""),
            "labels": labels,
            "markings": markings,
            "threat_actors": actors,
            "malware": malware,
            "campaigns": campaigns,
            "techniques": techniques[:5],
            "sectors": sectors,
            "vulnerabilities": vulns,
            "link": f"{OPENCTI_URL}/dashboard/analyses/reports/{node['id']}",
        })
    return results


# ---------------------------------------------------------------------------
# 2. Cross-reference — batch lookup of IOC values against OpenCTI
# ---------------------------------------------------------------------------

def batch_ioc_xref(iocs: list[dict]) -> list[dict]:
    """Batch-lookup IOC values in OpenCTI. Each ioc dict has 'value' and 'type'.

    Returns the input list enriched with opencti_score, opencti_verdict, opencti_link.
    """
    if not _available() or not iocs:
        return iocs

    # Build a single query with aliases for each IOC
    parts = []
    for i, ioc in enumerate(iocs):
        val = ioc.get("value") or ioc.get("ioc", "")
        if not val:
            continue
        escaped = val.replace('"', '\\"')
        parts.append("""
        ioc%d: stixCyberObservables(
          first: 1,
          filters: {
            mode: and,
            filters: [{key: "value", values: ["%s"], operator: eq}],
            filterGroups: []
          }
        ) {
          edges {
            node {
              id
              entity_type
              x_opencti_score
              indicators { edges { node { name x_opencti_score } } }
            }
          }
        }
        """ % (i, escaped))

    if not parts:
        return iocs

    # Split into batches of 10 to avoid oversized queries
    BATCH_SIZE = 10
    all_results: dict[int, dict] = {}
    for batch_start in range(0, len(parts), BATCH_SIZE):
        batch = parts[batch_start:batch_start + BATCH_SIZE]
        query = "{ " + "\n".join(batch) + " }"
        try:
            data = _post(query)
        except Exception:
            continue
        for j in range(len(batch)):
            idx = batch_start + j
            key = f"ioc{idx}"
            edges = data.get(key, {}).get("edges", [])
            if edges:
                all_results[idx] = edges[0]["node"]

    # Enrich the IOC list
    enriched = []
    for i, ioc in enumerate(iocs):
        entry = dict(ioc)
        node = all_results.get(i)
        if node:
            score = node.get("x_opencti_score")
            verdict = ("malicious" if score and score >= 70 else
                       "suspicious" if score and score >= 40 else
                       "clean" if score is not None else "unknown")
            entity_path = "observations/observables"
            indicators = [
                e["node"]["name"]
                for e in node.get("indicators", {}).get("edges", [])
            ]
            entry.update({
                "opencti_score": score,
                "opencti_verdict": verdict,
                "opencti_indicators": indicators[:3],
                "opencti_link": f"{OPENCTI_URL}/dashboard/{entity_path}/{node['id']}",
            })
        else:
            entry.update({
                "opencti_score": None,
                "opencti_verdict": "not_found",
                "opencti_indicators": [],
                "opencti_link": "",
            })
        enriched.append(entry)
    return enriched


# ---------------------------------------------------------------------------
# 3. Trending Indicators — recently created, high-score indicators
# ---------------------------------------------------------------------------

def fetch_trending_indicators(days: int = 7, limit: int = 20) -> list[dict]:
    """Fetch recently created indicators sorted by score."""
    if not _available():
        return []

    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")

    query = """
    {
      indicators(
        first: %d,
        orderBy: x_opencti_score,
        orderMode: desc,
        filters: {
          mode: and,
          filters: [
            { key: "created_at", values: ["%s"], operator: gte },
            { key: "x_opencti_score", values: ["40"], operator: gte }
          ],
          filterGroups: []
        }
      ) {
        edges {
          node {
            id
            name
            pattern
            pattern_type
            x_opencti_score
            created_at
            valid_from
            valid_until
            objectLabel { value color }
            createdBy { name }
            observables(first: 3) {
              edges { node { observable_value entity_type } }
            }
          }
        }
      }
    }
    """ % (limit, since)

    try:
        data = _post(query)
    except Exception:
        return []

    results = []
    for edge in data.get("indicators", {}).get("edges", []):
        node = edge["node"]
        observables = [
            {"value": e["node"]["observable_value"], "type": e["node"]["entity_type"]}
            for e in node.get("observables", {}).get("edges", [])
        ]
        labels = [lb.get("value", "") for lb in node.get("objectLabel", []) if lb.get("value")]
        results.append({
            "id": node["id"],
            "name": node["name"],
            "pattern": node.get("pattern", ""),
            "pattern_type": node.get("pattern_type", ""),
            "score": node.get("x_opencti_score"),
            "created_at": node.get("created_at", ""),
            "valid_from": node.get("valid_from", ""),
            "valid_until": node.get("valid_until", ""),
            "author": (node.get("createdBy") or {}).get("name", ""),
            "labels": labels,
            "observables": observables,
            "link": f"{OPENCTI_URL}/dashboard/observations/indicators/{node['id']}",
        })
    return results


# ---------------------------------------------------------------------------
# 4. MITRE ATT&CK Heatmap — technique counts from OpenCTI
# ---------------------------------------------------------------------------

_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

_TACTIC_LABELS = {
    "reconnaissance": "Recon",
    "resource-development": "Resource Dev",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Priv Esc",
    "defense-evasion": "Def Evasion",
    "credential-access": "Cred Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Mov",
    "collection": "Collection",
    "command-and-control": "C2",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def fetch_attack_heatmap() -> dict:
    """Fetch ATT&CK technique distribution grouped by tactic.

    If kill chain phases are populated, groups by tactic.
    Otherwise falls back to a flat top-N view sorted by relationship count.
    """
    if not _available():
        return {"tactics": [], "top_techniques": [], "max_count": 0}

    query = """
    {
      attackPatterns(first: 500, orderBy: x_mitre_id, orderMode: asc) {
        edges {
          node {
            name
            x_mitre_id
            killChainPhases { kill_chain_name phase_name }
            stixCoreRelationships(first: 0) { pageInfo { globalCount } }
          }
        }
      }
    }
    """

    try:
        data = _post(query)
    except Exception:
        return {"tactics": [], "top_techniques": [], "max_count": 0}

    # Collect all techniques
    all_techniques = []
    tactic_techniques: dict[str, list] = {t: [] for t in _TACTIC_ORDER}
    has_phases = False
    max_count = 0

    for edge in data.get("attackPatterns", {}).get("edges", []):
        node = edge["node"]
        mitre_id = node.get("x_mitre_id", "")
        name = node.get("name", "")
        rel_count = (
            node.get("stixCoreRelationships", {})
            .get("pageInfo", {})
            .get("globalCount", 0)
        )
        if rel_count > max_count:
            max_count = rel_count

        tech = {"id": mitre_id, "name": name, "count": rel_count}
        all_techniques.append(tech)

        for phase in node.get("killChainPhases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            has_phases = True
            tactic = phase.get("phase_name", "")
            if tactic in tactic_techniques:
                tactic_techniques[tactic].append(tech)

    # Build tactic-grouped view if phases exist
    tactics = []
    if has_phases:
        for t in _TACTIC_ORDER:
            techs = sorted(tactic_techniques[t], key=lambda x: x["count"], reverse=True)
            tactics.append({
                "tactic": t,
                "label": _TACTIC_LABELS.get(t, t),
                "techniques": techs[:15],
                "total": len(tactic_techniques[t]),
            })

    # Always provide a flat top-N list (used when phases are missing)
    top_techniques = sorted(
        [t for t in all_techniques if t["count"] > 0],
        key=lambda x: x["count"],
        reverse=True,
    )[:50]

    return {
        "tactics": tactics,
        "top_techniques": top_techniques,
        "max_count": max_count,
        "has_tactic_grouping": has_phases,
    }


# ---------------------------------------------------------------------------
# 5. Threat Actor Watchlist — activity on watched actors
# ---------------------------------------------------------------------------

_WATCHLIST_PATH = Path(__file__).resolve().parent.parent / "registry" / "cti_watchlist.json"


def _load_watchlist() -> list[dict]:
    if not _WATCHLIST_PATH.exists():
        return []
    try:
        with open(_WATCHLIST_PATH) as f:
            return json.load(f)
    except Exception:
        return []


def _save_watchlist(entries: list[dict]) -> None:
    _WATCHLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_WATCHLIST_PATH, "w") as f:
        json.dump(entries, f, indent=2)


def get_watchlist() -> list[dict]:
    """Return the current watchlist."""
    return _load_watchlist()


def add_to_watchlist(name: str, added_by: str = "") -> list[dict]:
    """Add a threat actor to the watchlist."""
    entries = _load_watchlist()
    # Deduplicate
    if any(e["name"].lower() == name.lower() for e in entries):
        return entries
    entries.append({
        "name": name,
        "added_by": added_by,
        "added": datetime.now(timezone.utc).isoformat(),
    })
    _save_watchlist(entries)
    return entries


def remove_from_watchlist(name: str) -> list[dict]:
    """Remove a threat actor from the watchlist."""
    entries = _load_watchlist()
    entries = [e for e in entries if e["name"].lower() != name.lower()]
    _save_watchlist(entries)
    return entries


def fetch_watchlist_activity(days: int = 30) -> list[dict]:
    """For each watched actor, fetch recent reports and indicators from OpenCTI."""
    if not _available():
        return []

    entries = _load_watchlist()
    if not entries:
        return []

    results = []
    for entry in entries:
        name = entry["name"]
        escaped = name.replace('"', '\\"')

        query = """
        {
          intrusionSets(
            first: 1,
            filters: {
              mode: and,
              filters: [{ key: "name", values: ["%s"], operator: eq }],
              filterGroups: []
            }
          ) {
            edges {
              node {
                id
                name
                description
                first_seen
                last_seen
                objectLabel { value }
                reports(first: 5) {
                  edges { node { name published } }
                }
              }
            }
          }
          threatActorsGroup(
            first: 1,
            filters: {
              mode: and,
              filters: [{ key: "name", values: ["%s"], operator: eq }],
              filterGroups: []
            }
          ) {
            edges {
              node {
                id
                name
                description
                first_seen
                last_seen
                objectLabel { value }
                reports(first: 5) {
                  edges { node { name published } }
                }
              }
            }
          }
        }
        """ % (escaped, escaped)

        try:
            data = _post(query)
        except Exception:
            results.append({"name": name, "status": "error", **entry})
            continue

        # Try intrusionSet first, then threatActorGroup
        node = None
        entity_path = ""
        for key, path in [
            ("intrusionSets", "threats/intrusion_sets"),
            ("threatActorsGroup", "threats/threat_actors_group"),
        ]:
            edges = data.get(key, {}).get("edges", [])
            if edges:
                node = edges[0]["node"]
                entity_path = path
                break

        if not node:
            results.append({"name": name, "status": "not_found", **entry})
            continue

        recent_reports = [
            {"name": r["node"]["name"], "published": r["node"].get("published", "")}
            for r in node.get("reports", {}).get("edges", [])
        ]
        labels = [lb.get("value", "") for lb in node.get("objectLabel", []) if lb.get("value")]

        results.append({
            **entry,
            "status": "ok",
            "description": (node.get("description") or "")[:200],
            "first_seen": node.get("first_seen", ""),
            "last_seen": node.get("last_seen", ""),
            "labels": labels,
            "recent_reports": recent_reports,
            "link": f"{OPENCTI_URL}/dashboard/{entity_path}/{node['id']}",
        })

    return results


# ---------------------------------------------------------------------------
# 6. IOC Decay / Ageing — check indicator validity for case IOCs
# ---------------------------------------------------------------------------

def fetch_ioc_decay(ioc_values: list[str]) -> list[dict]:
    """Check indicator validity for a list of IOC values via observable lookup.

    Looks up each IOC as a StixCyberObservable, then checks linked indicators
    for validity periods. Returns each IOC with decay status:
    active, expired, revoked, or not_found.
    """
    if not _available() or not ioc_values:
        return []

    parts = []
    for i, val in enumerate(ioc_values):
        escaped = val.replace('"', '\\"')
        parts.append("""
        decay%d: stixCyberObservables(
          first: 1,
          filters: {
            mode: and,
            filters: [{ key: "value", values: ["%s"], operator: eq }],
            filterGroups: []
          }
        ) {
          edges {
            node {
              observable_value
              x_opencti_score
              indicators(first: 1) {
                edges {
                  node {
                    name
                    x_opencti_score
                    valid_from
                    valid_until
                    revoked
                    x_opencti_detection
                  }
                }
              }
            }
          }
        }
        """ % (i, escaped))

    results = []
    BATCH_SIZE = 10
    now = datetime.now(timezone.utc)

    for batch_start in range(0, len(parts), BATCH_SIZE):
        batch = parts[batch_start:batch_start + BATCH_SIZE]
        query = "{ " + "\n".join(batch) + " }"
        try:
            data = _post(query)
        except Exception:
            for j in range(len(batch)):
                idx = batch_start + j
                results.append({"ioc": ioc_values[idx], "status": "error"})
            continue

        for j in range(len(batch)):
            idx = batch_start + j
            key = f"decay{idx}"
            edges = data.get(key, {}).get("edges", [])
            if not edges:
                results.append({"ioc": ioc_values[idx], "status": "not_found"})
                continue

            obs_node = edges[0]["node"]
            obs_score = obs_node.get("x_opencti_score")

            # Check linked indicator for validity
            ind_edges = obs_node.get("indicators", {}).get("edges", [])
            if not ind_edges:
                # Observable exists but no indicator — treat as active (known to CTI)
                results.append({
                    "ioc": ioc_values[idx],
                    "status": "active",
                    "score": obs_score,
                    "valid_from": "",
                    "valid_until": "",
                    "indicator_name": "",
                    "detection": False,
                })
                continue

            ind = ind_edges[0]["node"]
            valid_until = ind.get("valid_until")
            revoked = ind.get("revoked", False)

            if revoked:
                decay_status = "revoked"
            elif valid_until:
                try:
                    exp = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                    decay_status = "expired" if exp < now else "active"
                except Exception:
                    decay_status = "unknown"
            else:
                decay_status = "active"

            results.append({
                "ioc": ioc_values[idx],
                "status": decay_status,
                "score": ind.get("x_opencti_score") or obs_score,
                "valid_from": ind.get("valid_from", ""),
                "valid_until": valid_until or "",
                "indicator_name": ind.get("name", ""),
                "detection": ind.get("x_opencti_detection", False),
            })

    return results
