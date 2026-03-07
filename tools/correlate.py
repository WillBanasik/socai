"""
tool: correlate
---------------
Cross-references IOCs from artefacts with log entity data to find
overlapping indicators.  Produces a correlation matrix and a timeline
of relevant log events.

Writes:
  cases/<case_id>/artefacts/correlation/correlation.json
  cases/<case_id>/artefacts/correlation/timeline.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, utcnow, write_artefact


def _load_all_entities(logs_dir: Path) -> dict[str, list]:
    """Merge entities from all *.entities.json files in the logs dir."""
    merged: dict[str, set] = {}
    for ef in logs_dir.glob("*.entities.json"):
        try:
            data = load_json(ef)
            for k, vals in data.items():
                merged.setdefault(k, set()).update(vals)
        except Exception as exc:
            log_error("", "correlate.load_entities", str(exc),
                      severity="warning", context={"file": str(ef)})
    return {k: sorted(v) for k, v in merged.items()}


def _load_iocs(case_dir: Path) -> dict[str, list]:
    iocs_path = case_dir / "iocs" / "iocs.json"
    if not iocs_path.exists():
        return {}
    return load_json(iocs_path).get("iocs", {})


def _load_all_parsed_rows(logs_dir: Path) -> list[dict]:
    """Collect all rows_sample from parsed log files."""
    rows = []
    for pf in logs_dir.glob("*.parsed.json"):
        try:
            data = load_json(pf)
            rows.extend(data.get("rows_sample", []))
        except Exception as exc:
            log_error("", "correlate.load_parsed_rows", str(exc),
                      severity="warning", context={"file": str(pf)})
    return rows


def correlate(case_id: str) -> dict:
    """
    Correlate extracted IOCs against log entities.
    Returns a dict of hits and a basic timeline.
    """
    case_dir = CASES_DIR / case_id
    logs_dir = case_dir / "logs"
    corr_dir = case_dir / "artefacts" / "correlation"
    corr_dir.mkdir(parents=True, exist_ok=True)

    iocs     = _load_iocs(case_dir)
    entities = _load_all_entities(logs_dir) if logs_dir.exists() else {}
    rows     = _load_all_parsed_rows(logs_dir) if logs_dir.exists() else []

    hits: dict[str, list] = {}

    # Match IOC IPs against log IPs
    ioc_ips = set(iocs.get("ipv4", []))
    log_ips = set(entities.get("ips", []))
    ip_hits = sorted(ioc_ips & log_ips)
    if ip_hits:
        hits["ip_matches"] = ip_hits

    # Match IOC domains against log users / commands (crude hostname extract)
    ioc_domains = set(iocs.get("domain", []))
    # Check if any domain appears in any log entity value
    domain_hits = []
    for dom in ioc_domains:
        for ent_vals in entities.values():
            for val in ent_vals:
                if dom.lower() in val.lower():
                    domain_hits.append({"domain": dom, "matched_in": val})
                    break
    if domain_hits:
        hits["domain_matches"] = domain_hits

    # Hash matches
    ioc_hashes = set(iocs.get("sha256", []) + iocs.get("md5", []) + iocs.get("sha1", []))
    hash_hits = []
    for row in rows:
        row_str = json.dumps(row, default=str).lower()
        for h in ioc_hashes:
            if h.lower() in row_str:
                hash_hits.append({"hash": h, "row_preview": row_str[:200]})
    if hash_hits:
        hits["hash_matches"] = hash_hits

    # Build a basic timeline from rows that matched any IOC IP
    timeline = []
    for row in rows:
        row_str = json.dumps(row, default=str)
        matched = any(ip in row_str for ip in ip_hits)
        if matched:
            timeline.append({
                "ts": next((v for k, v in row.items() if "time" in k.lower()), "unknown"),
                "event": row,
            })
    timeline.sort(key=lambda x: str(x.get("ts", "")))

    result = {
        "case_id": case_id,
        "ts": utcnow(),
        "ioc_count": {k: len(v) for k, v in iocs.items()},
        "entity_count": {k: len(v) for k, v in entities.items()},
        "hits": hits,
        "hit_summary": {k: len(v) for k, v in hits.items()},
        "timeline_events": len(timeline),
    }

    write_artefact(corr_dir / "correlation.json", json.dumps(result, indent=2))
    write_artefact(corr_dir / "timeline.json",    json.dumps(timeline, indent=2))
    print(f"[correlate] Correlation complete for {case_id}: {result['hit_summary']}")
    return result


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Correlate IOCs with logs for a case.")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = correlate(args.case_id)
    print(json.dumps(result, indent=2))
