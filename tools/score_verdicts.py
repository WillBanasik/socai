"""
tool: score_verdicts
--------------------
Aggregates per-provider enrichment verdicts into a composite score per IOC,
then merges results into the cross-case IOC index.

score_verdicts(case_id)
    Reads:  cases/<case_id>/artefacts/enrichment/enrichment.json
    Writes: cases/<case_id>/artefacts/enrichment/verdict_summary.json

    Composite verdict rules (applied in priority order):
      malicious  — ≥1 provider returned malicious AND malicious_count ≥ suspicious_count
      suspicious — ≥1 provider returned suspicious AND malicious_count == 0
      clean      — all responsive providers returned clean
      unknown    — fewer than 2 responsive providers, or split with no clear majority

    Confidence:
      HIGH   — ≥3 responsive providers and winning verdict ≥66% agreement
      MEDIUM — winning verdict ≥50% agreement
      LOW    — otherwise

update_ioc_index(case_id)
    Reads:  cases/<case_id>/artefacts/enrichment/verdict_summary.json
    Writes: registry/ioc_index.json  (merged; creates on first run)

    Keyed by IOC value.  Tracks first/last seen timestamps, all cases, and
    the latest composite verdict.  Existing entries are updated, not replaced.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, IOC_INDEX_FILE
from tools.common import load_json, log_error, save_json, utcnow

# Provider statuses that carry a meaningful verdict
_OK_STATUSES = {"ok"}


def _composite_verdict(providers: dict[str, str]) -> tuple[str, str]:
    """
    Given {provider_name: verdict_string}, return (composite_verdict, confidence).
    Only counts providers that returned a recognised verdict (not None / empty).
    """
    counts: dict[str, int] = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
    for v in providers.values():
        key = v if v in counts else "unknown"
        counts[key] += 1

    total = sum(counts.values())
    if total == 0:
        return "unknown", "LOW"

    if counts["malicious"] > 0 and counts["malicious"] >= counts["suspicious"]:
        verdict = "malicious"
    elif counts["suspicious"] > 0 and counts["malicious"] == 0:
        verdict = "suspicious"
    elif counts["clean"] > 0 and counts["malicious"] == 0 and counts["suspicious"] == 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    winning = counts[verdict]
    pct = winning / total if total > 0 else 0
    if total >= 3 and pct >= 0.66:
        confidence = "HIGH"
    elif total >= 2 and pct > 0.50:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return verdict, confidence


def score_verdicts(case_id: str) -> dict:
    """
    Aggregate per-provider verdicts from enrichment.json into verdict_summary.json.
    Returns the summary dict (also written to disk).
    """
    enrich_path = CASES_DIR / case_id / "artefacts" / "enrichment" / "enrichment.json"
    if not enrich_path.exists():
        print(f"[score_verdicts] enrichment.json not found — skipping verdict scoring.")
        return {"error": "enrichment.json not found", "case_id": case_id}

    data = load_json(enrich_path)
    results = data.get("results", [])

    # Group by IOC value, collecting per-provider verdicts from OK results only
    by_ioc: dict[str, dict] = {}
    for r in results:
        ioc      = r.get("ioc", "")
        ioc_type = r.get("ioc_type", "")
        provider = r.get("provider", "")
        verdict  = r.get("verdict")
        status   = r.get("status", "")

        if not ioc or not provider or status not in _OK_STATUSES or verdict is None:
            continue

        if ioc not in by_ioc:
            by_ioc[ioc] = {"ioc_type": ioc_type, "providers": {}}
        by_ioc[ioc]["providers"][provider] = verdict

    # Compute composite scores
    ioc_scores:   dict[str, dict] = {}
    high_priority: list[str] = []
    needs_review:  list[str] = []
    clean_iocs:    list[str] = []

    for ioc, info in by_ioc.items():
        providers = info["providers"]
        if not providers:
            continue

        composite, confidence = _composite_verdict(providers)

        counts = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
        for v in providers.values():
            counts[v if v in counts else "unknown"] += 1

        ioc_scores[ioc] = {
            "ioc_type":       info["ioc_type"],
            "verdict":        composite,
            "confidence":     confidence,
            "malicious":      counts["malicious"],
            "suspicious":     counts["suspicious"],
            "clean":          counts["clean"],
            "unknown":        counts["unknown"],
            "total_providers": len(providers),
            "providers":      providers,
        }

        if composite == "malicious":
            high_priority.append(ioc)
        elif composite == "suspicious":
            needs_review.append(ioc)
        elif composite == "clean":
            clean_iocs.append(ioc)

    output = {
        "case_id":      case_id,
        "ts":           utcnow(),
        "ioc_count":    len(ioc_scores),
        "high_priority": high_priority,
        "needs_review": needs_review,
        "clean":        clean_iocs,
        "iocs":         ioc_scores,
    }

    out_path = CASES_DIR / case_id / "artefacts" / "enrichment" / "verdict_summary.json"
    save_json(out_path, output)
    print(
        f"[score_verdicts] {len(high_priority)} malicious, "
        f"{len(needs_review)} suspicious, {len(clean_iocs)} clean "
        f"({len(ioc_scores)} IOCs scored for case {case_id})"
    )
    return output


def update_ioc_index(case_id: str) -> dict:
    """
    Merge this case's verdict_summary.json into registry/ioc_index.json.

    Each entry in the index is keyed by IOC value and stores:
      ioc_type, first_seen, last_seen, cases[], verdict,
      malicious, suspicious, clean counts.

    Returns a summary dict with new/recurring IOC counts.
    """
    verdict_path = (
        CASES_DIR / case_id / "artefacts" / "enrichment" / "verdict_summary.json"
    )
    if not verdict_path.exists():
        print(f"[update_ioc_index] verdict_summary.json not found — skipping index update.")
        return {"error": "verdict_summary.json not found", "case_id": case_id}

    verdict_data = load_json(verdict_path)
    ioc_scores   = verdict_data.get("iocs", {})

    # Load existing index
    index: dict = {}
    if IOC_INDEX_FILE.exists():
        try:
            index = load_json(IOC_INDEX_FILE)
        except FileNotFoundError:
            index = {}
        except Exception as exc:
            log_error(case_id, "score_verdicts.load_ioc_index", str(exc),
                      severity="warning", context={"path": str(IOC_INDEX_FILE)})
            index = {}

    now           = utcnow()
    new_iocs:       list[str] = []
    recurring_iocs: list[str] = []

    for ioc, score in ioc_scores.items():
        if ioc in index:
            entry = index[ioc]
            if case_id not in entry.get("cases", []):
                entry.setdefault("cases", []).append(case_id)
                recurring_iocs.append(ioc)
            # Always refresh verdict and timestamps from the latest run
            entry["last_seen"]  = now
            entry["verdict"]    = score["verdict"]
            entry["malicious"]  = score["malicious"]
            entry["suspicious"] = score["suspicious"]
            entry["clean"]      = score["clean"]
        else:
            index[ioc] = {
                "ioc_type":   score["ioc_type"],
                "first_seen": now,
                "last_seen":  now,
                "cases":      [case_id],
                "verdict":    score["verdict"],
                "malicious":  score["malicious"],
                "suspicious": score["suspicious"],
                "clean":      score["clean"],
            }
            new_iocs.append(ioc)

    IOC_INDEX_FILE.parent.mkdir(parents=True, exist_ok=True)
    save_json(IOC_INDEX_FILE, index)

    if recurring_iocs:
        print(
            f"[update_ioc_index] {len(recurring_iocs)} RECURRING IOC(s) "
            f"seen in other cases: {recurring_iocs[:5]}"
            + (" ..." if len(recurring_iocs) > 5 else "")
        )
    print(
        f"[update_ioc_index] {len(new_iocs)} new | "
        f"{len(recurring_iocs)} recurring | "
        f"{len(index)} total indexed"
    )

    return {
        "case_id":       case_id,
        "ts":            now,
        "new_iocs":      len(new_iocs),
        "recurring_iocs": len(recurring_iocs),
        "recurring":     recurring_iocs,
        "total_indexed": len(index),
    }


if __name__ == "__main__":
    import argparse, json

    p = argparse.ArgumentParser(description="Score IOC verdicts and update the cross-case index.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--skip-index", action="store_true", help="Score only; do not update ioc_index.")
    args = p.parse_args()

    sv = score_verdicts(args.case_id)
    print(json.dumps(sv, indent=2))
    if not args.skip_index:
        idx = update_ioc_index(args.case_id)
        print(json.dumps(idx, indent=2))
