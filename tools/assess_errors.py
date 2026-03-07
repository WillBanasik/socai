"""
tool: assess_errors
--------------------
On-demand analysis of collected error data from registry/error_log.jsonl.

Aggregates errors by step, severity, and frequency; computes impact scores;
and generates a prioritised assessment with actionable improvement suggestions.

Usage (standalone):
  python3 tools/assess_errors.py
  python3 tools/assess_errors.py --top 20
  python3 tools/assess_errors.py --severity error
  python3 tools/assess_errors.py --json
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ERROR_LOG


def _load_errors(severity_filter: str | None = None) -> list[dict]:
    """Load all error records from the JSONL log."""
    if not ERROR_LOG.exists():
        return []
    records: list[dict] = []
    with open(ERROR_LOG, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if severity_filter and rec.get("severity") != severity_filter:
                continue
            records.append(rec)
    return records


def _parse_ts(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def assess_errors(
    top_n: int = 15,
    severity_filter: str | None = None,
    json_output: bool = False,
) -> dict:
    """
    Analyse error_log.jsonl and return a prioritised assessment.

    Impact score per step = (error_count * 3) + (warning_count * 1) + (info_count * 0.25)
    Higher score = more processing impact.
    """
    records = _load_errors(severity_filter)
    if not records:
        result = {
            "status": "empty",
            "message": "No errors recorded yet." if not severity_filter
                       else f"No '{severity_filter}' errors recorded.",
            "total_records": 0,
        }
        if not json_output:
            print(result["message"])
        return result

    # --- Aggregation ---
    severity_weights = {"error": 3.0, "warning": 1.0, "info": 0.25}

    by_step: dict[str, dict] = defaultdict(lambda: {
        "count": 0, "error": 0, "warning": 0, "info": 0,
        "cases": set(), "errors": [], "first_seen": None, "last_seen": None,
    })
    by_error_msg: Counter[str] = Counter()
    by_case: Counter[str] = Counter()
    severity_totals: Counter[str] = Counter()
    timeline: Counter[str] = Counter()  # date -> count

    for rec in records:
        step = rec.get("step", "unknown")
        sev = rec.get("severity", "error")
        case = rec.get("case_id", "")
        error_msg = rec.get("error", "")
        ts_str = rec.get("ts", "")

        entry = by_step[step]
        entry["count"] += 1
        entry[sev] = entry.get(sev, 0) + 1
        if case:
            entry["cases"].add(case)

        # Track unique error messages per step (keep first 3)
        if len(entry["errors"]) < 3 and error_msg not in entry["errors"]:
            entry["errors"].append(error_msg)

        # Timestamps
        ts = _parse_ts(ts_str)
        if ts:
            if entry["first_seen"] is None or ts_str < entry["first_seen"]:
                entry["first_seen"] = ts_str
            if entry["last_seen"] is None or ts_str > entry["last_seen"]:
                entry["last_seen"] = ts_str
            timeline[ts_str[:10]] += 1  # YYYY-MM-DD

        by_error_msg[error_msg] += 1
        if case:
            by_case[case] += 1
        severity_totals[sev] += 1

    # --- Impact scoring ---
    scored: list[dict] = []
    for step, data in by_step.items():
        impact = (
            data["error"] * severity_weights["error"]
            + data["warning"] * severity_weights["warning"]
            + data["info"] * severity_weights["info"]
        )
        scored.append({
            "step": step,
            "impact_score": round(impact, 2),
            "total": data["count"],
            "error": data["error"],
            "warning": data["warning"],
            "info": data["info"],
            "affected_cases": len(data["cases"]),
            "sample_errors": data["errors"],
            "first_seen": data["first_seen"],
            "last_seen": data["last_seen"],
        })

    scored.sort(key=lambda x: x["impact_score"], reverse=True)
    top_steps = scored[:top_n]

    # --- Most repeated error messages ---
    top_messages = [
        {"message": msg[:200], "count": cnt}
        for msg, cnt in by_error_msg.most_common(10)
    ]

    # --- Most error-prone cases ---
    top_cases = [
        {"case_id": cid, "error_count": cnt}
        for cid, cnt in by_case.most_common(10)
    ]

    # --- Build result ---
    result = {
        "status": "ok",
        "total_records": len(records),
        "severity_breakdown": dict(severity_totals),
        "unique_steps": len(by_step),
        "date_range": {
            "earliest": min(timeline.keys()) if timeline else None,
            "latest": max(timeline.keys()) if timeline else None,
        },
        "prioritised_steps": top_steps,
        "top_repeated_messages": top_messages,
        "top_error_prone_cases": top_cases,
        "daily_volume": dict(sorted(timeline.items())),
    }

    if json_output:
        return result

    # --- Pretty print ---
    print(f"\n{'='*70}")
    print(f"  ERROR ASSESSMENT REPORT")
    print(f"{'='*70}")
    print(f"  Total records: {len(records)}")
    print(f"  Severity: {dict(severity_totals)}")
    print(f"  Unique steps: {len(by_step)}")
    if timeline:
        print(f"  Date range: {min(timeline.keys())} to {max(timeline.keys())}")
    print()

    # Priority table
    print(f"  {'RANK':<5} {'IMPACT':>7}  {'ERR':>4} {'WARN':>4} {'INFO':>4}  {'CASES':>5}  STEP")
    print(f"  {'-'*5} {'-'*7}  {'-'*4} {'-'*4} {'-'*4}  {'-'*5}  {'-'*30}")
    for i, s in enumerate(top_steps, 1):
        print(
            f"  {i:<5} {s['impact_score']:>7.1f}  "
            f"{s['error']:>4} {s['warning']:>4} {s['info']:>4}  "
            f"{s['affected_cases']:>5}  {s['step']}"
        )

    print()
    print(f"  TOP REPEATED ERROR MESSAGES")
    print(f"  {'-'*60}")
    for m in top_messages[:7]:
        msg_short = m["message"][:80].replace("\n", " ")
        print(f"  [{m['count']:>3}x] {msg_short}")

    if top_cases:
        print()
        print(f"  MOST ERROR-PRONE CASES")
        print(f"  {'-'*40}")
        for c in top_cases[:5]:
            print(f"  {c['case_id']:<12} {c['error_count']} errors")

    # Daily volume sparkline
    if len(timeline) > 1:
        print()
        print(f"  DAILY VOLUME")
        print(f"  {'-'*40}")
        for date, count in sorted(timeline.items()):
            bar = "#" * min(count, 50)
            print(f"  {date}  {count:>4}  {bar}")

    print(f"\n{'='*70}\n")
    return result


def clear_error_log() -> dict:
    """Truncate the error log. Returns count of records removed."""
    count = 0
    if ERROR_LOG.exists():
        with open(ERROR_LOG, "r") as fh:
            count = sum(1 for line in fh if line.strip())
        ERROR_LOG.unlink()
    return {"cleared": count}


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Assess collected error data.")
    p.add_argument("--top", type=int, default=15, help="Top N steps to show (default 15)")
    p.add_argument("--severity", default=None, choices=["error", "warning", "info"],
                   help="Filter by severity level")
    p.add_argument("--json", action="store_true", dest="json_output",
                   help="Output raw JSON instead of formatted report")
    p.add_argument("--clear", action="store_true",
                   help="Clear the error log after assessment")
    args = p.parse_args()

    result = assess_errors(top_n=args.top, severity_filter=args.severity,
                           json_output=args.json_output)
    if args.json_output:
        print(json.dumps(result, indent=2))

    if args.clear:
        cleared = clear_error_log()
        print(f"Cleared {cleared['cleared']} error records.")
