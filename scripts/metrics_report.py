#!/usr/bin/env python3
"""Query and summarise investigation metrics from registry/metrics.jsonl.

Usage:
    python3 scripts/metrics_report.py                      # full summary
    python3 scripts/metrics_report.py --event enrichment_complete
    python3 scripts/metrics_report.py --case IV_CASE_030
    python3 scripts/metrics_report.py --analyst will
    python3 scripts/metrics_report.py --since 2026-03-01
    python3 scripts/metrics_report.py --compare            # analyst comparison
    python3 scripts/metrics_report.py --json               # raw JSON output
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import METRICS_LOG


def _load_records(
    *,
    event: str | None = None,
    case_id: str | None = None,
    analyst: str | None = None,
    since: str | None = None,
) -> list[dict]:
    """Load and filter metrics records."""
    if not METRICS_LOG.exists():
        return []

    records = []
    since_dt = None
    if since:
        since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)

    with open(METRICS_LOG) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event and rec.get("event") != event:
                continue
            if case_id and rec.get("case_id") != case_id:
                continue
            if analyst and rec.get("analyst") != analyst:
                continue
            if since_dt:
                try:
                    ts = datetime.fromisoformat(rec["ts"].replace("Z", "+00:00"))
                    if ts < since_dt:
                        continue
                except (ValueError, KeyError):
                    continue

            records.append(rec)
    return records


def _fmt_duration(minutes: float | None) -> str:
    if minutes is None:
        return "-"
    if minutes < 60:
        return f"{minutes:.1f}m"
    hours = minutes / 60
    return f"{hours:.1f}h"


def _print_summary(records: list[dict]) -> None:
    """Print a full summary across all event types."""
    by_event: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_event[r.get("event", "unknown")].append(r)

    total = len(records)
    print(f"\n{'='*60}")
    print(f"  SOCAI METRICS SUMMARY  ({total} records)")
    print(f"{'='*60}\n")

    # Phase changes
    phases = by_event.get("case_phase_change", [])
    if phases:
        phase_counts: dict[str, int] = defaultdict(int)
        for p in phases:
            phase_counts[p.get("phase", "?")] += 1
        print(f"Case Phase Changes ({len(phases)} events):")
        for phase, count in sorted(phase_counts.items()):
            print(f"  {phase:<15} {count}")
        print()

    # Enrichment
    enrichments = by_event.get("enrichment_complete", [])
    if enrichments:
        durations = [e["duration_ms"] for e in enrichments if "duration_ms" in e]
        coverages = [e["ioc_coverage_pct"] for e in enrichments if "ioc_coverage_pct" in e]
        cache_rates = []
        for e in enrichments:
            total_lookups = e.get("total_lookups", 0)
            if total_lookups:
                cache_rates.append(e.get("cache_hits", 0) / total_lookups * 100)
        print(f"Enrichment ({len(enrichments)} runs):")
        if durations:
            print(f"  Duration:    median {statistics.median(durations):.0f}ms, "
                  f"mean {statistics.mean(durations):.0f}ms, "
                  f"max {max(durations):.0f}ms")
        if coverages:
            print(f"  IOC Coverage: median {statistics.median(coverages):.1f}%, "
                  f"mean {statistics.mean(coverages):.1f}%")
        if cache_rates:
            print(f"  Cache Rate:   median {statistics.median(cache_rates):.1f}%, "
                  f"mean {statistics.mean(cache_rates):.1f}%")
        print()

    # Verdicts
    verdicts = by_event.get("verdict_scored", [])
    if verdicts:
        total_mal = sum(v.get("malicious_count", 0) for v in verdicts)
        total_sus = sum(v.get("suspicious_count", 0) for v in verdicts)
        total_cln = sum(v.get("clean_count", 0) for v in verdicts)
        conf_high = sum(v.get("confidence_dist", {}).get("HIGH", 0) for v in verdicts)
        conf_med = sum(v.get("confidence_dist", {}).get("MEDIUM", 0) for v in verdicts)
        conf_low = sum(v.get("confidence_dist", {}).get("LOW", 0) for v in verdicts)
        conf_total = conf_high + conf_med + conf_low
        print(f"Verdicts ({len(verdicts)} scoring runs):")
        print(f"  Malicious: {total_mal}  Suspicious: {total_sus}  Clean: {total_cln}")
        if conf_total:
            print(f"  Confidence: HIGH {conf_high} ({conf_high/conf_total*100:.0f}%)  "
                  f"MEDIUM {conf_med} ({conf_med/conf_total*100:.0f}%)  "
                  f"LOW {conf_low} ({conf_low/conf_total*100:.0f}%)")
        print()

    # Reports
    reports = by_event.get("report_saved", [])
    if reports:
        completeness = [r["completeness_pct"] for r in reports if "completeness_pct" in r]
        by_type: dict[str, int] = defaultdict(int)
        for r in reports:
            by_type[r.get("report_type", "?")] += 1
        print(f"Reports ({len(reports)} saved):")
        for rtype, count in sorted(by_type.items()):
            print(f"  {rtype:<25} {count}")
        if completeness:
            print(f"  Completeness: median {statistics.median(completeness):.0f}%, "
                  f"mean {statistics.mean(completeness):.0f}%")
        print()

    # Investigation summaries
    summaries = by_event.get("investigation_summary", [])
    if summaries:
        _print_investigation_stats(summaries)


def _print_investigation_stats(summaries: list[dict]) -> None:
    """Print investigation duration and disposition stats."""
    total_mins = [s["durations"]["total_minutes"]
                  for s in summaries
                  if s.get("durations", {}).get("total_minutes") is not None]
    triage_mins = [s["durations"]["triage_minutes"]
                   for s in summaries
                   if s.get("durations", {}).get("triage_minutes") is not None]
    inv_mins = [s["durations"]["investigation_minutes"]
                for s in summaries
                if s.get("durations", {}).get("investigation_minutes") is not None]

    disp_counts: dict[str, int] = defaultdict(int)
    for s in summaries:
        disp_counts[s.get("disposition", "unknown")] += 1

    print(f"Investigations ({len(summaries)} closed):")
    if total_mins:
        print(f"  Total time:       median {_fmt_duration(statistics.median(total_mins))}, "
              f"mean {_fmt_duration(statistics.mean(total_mins))}")
    if triage_mins:
        print(f"  Triage time:      median {_fmt_duration(statistics.median(triage_mins))}, "
              f"mean {_fmt_duration(statistics.mean(triage_mins))}")
    if inv_mins:
        print(f"  Investigation:    median {_fmt_duration(statistics.median(inv_mins))}, "
              f"mean {_fmt_duration(statistics.mean(inv_mins))}")
    print(f"  Dispositions:")
    for disp, count in sorted(disp_counts.items(), key=lambda x: -x[1]):
        print(f"    {disp:<20} {count}")
    print()


def _print_compare(records: list[dict]) -> None:
    """Side-by-side analyst comparison from investigation_summary events."""
    summaries = [r for r in records if r.get("event") == "investigation_summary"]
    enrichments = [r for r in records if r.get("event") == "enrichment_complete"]
    reports = [r for r in records if r.get("event") == "report_saved"]
    verdicts_all = [r for r in records if r.get("event") == "verdict_scored"]

    if not summaries:
        print("No investigation_summary events found. Close some cases first.")
        return

    # Group summaries by analyst
    by_analyst: dict[str, list[dict]] = defaultdict(list)
    for s in summaries:
        by_analyst[s.get("analyst", "unassigned")].append(s)

    # Build enrichment/report lookups by case_id
    enrich_by_case = {}
    for e in enrichments:
        cid = e.get("case_id")
        if cid:
            enrich_by_case[cid] = e

    report_by_case = {}
    for r in reports:
        cid = r.get("case_id")
        if cid:
            report_by_case[cid] = r

    verdict_by_case = {}
    for v in verdicts_all:
        cid = v.get("case_id")
        if cid:
            verdict_by_case[cid] = v

    # Date range for throughput
    all_dates = set()
    for s in summaries:
        try:
            dt = datetime.fromisoformat(s["ts"].replace("Z", "+00:00"))
            all_dates.add(dt.date())
        except (ValueError, KeyError):
            pass
    num_days = max(len(all_dates), 1)

    print(f"\n{'='*80}")
    print(f"  ANALYST COMPARISON  ({len(summaries)} investigations, {num_days} active day(s))")
    print(f"{'='*80}\n")

    # Header
    analysts = sorted(by_analyst.keys())
    col_w = 18
    header = f"{'Metric':<30}" + "".join(f"{a:>{col_w}}" for a in analysts)
    print(header)
    print("-" * len(header))

    def _row(label: str, values: dict[str, str]) -> None:
        cols = "".join(f"{values.get(a, '-'):>{col_w}}" for a in analysts)
        print(f"{label:<30}{cols}")

    # Cases closed
    _row("Cases closed", {a: str(len(cases)) for a, cases in by_analyst.items()})

    # Cases/day
    analyst_dates: dict[str, set] = defaultdict(set)
    for a, cases in by_analyst.items():
        for s in cases:
            try:
                dt = datetime.fromisoformat(s["ts"].replace("Z", "+00:00"))
                analyst_dates[a].add(dt.date())
            except (ValueError, KeyError):
                pass
    _row("Cases/day (avg)", {
        a: f"{len(cases) / max(len(analyst_dates.get(a, {1})), 1):.1f}"
        for a, cases in by_analyst.items()
    })

    # Median time-to-close
    _row("Time-to-close (med)", {
        a: _fmt_duration(statistics.median([
            s["durations"]["total_minutes"]
            for s in cases
            if s.get("durations", {}).get("total_minutes") is not None
        ])) if any(s.get("durations", {}).get("total_minutes") is not None for s in cases) else "-"
        for a, cases in by_analyst.items()
    })

    # Median triage time
    _row("Triage time (med)", {
        a: _fmt_duration(statistics.median([
            s["durations"]["triage_minutes"]
            for s in cases
            if s.get("durations", {}).get("triage_minutes") is not None
        ])) if any(s.get("durations", {}).get("triage_minutes") is not None for s in cases) else "-"
        for a, cases in by_analyst.items()
    })

    # IOC coverage
    def _analyst_coverage(a: str, cases: list[dict]) -> str:
        covs = []
        for s in cases:
            cid = s.get("case_id")
            if cid and cid in enrich_by_case:
                c = enrich_by_case[cid].get("ioc_coverage_pct")
                if c is not None:
                    covs.append(c)
        return f"{statistics.mean(covs):.0f}%" if covs else "-"

    _row("IOC coverage (avg)", {a: _analyst_coverage(a, cases) for a, cases in by_analyst.items()})

    # Report completeness
    def _analyst_report(a: str, cases: list[dict]) -> str:
        comps = []
        for s in cases:
            cid = s.get("case_id")
            if cid and cid in report_by_case:
                c = report_by_case[cid].get("completeness_pct")
                if c is not None:
                    comps.append(c)
        return f"{statistics.mean(comps):.0f}%" if comps else "-"

    _row("Report complete (avg)", {a: _analyst_report(a, cases) for a, cases in by_analyst.items()})

    # Verdict confidence
    def _analyst_confidence(a: str, cases: list[dict]) -> str:
        high = med = low = 0
        for s in cases:
            cid = s.get("case_id")
            if cid and cid in verdict_by_case:
                dist = verdict_by_case[cid].get("confidence_dist", {})
                high += dist.get("HIGH", 0)
                med += dist.get("MEDIUM", 0)
                low += dist.get("LOW", 0)
        total = high + med + low
        if not total:
            return "-"
        return f"{high/total*100:.0f}%H {med/total*100:.0f}%M"

    _row("Verdict conf (H/M)", {a: _analyst_confidence(a, cases) for a, cases in by_analyst.items()})

    # Disposition breakdown
    print()
    print("Dispositions:")
    for a in analysts:
        disps: dict[str, int] = defaultdict(int)
        for s in by_analyst[a]:
            disps[s.get("disposition", "unknown")] += 1
        disp_str = ", ".join(f"{d}={c}" for d, c in sorted(disps.items(), key=lambda x: -x[1]))
        print(f"  {a:<20} {disp_str}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Query socai investigation metrics")
    parser.add_argument("--event", help="Filter by event type")
    parser.add_argument("--case", help="Filter by case ID")
    parser.add_argument("--analyst", help="Filter by analyst name")
    parser.add_argument("--since", help="Filter records after date (ISO 8601)")
    parser.add_argument("--compare", action="store_true", help="Side-by-side analyst comparison")
    parser.add_argument("--json", action="store_true", help="Raw JSON output")
    args = parser.parse_args()

    records = _load_records(
        event=args.event,
        case_id=args.case,
        analyst=args.analyst,
        since=args.since,
    )

    if not records:
        print("No metrics records found.", file=sys.stderr)
        if not METRICS_LOG.exists():
            print(f"  Metrics log not found at {METRICS_LOG}", file=sys.stderr)
            print(f"  Run some investigations to generate metrics.", file=sys.stderr)
        sys.exit(1)

    if args.json:
        for r in records:
            print(json.dumps(r))
        return

    if args.compare:
        # Load all records (not just filtered) for cross-referencing
        all_records = _load_records(since=args.since)
        _print_compare(all_records)
        return

    _print_summary(records)


if __name__ == "__main__":
    main()
