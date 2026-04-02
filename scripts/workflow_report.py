#!/usr/bin/env python3
"""Workflow analytics — analyse MCP tool sequences for friction and efficiency.

Reads ``workflow_summary`` events from ``registry/metrics.jsonl`` (emitted
automatically by the MCP session tracker on session expiry or server shutdown).

Usage:
    python3 scripts/workflow_report.py                      # full summary
    python3 scripts/workflow_report.py --since 2026-03-25   # last week
    python3 scripts/workflow_report.py --friction            # friction patterns only
    python3 scripts/workflow_report.py --case IV_CASE_042    # single case
    python3 scripts/workflow_report.py --sequences           # top tool sequences
    python3 scripts/workflow_report.py --json                # raw JSON output
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import METRICS_LOG


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _load_workflows(
    *,
    since: str | None = None,
    case_id: str | None = None,
) -> list[dict]:
    """Load workflow_summary events from metrics log."""
    if not METRICS_LOG.exists():
        return []

    since_dt = None
    if since:
        since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)

    records = []
    with open(METRICS_LOG) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            if rec.get("event") != "workflow_summary":
                continue
            if case_id and rec.get("case_id") != case_id:
                continue
            if since_dt:
                try:
                    ts = datetime.fromisoformat(
                        rec["ts"].replace("Z", "+00:00"))
                    if ts < since_dt:
                        continue
                except (KeyError, ValueError):
                    continue

            records.append(rec)

    return records


# ---------------------------------------------------------------------------
# Summary report
# ---------------------------------------------------------------------------

def _print_header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def _fmt_ms(ms: int | float) -> str:
    """Format milliseconds as human-readable duration."""
    if ms < 1000:
        return f"{int(ms)}ms"
    elif ms < 60_000:
        return f"{ms / 1000:.1f}s"
    else:
        return f"{ms / 60_000:.1f}m"


def _fmt_s(s: int | float) -> str:
    """Format seconds as human-readable duration."""
    if s < 60:
        return f"{int(s)}s"
    elif s < 3600:
        return f"{s / 60:.1f}m"
    else:
        return f"{s / 3600:.1f}h"


def report_summary(workflows: list[dict]) -> dict:
    """Generate a summary report dict."""
    if not workflows:
        return {"total_sessions": 0}

    # Basic counts
    total = len(workflows)
    case_sessions = [w for w in workflows if w.get("case_id")]
    adhoc_sessions = [w for w in workflows if not w.get("case_id")]

    # Timing
    wall_clocks = [w["wall_clock_s"] for w in workflows if "wall_clock_s" in w]
    tool_times = [w["tool_time_ms"] for w in workflows if "tool_time_ms" in w]
    step_counts = [w["step_count"] for w in workflows if "step_count" in w]

    # Goals
    goal_counts = Counter(w.get("goal_reached", "unknown") for w in workflows)

    # Friction
    all_friction = []
    for w in workflows:
        all_friction.extend(w.get("friction", []))
    friction_types = Counter(f["type"] for f in all_friction)
    sessions_with_friction = sum(1 for w in workflows if w.get("friction"))

    # Error rates
    total_errors = sum(w.get("error_count", 0) for w in workflows)
    total_steps = sum(w.get("step_count", 0) for w in workflows)

    # Category breakdown across all sessions
    cat_totals: Counter = Counter()
    for w in workflows:
        for cat, count in w.get("category_breakdown", {}).items():
            cat_totals[cat] += count

    summary = {
        "total_sessions": total,
        "case_sessions": len(case_sessions),
        "adhoc_sessions": len(adhoc_sessions),
        "total_steps": total_steps,
        "total_errors": total_errors,
        "error_rate_pct": round(total_errors / total_steps * 100, 1) if total_steps else 0,
        "goals": dict(goal_counts),
        "timing": {
            "median_wall_clock_s": int(statistics.median(wall_clocks)) if wall_clocks else 0,
            "mean_wall_clock_s": int(statistics.mean(wall_clocks)) if wall_clocks else 0,
            "median_tool_time_ms": int(statistics.median(tool_times)) if tool_times else 0,
            "mean_tool_time_ms": int(statistics.mean(tool_times)) if tool_times else 0,
            "median_steps": int(statistics.median(step_counts)) if step_counts else 0,
            "mean_steps": round(statistics.mean(step_counts), 1) if step_counts else 0,
        },
        "category_breakdown": dict(cat_totals.most_common()),
        "friction": {
            "sessions_with_friction": sessions_with_friction,
            "friction_rate_pct": round(sessions_with_friction / total * 100, 1) if total else 0,
            "total_friction_signals": len(all_friction),
            "by_type": dict(friction_types.most_common()),
        },
    }

    return summary


def print_summary(workflows: list[dict]) -> None:
    """Print a human-readable summary report."""
    s = report_summary(workflows)

    if s["total_sessions"] == 0:
        print("\nNo workflow data found. Workflow summaries are emitted when")
        print("MCP sessions expire (1h inactivity) or on server shutdown.")
        print("\nUse the MCP server normally — data will accumulate automatically.")
        return

    _print_header("WORKFLOW ANALYTICS SUMMARY")

    print(f"\n  Sessions:       {s['total_sessions']} total "
          f"({s['case_sessions']} case-bound, {s['adhoc_sessions']} ad-hoc)")
    print(f"  Total steps:    {s['total_steps']}")
    print(f"  Total errors:   {s['total_errors']} ({s['error_rate_pct']}% error rate)")

    print(f"\n  Goals reached:")
    for goal, count in s["goals"].items():
        pct = round(count / s["total_sessions"] * 100, 1)
        print(f"    {goal:<20} {count:>4}  ({pct}%)")

    t = s["timing"]
    print(f"\n  Timing (median / mean):")
    print(f"    Wall clock:   {_fmt_s(t['median_wall_clock_s'])} / {_fmt_s(t['mean_wall_clock_s'])}")
    print(f"    Tool time:    {_fmt_ms(t['median_tool_time_ms'])} / {_fmt_ms(t['mean_tool_time_ms'])}")
    print(f"    Steps:        {t['median_steps']} / {t['mean_steps']}")

    print(f"\n  Tool categories:")
    for cat, count in s["category_breakdown"].items():
        pct = round(count / s["total_steps"] * 100, 1) if s["total_steps"] else 0
        print(f"    {cat:<16} {count:>5}  ({pct}%)")

    f = s["friction"]
    print(f"\n  Friction:")
    print(f"    Sessions affected:  {f['sessions_with_friction']} "
          f"({f['friction_rate_pct']}%)")
    print(f"    Total signals:      {f['total_friction_signals']}")
    if f["by_type"]:
        for ftype, count in f["by_type"].items():
            print(f"      {ftype:<28} {count:>4}")


# ---------------------------------------------------------------------------
# Friction detail report
# ---------------------------------------------------------------------------

def print_friction(workflows: list[dict]) -> None:
    """Print detailed friction analysis."""
    _print_header("FRICTION ANALYSIS")

    friction_sessions = [w for w in workflows if w.get("friction")]
    if not friction_sessions:
        print("\n  No friction detected. All workflows ran cleanly.")
        return

    print(f"\n  {len(friction_sessions)} session(s) with friction "
          f"(out of {len(workflows)} total)\n")

    # Group friction by type with examples
    by_type: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for w in friction_sessions:
        for f in w.get("friction", []):
            by_type[f["type"]].append((f, w))

    for ftype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
        print(f"  {ftype} ({len(items)} occurrence(s))")
        print(f"  {'-' * 50}")

        # Show up to 3 examples
        for f, w in items[:3]:
            case = w.get("case_id", "ad-hoc")
            sid = w.get("session_id", "?")[:20]
            print(f"    [{case}] {f.get('detail', '')}")

            if ftype == "long_gap":
                gap = f.get("gap_seconds", 0)
                print(f"      Gap: {_fmt_s(gap)}")

            if ftype == "unnecessary_prerequisite" and "step_range" in f:
                steps = w.get("steps", [])
                sr = f["step_range"]
                for s in steps[sr[0]-1:sr[1]]:
                    print(f"      Step {s['seq']}: {s['tool']} ({_fmt_ms(s['duration_ms'])})")

        if len(items) > 3:
            print(f"    ... and {len(items) - 3} more")
        print()


# ---------------------------------------------------------------------------
# Tool sequence patterns
# ---------------------------------------------------------------------------

def print_sequences(workflows: list[dict]) -> None:
    """Print most common tool call sequences."""
    _print_header("TOOL SEQUENCE PATTERNS")

    # Extract tool sequences (just names)
    sequences: list[tuple[str, ...]] = []
    for w in workflows:
        steps = w.get("steps", [])
        if steps:
            seq = tuple(s["tool"] for s in steps)
            sequences.append(seq)

    if not sequences:
        print("\n  No sequences recorded yet.")
        return

    # Full sequences
    seq_counts = Counter(sequences)
    print(f"\n  Top 10 complete sequences (of {len(sequences)} total):\n")
    for seq, count in seq_counts.most_common(10):
        tools = " → ".join(seq)
        print(f"    {count:>3}x  {tools}")

    # Bigrams (consecutive tool pairs)
    bigrams: Counter = Counter()
    for seq in sequences:
        for i in range(len(seq) - 1):
            bigrams[(seq[i], seq[i+1])] += 1

    print(f"\n  Top 15 tool transitions:\n")
    for (a, b), count in bigrams.most_common(15):
        print(f"    {count:>3}x  {a} → {b}")

    # Category sequences
    cat_sequences: list[tuple[str, ...]] = []
    for w in workflows:
        steps = w.get("steps", [])
        if steps:
            cats = tuple(s.get("category", "?") for s in steps)
            cat_sequences.append(cats)

    cat_counts = Counter(cat_sequences)
    print(f"\n  Top 10 category patterns:\n")
    for cats, count in cat_counts.most_common(10):
        pattern = " → ".join(cats)
        print(f"    {count:>3}x  {pattern}")


# ---------------------------------------------------------------------------
# Per-tool efficiency
# ---------------------------------------------------------------------------

def print_tool_stats(workflows: list[dict]) -> None:
    """Print per-tool timing and error statistics."""
    _print_header("PER-TOOL STATISTICS")

    tool_data: dict[str, dict] = defaultdict(
        lambda: {"calls": 0, "errors": 0, "durations": []})

    for w in workflows:
        for s in w.get("steps", []):
            t = s["tool"]
            tool_data[t]["calls"] += 1
            tool_data[t]["durations"].append(s["duration_ms"])
            if not s.get("success", True):
                tool_data[t]["errors"] += 1

    if not tool_data:
        print("\n  No tool data yet.")
        return

    # Sort by call count descending
    sorted_tools = sorted(tool_data.items(), key=lambda x: -x[1]["calls"])

    print(f"\n  {'Tool':<32} {'Calls':>6} {'Errors':>7} "
          f"{'Err%':>5} {'Med':>8} {'Mean':>8} {'P95':>8}")
    print(f"  {'-'*32} {'-'*6} {'-'*7} {'-'*5} {'-'*8} {'-'*8} {'-'*8}")

    for tool, data in sorted_tools[:30]:
        calls = data["calls"]
        errors = data["errors"]
        err_pct = round(errors / calls * 100) if calls else 0
        durs = sorted(data["durations"])
        med = statistics.median(durs) if durs else 0
        mean = statistics.mean(durs) if durs else 0
        p95 = durs[int(len(durs) * 0.95)] if durs else 0

        print(f"  {tool:<32} {calls:>6} {errors:>7} "
              f"{err_pct:>4}% {_fmt_ms(med):>8} {_fmt_ms(mean):>8} {_fmt_ms(p95):>8}")


# ---------------------------------------------------------------------------
# Time-based trends
# ---------------------------------------------------------------------------

def print_trends(workflows: list[dict]) -> None:
    """Print daily/weekly trend summary."""
    _print_header("DAILY TRENDS")

    # Group by date
    by_date: dict[str, list[dict]] = defaultdict(list)
    for w in workflows:
        ts = w.get("started_ts") or w.get("ts", "")
        if ts:
            date = ts[:10]
            by_date[date].append(w)

    if not by_date:
        print("\n  No data to show trends.")
        return

    print(f"\n  {'Date':<12} {'Sessions':>9} {'Steps':>7} {'Errors':>7} "
          f"{'Friction':>9} {'Med Time':>9}")
    print(f"  {'-'*12} {'-'*9} {'-'*7} {'-'*7} {'-'*9} {'-'*9}")

    for date in sorted(by_date.keys()):
        wfs = by_date[date]
        sessions = len(wfs)
        steps = sum(w.get("step_count", 0) for w in wfs)
        errors = sum(w.get("error_count", 0) for w in wfs)
        friction = sum(1 for w in wfs if w.get("friction"))
        wall_clocks = [w["wall_clock_s"] for w in wfs if "wall_clock_s" in w]
        med_time = _fmt_s(statistics.median(wall_clocks)) if wall_clocks else "n/a"

        print(f"  {date:<12} {sessions:>9} {steps:>7} {errors:>7} "
              f"{friction:>9} {med_time:>9}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Workflow analytics — analyse MCP tool sequences for "
                    "friction and efficiency.")
    parser.add_argument("--since", help="Only include data from this date onwards (ISO)")
    parser.add_argument("--case", help="Filter to a specific case ID")
    parser.add_argument("--friction", action="store_true",
                        help="Show detailed friction analysis only")
    parser.add_argument("--sequences", action="store_true",
                        help="Show tool sequence patterns")
    parser.add_argument("--tools", action="store_true",
                        help="Show per-tool statistics")
    parser.add_argument("--trends", action="store_true",
                        help="Show daily trends")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON summary")

    args = parser.parse_args()

    workflows = _load_workflows(since=args.since, case_id=args.case)

    if args.json:
        summary = report_summary(workflows)
        print(json.dumps(summary, indent=2))
        return

    # Specific reports
    if args.friction:
        print_friction(workflows)
        return
    if args.sequences:
        print_sequences(workflows)
        return
    if args.tools:
        print_tool_stats(workflows)
        return
    if args.trends:
        print_trends(workflows)
        return

    # Full report
    print_summary(workflows)
    print_friction(workflows)
    print_sequences(workflows)
    print_tool_stats(workflows)
    print_trends(workflows)


if __name__ == "__main__":
    main()
