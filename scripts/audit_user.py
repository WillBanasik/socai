#!/usr/bin/env python3
"""User activity audit — reconstruct what each analyst did via MCP.

Usage:
    python3 scripts/audit_user.py                            # all users, full window
    python3 scripts/audit_user.py --user will@perf.com       # one user
    python3 scripts/audit_user.py --since 2026-05-15         # last few days
    python3 scripts/audit_user.py --errors-only              # only failed calls
    python3 scripts/audit_user.py --json                     # machine-readable
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.audit_user import audit_user, SLOW_CALL_THRESHOLD_MS


def _fmt_ms(ms: int) -> str:
    if ms < 1000:
        return f"{ms}ms"
    if ms < 60_000:
        return f"{ms / 1000:.1f}s"
    return f"{ms / 60_000:.1f}m"


def _print_text(report: dict) -> None:
    s = report["summary"]
    meta = report["_meta"]

    print("=" * 70)
    print("  USER ACTIVITY AUDIT")
    print("=" * 70)
    flt = []
    if meta["user_filter"]:
        flt.append(f"user={meta['user_filter']}")
    if meta["since"]:
        flt.append(f"since={meta['since']}")
    if meta["until"]:
        flt.append(f"until={meta['until']}")
    if meta["errors_only"]:
        flt.append("errors-only")
    if flt:
        print(f"  Filters: {', '.join(flt)}")
    print(f"  Scanned {meta['events_scanned']} log events, matched {meta['events_matched']}"
          f"{' (TRUNCATED)' if meta['truncated'] else ''}")
    print()
    print(f"  Total tool calls   : {s['total_calls']}")
    print(f"  Failures           : {s['total_failures']} ({100*s['failure_rate']:.1f}%)")
    print(f"  Distinct users     : {s['distinct_users']}")
    print(f"  Distinct tools     : {s['distinct_tools']}")
    print(f"  Slow calls (>{SLOW_CALL_THRESHOLD_MS // 1000}s) : {s['slow_call_count']}")
    print()

    # Per-user breakdown
    if report["users"]:
        print("-" * 70)
        print("  PER-USER BREAKDOWN")
        print("-" * 70)
        for u in report["users"]:
            print(f"\n  {u['caller']}")
            print(f"    Calls          : {u['calls']}  ({u['successes']} ok / {u['failures']} failed)")
            print(f"    Failure rate   : {100 * u['failure_rate']:.1f}%")
            print(f"    Avg duration   : {_fmt_ms(u['avg_duration_ms'])}")
            print(f"    Max duration   : {_fmt_ms(u['max_duration_ms'])}")
            print(f"    First seen     : {u['first_seen']}")
            print(f"    Last seen      : {u['last_seen']}")
            print(f"    Cases touched  : {len(u['cases_touched'])}"
                  + (f" ({', '.join(u['cases_touched'][:5])}{'...' if len(u['cases_touched']) > 5 else ''})"
                     if u["cases_touched"] else ""))
            print(f"    Top tools      :")
            for tool, n in list(u["tools"].items())[:5]:
                fails = u["tool_failures"].get(tool, 0)
                fail_part = f" ({fails} failed)" if fails else ""
                print(f"      {n:4} {tool}{fail_part}")
        print()

    # Errors
    if report["errors"]:
        print("-" * 70)
        print(f"  ERRORS ({len(report['errors'])})")
        print("-" * 70)
        for e in report["errors"][:50]:
            ts = e.get("ts", "")
            tool = e.get("tool", "")
            caller = e.get("caller", "")
            case = e.get("case_id", "")
            err = e.get("error", "")
            # Trim "Error executing tool X: " prefix if present
            if err.startswith(f"Error executing tool {tool}: "):
                err = err[len(f"Error executing tool {tool}: "):]
            case_part = f" case={case}" if case else ""
            print(f"  {ts}  {caller}  {tool}{case_part}")
            print(f"      ! {err[:200]}")
        if len(report["errors"]) > 50:
            print(f"\n  ... and {len(report['errors']) - 50} more (use --json for full list)")
        print()

    # Slow calls
    if report["slow_calls"]:
        print("-" * 70)
        print(f"  SLOW CALLS (>{SLOW_CALL_THRESHOLD_MS // 1000}s, top 10)")
        print("-" * 70)
        for sc in report["slow_calls"][:10]:
            ts = sc.get("ts", "")
            tool = sc.get("tool", "")
            caller = sc.get("caller", "")
            d = sc.get("duration_ms", 0)
            case = sc.get("case_id", "")
            case_part = f" case={case}" if case else ""
            print(f"  {ts}  {caller}  {tool} ({_fmt_ms(d)}){case_part}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit MCP tool activity per user.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--user", help="Filter to a single caller email (substring match)")
    parser.add_argument("--since", help="ISO date/timestamp, e.g. 2026-05-15 or 2026-05-15T09:00:00Z")
    parser.add_argument("--until", help="ISO date/timestamp (exclusive upper bound)")
    parser.add_argument("--errors-only", action="store_true",
                        help="Only show failed calls in timeline / count")
    parser.add_argument("--max-events", type=int, default=5000,
                        help="Cap on events scanned (default 5000)")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON instead of formatted text")
    args = parser.parse_args()

    report = audit_user(
        user=args.user,
        since=args.since,
        until=args.until,
        errors_only=args.errors_only,
        max_events=args.max_events,
    )

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_text(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
