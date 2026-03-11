"""
tool: mcp_usage
---------------
On-demand analysis of MCP server usage data from registry/mcp_usage.jsonl.

Aggregates calls by tool and caller; computes error rates; surfaces recent
failures. Follows the same pattern as ``tools/assess_errors.py``.

Usage (standalone):
  python3 tools/mcp_usage.py
  python3 tools/mcp_usage.py --top 10
  python3 tools/mcp_usage.py --tool investigate
  python3 tools/mcp_usage.py --caller local
  python3 tools/mcp_usage.py --json
  python3 tools/mcp_usage.py --clear
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import MCP_USAGE_LOG


def _load_records(
    caller_filter: str | None = None,
    tool_filter: str | None = None,
) -> list[dict]:
    """Load usage records from the JSONL log, with optional filters."""
    if not MCP_USAGE_LOG.exists():
        return []
    records: list[dict] = []
    with open(MCP_USAGE_LOG, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if caller_filter and rec.get("caller") != caller_filter:
                continue
            if tool_filter and rec.get("tool") != tool_filter:
                continue
            records.append(rec)
    return records


def assess_mcp_usage(
    top_n: int = 20,
    caller_filter: str | None = None,
    tool_filter: str | None = None,
    json_output: bool = False,
) -> dict:
    """Analyse mcp_usage.jsonl and return an aggregated summary."""
    records = _load_records(caller_filter, tool_filter)
    if not records:
        result = {
            "status": "empty",
            "message": "No MCP usage recorded yet.",
            "total_calls": 0,
        }
        if not json_output:
            print(result["message"])
        return result

    # --- Aggregation ---
    by_tool: dict[str, dict] = defaultdict(lambda: {
        "calls": 0, "success": 0, "failure": 0, "total_ms": 0,
        "errors": [],
    })
    by_caller: Counter[str] = Counter()
    total_success = 0
    total_failure = 0
    total_ms = 0
    timeline: Counter[str] = Counter()
    recent_errors: list[dict] = []

    for rec in records:
        tool = rec.get("tool", "unknown")
        caller = rec.get("caller", "unknown")
        success = rec.get("success", True)
        duration = rec.get("duration_ms", 0)
        ts_str = rec.get("ts", "")

        entry = by_tool[tool]
        entry["calls"] += 1
        entry["total_ms"] += duration
        if success:
            entry["success"] += 1
            total_success += 1
        else:
            entry["failure"] += 1
            total_failure += 1
            err = rec.get("error", "")
            if len(entry["errors"]) < 3 and err not in entry["errors"]:
                entry["errors"].append(err)
            recent_errors.append({
                "ts": ts_str, "tool": tool, "caller": caller,
                "error": (err or "")[:200], "duration_ms": duration,
            })

        by_caller[caller] += 1
        total_ms += duration
        if ts_str:
            timeline[ts_str[:10]] += 1

    # --- Per-tool summary ---
    tool_stats: list[dict] = []
    for tool, data in by_tool.items():
        calls = data["calls"]
        err_rate = (data["failure"] / calls * 100) if calls else 0
        avg_ms = data["total_ms"] // calls if calls else 0
        tool_stats.append({
            "tool": tool,
            "calls": calls,
            "success": data["success"],
            "failure": data["failure"],
            "error_rate_pct": round(err_rate, 1),
            "avg_ms": avg_ms,
            "sample_errors": data["errors"],
        })
    tool_stats.sort(key=lambda x: x["calls"], reverse=True)
    top_tools = tool_stats[:top_n]

    # --- Per-caller summary ---
    caller_stats = [
        {"caller": c, "calls": n} for c, n in by_caller.most_common()
    ]

    # Recent errors (last 10, newest first)
    recent_errors = recent_errors[-10:][::-1]

    total = len(records)
    err_rate = (total_failure / total * 100) if total else 0

    result = {
        "status": "ok",
        "total_calls": total,
        "total_success": total_success,
        "total_failure": total_failure,
        "error_rate_pct": round(err_rate, 1),
        "avg_duration_ms": total_ms // total if total else 0,
        "unique_tools": len(by_tool),
        "unique_callers": len(by_caller),
        "date_range": {
            "earliest": min(timeline.keys()) if timeline else None,
            "latest": max(timeline.keys()) if timeline else None,
        },
        "top_tools": top_tools,
        "callers": caller_stats,
        "recent_errors": recent_errors,
        "daily_volume": dict(sorted(timeline.items())),
    }

    if json_output:
        return result

    # --- Pretty print ---
    print(f"\n{'='*70}")
    print(f"  MCP USAGE REPORT")
    print(f"{'='*70}")
    print(f"  Total calls: {total}  (success: {total_success}, failure: {total_failure})")
    print(f"  Error rate: {err_rate:.1f}%")
    print(f"  Avg duration: {result['avg_duration_ms']}ms")
    print(f"  Unique tools: {len(by_tool)}, Unique callers: {len(by_caller)}")
    if timeline:
        print(f"  Date range: {min(timeline.keys())} to {max(timeline.keys())}")
    print()

    # Tool table
    print(f"  {'RANK':<5} {'CALLS':>6} {'OK':>5} {'ERR':>4} {'ERR%':>6} {'AVG ms':>7}  TOOL")
    print(f"  {'-'*5} {'-'*6} {'-'*5} {'-'*4} {'-'*6} {'-'*7}  {'-'*30}")
    for i, t in enumerate(top_tools, 1):
        print(
            f"  {i:<5} {t['calls']:>6} {t['success']:>5} {t['failure']:>4} "
            f"{t['error_rate_pct']:>5.1f}% {t['avg_ms']:>7}  {t['tool']}"
        )

    if caller_stats:
        print()
        print(f"  CALLERS")
        print(f"  {'-'*40}")
        for c in caller_stats:
            print(f"  {c['caller']:<20} {c['calls']} calls")

    if recent_errors:
        print()
        print(f"  RECENT ERRORS (newest first)")
        print(f"  {'-'*60}")
        for e in recent_errors[:7]:
            err_short = e["error"][:80].replace("\n", " ")
            print(f"  {e['ts'][:19]}  {e['tool']:<20} {err_short}")

    if len(timeline) > 1:
        print()
        print(f"  DAILY VOLUME")
        print(f"  {'-'*40}")
        for date, count in sorted(timeline.items()):
            bar = "#" * min(count, 50)
            print(f"  {date}  {count:>4}  {bar}")

    print(f"\n{'='*70}\n")
    return result


def clear_mcp_usage_log() -> dict:
    """Truncate the usage log. Returns count of records removed."""
    count = 0
    if MCP_USAGE_LOG.exists():
        with open(MCP_USAGE_LOG, "r") as fh:
            count = sum(1 for line in fh if line.strip())
        MCP_USAGE_LOG.unlink()
    return {"cleared": count}


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Assess MCP server usage data.")
    p.add_argument("--top", type=int, default=20, help="Top N tools to show (default 20)")
    p.add_argument("--tool", default=None, help="Filter by tool name")
    p.add_argument("--caller", default=None, help="Filter by caller")
    p.add_argument("--json", action="store_true", dest="json_output",
                   help="Output raw JSON instead of formatted report")
    p.add_argument("--clear", action="store_true",
                   help="Clear the usage log after assessment")
    args = p.parse_args()

    result = assess_mcp_usage(
        top_n=args.top, caller_filter=args.caller,
        tool_filter=args.tool, json_output=args.json_output,
    )
    if args.json_output:
        print(json.dumps(result, indent=2))

    if args.clear:
        cleared = clear_mcp_usage_log()
        print(f"Cleared {cleared['cleared']} usage records.")
