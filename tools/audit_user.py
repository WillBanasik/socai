"""User activity audit — reconstruct what each analyst did via MCP.

Reads ``tool_result`` and ``tool_error`` events from ``registry/mcp_server.jsonl``
(plus rotated backups ``mcp_server.jsonl.1``, ``.2``, ``.3``) and aggregates
per-caller activity with errors highlighted.

Designed to be called from both ``scripts/audit_user.py`` (CLI) and an MCP tool
so a single query backend powers both.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.settings import MCP_SERVER_LOG


SLOW_CALL_THRESHOLD_MS = 30_000  # >30s flagged as slow


def _iter_log_files() -> list[Path]:
    """Return all MCP server log files (current + rotated backups), newest first."""
    files = [MCP_SERVER_LOG]
    for i in range(1, 4):
        rotated = MCP_SERVER_LOG.with_suffix(MCP_SERVER_LOG.suffix + f".{i}")
        if rotated.exists():
            files.append(rotated)
    return files


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Always return UTC-aware so naive user-supplied dates compare with log Zs.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def audit_user(
    *,
    user: str | None = None,
    since: str | None = None,
    until: str | None = None,
    errors_only: bool = False,
    max_events: int = 5000,
) -> dict[str, Any]:
    """Return a structured audit of MCP tool activity.

    Parameters
    ----------
    user
        Filter to a single caller email. ``None`` returns activity for all users.
    since, until
        ISO 8601 timestamps (e.g. ``"2026-05-15"`` or ``"2026-05-15T09:00:00Z"``).
        Inclusive lower bound, exclusive upper bound. ``None`` = unbounded.
    errors_only
        If True, only return failed calls in the timeline.
    max_events
        Cap on the number of events scanned (newest first). Prevents runaway
        scans on multi-GB logs. Defaults to 5000.

    Returns
    -------
    A dict with keys:
        ``summary``         — totals and aggregates per user
        ``users``           — per-user breakdown of tools/errors/cases
        ``timeline``        — chronological list of events (oldest first)
        ``errors``          — every failed call with details
        ``slow_calls``      — calls exceeding SLOW_CALL_THRESHOLD_MS
        ``_meta``           — query parameters and scan stats
    """
    since_dt = _parse_ts(since) if since else None
    until_dt = _parse_ts(until) if until else None

    # Per-user accumulators
    per_user: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "caller": "",
        "calls": 0,
        "successes": 0,
        "failures": 0,
        "total_duration_ms": 0,
        "max_duration_ms": 0,
        "tools": Counter(),
        "tool_failures": Counter(),
        "cases_touched": set(),
        "first_seen": None,
        "last_seen": None,
    })
    timeline: list[dict] = []
    errors: list[dict] = []
    slow_calls: list[dict] = []
    scanned = 0
    matched = 0

    for log_path in _iter_log_files():
        if not log_path.exists():
            continue
        with open(log_path) as fh:
            for line in fh:
                scanned += 1
                try:
                    r = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue

                ev = r.get("event", "")
                if ev not in ("tool_result", "tool_error"):
                    continue

                caller = r.get("caller", "")
                if user and caller != user:
                    continue

                ts = r.get("ts", "")
                ts_dt = _parse_ts(ts)
                if since_dt and ts_dt and ts_dt < since_dt:
                    continue
                if until_dt and ts_dt and ts_dt >= until_dt:
                    continue

                tool = r.get("tool", "")
                duration_ms = r.get("duration_ms", 0) or 0
                case_id = r.get("case_id") or ""
                is_error = (ev == "tool_error")

                if errors_only and not is_error:
                    continue

                matched += 1
                if matched > max_events:
                    break

                bucket = per_user[caller]
                bucket["caller"] = caller
                bucket["calls"] += 1
                bucket["total_duration_ms"] += duration_ms
                bucket["max_duration_ms"] = max(bucket["max_duration_ms"], duration_ms)
                bucket["tools"][tool] += 1
                if case_id:
                    bucket["cases_touched"].add(case_id)
                if ts:
                    if not bucket["first_seen"] or ts < bucket["first_seen"]:
                        bucket["first_seen"] = ts
                    if not bucket["last_seen"] or ts > bucket["last_seen"]:
                        bucket["last_seen"] = ts

                event_rec: dict[str, Any] = {
                    "ts": ts,
                    "caller": caller,
                    "tool": tool,
                    "duration_ms": duration_ms,
                    "case_id": case_id,
                    "success": not is_error,
                }
                if is_error:
                    bucket["failures"] += 1
                    bucket["tool_failures"][tool] += 1
                    err_msg = r.get("error", "")[:300]
                    event_rec["error"] = err_msg
                    errors.append(event_rec)
                else:
                    bucket["successes"] += 1

                if duration_ms >= SLOW_CALL_THRESHOLD_MS:
                    slow_calls.append(event_rec)

                timeline.append(event_rec)

            if matched > max_events:
                break

    # Sort timeline oldest-first
    timeline.sort(key=lambda r: r.get("ts", ""))
    errors.sort(key=lambda r: r.get("ts", ""))
    slow_calls.sort(key=lambda r: r["duration_ms"], reverse=True)

    # Finalise per-user dicts (convert sets/Counters to JSON-friendly types)
    users_out = []
    for caller, b in per_user.items():
        avg_ms = (b["total_duration_ms"] / b["calls"]) if b["calls"] else 0
        users_out.append({
            "caller": caller,
            "calls": b["calls"],
            "successes": b["successes"],
            "failures": b["failures"],
            "failure_rate": round(b["failures"] / b["calls"], 3) if b["calls"] else 0,
            "avg_duration_ms": int(avg_ms),
            "max_duration_ms": b["max_duration_ms"],
            "tools": dict(b["tools"].most_common()),
            "tool_failures": dict(b["tool_failures"].most_common()),
            "cases_touched": sorted(b["cases_touched"]),
            "first_seen": b["first_seen"],
            "last_seen": b["last_seen"],
        })
    users_out.sort(key=lambda u: u["calls"], reverse=True)

    total_calls = sum(u["calls"] for u in users_out)
    total_failures = sum(u["failures"] for u in users_out)

    return {
        "summary": {
            "total_calls": total_calls,
            "total_failures": total_failures,
            "failure_rate": round(total_failures / total_calls, 3) if total_calls else 0,
            "distinct_users": len(users_out),
            "distinct_tools": len({t for u in users_out for t in u["tools"]}),
            "slow_call_count": len(slow_calls),
        },
        "users": users_out,
        "timeline": timeline,
        "errors": errors,
        "slow_calls": slow_calls,
        "_meta": {
            "user_filter": user,
            "since": since,
            "until": until,
            "errors_only": errors_only,
            "events_scanned": scanned,
            "events_matched": matched,
            "max_events_cap": max_events,
            "truncated": matched > max_events,
        },
    }
