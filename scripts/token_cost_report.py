#!/usr/bin/env python3
"""Per-investigation token cost — join real Claude Code telemetry to MCP sessions.

socai never calls the model: all LLM reasoning happens in the client (Claude
Code / Desktop), so the only ground-truth token counts live in the client's
session transcripts. Claude Code writes one JSONL per session under
``~/.claude/projects/<encoded-cwd>/``; every ``assistant`` record carries a
``message.usage`` block (input / cache-read / cache-creation / output tokens)
and a ``timestamp``.

This script:
  1. Reads those transcripts (filtered to this repo by each record's ``cwd``).
  2. Loads ``workflow_summary`` events from ``registry/metrics.jsonl`` — each
     gives an investigation's time window (first→last tool call) plus the
     server-side ``est_result_tokens`` payload estimate.
  3. Attributes each assistant turn to the investigation whose window contains
     it (turns in no window → "unattributed": engineering chat, idle, etc.).
  4. Prices the real tokens in GBP and reports the **effective multiplier**
     (true input ÷ server-side payload estimate) — the calibration constant
     that lets you project cost from the cheap server-side metric alone.

The window join is approximate: interleaved investigations, context compaction,
and Desktop-driven sessions (no local transcript) all blur attribution. Treat
the per-investigation figures as good estimates and the aggregate
multiplier/cost as the reliable output.

Usage:
    python3 scripts/token_cost_report.py
    python3 scripts/token_cost_report.py --since 2026-06-01
    python3 scripts/token_cost_report.py --case IV_CASE_166
    python3 scripts/token_cost_report.py --gbp 0.74 --json
    python3 scripts/token_cost_report.py --transcripts /path/to/project/dir
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from config.settings import METRICS_LOG

# ---------------------------------------------------------------------------
# Pricing — Anthropic API list prices, USD per MILLION tokens.
# VERIFY before relying on these for billing: prices change. Confirm current
# rates at https://www.anthropic.com/pricing before quoting figures.
# ---------------------------------------------------------------------------
PRICING: dict[str, dict[str, float]] = {
    "opus":   {"input": 15.0, "output": 75.0},
    "sonnet": {"input": 3.0,  "output": 15.0},
    "haiku":  {"input": 1.0,  "output": 5.0},
}
_FALLBACK_TIER = "sonnet"          # used (with a warning) for unrecognised models
CACHE_READ_MULT = 0.10             # cache hit billed at 0.1x input
CACHE_WRITE_5M_MULT = 1.25         # 5-minute cache write
CACHE_WRITE_1H_MULT = 2.00         # 1-hour cache write
DEFAULT_GBP_PER_USD = 0.7446       # as of 2026-06-03; override with --gbp

# Window padding (seconds): the assistant turn that *requests* the first tool
# fires just before its result timestamp; the turn that *consumes* the last
# result fires after it.
DEFAULT_PRE_BUFFER = 30
DEFAULT_POST_BUFFER = 120


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    # Treat naive inputs (e.g. a bare --since date) as UTC so all comparisons
    # are between offset-aware datetimes.
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _model_tier(model: str | None) -> str | None:
    """Map a model id to a pricing tier, or None if unrecognised."""
    if not model:
        return None
    m = model.lower()
    for tier in ("opus", "sonnet", "haiku"):
        if tier in m:
            return tier
    return None


# ---------------------------------------------------------------------------
# Transcript loading (client ground truth)
# ---------------------------------------------------------------------------

def _default_transcript_dir() -> Path:
    """Encode the repo root the way Claude Code names its project dir."""
    encoded = "-" + str(REPO_ROOT).strip("/").replace("/", "-").replace(".", "-")
    return Path.home() / ".claude" / "projects" / encoded


def _load_turns(transcripts: Path | None) -> list[dict]:
    """Return assistant turns {ts, model, tier, usage, sidechain} for this repo.

    Records are filtered to this repo by their ``cwd`` field, so scanning a
    dir that holds transcripts for several cwds (or the whole projects tree)
    is safe.
    """
    search_dirs: list[Path] = []
    if transcripts:
        search_dirs = [transcripts]
    else:
        d = _default_transcript_dir()
        if d.is_dir():
            search_dirs = [d]
        else:
            # Fall back to scanning every project dir; cwd filter keeps us honest.
            root = Path.home() / ".claude" / "projects"
            search_dirs = [p for p in root.glob("*") if p.is_dir()] if root.is_dir() else []

    repo_str = str(REPO_ROOT)
    turns: list[dict] = []
    for d in search_dirs:
        for fp in d.glob("*.jsonl"):
            try:
                fh = fp.open()
            except OSError:
                continue
            with fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("type") != "assistant":
                        continue
                    if rec.get("cwd") != repo_str:
                        continue
                    msg = rec.get("message") or {}
                    # Skip client-generated synthetic turns (interrupted/error
                    # placeholders) — they carry a usage block but are not
                    # billable model calls.
                    if msg.get("model") == "<synthetic>":
                        continue
                    usage = msg.get("usage")
                    if not usage:
                        continue
                    ts = _parse_ts(rec.get("timestamp"))
                    if ts is None:
                        continue
                    turns.append({
                        "ts": ts,
                        "model": msg.get("model"),
                        "tier": _model_tier(msg.get("model")),
                        "usage": usage,
                        "sidechain": bool(rec.get("isSidechain")),
                    })
    turns.sort(key=lambda t: t["ts"])
    return turns


# ---------------------------------------------------------------------------
# Investigation windows (server-side sessions)
# ---------------------------------------------------------------------------

def _load_windows(*, since: str | None, case_id: str | None) -> list[dict]:
    """Build investigation time windows from workflow_summary events."""
    if not METRICS_LOG.exists():
        return []

    since_dt = _parse_ts(since) if since else None
    windows: list[dict] = []
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

            steps = rec.get("steps", [])
            step_ts = [t for t in (_parse_ts(s.get("ts")) for s in steps) if t]
            start = min(step_ts) if step_ts else _parse_ts(rec.get("started_ts"))
            if start is None:
                continue
            if step_ts:
                end = max(step_ts)
            else:
                end = start + timedelta(seconds=rec.get("wall_clock_s", 0))

            if since_dt and start < since_dt:
                continue

            windows.append({
                "case_id": rec.get("case_id", ""),
                "session_id": rec.get("session_id", ""),
                "caller": rec.get("caller", ""),
                "start": start,
                "end": end,
                "est_result_tokens": rec.get("est_result_tokens", 0),
                "est_context_input_tokens": rec.get("est_context_input_tokens", 0),
            })
    windows.sort(key=lambda w: w["start"])
    return windows


# ---------------------------------------------------------------------------
# Attribution + costing
# ---------------------------------------------------------------------------

def _attribute(turns: list[dict], windows: list[dict],
               pre: int, post: int) -> tuple[list[dict], list[dict]]:
    """Assign each turn to at most one window. Returns (windows, unattributed).

    Each window gets a padded [start-pre, end+post] span. A turn inside
    several spans goes to the one whose centre is nearest (interleaved
    investigations are rare but handled deterministically).
    """
    for w in windows:
        w["_lo"] = w["start"] - timedelta(seconds=pre)
        w["_hi"] = w["end"] + timedelta(seconds=post)
        w["_centre"] = w["start"] + (w["end"] - w["start"]) / 2
        w["turns"] = []

    unattributed: list[dict] = []
    for t in turns:
        candidates = [w for w in windows if w["_lo"] <= t["ts"] <= w["_hi"]]
        if not candidates:
            unattributed.append(t)
            continue
        best = min(candidates, key=lambda w: abs((t["ts"] - w["_centre"]).total_seconds()))
        best["turns"].append(t)
    return windows, unattributed


def _turn_cost_usd(turn: dict, default_tier: str, unknown: set[str]) -> dict:
    """Break a turn's usage into token totals and USD cost."""
    u = turn["usage"]
    tier = turn["tier"]
    if tier is None:
        tier = default_tier
        if turn["model"]:
            unknown.add(turn["model"])
    rate = PRICING[tier]

    fresh_in = u.get("input_tokens", 0)
    cache_read = u.get("cache_read_input_tokens", 0)
    output = u.get("output_tokens", 0)

    # Cache creation: prefer the 1h/5m breakdown (different write multipliers),
    # else fall back to the flat field and assume the cheaper 5m tier.
    cc = u.get("cache_creation") or {}
    cc_5m = cc.get("ephemeral_5m_input_tokens", 0)
    cc_1h = cc.get("ephemeral_1h_input_tokens", 0)
    if not cc:
        cc_5m = u.get("cache_creation_input_tokens", 0)
    cache_create = cc_5m + cc_1h

    in_rate = rate["input"] / 1_000_000
    out_rate = rate["output"] / 1_000_000
    cost = (
        fresh_in * in_rate
        + cache_read * in_rate * CACHE_READ_MULT
        + cc_5m * in_rate * CACHE_WRITE_5M_MULT
        + cc_1h * in_rate * CACHE_WRITE_1H_MULT
        + output * out_rate
    )
    return {
        "input_total": fresh_in + cache_read + cache_create,
        "fresh_in": fresh_in,
        "cache_read": cache_read,
        "cache_create": cache_create,
        "output": output,
        "cost_usd": cost,
    }


def _sum_costs(turns: list[dict], default_tier: str, unknown: set[str]) -> dict:
    agg = {"turns": len(turns), "input_total": 0, "fresh_in": 0,
           "cache_read": 0, "cache_create": 0, "output": 0, "cost_usd": 0.0}
    for t in turns:
        c = _turn_cost_usd(t, default_tier, unknown)
        for k in ("input_total", "fresh_in", "cache_read", "cache_create", "output"):
            agg[k] += c[k]
        agg["cost_usd"] += c["cost_usd"]
    return agg


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_report(*, since: str | None, case_id: str | None, gbp: float,
                 transcripts: Path | None, pre: int, post: int,
                 default_tier: str) -> dict:
    turns = _load_turns(transcripts)
    windows = _load_windows(since=since, case_id=case_id)
    windows, unattributed = _attribute(turns, windows, pre, post)

    unknown: set[str] = set()
    investigations = []
    for w in windows:
        agg = _sum_costs(w["turns"], default_tier, unknown)
        est = w["est_result_tokens"]
        investigations.append({
            "case_id": w["case_id"],
            "session_id": w["session_id"],
            "caller": w["caller"],
            "start": w["start"].isoformat(),
            "turns": agg["turns"],
            "true_input_tokens": agg["input_total"],
            "cache_read_tokens": agg["cache_read"],
            "output_tokens": agg["output"],
            "cost_usd": round(agg["cost_usd"], 4),
            "cost_gbp": round(agg["cost_usd"] * gbp, 4),
            "est_result_tokens": est,
            # Effective multiplier: how much real input the model billed per
            # token of raw payload socai shipped (system prompt + tool schemas
            # + per-turn re-send all live in here; caching pulls it back down).
            "multiplier": round(agg["input_total"] / est, 1) if est else None,
        })

    un_agg = _sum_costs(unattributed, default_tier, unknown)
    multipliers = [i["multiplier"] for i in investigations
                   if i["multiplier"] is not None and i["turns"] > 0]
    total_inv_usd = sum(i["cost_usd"] for i in investigations)

    return {
        "gbp_per_usd": gbp,
        "transcript_turns": len(turns),
        "investigations": investigations,
        "investigation_count": len(investigations),
        "with_telemetry": sum(1 for i in investigations if i["turns"] > 0),
        "median_multiplier": round(statistics.median(multipliers), 1) if multipliers else None,
        "investigation_cost_gbp": round(total_inv_usd * gbp, 2),
        "unattributed": {
            "turns": un_agg["turns"],
            "cost_gbp": round(un_agg["cost_usd"] * gbp, 2),
        },
        "unknown_models": sorted(unknown),
        "default_tier": default_tier,
    }


def print_report(rep: dict) -> None:
    print(f"\n{'=' * 72}")
    print("  PER-INVESTIGATION TOKEN COST  (real client telemetry)")
    print(f"{'=' * 72}")

    if rep["transcript_turns"] == 0:
        print("\n  No Claude Code transcripts found for this repo.")
        print(f"  Looked in: {_default_transcript_dir()}")
        print("  Pass --transcripts <dir> if your project dir differs, or run")
        print("  some investigations through the TUI first.")
        return

    print(f"\n  Transcript turns: {rep['transcript_turns']}   "
          f"GBP/USD: {rep['gbp_per_usd']}   "
          f"Investigations: {rep['investigation_count']} "
          f"({rep['with_telemetry']} with TUI telemetry)")
    if rep["unknown_models"]:
        print(f"  ! Unrecognised model(s) priced as '{rep['default_tier']}': "
              f"{', '.join(rep['unknown_models'])}")

    rows = [i for i in rep["investigations"] if i["turns"] > 0]
    if rows:
        print(f"\n  {'Case':<16} {'Turns':>5} {'TrueIn':>10} {'CacheRd':>10} "
              f"{'Out':>8} {'£':>8} {'Mult':>6}")
        print(f"  {'-'*16} {'-'*5} {'-'*10} {'-'*10} {'-'*8} {'-'*8} {'-'*6}")
        for i in sorted(rows, key=lambda x: -x["cost_gbp"])[:40]:
            mult = f"{i['multiplier']}x" if i["multiplier"] is not None else "-"
            case = (i["case_id"] or "(ad-hoc)")[:16]
            print(f"  {case:<16} {i['turns']:>5} {i['true_input_tokens']:>10,} "
                  f"{i['cache_read_tokens']:>10,} {i['output_tokens']:>8,} "
                  f"£{i['cost_gbp']:>7.2f} {mult:>6}")

    no_tel = [i for i in rep["investigations"] if i["turns"] == 0]
    if no_tel:
        print(f"\n  {len(no_tel)} investigation(s) had no local telemetry "
              "(Desktop-driven or pre-dating telemetry) — not costed.")

    print(f"\n  Investigation total:  £{rep['investigation_cost_gbp']:.2f}")
    print(f"  Unattributed turns:   {rep['unattributed']['turns']} "
          f"(£{rep['unattributed']['cost_gbp']:.2f}) — engineering/chat, not investigations")
    if rep["median_multiplier"] is not None:
        print(f"\n  Median effective multiplier: {rep['median_multiplier']}x")
        print("    → true input tokens per token of raw payload socai shipped.")
        print("    Project cost from the cheap server-side estimate:")
        print("    est_result_tokens × multiplier × input_rate × GBP.")
    print("\n  NOTE: window-based attribution is approximate; verify pricing")
    print("        constants at anthropic.com/pricing before quoting figures.")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Per-investigation token cost from real Claude Code telemetry.")
    ap.add_argument("--since", help="Only investigations starting on/after this date (ISO)")
    ap.add_argument("--case", help="Filter to a single case ID")
    ap.add_argument("--gbp", type=float, default=DEFAULT_GBP_PER_USD,
                    help=f"GBP per USD (default {DEFAULT_GBP_PER_USD})")
    ap.add_argument("--transcripts", type=Path,
                    help="Claude Code project transcript dir (default: auto-detect)")
    ap.add_argument("--pre-buffer", type=int, default=DEFAULT_PRE_BUFFER,
                    help=f"Seconds before first tool call to include (default {DEFAULT_PRE_BUFFER})")
    ap.add_argument("--post-buffer", type=int, default=DEFAULT_POST_BUFFER,
                    help=f"Seconds after last tool call to include (default {DEFAULT_POST_BUFFER})")
    ap.add_argument("--tier", default=_FALLBACK_TIER, choices=list(PRICING),
                    help=f"Pricing tier for unrecognised models (default {_FALLBACK_TIER})")
    ap.add_argument("--json", action="store_true", help="Raw JSON output")
    args = ap.parse_args()

    rep = build_report(
        since=args.since, case_id=args.case, gbp=args.gbp,
        transcripts=args.transcripts, pre=args.pre_buffer, post=args.post_buffer,
        default_tier=args.tier,
    )

    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print_report(rep)


if __name__ == "__main__":
    main()
