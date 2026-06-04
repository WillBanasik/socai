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

Windows come from the live per-call log (registry/mcp_usage.jsonl, written
synchronously) by default, so an investigation is costable the moment it ends —
no waiting for the workflow_summary flush. Use --source summary for the flushed
aggregates. --project-api estimates what the same steps would cost an
API-driven agent (re-prices socai's client-agnostic payload estimate at a
target model + your caching/overhead assumptions) — works even with no local
transcripts.

Usage:
    python3 scripts/token_cost_report.py                       # recent, live
    python3 scripts/token_cost_report.py --case IV_CASE_166    # one case, true £
    python3 scripts/token_cost_report.py --source summary --since 2026-06-01
    python3 scripts/token_cost_report.py --case IV_CASE_166 --project-api --api-model sonnet
    python3 scripts/token_cost_report.py --case IV_CASE_166 --reprice sonnet
    python3 scripts/token_cost_report.py --case IV_CASE_165 \
        --from 2026-06-03T20:24:00 --to 2026-06-03T21:24:00 --reprice sonnet
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

from config.settings import METRICS_LOG, MCP_USAGE_LOG

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

# --- API projection defaults (--project-api) ----------------------------
# These are assumptions about a hypothetical API-driven agent doing the same
# investigation steps, NOT measurements. Override them per your real agent.
#
# api_system_tokens: fixed per-request overhead the agent re-sends every turn
#   — its system prompt + the socai MCP tool schemas (socai exposes 80+ tools;
#   the full schema set is the bulk of this). Rough default; measure yours.
# api_cache_hit: fraction of re-sent input served from cache (0.1x) rather than
#   billed fresh. A well-built agent caches the stable prefix → ~0.9.
# api_output_tokens: model output for the whole investigation. Least
#   transferable of all; set from your own runs.
DEFAULT_API_MODEL = "sonnet"
DEFAULT_API_SYSTEM_TOKENS = 25_000
DEFAULT_API_CACHE_HIT = 0.9
DEFAULT_API_OUTPUT_TOKENS = 8_000


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
                "step_count": rec.get("step_count", len(steps)),
                "est_result_tokens": rec.get("est_result_tokens", 0),
                "est_context_input_tokens": rec.get("est_context_input_tokens", 0),
            })
    windows.sort(key=lambda w: w["start"])
    return windows


def _case_from_session(session_id: str) -> str:
    """Recover the case id from an ``inv_<CASE>_<8hex>`` session id (else "")."""
    if session_id.startswith("inv_") and len(session_id) > 4 + 9:
        return session_id[4:-9]   # strip "inv_" prefix and "_<8hex>" suffix
    return ""


def _load_windows_live(*, since: str | None, case_id: str | None) -> list[dict]:
    """Build windows from the live per-call log (registry/mcp_usage.jsonl).

    Written synchronously on every tool call, so a just-finished investigation
    is costable immediately — no waiting for the workflow_summary flush (which
    only happens on 1h inactivity or server shutdown). Groups successful calls
    by session_id and reconstructs the same token fields the flush would emit.
    """
    if not MCP_USAGE_LOG.exists():
        return []

    since_dt = _parse_ts(since) if since else None
    by_session: dict[str, dict] = {}
    with open(MCP_USAGE_LOG) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = rec.get("session_id")
            if not sid:
                continue
            ts = _parse_ts(rec.get("ts"))
            if ts is None:
                continue
            cid = (rec.get("params") or {}).get("case_id") or _case_from_session(sid)
            entry = by_session.setdefault(sid, {
                "case_id": cid or "",
                "session_id": sid,
                "caller": rec.get("caller", ""),
                "calls": [],   # (ts, est_tokens) in log order
            })
            if cid and not entry["case_id"]:
                entry["case_id"] = cid
            entry["calls"].append((ts, rec.get("est_tokens", 0)))

    windows: list[dict] = []
    for entry in by_session.values():
        if case_id and entry["case_id"] != case_id:
            continue
        calls = sorted(entry["calls"], key=lambda c: c[0])
        ts_list = [c[0] for c in calls]
        start, end = ts_list[0], ts_list[-1]
        if since_dt and start < since_dt:
            continue
        n = len(calls)
        # Same definitions as the flush (see mcp_server.usage._flush_session).
        est_result = sum(tok for _, tok in calls)
        est_context = sum(tok * (n - i) for i, (_, tok) in enumerate(calls))
        windows.append({
            "case_id": entry["case_id"],
            "session_id": entry["session_id"],
            "caller": entry["caller"],
            "start": start,
            "end": end,
            "step_count": n,
            "est_result_tokens": est_result,
            "est_context_input_tokens": est_context,
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


def _turn_cost_usd(turn: dict, default_tier: str, unknown: set[str], *,
                   force_tier: str | None = None, no_cache: bool = False) -> dict:
    """Break a turn's usage into token totals and USD cost.

    ``force_tier`` re-prices the same measured token profile at another model
    (Opus→Sonnet etc.). ``no_cache`` bills cache reads/writes as ordinary fresh
    input — modelling an agent that doesn't implement prompt caching.
    """
    u = turn["usage"]
    tier = force_tier or turn["tier"]
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
    if no_cache:
        # Everything that was cached is re-sent as fresh input instead.
        cost = (fresh_in + cache_read + cache_create) * in_rate + output * out_rate
    else:
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


def _sum_costs(turns: list[dict], default_tier: str, unknown: set[str], *,
               force_tier: str | None = None, no_cache: bool = False) -> dict:
    agg = {"turns": len(turns), "input_total": 0, "fresh_in": 0,
           "cache_read": 0, "cache_create": 0, "output": 0, "cost_usd": 0.0}
    for t in turns:
        c = _turn_cost_usd(t, default_tier, unknown,
                           force_tier=force_tier, no_cache=no_cache)
        for k in ("input_total", "fresh_in", "cache_read", "cache_create", "output"):
            agg[k] += c[k]
        agg["cost_usd"] += c["cost_usd"]
    return agg


# ---------------------------------------------------------------------------
# API cost projection (--project-api)
# ---------------------------------------------------------------------------

def _project_api(est_result: int, est_context: int, step_count: int, *,
                 model: str, system_tokens: int, cache_hit: float,
                 output_tokens: int, turns: int | None, gbp: float) -> dict:
    """Project the cost of an API-driven agent doing the same steps.

    This is an ESTIMATE, not a measurement. Two client-agnostic figures bound
    the payload re-send: ``est_result`` (each tool payload counted once, the
    perfect-cache floor) and ``est_context`` (full re-send every turn, the
    no-cache ceiling). The real figure sits between, fixed by ``cache_hit``.
    Client-specific overhead (system prompt + tool schemas, re-sent each turn)
    is added on top. Output tokens are the least transferable input — supply
    your own. See module docstring and DEFAULT_API_* constants.
    """
    rate = PRICING[model]
    in_rate = rate["input"] / 1_000_000
    out_rate = rate["output"] / 1_000_000
    n_turns = turns if turns is not None else step_count + 1
    payload_resend = max(est_context - est_result, 0)
    output_usd = output_tokens * out_rate

    def _input_usd(ch: float) -> float:
        # Blended per-token rate for *re-sent* input: a fraction served from
        # cache (0.1x), the rest billed fresh (1.0x).
        rf = (1 - ch) * 1.0 + ch * CACHE_READ_MULT
        payload = est_result + payload_resend * rf          # first ingest fresh, re-sends blended
        overhead = system_tokens * (1 + max(n_turns - 1, 0) * rf)
        return (payload + overhead) * in_rate

    cache_hit = min(max(cache_hit, 0.0), 1.0)
    point_usd = _input_usd(cache_hit) + output_usd
    lo_usd = _input_usd(1.0) + output_usd     # perfect caching  → cheapest
    hi_usd = _input_usd(0.0) + output_usd     # no caching       → dearest

    return {
        "model": model,
        "assumed_turns": n_turns,
        "assumed_system_tokens": system_tokens,
        "assumed_cache_hit": cache_hit,
        "output_tokens": output_tokens,
        "projected_cost_usd": round(point_usd, 4),
        "projected_cost_gbp": round(point_usd * gbp, 4),
        "range_gbp": [round(lo_usd * gbp, 4), round(hi_usd * gbp, 4)],
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_report(*, since: str | None, case_id: str | None, gbp: float,
                 transcripts: Path | None, pre: int, post: int,
                 default_tier: str, source: str = "live",
                 project: dict | None = None,
                 window_from: str | None = None,
                 window_to: str | None = None,
                 reprice: str | None = None) -> dict:
    turns = _load_turns(transcripts)
    if window_from or window_to:
        # Explicit window: cost every transcript turn between two timestamps,
        # across session files. For investigations the tool can't auto-locate
        # (no workflow_summary, live log cleared) — reconstruct the span from
        # the case's own audit/timeline and pass it here. No payload estimate
        # is available this way, so est_*_tokens are 0 and --project-api shows
        # overhead+output only. Exact bounds — no pre/post padding.
        lo = _parse_ts(window_from) or datetime.min.replace(tzinfo=timezone.utc)
        hi = _parse_ts(window_to) or datetime.max.replace(tzinfo=timezone.utc)
        windows = [{
            "case_id": case_id or "", "session_id": "explicit-window",
            "caller": "", "start": lo, "end": hi, "step_count": 0,
            "est_result_tokens": 0, "est_context_input_tokens": 0,
        }]
        pre = post = 0
    else:
        loader = _load_windows_live if source == "live" else _load_windows
        windows = loader(since=since, case_id=case_id)
    windows, unattributed = _attribute(turns, windows, pre, post)

    unknown: set[str] = set()
    investigations = []
    for w in windows:
        agg = _sum_costs(w["turns"], default_tier, unknown)
        est = w["est_result_tokens"]
        rec = {
            "case_id": w["case_id"],
            "session_id": w["session_id"],
            "caller": w["caller"],
            "start": w["start"].isoformat(),
            "step_count": w.get("step_count", 0),
            "turns": agg["turns"],
            "true_input_tokens": agg["input_total"],
            "cache_read_tokens": agg["cache_read"],
            "output_tokens": agg["output"],
            "cost_usd": round(agg["cost_usd"], 4),
            "cost_gbp": round(agg["cost_usd"] * gbp, 4),
            "est_result_tokens": est,
            "est_context_input_tokens": w.get("est_context_input_tokens", 0),
            # Effective multiplier: how much real input the model billed per
            # token of raw payload socai shipped (system prompt + tool schemas
            # + per-turn re-send all live in here; caching pulls it back down).
            "multiplier": round(agg["input_total"] / est, 1) if est else None,
        }
        if reprice is not None and agg["turns"] > 0:
            # Re-price the SAME measured token profile at another model, with
            # the caching as measured and (separately) with no caching.
            rp = _sum_costs(w["turns"], default_tier, unknown, force_tier=reprice)
            rp_nc = _sum_costs(w["turns"], default_tier, unknown,
                               force_tier=reprice, no_cache=True)
            rec["reprice_model"] = reprice
            rec["reprice_cost_gbp"] = round(rp["cost_usd"] * gbp, 4)
            rec["reprice_nocache_gbp"] = round(rp_nc["cost_usd"] * gbp, 4)
        if project is not None:
            # Output tokens: prefer this investigation's *measured* output when
            # telemetry exists; else the supplied assumption.
            out = project["output_tokens"]
            if out is None:
                out = agg["output"] if agg["turns"] > 0 and agg["output"] > 0 \
                    else DEFAULT_API_OUTPUT_TOKENS
            rec["projection"] = _project_api(
                est, rec["est_context_input_tokens"], rec["step_count"],
                model=project["model"], system_tokens=project["system_tokens"],
                cache_hit=project["cache_hit"], output_tokens=out,
                turns=project["turns"], gbp=gbp)
        investigations.append(rec)

    un_agg = _sum_costs(unattributed, default_tier, unknown)
    multipliers = [i["multiplier"] for i in investigations
                   if i["multiplier"] is not None and i["turns"] > 0]
    total_inv_usd = sum(i["cost_usd"] for i in investigations)

    out: dict = {
        "source": source,
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
    if project is not None:
        out["projection_opts"] = project
        out["projected_total_gbp"] = round(
            sum(i["projection"]["projected_cost_gbp"] for i in investigations), 2)
    if reprice is not None:
        out["reprice_model"] = reprice
        out["reprice_total_gbp"] = round(
            sum(i.get("reprice_cost_gbp", 0) for i in investigations), 2)
        out["reprice_total_nocache_gbp"] = round(
            sum(i.get("reprice_nocache_gbp", 0) for i in investigations), 2)
    return out


def print_report(rep: dict) -> None:
    print(f"\n{'=' * 72}")
    print("  PER-INVESTIGATION TOKEN COST  (real client telemetry)")
    print(f"{'=' * 72}")

    has_projection = "projection_opts" in rep
    if rep["transcript_turns"] == 0 and not has_projection:
        print("\n  No Claude Code transcripts found for this repo.")
        print(f"  Looked in: {_default_transcript_dir()}")
        print("  Pass --transcripts <dir> if your project dir differs, or run")
        print("  some investigations through the TUI first.")
        return

    print(f"\n  Source: {rep['source']}   Transcript turns: {rep['transcript_turns']}   "
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

    if "reprice_model" in rep:
        _print_reprice(rep)

    if "projection_opts" in rep:
        _print_projection(rep)

    print("\n  NOTE: window-based attribution is approximate; verify pricing")
    print("        constants at anthropic.com/pricing before quoting figures.")


def _print_reprice(rep: dict) -> None:
    """Print the same measured token profile re-priced at another model."""
    model = rep["reprice_model"]
    rows = [i for i in rep["investigations"] if "reprice_cost_gbp" in i]
    if not rows:
        return
    print(f"\n  {'-' * 68}")
    print(f"  RE-PRICED AT {model.upper()}  (same measured tokens, different model)")
    print(f"  {'-' * 68}")
    print(f"  {'Case':<16} {'as-run £':>10} {f'{model} £':>10} {f'{model} no-cache':>16}")
    print(f"  {'-'*16} {'-'*10} {'-'*10} {'-'*16}")
    for i in sorted(rows, key=lambda x: -x["cost_gbp"])[:40]:
        case = (i["case_id"] or "(ad-hoc)")[:16]
        print(f"  {case:<16} £{i['cost_gbp']:>8.2f} £{i['reprice_cost_gbp']:>8.2f} "
              f"£{i['reprice_nocache_gbp']:>14.2f}")
    print(f"\n  Totals: as-run £{rep['investigation_cost_gbp']:.2f}  →  "
          f"{model} £{rep['reprice_total_gbp']:.2f} (cached)  /  "
          f"£{rep['reprice_total_nocache_gbp']:.2f} (no caching)")
    print(f"  Re-price assumes the same token profile + turn count on {model};")
    print("  no-cache models an agent without prompt caching (re-sends billed fresh).")


def _print_projection(rep: dict) -> None:
    """Print the projected API cost section (--project-api)."""
    o = rep["projection_opts"]
    print(f"\n  {'-' * 68}")
    print(f"  PROJECTED API COST  (estimate of an agent doing the same steps)")
    print(f"  {'-' * 68}")
    turns_note = o["turns"] if o["turns"] is not None else "step_count+1"
    out_note = o["output_tokens"] if o["output_tokens"] is not None else "measured/assumed"
    print(f"  Assumptions: model={o['model']}  system+schemas={o['system_tokens']:,} tok  "
          f"cache_hit={o['cache_hit']}  turns={turns_note}  output={out_note}")

    rows = [i for i in rep["investigations"] if i.get("projection")]
    if rows:
        print(f"\n  {'Case':<16} {'Steps':>5} {'PayloadTok':>11} {'£ proj':>9} "
              f"{'£ range (cache→none)':>22}")
        print(f"  {'-'*16} {'-'*5} {'-'*11} {'-'*9} {'-'*22}")
        for i in sorted(rows, key=lambda x: -x["projection"]["projected_cost_gbp"])[:40]:
            p = i["projection"]
            case = (i["case_id"] or "(ad-hoc)")[:16]
            rng = f"£{p['range_gbp'][0]:.2f}–£{p['range_gbp'][1]:.2f}"
            print(f"  {case:<16} {i['step_count']:>5} {i['est_result_tokens']:>11,} "
                  f"£{p['projected_cost_gbp']:>8.2f} {rng:>22}")

    print(f"\n  Projected total (point estimate): £{rep['projected_total_gbp']:.2f}")
    print("  Range per row spans perfect caching → no caching. The point")
    print("  estimate uses your --api-cache-hit. PROJECTION, not measurement —")
    print("  re-priced at the target model from socai's client-agnostic payload")
    print("  estimate; tune --api-system-tokens / --api-output-tokens to your agent.")


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
    ap.add_argument("--source", choices=["live", "summary"], default="live",
                    help="Window source: 'live' (registry/mcp_usage.jsonl, always "
                         "current — use right after an investigation) or 'summary' "
                         "(flushed workflow_summary in metrics.jsonl). Default live.")
    ap.add_argument("--from", dest="window_from",
                    help="Cost an explicit window: start timestamp (ISO). Sums all "
                         "transcript turns in [--from, --to] across session files. "
                         "Use --case to label it.")
    ap.add_argument("--to", dest="window_to",
                    help="Explicit window end timestamp (ISO)")
    ap.add_argument("--reprice", choices=list(PRICING),
                    help="Re-price the same measured token profile at this model "
                         "(e.g. what the Opus TUI run would cost on Sonnet), shown "
                         "with caching as measured and with no caching.")
    ap.add_argument("--json", action="store_true", help="Raw JSON output")

    grp = ap.add_argument_group("API projection (--project-api)")
    grp.add_argument("--project-api", action="store_true",
                     help="Project the cost of an API agent doing the same steps")
    grp.add_argument("--api-model", default=DEFAULT_API_MODEL, choices=list(PRICING),
                     help=f"Target model for the projection (default {DEFAULT_API_MODEL})")
    grp.add_argument("--api-system-tokens", type=int, default=DEFAULT_API_SYSTEM_TOKENS,
                     help=f"Agent system prompt + tool schema tokens, re-sent each "
                          f"turn (default {DEFAULT_API_SYSTEM_TOKENS:,})")
    grp.add_argument("--api-cache-hit", type=float, default=DEFAULT_API_CACHE_HIT,
                     help=f"Fraction of re-sent input served from cache, 0..1 "
                          f"(default {DEFAULT_API_CACHE_HIT})")
    grp.add_argument("--api-turns", type=int, default=None,
                     help="Model turns (default: step_count + 1)")
    grp.add_argument("--api-output-tokens", type=int, default=None,
                     help="Output tokens per investigation (default: measured if "
                          f"telemetry present, else {DEFAULT_API_OUTPUT_TOKENS:,})")
    args = ap.parse_args()

    project = None
    if args.project_api:
        project = {
            "model": args.api_model,
            "system_tokens": args.api_system_tokens,
            "cache_hit": args.api_cache_hit,
            "turns": args.api_turns,
            "output_tokens": args.api_output_tokens,
        }

    rep = build_report(
        since=args.since, case_id=args.case, gbp=args.gbp,
        transcripts=args.transcripts, pre=args.pre_buffer, post=args.post_buffer,
        default_tier=args.tier, source=args.source, project=project,
        window_from=args.window_from, window_to=args.window_to,
        reprice=args.reprice,
    )

    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print_report(rep)


if __name__ == "__main__":
    main()
