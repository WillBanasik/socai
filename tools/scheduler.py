"""
Background task scheduler for socai.

Runs periodic maintenance tasks in a single daemon thread:

  Task                    Interval    Purpose
  ──────────────────────  ─────────   ──────────────────────────────────────────
  case_memory_rebuild     6 hours     Keep BM25 case memory index fresh
  geoip_refresh           7 days      Update MaxMind GeoLite2-City database
  baseline_refresh        24 hours    Rebuild per-client behavioural baselines

Started by the MCP server lifespan (server.py).  Safe to call start_scheduler()
multiple times — only one thread runs (singleton guard).

Usage:
    from tools.scheduler import start_scheduler, stop_scheduler

    start_scheduler()   # called at MCP server startup
    stop_scheduler()    # called at MCP server shutdown
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.common import log_error

# ---------------------------------------------------------------------------
# Singleton state
# ---------------------------------------------------------------------------

_scheduler_thread: threading.Thread | None = None
_stop_event = threading.Event()
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Task runner
# ---------------------------------------------------------------------------

def _run_task(name: str, fn) -> None:
    """Execute *fn*, logging outcome without propagating exceptions."""
    try:
        result = fn()
        try:
            from mcp_server.logging_config import mcp_log
            mcp_log("scheduler_task", task=name, status="ok",
                    result=str(result)[:200] if result else None)
        except Exception:
            pass  # logging unavailable (e.g. running outside MCP context)
    except Exception as exc:
        log_error("", f"scheduler.{name}", str(exc),
                  severity="warning", context={"task": name})


# ---------------------------------------------------------------------------
# Scheduler loop
# ---------------------------------------------------------------------------

def _scheduler_loop(tasks: list[tuple[str, float, object]]) -> None:
    """
    Main loop.

    tasks: list of (name, interval_seconds, callable)

    All tasks run immediately on first iteration, then on their respective
    intervals thereafter.
    """
    next_run: dict[str, float] = {name: time.monotonic() for name, _, _ in tasks}

    while not _stop_event.is_set():
        now = time.monotonic()
        for name, interval, fn in tasks:
            if now >= next_run[name]:
                _run_task(name, fn)
                next_run[name] = now + interval

        # Sleep in 60-second increments to stay responsive to stop signals
        _stop_event.wait(timeout=60)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_scheduler() -> None:
    """
    Start the background scheduler daemon thread.

    Idempotent — subsequent calls while the thread is alive are no-ops.
    """
    global _scheduler_thread
    with _lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return  # already running

        _stop_event.clear()

        from tools.case_memory import build_case_memory_index
        from tools.geoip import refresh_geoip_db

        tasks: list[tuple[str, float, object]] = [
            ("case_memory_rebuild", 6 * 3600, build_case_memory_index),
            ("geoip_refresh", 7 * 24 * 3600, refresh_geoip_db),
        ]

        # Baseline refresh — only if clients are configured
        try:
            from config.settings import CLIENT_ENTITIES
            from tools.common import load_json
            entities = load_json(CLIENT_ENTITIES).get("clients", [])
            client_names = [e.get("name", "") for e in entities if e.get("name")]
            if client_names:
                def _refresh_all_baselines(_names=client_names):
                    from tools.client_baseline import build_client_baseline
                    results = {name: build_client_baseline(name) for name in _names}
                    return {"refreshed": list(results.keys())}
                tasks.append(("baseline_refresh", 24 * 3600, _refresh_all_baselines))
        except Exception:
            pass

        # Article discovery — daily or weekly auto-fetch of RSS candidates
        try:
            from config.settings import ARTICLE_AUTO_DISCOVER
            if ARTICLE_AUTO_DISCOVER in ("daily", "weekly"):
                interval = 24 * 3600 if ARTICLE_AUTO_DISCOVER == "daily" else 7 * 24 * 3600
                def _auto_discover_articles():
                    from tools.threat_articles import fetch_candidates
                    candidates = fetch_candidates(days=7, max_candidates=30)
                    uncovered = [c for c in candidates if not c.get("already_covered")]
                    return {"total": len(candidates), "new": len(uncovered),
                            "candidates": [c["title"] for c in uncovered[:10]]}
                tasks.append(("article_discovery", interval, _auto_discover_articles))
        except Exception:
            pass

        # Article auto-publish — push unpublished articles to OpenCTI (daily)
        try:
            from config.settings import ARTICLE_AUTO_PUBLISH, OPENCTI_PUBLISH_ENABLED
            if ARTICLE_AUTO_PUBLISH and OPENCTI_PUBLISH_ENABLED:
                def _auto_publish_articles():
                    from tools.common import load_json as _lj
                    from config.settings import ARTICLE_INDEX_FILE as _aif
                    from tools.opencti_publish import publish_report
                    index = _lj(_aif)
                    published = []
                    for a in index.get("articles", []):
                        if a.get("opencti_report_id"):
                            continue  # already published
                        result = publish_report(a["article_id"])
                        if result.get("status") == "ok":
                            published.append(a["article_id"])
                    return {"published": published, "count": len(published)}
                tasks.append(("article_auto_publish", 24 * 3600, _auto_publish_articles))
        except Exception:
            pass

        _scheduler_thread = threading.Thread(
            target=_scheduler_loop,
            args=(tasks,),
            daemon=True,
            name="socai-scheduler",
        )
        _scheduler_thread.start()


def stop_scheduler() -> None:
    """Signal the scheduler thread to stop at its next wake interval."""
    _stop_event.set()
