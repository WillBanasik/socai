"""
tool: index_case
----------------
Updates registry/case_index.json with the latest case metadata,
artefact list, IOC counts, and report path.
Call this after major analysis steps or when closing a case.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, REGISTRY_FILE
from tools.common import load_json, save_json, utcnow

# Thread-safety: protects the read-modify-write cycle on case_index.json
# when concurrent investigations both call index_case().
_registry_lock = threading.Lock()


def index_case(
    case_id: str,
    status: str | None = None,
    report_path: str | None = None,
    disposition: str | None = None,
) -> dict:
    """
    Re-index a case into the registry.  Scans the case folder for artefacts.
    """
    case_dir = CASES_DIR / case_id
    meta_path = case_dir / "case_meta.json"

    if not meta_path.exists():
        # Case dir missing but registry entry may exist — update registry directly
        if status and REGISTRY_FILE.exists():
            with _registry_lock:
                registry = load_json(REGISTRY_FILE)
                if case_id in registry.get("cases", {}):
                    entry = registry["cases"][case_id]
                    entry["status"] = status
                    if disposition:
                        entry["disposition"] = disposition
                    entry["updated_at"] = utcnow()
                    save_json(REGISTRY_FILE, registry)
                    print(f"[index_case] Case {case_id} registry updated (status={status}, dir missing)")
                    return {**entry, "case_id": case_id, "_warning": "case directory missing, registry updated"}
        return {"error": f"case_meta.json not found at {meta_path}"}

    meta = load_json(meta_path)

    # Backward-compat: silently migrate legacy "open" → "active"
    if meta.get("status") == "open" and status != "open":
        meta["status"] = "active"

    prev_status = meta.get("status", "")

    if status:
        meta["status"] = status
    if report_path:
        meta["report_path"] = report_path
    if disposition:
        meta["disposition"] = disposition
    meta["updated_at"] = utcnow()

    # Record phase timestamp
    if status:
        pts = meta.setdefault("phase_timestamps", {})
        ts_key = f"{status}_at"
        if ts_key not in pts:
            pts[ts_key] = utcnow()
        from tools.common import log_metric
        log_metric("case_phase_change", case_id=case_id,
                   phase=status,
                   prev_status=prev_status,
                   analyst=meta.get("analyst", ""),
                   client=meta.get("client", ""),
                   severity=meta.get("severity", ""))

    # Count artefacts via targeted subdirectory check (avoids expensive
    # rglob over the entire case directory — 5-10× faster on large cases)
    artefact_count = 0
    for subdir in ("artefacts", "iocs", "reports", "logs", "notes"):
        d = case_dir / subdir
        if d.is_dir():
            artefact_count += sum(1 for f in d.rglob("*") if f.is_file())
    meta["artefact_count"] = artefact_count

    # IOC counts
    iocs_path = case_dir / "iocs" / "iocs.json"
    if iocs_path.exists():
        iocs_data = load_json(iocs_path)
        meta["ioc_totals"] = iocs_data.get("total", {})
    else:
        meta["ioc_totals"] = {}

    save_json(meta_path, meta)

    if status == "closed":
        pts = meta.get("phase_timestamps", {})
        durations = {}
        try:
            from datetime import datetime as _dt, timezone as _tz
            def _parse_ts(s):
                return _dt.fromisoformat(s.replace("Z", "+00:00"))
            if pts.get("created_at") and pts.get("closed_at"):
                durations["total_minutes"] = round((_parse_ts(pts["closed_at"]) - _parse_ts(pts["created_at"])).total_seconds() / 60, 1)
            if pts.get("created_at") and pts.get("active_at"):
                durations["triage_minutes"] = round((_parse_ts(pts["active_at"]) - _parse_ts(pts["created_at"])).total_seconds() / 60, 1)
            if pts.get("active_at") and pts.get("closed_at"):
                durations["investigation_minutes"] = round((_parse_ts(pts["closed_at"]) - _parse_ts(pts["active_at"])).total_seconds() / 60, 1)
        except (ValueError, TypeError):
            pass
        from tools.common import log_metric
        log_metric("investigation_summary", case_id=case_id,
                   disposition=meta.get("disposition", ""),
                   severity=meta.get("severity", ""),
                   attack_type=meta.get("attack_type", ""),
                   client=meta.get("client", ""),
                   analyst=meta.get("analyst", ""),
                   ioc_totals=meta.get("ioc_totals", {}),
                   durations=durations,
                   phase_timestamps=pts)

    # Update registry (locked for concurrent investigation safety)
    with _registry_lock:
        if REGISTRY_FILE.exists():
            registry = load_json(REGISTRY_FILE)
        else:
            registry = {"cases": {}}

        registry["cases"][case_id] = {
            "title":       meta.get("title", case_id),
            "severity":    meta.get("severity", "medium"),
            "status":      meta.get("status", "open"),
            "disposition": meta.get("disposition"),
            "created_at":  meta.get("created_at", ""),
            "updated_at":  meta["updated_at"],
            "case_dir":    str(case_dir),
            "report_path": meta.get("report_path"),
            "ioc_totals":  meta.get("ioc_totals", {}),
        }
        save_json(REGISTRY_FILE, registry)
    print(f"[index_case] Case {case_id} indexed (status={meta['status']})")
    return meta


def promote_case(
    case_id: str,
    title: str | None = None,
    severity: str | None = None,
    disposition: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Promote a case from triage to active status.

    Guard: must be "triage" status (or "open" for backward compat).
    Transitions to "active" via index_case().
    Optional overrides for title, severity, disposition, tags.
    """
    case_dir = CASES_DIR / case_id
    meta_path = case_dir / "case_meta.json"
    if not meta_path.exists():
        return {"error": f"case_meta.json not found at {meta_path}"}

    meta = load_json(meta_path)
    current = meta.get("status", "")

    if current not in ("triage", "open"):
        return {
            "error": f"Cannot promote case {case_id}: status is '{current}', "
                     f"must be 'triage'. Only triage cases can be promoted.",
        }

    # Apply optional overrides
    if title is not None:
        meta["title"] = title
    if severity is not None:
        meta["severity"] = severity
    if tags is not None:
        meta["tags"] = tags
    meta["updated_at"] = utcnow()
    pts = meta.setdefault("phase_timestamps", {})
    if "triage_at" not in pts:
        pts["triage_at"] = meta.get("created_at", utcnow())
    save_json(meta_path, meta)

    return index_case(case_id, status="active", disposition=disposition)


def discard_case(case_id: str, reason: str = "") -> dict:
    """Discard a case during triage.

    Guard: must be "triage" status (or "open" for backward compat).
    Transitions to "discarded" via index_case().
    Saves reason to case_meta.
    """
    case_dir = CASES_DIR / case_id
    meta_path = case_dir / "case_meta.json"
    if not meta_path.exists():
        return {"error": f"case_meta.json not found at {meta_path}"}

    meta = load_json(meta_path)
    current = meta.get("status", "")

    if current not in ("triage", "open"):
        return {
            "error": f"Cannot discard case {case_id}: status is '{current}', "
                     f"must be 'triage'. Only triage cases can be discarded.",
        }

    if reason:
        meta["discard_reason"] = reason
    meta["updated_at"] = utcnow()
    save_json(meta_path, meta)

    return index_case(case_id, status="discarded")


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Index/update a case in the registry.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--status", choices=["open", "triage", "active", "discarded", "closed", "escalated", "archived"])
    p.add_argument("--report-path", default=None)
    args = p.parse_args()

    result = index_case(args.case_id, args.status, args.report_path)
    print(json.dumps(result, indent=2))
