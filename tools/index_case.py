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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, REGISTRY_FILE
from tools.common import load_json, save_json, utcnow


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

    if status:
        meta["status"] = status
    if report_path:
        meta["report_path"] = report_path
    if disposition:
        meta["disposition"] = disposition
    meta["updated_at"] = utcnow()

    # Rebuild artefact list
    artefacts = []
    for f in sorted(case_dir.rglob("*")):
        if f.is_file() and f.suffix not in (".json",) or f.name.endswith(".analysis.json"):
            artefacts.append(str(f.relative_to(case_dir)))
    meta["artefacts"] = artefacts

    # IOC counts
    iocs_path = case_dir / "iocs" / "iocs.json"
    if iocs_path.exists():
        iocs_data = load_json(iocs_path)
        meta["ioc_totals"] = iocs_data.get("total", {})
    else:
        meta["ioc_totals"] = {}

    save_json(meta_path, meta)

    # Update registry
    if REGISTRY_FILE.exists():
        registry = load_json(REGISTRY_FILE)
    else:
        registry = {"cases": {}}

    registry["cases"][case_id] = {
        "title":       meta.get("title", case_id),
        "severity":    meta.get("severity", "medium"),
        "status":      meta.get("status", "open"),
        "created_at":  meta.get("created_at", ""),
        "updated_at":  meta["updated_at"],
        "case_dir":    str(case_dir),
        "report_path": meta.get("report_path"),
        "ioc_totals":  meta.get("ioc_totals", {}),
    }
    save_json(REGISTRY_FILE, registry)
    print(f"[index_case] Case {case_id} indexed (status={meta['status']})")
    return meta


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Index/update a case in the registry.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--status", choices=["open", "closed", "escalated", "archived"])
    p.add_argument("--report-path", default=None)
    args = p.parse_args()

    result = index_case(args.case_id, args.status, args.report_path)
    print(json.dumps(result, indent=2))
