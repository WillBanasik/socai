"""
tool: case_create
-----------------
Initialises a new case folder under cases/<case_id>/ and registers it
in registry/case_index.json.

Outputs
  cases/<case_id>/case_meta.json   – case metadata
  cases/<case_id>/artefacts/       – artefact staging area
  cases/<case_id>/iocs/            – extracted IOC files
  cases/<case_id>/reports/         – per-case report outputs
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# allow running as script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, DEFAULT_CLIENT, REGISTRY_FILE
from tools.common import audit, load_json, save_json, utcnow


def case_create(
    case_id: str,
    title: str = "",
    severity: str = "medium",
    analyst: str = "unassigned",
    tags: list[str] | None = None,
    client: str = "",
) -> dict:
    """
    Create folder structure and registry entry for *case_id*.
    Returns the case metadata dict.
    """
    case_dir = CASES_DIR / case_id
    if case_dir.exists():
        print(f"[case_create] Case {case_id} already exists at {case_dir}")
    else:
        for sub in ("artefacts", "iocs", "reports", "logs"):
            (case_dir / sub).mkdir(parents=True, exist_ok=True)

    resolved_client = client or DEFAULT_CLIENT
    meta = {
        "case_id": case_id,
        "title": title or f"Investigation {case_id}",
        "severity": severity,
        "analyst": analyst,
        "client": resolved_client,
        "tags": tags or [],
        "status": "open",
        "created_at": utcnow(),
        "updated_at": utcnow(),
        "artefacts": [],
        "iocs": [],
        "report_path": None,
    }
    save_json(case_dir / "case_meta.json", meta)

    # Update registry
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if REGISTRY_FILE.exists():
        registry = load_json(REGISTRY_FILE)
    else:
        registry = {"cases": {}}

    registry["cases"][case_id] = {
        "title": meta["title"],
        "severity": severity,
        "status": "open",
        "created_at": meta["created_at"],
        "updated_at": meta["updated_at"],
        "case_dir": str(case_dir),
        "report_path": None,
    }
    save_json(REGISTRY_FILE, registry)
    audit("case_create", str(case_dir / "case_meta.json"), extra={"case_id": case_id})
    print(f"[case_create] Case {case_id} initialised at {case_dir}")
    return meta


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Create a new SOC case.")
    p.add_argument("case_id")
    p.add_argument("--title", default="")
    p.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    p.add_argument("--analyst", default="unassigned")
    p.add_argument("--tags", nargs="*", default=[])
    args = p.parse_args()

    result = case_create(args.case_id, args.title, args.severity, args.analyst, args.tags)
    print(json.dumps(result, indent=2))
