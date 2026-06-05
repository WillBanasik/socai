#!/usr/bin/env python3
"""One-shot backfill: repopulate client/tags/attack_type on registry entries.

Before the index_case fix, re-indexing a case rewrote its registry/case_index.json
entry without `client`, `tags`, or `attack_type` (case_create set them, but every
subsequent status transition stripped them — ~92% of cases ended up with no
client). case_meta.json kept the fields, so this script reads each case's meta
(the source of truth) and patches the registry entry in place.

Additive and idempotent: only the three fields are touched, never removed; other
registry data is preserved. Safe to re-run.

Run from repo root:
    python3 scripts/backfill_registry_fields.py --dry-run   # report only
    python3 scripts/backfill_registry_fields.py             # apply
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, REGISTRY_FILE
from tools.common import load_json, save_json


def backfill(dry_run: bool = False) -> dict:
    if not REGISTRY_FILE.exists():
        return {"error": f"registry not found at {REGISTRY_FILE}"}

    registry = load_json(REGISTRY_FILE)
    cases = registry.get("cases", {})
    patched = 0
    skipped_no_meta = 0

    for case_id, entry in cases.items():
        meta_path = CASES_DIR / case_id / "case_meta.json"
        if not meta_path.exists():
            skipped_no_meta += 1
            continue
        try:
            meta = load_json(meta_path)
        except Exception:
            skipped_no_meta += 1
            continue

        before = (entry.get("client"), entry.get("tags"), entry.get("attack_type"))
        entry["client"] = meta.get("client") or entry.get("client", "")
        entry["tags"] = (
            meta.get("tags") if meta.get("tags") is not None
            else entry.get("tags", [])
        )
        entry["attack_type"] = meta.get("attack_type", entry.get("attack_type"))
        after = (entry.get("client"), entry.get("tags"), entry.get("attack_type"))
        if before != after:
            patched += 1

    if not dry_run:
        save_json(REGISTRY_FILE, registry)

    return {
        "total": len(cases),
        "patched": patched,
        "skipped_no_meta": skipped_no_meta,
        "dry_run": dry_run,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Backfill registry client/tags/attack_type.")
    ap.add_argument("--dry-run", action="store_true", help="report without writing")
    args = ap.parse_args()
    print(json.dumps(backfill(dry_run=args.dry_run), indent=2))
