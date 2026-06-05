#!/usr/bin/env python3
"""One-shot backfill: give every CLOSED case a canonical disposition.

Closed cases could previously end up with a blank disposition (save_report or a
direct index_case call with no disposition arg) or the non-canonical "resolved"
(close_case's old default). This patches those to a canonical value, inferred
from the case's own deliverables:

    closure_comment manifest disposition  ->  that value
    mdr_report.md present                 ->  true_positive
    pup_report.md present                 ->  pup_pua
    otherwise                             ->  inconclusive  (honest "not recorded")

Canonical dispositions are left untouched. Updates case_meta.json and the
registry entry directly (no re-close, so it doesn't inflate the
investigation_summary metric). Idempotent; safe to re-run.

Run from repo root:
    python3 scripts/backfill_dispositions.py --dry-run   # report only
    python3 scripts/backfill_dispositions.py             # apply
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, REGISTRY_FILE
from tools.common import load_json, save_json
from tools.index_case import CANONICAL_DISPOSITIONS


def _infer(case_dir: Path) -> str:
    # 1. A closure_comment manifest records the disposition explicitly.
    for mf in case_dir.glob("artefacts/closure_comments/*manifest*.json"):
        try:
            d = load_json(mf).get("disposition")
            if d in CANONICAL_DISPOSITIONS:
                return d
        except Exception:
            pass
    # 2. Infer from the deliverable type.
    if (case_dir / "reports" / "mdr_report.md").exists():
        return "true_positive"
    if (case_dir / "reports" / "pup_report.md").exists():
        return "pup_pua"
    # 3. Honest fallback — the determination was never recorded.
    return "inconclusive"


def backfill(dry_run: bool = False) -> dict:
    registry = load_json(REGISTRY_FILE) if REGISTRY_FILE.exists() else {"cases": {}}
    reg_cases = registry.get("cases", {})
    changes = []

    for mp in glob.glob(str(CASES_DIR / "*" / "case_meta.json")):
        meta = load_json(mp)
        if meta.get("status") != "closed":
            continue
        disp = meta.get("disposition")
        if disp in CANONICAL_DISPOSITIONS:
            continue
        case_dir = Path(mp).parent
        cid = case_dir.name
        new = _infer(case_dir)
        changes.append({"case_id": cid, "from": disp or None, "to": new})
        if not dry_run:
            meta["disposition"] = new
            save_json(Path(mp), meta)
            if cid in reg_cases:
                reg_cases[cid]["disposition"] = new

    if not dry_run and changes:
        save_json(REGISTRY_FILE, registry)

    return {"closed_patched": len(changes), "dry_run": dry_run, "changes": changes}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Backfill canonical dispositions on closed cases.")
    ap.add_argument("--dry-run", action="store_true", help="report without writing")
    args = ap.parse_args()
    print(json.dumps(backfill(dry_run=args.dry_run), indent=2))
