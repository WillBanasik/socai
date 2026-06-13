#!/usr/bin/env python3
"""One-shot backfill: add platforms.identity_response to every client.

`identity_response` is the per-client determinant for identity containment
authority (see docs/containment-authority.md / socai://containment-authority):

    performanta_delegated  — we hold Entra/Defender identity-action delegation
                             AND SOP cover; the analyst can reset passwords and
                             revoke sessions (client does MFA reset / disable /
                             OAuth-grant revoke).
    client_actioned        — no identity-plane delegation (e.g. Falcon/NGSIEM-only
                             clients); ALL identity actions go to the client.

This is a POLICY fact and must never be inferred from integration presence
(SIEM/log-read access != identity-action delegation). So this backfill defaults
every client to the conservative `client_actioned` and lists them for manual
confirmation — flip the ones where we genuinely hold delegation to
`performanta_delegated` by hand (or via a follow-up).

Additive and idempotent: only `platforms.identity_response` is added when
absent; existing values are never overwritten. Safe to re-run.

Run from repo root:
    python3 scripts/backfill_identity_response.py --dry-run   # report only
    python3 scripts/backfill_identity_response.py             # apply
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CLIENT_ENTITIES
from tools.common import load_json, save_json

_DEFAULT = "client_actioned"
_VALID = {"performanta_delegated", "client_actioned"}


def backfill(dry_run: bool = False) -> dict:
    if not CLIENT_ENTITIES.exists():
        return {"error": f"client_entities not found at {CLIENT_ENTITIES}"}

    data = load_json(CLIENT_ENTITIES)
    clients = data.get("clients", [])

    added: list[str] = []
    existing: dict[str, str] = {}
    invalid: list[str] = []

    for ent in clients:
        name = ent.get("name", "?")
        platforms = ent.setdefault("platforms", {})
        current = platforms.get("identity_response")
        if current is None:
            platforms["identity_response"] = _DEFAULT
            added.append(name)
        elif str(current).lower() not in _VALID:
            invalid.append(f"{name}={current}")
        else:
            existing[name] = str(current).lower()

    if added and not dry_run:
        save_json(CLIENT_ENTITIES, data)

    return {
        "total_clients": len(clients),
        "added_default": added,
        "already_set": existing,
        "invalid_values": invalid,
        "dry_run": dry_run,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report only, do not write")
    args = ap.parse_args()

    result = backfill(dry_run=args.dry_run)
    if "error" in result:
        print(f"ERROR: {result['error']}")
        return 1

    mode = "DRY RUN" if result["dry_run"] else "APPLIED"
    print(f"[{mode}] {result['total_clients']} clients")
    print(f"  added '{_DEFAULT}' default to {len(result['added_default'])}: "
          f"{', '.join(result['added_default']) or '(none)'}")
    if result["already_set"]:
        print(f"  already set ({len(result['already_set'])}):")
        for n, v in sorted(result["already_set"].items()):
            print(f"    - {n}: {v}")
    if result["invalid_values"]:
        print(f"  INVALID values (fix by hand): {', '.join(result['invalid_values'])}")
    if result["added_default"]:
        print("\n  NEXT: review the defaulted clients and flip any where we hold "
              "Entra/Defender identity delegation to 'performanta_delegated'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
