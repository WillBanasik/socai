"""Lint: no playbook stage may be an uncapped raw-row dump.

Enforces rule 1 of docs/playbook-query-style.md — every stage query must
terminate in either an aggregation (SUMMARY) or carry an explicit row cap
(BOUNDED). A broad filter with neither is a RAW-DUMP and is disallowed.

Detection granularity mirrors the executor:
  * KQL stage files run as a single statement -> checked file-level.
  * CQL stage files are split into independently-run sub-queries by
    ``// --- Sub-query X ---`` markers -> each available block checked.

This is a RATCHET. ``BASELINE`` lists the known-not-yet-fixed violations
(Tiers 2/3 of the playbook-query cleanup). The test fails if:
  * a NEW violation appears (regression — a new/edited stage dumps raw), or
  * a BASELINE entry is no longer a violation (stale — remove it once fixed).
Drive ``BASELINE`` to empty as the remaining stages are refactored.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from tools.cql_playbooks import _parse_sub_queries

_AGG = re.compile(
    r"\bsummarize\b|\bmake-series\b|\bgroupBy\s*\(|\bbucket\s*\("
    r"|\btimeChart\s*\(|\bstats\s*\(|\btop\s*\(",
    re.I,
)
_CAP_KQL = re.compile(r"\|\s*take\s+\d|\|\s*limit\s+\d", re.I)
_CAP_CQL = re.compile(r"limit\s*=\s*\d|\bhead\s*\(|\btail\s*\(", re.I)


def _is_dump(block: str, cap_re: re.Pattern) -> bool:
    """True if a query block neither aggregates nor caps its row count."""
    return not _AGG.search(block) and not cap_re.search(block)


def _current_violations() -> set[str]:
    viol: set[str] = set()
    # KQL — single statement per file (v2 stages + legacy monolithic).
    for f in sorted(
        list((REPO / "config/playbooks").rglob("*.kql"))
        + list((REPO / "config/kql_playbooks").rglob("*.kql"))
    ):
        if _is_dump(f.read_text(), _CAP_KQL):
            viol.add(str(f.relative_to(REPO)))
    # CQL — one independently-run block per sub-query marker.
    for f in sorted((REPO / "config/playbooks").rglob("*.cql")):
        for sub in _parse_sub_queries(f.read_text()):
            if not sub.get("available"):
                continue
            block = sub["query"]
            if block.strip() and _is_dump(block, _CAP_CQL):
                label = sub["title"].split(":")[0].strip() or "(whole)"
                viol.add(f"{f.relative_to(REPO)}::{label}")
    return viol


# Known-outstanding violations (Phase 2 Tier-2 scope fix + Phase 3 Tier-3
# summarise-first refactor). Shrink to empty as each is addressed.
BASELINE: set[str] = set()  # clean — no known uncapped raw-dump stages remain.


def test_no_new_uncapped_raw_dump_stages():
    """No stage query outside the tracked baseline may be an uncapped raw dump."""
    new = _current_violations() - BASELINE
    assert not new, (
        "New uncapped raw-row playbook stage(s) — add a cap or an aggregation "
        "(see docs/playbook-query-style.md):\n  " + "\n  ".join(sorted(new))
    )


def test_baseline_has_no_stale_entries():
    """A fixed stage must be removed from BASELINE (keeps the ratchet honest)."""
    stale = BASELINE - _current_violations()
    assert not stale, (
        "BASELINE lists stage(s) that are now compliant — remove them so the "
        "ratchet can't slip back:\n  " + "\n  ".join(sorted(stale))
    )
