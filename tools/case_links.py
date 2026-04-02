"""
tool: case_links
-----------------
Link, group, and merge related cases (locally) with external reference
support for Zoho Service Desk and SOAR platform sync.

Naming convention (aligned with Zoho / SOAR):
  - "ticket"     — Zoho Service Desk item (external_refs.zoho_ticket_id)
  - "incident"   — SOAR/SIEM incident ID (external_refs.incident_id)
  - "case"       — socai's local investigation unit (case_id)
  - All three can refer to the same investigation; the link graph connects them.

Link types:
  - duplicate  : same investigation repeated (one becomes canonical)
  - related    : same campaign, actor, or IOC overlap
  - parent     : escalation chain (child was escalated into parent)

Storage:
  LOCAL (always present — investigation-critical data):
    - case_meta.json → "links" key (per-case relationships)
    - case_meta.json → "external_refs" key (Zoho ticket ID, SOAR incident ID, etc.)
    - registry/case_links.json (global adjacency index for fast lookups)

  EXTERNAL (future — synced bidirectionally):
    - Zoho Service Desk: linked tickets mirror the local link graph
    - SOAR: incident IDs mapped via external_refs

The public functions below are the LOCAL implementation. A Zoho/SOAR adapter
would call these same functions and then push the resulting changes to the
external platform (or receive webhook events and call these to sync inbound).

Usage:
    from tools.case_links import (
        link_cases, get_links, merge_cases, unlink_cases,
        set_external_ref, get_external_ref,
    )
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR, CASES_DIR, REGISTRY_FILE
from tools.common import load_json, log_error, save_json, utcnow

LINKS_INDEX_FILE = BASE_DIR / "registry" / "case_links.json"

# Valid link types
LINK_TYPES = {"duplicate", "related", "parent"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_links_index() -> dict:
    """Load the global links index. Structure: {case_id: [{case_id, type, direction, ts}]}"""
    if not LINKS_INDEX_FILE.exists():
        return {}
    try:
        return load_json(LINKS_INDEX_FILE)
    except Exception as exc:
        log_error("", "case_links.load_links_index", str(exc),
                  severity="warning", traceback=True, context={"path": str(LINKS_INDEX_FILE)})
        return {}


def _save_links_index(index: dict) -> None:
    save_json(LINKS_INDEX_FILE, index)


def _load_case_meta(case_id: str) -> dict | None:
    path = CASES_DIR / case_id / "case_meta.json"
    if not path.exists():
        return None
    try:
        return load_json(path)
    except Exception as exc:
        log_error("", "case_links.load_case_meta", str(exc),
                  severity="warning", traceback=True, context={"case_id": case_id, "path": str(path)})
        return None


def _save_case_meta(case_id: str, meta: dict) -> None:
    path = CASES_DIR / case_id / "case_meta.json"
    save_json(path, meta)


def _add_link_to_meta(meta: dict, target_id: str, link_type: str, direction: str, ts: str) -> None:
    """Add a link entry to a case_meta dict (idempotent)."""
    links = meta.setdefault("links", [])
    # Avoid duplicates
    for existing in links:
        if existing.get("case_id") == target_id and existing.get("type") == link_type:
            return
    links.append({
        "case_id": target_id,
        "type": link_type,
        "direction": direction,
        "linked_at": ts,
    })


def _remove_link_from_meta(meta: dict, target_id: str, link_type: str | None = None) -> bool:
    """Remove a link entry from a case_meta dict. Returns True if removed."""
    links = meta.get("links", [])
    original_len = len(links)
    meta["links"] = [
        l for l in links
        if not (l.get("case_id") == target_id and (link_type is None or l.get("type") == link_type))
    ]
    return len(meta["links"]) < original_len


def _add_to_index(index: dict, case_a: str, case_b: str, link_type: str, ts: str) -> None:
    """Add a bidirectional link to the global index."""
    for src, tgt, direction in [(case_a, case_b, "outbound"), (case_b, case_a, "inbound")]:
        entries = index.setdefault(src, [])
        # Avoid duplicates
        if not any(e["case_id"] == tgt and e["type"] == link_type for e in entries):
            entries.append({
                "case_id": tgt,
                "type": link_type,
                "direction": direction,
                "linked_at": ts,
            })


def _remove_from_index(index: dict, case_a: str, case_b: str, link_type: str | None = None) -> None:
    """Remove a link from the global index (both directions)."""
    for src, tgt in [(case_a, case_b), (case_b, case_a)]:
        entries = index.get(src, [])
        index[src] = [
            e for e in entries
            if not (e["case_id"] == tgt and (link_type is None or e["type"] == link_type))
        ]
        if not index[src]:
            index.pop(src, None)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def link_cases(
    case_a: str,
    case_b: str,
    link_type: str = "related",
    *,
    canonical: str | None = None,
    reason: str = "",
) -> dict:
    """
    Create a link between two cases.

    Args:
        case_a: First case ID
        case_b: Second case ID
        link_type: One of "duplicate", "related", "parent"
        canonical: For duplicate links, which case is the canonical one.
                   Defaults to the most recent case (highest case number).
        reason: Optional human-readable reason for the link

    Returns:
        {"status": "ok", "link_type": ..., "canonical": ..., ...}
    """
    if link_type not in LINK_TYPES:
        return {"status": "error", "reason": f"Invalid link type '{link_type}'. Valid: {', '.join(sorted(LINK_TYPES))}"}

    meta_a = _load_case_meta(case_a)
    meta_b = _load_case_meta(case_b)
    if not meta_a:
        return {"status": "error", "reason": f"Case {case_a} not found"}
    if not meta_b:
        return {"status": "error", "reason": f"Case {case_b} not found"}

    ts = utcnow()
    index = _load_links_index()

    if link_type == "duplicate":
        # Determine canonical case
        if not canonical:
            # Default: most recent case is canonical (it likely has the most data)
            _metas = {case_a: meta_a, case_b: meta_b}
            canonical = max(case_a, case_b, key=lambda c: _metas[c].get("created_at", ""))
        duplicate = case_a if canonical == case_b else case_b

        # Mark the duplicate case
        _add_link_to_meta(meta_a, case_b, "duplicate",
                          "canonical" if case_a == canonical else "duplicate", ts)
        _add_link_to_meta(meta_b, case_a, "duplicate",
                          "canonical" if case_b == canonical else "duplicate", ts)

        # Update duplicate case status
        dup_meta = meta_a if duplicate == case_a else meta_b
        dup_meta["status"] = "duplicate"
        dup_meta["canonical_case"] = canonical

    elif link_type == "parent":
        # case_a is the parent, case_b is the child
        _add_link_to_meta(meta_a, case_b, "parent", "parent", ts)
        _add_link_to_meta(meta_b, case_a, "parent", "child", ts)
        canonical = case_a

    else:  # related
        _add_link_to_meta(meta_a, case_b, "related", "related", ts)
        _add_link_to_meta(meta_b, case_a, "related", "related", ts)
        canonical = None

    # Persist
    _save_case_meta(case_a, meta_a)
    _save_case_meta(case_b, meta_b)
    _add_to_index(index, case_a, case_b, link_type, ts)
    _save_links_index(index)

    return {
        "status": "ok",
        "case_a": case_a,
        "case_b": case_b,
        "link_type": link_type,
        "canonical": canonical,
        "reason": reason,
        "ts": ts,
    }


def unlink_cases(case_a: str, case_b: str, link_type: str | None = None) -> dict:
    """
    Remove a link between two cases.

    Args:
        case_a: First case ID
        case_b: Second case ID
        link_type: Optional — remove only this link type. None removes all links between them.
    """
    meta_a = _load_case_meta(case_a)
    meta_b = _load_case_meta(case_b)

    removed = False
    if meta_a:
        if _remove_link_from_meta(meta_a, case_b, link_type):
            # If this was a duplicate link, restore status
            if meta_a.get("status") == "duplicate" and meta_a.get("canonical_case") == case_b:
                meta_a["status"] = "open"
                meta_a.pop("canonical_case", None)
            _save_case_meta(case_a, meta_a)
            removed = True

    if meta_b:
        if _remove_link_from_meta(meta_b, case_a, link_type):
            if meta_b.get("status") == "duplicate" and meta_b.get("canonical_case") == case_a:
                meta_b["status"] = "open"
                meta_b.pop("canonical_case", None)
            _save_case_meta(case_b, meta_b)
            removed = True

    index = _load_links_index()
    _remove_from_index(index, case_a, case_b, link_type)
    _save_links_index(index)

    return {"status": "ok" if removed else "no_link_found", "case_a": case_a, "case_b": case_b}


def get_links(case_id: str) -> dict:
    """
    Get all links for a case.

    Returns:
        {
            "case_id": str,
            "links": [...],
            "canonical_case": str | None,
            "duplicate_of": str | None,
            "related": [str],
            "duplicates": [str],
            "children": [str],
            "parent": str | None,
        }
    """
    meta = _load_case_meta(case_id)
    if not meta:
        return {"status": "error", "reason": f"Case {case_id} not found"}

    links = meta.get("links", [])
    result = {
        "case_id": case_id,
        "links": links,
        "canonical_case": meta.get("canonical_case"),
        "is_duplicate": meta.get("status") == "duplicate",
        "related": [],
        "duplicates": [],
        "children": [],
        "parent": None,
    }

    for link in links:
        lid = link.get("case_id")
        ltype = link.get("type")
        direction = link.get("direction")

        if ltype == "related":
            result["related"].append(lid)
        elif ltype == "duplicate":
            if direction == "canonical":
                result["duplicates"].append(lid)
            elif direction == "duplicate":
                result["duplicates"].append(lid)
        elif ltype == "parent":
            if direction == "parent":
                result["children"].append(lid)
            elif direction == "child":
                result["parent"] = lid

    return result


def merge_cases(source_ids: list[str], target_id: str, *, close_sources: bool = True) -> dict:
    """
    Merge artefacts and IOCs from source cases into the target (canonical) case.

    - Copies artefacts, IOCs, findings, and reports from sources into target
    - Links source cases as duplicates of target
    - Optionally marks source cases as status=duplicate

    This is a LOCAL operation. For Zoho integration, wrap this function and
    sync the resulting link/status changes to the service desk.

    Args:
        source_ids: Case IDs to merge FROM
        target_id: Case ID to merge INTO (becomes canonical)
        close_sources: Whether to mark source cases as duplicate (default True)
    """
    target_meta = _load_case_meta(target_id)
    if not target_meta:
        return {"status": "error", "reason": f"Target case {target_id} not found"}

    target_dir = CASES_DIR / target_id
    merged_artefacts: list[str] = []
    merged_iocs: dict = {}
    merged_findings: list[dict] = []
    errors: list[str] = []

    for src_id in source_ids:
        if src_id == target_id:
            continue

        src_meta = _load_case_meta(src_id)
        if not src_meta:
            errors.append(f"Case {src_id} not found — skipped")
            continue

        src_dir = CASES_DIR / src_id

        # Copy artefacts (skip if already exists in target)
        for subdir in ("artefacts", "uploads", "notes"):
            src_sub = src_dir / subdir
            if not src_sub.exists():
                continue
            dst_sub = target_dir / subdir
            dst_sub.mkdir(parents=True, exist_ok=True)
            for item in src_sub.rglob("*"):
                if not item.is_file():
                    continue
                rel = item.relative_to(src_sub)
                dst_path = dst_sub / rel
                if dst_path.exists():
                    # Don't overwrite — target's version takes precedence
                    continue
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(item), str(dst_path))
                merged_artefacts.append(f"{src_id}/{subdir}/{rel}")

        # Merge IOCs
        src_iocs_path = src_dir / "iocs" / "iocs.json"
        if src_iocs_path.exists():
            try:
                src_iocs = load_json(src_iocs_path).get("iocs", {})
                for itype, vals in src_iocs.items():
                    if vals:
                        existing = merged_iocs.setdefault(itype, set())
                        existing.update(vals)
            except Exception as exc:
                log_error(target_id, "case_links.merge_cases.load_iocs", str(exc),
                          severity="warning", traceback=True, context={"source_case": src_id})
                errors.append(f"Failed to load IOCs from {src_id}: {exc}")

        # Merge findings from session context
        src_ctx_path = src_dir / "session_context.json"
        if src_ctx_path.exists():
            try:
                src_ctx = load_json(src_ctx_path)
                for f in src_ctx.get("findings", []):
                    f["source_case"] = src_id
                    merged_findings.append(f)
            except Exception as exc:
                log_error(target_id, "case_links.merge_cases.load_context", str(exc),
                          severity="warning", traceback=True, context={"source_case": src_id})
                errors.append(f"Failed to load context from {src_id}: {exc}")

        # Link as duplicate
        link_cases(target_id, src_id, "duplicate", canonical=target_id,
                   reason=f"Merged into {target_id}")

        # Mark source as duplicate
        if close_sources:
            src_meta = _load_case_meta(src_id)  # reload after link_cases modified it
            if src_meta:
                src_meta["status"] = "duplicate"
                src_meta["canonical_case"] = target_id
                _save_case_meta(src_id, src_meta)

    # Apply merged IOCs to target
    if merged_iocs:
        target_iocs_path = target_dir / "iocs" / "iocs.json"
        target_iocs_path.parent.mkdir(parents=True, exist_ok=True)
        existing_iocs: dict = {}
        if target_iocs_path.exists():
            try:
                existing_iocs = load_json(target_iocs_path).get("iocs", {})
            except Exception as exc:
                log_error(target_id, "case_links.merge_cases.load_target_iocs", str(exc),
                          severity="warning", traceback=True, context={"path": str(target_iocs_path)})
                pass
        for itype, vals in merged_iocs.items():
            existing_set = set(existing_iocs.get(itype, []))
            existing_set.update(vals)
            existing_iocs[itype] = sorted(existing_set)
        save_json(target_iocs_path, {"iocs": existing_iocs, "source": "merged"})

    # Append merged findings to target notes
    if merged_findings:
        notes_dir = target_dir / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        merge_notes_path = notes_dir / "merged_findings.md"
        lines = ["# Findings Merged from Related Cases\n"]
        for f in merged_findings:
            src = f.get("source_case", "?")
            lines.append(f"- **[{f.get('type', '?')}]** ({src}) {f.get('summary', '')}")
            if f.get("detail"):
                lines.append(f"  {f['detail']}")
        existing_text = merge_notes_path.read_text(errors="replace") if merge_notes_path.exists() else ""
        merge_notes_path.write_text(existing_text + "\n".join(lines) + "\n")

    # Update target metadata
    target_meta["updated_at"] = utcnow()
    _save_case_meta(target_id, target_meta)

    return {
        "status": "ok",
        "target": target_id,
        "sources": source_ids,
        "artefacts_merged": len(merged_artefacts),
        "ioc_types_merged": list(merged_iocs.keys()),
        "findings_merged": len(merged_findings),
        "errors": errors,
        "ts": utcnow(),
    }


def find_related(case_id: str, *, depth: int = 2) -> list[str]:
    """
    Walk the link graph from a case to find all transitively related cases.

    Args:
        case_id: Starting case
        depth: How many hops to follow (default 2)

    Returns:
        List of related case IDs (excluding the starting case)
    """
    index = _load_links_index()
    visited: set[str] = set()
    queue = [case_id]
    current_depth = 0

    while queue and current_depth < depth:
        next_queue: list[str] = []
        for cid in queue:
            if cid in visited:
                continue
            visited.add(cid)
            for entry in index.get(cid, []):
                linked = entry["case_id"]
                if linked not in visited:
                    next_queue.append(linked)
        queue = next_queue
        current_depth += 1

    visited.discard(case_id)
    return sorted(visited)


# ---------------------------------------------------------------------------
# External references (Zoho / SOAR)
# ---------------------------------------------------------------------------

# Known external reference keys — extend as integrations are added.
# These are stored in case_meta.json under "external_refs".
EXTERNAL_REF_KEYS = {
    "zoho_ticket_id",       # Zoho Service Desk ticket ID
    "zoho_ticket_number",   # Zoho human-readable ticket number
    "incident_id",          # SOAR / SIEM incident ID
    "sentinel_incident_id", # Microsoft Sentinel incident ID
    "sentinel_incident_number",
    "crowdstrike_detection_id",
}


def set_external_ref(case_id: str, ref_key: str, ref_value: str) -> dict:
    """
    Attach an external platform reference to a case.

    Args:
        case_id: Local case ID
        ref_key: Reference key (e.g. "zoho_ticket_id", "incident_id")
        ref_value: The external ID value

    Returns:
        {"status": "ok", ...}
    """
    meta = _load_case_meta(case_id)
    if not meta:
        return {"status": "error", "reason": f"Case {case_id} not found"}

    refs = meta.setdefault("external_refs", {})
    refs[ref_key] = ref_value
    meta["updated_at"] = utcnow()
    _save_case_meta(case_id, meta)

    return {"status": "ok", "case_id": case_id, "ref_key": ref_key, "ref_value": ref_value}


def get_external_ref(case_id: str, ref_key: str | None = None) -> dict:
    """
    Get external references for a case.

    Args:
        case_id: Local case ID
        ref_key: Optional — get a specific ref. None returns all refs.
    """
    meta = _load_case_meta(case_id)
    if not meta:
        return {"status": "error", "reason": f"Case {case_id} not found"}

    refs = meta.get("external_refs", {})
    if ref_key:
        return {"status": "ok", "case_id": case_id, "ref_key": ref_key, "ref_value": refs.get(ref_key)}
    return {"status": "ok", "case_id": case_id, "external_refs": refs}


def find_by_external_ref(ref_key: str, ref_value: str) -> str | None:
    """
    Find a local case ID by an external reference.

    Scans case_meta.json files — for production scale, this should be indexed.
    Useful for Zoho webhook handlers that receive a ticket ID and need the local case.
    """
    if not CASES_DIR.exists():
        return None
    for case_dir in CASES_DIR.iterdir():
        if not case_dir.is_dir():
            continue
        meta_path = case_dir / "case_meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = load_json(meta_path)
            refs = meta.get("external_refs", {})
            if refs.get(ref_key) == ref_value:
                return meta.get("case_id", case_dir.name)
        except Exception as exc:
            log_error("", "case_links.find_by_external_ref", str(exc),
                      severity="warning", traceback=True, context={"path": str(meta_path)})
            continue
    return None
