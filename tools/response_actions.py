"""
tool: response_actions
-----------------------
Deterministic client-specific response plan generator.

Resolves the client playbook against case evidence (verdict summary, severity,
crown jewels) and outputs a structured, actionable response plan. No LLM call
— purely rule-based resolution.

Results are computed and returned to the caller; no artefacts are persisted to disk.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, CLIENT_PLAYBOOKS_DIR
from tools.common import load_json, log_error, utcnow


# ---------------------------------------------------------------------------
# Severity → priority mapping
# ---------------------------------------------------------------------------

_SEVERITY_TO_PRIORITY = {
    "critical": "p1",
    "high":     "p2",
    "medium":   "p3",
    "low":      "p4",
}

_RESPONSE_ACTION_LABELS = {
    "asset_containment":              "Asset Containment",
    "confirm_asset_containment":      "Confirm Asset Containment",
    "asset_containment_not_required": "Not Required (Blocked)",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_load(path: Path) -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "response_actions.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _load_playbook(client: str) -> dict | None:
    """Load client playbook from config/clients/<client>/playbook.json or legacy flat layout."""
    slug = client.lower().replace(" ", "_")
    candidates = [
        CLIENT_PLAYBOOKS_DIR / slug / "playbook.json",
        CLIENT_PLAYBOOKS_DIR / f"{slug}.json",
    ]
    for path in candidates:
        data = _safe_load(path)
        if data is not None:
            return data
    return None


def _match_alert_override(playbook: dict, title: str) -> dict | None:
    """Check response[] for alert-name-specific overrides matched against case title."""
    for entry in playbook.get("response", []):
        alert_name = entry.get("alert_name", "none")
        if alert_name and alert_name.lower() != "none":
            if alert_name.lower() in title.lower():
                return entry
    return None


def _check_crown_jewels(playbook: dict, malicious_iocs: list[str]) -> bool:
    """Check if any malicious IOC target host is a crown jewel.

    Supports wildcard patterns (e.g. ``"karel*chudej*"``) via fnmatch.
    """
    from fnmatch import fnmatch

    crown_hosts = [h.lower() for h in playbook.get("crown_jewels", {}).get("hosts", [])]
    if not crown_hosts:
        return False
    for ioc in malicious_iocs:
        ioc_lower = ioc.lower()
        for pattern in crown_hosts:
            if fnmatch(ioc_lower, pattern):
                return True
    return False


def _resolve_escalation(playbook: dict, priority: str) -> list[dict]:
    """Filter escalation_matrix by priority, return matching entries."""
    matches = []
    for entry in playbook.get("escalation_matrix", []):
        if entry.get("priority", "").lower() == priority.lower():
            matches.append(entry)
    return matches


def _get_default_contact_process(playbook: dict) -> str:
    """Get default contact process from the response[] entry with priority=none."""
    for entry in playbook.get("response", []):
        if entry.get("priority", "").lower() == "none":
            return entry.get("contact_process", "")
    return ""


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def _render_markdown(data: dict) -> str:
    """Render response_actions.json into a human-readable markdown summary."""
    lines = [
        f"# Response Actions — {data['case_id']}",
        "",
        f"**Client:** {data['client']}",
        f"**Priority:** {data['priority'].upper()} ({data['priority_source']})",
        f"**Generated:** {data['ts']}",
        "",
    ]

    # Crown jewel warning
    if data.get("crown_jewel_match"):
        lines.append("> **CROWN JEWEL ALERT:** A malicious IOC matches a crown jewel host. "
                     "Priority escalated to P1.")
        lines.append("")

    # Alert override
    if data.get("alert_override_match"):
        lines.append(f"> **Alert-specific override matched:** {data['alert_override_match']}")
        lines.append("")

    # Escalation
    esc = data.get("escalation", {})
    lines.append("## Escalation Procedure")
    lines.append("")
    contact = esc.get("contact_process", "N/A")
    if contact:
        lines.append(f"**Contact process:** {contact}")
        lines.append("")

    # Response matrix table
    permitted = esc.get("permitted_actions", [])
    if permitted:
        lines.append(f"### Response Matrix ({data['priority'].upper()})")
        lines.append("")
        lines.append("| Asset Type | Blocked | SD Ticket | Phone Call | Response Action |")
        lines.append("|------------|---------|-----------|------------|-----------------|")
        for entry in permitted:
            if isinstance(entry, dict):
                asset = entry.get("asset_type", "any")
                blocked = "Yes" if entry.get("activity_blocked") else "No"
                sd = entry.get("sd_ticket", "standard").capitalize()
                phone = "Yes" if entry.get("phone_call") else "No"
                action = _RESPONSE_ACTION_LABELS.get(
                    entry.get("response_action", "asset_containment"),
                    entry.get("response_action", "Asset Containment"),
                )
                lines.append(f"| {asset} | {blocked} | {sd} | {phone} | {action} |")
        lines.append("")

    contacts = esc.get("contacts", [])
    if contacts and any(c for c in contacts if c):
        lines.append("### Contacts")
        for c in contacts:
            if c:
                parts = [f"{k}: {v}" for k, v in c.items() if v]
                if parts:
                    lines.append(f"- {', '.join(parts)}")
        lines.append("")

    # Containment capabilities
    caps = data.get("containment_capabilities", [])
    if caps:
        lines.append("## Available Containment Actions (SOC-Executed)")
        lines.append("")
        for group in caps:
            lines.append(f"### {group.get('technology', 'Unknown')}")
            for a in group.get("actions", []):
                lines.append(f"- {a}")
            lines.append("")

    # Remediation actions
    remed = data.get("remediation_actions", [])
    if remed:
        lines.append("## Recommended Remediation (Client Responsibility)")
        lines.append("")
        for group in remed:
            lines.append(f"### {group.get('technology', 'Unknown')}")
            for a in group.get("actions", []):
                lines.append(f"- {a}")
            lines.append("")

    # IOCs
    mal = data.get("malicious_iocs", [])
    sus = data.get("suspicious_iocs", [])
    if mal or sus:
        lines.append("## IOCs Requiring Action")
        if mal:
            lines.append(f"\n### Malicious ({len(mal)})")
            for ioc in mal:
                lines.append(f"- `{ioc}`")
        if sus:
            lines.append(f"\n### Suspicious ({len(sus)})")
            for ioc in sus:
                lines.append(f"- `{ioc}`")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def generate_response_actions(case_id: str) -> dict:
    """
    Generate a deterministic, client-specific response plan for *case_id*.

    Returns a result dict with escalation, containment, and remediation data.
    """
    case_dir = CASES_DIR / case_id

    # Load case metadata
    meta = _safe_load(case_dir / "case_meta.json")
    if not meta:
        return {"status": "skipped", "reason": "No case_meta.json found", "case_id": case_id, "ts": utcnow()}

    client = meta.get("client", "")
    severity = meta.get("severity", "medium")
    title = meta.get("title", "")

    # Skip if no client configured
    if not client:
        return {"status": "skipped", "reason": "No client playbook configured", "case_id": case_id, "ts": utcnow()}

    # Load client playbook
    playbook = _load_playbook(client)
    if not playbook:
        return {"status": "skipped", "reason": f"No client playbook found for '{client}'",
                "case_id": case_id, "ts": utcnow()}

    # Load verdict summary
    verdict = _safe_load(case_dir / "artefacts" / "enrichment" / "verdict_summary.json")
    malicious_iocs = verdict.get("high_priority", []) if verdict else []
    suspicious_iocs = verdict.get("needs_review", []) if verdict else []

    # Skip if no actionable IOCs
    if not malicious_iocs and not suspicious_iocs:
        return {"status": "skipped", "reason": "No malicious/suspicious IOCs",
                "case_id": case_id, "ts": utcnow()}

    # --- Playbook resolution ---

    # 1. Base priority from severity
    priority = _SEVERITY_TO_PRIORITY.get(severity, "p3")
    priority_source = "severity_mapping"

    # 2. Crown jewel check — escalate to p1 if matched
    crown_match = _check_crown_jewels(playbook, malicious_iocs)
    if crown_match:
        priority = "p1"
        priority_source = "crown_jewel_escalation"

    # 3. Alert-name override
    alert_override = _match_alert_override(playbook, title)
    alert_override_name = None
    if alert_override:
        override_priority = alert_override.get("priority", "").lower()
        if override_priority and override_priority != "none":
            priority = override_priority
            priority_source = "alert_override"
        alert_override_name = alert_override.get("alert_name")

    # 4. Resolve escalation matrix
    escalation_entries = _resolve_escalation(playbook, priority)
    permitted_actions = []
    for entry in escalation_entries:
        permitted_actions.append({
            "asset_type": entry.get("asset_type", "any"),
            "activity_blocked": entry.get("activity_blocked"),
            "sd_ticket": entry.get("sd_ticket", "standard"),
            "phone_call": entry.get("phone_call", False),
            "response_action": entry.get("response_action", "asset_containment"),
            "actions": entry.get("actions", []),
        })

    # 5. Contact process
    contact_process = _get_default_contact_process(playbook)
    if alert_override and alert_override.get("contact_process"):
        contact_process = alert_override["contact_process"]

    # Build result
    result = {
        "case_id": case_id,
        "client": client,
        "priority": priority,
        "priority_source": priority_source,
        "escalation": {
            "contact_process": contact_process,
            "contacts": playbook.get("contacts", []),
            "permitted_actions": permitted_actions,
        },
        "containment_capabilities": playbook.get("containment_capabilities", []),
        "remediation_actions": playbook.get("remediation_actions", []),
        "malicious_iocs": malicious_iocs,
        "suspicious_iocs": suspicious_iocs,
        "crown_jewel_match": crown_match,
        "alert_override_match": alert_override_name,
        "status": "ok",
        "ts": utcnow(),
    }

    # LLM response prioritisation (advisory)
    try:
        from tools.llm_insight import prioritise_response_actions
        llm_priority = prioritise_response_actions(result, meta)
        if llm_priority:
            result["llm_priority_assessment"] = llm_priority
    except Exception:
        pass

    print(f"[response_actions] Response plan generated for {case_id} "
          f"(client={client}, priority={priority}, source={priority_source})")
    return result
