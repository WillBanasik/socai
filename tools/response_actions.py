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

from config.settings import CASES_DIR
from tools.common import eprint, get_client_config, load_json, log_error, utcnow


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
# Containment & remediation authority (capability layer)
# ---------------------------------------------------------------------------
# General rule of thumb — what the SOC is *technically able* to do, derived from
# the client's platform / identity-plane access. The per-client GitHub response
# process is the authority of record and overrides this (see _apply_containment
# _override). Canonical reference: docs/containment-authority.md
# (socai://containment-authority).

# Identity actions split by platforms.identity_response. Per SOP the analyst's
# identity authority is password reset + session revoke ONLY; everything that
# changes the account's standing is client remediation.
_IDENTITY_CAPABILITY = {
    "performanta_delegated": {
        "analyst": [
            "Reset password",
            "Revoke sessions (invalidates refresh tokens; ~1 h access-token tail)",
        ],
        "client": [
            "Reset / re-register MFA",
            "Disable account",
            "Revoke OAuth / app-consent grant",
        ],
    },
    "client_actioned": {
        "analyst": [],
        "client": [
            "Reset password",
            "Revoke sessions",
            "Reset / re-register MFA",
            "Disable account",
            "Revoke OAuth / app-consent grant",
        ],
    },
}

# Endpoint containment is symmetric across EDR/XDR — the SOC actions it wherever
# we hold the action API. No SOC-vs-client split, only the GitHub override.
_ENDPOINT_ACTIONS = [
    "Network contain / isolate device",
    "Add IOCs (block hash / domain / IP)",
    "AV / on-demand scan",
]

# GitHub response-template top-level containment_policy → effect on SOC execution.
_CONTAINMENT_POLICY_EFFECT = {
    "pre_approved":  {"soc_may_execute": True,  "label": "Pre-approved — SOC may execute permitted containment"},
    "confirm_first": {"soc_may_execute": True,  "label": "Confirm-first — SOC must confirm with client before containing"},
    "prohibited":    {"soc_may_execute": False, "label": "Prohibited — SOC must NOT contain; notify only"},
}


def _compute_containment_authority(client: str, playbook: dict) -> dict:
    """Resolve who actions containment/remediation for *client*.

    Capability layer (rule of thumb, from ``platforms``) gated by the GitHub
    response process (authority of record — can only restrict). See
    docs/containment-authority.md.
    """
    cfg = get_client_config(client) or {}
    platforms = cfg.get("platforms", {}) or {}

    identity_mode = str(platforms.get("identity_response", "client_actioned")).lower()
    if identity_mode not in _IDENTITY_CAPABILITY:
        identity_mode = "client_actioned"
    identity_cap = _IDENTITY_CAPABILITY[identity_mode]

    # Some delegated clients action identity through an integration that fuses
    # password reset + session revoke into a single, non-separable action
    # (e.g. NetIQ at UoP) — collapse the two discrete analyst actions into one
    # combined entry so the plan doesn't imply they can be done independently.
    identity_integration = str(platforms.get("identity_integration", "")).lower()
    analyst_identity = list(identity_cap["analyst"])
    if identity_mode == "performanta_delegated" and identity_integration == "netiq":
        analyst_identity = [
            "Reset password + revoke sessions (combined — actioned together via "
            "NetIQ; the two cannot be performed separately)"
        ]

    # Endpoint capability — present wherever we hold an EDR/XDR action API.
    endpoint_tech = []
    if (platforms.get("defender_xdr") or {}).get("api_enabled"):
        endpoint_tech.append("Defender XDR")
    if (platforms.get("crowdstrike") or {}).get("api_enabled"):
        endpoint_tech.append("CrowdStrike Falcon")
    endpoint_actions = list(_ENDPOINT_ACTIONS) if endpoint_tech else []

    # GitHub override gate — authority of record, can only restrict.
    policy = str(playbook.get("containment_policy", "pre_approved")).lower()
    effect = _CONTAINMENT_POLICY_EFFECT.get(policy, _CONTAINMENT_POLICY_EFFECT["pre_approved"])
    soc_may_execute = effect["soc_may_execute"]

    # SOC-executed actions = analyst identity actions + endpoint actions,
    # suppressed when the client response process prohibits containment.
    soc_actions = list(analyst_identity) + endpoint_actions
    suppressed = (not soc_may_execute) and bool(soc_actions)

    return {
        "identity_response_mode": identity_mode,
        "identity_integration": identity_integration or None,
        "identity_analyst_actions": analyst_identity,
        "identity_client_actions": identity_cap["client"],
        "endpoint_technologies": endpoint_tech,
        "endpoint_actions": endpoint_actions,
        "soc_executed_actions": soc_actions,
        "containment_policy": policy,
        "containment_policy_label": effect["label"],
        "soc_may_execute": soc_may_execute,
        "soc_actions_suppressed": suppressed,
        "suppression_reason": (
            f"Suppressed by client response process (containment_policy={policy})"
            if suppressed else None
        ),
        "note": "Capability = what the SOC can do (platform access). The GitHub "
                "response process is the authority of record and overrides it.",
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


_GH_PLAYBOOK_REPO = "PerformantaLab/mdr_soar"


def _resolve_template_slug(client: str) -> str:
    """Map a socai client name to its GitHub response-template slug.

    Defaults to the client-name slug. An explicit ``response_template`` field in
    client_entities.json overrides it — used where the GitHub filename differs
    from the socai client name (e.g. ``aztec_group`` → ``aztec``,
    ``southern_sun`` → ``tsogo``).
    """
    cfg = get_client_config(client)
    if cfg and cfg.get("response_template"):
        return str(cfg["response_template"]).strip()
    return client.lower().replace(" ", "_")


def _fetch_github_playbook(template_slug: str) -> dict | None:
    """Fetch a client response template live from PerformantaLab/mdr_soar via ``gh``.

    GitHub is the single source of truth for client response playbooks — no local
    copies are kept. Returns the parsed playbook dict, or None if the template does
    not exist, ``gh`` is unavailable, or the fetch/parse fails (all degrade to None
    so callers fall back to a generic response plan).
    """
    import base64, json, re, subprocess  # noqa: PLC0415

    gh_path = f"client_response_templates/{template_slug}.json"
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{_GH_PLAYBOOK_REPO}/contents/{gh_path}", "--jq", ".content"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            # 404 (template absent) is normal; anything else (auth, gh missing) is worth a note.
            stderr = (result.stderr or "").strip()
            if "404" not in stderr and "Not Found" not in stderr:
                log_error("", "response_actions.fetch_github_playbook",
                          f"gh exited {result.returncode}: {stderr[:300]}",
                          severity="warning",
                          context={"template_slug": template_slug, "gh_path": gh_path})
            return None
        if not result.stdout.strip():
            return None
        raw = base64.b64decode(result.stdout.strip()).decode()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # GitHub templates sometimes carry trailing commas (valid JS, invalid
            # JSON) — strip ``,`` before a closing ``}``/``]`` and retry. Only
            # reached for already-malformed files; valid JSON is never rewritten.
            return json.loads(re.sub(r",(\s*[}\]])", r"\1", raw))
    except Exception as exc:
        log_error("", "response_actions.fetch_github_playbook", str(exc),
                  severity="warning", context={"template_slug": template_slug, "gh_path": gh_path})
    return None


def _load_playbook(client: str) -> dict | None:
    """Load a client's response playbook live from GitHub (PerformantaLab/mdr_soar).

    GitHub is authoritative — no local copies. The client name maps to a template
    slug (overridable via ``response_template`` in client_entities.json). Returns
    None when no template exists for the client.
    """
    return _fetch_github_playbook(_resolve_template_slug(client))


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

    # Containment authority (capability layer + GitHub override)
    auth = data.get("containment_authority")
    if auth:
        lines.append("## Containment Authority")
        lines.append("")
        lines.append(f"> Capability rule of thumb (identity mode: `{auth['identity_response_mode']}`), "
                     "gated by the client's GitHub response process. "
                     "GitHub is the authority of record and can only restrict.")
        lines.append("")
        lines.append(f"**Client response process:** {auth['containment_policy_label']}")
        lines.append("")
        if auth.get("soc_actions_suppressed"):
            lines.append(f"> **Containment withheld — {auth['suppression_reason']}.** "
                         "The actions below are within SOC *capability* but the client's "
                         "agreed response process prohibits SOC execution — notify only.")
            lines.append("")

        # SOC-executed (identity analyst actions + endpoint)
        soc = auth.get("soc_executed_actions", [])
        if soc:
            tail = " — *SUPPRESSED, notify only*" if auth.get("soc_actions_suppressed") else ""
            lines.append(f"### SOC-Executed (capability){tail}")
            for a in soc:
                lines.append(f"- {a}")
            if auth.get("endpoint_technologies"):
                lines.append(f"- _Endpoint via: {', '.join(auth['endpoint_technologies'])}_")
            lines.append("")
        else:
            lines.append("### SOC-Executed (capability)")
            lines.append("- _None — no SOC-actionable identity or endpoint capability for this client._")
            lines.append("")

        # Client responsibility (identity remediation)
        client_ident = auth.get("identity_client_actions", [])
        if client_ident:
            lines.append("### Client Responsibility (identity)")
            for a in client_ident:
                lines.append(f"- {a}")
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

    # 6. Containment authority — capability (rule of thumb) gated by GitHub override
    containment_authority = _compute_containment_authority(client, playbook)

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
        "containment_authority": containment_authority,
        "containment_capabilities": playbook.get("containment_capabilities", []),
        "remediation_actions": playbook.get("remediation_actions", []),
        "malicious_iocs": malicious_iocs,
        "suspicious_iocs": suspicious_iocs,
        "crown_jewel_match": crown_match,
        "alert_override_match": alert_override_name,
        "status": "ok",
        "ts": utcnow(),
    }

    eprint(f"[response_actions] Response plan generated for {case_id} "
          f"(client={client}, priority={priority}, source={priority_source})")
    return result
