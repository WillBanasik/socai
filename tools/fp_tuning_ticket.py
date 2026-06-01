"""
tool: fp_tuning_ticket
----------------------
FP tuning ticket context builder and helpers.

The tuning ticket is now written by the local Claude Desktop agent using the
``write_fp_tuning`` MCP prompt, then persisted via
``save_report(type=fp_tuning_ticket)``.

This module retains ``_SYSTEM_PROMPT``, ``_SYSTEM_CACHED``, and
``_build_context()`` which the MCP prompt imports.  It also keeps
``_resolve_workspace_id()`` and ``_build_recurrence_context()`` for
live-query resolution and prior-case recall.

Unlike ``closure_comment`` (the 2-sentence Sentinel-aligned closure note),
the tuning ticket is a full engineering handoff document: it states whether the
detection fired correctly, branches remediation by control model (SIEM rule edit
vs EDR SOAR suppression), carries the source product incident IDs, and ends with
a machine-readable JSON block so a downstream (AI) engineering pipeline can act on
it. Auto-closes the case on save — disposition defaults to ``false_positive``
(detection fired incorrectly) but the caller may override to ``benign_positive``
(fired correctly on authorised activity → suppress).

Output (via save_report):
  cases/<case_id>/artefacts/fp_comms/fp_tuning_ticket.md
  cases/<case_id>/artefacts/fp_comms/fp_tuning_ticket_manifest.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, utcnow

# ---------------------------------------------------------------------------
# Workspace resolution helpers
# ---------------------------------------------------------------------------


def _resolve_workspace_id(alert_data: dict | None, case_id: str) -> str | None:
    """Resolve the Sentinel Log Analytics workspace GUID for this case.

    Resolution order (EXACT only — never fuzzy):
      1. ``alert_data["WorkspaceId"]`` — the workspace the alert actually came from.
      2. The case client's configured Sentinel ``workspace_id`` (exact client-name
         match via ``get_client_config``).

    Returns ``None`` rather than guessing. The previous implementation fuzzy-matched
    ``alert_data["DataSources"]`` as a substring against client names, which could
    bind a ticket to the WRONG client's workspace_id — a cross-client leak. It also
    compared ``TenantId`` against ``workspace_id`` (semantically different GUIDs).
    Do not reintroduce either fallback.
    """
    if isinstance(alert_data, dict):
        wid = alert_data.get("WorkspaceId")
        if wid:
            return str(wid)

    meta = _safe_load(CASES_DIR / case_id / "case_meta.json", case_id) or {}
    client = (meta.get("client") or "").strip()
    if not client:
        return None

    try:
        from tools.common import get_client_config
        cfg = get_client_config(client)
    except Exception as exc:
        log_error(case_id, "fp_tuning_ticket.resolve_workspace", str(exc), severity="info")
        return None
    if not isinstance(cfg, dict):
        return None

    sentinel = (cfg.get("platforms") or {}).get("sentinel") or {}
    if isinstance(sentinel, dict) and sentinel.get("workspace_id"):
        return sentinel["workspace_id"]
    return cfg.get("workspace_id") or None


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a SOC analyst writing a detection TUNING TICKET. This ticket is an engineering \
handoff: a detection-engineering pipeline (increasingly AI-driven) must be able to pick it \
up and act on it WITHOUT having seen the original alert. Be specific and machine-actionable.

Write the ticket as markdown with the sections below, in order. All sections are required; \
where data is genuinely absent, write "Unknown — <what is missing>" rather than guessing.

### 1. Determination — did the detection fire correctly?
State ONE of exactly two outcomes up front, in bold:
- **Fired incorrectly (False Positive)** — the detection logic itself is wrong (it matched \
  activity it should never have matched). This is a logic defect.
- **Fired correctly but benign (Benign Positive)** — the logic worked; the matched activity \
  is real but authorised/expected, so it is noise to be suppressed, not a logic fix.
Do NOT conflate the two — the remediation differs (FP → fix the logic, SIEM only; BP → suppress).

### 2. Why — rationale & factors considered
- The case evidence that proves the determination (entities, enrichment verdicts, client \
  baseline / known-good context, prior-case recurrence). Never assert without case data.
- The factors weighed: entity scope, time window / threshold, allowlist gaps, legitimate \
  admin or automation patterns, environment-specific known-good, data-quality issues.
- If FP: precisely which part of the logic is over-broad or wrong, and why it misfired.
- If BP: why the activity is authorised and why suppression (not a logic change) is correct.

### 3. Source & provenance (machine-consumable)
Reproduce EVERY source identifier available so the engineering pipeline can locate the \
originating detection: source product, incident number/ID, alert ID(s), analytic/rule ID, \
rule name, workspace ID, tenant ID, EDR detection/composite IDs, and any alert link. These \
are listed in the "Source Identifiers" block of the context — copy them verbatim.

### 4. Detection identification & control model
- Detection platform and product.
- The control model (see the Detection-Control Model block in context): SIEM detections \
  (Microsoft Sentinel) are Performanta-controlled — the analytic rule logic is directly \
  editable. EDR detections (Defender XDR, CrowdStrike Falcon) are vendor-controlled — \
  Performanta CANNOT edit the detector; the only lever is SUPPRESSION via SOAR.
- Data source table(s) and MITRE ATT&CK technique if mapped.

### 5. Remediation — follow the control model
Use the branch that matches the platform:

**(A) SIEM (Sentinel) — tune the rule:**
- **Before:** the current rule logic (KQL). If the exact query is not provided, describe the \
  logic as precisely as possible / as commented pseudocode.
- **After:** the modified logic with the fix applied — tighter WHERE clause, entity \
  allowlist, threshold or time-window change, correlation enrichment, or severity downgrade \
  (choose what fits the root cause).
- Explain each change and why it removes the FP without blinding the rule to real threats.

**(B) EDR (Defender XDR / CrowdStrike Falcon) — suppress via SOAR:**
- You CANNOT rewrite the detector. Do NOT propose detector-logic edits.
- Specify the exact SUPPRESSION CRITERIA: the precise entity/condition set to suppress \
  (e.g. this hash on these hosts, this command line for this service account), scoped as \
  tightly as the evidence allows.
- **SOAR Suppression Plan:** leave this as a structured placeholder — the SOAR suppression \
  mechanism is not yet defined (context to follow). Give the criteria the SOAR action will \
  consume, and mark the execution steps "TBD — pending SOAR suppression procedure".

### 6. Impact assessment
- Does the change risk suppressing real threats? Evaluate honestly.
- What monitoring gap (if any) does it create, and what compensating control covers it?
- Scope of the change (how many entities, how broad).

### 7. Recurrence
- Has this pattern been seen before? Use the prior-case recurrence data in context — how \
  many times, over what period, with what dispositions. Is permanent exclusion/suppression \
  warranted?

### 8. Machine-readable handoff
End the ticket with a SINGLE fenced ```json block (and nothing after it) capturing the \
ticket in structured form for the downstream pipeline. Use exactly these keys; use null \
(or [] ) for unknowns, and make every value consistent with the prose above:
```json
{
  "determination": "false_positive | benign_positive",
  "fired_correctly": false,
  "platform": "sentinel | defender_xdr | crowdstrike | other",
  "control_type": "siem_rule_edit | edr_soar_suppression",
  "source_ids": {"<FieldName>": "<value>"},
  "rule": {"id": null, "name": null, "analytic_rule_ids": []},
  "workspace_id": null,
  "tenant_id": null,
  "mitre_techniques": [],
  "recommended_action": "<one line: tune rule | suppress via SOAR>",
  "suppression_criteria": null,
  "entities": {"users": [], "hosts": [], "ips": [], "processes": [], "hashes": []},
  "soar_suppression": {"status": "tbd_pending_procedure", "criteria": null},
  "recurrence": {"prior_case_count": 0, "permanent_exclusion_recommended": false}
}
```

RULES:
1. Be SPECIFIC — "add an allowlist" is useless without the actual entities to allow/suppress.
2. SIEM gets before/after logic; EDR gets suppression criteria + the SOAR placeholder — \
   never propose editing an EDR detector's logic.
3. Cite case evidence for every claim; never speculate (analytical standards apply).
4. Tone: technical, direct, structured — an engineering document, not a narrative.
5. The source_ids in the JSON block MUST match the Source Identifiers given in context.
6. Output the markdown ticket only — no preamble, no sign-off; the json block is the last thing.
"""

# ---------------------------------------------------------------------------
# Source-identifier extraction + control model (engineering handoff)
# ---------------------------------------------------------------------------

# Identifier fields that locate the originating detection, per product. Used to
# give the downstream (AI) engineering pipeline machine-consumable provenance.
_SOURCE_ID_FIELDS = {
    "sentinel": [
        "IncidentNumber", "IncidentName", "SystemAlertId", "AlertIds",
        "AlertName", "RelatedAnalyticRuleIds", "ProviderName",
        "WorkspaceId", "TenantId", "AlertLink",
    ],
    "defender_xdr": [
        "IncidentId", "incidentId", "AlertId", "alertId",
        "DetectionSource", "DetectorId", "Title",
    ],
    "crowdstrike": [
        "detection_id", "composite_id", "incident_id", "DetectId",
        "pattern_id", "rule_name", "cid",
    ],
}

_KNOWN_ID_FIELDS = {f.lower() for fields in _SOURCE_ID_FIELDS.values() for f in fields}

_SIEM_PLATFORMS = {"sentinel"}
_EDR_PLATFORMS = {"defender_xdr", "crowdstrike"}


def _extract_source_ids(alert_data: str) -> dict:
    """Best-effort pull of source incident/alert identifiers from raw alert JSON.

    Recursively walks the parsed alert and collects any known identifier field
    (see ``_SOURCE_ID_FIELDS``). Non-JSON alert text returns ``{}`` — the raw
    block in the prompt still carries whatever IDs it contains.
    """
    if not alert_data:
        return {}
    try:
        data = json.loads(alert_data)
    except (ValueError, TypeError):
        return {}

    found: dict[str, str] = {}

    def _walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in _KNOWN_ID_FIELDS and v not in (None, "", []):
                    # Scalar id field, or a list of scalar ids (e.g. AlertIds,
                    # RelatedAnalyticRuleIds) — capture and don't recurse into it.
                    if isinstance(v, list) and all(
                        not isinstance(x, (dict, list)) for x in v
                    ):
                        found.setdefault(k, ", ".join(str(x) for x in v))
                        continue
                    if not isinstance(v, (dict, list)):
                        found.setdefault(k, str(v))
                        continue
                if isinstance(v, (dict, list)):
                    _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return found


def _infer_platform(alert_data: str, platform_override: str | None) -> str:
    """Infer the detection product from an override or alert-data signals.

    Heuristic only — a hint for the ticket author, who confirms against the
    control-model context. Returns sentinel|defender_xdr|crowdstrike|other.
    """
    if platform_override:
        p = platform_override.strip().lower()
        if p in ("defender", "defender_xdr", "mde", "mdatp", "xdr"):
            return "defender_xdr"
        if p in ("crowdstrike", "falcon", "ngsiem"):
            return "crowdstrike"
        if p == "sentinel":
            return "sentinel"
        return p
    text = (alert_data or "").lower()
    if any(s in text for s in ("crowdstrike", "falcon", "composite_id", "detection_id")):
        return "crowdstrike"
    if any(s in text for s in ("defender", "mdatp", "\"incidentid\"", "microsoft 365 defender")):
        return "defender_xdr"
    if any(s in text for s in ("sentinel", "workspaceid", "incidentnumber", "analyticrule")):
        return "sentinel"
    return "other"


def _control_model_context(case_id: str, platform: str) -> str:
    """Markdown describing the SIEM-vs-EDR control model for this case/client."""
    meta = _safe_load(CASES_DIR / case_id / "case_meta.json", case_id) or {}
    client = (meta.get("client") or "").strip()
    lines = [
        "## Detection-Control Model (where Performanta can act)",
        "",
        "- **SIEM — Microsoft Sentinel:** Performanta-controlled. The analytic rule "
        "logic is directly editable (KQL, thresholds, entity mapping, allowlists, "
        "scheduling). False positives are fixed by tuning the rule.",
        "- **EDR — Defender XDR / CrowdStrike Falcon:** vendor-controlled detection "
        "logic. Performanta **cannot edit the detector**. The only lever is "
        "**suppression via SOAR**. The exact SOAR suppression procedure is **not yet "
        "defined (context to follow)** — produce the suppression criteria and leave the "
        "SOAR execution steps as a TBD placeholder for the engineering pipeline.",
        "",
    ]
    if platform in _EDR_PLATFORMS:
        lines.append(
            f"> This alert is **EDR ({platform})** — remediation is SOAR suppression, "
            "not a detector-logic edit."
        )
    elif platform in _SIEM_PLATFORMS:
        lines.append(
            "> This alert is **SIEM (Sentinel)** — remediation is a rule-logic tune."
        )
    else:
        lines.append(
            "> Platform not conclusively identified — confirm SIEM vs EDR before "
            "choosing the remediation branch."
        )
    if client:
        try:
            from tools.common import get_client_config
            cfg = get_client_config(client) or {}
        except Exception:
            cfg = {}
        platforms = (cfg.get("platforms") or {}) if isinstance(cfg, dict) else {}
        configured = [p for p in ("sentinel", "defender_xdr", "crowdstrike") if p in platforms]
        if configured:
            lines.append("")
            lines.append(f"**{client} configured detection platforms:** {', '.join(configured)}")
    lines.append("")
    return "\n".join(lines)


def fp_handoff_context(case_id: str, alert_data: str = "",
                       platform_override: str | None = None) -> str:
    """Assemble the engineering-handoff context injected into the write_fp_tuning
    prompt: control model, source identifiers, inferred platform, and prior-case
    recurrence. Keeps the prompt body thin and the logic unit-testable.
    """
    platform = _infer_platform(alert_data, platform_override)

    source_ids = _extract_source_ids(alert_data)
    # Backfill the workspace from the case client when the alert omits it.
    if "WorkspaceId" not in source_ids:
        try:
            alert_obj = json.loads(alert_data) if alert_data else None
        except (ValueError, TypeError):
            alert_obj = None
        ws = _resolve_workspace_id(alert_obj if isinstance(alert_obj, dict) else None, case_id)
        if ws:
            source_ids["WorkspaceId"] = ws

    parts = [_control_model_context(case_id, platform), ""]

    parts.append("## Source Identifiers (copy verbatim into the ticket + JSON block)")
    if source_ids:
        for k, v in source_ids.items():
            parts.append(f"- **{k}:** {v}")
    else:
        parts.append("- None parsed from alert data — extract any IDs from the raw "
                     "Alert Data block below; use null where genuinely absent.")
    parts.append(f"\n**Inferred platform:** {platform} "
                 "(confirm against the control model above).")
    parts.append("")

    recurrence = _build_recurrence_context(case_id, alert_data)
    if recurrence:
        parts.append(recurrence)

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _safe_load(path: Path, case_id: str = "") -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error(case_id, "fp_tuning_ticket.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _build_context(case_id: str) -> str:
    """Assemble case context from all available artefacts."""
    case_dir = CASES_DIR / case_id
    parts: list[str] = [f"# Case: {case_id}\n"]

    # Case metadata
    meta = _safe_load(case_dir / "case_meta.json", case_id)
    if meta:
        parts.append("## Case Metadata")
        parts.append(f"- Title: {meta.get('title', 'N/A')}")
        parts.append(f"- Severity: {meta.get('severity', 'N/A')}")
        parts.append(f"- Status: {meta.get('status', 'N/A')}")
        parts.append(f"- Attack Type: {meta.get('attack_type', 'N/A')}")
        parts.append(f"- Analyst: {meta.get('analyst', 'unassigned')}")
        parts.append(f"- Created: {meta.get('created_at', 'N/A')}")
        parts.append("")

    # IOC list
    iocs_data = _safe_load(case_dir / "iocs" / "iocs.json", case_id)
    if iocs_data:
        ioc_dict = iocs_data.get("iocs", {})
        parts.append("## Extracted IOCs")
        for ioc_type, vals in ioc_dict.items():
            if vals:
                parts.append(f"### {ioc_type.upper()} ({len(vals)})")
                for v in vals[:30]:
                    parts.append(f"  - {v}")
        parts.append("")

    # Verdict summary
    verdict = _safe_load(
        case_dir / "artefacts" / "enrichment" / "verdict_summary.json", case_id
    )
    if verdict:
        parts.append("## Enrichment Verdict Summary")
        parts.append(f"- Total IOCs scored: {verdict.get('ioc_count', 0)}")
        parts.append(f"- Malicious: {len(verdict.get('high_priority', []))}")
        parts.append(f"- Suspicious: {len(verdict.get('needs_review', []))}")
        parts.append(f"- Clean: {len(verdict.get('clean', []))}")
        ioc_details = verdict.get("iocs", {})
        if ioc_details:
            parts.append("\n### Per-IOC Verdict")
            for ioc_val, info in list(ioc_details.items())[:30]:
                providers = ", ".join(
                    f"{p}:{v}" for p, v in info.get("providers", {}).items()
                )
                parts.append(
                    f"  - `{ioc_val}` | {info.get('ioc_type','?').upper()} | "
                    f"{info.get('verdict','?').upper()} ({info.get('confidence','?')}) | "
                    f"{providers}"
                )
        parts.append("")

    # Investigation report (capped)
    report_path = case_dir / "reports" / "investigation_report.md"
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8")
        if len(report_text) > 6000:
            report_text = report_text[:6000] + "\n\n[...report truncated...]"
        parts.append("## Investigation Report (excerpt)")
        parts.append(report_text)
        parts.append("")

    # Log files
    logs_dir = case_dir / "logs"
    if logs_dir.exists():
        log_chunks: list[str] = []
        total_chars = 0
        for log_file in sorted(logs_dir.iterdir()):
            if log_file.is_file() and total_chars < 4000:
                try:
                    text = log_file.read_text(encoding="utf-8", errors="replace")
                    if len(text) > 2000:
                        text = text[:2000] + "\n[...truncated...]"
                    log_chunks.append(f"### {log_file.name}\n{text}")
                    total_chars += len(text)
                except Exception as exc:
                    log_error(case_id, "fp_tuning_ticket.read_log", str(exc),
                              severity="info", context={"file": str(log_file)})
        if log_chunks:
            parts.append("## Log Records")
            parts.extend(log_chunks)
            parts.append("")

    # Web captures
    web_dir = case_dir / "artefacts" / "web"
    if web_dir.exists():
        capture_chunks: list[str] = []
        total_chars = 0
        for page_txt in web_dir.rglob("page.txt"):
            if total_chars >= 2000:
                break
            try:
                text = page_txt.read_text(encoding="utf-8", errors="replace")
                host = page_txt.parent.name
                if len(text) > 800:
                    text = text[:800] + "\n[...truncated...]"
                capture_chunks.append(f"### Capture: {host}\n{text}")
                total_chars += len(text)
            except Exception as exc:
                log_error(case_id, "fp_tuning_ticket.read_capture", str(exc),
                          severity="info", context={"file": str(page_txt)})
        if capture_chunks:
            parts.append("## Web Captures")
            parts.extend(capture_chunks)
            parts.append("")

    # Closure comment (if already generated — provides the closure justification)
    closure_candidates = (
        case_dir / "artefacts" / "closure_comments" / "closure_comment.md",
        # Legacy path from the pre-2026-05 fp_ticket flow
        case_dir / "artefacts" / "fp_comms" / "fp_ticket.md",
    )
    for candidate in closure_candidates:
        if candidate.exists():
            text = candidate.read_text(encoding="utf-8")
            if len(text) > 1000:
                text = text[:1000] + "\n[...truncated...]"
            parts.append("## Closure Comment (already generated)")
            parts.append(text)
            parts.append("")
            break

    return "\n".join(parts)


def _build_recurrence_context(case_id: str, alert_data: str) -> str:
    """Check prior cases for recurrence of similar FP patterns."""
    try:
        from tools.recall import recall
        from tools.extract_iocs import extract_iocs_from_text

        # Extract IOCs from alert data for recall search
        iocs_result = extract_iocs_from_text(alert_data)
        iocs = iocs_result.get("iocs", {})
        flat_iocs: list[str] = []
        for vals in iocs.values():
            flat_iocs.extend(vals[:10])

        if not flat_iocs:
            return ""

        recall_result = recall(iocs=flat_iocs[:20])
        prior_cases = recall_result.get("prior_cases", [])
        known_iocs = recall_result.get("known_iocs", [])

        if not prior_cases and not known_iocs:
            return ""

        parts = ["## Prior Case Recurrence Data\n"]
        if prior_cases:
            parts.append(f"**{len(prior_cases)} prior case(s) with overlapping IOCs:**")
            for pc in prior_cases[:10]:
                parts.append(
                    f"- {pc.get('case_id', '?')} — {pc.get('title', 'N/A')} "
                    f"(disposition: {pc.get('disposition', 'N/A')}, "
                    f"overlap: {', '.join(pc.get('overlapping_iocs', [])[:5])})"
                )
            parts.append("")

        if known_iocs:
            parts.append(f"**{len(known_iocs)} IOC(s) seen in prior investigations:**")
            for ki in known_iocs[:10]:
                parts.append(
                    f"- `{ki.get('ioc', '?')}` — seen in {ki.get('case_count', '?')} case(s), "
                    f"last: {ki.get('last_seen', 'N/A')}"
                )
            parts.append("")

        return "\n".join(parts)

    except Exception as exc:
        log_error(case_id, "fp_tuning_ticket.recall", str(exc), severity="warning")
        return ""


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def fp_tuning_ticket(case_id, alert_data, query_text=None, platform=None, live_query=False):
    """Stub — direct LLM generation removed.

    Use the ``write_fp_tuning`` MCP prompt to generate the tuning ticket via
    the local Claude Desktop agent, then call
    ``save_report(type=fp_tuning_ticket)`` to persist it.
    """
    return {
        "status": "use_prompt",
        "prompt": "write_fp_tuning",
        "save_tool": "save_report",
        "save_args": {"report_type": "fp_tuning_ticket"},
        "case_id": case_id,
        "ts": utcnow(),
    }


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Generate a SIEM engineering tuning ticket for a case.")
    p.add_argument("--case",        required=True, dest="case_id")
    p.add_argument("--alert",       metavar="FILE", help="Path to alert JSON/text file")
    p.add_argument("--alert-text",  metavar="TEXT", help="Inline alert string")
    p.add_argument("--query",       metavar="FILE", help="Path to KQL rule file (Sentinel)")
    p.add_argument("--query-text",  metavar="KQL",  help="Inline KQL string")
    p.add_argument("--platform",    choices=["sentinel", "crowdstrike", "defender", "entra", "cloudapps", "splunk"])
    p.add_argument("--live-query",  action="store_true",
                   help="Enable read-only KQL queries against the alert workspace (requires az CLI auth)")
    args = p.parse_args()

    if args.alert:
        alert_str = Path(args.alert).read_text(encoding="utf-8")
    elif args.alert_text:
        alert_str = args.alert_text
    else:
        p.error("Provide --alert or --alert-text")

    query_str = None
    if args.query:
        query_str = Path(args.query).read_text(encoding="utf-8")
    elif args.query_text:
        query_str = args.query_text

    result = fp_tuning_ticket(
        case_id=args.case_id,
        alert_data=alert_str,
        query_text=query_str,
        platform=args.platform,
        live_query=args.live_query,
    )
    print(json.dumps(result, indent=2, default=str))
