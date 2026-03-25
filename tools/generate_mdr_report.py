"""
tool: generate_mdr_report
-------------------------
MDR report data-gathering and system prompt.

The actual report is written by the local Claude Desktop agent using the
``write_mdr_report`` MCP prompt, then persisted via ``save_report``.

This module retains ``_SYSTEM_PROMPT`` and ``_build_context()`` which the
MCP prompt imports.  The former LLM-calling function is replaced by a stub.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, IOC_INDEX_FILE
from tools.common import (
    load_json, log_error, utcnow,
)

# ---------------------------------------------------------------------------
# Analytical guidelines — loaded from config/analytical_guidelines.md
# ---------------------------------------------------------------------------

_GUIDELINES_PATH = Path(__file__).resolve().parent.parent / "config" / "analytical_guidelines.md"
try:
    _ANALYTICAL_GUIDELINES = _GUIDELINES_PATH.read_text()
except FileNotFoundError:
    _ANALYTICAL_GUIDELINES = ""

# ---------------------------------------------------------------------------
# System prompt — Gold MDR / XDR Analyst Instruction Set
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
# Gold MDR / XDR Analyst Instruction Set

## Role & Operating Context
Act as a **senior MDR analyst** delivering a **managed XDR service for an MSP**, \
using **UK English** and a **professional SOC tone**.

Primary technologies include **Microsoft Defender, Microsoft Entra ID, Microsoft \
Sentinel**, and **CrowdStrike EDR / NGSIEM**, with supporting context from email \
security, proxy/web, and firewall platforms.

---

## Analysis Philosophy (Non-Negotiable)
- **Evidence-first, not alert-first** — never draw conclusions without evidence.
- **Context always matters** — detections may involve normal, environment-specific \
user behaviour.
- **Indicators ≠ compromise** — isolated indicators require corroboration.
- **Objectivity over certainty** — if evidence supports multiple interpretations, \
state this explicitly.

---

## REPORT STRUCTURE (MANDATORY)

You MUST always produce a report using the five sections below. Never refuse to \
write the report. If evidence is incomplete, write the report with what you have \
and clearly mark gaps within each section using the confidence labels \
(CONFIRMED / ASSESSED / UNKNOWN).

### Section 1 — Executive Summary
A concise high-level summary of the incident. Include:
- What was detected and by which platform
- Which users, hosts, and assets are involved
- The overall assessment (malicious / benign / indeterminate)
- Confidence level (Low / Medium / High) with brief justification
- Key evidence gaps that limit confidence (if any)

Keep this to one short paragraph. Include hostnames and usernames.

### Section 2 — Technical Analysis
A detailed, low-level technical narrative covering:
- Chronological sequence of events with timestamps
- Relevant processes, commands, file hashes, authentication events
- Network activity: IPs, domains, URLs (only if directly observed)
- Endpoint telemetry: process trees, file writes, registry modifications
- Identity plane: sign-in activity, MFA events, token usage
- Enrichment results: threat intelligence verdicts per IOC

Present technical data in clean bullet points. Embed IOCs inline rather than \
in a separate section. Where evidence is missing for a step in the chain, state \
"UNKNOWN — [what data would be needed]" and continue.

### Section 3 — Plain-Language Risk Explanation
Explain the security risk in language a non-technical stakeholder can understand:
- What actually happened (or is assessed to have happened)
- What the realistic business impact is
- What could happen if no action is taken
- No vendor marketing language or jargon

### Section 4 — What Was NOT Observed
Explicitly document notable absences relevant to the detection type. Examples:
- No command-and-control traffic
- No lateral movement
- No privilege escalation
- No data exfiltration
- No persistence mechanisms
- No credential harvesting activity
- No post-exploitation tooling

Tailor this list to the specific incident — do not use a generic checklist.

### Section 5 — Recommendations
Actionable recommendations split into two categories:

**SOC-Executed Containment** (actions the MDR service can take):
- Reference the client's Approved Response Actions and response matrix if provided
- Reference containment capabilities by technology (EDR isolation, session \
revocation, IOC blocking, process kill, file quarantine)
- Note the SD ticket urgency (Immediate / Standard) and phone call requirement
- Distinguish Asset Containment (immediate) from Confirm Asset Containment \
(requires client approval) from Not Required (already blocked)

**Client-Responsible Remediation** (actions the client must take):
- Password resets, conditional access policy changes, firewall rules, etc.
- Do NOT imply the MDR/XDR service performs remediation
- Be specific — name the user, host, or IOC that needs action

If no response matrix is provided, give practical recommendations based on \
the evidence and clearly state they are advisory.

---

## Environmental Context (Evaluate Where Applicable)
For IP- or identity-based detections, consider:
- VPN usage (commercial, corporate, personal)
- Residential ISPs and mobile networks
- Personal or unmanaged devices
- Shared IP ranges and region-hopping without device identifiers
- User role and expected behaviour

---

## False Positive Determinations
When the conclusion is FP, the Executive Summary should state this directly. \
The Technical Analysis section should still present the evidence that rules out \
malicious activity. Keep the overall report concise but complete.

---

## Language & Tone
- UK English, analyst-to-client language (no vendor hype or ML jargon)
- Clearly label assumptions
- Calm, precise, and defensible
- Write as if content may be reviewed by security leadership, auditors, and \
incident responders

---

## Analytical Integrity Rules (Non-Negotiable)
1. **Every finding must be provable with supplied data.** If data does not exist \
to support a claim, mark it as UNKNOWN — never present it as fact.
2. **Temporal proximity is never causation.** Causation requires a concrete \
data-level link (shared URL, hash, process ID, network connection, audit entry).
3. **No gap-filling with speculation.** Missing evidence = "UNKNOWN from \
available data". Never write "X led to Y" without proof.
4. **Classify every finding:** CONFIRMED = data proves it. \
ASSESSED (high/medium/low confidence) = inference supported by evidence. \
UNKNOWN = no data available.

---

""" + _ANALYTICAL_GUIDELINES


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_context(case_id: str) -> str:
    """Assemble a structured context block from all available case artefacts."""
    case_dir = CASES_DIR / case_id
    parts: list[str] = [f"# Case: {case_id}\n"]

    # Case metadata
    meta = _safe_load(case_dir / "case_meta.json")
    if meta:
        parts.append("## Case Metadata")
        parts.append(f"- Title: {meta.get('title', 'N/A')}")
        parts.append(f"- Severity: {meta.get('severity', 'N/A')}")
        parts.append(f"- Status: {meta.get('status', 'N/A')}")
        parts.append(f"- Created: {meta.get('created_at', 'N/A')}")
        parts.append("")

    # IOC summary
    iocs_data = _safe_load(case_dir / "iocs" / "iocs.json")
    ioc_dict: dict = {}
    if iocs_data:
        ioc_dict = iocs_data.get("iocs", {})
        parts.append("## Extracted IOCs")
        for ioc_type, vals in ioc_dict.items():
            if vals:
                parts.append(f"### {ioc_type.upper()} ({len(vals)})")
                for v in vals[:50]:
                    parts.append(f"  - {v}")
        parts.append("")

    # Verdict summary
    verdict = _safe_load(
        case_dir / "artefacts" / "enrichment" / "verdict_summary.json"
    )
    if verdict:
        parts.append("## Enrichment Verdict Summary")
        parts.append(f"- Total IOCs scored: {verdict.get('ioc_count', 0)}")
        parts.append(f"- Malicious (high priority): {len(verdict.get('high_priority', []))}")
        parts.append(f"- Suspicious (needs review): {len(verdict.get('needs_review', []))}")
        parts.append(f"- Clean: {len(verdict.get('clean', []))}")
        ioc_details = verdict.get("iocs", {})
        if ioc_details:
            parts.append("\n### Per-IOC Verdict Detail")
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

    # Correlation results
    correlation = _safe_load(
        case_dir / "artefacts" / "correlation" / "correlation.json"
    )
    if correlation:
        parts.append("## Correlation Results")
        hit_summary = correlation.get("hit_summary", {})
        if hit_summary:
            parts.append(f"- Hit summary: {json.dumps(hit_summary)}")
        tl_events = correlation.get("timeline_events", 0)
        parts.append(f"- Timeline events: {tl_events}")
        hits = correlation.get("hits", {})
        for hit_type, hit_list in hits.items():
            if hit_list:
                parts.append(f"- {hit_type}: {hit_list[:10]}")
        parts.append("")

    # EDR / endpoint telemetry summary (e.g. parsed Falcon CSV exports)
    telemetry = _safe_load(case_dir / "artefacts" / "falcon_telemetry_summary.json")
    if telemetry:
        parts.append("## Endpoint Telemetry Summary (CrowdStrike Falcon)")
        tel_text = json.dumps(telemetry, indent=2, default=str)
        if len(tel_text) > 12000:
            tel_text = tel_text[:12000] + "\n\n[...telemetry truncated for context...]"
        parts.append(tel_text)
        parts.append("")

    # Investigation report (truncated to avoid token overflow)
    report_path = case_dir / "reports" / "investigation_report.md"
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8")
        if len(report_text) > 8000:
            report_text = report_text[:8000] + "\n\n[...report truncated for context...]"
        parts.append("## Investigation Report (source narrative)")
        parts.append(report_text)
        parts.append("")

    # Response actions (client-specific)
    actions_data = _safe_load(case_dir / "artefacts" / "response_actions" / "response_actions.json")
    if actions_data and actions_data.get("status") == "ok":
        parts.append("## Approved Response Actions")
        parts.append(f"- Client: {actions_data.get('client', 'N/A')}")
        parts.append(f"- Priority: {actions_data.get('priority', 'N/A').upper()} "
                     f"({actions_data.get('priority_source', 'N/A')})")
        esc = actions_data.get("escalation", {})
        cp = esc.get("contact_process")
        if cp:
            parts.append(f"- Contact process: {cp}")
        if actions_data.get("crown_jewel_match"):
            parts.append("- **CROWN JEWEL MATCH** — priority escalated to P1")

        # Response matrix — escalation procedure per asset type / blocked status
        permitted = esc.get("permitted_actions", [])
        if permitted:
            _action_labels = {
                "asset_containment": "Asset Containment",
                "confirm_asset_containment": "Confirm Asset Containment",
                "asset_containment_not_required": "Not Required (Blocked)",
            }
            parts.append("")
            parts.append(f"### Response Matrix ({actions_data.get('priority', '?').upper()})")
            parts.append("| Asset Type | Blocked | SD Ticket | Phone Call | Response Action |")
            parts.append("|------------|---------|-----------|------------|-----------------|")
            for entry in permitted:
                asset = entry.get("asset_type", "any")
                blocked = "Yes" if entry.get("activity_blocked") else "No"
                sd = entry.get("sd_ticket", "standard").capitalize()
                phone = "Yes" if entry.get("phone_call") else "No"
                action = _action_labels.get(
                    entry.get("response_action", "asset_containment"),
                    entry.get("response_action", "Asset Containment"),
                )
                parts.append(f"| {asset} | {blocked} | {sd} | {phone} | {action} |")

        # Containment capabilities
        caps = actions_data.get("containment_capabilities", [])
        if caps:
            parts.append("")
            parts.append("### Available Containment Actions (SOC-Executed)")
            for group in caps:
                tech = group.get("technology", "Unknown")
                for a in group.get("actions", []):
                    parts.append(f"  - [{tech}] {a}")

        # Remediation actions (client responsibility)
        remed = actions_data.get("remediation_actions", [])
        if remed:
            parts.append("")
            parts.append("### Recommended Remediation (Client Responsibility)")
            for group in remed:
                tech = group.get("technology", "Unknown")
                for a in group.get("actions", []):
                    parts.append(f"  - [{tech}] {a}")

        parts.append("")

    # IOC index — recurring IOCs from prior cases
    ioc_index = _safe_load(IOC_INDEX_FILE)
    if ioc_index and ioc_dict:
        recurring = []
        for ioc_val in [v for vals in ioc_dict.values() for v in vals]:
            entry = ioc_index.get(ioc_val)
            if entry:
                other = [c for c in entry.get("cases", []) if c != case_id]
                if other:
                    recurring.append(
                        f"  - `{ioc_val}` seen in prior cases: {', '.join(other[:5])}"
                    )
        if recurring:
            parts.append("## Recurring IOCs (seen in prior investigations)")
            parts.extend(recurring)
            parts.append("")

    return "\n".join(parts)


def _safe_load(path: Path) -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "generate_mdr_report.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def generate_mdr_report(case_id: str) -> dict:
    """Stub — direct LLM generation removed.

    Use the ``write_mdr_report`` MCP prompt to generate the report via the
    local Claude Desktop agent, then call ``save_report(type=mdr_report)``
    to persist it.
    """
    return {
        "status": "use_prompt",
        "prompt": "write_mdr_report",
        "save_tool": "save_report",
        "save_args": {"report_type": "mdr_report"},
        "case_id": case_id,
        "ts": utcnow(),
    }


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(
        description="Generate an MDR-style incident report for a case."
    )
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = generate_mdr_report(args.case_id)
    print(json.dumps(result, indent=2, default=str))
