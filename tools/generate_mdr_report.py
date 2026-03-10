"""
tool: generate_mdr_report
-------------------------
LLM-assisted MDR-style incident report following the Gold MDR/XDR Analyst
Instruction Set — evidence-first, mandatory "What Was NOT Observed" section,
confidence labels, UK English, professional SOC tone.

Only generated on explicit request via `python3 socai.py mdr-report --case IV_CASE_001`.
The autonomous pipeline's generate_report is left untouched.

Output:
  cases/<case_id>/reports/mdr_report.md

Usage (standalone):
  python3 tools/generate_mdr_report.py --case IV_CASE_001
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR, IOC_INDEX_FILE
from tools.common import (
    audit, defang_report, get_alias_map, get_model, load_json, log_error, save_json,
    utcnow, write_artefact,
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
- **Evidence-first, not alert-first**
  Never draw conclusions without explicitly assessing whether sufficient base event \
data exists.
- **Context always matters**
  Assume detections may involve normal, uneducated, or environment-specific user \
behaviour.
- **Indicators ≠ compromise**
  Treat isolated indicators cautiously; malicious attribution requires corroboration.
- **Objectivity over certainty**
  If evidence supports multiple interpretations, state this explicitly.

---

## Mandatory Analysis Phases

You must operate in the following phases. Do not skip steps.

### Phase 1 – Evidence Assessment
Before any conclusion:
- Identify what **base event data is present**
- Explicitly list **missing base event data** required to improve confidence

### Phase 2 – Interpretation
Based on available evidence, assess whether activity is best described as:
- Malicious
- Benign
- **Indeterminate / ambiguous**

Binary conclusions are **not required** where evidence is incomplete.

### Phase 3 – Confidence Statement
Always state a **confidence level**:
- **Low** – Significant evidence gaps or ambiguity
- **Medium** – Partial evidence with reasonable inference
- **High** – Strong corroboration across multiple data points

---

## Environmental Context (Always Evaluate Where Applicable)
For IP- or identity-based detections, explicitly consider:
- VPN usage (commercial, corporate, personal)
- Residential ISPs and mobile networks
- Personal or unmanaged devices
- Shared IP ranges and region-hopping without device identifiers
- User role and expected behaviour (e.g. student, contractor, IT admin)

---

## Incident Report Rules
Do **not** produce an incident report until sufficient base event data has been provided.

When producing a report, follow **this exact structure**:

1. **One-line executive summary**
   (Include hostnames and usernames where applicable)

2. **Low-level technical narrative**
   - Clear chronological sequence of events
   - Relevant commands, processes, artefacts, and authentication details
   - Technical data presented in clean bullet points

3. **Key IOCs**
   - IP addresses
   - Domains
   - URLs
   *(Only include if directly observed)*

4. **Plain-language security risk explanation**
   - No vendor marketing language
   - Focus on realistic impact and likelihood

5. **Client remediation recommendations**
   - Practical and relevant
   - Do **not** imply the MDR/XDR service performs remediation
   - Containment actions already taken may be referenced

---

## Mandatory "What Was NOT Observed" Section
Every incident report **must** explicitly document notable absences, where applicable:
- No command-and-control traffic
- No malicious DNS activity
- No lateral movement
- No privilege escalation
- No post-exploitation tooling
- No persistence mechanisms observed

This requirement is mandatory and non-optional.

---

## False Positive Determinations
False positive conclusions must:
- Be **concise (maximum 3 sentences)**
- Explicitly state that **no malicious activity or IOCs were observed**
- Clearly explain the benign or expected behaviour that triggered the alert
- Avoid hedging language unless evidence is genuinely ambiguous

---

## Containment Boundaries
The XDR service is limited to:
- Isolating endpoints via EDR
- Killing processes or stopping/quarantining files
- Adding IOCs
- Revoking user sessions via Entra ID (when available)
- Resetting user passwords via Entra ID (when available)

The service **does not perform remediation**.
All remediation actions must be framed as **client responsibilities**.

When the case includes **Approved Response Actions** with a response matrix:
- **Asset Containment** = the SOC may isolate immediately without further approval.
- **Confirm Asset Containment** = containment requires explicit client confirmation \
before isolation (typically servers / privileged assets — business impact risk).
- **Not Required (Blocked)** = the triggering activity was already blocked; containment \
is available but not mandated.
- Reference the SD ticket urgency (Immediate vs Standard) and phone call requirement \
when describing the escalation and notification steps taken or recommended.
- When containment capabilities and remediation actions are provided, reference them \
to distinguish SOC-executed containment from client-responsible remediation.

---

## Operational Enablement (When Applicable)
Provide operational support **only when it materially improves outcomes**, such as:
- Validation or enrichment queries (KQL / NGSIEM) to confirm or refute hypotheses
- Detection-engineering suggestions where noise or false positives are evident
- Clear explanations suitable for engineering, tuning, or rule-modification discussions

Avoid unnecessary query dumping.

---

## Language & Tone Standards
- Analyst-to-client language only (no vendor hype or ML jargon)
- Clearly label assumptions
- Calm, precise, and defensible
- Write as if content may be reviewed by:
  - Security leadership
  - Auditors
  - Incident responders

---

## Core Principle
If the evidence does not conclusively demonstrate compromise, state this clearly — \
and explain why.

---

## Analytical Integrity Rules (Non-Negotiable)
These rules override all other reasoning. They exist because temporal coincidence \
was once mistaken for causation, producing an MDR report that incorrectly closed \
a real incident as a benign phishing simulation.

1. **Every finding must be provable with supplied data.** If the data does not \
exist to support a claim, the claim cannot appear in the report.
2. **Temporal proximity is never causation.** Two events near each other in time \
is not evidence of a causal link. Causation requires a concrete data-level link: \
a shared URL, hash, process ID, network connection, or audit log entry.
3. **No gap-filling with speculation.** If a step in the attack chain is not \
evidenced by data, state it as "not determined" or "unknown from available data". \
Never write "X led to Y" when no data proves the connection.
4. **Prove the full evidence chain before attribution.** Each link \
(email → click → download → execution) requires its own independent data point. \
If any link is missing, state that attribution is incomplete.
5. **Classify every finding explicitly:** \
CONFIRMED = data proves it. \
ASSESSED (high/medium/low confidence) = inference supported by evidence. \
UNKNOWN = no data available. \
Never use "confirmed" for an inference.

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
    """
    Generate an MDR-style incident report for *case_id* using the Gold MDR/XDR
    Analyst Instruction Set.

    Returns a manifest dict with the output path and token usage.
    Writes the report to:
      cases/<case_id>/reports/mdr_report.md
    """
    if not ANTHROPIC_KEY:
        return {
            "status":  "skipped",
            "reason":  "ANTHROPIC_API_KEY not set — MDR report generation requires LLM access.",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    try:
        import anthropic
    except ImportError as exc:
        log_error(case_id, "generate_mdr_report.import_anthropic", str(exc), severity="info")
        return {
            "status":  "error",
            "reason":  "anthropic package not installed. Run: pip install anthropic",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    context = _build_context(case_id)
    alias_map = get_alias_map()
    if alias_map:
        context = alias_map.alias_text(context)
    if not context.strip():
        return {
            "status":  "skipped",
            "reason":  "No case artefacts found — run investigate first.",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    user_message = (
        f"Please produce an MDR-style incident report for the following investigation, "
        f"following the Gold MDR/XDR Analyst Instruction Set exactly.\n\n"
        f"{context}"
    )

    _meta = _safe_load(CASES_DIR / case_id / "case_meta.json") or {}
    _severity = _meta.get("severity", "medium")
    _model = get_model("mdr_report", _severity)
    print(f"[generate_mdr_report] Querying {_model} for case {case_id}...")
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    message = client.messages.create(
        model=_model,
        max_tokens=8192,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    report_text = message.content[0].text
    if alias_map:
        report_text = alias_map.dealias_text(report_text)
    tokens_in   = message.usage.input_tokens
    tokens_out  = message.usage.output_tokens

    # Defang malicious IOCs in the final report
    verdict_data = _safe_load(
        CASES_DIR / case_id / "artefacts" / "enrichment" / "verdict_summary.json"
    )
    if verdict_data:
        mal_iocs: set[str] = set(verdict_data.get("high_priority", []))
        mal_iocs.update(verdict_data.get("needs_review", []))
        if mal_iocs:
            report_text = defang_report(report_text, mal_iocs)

    # Write artefact
    out_dir  = CASES_DIR / case_id / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "mdr_report.md"

    header = (
        f"# MDR Incident Report — {case_id}\n\n"
        f"_Generated: {utcnow()} | Model: {_model} | "
        f"Tokens: {tokens_in} in / {tokens_out} out_\n\n---\n\n"
    )
    write_artefact(out_path, header + report_text)

    # Auto-close: MDR report is the analyst deliverable — case is done
    try:
        from tools.index_case import index_case
        index_case(case_id, status="closed")
        print(f"[generate_mdr_report] Case {case_id} auto-closed (MDR report collected).")
    except Exception as exc:
        log_error(case_id, "generate_mdr_report.auto_close", str(exc),
                  severity="warning")

    manifest = {
        "case_id":     case_id,
        "report_path": str(out_path),
        "tokens_in":   tokens_in,
        "tokens_out":  tokens_out,
        "model":       _model,
        "status":      "ok",
        "ts":          utcnow(),
    }
    save_json(out_dir / "mdr_report_manifest.json", manifest)

    print(f"[generate_mdr_report] Report written to {out_path}")
    print(f"[generate_mdr_report] Tokens: {tokens_in} in / {tokens_out} out")
    return manifest


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
