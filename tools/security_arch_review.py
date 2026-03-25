"""
tool: security_arch_review
--------------------------
Security architecture review for a completed investigation.

The review is now written by the local Claude Desktop agent using the
``write_security_arch_review`` MCP prompt, then persisted via ``save_report``.

This module retains ``_SYSTEM_PROMPT`` / ``_SYSTEM_CACHED`` and
``_build_context()`` which the MCP prompt imports for context assembly.

Data-gathering helpers (``_build_context``, ``_safe_load``) remain available
for use by the MCP prompt layer.

Output (via save_report):
  cases/<case_id>/artefacts/security_architecture/security_arch_review.md
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, IOC_INDEX_FILE
from tools.common import load_json, log_error, utcnow

# ---------------------------------------------------------------------------
# Analytical guidelines — loaded from config/analytical_guidelines.md
# ---------------------------------------------------------------------------

_GUIDELINES_PATH = Path(__file__).resolve().parent.parent / "config" / "analytical_guidelines.md"
try:
    _ANALYTICAL_GUIDELINES = _GUIDELINES_PATH.read_text()
except FileNotFoundError:
    _ANALYTICAL_GUIDELINES = ""

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a Principal Security Architect with deep hands-on expertise across the \
Microsoft security stack and CrowdStrike Falcon platform. You advise enterprise \
SOC and security engineering teams on how to detect, prevent, and respond to \
threats using their existing tooling.

Your Microsoft expertise covers:
- Microsoft Entra ID: Conditional Access (policy design, named locations, \
  exclusion governance), Identity Protection (risk policies, sign-in/user risk), \
  Privileged Identity Management (PIM), Authentication Methods, Hybrid Identity
- Microsoft Sentinel: Analytics rules (Scheduled, NRT, Fusion, ML), UEBA, \
  Watchlists, Threat Intelligence ingestion, Playbooks (Logic Apps), Workbooks, \
  entity mapping, incident correlation
- Microsoft Defender XDR suite: Defender for Endpoint (MDE) prevention policies, \
  ASR rules, EDR detections, Live Response; Defender for Identity (MDI) lateral \
  movement/pass-the-hash/Kerberoasting detections; Defender for Office 365 (MDO) \
  Safe Links, Safe Attachments, anti-phishing; Defender for Cloud Apps (MDCA) \
  CASB policies, session controls, anomaly detections; Defender for Cloud \
  (CSPM/CWPP)
- Microsoft Purview: DLP policies, Insider Risk Management, Communication \
  Compliance, Sensitivity Labels, Audit (Standard and Premium)
- Azure networking controls: NSGs, Azure Firewall, Private Link, DDoS Protection

Your CrowdStrike Falcon expertise covers:
- Falcon Insight EDR: prevention policy tuning (ML-based, exploit mitigation, \
  suspicious process blocking), custom Indicator of Attack (IOA) rules, \
  custom Indicators of Compromise (IOC) hash/IP/domain blocking, Real Time \
  Response (RTR) for live investigation and remediation
- Falcon NGSIEM (LogScale): ingestion pipeline configuration, query language \
  (LSQL), dashboards, real-time alerts, scheduled searches, package deployment
- Falcon Identity Protection (formerly Falcon Zero Trust): identity-based \
  threat detection, MFA enforcement via Falcon, lateral movement detection
- Falcon Spotlight: vulnerability prioritisation, exposure management
- Falcon Fusion: workflow automation, SOAR playbooks
- Falcon Overwatch: managed threat hunting integration

When given a case investigation summary, you will produce a structured \
Security Architecture Review with the following sections:

1. **Threat Profile** — Map observed TTPs to MITRE ATT&CK. Be specific about \
   technique IDs (e.g. T1078.004 — Cloud Accounts). Include confidence in each \
   mapping based on evidence quality.

2. **Control Gap Analysis** — For each identified TTP, state whether a \
   preventive or detective control was present, absent, or misconfigured in \
   the environment. Reference specific policy names, rule names, or settings \
   where visible in the case data.

3. **Microsoft Stack Recommendations** — Prioritised, actionable recommendations \
   per product area. Be specific: name the exact Conditional Access policy change, \
   the Sentinel analytics rule to deploy (reference the OOTB rule name or \
   provide the KQL), the MDE ASR rule to enable, etc. Do not give generic advice.

4. **CrowdStrike Falcon Recommendations** — Prioritised, actionable \
   recommendations per Falcon module. Be specific: custom IOA rule logic, \
   LogScale query to create as a scheduled search, prevention policy toggle, etc.

5. **Prioritised Remediation Table** — A markdown table with columns: \
   Priority (Critical/High/Medium/Low), Action, Platform, Effort (Hours estimate), \
   Risk Reduced. Sorted by priority descending.

6. **Detection Engineering Notes** — Any new detection logic, sigma rules, \
   or query patterns that should be written as a result of this investigation.

Tone: Direct, technical, practitioner-level. No marketing language. \
Assume the reader is a senior SOC analyst or security engineer. \
Cite specific policy names, rule IDs, or configuration settings observed \
in the case data whenever possible — do not invent details not present in \
the evidence.

---

""" + _ANALYTICAL_GUIDELINES

# Cached system prompt block — sent once and reused across calls
_SYSTEM_CACHED = [
    {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
]

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

    # Analyst notes (submitted via web UI or API)
    analyst_notes_path = case_dir / "notes" / "analyst_input.md"
    if analyst_notes_path.exists():
        notes_text = analyst_notes_path.read_text(errors="replace").strip()
        if notes_text:
            parts.append("## Analyst Notes")
            parts.append(notes_text)
            parts.append("")

    # IOC summary
    iocs_data = _safe_load(case_dir / "iocs" / "iocs.json")
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

    # Investigation report (truncated to avoid token overflow)
    report_path = case_dir / "reports" / "investigation_report.md"
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8")
        if len(report_text) > 6000:
            report_text = report_text[:6000] + "\n\n[...report truncated for context...]"
        parts.append("## Investigation Report (summary)")
        parts.append(report_text)
        parts.append("")

    # IOC index — recurring IOCs from prior cases
    ioc_index = _safe_load(IOC_INDEX_FILE)
    if ioc_index and iocs_data:
        ioc_dict = iocs_data.get("iocs", {})
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
        log_error("", "security_arch_review.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


# ---------------------------------------------------------------------------
# Main function (stub — LLM generation removed)
# ---------------------------------------------------------------------------

def security_arch_review(case_id: str) -> dict:
    """Stub — direct LLM generation removed.

    Use the ``write_security_arch_review`` MCP prompt to generate the review
    via the local Claude Desktop agent, then call
    ``save_report(type=security_arch_review)`` to persist it.
    """
    return {
        "status": "use_prompt",
        "prompt": "write_security_arch_review",
        "save_tool": "save_report",
        "save_args": {"report_type": "security_arch_review"},
        "case_id": case_id,
        "ts": utcnow(),
    }
