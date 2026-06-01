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

A security architecture review is a FORWARD-LOOKING, PREVENTATIVE deliverable. \
A specific incident is the entry point — the trigger that prompted the review — \
but the deliverable's purpose is to harden the client's PREVENTATIVE CONTROLS \
and CONFIGURATION BASELINE so this class of incident cannot recur. You are not \
re-investigating the incident; you are using it as a lens to assess whether the \
client's environment is configured to best practice, and to give specific, \
targeted recommendations that close the gaps. Always reason about what control \
SHOULD have prevented or detected the activity, and whether it was present, \
absent, or misconfigured in the actual environment.

You will be given two inputs: (1) the completed investigation for the triggering \
incident, and (2) where available, the client's LIVE configuration baseline \
pulled from Encore EQL (Secure Score, MFA/identity coverage, privileged access, \
app-credential hygiene, device/encryption compliance, Defender configuration \
recommendations, vulnerability exposure, security-awareness training). Ground \
every recommendation in that live baseline wherever it exists — do not give \
generic advice when real configuration state is in front of you.

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

You will produce a structured Security Architecture Review with the following \
sections:

1. **Posture Baseline Summary** — The client's current standing against \
   best practice, read directly from the live Encore EQL baseline. Cover, where \
   data exists: Microsoft Secure Score (current vs max, % and trend), MFA / \
   strong-auth coverage (users not MFA-registered, admins without MFA, accounts \
   with no auth method), privileged-access exposure (Global Admin count, \
   standing role assignments), app-credential hygiene (expired/expiring secrets \
   and certs), device & encryption compliance (compliant vs non-compliant, \
   encrypted vs not, LAPS coverage), patch / vulnerability exposure (exposure \
   score vs peer average, imminent/emerging threats), and security-awareness \
   training completion. State each metric as **Confirmed** (EQL data present), \
   **Assessed** (inference), or **Unknown** (no data / not ingested). Never \
   present an absent EQL table as a passing control.

2. **Threat Profile** — Map the triggering incident's observed TTPs to MITRE \
   ATT&CK. Be specific about technique IDs (e.g. T1078.004 — Cloud Accounts). \
   Include confidence in each mapping based on evidence quality.

3. **Control Gap Analysis** — The core of the review. For each observed TTP AND \
   each weak signal in the posture baseline, state whether a preventative or \
   detective control was present, absent, or misconfigured — grounded in the \
   EQL baseline and case data, not assumption. Reference specific policy names, \
   rule names, Defender recommendations, or settings where visible. Tie each gap \
   to the best-practice target it falls short of.

4. **Preventative Control Recommendations — Microsoft Stack** — Prioritised, \
   specific, actionable hardening per product area: the exact Conditional Access \
   policy to create/tighten (e.g. block legacy auth, require phishing-resistant \
   MFA, sign-in risk policy), Identity Protection risk policies, PIM for standing \
   privileged roles, the MDE ASR rule or Defender MachineRecommendation to \
   action, Intune compliance/baseline policy, Purview DLP. Anchor each to the \
   specific posture gap from sections 1 and 3. Do not give generic advice.

5. **Preventative Control Recommendations — CrowdStrike Falcon** — Prioritised, \
   specific hardening per Falcon module: prevention-policy toggles, custom IOA \
   rule logic, Spotlight vulnerability prioritisation, Falcon Identity Protection \
   enforcement, NGSIEM scheduled searches.

6. **Prioritised Remediation Roadmap** — A markdown table with columns: \
   Priority (Critical/High/Medium/Low), Control / Action, Platform, \
   Best-practice target, Effort (hours estimate), Risk reduced. Sorted by \
   priority descending. This is the client's hardening backlog.

7. **Detection Engineering Notes** — Any new detection logic, sigma rules, or \
   query patterns that should be written as a result of this investigation.

**Scope boundary — do not invent configuration you cannot see.** Encore EQL \
exposes Conditional Access *enforcement outcomes* (per-sign-in CA status), \
per-user MFA *enforcement policy*, Secure Score, and Defender's own config \
recommendations — but it does NOT enumerate the full Conditional Access policy \
*definitions* (conditions / grant controls). You may prove "CA is/was not being \
applied to these sign-ins" or "MFA coverage is X%"; you may NOT list a CAP's \
exact ruleset as if you had read it. Frame CA/policy recommendations from \
observed outcomes and posture, and flag where the client should confirm the \
underlying policy definition.

Tone: Direct, technical, practitioner-level. No marketing language. \
Assume the reader is a senior SOC analyst or security engineer. \
Cite specific policy names, rule IDs, Secure Score figures, or configuration \
settings observed in the EQL baseline / case data whenever possible — do not \
invent details not present in the evidence.

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
# Encore EQL guidance — live posture baseline for the review
# ---------------------------------------------------------------------------

def _eql_entity_candidates(case_id: str) -> dict[str, list[str]]:
    """Map a case's IOCs to EQL entity types for the reactive entity pull.

    Only the deterministic mappings are surfaced: ``email`` IOCs → ``user``
    (UPN) and ``ipv4`` IOCs → ``ip``. Hostnames are not a distinct IOC type
    from extraction, so they are left for the agent to pull from the narrative.
    Returns ``{}`` on any error.
    """
    iocs_data = _safe_load(CASES_DIR / case_id / "iocs" / "iocs.json")
    if not iocs_data:
        return {}
    ioc_dict = iocs_data.get("iocs", {}) or {}
    out: dict[str, list[str]] = {}
    if ioc_dict.get("email"):
        out["user"] = list(ioc_dict["email"])[:10]
    if ioc_dict.get("ipv4"):
        out["ip"] = list(ioc_dict["ipv4"])[:10]
    return out


def _eql_guidance(case_id: str) -> str:
    """Build the Encore EQL guidance block for the security-arch-review prompt.

    Runs server-side, config-only (no HTTP): resolves the case's client and
    checks whether Encore EQL is mapped for it. If enabled, returns a markdown
    block telling the local agent to pull the client-wide posture baseline
    (``eql_posture_context``) plus reactive context for the incident's entities
    (``eql_entity_context``), and bakes in the coverage/freshness discipline.
    Best-effort — never raises.
    """
    try:
        meta = _safe_load(CASES_DIR / case_id / "case_meta.json") or {}
        client = meta.get("client", "")
        from tools.eql import is_eql_configured
        configured = bool(client) and is_eql_configured(client)
    except Exception as exc:
        log_error(case_id, "security_arch_review.eql_guidance", str(exc),
                  severity="warning")
        return ""

    if not configured:
        return (
            "## Live Configuration Baseline (Encore EQL)\n"
            f"Encore EQL is **not enabled** for this case's client "
            f"(`{client or 'unknown'}`). No live posture data is available — base "
            "the Posture Baseline Summary on the case artefacts only and mark its "
            "metrics **Unknown** where no data exists. Do not attempt EQL calls."
        )

    lines = [
        "## Live Configuration Baseline (Encore EQL) — gather BEFORE writing",
        f"Encore EQL **is enabled** for this client (`{client}`). This is the "
        "primary input for the Posture Baseline Summary and Control Gap Analysis. "
        "Pull it before drafting any recommendation so the review reflects the "
        "client's real configuration, not assumptions.",
        "",
        "**1. Client-wide posture baseline (always call first):**",
        f'  - `eql_posture_context("{case_id}")` — Secure Score, MFA / identity '
        "coverage, privileged-role assignments, app-credential hygiene, device & "
        "encryption compliance, Defender configuration recommendations, "
        "vulnerability exposure, and security-awareness training. This powers "
        "sections 1, 3 and 4.",
        "",
        "**2. Reactive entity context (for the incident's entities):**",
        f'  - `eql_entity_context("{case_id}", user=…, host=…, ip=…)` — identity '
        "risk, sign-in / conditional-access outcomes, device posture, detections, "
        "and vulnerability exposure for a named entity.",
    ]
    cands = _eql_entity_candidates(case_id)
    if cands:
        lines.append("")
        lines.append("  Candidate entities from this case's IOCs — seed your calls:")
        for etype, vals in cands.items():
            for v in vals:
                lines.append(f'    - `eql_entity_context("{case_id}", {etype}="{v}")`')
    lines.extend([
        "",
        "  Also identify any **hostnames** named in the analyst notes / "
        "investigation report above and pull them with `host=…`.",
        "",
        "For anything the curated sets miss (e.g. OAuth consent grants, app "
        "permissions, directory audits), use the `eql_query` escape hatch.",
        "",
        "**Coverage discipline (mandatory):** an empty result / "
        "`no_data_for_client` means the product is **not ingested** for this "
        "client — it is NOT evidence of a clean, compliant, or healthy state. "
        "Snapshot tables are ordered newest-first (the top row is current state); "
        "`SignInAudits` is a rolling ~7-day window. Label every EQL-derived claim "
        "per the analytical standards: data present = *Confirmed*, inference = "
        "*Assessed*, no data = *Unknown*.",
    ])
    return "\n".join(lines)


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
