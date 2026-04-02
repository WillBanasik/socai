"""
tool: generate_pup_report
--------------------------
PUP/PUA (Potentially Unwanted Program/Application) report data-gathering and
detection helpers.

The report is now written by the local Claude Desktop agent using the
``write_pup_report`` MCP prompt, then persisted via ``save_report``.

This module retains ``_SYSTEM_PROMPT`` and ``_build_context()`` which the
MCP prompt imports.

Triggered when:
  - Analyst explicitly identifies the detection as PUP/PUA
  - Alert title/details contain PUP/PUA classification keywords
  - Post-enrichment verdicts indicate PUP/PUA (e.g. adware, bundleware, toolbar)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, IOC_INDEX_FILE
from tools.common import load_json, log_error, utcnow

# ---------------------------------------------------------------------------
# PUP/PUA detection keywords — used by detect_pup() and the pipeline
# ---------------------------------------------------------------------------

PUP_KEYWORDS: set[str] = {
    "pup", "pua", "potentially unwanted", "adware", "bundleware",
    "browser hijack", "search hijack", "toolbar", "browser toolbar",
    "unwanted program", "unwanted application", "unwanted software",
    "grayware", "greyware", "junkware", "bloatware", "spigot",
    "installcore", "opencandy", "conduit", "mindspark", "ask toolbar",
    "crossrider", "superfish", "wajam", "mywebsearch",
}

# VT / enrichment tags that indicate PUP rather than outright malicious
PUP_VERDICT_TAGS: set[str] = {
    "pup", "pua", "adware", "not-a-virus", "riskware", "grayware",
    "greyware", "potentially unwanted", "bundler", "toolbar",
}


def detect_pup(
    title: str = "",
    analyst_notes: str = "",
    alert_text: str = "",
    verdict_summary: dict | None = None,
) -> dict:
    """Check multiple signals to determine if this investigation is a PUP/PUA.

    Returns:
        {"is_pup": bool, "signals": list[str], "confidence": str}
    """
    signals: list[str] = []

    # Check title / analyst notes / alert text for PUP keywords
    combined = f"{title} {analyst_notes} {alert_text}".lower()
    for kw in PUP_KEYWORDS:
        if kw in combined:
            signals.append(f"keyword '{kw}' found in alert/title/notes")
            break  # one keyword match is enough from text

    # Check enrichment verdicts for PUP-specific tags
    if verdict_summary:
        iocs = verdict_summary.get("iocs", {})
        for ioc_val, info in iocs.items():
            providers = info.get("providers", {})
            for provider, prov_verdict in providers.items():
                if isinstance(prov_verdict, str) and any(
                    tag in prov_verdict.lower() for tag in PUP_VERDICT_TAGS
                ):
                    signals.append(
                        f"enrichment: {provider} tagged '{ioc_val}' as '{prov_verdict}'"
                    )
            # Also check tags/categories if present
            for tag in info.get("tags", []):
                if any(pt in tag.lower() for pt in PUP_VERDICT_TAGS):
                    signals.append(f"enrichment tag: '{tag}' on '{ioc_val}'")

    is_pup = len(signals) > 0
    confidence = "high" if len(signals) >= 2 else ("medium" if signals else "none")

    return {"is_pup": is_pup, "signals": signals, "confidence": confidence}


# ---------------------------------------------------------------------------
# Analytical guidelines — same as MDR reports
# ---------------------------------------------------------------------------

_GUIDELINES_PATH = Path(__file__).resolve().parent.parent / "config" / "analytical_guidelines.md"
try:
    _ANALYTICAL_GUIDELINES = _GUIDELINES_PATH.read_text()
except FileNotFoundError:
    _ANALYTICAL_GUIDELINES = ""

# ---------------------------------------------------------------------------
# System prompt — PUP/PUA Analyst Instruction Set
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
# PUP/PUA Analyst Instruction Set

## Role & Operating Context
Act as a **senior MDR analyst** delivering a **managed XDR service for an MSP**, \
using **UK English** and a **professional SOC tone**.

You are writing a report for a **Potentially Unwanted Program/Application (PUP/PUA)** \
detection — not an active compromise or targeted attack. Frame your analysis accordingly: \
the tone is "unwanted software found, recommended action required" rather than "attack \
detected/blocked".

Primary technologies include **Microsoft Defender, Microsoft Entra ID, Microsoft \
Sentinel**, and **CrowdStrike EDR / NGSIEM**, with supporting context from email \
security, proxy/web, and firewall platforms.

---

## Analysis Philosophy (Non-Negotiable)
- **Evidence-first, not alert-first**
  Never draw conclusions without explicitly assessing whether sufficient base event \
data exists.
- **Context always matters**
  PUP/PUA detections are common in environments with user-installed software, \
  bundleware, or browser extensions. Consider the user's role and typical behaviour.
- **PUP ≠ Malware**
  Treat PUP/PUA as unwanted software that may pose risk, not as confirmed malware. \
  Be precise about what it does vs. what it could do.
- **Objectivity over certainty**
  If evidence supports multiple interpretations, state this explicitly.

---

## Mandatory Analysis Phases

### Phase 1 — Software Identification
- What is the software? (Name, publisher, version if known)
- What category does it fall into? (Adware, browser hijacker, search redirector, \
  bundleware, crypto miner, toolbar, system optimiser, etc.)
- How was it installed? (User-initiated, bundled with legitimate software, \
  drive-by download, group policy, unknown)

### Phase 2 — Scope & Impact Assessment
- Which host(s) and user(s) are affected?
- When was it first observed? Is there evidence of spread to other endpoints?
- What is the functional impact? (Browser redirects, pop-ups, data collection, \
  resource usage, network callbacks, registry modifications)
- Is user data or credential exposure a concern?

### Phase 3 — Risk Evaluation
Assess realistic risk:
- **Low** — Nuisance adware, no data exfiltration, easily removed
- **Medium** — Persistent hooks, data collection, or network callbacks to \
  questionable infrastructure
- **High** — Credential harvesting, acts as a downloader for additional payloads, \
  or has known ties to malware delivery chains

### Phase 4 — Confidence Statement
- **Low** — Minimal evidence, unable to fully characterise the software
- **Medium** — Partial evidence, reasonable inference about behaviour
- **High** — Strong identification with multiple data points confirming behaviour

---

## Report Structure (Mandatory)

1. **One-line executive summary**
   (Include hostname, username, software name, and category)

2. **Software identification**
   - Name, category, publisher (if known)
   - Detection method (EDR signature, heuristic, ML, user report, enrichment)
   - Installation context (how it arrived, bundled with what, user-initiated vs silent)

3. **Technical narrative**
   - Chronological events related to the PUP detection
   - File paths, registry keys, process names, network activity
   - Any persistence mechanisms observed

4. **Key IOCs**
   - File hashes (SHA256 preferred)
   - Domains/URLs contacted by the PUP
   - File paths and registry keys
   *(Only include if directly observed)*

5. **Risk assessment**
   - Realistic impact to the environment
   - Whether the software is a known vector for further compromise
   - Data collection / exfiltration concerns

6. **Client recommendations**
   - Removal steps (uninstall, EDR quarantine, manual cleanup)
   - Prevention measures (block publisher, restrict user installs, browser policy)
   - Whether user awareness/training is recommended
   - Frame all actions as **client responsibilities** — the MDR service does not \
     perform remediation

7. **What Was NOT Observed**
   Every report **must** document notable absences:
   - No credential theft or harvesting activity
   - No secondary payload downloads
   - No command-and-control traffic
   - No lateral movement
   - No data exfiltration
   - No privilege escalation
   *(Adjust list based on what is relevant to the specific PUP category)*

8. **Confidence Assessment**
   - Risk level: Low / Medium / High
   - Confidence: Low / Medium / High
   - Classification: CONFIRMED / ASSESSED / UNKNOWN for each key finding

---

## Analytical Integrity Rules (Non-Negotiable)
1. **Every finding must be provable with supplied data.** If the data does not \
exist to support a claim, the claim cannot appear in the report.
2. **Temporal proximity is never causation.** Two events near each other in time \
is not evidence of a causal link.
3. **No gap-filling with speculation.** If evidence is missing, state it as \
"not determined" or "unknown from available data".
4. **Classify every finding explicitly:** \
CONFIRMED = data proves it. \
ASSESSED (high/medium/low confidence) = inference supported by evidence. \
UNKNOWN = no data available. \
Never use "confirmed" for an inference.

---

## Language & Tone
- UK English, professional SOC tone
- Analyst-to-client language (no vendor hype)
- Clearly label assumptions
- Write as if content may be reviewed by security leadership and auditors

---

""" + _ANALYTICAL_GUIDELINES


# ---------------------------------------------------------------------------
# Context builder — lighter weight than MDR, focused on PUP-relevant data
# ---------------------------------------------------------------------------

def _build_context(case_id: str) -> str:
    """Assemble a structured context block from PUP-relevant case artefacts."""
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

    # Analyst notes — often contain the PUP context
    notes_path = case_dir / "notes" / "analyst_input.md"
    if notes_path.exists():
        notes_text = notes_path.read_text(encoding="utf-8")
        if len(notes_text) > 4000:
            notes_text = notes_text[:4000] + "\n\n[...notes truncated...]"
        parts.append("## Analyst Notes")
        parts.append(notes_text)
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
                for v in vals[:10]:
                    parts.append(f"  - {v}")
                if len(vals) > 10:
                    parts.append(f"  - ... and {len(vals) - 10} more")
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
            for ioc_val, info in list(ioc_details.items())[:15]:
                providers = ", ".join(
                    f"{p}:{v}" for p, v in info.get("providers", {}).items()
                )
                parts.append(
                    f"  - `{ioc_val}` | {info.get('ioc_type', '?').upper()} | "
                    f"{info.get('verdict', '?').upper()} ({info.get('confidence', '?')}) | "
                    f"{providers}"
                )
        parts.append("")

    # File analysis artefacts (useful for PUP — shows what the file does)
    static_manifest = _safe_load(case_dir / "artefacts" / "zip" / "static_analysis_manifest.json")
    if static_manifest:
        parts.append("## Static File Analysis")
        for entry in static_manifest.get("files", [])[:10]:
            parts.append(f"- {entry.get('filename', '?')}: {entry.get('file_type', '?')}")
            if entry.get("sha256"):
                parts.append(f"  SHA256: {entry['sha256']}")
            if entry.get("detections"):
                parts.append(f"  Detections: {entry['detections']}")
        parts.append("")

    # Investigation report (if exists — truncated)
    report_path = case_dir / "reports" / "investigation_report.md"
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8")
        if len(report_text) > 6000:
            report_text = report_text[:6000] + "\n\n[...report truncated for context...]"
        parts.append("## Investigation Report (source narrative)")
        parts.append(report_text)
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
        log_error("", "generate_pup_report.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def generate_pup_report(case_id: str) -> dict:
    """Stub — direct LLM generation removed.

    Use the ``write_pup_report`` MCP prompt to generate the report via the
    local Claude Desktop agent, then call ``save_report(type=pup_report)``
    to persist it.
    """
    return {
        "status": "use_prompt",
        "prompt": "write_pup_report",
        "save_tool": "save_report",
        "save_args": {"report_type": "pup_report"},
        "case_id": case_id,
        "ts": utcnow(),
    }


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(
        description="Generate a PUP/PUA report for a case."
    )
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = generate_pup_report(args.case_id)
    print(json.dumps(result, indent=2, default=str))
