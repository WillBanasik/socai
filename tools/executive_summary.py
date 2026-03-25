"""
tool: executive_summary
-----------------------
Data-gathering module for executive summaries.

The summary itself is now written by the local Claude Desktop agent using
the ``write_executive_summary`` MCP prompt, then persisted via
``save_report``.  This module retains ``_SYSTEM_PROMPT``,
``_SYSTEM_CACHED``, and ``_build_context()`` which the MCP prompt imports.

Usage (standalone — returns stub directing caller to the MCP prompt):
  python3 tools/executive_summary.py --case IV_CASE_001
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, utcnow

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior cybersecurity advisor writing an executive summary for \
non-technical business leadership.

Your task is to distil a completed security investigation into a clear, \
concise summary that a board member or C-suite executive can understand \
and act on in under two minutes.

Constraints:
- No CVE IDs, no IP addresses, no file hashes, no tool names.
- No unexplained acronyms — spell out on first use.
- Target reading age: 14 (plain English).
- Maximum 500 words total.
- Use the RAG (Red/Amber/Green) risk rating system:
  - RED: Active or confirmed threat requiring immediate executive action.
  - AMBER: Significant risk identified; remediation needed within days.
  - GREEN: Low risk; routine findings or confirmed benign activity.

Produce a structured executive summary with all required fields.\
"""

_SYSTEM_CACHED = [
    {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_optional(path: Path, case_id: str) -> dict | None:
    """Load a JSON file, returning None if missing or broken."""
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error(case_id, "executive_summary.load_optional", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _build_context(case_id: str) -> str:
    """Assemble a structured context block from available case artefacts."""
    case_dir = CASES_DIR / case_id
    parts: list[str] = [f"# Case: {case_id}\n"]

    # Case metadata
    meta = _load_optional(case_dir / "case_meta.json", case_id)
    if meta:
        parts.append("## Case Metadata")
        parts.append(f"- Title: {meta.get('title', 'N/A')}")
        parts.append(f"- Severity: {meta.get('severity', 'N/A')}")
        parts.append(f"- Status: {meta.get('status', 'N/A')}")
        parts.append(f"- Created: {meta.get('created_at', 'N/A')}")
        if meta.get("analyst"):
            parts.append(f"- Analyst: {meta.get('analyst')}")
        parts.append("")

    # Investigation report (truncated)
    report_text = None
    for report_candidate in [
        case_dir / "reports" / "investigation_report.md",
        case_dir / "artefacts" / "reports" / "investigation_report.md",
    ]:
        if report_candidate.exists():
            try:
                report_text = report_candidate.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                log_error(case_id, "executive_summary.read_report", str(exc),
                          severity="warning", context={"path": str(report_candidate)})
            break
    if report_text:
        if len(report_text) > 5000:
            report_text = report_text[:5000] + "\n\n[...report truncated...]"
        parts.append("## Investigation Report (excerpt)")
        parts.append(report_text)
        parts.append("")

    # Verdict summary
    verdict = _load_optional(
        case_dir / "artefacts" / "enrichment" / "verdict_summary.json", case_id
    )
    if verdict:
        parts.append("## Enrichment Verdict Summary")
        parts.append(f"- Total IOCs scored: {verdict.get('ioc_count', 0)}")
        parts.append(f"- Malicious (high priority): {len(verdict.get('high_priority', []))}")
        parts.append(f"- Suspicious (needs review): {len(verdict.get('needs_review', []))}")
        parts.append(f"- Clean: {len(verdict.get('clean', []))}")
        parts.append("")

    # Security architecture structured data
    secarch = _load_optional(
        case_dir / "artefacts" / "security_architecture" / "security_arch_structured.json",
        case_id,
    )
    if secarch:
        parts.append("## Security Architecture Findings")
        if secarch.get("risk_rating"):
            parts.append(f"- Risk rating: {secarch['risk_rating']}")
        if secarch.get("top_actions"):
            parts.append("- Top actions:")
            for action in secarch["top_actions"][:5]:
                parts.append(f"  - {action}")
        if secarch.get("ttps"):
            ttp_names = [t.get("technique_name", t.get("technique_id", "?"))
                         for t in secarch["ttps"][:10]]
            parts.append(f"- MITRE ATT&CK TTPs: {', '.join(ttp_names)}")
        parts.append("")

    # Timeline
    timeline = _load_optional(
        case_dir / "artefacts" / "timeline" / "timeline.json", case_id
    )
    if timeline:
        parts.append("## Timeline")
        events = timeline.get("events", timeline.get("timeline", []))
        if isinstance(events, list):
            for evt in events[:20]:
                if isinstance(evt, dict):
                    parts.append(f"- {evt.get('time', '?')}: {evt.get('description', evt.get('event', '?'))}")
                elif isinstance(evt, str):
                    parts.append(f"- {evt}")
        parts.append("")

    # CVE context
    cve = _load_optional(
        case_dir / "artefacts" / "cve" / "cve_context.json", case_id
    )
    if cve:
        parts.append("## CVE Context")
        parts.append(json.dumps(cve, indent=2, default=str)[:2000])
        parts.append("")

    # Campaign links
    campaigns = _load_optional(
        case_dir / "artefacts" / "campaign" / "campaign_links.json", case_id
    )
    if campaigns:
        parts.append("## Campaign Membership")
        camp_list = campaigns.get("campaigns", [])
        if isinstance(camp_list, list):
            for camp in camp_list:
                if isinstance(camp, dict):
                    parts.append(
                        f"- {camp.get('campaign_id', '?')}: "
                        f"{len(camp.get('shared_iocs', []))} shared IOCs, "
                        f"confidence {camp.get('confidence', '?')}"
                    )
        parts.append("")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def executive_summary(case_id: str) -> dict:
    """Stub — direct LLM generation removed.

    Use the ``write_executive_summary`` MCP prompt to generate the summary
    via the local Claude Desktop agent, then call
    ``save_report(type=executive_summary)`` to persist it.
    """
    return {
        "status": "use_prompt",
        "prompt": "write_executive_summary",
        "save_tool": "save_report",
        "save_args": {"report_type": "executive_summary"},
        "case_id": case_id,
        "ts": utcnow(),
    }


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(
        description="Generate an executive summary for a completed investigation."
    )
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = executive_summary(args.case_id)
    print(json.dumps(result, indent=2, default=str))
