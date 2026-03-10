"""
tool: executive_summary
-----------------------
LLM-assisted executive summary generator for non-technical business leadership.

Reads case artefacts and produces a plain-English executive summary with
RAG (Red/Amber/Green) risk rating, structured via Claude tool_use.

Output:
  cases/<case_id>/artefacts/executive_summary/executive_summary.md
  cases/<case_id>/artefacts/executive_summary/executive_summary_manifest.json

Usage (standalone):
  python3 tools/executive_summary.py --case IV_CASE_001
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_alias_map, get_model, load_json, log_error, save_json, utcnow, write_artefact

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
    """
    Generate an LLM-assisted executive summary for *case_id*.

    Returns a manifest dict with the output path, risk rating, and token usage.
    """
    # ── 1. Early-exit checks ──────────────────────────────────────────────
    if not ANTHROPIC_KEY:
        return {"status": "skipped", "reason": "ANTHROPIC_API_KEY not set"}

    try:
        import anthropic
    except ImportError as exc:
        log_error(case_id, "executive_summary.import_anthropic", str(exc), severity="info")
        return {
            "status": "error",
            "reason": "anthropic package not installed. Run: pip install anthropic",
            "case_id": case_id,
            "ts": utcnow(),
        }

    # ── 2. Build context ──────────────────────────────────────────────────
    context_text = _build_context(case_id)
    alias_map = get_alias_map()
    if alias_map:
        context_text = alias_map.alias_text(context_text)

    if not context_text.strip():
        return {
            "status": "skipped",
            "reason": "No case artefacts found — run investigate first.",
            "case_id": case_id,
            "ts": utcnow(),
        }

    # ── 3. Load metadata for template ────────────────────────────────────
    case_dir = CASES_DIR / case_id
    meta = _load_optional(case_dir / "case_meta.json", case_id) or {}
    title = meta.get("title", "Untitled Investigation")
    severity = meta.get("severity", "unknown")

    # ── 4. LLM call (structured output) ─────────────────────────────────
    from tools.structured_llm import structured_call
    from tools.schemas import ExecutiveSummary as ExecutiveSummarySchema

    _model = get_model("exec_summary", severity)
    print(f"[executive_summary] Querying {_model} for case {case_id}...")

    try:
        structured_result, usage = structured_call(
            model=_model,
            system=_SYSTEM_CACHED,
            messages=[{
                "role": "user",
                "content": (
                    "Produce an executive summary for the following security "
                    f"investigation.\n\n{context_text}"
                ),
            }],
            output_schema=ExecutiveSummarySchema,
            max_tokens=4096,
        )
    except Exception as exc:
        log_error(case_id, "executive_summary.llm_call", str(exc), severity="error")
        return {
            "status": "error",
            "reason": f"LLM call failed: {exc}",
            "case_id": case_id,
            "ts": utcnow(),
        }

    # ── 5. Extract structured data ───────────────────────────────────────
    structured_data = structured_result.model_dump() if structured_result else None

    tokens_in = usage.get("input_tokens", 0)
    tokens_out = usage.get("output_tokens", 0)

    print(
        f"[executive_summary] Tokens: {tokens_in} in / {tokens_out} out"
    )

    # ── 6. Assemble markdown ─────────────────────────────────────────────
    ts = utcnow()

    if structured_data:
        what_happened = structured_data.get("what_happened", "")
        who_affected = structured_data.get("who_affected", "")
        risk_rating = structured_data.get("risk_rating", "AMBER")
        risk_justification = structured_data.get("risk_justification", "")
        what_done = structured_data.get("what_done", "")
        next_steps = structured_data.get("next_steps", [])
        business_risk = structured_data.get("business_risk", "")

        next_steps_md = "\n".join(
            f"{i}. {step}" for i, step in enumerate(next_steps, 1)
        )

        summary_text = (
            f"# Executive Summary — {case_id}: {title}\n\n"
            f"**Risk Rating: {risk_rating}** — {risk_justification}\n\n"
            f"## What Happened\n{what_happened}\n\n"
            f"## Who Was Affected\n{who_affected}\n\n"
            f"## What Has Been Done\n{what_done}\n\n"
            f"## Recommended Actions\n{next_steps_md}\n\n"
            f"## Business Risk\n{business_risk}\n\n"
            f"---\n"
            f"*Generated: {ts} | Case: {case_id} | Severity: {severity}*\n"
        )
    else:
        # Fallback: structured output parse failed
        risk_rating = "AMBER"
        print("[executive_summary] WARNING: Structured output not returned — using fallback")
        summary_text = (
            f"# Executive Summary — {case_id}: {title}\n\n"
            f"*Structured output could not be generated. Please re-run.*\n\n"
            f"---\n"
            f"*Generated: {ts} | Case: {case_id} | Severity: {severity}*\n"
        )

    # ── 7. Dealias ────────────────────────────────────────────────────────
    if alias_map:
        summary_text = alias_map.dealias_text(summary_text)

    # ── 8. Write artefacts ────────────────────────────────────────────────
    out_dir = case_dir / "artefacts" / "executive_summary"
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_path = out_dir / "executive_summary.md"
    write_artefact(summary_path, summary_text)

    word_count = len(summary_text.split())

    manifest = {
        "status": "ok",
        "summary_path": str(summary_path),
        "risk_rating": risk_rating,
        "word_count": word_count,
        "tokens_input": tokens_in,
        "tokens_output": tokens_out,
        "model": _model,
        "ts": ts,
    }
    save_json(out_dir / "executive_summary_manifest.json", manifest)

    print(f"[executive_summary] Summary written to {summary_path} ({word_count} words)")
    return manifest


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
