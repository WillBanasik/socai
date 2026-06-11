"""
tool: closure_comment
---------------------
Generic closure-comment context builder for Sentinel-style incident
classifications (BP / FP / Undetermined). Replaces the old fp_ticket
flow with a single workflow that covers every non-TP disposition.

The closure comment itself is written by the local Claude Desktop agent
using the ``write_closure_comment`` MCP prompt, then persisted via
``save_report(report_type="closure_comment", ...)``.

This module exposes:
  - ``CLASSIFICATIONS`` — Sentinel-aligned enum + disposition map
  - ``_SYSTEM_PROMPT_FOR(classification)`` — classification-specific guidance
  - ``_build_context(case_id)``                — case data block for the prompt

Output (via save_report):
  cases/<case_id>/artefacts/closure_comments/closure_comment.md
  cases/<case_id>/artefacts/closure_comments/closure_comment_manifest.json
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, utcnow


# ---------------------------------------------------------------------------
# Sentinel-aligned classification enum
# ---------------------------------------------------------------------------

CLASSIFICATIONS: dict[str, dict] = {
    "bp_suspicious_but_expected": {
        "disposition": "benign_positive",
        "label": "Benign Positive — Suspicious but expected",
        "sentinel_classification": "BenignPositive",
        "sentinel_reason": "SuspiciousButExpected",
        "tone": (
            "State that the activity is real and matches the detection logic, "
            "but is authorised/expected for this client. Name the expected source "
            "(scheduled task, known admin tool, business process, named user). "
            "Do NOT use the words 'false positive' — this is real activity, just benign."
        ),
    },
    "bp_suspicious_not_malicious": {
        "disposition": "benign_positive",
        "label": "Benign Positive — Suspicious but not malicious",
        "sentinel_classification": "BenignPositive",
        "sentinel_reason": "SuspiciousButNotMalicious",
        "tone": (
            "State that the activity is unusual / out-of-baseline but does not "
            "constitute a threat. Reference the specific evidence that rules out "
            "malicious intent (enrichment clean, no follow-on activity, user "
            "context confirms, etc.). Do NOT use 'false positive'."
        ),
    },
    "fp_incorrect_logic": {
        "disposition": "false_positive",
        "label": "False Positive — Incorrect alert logic",
        "sentinel_classification": "FalsePositive",
        "sentinel_reason": "IncorrectAlertLogic",
        "tone": (
            "State that the detection logic fired on activity it should not match. "
            "Briefly note WHY the rule misfires (e.g. matches legitimate admin tooling, "
            "overly broad indicator, expected business pattern). Recommend tuning "
            "implicitly by naming the misfire condition — but do not write the tuning "
            "ticket here (that is a separate deliverable)."
        ),
    },
    "fp_inaccurate_data": {
        "disposition": "false_positive",
        "label": "False Positive — Inaccurate data",
        "sentinel_classification": "FalsePositive",
        "sentinel_reason": "InaccurateData",
        "tone": (
            "State that the alert was driven by stale/inaccurate source data "
            "(e.g. outdated reputation, expired indicator, mis-parsed field, stale "
            "user attribute). Reference the current data that shows the input was "
            "wrong. Make clear the underlying activity was not malicious."
        ),
    },
    "undetermined": {
        "disposition": "inconclusive",
        "label": "Undetermined",
        "sentinel_classification": "Undetermined",
        "sentinel_reason": "",
        "tone": (
            "State that available evidence is insufficient to confirm or rule out "
            "malicious activity. Name the specific gap (missing logs, expired retention, "
            "no access to upstream system, user unreachable). Note what additional "
            "data would be needed to resolve."
        ),
    },
}


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_BASE = """\
You are a SOC analyst closing an incident. Write a short closure comment \
(maximum two sentences) that justifies the disposition decision.

RULES:
1. Maximum TWO sentences. No headers, no tables, no bullet points, no markdown formatting in the comment body.
2. Reference specific evidence from the case data — name the IP, host, user, tool, indicator, or rule condition.
3. Do NOT use the words "false positive" unless the classification is one of the False Positive variants.
4. Do NOT suggest tuning, remediation, or follow-up actions — just the closure justification.
5. Tone: direct, factual, confident.
6. Language discipline (analytical standards): "confirmed" only where the case data proves it — \
an inference is "assessed"; if the data is missing, say undetermined rather than overstating.

CLASSIFICATION-SPECIFIC GUIDANCE:
{tone}

OUTPUT FORMAT (markdown — the prompt template will wrap your text in a metadata header):
Return ONLY the two-sentence (or fewer) closure comment as plain text. No preamble, no \
headers, no analyst signature. The save tool persists the comment as the body of a \
markdown file with classification metadata prepended.
"""


def _SYSTEM_PROMPT_FOR(classification: str) -> str:
    """Return the classification-aware system prompt."""
    cfg = CLASSIFICATIONS.get(classification)
    if cfg is None:
        valid = ", ".join(CLASSIFICATIONS)
        raise ValueError(f"Unknown classification {classification!r}. Valid: {valid}")
    return _SYSTEM_PROMPT_BASE.format(tone=cfg["tone"])


# ---------------------------------------------------------------------------
# Context builder (case data block for the prompt)
# ---------------------------------------------------------------------------

def _safe_load(path: Path, case_id: str = "") -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error(case_id, "closure_comment.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _build_context(case_id: str) -> str:
    """Assemble case context from all available artefacts."""
    case_dir = CASES_DIR / case_id
    parts: list[str] = [f"# Case: {case_id}\n"]

    meta = _safe_load(case_dir / "case_meta.json", case_id)
    if meta:
        parts.append("## Case Metadata")
        parts.append(f"- Title: {meta.get('title', 'N/A')}")
        parts.append(f"- Severity: {meta.get('severity', 'N/A')}")
        parts.append(f"- Status: {meta.get('status', 'N/A')}")
        parts.append(f"- Analyst: {meta.get('analyst', 'unassigned')}")
        parts.append(f"- Created: {meta.get('created_at', 'N/A')}")
        parts.append("")

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

    logs_dir = case_dir / "logs"
    if logs_dir.exists():
        log_chunks: list[str] = []
        total_chars = 0
        for log_file in sorted(logs_dir.iterdir()):
            if log_file.is_file() and total_chars < 3000:
                try:
                    text = log_file.read_text(encoding="utf-8", errors="replace")
                    if len(text) > 1500:
                        text = text[:1500] + "\n[...truncated...]"
                    log_chunks.append(f"### {log_file.name}\n{text}")
                    total_chars += len(text)
                except Exception as exc:
                    log_error(case_id, "closure_comment.read_log", str(exc),
                              severity="info", context={"file": str(log_file)})
        if log_chunks:
            parts.append("## Log Records")
            parts.extend(log_chunks)
            parts.append("")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public stub (kept for parity with other deliverable modules)
# ---------------------------------------------------------------------------

def closure_comment(case_id: str, classification: str) -> dict:
    """Stub — direct LLM generation removed.

    Use the ``write_closure_comment`` MCP prompt to generate the comment
    via the local Claude Desktop agent, then call
    ``save_report(report_type="closure_comment", disposition=<...>)`` to persist it.
    """
    if classification not in CLASSIFICATIONS:
        return {
            "status": "error",
            "reason": f"Unknown classification {classification!r}.",
            "valid": list(CLASSIFICATIONS),
            "case_id": case_id,
            "ts": utcnow(),
        }
    return {
        "status": "use_prompt",
        "prompt": "write_closure_comment",
        "save_tool": "save_report",
        "save_args": {
            "report_type": "closure_comment",
            "disposition": CLASSIFICATIONS[classification]["disposition"],
        },
        "classification": classification,
        "case_id": case_id,
        "ts": utcnow(),
    }
