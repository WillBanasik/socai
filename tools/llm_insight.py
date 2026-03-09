"""
tool: llm_insight
-----------------
Shared LLM helper module for pipeline enhancement steps.

Provides lightweight, resilient LLM calls that add analytical depth to
deterministic pipeline outputs. Every public function is safe to call even
when ANTHROPIC_API_KEY is unset or the anthropic package is missing — they
return None (or a safe default) and never crash the pipeline.

Functions:
  synthesise_report_narrative   — executive narrative for a completed case
  generate_campaign_narrative   — campaign description from cluster data
  refine_hunt_queries           — additional KQL queries the template generator misses
  contextualise_triage          — escalation justification from IOC history
  contextualise_anomalies       — filter/chain/prioritise behavioural anomalies
  interpret_correlations        — IOC-to-log correlation interpretation
  prioritise_response_actions   — urgency ordering + exec impact summary
  reconcile_verdict_conflicts   — advisory reconciliation of conflicting provider verdicts
  validate_auto_close           — LLM review of auto-close decisions
"""
from __future__ import annotations

import json
import sys
import traceback as _tb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_model, load_json, log_error


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_load(path: Path) -> dict | None:
    """Load JSON, returning None on missing file or parse error."""
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "llm_insight._safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _call_llm(
    task: str,
    severity: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 1024,
) -> str | None:
    """Call the Anthropic Messages API with graceful degradation.

    Returns the text response on success, or None on any failure.
    Never raises — all exceptions are caught and logged.
    """
    if not ANTHROPIC_KEY:
        return None

    try:
        import anthropic
    except ImportError:
        log_error("", f"llm_insight.{task}", "anthropic package not installed",
                  severity="info")
        return None

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        model = get_model(task, severity)
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = message.content[0].text.strip()
        tokens_in = message.usage.input_tokens
        tokens_out = message.usage.output_tokens
        print(f"[llm_insight] {task} completed ({tokens_in}/{tokens_out} tokens)")
        return text
    except Exception as exc:
        log_error("", f"llm_insight.{task}", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 1. synthesise_report_narrative
# ---------------------------------------------------------------------------

def synthesise_report_narrative(case_id: str) -> str | None:
    """Generate a concise executive narrative (3-5 sentences) for a case.

    Reads case_meta.json, verdict_summary.json, anomaly_report.json,
    campaign_links.json, and correlation.json to build context.
    """
    case_dir = CASES_DIR / case_id

    meta = _safe_load(case_dir / "case_meta.json") or {}
    verdict = _safe_load(case_dir / "artefacts" / "enrichment" / "verdict_summary.json") or {}
    anomalies = _safe_load(case_dir / "artefacts" / "anomalies" / "anomaly_report.json") or {}
    campaign = _safe_load(case_dir / "artefacts" / "campaign" / "campaign_links.json") or {}
    correlation = _safe_load(case_dir / "artefacts" / "correlation" / "correlation.json") or {}

    severity = meta.get("severity", "medium")

    parts: list[str] = [f"Case: {case_id}"]
    if meta:
        parts.append(f"Title: {meta.get('title', 'N/A')}")
        parts.append(f"Severity: {severity}")
        parts.append(f"Status: {meta.get('status', 'N/A')}")
    if verdict:
        parts.append(f"Malicious IOCs: {len(verdict.get('high_priority', []))}")
        parts.append(f"Suspicious IOCs: {len(verdict.get('needs_review', []))}")
        parts.append(f"Clean IOCs: {len(verdict.get('clean', []))}")
    if anomalies:
        parts.append(f"Anomalies detected: {len(anomalies.get('anomalies', []))}")
    if campaign:
        parts.append(f"Campaign links: {json.dumps(campaign, default=str)[:500]}")
    if correlation:
        parts.append(f"Correlation hit summary: {json.dumps(correlation.get('hit_summary', {}), default=str)[:300]}")

    user_prompt = "\n".join(parts)

    try:
        return _call_llm(
            task="report_narrative",
            severity=severity,
            system_prompt=(
                "You are a SOC analyst. Synthesise a concise executive narrative "
                "(3-5 sentences) for this investigation. Focus on what happened, "
                "what was found, and what matters. Mark inferences as 'assessed'. "
                "Use UK English."
            ),
            user_prompt=user_prompt,
            max_tokens=512,
        )
    except Exception as exc:
        log_error(case_id, "llm_insight.synthesise_report_narrative", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 2. generate_campaign_narrative
# ---------------------------------------------------------------------------

def generate_campaign_narrative(campaign: dict) -> str | None:
    """Generate a 2-3 sentence campaign description from cluster data."""
    try:
        user_prompt = json.dumps(campaign, indent=2, default=str)[:2000]
        return _call_llm(
            task="campaign_narrative",
            severity="medium",
            system_prompt=(
                "You are a threat intelligence analyst. Generate a 2-3 sentence "
                "campaign description covering: shared infrastructure, suspected "
                "threat type, and whether the campaign appears to be evolving. "
                "Use UK English."
            ),
            user_prompt=user_prompt,
            max_tokens=256,
        )
    except Exception as exc:
        log_error("", "llm_insight.generate_campaign_narrative", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 3. refine_hunt_queries
# ---------------------------------------------------------------------------

def refine_hunt_queries(
    case_id: str,
    existing_patterns: str,
    ioc_summary: str,
) -> str | None:
    """Suggest 2-3 additional KQL hunt queries the template generator would miss."""
    case_dir = CASES_DIR / case_id
    meta = _safe_load(case_dir / "case_meta.json") or {}
    severity = meta.get("severity", "medium")

    user_prompt = (
        f"Case: {case_id}\n"
        f"Severity: {severity}\n\n"
        f"Existing threat patterns:\n{existing_patterns}\n\n"
        f"IOC summary:\n{ioc_summary}"
    )

    try:
        return _call_llm(
            task="query_refinement",
            severity=severity,
            system_prompt=(
                "You are a SIEM threat hunter. Given the case context and detected "
                "threat patterns, suggest 2-3 additional KQL hunt queries that the "
                "template-based generator would miss. Focus on attacker techniques "
                "specific to this case. Return Markdown with ```kql code blocks. "
                "Use UK English."
            ),
            user_prompt=user_prompt,
            max_tokens=1024,
        )
    except Exception as exc:
        log_error(case_id, "llm_insight.refine_hunt_queries", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 4. contextualise_triage
# ---------------------------------------------------------------------------

def contextualise_triage(triage_data: dict, severity: str) -> str | None:
    """Provide a 2-3 sentence contextualisation of the escalation decision."""
    try:
        user_prompt = json.dumps(triage_data, indent=2, default=str)[:2000]
        return _call_llm(
            task="triage_context",
            severity=severity,
            system_prompt=(
                "You are a SOC triage analyst. Given the known IOC matches from "
                "prior cases, provide a 2-3 sentence contextualisation of the "
                "escalation decision. Explain WHY the escalation is or isn't "
                "justified based on the IOC history. Use UK English."
            ),
            user_prompt=user_prompt,
            max_tokens=256,
        )
    except Exception as exc:
        log_error("", "llm_insight.contextualise_triage", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 5. contextualise_anomalies
# ---------------------------------------------------------------------------

def contextualise_anomalies(anomaly_data: dict, meta: dict) -> str | None:
    """Filter false positives, chain anomalies, and prioritise by risk."""
    severity = meta.get("severity", "medium")

    user_prompt = (
        f"Case metadata:\n{json.dumps(meta, indent=2, default=str)[:500]}\n\n"
        f"Anomaly data:\n{json.dumps(anomaly_data, indent=2, default=str)[:3000]}"
    )

    try:
        return _call_llm(
            task="anomaly_context",
            severity=severity,
            system_prompt=(
                "You are a SOC analyst reviewing behavioural anomalies. Filter "
                "false positives, chain related anomalies into attack sequences, "
                "and prioritise findings by risk. Mark reasoning as 'assessed'. "
                "Return a brief Markdown summary (bullet points). Use UK English."
            ),
            user_prompt=user_prompt,
            max_tokens=512,
        )
    except Exception as exc:
        log_error("", "llm_insight.contextualise_anomalies", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 6. interpret_correlations
# ---------------------------------------------------------------------------

def interpret_correlations(correlation: dict, meta: dict) -> str | None:
    """Interpret IOC-to-log correlations for investigative significance."""
    severity = meta.get("severity", "medium")

    user_prompt = (
        f"Case metadata:\n{json.dumps(meta, indent=2, default=str)[:500]}\n\n"
        f"Correlation data:\n{json.dumps(correlation, indent=2, default=str)[:3000]}"
    )

    try:
        return _call_llm(
            task="correlation_insight",
            severity=severity,
            system_prompt=(
                "You are a SOC analyst. Interpret what these IOC-to-log correlations "
                "mean for the investigation. Focus on temporal sequence, causal "
                "relationships (only if data supports them), and which correlations "
                "are noise vs actionable. Mark inferences as 'assessed'. Use UK English."
            ),
            user_prompt=user_prompt,
            max_tokens=512,
        )
    except Exception as exc:
        log_error("", "llm_insight.interpret_correlations", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 7. prioritise_response_actions
# ---------------------------------------------------------------------------

def prioritise_response_actions(response_data: dict, meta: dict) -> str | None:
    """Prioritise response actions by urgency with an exec impact summary."""
    severity = meta.get("severity", "medium")

    user_prompt = (
        f"Case metadata:\n{json.dumps(meta, indent=2, default=str)[:500]}\n\n"
        f"Response plan:\n{json.dumps(response_data, indent=2, default=str)[:3000]}"
    )

    try:
        return _call_llm(
            task="response_priority",
            severity=severity,
            system_prompt=(
                "You are an incident responder. Given the response plan and case "
                "context, prioritise the permitted actions by urgency and generate "
                "a 1-paragraph business impact summary for executives. Use UK English."
            ),
            user_prompt=user_prompt,
            max_tokens=384,
        )
    except Exception as exc:
        log_error("", "llm_insight.prioritise_response_actions", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 8. reconcile_verdict_conflicts
# ---------------------------------------------------------------------------

def reconcile_verdict_conflicts(conflicting_iocs: list[dict]) -> str | None:
    """Advisory reconciliation of IOCs where providers disagree."""
    if not conflicting_iocs:
        return None

    user_prompt = json.dumps(conflicting_iocs, indent=2, default=str)[:3000]

    try:
        return _call_llm(
            task="verdict_reconcile",
            severity="medium",
            system_prompt=(
                "You are a threat intelligence analyst. Reconcile conflicting "
                "provider verdicts for these IOCs. Consider provider reliability, "
                "data freshness, and detection methodology. This is ADVISORY ONLY "
                "— do not override the deterministic verdict. Mark all conclusions "
                "as 'assessed'. Use UK English."
            ),
            user_prompt=user_prompt,
            max_tokens=512,
        )
    except Exception as exc:
        log_error("", "llm_insight.reconcile_verdict_conflicts", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


# ---------------------------------------------------------------------------
# 9. validate_auto_close
# ---------------------------------------------------------------------------

def validate_auto_close(
    case_id: str,
    meta: dict,
    verdicts: dict,
    anomaly_data: dict,
) -> dict:
    """LLM review of an auto-close decision.

    Returns {"keep_open": bool, "reason": str}.
    On any failure returns the safe default: {"keep_open": False, "reason": ""}.
    """
    safe_default: dict = {"keep_open": False, "reason": ""}

    user_prompt = (
        f"Case: {case_id}\n"
        f"Metadata:\n{json.dumps(meta, indent=2, default=str)[:500]}\n\n"
        f"Verdicts:\n{json.dumps(verdicts, indent=2, default=str)[:500]}\n\n"
        f"Anomaly data:\n{json.dumps(anomaly_data, indent=2, default=str)[:500]}"
    )

    try:
        raw = _call_llm(
            task="auto_close_review",
            severity=meta.get("severity", "medium"),
            system_prompt=(
                "You are a SOC supervisor reviewing an auto-close decision. The "
                "case has 0 malicious and 0 suspicious IOCs. Check if there are "
                "reasons to keep the case open (anomalies, first-seen entities, "
                "high severity, executive-related title). Return JSON: "
                '{"keep_open": bool, "reason": "..."} Use UK English.'
            ),
            user_prompt=user_prompt,
            max_tokens=256,
        )
        if not raw:
            return safe_default

        # Extract JSON from the response (handle markdown code fences)
        text = raw.strip()
        if text.startswith("```"):
            # Strip code fences
            lines = text.splitlines()
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()

        parsed = json.loads(text)
        return {
            "keep_open": bool(parsed.get("keep_open", False)),
            "reason": str(parsed.get("reason", "")),
        }
    except Exception as exc:
        log_error(case_id, "llm_insight.validate_auto_close", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return safe_default
