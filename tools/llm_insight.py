"""
tool: llm_insight
-----------------
Shared LLM helper stubs — formerly pipeline enhancement via Anthropic API.

All LLM reasoning is now handled by the local Claude Desktop agent.
These functions return None (or a safe default) unconditionally so that
callers continue to degrade gracefully with no code changes required.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# 1. synthesise_report_narrative
# ---------------------------------------------------------------------------

def synthesise_report_narrative(case_id: str) -> str | None:
    """Return None — narrative synthesis handled by local Claude agent."""
    return None


# ---------------------------------------------------------------------------
# 2. generate_campaign_narrative
# ---------------------------------------------------------------------------

def generate_campaign_narrative(campaign: dict) -> str | None:
    """Return None — campaign narrative handled by local Claude agent."""
    return None


# ---------------------------------------------------------------------------
# 3. refine_hunt_queries
# ---------------------------------------------------------------------------

def refine_hunt_queries(
    case_id: str,
    existing_patterns: str,
    ioc_summary: str,
) -> str | None:
    """Return None — query refinement handled by local Claude agent."""
    return None


# ---------------------------------------------------------------------------
# 4. contextualise_triage
# ---------------------------------------------------------------------------

def contextualise_triage(triage_data: dict, severity: str) -> str | None:
    """Return None — triage contextualisation handled by local Claude agent."""
    return None


# ---------------------------------------------------------------------------
# 5. contextualise_anomalies
# ---------------------------------------------------------------------------

def contextualise_anomalies(anomaly_data: dict, meta: dict) -> str | None:
    """Return None — anomaly analysis handled by local Claude agent."""
    return None


# ---------------------------------------------------------------------------
# 6. interpret_correlations
# ---------------------------------------------------------------------------

def interpret_correlations(correlation: dict, meta: dict) -> str | None:
    """Return None — correlation interpretation handled by local Claude agent."""
    return None


# ---------------------------------------------------------------------------
# 7. prioritise_response_actions
# ---------------------------------------------------------------------------

def prioritise_response_actions(response_data: dict, meta: dict) -> str | None:
    """Return None — response prioritisation handled by local Claude agent."""
    return None


# ---------------------------------------------------------------------------
# 8. reconcile_verdict_conflicts
# ---------------------------------------------------------------------------

def reconcile_verdict_conflicts(conflicting_iocs: list[dict]) -> str | None:
    """Return None — verdict reconciliation handled by local Claude agent."""
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
    """Return safe default — auto-close validation handled by local Claude agent."""
    return {"keep_open": False, "reason": ""}
