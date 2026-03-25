"""
tool: followup
--------------
Follow-up proposal management — gap analysis, proposal generation, and
analyst-approved execution.

Relocated from agents/rumsfeld.py during the HITL refactor.
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, save_json, utcnow


# ---------------------------------------------------------------------------
# Gap analysis — identify unresolved evidence gaps
# ---------------------------------------------------------------------------

def _analyse_gaps(matrix: dict) -> list[dict]:
    """Identify unresolved known_unknowns and untested hypotheses."""
    gaps: list[dict] = []

    # Unresolved known unknowns
    for ku in matrix.get("known_unknowns", []):
        if ku.get("resolution") is None:
            gaps.append({
                "type": "known_unknown",
                "id": ku.get("id"),
                "category": ku.get("category"),
                "question": ku.get("question"),
                "required_evidence": ku.get("required_evidence"),
                "suggested_tool": ku.get("suggested_tool"),
                "priority": ku.get("priority", "medium"),
            })

    # Untested hypothesis disconfirming checks
    for hyp in matrix.get("hypotheses", []):
        if hyp.get("status") == "unresolved":
            for check in hyp.get("disconfirming_checks", []):
                if check.get("result") is None:
                    gaps.append({
                        "type": "untested_hypothesis_check",
                        "hypothesis_id": hyp.get("id"),
                        "claim": hyp.get("claim"),
                        "check": check.get("check"),
                        "tool": check.get("tool"),
                        "priority": "high",  # Untested disconfirming checks are high priority
                    })

    # Sort by priority
    priority_order = {"high": 0, "medium": 1, "low": 2}
    gaps.sort(key=lambda g: priority_order.get(g.get("priority", "medium"), 1))

    return gaps


# ---------------------------------------------------------------------------
# Follow-up proposal generation
# ---------------------------------------------------------------------------

# Map suggested tools to actual socai tool calls
_TOOL_MAP = {
    "sentinel_query": {
        "tool": "generate_sentinel_query",
        "description": "Run Sentinel composite query",
    },
    "log_correlate": {
        "tool": "correlate",
        "description": "Re-run log correlation with updated IOCs",
    },
    "enrich": {
        "tool": "enrich",
        "description": "Run enrichment pass (with pivot IOCs)",
    },
    "web_capture": {
        "tool": "capture_urls",
        "description": "Capture additional URLs",
    },
    "sandbox": {
        "tool": "sandbox_session",
        "description": "Submit sample for sandbox detonation",
    },
    "velociraptor": {
        "tool": "velociraptor",
        "description": "Ingest Velociraptor collection for endpoint data",
    },
    "mde_package": {
        "tool": "mde_package",
        "description": "Ingest MDE investigation package",
    },
    "browser_session": {
        "tool": "browser_session",
        "description": "Open disposable browser session for URL analysis",
    },
}


def _propose_followups(
    case_id: str,
    matrix: dict,
    gaps: list[dict],
    determination: dict | None = None,
) -> list[dict]:
    """Generate follow-up proposals from gaps.

    Each proposal maps a gap to a specific tool call with reasoning.
    Uses deterministic tool mapping from the investigation matrix.
    """
    proposals: list[dict] = []

    # Deterministic mapping from suggested tools
    for i, gap in enumerate(gaps, 1):
        suggested = gap.get("suggested_tool") or gap.get("tool", "")
        tool_info = _TOOL_MAP.get(suggested)

        if tool_info:
            proposals.append({
                "id": f"p_{i:03d}",
                "resolves": gap.get("id") or gap.get("hypothesis_id", ""),
                "action": tool_info["description"],
                "tool": tool_info["tool"],
                "params": {"case_id": case_id},
                "reasoning": gap.get("question") or gap.get("check", ""),
                "priority": gap.get("priority", "medium"),
                "estimated_cost": "1 tool call",
            })
        else:
            # Generic proposal
            proposals.append({
                "id": f"p_{i:03d}",
                "resolves": gap.get("id") or gap.get("hypothesis_id", ""),
                "action": f"Investigate: {gap.get('question') or gap.get('check', 'N/A')}",
                "tool": "manual",
                "params": {},
                "reasoning": gap.get("required_evidence") or gap.get("check", ""),
                "priority": gap.get("priority", "medium"),
                "estimated_cost": "analyst review",
            })

    return proposals


# ---------------------------------------------------------------------------
# Follow-up execution (analyst-approved)
# ---------------------------------------------------------------------------

def execute_followup(case_id: str, proposal_id: str) -> dict:
    """Execute a single approved follow-up proposal.

    Returns the tool result dict. Updates the proposal status.
    """
    proposals_path = (CASES_DIR / case_id / "artefacts" / "analysis"
                      / "followup_proposals.json")
    if not proposals_path.exists():
        return {"error": "No follow-up proposals found", "case_id": case_id}

    data = load_json(proposals_path)
    proposals = data.get("proposals", [])

    # Find the proposal
    target = None
    for p in proposals:
        if p.get("id") == proposal_id:
            target = p
            break

    if not target:
        return {"error": f"Proposal {proposal_id} not found", "case_id": case_id}

    tool_name = target.get("tool", "")
    params = target.get("params", {})
    params.setdefault("case_id", case_id)

    if tool_name == "manual":
        return {"status": "manual", "message": "Requires analyst action",
                "action": target.get("action")}

    # Execute via actions layer
    try:
        from api import actions
        action_fn = getattr(actions, tool_name, None)
        if action_fn:
            result = action_fn(**params)
        else:
            result = {"error": f"Unknown tool: {tool_name}"}

        # Update proposal status
        target["status"] = "executed"
        target["executed_at"] = utcnow()
        target["result_status"] = result.get("status", "unknown")
        save_json(proposals_path, data)

        # Try to update the matrix with new findings
        try:
            from tools.investigation_matrix import update_matrix
            update_matrix(case_id, f"followup.{proposal_id}", {
                "resolve_unknowns": [target.get("resolves", "")],
            })
        except Exception:
            pass

        return result
    except Exception as exc:
        log_error(case_id, f"followup.execute_followup.{proposal_id}",
                  str(exc), traceback=traceback.format_exc())
        return {"error": str(exc), "case_id": case_id}


def list_proposals(case_id: str) -> list[dict]:
    """List all follow-up proposals for a case."""
    proposals_path = (CASES_DIR / case_id / "artefacts" / "analysis"
                      / "followup_proposals.json")
    if not proposals_path.exists():
        return []
    data = load_json(proposals_path)
    return data.get("proposals", [])
