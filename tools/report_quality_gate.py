"""
tool: report_quality_gate
-------------------------
Deterministic review of generated investigation reports against the
investigation matrix and analytical standards. Quality gate LLM review
removed. Module retains deterministic check functions. Full review
available via ``review_report`` MCP prompt.

Checks:
  1. Deterministic: "confirmed" claims cross-referenced against matrix known_knowns
  2. Deterministic: causal language detection
  3. Deterministic: speculative language detection
  4. Deterministic: matrix coverage — are all known_knowns addressed in the report?

Returns the review dict in-memory; does NOT write to disk.

All functions are resilient — return safe defaults on failure, never crash.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, utcnow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_load(path: Path) -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "report_quality_gate._safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


# ---------------------------------------------------------------------------
# Deterministic checks
# ---------------------------------------------------------------------------

# Patterns that indicate "confirmed" claims in report text
_CONFIRMED_PATTERN = re.compile(
    r"\bconfirmed?\b", re.IGNORECASE,
)

# Causal language patterns that should be flagged without evidence
_CAUSAL_PATTERNS = [
    re.compile(r"\b(?:led to|resulted in|caused|triggered)\b", re.IGNORECASE),
    re.compile(r"\b(?:the user clicked)\b", re.IGNORECASE),
    re.compile(r"\b(?:the email delivered the)\b", re.IGNORECASE),
    re.compile(r"\b(?:this (?:led|caused|resulted))\b", re.IGNORECASE),
]

# Speculative language
_SPECULATION_PATTERNS = [
    re.compile(r"\b(?:likely|probably|presumably|possibly)\b", re.IGNORECASE),
    re.compile(r"\b(?:it is believed|we believe|it appears)\b", re.IGNORECASE),
]


def _check_confirmed_claims(report_text: str, matrix: dict | None) -> list[dict]:
    """Flag 'confirmed' claims that aren't backed by matrix known_knowns."""
    flags: list[dict] = []
    if not matrix:
        return flags

    confirmed_findings = {
        kk.get("finding", "").lower()
        for kk in matrix.get("known_knowns", [])
        if kk.get("confidence") == "confirmed"
    }

    # Find all "confirmed" usages in the report
    for match in _CONFIRMED_PATTERN.finditer(report_text):
        # Get surrounding context (sentence-ish)
        start = max(0, match.start() - 100)
        end = min(len(report_text), match.end() + 100)
        context = report_text[start:end].strip()

        # Check if any confirmed known_known is referenced nearby
        context_lower = context.lower()
        found_backing = any(
            finding[:40] in context_lower
            for finding in confirmed_findings
            if finding
        )

        if not found_backing:
            # Get rough line number
            line_num = report_text[:match.start()].count("\n") + 1
            flags.append({
                "severity": "error",
                "rule": "confirmed_without_evidence",
                "location": f"Line ~{line_num}",
                "finding": f"'confirmed' used but no matching known_known in matrix",
                "context": context[:200],
                "suggestion": "Change to 'assessed with [high/medium/low] confidence' "
                              "or add evidence to the matrix",
            })

    return flags


def _check_causal_language(report_text: str) -> list[dict]:
    """Flag causal claims that may lack evidence backing."""
    flags: list[dict] = []
    for pattern in _CAUSAL_PATTERNS:
        for match in pattern.finditer(report_text):
            start = max(0, match.start() - 80)
            end = min(len(report_text), match.end() + 80)
            context = report_text[start:end].strip()
            line_num = report_text[:match.start()].count("\n") + 1
            flags.append({
                "severity": "warning",
                "rule": "causal_claim",
                "location": f"Line ~{line_num}",
                "finding": f"Causal language detected: '{match.group()}'",
                "context": context[:200],
                "suggestion": "Verify causal link with specific evidence. "
                              "Temporal proximity is not causation.",
            })
    return flags


def _check_speculation(report_text: str) -> list[dict]:
    """Flag speculative language."""
    flags: list[dict] = []
    for pattern in _SPECULATION_PATTERNS:
        for match in pattern.finditer(report_text):
            start = max(0, match.start() - 80)
            end = min(len(report_text), match.end() + 80)
            context = report_text[start:end].strip()
            line_num = report_text[:match.start()].count("\n") + 1
            flags.append({
                "severity": "warning",
                "rule": "speculative_language",
                "location": f"Line ~{line_num}",
                "finding": f"Speculative language: '{match.group()}'",
                "context": context[:200],
                "suggestion": "Replace with 'assessed with [confidence]' or "
                              "state as 'unknown / not determined' if no evidence.",
            })
    return flags


def _check_matrix_coverage(report_text: str, matrix: dict | None) -> dict:
    """Check how many known_knowns and known_unknowns are addressed in the report."""
    if not matrix:
        return {
            "known_knowns_addressed": 0,
            "known_knowns_total": 0,
            "known_unknowns_acknowledged": 0,
            "known_unknowns_total": 0,
            "unaddressed_knowns": [],
            "unaddressed_unknowns": [],
        }

    report_lower = report_text.lower()

    # Check known_knowns
    kk_addressed = 0
    kk_unaddressed = []
    for kk in matrix.get("known_knowns", []):
        finding = kk.get("finding", "")
        # Check if key terms from the finding appear in the report
        key_terms = [t for t in finding.lower().split() if len(t) > 4][:5]
        if key_terms and sum(1 for t in key_terms if t in report_lower) >= len(key_terms) // 2 + 1:
            kk_addressed += 1
        else:
            kk_unaddressed.append(kk.get("id", "unknown"))

    # Check known_unknowns (should be acknowledged as gaps)
    ku_acknowledged = 0
    ku_unaddressed = []
    for ku in matrix.get("known_unknowns", []):
        question = ku.get("question", "")
        key_terms = [t for t in question.lower().split() if len(t) > 4][:5]
        if key_terms and sum(1 for t in key_terms if t in report_lower) >= len(key_terms) // 2 + 1:
            ku_acknowledged += 1
        else:
            ku_unaddressed.append(ku.get("id", "unknown"))

    return {
        "known_knowns_addressed": kk_addressed,
        "known_knowns_total": len(matrix.get("known_knowns", [])),
        "known_unknowns_acknowledged": ku_acknowledged,
        "known_unknowns_total": len(matrix.get("known_unknowns", [])),
        "unaddressed_knowns": kk_unaddressed,
        "unaddressed_unknowns": ku_unaddressed,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def review_report(case_id: str) -> dict | None:
    """Review the investigation report against matrix and analytical standards.

    Returns review dict on success, None if no report exists.  Does not
    write to disk.
    """
    case_dir = CASES_DIR / case_id

    # Load report
    report_path = case_dir / "reports" / "investigation_report.md"
    if not report_path.exists():
        return None

    report_text = report_path.read_text(errors="ignore")
    if not report_text.strip():
        return None

    # Load matrix (may not exist)
    matrix = _safe_load(
        case_dir / "artefacts" / "analysis" / "investigation_matrix.json"
    )

    # Run all checks
    flags: list[dict] = []

    # 1. Deterministic: confirmed claims
    flags.extend(_check_confirmed_claims(report_text, matrix))

    # 2. Deterministic: causal language
    flags.extend(_check_causal_language(report_text))

    # 3. Deterministic: speculative language
    flags.extend(_check_speculation(report_text))

    # 4. Matrix coverage
    coverage = _check_matrix_coverage(report_text, matrix)

    # Determine pass/fail
    error_count = sum(1 for f in flags if f.get("severity") == "error")
    passed = error_count == 0

    result = {
        "case_id": case_id,
        "ts": utcnow(),
        "passed": passed,
        "error_count": error_count,
        "warning_count": sum(1 for f in flags if f.get("severity") == "warning"),
        "flags": flags,
        "coverage": coverage,
        "matrix_available": matrix is not None,
    }

    status = "PASSED" if passed else f"FAILED ({error_count} error(s))"
    print(f"[quality_gate] {case_id}: {status}, "
          f"{len(flags)} flag(s) total, "
          f"coverage: {coverage['known_knowns_addressed']}/{coverage['known_knowns_total']} knowns")

    return result
