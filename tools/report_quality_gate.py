"""
tool: report_quality_gate
-------------------------
Hybrid deterministic + LLM review of generated investigation reports against
the investigation matrix and analytical standards.

Checks:
  1. Deterministic: "confirmed" claims cross-referenced against matrix known_knowns
  2. Deterministic: matrix coverage — are all known_knowns addressed in the report?
  3. LLM (Haiku): causal claims without cited evidence
  4. LLM (Haiku): speculation or gap-filling language

Output: cases/<ID>/artefacts/analysis/report_review.json

All functions are resilient — return safe defaults on failure, never crash.
"""
from __future__ import annotations

import json
import re
import sys
import traceback as _tb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_model, load_json, log_error, save_json, utcnow


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
# LLM review (Haiku tier — cheap validation)
# ---------------------------------------------------------------------------

def _llm_review(report_text: str, matrix: dict | None, severity: str) -> list[dict]:
    """LLM check for analytical standard violations."""
    if not ANTHROPIC_KEY:
        return []

    try:
        import anthropic
    except ImportError:
        return []

    system_prompt = (
        "You are a senior SOC quality reviewer auditing an MDR investigation "
        "report against analytical and operational standards.\n\n"
        "## Analytical Standards\n"
        "1. Every 'confirmed' claim must cite specific data/evidence — the "
        "artefact, field, and value that proves it\n"
        "2. Temporal proximity is NEVER causation — two events close in time "
        "is not evidence of a causal link without a data-level connection "
        "(shared URL, hash, process ID, audit log entry)\n"
        "3. No gap-filling with speculation — if a step in the attack chain "
        "lacks evidence, it must be stated as unknown, not inferred\n"
        "4. Evidence chain links must be independently verified — each link "
        "(email → click → download → execution) requires its own evidence\n"
        "5. Distinguish fact from inference — 'confirmed' = data proves it, "
        "'assessed with [high/medium/low] confidence' = inference, "
        "'unknown' = no data\n\n"
        "## Operational Standards\n"
        "6. The report MUST include a 'What Was NOT Observed' section "
        "documenting the absence of: C2 traffic, lateral movement, "
        "persistence mechanisms, privilege escalation, data exfiltration "
        "(whichever are relevant). Absence of evidence is informative.\n"
        "7. Containment/response recommendations must be proportional to "
        "assessed risk — a clean/benign case should not recommend password "
        "resets or device isolation; a confirmed credential harvest should\n"
        "8. Malicious IOCs (IPs, domains, URLs) must be defanged in the "
        "report text (e.g. evil[.]com, hxxps://). Hashes and file paths "
        "are never defanged. Flag any un-defanged malicious IOC.\n"
        "9. For phishing cases: the report must address the full kill chain "
        "up to the point evidence exists — delivery mechanism, landing page "
        "content, credential form presence, and whether credentials were "
        "submitted. Each step must be explicitly confirmed or marked unknown.\n"
        "10. For enrichment-heavy cases: the report must distinguish between "
        "IOCs that are actual investigation targets vs page resources "
        "(CDN domains, analytics, certificate infrastructure) that appeared "
        "during web capture. Treating CDN noise as threat indicators is an "
        "error.\n\n"
        "## Severity Levels\n"
        "- error: analytical standard violation that could mislead the reader "
        "(unsupported 'confirmed', causal claim without evidence link, "
        "missing kill chain step presented as known)\n"
        "- warning: style/quality issue that weakens the report but doesn't "
        "mislead (speculative language, missing NOT-observed section, "
        "disproportionate recommendations)\n\n"
        "Return JSON array of violations found:\n"
        '[{"severity": "error|warning", "rule": "<rule_name>", '
        '"location": "<section or paragraph reference>", '
        '"finding": "<what is wrong>", '
        '"suggestion": "<specific fix>"}]\n\n'
        "Return [] if no violations found. Return ONLY the JSON array. "
        "Use UK English."
    )

    matrix_summary = ""
    if matrix:
        matrix_summary = (
            f"\n\nInvestigation matrix summary:\n"
            f"- Known knowns: {len(matrix.get('known_knowns', []))}\n"
            f"- Known unknowns: {len(matrix.get('known_unknowns', []))}\n"
            f"- Hypotheses: {len(matrix.get('hypotheses', []))}\n"
        )
        # Include hypothesis statuses
        for h in matrix.get("hypotheses", []):
            matrix_summary += (
                f"  - {h.get('id')}: {h.get('claim', '')[:80]} "
                f"[{h.get('status', 'unresolved')}]\n"
            )

    user_prompt = f"Report to review:\n{report_text[:6000]}{matrix_summary}"

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
        model = get_model("quality_gate", severity)
        message = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = message.content[0].text.strip()
        tokens_in = message.usage.input_tokens
        tokens_out = message.usage.output_tokens
        print(f"[quality_gate] LLM review completed "
              f"({tokens_in}/{tokens_out} tokens, model={model})")

        # Parse
        if text.startswith("```"):
            lines = text.splitlines()
            lines = [ln for ln in lines if not ln.strip().startswith("```")]
            text = "\n".join(lines).strip()

        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        return []
    except Exception as exc:
        log_error("", "report_quality_gate._llm_review", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def review_report(case_id: str) -> dict | None:
    """Review the investigation report against matrix and analytical standards.

    Returns review dict on success, None if no report exists.
    Writes to cases/<case_id>/artefacts/analysis/report_review.json.
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

    meta = _safe_load(case_dir / "case_meta.json") or {}
    severity = meta.get("severity", "medium")

    # Run all checks
    flags: list[dict] = []

    # 1. Deterministic: confirmed claims
    flags.extend(_check_confirmed_claims(report_text, matrix))

    # 2. Deterministic: causal language
    flags.extend(_check_causal_language(report_text))

    # 3. Deterministic: speculative language
    flags.extend(_check_speculation(report_text))

    # 4. LLM review
    llm_flags = _llm_review(report_text, matrix, severity)
    for flag in llm_flags:
        flag["source"] = "llm"
    flags.extend(llm_flags)

    # 5. Matrix coverage
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

    # Write artefact
    analysis_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    save_json(analysis_dir / "report_review.json", result)

    status = "PASSED" if passed else f"FAILED ({error_count} error(s))"
    print(f"[quality_gate] {case_id}: {status}, "
          f"{len(flags)} flag(s) total, "
          f"coverage: {coverage['known_knowns_addressed']}/{coverage['known_knowns_total']} knowns")

    return result
