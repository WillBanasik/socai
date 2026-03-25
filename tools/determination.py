"""
tool: determination
-------------------
Determination is now done by the local Claude Desktop agent using the
``run_determination`` MCP prompt. This module retains
``_DETERMINATION_SYSTEM_PROMPT``, ``compare_dispositions()``, and
normalisation helpers.

Output: cases/<ID>/artefacts/analysis/determination.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.common import load_json, log_error


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_load(path: Path) -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "determination._safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None



# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_DETERMINATION_SYSTEM_PROMPT = """\
You are a senior SOC analyst performing evidence-chain disposition analysis. \
Given the investigation artefacts, produce a structured disposition proposal.

## Analytical Standards (MANDATORY)
- "confirmed" = data directly proves this link. Cite the specific evidence.
- "assessed" = inference supported by evidence but not conclusively proven.
- "unknown" = no data available for this link.
- Temporal proximity is NEVER sufficient for causal claims.
- Every chain link must be independently verified. If any link is missing, \
  the chain is incomplete — say so explicitly.
- Actively seek disconfirming evidence. State what you checked that could \
  have disproved your conclusion.

## Evidence Weighting Rules

### Web captures vs enrichment API verdicts
Web capture evidence (page titles, redirect chains, credential harvest forms, \
brand impersonation) is often STRONGER than enrichment API verdicts for \
URL/domain-based cases. A page titled "Secure Document Shared" that redirects \
to a credential form on a non-brand domain is a high-confidence phishing \
indicator regardless of what VT or AbuseIPDB returns for the domain. \
**Never dismiss web capture findings because enrichment APIs returned clean.**

### Enrichment noise patterns — do NOT treat these as evidence of benign
- **OTX pulse co-occurrence:** Domains appearing in 1–2 OTX pulses are often \
CDN/analytics/infrastructure domains observed in sandbox PCAPs alongside \
actual malware. A Cloudflare, Weglot, WhoisXML, or Google Analytics domain \
flagged by OTX is almost certainly co-occurrence noise, not a threat. \
However, the ACTUAL target domains in the case may have zero OTX pulses \
because they are newly registered phishing infrastructure — absence from \
OTX is not evidence of legitimacy.
- **Infrastructure IPs:** IPs on Microsoft, AWS, Google, Cloudflare, Akamai, \
Fastly, Apple, or Meta ASNs are tagged infra_clean. These are legitimate \
infrastructure unless specific evidence shows abuse (C2 hosting, phishing \
kit hosting on cloud services).
- **GreyNoise RIOT:** RIOT=true means the IP belongs to a known business \
service. Treat as confirmed legitimate infrastructure.
- **Provider disagreement:** When enrichment providers disagree on an IOC, \
the composite confidence is LOW. Do not use low-confidence verdicts as \
the sole basis for disposition.

### Verdict distributions
Evaluate the RATIO of flagged vs clean IOCs, not just the count. 3 flagged \
out of 86 total (3.5%) where the flagged IOCs are CDN/analytics domains is \
a very different signal from 3 flagged out of 5 (60%). A case with mostly \
clean IOCs may still be true_positive if the 2-3 flagged IOCs are the \
actual attack infrastructure and the rest are legitimate page resources.

### Attack-type-specific evidence chains

**Phishing:** delivery (email/link) → landing page (web capture: title, \
redirect chain) → credential harvest (password form + external form action) → \
exfiltration (POST to attacker domain). Web capture page titles like "Secure \
Document Shared", "Verify Your Account", "DocuSign" on non-DocuSign domains \
are HIGH confidence indicators. Domain age < 30 days + brand impersonation = \
near-certain phishing.

**Malware:** delivery → execution (PE analysis, process creation) → \
persistence (registry, scheduled tasks, services) → C2 (network callbacks, \
DNS beaconing) → impact (encryption, exfiltration). Sandbox behavioural \
results and YARA matches carry high weight.

**Account compromise:** initial access (credential spray/theft, impossible \
travel) → session (new device/location sign-in) → persistence (inbox rules, \
OAuth consent, mailbox delegation) → abuse (BEC, data access). Sign-in log \
anomalies and inbox rule creation are the primary evidence.

## Disposition values
- true_positive: the alert correctly detected genuinely malicious activity. \
  An actual threat actor, malware, or unauthorised action was present, \
  regardless of whether it succeeded.
- benign_positive: the alert correctly fired on real activity that matches \
  the detection logic, but that activity is expected, authorised, or \
  non-threatening. The detection worked as designed — the activity genuinely \
  was unusual or matched a threat pattern — but investigation confirmed it \
  was legitimate. Common scenarios: new service account from unfamiliar \
  infrastructure, admin-authorised pen-testing, security tooling triggering \
  behavioural detections, legitimate bulk file operations, real user travel \
  triggering impossible-travel. Sub-classifications: "suspicious but expected" \
  (known/authorised operation) or "suspicious but not malicious" (genuinely \
  unusual but no threat confirmed).
- false_positive: the alert misfired — the detection logic was wrong. The \
  activity it flagged either didn't happen as described, or doesn't match \
  what the rule was designed to detect. The alert should not have fired at all. \
  Common scenarios: geo-IP database error, benign string matching a malware \
  signature, duplicate/stale alerts on remediated activity, detection logic bugs.
- benign: no malicious indicators found across all evidence sources and no \
  alert-specific context to classify as benign_positive or false_positive.
- pup_pua: potentially unwanted but not malicious (adware, toolbars, bundleware)
- inconclusive: conflicting evidence or critical gaps preventing determination. \
  **Prefer inconclusive over false_positive when evidence is incomplete.** \
  A case with unexamined web captures, missing log data, or unresolved \
  provider conflicts is inconclusive, not FP.

## Decision guide for TP / BP / FP
Did the detection logic fire correctly on real activity?
  NO  → false_positive
  YES → Was that activity malicious?
          YES → true_positive
          NO  → benign_positive
Never combine classifications — "True Positive Benign Positive" is invalid. \
If the alert was accurate but the activity was authorised, classify as \
benign_positive, NOT true_positive.

## Confidence
- high: strong evidence chain, most links confirmed, no contradictions, \
  all major evidence sources examined
- medium: partial chain, key links assessed, no strong contradictions
- low: significant gaps, links mostly assessed or unknown, or major \
  evidence sources not examined

## Output Format (strict JSON)
{
  "disposition": "<true_positive|benign_positive|false_positive|benign|pup_pua|inconclusive>",
  "confidence": "<high|medium|low>",
  "evidence_chain": [
    {
      "link": "<step in the attack/event chain>",
      "status": "<confirmed|assessed|unknown>",
      "evidence": "<specific data citation or null>",
      "gap": "<what is missing, if status is unknown>"
    }
  ],
  "gaps": ["<list of evidence gaps that affect the determination>"],
  "disconfirming_checks": [
    {
      "hypothesis": "<what was being checked>",
      "check": "<what was looked for>",
      "result": "<what was found or not found>"
    }
  ],
  "reasoning": "<1-3 sentence explanation of the determination>"
}

Return ONLY the JSON object. Use UK English.
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def llm_determine(case_id: str) -> dict | None:
    """Stub — direct LLM determination removed.

    Use the ``run_determination`` MCP prompt for evidence-chain analysis
    via the local Claude Desktop agent, then call ``add_finding``
    to record the result.
    """
    return {
        "status": "use_prompt",
        "prompt": "run_determination",
        "save_tool": "add_finding",
        "case_id": case_id,
    }


def compare_dispositions(
    deterministic: str | None,
    llm_result: dict,
) -> dict:
    """Compare deterministic and LLM dispositions, returning agreement status.

    Parameters
    ----------
    deterministic : str or None
        The deterministic disposition (e.g. "benign_auto_closed", None if not set).
    llm_result : dict
        The output from ``llm_determine()``.

    Returns
    -------
    dict with keys:
        agrees : bool
        deterministic_disposition : str
        llm_disposition : str
        llm_confidence : str
        recommendation : str
    """
    llm_disp = llm_result.get("disposition", "inconclusive")
    llm_conf = llm_result.get("confidence", "low")

    # Map deterministic labels to comparable values
    det_normalised = _normalise_disposition(deterministic)

    agrees = _dispositions_compatible(det_normalised, llm_disp)

    if agrees:
        recommendation = "proceed"
    elif llm_conf == "low":
        # Low-confidence LLM disagreement — log but don't block
        recommendation = "log_disagreement"
    else:
        # Medium/high-confidence disagreement — flag for analyst
        recommendation = "flag_for_review"

    return {
        "agrees": agrees,
        "deterministic_disposition": deterministic or "none",
        "llm_disposition": llm_disp,
        "llm_confidence": llm_conf,
        "recommendation": recommendation,
        "reasoning": llm_result.get("reasoning", ""),
    }


def _normalise_disposition(disposition: str | None) -> str:
    """Map pipeline disposition labels to comparable values."""
    if not disposition:
        return "none"
    mapping = {
        "benign_auto_closed": "benign",
        "false_positive": "false_positive",
        "true_positive": "true_positive",
        "benign_positive": "benign_positive",
        "pup_pua": "pup_pua",
    }
    return mapping.get(disposition, disposition)


def _dispositions_compatible(deterministic: str, llm: str) -> bool:
    """Check if two dispositions are compatible (not contradictory)."""
    if deterministic == "none":
        return True  # No deterministic disposition — no disagreement possible

    # Direct match
    if deterministic == llm:
        return True

    # Benign, benign_positive, and false_positive are all non-malicious
    non_malicious = {"benign", "benign_positive", "false_positive"}
    if deterministic in non_malicious and llm in non_malicious:
        return True

    # Inconclusive is compatible with anything (LLM says "not sure")
    if llm == "inconclusive":
        return True

    return False
