"""
Pydantic models for structured LLM outputs.

Used by ``tools/structured_llm.py`` to enforce JSON-schema structured outputs
via the Anthropic ``output_config`` parameter, replacing fragile ``json.loads()``
and tool-use workarounds.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# detect_phishing_page  — brand impersonation vision check
# ---------------------------------------------------------------------------

class BrandImpersonationResult(BaseModel):
    brand_impersonation: bool
    impersonated_brand: str | None = None
    login_form: bool = False
    confidence: str = Field(default="medium", pattern="^(high|medium|low)$")
    reasoning: str = ""


class PagePurposeAssessment(BaseModel):
    """LLM assessment of what a captured web page does and whether it has a
    clear, legitimate purpose."""
    has_clear_purpose: bool = Field(
        description="True if the page serves an obvious, legitimate function "
        "(e-commerce product, news article, documentation, corporate info, "
        "SaaS dashboard, etc.). False if the page's purpose is unclear, "
        "absent, or appears designed to deceive.",
    )
    stated_purpose: str = Field(
        description="One-sentence description of what the page claims to do or show.",
    )
    suspicious_elements: list[str] = Field(
        default_factory=list,
        description="List of suspicious elements observed: urgency language, "
        "fake countdowns, 'verify your account' bait, document-preview lures, "
        "CAPTCHA gates with no content behind them, mismatch between domain and "
        "content, etc.",
    )
    deceptive_intent: bool = Field(
        default=False,
        description="True if the page appears designed to trick the user into "
        "entering credentials, downloading malware, or calling a fake support "
        "number. False if benign or genuinely unclear.",
    )
    confidence: str = Field(default="medium", pattern="^(high|medium|low)$")
    reasoning: str = Field(
        default="",
        description="Brief explanation of the assessment.",
    )


# ---------------------------------------------------------------------------
# executive_summary
# ---------------------------------------------------------------------------

class ExecutiveSummary(BaseModel):
    what_happened: str = Field(description="2-3 sentences in plain English describing what occurred.")
    who_affected: str = Field(description="Systems, users, or data affected.")
    risk_rating: str = Field(description="RAG risk rating.", pattern="^(RED|AMBER|GREEN)$")
    risk_justification: str = Field(description="One sentence justifying the risk rating.")
    what_done: str = Field(description="Investigation steps that have been taken.")
    next_steps: list[str] = Field(
        description="Up to 5 recommended actions. Each starts with an action verb and includes owner role + timeframe.",
    )
    business_risk: str = Field(description="One sentence describing the risk if the issue is left unaddressed.")


# ---------------------------------------------------------------------------
# timeline_reconstruct
# ---------------------------------------------------------------------------

class AttackPhase(BaseModel):
    phase: str = Field(description="MITRE ATT&CK tactic name")
    timespan: str = Field(description="Time range for this phase (ISO 8601 start - end)")
    events: list[int] = Field(description="Indices into the raw event list")


class DwellTimeGap(BaseModel):
    start: str = Field(description="ISO 8601 timestamp")
    end: str = Field(description="ISO 8601 timestamp")
    duration: str = Field(description="Human-readable duration")
    significance: str = Field(description="Why this gap matters")


class KeyEvent(BaseModel):
    index: int = Field(description="Index in the raw event list")
    reason: str = Field(description="Why this event is significant")


class TimelineAnalysis(BaseModel):
    attack_phases: list[AttackPhase] = Field(description="Events grouped by MITRE ATT&CK tactic")
    dwell_time_gaps: list[DwellTimeGap] = Field(description="Significant gaps between activity clusters")
    key_events: list[KeyEvent] = Field(description="5-10 most forensically important events")
    narrative: str = Field(description="2-3 sentence summary of the attack timeline")


# ---------------------------------------------------------------------------
# cve_contextualise
# ---------------------------------------------------------------------------

class ExploitedAssessmentItem(BaseModel):
    cve_id: str
    likely_exploited: bool
    confidence: str = Field(pattern="^(high|medium|low)$")
    reasoning: str


class PatchingPriorityItem(BaseModel):
    cve_id: str
    priority: str = Field(pattern="^(critical|high|medium|low)$")
    reasoning: str


class DetectionOpportunity(BaseModel):
    cve_id: str
    detection_method: str
    data_source: str


class CveAssessment(BaseModel):
    exploited_assessment: list[ExploitedAssessmentItem] = Field(
        description="Per-CVE exploitation likelihood assessment",
    )
    relevance_to_ttps: str = Field(
        description="How the CVEs relate to observed attack techniques in this case",
    )
    patching_priority: list[PatchingPriorityItem] = Field(
        description="Per-CVE patching priority recommendation",
    )
    detection_opportunities: list[DetectionOpportunity] = Field(
        description="Detection methods for each CVE",
    )


# ---------------------------------------------------------------------------
# pe_analysis
# ---------------------------------------------------------------------------

class PeAssessment(BaseModel):
    malicious_likelihood: int = Field(description="Likelihood the file is malicious, 0-100.")
    likely_category: str = Field(
        description="Most likely malware category.",
        pattern="^(dropper|RAT|ransomware|loader|backdoor|infostealer|wiper|legitimate|unknown)$",
    )
    indicators: list[str] = Field(description="List of concerning findings from the analysis.")
    recommended_next_steps: list[str] = Field(description="Recommended next investigation steps.")


# ---------------------------------------------------------------------------
# evtx_correlate
# ---------------------------------------------------------------------------

class MitreMapping(BaseModel):
    tactic: str
    technique: str
    technique_id: str
    evidence: str


class AttackerSkill(BaseModel):
    level: str = Field(pattern="^(low|medium|high|advanced)$")
    justification: str


class DetectionRule(BaseModel):
    title: str
    logic: str
    data_source: str


class EvtxAnalysis(BaseModel):
    narrative: str = Field(description="Chronological attack story reconstructed from the chains.")
    mitre_mapping: list[MitreMapping] = Field(
        description="MITRE ATT&CK mapping for each observed chain.",
    )
    attacker_skill: AttackerSkill
    detection_rules: list[DetectionRule] = Field(description="Recommended detection rules.")
