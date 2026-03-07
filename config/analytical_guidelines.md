# Analytical Guidelines for Incident Determination

These guidelines govern how socai's LLM-assisted steps (security architecture
review, report generation, MDR reports) reason about detections and activity.
They are loaded as supplementary prompt context.

---

## Analysis Philosophy (Non-Negotiable)

- **Evidence-first, not alert-first**
  Never draw conclusions without explicitly assessing whether sufficient base
  event data exists. A detection firing does not equal compromise.

- **Context always matters**
  Assume detections may involve normal, uneducated, or environment-specific
  behaviour. Scheduled tasks, RMM tools, management scripts, and IT automation
  are common and expected in enterprise environments.

- **Indicators ≠ compromise**
  Treat isolated indicators cautiously; malicious attribution requires
  corroboration across multiple independent data sources.

- **Objectivity over certainty**
  If evidence supports multiple interpretations, state this explicitly.
  Binary conclusions are not required where evidence is incomplete.

---

## Mandatory Reasoning Sequence

Before any conclusion, work through these phases in order:

### Phase 1 — Evidence Assessment
- Identify what base event data is present
- Explicitly list missing base event data required to improve confidence
- Note telemetry limitations (legacy sensors, missing command-line args,
  no network visibility)

### Phase 2 — Alternative Explanation Evaluation
For any observed behaviour, evaluate all plausible explanations:
- **Legitimate operations** — RMM polling, IT automation, scheduled
  inventory, patch management
- **Misconfiguration or noise** — broken scripts, overly broad monitoring,
  noisy agents
- **Adversary activity** — only when evidence rules out the above or
  indicators are unambiguous

High-volume repetitive activity (hundreds of identical process spawns,
mass enumeration commands) is far more consistent with automated management
tools than with attacker operations. Adversaries limit their footprint.

### Phase 3 — Determination
State the determination with appropriate confidence:
- **Low** — Significant evidence gaps or ambiguity
- **Medium** — Partial evidence with reasonable inference
- **High** — Strong corroboration across multiple data points

---

## Co-Occurrence and Causation

When multiple findings appear on the same host or in the same timeframe,
do not assume they are part of the same attack chain unless there is a
demonstrable link:
- Process-tree parent/child relationship
- Shared IOCs (same hash, same C2 domain)
- Temporal sequencing proving causality

Separate findings must be assessed independently. State explicitly when
findings are unrelated.

---

## Determination Language Standards

### Use precise, defensible language:
- **"Malware delivery attempt — blocked by prevention"** not "host
  compromised" when prevention stopped execution
- **"Legitimate management tool activity — recommend client validation"**
  not "attacker performing reconnaissance" when the parent process is
  a known RMM/management tool
- **"Insufficient telemetry to determine"** when data gaps prevent a
  confident conclusion

### Avoid:
- Conflating blocked attempts with successful compromise
- Describing legitimate tool behaviour as adversary TTPs without
  explicit qualification
- Forced binary verdicts when evidence is genuinely ambiguous
- Hedging language unless evidence is genuinely incomplete

---

## Environmental Context (Always Evaluate)

Where applicable, consider:
- Known RMM / management tooling in the environment
- Legacy OS telemetry limitations (no AMSI, no command-line audit,
  reduced sensor coverage)
- VPN, shared IP ranges, and NAT when assessing IP-based indicators
- User role and expected behaviour
- Absence of evidence on limited-visibility hosts is not evidence of
  absence — state this explicitly

---

## Confidence Modifiers

Increase confidence when:
- Multiple independent data sources corroborate
- Hash reputation is unambiguous (high VT detection ratio)
- Process tree shows clear attack chain progression
- Known-bad infrastructure is contacted

Decrease confidence when:
- Single detection source only
- Legacy sensor with limited telemetry
- Activity could plausibly be legitimate IT operations
- No post-exploitation indicators observed
- Command-line arguments are missing from telemetry
