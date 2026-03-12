"""
tool: investigation_matrix
--------------------------
Generates an investigation reasoning matrix (Rumsfeld method) from case
artefacts. Produces a structured JSON artefact with:

  - known_knowns:    Facts proved by collected data (with evidence citations)
  - known_unknowns:  Specific evidence gaps and what data would close them
  - hypotheses:      Testable claims with supporting/disconfirming checks

The matrix is an analyst aid and audit artefact — it does not drive pipeline
decisions. Every LLM call is resilient (returns None on failure, never crashes
the pipeline).

Output: cases/<ID>/artefacts/analysis/investigation_matrix.json

Usage:
    from tools.investigation_matrix import generate_matrix, load_matrix
    matrix = generate_matrix("IV_CASE_001")
    matrix = load_matrix("IV_CASE_001")        # read existing
    matrix = update_matrix("IV_CASE_001", "enrich", {"id": "kk_005", ...})
"""
from __future__ import annotations

import json
import sys
import traceback as _tb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import get_model, load_json, log_error, save_json, utcnow


# ---------------------------------------------------------------------------
# Schema version — bump when the matrix structure changes
# ---------------------------------------------------------------------------
MATRIX_VERSION = 1

# Categories for known_knowns / known_unknowns
EVIDENCE_CATEGORIES = (
    "delivery", "infrastructure", "payload", "user_action",
    "credential_access", "persistence", "lateral_movement",
    "exfiltration", "command_and_control", "impact",
)

# Confidence levels (aligned with analytical standards)
CONFIDENCE_LEVELS = ("confirmed", "assessed_high", "assessed_medium", "assessed_low")


# ---------------------------------------------------------------------------
# Artefact loading helpers
# ---------------------------------------------------------------------------

def _safe_load(path: Path) -> dict | None:
    """Load JSON, returning None on missing file or parse error."""
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "investigation_matrix._safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _collect_case_context(case_id: str) -> dict:
    """Gather all available case artefacts for matrix generation."""
    case_dir = CASES_DIR / case_id

    ctx: dict = {}
    ctx["meta"] = _safe_load(case_dir / "case_meta.json") or {}
    ctx["iocs"] = _safe_load(case_dir / "iocs" / "iocs.json") or {}
    ctx["enrichment"] = _safe_load(
        case_dir / "artefacts" / "enrichment" / "enrichment.json"
    ) or {}
    ctx["verdicts"] = _safe_load(
        case_dir / "artefacts" / "enrichment" / "verdict_summary.json"
    ) or {}
    ctx["anomalies"] = _safe_load(
        case_dir / "artefacts" / "anomalies" / "anomaly_report.json"
    ) or {}
    ctx["correlation"] = _safe_load(
        case_dir / "artefacts" / "correlation" / "correlation.json"
    ) or {}
    ctx["response_actions"] = _safe_load(
        case_dir / "artefacts" / "response" / "response_actions.json"
    ) or {}

    # Email analysis (if present)
    ctx["email"] = _safe_load(
        case_dir / "artefacts" / "email" / "email_analysis.json"
    ) or {}

    # Web captures — load capture manifests for key context
    web_dir = case_dir / "artefacts" / "web"
    ctx["web_captures"] = []
    if web_dir.is_dir():
        for sub in sorted(web_dir.iterdir()):
            manifest_path = sub / "capture_manifest.json" if sub.is_dir() else None
            if manifest_path and manifest_path.exists():
                manifest = _safe_load(manifest_path)
                if manifest:
                    ctx["web_captures"].append({
                        "domain": sub.name,
                        "url": manifest.get("url"),
                        "final_url": manifest.get("final_url"),
                        "title": manifest.get("title"),
                        "status_code": manifest.get("status_code"),
                        "redirect_chain": manifest.get("redirect_chain", []),
                    })

    # Analyst notes
    notes_path = case_dir / "notes" / "analyst_input.md"
    if notes_path.exists():
        ctx["analyst_notes"] = notes_path.read_text(errors="ignore")[:2000]
    else:
        ctx["analyst_notes"] = ""

    return ctx


# ---------------------------------------------------------------------------
# LLM call (resilient — never raises)
# ---------------------------------------------------------------------------

def _call_llm(
    task: str,
    severity: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 2048,
) -> str | None:
    """Call Anthropic Messages API with graceful degradation."""
    if not ANTHROPIC_KEY:
        return None

    try:
        import anthropic
    except ImportError:
        log_error("", f"investigation_matrix.{task}",
                  "anthropic package not installed", severity="info")
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
        print(f"[matrix] {task} completed ({tokens_in}/{tokens_out} tokens, model={model})")
        return text
    except Exception as exc:
        log_error("", f"investigation_matrix.{task}", str(exc),
                  severity="warning", traceback=_tb.format_exc())
        return None


def _parse_json_response(raw: str) -> dict | None:
    """Extract JSON from an LLM response, handling code fences."""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object in the response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                return None
    return None


# ---------------------------------------------------------------------------
# Attack-type → query recommendations (duplicated from mcp_server/tools.py)
# ---------------------------------------------------------------------------

_PLAYBOOK_MAP = {
    "phishing": "phishing",
    "malware": "malware-execution",
    "account_compromise": "account-compromise",
    "privilege_escalation": "privilege-escalation",
    "data_exfiltration": "data-exfiltration",
    "lateral_movement": "lateral-movement",
}

_COMPOSITE_MAP = {
    "phishing": ["email-threat-zap", "inbox-rule-bec"],
    "account_compromise": ["suspicious-signin", "mailbox-permission-change", "inbox-rule-bec"],
    "privilege_escalation": ["suspicious-signin", "oauth-consent-grant"],
    "data_exfiltration": ["dlp-exfiltration"],
    "lateral_movement": ["suspicious-signin"],
}


def _build_query_context(attack_type: str) -> str:
    """Build a prompt-ready text block describing available Sentinel queries and tables.

    Calls existing read-only APIs:
      - tools.sentinel_queries.list_scenarios()
      - tools.kql_playbooks.list_playbooks()
      - config.sentinel_schema.get_ip_tables(), get_domain_tables(), etc.

    Highlights which scenarios/playbooks are recommended for the current attack type.
    Returns empty string on any failure (resilient — never crashes).
    """
    parts: list[str] = ["\n\n## Available Sentinel Queries & Schema"]

    # -- Composite scenarios --------------------------------------------------
    try:
        from tools.sentinel_queries import list_scenarios
        scenarios = list_scenarios()
        if scenarios:
            recommended = set(_COMPOSITE_MAP.get(attack_type, []))
            parts.append("\n### Composite Sentinel Queries (single-execution full-picture)")
            parts.append("Use generate_sentinel_query(scenario=<id>, upn=...) to run these.")
            for s in scenarios:
                marker = " **[RECOMMENDED for this attack type]**" if s["id"] in recommended else ""
                params = ", ".join(s.get("parameters", []))
                tables = ", ".join(s.get("tables", []))
                parts.append(
                    f"- **{s['id']}**: {s.get('description', s.get('name', ''))}{marker}\n"
                    f"  Parameters: {params or 'none'} | Tables: {tables or 'N/A'}"
                )
    except Exception:
        pass  # Resilient — skip if unavailable

    # -- Multi-stage KQL playbooks --------------------------------------------
    try:
        from tools.kql_playbooks import list_playbooks
        playbooks = list_playbooks()
        if playbooks:
            recommended_pb = _PLAYBOOK_MAP.get(attack_type)
            parts.append("\n### Multi-Stage KQL Playbooks")
            parts.append("Use load_kql_playbook(<id>) then run_kql for each stage.")
            for pb in playbooks:
                marker = " **[RECOMMENDED for this attack type]**" if pb["id"] == recommended_pb else ""
                stages = ", ".join(pb.get("stages", []))
                params = ", ".join(pb.get("parameters", []))
                parts.append(
                    f"- **{pb['id']}**: {pb.get('description', pb.get('name', ''))}{marker}\n"
                    f"  Stages: {stages or 'N/A'} | Parameters: {params or 'none'}"
                )
    except Exception:
        pass

    # -- IOC-type table recommendations ---------------------------------------
    try:
        from config.sentinel_schema import (
            get_domain_tables, get_email_tables, get_hash_tables, get_ip_tables,
            get_url_tables, has_registry,
        )
        if has_registry():
            parts.append("\n### Sentinel Tables by IOC Type")
            parts.append("When suggesting sentinel_query, reference these specific tables:")
            for label, tables in [
                ("IP", get_ip_tables()),
                ("Domain", get_domain_tables()),
                ("URL", get_url_tables()),
                ("Email/UPN", get_email_tables()),
                ("SHA256", get_hash_tables("sha256")),
            ]:
                if tables:
                    table_names = [t[0] for t in tables[:8]]
                    extra = f" (+{len(tables) - 8} more)" if len(tables) > 8 else ""
                    parts.append(f"- **{label}**: {', '.join(table_names)}{extra}")
    except Exception:
        pass

    # Only return content if we actually added something beyond the header
    if len(parts) <= 1:
        return ""
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# System prompt — embeds analytical standards as constraints
# ---------------------------------------------------------------------------

_MATRIX_SYSTEM_PROMPT = """\
You are a senior SOC analyst building an investigation reasoning matrix.

Given case artefacts, produce a structured JSON matrix with three sections:

1. **known_knowns** — Facts proved by data. Each MUST cite a specific \
artefact, field, or value as evidence.
2. **known_unknowns** — Specific evidence gaps in THIS case (not generic \
MITRE possibilities). Each must state what data would close the gap and \
name the tool that could provide it.
3. **hypotheses** — Testable claims about the incident. Each MUST list at \
least one disconfirming check with a specific tool or data source.

## Analytical Standards (MANDATORY)
- "confirmed" = data proves it. Only use for known_knowns with direct evidence.
- "assessed_high/medium/low" = inference. Use for hypotheses.
- Never fill evidence gaps with speculation — state them as known_unknowns.
- Temporal proximity is NEVER sufficient for causal claims.
- Every hypothesis must have at least one disconfirming_check.

## Evidence Evaluation by Attack Type

### Phishing
- **Web captures are the primary evidence source.** Page titles (e.g. \
"Secure Document Shared", "Verify Your Account"), redirect chains (301 to \
/login or /verify paths), and credential harvest forms (password input + \
external form action posting to a different domain) are the strongest \
phishing signals — stronger than enrichment API verdicts for URL-based cases.
- Brand impersonation: page title or body matching a known brand (Microsoft, \
Google, PayPal, DocuSign, etc.) on a non-brand domain = high-confidence \
phishing indicator.
- Redirect hops through unrelated domains, URL shorteners (bit.ly, tinyurl), \
or meta-refresh redirects are evasion indicators.
- Domain age < 30 days combined with brand impersonation is near-certain \
phishing infrastructure.
- Kill chain to evaluate: delivery (email/link) → landing page → credential \
harvest form → exfiltration (form POST to attacker endpoint). Each link \
requires independent evidence.

### Malware
- PE analysis, sandbox detonation, and YARA matches are the primary evidence.
- Focus on: binary capabilities (imports, sections, entropy), behavioural \
indicators (process creation, file drops, registry modifications, network \
callbacks), and static signatures.
- Kill chain: delivery → execution → persistence → C2 → lateral movement → \
impact. Each phase is a separate evidence question.

### Account Compromise
- Sign-in logs, impossible travel, MFA fatigue patterns, and inbox rule \
creation are the primary evidence.
- Evaluate: authentication anomalies (new device/location/IP), token theft \
indicators, mailbox delegation or forwarding rule changes, consent grant \
abuse (OAuth).
- Kill chain: initial access (credential theft/spray) → session establishment \
→ persistence (inbox rules, app consent) → abuse (BEC, data access).

## Enrichment Provider Reliability
- **OTX (AlienVault) pulses are noisy.** A domain appearing in 1–2 OTX \
pulses often means it was observed in a sandbox PCAP alongside actual \
malware (co-occurrence), NOT that the domain itself is malicious. CDN \
domains (Cloudflare, Weglot, WhoisXML, analytics providers) routinely \
appear in OTX pulses because sandboxed malware contacts legitimate \
services. Treat low-pulse-count OTX hits on infrastructure domains as \
noise unless corroborated by another provider.
- **Infrastructure IPs** (Microsoft, AWS, Google, Cloudflare, Akamai, Fastly, \
Apple, Meta ASNs) are pre-screened as infra_clean — do not treat these as \
IOCs unless there is specific evidence of abuse (e.g. C2 hosted on Azure).
- **GreyNoise RIOT** tags known business services (CDNs, scanners, SaaS) — \
a RIOT=true IP is confirmed legitimate infrastructure.
- **Verdict distributions matter:** 83 clean / 3 flagged out of 86 IOCs is a \
very different signal from 3 flagged out of 5. Evaluate the ratio, not \
just the presence of flags.
- **Provider disagreement** = low confidence. When providers disagree, the \
composite verdict should be treated cautiously — this is often a sign of \
noise or context-dependent detection.

## Available Tools for suggested_tool / disconfirming checks
- enrich_iocs: IOC enrichment (VT, AbuseIPDB, Shodan, GreyNoise, OTX, etc.)
- web_capture / browser_session: page capture with redirect chains, forms, TLS
- detect_phishing_page: brand impersonation, credential form, structural heuristics
- sandbox_session: dynamic malware analysis (strace, tcpdump, filesystem)
- sentinel_query: KQL queries against Sentinel logs (sign-ins, mailbox, alerts)
- log_correlate: correlate IOCs against log sources
- email_analyse: EML header/body/attachment analysis
- pe_analysis / yara_scan: static binary analysis
- timeline: case event reconstruction

## Output Format (strict JSON)
{
  "known_knowns": [
    {
      "id": "kk_001",
      "category": "<one of: delivery, infrastructure, payload, user_action, \
credential_access, persistence, lateral_movement, exfiltration, \
command_and_control, impact>",
      "finding": "<what the data proves>",
      "evidence": "<specific data citation: artefact, field, value>",
      "confidence": "confirmed",
      "source_step": "<pipeline step that produced the evidence>"
    }
  ],
  "known_unknowns": [
    {
      "id": "ku_001",
      "category": "<same categories as above>",
      "question": "<specific question about THIS case>",
      "required_evidence": "<what data would answer this>",
      "suggested_tool": "<socai tool or data source>",
      "priority": "high|medium|low"
    }
  ],
  "hypotheses": [
    {
      "id": "h_001",
      "claim": "<testable assertion>",
      "supporting": ["<evidence point 1>", "<evidence point 2>"],
      "disconfirming_checks": [
        {
          "check": "<what to verify>",
          "tool": "<tool or data source>",
          "result": null
        }
      ],
      "status": "unresolved"
    }
  ]
}

Return ONLY the JSON object. No preamble, no markdown. Use UK English.
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_matrix(case_id: str) -> dict | None:
    """Build investigation matrix from case artefacts.

    Returns the matrix dict on success, None on failure.
    Writes to cases/<case_id>/artefacts/analysis/investigation_matrix.json.
    """
    ctx = _collect_case_context(case_id)
    severity = ctx["meta"].get("severity", "medium")
    attack_type = ctx["meta"].get("attack_type", "generic")

    # Build the user prompt from collected context
    parts: list[str] = [
        f"Case: {case_id}",
        f"Attack type: {attack_type} (confidence: {ctx['meta'].get('attack_type_confidence', 'unknown')})",
        f"Title: {ctx['meta'].get('title', 'N/A')}",
        f"Severity: {severity}",
    ]

    if ctx["analyst_notes"]:
        parts.append(f"\n## Analyst Notes\n{ctx['analyst_notes']}")

    # IOCs summary
    iocs = ctx["iocs"].get("iocs", {})
    if iocs:
        ioc_summary = []
        for ioc_type, values in iocs.items():
            if values:
                ioc_summary.append(f"  {ioc_type}: {len(values)} ({', '.join(str(v) for v in values[:5])}{'...' if len(values) > 5 else ''})")
        if ioc_summary:
            parts.append(f"\n## IOCs Extracted\n" + "\n".join(ioc_summary))

    # Enrichment verdicts
    verdicts = ctx["verdicts"]
    if verdicts:
        v_parts = []
        for category in ("high_priority", "needs_review", "clean", "unknown"):
            items = verdicts.get(category, [])
            if items:
                v_parts.append(f"  {category}: {len(items)}")
                for item in items[:3]:
                    if isinstance(item, dict):
                        v_parts.append(f"    - {item.get('ioc', 'N/A')}: {item.get('verdict', 'N/A')} "
                                       f"(providers: {item.get('providers_checked', 'N/A')})")
        if v_parts:
            parts.append(f"\n## Enrichment Verdicts\n" + "\n".join(v_parts))

    # Enrichment details (truncated)
    enrich_results = ctx["enrichment"].get("results", [])
    if enrich_results:
        # Include up to 20 most relevant results
        significant = [r for r in enrich_results
                       if r.get("verdict") in ("malicious", "suspicious")
                       or r.get("total_reports", 0) > 0
                       or r.get("malware")]
        if not significant:
            significant = enrich_results[:10]
        parts.append(f"\n## Key Enrichment Results ({len(significant)} of {len(enrich_results)} total)\n"
                     + json.dumps(significant[:20], indent=2, default=str)[:3000])

    # Email analysis
    if ctx["email"]:
        parts.append(f"\n## Email Analysis\n{json.dumps(ctx['email'], indent=2, default=str)[:1500]}")

    # Web captures
    if ctx["web_captures"]:
        wc_parts = []
        for wc in ctx["web_captures"][:20]:
            line = f"  - {wc.get('domain', 'N/A')}: {wc.get('title', 'N/A')}"
            if wc.get("final_url") and wc["final_url"] != wc.get("url"):
                line += f" (redirected → {wc['final_url']})"
            if wc.get("redirect_chain") and len(wc["redirect_chain"]) > 1:
                line += f" [{len(wc['redirect_chain'])} hops]"
            wc_parts.append(line)
        parts.append(f"\n## Web Captures ({len(ctx['web_captures'])} domains)\n" + "\n".join(wc_parts))

    # Anomalies
    if ctx["anomalies"]:
        parts.append(f"\n## Anomalies\n{json.dumps(ctx['anomalies'], indent=2, default=str)[:1000]}")

    # Correlations
    if ctx["correlation"]:
        parts.append(f"\n## Correlations\n{json.dumps(ctx['correlation'], indent=2, default=str)[:1000]}")

    user_prompt = "\n".join(parts)

    # Append query context so the LLM knows available Sentinel queries & tables
    query_context = _build_query_context(attack_type)
    system_prompt = _MATRIX_SYSTEM_PROMPT + query_context

    # Call LLM
    raw = _call_llm(
        task="matrix",
        severity=severity,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        max_tokens=3000,
    )

    if not raw:
        print(f"[matrix] LLM call failed or no API key — skipping matrix generation")
        return None

    # Parse the response
    parsed = _parse_json_response(raw)
    if not parsed:
        snippet = raw[:300].replace("\n", " ")
        log_error(case_id, "investigation_matrix.generate_matrix",
                  "Failed to parse LLM response as JSON",
                  severity="warning", context={
                      "raw_length": len(raw),
                      "snippet": snippet,
                  })
        print(f"[matrix] Parse failure — first 300 chars: {snippet}")
        return None

    # Validate and normalise
    matrix = _build_matrix(case_id, attack_type, parsed)

    # Write artefact
    analysis_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    save_json(analysis_dir / "investigation_matrix.json", matrix)

    # Summary
    kk = len(matrix.get("known_knowns", []))
    ku = len(matrix.get("known_unknowns", []))
    hyp = len(matrix.get("hypotheses", []))
    print(f"[matrix] Generated for {case_id}: "
          f"{kk} known, {ku} unknown, {hyp} hypotheses")

    return matrix


def _build_matrix(case_id: str, attack_type: str, parsed: dict) -> dict:
    """Normalise and wrap the LLM output into a versioned matrix artefact."""
    now = utcnow()

    # Ensure all IDs are present
    for i, kk in enumerate(parsed.get("known_knowns", []), 1):
        kk.setdefault("id", f"kk_{i:03d}")
        kk.setdefault("confidence", "confirmed")
    for i, ku in enumerate(parsed.get("known_unknowns", []), 1):
        ku.setdefault("id", f"ku_{i:03d}")
        ku.setdefault("priority", "medium")
        ku.setdefault("resolution", None)
    for i, hyp in enumerate(parsed.get("hypotheses", []), 1):
        hyp.setdefault("id", f"h_{i:03d}")
        hyp.setdefault("status", "unresolved")
        hyp.setdefault("disconfirming_checks", [])

    return {
        "version": MATRIX_VERSION,
        "case_id": case_id,
        "attack_type": attack_type,
        "created_at": now,
        "updated_at": now,
        "known_knowns": parsed.get("known_knowns", []),
        "known_unknowns": parsed.get("known_unknowns", []),
        "hypotheses": parsed.get("hypotheses", []),
        "history": [
            {"ts": now, "step": "generate_matrix", "delta": "Initial matrix from case artefacts"},
        ],
    }


def load_matrix(case_id: str) -> dict | None:
    """Load an existing investigation matrix from case artefacts."""
    path = CASES_DIR / case_id / "artefacts" / "analysis" / "investigation_matrix.json"
    return _safe_load(path)


def update_matrix(case_id: str, step: str, findings: dict) -> dict | None:
    """Merge new findings into an existing matrix.

    Parameters
    ----------
    case_id : str
        The case to update.
    step : str
        Pipeline step that produced the findings (for history).
    findings : dict
        May contain any of: ``new_known_knowns``, ``new_known_unknowns``,
        ``new_hypotheses``, ``resolve_unknowns`` (list of ku IDs),
        ``update_hypotheses`` (list of {id, status, check_results}).

    Returns the updated matrix, or None if no matrix exists.
    """
    matrix = load_matrix(case_id)
    if not matrix:
        return None

    now = utcnow()
    changes: list[str] = []

    # Add new known_knowns
    for kk in findings.get("new_known_knowns", []):
        existing_ids = {k["id"] for k in matrix["known_knowns"]}
        if kk.get("id") not in existing_ids:
            matrix["known_knowns"].append(kk)
            changes.append(f"added {kk.get('id', 'kk')}")

    # Add new known_unknowns
    for ku in findings.get("new_known_unknowns", []):
        existing_ids = {k["id"] for k in matrix["known_unknowns"]}
        if ku.get("id") not in existing_ids:
            matrix["known_unknowns"].append(ku)
            changes.append(f"added {ku.get('id', 'ku')}")

    # Add new hypotheses
    for hyp in findings.get("new_hypotheses", []):
        existing_ids = {h["id"] for h in matrix["hypotheses"]}
        if hyp.get("id") not in existing_ids:
            matrix["hypotheses"].append(hyp)
            changes.append(f"added {hyp.get('id', 'h')}")

    # Resolve known_unknowns
    for ku_id in findings.get("resolve_unknowns", []):
        for ku in matrix["known_unknowns"]:
            if ku["id"] == ku_id and ku.get("resolution") is None:
                ku["resolution"] = {
                    "resolved_by": step,
                    "resolved_at": now,
                }
                changes.append(f"resolved {ku_id}")

    # Update hypothesis statuses
    for update in findings.get("update_hypotheses", []):
        for hyp in matrix["hypotheses"]:
            if hyp["id"] == update.get("id"):
                if "status" in update:
                    hyp["status"] = update["status"]
                for check_update in update.get("check_results", []):
                    for check in hyp.get("disconfirming_checks", []):
                        if check["check"] == check_update.get("check"):
                            check["result"] = check_update.get("result")
                changes.append(f"updated {hyp['id']}")

    if changes:
        matrix["updated_at"] = now
        matrix["history"].append({
            "ts": now,
            "step": step,
            "delta": "; ".join(changes),
        })

        # Persist
        analysis_dir = CASES_DIR / case_id / "artefacts" / "analysis"
        analysis_dir.mkdir(parents=True, exist_ok=True)
        save_json(analysis_dir / "investigation_matrix.json", matrix)

    return matrix


def get_matrix_summary(case_id: str) -> dict | None:
    """Return a compact summary of the matrix state for display."""
    matrix = load_matrix(case_id)
    if not matrix:
        return None

    kk_count = len(matrix.get("known_knowns", []))
    ku_total = len(matrix.get("known_unknowns", []))
    ku_resolved = sum(1 for ku in matrix.get("known_unknowns", [])
                      if ku.get("resolution") is not None)
    hyp_total = len(matrix.get("hypotheses", []))
    hyp_resolved = sum(1 for h in matrix.get("hypotheses", [])
                       if h.get("status") != "unresolved")

    return {
        "case_id": case_id,
        "version": matrix.get("version"),
        "attack_type": matrix.get("attack_type"),
        "known_knowns": kk_count,
        "known_unknowns": f"{ku_resolved}/{ku_total} resolved",
        "hypotheses": f"{hyp_resolved}/{hyp_total} resolved",
        "last_updated": matrix.get("updated_at"),
        "history_entries": len(matrix.get("history", [])),
    }
