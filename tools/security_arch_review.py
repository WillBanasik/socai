"""
tool: security_arch_review
--------------------------
LLM-assisted security architecture review for a completed investigation.

Reads all available case artefacts (IOCs, enrichment verdicts, correlation,
report text, case metadata) and produces an actionable security control
recommendations document mapped to the Microsoft security stack and
CrowdStrike Falcon platform.

Enhancements (Claude API features):
  - Prompt caching    : system prompt sent with cache_control for cross-run savings
  - Adaptive thinking : enabled for high/critical severity cases (works alongside tools)
  - Structured tool   : record_structured_analysis tool extracts TTPs + top actions
  - Files API         : PDFs under artefacts/web/ uploaded and sent as document blocks
  - Parallel subagents: network + file IOC clusters analysed concurrently with main call

Output:
  cases/<case_id>/artefacts/security_architecture/security_arch_review.md
  cases/<case_id>/artefacts/security_architecture/security_arch_structured.json  (when tool fires)

Usage (standalone):
  python3 tools/security_arch_review.py --case IV_CASE_001
"""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR, IOC_INDEX_FILE
from tools.common import get_alias_map, get_model, load_json, log_error, save_json, utcnow, write_artefact, write_report

# ---------------------------------------------------------------------------
# Analytical guidelines — loaded from config/analytical_guidelines.md
# ---------------------------------------------------------------------------

_GUIDELINES_PATH = Path(__file__).resolve().parent.parent / "config" / "analytical_guidelines.md"
try:
    _ANALYTICAL_GUIDELINES = _GUIDELINES_PATH.read_text()
except FileNotFoundError:
    _ANALYTICAL_GUIDELINES = ""

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a Principal Security Architect with deep hands-on expertise across the \
Microsoft security stack and CrowdStrike Falcon platform. You advise enterprise \
SOC and security engineering teams on how to detect, prevent, and respond to \
threats using their existing tooling.

Your Microsoft expertise covers:
- Microsoft Entra ID: Conditional Access (policy design, named locations, \
  exclusion governance), Identity Protection (risk policies, sign-in/user risk), \
  Privileged Identity Management (PIM), Authentication Methods, Hybrid Identity
- Microsoft Sentinel: Analytics rules (Scheduled, NRT, Fusion, ML), UEBA, \
  Watchlists, Threat Intelligence ingestion, Playbooks (Logic Apps), Workbooks, \
  entity mapping, incident correlation
- Microsoft Defender XDR suite: Defender for Endpoint (MDE) prevention policies, \
  ASR rules, EDR detections, Live Response; Defender for Identity (MDI) lateral \
  movement/pass-the-hash/Kerberoasting detections; Defender for Office 365 (MDO) \
  Safe Links, Safe Attachments, anti-phishing; Defender for Cloud Apps (MDCA) \
  CASB policies, session controls, anomaly detections; Defender for Cloud \
  (CSPM/CWPP)
- Microsoft Purview: DLP policies, Insider Risk Management, Communication \
  Compliance, Sensitivity Labels, Audit (Standard and Premium)
- Azure networking controls: NSGs, Azure Firewall, Private Link, DDoS Protection

Your CrowdStrike Falcon expertise covers:
- Falcon Insight EDR: prevention policy tuning (ML-based, exploit mitigation, \
  suspicious process blocking), custom Indicator of Attack (IOA) rules, \
  custom Indicators of Compromise (IOC) hash/IP/domain blocking, Real Time \
  Response (RTR) for live investigation and remediation
- Falcon NGSIEM (LogScale): ingestion pipeline configuration, query language \
  (LSQL), dashboards, real-time alerts, scheduled searches, package deployment
- Falcon Identity Protection (formerly Falcon Zero Trust): identity-based \
  threat detection, MFA enforcement via Falcon, lateral movement detection
- Falcon Spotlight: vulnerability prioritisation, exposure management
- Falcon Fusion: workflow automation, SOAR playbooks
- Falcon Overwatch: managed threat hunting integration

When given a case investigation summary, you will produce a structured \
Security Architecture Review with the following sections:

1. **Threat Profile** — Map observed TTPs to MITRE ATT&CK. Be specific about \
   technique IDs (e.g. T1078.004 — Cloud Accounts). Include confidence in each \
   mapping based on evidence quality.

2. **Control Gap Analysis** — For each identified TTP, state whether a \
   preventive or detective control was present, absent, or misconfigured in \
   the environment. Reference specific policy names, rule names, or settings \
   where visible in the case data.

3. **Microsoft Stack Recommendations** — Prioritised, actionable recommendations \
   per product area. Be specific: name the exact Conditional Access policy change, \
   the Sentinel analytics rule to deploy (reference the OOTB rule name or \
   provide the KQL), the MDE ASR rule to enable, etc. Do not give generic advice.

4. **CrowdStrike Falcon Recommendations** — Prioritised, actionable \
   recommendations per Falcon module. Be specific: custom IOA rule logic, \
   LogScale query to create as a scheduled search, prevention policy toggle, etc.

5. **Prioritised Remediation Table** — A markdown table with columns: \
   Priority (Critical/High/Medium/Low), Action, Platform, Effort (Hours estimate), \
   Risk Reduced. Sorted by priority descending.

6. **Detection Engineering Notes** — Any new detection logic, sigma rules, \
   or query patterns that should be written as a result of this investigation.

Tone: Direct, technical, practitioner-level. No marketing language. \
Assume the reader is a senior SOC analyst or security engineer. \
Cite specific policy names, rule IDs, or configuration settings observed \
in the case data whenever possible — do not invent details not present in \
the evidence.

---

""" + _ANALYTICAL_GUIDELINES

# Cached system prompt block — sent once and reused across calls
_SYSTEM_CACHED = [
    {"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
]

# ---------------------------------------------------------------------------
# Structured output tool (used when thinking is disabled)
# ---------------------------------------------------------------------------

_STRUCTURED_TOOL = {
    "name": "record_structured_analysis",
    "description": (
        "Record the structured findings from the security architecture review. "
        "Call this tool once after completing the narrative review sections."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ttps": {
                "type": "array",
                "description": "List of MITRE ATT&CK TTPs identified",
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id":   {"type": "string", "description": "e.g. T1078.004"},
                        "technique_name": {"type": "string"},
                        "confidence":     {"type": "string", "enum": ["high", "medium", "low"]},
                        "evidence":       {"type": "string"},
                    },
                    "required": ["technique_id", "technique_name", "confidence"],
                },
            },
            "top_actions": {
                "type": "array",
                "description": "Top 5 prioritised remediation actions (one sentence each)",
                "items": {"type": "string"},
            },
            "risk_rating": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low"],
                "description": "Overall risk rating for this case",
            },
        },
        "required": ["ttps", "top_actions", "risk_rating"],
    },
}


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_context(case_id: str) -> str:
    """Assemble a structured context block from all available case artefacts."""
    case_dir = CASES_DIR / case_id
    parts: list[str] = [f"# Case: {case_id}\n"]

    # Case metadata
    meta = _safe_load(case_dir / "case_meta.json")
    if meta:
        parts.append("## Case Metadata")
        parts.append(f"- Title: {meta.get('title', 'N/A')}")
        parts.append(f"- Severity: {meta.get('severity', 'N/A')}")
        parts.append(f"- Status: {meta.get('status', 'N/A')}")
        parts.append(f"- Created: {meta.get('created_at', 'N/A')}")
        parts.append("")

    # Analyst notes (submitted via web UI or API)
    analyst_notes_path = case_dir / "notes" / "analyst_input.md"
    if analyst_notes_path.exists():
        notes_text = analyst_notes_path.read_text(errors="replace").strip()
        if notes_text:
            parts.append("## Analyst Notes")
            parts.append(notes_text)
            parts.append("")

    # IOC summary
    iocs_data = _safe_load(case_dir / "iocs" / "iocs.json")
    if iocs_data:
        ioc_dict = iocs_data.get("iocs", {})
        parts.append("## Extracted IOCs")
        for ioc_type, vals in ioc_dict.items():
            if vals:
                parts.append(f"### {ioc_type.upper()} ({len(vals)})")
                for v in vals[:50]:
                    parts.append(f"  - {v}")
        parts.append("")

    # Verdict summary
    verdict = _safe_load(
        case_dir / "artefacts" / "enrichment" / "verdict_summary.json"
    )
    if verdict:
        parts.append("## Enrichment Verdict Summary")
        parts.append(f"- Total IOCs scored: {verdict.get('ioc_count', 0)}")
        parts.append(f"- Malicious (high priority): {len(verdict.get('high_priority', []))}")
        parts.append(f"- Suspicious (needs review): {len(verdict.get('needs_review', []))}")
        parts.append(f"- Clean: {len(verdict.get('clean', []))}")
        ioc_details = verdict.get("iocs", {})
        if ioc_details:
            parts.append("\n### Per-IOC Verdict Detail")
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

    # Correlation results
    correlation = _safe_load(
        case_dir / "artefacts" / "correlation" / "correlation.json"
    )
    if correlation:
        parts.append("## Correlation Results")
        hit_summary = correlation.get("hit_summary", {})
        if hit_summary:
            parts.append(f"- Hit summary: {json.dumps(hit_summary)}")
        tl_events = correlation.get("timeline_events", 0)
        parts.append(f"- Timeline events: {tl_events}")
        hits = correlation.get("hits", {})
        for hit_type, hit_list in hits.items():
            if hit_list:
                parts.append(f"- {hit_type}: {hit_list[:10]}")
        parts.append("")

    # Investigation report (truncated to avoid token overflow)
    report_path = case_dir / "reports" / "investigation_report.md"
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8")
        if len(report_text) > 6000:
            report_text = report_text[:6000] + "\n\n[...report truncated for context...]"
        parts.append("## Investigation Report (summary)")
        parts.append(report_text)
        parts.append("")

    # IOC index — recurring IOCs from prior cases
    ioc_index = _safe_load(IOC_INDEX_FILE)
    if ioc_index and iocs_data:
        ioc_dict = iocs_data.get("iocs", {})
        recurring = []
        for ioc_val in [v for vals in ioc_dict.values() for v in vals]:
            entry = ioc_index.get(ioc_val)
            if entry:
                other = [c for c in entry.get("cases", []) if c != case_id]
                if other:
                    recurring.append(
                        f"  - `{ioc_val}` seen in prior cases: {', '.join(other[:5])}"
                    )
        if recurring:
            parts.append("## Recurring IOCs (seen in prior investigations)")
            parts.extend(recurring)
            parts.append("")

    return "\n".join(parts)


def _safe_load(path: Path) -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "security_arch_review.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


# ---------------------------------------------------------------------------
# Files API helper — upload PDFs from web artefacts
# ---------------------------------------------------------------------------

def _upload_case_pdfs(case_id: str, client) -> list[dict]:
    """
    Upload PDF files found under cases/<id>/artefacts/web/ via the Files API.
    Returns a list of document content blocks for inclusion in the user message.
    Silently skips any file that fails to upload.
    """
    web_dir = CASES_DIR / case_id / "artefacts" / "web"
    if not web_dir.exists():
        return []

    blocks: list[dict] = []
    for pdf_path in web_dir.rglob("document.pdf"):
        rel = pdf_path.relative_to(CASES_DIR / case_id)
        try:
            pdf_bytes = pdf_path.read_bytes()
            response  = client.beta.files.upload(
                file=(pdf_path.name, pdf_bytes, "application/pdf")
            )
            blocks.append({
                "type": "document",
                "source": {
                    "type":    "file",
                    "file_id": response.id,
                },
                "title": str(rel),
            })
            print(f"[security_arch_review] Files API: uploaded {rel} → {response.id}")
        except Exception as exc:
            log_error(case_id, "security_arch_review.files_api", str(exc),
                      severity="warning", context={"file": str(rel)})
            print(f"[security_arch_review] Files API: could not upload {rel}: {exc}")

    return blocks


# ---------------------------------------------------------------------------
# Parallel cluster subagent
# ---------------------------------------------------------------------------

def _parallel_cluster_analysis(case_id: str, client, ioc_dict: dict, severity: str = "medium") -> str:
    """
    Run two focused LLM calls concurrently:
      1. Network IOC cluster (IPv4 + domain)
      2. File IOC cluster (sha256 + md5 + sha1)
    Returns combined markdown or empty string on failure.
    """
    network_iocs = (
        [f"IP: {v}" for v in ioc_dict.get("ipv4", [])[:20]]
        + [f"Domain: {v}" for v in ioc_dict.get("domain", [])[:20]]
    )
    file_iocs = (
        [f"SHA256: {v}" for v in ioc_dict.get("sha256", [])[:10]]
        + [f"MD5: {v}" for v in ioc_dict.get("md5", [])[:10]]
        + [f"SHA1: {v}" for v in ioc_dict.get("sha1", [])[:10]]
    )

    cluster_system = [
        {
            "type": "text",
            "text": (
                "You are a concise threat intelligence analyst. "
                "Given a list of IOCs from a security investigation, briefly characterise "
                "the infrastructure cluster: likely threat actor category, hosting patterns, "
                "shared infrastructure indicators, and any notable findings. "
                "Be direct and technical. Maximum 300 words."
            ),
            "cache_control": {"type": "ephemeral"},
        }
    ]

    def _call(label: str, iocs: list[str]) -> str:
        if not iocs:
            return ""
        ioc_text = "\n".join(iocs)
        _alias_map = get_alias_map()
        if _alias_map:
            ioc_text = _alias_map.alias_text(ioc_text)
        try:
            msg = client.messages.create(
                model=get_model("secarch", severity),
                max_tokens=1024,
                system=cluster_system,
                messages=[{
                    "role": "user",
                    "content": f"Analyse this IOC cluster for case {case_id}:\n\n{ioc_text}",
                }],
            )
            result_text = msg.content[0].text.strip()
            if _alias_map:
                result_text = _alias_map.dealias_text(result_text)
            return result_text
        except Exception as exc:
            log_error(case_id, f"security_arch_review.cluster_{label}", str(exc),
                      severity="warning", context={"label": label})
            print(f"[security_arch_review] Cluster analysis ({label}) failed: {exc}")
            return ""

    with ThreadPoolExecutor(max_workers=2) as pool:
        net_fut  = pool.submit(_call, "network", network_iocs)
        file_fut = pool.submit(_call, "file",    file_iocs)
        net_result  = net_fut.result()
        file_result = file_fut.result()

    parts: list[str] = []
    if net_result:
        parts.append(f"### Network IOC Cluster Analysis\n\n{net_result}")
    if file_result:
        parts.append(f"### File IOC Cluster Analysis\n\n{file_result}")

    return "\n\n".join(parts)


def _dealias_dict(alias_map, obj):
    """Recursively dealias all string values in a dict/list structure."""
    if isinstance(obj, str):
        return alias_map.dealias_text(obj)
    if isinstance(obj, list):
        return [_dealias_dict(alias_map, item) for item in obj]
    if isinstance(obj, dict):
        return {k: _dealias_dict(alias_map, v) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------------------
# Main function
# ---------------------------------------------------------------------------

def security_arch_review(case_id: str) -> dict:
    """
    Run an LLM-assisted security architecture review for *case_id*.

    Returns a manifest dict with the output path and token usage.
    Writes the review to:
      cases/<case_id>/artefacts/security_architecture/security_arch_review.md
    """
    # ── 1. Early-exit checks ──────────────────────────────────────────────
    if not ANTHROPIC_KEY:
        return {
            "status":  "skipped",
            "reason":  "ANTHROPIC_API_KEY not set — security arch review requires LLM access.",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    try:
        import anthropic
    except ImportError as exc:
        log_error(case_id, "security_arch_review.import_anthropic", str(exc), severity="info")
        return {
            "status":  "error",
            "reason":  "anthropic package not installed. Run: pip install anthropic",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    # ── 2. Read severity → determine extended thinking ────────────────────
    case_dir  = CASES_DIR / case_id
    meta      = _safe_load(case_dir / "case_meta.json") or {}
    severity  = meta.get("severity", "").lower()
    use_thinking = severity in ("high", "critical")

    # ── 2b. Skip if enrichment shows all-clean (no malicious/suspicious IOCs) ──
    verdict_path = case_dir / "artefacts" / "enrichment" / "verdict_summary.json"
    if verdict_path.exists():
        verdicts = _safe_load(verdict_path) or {}
        mal_count = len(verdicts.get("high_priority", []))
        sus_count = len(verdicts.get("needs_review", []))
        if mal_count == 0 and sus_count == 0:
            print(f"[security_arch_review] Skipping — verdict summary shows 0 malicious, "
                  f"0 suspicious IOCs for {case_id}")
            return {
                "status":  "skipped",
                "reason":  "All IOCs clean — security arch review not warranted.",
                "case_id": case_id,
                "ts":      utcnow(),
            }

    # ── 3. Build context ──────────────────────────────────────────────────
    context = _build_context(case_id)
    alias_map = get_alias_map()
    if alias_map:
        context = alias_map.alias_text(context)
    if not context.strip():
        return {
            "status":  "skipped",
            "reason":  "No case artefacts found — run enrich_iocs or add_evidence first.",
            "case_id": case_id,
            "ts":      utcnow(),
        }

    # ── 4. Create client ──────────────────────────────────────────────────
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    # ── 5. Upload PDFs via Files API ──────────────────────────────────────
    pdf_blocks = _upload_case_pdfs(case_id, client)

    # ── 6. Load IOCs for cluster analysis ─────────────────────────────────
    iocs_data = _safe_load(case_dir / "iocs" / "iocs.json") or {}
    ioc_dict  = iocs_data.get("iocs", {})
    has_network = bool(ioc_dict.get("ipv4") or ioc_dict.get("domain"))
    has_files   = bool(ioc_dict.get("sha256") or ioc_dict.get("md5") or ioc_dict.get("sha1"))

    # ── 7. Submit cluster analysis to background thread (runs concurrently) ──
    focused_future = None
    cluster_executor = None
    if has_network and has_files:
        cluster_executor = ThreadPoolExecutor(max_workers=1)
        focused_future   = cluster_executor.submit(
            _parallel_cluster_analysis, case_id, client, ioc_dict, severity
        )

    # ── 8. Build user content + make main LLM call ────────────────────────
    user_content: list[dict] = []

    # Prepend any uploaded PDF document blocks
    user_content.extend(pdf_blocks)

    # Main text context
    user_content.append({
        "type": "text",
        "text": (
            f"Please produce a Security Architecture Review for the following investigation.\n\n"
            f"{context}"
        ),
    })

    _model = get_model("secarch", severity)
    call_kwargs: dict = {
        "model":    _model,
        "system":   _SYSTEM_CACHED,
        "messages": [{"role": "user", "content": user_content}],
    }

    # Adaptive thinking works with tools — no mutual exclusion needed
    call_kwargs["tools"]      = [_STRUCTURED_TOOL]
    call_kwargs["tool_choice"] = {"type": "auto"}

    if use_thinking:
        call_kwargs["thinking"]      = {"type": "adaptive"}
        call_kwargs["output_config"] = {"effort": "high"}
        call_kwargs["max_tokens"]    = 16000
        print(f"[security_arch_review] Adaptive thinking ENABLED (severity={severity})")
    else:
        call_kwargs["max_tokens"] = 8192

    print(f"[security_arch_review] Querying {_model} for case {case_id}...")
    if pdf_blocks:
        print(f"[security_arch_review] Including {len(pdf_blocks)} PDF document(s) via Files API")

    message = client.messages.create(**call_kwargs)

    # ── 9. Extract review_text + structured_data ──────────────────────────
    review_text     = ""
    structured_data = None

    for block in message.content:
        if block.type == "thinking":
            continue  # adaptive thinking block — skip
        elif block.type == "text":
            review_text += block.text
        elif block.type == "tool_use" and block.name == "record_structured_analysis":
            structured_data = block.input

    review_text = review_text.strip()

    tokens_in        = message.usage.input_tokens
    tokens_out       = message.usage.output_tokens
    tokens_cache_read = getattr(message.usage, "cache_read_input_tokens", 0) or 0
    tokens_cache_write = getattr(message.usage, "cache_creation_input_tokens", 0) or 0

    print(
        f"[security_arch_review] Tokens: {tokens_in} in / {tokens_out} out "
        f"| cache_read={tokens_cache_read} cache_write={tokens_cache_write}"
    )

    # ── 10. Collect cluster deep-dive result ──────────────────────────────
    if focused_future is not None:
        try:
            cluster_text = focused_future.result(timeout=90)
            if cluster_text:
                review_text += f"\n\n## IOC Cluster Deep-Dive\n\n{cluster_text}"
        except FuturesTimeoutError:
            log_error(case_id, "security_arch_review.cluster_timeout", "90s timeout",
                      severity="warning")
            print("[security_arch_review] Cluster analysis timed out (90 s) — skipped")
        except Exception as exc:
            log_error(case_id, "security_arch_review.cluster_collect", str(exc),
                      severity="warning")
            print(f"[security_arch_review] Cluster analysis error: {exc}")
        finally:
            cluster_executor.shutdown(wait=False)

    # ── 11. Dealias all LLM output ────────────────────────────────────────
    if alias_map:
        review_text = alias_map.dealias_text(review_text)

    # ── 12. Write artefacts ───────────────────────────────────────────────
    out_dir  = case_dir / "artefacts" / "security_architecture"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "security_arch_review.md"

    header = (
        f"# Security Architecture Review — {case_id}\n\n"
        f"_Generated: {utcnow()} | Model: {_model} | "
        f"Tokens: {tokens_in} in / {tokens_out} out"
        + (f" | Cache read: {tokens_cache_read}" if tokens_cache_read else "")
        + (f" | Thinking: enabled" if use_thinking else "")
        + f"_\n\n---\n\n"
    )
    write_report(out_path, header + review_text, title=f"Security Architecture Review — {case_id}")

    # Structured sidecar
    if structured_data:
        if alias_map:
            structured_data = _dealias_dict(alias_map, structured_data)
        sidecar_path = out_dir / "security_arch_structured.json"
        save_json(sidecar_path, structured_data)
        print(f"[security_arch_review] Structured analysis saved to {sidecar_path}")

    manifest = {
        "case_id":             case_id,
        "review_path":         str(out_path),
        "tokens_in":           tokens_in,
        "tokens_out":          tokens_out,
        "tokens_cache_read":   tokens_cache_read,
        "tokens_cache_write":  tokens_cache_write,
        "model":               _model,
        "use_thinking":        use_thinking,
        "structured":          bool(structured_data),
        "pdf_files_uploaded":  len(pdf_blocks),
        "status":              "ok",
        "ts":                  utcnow(),
    }
    save_json(out_dir / "security_arch_manifest.json", manifest)

    print(f"[security_arch_review] Review written to {out_path}")
    return manifest


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(
        description="LLM-assisted security architecture review for a case."
    )
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = security_arch_review(args.case_id)
    print(json.dumps(result, indent=2, default=str))
