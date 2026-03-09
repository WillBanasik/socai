"""
tool: generate_report
---------------------
Builds a Markdown investigation report for a single case from all
persisted artefact JSON files.

Sections:
  1. Executive Summary
  2. Technical Narrative (chronological bullets)
  3. Key IOCs (observed only)
  4. Risk Explanation
  5. Recommendations
  6. What Was NOT Observed
  7. Confidence Assessment (LOW / MEDIUM / HIGH)

Writes:
  cases/<case_id>/reports/investigation_report.md
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from textwrap import fill

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, CONF_HIGH, CONF_MED, IOC_INDEX_FILE
from tools.common import defang_report, load_json, log_error, utcnow, write_artefact
from tools.index_case import index_case


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_optional(path: Path) -> dict | list | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "generate_report.load_optional", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _confidence_label(score: float) -> str:
    if score >= CONF_HIGH:
        return "HIGH"
    if score >= CONF_MED:
        return "MEDIUM"
    return "LOW"


def _ioc_table(iocs: dict[str, list]) -> str:
    lines = ["| Type | Value |", "|------|-------|"]
    any_found = False
    for ioc_type, vals in iocs.items():
        for v in vals[:30]:
            lines.append(f"| {ioc_type.upper()} | `{v}` |")
            any_found = True
    if not any_found:
        return "_No IOCs extracted from artefacts._\n"
    return "\n".join(lines) + "\n"


def _format_chain(chain: list[dict]) -> str:
    lines = []
    for i, hop in enumerate(chain, 1):
        loc = f" → `{hop.get('location', '')}`" if hop.get("location") else ""
        lines.append(f"  {i}. `{hop.get('url', '?')}` [{hop.get('status', '?')}]{loc}")
    return "\n".join(lines)


def _bullets(items: list[str], indent: int = 0) -> str:
    prefix = "  " * indent
    return "\n".join(f"{prefix}- {item}" for item in items)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_executive_summary(meta: dict, iocs: dict | None, correlation: dict | None) -> str:
    case_id  = meta.get("case_id", "?")
    title    = meta.get("title", case_id)
    severity = meta.get("severity", "unknown").upper()
    status   = meta.get("status", "open")
    analyst  = meta.get("analyst", "unassigned")
    created  = meta.get("created_at", "")

    ioc_summary = ""
    if iocs:
        totals = iocs.get("total", {})
        parts  = [f"{v} {k}" for k, v in totals.items() if v > 0]
        ioc_summary = f"  \nIOC extraction yielded: {', '.join(parts)}." if parts else ""

    corr_summary = ""
    if correlation and correlation.get("hit_summary"):
        hits = correlation["hit_summary"]
        corr_summary = f"  \nCorrelation identified: {json.dumps(hits)}."

    return f"""## Executive Summary

| Field | Value |
|-------|-------|
| Case ID | {case_id} |
| Title | {title} |
| Severity | {severity} |
| Status | {status} |
| Analyst | {analyst} |
| Created | {created} |

This investigation was initiated following submission of artefacts for case **{case_id}**.
Automated tooling performed web capture, static file analysis, IOC extraction, log parsing,
and enrichment lookups against available threat-intelligence providers.{ioc_summary}{corr_summary}
"""


def _build_technical_narrative(
    meta: dict,
    captures: list[dict],
    zip_manifests: list[dict],
    analyses: list[dict],
    log_parses: list[dict],
    iocs: dict | None,
    correlation: dict | None,
) -> str:
    bullets: list[str] = []
    ts_base = meta.get("created_at", "")

    bullets.append(f"**{ts_base}** — Case {meta.get('case_id')} initialised. "
                   f"Severity: {meta.get('severity', 'unknown')}.")

    for cap in captures:
        ts  = cap.get("ts", "")
        url = cap.get("url", "?")
        final = cap.get("final_url", url)
        chain = cap.get("redirect_chain", [])
        arts  = cap.get("artefacts", {})
        lines = [f"**{ts}** — Web capture of `{url}`."]
        if len(chain) > 1:
            lines.append(f"  Redirect chain ({len(chain)} hop(s)):")
            lines.append(_format_chain(chain))
        lines.append(f"  Final URL: `{final}`")
        if arts.get("screenshot"):
            lines.append(f"  Screenshot: `{arts['screenshot']['path']}`")
        if arts.get("html"):
            lines.append(f"  HTML saved: `{arts['html']['path']}`")
        bullets.append("\n".join(lines))

    for zm in zip_manifests:
        ts    = zm.get("ts", "")
        src   = zm.get("source_zip", "?")
        files = zm.get("files", [])
        errs  = zm.get("errors", [])
        lines = [f"**{ts}** — ZIP extracted: `{src}`. {len(files)} file(s) extracted."]
        for f in files[:10]:
            lines.append(f"  - `{f['name']}` SHA-256: `{f['sha256']}`")
        if errs:
            lines.append(f"  Errors: {len(errs)}")
        bullets.append("\n".join(lines))

    for an in analyses:
        ts     = an.get("ts", "")
        fname  = an.get("filename", "?")
        ftype  = an.get("file_type", "?")
        ent    = an.get("entropy", 0)
        flags  = an.get("flags", [])
        hashes = an.get("hashes", {})
        lines  = [f"**{ts}** — Static analysis: `{fname}` ({ftype})."]
        lines.append(f"  Entropy: {ent}. SHA-256: `{hashes.get('sha256', 'N/A')}`")
        if flags:
            for fl in flags:
                lines.append(f"  **Flag:** {fl}")
        bullets.append("\n".join(lines))

    for lp in log_parses:
        ts   = lp.get("ts", "")
        src  = lp.get("source_file", "?")
        rows = lp.get("row_count", 0)
        ents = lp.get("entity_totals", {})
        e_parts = [f"{v} {k}" for k, v in ents.items() if v > 0]
        bullets.append(
            f"**{ts}** — Log parsed: `{src}`. {rows} row(s). "
            f"Entities: {', '.join(e_parts) or 'none'}."
        )

    if iocs:
        totals  = iocs.get("total", {})
        sources = iocs.get("sources", [])
        parts   = [f"{v} {k}" for k, v in totals.items() if v > 0]
        bullets.append(
            f"**{iocs.get('ts', '')}** — IOC extraction complete. "
            f"Totals: {', '.join(parts)}. "
            f"Sources scanned: {len(sources)}."
        )

    if correlation and correlation.get("hits"):
        hit_sum = correlation.get("hit_summary", {})
        tl      = correlation.get("timeline_events", 0)
        bullets.append(
            f"**{correlation.get('ts', '')}** — Correlation run. "
            f"Hits: {hit_sum}. Timeline events: {tl}."
        )

    return "## Technical Narrative\n\n" + "\n\n".join(bullets) + "\n"


def _build_iocs_section(iocs: dict | None) -> str:
    if not iocs:
        return "## Key IOCs\n\n_No IOC data available._\n"
    return "## Key IOCs\n\n" + _ioc_table(iocs.get("iocs", {}))


def _build_risk_section(meta: dict, analyses: list[dict], iocs: dict | None) -> str:
    severity = meta.get("severity", "medium").lower()
    high_entropy = [a["filename"] for a in analyses if a.get("entropy", 0) > 7.2]
    executables  = [a["filename"] for a in analyses if "executable" in a.get("file_type", "").lower()]
    has_iocs     = bool(iocs and any(iocs.get("iocs", {}).values()))

    risk_factors = []
    if severity in ("high", "critical"):
        risk_factors.append(f"Case severity is rated **{severity.upper()}**.")
    if high_entropy:
        risk_factors.append(
            f"File(s) with anomalous entropy (>7.2) detected: {', '.join(high_entropy)}. "
            "High entropy is consistent with packing, encryption, or obfuscation."
        )
    if executables:
        risk_factors.append(
            f"Executable file(s) identified: {', '.join(executables)}. "
            "Executables require additional dynamic analysis and sandboxing before handling."
        )
    if has_iocs:
        risk_factors.append(
            "Network-based IOCs extracted. Verify these are not already blocked at the perimeter."
        )
    if not risk_factors:
        risk_factors.append(
            "No significant automated risk indicators identified at this time. "
            "Manual analyst review is still recommended."
        )

    body = "\n".join(f"- {r}" for r in risk_factors)
    return f"## Risk Explanation\n\n{body}\n"


def _build_recommendations(analyses: list[dict], iocs: dict | None, correlation: dict | None) -> str:
    recs: list[str] = []

    if analyses:
        recs.append(
            "Submit all extracted executable files to an isolated sandbox for dynamic analysis "
            "(e.g., ANY.RUN, Cuckoo) prior to further handling."
        )
    if iocs and iocs.get("iocs", {}).get("ipv4"):
        recs.append(
            "Block or monitor extracted IP IOCs at the network perimeter and SIEM. "
            f"Reference: `{CASES_DIR}/<case_id>/iocs/iocs.json`"
        )
    if iocs and iocs.get("iocs", {}).get("domain"):
        recs.append(
            "Review extracted domain IOCs against DNS logs and proxy/firewall blocklists."
        )
    if correlation and correlation.get("hits", {}).get("ip_matches"):
        recs.append(
            "Matched IPs found in log data. Initiate host-based investigation on affected systems."
        )
    recs.append(
        "Enrich remaining stubs by populating API keys in `config/settings.py` "
        "(VirusTotal, AbuseIPDB, URLScan.io)."
    )
    recs.append("Close the case or escalate within 72 hours per SLA requirements.")

    return "## Recommendations\n\n" + _bullets(recs) + "\n"


def _build_verdict_summary_section(
    verdict_summary: dict | None,
    ioc_index: dict | None,
    case_id: str,
) -> str:
    """
    Renders the Threat Verdict Summary section.

    Shows a per-IOC composite verdict table (malicious/suspicious IOCs only)
    and a Recurring IOCs subsection when the cross-case index has prior hits.
    Returns an empty string when no enrichment data is available.
    """
    if not verdict_summary or not verdict_summary.get("iocs"):
        return ""

    iocs       = verdict_summary["iocs"]
    high       = verdict_summary.get("high_priority", [])
    review     = verdict_summary.get("needs_review", [])
    clean      = verdict_summary.get("clean", [])

    # Count distinct providers that contributed verdicts
    all_providers: set[str] = set()
    for info in iocs.values():
        all_providers.update(info.get("providers", {}).keys())
    provider_count = len(all_providers)

    lines: list[str] = [
        "## Threat Verdict Summary\n",
        f"Provider coverage: **{provider_count}** enrichment source(s) queried "
        f"across **{verdict_summary.get('ioc_count', 0)}** IOC(s).\n",
        "| Priority | Count |",
        "|----------|-------|",
        f"| MALICIOUS | {len(high)} |",
        f"| SUSPICIOUS | {len(review)} |",
        f"| CLEAN | {len(clean)} |",
        "",
    ]

    actionable = [(ioc, iocs[ioc]) for ioc in high if ioc in iocs] + \
                 [(ioc, iocs[ioc]) for ioc in review if ioc in iocs]

    if actionable:
        lines += [
            "### Per-IOC Verdict Detail\n",
            "| IOC | Type | Verdict | Confidence | Malicious / Total Providers | Provider Breakdown |",
            "|-----|------|---------|------------|-----------------------------|-------------------|",
        ]
        for ioc, info in actionable[:40]:
            v          = info["verdict"].upper()
            conf       = info["confidence"]
            mal        = info["malicious"]
            total      = info["total_providers"]
            breakdown  = ", ".join(
                f"{p}:{vd}" for p, vd in sorted(info.get("providers", {}).items())
            )
            lines.append(
                f"| `{ioc}` | {info['ioc_type'].upper()} | **{v}** | {conf} "
                f"| {mal}/{total} | {breakdown} |"
            )
        lines.append("")

    # --- Recurring IOCs from the cross-case index ---
    if ioc_index:
        recurring: list[tuple[str, list[str], str]] = []
        for ioc_val, info in iocs.items():
            entry = ioc_index.get(ioc_val)
            if entry:
                other_cases = [c for c in entry.get("cases", []) if c != case_id]
                if other_cases:
                    recurring.append((ioc_val, other_cases, info["ioc_type"]))

        if recurring:
            lines += [
                "### Recurring IOCs — Seen in Prior Investigations\n",
                "> The following IOCs have been observed in previous cases. "
                "This suggests persistent or reused attacker infrastructure.\n",
                "| IOC | Type | Current Verdict | Also Seen In |",
                "|-----|------|-----------------|-------------|",
            ]
            for ioc_val, cases, ioc_type in recurring[:25]:
                verdict = iocs.get(ioc_val, {}).get("verdict", "unknown").upper()
                cases_str = ", ".join(cases[:6]) + (" ..." if len(cases) > 6 else "")
                lines.append(
                    f"| `{ioc_val}` | {ioc_type.upper()} | **{verdict}** | {cases_str} |"
                )
            lines.append("")

    return "\n".join(lines) + "\n"


def _build_phishing_detection_section(phishing_detection: dict | None) -> str:
    if not phishing_detection:
        return ""
    findings = phishing_detection.get("findings", [])
    form_analysis = phishing_detection.get("form_analysis", [])
    tls_signals = phishing_detection.get("tls_signals", [])
    if not findings and not form_analysis and not tls_signals:
        return ""

    lines = ["## ⚠ Phishing Indicators Detected\n"]

    # --- Brand impersonation findings ---
    if findings:
        lines.append(
            "The following captured pages display a known brand identity but are "
            "hosted on a domain that is **not** associated with that brand. "
            "This is a strong indicator of credential-harvesting phishing.\n"
        )

        for f in findings:
            conf_label = {"high": "\U0001f534 HIGH", "medium": "\U0001f7e1 MEDIUM"}.get(f["confidence"], f["confidence"].upper())
            lines.append(f"### {f['brand']} — {conf_label} confidence\n")
            lines.append(f"- **Phishing URL:** `{f['final_url']}`")
            lines.append(f"- **Hostname:** `{f['hostname']}`")
            where = []
            if f.get("title_hit"):
                where.append("page title")
            if f.get("body_hit"):
                where.append("page body")
            if f.get("source") == "llm_vision":
                where.append("screenshot (LLM vision)")
            if f.get("source") == "form_analysis":
                where.append("credential harvest form")
            if where:
                lines.append(f"- **Brand detected in:** {', '.join(where)}")
            lines.append(f"- **Pattern matched:** `{f['matched_pattern']}`")
            if f.get("credential_harvest"):
                harvest_detail = "password form detected"
                if f.get("external_harvest"):
                    targets = f.get("harvest_targets", [])
                    harvest_detail += f" — credentials sent to external host(s): {', '.join(f'`{t}`' for t in targets)}"
                lines.append(f"- **Credential harvest:** {harvest_detail}")
            if f.get("domain_age_days") is not None:
                age = f["domain_age_days"]
                age_label = f"**{age} days** (newly registered)" if age < 30 else f"{age} days"
                lines.append(f"- **Domain age:** {age_label}")
            if f.get("confidence_boosted_by"):
                lines.append(f"- **Confidence boosted by:** {f['confidence_boosted_by'].replace('_', ' ')}")
            lines.append("")

    # --- Suspicious TLS certificates ---
    if tls_signals:
        lines.append("### Suspicious TLS Certificates\n")
        lines.append(
            "The following domains present TLS certificates with characteristics "
            "commonly seen on phishing infrastructure.\n"
        )
        for ts in tls_signals:
            cert = ts.get("cert_details", {})
            lines.append(f"- **{ts['hostname']}** — {', '.join(ts['reasons'])}")
            if cert.get("issuer_org"):
                lines.append(f"  - Issuer: {cert['issuer_org']} ({cert.get('issuer_cn', '')})")
            if cert.get("cert_age_days") is not None:
                lines.append(f"  - Certificate age: {cert['cert_age_days']} days")
            if cert.get("san"):
                san_display = ", ".join(cert["san"][:5])
                if len(cert["san"]) > 5:
                    san_display += f" (+{len(cert['san']) - 5} more)"
                lines.append(f"  - SAN: {san_display}")
        lines.append("")

    lines.append(
        "> **Recommended action:** Block the domain at the email/web gateway, "
        "reset credentials for any users who may have entered them, "
        "and report the URL to the brand's abuse team.\n"
    )
    return "\n".join(lines)


def _build_cloudflare_warnings(captures: list) -> str:
    blocked = [c for c in captures if c.get("cloudflare_blocked")]
    if not blocked:
        return ""
    lines = ["## ⚠ Cloudflare-Blocked Captures\n"]
    lines.append(
        "The following URLs were blocked or challenged by Cloudflare during capture. "
        "The content recorded **may be a challenge/interstitial page only**, not the actual target. "
        "Manual review via an authenticated browser session is recommended.\n"
    )
    challenge_advice = {
        "managed_challenge": "Turnstile/managed challenge — Playwright cannot solve this automatically.",
        "captcha":           "hCaptcha/CAPTCHA challenge — requires human interaction.",
        "block":             "Hard block (HTTP 403/1020) — access denied by site policy.",
        "js_challenge":      "Automatic JS challenge — may have resolved; verify screenshot.",
        "unknown":           "Unknown challenge type — inspect `screenshot.png` and `page.html`.",
    }
    for c in blocked:
        ct = c.get("cloudflare_challenge") or "unknown"
        advice = challenge_advice.get(ct, "")
        lines.append(f"- **{c.get('url', c.get('final_url', '?'))}**")
        lines.append(f"  - Challenge type: `{ct}`")
        if advice:
            lines.append(f"  - {advice}")
    lines.append("")
    return "\n".join(lines)


def _build_not_observed(
    captures: list, zip_manifests: list, analyses: list, log_parses: list,
    sandbox_data: dict | None = None,
) -> str:
    not_obs: list[str] = []
    if not captures:
        not_obs.append("No web capture was performed for this case.")
    if not zip_manifests:
        not_obs.append("No ZIP/archive extraction was performed for this case.")
    if not analyses:
        not_obs.append("No static file analysis was performed for this case.")
    if not log_parses:
        not_obs.append("No log files were parsed for this case.")
    if not sandbox_data or sandbox_data.get("status") != "ok":
        not_obs.append("Dynamic/behavioural sandbox analysis was not performed.")
    not_obs.append("Live memory acquisition or endpoint forensics were not performed.")

    return "## What Was NOT Observed\n\n" + _bullets(not_obs) + "\n"


def _build_confidence(
    captures: list, zip_manifests: list, analyses: list,
    log_parses: list, iocs: dict | None, correlation: dict | None,
    verdict_summary: dict | None = None,
) -> tuple[str, float]:
    score = 0.0
    notes: list[str] = []

    if captures:
        score += 0.15
        notes.append("Web capture performed (+0.15).")
    if zip_manifests:
        score += 0.15
        notes.append("ZIP extraction and hash verification performed (+0.15).")
    if analyses:
        score += 0.15
        notes.append("Static file analysis performed (+0.15).")
    if log_parses:
        score += 0.15
        notes.append("Log parsing performed (+0.15).")
    if iocs and any(iocs.get("iocs", {}).values()):
        score += 0.15
        notes.append("IOCs extracted from artefacts (+0.15).")
    if correlation and correlation.get("hits"):
        score += 0.15
        notes.append("Positive correlation hits between IOCs and logs (+0.15).")

    # Enrichment verdict signal
    if verdict_summary:
        malicious_count  = len(verdict_summary.get("high_priority", []))
        suspicious_count = len(verdict_summary.get("needs_review", []))
        if malicious_count > 0:
            score += 0.20
            notes.append(
                f"Enrichment confirmed {malicious_count} malicious IOC(s) "
                f"across multiple providers (+0.20)."
            )
        elif suspicious_count > 0:
            score += 0.10
            notes.append(
                f"Enrichment flagged {suspicious_count} suspicious IOC(s) (+0.10)."
            )

    label = _confidence_label(score)
    notes_str = "\n".join(f"- {n}" for n in notes)
    body = (
        f"**Overall Confidence: {label}** (score: {score:.2f})\n\n"
        f"Confidence is based on breadth of evidence collected:\n\n{notes_str}\n\n"
        "_Note: confidence reflects evidence coverage, not threat certainty._"
    )
    return f"## Confidence Assessment\n\n{body}\n", score


def _build_triage_section(triage_data: dict | None) -> str:
    """Build triage warning section when known-bad IOCs are found."""
    if not triage_data:
        return ""
    known_malicious = triage_data.get("known_malicious", [])
    known_suspicious = triage_data.get("known_suspicious", [])
    if not known_malicious and not known_suspicious:
        return ""

    lines = ["## ⚠ Triage — Known IOCs Detected\n"]
    if known_malicious:
        lines.append(
            f"**{len(known_malicious)} known MALICIOUS IOC(s)** from prior investigations "
            "were identified in the input to this case:\n"
        )
        lines.append("| IOC | Verdict | Confidence | Prior Cases |")
        lines.append("|-----|---------|------------|-------------|")
        for hit in known_malicious[:15]:
            cases_str = ", ".join(hit.get("cases", [])[:5])
            lines.append(
                f"| `{hit['ioc']}` | **MALICIOUS** | {hit.get('confidence', '?')} | {cases_str} |"
            )
        lines.append("")

    if known_suspicious:
        lines.append(
            f"**{len(known_suspicious)} known SUSPICIOUS IOC(s)** were also identified:\n"
        )
        for hit in known_suspicious[:10]:
            lines.append(f"- `{hit['ioc']}` (confidence: {hit.get('confidence', '?')})")
        lines.append("")

    escalate = triage_data.get("escalate_severity")
    if escalate:
        lines.append(f"> **Severity was auto-escalated to {escalate.upper()}** based on triage findings.\n")

    return "\n".join(lines)


def _build_email_analysis_section(email_data: dict | None) -> str:
    """Build email analysis section from email_analysis.json."""
    if not email_data:
        return ""
    if email_data.get("status") != "ok":
        return ""

    headers = email_data.get("headers", {})
    auth = email_data.get("auth_results", {})
    spoofing = email_data.get("spoofing_signals", [])
    urls = email_data.get("urls", [])
    attachments = email_data.get("attachments", [])

    lines = ["## Email Analysis\n"]

    # Header summary table
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| From | `{headers.get('from', '?')}` |")
    lines.append(f"| To | `{headers.get('to', '?')}` |")
    lines.append(f"| Subject | {headers.get('subject', '?')} |")
    lines.append(f"| Date | {headers.get('date', '?')} |")
    if headers.get("reply_to"):
        lines.append(f"| Reply-To | `{headers['reply_to']}` |")
    if headers.get("return_path"):
        lines.append(f"| Return-Path | `{headers['return_path']}` |")
    if headers.get("x_mailer"):
        lines.append(f"| X-Mailer | `{headers['x_mailer']}` |")
    lines.append("")

    # Authentication results
    lines.append("### Authentication Results\n")
    lines.append("| Check | Result |")
    lines.append("|-------|--------|")
    for check in ("spf", "dkim", "dmarc"):
        result = auth.get(check, "N/A")
        icon = "✓" if result == "pass" else "✗" if result in ("fail", "softfail") else "?"
        lines.append(f"| {check.upper()} | {icon} {result or 'N/A'} |")
    lines.append("")

    # Spoofing signals
    if spoofing:
        lines.append("### ⚠ Spoofing Indicators\n")
        for sig in spoofing:
            sev_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(sig["severity"], "⚪")
            lines.append(f"- {sev_icon} **{sig['type']}** — {sig['detail']}")
        lines.append("")

    # URLs
    if urls:
        lines.append(f"### Extracted URLs ({len(urls)})\n")
        for url in urls[:20]:
            lines.append(f"- `{url}`")
        lines.append("")

    # Attachments
    if attachments:
        lines.append(f"### Attachments ({len(attachments)})\n")
        lines.append("| Filename | Type | Size | SHA-256 |")
        lines.append("|----------|------|------|---------|")
        for att in attachments:
            lines.append(
                f"| `{att['filename']}` | {att.get('content_type', '?')} "
                f"| {att.get('size_bytes', '?')} B | `{att.get('sha256', '?')[:16]}...` |"
            )
        lines.append("")

    return "\n".join(lines)


def _build_sandbox_section(sandbox_data: dict | None) -> str:
    """Build sandbox analysis section."""
    if not sandbox_data:
        return ""
    if sandbox_data.get("status") not in ("ok",):
        return ""

    per_hash = sandbox_data.get("per_hash", {})
    sandbox_iocs = sandbox_data.get("sandbox_iocs", [])
    mitre_ttps = sandbox_data.get("mitre_ttps", [])
    c2_beacons = sandbox_data.get("c2_beacons", [])

    if not per_hash:
        return ""

    lines = ["## Sandbox Analysis Results\n"]
    lines.append(
        f"Checked **{sandbox_data.get('hashes_checked', 0)}** file hash(es) across sandbox providers. "
        f"**{sandbox_data.get('ok_results', 0)}** existing report(s) found.\n"
    )

    for sha, results in per_hash.items():
        ok_results = [r for r in results if r.get("status") == "ok"]
        if not ok_results:
            continue
        lines.append(f"### `{sha[:16]}...`\n")
        lines.append("| Provider | Verdict | Score | Report |")
        lines.append("|----------|---------|-------|--------|")
        for r in ok_results:
            report_url = r.get("report_url", "")
            link = f"[View]({report_url})" if report_url else "N/A"
            lines.append(
                f"| {r['provider']} | **{r.get('verdict', '?').upper()}** "
                f"| {r.get('score', r.get('threat_score', '?'))} | {link} |"
            )
        lines.append("")

    if mitre_ttps:
        lines.append(f"### MITRE ATT&CK TTPs\n")
        lines.append(", ".join(f"`{t}`" for t in mitre_ttps[:20]))
        lines.append("")

    if c2_beacons:
        lines.append(f"### C2 Beacons\n")
        for c2 in c2_beacons[:10]:
            lines.append(f"- `{c2}`")
        lines.append("")

    if sandbox_iocs:
        lines.append(f"### Supplementary IOCs from Sandbox ({len(sandbox_iocs)})\n")
        lines.append("| Type | Value |")
        lines.append("|------|-------|")
        for ioc in sandbox_iocs[:20]:
            lines.append(f"| {ioc['type'].upper()} | `{ioc['value']}` |")
        lines.append("")

    return "\n".join(lines)


def _build_anomaly_section(anomaly_data: dict | None) -> str:
    """Build behavioural anomaly detection section."""
    if not anomaly_data:
        return ""
    findings = anomaly_data.get("findings", [])
    if not findings:
        return ""

    severity_counts = anomaly_data.get("severity_counts", {})
    type_counts = anomaly_data.get("type_counts", {})

    lines = ["## Behavioural Anomalies\n"]
    lines.append(
        f"Analysed **{anomaly_data.get('total_events_analysed', 0)}** log events. "
        f"**{len(findings)}** anomaly(ies) detected.\n"
    )

    # Summary table
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("high", "medium", "low"):
        count = severity_counts.get(sev, 0)
        if count:
            lines.append(f"| {sev.upper()} | {count} |")
    lines.append("")

    # High-severity detail
    high_findings = [f for f in findings if f.get("severity") == "high"]
    if high_findings:
        lines.append("### High-Severity Findings\n")
        for f in high_findings[:15]:
            icon = {
                "brute_force": "🔓",
                "impossible_travel": "✈",
                "lateral_movement": "↔",
                "first_seen_entity": "🆕",
            }.get(f["type"], "⚠")
            lines.append(f"- {icon} **{f['type']}** — {f['detail']}")
        lines.append("")

    # Type breakdown
    if type_counts:
        lines.append("### Detection Type Summary\n")
        for atype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"- **{atype}**: {count}")
        lines.append("")

    return "\n".join(lines)


def _build_campaign_section(campaign_data: dict | None) -> str:
    """Build related campaigns section."""
    if not campaign_data:
        return ""
    campaigns = campaign_data.get("campaigns", [])
    if not campaigns:
        return ""

    lines = ["## Related Campaigns\n"]
    lines.append(
        "This case shares IOCs with other investigations, suggesting "
        "related or reused attacker infrastructure.\n"
    )

    for camp in campaigns:
        lines.append(f"### {camp['campaign_id']} — Confidence: {camp.get('confidence', '?')}\n")
        lines.append(f"- **Member cases:** {', '.join(camp.get('cases', []))}")
        lines.append(f"- **Shared IOCs:** {camp.get('shared_ioc_count', 0)}")

        shared = camp.get("shared_iocs", [])
        if shared:
            lines.append("")
            lines.append("| IOC | Type | Verdict |")
            lines.append("|-----|------|---------|")
            for ioc in shared[:15]:
                lines.append(
                    f"| `{ioc['ioc']}` | {ioc.get('type', '?').upper()} "
                    f"| **{ioc.get('verdict', '?').upper()}** |"
                )

        ttps = camp.get("common_ttps", [])
        if ttps:
            lines.append(f"\n- **Common TTPs:** {', '.join(f'`{t}`' for t in ttps[:10])}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_report(case_id: str) -> dict:
    """
    Build and save the investigation report for *case_id*.
    Returns a dict with the report path and metadata.
    """
    case_dir    = CASES_DIR / case_id
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    meta = _load_optional(case_dir / "case_meta.json") or {"case_id": case_id}

    # Load all capture manifests
    captures = []
    for cm in (case_dir / "artefacts" / "web").rglob("capture_manifest.json"):
        d = _load_optional(cm)
        if d:
            captures.append(d)

    # Load ZIP manifests
    zip_manifests = []
    for zm in (case_dir / "artefacts" / "zip").rglob("hash_manifest.json"):
        d = _load_optional(zm)
        if d:
            zip_manifests.append(d)

    # Load static analysis results
    analyses = []
    for af in (case_dir / "artefacts" / "analysis").rglob("*.analysis.json"):
        d = _load_optional(af)
        if d:
            analyses.append(d)

    # Load log parse results
    log_parses = []
    for lf in (case_dir / "logs").rglob("*.parsed.json"):
        d = _load_optional(lf)
        if d:
            log_parses.append(d)

    phishing_detection = _load_optional(
        case_dir / "artefacts" / "phishing_detection" / "phishing_detection.json"
    )
    iocs        = _load_optional(case_dir / "iocs" / "iocs.json")
    correlation = _load_optional(case_dir / "artefacts" / "correlation" / "correlation.json")
    verdict_summary = _load_optional(
        case_dir / "artefacts" / "enrichment" / "verdict_summary.json"
    )
    ioc_index = _load_optional(IOC_INDEX_FILE)

    # Load new enhancement data (all optional)
    triage_data = _load_optional(case_dir / "artefacts" / "triage" / "triage_summary.json")
    email_data = _load_optional(case_dir / "artefacts" / "email" / "email_analysis.json")
    sandbox_data = _load_optional(case_dir / "artefacts" / "sandbox" / "sandbox_results.json")
    anomaly_data = _load_optional(case_dir / "artefacts" / "anomalies" / "anomaly_report.json")
    campaign_data = _load_optional(case_dir / "artefacts" / "campaign" / "campaign_links.json")

    # Build report sections
    sections = []
    now_str = utcnow()
    sections.append(f"# Investigation Report – {case_id}\n\n_Generated: {now_str}_\n")
    sections.append(_build_executive_summary(meta, iocs, correlation))

    # Analyst notes (submitted via web UI or API)
    analyst_notes_path = case_dir / "notes" / "analyst_input.md"
    if analyst_notes_path.exists():
        notes_text = analyst_notes_path.read_text(errors="replace").strip()
        if notes_text:
            sections.append("## Analyst Notes\n")
            sections.append(notes_text)
            sections.append("")

    # Triage warnings (known-bad IOCs from prior cases)
    triage_section = _build_triage_section(triage_data)
    if triage_section:
        sections.append(triage_section)

    phishing_section = _build_phishing_detection_section(phishing_detection)
    if phishing_section:
        sections.append(phishing_section)
    cf_warnings = _build_cloudflare_warnings(captures)
    if cf_warnings:
        sections.append(cf_warnings)

    # Email analysis
    email_section = _build_email_analysis_section(email_data)
    if email_section:
        sections.append(email_section)

    sections.append(_build_technical_narrative(
        meta, captures, zip_manifests, analyses, log_parses, iocs, correlation
    ))
    sections.append(_build_iocs_section(iocs))

    verdict_section = _build_verdict_summary_section(verdict_summary, ioc_index, case_id)
    if verdict_section:
        sections.append(verdict_section)

    # Sandbox results
    sandbox_section = _build_sandbox_section(sandbox_data)
    if sandbox_section:
        sections.append(sandbox_section)

    # Behavioural anomalies
    anomaly_section = _build_anomaly_section(anomaly_data)
    if anomaly_section:
        sections.append(anomaly_section)

    # Campaign links
    campaign_section = _build_campaign_section(campaign_data)
    if campaign_section:
        sections.append(campaign_section)

    sections.append(_build_risk_section(meta, analyses, iocs))
    sections.append(_build_recommendations(analyses, iocs, correlation))
    sections.append(_build_not_observed(captures, zip_manifests, analyses, log_parses, sandbox_data))
    confidence_section, conf_score = _build_confidence(
        captures, zip_manifests, analyses, log_parses, iocs, correlation, verdict_summary
    )
    sections.append(confidence_section)

    # LLM-synthesised executive narrative (advisory; graceful skip if no API key)
    try:
        from tools.llm_insight import synthesise_report_narrative
        narrative = synthesise_report_narrative(case_id)
        if narrative:
            sections.insert(1, f"## Analytical Narrative\n\n> *The following narrative is LLM-synthesised (assessed, not confirmed).*\n\n{narrative}\n")
    except Exception:
        pass  # LLM enhancement is optional

    # Artefact index
    sections.append("## Artefact Index\n")
    all_artefacts = sorted(case_dir.rglob("*"))
    for f in all_artefacts:
        if f.is_file():
            sections.append(f"- `{f.relative_to(case_dir)}`")
    sections.append("")

    report_text = "\n".join(sections)

    # Defang malicious/suspicious IOCs in the final report
    if verdict_summary:
        mal_iocs: set[str] = set(verdict_summary.get("high_priority", []))
        mal_iocs.update(verdict_summary.get("needs_review", []))
        if mal_iocs:
            report_text = defang_report(report_text, mal_iocs)

    report_path = reports_dir / "investigation_report.md"
    write_artefact(report_path, report_text)

    # Update registry
    index_case(case_id, report_path=str(report_path))

    print(f"[generate_report] Report written to {report_path}")
    return {
        "case_id":     case_id,
        "report_path": str(report_path),
        "confidence":  _confidence_label(conf_score),
        "score":       conf_score,
        "ts":          utcnow(),
    }


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Generate investigation report for a case.")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = generate_report(args.case_id)
    print(json.dumps(result, indent=2))
