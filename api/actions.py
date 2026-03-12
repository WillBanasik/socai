"""Individual pipeline actions that can be triggered on demand."""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import timeline
from api.jobs import JobManager
from config.settings import CASES_DIR
from tools.common import md_file_note


def _run_action(case_id: str, action: str, fn, **extra_data) -> dict:
    """Run a pipeline action, update timeline, return result."""
    timeline.append(case_id, "action_start", {"action": action, **extra_data})
    try:
        result = fn()
        msg = result.pop("_message", None) if isinstance(result, dict) else None
        timeline.append(case_id, "action_done", {
            "action": action,
            "message": msg or f"{action} completed.",
        })
        return {"status": "ok", "action": action, "message": msg, "result": result}
    except Exception as exc:
        tb = traceback.format_exc()
        from tools.common import log_error
        log_error(case_id, f"api.actions.{action}", str(exc),
                  severity="error", traceback=tb)
        err_msg = f"{action} failed: {exc}"
        timeline.append(case_id, "action_error", {
            "action": action,
            "error": err_msg,
        })
        return {"status": "error", "action": action, "error": err_msg}


# ---------------------------------------------------------------------------
# Individual actions
# ---------------------------------------------------------------------------

def create_case(case_id: str, title: str, severity: str, analyst: str,
                tags: list[str] | None = None, analyst_notes: str | None = None) -> dict:
    """Create case and save analyst notes."""
    from tools.case_create import case_create

    result = _run_action(case_id, "case_create", lambda: {
        **case_create(case_id, title=title, severity=severity, analyst=analyst, tags=tags or []),
        "_message": f"Case {case_id} created — {title} (severity: {severity})",
    })

    if analyst_notes:
        notes_dir = CASES_DIR / case_id / "notes"
        notes_dir.mkdir(parents=True, exist_ok=True)
        (notes_dir / "analyst_input.md").write_text(analyst_notes)
        timeline.append(case_id, "system", {
            "message": f"Analyst notes saved ({len(analyst_notes)} chars)",
        })

    return result


def add_evidence(case_id: str, text: str) -> dict:
    """Parse new analyst input, append notes, return extracted IOCs."""
    from api.parse_input import parse_analyst_input

    parsed = parse_analyst_input(text)

    # Append to analyst notes
    notes_path = CASES_DIR / case_id / "notes" / "analyst_input.md"
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    existing = notes_path.read_text(errors="replace") if notes_path.exists() else ""
    notes_path.write_text(existing + f"\n\n---\n\n{text}\n")

    # Build human-readable summary
    parts = []
    if parsed.get("urls"):
        parts.append(f"{len(parsed['urls'])} URL(s)")
    if parsed.get("ips"):
        parts.append(f"{len(parsed['ips'])} IP(s)")
    if parsed.get("hashes"):
        parts.append(f"{len(parsed['hashes'])} hash(es)")
    if parsed.get("emails"):
        parts.append(f"{len(parsed['emails'])} email address(es)")
    if parsed.get("cves"):
        parts.append(f"{len(parsed['cves'])} CVE(s)")

    if parts:
        msg = "Evidence added — extracted " + ", ".join(parts) + ". Use the action buttons to process."
    else:
        msg = "Context noted. No IOCs detected in this message."

    timeline.append(case_id, "analyst", {"message": text})
    timeline.append(case_id, "system", {"message": msg})
    return {**parsed, "_message": msg}


def capture_urls(case_id: str, urls: list[str]) -> dict:
    """Run web capture on URLs."""
    def _do():
        from tools.web_capture import web_capture, web_capture_batch
        if len(urls) == 1:
            result = web_capture(urls[0], case_id)
        else:
            result = web_capture_batch(urls, case_id)

        # Build contextual message
        lines = [f"Captured {len(urls)} URL(s):"]
        for u in urls[:5]:
            lines.append(f"  {u}")
        if len(urls) > 5:
            lines.append(f"  ...and {len(urls) - 5} more")

        if isinstance(result, dict):
            if result.get("cloudflare_blocked"):
                lines.append("\nCloudflare blocked detected — page may be incomplete.")
            if result.get("redirect_chain"):
                chain = result["redirect_chain"]
                if len(chain) > 1:
                    lines.append(f"\nRedirect chain: {' → '.join(c.get('url', str(c)) if isinstance(c, dict) else str(c) for c in chain[:5])}")

        result = result if isinstance(result, dict) else {"captures": result}
        result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "web_capture", _do, urls=urls)


def triage(case_id: str, urls: list[str] | None = None) -> dict:
    """Run triage against IOC index."""
    def _do():
        from tools.triage import triage as _triage
        result = _triage(case_id, urls=urls)

        lines = []
        checked = result.get("iocs_checked", 0)
        lines.append(f"Triage checked {checked} IOC(s) against intelligence index.")

        mal = result.get("known_malicious", [])
        sus = result.get("known_suspicious", [])
        clean = result.get("known_clean", [])
        skip = result.get("skip_enrichment_iocs", [])

        if mal:
            lines.append(f"\n**Known malicious ({len(mal)}):**")
            for m in mal[:5]:
                ioc = m.get("ioc", m) if isinstance(m, dict) else m
                cases = m.get("cases", []) if isinstance(m, dict) else []
                lines.append(f"  {ioc}" + (f" (seen in {', '.join(cases[:3])})" if cases else ""))
        if sus:
            lines.append(f"\n**Known suspicious ({len(sus)}):**")
            for s in sus[:5]:
                ioc = s.get("ioc", s) if isinstance(s, dict) else s
                lines.append(f"  {ioc}")
        if not mal and not sus:
            lines.append("No known malicious or suspicious IOCs found in prior cases.")
        if skip:
            lines.append(f"\n{len(skip)} IOC(s) already well-covered in enrichment cache — can skip re-enrichment.")
        if result.get("escalate_severity"):
            lines.append(f"\nSeverity escalation recommended → {result['escalate_severity']}")

        result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "triage", _do)


def extract_and_enrich(case_id: str, include_private: bool = False) -> dict:
    """Extract IOCs, enrich, score verdicts, update IOC index."""
    def _do():
        from tools.extract_iocs import extract_iocs
        from tools.enrich import enrich
        from tools.score_verdicts import score_verdicts, update_ioc_index

        ioc_result = extract_iocs(case_id, include_private=include_private)
        enrich_result = enrich(case_id)
        verdict_result = score_verdicts(case_id)
        idx_result = update_ioc_index(case_id)

        # Build contextual summary
        ioc_total = ioc_result.get("total", 0)
        ioc_types = ioc_result.get("iocs", {})
        type_counts = {t: len(v) for t, v in ioc_types.items() if v and not t.startswith("_")}

        enriched = enrich_result.get("enriched", 0) if enrich_result else 0
        cached = enrich_result.get("cached", 0) if enrich_result else 0

        mal_count = len(verdict_result.get("high_priority", [])) if verdict_result else 0
        sus_count = len(verdict_result.get("needs_review", [])) if verdict_result else 0
        clean_count = len(verdict_result.get("clean", [])) if verdict_result else 0

        lines = [f"Extracted {ioc_total} IOC(s) from case artefacts."]
        if type_counts:
            breakdown = ", ".join(f"{c} {t}" for t, c in sorted(type_counts.items(), key=lambda x: -x[1]))
            lines.append(f"  Breakdown: {breakdown}")

        lines.append(f"\nEnriched across threat intelligence providers ({enriched} live lookups, {cached} cached).")
        lines.append(f"\nVerdict summary:")
        if mal_count:
            lines.append(f"  **{mal_count} malicious** — confirmed threats requiring action")
            if verdict_result:
                for item in verdict_result.get("high_priority", [])[:5]:
                    ioc = item.get("ioc", item) if isinstance(item, dict) else item
                    lines.append(f"    {ioc}")
        if sus_count:
            lines.append(f"  **{sus_count} suspicious** — needs further review")
            if verdict_result:
                for item in verdict_result.get("needs_review", [])[:3]:
                    ioc = item.get("ioc", item) if isinstance(item, dict) else item
                    lines.append(f"    {ioc}")
        if clean_count:
            lines.append(f"  {clean_count} clean")
        if not mal_count and not sus_count:
            lines.append("  No malicious or suspicious IOCs detected.")

        new_idx = idx_result.get("new", 0) if idx_result else 0
        recurring = idx_result.get("recurring", 0) if idx_result else 0
        if recurring:
            lines.append(f"\n{recurring} IOC(s) seen in prior investigations — recurring infrastructure.")

        return {
            "iocs_extracted": ioc_total,
            "enriched": enriched,
            "malicious": mal_count,
            "suspicious": sus_count,
            "clean": clean_count,
            "_message": "\n".join(lines),
        }

    return _run_action(case_id, "enrich", _do)


def detect_phishing(case_id: str) -> dict:
    """Run brand impersonation detection."""
    def _do():
        from tools.detect_phishing_page import detect_phishing_page
        result = detect_phishing_page(case_id)

        findings = result.get("findings", []) if isinstance(result, dict) else []
        if not findings:
            msg = "Phishing scan complete — no brand impersonation detected across captured pages."
        else:
            lines = [f"**Brand impersonation detected** — {len(findings)} finding(s):"]
            for f in findings[:5]:
                brand = f.get("brand", "unknown")
                host = f.get("hostname", f.get("url", ""))
                conf = f.get("confidence", "")
                lines.append(f"  {brand} impersonation on {host} (confidence: {conf})")
            msg = "\n".join(lines)

        if isinstance(result, dict):
            result["_message"] = msg
        else:
            result = {"findings": findings, "_message": msg}
        return result

    return _run_action(case_id, "detect_phishing", _do)


def correlate(case_id: str) -> dict:
    """Run IOC correlation."""
    def _do():
        from tools.correlate import correlate as _correlate
        result = _correlate(case_id)

        hit_summary = result.get("hit_summary", {}) if isinstance(result, dict) else {}
        timeline_events = result.get("timeline_events", 0) if isinstance(result, dict) else 0

        total_hits = sum(hit_summary.values()) if hit_summary else 0
        if total_hits:
            lines = [f"Correlation found {total_hits} hit(s) across artefacts:"]
            for hit_type, count in hit_summary.items():
                if count:
                    lines.append(f"  {hit_type}: {count}")
            if timeline_events:
                lines.append(f"\n{timeline_events} timeline events reconstructed.")
        else:
            lines = ["Correlation complete — no cross-artefact IOC hits found."]
            if timeline_events:
                lines.append(f"{timeline_events} timeline events reconstructed.")

        if isinstance(result, dict):
            result["_message"] = "\n".join(lines)
        else:
            result = {"_message": "\n".join(lines)}
        return result

    return _run_action(case_id, "correlate", _do)


def analyse_email(case_id: str, eml_paths: list[str]) -> dict:
    """Analyse email files."""
    def _do():
        from tools.analyse_email import analyse_email as _analyse
        results = []
        for path in eml_paths:
            results.append(_analyse(path, case_id))

        lines = [f"Analysed {len(results)} email file(s)."]
        for r in results:
            if not isinstance(r, dict):
                continue
            subj = r.get("subject", "")
            sender = r.get("from", r.get("sender", ""))
            urls_found = len(r.get("urls", []))
            attachments = len(r.get("attachments", []))
            spoofing = r.get("spoofing_signals", [])

            lines.append(f"\n  From: {sender}")
            if subj:
                lines.append(f"  Subject: {subj}")
            if urls_found:
                lines.append(f"  {urls_found} URL(s) extracted from email body")
            if attachments:
                lines.append(f"  {attachments} attachment(s) saved for analysis")

            # Auth results
            auth = r.get("authentication", {})
            if auth:
                spf = auth.get("spf", "")
                dkim = auth.get("dkim", "")
                dmarc = auth.get("dmarc", "")
                if spf or dkim or dmarc:
                    lines.append(f"  Auth: SPF={spf or '?'}, DKIM={dkim or '?'}, DMARC={dmarc or '?'}")

            if spoofing:
                lines.append(f"  **Spoofing signals detected:** {', '.join(str(s) for s in spoofing[:3])}")

        return {"emails_analysed": len(results), "_message": "\n".join(lines)}

    return _run_action(case_id, "analyse_email", _do)


def generate_report(case_id: str, close_case: bool = False) -> dict:
    """Generate investigation report."""
    def _do():
        from tools.generate_report import generate_report as _report
        from tools.index_case import index_case
        result = _report(case_id)
        status = "closed" if close_case else "open"
        index_case(case_id, status=status, report_path=result["report_path"])

        conf = result.get("confidence", "")
        score = result.get("score", 0)
        path = result.get("report_path", "")

        msg = f"Investigation report generated (confidence: {conf}, score: {score:.2f})."
        if close_case:
            msg += "\nCase marked as closed."
        if path:
            msg += md_file_note(path)
        result["_message"] = msg
        return result

    return _run_action(case_id, "generate_report", _do)


def generate_fp_ticket(case_id: str, alert_data: str,
                       platform: str | None = None,
                       query_text: str | None = None) -> dict:
    """Generate FP suppression ticket."""
    def _do():
        from tools.fp_ticket import fp_ticket
        result = fp_ticket(case_id, alert_data=alert_data,
                           platform=platform, query_text=query_text)

        if result.get("status") == "ok":
            ticket_path = result.get('ticket_path', '')
            result["_message"] = f"FP suppression ticket generated.\nPlatform: {result.get('platform', 'auto-detected')}" + md_file_note(ticket_path)
        elif result.get("status") == "needs_clarification":
            result["_message"] = f"Need more information to generate FP ticket:\n{result.get('question', '')}"
        else:
            result["_message"] = f"FP ticket generation: {result.get('reason', result.get('status', 'unknown'))}"
        return result

    return _run_action(case_id, "fp_ticket", _do,
                       platform=platform or "auto-detect")


def generate_fp_tuning_ticket(case_id: str, alert_data: str,
                              platform: str | None = None,
                              query_text: str | None = None) -> dict:
    """Generate SIEM engineering tuning ticket."""
    def _do():
        from tools.fp_tuning_ticket import fp_tuning_ticket
        result = fp_tuning_ticket(case_id, alert_data=alert_data,
                                  platform=platform, query_text=query_text)

        if result.get("status") == "ok":
            ticket_path = result.get('ticket_path', '')
            result["_message"] = f"SIEM tuning ticket generated." + md_file_note(ticket_path)
        elif result.get("status") == "needs_clarification":
            result["_message"] = f"Need more information to generate tuning ticket:\n{result.get('question', '')}"
        else:
            result["_message"] = f"Tuning ticket generation: {result.get('reason', result.get('status', 'unknown'))}"
        return result

    return _run_action(case_id, "fp_tuning_ticket", _do,
                       platform=platform or "auto-detect")


def generate_queries(case_id: str,
                     platforms: list[str] | None = None,
                     tables: list[str] | None = None) -> dict:
    """Generate SIEM hunt queries."""
    def _do():
        from tools.generate_queries import generate_queries as _queries
        result = _queries(case_id, platforms=platforms, tables=tables)

        if result.get("status") == "no_iocs":
            result["_message"] = "No IOCs available — run enrichment first to extract IOCs."
            return result

        plats = result.get("platforms", [])
        ioc_counts = result.get("ioc_counts", {})
        patterns = result.get("patterns", [])

        lines = [f"SIEM hunt queries generated for: {', '.join(plats) if plats else 'all platforms'}"]
        if ioc_counts:
            lines.append(f"IOCs covered: {', '.join(f'{c} {t}' for t, c in ioc_counts.items() if c)}")
        if patterns:
            lines.append(f"Threat patterns detected: {', '.join(patterns[:5])}")
        lines.append(f"\nQuery file: {result.get('query_path', '')}")

        result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "generate_queries", _do)


def run_campaign_cluster(case_id: str) -> dict:
    """Run cross-case campaign clustering."""
    def _do():
        from tools.campaign_cluster import campaign_cluster
        result = campaign_cluster(case_id)

        campaigns = result.get("campaigns", []) if isinstance(result, dict) else []
        if not campaigns:
            msg = "Campaign clustering complete — no cross-case campaigns detected for this case's IOCs."
        else:
            lines = [f"Found {len(campaigns)} campaign(s) linked to this case:"]
            for c in campaigns[:5]:
                cid = c.get("campaign_id", "?")
                members = c.get("cases", [])
                shared = c.get("shared_iocs", [])
                conf = c.get("confidence", "")
                lines.append(f"\n  {cid} ({conf} confidence)")
                lines.append(f"    Cases: {', '.join(members[:5])}")
                if shared:
                    lines.append(f"    Shared IOCs: {', '.join(str(s) for s in shared[:5])}")
            msg = "\n".join(lines)

        if isinstance(result, dict):
            result["_message"] = msg
        else:
            result = {"_message": msg}
        return result

    return _run_action(case_id, "campaign_cluster", _do)


def security_arch_review(case_id: str) -> dict:
    """Run LLM security architecture review."""
    def _do():
        from tools.security_arch_review import security_arch_review as _review
        result = _review(case_id)

        if result.get("status") == "skipped":
            result["_message"] = f"Security architecture review skipped: {result.get('reason', '')}"
        elif result.get("status") == "error":
            result["_message"] = f"Security architecture review error: {result.get('reason', '')}"
        else:
            msg = "Security architecture review complete."
            tokens = result.get("tokens_input", 0) + result.get("tokens_output", 0)
            if tokens:
                msg += f"\nLLM tokens used: {tokens:,}"
            if result.get("review_path"):
                msg += md_file_note(result["review_path"])
            result["_message"] = msg
        return result

    return _run_action(case_id, "security_arch", _do)


def reconstruct_timeline(case_id: str) -> dict:
    """Reconstruct forensic timeline from case artefacts."""
    def _do():
        from tools.timeline_reconstruct import timeline_reconstruct
        result = timeline_reconstruct(case_id)
        events = result.get("total_events", 0)
        llm = result.get("llm_analysis", False)
        msg = f"Timeline reconstructed — {events} event(s) assembled"
        if llm:
            msg += " with LLM narrative analysis."
        else:
            msg += "."
        result["_message"] = msg
        return result

    return _run_action(case_id, "timeline_reconstruct", _do)


def analyse_pe_files(case_id: str) -> dict:
    """Run deep PE file analysis."""
    def _do():
        from tools.pe_analysis import pe_deep_analyse
        result = pe_deep_analyse(case_id)
        files = result.get("files", [])
        if not files:
            result["_message"] = "No PE files found in case artefacts."
        else:
            lines = [f"Analysed {len(files)} PE file(s):"]
            for f in files[:5]:
                name = f.get("filename", "?")
                entropy = f.get("overall_entropy", 0)
                suspicious = len(f.get("suspicious_imports", []))
                packer = f.get("packer", "none")
                lines.append(f"  {name} — entropy: {entropy:.2f}, suspicious imports: {suspicious}, packer: {packer}")
            result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "pe_analysis", _do)


def yara_scan_action(case_id: str, generate_rules: bool = False) -> dict:
    """Run YARA scan on case files."""
    def _do():
        from tools.yara_scan import yara_scan
        result = yara_scan(case_id, generate_rules=generate_rules)
        matches = result.get("total_matches", 0)
        scanned = result.get("files_scanned", 0)
        if matches:
            lines = [f"YARA: {matches} match(es) across {scanned} file(s):"]
            for m in result.get("matches", [])[:10]:
                lines.append(f"  {m.get('rule', '?')} → {m.get('file', '?')}")
            result["_message"] = "\n".join(lines)
        else:
            result["_message"] = f"YARA scan complete — no matches across {scanned} file(s)."
        return result

    return _run_action(case_id, "yara_scan", _do)


def correlate_event_logs(case_id: str) -> dict:
    """Correlate Windows Event Log attack chains."""
    def _do():
        from tools.evtx_correlate import evtx_correlate
        result = evtx_correlate(case_id)
        chains = result.get("chains", [])
        if not chains:
            result["_message"] = "EVTX correlation complete — no attack chains detected."
        else:
            lines = [f"Detected {len(chains)} attack chain(s):"]
            for c in chains[:10]:
                chain_type = c.get("chain", "?")
                severity = c.get("severity", "?")
                lines.append(f"  [{severity}] {chain_type}")
                if c.get("source_ip"):
                    lines.append(f"    Source: {c['source_ip']} → {c.get('target_user', '?')}")
            result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "evtx_correlate", _do)


def contextualise_cves(case_id: str) -> dict:
    """Contextualise CVEs found in case artefacts."""
    def _do():
        from tools.cve_contextualise import cve_contextualise
        result = cve_contextualise(case_id)
        cves = result.get("cves", [])
        if not cves:
            result["_message"] = "No CVE identifiers found in case artefacts."
        else:
            lines = [f"Contextualised {len(cves)} CVE(s):"]
            kev_count = result.get("cves_in_kev", 0)
            highest = result.get("highest_cvss", 0)
            if kev_count:
                lines.append(f"  **{kev_count} in CISA Known Exploited Vulnerabilities catalog**")
            lines.append(f"  Highest CVSS: {highest:.1f}")
            for c in cves[:5]:
                cve_id = c.get("cve_id", "?")
                cvss = c.get("nvd", {}).get("cvss_score", "?")
                epss = c.get("epss", {}).get("score", "?")
                kev = "KEV" if c.get("cisa_kev") else ""
                lines.append(f"  {cve_id} — CVSS: {cvss}, EPSS: {epss} {kev}")
            result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "cve_contextualise", _do)


def generate_exec_summary(case_id: str) -> dict:
    """Generate executive summary for leadership."""
    def _do():
        from tools.executive_summary import executive_summary
        result = executive_summary(case_id)
        if result.get("status") == "ok":
            rating = result.get("risk_rating", "?")
            result["_message"] = f"Executive summary generated (risk: **{rating}**)." + md_file_note(result.get('summary_path', ''))
        elif result.get("status") == "skipped":
            result["_message"] = f"Executive summary skipped: {result.get('reason', '')}"
        else:
            result["_message"] = f"Executive summary: {result.get('reason', result.get('status', 'unknown'))}"
        return result

    return _run_action(case_id, "executive_summary", _do)


def run_full_pipeline(case_id: str, kwargs: dict) -> dict:
    """Run the full ChiefAgent pipeline."""
    def _do():
        from agents.chief import ChiefAgent
        result = ChiefAgent(case_id).run(**kwargs)

        ok = sum(1 for s in result.get("steps", []) if s.get("status") == "ok")
        errors = len(result.get("errors", []))
        report = result.get("report", {})
        report_path = report.get("report_path", "") if report else ""

        lines = [f"Full pipeline complete — {ok} step(s) succeeded, {errors} error(s)."]
        if report_path:
            lines.append(f"Report: {report_path}")
        if errors:
            lines.append("\nErrors:")
            for e in result.get("errors", [])[:5]:
                lines.append(f"  {e.get('step', '?')}: {e.get('error', '?')}")

        result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "full_pipeline", _do)


def ingest_velociraptor(case_id: str, run_analysis: bool = True) -> dict:
    """Ingest Velociraptor collection results from case uploads directory."""
    def _do():
        from tools.velociraptor_ingest import velociraptor_ingest

        # Look for Velociraptor files in uploads/
        uploads_dir = CASES_DIR / case_id / "uploads"
        if not uploads_dir.exists():
            return {"_message": "No uploads directory found — upload Velociraptor files first."}

        # Find eligible files (ZIP or VQL exports)
        vr_files = sorted(
            f for f in uploads_dir.iterdir()
            if f.is_file() and f.suffix.lower() in (".zip", ".json", ".csv", ".jsonl")
        )
        if not vr_files:
            return {"_message": "No Velociraptor-compatible files found in uploads (ZIP, JSON, CSV)."}

        all_results = []
        total_artefacts = 0
        total_rows = 0
        total_raw = 0

        for vr_file in vr_files:
            result = velociraptor_ingest(str(vr_file), case_id)
            all_results.append(result)
            m = result.get("manifest", {})
            total_artefacts += m.get("total_vql_artefacts", 0)
            total_rows += m.get("total_rows_ingested", 0)
            total_raw += m.get("total_raw_files", 0)

        lines = [
            f"Ingested {len(vr_files)} file(s) — "
            f"{total_artefacts} VQL artefact(s), "
            f"{total_rows} row(s), "
            f"{total_raw} raw file(s)."
        ]

        if run_analysis:
            lines.append("\nRunning analysis pipeline...")
            from tools.extract_iocs import extract_iocs
            from tools.enrich import enrich
            from tools.score_verdicts import score_verdicts, update_ioc_index
            from tools.correlate import correlate

            extract_iocs(case_id)
            enrich_result = enrich(case_id)
            score_verdicts(case_id)
            update_ioc_index(case_id)
            correlate(case_id)

            try:
                from tools.evtx_correlate import evtx_correlate
                evtx_result = evtx_correlate(case_id)
                chains = evtx_result.get("chains", [])
                if chains:
                    lines.append(f"EVTX: {len(chains)} attack chain(s) detected")
            except Exception:
                pass

            try:
                from tools.detect_anomalies import detect_anomalies
                detect_anomalies(case_id)
            except Exception:
                pass

            try:
                from tools.timeline_reconstruct import timeline_reconstruct
                timeline_reconstruct(case_id)
            except Exception:
                pass

            lines.append("Analysis pipeline complete.")

        return {
            "files_processed": len(vr_files),
            "total_artefacts": total_artefacts,
            "total_rows": total_rows,
            "total_raw_files": total_raw,
            "_message": "\n".join(lines),
        }

    return _run_action(case_id, "ingest_velociraptor", _do)


def ingest_mde_package(case_id: str, run_analysis: bool = True) -> dict:
    """Ingest MDE investigation package from case uploads directory."""
    def _do():
        from tools.mde_ingest import mde_ingest

        uploads_dir = CASES_DIR / case_id / "uploads"
        if not uploads_dir.exists():
            return {"_message": "No uploads directory found — upload an MDE investigation package ZIP first."}

        zip_files = sorted(
            f for f in uploads_dir.iterdir()
            if f.is_file() and f.suffix.lower() == ".zip"
        )
        if not zip_files:
            return {"_message": "No ZIP files found in uploads."}

        all_results = []
        total_artefacts = 0
        total_rows = 0
        total_raw = 0

        for zf in zip_files:
            result = mde_ingest(str(zf), case_id)
            if result.get("status") != "ok":
                continue
            all_results.append(result)
            m = result.get("manifest", {})
            total_artefacts += m.get("total_artefacts", 0)
            total_rows += m.get("total_rows_ingested", 0)
            total_raw += m.get("total_raw_files", 0)

        if not all_results:
            return {"_message": "No valid MDE investigation packages found in uploads."}

        lines = [
            f"Ingested {len(all_results)} MDE package(s) — "
            f"{total_artefacts} artefact(s), "
            f"{total_rows} row(s), "
            f"{total_raw} raw file(s)."
        ]

        if run_analysis:
            lines.append("\nRunning analysis pipeline...")
            from tools.extract_iocs import extract_iocs
            from tools.enrich import enrich
            from tools.score_verdicts import score_verdicts, update_ioc_index
            from tools.correlate import correlate

            extract_iocs(case_id)
            enrich(case_id)
            score_verdicts(case_id)
            update_ioc_index(case_id)
            correlate(case_id)

            try:
                from tools.evtx_correlate import evtx_correlate
                evtx_result = evtx_correlate(case_id)
                chains = evtx_result.get("chains", [])
                if chains:
                    lines.append(f"EVTX: {len(chains)} attack chain(s) detected")
            except Exception:
                pass

            try:
                from tools.detect_anomalies import detect_anomalies
                detect_anomalies(case_id)
            except Exception:
                pass

            try:
                from tools.timeline_reconstruct import timeline_reconstruct
                timeline_reconstruct(case_id)
            except Exception:
                pass

            lines.append("Analysis pipeline complete.")

        return {
            "packages_processed": len(all_results),
            "total_artefacts": total_artefacts,
            "total_rows": total_rows,
            "total_raw_files": total_raw,
            "_message": "\n".join(lines),
        }

    return _run_action(case_id, "ingest_mde_package", _do)


def memory_dump_guide(
    case_id: str,
    process_name: str = "",
    pid: str = "",
    alert_title: str = "",
    hostname: str = "",
) -> dict:
    """Generate memory dump collection guidance."""
    def _do():
        from tools.memory_guidance import generate_dump_guidance

        result = generate_dump_guidance(
            case_id,
            process_name=process_name,
            pid=pid,
            alert_title=alert_title,
            hostname=hostname,
        )

        # Read the guidance file to return content
        guidance_path = result.get("guidance_path", "")
        try:
            from pathlib import Path
            content = Path(guidance_path).read_text()
        except Exception:
            content = ""

        return {
            "guidance_path": guidance_path,
            "_message": content or "Guidance generated — see artefacts/memory/dump_guidance.md",
        }

    return _run_action(case_id, "memory_dump_guide", _do)


def analyse_memory_dump_action(case_id: str, run_analysis: bool = True) -> dict:
    """Analyse memory dump(s) from case uploads directory."""
    def _do():
        from tools.memory_guidance import analyse_memory_dump

        uploads_dir = CASES_DIR / case_id / "uploads"
        if not uploads_dir.exists():
            return {"_message": "No uploads directory found — upload a .dmp file first."}

        dump_files = sorted(
            f for f in uploads_dir.iterdir()
            if f.is_file() and f.suffix.lower() in (".dmp", ".dump", ".raw", ".bin")
        )
        if not dump_files:
            return {"_message": "No memory dump files found in uploads (.dmp, .dump, .raw, .bin)."}

        all_results = []
        for df in dump_files:
            result = analyse_memory_dump(str(df), case_id)
            if result.get("status") == "ok":
                all_results.append(result)

        if not all_results:
            return {"_message": "No valid memory dumps could be analysed."}

        lines = [f"Analysed {len(all_results)} dump file(s):"]
        for r in all_results:
            risk = r.get("risk_indicators", {})
            lines.append(
                f"  • {Path(r['source']).name}: "
                f"{r.get('strings_extracted', 0)} strings, "
                f"risk={risk.get('level', 'unknown').upper()}"
            )
            if risk.get("reasons"):
                for reason in risk["reasons"]:
                    lines.append(f"    — {reason}")

        if run_analysis:
            lines.append("\nRunning IOC enrichment...")
            from tools.extract_iocs import extract_iocs
            from tools.enrich import enrich
            from tools.score_verdicts import score_verdicts, update_ioc_index

            extract_iocs(case_id)
            enrich(case_id)
            score_verdicts(case_id)
            update_ioc_index(case_id)
            lines.append("Enrichment complete.")

        return {
            "dumps_analysed": len(all_results),
            "_message": "\n".join(lines),
        }

    return _run_action(case_id, "analyse_memory_dump", _do)


def parse_logs_action(case_id: str) -> dict:
    """Parse log files from case uploads directory."""
    def _do():
        from tools.parse_logs import parse_logs

        uploads_dir = CASES_DIR / case_id / "uploads"
        if not uploads_dir.exists():
            return {"_message": "No uploads directory found — upload log files first."}

        log_exts = {".csv", ".json", ".jsonl", ".log", ".txt"}
        log_files = sorted(
            f for f in uploads_dir.iterdir()
            if f.is_file() and f.suffix.lower() in log_exts
        )
        if not log_files:
            return {"_message": f"No log files found in uploads ({', '.join(log_exts)})."}

        all_results = []
        for lf in log_files:
            result = parse_logs(lf, case_id)
            all_results.append(result)

        total_rows = sum(r.get("row_count", 0) for r in all_results)
        lines = [f"Parsed {len(all_results)} log file(s), {total_rows} total row(s):"]
        for r in all_results:
            lines.append(
                f"  • {Path(r.get('source_file', '?')).name}: "
                f"{r.get('row_count', 0)} rows, format={r.get('format', '?')}"
            )

        return {
            "files_parsed": len(all_results),
            "total_rows": total_rows,
            "_message": "\n".join(lines),
        }

    return _run_action(case_id, "parse_logs", _do)


def detect_anomalies_action(case_id: str) -> dict:
    """Run behavioural anomaly detection on parsed logs."""
    def _do():
        from tools.detect_anomalies import detect_anomalies
        result = detect_anomalies(case_id)

        findings = result.get("findings", [])
        if not findings:
            result["_message"] = "Anomaly detection complete — no anomalies found."
        else:
            lines = [f"Detected {len(findings)} anomaly(ies):"]
            type_counts = result.get("type_counts", {})
            for atype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  {atype}: {count}")
            result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "detect_anomalies", _do)


def pe_analysis_action(case_id: str) -> dict:
    """Run deep PE analysis on case artefacts."""
    def _do():
        from tools.pe_analysis import pe_deep_analyse
        result = pe_deep_analyse(case_id)

        files = result.get("files", [])
        if not files:
            result["_message"] = result.get("reason", "No PE files found to analyse.")
        else:
            lines = [f"Analysed {len(files)} PE file(s):"]
            for f in files:
                flagged = len(f.get("flagged_apis", []))
                packed = bool(f.get("packer_signatures"))
                ent = f.get("overall_entropy", 0)
                lines.append(
                    f"  • {f.get('filename', '?')}: "
                    f"entropy={ent:.2f}, flagged_apis={flagged}"
                    + (", PACKED" if packed else "")
                )
            result["_message"] = "\n".join(lines)
        return result

    return _run_action(case_id, "pe_analysis", _do)


# ---------------------------------------------------------------------------
# Rumsfeld investigation pipeline actions
# ---------------------------------------------------------------------------

def generate_investigation_matrix(case_id: str) -> dict:
    """Generate or regenerate the investigation reasoning matrix."""
    from tools.investigation_matrix import generate_matrix
    return _run_action(case_id, "investigation_matrix",
                       lambda: generate_matrix(case_id) or {"status": "no_result"})


def review_report_quality(case_id: str) -> dict:
    """Run the report quality gate."""
    from tools.report_quality_gate import review_report
    return _run_action(case_id, "quality_gate",
                       lambda: review_report(case_id) or {"status": "no_report"})


def run_determination(case_id: str) -> dict:
    """Run evidence-chain determination analysis."""
    from tools.determination import llm_determine
    return _run_action(case_id, "determination",
                       lambda: llm_determine(case_id) or {"status": "no_result"})


def get_matrix_summary(case_id: str) -> dict:
    """Return compact investigation matrix summary."""
    from tools.investigation_matrix import get_matrix_summary as _summary
    result = _summary(case_id)
    if not result:
        return {"status": "not_found", "case_id": case_id}
    return result


def list_followup_proposals(case_id: str) -> dict:
    """List follow-up proposals for a case."""
    from agents.rumsfeld import list_proposals
    proposals = list_proposals(case_id)
    return {"case_id": case_id, "proposals": proposals, "count": len(proposals)}


def execute_followup_proposal(case_id: str, proposal_id: str) -> dict:
    """Execute a single approved follow-up proposal."""
    from agents.rumsfeld import execute_followup
    return _run_action(case_id, f"followup.{proposal_id}",
                       lambda: execute_followup(case_id, proposal_id))


def run_full_rumsfeld_pipeline(case_id: str, **kwargs) -> dict:
    """Run the full Rumsfeld investigation pipeline."""
    from agents.rumsfeld import RumsfeldAgent
    return _run_action(case_id, "rumsfeld_pipeline",
                       lambda: RumsfeldAgent(case_id).run(**kwargs))
