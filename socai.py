#!/usr/bin/env python3
"""
SOC-AI  –  Local Multi-Agent SOC Automation
============================================

Usage examples:

  # Just generate a weekly report
  python socai.py weekly --year 2026 --week 08 --include-open

  # Re-run report for existing case
  python socai.py report --case IV_CASE_001

  # Close a case
  python socai.py close --case IV_CASE_001

  # List registered cases
  python socai.py list

  # Ad-hoc client query — no case created, stdout only
  python socai.py client-query --prompt "Was folder 2026 created on AFGRICENTFNP03?"
  python socai.py client-query --prompt "..." --platforms kql --tables DeviceFileEvents DeviceEvents

  # All subcommands: python socai.py --help
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# Ensure repo root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config.settings import REGISTRY_FILE


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=level,
    )


def _read_lines(path: str | None) -> list[str]:
    """Read non-blank lines from a file path."""
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        print(f"[warn] File not found: {path}")
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip()]


def _glob_logs(log_arg: str | None) -> list[str]:
    """Accept a directory, a glob, or a single file."""
    if not log_arg:
        return []
    p = Path(log_arg)
    if p.is_dir():
        found = list(p.glob("*.csv")) + list(p.glob("*.json")) + list(p.glob("*.log"))
        return [str(f) for f in found]
    if p.is_file():
        return [str(p)]
    # Glob
    import glob
    return glob.glob(log_arg)


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_create_case(args: argparse.Namespace) -> None:
    from tools.case_create import case_create, next_case_id
    case_id = args.case or next_case_id()
    tags = [t.strip() for t in args.tags.split(",")] if args.tags else None
    result = case_create(
        case_id,
        title=args.title or "",
        severity=args.severity,
        analyst=args.analyst,
        tags=tags,
        client=args.client or "",
    )
    print(f"Case {result['case_id']} created at cases/{result['case_id']}/")
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_report(args: argparse.Namespace) -> None:
    from tools.generate_report import generate_report
    result = generate_report(args.case)
    print(f"Report: {result['report_path']}")
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_weekly(args: argparse.Namespace) -> None:
    from tools.generate_weekly_report import generate_weekly_report
    result = generate_weekly_report(
        year=args.year, week=args.week, include_open=args.include_open
    )
    print(f"Weekly report: {result['report_path']}")
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_close(args: argparse.Namespace) -> None:
    from tools.index_case import index_case
    result = index_case(args.case, status="closed")
    print(f"Case {args.case} closed.")
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_list(args: argparse.Namespace) -> None:
    if not REGISTRY_FILE.exists():
        print("No registry found.")
        return
    from tools.common import load_json
    registry = load_json(REGISTRY_FILE)
    cases = registry.get("cases", {})
    if not cases:
        print("No cases registered.")
        return
    print(f"{'Case ID':<15} {'Severity':<10} {'Status':<12} {'Title'}")
    print("-" * 70)
    for cid, meta in sorted(cases.items()):
        print(f"{cid:<15} {meta.get('severity','?'):<10} {meta.get('status','?'):<12} {meta.get('title','?')}")


def cmd_enrich(args: argparse.Namespace) -> None:
    from tools.extract_iocs import extract_iocs
    from tools.enrich import enrich
    extract_iocs(args.case)
    result = enrich(args.case)
    print(f"Enrichment complete: {result.get('total_lookups',0)} lookup(s)")
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_client_query(args: argparse.Namespace) -> None:
    print("Ad-hoc queries are now handled directly by the local Claude Desktop agent.")
    print("Ask your question in the Claude Desktop conversation instead.")


def cmd_mdr_report(args: argparse.Namespace) -> None:
    print("MDR report generation now uses the local Claude Desktop agent.")
    print(f"Use the write_mdr_report MCP prompt for case {args.case},")
    print('then call save_report with report_type="mdr_report" to persist it.')


def cmd_pup_report(args: argparse.Namespace) -> None:
    print("PUP/PUA report generation now uses the local Claude Desktop agent.")
    print(f"Use the write_pup_report MCP prompt for case {args.case},")
    print('then call save_report with report_type="pup_report" to persist it.')


def cmd_secarch(args: argparse.Namespace) -> None:
    print("Security architecture review now uses the local Claude Desktop agent.")
    print(f"Use the write_security_arch_review MCP prompt for case {args.case},")
    print('then call save_report with report_type="security_arch_review" to persist it.')


def cmd_queries(args: argparse.Namespace) -> None:
    from tools.generate_queries import generate_queries
    result = generate_queries(
        args.case,
        platforms=args.platforms or ["kql", "splunk", "logscale"],
        tables=args.tables or None,
    )
    if result.get("status") == "no_iocs":
        print(f"[warn] {result['message']}")
        return
    print(f"Hunt queries: {result['query_path']}")
    if result.get("patterns"):
        print(f"Threat patterns detected: {', '.join(result['patterns'])}")
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_triage(args: argparse.Namespace) -> None:
    from tools.triage import triage
    result = triage(args.case, urls=args.url or [], severity=args.severity)
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_email_analyse(args: argparse.Namespace) -> None:
    from tools.analyse_email import analyse_email
    for eml_path in args.eml:
        result = analyse_email(eml_path, args.case)
        if args.json:
            print(json.dumps(result, indent=2))


def cmd_landscape(args: argparse.Namespace) -> None:
    from tools.case_landscape import assess_landscape
    result = assess_landscape(
        days=getattr(args, "days", None),
        client=getattr(args, "client", None),
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(result.get("summary", "No data."))


def cmd_campaigns(args: argparse.Namespace) -> None:
    from tools.campaign_cluster import cluster_campaigns
    result = cluster_campaigns(case_id=getattr(args, "case", None))
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_errors(args: argparse.Namespace) -> None:
    from tools.assess_errors import assess_errors, clear_error_log
    result = assess_errors(top_n=args.top, severity_filter=args.severity,
                           json_output=args.json)
    if args.json:
        print(json.dumps(result, indent=2))
    if args.clear:
        cleared = clear_error_log()
        print(f"Cleared {cleared['cleared']} error records.")


def cmd_mcp_usage(args: argparse.Namespace) -> None:
    from tools.mcp_usage import assess_mcp_usage, clear_mcp_usage_log
    result = assess_mcp_usage(
        top_n=args.top, caller_filter=args.caller,
        tool_filter=args.tool, json_output=args.json,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    if args.clear:
        cleared = clear_mcp_usage_log()
        print(f"Cleared {cleared['cleared']} usage records.")


def cmd_sandbox(args: argparse.Namespace) -> None:
    from tools.sandbox_analyse import sandbox_analyse
    result = sandbox_analyse(args.case, detonate=args.detonate)
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_anomalies(args: argparse.Namespace) -> None:
    from tools.detect_anomalies import detect_anomalies
    result = detect_anomalies(args.case)
    if args.json:
        print(json.dumps(result, indent=2))


def cmd_timeline(args: argparse.Namespace) -> None:
    from tools.timeline_reconstruct import timeline_reconstruct
    result = timeline_reconstruct(args.case)
    if result.get("status") == "ok":
        print(f"Timeline: {result.get('total_events', 0)} events reconstructed")
    else:
        print(f"[timeline] {result.get('status', '?')}: {result.get('reason', '')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_pe_analysis(args: argparse.Namespace) -> None:
    from tools.pe_analysis import pe_deep_analyse
    result = pe_deep_analyse(args.case)
    if result.get("status") == "ok":
        files = result.get("files", [])
        print(f"PE analysis: {len(files)} file(s) analysed")
    else:
        print(f"[pe-analysis] {result.get('status', '?')}: {result.get('reason', '')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_yara(args: argparse.Namespace) -> None:
    from tools.yara_scan import yara_scan
    result = yara_scan(args.case, generate_rules=args.generate_rules)
    if result.get("status") == "ok":
        print(f"YARA scan: {result.get('total_matches', 0)} match(es) across {result.get('files_scanned', 0)} file(s)")
    else:
        print(f"[yara] {result.get('status', '?')}: {result.get('reason', '')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_evtx(args: argparse.Namespace) -> None:
    from tools.evtx_correlate import evtx_correlate
    result = evtx_correlate(args.case)
    if result.get("status") == "ok":
        chains = result.get("chains", [])
        print(f"EVTX correlation: {len(chains)} attack chain(s) detected")
    else:
        print(f"[evtx] {result.get('status', '?')}: {result.get('reason', '')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_cve_context(args: argparse.Namespace) -> None:
    from tools.cve_contextualise import cve_contextualise
    result = cve_contextualise(args.case)
    if result.get("status") == "ok":
        print(f"CVE context: {result.get('total_cves', 0)} CVE(s), {result.get('cves_in_kev', 0)} in CISA KEV")
    else:
        print(f"[cve-context] {result.get('status', '?')}: {result.get('reason', '')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_exec_summary(args: argparse.Namespace) -> None:
    print("Executive summary generation now uses the local Claude Desktop agent.")
    print(f"Use the write_executive_summary MCP prompt for case {args.case},")
    print('then call save_report with report_type="executive_summary" to persist it.')


def cmd_response_actions(args: argparse.Namespace) -> None:
    from tools.response_actions import generate_response_actions
    result = generate_response_actions(args.case)
    status = result.get("status", "unknown")
    if status == "ok":
        print(f"Response actions: priority={result['priority']} "
              f"(source={result['priority_source']})")
    else:
        print(f"[response-actions] {status}: {result.get('reason', '')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_fp_ticket(args: argparse.Namespace) -> None:
    from agents.fp_comms_agent import FPCommsAgent

    if args.alert:
        alert_data = Path(args.alert).read_text(encoding="utf-8")
    elif args.alert_text:
        alert_data = args.alert_text
    else:
        print("[error] Provide --alert <file> or --alert-text <string>")
        sys.exit(1)

    query_text = None
    if args.query:
        query_text = Path(args.query).read_text(encoding="utf-8")
    elif args.query_text:
        query_text = args.query_text

    result = FPCommsAgent(args.case).run(
        alert_data=alert_data,
        query_text=query_text,
        platform=args.platform,
        live_query=args.live_query,
    )

    status = result.get("status", "unknown")
    if status == "ok":
        print(f"FP ticket: {result['ticket_path']}")
        if args.json:
            print(json.dumps(result, indent=2, default=str))
    elif status == "needs_clarification":
        print(f"[fp-ticket] Platform unclear — analyst input required:")
        print(f"  {result.get('question', '')}")
        print("\nRe-run with --platform <sentinel|crowdstrike|defender|entra|cloudapps>")
        sys.exit(2)
    else:
        print(f"[fp-ticket] {status}: {result.get('reason', '')}")
        if args.json:
            print(json.dumps(result, indent=2, default=str))


def cmd_fp_tuning(args: argparse.Namespace) -> None:
    from agents.fp_tuning_agent import FPTuningAgent

    if args.alert:
        alert_data = Path(args.alert).read_text(encoding="utf-8")
    elif args.alert_text:
        alert_data = args.alert_text
    else:
        print("[error] Provide --alert <file> or --alert-text <string>")
        sys.exit(1)

    query_text = None
    if args.query:
        query_text = Path(args.query).read_text(encoding="utf-8")
    elif args.query_text:
        query_text = args.query_text

    result = FPTuningAgent(args.case).run(
        alert_data=alert_data,
        query_text=query_text,
        platform=args.platform,
        live_query=args.live_query,
    )

    status = result.get("status", "unknown")
    if status == "ok":
        print(f"Tuning ticket: {result['ticket_path']}")
        if args.json:
            print(json.dumps(result, indent=2, default=str))
    elif status == "needs_clarification":
        print(f"[fp-tuning] Information missing — analyst input required:")
        print(f"  {result.get('question', '')}")
        print("\nRe-run with --platform <sentinel|crowdstrike|defender|entra|cloudapps|splunk>")
        sys.exit(2)
    else:
        print(f"[fp-tuning] {status}: {result.get('reason', '')}")
        if args.json:
            print(json.dumps(result, indent=2, default=str))


def _next_case_id() -> str:
    """Generate the next sequential case ID from the registry."""
    from tools.case_create import next_case_id
    return next_case_id()


def cmd_matrix(args: argparse.Namespace) -> None:
    from tools.investigation_matrix import generate_matrix, get_matrix_summary, load_matrix

    if args.summary:
        summary = get_matrix_summary(args.case)
        if summary:
            print(json.dumps(summary, indent=2, default=str))
        else:
            print(f"No matrix found for {args.case}")
        return

    # Generate or reload matrix
    matrix = load_matrix(args.case) if not args.regenerate else None
    if not matrix:
        matrix = generate_matrix(args.case)

    if matrix and args.json:
        print(json.dumps(matrix, indent=2, default=str))
    elif matrix:
        kk = len(matrix.get("known_knowns", []))
        ku = len(matrix.get("known_unknowns", []))
        hyp = len(matrix.get("hypotheses", []))
        print(f"\nInvestigation Matrix for {args.case}")
        print(f"  Known:     {kk}")
        print(f"  Unknown:   {ku}")
        print(f"  Hypotheses: {hyp}")
        for ku_item in matrix.get("known_unknowns", []):
            status = "✓" if ku_item.get("resolution") else "○"
            print(f"    {status} [{ku_item.get('priority', '?')}] {ku_item.get('question', 'N/A')}")
    else:
        print(f"Failed to generate matrix for {args.case}")


def cmd_followup(args: argparse.Namespace) -> None:
    from tools.followup import execute_followup, list_proposals

    proposals = list_proposals(args.case)
    if not proposals:
        print(f"No follow-up proposals for {args.case}")
        return

    if args.approve:
        result = execute_followup(args.case, args.approve)
        print(json.dumps(result, indent=2, default=str))
    elif args.approve_all:
        for p in proposals:
            pid = p.get("id", "")
            if p.get("status") != "executed":
                print(f"\nExecuting {pid}: {p.get('action', '')}")
                result = execute_followup(args.case, pid)
                status = result.get("status", "unknown")
                print(f"  → {status}")
    else:
        # List proposals
        print(f"\nFollow-up proposals for {args.case}:")
        for p in proposals:
            status = p.get("status", "pending")
            icon = "✓" if status == "executed" else "○"
            print(f"  {icon} {p.get('id', '?')} [{p.get('priority', '?')}] "
                  f"{p.get('action', 'N/A')}")
            print(f"      Tool: {p.get('tool', 'N/A')} | "
                  f"Resolves: {p.get('resolves', 'N/A')}")
            if p.get("reasoning"):
                print(f"      Reason: {p['reasoning'][:100]}")


def cmd_quality_gate(args: argparse.Namespace) -> None:
    from tools.report_quality_gate import review_report

    result = review_report(args.case)
    if not result:
        print(f"No report found for {args.case}")
        return

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        status = "PASSED" if result.get("passed") else "FAILED"
        print(f"\nQuality Gate: {status}")
        print(f"  Errors:   {result.get('error_count', 0)}")
        print(f"  Warnings: {result.get('warning_count', 0)}")
        cov = result.get("coverage", {})
        print(f"  Coverage: {cov.get('known_knowns_addressed', 0)}/"
              f"{cov.get('known_knowns_total', 0)} knowns addressed")
        for flag in result.get("flags", []):
            sev = flag.get("severity", "?").upper()
            print(f"\n  [{sev}] {flag.get('rule', 'N/A')}")
            print(f"    {flag.get('finding', '')}")
            if flag.get("suggestion"):
                print(f"    → {flag['suggestion']}")


def cmd_determination(args: argparse.Namespace) -> None:
    from tools.determination import llm_determine

    result = llm_determine(args.case)
    if not result:
        print(f"Failed to generate determination for {args.case}")
        return

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"\nDetermination for {args.case}")
        print(f"  Disposition: {result.get('disposition', 'N/A')}")
        print(f"  Confidence:  {result.get('confidence', 'N/A')}")
        print(f"  Reasoning:   {result.get('reasoning', 'N/A')}")
        chain = result.get("evidence_chain", [])
        if chain:
            print(f"\n  Evidence chain ({len(chain)} links):")
            for link in chain:
                status = link.get("status", "?")
                icon = "✓" if status == "confirmed" else ("~" if status == "assessed" else "?")
                print(f"    {icon} {link.get('link', 'N/A')}: {link.get('evidence') or link.get('gap', 'N/A')}")
        gaps = result.get("gaps", [])
        if gaps:
            print(f"\n  Gaps: {', '.join(gaps)}")


def cmd_articles(args: argparse.Namespace) -> None:
    from tools.threat_articles import fetch_candidates, generate_articles

    print("[articles] Fetching recent threat intelligence stories...")
    candidates = fetch_candidates(
        days=args.days,
        max_candidates=args.max or 20,
        category=args.category,
    )

    if not candidates:
        print("[articles] No candidates found. Try increasing --days or checking your network.")
        return

    # Display candidates
    print(f"\n{'#':<4} {'Cat':<4} {'Source':<25} {'Title'}")
    print("-" * 90)
    for i, c in enumerate(candidates, 1):
        covered = " [already covered]" if c["already_covered"] else ""
        print(f"{i:<4} {c['category']:<4} {c['source_name']:<25} {c['title'][:60]}{covered}")

    # Interactive selection or pre-selected
    if args.pick:
        picks = [int(x.strip()) for x in args.pick.split(",")]
    else:
        print(f"\nSelect articles (comma-separated numbers, e.g. 1,3,5) [default: first {args.count}]:")
        try:
            raw = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return
        if raw:
            picks = [int(x.strip()) for x in raw.split(",")]
        else:
            # Auto-pick first N uncovered
            uncovered = [i + 1 for i, c in enumerate(candidates) if not c["already_covered"]]
            picks = uncovered[:args.count]

    if not picks:
        print("[articles] No articles selected.")
        return

    selected = [candidates[p - 1] for p in picks if 0 < p <= len(candidates)]
    print(f"\n[articles] Generating {len(selected)} article(s)...")

    results = generate_articles(
        selected,
        analyst=args.analyst,
        case_id=getattr(args, "case", None),
    )

    for r in results:
        print(f"  ✓ {r['category']} | {r['title']}")
        print(f"    → {r['article_path']}")

    print(f"\n[articles] Done — {len(results)} article(s) written.")
    if args.json:
        print(json.dumps(results, indent=2, default=str))


def cmd_articles_list(args: argparse.Namespace) -> None:
    from tools.threat_articles import list_articles

    articles = list_articles(month=args.month, category=args.category)
    if not articles:
        print("No articles found.")
        return

    print(f"{'ID':<22} {'Cat':<4} {'Date':<12} {'Analyst':<15} {'Title'}")
    print("-" * 90)
    for a in articles:
        print(f"{a.get('article_id', '?'):<22} {a.get('category', '?'):<4} "
              f"{a.get('date', '?'):<12} {a.get('analyst', '?'):<15} "
              f"{a.get('title', '?')[:40]}")


def cmd_articles_generate(args: argparse.Namespace) -> None:
    from tools.threat_articles import generate_articles

    candidates = [{
        "id": f"manual-{i}",
        "title": args.title or f"Article from {url}",
        "category": args.category or "ET",
        "source_name": "manual",
        "source_url": url,
        "summary": "",
        "already_covered": False,
    } for i, url in enumerate(args.urls)]

    print(f"[articles-generate] Generating article from {len(args.urls)} URL(s)...")
    results = generate_articles(
        candidates,
        analyst=args.analyst,
        case_id=getattr(args, "case", None),
    )

    for r in results:
        print(f"  ✓ {r['category']} | {r['title']}")
        print(f"    → {r['article_path']}")

    if args.json:
        print(json.dumps(results, indent=2, default=str))


def cmd_batch_submit(args: argparse.Namespace) -> None:
    print("Batch processing has been removed. Use the MCP prompt workflow instead.")


def cmd_batch_status(args: argparse.Namespace) -> None:
    print("Batch processing has been removed.")


def cmd_batch_collect(args: argparse.Namespace) -> None:
    print("Batch processing has been removed.")


def cmd_velociraptor(args: argparse.Namespace) -> None:
    from tools.velociraptor_ingest import velociraptor_ingest

    source = Path(args.target)
    if not source.exists():
        print(f"[error] Source not found: {args.target}")
        sys.exit(1)

    case_id = args.case or _next_case_id()

    # Create case if it doesn't exist
    from config.settings import CASES_DIR
    if not (CASES_DIR / case_id).exists():
        from tools.case_create import case_create
        title = f"Velociraptor collection: {source.name}"
        case_create(case_id, title=title, severity=args.severity,
                    client=getattr(args, "client", "") or "")

    result = velociraptor_ingest(args.target, case_id, password=args.password)

    if result.get("status") != "ok":
        print(f"[error] {result.get('reason', 'Ingest failed')}")
        sys.exit(1)

    manifest = result.get("manifest", {})
    print(f"\nCase {case_id}: {manifest.get('total_vql_artefacts', 0)} artefact(s), "
          f"{manifest.get('total_rows_ingested', 0)} row(s), "
          f"{manifest.get('total_raw_files', 0)} raw file(s)")

    if not args.no_analyse:
        print("\n[velociraptor] Running analysis pipeline...")
        from tools.extract_iocs import extract_iocs
        from tools.enrich import enrich
        from tools.score_verdicts import score_verdicts, update_ioc_index
        from tools.correlate import correlate

        extract_iocs(case_id)
        enrich(case_id)
        score_verdicts(case_id)
        update_ioc_index(case_id)
        correlate(case_id)

        # EVTX correlation (if event log data present)
        try:
            from tools.evtx_correlate import evtx_correlate
            evtx_result = evtx_correlate(case_id)
            chains = evtx_result.get("chains", [])
            if chains:
                print(f"[velociraptor] EVTX: {len(chains)} attack chain(s) detected")
        except Exception as exc:
            from tools.common import log_error
            log_error(case_id, "cmd_velociraptor.evtx", str(exc), severity="warning")

        # Anomaly detection
        try:
            from tools.detect_anomalies import detect_anomalies
            detect_anomalies(case_id)
        except Exception as exc:
            from tools.common import log_error
            log_error(case_id, "cmd_velociraptor.anomalies", str(exc), severity="warning")

        # Timeline
        try:
            from tools.timeline_reconstruct import timeline_reconstruct
            timeline_reconstruct(case_id)
        except Exception as exc:
            from tools.common import log_error
            log_error(case_id, "cmd_velociraptor.timeline", str(exc), severity="warning")

        # Report
        from tools.generate_report import generate_report
        report_result = generate_report(case_id)
        print(f"\nReport: {report_result['report_path']}")

    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_browser_session(args: argparse.Namespace) -> None:
    from tools.browser_session import (start_session, stop_session,
                                       _session_done_events, _session_results,
                                       _load_session_state)

    case_id = args.case or ""

    # Only create a case if the analyst explicitly passed --case
    if case_id:
        from config.settings import CASES_DIR
        if not (CASES_DIR / case_id).exists():
            from tools.case_create import case_create
            title = f"Browser session: {args.target}"
            case_create(case_id, title=title, severity=args.severity,
                        client=getattr(args, "client", "") or "")

    result = start_session(args.target, case_id)

    if result.get("status") != "ok":
        print(f"[error] {result.get('reason', 'Session start failed')}")
        sys.exit(1)

    session_id = result["session_id"]
    idle_timeout = result.get("idle_timeout", 300)
    done_event = _session_done_events.get(session_id)

    # Block until idle timeout fires or Ctrl+C
    try:
        if idle_timeout > 0:
            print(f"Press Ctrl+C to stop, or wait — auto-stops after {int(idle_timeout)}s of network inactivity")
        else:
            print("Press Ctrl+C to stop the session and collect artefacts...")
        if done_event:
            done_event.wait()
        else:
            import signal as _signal
            _signal.pause()
    except KeyboardInterrupt:
        print("\n")

    # Stop session (idempotent — returns early if watchdog already stopped it)
    state = _load_session_state(session_id)
    if state and state.get("status") == "completed":
        stop_result = _session_results.get(session_id, {"status": "ok"})
    else:
        stop_result = stop_session(session_id)

    if stop_result.get("status") != "ok":
        print(f"[error] {stop_result.get('reason', 'Session stop failed')}")
        sys.exit(1)

    # Optionally run analysis pipeline (only when a case exists)
    if case_id and not args.no_analyse:
        print("\n[browser] Running analysis pipeline...")
        from tools.extract_iocs import extract_iocs
        from tools.enrich import enrich
        from tools.score_verdicts import score_verdicts, update_ioc_index
        from tools.correlate import correlate

        extract_iocs(case_id)
        enrich(case_id)
        score_verdicts(case_id)
        update_ioc_index(case_id)
        correlate(case_id)

        from tools.generate_report import generate_report
        report_result = generate_report(case_id)
        print(f"\nReport: {report_result['report_path']}")

    if args.json:
        print(json.dumps(stop_result, indent=2, default=str))


def cmd_browser_stop(args: argparse.Namespace) -> None:
    from tools.browser_session import stop_session
    result = stop_session(args.session_id)
    if result.get("status") != "ok":
        print(f"[error] {result.get('reason', 'Stop failed')}")
        sys.exit(1)
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_browser_list(args: argparse.Namespace) -> None:
    from tools.browser_session import list_sessions
    sessions = list_sessions()
    if not sessions:
        print("No browser sessions found.")
        return
    for s in sessions:
        status = s.get("status", "unknown")
        sid = s.get("session_id", "?")
        url = s.get("start_url", "")
        case = s.get("case_id", "")
        started = s.get("started_at", "")
        novnc = s.get("novnc_url", "")
        line = f"  [{status.upper():10s}] {sid}  case={case}  {url}"
        if status == "active" and novnc:
            line += f"  → {novnc}"
        if started:
            line += f"  (started {started})"
        print(line)


def cmd_sandbox_session(args: argparse.Namespace) -> None:
    from tools.sandbox_session import start_session, stop_session, wait_for_completion

    sample_path = Path(args.target)
    if not sample_path.exists():
        print(f"[error] Sample not found: {args.target}")
        sys.exit(1)

    case_id = args.case or _next_case_id()

    from config.settings import CASES_DIR
    if not (CASES_DIR / case_id).exists():
        from tools.case_create import case_create
        title = f"Sandbox detonation: {sample_path.name}"
        case_create(case_id, title=title, severity=args.severity,
                    client=getattr(args, "client", "") or "")

    result = start_session(
        str(sample_path), case_id,
        timeout=args.timeout,
        network_mode=args.network,
        interactive=args.interactive,
    )

    if result.get("status") != "ok":
        print(f"[error] {result.get('reason', 'Session start failed')}")
        sys.exit(1)

    session_id = result["session_id"]
    print(f"[sandbox] Session {session_id} started")
    print(f"[sandbox] Sample: {sample_path.name} ({result.get('sample_type', '?')})")
    print(f"[sandbox] Image: {result.get('image', '?')} | Network: {args.network}")

    if args.interactive:
        from tools.sandbox_session import _is_container_running
        try:
            print("Interactive mode — press Ctrl+C to stop and collect artefacts...")
            # Poll for container exit rather than blocking forever on signal.pause()
            while _is_container_running(session_id):
                time.sleep(2)
            print("[sandbox] Container exited.")
        except KeyboardInterrupt:
            print("\n")
    else:
        print(f"[sandbox] Waiting up to {args.timeout}s for execution to complete...")
        wait_for_completion(session_id)

    stop_result = stop_session(session_id)

    if stop_result.get("status") != "ok":
        print(f"[error] {stop_result.get('reason', 'Session stop failed')}")
        sys.exit(1)

    dur = stop_result.get("duration_seconds", 0)
    entities = stop_result.get("entities_summary", {})
    print(f"[sandbox] Session stopped — duration: {dur}s")
    print(f"[sandbox] Entities: IPs={entities.get('ips', 0)}, "
          f"Domains={entities.get('domains', 0)}, URLs={entities.get('urls', 0)}")

    if stop_result.get("execution_error"):
        print(f"[sandbox] Execution error: {stop_result['execution_error']}")

    # Optionally run analysis pipeline
    if not args.no_analyse:
        print("\n[sandbox] Running analysis pipeline...")
        from tools.extract_iocs import extract_iocs
        from tools.enrich import enrich
        from tools.score_verdicts import score_verdicts, update_ioc_index
        from tools.correlate import correlate

        extract_iocs(case_id)
        enrich(case_id)
        score_verdicts(case_id)
        update_ioc_index(case_id)
        correlate(case_id)

        from tools.generate_report import generate_report
        report_result = generate_report(case_id)
        print(f"\nReport: {report_result['report_path']}")

    if args.json:
        print(json.dumps(stop_result, indent=2, default=str))


def cmd_sandbox_stop(args: argparse.Namespace) -> None:
    from tools.sandbox_session import stop_session
    result = stop_session(args.session_id)
    if result.get("status") != "ok":
        print(f"[error] {result.get('reason', 'Stop failed')}")
        sys.exit(1)
    dur = result.get("duration_seconds", 0)
    print(f"[sandbox] Session {args.session_id} stopped — duration: {dur}s")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_sandbox_list(args: argparse.Namespace) -> None:
    from tools.sandbox_session import list_sessions
    sessions = list_sessions()
    if not sessions:
        print("No sandbox sessions found.")
        return
    for s in sessions:
        status = s.get("status", "unknown")
        sid = s.get("session_id", "?")
        sample = s.get("sample_name", "")
        stype = s.get("sample_type", "")
        case = s.get("case_id", "")
        net = s.get("network_mode", "")
        started = s.get("started_at", "")
        line = f"  [{status.upper():15s}] {sid}  case={case}  {sample} ({stype})  net={net}"
        if started:
            line += f"  (started {started})"
        print(line)


def cmd_mde_package(args: argparse.Namespace) -> None:
    from tools.mde_ingest import mde_ingest

    source = Path(args.target)
    if not source.exists():
        print(f"[error] Source not found: {args.target}")
        sys.exit(1)

    case_id = args.case or _next_case_id()

    # Create case if it doesn't exist
    from config.settings import CASES_DIR
    if not (CASES_DIR / case_id).exists():
        from tools.case_create import case_create
        title = f"MDE investigation package: {source.name}"
        case_create(case_id, title=title, severity=args.severity,
                    client=getattr(args, "client", "") or "")

    result = mde_ingest(args.target, case_id, password=args.password)

    if result.get("status") != "ok":
        print(f"[error] {result.get('reason', 'Ingest failed')}")
        sys.exit(1)

    manifest = result.get("manifest", {})
    print(f"\nCase {case_id}: {manifest.get('total_artefacts', 0)} artefact(s), "
          f"{manifest.get('total_rows_ingested', 0)} row(s), "
          f"{manifest.get('total_raw_files', 0)} raw file(s)")

    if not args.no_analyse:
        print("\n[mde] Running analysis pipeline...")
        from tools.extract_iocs import extract_iocs
        from tools.enrich import enrich
        from tools.score_verdicts import score_verdicts, update_ioc_index
        from tools.correlate import correlate

        extract_iocs(case_id)
        enrich(case_id)
        score_verdicts(case_id)
        update_ioc_index(case_id)
        correlate(case_id)

        # EVTX correlation (if security event log was extracted)
        try:
            from tools.evtx_correlate import evtx_correlate
            evtx_result = evtx_correlate(case_id)
            chains = evtx_result.get("chains", [])
            if chains:
                print(f"[mde] EVTX: {len(chains)} attack chain(s) detected")
        except Exception as exc:
            from tools.common import log_error
            log_error(case_id, "cmd_mde_package.evtx", str(exc), severity="warning")

        # Anomaly detection
        try:
            from tools.detect_anomalies import detect_anomalies
            detect_anomalies(case_id)
        except Exception as exc:
            from tools.common import log_error
            log_error(case_id, "cmd_mde_package.anomalies", str(exc), severity="warning")

        # Timeline
        try:
            from tools.timeline_reconstruct import timeline_reconstruct
            timeline_reconstruct(case_id)
        except Exception as exc:
            from tools.common import log_error
            log_error(case_id, "cmd_mde_package.timeline", str(exc), severity="warning")

        # Report
        from tools.generate_report import generate_report
        report_result = generate_report(case_id)
        print(f"\nReport: {report_result['report_path']}")

    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_memory_guide(args: argparse.Namespace) -> None:
    from tools.memory_guidance import generate_dump_guidance

    case_id = args.case or _next_case_id()

    from config.settings import CASES_DIR
    if not (CASES_DIR / case_id).exists():
        from tools.case_create import case_create
        title = f"Memory dump guidance: {args.process or 'unknown process'}"
        case_create(case_id, title=title, severity=args.severity,
                    client=getattr(args, "client", "") or "")

    result = generate_dump_guidance(
        case_id,
        process_name=args.process,
        pid=args.pid,
        alert_title=args.alert,
        hostname=args.host,
    )
    print(f"\nGuidance: {result['guidance_path']}")

    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_memory_analyse(args: argparse.Namespace) -> None:
    from tools.memory_guidance import analyse_memory_dump

    source = Path(args.target)
    if not source.exists():
        print(f"[error] Dump file not found: {args.target}")
        sys.exit(1)

    case_id = args.case or _next_case_id()

    from config.settings import CASES_DIR
    if not (CASES_DIR / case_id).exists():
        from tools.case_create import case_create
        title = f"Memory dump analysis: {source.name}"
        case_create(case_id, title=title, severity=args.severity,
                    client=getattr(args, "client", "") or "")

    result = analyse_memory_dump(args.target, case_id)

    if result.get("status") != "ok":
        print(f"[error] {result.get('reason', 'Analysis failed')}")
        sys.exit(1)

    risk = result.get("risk_indicators", {})
    print(f"\nCase {case_id}: Risk={risk.get('level', 'unknown').upper()}")

    # Run enrichment pipeline on extracted IOCs if not skipped
    if not args.no_analyse:
        print("\n[memory] Running enrichment pipeline...")
        from tools.extract_iocs import extract_iocs
        from tools.enrich import enrich
        from tools.score_verdicts import score_verdicts, update_ioc_index

        extract_iocs(case_id)
        enrich(case_id)
        score_verdicts(case_id)
        update_ioc_index(case_id)

        from tools.generate_report import generate_report
        report_result = generate_report(case_id)
        print(f"\nReport: {report_result['report_path']}")

    if args.json:
        print(json.dumps(result, indent=2, default=str))


# ---------------------------------------------------------------------------
# Cyberint CLI handlers
# ---------------------------------------------------------------------------

def cmd_cyberint(args: argparse.Namespace) -> None:
    from tools.cyberint_read import _is_configured, get_alert, list_alerts
    if not _is_configured():
        print("[error] Cyberint not configured — set CYBERINT_API_KEY in .env")
        return

    if args.ref_id:
        result = get_alert(args.ref_id)
        if not result:
            print(f"[error] Alert {args.ref_id} not found or not accessible.")
            return
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            _print_cyberint_alert(result)
        return

    result = list_alerts(
        page=args.page, size=args.size,
        severity=args.severity,
        status=args.status,
        category=args.category,
        environment=args.environment,
        created_from=args.created_from,
        created_to=args.created_to,
    )
    if not result:
        print("[error] Cyberint alert query failed — check logs.")
        return
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        alerts = result.get("alerts", [])
        total = result.get("total", 0)
        print(f"Cyberint alerts: {len(alerts)} shown / {total} total\n")
        for a in alerts:
            ref = a.get("ref_id", a.get("id", "?"))
            sev = a.get("severity", "?")
            title = a.get("title", a.get("description", ""))[:80]
            status = a.get("status", "?")
            created = a.get("created_date", a.get("created_at", ""))
            print(f"  [{sev:>9}] {ref}  {status:<14} {created[:10]}  {title}")


def _print_cyberint_alert(alert: dict) -> None:
    """Pretty-print a single Cyberint alert."""
    for key in ("ref_id", "id", "title", "description", "severity", "status",
                "category", "type", "environment", "created_date",
                "modification_date", "closure_reason"):
        val = alert.get(key)
        if val:
            print(f"  {key}: {val}")
    # Print nested fields if present
    for section in ("iocs", "indicators", "attachments", "impacts"):
        items = alert.get(section)
        if items:
            print(f"  {section}: {json.dumps(items, indent=4, default=str)}")


def cmd_cyberint_metadata(args: argparse.Namespace) -> None:
    from tools.cyberint_read import _is_configured, get_alert_metadata
    if not _is_configured():
        print("[error] Cyberint not configured — set CYBERINT_API_KEY in .env")
        return
    result = get_alert_metadata()
    if not result:
        print("[error] Failed to retrieve Cyberint metadata.")
        return
    print(json.dumps(result, indent=2, default=str))


def cmd_cyberint_risk(args: argparse.Namespace) -> None:
    from tools.cyberint_read import _is_configured, get_risk_scores
    if not _is_configured():
        print("[error] Cyberint not configured — set CYBERINT_API_KEY in .env")
        return
    result = get_risk_scores(args.environment)
    if not result:
        print(f"[error] Risk scores for '{args.environment}' not found.")
        return
    print(json.dumps(result, indent=2, default=str))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="socai",
        description="SOC-AI – Local multi-agent SOC automation.",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", action="store_true", help="Output JSON summary.")
    sub = parser.add_subparsers(dest="command", required=True)

    # report
    p_rep = sub.add_parser("report", help="Re-generate investigation report for a case.")
    p_rep.add_argument("--case", required=True)

    # weekly
    p_wk = sub.add_parser("weekly", help="Generate weekly rollup report.")
    p_wk.add_argument("--year",  type=int, default=None)
    p_wk.add_argument("--week",  type=int, default=None)
    p_wk.add_argument("--include-open", action="store_true", dest="include_open")

    # close
    p_cl = sub.add_parser("close", help="Mark a case as closed.")
    p_cl.add_argument("--case", required=True)

    # list
    sub.add_parser("list", help="List all registered cases.")

    # create-case
    p_cc = sub.add_parser("create-case", help="Create a new investigation case.")
    p_cc.add_argument("--case", default=None, help="Case ID (auto-generated if omitted).")
    p_cc.add_argument("--title", "-t", default=None, help="Case title.")
    p_cc.add_argument("--severity", "-s", default="medium", choices=["low", "medium", "high", "critical"])
    p_cc.add_argument("--analyst", "-a", default="unassigned")
    p_cc.add_argument("--client", "-c", default=None, help="Client name.")
    p_cc.add_argument("--tags", default=None, help="Comma-separated tags.")

    # enrich
    p_en = sub.add_parser("enrich", help="Re-run IOC extraction + enrichment for a case.")
    p_en.add_argument("--case", required=True)

    # queries
    p_qry = sub.add_parser("queries", help="Generate SIEM hunt queries for a case.")
    p_qry.add_argument("--case", required=True)
    p_qry.add_argument(
        "--platforms", nargs="*", default=None,
        choices=["kql", "splunk", "logscale"],
        help="Platforms to generate for (default: all three)",
    )
    p_qry.add_argument(
        "--tables", nargs="*", default=None,
        metavar="TABLE",
        help="Confirmed KQL tables where IOCs exist — scopes KQL output to these only. "
             "E.g. --tables DeviceNetworkEvents IdentityLogonEvents SecurityEvent",
    )

    # mdr-report
    p_mdr = sub.add_parser(
        "mdr-report",
        help="Generate MDR report (redirects to MCP prompt workflow).",
    )
    p_mdr.add_argument("--case", required=True)

    # pup-report
    p_pup = sub.add_parser(
        "pup-report",
        help="Generate PUP/PUA report (redirects to MCP prompt workflow).",
    )
    p_pup.add_argument("--case", required=True)

    # secarch
    p_sa = sub.add_parser(
        "secarch",
        help="Security architecture review (redirects to MCP prompt workflow).",
    )
    p_sa.add_argument("--case", required=True)

    # client-query
    p_cq = sub.add_parser(
        "client-query",
        help="Ad-hoc queries (redirects to Claude Desktop agent).",
    )
    p_cq.add_argument(
        "--prompt", required=True,
        help="Free-text description of what the client wants to find",
    )
    p_cq.add_argument(
        "--platforms", nargs="*", default=None,
        choices=["kql", "splunk", "logscale"],
        help="SIEM platforms to generate for (default: kql)",
    )
    p_cq.add_argument(
        "--tables", nargs="*", default=None,
        metavar="TABLE",
        help="Confirmed available tables — scopes output to these",
    )

    # triage
    p_tr = sub.add_parser("triage", help="Pre-pipeline IOC triage against existing intelligence.")
    p_tr.add_argument("--case", required=True)
    p_tr.add_argument("--url", nargs="*", default=[], help="URL(s) to triage")
    p_tr.add_argument("--severity", default="medium",
                      choices=["low", "medium", "high", "critical"])

    # email-analyse
    p_eml = sub.add_parser("email-analyse", help="Parse .eml file(s) for security indicators.")
    p_eml.add_argument("--case", required=True)
    p_eml.add_argument("--eml", nargs="+", required=True, metavar="FILE",
                       help="Path(s) to .eml file(s)")

    # landscape
    p_ls = sub.add_parser("landscape", help="Holistic cross-case intelligence assessment.")
    p_ls.add_argument("--days", type=int, default=None, help="Only last N days")
    p_ls.add_argument("--client", default=None, help="Filter to client/org name")

    # campaigns
    p_camp = sub.add_parser("campaigns", help="List all cross-case campaigns (shared IOC clusters).")
    p_camp.add_argument("--case", default=None, help="Optional case ID for per-case links")

    # sandbox
    p_sb = sub.add_parser("sandbox", help="Query sandbox APIs for file analysis results.")
    p_sb.add_argument("--case", required=True)
    p_sb.add_argument("--detonate", action="store_true",
                      help="Submit files for live sandbox detonation")

    # anomalies
    p_an = sub.add_parser("anomalies", help="Detect behavioural anomalies in parsed logs.")
    p_an.add_argument("--case", required=True)

    # errors
    p_err = sub.add_parser("errors", help="Assess collected errors — prioritised impact report.")
    p_err.add_argument("--top", type=int, default=15, help="Top N steps to show")
    p_err.add_argument("--severity", default=None, choices=["error", "warning", "info"],
                       help="Filter by severity level")
    p_err.add_argument("--clear", action="store_true",
                       help="Clear the error log after assessment")

    # mcp-usage
    p_mu = sub.add_parser("mcp-usage", help="Assess MCP server usage — calls, errors, latency.")
    p_mu.add_argument("--top", type=int, default=20, help="Top N tools to show")
    p_mu.add_argument("--tool", default=None, help="Filter by tool name")
    p_mu.add_argument("--caller", default=None, help="Filter by caller")
    p_mu.add_argument("--clear", action="store_true",
                      help="Clear the usage log after assessment")

    # timeline
    p_tl = sub.add_parser("timeline", help="Reconstruct forensic timeline from case artefacts.")
    p_tl.add_argument("--case", required=True)

    # pe-analysis
    p_pe = sub.add_parser("pe-analysis", help="Deep PE file analysis (imports, entropy, packers).")
    p_pe.add_argument("--case", required=True)

    # yara
    p_yr = sub.add_parser("yara", help="YARA scan case files against built-in and custom rules.")
    p_yr.add_argument("--case", required=True)
    p_yr.add_argument("--generate-rules", action="store_true", dest="generate_rules",
                      help="Use LLM to generate case-specific YARA rules and re-scan")

    # evtx
    p_ev = sub.add_parser("evtx", help="Correlate Windows Event Log attack chains from parsed logs.")
    p_ev.add_argument("--case", required=True)

    # cve-context
    p_cve = sub.add_parser("cve-context", help="Contextualise CVEs found in case artefacts (NVD, EPSS, KEV).")
    p_cve.add_argument("--case", required=True)

    # exec-summary
    p_es = sub.add_parser("exec-summary", help="Executive summary (redirects to MCP prompt workflow).")
    p_es.add_argument("--case", required=True)

    # response-actions
    p_ra = sub.add_parser(
        "response-actions",
        help="Generate client-specific response actions for a case.",
    )
    p_ra.add_argument("--case", required=True)

    # matrix — investigation reasoning matrix
    p_mx = sub.add_parser("matrix", help="Generate or view the investigation reasoning matrix.")
    p_mx.add_argument("--case", required=True)
    p_mx.add_argument("--summary", action="store_true", help="Show compact summary only")
    p_mx.add_argument("--regenerate", action="store_true", help="Force regeneration")

    # followup — review and execute follow-up proposals
    p_fu = sub.add_parser("followup", help="Review and execute Rumsfeld follow-up proposals.")
    p_fu.add_argument("--case", required=True)
    p_fu.add_argument("--approve", metavar="ID", help="Execute a specific proposal (e.g. p_001)")
    p_fu.add_argument("--approve-all", action="store_true", dest="approve_all",
                       help="Execute all pending proposals")

    # quality-gate — report quality validation
    p_qg = sub.add_parser("quality-gate", help="Run analytical standards quality gate on a report.")
    p_qg.add_argument("--case", required=True)

    # determination — evidence-chain disposition analysis
    p_det = sub.add_parser("determination", help="Run evidence-chain determination analysis.")
    p_det.add_argument("--case", required=True)

    # fp-ticket
    p_fp = sub.add_parser(
        "fp-ticket",
        help="Generate an FP suppression ticket with platform-specific rule/control improvements.",
    )
    p_fp.add_argument("--case",        required=True, help="Case ID (e.g. IV_CASE_001)")
    p_fp.add_argument("--alert",       metavar="FILE", default=None,
                      help="Path to alert JSON/text file")
    p_fp.add_argument("--alert-text",  metavar="TEXT", default=None, dest="alert_text",
                      help="Inline alert string")
    p_fp.add_argument("--query",       metavar="FILE", default=None,
                      help="Path to KQL rule file (Sentinel cases)")
    p_fp.add_argument("--query-text",  metavar="KQL",  default=None, dest="query_text",
                      help="Inline KQL rule string")
    p_fp.add_argument("--platform",    default=None,
                      choices=["sentinel", "crowdstrike", "defender", "entra", "cloudapps"],
                      help="Override platform detection")
    p_fp.add_argument("--live-query",  action="store_true", default=False, dest="live_query",
                      help="Enable read-only KQL queries against the alert workspace (requires az CLI auth)")

    # fp-tuning
    p_ft = sub.add_parser(
        "fp-tuning",
        help="Generate a SIEM engineering tuning ticket with root cause analysis and before/after query modifications.",
    )
    p_ft.add_argument("--case",        required=True, help="Case ID (e.g. IV_CASE_001)")
    p_ft.add_argument("--alert",       metavar="FILE", default=None,
                      help="Path to alert JSON/text file")
    p_ft.add_argument("--alert-text",  metavar="TEXT", default=None, dest="alert_text",
                      help="Inline alert string")
    p_ft.add_argument("--query",       metavar="FILE", default=None,
                      help="Path to KQL rule file (Sentinel)")
    p_ft.add_argument("--query-text",  metavar="KQL",  default=None, dest="query_text",
                      help="Inline KQL rule string")
    p_ft.add_argument("--platform",    default=None,
                      choices=["sentinel", "crowdstrike", "defender", "entra", "cloudapps", "splunk"],
                      help="Override platform detection")
    p_ft.add_argument("--live-query",  action="store_true", default=False, dest="live_query",
                      help="Enable read-only KQL queries against the alert workspace (requires az CLI auth)")

    # velociraptor
    p_vr = sub.add_parser(
        "velociraptor",
        help="Ingest Velociraptor collection results (offline collector ZIP, VQL exports, or directory).",
    )
    p_vr.add_argument("target", help="Path to collector ZIP, result directory, or individual VQL file")
    p_vr.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_vr.add_argument("--severity", default="medium",
                       choices=["low", "medium", "high", "critical"])
    p_vr.add_argument("--password", default=None, help="ZIP password")
    p_vr.add_argument("--no-analyse", action="store_true", dest="no_analyse",
                       help="Ingest only — skip enrichment, EVTX correlation, anomaly detection, and reporting")
    p_vr.add_argument("--client", default="",
                       help="Client name (loads playbook from config/clients/<name>.json)")

    # browser-session
    p_bs = sub.add_parser(
        "browser-session",
        help="Start a disposable Chrome browser session for manual phishing investigation.",
    )
    p_bs.add_argument("target", help="Starting URL to navigate to")
    p_bs.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_bs.add_argument("--severity", default="medium",
                       choices=["low", "medium", "high", "critical"])
    p_bs.add_argument("--no-analyse", action="store_true", dest="no_analyse",
                       help="Skip enrichment pipeline after session ends")
    p_bs.add_argument("--client", default="",
                       help="Client name (loads playbook from config/clients/<name>.json)")

    # browser-stop
    p_bstop = sub.add_parser("browser-stop", help="Stop an active browser session and collect artefacts.")
    p_bstop.add_argument("--session", required=True, dest="session_id",
                          help="Session ID to stop")

    # browser-list
    sub.add_parser("browser-list", help="List all browser sessions (active and completed).")

    # sandbox-session
    p_ss = sub.add_parser(
        "sandbox-session",
        help="Detonate a suspicious file in a containerised sandbox.",
    )
    p_ss.add_argument("target", help="Path to sample file to detonate")
    p_ss.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_ss.add_argument("--severity", default="medium",
                       choices=["low", "medium", "high", "critical"])
    p_ss.add_argument("--timeout", type=int, default=120,
                       help="Execution timeout in seconds (default 120, max 600)")
    p_ss.add_argument("--network", default="monitor", choices=["monitor", "isolate"],
                       help="Network mode: monitor (honeypot) or isolate (air-gapped)")
    p_ss.add_argument("--interactive", action="store_true",
                       help="Keep container running for manual inspection via exec")
    p_ss.add_argument("--no-analyse", action="store_true", dest="no_analyse",
                       help="Skip enrichment pipeline after detonation")
    p_ss.add_argument("--client", default="",
                       help="Client name (loads playbook from config/clients/<name>.json)")

    # sandbox-stop
    p_sstop = sub.add_parser("sandbox-stop", help="Stop an active sandbox session and collect artefacts.")
    p_sstop.add_argument("--session", required=True, dest="session_id",
                          help="Session ID to stop")

    # sandbox-list
    sub.add_parser("sandbox-list", help="List all sandbox detonation sessions (active and completed).")

    # mde-package
    p_mde = sub.add_parser(
        "mde-package",
        help="Ingest MDE investigation package ZIP (Defender for Endpoint triage collection).",
    )
    p_mde.add_argument("target", help="Path to MDE investigation package ZIP")
    p_mde.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_mde.add_argument("--severity", default="medium",
                        choices=["low", "medium", "high", "critical"])
    p_mde.add_argument("--password", default=None, help="ZIP password")
    p_mde.add_argument("--no-analyse", action="store_true", dest="no_analyse",
                        help="Ingest only — skip enrichment, correlation, and reporting")
    p_mde.add_argument("--client", default="",
                        help="Client name (loads playbook from config/clients/<name>.json)")

    # memory-guide
    p_mg = sub.add_parser(
        "memory-guide",
        help="Generate process memory dump collection guidance for an analyst.",
    )
    p_mg.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_mg.add_argument("--severity", default="medium",
                       choices=["low", "medium", "high", "critical"])
    p_mg.add_argument("--process", default="", help="Target process name (e.g. svchost.exe)")
    p_mg.add_argument("--pid", default="", help="Target PID")
    p_mg.add_argument("--alert", default="", help="Alert title for context")
    p_mg.add_argument("--host", default="", help="Target hostname")
    p_mg.add_argument("--client", default="",
                       help="Client name (loads playbook from config/clients/<name>.json)")

    # memory-analyse
    p_ma = sub.add_parser(
        "memory-analyse",
        help="Analyse a collected process memory dump (.dmp) file.",
    )
    p_ma.add_argument("target", help="Path to .dmp file")
    p_ma.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_ma.add_argument("--severity", default="medium",
                       choices=["low", "medium", "high", "critical"])
    p_ma.add_argument("--no-analyse", action="store_true", dest="no_analyse",
                       help="Analysis only — skip enrichment pipeline")
    p_ma.add_argument("--client", default="",
                       help="Client name (loads playbook from config/clients/<name>.json)")

    # articles (interactive discovery)
    p_art = sub.add_parser(
        "articles",
        help="Discover and write threat intelligence articles (ET/EV) for monthly reporting.",
    )
    p_art.add_argument("--days", type=int, default=7, help="Lookback window in days (default 7)")
    p_art.add_argument("--count", type=int, default=3, help="Number of articles to produce (default 3)")
    p_art.add_argument("--max", type=int, default=20, help="Max candidates to show (default 20)")
    p_art.add_argument("--category", choices=["ET", "EV"], default=None,
                       help="Filter candidates by category")
    p_art.add_argument("--analyst", default="unassigned", help="Analyst name for attribution")
    p_art.add_argument("--case", default=None, help="Optional case ID to attach articles to")
    p_art.add_argument("--pick", default=None,
                       help="Pre-select articles by number (e.g. '1,3,5') for non-interactive use")

    # articles-list
    p_artl = sub.add_parser("articles-list", help="List produced threat articles.")
    p_artl.add_argument("--month", default=None, help="Filter by month (YYYY-MM)")
    p_artl.add_argument("--category", choices=["ET", "EV"], default=None,
                        help="Filter by category")

    # articles-generate (direct URL mode)
    p_artg = sub.add_parser(
        "articles-generate",
        help="Generate a threat article from provided URLs (skip discovery).",
    )
    p_artg.add_argument("--urls", nargs="+", required=True, metavar="URL",
                        help="URL(s) to summarise")
    p_artg.add_argument("--title", default=None, help="Article title (auto-generated if omitted)")
    p_artg.add_argument("--category", choices=["ET", "EV"], default="ET",
                        help="Article category (default ET)")
    p_artg.add_argument("--analyst", default="unassigned", help="Analyst name")
    p_artg.add_argument("--case", default=None, help="Optional case ID to attach article to")

    # batch-submit
    p_bsub = sub.add_parser("batch-submit", help="Batch processing (removed — use MCP prompts).")
    p_bsub.add_argument("--cases", nargs="+", required=True, metavar="CASE_ID",
                         help="Case IDs to include in the batch")
    p_bsub.add_argument("--tools", nargs="+", required=True,
                         choices=["mdr-report", "exec-summary", "secarch"],
                         help="Tools to run for each case")
    p_bsub.add_argument("--label", default="", help="Optional label for the batch")

    # batch-status
    p_bst = sub.add_parser("batch-status", help="Batch processing (removed).")
    p_bst.add_argument("--batch-id", default=None, dest="batch_id",
                       help="Batch ID to check")
    p_bst.add_argument("--list", action="store_true", dest="list_batches",
                       help="List all known batches")

    # batch-collect
    p_bc = sub.add_parser("batch-collect", help="Batch processing (removed).")
    p_bc.add_argument("--batch-id", required=True, dest="batch_id",
                      help="Batch ID to collect results for")

    # cyberint — query/list Cyberint CTI alerts
    p_ci = sub.add_parser("cyberint", help="Query Cyberint CTI alerts (read-only).")
    p_ci.add_argument("--ref-id", default=None, dest="ref_id",
                      help="Specific alert reference ID for detail view")
    p_ci.add_argument("--severity", default=None, help="Filter by severity")
    p_ci.add_argument("--status", default=None, help="Filter by status")
    p_ci.add_argument("--category", default=None, help="Filter by category")
    p_ci.add_argument("--environment", default=None, help="Filter by environment")
    p_ci.add_argument("--created-from", default=None, dest="created_from",
                      help="ISO date — alerts created after this date")
    p_ci.add_argument("--created-to", default=None, dest="created_to",
                      help="ISO date — alerts created before this date")
    p_ci.add_argument("--page", type=int, default=1, help="Page number (default 1)")
    p_ci.add_argument("--size", type=int, default=10, help="Results per page (default 10)")

    # cyberint-metadata — print alert catalog metadata
    sub.add_parser("cyberint-metadata", help="Print Cyberint alert catalog metadata.")

    # cyberint-risk — print current risk scores
    p_cr = sub.add_parser("cyberint-risk", help="Print Cyberint risk scores for an environment.")
    p_cr.add_argument("--environment", required=True, help="Environment name")

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    _setup_logging(args.verbose)

    dispatch = {
        "create-case":    cmd_create_case,
        "report":         cmd_report,
        "weekly":         cmd_weekly,
        "close":          cmd_close,
        "list":           cmd_list,
        "enrich":         cmd_enrich,
        "queries":        cmd_queries,
        "client-query":   cmd_client_query,
        "secarch":        cmd_secarch,
        "mdr-report":     cmd_mdr_report,
        "pup-report":     cmd_pup_report,
        "triage":         cmd_triage,
        "email-analyse":  cmd_email_analyse,
        "landscape":      cmd_landscape,
        "campaigns":      cmd_campaigns,
        "sandbox":        cmd_sandbox,
        "anomalies":      cmd_anomalies,
        "errors":         cmd_errors,
        "mcp-usage":      cmd_mcp_usage,
        "response-actions": cmd_response_actions,
        "matrix":         cmd_matrix,
        "followup":       cmd_followup,
        "quality-gate":   cmd_quality_gate,
        "determination":  cmd_determination,
        "fp-ticket":      cmd_fp_ticket,
        "fp-tuning":      cmd_fp_tuning,
        "timeline":       cmd_timeline,
        "pe-analysis":    cmd_pe_analysis,
        "yara":           cmd_yara,
        "evtx":           cmd_evtx,
        "cve-context":    cmd_cve_context,
        "exec-summary":   cmd_exec_summary,
        "velociraptor":   cmd_velociraptor,
        "browser-session": cmd_browser_session,
        "browser-stop":   cmd_browser_stop,
        "browser-list":   cmd_browser_list,
        "sandbox-session": cmd_sandbox_session,
        "sandbox-stop":   cmd_sandbox_stop,
        "sandbox-list":   cmd_sandbox_list,
        "mde-package":    cmd_mde_package,
        "memory-guide":   cmd_memory_guide,
        "memory-analyse": cmd_memory_analyse,
        "articles":       cmd_articles,
        "articles-list":  cmd_articles_list,
        "articles-generate": cmd_articles_generate,
        "batch-submit":       cmd_batch_submit,
        "batch-status":       cmd_batch_status,
        "batch-collect":      cmd_batch_collect,
        "cyberint":           cmd_cyberint,
        "cyberint-metadata":  cmd_cyberint_metadata,
        "cyberint-risk":      cmd_cyberint_risk,
    }
    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
