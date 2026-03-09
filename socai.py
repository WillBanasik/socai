#!/usr/bin/env python3
"""
SOC-AI  –  Local Multi-Agent SOC Automation
============================================

Usage examples:

  # Full investigation
  python socai.py investigate --case C001 --title "Phishing lure" --severity high \
      --urls urls.txt --logs ./logs --zip sample.zip --zip-pass infected

  # Full investigation with email input
  python socai.py investigate --case C001 --title "Phishing email" --severity high \
      --eml phish.eml --url "https://example.com"

  # Just generate a weekly report
  python socai.py weekly --year 2026 --week 08 --include-open

  # Re-run report for existing case
  python socai.py report --case C001

  # Close a case
  python socai.py close --case C001

  # List registered cases
  python socai.py list

  # Ad-hoc client query — no case created, stdout only
  python socai.py client-query --prompt "Was folder 2026 created on AFGRICENTFNP03?"
  python socai.py client-query --prompt "..." --platforms kql --tables DeviceFileEvents DeviceEvents
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
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

def cmd_investigate(args: argparse.Namespace) -> None:
    from agents.chief import ChiefAgent

    urls      = _read_lines(args.urls) if args.urls else (args.url or [])
    log_paths = _glob_logs(args.logs)
    eml_paths = args.eml or []

    chief = ChiefAgent(args.case)
    result = chief.run(
        title              = args.title or f"Investigation {args.case}",
        severity           = args.severity,
        analyst            = args.analyst,
        tags               = args.tags or [],
        urls               = urls,
        zip_path           = args.zip,
        zip_pass           = args.zip_pass,
        log_paths          = log_paths,
        eml_paths          = eml_paths if eml_paths else None,
        close_case         = args.close,
        include_private_ips= args.include_private,
        detonate           = args.detonate,
        client             = getattr(args, "client", "") or "",
    )
    if args.json:
        print(json.dumps(result, indent=2, default=str))


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
    from tools.client_query import client_query
    client_query(
        prompt=args.prompt,
        platforms=args.platforms or None,
        tables=args.tables or None,
    )


def cmd_mdr_report(args: argparse.Namespace) -> None:
    from tools.generate_mdr_report import generate_mdr_report
    result = generate_mdr_report(args.case)
    if result.get("status") == "ok":
        print(f"MDR report: {result['report_path']}")
    else:
        print(f"[mdr-report] {result.get('status','?')}: {result.get('reason','')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


def cmd_secarch(args: argparse.Namespace) -> None:
    from tools.security_arch_review import security_arch_review
    result = security_arch_review(args.case)
    if result.get("status") == "ok":
        print(f"Security architecture review: {result['review_path']}")
    else:
        print(f"[secarch] {result.get('status','?')}: {result.get('reason','')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


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
    from tools.executive_summary import executive_summary
    result = executive_summary(args.case)
    if result.get("status") == "ok":
        print(f"Executive summary: {result.get('summary_path', '')}")
    else:
        print(f"[exec-summary] {result.get('status', '?')}: {result.get('reason', '')}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))


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


# ---------------------------------------------------------------------------
# Quick-run helpers (auto-create case, run mini pipeline, report)
# ---------------------------------------------------------------------------

def _next_case_id() -> str:
    """Generate the next sequential case ID from the registry."""
    from tools.common import load_json
    max_num = 0
    if REGISTRY_FILE.exists():
        try:
            registry = load_json(REGISTRY_FILE)
            for cid in registry.get("cases", {}):
                # Extract numeric part from IDs like C001, C123, QUICK-001
                import re
                m = re.search(r"(\d+)$", cid)
                if m:
                    max_num = max(max_num, int(m.group(1)))
        except Exception as exc:
            from tools.common import log_error
            log_error("", "socai.next_case_id", str(exc), severity="warning",
                      context={"registry": str(REGISTRY_FILE)})
    return f"C{max_num + 1:03d}"


def _quick_pipeline(case_id: str, title: str, severity: str,
                    urls: list[str] | None = None,
                    file_path: str | None = None,
                    zip_path: str | None = None,
                    zip_pass: str | None = None,
                    json_output: bool = False,
                    client: str = "") -> None:
    """Run a focused mini-pipeline: case_create → capture/analyse → enrich → report."""
    from tools.case_create import case_create
    from tools.extract_iocs import extract_iocs
    from tools.enrich import enrich
    from tools.score_verdicts import score_verdicts, update_ioc_index
    from tools.correlate import correlate
    from tools.generate_report import generate_report

    case_create(case_id, title=title, severity=severity, client=client)

    if urls:
        from tools.web_capture import web_capture, web_capture_batch
        if len(urls) == 1:
            web_capture(urls[0], case_id)
        else:
            web_capture_batch(urls, case_id)
        # Phishing detection
        from tools.detect_phishing_page import detect_phishing_page
        try:
            detect_phishing_page(case_id)
        except Exception as exc:
            from tools.common import log_error
            log_error(case_id, "quick_pipeline.phishing_detect", str(exc), severity="warning")

    if zip_path:
        from tools.extract_zip import extract_zip
        from tools.static_file_analyse import static_file_analyse
        from config.settings import CASES_DIR
        extract_zip(zip_path, case_id, password=zip_pass)
        # Run static analysis on each extracted file
        zip_dir = CASES_DIR / case_id / "artefacts" / "zip"
        if zip_dir.exists():
            for f in zip_dir.rglob("*"):
                if f.is_file() and f.suffix not in (".json", ".txt"):
                    try:
                        static_file_analyse(str(f), case_id)
                    except Exception as exc:
                        from tools.common import log_error
                        log_error(case_id, "quick_pipeline.static_analyse", str(exc),
                                  severity="warning", context={"file": str(f)})

    if file_path:
        from tools.static_file_analyse import static_file_analyse
        static_file_analyse(file_path, case_id)

    # Enrichment pipeline
    extract_iocs(case_id)
    enrich(case_id)
    score_verdicts(case_id)
    update_ioc_index(case_id)
    correlate(case_id)

    # Report
    result = generate_report(case_id)
    print(f"\nReport: {result['report_path']}")

    if json_output:
        print(json.dumps(result, indent=2))


def cmd_url(args: argparse.Namespace) -> None:
    case_id = args.case or _next_case_id()
    title = f"URL investigation: {args.target}"
    _quick_pipeline(case_id, title, args.severity,
                    urls=[args.target], json_output=args.json,
                    client=getattr(args, "client", "") or "")


def cmd_domain(args: argparse.Namespace) -> None:
    case_id = args.case or _next_case_id()
    target = args.target
    # Ensure it's a full URL for web capture
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    title = f"Domain investigation: {args.target}"
    _quick_pipeline(case_id, title, args.severity,
                    urls=[target], json_output=args.json,
                    client=getattr(args, "client", "") or "")


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
    from tools.batch import (
        prepare_mdr_report_batch, prepare_executive_summary_batch,
        prepare_secarch_batch, submit_batch,
    )

    _TOOL_PREPARERS = {
        "mdr-report": prepare_mdr_report_batch,
        "exec-summary": prepare_executive_summary_batch,
        "secarch": prepare_secarch_batch,
    }

    requests = []
    for case_id in args.cases:
        for tool_name in args.tools:
            preparer = _TOOL_PREPARERS.get(tool_name)
            if not preparer:
                print(f"[warn] Unknown batch tool: {tool_name}")
                continue
            req = preparer(case_id)
            if req:
                requests.append(req)
            else:
                print(f"[warn] Could not prepare {tool_name} for {case_id} (no data?)")

    if not requests:
        print("[batch-submit] No valid requests to submit.")
        return

    result = submit_batch(requests, batch_label=f"CLI batch: {', '.join(args.tools)}")
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Batch ID: {result.get('batch_id', '?')}")
        print(f"Status: {result.get('status', '?')}")
        print(f"Requests: {result.get('request_count', 0)}")


def cmd_batch_status(args: argparse.Namespace) -> None:
    if args.list:
        from tools.batch import list_batches
        batches = list_batches()
        if not batches:
            print("No batches found.")
            return
        print(f"{'Batch ID':<45} {'Status':<12} {'Requests':<10} {'Label'}")
        print("-" * 100)
        for b in batches:
            print(f"{b.get('batch_id', '?'):<45} {b.get('status', '?'):<12} "
                  f"{b.get('request_count', '?'):<10} {b.get('label', '')}")
        return

    if not args.batch_id:
        print("[error] Provide --batch-id <id> or --list")
        sys.exit(1)

    from tools.batch import poll_batch
    result = poll_batch(args.batch_id, poll_interval=5, timeout=10)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"Batch: {result.get('batch_id', '?')}")
        print(f"Status: {result.get('status', '?')}")


def cmd_batch_collect(args: argparse.Namespace) -> None:
    from tools.batch import collect_batch_results, dispatch_batch_results

    results = collect_batch_results(args.batch_id)
    if not results:
        print("[batch-collect] No results found.")
        return

    summary = dispatch_batch_results(results)
    print(f"Dispatched: {summary['dispatched']}, Errors: {summary['errors']}, Total: {summary['total']}")
    if args.json:
        print(json.dumps(summary, indent=2, default=str))


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
    from tools.browser_session import start_session, stop_session

    case_id = args.case or _next_case_id()

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

    # Block until Ctrl+C
    import signal as _signal
    try:
        print("Press Ctrl+C to stop the session and collect artefacts...")
        _signal.pause()
    except KeyboardInterrupt:
        print("\n")

    stop_result = stop_session(session_id)

    if stop_result.get("status") != "ok":
        print(f"[error] {stop_result.get('reason', 'Session stop failed')}")
        sys.exit(1)

    # Optionally run analysis pipeline
    if not args.no_analyse:
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
        import signal as _signal
        try:
            print("Interactive mode — press Ctrl+C to stop and collect artefacts...")
            _signal.pause()
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


def cmd_file(args: argparse.Namespace) -> None:
    p = Path(args.target)
    if not p.exists():
        print(f"[error] File not found: {args.target}")
        sys.exit(1)
    case_id = args.case or _next_case_id()
    title = f"File analysis: {p.name}"

    # Detect ZIP files and auto-extract with known passwords
    if p.suffix.lower() == ".zip":
        import zipfile
        zip_pass = None
        try:
            with zipfile.ZipFile(p) as zf:
                # Test if encrypted by trying to read first file
                first = zf.namelist()[0] if zf.namelist() else None
                if first:
                    try:
                        zf.read(first)
                        # No password needed
                    except RuntimeError:
                        # Encrypted — try known passwords
                        for pw in ("infected", "password"):
                            try:
                                zf.read(first, pwd=pw.encode())
                                zip_pass = pw
                                print(f"[file] ZIP password: {pw}")
                                break
                            except RuntimeError:
                                continue
                        if zip_pass is None:
                            print("[error] ZIP is encrypted and neither 'infected' nor 'password' worked")
                            sys.exit(1)
        except zipfile.BadZipFile as exc:
            from tools.common import log_error
            log_error(case_id, "cmd_file.bad_zip", str(exc), severity="warning",
                      context={"file": str(p)})
            print(f"[error] {p} is not a valid ZIP file: {exc}")
            sys.exit(1)

        if zip_pass is not None or p.suffix.lower() == ".zip":
            _quick_pipeline(case_id, title, args.severity,
                            zip_path=str(p), zip_pass=zip_pass,
                            json_output=args.json,
                            client=getattr(args, "client", "") or "")
            return

    _quick_pipeline(case_id, title, args.severity,
                    file_path=str(p), json_output=args.json,
                    client=getattr(args, "client", "") or "")


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

    # investigate
    p_inv = sub.add_parser("investigate", help="Run full investigation pipeline.")
    p_inv.add_argument("--case",    required=True, help="Case ID (e.g. C001)")
    p_inv.add_argument("--title",   default="", help="Human-readable case title")
    p_inv.add_argument("--severity",default="medium",
                       choices=["low","medium","high","critical"])
    p_inv.add_argument("--analyst", default="unassigned")
    p_inv.add_argument("--tags",    nargs="*", default=[])
    p_inv.add_argument("--urls",    metavar="FILE",
                       help="Path to a file containing one URL per line")
    p_inv.add_argument("--url",     nargs="*", metavar="URL",
                       help="URL(s) passed directly on the command line")
    p_inv.add_argument("--logs",    metavar="DIR_OR_FILE",
                       help="Directory or file with log files (CSV/JSON)")
    p_inv.add_argument("--zip",     metavar="FILE", help="Path to ZIP archive")
    p_inv.add_argument("--zip-pass",metavar="PASS", default=None,
                       dest="zip_pass", help="ZIP password")
    p_inv.add_argument("--eml",     nargs="*", metavar="FILE",
                       help="Path(s) to .eml file(s) for email analysis")
    p_inv.add_argument("--close",   action="store_true",
                       help="Mark case as closed after pipeline completes")
    p_inv.add_argument("--include-private", action="store_true",
                       dest="include_private",
                       help="Include RFC-1918 IPs in IOC extraction")
    p_inv.add_argument("--detonate", action="store_true",
                       help="Submit files to sandbox for live detonation")
    p_inv.add_argument("--client", default="",
                       help="Client name (loads playbook from config/clients/<name>.json)")

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
        help="Generate an MDR-style incident report using the Gold MDR/XDR Analyst Instruction Set.",
    )
    p_mdr.add_argument("--case", required=True)

    # secarch
    p_sa = sub.add_parser(
        "secarch",
        help="LLM-assisted security architecture review for a completed case.",
    )
    p_sa.add_argument("--case", required=True)

    # client-query
    p_cq = sub.add_parser(
        "client-query",
        help="Ad-hoc SIEM queries from a free-text client request. No case created.",
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
    p_es = sub.add_parser("exec-summary", help="Generate a plain-English executive summary for leadership.")
    p_es.add_argument("--case", required=True)

    # response-actions
    p_ra = sub.add_parser(
        "response-actions",
        help="Generate client-specific response actions for a case.",
    )
    p_ra.add_argument("--case", required=True)

    # fp-ticket
    p_fp = sub.add_parser(
        "fp-ticket",
        help="Generate an FP suppression ticket with platform-specific rule/control improvements.",
    )
    p_fp.add_argument("--case",        required=True, help="Case ID (e.g. C001)")
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

    # Quick-run: url
    p_url = sub.add_parser("url", help="Quick-run: capture + enrich + report for a single URL.")
    p_url.add_argument("target", help="URL to investigate (e.g. https://example.com)")
    p_url.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_url.add_argument("--severity", default="medium",
                       choices=["low", "medium", "high", "critical"])
    p_url.add_argument("--client", default="",
                       help="Client name (loads playbook from config/clients/<name>.json)")

    # Quick-run: domain
    p_dom = sub.add_parser("domain", help="Quick-run: capture + enrich + report for a domain.")
    p_dom.add_argument("target", help="Domain to investigate (e.g. evil.example.com)")
    p_dom.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_dom.add_argument("--severity", default="medium",
                       choices=["low", "medium", "high", "critical"])
    p_dom.add_argument("--client", default="",
                       help="Client name (loads playbook from config/clients/<name>.json)")

    # Quick-run: file
    p_file = sub.add_parser("file", help="Quick-run: static analysis + enrich + report for a file.")
    p_file.add_argument("target", help="Path to file to analyse")
    p_file.add_argument("--case", default=None, help="Case ID (auto-generated if omitted)")
    p_file.add_argument("--severity", default="medium",
                        choices=["low", "medium", "high", "critical"])
    p_file.add_argument("--client", default="",
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
    p_bsub = sub.add_parser("batch-submit", help="Submit a batch of LLM requests for multiple cases/tools.")
    p_bsub.add_argument("--cases", nargs="+", required=True, metavar="CASE_ID",
                         help="Case IDs to include in the batch")
    p_bsub.add_argument("--tools", nargs="+", required=True,
                         choices=["mdr-report", "exec-summary", "secarch"],
                         help="Tools to run for each case")
    p_bsub.add_argument("--label", default="", help="Optional label for the batch")

    # batch-status
    p_bst = sub.add_parser("batch-status", help="Check batch processing status.")
    p_bst.add_argument("--batch-id", default=None, dest="batch_id",
                       help="Batch ID to check")
    p_bst.add_argument("--list", action="store_true", dest="list_batches",
                       help="List all known batches")

    # batch-collect
    p_bc = sub.add_parser("batch-collect", help="Collect batch results and write artefacts.")
    p_bc.add_argument("--batch-id", required=True, dest="batch_id",
                      help="Batch ID to collect results for")

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    _setup_logging(args.verbose)

    dispatch = {
        "investigate":    cmd_investigate,
        "report":         cmd_report,
        "weekly":         cmd_weekly,
        "close":          cmd_close,
        "list":           cmd_list,
        "enrich":         cmd_enrich,
        "queries":        cmd_queries,
        "client-query":   cmd_client_query,
        "secarch":        cmd_secarch,
        "mdr-report":     cmd_mdr_report,
        "triage":         cmd_triage,
        "email-analyse":  cmd_email_analyse,
        "landscape":      cmd_landscape,
        "campaigns":      cmd_campaigns,
        "sandbox":        cmd_sandbox,
        "anomalies":      cmd_anomalies,
        "errors":         cmd_errors,
        "response-actions": cmd_response_actions,
        "fp-ticket":      cmd_fp_ticket,
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
        "url":            cmd_url,
        "domain":         cmd_domain,
        "file":           cmd_file,
        "articles":       cmd_articles,
        "articles-list":  cmd_articles_list,
        "articles-generate": cmd_articles_generate,
        "batch-submit":   cmd_batch_submit,
        "batch-status":   cmd_batch_status,
        "batch-collect":  cmd_batch_collect,
    }
    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
