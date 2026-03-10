"""
Chief Agent (Orchestrator)
--------------------------
Drives the full investigation pipeline by:
  1. Classifying the attack type from inputs
  2. Selecting a pipeline profile (which steps to skip)
  3. Dispatching to specialist agents in order
  4. Collecting results and surfacing errors

Attack-type classification adapts the pipeline:
  - phishing:             skip sandbox
  - malware:              skip phishing detection, recursive capture
  - account_compromise:   skip domain investigation, sandbox, phishing
  - privilege_escalation: skip domain investigation, sandbox, phishing
  - pup_pua:              short-circuit to PUP report after enrichment
  - generic:              run everything permitted by inputs

Usage (programmatic):
    chief = ChiefAgent(case_id="C001")
    result = chief.run(
        title="Phishing email analysis",
        severity="high",
        urls=["https://suspect.example.com"],
        zip_path="/tmp/sample.zip",
        zip_pass="infected",
        log_paths=["/tmp/proxy.csv"],
        eml_paths=["/tmp/phish.eml"],
    )
"""
from __future__ import annotations

import logging
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agents.base_agent import BaseAgent
from agents.domain_investigator import DomainInvestigatorAgent
from agents.enrichment_agent import EnrichmentAgent
from agents.file_analyst import FileAnalystAgent
from agents.log_correlator import LogCorrelatorAgent
from agents.planner import PlannerAgent
from agents.query_gen_agent import QueryGenAgent
from agents.report_writer import ReportWriterAgent
from agents.security_arch_agent import SecurityArchAgent
from config.settings import CASES_DIR, CONF_AUTO_CLOSE, CRAWL_DEPTH, CRAWL_MAX_URLS
from tools.case_create import case_create
from tools.classify_attack import classify_attack_type, should_skip_step
from tools.common import KNOWN_CLEAN_DOMAINS, load_json, log_error, save_json
from tools.detect_phishing_page import detect_phishing_page as _detect_phishing
from tools.extract_iocs import extract_iocs as _extract_iocs
from tools.generate_pup_report import detect_pup
from tools.web_capture import _safe_dirname

logger = logging.getLogger("socai.chief")


def _crawl_skip(url: str) -> bool:
    """Return True if *url* should be excluded from recursive capture."""
    import urllib.parse
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception as exc:
        log_error("", "crawl_skip", str(exc), severity="warning",
                  context={"url": url})
        return False
    for d in KNOWN_CLEAN_DOMAINS:
        if host == d or host.endswith("." + d):
            return True
    return False


class ChiefAgent(BaseAgent):
    name = "chief"

    def run(
        self,
        title: str = "",
        severity: str = "medium",
        analyst: str = "unassigned",
        tags: list[str] | None = None,
        urls: list[str] | None = None,
        zip_path: str | None = None,
        zip_pass: str | None = None,
        log_paths: list[str] | None = None,
        eml_paths: list[str] | None = None,
        close_case: bool = False,
        include_private_ips: bool = False,
        detonate: bool = False,
        analyst_notes: str | None = None,
        client: str = "",
        **kwargs,
    ) -> dict:
        pipeline_results: dict = {
            "case_id":  self.case_id,
            "steps":    [],
            "errors":   [],
            "report":   None,
        }
        _results_lock = threading.Lock()

        def _step(name: str, fn):
            self._emit("step_start", {"step": name})
            try:
                result = fn()
                with _results_lock:
                    pipeline_results["steps"].append({"step": name, "status": "ok"})
                self._emit("step_done", {"step": name})
                return result
            except Exception as exc:
                msg = traceback.format_exc()
                logger.error("Step %s failed: %s", name, msg)
                log_error(self.case_id, name, str(exc), traceback=msg)
                with _results_lock:
                    pipeline_results["steps"].append({"step": name, "status": "error", "error": str(exc)})
                    pipeline_results["errors"].append({"step": name, "error": str(exc)})
                return None

        def _skip(step_name: str) -> bool:
            """Check if step should be skipped by the attack-type profile."""
            return should_skip_step(step_name, attack_type)

        # ==================================================================
        # 1. Initialise case
        # ==================================================================
        _step("case_create", lambda: case_create(
            self.case_id, title=title, severity=severity,
            analyst=analyst, tags=tags or [], client=client,
        ))

        # 1b. Save analyst notes so downstream tools (report, security_arch) can read them
        if analyst_notes:
            notes_dir = CASES_DIR / self.case_id / "notes"
            notes_dir.mkdir(parents=True, exist_ok=True)
            from tools.common import write_artefact
            write_artefact(notes_dir / "analyst_input.md", analyst_notes)
            print(f"[chief] Analyst notes saved ({len(analyst_notes)} chars)")

        # ==================================================================
        # 1c. Classify attack type — determines which steps to skip
        # ==================================================================
        classification = classify_attack_type(
            title=title,
            analyst_notes=analyst_notes or "",
            tags=tags,
            eml_paths=eml_paths,
            urls=urls,
            zip_path=zip_path,
            log_paths=log_paths,
        )
        attack_type = classification["attack_type"]
        pipeline_results["attack_type"] = attack_type
        pipeline_results["classification"] = classification

        print(f"[chief] Attack type: {attack_type} "
              f"(confidence: {classification['confidence']}, "
              f"signals: {classification['signals']})")

        # Persist to case metadata
        meta_path = CASES_DIR / self.case_id / "case_meta.json"
        if meta_path.exists():
            meta = load_json(meta_path)
            meta["attack_type"] = attack_type
            meta["attack_type_confidence"] = classification["confidence"]
            save_json(meta_path, meta)

        skipped_steps = classification["profile"]["skip"]
        if skipped_steps:
            print(f"[chief] Profile skips: {', '.join(sorted(skipped_steps))}")

        # ==================================================================
        # 2. Triage — check input IOCs against ioc_index / enrichment cache
        # ==================================================================
        triage_result = None
        if urls:
            try:
                from agents.triage_agent import TriageAgent
                triage_result = _step("triage", lambda: TriageAgent(self.case_id).run(
                    urls=urls, severity=severity,
                ))
                # Apply severity escalation if recommended
                if triage_result and triage_result.get("escalate_severity"):
                    new_sev = triage_result["escalate_severity"]
                    if new_sev != severity:
                        print(f"[chief] Triage recommends severity escalation: {severity} → {new_sev}")
                        severity = new_sev
                        if meta_path.exists():
                            meta = load_json(meta_path)
                            meta["severity"] = new_sev
                            save_json(meta_path, meta)
            except ImportError as exc:
                log_error(self.case_id, "triage", str(exc), severity="info",
                          context={"reason": "TriageAgent import unavailable"})

        # ==================================================================
        # 3. Plan — informational task list (skipped for lightweight profiles)
        # ==================================================================
        if not _skip("plan"):
            planner = PlannerAgent(self.case_id)
            _step("plan", lambda: planner.run(
                urls=urls, zip_path=zip_path, zip_pass=zip_pass, log_paths=log_paths
            ))

        # ==================================================================
        # 4. Email analysis — parse .eml files, extract URLs + attachments
        #    Always runs if EML provided (input-driven, not profile-gated)
        # ==================================================================
        if eml_paths:
            try:
                from agents.email_analyst import EmailAnalystAgent
                email_result = _step("email_analyse", lambda: EmailAnalystAgent(self.case_id).run(
                    eml_paths=eml_paths,
                ))
                if email_result:
                    extracted_urls = email_result.get("extracted_urls", [])
                    if extracted_urls:
                        urls = list(set((urls or []) + extracted_urls))
                        print(f"[chief] Email analysis added {len(extracted_urls)} URL(s) to investigation")
            except ImportError as exc:
                log_error(self.case_id, "email_analyse", str(exc), severity="info",
                          context={"reason": "EmailAnalystAgent import unavailable"})

        # ==================================================================
        # 5. PARALLEL: Domain investigation, File analysis, Log correlation
        # ==================================================================
        parallel_tasks = []

        # 5a. Domain investigation — profile + input gated
        uncaptured = []
        if urls and not _skip("domain_investigate"):
            for url in urls:
                manifest = (
                    CASES_DIR / self.case_id / "artefacts" / "web"
                    / _safe_dirname(url) / "capture_manifest.json"
                )
                if manifest.exists():
                    print(f"[chief] Skipping already-captured URL: {url}")
                else:
                    uncaptured.append(url)
            if uncaptured:
                parallel_tasks.append(("domain_investigate", uncaptured))
        elif urls and _skip("domain_investigate"):
            print(f"[chief] Skipping domain investigation ({attack_type} profile)")

        # 5b. File analysis (ZIP) — always runs if ZIP provided (not profile-gated)
        run_file_analyse = False
        if zip_path:
            zip_art_dir = CASES_DIR / self.case_id / "artefacts" / "zip"
            if zip_art_dir.exists() and any(zip_art_dir.iterdir()):
                print(f"[chief] Skipping ZIP analysis — artefacts already exist at {zip_art_dir}")
            else:
                run_file_analyse = True

        # 5c. Log parsing + correlation — input-driven
        run_log_correlate = bool(log_paths)

        # Execute parallel block
        if len([x for x in [parallel_tasks, [run_file_analyse], [run_log_correlate]] if x and x[0]]) > 1:
            print("[chief] Running domain/file/log agents in parallel...")
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {}
                if parallel_tasks:
                    u = uncaptured
                    futures[executor.submit(
                        _step, "domain_investigate",
                        lambda u=u: DomainInvestigatorAgent(self.case_id).run(urls=u),
                    )] = "domain_investigate"
                if run_file_analyse:
                    futures[executor.submit(
                        _step, "file_analyse",
                        lambda: FileAnalystAgent(self.case_id).run(
                            zip_path=zip_path, zip_pass=zip_pass
                        ),
                    )] = "file_analyse"
                if run_log_correlate:
                    futures[executor.submit(
                        _step, "log_correlate",
                        lambda: LogCorrelatorAgent(self.case_id).run(log_paths=log_paths),
                    )] = "log_correlate"
                try:
                    for future in as_completed(futures, timeout=600):
                        step_name = futures[future]
                        try:
                            future.result()
                        except Exception as exc:
                            logger.error("Parallel step %s raised: %s", step_name, exc)
                            log_error(self.case_id, step_name, str(exc),
                                      traceback=traceback.format_exc(),
                                      context={"parallel": True})
                            with _results_lock:
                                pipeline_results["errors"].append({"step": step_name, "error": str(exc)})
                except TimeoutError:
                    log_error(self.case_id, "parallel_block", "600s timeout exceeded",
                              severity="error", context={"pending": [futures[f] for f in futures]})
        else:
            # Sequential fallback when only 0-1 tasks
            if uncaptured:
                _step(
                    "domain_investigate",
                    lambda u=uncaptured: DomainInvestigatorAgent(self.case_id).run(urls=u),
                )
            if run_file_analyse:
                _step("file_analyse", lambda: FileAnalystAgent(self.case_id).run(
                    zip_path=zip_path, zip_pass=zip_pass
                ))
            if run_log_correlate:
                _step("log_correlate", lambda: LogCorrelatorAgent(self.case_id).run(
                    log_paths=log_paths
                ))

        # ==================================================================
        # 6. Sandbox analysis — profile gated
        # ==================================================================
        sandbox_result = None
        if not _skip("sandbox_analyse"):
            try:
                from agents.sandbox_agent import SandboxAgent
                sandbox_result = _step("sandbox_analyse", lambda: SandboxAgent(self.case_id).run(
                    detonate=detonate,
                ))
            except ImportError as exc:
                log_error(self.case_id, "sandbox_analyse", str(exc), severity="info",
                          context={"reason": "SandboxAgent import unavailable"})

            # 6b. Local sandbox detonation — if --detonate and cloud lookups inconclusive
            if detonate and not _skip("sandbox_detonate"):
                cloud_has_verdict = (
                    sandbox_result
                    and sandbox_result.get("status") == "ok"
                    and sandbox_result.get("ok_results", 0) > 0
                )
                if not cloud_has_verdict:
                    try:
                        from agents.sandbox_detonation_agent import SandboxDetonationAgent
                        _step("sandbox_detonate", lambda: SandboxDetonationAgent(self.case_id).run())
                    except ImportError as exc:
                        log_error(self.case_id, "sandbox_detonate", str(exc), severity="info",
                                  context={"reason": "SandboxDetonationAgent import unavailable"})
                    except Exception as exc:
                        log_error(self.case_id, "sandbox_detonate", str(exc), severity="warning",
                                  traceback=traceback.format_exc(),
                                  context={"reason": "Local detonation failed"})
        elif urls or zip_path:
            print(f"[chief] Skipping sandbox analysis ({attack_type} profile)")

        # ==================================================================
        # 7. Recursive capture — profile gated
        # ==================================================================
        if urls and not _skip("recursive_capture"):
            captured_urls: set[str] = set(urls)
            for depth in range(2, CRAWL_DEPTH + 1):
                ioc_result = _extract_iocs(self.case_id, include_private=include_private_ips)
                extracted_urls = (
                    set(ioc_result.get("iocs", {}).get("url", []))
                    | set(ioc_result.get("iocs", {}).get("_http_urls", []))
                )
                new_urls = [
                    u for u in extracted_urls
                    if u not in captured_urls and not _crawl_skip(u)
                ][:CRAWL_MAX_URLS]
                uncaptured_new = [
                    u for u in new_urls
                    if not (
                        CASES_DIR / self.case_id / "artefacts" / "web"
                        / _safe_dirname(u) / "capture_manifest.json"
                    ).exists()
                ]
                if not uncaptured_new:
                    print(f"[chief] Recursive capture depth {depth}: no new URLs — stopping")
                    break
                print(f"[chief] Recursive capture depth {depth}: {len(uncaptured_new)} new URL(s)")
                _step(
                    f"recursive_capture_depth_{depth}",
                    lambda u=uncaptured_new: DomainInvestigatorAgent(self.case_id).run(urls=u),
                )
                captured_urls.update(uncaptured_new)
        elif urls and _skip("recursive_capture"):
            print(f"[chief] Skipping recursive capture ({attack_type} profile)")

        # ==================================================================
        # 8. Brand impersonation detection — profile gated
        # ==================================================================
        if urls and not _skip("detect_phishing_page"):
            _step("detect_phishing_page", lambda: _detect_phishing(self.case_id))
        elif urls and _skip("detect_phishing_page"):
            print(f"[chief] Skipping phishing detection ({attack_type} profile)")

        # ==================================================================
        # 9. Enrichment — always runs
        # ==================================================================
        skip_iocs = set()
        if triage_result and triage_result.get("skip_enrichment_iocs"):
            skip_iocs = set(triage_result["skip_enrichment_iocs"])

        _step("enrich", lambda: EnrichmentAgent(self.case_id).run(
            include_private=include_private_ips,
            skip_iocs=skip_iocs,
        ))

        # ==================================================================
        # 9b. Late PUP/PUA detection — post-enrichment verdict check
        # ==================================================================
        if attack_type != "pup_pua":
            verdict_path_pup = CASES_DIR / self.case_id / "artefacts" / "enrichment" / "verdict_summary.json"
            if verdict_path_pup.exists():
                pup_verdicts = load_json(verdict_path_pup)
                pup_check = detect_pup(
                    title=title,
                    analyst_notes=analyst_notes or "",
                    verdict_summary=pup_verdicts,
                )
                if pup_check["is_pup"]:
                    attack_type = "pup_pua"
                    pipeline_results["attack_type"] = "pup_pua"
                    print(f"[chief] PUP/PUA detected (post-enrichment): {pup_check['signals']}")
                    # Update case metadata
                    if meta_path.exists():
                        meta = load_json(meta_path)
                        meta["attack_type"] = "pup_pua"
                        save_json(meta_path, meta)

        # ==================================================================
        # PUP/PUA SHORT-CIRCUIT — skip remaining steps, generate PUP report
        # ==================================================================
        if attack_type == "pup_pua":
            print("[chief] PUP/PUA pipeline — skipping attack-chain analysis steps")
            from tools.generate_pup_report import generate_pup_report
            pup_result = _step("pup_report", lambda: generate_pup_report(self.case_id))
            pipeline_results["report"] = pup_result

            try:
                from tools.index_case import index_case
                report_path = pup_result.get("report_path") if pup_result else None
                index_case(self.case_id, status="open", disposition="pup_pua",
                           report_path=report_path)
            except Exception as exc:
                log_error(self.case_id, "index_case_pup", str(exc),
                          severity="warning", traceback=traceback.format_exc())

            ok_steps  = sum(1 for s in pipeline_results["steps"] if s["status"] == "ok")
            err_steps = len(pipeline_results["errors"])
            self._emit("pipeline_complete", {
                "ok": ok_steps, "errors": err_steps,
                "report": pup_result.get("report_path") if pup_result else None,
                "disposition": "pup_pua",
            })
            print(f"\n[chief] PUP/PUA pipeline complete for {self.case_id}: "
                  f"{ok_steps} step(s) OK, {err_steps} error(s).")
            if pup_result:
                print(f"[chief] PUP Report: {pup_result.get('report_path')}")
            return pipeline_results

        # ==================================================================
        # 10. Correlate — runs unless logs already handled it
        # ==================================================================
        if not log_paths:
            from tools.correlate import correlate
            _step("correlate", lambda: correlate(self.case_id))

        # ==================================================================
        # 11. Anomaly detection — behavioural anomaly detection on parsed logs
        # ==================================================================
        try:
            from agents.anomaly_detection_agent import AnomalyDetectionAgent
            _step("anomaly_detection", lambda: AnomalyDetectionAgent(self.case_id).run())
        except ImportError as exc:
            log_error(self.case_id, "anomaly_detection", str(exc), severity="info",
                      context={"reason": "AnomalyDetectionAgent import unavailable"})

        # ==================================================================
        # 12. Campaign clustering — cross-case IOC clustering
        # ==================================================================
        try:
            from agents.campaign_agent import CampaignAgent
            _step("campaign_cluster", lambda: CampaignAgent(self.case_id).run())
        except ImportError as exc:
            log_error(self.case_id, "campaign_cluster", str(exc), severity="info",
                      context={"reason": "CampaignAgent import unavailable"})

        # ==================================================================
        # 13. Response actions — client-specific response plan for TP cases
        # ==================================================================
        try:
            from agents.response_agent import ResponseActionsAgent
            _step("response_actions", lambda: ResponseActionsAgent(self.case_id).run())
        except ImportError as exc:
            log_error(self.case_id, "response_actions", str(exc), severity="info",
                      context={"reason": "ResponseActionsAgent import unavailable"})

        # ==================================================================
        # 14. Auto-disposition check before report
        # ==================================================================
        auto_disposition = None
        should_auto_close = False
        verdict_path = CASES_DIR / self.case_id / "artefacts" / "enrichment" / "verdict_summary.json"
        if not close_case and verdict_path.exists():
            verdicts = load_json(verdict_path)
            mal_count = len(verdicts.get("high_priority", []))
            sus_count = len(verdicts.get("needs_review", []))
            if mal_count == 0 and sus_count == 0:
                should_auto_close = True
                auto_disposition = "benign_auto_closed"

                # LLM auto-close validation (advisory override)
                try:
                    from tools.llm_insight import validate_auto_close
                    meta = load_json(CASES_DIR / self.case_id / "case_meta.json")
                    anomaly_path = CASES_DIR / self.case_id / "artefacts" / "anomalies" / "anomaly_report.json"
                    anomaly_data = load_json(anomaly_path) if anomaly_path.exists() else {}
                    llm_review = validate_auto_close(self.case_id, meta, verdicts, anomaly_data)
                    if llm_review.get("keep_open"):
                        print(f"[chief] LLM recommends keeping case open: {llm_review['reason']}")
                        should_auto_close = False
                        auto_disposition = None
                except Exception as exc:
                    log_error(self.case_id, "auto_close_llm_review", str(exc),
                              severity="info", context={"advisory": True})

        # ==================================================================
        # 15. Report
        # ==================================================================
        report_agent = ReportWriterAgent(self.case_id)
        report_result = _step("report", lambda: report_agent.run(
            close_case=close_case or should_auto_close,
            auto_disposition=auto_disposition,
        ))
        pipeline_results["report"] = report_result

        if should_auto_close:
            report_path = report_result.get("report_path") if report_result else None
            if report_path and Path(report_path).exists():
                report_text = Path(report_path).read_text(errors="ignore")
                import re
                conf_match = re.search(r"Confidence:\s*([\d.]+)", report_text)
                if conf_match:
                    confidence = float(conf_match.group(1))
                    if confidence >= CONF_AUTO_CLOSE:
                        print(f"[chief] Confidence {confidence:.2f} >= {CONF_AUTO_CLOSE} — reverting auto-close")
                        should_auto_close = False
                        from tools.index_case import index_case
                        index_case(self.case_id, status="open", report_path=report_path)
                    else:
                        print(f"[chief] Auto-closing case {self.case_id}: "
                              f"confidence={confidence:.2f}, 0 malicious, 0 suspicious → benign_auto_closed")

        # ==================================================================
        # 16. Hunt query generation
        # ==================================================================
        query_result = _step("query_gen", lambda: QueryGenAgent(self.case_id).run())
        if query_result:
            pipeline_results["queries"] = query_result.get("query_path")

        # ==================================================================
        # 17. Security architecture review
        # ==================================================================
        arch_result = _step("security_arch", lambda: SecurityArchAgent(self.case_id).run())
        if arch_result and arch_result.get("status") == "ok":
            pipeline_results["security_arch_review"] = arch_result.get("review_path")

        # ==================================================================
        # Summary
        # ==================================================================
        ok_steps  = sum(1 for s in pipeline_results["steps"] if s["status"] == "ok")
        err_steps = len(pipeline_results["errors"])
        self._emit("pipeline_complete", {
            "ok": ok_steps, "errors": err_steps,
            "report": report_result.get("report_path") if report_result else None,
            "attack_type": attack_type,
        })

        print(f"\n[chief] Pipeline complete for {self.case_id} [{attack_type}]: "
              f"{ok_steps} step(s) OK, {err_steps} error(s).")
        if report_result:
            print(f"[chief] Report: {report_result.get('report_path')}")

        return pipeline_results
