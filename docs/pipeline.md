# Pipeline Flow

## ChiefAgent.run() — Full Investigation Pipeline

```
ChiefAgent.run()
  1.  case_create                         always first
  1b. classify_attack_type                deterministic keyword + input-shape classifier
                                          → sets attack_type + attack_type_confidence in case_meta
                                          → selects pipeline profile (steps to skip per type)
                                          → PUP/PUA short-circuits to step 9 → PUP report → done
  2.  TriageAgent                         if URLs provided; check vs ioc_index, escalate severity
  3.  PlannerAgent                        informational only; result not used for routing
  4.  EmailAnalystAgent                   if --eml provided; parse headers, extract URLs + attachments
  5.  [PARALLEL]                          concurrent via ThreadPoolExecutor(max_workers=3)
      ├─ DomainInvestigatorAgent          if URLs provided (input + email-extracted)
      ├─ FileAnalystAgent                 if ZIP provided and not already extracted
      └─ LogCorrelatorAgent               if log paths provided (also runs correlate)
  6.  SandboxAgent                        query sandbox APIs for file hashes
  6b. SandboxDetonationAgent              if --detonate and no cloud verdict: local containerised detonation
  7.  recursive capture loop (depth 2–N)  if URLs provided:
        extract_iocs → find new URLs → DomainInvestigatorAgent (repeat up to CRAWL_DEPTH)
  8.  detect_phishing_page                if URLs provided; 3-tier phishing detection
                                          Tier 1: brand/forms/TLS (instant)
                                          Tier 2: structural heuristics (all pages)
                                          Tier 3: LLM purpose analysis (score >= 0.4)
  9.  EnrichmentAgent                     always:
        extract_iocs → enrich (tiered for IPv4; skip triage IOCs) → score_verdicts → update_ioc_index
        IPv4 flow: ASN pre-screen → fast providers (AbuseIPDB/URLhaus/ThreatFox/OpenCTI) →
                   deep OSINT only if signal detected (VT/Shodan/GreyNoise/ProxyCheck/Censys/OTX)
  10. correlate                           only if no logs (LogCorrelator already ran it)
  11. AnomalyDetectionAgent               behavioural anomaly detection on parsed logs
  12. CampaignAgent                       cross-case IOC clustering into campaigns
  13. ResponseActionsAgent                client-specific response plan (deterministic; no LLM)
                                          Skipped if no client playbook or no malicious/suspicious IOCs
  14. ReportWriterAgent                   always: generate_report + index_case
  15. QueryGenAgent                       generates SIEM hunt queries
  16. SecurityArchAgent                   always last; LLM security architecture review
                                          (skipped gracefully if ANTHROPIC_API_KEY not set)
```

## Execution Model

`socai.py` is the CLI entrypoint. The main pipeline runs synchronously with **parallel execution** for independent investigation agents. `ChiefAgent.run()` orchestrates the full pipeline for `investigate`; other sub-commands call tool wrappers directly.

**Agent layer** (`agents/`) — thin orchestration classes inheriting `BaseAgent`. They receive `case_id` at construction, call tool functions, and return dicts. Agents never write files directly.

**Tool layer** (`tools/`) — stateless functions that do the actual work. Every tool (except `client_query.py`):
- Takes `case_id` as a required parameter
- Writes all outputs under `cases/<case_id>/` via `write_artefact()` from `tools/common.py`
- Appends a SHA-256 + timestamp record to `registry/audit.log`
- Returns a JSON-serialisable manifest dict

Each step is wrapped in `_step()` with `try/except`. A failing step is recorded in `pipeline_results["errors"]` but does not abort subsequent steps.

## Parallel Execution (Step 5)

When 2+ of Domain/File/Log agents are needed, they run concurrently via `ThreadPoolExecutor(max_workers=3)`. They write to non-overlapping paths (`artefacts/web/`, `artefacts/zip/`, `logs/`) and have no data dependencies. The `_step()` closure uses `threading.Lock` for thread-safe `pipeline_results` mutation. Each future has a 600s timeout; failures are independent per the `_step()` pattern. Falls back to sequential when only 0–1 agents are needed.

## Re-run Idempotency

`ChiefAgent` checks for existing artefacts before dispatching steps. URLs with an existing `capture_manifest.json` are skipped; ZIPs with an existing populated `artefacts/zip/` directory are skipped. This makes re-running `investigate` safe — only missing work is performed.

## Client Playbook Resolution (Step 13)

When a case has a `client` field and a matching playbook exists in `config/clients/<client>.json`, `ResponseActionsAgent` generates a structured response plan:

1. **Severity mapping** — `critical/high` → P1, `medium` → P2, `low` → P3
2. **Crown jewel check** — if any malicious IOC matches a crown jewel host, escalate to P1
3. **Alert override** — `response[]` entries with `alert_name` matched against case title
4. **Escalation matrix** — filtered by resolved priority; collects permitted actions per asset type
5. **Contact process** — from default `response[]` entry or alert-specific override

The tool is purely deterministic (no LLM call). Output is consumed by the MDR report's "Approved Response Actions" section.

## Attack-Type Classification (Step 1b)

After `case_create`, `classify_attack_type()` from `tools/classify_attack.py` analyses the case title, notes, and input shape (URLs, ZIPs, logs, EML) to determine the attack type. This is a deterministic keyword + input-shape scorer — no LLM call.

**Attack types:** `phishing`, `malware`, `account_compromise`, `privilege_escalation`, `pup_pua`, `generic`

Each type has a pipeline profile in `PIPELINE_PROFILES` defining which steps to skip:

| Type | Skipped steps |
|------|---------------|
| `phishing` | sandbox, anomaly_detection, evtx |
| `malware` | phishing_detection |
| `account_compromise` | sandbox, phishing_detection |
| `privilege_escalation` | sandbox, phishing_detection, web_capture |
| `pup_pua` | Full short-circuit: enrich → PUP report → done |
| `generic` | Nothing skipped (fallback) |

**Score threshold:** A single weak signal (score ≤ 1) falls through to `generic` to avoid misrouting on ambiguous input.

The classified `attack_type` and `attack_type_confidence` are stored in `case_meta.json`. Each pipeline step checks `should_skip_step(attack_type, step_name)` before executing.

### PUP/PUA Short-Circuit

When classified as `pup_pua`, the pipeline short-circuits after enrichment (step 9). Instead of the standard report, `generate_pup_report()` produces a lightweight PUP-specific report covering: software identification, scope assessment, risk evaluation, and removal steps. The report is saved to `cases/<ID>/reports/pup_report.md`. The case is auto-closed with disposition `pup_pua` when the PUP report is generated (handled inside the tool).

## Auto-disposition

After enrichment, if verdict_summary has 0 malicious and 0 suspicious IOCs, the case is auto-closed with disposition `benign_auto_closed` — unless the report confidence score meets or exceeds `SOCAI_CONF_AUTO_CLOSE` (default 0.20), in which case the auto-close is reverted.

## Auto-close on Deliverable Collection

Cases auto-close when the analyst collects their deliverable. The close logic lives in the tool layer so it works consistently across all entry points (CLI, web UI, MCP server):

| Deliverable | Tool | Disposition set |
|---|---|---|
| MDR report | `generate_mdr_report()` | Preserves existing disposition |
| PUP report | `generate_pup_report()` | `pup_pua` |
| FP ticket | `fp_ticket()` | `false_positive` |

Each tool calls `index_case(case_id, status="closed", ...)` on successful generation. If the tool fails (skipped, error, needs_clarification), the case remains open.

This means the standard workflow is: pipeline runs → sets disposition → case stays open → analyst collects deliverable → case auto-closes. For PUP cases where the pipeline generates the PUP report inline, the case closes at pipeline completion. For benign cases with 0 malicious/suspicious IOCs, the auto-disposition logic closes the case before the report step.

## Quick-run Commands

`socai.py url`, `domain`, and `file` provide one-shot investigation shortcuts. They auto-generate the next sequential case ID (e.g. `IV_CASE_042`) from the registry, then run a focused mini-pipeline: case_create → capture/analyse → extract_iocs → enrich → score → correlate → report.

- `url` — web capture + phishing detection + enrichment + report
- `domain` — same as `url` (bare domain is prefixed with `https://`)
- `file` — static analysis + enrichment + report. **ZIP detection:** if the file has a `.zip` extension, it auto-extracts and tries passwords `infected` then `password`; runs static analysis on each extracted file. Non-ZIP files go straight to static analysis.
- `velociraptor` — Velociraptor collection ingest + enrichment + EVTX correlation + anomaly detection + timeline + report. Accepts offline collector ZIPs, VQL result directories, or individual VQL files. Auto-generates case ID if `--case` omitted. Use `--no-analyse` to skip the analysis pipeline (ingest only).
- `mde-package` — MDE investigation package ingest + enrichment + EVTX correlation + anomaly detection + timeline + report. Accepts investigation package ZIPs or extracted directories. Same downstream pipeline as Velociraptor. Auto-generates case ID if `--case` omitted. Use `--no-analyse` for ingest only.
- `memory-guide` — generates step-by-step MDE Live Response ProcDump instructions contextual to the active alert. Requires `--process` and `--alert`; optional `--pid`, `--hostname`.
- `memory-analyse` — read-only analysis of process memory dump files. Extracts strings, PE headers, DLL references, suspicious API patterns. Produces risk score. Optionally chains enrichment pipeline with `--no-analyse` to skip.
- `browser-session` — starts a disposable Docker-based Chrome session (noVNC on :7900) with passive tcpdump network capture. No automation markers — analyst browses manually; socai captures DNS queries, TCP connections, HTTP requests, and TLS SNI from the pcap. Ctrl+C or idle timeout stops the session and collects artefacts. Use `--no-analyse` to skip enrichment pipeline after session ends.
- `browser-stop` — stops an active browser session by session ID and collects artefacts.
- `browser-list` — lists all browser sessions (active and completed).
- `sandbox-session` — detonates a suspicious file in a containerised sandbox. Auto-selects Linux or Wine image based on sample type. Captures syscalls (strace), network traffic (tcpdump), filesystem changes (inotify), and process creation. Default network mode uses honeypot DNS/HTTP for C2 domain discovery. Use `--interactive` to keep the container running for manual inspection. Use `--no-analyse` to skip enrichment pipeline after detonation.
- `sandbox-stop` — stops an active sandbox session by session ID and collects artefacts.
- `sandbox-list` — lists all sandbox detonation sessions (active and completed).
