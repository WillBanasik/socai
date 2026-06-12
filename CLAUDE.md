# CLAUDE.md

Guidance for Claude Code working with the socai codebase. **Details are in `docs/` — only read them when working on relevant areas.** (The Claude **Desktop** seat has its own instructions in `docs/claude-desktop-instructions.md` — this file governs the TUI.)

## Working mode (Claude Code / TUI)

Operate in one of two modes; pick based on the task and switch as it changes:

- **Engineering mode** — building, editing, refactoring, testing, or debugging socai itself (code, tests, config, docs). Use `Bash`/`Edit`/`Read`/`Grep` freely. This is the default whenever the work is about *changing the codebase*.
- **Investigation mode** — triaging alerts, pulling Sentinel incidents, enriching IOCs, correlating cases, producing deliverables. **Drive this through the socai MCP tools/prompts** (`mcp__socai__*`: `create_case`, `run_kql`, `enrich_iocs`, `recall_cases`, `classify_attack`, `get_client_baseline`, `prepare_*` → `save_report`, …), exactly as the Desktop seat does — so evidence/findings/timeline accumulate in the case and the audit trail is intact. **Do not hand-roll `az` / `curl` / raw `bash` for investigation steps when an MCP tool exists.** Drop to raw shell only when no tool covers the step, and say so explicitly.

The socai MCP server is wired into this repo's `.mcp.json` **twice**: `socai` (SSE on `127.0.0.1:8001`, the shared systemd user service `socai-mcp`, `deploy/socai-mcp.service`, auto-starts at WSL boot) and `socai-stdio` (a per-session stdio spawn of the same server — `SOCAI_MCP_TRANSPORT=stdio`, no port, no systemd, no auth/local trust). Both run identical code against the same filesystem state; the audit trail is the same. **Prefer `mcp__socai__*` (SSE) when it is connected; fall back to `mcp__socai-stdio__*` whenever the SSE seat is down or wedged** — the stdio spawn works even when the service never started or `systemctl --user` cannot reach the bus. To repair the SSE service: probe `curl -s http://127.0.0.1:8001/healthz`, then `systemctl --user restart socai-mcp`, falling back to a detached `python3 -m mcp_server` if the user bus is unreachable (WSL boot race / bus shadow — see "Startup troubleshooting" in `docs/mcp-server.md`). If the SSE server was down when the session started, restoring it is not enough: the client resumes the SSE stream without re-initialising and every call returns `-32602` — only a user-side `/mcp` → reconnect clears it; use `mcp__socai-stdio__*` in the meantime (the CLI / underlying tool functions remain the last-resort stopgap) and say so explicitly. When unsure which mode applies, ask.

## Commands

```bash
# Tests (run from repo root)
python3 -m pytest tests/ -v
python3 -m pytest tests/test_tools.py::test_extract_iocs_from_text -v

# Create a case
python3 socai.py create-case --title "Alert title" --severity high --analyst <name> --client <client> --tags "tag1,tag2"

# Re-run stages
python3 socai.py enrich --case IV_CASE_001
python3 socai.py closure-comment --case IV_CASE_001 --classification fp_incorrect_logic --alert alert.json
python3 socai.py fp-tuning --case IV_CASE_001 --alert alert.json [--query rule.kql] [--platform sentinel]

# Deliverable reports (mdr-report, pup-report, secarch, exec-summary)
# These now redirect to MCP prompt workflow — use the corresponding
# MCP prompts in Claude Desktop and save with save_report.

# Investigation metrics
python3 scripts/metrics_report.py                      # full summary
python3 scripts/metrics_report.py --compare            # analyst comparison
python3 scripts/metrics_report.py --event enrichment_complete
python3 scripts/metrics_report.py --json               # raw JSON

# Workflow analytics (auto-captured from MCP tool calls)
python3 scripts/workflow_report.py                      # full report
python3 scripts/workflow_report.py --since 2026-03-25   # date filter
python3 scripts/workflow_report.py --friction            # friction patterns only
python3 scripts/workflow_report.py --sequences           # tool sequence patterns
python3 scripts/workflow_report.py --tools               # per-tool timing + errors
python3 scripts/workflow_report.py --trends              # daily trends
python3 scripts/workflow_report.py --json                # raw JSON summary

# Registry maintenance (one-shot, idempotent backfills)
python3 scripts/backfill_registry_fields.py [--dry-run]  # restore client/tags/attack_type on registry entries
python3 scripts/backfill_dispositions.py [--dry-run]     # give every closed case a canonical disposition

# MCP server
python3 -m mcp_server                                         # SSE (default), all toolsets loaded
SOCAI_MCP_TRANSPORT=streamable-http python3 -m mcp_server      # Streamable HTTP
SOCAI_MCP_TOOLSETS=core python3 -m mcp_server                  # core only + on-demand load_toolset (narrow profile)

# All subcommands: python3 socai.py --help
```

Install: `pip install -r requirements.txt` (append `--break-system-packages` on Debian). Playwright: `playwright install chromium` (optional; falls back to `requests`).

All scripts must be run from the repo root (`sys.path.insert` is anchored to parent of `tools/`).

## Architecture at a Glance

- **CLI:** `socai.py` — entrypoint; `python3 socai.py --help` for full subcommand list
- **Tools** (`tools/`) — stateless functions; accept `case_id`, write via `write_artefact()`/`save_json()`, return manifest dicts. No direct LLM/API calls — all LLM reasoning is handled by the local Claude client (Claude Desktop or Claude Code) via MCP prompts.
- **MCP Server** (`mcp_server/`) — HTTP SSE on port 8001 (TLS terminated by an upstream reverse proxy), JWT RBAC; see `docs/mcp-server.md`
- **Modular toolsets** (`TOOLSETS` in `mcp_server/tools.py`) — default profile is `all`: every toolset (core + `phishing`, `malware`, `forensics`, `intel`, `darkweb`, `analysis`, `admin`) is registered up front, because Claude Desktop's client-side tool-search indexes the session-start tool list and cannot see tools added later via `tools/list_changed`. The on-demand `load_toolset` machinery remains in place for narrower profiles or transports that honour the notification — set `SOCAI_MCP_TOOLSETS=core` (or `core,phishing,...`) to opt back in. `classify_attack` still returns `recommended_toolsets` for documentation. Any new tool MUST be added to a `TOOLSETS` group (unassigned tools fall back to core with a warning). See `socai://toolsets`.
- **Shared API** (`api/`) — auth, actions, timeline, input parsing — used by MCP server
- **Pipeline:** HITL (human-in-the-loop) — analyst drives investigation step by step via MCP tools and prompts. Case creation is deferred — deliverable tools auto-create if needed. See `docs/pipeline.md`
- **State:** all filesystem, no database. Registry in `registry/`, per-case in `cases/<ID>/`, articles in `articles/`
- **Background scheduler** (`tools/scheduler.py`) — daemon thread started by MCP server; refreshes GeoIP (7d), rebuilds client baselines (24h), rebuilds case memory BM25 index (6h full reconcile — also incrementally upserted on case create/close via `index_case`, so recent cases are searchable immediately)
- **Metrics** (`registry/metrics.jsonl`) — investigation lifecycle events with timing, coverage, confidence, and completeness metrics; query via `scripts/metrics_report.py`. Includes `workflow_summary` events (auto-captured tool sequences, friction signals) — query via `scripts/workflow_report.py`
- **Workflow analytics** (`mcp_server/usage.py`) — auto-captures ordered tool sequences per session with timing, categories (via `TOOL_TAXONOMY`), and friction detection. Flushed to metrics on session expiry, `new_investigation` (session-clear), or server shutdown. New tools must be registered in `TOOL_TAXONOMY`
- **Caseless enrichment** (`registry/quick_enrichments/`) — `quick_enrich` persists ad-hoc IOC lookups here. Import into a case via `enrichment_id` parameter on `create_case` or `import_enrichment` tool
- **Caseless browser sessions** (`browser_sessions/<session_id>/artefacts/`) — `start_browser_session` without `case_id` stores artefacts here. Read via `read_browser_session_file` / `list_browser_session_files`. Import into a case via `import_browser_session(session_id, case_id)`
- **Caseless vuln hunts** (`registry/vuln_hunts/`) — `eql_vuln_hunt(client)` persists a proactive Encore EQL vulnerability hunt here (`VH_<ts>.json`). Import into a case via `vuln_hunt_id` parameter on `create_case` or the `import_vuln_hunt(hunt_id, case_id)` tool
- **Caseless Encore lookups** (`registry/eql_lookups/`) — `eql_entity_lookup(client, user/host/ip)` (caseless `eql_entity_context`, `EQL_<ts>.json`) and `eql_identity_scan(client, users/hosts)` (caseless `eql_identity_assessment`, `EQLID_<ts>.json`) persist ad-hoc "what is this user/device/IP" pulls here. Resolved by client *name* through the same scope gate (`resolve_client_by_name`); cross-client access is structurally impossible. Import into a case via `eql_lookup_id` parameter on `create_case` or the `import_eql_lookup(lookup_id, case_id)` tool — **the import refuses if the lookup's client ≠ the case's client** (same guard now backfilled onto `import_vuln_hunt`)
- **Intelligence layer** — `tools/case_memory.py` (BM25 semantic recall), `tools/client_baseline.py` (per-client profiles), `tools/geoip.py` (local MaxMind GeoLite2)
- **Disposition workflow — finalised** — Reports/comments are analyst-initiated. Per disposition:
  - **True Positive** → analyst-approved `prepare_mdr_report` → `write_mdr_report` prompt → `save_report(report_type="mdr_report", disposition="true_positive")`. The MDR report is the expected deliverable; recommend it, produce on the go-ahead.
  - **Benign Positive** (Suspicious but expected *or* Suspicious but not malicious) → `prepare_closure_comment(classification="bp_suspicious_but_expected" | "bp_suspicious_not_malicious")` → `write_closure_comment` prompt → `save_report(report_type="closure_comment", disposition="benign_positive")`. Output is a 2-sentence markdown comment.
  - **False Positive — incorrect alert logic** → `prepare_closure_comment(classification="fp_incorrect_logic")` → save as closure_comment, `disposition="false_positive"`. Optionally follow with `prepare_fp_tuning_ticket` + `save_report(report_type="fp_tuning_ticket")` when rule tuning is also required. The tuning ticket leads with a fired-correctly determination and branches remediation by control model (SIEM = tune the rule; EDR = SOAR suppression only, mechanism TBD), ending in a machine-readable JSON handoff; pass `disposition="benign_positive"` instead when the detection fired correctly on authorised activity. The `fp_tuning_ticket` save **preserves the case's existing disposition** (the closure_comment above sets it) — it no longer forces `false_positive`; pass `disposition=` to set or override it.
  - **False Positive — inaccurate data** → `prepare_closure_comment(classification="fp_inaccurate_data")` → save as closure_comment, `disposition="false_positive"`.
  - **Undetermined** → `prepare_closure_comment(classification="undetermined")` → save as closure_comment, `disposition="inconclusive"`.
  - **PUP/PUA** → `close_case(disposition="pup_pua")` with brief note. PUP report only on explicit analyst request via `write_pup_report` prompt → `save_report(report_type="pup_report")`.
  - All save tools auto-create and promote a case if none exists, then auto-close on save. `executive_summary`, `security_arch_review`, and `vuln_hunt_report` are supplementary and do NOT auto-close. `read_report` and `close_case` are idempotent. On auto-close the disposition resolves: explicit arg → report-type default (`mdr_report`→`true_positive`, `pup_report`→`pup_pua`, others preserve the case's existing value); `closure_comment` **requires** an explicit `disposition` (it spans BP/FP/inconclusive — it will refuse rather than close blank). As a final invariant `index_case` floors any close with no resolvable disposition to canonical `inconclusive` and logs a `close_without_disposition` metric.
  - **Vulnerability hunt worklist** (proactive, not an incident disposition) → caseless `eql_vuln_hunt(client)` → `import_vuln_hunt` / `create_case(vuln_hunt_id=)` → `prepare_vuln_hunt_report` → `write_vuln_hunt_report` prompt → `save_report(report_type="vuln_hunt_report")`. Prioritised remediation worklist with a machine-readable handoff (`control_type`: `patch` | `edr_soar_mitigation`). See `docs/encore-eql.md`.
- **All reports and closure comments are markdown (`.md`)** — `save_report` accepts markdown directly. Template resources (`socai://templates/mdr-report`, `socai://templates/pup-report`) provide markdown skeletons. The persisted `.md` file is the analyst's copy-paste source for the customer deliverable; legacy `.html` files remain readable via `read_report` and the reports HTTP middleware.
- **Report / comment rendering in the visualiser** — `save_report` returns the persisted (defanged) markdown as `report_md` in its response. **Render `report_md` as a markdown artifact** so Claude Desktop opens it in the visualiser (the Artifacts side panel). Do not paste the raw markdown into the chat body, summarise, truncate, paraphrase, or wrap it in code fences. The `.md` file on disk is the deliverable copy-paste source; the visualiser is the review surface. The same pattern applies to `save_threat_article` — it returns the article as `article_md` with the same `display_hint`.

## Sentinel Incident Classification

When closing Sentinel incidents, use exactly one of three mutually exclusive classifications:

- **True Positive (TP)** — alert correctly detected genuinely malicious activity
- **Benign Positive (BP)** — alert correctly fired on real matching activity, but that activity is authorised/non-threatening. Sub-types: "suspicious but expected", "suspicious but not malicious"
- **False Positive (FP)** — alert misfired, detection logic was wrong

Decision: Did the detection fire correctly? NO → FP. YES → Was activity malicious? YES → TP. NO → BP.

Never combine classifications ("True Positive Benign Positive" is invalid). Disposition values: `true_positive`, `benign_positive`, `false_positive`, `benign`, `pup_pua`, `inconclusive`. These six are the only canonical dispositions — a case cannot close without one: `index_case` floors a missing disposition to `inconclusive`, and `close_case` defaults to `inconclusive`.

## Case Isolation

**One alert = one case.** Every new alert gets its own case, even when the same user/host/IOCs appear in prior cases. Never append new alert data to an existing case. Cross-case correlation runs via `recall_cases` (historical IOC/keyword lookup), `recall_semantic` (BM25 contextual similarity), and `campaign_cluster` (IOC overlap comparison) — run proactively per **Cross-Case Correlation** below, not only on request.

## When to Open a Case (Case vs Caseless)

**An incident or alert under investigation = a case.** Open a case (`create_case`, or let the first deliverable tool auto-create one) as soon as the work is clearly an investigation: an alert JSON is pasted, a SIEM/EDR incident is referenced, the analyst says "investigate this", a structured triage starts. Investigations belong in cases — that is where evidence, findings, enrichment, timeline, and the audit trail accumulate.

**Caseless is only for non-incident work**: ad-hoc IOC lookups ("what is this hash/IP/domain?"), exploratory questions, threat-intel research, playbook lookups, planning discussions before any alert is in hand, and proactive vulnerability hunting. `quick_enrich`, `extract_iocs_from_text`, `classify_attack`, `plan_investigation`, `lookup_client`, `recall_cases`, `recall_semantic`, `search_threat_articles`, `web_search`, `eql_vuln_hunt`, `eql_entity_lookup`, `eql_identity_scan`, and `start_browser_session` (without `case_id`) all run caseless.

Promote a caseless session to a case the moment it turns into an investigation — call `create_case(..., enrichment_id=<id>)` to carry caseless `quick_enrich` results over without re-running providers, or `create_case(..., vuln_hunt_id=<id>)` for a vuln hunt, or `create_case(..., eql_lookup_id=<id>)` for a caseless Encore entity lookup / identity scan, or `import_enrichment` / `import_vuln_hunt` / `import_eql_lookup` / `import_browser_session` on an existing case. Do not chain long sequences of caseless tools through what is plainly an incident. Deliverable tools (`prepare_mdr_report`, `prepare_pup_report`, `prepare_closure_comment`, `prepare_fp_tuning_ticket`) will auto-create a case as a safety net if you somehow reach the end without one — treat that as a safety net, not the default flow.

## Analytical Standards (MANDATORY)

All investigative output — conversational analysis, reports, case artefacts — must comply with these rules. No exceptions.

1. **Every finding must be provable with supplied data.** If the data does not exist to support a claim, the claim cannot be made.
2. **Temporal proximity is never causation.** Two events happening near each other in time is not evidence of a causal link. Causation requires a data-level link (shared URL, hash, process ID, audit log entry).
3. **No gap-filling with speculation.** If a step in the attack chain is not evidenced by data, state it as unknown. Never write "X led to Y" when no data shows X led to Y.
4. **Prove the full evidence chain before attribution.** Each link (email → click → download → execution) requires its own independent evidence. If any link is missing, the attribution is incomplete — say so.
5. **Actively seek disconfirming evidence.** When a hypothesis forms, identify what data would disprove it and check that data before proceeding.
6. **Never produce final reports on incomplete evidence** without clearly marking what is confirmed, what is assessed (inference), and what is unknown.
7. **Language discipline:** "Confirmed" = data proves it. "Assessed" / "Assessed with [high/medium/low] confidence" = inference supported by evidence. "Unknown" / "Not determined" = no data. Never use "confirmed" for an inference.
8. **Verify before asserting.** Never assume a fact when the data to confirm it is available. If a directory, identity table, log, or lookup can resolve an attribute (role, department, ownership, configuration), query it before stating it. The data source is authoritative — inferences drawn from context, naming conventions, or prior assumptions are not.
9. **Evidence and findings MUST be logged via tools before any report is produced.** `save_report` (MDR, PUP, exec summary, sec arch) requires a prior chain of `add_evidence` (raw observations: query hits, file analysis, enrichment verdicts, audit log entries) and `add_finding` (analyst conclusions tied to specific evidence IDs). A report on a case with no recorded `evidence` or `findings` artefacts is by definition unprovable and violates rules 1–4. If the analyst asks for a report on such a case, **stop and backfill the evidence/findings record from the data already in context before generating the report.** Never paper over a missing chain by writing prose straight into the report. Enforced in code: `save_report` **refuses** evidence-bearing types (mdr_report, pup_report, executive_summary, security_arch_review) until the case notes contain at least one evidence entry and one `**Finding (...)**` entry — no bypass flag. The matching `prepare_*` tools return `evidence_entries`/`finding_entries` counts plus a `rule9_warning` when either is zero — backfill at prepare time, before writing the report. Every successful save also returns non-blocking `quality_warnings` (deterministic causal-language and speculative-language flags) — review them and revise the deliverable if a claim slipped through. The canonical long-form standards are served live as `socai://analytical-standards`.

### Behavioural Assessment

A suspicious IP or impossible-travel alert is a SIGNAL, not a verdict. Assess what the session **did**, not just where it came **from**:

- **Attacker TTPs:** inbox rule creation, mail forwarding, keyword searching (invoice/payment/password), BEC composition, OAuth app consent, MFA registration, bulk mail download, SharePoint mass exfiltration, rapid lateral movement.
- **Normal user behaviour:** reading routine emails, opening shared docs, calendar, standard app usage, slow organic browsing.

If session activity is entirely consistent with normal behaviour and shows zero attacker TTPs — even from a datacenter IP — the most likely explanation is a personal VPN. Confirm with the user before recommending containment.

## Cross-Case Correlation (MANDATORY when recurrence is plausible)

`recall_cases` and `campaign_cluster` are not optional polish — they are the only way to detect shared infrastructure across the one-alert-one-case boundary. Run them proactively, not reactively:

- **`recall_cases`** — call at the start of any investigation with a non-trivial IOC set (domains, hashes, sender addresses, infrastructure). Cheap; surfaces prior cases that touched the same indicators.
- **`campaign_cluster`** — call whenever `recall_cases` returns ≥1 prior case with overlapping IOCs, or whenever the alert pattern (phishing lure theme, malware family, target client) matches recent traffic. Do not wait to be asked.
- Document the result in `add_evidence` even when it returns no overlap — "no cross-case overlap found" is itself a finding that strengthens the report.

## Enrichment & Lookup Preferences

1. **Always use socai system tools first** — CLI (`socai.py enrich`, `socai.py triage`) or MCP tools (`enrich_iocs`, `quick_enrich`, `triage_iocs`, `extract_iocs_from_text`)
2. **Client baseline is MANDATORY, not optional.** Call `get_client_baseline` (and `lookup_client` for the knowledge base) on every case before drawing behavioural conclusions. Behavioural context is the primary defence against VPN/geo false positives, against misclassifying authorised activity as malicious, and against missing genuinely anomalous activity that looks routine in isolation. "Optional but recommended" wording elsewhere is superseded by this rule. Skip only when the case is closed at triage as a pure infrastructure FP (e.g. detection-logic bug with no user/host context required).
3. **Caseless first** — use `quick_enrich` for ad-hoc IOC lookups before creating a case. If IOCs are malicious, create a case with `enrichment_id` to auto-import results (no re-enrichment). RFC-1918 / private IPs are tagged `private_internal` instantly (no provider calls). Client-owned domains/URLs (the case client's `known_infrastructure` in `config/client_entities.json`) are auto-skipped from enrichment — known estate, never an IOC.
4. **Choose enrichment depth based on the situation** — both `quick_enrich` and `enrich_iocs` accept a `depth` parameter (`"auto"` default, `"fast"` for FP/PUP/bulk triage, `"full"` for high-severity / novel IOCs). See `socai://enrichment-depths` for the full decision matrix.
5. **Triage runs automatically before enrichment** — IOCs with sufficient cached coverage and IOCs that are routine for the client (via client baseline) are skipped automatically to save API quota.
6. **Use combined tools for efficiency** — `capture_urls` auto-runs phishing detection (`detect_phishing=True` default). `analyse_file` is tiered (`depth="auto"` smart escalates; `"fast"` Tier 1 only; `"full"` runs all tiers including YARA). Use `run_kql_batch` for multiple independent queries instead of sequential `run_kql`. `lookup_client` always returns the full knowledge base, response playbook, and Sentinel reference inline — raw context, no slimming.
7. **Web search is a last resort** — only when system tools return nothing or query is pure OSINT context
8. **Never use generic web lookups when a structured tool exists**

## Handling Files in Claude Desktop

When a file arrives in Claude Desktop's sandbox (PDF, doc, script, binary, archive, email), use the **`triage_file`** MCP prompt — it walks through Desktop-side extraction (hash, file type, IOCs) and only escalates to server-side upload when deep static analysis or sandbox detonation is actually required.

**Why:** Every byte shipped through the MCP transport costs context window space. `upload_file_content` (in-band base64) is especially costly — bytes land in the chat transcript and persist for the session. The default cap is 2 MB raw; anything larger must use `prepare_file_upload` + curl. For most malicious-file work the file does not need to leave the sandbox at all.

The upload tools (`prepare_file_upload`, `upload_file_content`) are the escalation path, not the default.

**Server-side analysers** (call after the file is on the MCP server, e.g. via `prepare_file_upload`):

- `analyse_file(file_path, case_id, depth="auto", run_yara="auto")` — **single entry point** for all static file analysis. Tier 1: hash, magic, entropy, strings, reputation. Tier 2 (auto-escalates on signal, forced by `depth="full"`): format-specific specialist parse — PE imports/sections, Office macros/DDE, PDF JS/actions, LNK target, OneNote embedded files, MSI streams, Mach-O, disk image. Tier 3 (auto on strong signal, forced by `depth="full"` or `run_yara="true"`): YARA scan + sandbox recommendation.
- `analyse_memory_dump` — fast string/IOC/pattern scan of `.dmp`/`.mem`/`.raw`
- `analyse_memory_volatility` — Volatility3 pslist/netscan/malfind/cmdline/svcscan with auto OS detection

## Critical Conventions

### File I/O
- **Always** use `write_artefact()` or `save_json()` from `tools/common.py` for all file outputs
- `save_json(path, data)` — path first, data second
- **Never** call `audit()` after `write_artefact()` or `save_json()` — they audit internally (duplicate entries)
- Only call `audit()` directly for non-file-write events

### Error handling
- Every `except` block must call `log_error(case_id, step, error, *, severity, traceback, context)`
- Severity levels: `error` (failed), `warning` (degraded), `info` (environment signal)
- Assess errors: `python3 socai.py errors`; clear after review: `--clear`

### Progress / status output
- Use `eprint(...)` from `tools/common.py` for any progress, status, or human-readable log line emitted during tool execution — **never** `print(...)`
- Stdio MCP transport uses **stdout as the JSON-RPC channel**. Any `print()` in tool code corrupts the protocol and shows up in Claude Desktop as `Unexpected token ... is not valid JSON` errors (orange toasts)
- `print(...)` is only acceptable inside `if __name__ == "__main__":` blocks (CLI entrypoints), where stdout legitimately carries the tool's user-facing output

### Timestamps and utilities
- Use `utcnow()` from `tools/common.py` for timestamp strings and `utcnow_dt()` for tz-aware `datetime` values — never `datetime.now()` or `datetime.utcnow()`

### Metrics logging
- Use `log_metric(event, *, case_id, **fields)` from `tools/common.py` for investigation metrics
- Metrics are written to `registry/metrics.jsonl` (thread-safe JSONL append, same pattern as `audit()`)
- Event types: `case_phase_change`, `enrichment_complete`, `verdict_scored`, `report_saved`, `investigation_summary`
- Pipeline tools emit metrics automatically — don't call `log_metric()` for events already emitted by `enrich()`, `score_verdicts()`, `save_report()`, or `index_case()`
- Query with: `python3 scripts/metrics_report.py` (summary), `--compare` (analyst comparison), `--json` (raw)

### Tool return shape (raw data, no slimming)
- **No slimming, no summarisation, no truncation.** Tools return raw payloads in full. Summaries lose accuracy: a "top-N" or per-type cap drops evidence the model would otherwise use to back a finding. Per-turn payload size is the cost of correctness, not a budget to optimise against.
- Findings that enter a report must be backed by the raw data already in context (see Analytical Standards rule 1) — never by an on-disk pointer the model "could" fetch.
- All enrichment payloads (`quick_enrich`, `enrich_iocs`), recall results, correlation hits, and client context (`lookup_client`) are returned full. The `_slim_*` helpers and `verbose`/`slim` parameters have been removed. `save_report`'s inline `report_md` is a deliberate *terminal* payload — also full.

### Report defanging
- Malicious + suspicious IOCs are defanged in final reports via `defang_report()` in `tools/common.py`
- Hashes and file paths are never defanged

### Tool discipline (Claude Desktop side)
- **Load schemas before calling.** Deferred MCP tools listed in `<system-reminder>` blocks are name-only — calling them blind produces schema errors (e.g. recurring `add_finding` missing `finding_type`). Run `tool_search "select:<tool>[,<tool>...]"` on the first use in a session, then call. Treat a schema error as a signal to schema-fetch, not to retry-with-guesses.
- One schema fetch per session per tool is enough — schemas are stable within a session.

### Tests
- All tests use case ID `IV_CASE_000` with autouse fixture for setup/teardown
- Fixtures in `tests/fixtures/`

## Detailed Documentation

Read these only when working on the relevant area:

| Doc | Contents |
|-----|----------|
| `docs/pipeline.md` | HITL workflow, tool sequence, auto-disposition, auto-close |
| `docs/tools-reference.md` | All tool details: case memory, baselines, GeoIP, scheduler, web capture, phishing, enrichment, sandbox, forensics, etc. |
| `docs/configuration.md` | Env vars, API keys, client config |
| `docs/artefacts.md` | Complete file/artefact path reference table |
| `docs/extending.md` | How to add new providers, tools, brands, detectors |
| `docs/architecture.md` | System overview, data flow, tool contracts |
| `docs/architecture_diagram.md` | Mermaid diagrams: system architecture, HITL sequence |
| `docs/sandbox.md` | Sandbox detonation: setup, network modes, artefacts, safety, interactive mode |
| `docs/mcp-server.md` | MCP server: auth, RBAC, tools, resources, prompts, deployment |
| `docs/defender-hunting.md` | Defender XDR Advanced Hunting API: multi-tenant app reg, per-client tenant_id, run_defender_kql |
| `docs/crowdstrike.md` | CrowdStrike Falcon + NG-SIEM/LogScale: per-client API client, falcon_region, run_falcon_cql + classic FQL tools |
| `docs/encore-eql.md` | Encore Gateway EQL: refresh-token auth, Cloudflare UA quirk, scripts/eql_direct.py, `eql-hosted` MCP server (Claude Code `.mcp.json` + Desktop `mcp-remote` wrapper), EQL syntax, case-scoped tools (`eql_identity_assessment` — internal/external user + device/asset scoping step, run before `eql_entity_context`; `eql_entity_context`, `eql_posture_context`, `eql_query`), and **vulnerability hunting** (caseless `eql_vuln_hunt` + `vulnerability-hunting` playbook + `vuln_hunt_report` deliverable; EQL boolean-WHERE quirk) |
| `docs/roadmap.md` | Planned features: tiered incident model, SOAR/Zoho integration |
