# CLAUDE.md

Guidance for Claude Code working with the socai codebase. **Details are in `docs/` — only read them when working on relevant areas.**

## Commands

```bash
# Tests (run from repo root)
python3 -m pytest tests/ -v
python3 -m pytest tests/test_tools.py::test_extract_iocs_from_text -v

# Full investigation
python3 socai.py investigate --case IV_CASE_001 --title "..." --severity high \
    --url "https://example.com" --logs ./logs --zip sample.zip --zip-pass infected

# Quick-run (auto-generates case ID)
python3 socai.py url "https://suspicious-site.com"
python3 socai.py domain evil-domain.com
python3 socai.py file sample.zip

# Re-run stages
python3 socai.py report --case IV_CASE_001
python3 socai.py enrich --case IV_CASE_001
python3 socai.py secarch --case IV_CASE_001
python3 socai.py fp-ticket --case IV_CASE_001 --alert alert.json
python3 socai.py fp-tuning --case IV_CASE_001 --alert alert.json [--query rule.kql] [--platform sentinel]
python3 socai.py pup-report --case IV_CASE_001

# Batch processing
python3 socai.py batch-submit --cases IV_CASE_001 IV_CASE_002 --tools mdr-report exec-summary
python3 socai.py batch-status --batch-id <id>
python3 socai.py batch-collect --batch-id <id>

# Threat articles (ET/EV monthly reporting)
python3 socai.py articles --days 7 --count 3 --analyst "J. Smith"
python3 socai.py articles --category EV --pick 1,3,5
python3 socai.py articles-generate --urls URL1 URL2 --title "..." --category ET
python3 socai.py articles-list --month 2026-03

# Velociraptor ingest (offline collector ZIP, VQL exports, or directory)
python3 socai.py velociraptor /path/to/collection.zip --case IV_CASE_001
python3 socai.py velociraptor /path/to/results/ --severity high
python3 socai.py velociraptor /path/to/Windows.System.Autoruns.json --case IV_CASE_001 --no-analyse

# MDE investigation package ingest (alternative to Velociraptor when MDE is available)
python3 socai.py mde-package /path/to/InvestigationPackage.zip --case IV_CASE_001
python3 socai.py mde-package /path/to/mde_export/ --severity high --no-analyse

# Process memory dump guidance & analysis
python3 socai.py memory-guide --case IV_CASE_001 --process lsass.exe --pid 672 --alert "Credential dumping detected"
python3 socai.py memory-analyse /path/to/process.dmp --case IV_CASE_001

# Disposable browser sessions (Docker-based, tcpdump-monitored, no automation markers)
python3 socai.py browser-session "https://suspicious-site.com" --case IV_CASE_001
python3 socai.py browser-stop <session-id>
python3 socai.py browser-list

# Rumsfeld investigation pipeline (LLM reasoning layer)
python3 socai.py investigate --case IV_CASE_001 --title "..." --mode rumsfeld
python3 socai.py matrix --case IV_CASE_001                    # generate/view investigation matrix
python3 socai.py matrix --case IV_CASE_001 --summary          # compact summary
python3 socai.py determination --case IV_CASE_001             # evidence-chain disposition analysis
python3 socai.py quality-gate --case IV_CASE_001              # report analytical standards check
python3 socai.py followup --case IV_CASE_001                  # list follow-up proposals
python3 socai.py followup --case IV_CASE_001 --approve p_001  # execute one proposal

# Sandbox detonation (Docker-based, strace/tcpdump-monitored)
python3 socai.py sandbox-session /path/to/sample --case IV_CASE_001 [--timeout 120] [--network monitor|isolate]
python3 socai.py sandbox-session /path/to/sample --case IV_CASE_001 --interactive
python3 socai.py sandbox-stop --session <session-id>
python3 socai.py sandbox-list

# MCP server (HTTPS SSE, port 8001, JWT auth)
python3 -m mcp_server                                # SSE transport (default)
SOCAI_MCP_TRANSPORT=streamable-http python3 -m mcp_server  # Streamable HTTP
SOCAI_MCP_PORT=9001 python3 -m mcp_server             # Custom port

# Other subcommands: mdr-report, triage, email-analyse, campaigns, sandbox,
#   anomalies, errors, timeline, pe-analysis, yara, evtx, cve-context,
#   exec-summary, queries, client-query, response-actions, weekly, list, close
```

Install: `pip install -r requirements.txt` (append `--break-system-packages` on Debian). Playwright: `playwright install chromium` (optional; falls back to `requests`).

All scripts must be run from the repo root (`sys.path.insert` is anchored to parent of `tools/`).

## Architecture at a Glance

- **CLI:** `socai.py` — entrypoint for all commands
- **Agents** (`agents/`) — thin orchestration classes inheriting `BaseAgent`; call tool functions, never write files directly
- **Tools** (`tools/`) — stateless functions; accept `case_id`, write via `write_artefact()`/`save_json()`, return manifest dicts
- **MCP Server** (`mcp_server/`) — HTTPS SSE transport on port 8001 with JWT RBAC; 72 tools, 22 resources, 5 prompts for external MCP clients (Claude Desktop, LLM agents)
- **Rumsfeld Pipeline** (`agents/rumsfeld.py` + `tools/investigation_matrix.py`, `tools/determination.py`, `tools/report_quality_gate.py`) — LLM reasoning layer wrapping ChiefAgent; produces investigation matrix (known_knowns, known_unknowns, hypotheses), evidence-chain determination (shadow mode), report quality gate, and gap analysis with follow-up proposals
- **Shared API** (`api/`) — auth (JWT), jobs (background pipeline), actions (tool orchestration), timeline, input parsing — used by MCP server
- **Batch** (`tools/batch.py`) — bulk LLM processing via Claude Messages Batch API
- **Threat Articles** (`tools/threat_articles.py`) — ET/EV article discovery, clustering, and generation for monthly reporting; dedup via local index + Confluence
- **Velociraptor** (`tools/velociraptor_ingest.py`) — offline collector ZIP / VQL result ingest with artefact-aware normalisation (EVTX, autoruns, netstat, processes, services, tasks, prefetch, shimcache, amcache, MFT, USN)
- **MDE Ingest** (`tools/mde_ingest.py`) — Microsoft Defender for Endpoint investigation package ingest with 13 normalisers; alternative to Velociraptor when MDE access is available
- **Memory Guidance** (`tools/memory_guidance.py`) — process memory dump guidance (MDE Live Response instructions) and read-only `.dmp` analysis (strings, PE headers, suspicious patterns, risk scoring)
- **Browser Session** (`tools/browser_session.py`) — disposable Docker-based Chrome sessions with passive tcpdump network capture via noVNC; no automation markers (no CDP, no Selenium) to avoid analysis-evasion by phishing kits
- **Sandbox Detonation** (`tools/sandbox_session.py`) — containerised malware sandbox for dynamic analysis; executes ELF/scripts/PE (via Wine) under strace with tcpdump, honeypot DNS/HTTP, and filesystem monitoring; automated and interactive modes (see `docs/sandbox.md`)
- **Web Search** (`tools/web_search.py`) — OSINT web search fallback; Brave Search API (if `SOCAI_BRAVE_SEARCH_KEY` set) or DuckDuckGo HTML (free, no key). Used by the LLM when structured enrichment APIs lack data.
- **Confluence** (`tools/confluence_read.py`) — read-only Confluence Cloud client (scoped token, single space)
- **State:** all filesystem, no database. Registry in `registry/`, per-case in `cases/<ID>/`, articles in `articles/`
- **Attack-Type Classification** (`tools/classify_attack.py`) — deterministic keyword + input-shape classifier; routes pipeline via per-type profiles (phishing, malware, account_compromise, privilege_escalation, pup_pua, generic)
- **PUP/PUA Playbook** (`tools/generate_pup_report.py`) — lightweight pipeline for Potentially Unwanted Program detections; auto-detected from title/notes/enrichment or analyst-triggered; skips attack-chain analysis, produces PUP-specific report with software ID, scope, risk, removal steps
- **Auto-close on Deliverable Collection** — cases auto-close when the analyst collects their deliverable: `generate_mdr_report` (preserves existing disposition), `generate_pup_report` (`pup_pua`), `fp_ticket` (`false_positive`). Close logic lives in the tool layer so it works across CLI and MCP server. Note: `fp_tuning_ticket` does NOT auto-close — it generates the SIEM engineering handoff alongside the FP closure.
- **Pipeline:** `ChiefAgent.run()` classifies attack type → selects profile → orchestrates steps with parallel execution; skips irrelevant steps per type (see `docs/pipeline.md`)
- **Rumsfeld Pipeline:** `RumsfeldAgent.run()` wraps ChiefAgent → adds investigation matrix (9c) → determination engine (14b, replaces auto-close validator) → report quality gate (15b) → gap analysis + follow-up proposals. Activated via `--mode rumsfeld` or MCP. All LLM components are advisory (cannot override deterministic logic), opt-in (`SOCAI_ENRICH_DIRECTOR=1`), and resilient (return None on failure)

## Sentinel Incident Classification

When closing Sentinel incidents, use exactly one of three mutually exclusive classifications:

- **True Positive (TP)** — alert correctly detected genuinely malicious activity
- **Benign Positive (BP)** — alert correctly fired on real matching activity, but that activity is authorised/non-threatening. Sub-types: "suspicious but expected", "suspicious but not malicious"
- **False Positive (FP)** — alert misfired, detection logic was wrong

Decision: Did the detection fire correctly? NO → FP. YES → Was activity malicious? YES → TP. NO → BP.

Never combine classifications ("True Positive Benign Positive" is invalid). Disposition values: `true_positive`, `benign_positive`, `false_positive`, `benign`, `pup_pua`, `inconclusive`.

## Case Isolation

**One alert = one case.** Every new alert gets its own case, even when the same user/host/IOCs appear in prior cases. Never append new alert data to an existing case. Cross-case correlation is on-demand via `recall_cases` (historical IOC/keyword lookup) and `campaign_cluster` (IOC overlap comparison).

## Analytical Standards (MANDATORY)

All investigative output — conversational analysis, reports, case artefacts — must comply with these rules. No exceptions.

1. **Every finding must be provable with supplied data.** If the data does not exist to support a claim, the claim cannot be made.
2. **Temporal proximity is never causation.** Two events happening near each other in time is not evidence of a causal link. Causation requires a data-level link (shared URL, hash, process ID, audit log entry).
3. **No gap-filling with speculation.** If a step in the attack chain is not evidenced by data, state it as unknown. Never write "X led to Y" when no data shows X led to Y.
4. **Prove the full evidence chain before attribution.** Each link (email → click → download → execution) requires its own independent evidence. If any link is missing, the attribution is incomplete — say so.
5. **Actively seek disconfirming evidence.** When a hypothesis forms, identify what data would disprove it and check that data before proceeding.
6. **Never produce final reports on incomplete evidence** without clearly marking what is confirmed, what is assessed (inference), and what is unknown.
7. **Language discipline:** "Confirmed" = data proves it. "Assessed" / "Assessed with [high/medium/low] confidence" = inference supported by evidence. "Unknown" / "Not determined" = no data. Never use "confirmed" for an inference.

## Enrichment & Lookup Preferences

When enriching IOCs (IPs, domains, hashes, URLs) or performing lookups:

1. **Always use socai system tools first** — CLI (`socai.py enrich`, `socai.py triage`) or MCP tools (`enrich_iocs`, `triage`, `extract_iocs`) provide structured enrichment via configured API integrations (VirusTotal, AbuseIPDB, Shodan, etc.)
2. **Web search is a last resort** — only fall back to `WebSearch`/`WebFetch` when system tools return no results or the query is OSINT/context that no structured API covers (e.g. threat actor background, CVE write-ups, vendor advisories)
3. **Never use generic web lookups when a structured tool exists** — manual web scraping of AbuseIPDB/VT pages is inferior to the API-backed enrichment the system already provides

## Critical Conventions

### File I/O
- **Always** use `write_artefact()` or `save_json()` from `tools/common.py` for all file outputs
- `save_json(path, data)` — path first, data second
- **Never** call `audit()` after `write_artefact()` or `save_json()` — they audit internally (duplicate entries)
- Only call `audit()` directly for non-file-write events (e.g. `BaseAgent._emit`)

### Error handling
- Every `except` block must call `log_error(case_id, step, error, *, severity, traceback, context)`
- Severity levels: `error` (failed), `warning` (degraded), `info` (environment signal)
- Assess errors: `python3 socai.py errors`; clear after review: `--clear`

### Timestamps and utilities
- Use `utcnow()` from `tools/common.py` — never `datetime.now()` or `datetime.utcnow()`

### Model selection
- Use `get_model(task, severity)` from `tools/common.py` — never hardcode model strings
- See `docs/model_tiering.md` for tier details and per-task assignments

### Client aliasing
- `SOCAI_ALIAS=1` redacts client names in LLM calls only; local artefacts stay real
- Alias/dealias cycle used in: `security_arch_review.py`, `generate_mdr_report.py`, `fp_ticket.py`, `client_query.py`, `executive_summary.py`
- `generate_report.py` has NO aliasing

### Report defanging
- Malicious + suspicious IOCs are defanged in final reports via `defang_report()` in `tools/common.py`
- Hashes and file paths are never defanged

### Tests
- All tests use case ID `TEST_AUTOMATED_001` with autouse fixture for setup/teardown
- Fixtures in `tests/fixtures/`

## Detailed Documentation

Read these only when working on the relevant area:

| Doc | Contents |
|-----|----------|
| `docs/pipeline.md` | Pipeline flow, execution model, parallel execution, auto-disposition, quick-run |
| `docs/tools-reference.md` | All tool details: web capture, phishing, enrichment, sandbox, forensics, etc. |
| `docs/configuration.md` | Env vars, API keys, model tiering summary, client aliasing config |
| `docs/artefacts.md` | Complete file/artefact path reference table |
| `docs/extending.md` | How to add new providers, tools, agents, brands, detectors |
| `docs/architecture.md` | High-level architecture diagram and data flow |
| `docs/model_tiering.md` | Full model tiering matrix and call site map |
| `docs/sandbox.md` | Sandbox detonation: setup, network modes, artefacts, safety, interactive mode |
| `docs/mcp-server.md` | MCP server: auth, RBAC, tools, resources, prompts, deployment |
| `docs/roadmap.md` | Planned features: tiered incident model, SOAR/Zoho integration |
