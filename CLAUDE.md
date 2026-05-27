# CLAUDE.md

Guidance for Claude Code working with the socai codebase. **Details are in `docs/` — only read them when working on relevant areas.**

## Commands

```bash
# Tests (run from repo root)
python3 -m pytest tests/ -v
python3 -m pytest tests/test_tools.py::test_extract_iocs_from_text -v

# Create a case
python3 socai.py create-case --title "Alert title" --severity high --analyst <name> --client <client> --tags "tag1,tag2"

# Re-run stages
python3 socai.py enrich --case IV_CASE_001
python3 socai.py fp-ticket --case IV_CASE_001 --alert alert.json
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

# MCP server
python3 -m mcp_server                                         # SSE (default), core toolset
SOCAI_MCP_TRANSPORT=streamable-http python3 -m mcp_server      # Streamable HTTP
SOCAI_MCP_TOOLSETS=all python3 -m mcp_server                   # register all 113 tools up front (legacy)

# All subcommands: python3 socai.py --help
```

Install: `pip install -r requirements.txt` (append `--break-system-packages` on Debian). Playwright: `playwright install chromium` (optional; falls back to `requests`).

All scripts must be run from the repo root (`sys.path.insert` is anchored to parent of `tools/`).

## Architecture at a Glance

- **CLI:** `socai.py` — entrypoint; `python3 socai.py --help` for full subcommand list
- **Tools** (`tools/`) — stateless functions; accept `case_id`, write via `write_artefact()`/`save_json()`, return manifest dicts. No direct LLM/API calls — all LLM reasoning is handled by the local Claude Desktop agent via MCP prompts.
- **MCP Server** (`mcp_server/`) — HTTPS SSE on port 8001, JWT RBAC; see `docs/mcp-server.md`
- **Modular toolsets** (`TOOLSETS` in `mcp_server/tools.py`) — only the **core** toolset (~63 tools: case mgmt, enrichment/triage, log hunting, recall, reporting/close) loads at startup; specialist groups (`phishing`, `malware`, `forensics`, `intel`, `darkweb`, `analysis`, `admin`) load **on demand** via `load_toolset`, which pushes `tools/list_changed`. This roughly halves per-session upfront token cost. `classify_attack` returns `recommended_toolsets`; **after classifying, immediately `load_toolset(<name>)` for each recommended group.** If a tool you need isn't available, call `list_toolsets` then `load_toolset`. Profile set by `SOCAI_MCP_TOOLSETS` (default `core`; `all` = legacy). Any new tool MUST be added to a `TOOLSETS` group (unassigned tools fall back to core with a warning). See `socai://toolsets`.
- **Shared API** (`api/`) — auth, actions, timeline, input parsing — used by MCP server
- **Pipeline:** HITL (human-in-the-loop) — analyst drives investigation step by step via MCP tools and prompts. Case creation is deferred — deliverable tools auto-create if needed. See `docs/pipeline.md`
- **State:** all filesystem, no database. Registry in `registry/`, per-case in `cases/<ID>/`, articles in `articles/`
- **Background scheduler** (`tools/scheduler.py`) — daemon thread started by MCP server; refreshes GeoIP (7d), rebuilds client baselines (24h), rebuilds case memory BM25 index (6h)
- **Metrics** (`registry/metrics.jsonl`) — investigation lifecycle events with timing, coverage, confidence, and completeness metrics; query via `scripts/metrics_report.py`. Includes `workflow_summary` events (auto-captured tool sequences, friction signals) — query via `scripts/workflow_report.py`
- **Workflow analytics** (`mcp_server/usage.py`) — auto-captures ordered tool sequences per session with timing, categories (via `TOOL_TAXONOMY`), and friction detection. Flushed to metrics on session expiry or server shutdown. New tools must be registered in `TOOL_TAXONOMY`
- **Caseless enrichment** (`registry/quick_enrichments/`) — `quick_enrich` persists ad-hoc IOC lookups here. Import into a case via `enrichment_id` parameter on `create_case` or `import_enrichment` tool
- **Caseless browser sessions** (`browser_sessions/<session_id>/artefacts/`) — `start_browser_session` without `case_id` stores artefacts here. Read via `read_browser_session_file` / `list_browser_session_files`. Import into a case via `import_browser_session(session_id, case_id)`
- **Intelligence layer** — `tools/case_memory.py` (BM25 semantic recall), `tools/client_baseline.py` (per-client profiles), `tools/geoip.py` (local MaxMind GeoLite2)
- **Reports are analyst-initiated and TP-gated** — Do **not** auto-generate reports. A full MDR report is produced only for **True Positive** cases, and only on analyst request (for a TP it is the expected deliverable — recommend it, then produce it on the analyst's go-ahead). Every other disposition (`benign_positive`, `false_positive`, `pup_pua`, `benign`, `inconclusive`) closes via `close_case` with a brief note and **no** auto-generated report. All deliverable prompts/tools remain available on demand — if the analyst decides a non-TP case needs written output, they ask, and only then is it generated. This supersedes any older "PUP short-circuit → auto PUP report" or "TP/BP → MDR report" wording.
- **Auto-close on Deliverable Collection** — `save_report` (after MCP prompt for MDR report, PUP report, etc.) and `fp_ticket` (`false_positive`). These tools auto-create and promote a case if one doesn't exist. Close logic in tool layer. Deliverable workflow: use MCP prompt to produce HTML report → `save_report` to persist and auto-close. All reports are HTML — `save_report` accepts HTML directly (markdown fallback for legacy). Template resources (`socai://templates/mdr-report`, `socai://templates/pup-report`) provide HTML skeletons and CSS. Reports are viewable via `socai://cases/{case_id}/report` after saving. `fp_tuning_ticket` auto-closes with `false_positive`. `executive_summary` and `security_arch_review` do NOT auto-close (supplementary outputs, typically produced after the primary deliverable has already closed the case). `read_report` is read-only (no auto-close). `close_case` is idempotent (no-op if already closed).
- **Report rendering in the visualiser** — `save_report` returns the persisted (defanged) HTML as `report_html` in its response. **Render `report_html` as a self-contained HTML artifact** so Claude Desktop opens it in the visualiser (the Artifacts side panel) — cards, badges, styled headers, syntax-highlighted IOCs. Do not paste the raw HTML into the chat body, summarise, truncate, paraphrase, or wrap it in code fences. The HTML is also persisted on disk for the customer deliverable, but the analyst's review happens in the visualiser.

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

1. **Always use socai system tools first** — CLI (`socai.py enrich`, `socai.py triage`) or MCP tools (`enrich_iocs`, `quick_enrich`, `triage`, `extract_iocs`)
2. **Caseless first** — use `quick_enrich` for ad-hoc IOC lookups before creating a case. If IOCs are malicious, create a case with `enrichment_id` to auto-import results (no re-enrichment). RFC-1918 / private IPs are tagged `private_internal` instantly (no provider calls).
3. **Choose enrichment depth based on the situation** — both `quick_enrich` and `enrich_iocs` accept a `depth` parameter (`"auto"` default, `"fast"` for FP/PUP/bulk triage, `"full"` for high-severity / novel IOCs). See `socai://enrichment-depths` for the full decision matrix.
4. **Triage runs automatically before enrichment** — IOCs with sufficient cached coverage and IOCs that are routine for the client (via client baseline) are skipped automatically to save API quota.
5. **Use combined tools for efficiency** — `capture_urls` auto-runs phishing detection (`detect_phishing=True` default). `analyse_file` is tiered (`depth="auto"` smart escalates; `"fast"` Tier 1 only; `"full"` runs all tiers including YARA). Use `run_kql_batch` for multiple independent queries instead of sequential `run_kql`. On re-lookup of a client already loaded this session, call `lookup_client(slim=True)` to skip the ~25 KB knowledge/playbook payload already in context.
6. **Web search is a last resort** — only when system tools return nothing or query is pure OSINT context
7. **Never use generic web lookups when a structured tool exists**

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
- Use `utcnow()` from `tools/common.py` — never `datetime.now()` or `datetime.utcnow()`

### Metrics logging
- Use `log_metric(event, *, case_id, **fields)` from `tools/common.py` for investigation metrics
- Metrics are written to `registry/metrics.jsonl` (thread-safe JSONL append, same pattern as `audit()`)
- Event types: `case_phase_change`, `enrichment_complete`, `verdict_scored`, `report_saved`, `investigation_summary`
- Pipeline tools emit metrics automatically — don't call `log_metric()` for events already emitted by `enrich()`, `score_verdicts()`, `save_report()`, or `index_case()`
- Query with: `python3 scripts/metrics_report.py` (summary), `--compare` (analyst comparison), `--json` (raw)

### Tool return shape (per-turn context cost)
- The real driver of MCP context cost is **per-turn result payloads**, which compound on every later turn — not the one-time tool-schema list. Shape what a tool *returns*, not just what it writes to disk.
- Any tool returning a **variable-length array or raw text** must return: the **conclusions in full** (verdicts, classifications, counts, links) + a **relevance-ranked top-N** of the bulky rows + an explicit **"N of M" disclosure** + a **pointer** to the full data (an `enrichment_id`, artefact path, or `socai://cases/{id}/…` resource), with a **`verbose=True`** escape hatch that returns the full payload. Full fidelity always persists to disk — nothing is discarded.
- **Never lossy-summarise evidence and never truncate silently.** Findings that enter a report must be backed by the raw data the model fetches via the pointer (see Analytical Standards).
- Reuse `_slim_enrichment()` / `_slim_recall()` / `_slim_correlate()` in `mcp_server/tools.py` as templates. `save_report`'s inline `report_html` is a deliberate *terminal* (last-action, non-compounding) payload — left full on purpose.

### Report defanging
- Malicious + suspicious IOCs are defanged in final reports via `defang_report()` in `tools/common.py`
- Hashes and file paths are never defanged

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
| `docs/roadmap.md` | Planned features: tiered incident model, SOAR/Zoho integration |
