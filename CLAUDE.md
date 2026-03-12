# CLAUDE.md

Guidance for Claude Code working with the socai codebase. **Details are in `docs/` — only read them when working on relevant areas.**

## Commands

```bash
# Tests (run from repo root)
python3 -m pytest tests/ -v
python3 -m pytest tests/test_tools.py::test_extract_iocs_from_text -v

# Re-run stages
python3 socai.py report --case IV_CASE_001
python3 socai.py enrich --case IV_CASE_001
python3 socai.py fp-ticket --case IV_CASE_001 --alert alert.json
python3 socai.py fp-tuning --case IV_CASE_001 --alert alert.json [--query rule.kql] [--platform sentinel]
python3 socai.py pup-report --case IV_CASE_001

# MCP server
python3 -m mcp_server                                         # SSE (default)
SOCAI_MCP_TRANSPORT=streamable-http python3 -m mcp_server      # Streamable HTTP

# All subcommands: python3 socai.py --help
```

Install: `pip install -r requirements.txt` (append `--break-system-packages` on Debian). Playwright: `playwright install chromium` (optional; falls back to `requests`).

All scripts must be run from the repo root (`sys.path.insert` is anchored to parent of `tools/`).

## Architecture at a Glance

- **CLI:** `socai.py` — entrypoint; `python3 socai.py --help` for full subcommand list
- **Tools** (`tools/`) — stateless functions; accept `case_id`, write via `write_artefact()`/`save_json()`, return manifest dicts
- **MCP Server** (`mcp_server/`) — HTTPS SSE on port 8001, JWT RBAC; see `docs/mcp-server.md`
- **Shared API** (`api/`) — auth, actions, timeline, input parsing — used by MCP server
- **Pipeline:** HITL (human-in-the-loop) — analyst drives investigation step by step via MCP tools; see `docs/pipeline.md`
- **State:** all filesystem, no database. Registry in `registry/`, per-case in `cases/<ID>/`, articles in `articles/`
- **Auto-close on Deliverable Collection** — `generate_mdr_report` (preserves disposition), `generate_pup_report` (`pup_pua`), `fp_ticket` (`false_positive`). Close logic in tool layer. `fp_tuning_ticket` does NOT auto-close.

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

1. **Always use socai system tools first** — CLI (`socai.py enrich`, `socai.py triage`) or MCP tools (`enrich_iocs`, `triage`, `extract_iocs`)
2. **Web search is a last resort** — only when system tools return nothing or query is pure OSINT context
3. **Never use generic web lookups when a structured tool exists**

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
| `docs/pipeline.md` | HITL workflow, tool sequence, auto-disposition, auto-close |
| `docs/tools-reference.md` | All tool details: web capture, phishing, enrichment, sandbox, forensics, etc. |
| `docs/configuration.md` | Env vars, API keys, model tiering summary, client aliasing config |
| `docs/artefacts.md` | Complete file/artefact path reference table |
| `docs/extending.md` | How to add new providers, tools, brands, detectors |
| `docs/architecture.md` | System overview, data flow, Claude API usage, tool contracts |
| `docs/architecture_diagram.md` | Mermaid diagrams: system architecture, HITL sequence |
| `docs/model_tiering.md` | Full model tiering matrix and call site map |
| `docs/sandbox.md` | Sandbox detonation: setup, network modes, artefacts, safety, interactive mode |
| `docs/mcp-server.md` | MCP server: auth, RBAC, tools, resources, prompts, deployment |
| `docs/roadmap.md` | Planned features: tiered incident model, SOAR/Zoho integration |
