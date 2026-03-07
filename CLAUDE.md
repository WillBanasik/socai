# CLAUDE.md

Guidance for Claude Code working with the socai codebase. **Details are in `docs/` — only read them when working on relevant areas.**

## Commands

```bash
# Tests (run from repo root)
python3 -m pytest tests/ -v
python3 -m pytest tests/test_tools.py::test_extract_iocs_from_text -v

# Full investigation
python3 socai.py investigate --case C001 --title "..." --severity high \
    --url "https://example.com" --logs ./logs --zip sample.zip --zip-pass infected

# Quick-run (auto-generates case ID)
python3 socai.py url "https://suspicious-site.com"
python3 socai.py domain evil-domain.com
python3 socai.py file sample.zip

# Re-run stages
python3 socai.py report --case C001
python3 socai.py enrich --case C001
python3 socai.py secarch --case C001
python3 socai.py fp-ticket --case C001 --alert alert.json

# Batch processing
python3 socai.py batch-submit --cases C001 C002 --tools mdr-report exec-summary
python3 socai.py batch-status --batch-id <id>
python3 socai.py batch-collect --batch-id <id>

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
- **Web UI:** `api/chat.py` + `api/main.py` + `ui/case.html` — streaming SSE chat with activity feed and session management (see `docs/web-ui.md`)
- **Sessions** (`api/sessions.py`) — pre-case investigation conversations; materialise into full cases
- **Batch** (`tools/batch.py`) — bulk LLM processing via Claude Messages Batch API
- **State:** all filesystem, no database. Registry in `registry/`, per-case in `cases/<ID>/`, sessions in `sessions/`
- **Pipeline:** `ChiefAgent.run()` orchestrates 16 steps with parallel execution (see `docs/pipeline.md`)

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
| `docs/web-ui.md` | Chat interface, API routes, access control, available tools |
| `docs/extending.md` | How to add new providers, tools, agents, brands, detectors |
| `docs/architecture.md` | High-level architecture diagram and data flow |
| `docs/model_tiering.md` | Full model tiering matrix and call site map |
| `docs/roadmap.md` | Planned features: tiered incident model, SOAR/Zoho integration |
