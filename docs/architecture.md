# SOC-AI Architecture

## Overview

SOC-AI is a single-process, multi-agent Python application.  Agents are
plain Python classes that delegate work to tool wrapper functions.  All
persistent state lives in the local filesystem.

```
CLI (socai.py)
    └── ChiefAgent
          ├── PlannerAgent          → task plan
          ├── DomainInvestigatorAgent → web_capture × N
          ├── FileAnalystAgent       → extract_zip + static_file_analyse
          ├── LogCorrelatorAgent     → parse_logs × N + correlate
          ├── EnrichmentAgent        → extract_iocs + enrich
          └── ReportWriterAgent      → generate_report + index_case

Web UI (api/main.py + api/chat.py + ui/*.html)
    ├── Case-mode chat       → 22 tools via TOOL_DEFS
    ├── Session-mode chat    → 31 tools via SESSION_TOOL_DEFS
    ├── SSE streaming        → progressive token delivery
    ├── Session management   → CRUD + materialisation to cases
    ├── Cases browse page    → filterable card grid (ui/cases.html)
    ├── Case detail page     → read-only summary with investigation log & KQL queries (ui/case-detail.html)
    ├── Dashboard            → Chart.js landscape visualisation (ui/dashboard.html)
    ├── CTI integration      → OpenCTI feed, trending, ATT&CK heatmap, watchlist, IOC decay (api/opencti.py)
    └── Case context switch  → load/save case context in sessions

Batch API (tools/batch.py)
    └── Bulk LLM processing  → submit / poll / collect pattern
```

## Data Flow

```
Input
  URLs / domains
  ZIP archive (+ password)
  Log files (CSV / JSON)
  .eml email files
        │
        ▼
cases/<CASE_ID>/
  artefacts/
    web/        ← redirect chain, HTML, screenshot
    zip/        ← extracted files, strings
    analysis/   ← per-file static analysis JSON
    enrichment/ ← enrichment results JSON
    correlation/← correlation matrix + timeline
    phishing_detection/ ← brand impersonation + heuristic analysis
  iocs/         ← iocs.json (all extracted IOCs)
  logs/         ← parsed log JSON + entity JSON
  reports/      ← investigation_report.md
  session_context.json  ← materialised session context (if from session)
        │
        ▼
registry/case_index.json  ← case registry
registry/audit.log        ← SHA-256 artefact audit trail
registry/batches/         ← batch API metadata + results
reports/weekly/           ← weekly rollup Markdown

sessions/<SESSION_ID>/    ← pre-case investigation sessions
  session_meta.json       ← status, user, expiry, backing case
  history.json            ← conversation history
  context.json            ← accumulated IOCs, findings, disposition
  uploads/                ← analyst-uploaded files
```

## Claude API Integration

| Feature | Where Used |
|---------|-----------|
| **Tool use** | All LLM-assisted tools; chat dispatches tools via `tool_use` API |
| **Prompt caching** | `security_arch_review.py`, `api/chat.py` system prompts |
| **Vision** | `detect_phishing_page.py` screenshot analysis |
| **Files API** | `security_arch_review.py` PDF uploads |
| **Streaming** | `api/chat.py` SSE endpoints for progressive web UI response |
| **Adaptive thinking** | `security_arch_review.py` for high/critical severity cases |
| **Structured outputs** | `tools/structured_llm.py` wrapper with JSON schema validation |
| **Compaction** | `api/chat.py` for long conversations (Opus models) |
| **Batch API** | `tools/batch.py` for bulk report generation |

## Agent Responsibilities

| Agent | Responsibility |
|-------|----------------|
| Chief | Orchestrates the pipeline; catches per-step errors |
| Planner | Inspects inputs and returns an ordered step list |
| DomainInvestigator | Web capture per URL (Playwright / requests) |
| FileAnalyst | ZIP extraction + static analysis of extracted files |
| LogCorrelator | Log parsing (CSV/JSON) + IOC-vs-entity correlation |
| Enrichment | IOC regex extraction + tiered provider lookups (ASN pre-screen → fast → deep OSINT) |
| ReportWriter | Markdown investigation report generation |
| WeeklyReportWriter | Weekly rollup from registry |

## Tool Contracts

Every tool wrapper:
1. Accepts `case_id` as a parameter.
2. Writes all outputs under `cases/<case_id>/`.
3. Records a SHA-256 and timestamp in `registry/audit.log`.
4. Returns a dict that can be serialised to JSON.

## Extending the System

### Adding a new tool
1. Create `tools/my_tool.py` following the pattern in `tools/extract_iocs.py`.
2. Register it in `agents/chief.py` as a new pipeline step.
3. Add a CLI sub-command in `socai.py` if needed.
4. For chat tools: add to `TOOL_DEFS` and/or `SESSION_TOOL_DEFS` in `api/tool_schemas.py`, then add dispatch in `api/chat.py`.

### Adding a new enrichment provider
See `tools/enrich.py` – implement a function and add it to the `PROVIDERS` and `_PROVIDER_NAMES` dicts. For IPv4 providers, also add to `PROVIDERS_IP_FAST` or `PROVIDERS_IP_DEEP`.

### Replacing the headless browser
Set `SOCAI_BROWSER=requests` to skip Playwright, or implement a new backend
in `tools/web_capture.py` following the `_capture_with_*` pattern.
