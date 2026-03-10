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

Web UI (api/main.py + api/chat.py + Svelte SPA: frontend/src/ → ui-dist/)
    ├── Case-mode chat       → 44 tools via TOOL_DEFS (22 case-only + 22 shared)
    ├── Session-mode chat    → 52 tools via SESSION_TOOL_DEFS (30 session-only + 22 shared)
    ├── SSE streaming        → progressive token delivery
    ├── Session management   → CRUD + auto-case creation + finalisation
    ├── Cases browse page    → filterable card grid (CasesBrowse.svelte)
    ├── Case detail page     → read-only summary with investigation log & KQL queries (CaseDetail.svelte)
    ├── Dashboard            → CTI-focused threat intelligence (DashboardView.svelte)
    ├── CTI integration      → OpenCTI feed, trending, ATT&CK heatmap, watchlist, IOC decay (api/opencti.py)
    └── Case context switch  → load/save case context in sessions

MCP Server (mcp_server/)
    ├── HTTPS SSE transport  → port 8001, separate process
    ├── JWT RBAC             → SocaiTokenVerifier bridges api/auth.py tokens
    ├── 47 tools (3 tiers)   → core investigation, extended analysis, advanced/restricted
    ├── 14 resources         → case data, clients, IOC index, playbooks, articles, landscape
    ├── 8 prompts            → investigation orchestrator, KQL playbooks, triage/FP workflows
    ├── Boundary enforcement → per-conversation client + case isolation (prevents cross-contamination)
    ├── Data hierarchy       → global (cross-client IOCs) / client (internal) / case (details)
    ├── stdio fallback       → Claude Desktop backward compat (no auth)
    └── Fire-and-forget      → long-running investigate returns job_id for polling

Batch API (tools/batch.py)
    └── Bulk LLM processing  → submit / poll / collect pattern

Threat Articles (tools/threat_articles.py)
    ├── RSS feed discovery    → 10 configurable feeds (config/article_sources.json)
    ├── ET/EV classification  → heuristic + LLM
    ├── Dedup                 → local index + Confluence MDR1 space
    ├── Topic clustering      → LLM groups related sources
    └── Article generation    → structured output (ArticleSummary schema)

Velociraptor Ingest (tools/velociraptor_ingest.py)
    ├── Offline collector ZIP  → results/ (VQL JSONL) + uploads/ (raw EVTX, MFT, etc.)
    ├── Individual VQL files   → JSONL, JSON array, or CSV
    ├── Directory of exports   → also checks nested results/ and uploads/
    └── 13 artefact normalisers → maps VQL fields to standard parse_logs schema

MDE Ingest (tools/mde_ingest.py)
    ├── Investigation package ZIP → processes, services, tasks, netstat, ARP, DNS cache, etc.
    ├── Directory of MDE exports  → auto-detects MDE folder structure
    └── 13 normalisers            → maps MDE-specific formats to standard parse_logs schema

Memory Guidance (tools/memory_guidance.py)
    ├── Guide mode    → MDE Live Response ProcDump instructions contextual to alert
    └── Analyse mode  → .dmp file analysis (strings, PE headers, DLLs, risk scoring)

Browser Session (tools/browser_session.py)
    ├── Docker (selenium/standalone-chrome) → disposable Chrome via noVNC (:7900)
    ├── CDP monitor (WebSocket)             → captures requests, responses, redirects, cookies, console
    └── Session lifecycle                   → start → analyst browses → stop → artefact collection

Confluence (tools/confluence_read.py)
    └── Read-only client      → scoped API token, single space (MDR1)
```

## Data Flow

```
Input
  URLs / domains
  ZIP archive (+ password)
  Log files (CSV / JSON)
  .eml email files
  Velociraptor exports (collector ZIP / VQL files / directory)
  MDE investigation packages (ZIP or directory)
  Process memory dumps (.dmp / .dump / .raw / .bin)
  Browser session traffic (CDP-captured network data)
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
  session_context.json  ← synced session context (if from session)
        │
        ▼
registry/case_index.json  ← case registry
registry/ioc_index.json   ← cross-case IOC index (tier + case_clients for boundary enforcement)
registry/audit.log        ← SHA-256 artefact audit trail
registry/batches/         ← batch API metadata + results
registry/article_index.json ← threat article dedup index
articles/YYYY-MM/         ← threat article summaries (ET/EV)

sessions/<SESSION_ID>/    ← investigation sessions (auto-create case at start)
  session_meta.json       ← status, user, expiry, case_id, reference_id
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
| **Structured outputs** | `tools/threat_articles.py` article generation via `ArticleSummary` schema |

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
4. For chat tools: add schema to `TOOL_DEFS` in `api/tool_schemas.py` and handler to `_dispatch_shared()` in `api/chat.py` for shared tools (also add to `_SHARED_TOOL_NAMES`); or add to `_SESSION_ONLY_DEFS` / `_dispatch_session_tool()` for session-only tools.

### Adding a new enrichment provider
See `tools/enrich.py` – implement a function and add it to the `PROVIDERS` and `_PROVIDER_NAMES` dicts. For IPv4 providers, also add to `PROVIDERS_IP_FAST` or `PROVIDERS_IP_DEEP`.

### Replacing the headless browser
Set `SOCAI_BROWSER=requests` to skip Playwright, or implement a new backend
in `tools/web_capture.py` following the `_capture_with_*` pattern.
