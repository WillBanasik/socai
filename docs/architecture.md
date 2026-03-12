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

Shared API (api/)
    ├── auth.py              → JWT constants + user store (shared with MCP)
    ├── jobs.py              → background job manager (thread pool, case ID gen)
    ├── actions.py           → tool orchestration wrappers (16+ pipeline actions)
    ├── timeline.py          → case timeline event log
    └── parse_input.py       → freeform analyst input → structured IOC extraction

MCP Server (mcp_server/)
    ├── HTTPS SSE transport  → port 8001, separate process
    ├── JWT RBAC             → SocaiTokenVerifier bridges api/auth.py tokens
    ├── 52 tools (3 tiers)   → core investigation, extended analysis, advanced/restricted
    ├── 18 resources         → case data, clients, IOC index, playbooks, sentinel queries, articles, landscape
    ├── 5 prompts            → investigation orchestrator, KQL investigation, triage, FP workflows, user security check
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
    ├── Docker (socai-browser:latest)       → vanilla Chrome via noVNC (:7900), no automation markers
    ├── tcpdump (passive capture)           → DNS, TCP, HTTP, TLS SNI extraction from pcap
    └── Session lifecycle                   → start → analyst browses manually → stop → pcap collection

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
  Browser session traffic (tcpdump pcap network capture)
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
        │
        ▼
registry/case_index.json  ← case registry
registry/ioc_index.json   ← cross-case IOC index (tier + case_clients for boundary enforcement)
registry/audit.log        ← SHA-256 artefact audit trail
registry/batches/         ← batch API metadata + results
registry/article_index.json ← threat article dedup index
articles/YYYY-MM/         ← threat article summaries (ET/EV)
```

## Claude API Integration

| Feature | Where Used |
|---------|-----------|
| **Tool use** | All LLM-assisted tools; MCP dispatches tools via `tool_use` API |
| **Prompt caching** | `security_arch_review.py` |
| **Vision** | `detect_phishing_page.py` screenshot analysis |
| **Files API** | `security_arch_review.py` PDF uploads |
| **Adaptive thinking** | `security_arch_review.py` for high/critical severity cases |
| **Structured outputs** | `tools/structured_llm.py` wrapper with JSON schema validation |
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
4. For MCP tools: add a `@mcp.tool()` handler in `mcp_server/tools.py` in the appropriate tier. Add an orchestration wrapper in `api/actions.py` if needed.

### Adding a new enrichment provider
See `tools/enrich.py` – implement a function and add it to the `PROVIDERS` and `_PROVIDER_NAMES` dicts. For IPv4 providers, also add to `PROVIDERS_IP_FAST` or `PROVIDERS_IP_DEEP`.

### Replacing the headless browser
Set `SOCAI_BROWSER=requests` to skip Playwright, or implement a new backend
in `tools/web_capture.py` following the `_capture_with_*` pattern.
