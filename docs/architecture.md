# SOC-AI Architecture

## Overview

SOC-AI is a single-process Python application.  Investigation logic lives
in stateless tool functions.  The MCP server and CLI both call these directly.
All persistent state lives in the local filesystem.

```
CLI (socai.py)
    └── Tool functions (HITL — analyst drives each step via MCP or CLI)

Shared API (api/)
    ├── auth.py              → JWT constants + user store (shared with MCP)
    ├── actions.py           → tool orchestration wrappers (16+ pipeline actions)
    ├── timeline.py          → case timeline event log
    └── parse_input.py       → freeform analyst input → structured IOC extraction

MCP Server (mcp_server/)
    ├── HTTPS SSE transport  → port 8001, separate process
    ├── JWT RBAC             → SocaiTokenVerifier bridges api/auth.py tokens
    ├── 106 tools (3 tiers)   → core investigation, extended analysis, advanced/restricted
    ├── 36 resources         → case data, clients, IOC index, playbooks, sentinel queries, NGSIEM/LogScale refs, articles, landscape
    ├── 21 prompts           → investigation, KQL, triage, FP, analysis, report generation, forensics
    ├── Save tools (2)       → save_report, save_threat_article (persist agent output)
    ├── RBAC                 → per-tool scopes via JWT claims; filesystem isolation (cases/<ID>/)
    ├── Data hierarchy       → global (cross-client IOCs) / client (internal + baseline profiles) / case (details)
    ├── Structured logging   → JSONL (mcp_server.jsonl, mcp_usage.jsonl, metrics.jsonl), PID file, signal handlers
    ├── Investigation metrics → phase timing, enrichment duration/coverage, verdict confidence, report completeness
    ├── stdio fallback       → Claude Desktop backward compat (no auth)
    ├── No LLM calls         → all reasoning handled by local Claude Desktop agent
    ├── Speculative enrich   → classify_attack / add_evidence fire background quick_enrich (fast providers, ≤20 IOCs)
    └── Enrichment depth     → agent-controlled depth param (auto/fast/full); triage-first + client baseline auto-skip routine IOCs

Threat Articles (tools/threat_articles.py)
    ├── RSS feed discovery    → 10 configurable feeds (config/article_sources.json)
    ├── ET/EV classification  → heuristic
    ├── Dedup                 → local index + Confluence MDR1 space
    ├── Topic clustering      → heuristic grouping
    └── Article generation    → via write_threat_article prompt + save_threat_article tool

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
    ├── Docker (socai-browser:latest)       → vanilla Chrome via noVNC (:7900), bridge networking, no automation markers
    ├── tcpdump (passive capture)           → DNS, TCP, HTTP, TLS SNI extraction (parsed inside container)
    ├── Session lifecycle                   → start → analyst browses manually → stop → pcap parsing → artefact collection
    └── Caseless workflow                   → start without case_id → read/list session files → import into case later

Confluence (tools/confluence_read.py)
    ├── Read-only client      → fine-grained API token, single space (MDR1)
    ├── v2 API                → pages, children, ancestors, versions, comments, attachments, labels
    └── v1 API (CQL search)   → title ~/text ~ queries via /rest/api/search
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
registry/metrics.jsonl    ← investigation metrics (phase timing, enrichment, verdicts, reports)
registry/mcp_usage.jsonl  ← per-tool invocation log (caller, tool, category, goal, duration, session_id)
registry/quick_enrichments/ ← saved caseless enrichment results (quick_enrich → import into case)
registry/batches/         ← batch API metadata + results
registry/article_index.json ← threat article dedup index
articles/YYYY-MM/         ← threat article summaries (ET/EV)
```

## LLM Architecture

The system makes **no direct Anthropic API calls**. All LLM reasoning is handled by the analyst's local Claude Desktop agent via MCP prompts.

| Component | Role |
|-----------|------|
| **Claude Desktop agent** | All analytical reasoning, report writing, disposition analysis, quality review |
| **MCP prompts (21)** | Load system instructions + case data into the local session |
| **Save tools (2)** | `save_report`, `save_threat_article` — persist agent output with defanging, HTML, auto-close, audit |
| **MCP tools (99)** | Data gathering only: enrichment APIs, Sentinel queries, file I/O, deterministic logic |

## Tool Contracts

Every tool wrapper:
1. Accepts `case_id` as a parameter.
2. Writes all outputs under `cases/<case_id>/`.
3. Records a SHA-256 and timestamp in `registry/audit.log`.
4. Returns a dict that can be serialised to JSON.
5. Key pipeline tools (`enrich`, `score_verdicts`, `save_report`, `index_case`) emit structured metrics to `registry/metrics.jsonl` via `log_metric()` for investigation analytics.
6. New tools must be registered in `TOOL_TAXONOMY` (`mcp_server/usage.py`) for workflow analytics — maps tool → category + goal.

## Workflow Analytics

The MCP usage watcher (`mcp_server/usage.py`) auto-captures ordered tool sequences per session. Each tool call is recorded with timing, category, goal, and success/error. On session expiry (1h inactivity) or server shutdown, a `workflow_summary` event is flushed to `metrics.jsonl` containing the full step sequence, friction signals (unnecessary prerequisites, retries, long gaps, abandoned workflows), and timing breakdown. Query via `scripts/workflow_report.py`.

See `docs/extending.md` for how to add new tools, providers, and brands.
