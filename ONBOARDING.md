# socai — Onboarding Reference for Claude Code

This document is the single source of truth for setting up and extending the
`socai` project on a new machine. It is written for a Claude Code instance
starting with a fresh copy of the repository.

---

## Table of Contents

1. [Quick Install](#1-quick-install)
2. [Architecture](#2-architecture)
3. [File Map](#3-file-map)
4. [Canonical Data Structures](#4-canonical-data-structures)
5. [Configuration Reference](#5-configuration-reference)
6. [MCP Setup (Claude Desktop)](#6-mcp-setup-claude-desktop)
7. [Web UI](#7-web-ui)
8. [Extension Patterns](#8-extension-patterns)
9. [Test Suite](#9-test-suite)

---

## 1. Quick Install

Run from the directory where the repo lives (or was cloned to):

```bash
# 1. Clone (skip if already copied)
git clone <repo-url> socai
cd socai

# 2. Install Python dependencies
pip install -r requirements.txt
# On Debian/Ubuntu externally-managed Python, append: --break-system-packages

# 3. Install Playwright browser (optional but recommended)
#    Without this, web_capture falls back to requests silently.
playwright install chromium

# 4. Smoke-test
python3 -m pytest tests/ -v

# 5. Run a minimal investigation
python3 socai.py investigate --case C001 --title "Test" --severity low
```

All commands must be run from the repo root. Every script does
`sys.path.insert(0, str(Path(__file__).resolve().parent))` to anchor imports.

### Environment variables (set in shell or `.env`)

A `.env` file at the repo root is auto-loaded by `python-dotenv`. It is
git-ignored; never commit it.

```bash
# Required for LLM-assisted steps
export ANTHROPIC_API_KEY=""

# Enrichment (all optional — leave blank to skip)
export SOCAI_VT_KEY=""
export ABUSEIPDB_API_KEY=""
export SHODAN_API_KEY=""
export GREYNOISE_API_KEY=""
# ... see config/settings.py for full list

# Browser backend
export SOCAI_BROWSER="playwright"  # or "requests" to force fallback
```

### Dependencies (`requirements.txt`)

```
# Core
anthropic>=0.40.0
requests>=2.31.0
beautifulsoup4>=4.12.0
python-dotenv>=1.0.0

# Optional – headless browser (recommended)
playwright>=1.43.0

# Optional – PE file analysis
# pefile>=2023.2.7

# Optional – YARA scanning
# yara-python>=4.3.0

# Optional – native EVTX parsing
# python-evtx>=0.7.0

# MCP server
mcp>=1.1.0

# Web API
fastapi>=0.115.0
uvicorn[standard]>=0.34.0
python-jose[cryptography]>=3.3.0
bcrypt>=4.0.0
python-multipart>=0.0.9
pydantic[email]>=2.0.0

# Dev / testing
pytest>=8.0.0
```

---

## 2. Architecture

### Execution model

The CLI pipeline runs **synchronously in a single process** with parallel
execution for independent investigation agents. The web UI is an async FastAPI
application with SSE streaming for real-time chat.

### Layer responsibilities

```
┌─────────────────────────────────────────────────────────────────────┐
│  CLI  socai.py  /  MCP  mcp_server.py  /  Web  api/main.py         │
│  Entry points only — no business logic                              │
└────────────────────┬───────────────────────────────────────────────┘
                     │
┌────────────────────▼───────────────────────────────────────────────┐
│  Agent layer  agents/                                               │
│  Thin orchestration classes inheriting BaseAgent.                    │
│  Receive case_id at construction. Call tool functions.               │
│  Never write files directly. Return dicts.                          │
└────────────────────┬───────────────────────────────────────────────┘
                     │
┌────────────────────▼───────────────────────────────────────────────┐
│  Tool layer  tools/                                                 │
│  Stateless functions. Take case_id. Write ALL outputs               │
│  via write_artefact() / save_json(). Append to audit.log.           │
│  Return a JSON-serialisable manifest dict.                          │
└────────────────────┬───────────────────────────────────────────────┘
                     │
┌────────────────────▼───────────────────────────────────────────────┐
│  Web UI  api/chat.py + api/main.py + ui/case.html                   │
│  Full-screen LLM chat with SSE streaming, tool dispatch,            │
│  session management, and activity feed.                             │
└────────────────────┬───────────────────────────────────────────────┘
                     │
┌────────────────────▼───────────────────────────────────────────────┐
│  Filesystem state  cases/  sessions/  registry/  reports/           │
│  No database. All persistence is on disk.                           │
└─────────────────────────────────────────────────────────────────────┘
```

### Pipeline flow (`ChiefAgent.run` — 16 steps)

```
case_create              always first
TriageAgent              if URLs provided; check vs ioc_index, escalate severity
PlannerAgent             informational only; result not used for routing
EmailAnalystAgent        if --eml provided; parse headers, extract URLs + attachments
[PARALLEL]               concurrent via ThreadPoolExecutor(max_workers=3)
  ├─ DomainInvestigator  if URLs provided (input + email-extracted)
  ├─ FileAnalystAgent    if ZIP provided and not already extracted
  └─ LogCorrelatorAgent  if log paths provided (also runs correlate)
SandboxAgent             query sandbox APIs for file hashes
recursive capture loop   extract_iocs → find new URLs → capture (up to CRAWL_DEPTH)
detect_phishing_page     3-tier phishing detection (brand/heuristics/LLM)
EnrichmentAgent          extract_iocs → enrich (tiered IPv4) → score_verdicts → update_ioc_index
correlate                only if no logs (LogCorrelator already ran it)
AnomalyDetectionAgent    behavioural anomaly detection on parsed logs
CampaignAgent            cross-case IOC clustering into campaigns
ResponseActionsAgent     client-specific response plan (deterministic; no LLM)
ReportWriterAgent        generate_report + index_case
QueryGenAgent            generates SIEM hunt queries
SecurityArchAgent        LLM security architecture review (adaptive thinking for high/critical)
```

Each step is wrapped in `_step()` with a `try/except`. A failing step is
recorded in `pipeline_results["errors"]` but does **not** abort subsequent
steps.

### Key invariants

- `tools/common.py` is the **only** shared dependency across all tools.
  Always use `write_artefact`, `save_json`, `load_json`, `audit`, `utcnow`,
  `log_error`, `defang_report`, `AliasMap`, `get_model` from there — never
  write files, timestamps, or model strings directly.
- `extract_iocs` scans **both** `cases/<id>/artefacts/` and
  `cases/<id>/logs/` — parsed log files land in `logs/`, not `artefacts/`.
- All outputs go under `cases/<case_id>/`. Tools never write outside this tree
  (except registry files).
- Every `except` block must call `log_error()`. Assess errors:
  `python3 socai.py errors`; clear after review: `--clear`.

---

## 3. File Map

### Root

| File | Purpose |
|------|---------|
| `socai.py` | CLI entrypoint — all sub-commands |
| `mcp_server.py` | MCP server (Claude Desktop) — 7 tools via FastMCP |
| `CLAUDE.md` | Claude Code project instructions (always loaded) |
| `ONBOARDING.md` | This document |
| `requirements.txt` | Python dependencies |

### `config/`

| File | Purpose |
|------|---------|
| `settings.py` | All paths + env-var-overridable settings |
| `client_entities.json` | Client alias configuration (git-ignored) |
| `client_entities.example.json` | Example schema for client entities |
| `client_playbook.example.json` | Example client response playbook |
| `clients/` | Client-specific response playbooks |
| `users.json` | Web UI user accounts |
| `workspace_tables.json` | Sentinel workspace table availability (git-ignored) |
| `sentinel_tables.json` | Sentinel table schemas |
| `sentinel_schema.py` | Sentinel schema discovery helpers |
| `analytical_guidelines.md` | LLM reasoning guidelines for analysis tools |
| `logscale_syntax.md` | CrowdStrike LogScale query language reference |
| `kql_playbooks/` | Parameterised KQL investigation playbooks |
| `fp_templates/` | FP ticket templates |

### `agents/`

| File | Purpose |
|------|---------|
| `base_agent.py` | Base class — `__init__(case_id)`, `run()`, `_emit()` |
| `chief.py` | Orchestrator — drives the full 16-step pipeline |
| `planner.py` | Inspects intake, builds ordered task list |
| `triage_agent.py` | Pre-pipeline IOC intelligence checks |
| `email_analyst.py` | Drives `analyse_email` for .eml files |
| `domain_investigator.py` | Drives `web_capture` for all URLs |
| `file_analyst.py` | Drives `extract_zip` + `static_file_analyse` |
| `log_correlator.py` | Drives `parse_logs` + `correlate` |
| `sandbox_agent.py` | Queries sandbox APIs for file hashes |
| `enrichment_agent.py` | Drives `extract_iocs` + `enrich` + `score_verdicts` |
| `anomaly_detection_agent.py` | Behavioural anomaly detection on logs |
| `campaign_agent.py` | Cross-case IOC clustering |
| `response_agent.py` | Client-specific response plan generation |
| `fp_comms_agent.py` | FP ticket generation |
| `report_writer.py` | Drives `generate_report` + `index_case` |
| `query_gen_agent.py` | Drives SIEM hunt query generation |
| `security_arch_agent.py` | LLM security architecture review |
| `weekly_report_writer.py` | Drives `generate_weekly_report` |

### `tools/`

| File | Purpose |
|------|---------|
| `common.py` | Shared utilities: hashing, audit, artefact writing, JSON helpers, error logging, IOC defanging, client aliasing, model selection |
| `case_create.py` | Initialise case folder + registry entry |
| `index_case.py` | Update registry with metadata, artefact list, IOC counts |
| `web_capture.py` | Fetch URLs: HTML/text/screenshot, TLS cert, Cloudflare detection, XHR interception |
| `extract_zip.py` | Extract password-protected ZIP; SHA-256 manifest; string extraction |
| `parse_logs.py` | Parse CSV/JSON logs; extract IPs, users, commands, EventIDs |
| `static_file_analyse.py` | File type, hashes, entropy, embedded strings, optional PE metadata |
| `extract_iocs.py` | Regex-based IOC extraction: IPv4, domain, URL, hashes, email, CVE |
| `correlate.py` | Cross-reference IOCs with log entities; correlation matrix + timeline |
| `enrich.py` | Tiered enrichment: ASN pre-screen → fast → deep OSINT (18 providers) |
| `score_verdicts.py` | Composite verdict scoring per IOC |
| `triage.py` | Pre-pipeline intelligence checks against ioc_index and cache |
| `analyse_email.py` | .eml parsing: headers, auth, spoofing detection, URL/attachment extraction |
| `detect_phishing_page.py` | 3-tier phishing detection: brands/forms/TLS → heuristics → LLM purpose analysis |
| `sandbox_analyse.py` | Sandbox API queries: Any.Run, Joe Sandbox, Hybrid Analysis |
| `detect_anomalies.py` | 6 behavioural detectors: temporal, travel, brute force, first-seen, volume, lateral |
| `campaign_cluster.py` | Union-Find IOC clustering across cases |
| `response_actions.py` | Deterministic client-specific response plans |
| `fp_ticket.py` | Platform-specific FP suppression tickets with live KQL |
| `generate_report.py` | Markdown investigation report (template-based, no LLM) |
| `generate_mdr_report.py` | MDR report with LLM analysis |
| `generate_queries.py` | SIEM hunt queries: KQL, Splunk, LogScale |
| `generate_pptx.py` | Management PowerPoint briefing |
| `generate_capabilities_pptx.py` | Capabilities overview PPTX |
| `generate_weekly_report.py` | Weekly rollup report across closed cases |
| `timeline_reconstruct.py` | Forensic timeline with optional LLM analysis |
| `pe_analysis.py` | Deep PE file static analysis (requires `pefile`) |
| `yara_scan.py` | YARA scanning with optional LLM rule generation (requires `yara-python`) |
| `evtx_correlate.py` | Windows Event Log attack chain correlation |
| `cve_contextualise.py` | CVE enrichment: NVD, EPSS, CISA KEV, OpenCTI |
| `executive_summary.py` | Plain-English executive summary for leadership |
| `security_arch_review.py` | LLM security architecture review with adaptive thinking |
| `client_query.py` | Ad-hoc analyst queries about client environments |
| `kql_playbooks.py` | Parameterised KQL investigation playbooks |
| `telemetry_analysis.py` | Telemetry file parsing and summarisation |
| `assess_errors.py` | Error log assessment and clearing |
| `schemas.py` | Pydantic models for structured LLM outputs |
| `structured_llm.py` | Helper wrapper for Claude structured output API |
| `batch.py` | Batch API infrastructure: submit, poll, collect |

### `api/`

| File | Purpose |
|------|---------|
| `main.py` | FastAPI app — all HTTP routes (chat, sessions, cases, actions, streaming) |
| `chat.py` | LLM chat backend — tool dispatch, history, streaming, compaction |
| `tool_schemas.py` | Tool definitions for case-mode (22) and session-mode (29) chat |
| `sessions.py` | Session CRUD, context accumulation, materialisation to cases |
| `actions.py` | Action functions called by chat tool dispatch |
| `auth.py` | JWT authentication and user management |
| `jobs.py` | Background job manager for long-running pipeline executions |
| `prompts.py` | System prompt builders for chat |
| `schemas.py` | Pydantic request/response schemas for API |
| `parse_input.py` | Input parsing utilities |
| `timeline.py` | Timeline rendering for the web UI |

### `ui/`

| File | Purpose |
|------|---------|
| `case.html` | Full-screen chat UI with SSE streaming, activity feed, session sidebar |

### `tests/`

| File | Purpose |
|------|---------|
| `test_tools.py` | 34 unit tests for tool functions |
| `fixtures/sample_ioc_text.txt` | Phishing text with IOCs for extraction tests |
| `fixtures/sample_proxy_log.csv` | Proxy log for `parse_logs` CSV test |
| `fixtures/sample_events.json` | Windows event log for `parse_logs` JSON test |
| `fixtures/sample_phishing.eml` | Phishing email for `analyse_email` tests |
| `fixtures/sample_ioc_index.json` | Pre-populated IOC index for triage tests |
| `fixtures/sample_sandbox_response.json` | Sandbox response for sandbox tests |
| `fixtures/sample_anomaly_logs.json` | Log data for anomaly detection tests |

### Runtime-generated (not in repo, created on first run)

```
registry/
  case_index.json        master case registry
  audit.log              append-only JSONL artefact log
  error_log.jsonl        append-only error log
  enrichment_cache.json  cross-run enrichment cache (TTL-controlled)
  ioc_index.json         cross-case IOC index with composite verdicts
  campaigns.json         cross-case campaign clusters
  alias_map.json         runtime alias mappings
  batches/               batch API metadata + results

cases/<CASE_ID>/
  case_meta.json
  session_context.json   (if materialised from a session)
  chat_history_{email}.json
  artefacts/
    web/<domain>/        redirect chain, HTML, screenshot, XHR, TLS
    zip/                 extracted files, strings
    analysis/            per-file static analysis JSON
    enrichment/          enrichment.json + verdict_summary.json
    correlation/         correlation matrix + timeline
    phishing_detection/  brand detection + heuristics + purpose assessments
    sandbox/             sandbox results + extracted IOCs
    anomalies/           behavioural anomaly findings
    campaign/            campaign membership links
    fp_comms/            FP ticket + manifest
    timeline/            forensic timeline
    yara/                YARA results + generated rules
    evtx/                EVTX attack chain correlation
    cve/                 CVE contextualisation
    executive_summary/   executive summary + manifest
    security_architecture/  secarch review + structured + manifest
    response_actions/    response plan (JSON + markdown)
  iocs/
    iocs.json            canonical IOC list
    iocs_summary.txt
  logs/                  parsed log files
  reports/
    investigation_report.md
  notes/                 session context notes (materialised sessions)
  uploads/               analyst-uploaded files

sessions/<SESSION_ID>/   pre-case investigation sessions
  session_meta.json      status, user, expiry, backing case link
  history.json           conversation history
  context.json           accumulated IOCs, findings, disposition
  uploads/               analyst-uploaded files

reports/weekly/          weekly rollup Markdown files
```

---

## 4. Canonical Data Structures

All JSON files are written by `save_json()` which calls `write_artefact()`
and appends to `audit.log`. Never write these files with raw `open()`.

### `cases/<id>/case_meta.json`

```json
{
  "case_id": "C001",
  "title": "Phishing lure – finance team",
  "severity": "high",
  "analyst": "alice@example.com",
  "client": "acme",
  "tags": ["phishing", "credential-harvest"],
  "status": "open",
  "created_at": "2026-02-24T10:00:00Z",
  "updated_at": "2026-02-24T10:05:00Z",
  "artefacts": [
    "artefacts/web/evil.com/page.txt",
    "artefacts/analysis/attachment.pdf.analysis.json",
    "iocs/iocs_summary.txt",
    "reports/investigation_report.md"
  ],
  "iocs": [],
  "report_path": "/absolute/path/to/cases/C001/reports/investigation_report.md",
  "ioc_totals": {
    "ipv4": 2, "domain": 3, "url": 5,
    "md5": 1, "sha1": 1, "sha256": 2,
    "email": 1, "cve": 0
  },
  "disposition": "true_positive"
}
```

`status` values: `"open"` | `"closed"`
`severity` values: `"low"` | `"medium"` | `"high"` | `"critical"`
`artefacts` is a list of **relative** paths from the case root. `report_path` is absolute.

---

### `registry/case_index.json`

```json
{
  "cases": {
    "C001": {
      "title": "Phishing lure – finance team",
      "severity": "high",
      "status": "open",
      "created_at": "2026-02-24T10:00:00Z",
      "updated_at": "2026-02-24T10:05:00Z",
      "case_dir": "/absolute/path/to/cases/C001",
      "report_path": "/absolute/path/to/cases/C001/reports/investigation_report.md"
    }
  }
}
```

---

### `cases/<id>/iocs/iocs.json`

This is the **canonical IOC list** consumed by `enrich` and `correlate`.

```json
{
  "case_id": "C001",
  "ts": "2026-02-24T10:03:00Z",
  "total": {
    "ipv4": 1, "domain": 3, "url": 5,
    "md5": 3, "sha1": 3, "sha256": 5,
    "email": 0, "cve": 0
  },
  "iocs": {
    "ipv4":   ["185.220.101.45"],
    "domain": ["evil.example.com", "cdn.malware.io"],
    "url":    ["https://evil.example.com/payload.exe"],
    "md5":    ["f41a63eb3f7b2794f1972e84dce16460"],
    "sha1":   ["c0b3f926a239bd30371c2dde41fc875a2f02e7b5"],
    "sha256": ["d4a1153c4e4b0748f8a8180b12fd655fbe12f2922d3b3c8b46987d2240772afa"],
    "email":  [],
    "cve":    []
  },
  "sources": [
    {
      "file": "/absolute/path/to/cases/C001/artefacts/web/evil.example.com/page.txt",
      "ioc_count": 4
    }
  ]
}
```

---

### `cases/<id>/artefacts/enrichment/enrichment.json`

```json
{
  "case_id": "C001",
  "ts": "2026-02-24T10:04:30Z",
  "total_lookups": 3,
  "tiered_enrichment": {
    "ipv4_total": 5,
    "asn_prescreen_skipped": 2,
    "fast_only": 2,
    "escalated_to_deep": 1
  },
  "results": [
    {
      "ioc": "185.220.101.45",
      "ioc_type": "ipv4",
      "provider": "abuseipdb",
      "status": "ok",
      "data": {
        "abuseConfidenceScore": 97,
        "countryCode": "DE",
        "usageType": "Data Center/Web Hosting/Transit"
      }
    }
  ]
}
```

When API keys are absent, `total_lookups` is `0` and `results` is `[]`.

---

### `cases/<id>/artefacts/enrichment/verdict_summary.json`

```json
{
  "case_id": "C001",
  "ts": "2026-02-24T10:04:35Z",
  "summary": {
    "185.220.101.45": {
      "verdict": "malicious",
      "confidence": "HIGH",
      "malicious_count": 3,
      "suspicious_count": 0,
      "clean_count": 1
    }
  },
  "high_priority": ["185.220.101.45"],
  "needs_review": [],
  "clean": ["cdn.example.com"]
}
```

---

### `cases/<id>/artefacts/correlation/correlation.json`

```json
{
  "case_id": "C001",
  "ts": "2026-02-24T10:04:00Z",
  "ioc_count": { "ipv4": 1, "domain": 2, "url": 1 },
  "entity_count": { "ips": 3, "users": 2, "commands": 1 },
  "hits": {
    "ip_matches": {
      "185.220.101.45": ["2026-02-23T09:12:00", "2026-02-23T09:14:00"]
    }
  },
  "hit_summary": { "185.220.101.45": 2 },
  "timeline_events": 2
}
```

`hits` is only populated when log data was parsed. When there are no logs,
`hits` is `{}` and `timeline_events` is `0` — this is not an error.

---

### Web capture manifest (`artefacts/web/<domain>/capture_manifest.json`)

```json
{
  "url": "https://evil.example.com",
  "final_url": "https://evil.example.com/landing",
  "domain": "evil.example.com",
  "ts": "2026-02-24T10:02:00Z",
  "backend": "playwright",
  "files": {
    "html": "page.html",
    "text": "page.txt",
    "screenshot": "screenshot.png"
  },
  "redirect_chain": ["https://evil.example.com", "https://evil.example.com/landing"],
  "status_code": 200,
  "content_length": 8420,
  "cloudflare_blocked": false,
  "cloudflare_challenge": null,
  "tls_certificate": {
    "subject_cn": "evil.example.com",
    "issuer_cn": "R11",
    "issuer_org": "Let's Encrypt",
    "san": ["evil.example.com"],
    "not_before": "2026-02-20",
    "not_after": "2026-05-21",
    "cert_age_days": 4,
    "days_remaining": 86,
    "self_signed": false
  }
}
```

---

### `sessions/<id>/session_meta.json`

```json
{
  "session_id": "S-20260307120000-a1b2c3d4",
  "user_email": "analyst@example.com",
  "status": "active",
  "case_id": null,
  "title": "Investigating suspicious email",
  "created": "2026-03-07T12:00:00+00:00",
  "expires": "2026-03-08T12:00:00+00:00"
}
```

`status` values: `"active"` | `"materialised"` | `"expired"`
When materialised, `case_id` links to the created case.

---

### `registry/audit.log` (one JSONL line per event)

```json
{"ts": "2026-02-24T10:00:00Z", "action": "write_artefact", "path": "/abs/path/case_meta.json", "sha256": "abc123..."}
{"ts": "2026-02-24T10:00:01Z", "action": "case_create",    "path": "/abs/path/case_meta.json", "sha256": "",           "case_id": "C001"}
{"ts": "2026-02-24T10:03:00Z", "action": "chief:step_done","path": "",                          "sha256": "",           "case_id": "C001", "step": "enrich"}
```

Append-only. Never rewrite or truncate this file.

---

### `registry/error_log.jsonl` (one JSONL line per error)

```json
{"ts": "2026-02-24T10:03:00Z", "case_id": "C001", "step": "enrich", "severity": "warning", "error": "Shodan API key not set"}
```

Append-only. Assess: `python3 socai.py errors`. Clear: `python3 socai.py errors --clear`.

---

## 5. Configuration Reference

### Full source: `config/settings.py`

```python
"""
Global configuration for SOC-AI.
Override values via environment variables prefixed with SOCAI_.
A .env file at the repo root is loaded automatically (never commit it).
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

BASE_DIR = Path(__file__).resolve().parent.parent

CASES_DIR        = BASE_DIR / "cases"
REPORTS_DIR      = BASE_DIR / "reports"
WEEKLY_REPORTS   = REPORTS_DIR / "weekly"
REGISTRY_FILE    = BASE_DIR / "registry" / "case_index.json"
AUDIT_LOG        = BASE_DIR / "registry" / "audit.log"
ERROR_LOG        = BASE_DIR / "registry" / "error_log.jsonl"

# Web capture
CAPTURE_TIMEOUT  = int(os.getenv("SOCAI_CAPTURE_TIMEOUT", "20"))
CAPTURE_SPA_DWELL = int(os.getenv("SOCAI_SPA_DWELL", "5000"))
CAPTURE_UA       = os.getenv("SOCAI_UA", "Mozilla/5.0 ...")
BROWSER_BACKEND  = os.getenv("SOCAI_BROWSER", "playwright")

# Static analysis
STRINGS_MIN_LEN  = int(os.getenv("SOCAI_STRINGS_MIN", "6"))

# Enrichment API keys (18 providers — see full file for all)
VIRUSTOTAL_KEY   = os.getenv("SOCAI_VT_KEY", "")
ABUSEIPDB_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
# ... many more — see config/settings.py

# Enrichment performance
ENRICH_CACHE_TTL  = int(os.getenv("SOCAI_ENRICH_CACHE_TTL", "24"))   # hours
ENRICH_WORKERS    = int(os.getenv("SOCAI_ENRICH_WORKERS", "10"))

# Recursive URL capture
CRAWL_DEPTH      = int(os.getenv("SOCAI_CRAWL_DEPTH", "3"))
CRAWL_MAX_URLS   = int(os.getenv("SOCAI_CRAWL_MAX_URLS", "30"))

# Confidence / auto-disposition
CONF_AUTO_CLOSE  = float(os.getenv("SOCAI_CONF_AUTO_CLOSE", "0.20"))

# Claude model (legacy fallback)
LLM_MODEL        = os.getenv("SOCAI_LLM_MODEL", "claude-sonnet-4-6")
ANTHROPIC_KEY    = os.getenv("ANTHROPIC_API_KEY", "")

# Model tiers
SOCAI_MODEL_HEAVY    = os.getenv("SOCAI_MODEL_HEAVY",    "claude-opus-4-6")
SOCAI_MODEL_STANDARD = os.getenv("SOCAI_MODEL_STANDARD", "claude-sonnet-4-6")
SOCAI_MODEL_FAST     = os.getenv("SOCAI_MODEL_FAST",     "claude-haiku-4-5-20251001")

# Per-task model assignments (value = tier name or full model string)
# chat_routing, chat_response, secarch, report, exec_summary,
# fp_ticket, evtx, pe_analysis, cve, yara, timeline, queries,
# planner, mdr_report, clarification

# Compaction (server-side context management for long chats)
SOCAI_COMPACTION_ENABLED = os.getenv("SOCAI_COMPACTION_ENABLED", "1") == "1"

# Batch API
BATCH_POLL_INTERVAL = int(os.getenv("SOCAI_BATCH_POLL_INTERVAL", "30"))
BATCH_TIMEOUT = int(os.getenv("SOCAI_BATCH_TIMEOUT", "3600"))
BATCH_DIR = BASE_DIR / "registry" / "batches"

# Client aliasing
ALIAS_ENABLED     = os.getenv("SOCAI_ALIAS", "0") == "1"
CLIENT_PLAYBOOKS_DIR = BASE_DIR / "config" / "clients"
DEFAULT_CLIENT    = os.getenv("SOCAI_DEFAULT_CLIENT", "")
```

### Model tiering

Every LLM call resolves its model through `get_model(task, severity)` in
`tools/common.py`. Three tiers: `fast` (Haiku), `standard` (Sonnet),
`heavy` (Opus). Tasks like `secarch`, `chat_response`, `fp_ticket`, `evtx`,
`report` escalate from their default tier on high/critical severity.

Override any task: `SOCAI_MODEL_SECARCH=heavy` forces Opus regardless of severity.

See `docs/model_tiering.md` for the full matrix and call site map.

---

## 6. MCP Setup (Claude Desktop)

Claude Desktop reads its MCP server config from:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "socai": {
      "command": "python3",
      "args": ["/path/to/socai/mcp_server.py"],
      "env": {
        "ANTHROPIC_API_KEY": "",
        "SOCAI_VT_KEY": ""
      }
    }
  }
}
```

Replace `/path/to/socai` with the actual absolute path.

### Tools exposed by the MCP server

| Tool | What it does |
|------|-------------|
| `investigate` | Runs the full pipeline (`ChiefAgent.run`) with all parameters |
| `list_cases` | Returns `registry/case_index.json` |
| `get_case` | Returns `cases/<id>/case_meta.json` |
| `read_report` | Returns investigation report as Markdown |
| `generate_weekly` | Weekly rollup report |
| `generate_queries` | SIEM hunt queries (KQL, Splunk, LogScale) |
| `close_case` | Marks a case as closed |

All tools return `str` — either `json.dumps(...)` or raw Markdown.
All imports inside tool functions are deferred to avoid slow startup.

---

## 7. Web UI

### Starting the server

```bash
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify: `curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/docs` (expect 200).

### Features

- **SSE streaming chat** — tokens appear incrementally as Claude generates them
- **Activity feed** — real-time tool execution indicators (pulsing amber → green tick)
- **Session management sidebar** — list, resume, rename, delete sessions
- **22 case-mode tools** — full investigation toolkit available via natural language
- **29 session-mode tools** — all case tools + session-specific features (upload, materialise, disposition)
- **Backing cases** — session tools that need artefact storage auto-create a case behind the scenes
- **Compaction** — long conversations use API-side context compaction (Opus models) to preserve earlier context

### Key endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/sessions` | Create session |
| GET | `/api/sessions` | List sessions |
| POST | `/api/sessions/{id}/chat/stream` | SSE streaming session chat |
| POST | `/api/cases/{id}/chat/stream` | SSE streaming case chat |
| POST | `/api/cases/{id}/chat` | Synchronous case chat |
| POST | `/api/cases/{id}/actions/{action}` | Dispatch action via Chief |
| PATCH | `/api/sessions/{id}` | Rename session |
| DELETE | `/api/sessions/{id}` | Delete session |
| DELETE | `/api/sessions` | Clear all sessions |

### Authentication

JWT-based. User accounts in `config/users.json`. Login via `/api/login`.

---

## 8. Extension Patterns

### Add a new enrichment provider

In `tools/enrich.py`, add a function and register it in `PROVIDERS` and
`_PROVIDER_NAMES`:

```python
def my_provider(ioc: str, ioc_type: str) -> dict:
    # return a JSON-serialisable dict; raise on hard failure
    ...

PROVIDERS = {
    "ipv4":   [..., my_provider],
    "domain": [..., my_provider],
}
_PROVIDER_NAMES[my_provider] = "my_provider"
```

For IPv4 providers, also add to `PROVIDERS_IP_FAST` (cheap/free) or
`PROVIDERS_IP_DEEP` (rate-limited, runs only when signal detected).

### Add a new tool

1. Create `tools/my_tool.py`:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.common import save_json, utcnow, log_error
from config.settings import CASES_DIR

def my_tool(case_id: str, **kwargs) -> dict:
    try:
        result_data = {"case_id": case_id, "ts": utcnow(), ...}
        out_path = CASES_DIR / case_id / "artefacts" / "my_output.json"
        save_json(out_path, result_data)
        return {"path": str(out_path), ...}
    except Exception as exc:
        log_error(case_id, "my_tool", str(exc), severity="error",
                  traceback=traceback.format_exc())
        raise
```

2. Register as a pipeline step in `agents/chief.py` inside `ChiefAgent.run()`.
3. Optionally add a CLI sub-command in `socai.py`.

### Add a new chat tool

Tool definitions are in `api/tool_schemas.py`:
- Add to `TOOL_DEFS` for case-mode (22 existing)
- Add to `SESSION_TOOL_DEFS` for session-mode (29 existing)

Then add the dispatch case in `api/chat.py`:
- `_dispatch_tool()` for case-mode
- `_dispatch_session_tool()` for session-mode

Session tools that need file storage use `_session_ensure_backing_case()` to
auto-create a case directory.

### Add a batch-capable tool

Add a `prepare_*_batch(case_id)` function that returns `messages.create()`
kwargs as a dict (without executing). Register in `tools/batch.py`'s dispatch
table.

### Add a new agent

Inherit `BaseAgent`, implement `run(**kwargs) -> dict`, call tool functions —
never write files directly:

```python
from agents.base_agent import BaseAgent
from tools.my_tool import my_tool

class MyAgent(BaseAgent):
    name = "my_agent"

    def run(self, **kwargs) -> dict:
        self._emit("start", {"case_id": self.case_id})
        result = my_tool(self.case_id, **kwargs)
        self._emit("done", result)
        return result
```

Register it in `agents/chief.py` as a pipeline step.

### Add a new phishing brand

Append to `_BRANDS` in `tools/detect_phishing_page.py` with `name`,
`patterns` (list of compiled regexes), and `allowed` (set of base domains).
Also add to `_BRAND_DOMAINS` in `tools/analyse_email.py` for homoglyph detection.

### Add a new IOC TLD

Add to the explicit allowlist in `_RE_DOMAIN` in `tools/extract_iocs.py`.

### Add a new anomaly detector

Add a `_detect_*()` function in `tools/detect_anomalies.py` returning
`list[dict]` with `type`, `severity`, and `detail` keys. Call it from
`detect_anomalies()` main function.

### Add a new sandbox provider

Add a `_*_lookup(sha256: str) -> dict` function in `tools/sandbox_analyse.py`,
add to `providers` list in `sandbox_analyse()`.

---

## 9. Test Suite

### Running tests

```bash
# All tests (must run from repo root)
python3 -m pytest tests/ -v

# Single test
python3 -m pytest tests/test_tools.py::test_extract_iocs_from_text -v
```

### How the fixture case works

All tests use the case ID `TEST_AUTOMATED_001`. An `autouse` fixture in
`test_tools.py` creates and tears down this case directory and its registry
entry around **every single test** — tests are fully isolated.

### Test coverage (34 tests)

| Test | Tool under test | Key assertions |
|------|----------------|----------------|
| `test_case_create` | `case_create` | Folder exists, `status == "open"` |
| `test_extract_iocs_from_text` | `extract_iocs` | IPv4, domain, CVE, email found in fixture text |
| `test_parse_logs_csv` | `parse_logs` | Rows parsed, IPs extracted from proxy log CSV |
| `test_parse_logs_json` | `parse_logs` | Rows parsed, users + commands from Windows event JSON |
| `test_static_file_analyse_text` | `static_file_analyse` | File type = "Plain text", hashes present |
| `test_correlate_no_logs` | `correlate` | Runs without crash when no logs exist |
| `test_generate_report` | `generate_report` | Report file exists, all required sections present |
| `test_index_case` | `index_case` | Registry `status` updated to `"closed"` |
| `test_analyse_email` | `analyse_email` | Email parsing, header extraction, URL extraction |
| `test_analyse_email_spoofing_return_path` | `analyse_email` | Spoofing detection via Return-Path mismatch |
| `test_triage_no_matches` | `triage` | No false positives on clean IOC index |
| `test_triage_known_malicious` | `triage` | Known-malicious IOC detected, severity escalation |
| `test_campaign_cluster_*` (2) | `campaign_cluster` | Cluster formation + single-IOC filtering |
| `test_sandbox_analyse_*` (2) | `sandbox_analyse` | No-hash skip + hash collection from analysis JSONs |
| `test_detect_anomalies_*` (4) | `detect_anomalies` | No-log skip, brute force, temporal, lateral movement |
| `test_alias_*` (11) | `AliasMap` | Root/exact aliasing, TLD/subdomain preservation, round-trip, persistence |
| `test_response_actions_*` (3) | `response_actions` | Playbook resolution, clean-skip, no-playbook handling |

### Fixture files

| Fixture | Used by |
|---------|---------|
| `fixtures/sample_ioc_text.txt` | IOC extraction, static analysis, correlate, report |
| `fixtures/sample_proxy_log.csv` | `parse_logs` CSV test |
| `fixtures/sample_events.json` | `parse_logs` JSON test |
| `fixtures/sample_phishing.eml` | `analyse_email` tests |
| `fixtures/sample_ioc_index.json` | `triage` tests |
| `fixtures/sample_sandbox_response.json` | `sandbox_analyse` tests |
| `fixtures/sample_anomaly_logs.json` | `detect_anomalies` tests |

---

## Appendix — Critical Source Files

These are inlined here so a new Claude Code instance has zero ambiguity about
the foundational conventions even before reading the rest of the codebase.

### `agents/base_agent.py`

```python
"""
Base agent class.  All agents inherit from this.
"""
from __future__ import annotations

import json
import logging

from tools.common import audit

logger = logging.getLogger(__name__)


class BaseAgent:
    name: str = "base"

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.log = logging.getLogger(f"socai.{self.name}")

    def run(self, **kwargs) -> dict:
        raise NotImplementedError

    def _emit(self, event: str, data: dict) -> None:
        """Log a structured event for this agent."""
        self.log.info("%s | %s | %s", self.name, event, json.dumps(data))
        audit(f"{self.name}:{event}", path="", extra={"case_id": self.case_id, **data})
```

### `tools/common.py` — key functions (abbreviated)

```python
from config.settings import AUDIT_LOG, ERROR_LOG

# Thread-safe locks for concurrent agent writes
_audit_lock = threading.Lock()
_error_lock = threading.Lock()

def sha256_file(path) -> str: ...
def sha256_bytes(data: bytes) -> str: ...
def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def audit(action, path, sha256="", extra=None) -> None:
    """Append a single audit record (thread-safe)."""
    ...

def log_error(case_id, step, error, *, severity="error", traceback="", context=None) -> None:
    """Append a structured error record to error_log.jsonl."""
    ...

def write_artefact(dest: Path, data: bytes | str, encoding="utf-8") -> dict:
    """Write data, compute SHA-256, audit, return manifest dict."""
    ...

def load_json(path) -> dict | list: ...
def save_json(path, data, indent=2) -> dict:
    """JSON-encode data, write via write_artefact()."""
    ...

def defang_ioc(value: str) -> str: ...
def defang_report(text: str, malicious_iocs: set[str] | None = None) -> str: ...

def get_model(task: str = "", severity: str = "") -> str:
    """Resolve model string from task + severity. Never hardcode model strings."""
    ...

class AliasMap:
    """Bidirectional alias map for client name minimisation."""
    ...

KNOWN_CLEAN_DOMAINS: frozenset[str] = frozenset({...})
    # 80+ domains: google.com, microsoft.com, github.com, etc.
    # Used for IOC skip, crawl skip, enrichment skip
```

### `tools/case_create.py`

```python
from config.settings import CASES_DIR, DEFAULT_CLIENT, REGISTRY_FILE
from tools.common import audit, load_json, save_json, utcnow

def case_create(
    case_id: str,
    title: str = "",
    severity: str = "medium",
    analyst: str = "unassigned",
    tags: list[str] | None = None,
    client: str = "",
) -> dict:
    """Create folder structure and registry entry for case_id."""
    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        for sub in ("artefacts", "iocs", "reports", "logs"):
            (case_dir / sub).mkdir(parents=True, exist_ok=True)

    resolved_client = client or DEFAULT_CLIENT
    meta = {
        "case_id": case_id,
        "title": title or f"Investigation {case_id}",
        "severity": severity,
        "analyst": analyst,
        "client": resolved_client,
        "tags": tags or [],
        "status": "open",
        "created_at": utcnow(),
        "updated_at": utcnow(),
        "artefacts": [],
        "iocs": [],
        "report_path": None,
    }
    save_json(case_dir / "case_meta.json", meta)
    # ... update registry ...
    return meta
```

---

## CLI Quick Reference

```bash
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

# Other subcommands
python3 socai.py mdr-report --case C001
python3 socai.py triage --case C001
python3 socai.py email-analyse --case C001 --eml phish.eml
python3 socai.py campaigns --case C001
python3 socai.py sandbox --case C001
python3 socai.py anomalies --case C001
python3 socai.py timeline --case C001
python3 socai.py pe-analysis --case C001
python3 socai.py yara --case C001
python3 socai.py evtx --case C001
python3 socai.py cve-context --case C001
python3 socai.py exec-summary --case C001
python3 socai.py queries --case C001
python3 socai.py client-query --query "..."
python3 socai.py response-actions --case C001
python3 socai.py weekly
python3 socai.py list
python3 socai.py close --case C001
python3 socai.py errors          # assess errors
python3 socai.py errors --clear  # clear after review

# Web UI
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
