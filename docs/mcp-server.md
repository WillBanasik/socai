# MCP Server

socai exposes its investigation tools to external MCP clients over HTTPS SSE with JWT-based role-based access control (RBAC).

## Quick Start

```bash
# Start MCP server (SSE transport, port 8001)
python3 -m mcp_server

# Custom port
SOCAI_MCP_PORT=9001 python3 -m mcp_server

# Streamable HTTP transport
SOCAI_MCP_TRANSPORT=streamable-http python3 -m mcp_server
```

## Architecture

Standalone process on port 8001. Shares filesystem state (`cases/`, `registry/`) with the CLI.

```
Client (Claude Desktop / LLM agent)
    │
    │ SSE + Bearer JWT
    ▼
┌─────────────────────────┐
│  mcp_server/ (port 8001)│
│  FastMCP + SSE transport│
│  SocaiTokenVerifier     │
│  77 tools, 26 resources │
│  16 prompts, JSONL logs │
└─────────────────────────┘
    │
    │ Shared filesystem
    ▼
cases/ + registry/ + articles/
```

### Design Principle: Local Thinking, Server Weapons

The MCP server provides two modes for report and analysis work:

- **Tools** — do real work: API calls (enrichment, Sentinel, sandbox), file I/O (case management), external integrations (Confluence, OpenCTI), deterministic logic (classification, response matrix). These stay server-side.
- **Prompts** — load instructions + case data into the analyst's local Claude Desktop session for report generation, analytical reasoning, and quality review. The local session has the full conversation context and produces better output than a cold server-side API call.

**Workflow:** Select prompt → local Claude generates → call `save_report` / `save_threat_article` to persist (handles defanging, HTML conversion, auto-close, audit).

## Authentication

### Local Auth (default)

Uses self-issued JWTs (`api/auth.py`). Clients authenticate with `Authorization: Bearer <token>`.

```bash
# Generate a token with role-resolved permissions (preferred)
python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('alice@soc.com', 'junior_mdr'))"
python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('bob@soc.com', 'mdr_analyst'))"
python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('charlie@soc.com', 'senior_analyst'))"

# Or with explicit permissions (legacy)
python3 -c "from api.auth import create_access_token; print(create_access_token('analyst@example.com', 'mdr_analyst', ['investigations:submit','investigations:read','campaigns:read','sentinel:query']))"
```

**Token TTL:** Controlled by `SOCAI_JWT_TTL_HOURS` (default `8`). For centrally hosted deployments behind a VPN, longer TTLs (24h–30d) reduce friction. Tokens carry the analyst's role, email, and permissions — the MCP server reads these on every request.

**Security checklist:**
- Set a strong random `SOCAI_JWT_SECRET` in `.env` (the default is insecure)
- Use TLS (Caddy/nginx reverse proxy) — JWTs over plain HTTP are interceptable
- Bind `SOCAI_MCP_HOST=127.0.0.1` when behind a reverse proxy
- `chmod 600 config/users.json` (contains password hashes)

### Entra ID (future)

Set `SOCAI_MCP_AUTH=entra_id` to validate Azure AD tokens instead. `SocaiTokenVerifier` is the only component that touches token validation — swap it to validate against Entra's JWKS endpoint. Map Entra security groups (`sg-soc-junior`, `sg-soc-analyst`, `sg-soc-senior`) to role names in `config/roles.json`. Everything downstream (RBAC, roles, resources, prompts) stays unchanged.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SOCAI_MCP_PORT` | `8001` | Server port |
| `SOCAI_MCP_HOST` | `0.0.0.0` | Bind address (`127.0.0.1` when behind reverse proxy) |
| `SOCAI_MCP_TRANSPORT` | `sse` | Transport: `sse`, `streamable-http`, or `stdio` |
| `SOCAI_MCP_AUTH` | `local` | Auth mode: `local` or `entra_id` |
| `SOCAI_MCP_MOUNT_PATH` | `/` | Mount path for SSE routes |
| `SOCAI_MCP_LOG_LEVEL` | `INFO` | Structured log level |
| `SOCAI_MCP_LOG_RESULTS` | `1` | Log tool result previews (`0` to disable) |
| `SOCAI_MCP_LOG_MAX_RESULT` | `2000` | Max chars per result preview in logs |
| `SOCAI_JWT_SECRET` | (insecure default) | JWT signing secret — **must set in production** |
| `SOCAI_JWT_TTL_HOURS` | `8` | Token expiry (hours); `720` = 30 days |

## RBAC Permissions

Per-tool permission checks using `_require_scope()`. Admin bypasses all checks.

| Permission | Grants |
|---|---|
| `investigations:read` | list_cases, get_case, read_report, read_case_file, recall_cases, classify_attack, plan_investigation, resources |
| `investigations:submit` | capture_urls, enrich_iocs, generate_report, parse_logs, detect_anomalies, correlate_evtx, analyse_pe, yara_scan, memory tools, all write tools |
| `campaigns:read` | campaign_cluster, assess_landscape, search_threat_articles |
| `sentinel:query` | run_kql, load_kql_playbook, generate_sentinel_query, run_kql_batch |
| `admin` | All tools including sandbox, browser, response_actions, merge_cases |

## Analyst Roles

Roles control **how** the platform talks to the analyst — tone, explanation depth, severity routing, and response authority. All roles access the same tools; the difference is in the assistant's behaviour. Defined in `config/roles.json`.

| Role | Severity Ceiling | Response Authority | Tone |
|---|---|---|---|
| `junior_mdr` | Medium | Observe & escalate | Educational — explains tools, verdicts, MITRE techniques; walks through evidence chains; flags high/critical for escalation |
| `mdr_analyst` | Critical | Containment | Professional — concise, presents findings directly, suggests next steps when multiple paths exist |
| `senior_analyst` | Critical | Full IR | Peer — terse, granular technical detail, supports deep IR and threat hunting, surfaces disconfirming evidence |

Admin access is via direct server SSH (stdio transport), not a role.

The `socai://role` resource returns the current analyst's role, guidance flags, and behavioural instructions. The assistant reads this at session start to adapt.

### Token Generation

```bash
# Create token with role-resolved permissions
python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('alice@soc.com', 'junior_mdr'))"
python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('bob@soc.com', 'mdr_analyst'))"
python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('charlie@soc.com', 'senior_analyst'))"
```

When Entra ID SSO is added, map Entra security groups (e.g. `sg-soc-junior`, `sg-soc-analyst`, `sg-soc-senior`) to these role names in the auth config.

## Tools (77)

### Tier 1 -- Core Investigation (24)

| Tool | Permission | Description |
|---|---|---|
| `new_investigation` | — | Reset conversation boundaries for new case/client |
| `lookup_client` | `investigations:read` | Confirm client and platform config |
| `create_case` | `investigations:submit` | Create new case in triage status (auto-generates ID) |
| `promote_case` | `investigations:submit` | Promote case from triage to active |
| `discard_case` | `investigations:submit` | Discard triage case (false alarm) |
| `list_cases` | `investigations:read` | List cases from registry (filterable by status) |
| `get_case` | `investigations:read` | Get case status and metadata |
| `case_summary` | `investigations:read` | Aggregated case view (meta + IOCs + verdicts + enrichment) |
| `read_report` | `investigations:read` | Read investigation report markdown |
| `read_case_file` | `investigations:read` | Read any case artefact file |
| `close_case` | `investigations:submit` | Close case with disposition |
| `add_evidence` | `investigations:submit` | Add raw evidence (alerts, IOCs, log snippets) |
| `add_finding` | `investigations:submit` | Record analytical finding/conclusion |
| `enrich_iocs` | `investigations:submit` | Extract and enrich IOCs |
| `generate_report` | `investigations:submit` | Generate investigation report |
| `generate_mdr_report` | `investigations:submit` | Generate MDR client report (auto-closes) |
| `generate_pup_report` | `investigations:submit` | Generate PUP/PUA report (auto-closes) |
| `generate_queries` | `investigations:submit` | Generate SIEM hunt queries |
| `classify_attack` | `investigations:read` | Deterministic attack-type classification |
| `plan_investigation` | `investigations:read` | Full investigation plan with phases and dependencies |
| `quick_enrich` | `investigations:read` | Caseless ad-hoc IOC enrichment (no case required) |
| `query_opencti` | `investigations:read` | Direct OpenCTI queries (IOCs, CVEs, keyword search) |
| `extract_iocs_from_text` | — | Extract IOCs from raw text (caseless) |
| `search_confluence` | `investigations:read` | Search/browse/read Confluence pages (docs, policies, published articles) |

### Tier 2 -- Extended Analysis (19)

| Tool | Permission | Description |
|---|---|---|
| `capture_urls` | `investigations:submit` | Screenshot and capture web page evidence |
| `detect_phishing` | `investigations:submit` | Brand impersonation / phishing detection |
| `analyse_email` | `investigations:submit` | Email header/content analysis |
| `correlate` | `investigations:submit` | IOC correlation across case artefacts |
| `reconstruct_timeline` | `investigations:read` | Forensic timeline reconstruction |
| `campaign_cluster` | `campaigns:read` | Cross-case IOC overlap clustering |
| `recall_cases` | `investigations:read` | Search prior cases by IOC or keyword |
| `assess_landscape` | `campaigns:read` | Threat landscape assessment |
| `search_threat_articles` | `campaigns:read` | Discover threat intel article candidates |
| `generate_threat_article` | `investigations:submit` | Write up selected threat articles |
| `web_search` | `investigations:submit` | OSINT web search (Brave/DuckDuckGo) |
| `generate_executive_summary` | `investigations:submit` | Non-technical leadership briefing |
| `parse_logs` | `investigations:submit` | Parse CSV/JSON/JSONL logs, extract entities |
| `detect_anomalies` | `investigations:submit` | Behavioural anomaly detection (6 detectors) |
| `correlate_evtx` | `investigations:submit` | Windows EVTX attack chain correlation (7 detectors) |
| `triage_iocs` | `investigations:submit` | Pre-pipeline IOC reputation check |
| `score_ioc_verdicts` | `investigations:submit` | Composite verdict scoring + IOC index update |
| `analyse_static_file` | `investigations:submit` | Quick binary file triage (PE headers, entropy, strings) |
| `sandbox_api_lookup` | `investigations:submit` | API-based sandbox report lookup (Hybrid Analysis, Any.Run, Joe) |

### Client-Side Persistence (2)

| Tool | Permission | Description |
|---|---|---|
| `save_report` | `investigations:submit` | Persist a locally-generated report (defang, HTML, auto-close, audit). No LLM call. |
| `save_threat_article` | `investigations:submit` | Persist a locally-generated threat article to the article index. No LLM call. |

### Tier 3 -- Advanced / Restricted (24)

| Tool | Permission | Description |
|---|---|---|
| `run_kql` | `sentinel:query` | Execute KQL query against Sentinel |
| `load_kql_playbook` | `sentinel:query` | Load KQL playbook stages |
| `generate_sentinel_query` | `sentinel:query` | Generate composite Sentinel queries |
| `run_kql_batch` | `sentinel:query` | Execute multiple KQL queries concurrently (max 4 workers) |
| `security_arch_review` | `investigations:submit` | LLM-powered security architecture review |
| `contextualise_cves` | `investigations:read` | CVE contextualisation (NVD, EPSS, CISA KEV) |
| `ingest_velociraptor` | `investigations:submit` | Ingest Velociraptor offline collector data |
| `ingest_mde_package` | `investigations:submit` | Ingest MDE investigation package |
| `generate_weekly` | `investigations:read` | Weekly SOC report |
| `link_cases` | `investigations:submit` | Link related cases |
| `merge_cases` | `admin` | Merge duplicate cases |
| `response_actions` | `investigations:submit` | Recommend containment/response actions |
| `generate_fp_ticket` | `investigations:submit` | FP suppression ticket (auto-closes) |
| `generate_fp_tuning_ticket` | `investigations:submit` | SIEM tuning ticket (does NOT auto-close) |
| `start_sandbox_session` | `admin` | Containerised malware detonation |
| `stop_sandbox_session` | `admin` | Stop sandbox and collect artefacts |
| `list_sandbox_sessions` | `admin` | List active/recent sandbox sessions |
| `start_browser_session` | `admin` | Stealth browser session (noVNC + tcpdump, no automation markers) |
| `stop_browser_session` | `admin` | Stop browser session and collect pcap/entities |
| `list_browser_sessions` | `admin` | List browser sessions |
| `analyse_pe` | `investigations:submit` | Deep PE static analysis (entropy, imports, packing) |
| `yara_scan` | `investigations:submit` | YARA rule scanning (built-in + external + LLM-generated) |
| `memory_dump_guide` | `investigations:submit` | MDE Live Response dump collection guidance |
| `analyse_memory_dump` | `investigations:submit` | Process memory dump analysis (strings, IOCs, risk scoring) |

## Resources (26)

| URI | Description |
|---|---|
| `socai://capabilities` | Structured overview of all tools, prompts, and resources |
| `socai://cases` | All cases from registry |
| `socai://cases/{case_id}/meta` | Case metadata |
| `socai://cases/{case_id}/report` | Investigation report |
| `socai://cases/{case_id}/iocs` | Extracted IOCs |
| `socai://cases/{case_id}/verdicts` | Verdict summary |
| `socai://cases/{case_id}/enrichment` | Enrichment data |
| `socai://cases/{case_id}/timeline` | Timeline events |
| `socai://cases/{case_id}/notes` | Analyst notes (free-text investigation context) |
| `socai://cases/{case_id}/response-actions` | Client response actions and containment plan |
| `socai://cases/{case_id}/fp-ticket` | Existing FP closure comment |
| `socai://cases/{case_id}/matrix` | Investigation reasoning matrix (Rumsfeld method) |
| `socai://cases/{case_id}/determination` | Evidence-chain determination analysis |
| `socai://cases/{case_id}/quality-gate` | Report quality gate review results |
| `socai://cases/{case_id}/followups` | Follow-up investigation proposals |
| `socai://clients` | Client registry with platform scope |
| `socai://clients/{client_name}` | Full client configuration |
| `socai://clients/{name}/playbook` | Client response playbook |
| `socai://ioc-index/stats` | IOC index summary with tier breakdown |
| `socai://playbooks` | KQL playbook index |
| `socai://playbooks/{id}` | Full playbook with stages |
| `socai://sentinel-queries` | Sentinel composite query scenarios |
| `socai://pipeline-profiles` | Attack-type routing profiles |
| `socai://articles` | Threat article index |
| `socai://landscape` | Threat landscape summary |
| `socai://role` | Current analyst role, permissions, and behavioural instructions |

## Prompts (16)

### Guided Workflows (5)

| Prompt | Description |
|---|---|
| `hitl_investigation` | Guided step-by-step investigation (client gate → intake → playbook → disposition → output) |
| `triage_alert` | Guided alert triage workflow |
| `write_fp_ticket` | FP ticket generation workflow |
| `kql_investigation` | Unified KQL playbook prompt (select playbook: phishing, account-compromise, malware-execution, privilege-escalation, data-exfiltration, lateral-movement, ioc-hunt) |
| `user_security_check` | Broad-scope user account security review (identity validation → alerts → sign-in risk → email threats → activity audit → risk assessment) |

### Client-Side Report Generation (8)

These prompts load system instructions + case data into the analyst's local Claude Desktop session. The local session generates the report, then `save_report` / `save_threat_article` persists it (handles defanging, HTML conversion, auto-close, audit).

| Prompt | Replaces (server-side) | Auto-closes |
|---|---|---|
| `write_mdr_report` | `generate_mdr_report` | Yes (preserves disposition) |
| `write_pup_report` | `generate_pup_report` | Yes (`pup_pua`) |
| `write_fp_closure` | `generate_fp_ticket` | Yes (`false_positive`) |
| `write_fp_tuning` | `generate_fp_tuning_ticket` | No |
| `write_executive_summary` | `generate_executive_summary` | No |
| `write_security_arch_review` | `security_arch_review` | No |
| `write_threat_article` | `generate_threat_article` | N/A |
| `write_response_plan` | `response_actions` (advisory) | No |

### Client-Side Analysis (3)

| Prompt | Replaces (server-side) | Purpose |
|---|---|---|
| `run_determination` | `run_determination` tool | Evidence-chain disposition analysis (TP/BP/FP) |
| `build_investigation_matrix` | `generate_investigation_matrix` tool | Rumsfeld matrix (knowns/unknowns/hypotheses) |
| `review_report` | `review_report_quality` tool | Report quality gate review |

## Access Control

Access control is handled by RBAC (per-tool scopes via JWT claims) and filesystem isolation (`cases/<ID>/`). There are no in-process conversation boundaries — analysts can freely work across multiple cases and clients in a single session.

**One alert = one case.** Every new alert gets its own case, even if the same user, host, or IOCs appeared in a prior case. Cross-case correlation is handled by `recall_cases` (historical IOC/keyword lookup) and `campaign_cluster` (IOC overlap comparison), not by appending to existing cases.

### Data Hierarchy

Cross-case search (`recall_cases`) respects a three-tier data hierarchy:

| Tier | Scope | What's searchable | Cross-client visibility |
|---|---|---|---|
| **Global** | All cases, all clients | Public IPs, domains, URLs, hashes, CVEs, emails | IOC value + verdict (no case details) |
| **Client** | Same client only | Private IPs, bare hostnames | Invisible to other clients |
| **Case** | Single case only | Findings, reports, timelines, analyst notes | Same-client cases only |

Classification is determined by `tools/ioc_classify.py` and stored in the IOC index (`registry/ioc_index.json`) as the `tier` field.

## Investigation Workflow

See `docs/pipeline.md` for the full HITL workflow, tool sequence, auto-close rules, and attack-type classification.

**Speculative enrichment:** When `classify_attack` or `add_evidence` is called, the server fires a background thread that calls `quick_enrich(iocs, deep=False)` on extracted IOCs (capped at 20, fast providers only). Results go to the enrichment cache so subsequent calls get cache hits.

## File Structure

```
mcp_server/
    __init__.py        # Package marker
    __main__.py        # python -m mcp_server entry point
    server.py          # FastMCP instance, registration, main()
                       #   PID file (crash recovery), signal handlers (SIGTERM/SIGINT),
                       #   unhandled exception hook, SSE connection lifecycle middleware
    auth.py            # SocaiTokenVerifier, _require_scope
    config.py          # Env var configuration
    tools.py           # 77 MCP tool wrappers
    resources.py       # 26 MCP resource implementations
    prompts.py         # 16 MCP prompt implementations
    usage.py           # Tool invocation logging (JSONL + stderr); emits tool_call,
                       #   tool_result, tool_error events with result previews
    logging_config.py  # Structured JSONL logger (RotatingFileHandler, 10 MB × 3 backups)
                       #   setup_mcp_logger() + mcp_log(event, **fields)
                       #   Output: registry/mcp_server.jsonl + stderr
```

## Logging & Observability

The MCP server writes structured JSONL events to `registry/mcp_server.jsonl` (10 MB rotation, 3 backups) and mirrors to stderr for live tailing.

**Event types:**

| Event | When | Key fields |
|---|---|---|
| `server_start` | Server boots | transport, host, port, pid, tool_count |
| `server_stop` | Clean shutdown | reason, pid, uptime_s |
| `server_signal` | SIGTERM/SIGINT received | signal, pid, uptime_s |
| `server_crash` | Unhandled exception | error, traceback (truncated 4 KB) |
| `server_recovery` | Stale PID detected on startup | stale_pid, note |
| `sse_connect` | SSE client connects | ip, user_agent, path |
| `sse_disconnect` | SSE client disconnects | ip, duration_s |
| `tool_call` | Tool invoked | tool, args (summarised) |
| `tool_result` | Tool returns | tool, duration_ms, result_preview |
| `tool_error` | Tool raises | tool, error, duration_ms |

**PID file:** `registry/mcp_server.pid` — written on startup, removed on clean shutdown. On next startup, `_check_stale_pid()` detects unclean shutdowns and logs a recovery event.

**Tailing logs:**
```bash
tail -f registry/mcp_server.jsonl | python3 -m json.tool
```

## Production Deployment

### Architecture

```
Analyst's Claude Desktop (VPN / corporate network)
    │
    │ SSE + Bearer JWT over HTTPS
    ▼
┌──────────────────────────┐
│  Caddy / nginx (TLS)     │  ← socai.yourcompany.com
│  Automatic HTTPS certs   │
└──────────────────────────┘
    │
    │ HTTP (localhost only)
    ▼
┌──────────────────────────┐
│  mcp_server (port 8001)  │  ← SOCAI_MCP_HOST=127.0.0.1
│  77 tools, 26 resources  │
│  JWT RBAC, role system   │
└──────────────────────────┘
    │
    │ Filesystem
    ▼
cases/ + registry/ + articles/
```

### Caddy (recommended — automatic HTTPS)

```
socai.yourcompany.com {
    reverse_proxy 127.0.0.1:8001 {
        flush_interval -1
        transport http {
            read_timeout 0
        }
    }
}
```

`flush_interval -1` is critical — without it Caddy buffers SSE events and the MCP connection stalls.

### nginx

```nginx
location / {
    proxy_pass http://127.0.0.1:8001/;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
}
```

### Server startup

```bash
# Bind to localhost only (reverse proxy handles external traffic)
SOCAI_MCP_HOST=127.0.0.1 python3 -m mcp_server
```

### Security checklist

- [ ] Set `SOCAI_JWT_SECRET` to a strong random value in `.env`
- [ ] Set `SOCAI_MCP_HOST=127.0.0.1` (don't expose port 8001 directly)
- [ ] TLS via reverse proxy (Caddy auto-HTTPS or nginx + certbot)
- [ ] VPN or network-level access control (don't expose to the internet without)
- [ ] `chmod 600 config/users.json` and `.env`
- [ ] Set `SOCAI_JWT_TTL_HOURS` appropriate to your environment (8h–720h)

## Claude Desktop Configuration

### Centrally Hosted (SSE over HTTPS)

Analysts connect Claude Desktop to the central server. Each analyst gets a JWT token with their role:

```bash
# Admin generates tokens for the team
python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('alice@soc.com', 'junior_mdr'))"
```

Analyst's Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "socai": {
      "url": "https://socai.yourcompany.com/sse",
      "headers": {
        "Authorization": "Bearer <their-token>"
      }
    }
  }
}
```

The token carries the analyst's email, role, and permissions. The `socai://role` resource returns role-specific behavioural instructions at session start, so the assistant adapts to the analyst's experience level automatically.

### Local Development — WSL2 (Windows host, socai in WSL)

The `env` block in Claude Desktop config is **not** forwarded into WSL processes, so environment variables must be set inline:

```json
{
  "mcpServers": {
    "socai": {
      "command": "wsl",
      "args": ["bash", "-c", "cd /home/<user>/socai && SOCAI_MCP_TRANSPORT=stdio ANTHROPIC_API_KEY=sk-... python3 -m mcp_server"]
    }
  }
}
```

### Local Development — Native Linux / macOS

```json
{
  "mcpServers": {
    "socai": {
      "command": "python3",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/socai",
      "env": { "SOCAI_MCP_TRANSPORT": "stdio", "ANTHROPIC_API_KEY": "..." }
    }
  }
}
```

### Transport Modes

| Mode | Auth | Use case |
|------|------|----------|
| `stdio` | None (local trust) | Local dev, Claude Desktop on same machine. Caller is `"local"` with admin scopes, `senior_analyst` role. |
| `sse` | Bearer JWT | Central server. Analysts connect over HTTPS via reverse proxy. |
| `streamable-http` | Bearer JWT | Alternative to SSE for clients that prefer HTTP streaming. |

**Project instructions:** `docs/claude-desktop-instructions.md` — loaded via Claude Desktop `.claude_project`.
