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
│  67 tools, 18 resources │
│  5 prompts              │
└─────────────────────────┘
    │
    │ Shared filesystem
    ▼
cases/ + registry/ + articles/
```

## Authentication

### Local Auth (default)

Uses self-issued JWTs (`api/auth.py`). Clients authenticate with `Authorization: Bearer <token>`.

```bash
# Generate a token via Python
python3 -c "from api.auth import create_access_token; print(create_access_token('analyst@example.com', 'analyst', ['investigations:submit','investigations:read','campaigns:read','sentinel:query']))"
```

### Entra ID (future)

Set `SOCAI_MCP_AUTH=entra_id` to validate Azure AD tokens instead. No other code changes needed -- the verifier is the only component that touches token validation.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SOCAI_MCP_PORT` | `8001` | Server port |
| `SOCAI_MCP_HOST` | `0.0.0.0` | Bind address |
| `SOCAI_MCP_TRANSPORT` | `sse` | Transport: `sse`, `streamable-http`, or `stdio` |
| `SOCAI_MCP_AUTH` | `local` | Auth mode: `local` or `entra_id` |
| `SOCAI_MCP_MOUNT_PATH` | `/` | Mount path for SSE routes |

## RBAC Permissions

Per-tool permission checks using `_require_scope()`. Admin bypasses all checks.

| Permission | Grants |
|---|---|
| `investigations:read` | list_cases, get_case, read_report, read_case_file, recall_cases, classify_attack, plan_investigation, resources |
| `investigations:submit` | investigate, quick_investigate_*, capture_urls, enrich_iocs, generate_report, parse_logs, detect_anomalies, correlate_evtx, analyse_pe, yara_scan, memory tools, all write tools |
| `campaigns:read` | campaign_cluster, assess_landscape, search_threat_articles |
| `sentinel:query` | run_kql, load_kql_playbook, generate_sentinel_query |
| `admin` | All tools including sandbox, browser, response_actions, merge_cases |

## Tools (67)

### Tier 1 -- Core Investigation (25)

| Tool | Permission | Description |
|---|---|---|
| `new_investigation` | — | Reset conversation boundaries for new case/client |
| `investigate` | `investigations:submit` | Run full investigation pipeline |
| `quick_investigate_url` | `investigations:submit` | Quick URL investigation (auto-generates case) |
| `quick_investigate_domain` | `investigations:submit` | Quick domain investigation |
| `quick_investigate_file` | `investigations:submit` | Quick file investigation |
| `lookup_client` | `investigations:read` | Confirm client and platform config |
| `list_cases` | `investigations:read` | List cases from registry |
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

### Tier 3 -- Advanced / Restricted (23)

| Tool | Permission | Description |
|---|---|---|
| `run_kql` | `sentinel:query` | Execute KQL query against Sentinel |
| `load_kql_playbook` | `sentinel:query` | Load KQL playbook stages |
| `generate_sentinel_query` | `sentinel:query` | Generate composite Sentinel queries |
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

## Resources (18)

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

## Prompts (5)

| Prompt | Description |
|---|---|
| `investigate_incident` | End-to-end investigation orchestrator (client gate → intake → playbook → disposition → output) |
| `triage_alert` | Guided alert triage workflow |
| `write_fp_ticket` | FP ticket generation workflow |
| `kql_investigation` | Unified KQL playbook prompt (select playbook: phishing, account-compromise, malware-execution, privilege-escalation, data-exfiltration, lateral-movement, ioc-hunt) |
| `user_security_check` | Broad-scope user account security review (identity validation → alerts → sign-in risk → email threats → activity audit → risk assessment) |

## Conversation Boundary Enforcement

The MCP server enforces per-conversation client and case isolation to prevent cross-contamination when analysts work across multiple clients.

### Client Boundary

The first client referenced in a conversation (via `lookup_client` or inferred from a `run_kql` workspace) locks the session to that client. Subsequent references to a different client raise a `ToolError` instructing the analyst to start a new chat session.

Enforcement points:
- **`lookup_client`** — calls `_set_client_boundary()` on successful lookup
- **`run_kql`** — calls `_check_workspace_boundary()` which resolves workspace → client via `client_entities.json`
- **Case-touching tools** (all tools accepting `case_id`) — call `_check_client_boundary(case_id)` which reads the client from `case_meta.json`

### Case Boundary

The first `case_id` used in a conversation locks the session to that case. Attempting to reference a different case raises a `ToolError`.

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

The `quick_investigate_*` and `investigate` tools are long-running (2-10 min). Two modes:

- **Fire-and-forget** (default): Returns `{"status": "submitted", "case_id": "..."}` immediately.
- **Inline** (`wait=True`): Blocks until pipeline completes.

### Expected tool-call sequence (fire-and-forget)

```
quick_investigate_url(url)              → {"case_id": "IV_CASE_042", "status": "submitted"}
case_summary("IV_CASE_042")             → full case overview (IOCs, verdicts, enrichment, response actions)
get_case("IV_CASE_042")                 → {"pipeline_complete": false, "_hint": "...poll again..."}
  ... wait 30s, repeat ...
get_case("IV_CASE_042")                 → {"pipeline_complete": true, "status": "open", "_hint": "...read report, then close..."}
read_report("IV_CASE_042")              → full investigation report (Markdown)
generate_mdr_report("IV_CASE_042")      → MDR report generated, case auto-closed
```

### Auto-close on deliverable collection

Generating a deliverable auto-closes the case — no separate `close_case` call needed:

| Tool | Disposition set |
|---|---|
| `generate_mdr_report` | Preserves existing |
| `generate_pup_report` | `pup_pua` |
| `generate_fp_ticket` | `false_positive` |

The `close_case` tool still exists for explicit closing (e.g. `true_positive`, `benign_positive`, `false_positive`, `inconclusive`, `resolved`) or when no deliverable is generated.

> **Note:** `get_case` includes a `_hint` field that guides the client through the
> workflow. When `pipeline_complete` is true and status is "open", the hint instructs
> the client to read the report, summarise findings, and generate the appropriate deliverable.

## File Structure

```
mcp_server/
    __init__.py     # Package marker
    __main__.py     # python -m mcp_server entry point
    server.py       # FastMCP instance, registration, main()
    auth.py         # SocaiTokenVerifier, _require_scope
    config.py       # Env var configuration
    tools.py        # 67 MCP tool wrappers
    resources.py    # 18 MCP resource implementations
    prompts.py      # 5 MCP prompt implementations
    usage.py        # Tool invocation logging (JSONL + stderr)
```

## Production Deployment

Use a reverse proxy (nginx/Caddy) to terminate TLS:

```nginx
location / {
    proxy_pass http://127.0.0.1:8001/;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
}
```

## Claude Desktop Configuration

### WSL2 (Windows host, socai in WSL)

The `env` block in Claude Desktop config is **not** forwarded into WSL processes,
so environment variables must be set inline in the bash command:

```json
{
  "mcpServers": {
    "socai": {
      "command": "wsl",
      "args": [
        "bash", "-c",
        "cd /home/<user>/socai && SOCAI_MCP_TRANSPORT=stdio ANTHROPIC_API_KEY=sk-... SOCAI_VT_KEY=... python3 -m mcp_server"
      ]
    }
  }
}
```

Config file location: `%APPDATA%\Claude\claude_desktop_config.json`

### Native Linux / macOS

```json
{
  "mcpServers": {
    "socai": {
      "command": "python3",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/socai",
      "env": {
        "SOCAI_MCP_TRANSPORT": "stdio",
        "ANTHROPIC_API_KEY": "...",
        "SOCAI_VT_KEY": "..."
      }
    }
  }
}
```

### SSE transport (remote use)

Configure the MCP client to connect to `http://host:8001/sse` with a Bearer token.

### stdio auth model

In stdio mode all RBAC scope checks are bypassed (local trust model) — no JWT
needed. The caller is identified as `"local"` with `["admin"]` scopes.
