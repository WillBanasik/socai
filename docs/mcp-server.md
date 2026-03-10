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

Separate process on port 8001, independent of the web UI (port 8000). Both share the same filesystem state (`cases/`, `registry/`).

```
Client (Claude Desktop / LLM agent)
    │
    │ SSE + Bearer JWT
    ▼
┌─────────────────────────┐
│  mcp_server/ (port 8001)│
│  FastMCP + SSE transport│
│  SocaiTokenVerifier     │
│  47 tools, 14 resources │
│  8 prompts              │
└─────────────────────────┘
    │
    │ Shared filesystem
    ▼
cases/ + registry/ + articles/
    ▲
    │
┌─────────────────────────┐
│  api/ (port 8000)       │
│  Web UI for analysts    │
└─────────────────────────┘
```

## Authentication

### Local Auth (default)

Uses the same JWT tokens as the web UI (`api/auth.py`). Clients authenticate with `Authorization: Bearer <token>`.

```bash
# Generate a token via the web UI login endpoint
curl -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email": "analyst@example.com", "password": "..."}'
```

### Entra ID (future)

Set `SOCAI_MCP_AUTH=entra_id` to validate Azure AD tokens instead. No other code changes needed -- the verifier is the only component that touches token validation.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SOCAI_MCP_PORT` | `8001` | Server port |
| `SOCAI_MCP_HOST` | `0.0.0.0` | Bind address |
| `SOCAI_MCP_TRANSPORT` | `sse` | Transport: `sse` or `streamable-http` |
| `SOCAI_MCP_AUTH` | `local` | Auth mode: `local` or `entra_id` |
| `SOCAI_MCP_MOUNT_PATH` | `/` | Mount path for SSE routes |

## RBAC Permissions

Per-tool permission checks using `_require_scope()`. Admin bypasses all checks.

| Permission | Grants |
|---|---|
| `investigations:read` | list_cases, get_case, read_report, read_case_file, recall_cases, resources |
| `investigations:submit` | investigate, quick_investigate_*, capture_urls, enrich_iocs, generate_report, all write tools |
| `campaigns:read` | campaign_cluster, assess_landscape, search_threat_articles |
| `sentinel:query` | run_kql, load_kql_playbook |
| `admin` | All tools including sandbox, browser, response_actions, merge_cases |

## Tools (47)

### Tier 1 -- Core Investigation (17)

| Tool | Permission |
|---|---|
| `investigate` | `investigations:submit` |
| `quick_investigate_url` | `investigations:submit` |
| `quick_investigate_domain` | `investigations:submit` |
| `quick_investigate_file` | `investigations:submit` |
| `list_cases` | `investigations:read` |
| `get_case` | `investigations:read` |
| `case_summary` | `investigations:read` |
| `read_report` | `investigations:read` |
| `read_case_file` | `investigations:read` |
| `close_case` | `investigations:submit` |
| `add_evidence` | `investigations:submit` |
| `add_finding` | `investigations:submit` |
| `enrich_iocs` | `investigations:submit` |
| `generate_report` | `investigations:submit` |
| `generate_mdr_report` | `investigations:submit` |
| `generate_queries` | `investigations:submit` |
| `lookup_client` | `investigations:read` |

### Tier 2 -- Extended Analysis (12)

| Tool | Permission |
|---|---|
| `capture_urls` | `investigations:submit` |
| `detect_phishing` | `investigations:submit` |
| `analyse_email` | `investigations:submit` |
| `correlate` | `investigations:submit` |
| `reconstruct_timeline` | `investigations:read` |
| `campaign_cluster` | `campaigns:read` |
| `recall_cases` | `investigations:read` |
| `assess_landscape` | `campaigns:read` |
| `search_threat_articles` | `campaigns:read` |
| `generate_threat_article` | `investigations:submit` |
| `web_search` | `investigations:submit` |
| `generate_executive_summary` | `investigations:submit` |

### Tier 3 -- Advanced / Restricted (17)

| Tool | Permission |
|---|---|
| `run_kql` | `sentinel:query` |
| `load_kql_playbook` | `sentinel:query` |
| `security_arch_review` | `investigations:submit` |
| `contextualise_cves` | `investigations:read` |
| `ingest_velociraptor` | `investigations:submit` |
| `ingest_mde_package` | `investigations:submit` |
| `generate_weekly` | `investigations:read` |
| `link_cases` | `investigations:submit` |
| `merge_cases` | `admin` |
| `response_actions` | `investigations:submit` |
| `generate_fp_ticket` | `investigations:submit` |
| `start_sandbox_session` | `admin` |
| `stop_sandbox_session` | `admin` |
| `list_sandbox_sessions` | `admin` |
| `start_browser_session` | `admin` |
| `stop_browser_session` | `admin` |
| `list_browser_sessions` | `admin` |

## Resources (14)

| URI | Description |
|---|---|
| `socai://cases` | All cases from registry |
| `socai://cases/{case_id}/meta` | Case metadata |
| `socai://cases/{case_id}/report` | Investigation report |
| `socai://cases/{case_id}/iocs` | Extracted IOCs |
| `socai://cases/{case_id}/verdicts` | Verdict summary |
| `socai://cases/{case_id}/enrichment` | Enrichment data |
| `socai://cases/{case_id}/timeline` | Timeline events |
| `socai://clients` | Client registry with platform scope |
| `socai://clients/{client_name}` | Full client configuration |
| `socai://ioc-index/stats` | IOC index summary with tier breakdown |
| `socai://playbooks` | KQL playbook index |
| `socai://playbooks/{id}` | Full playbook with stages |
| `socai://articles` | Threat article index |
| `socai://landscape` | Threat landscape summary |

## Prompts (8)

| Prompt | Description |
|---|---|
| `investigate_incident` | End-to-end investigation orchestrator (client gate → intake → playbook → disposition → output) |
| `investigate_phishing` | Multi-stage KQL phishing playbook |
| `investigate_account_compromise` | Account compromise KQL playbook |
| `investigate_ioc_hunt` | IOC hunting KQL playbook |
| `investigate_malware_execution` | Malware execution KQL playbook |
| `investigate_privilege_escalation` | Privilege escalation KQL playbook |
| `triage_alert` | Guided alert triage workflow |
| `write_fp_ticket` | FP ticket generation workflow |

## Conversation Boundary Enforcement

The MCP server enforces per-conversation client and case isolation to prevent cross-contamination when analysts work across multiple clients.

### Client Boundary

The first client referenced in a conversation (via `lookup_client` or inferred from a `run_kql` workspace) locks the session to that client. Subsequent references to a different client raise a `ToolError` instructing the analyst to start a new chat session.

Enforcement points:
- **`lookup_client`** — calls `_set_client_boundary()` on successful lookup
- **`run_kql`** — calls `_check_workspace_boundary()` which resolves workspace → client via `client_entities.json`
- **Case-touching tools** (20 tools) — call `_check_client_boundary(case_id)` which reads the client from `case_meta.json`

### Case Boundary

The first `case_id` used in a conversation locks the session to that case. Attempting to reference a different case raises a `ToolError`.

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

The `close_case` tool still exists for explicit closing (e.g. `true_positive`, `inconclusive`, `resolved`) or when no deliverable is generated.

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
    tools.py        # 45 MCP tool wrappers
    resources.py    # 14 MCP resource implementations
    prompts.py      # 8 MCP prompt implementations
```

## Production Deployment

Use a reverse proxy (nginx/Caddy) to terminate TLS:

```nginx
# /mcp/ -> MCP server (8001)
location /mcp/ {
    proxy_pass http://127.0.0.1:8001/;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
}

# / -> Web UI (8000)
location / {
    proxy_pass http://127.0.0.1:8000;
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
