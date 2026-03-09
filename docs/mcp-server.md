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
│  44 tools, 11 resources │
│  7 prompts              │
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

## Tools (44)

### Tier 1 -- Core Investigation (15)

| Tool | Permission |
|---|---|
| `investigate` | `investigations:submit` |
| `quick_investigate_url` | `investigations:submit` |
| `quick_investigate_domain` | `investigations:submit` |
| `quick_investigate_file` | `investigations:submit` |
| `list_cases` | `investigations:read` |
| `get_case` | `investigations:read` |
| `read_report` | `investigations:read` |
| `read_case_file` | `investigations:read` |
| `close_case` | `investigations:submit` |
| `add_evidence` | `investigations:submit` |
| `add_finding` | `investigations:submit` |
| `enrich_iocs` | `investigations:submit` |
| `generate_report` | `investigations:submit` |
| `generate_mdr_report` | `investigations:submit` |
| `generate_queries` | `investigations:submit` |

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

## Resources (11)

| URI | Description |
|---|---|
| `socai://cases` | All cases from registry |
| `socai://cases/{case_id}/meta` | Case metadata |
| `socai://cases/{case_id}/report` | Investigation report |
| `socai://cases/{case_id}/iocs` | Extracted IOCs |
| `socai://cases/{case_id}/verdicts` | Verdict summary |
| `socai://cases/{case_id}/enrichment` | Enrichment data |
| `socai://cases/{case_id}/timeline` | Timeline events |
| `socai://playbooks` | KQL playbook index |
| `socai://playbooks/{id}` | Full playbook with stages |
| `socai://articles` | Threat article index |
| `socai://landscape` | Threat landscape summary |

## Prompts (7)

| Prompt | Description |
|---|---|
| `investigate_phishing` | Multi-stage KQL phishing playbook |
| `investigate_account_compromise` | Account compromise KQL playbook |
| `investigate_ioc_hunt` | IOC hunting KQL playbook |
| `investigate_malware_execution` | Malware execution KQL playbook |
| `investigate_privilege_escalation` | Privilege escalation KQL playbook |
| `triage_alert` | Guided alert triage workflow |
| `write_fp_ticket` | FP ticket generation workflow |

## Investigation Workflow

The `quick_investigate_*` and `investigate` tools are long-running (2-10 min). Two modes:

- **Fire-and-forget** (default): Returns `{"status": "submitted", "case_id": "..."}` immediately.
- **Inline** (`wait=True`): Blocks until pipeline completes.

### Expected tool-call sequence (fire-and-forget)

```
quick_investigate_url(url)          → {"case_id": "C042", "status": "submitted"}
get_case("C042")                    → {"pipeline_complete": false, "_hint": "...poll again..."}
  ... wait 30s, repeat ...
get_case("C042")                    → {"pipeline_complete": true, "status": "open", "_hint": "...read report, then close..."}
read_report("C042")                 → full investigation report (Markdown)
close_case("C042", "true_positive") → case status set to "closed"
```

The `close_case` tool accepts a `disposition` parameter to record the closing reason:
`true_positive`, `false_positive`, `benign`, `inconclusive`, or `resolved` (default).

> **Note:** `get_case` includes a `_hint` field that guides the client through the
> workflow. When `pipeline_complete` is true and status is "open", the hint instructs
> the client to read the report, summarise findings, and close the case.

## File Structure

```
mcp_server/
    __init__.py     # Package marker
    __main__.py     # python -m mcp_server entry point
    server.py       # FastMCP instance, registration, main()
    auth.py         # SocaiTokenVerifier, _require_scope
    config.py       # Env var configuration
    tools.py        # 44 MCP tool wrappers
    resources.py    # 11 MCP resource implementations
    prompts.py      # 7 MCP prompt implementations
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
