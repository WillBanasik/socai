# Encore Gateway EQL Integration

Query Encore's multi-client telemetry warehouse with **EQL** (Encore Query Language) — a read-only query layer over normalised security data (Active Directory, Entra ID, Sentinel, CrowdStrike, Defender ATP, Intune, CloudFlare, O365, vulnerability prioritisation, and more) across all onboarded clients.

EQL is **not** Elasticsearch EQL and **not** SQL. See [EQL syntax](#eql-syntax) below.

## Architecture

| | |
|---|---|
| Gateway endpoint | `https://za.encore.io/gateway` (production, read-only, multi-client) |
| MCP endpoint | `https://za.encore.io/gateway/api/mcp-eql/` (Streamable HTTP) |
| Auth | Personal **refresh token** in `ENCORE_EQL_TOKEN` → short-lived (~30 min) access token |
| Token exchange | `POST /gateway/api/auth/refresh` `{"refreshToken": "<token>"}` → `{accessToken, refreshToken}` |
| Regions | Clients are tagged `EU` or `ZA` (`targetRegionId`); the gateway routes by client |
| Edge | Cloudflare in front — **a browser User-Agent is required** (see quirks) |

**The `ENCORE_EQL_TOKEN` is a personal token with access to ALL Encore clients — guard it.** Service-account tokens: request from `support@encore.io`. Tokens rotate; a rotated token immediately kills the old one. A dead token returns `401 {"invalid_token"}` from `/auth/refresh`.

## Two access paths

| Path | Used by | Setup |
|---|---|---|
| **A. Direct API** — `scripts/eql_direct.py` | Shell / Claude Code Bash | Reads `ENCORE_EQL_TOKEN`, does the refresh exchange, sends a browser UA. No MCP needed. |
| **B. MCP server** — `eql-hosted` | Claude Code (`.mcp.json`) and Claude Desktop (`mcp-remote` wrapper) | Exposes `mcp__eql-hosted__*` tools. The gateway does the refresh exchange server-side — pass the raw refresh token as Bearer. |

Both paths read the same `ENCORE_EQL_TOKEN` env var (kept in `~/.bashrc`, never in a committed file).

### Auth flow (direct API)

1. `POST https://za.encore.io/gateway/api/auth/refresh` with body `{"refreshToken": "<ENCORE_EQL_TOKEN>"}` → `{accessToken (~30-min TTL), refreshToken}`. The original refresh token stays valid for a long time.
2. Send `Authorization: Bearer <accessToken>` on every query.

For the **MCP path the exchange is server-side** — the gateway accepts the refresh token directly as the Bearer header and mints the access token internally. Confirmed: an MCP `initialize` against the endpoint with the refresh token as Bearer returns `200 text/event-stream`, serverInfo `EQL Gateway`.

### Cloudflare User-Agent quirk

`za.encore.io/gateway` is behind Cloudflare. The default `curl` / Python `urllib` User-Agent is **403-blocked** (Cloudflare HTML block page — looks like an IP block but is not). Sending a **browser UA** (`Mozilla/5.0 … Chrome/…`) passes. `scripts/eql_direct.py` sets a browser UA on every request; `mcp-remote` and Claude Code's HTTP MCP client are accepted as-is.

Distinguish failures: **Cloudflare HTML 403** = UA/edge problem; **clean JSON 401** = reached the app, token problem.

## Path A — `scripts/eql_direct.py`

```bash
python3 scripts/eql_direct.py query "list version"            # health check
python3 scripts/eql_direct.py clients                         # all client aliases + region
python3 scripts/eql_direct.py query "list tables" [--client <alias>]
python3 scripts/eql_direct.py query "list labels"
python3 scripts/eql_direct.py query "list tables label:<label>"
python3 scripts/eql_direct.py query "list columns <TableName>"
python3 scripts/eql_direct.py query '<TableName> WHERE <col> = "x" SELECT <col1>, <col2>' --client <alias>
```

Defaults to the `Performanta` client. Reads `ENCORE_EQL_TOKEN`, refreshes, sends a browser UA, never prints the token. Query endpoint: `POST /client/request?client=<alias>` with the raw EQL string as the body. Clients: `GET /system/clients` → `[{internalClientId, targetRegionId, aliases[]}]` — use any alias as the `--client` value.

## Path B — MCP server (`eql-hosted`)

The `eql-hosted` MCP server exposes these tools: `list_clients`, `resolve_client`, `list_tables`, `list_columns`, `list_labels`, `execute_eql`. Tools that receive a `clientId` route to the multi-client gateway; tools without one route to the single-client local endpoint.

### Claude Code (project `.mcp.json`)

```json
{
  "mcpServers": {
    "eql-hosted": {
      "type": "http",
      "url": "https://za.encore.io/gateway/api/mcp-eql/",
      "headers": { "Authorization": "Bearer ${ENCORE_EQL_TOKEN}" }
    }
  }
}
```

Project `.mcp.json` servers are **pending approval until enabled**. Check `enabledMcpjsonServers` for the project in `~/.claude.json`; if `[]`, approve via `/mcp`. (Tools may still appear as session-pending even while the array is empty — that is not-persistently-approved, not disconnected.) Claude Code expands `${ENCORE_EQL_TOKEN}` and its HTTP client passes Cloudflare.

### Claude Desktop (`mcp-remote` wrapper)

Claude Desktop has **no native HTTP MCP transport**, so it bridges to stdio via `mcp-remote`. Two gotchas make a wrapper script necessary:

1. **`mcp-remote` does not expand `${VAR}`** in `--header` — a placeholder is sent literally and 401s.
2. **Desktop spawns commands with no shell**, so the OS can't expand it either, and a GUI-launched Desktop does not inherit `~/.bashrc`, so the token isn't in its environment.

The fix is a launch wrapper that resolves the token at runtime — the secret stays in `~/.bashrc` and never lands in a config file.

`~/.config/Claude/eql-remote.sh` (`chmod +x`):

```bash
#!/usr/bin/env bash
set -euo pipefail
# Resolve the refresh token without baking it into any config file.
if [ -z "${ENCORE_EQL_TOKEN:-}" ]; then
  # plain `source ~/.bashrc` early-returns on its non-interactive guard,
  # so eval only the export line.
  eval "$(grep -E '^[[:space:]]*export[[:space:]]+ENCORE_EQL_TOKEN=' "$HOME/.bashrc" | tail -1)"
fi
[ -n "${ENCORE_EQL_TOKEN:-}" ] || { echo "eql-remote: ENCORE_EQL_TOKEN not set" >&2; exit 1; }
exec /path/to/npx -y mcp-remote \
  "https://za.encore.io/gateway/api/mcp-eql/" \
  --header "Authorization: Bearer ${ENCORE_EQL_TOKEN}"
```

> The `npx` path is machine-specific (e.g. an nvm path like `~/.nvm/versions/node/<ver>/bin/npx`). Use an absolute path — a GUI-launched Desktop won't have nvm's `node` on `PATH`.

`~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "eql-hosted": { "command": "/home/<user>/.config/Claude/eql-remote.sh" }
  }
}
```

After editing the Desktop config **or rotating the token**, fully **quit and relaunch** Desktop (tray-quit, not just close the window) to reload. The wrapper picks up a rotated token from `~/.bashrc` automatically — no config edit needed.

## EQL syntax

Format: `<TableName> WHERE <col> = "val", <col2> LIKE "%x%" SELECT <col1>, <col2> ORDER BY <col> DESCENDING`

- **No** pipe operators (`|`), `FROM`, standalone `KEEP`/`LIMIT`, or `like~`.
- Always `list_tables` to confirm the exact table name, then `list_columns <TableName>` to confirm column names before querying.
- **BATCH-JOIN** chains datasets: `<table> SELECT <col>, <joinCol> BATCH-JOIN <Table2> AS <alias> ON <joinCol> = <alias>_<rightCol> SELECT <col2>, <rightCol>`. First-table columns need no alias prefix on the left of a join predicate; all subsequent joined columns use `alias_Col`. Join-predicate columns must appear in each dataset's `SELECT`.

Discovery queries: `list version`, `list clients`, `list tables`, `list tables label:<label>`, `list labels`, `list columns`, `list columns <TableName>`.

## Data surface (indicative)

~172 tables across these label families (query `list labels` / `list tables` for the live set): `activedirectory`, `azureactivedirectory`, `azureupdatemanager`, `cloudflare`, `crowdstrike`, `intune`, `ironscales`, `lateralmovement`, `microsoftoffice365`, `mimecast`, `sentinel`, `vulnerabilityprioritization`, `windowsdefenderatp`, plus cross-cutting `host`/`user`/`domain`/`ip`/`statistics`. `list_clients` returns ~78 client aliases spanning EU and ZA regions.

## Known server quirks

- **MCP is one version ahead** of the EQL server — some queries fail with "unsupported feature of Gateway". Expected, not a real failure.
- **Baseline-only illusion** — `list tables` sometimes surfaces only `Baseline-*` tables and misses product tables. Force the product set with `list tables label:<label>` per label.
- **`list labels` is flaky** — does not always return. Retry; distinguish from auth/network errors.
- If a gateway-bound call raises `GatewayUnavailableError`, tell the user and ask whether to retry against the local endpoint.

## See also

- `config/client_entities.json` — `platforms.encore.access` is a defined platform-scope flag (see `docs/configuration.md`), but EQL access is governed by the `ENCORE_EQL_TOKEN` (all clients), not per-client config; no client entry sets it today.
- Memory: `encore-gateway-integration` (operational notes, token rotation, wrapper rationale)
- `scripts/eql_direct.py` — the direct-API helper
