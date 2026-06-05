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

All paths read the same `ENCORE_EQL_TOKEN`. **Put it in the repo-root `.env`** (gitignored) as `ENCORE_EQL_TOKEN=<refresh-token>` — single source of truth, loaded via `load_dotenv` by `config/settings.py` (the MCP server) and by `scripts/eql_direct.py`.

> **`.env` syntax, not bashrc syntax.** Use a bare `KEY=value` line. Do **not** paste the `~/.bashrc` form `export ENCORE_EQL_TOKEN="…"` — the `export ` prefix and unbalanced/stray quotes make python-dotenv fail to parse the line (`could not parse statement starting at line N`), so the token silently doesn't load. Append it cleanly from your shell instead: `printf 'ENCORE_EQL_TOKEN=%s\n' "$ENCORE_EQL_TOKEN" >> .env`.
>
> **Why `.env`, not `~/.bashrc`:** the socai MCP server is spawned by Claude Desktop (and could be by boot scripts) **without inheriting your shell**, so `~/.bashrc` exports are invisible to it — only `.env` is read. This is the single most common cause of `eql_entity_context` failing with `required secret 'ENCORE_EQL_TOKEN' is not set`. The token must be the **refresh** token (it is exchanged at `/auth/refresh`); an access token will 401.

### Auth flow (direct API)

1. `POST https://za.encore.io/gateway/api/auth/refresh` with body `{"refreshToken": "<ENCORE_EQL_TOKEN>"}` → `{accessToken (~30-min TTL), refreshToken}`. The original refresh token stays valid for a long time.
2. Send `Authorization: Bearer <accessToken>` on every query.

For the **MCP path the exchange is server-side** — the gateway accepts the refresh token directly as the Bearer header and mints the access token internally. Confirmed: an MCP `initialize` against the endpoint with the refresh token as Bearer returns `200 text/event-stream`, serverInfo `EQL Gateway`.

**Access-token cache (case-scoped tools, `tools/eql.py`).** The minted access token is cached in-process under a single `"access"` key (one token covers all clients) and reused until 120 s before its assumed ~30-min expiry. The refresh is performed under the cache lock so concurrent cold-cache callers coalesce onto one `/auth/refresh` instead of each firing their own. Because the warehouse can rotate/revoke a token before that assumed expiry, a query that comes back **401 evicts the cached token and retries once** with a freshly-minted one; a second 401 surfaces as an `EqlError`. All EQL HTTP goes through the pooled `get_session()` for connection reuse.

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

Project `.mcp.json` servers are **pending approval until enabled**. Check `enabledMcpjsonServers` for the project in `~/.claude.json`; if `[]`, approve via `/mcp`. (Tools may still appear as session-pending even while the array is empty — that is not-persistently-approved, not disconnected.) Claude Code's HTTP client passes Cloudflare as-is.

> **`${ENCORE_EQL_TOKEN}` only expands if the variable is in Claude Code's environment — Claude Code does *not* read the project `.env`.** A token that lives only in `.env` expands to empty and the gateway returns 401. Put it in the gitignored `.claude/settings.local.json` `env` block (the channel Claude Code uses for `${VAR}` expansion), then restart / `/mcp` reconnect. This is the same mechanism used for the socai server — see `docs/mcp-server.md` → "Claude Code (TUI) Configuration".

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
- **BATCH-JOIN** chains two or more datasets into one result set — see [BATCH-JOIN (dataset joins)](#batch-join-dataset-joins) below for the full syntax, the column-reference rules, and worked examples.

Discovery queries: `list version`, `list clients`, `list tables`, `list tables label:<label>`, `list labels`, `list columns`, `list columns <TableName>`.

### BATCH-JOIN (dataset joins)

`BATCH-JOIN` chains two or more datasets into a single result set, so one query can enrich event rows with context from another table — a device's vulnerabilities and logged-on users, a sign-in's identity attributes — without a second round-trip and Python-side stitching. (Validated against the live gateway, 2026-06-05; experiment matrix in the `encore-eql-batch-join` memory.)

**Shape** — each table is a *dataset* with its own optional `WHERE` and a mandatory `SELECT`:

```
<TableA> [WHERE …] SELECT <colsA…, joinKeyA>
BATCH-JOIN <TableB> AS <b> ON <joinKeyA> = <b>_<joinKeyB> [WHERE <bareColB …>] SELECT <colsB…, joinKeyB>
[BATCH-JOIN <TableC> AS <c> ON <keyFromA-or-B> = <c>_<joinKeyC> [WHERE …] SELECT <colsC…, joinKeyC>]
[ORDER BY <bareCol> DESCENDING]
```

**Column-reference rules** — the single biggest source of errors. *Where* a joined column sits decides whether it takes the `alias_` prefix:

| Position | First table | Joined table |
|---|---|---|
| `SELECT` list | bare (`Id`) | **bare** (`Severity`) |
| Join predicate, left of `=` | bare (`Id`) | — |
| Join predicate, right of `=` | — | **`alias_Col`** (`v_MachineId`) |
| `WHERE` on that dataset | bare | **bare** (`Severity`) |
| `ORDER BY` | bare | **bare** (`CvssV3`) |
| **Output JSON key** | bare (`Id`) | **`alias_Col`** (`v_Severity`) |

So `alias_Col` appears in exactly two places — the **right side of a join predicate** and the **output keys**. Everywhere else the joined column is referenced **bare**.

**Hard rules (each is enforced; the error message names the fix):**

- **Every join-predicate column must appear in its own dataset's `SELECT`** — both the left key (in TableA's `SELECT`) and the right key (in the joined table's `SELECT`). Omitting it → `The following column names (MachineId) were not found in the incoming data set (v) … include the predicate column(s) in the select statement.`
- A joined-table `WHERE` uses the **bare** column name. Using `alias_Col` there → `v_Severity is not a valid column name, permitted option for the … table are: …`.
- **It is a LEFT join.** An unmatched left row is *kept*, with the joined columns returned as empty strings (`""`) — not dropped. For inner-join behaviour, add a `WHERE` on the joined dataset (any always-present column) or discard rows whose `alias_*` keys are blank.
- **Join-key equality is case-insensitive** (`tlangelani.mathebula@…` matched `Tlangelani.Mathebula@…`). No need to normalise case before joining.
- **No `LIMIT` exists** — bound *every* dataset with `WHERE`. A multi-hop star (below) multiplies rows (users × vulnerabilities), so filter the fan-out side hard.
- **Different column names on each side are expected** (`ON Id = v_MachineId`); **identical names also work** — the alias disambiguates them in the output (`UserPrincipalName` vs `u_UserPrincipalName`).
- A later join may key off the **first table's** column, not only the immediately-preceding dataset — so you can *star* several tables off one anchor key as well as *chain* A→B→C.
- The **boolean-filter quirk still applies inside joins**: filter on the `*AsText` mirror column, never the raw boolean (`WHERE IsElevatedAsText = "true"`, not `IsElevated`).

**Worked example 1 — device → logged-on users → critical vulns (3-table star on `MachineId`):**

```
WindowsDefenderAtp-Machines WHERE Id = "<machineId>" SELECT Id, ComputerDnsName
BATCH-JOIN WindowsDefenderAtp-MachineUsers AS u ON Id = u_MachineId SELECT AccountName, AccountDomain, MachineId
BATCH-JOIN WindowsDefenderAtp-MachineVulnerabilities AS v ON Id = v_MachineId WHERE Severity = "Critical" SELECT Name, Severity, CvssV3, MachineId
```

→ each logged-on user paired with each Critical CVE on their device. Output keys: `Id`/`ComputerDnsName` (anchor, bare), `u_*`, `v_*`. Both joins star off the anchor's `Id`.

**Worked example 2 — sign-in events → identity context (enrich on UPN):**

```
AzureActiveDirectory-SignInAudits WHERE UserPrincipalName = "<upn>", ConditionalAccessStatus = "failure"
  SELECT UserPrincipalName, IpAddress, CountryName, ClientAppUsed
BATCH-JOIN AzureActiveDirectory-Users AS u ON UserPrincipalName = u_UserPrincipalName
  SELECT Department, IsMfaRegisteredAsText, UserPrincipalName
```

→ each failed-CA sign-in annotated with the user's department and MFA-registration state — the SOC "who is this and were they protected" pivot in one query.

**Where this helps socai.** The case-scoped `eql_*` tools (`tools/eql.py`) currently fire separate per-entity queries and stitch the results in Python. Joins can collapse the common *event + identity/device context* pairs into a single server-side call: sign-in / risky-activity rows + `AzureActiveDirectory-Users` attributes, or Defender machine rows + `MachineVulnerabilities` / `MachineUsers`. Not yet wired into `QUERY_TEMPLATES` / `POSTURE_TEMPLATES` — candidate optimisation, mind the LEFT-join semantics (an enriched query must not silently swallow unmatched entities).

## Data surface (indicative)

~172 tables across these label families (query `list labels` / `list tables` for the live set): `activedirectory`, `azureactivedirectory`, `azureupdatemanager`, `cloudflare`, `crowdstrike`, `intune`, `ironscales`, `lateralmovement`, `microsoftoffice365`, `mimecast`, `sentinel`, `vulnerabilityprioritization`, `windowsdefenderatp`, plus cross-cutting `host`/`user`/`domain`/`ip`/`statistics`. `list_clients` returns ~78 client aliases spanning EU and ZA regions.

## Known server quirks

- **MCP is one version ahead** of the EQL server — some queries fail with "unsupported feature of Gateway". Expected, not a real failure.
- **Baseline-only illusion** — `list tables` sometimes surfaces only `Baseline-*` tables and misses product tables. Force the product set with `list tables label:<label>` per label.
- **`list labels` is flaky** — does not always return. Retry; distinguish from auth/network errors.
- If a gateway-bound call raises `GatewayUnavailableError`, tell the user and ask whether to retry against the local endpoint.

## Path C — socai-native, case-scoped tools (`tools/eql.py`)

For inline HITL use, three socai MCP tools wrap EQL so the analyst never hand-resolves clients, hand-writes EQL, or hand-logs evidence:

- **`eql_identity_assessment(case_id, users=, hosts=, cap=5)`** — the **lean scoping step that runs first**, before the heavier `eql_entity_context` pull. Given several users (and/or hosts), it classifies each user **internal vs external** from authoritative directory data — `UserType=Member` → internal (with on-prem-sync sub-state from `OnPremisesSamAccountName`), `Guest` / `#EXT#` UPN → external, no record → not-in-directory — and pulls **lean managed-device context** (`Intune-ManagedDevices`: name/OS/compliance/encryption/last-seen) so the exact device context is in session. A **host need not map to a single user** — a server or shared device is classified as an **asset** instead: `managed_asset` (known + in a control plane), `known_unmanaged`, or `not_in_directory`, with `managed_in` listing which platforms manage it. For any *known* host it also pulls **local admins** (`LateralMovement-LocalAdmins`) — the "who operates this device" answer for a multi-user server — skipping that query for an unknown (`not_in_directory`) host. **Request discipline:** a device query fires *only* for users that resolve to a real non-guest record (guests / not-in-directory cost a single query each), and a **soft cap** (`cap`, default 5 per list) means entries beyond the cap are returned under `not_assessed` rather than queried — raise `cap` to assess more; nothing is silently dropped. Optional zero-request overlay: a per-client `identity.internal_domains` list (in `client_entities.json`) flags a Member account sitting on an unexpected UPN domain. Use this to decide *which* entities are worth the deep `eql_entity_context` look. *Reactive — keyed on the entities named in the incident.*
- **`eql_entity_context(case_id, user=, host=, ip=)`** — runs a curated query set (identity, sign-ins, risky activities, device posture across CrowdStrike/Defender/Intune, detections, vuln exposure, Cloudflare) for the named entity, stamps freshness + coverage, writes the raw payload to `cases/<id>/artefacts/eql_context/` and a provenance note into the evidence chain. Call it during the baseline/contextualisation step for the entities `eql_identity_assessment` flagged as worth it. *Reactive — keyed on an entity named in the incident.*
- **`eql_posture_context(case_id)`** — runs a curated **client-wide** (no-WHERE) query set for the preventative-control / best-practice configuration baseline: Secure Score, MFA/identity coverage, privileged-role assignments, app-credential hygiene, device/encryption compliance, Defender configuration recommendations, vulnerability exposure, security-awareness training. Writes the full payload to `artefacts/eql_context/posture.json` + an evidence note. Snapshot tables are ordered newest-first (top row = current state). *This is the primary input to the security architecture review (`write_security_arch_review`).* See `POSTURE_TEMPLATES` in `tools/eql.py`.
- **`eql_query(case_id, eql)`** — analyst escape hatch for a raw EQL string, same scope gate, same persistence.
- **`eql_vuln_hunt(client)`** — a **caseless** EQL tool: proactive vulnerability hunting. Resolves the client by name (exact, via the same `_resolve_encore_id` gate — never fuzzy) and runs `VULN_HUNT_TEMPLATES` (exposed hosts ranked by exploitability; actively-exploited CVEs; new 48h KEVs; EDR compensating-control tasks; exposure summary). Persists to `registry/vuln_hunts/VH_<ts>.json` (mirrors `quick_enrich`) and returns a `hunt_id` + triage summary. **Promote** with `import_vuln_hunt(hunt_id, case_id)` or `create_case(vuln_hunt_id=…)`. See `VULN_HUNT_TEMPLATES` in `tools/eql.py`.

### Caseless lookups (entity + identity)

The case-scoped tools above all pin to a case's client. For **ad-hoc, pre-investigation** questions ("what is this user / device / IP?") there are caseless twins that resolve the client **by name** (`resolve_client_by_name` — the same exact-match `_resolve_encore_id` scope gate `eql_vuln_hunt` uses; cross-client access is structurally impossible) and persist to `registry/eql_lookups/` instead of a case:

- **`eql_entity_lookup(client, user=, host=, ip=)`** — caseless `eql_entity_context`. Runs the identical curated `QUERY_TEMPLATES` set; persists the full payload to `registry/eql_lookups/EQL_<ts>.json` and returns a `lookup_id`. No evidence chain is written (there is no case yet).
- **`eql_identity_scan(client, users=, hosts=, cap=5)`** — caseless `eql_identity_assessment`. Same internal/external classification + device/host asset engine; persists to `registry/eql_lookups/EQLID_<ts>.json`.

**Promote** either with `import_eql_lookup(lookup_id, case_id)` or `create_case(eql_lookup_id=…)` — the import copies the full payload into `cases/<id>/artefacts/eql_context/` and appends the matching evidence note (`entity context` / `identity assessment`). **Cross-client guard:** `import_eql_lookup` **refuses** if the lookup's Encore `internal_client_id` ≠ the case's, so a lookup run for client A can never be imported into client B's case. The same guard is backfilled onto `import_vuln_hunt`. (The engine is shared with the case-scoped tools via `_run_entity_queries` / `_assess_identities`, so coverage, freshness, and capping semantics are identical.)

### Vulnerability hunting (two modes)

Encore pre-computes the exploit/KEV prioritisation (EPSS, in-the-wild, ransomware flags, a priority index), so socai doesn't have to. The capability has two chained modes:

1. **Exposure hunt** — `eql_vuln_hunt(client)` surfaces *what is exploitable and where* (caseless, recurring-friendly: `NewKevsIn48Hrs` is the "what just became urgent" feed).
2. **Active-exploitation hunt** — the **`vulnerability-hunting`** playbook (`config/playbooks/vulnerability-hunting/`, KQL + CQL) pivots the top CVEs/hosts into the live log layer (`run_kql` / `run_defender_kql` / `run_falcon_cql`) to check whether the vulnerability is actually being exploited. The bridge from vuln management to threat hunting.

The deliverable is **`prepare_vuln_hunt_report`** → `write_vuln_hunt_report` prompt → `save_report(report_type="vuln_hunt_report")` — a prioritised remediation worklist ending in a machine-readable JSON handoff (`control_type`: `patch` | `edr_soar_mitigation`) for a downstream engineering pipeline. Non-closing (a hunt is proactive). Confirmed exploitation escalates to a live incident, not just a ticket.

**EQL filter quirk (load-bearing):** boolean columns cannot be filtered (`WHERE HasActiveExploit = "true"` → `Boolean is not compatible with true (Text)`), and there is no `LIMIT`. So large catalogues are bounded via a **Text** `WHERE` (the 41k-row `VulnerabilityPrioritization-Vulnerabilities` table → `Classification = "Actively Exploited"`, ~117 rows) and exploit flags are filtered **client-side** on ranked results. The CVE table's `PrioritizationIndex` saturates — rank CVEs by `Epss`, not the index (the host table's index ranks fine).

Posture additions (client-wide, for the security architecture review): `AllServicePrincipals` (enterprise-app / OAuth privilege inventory) and `DirectoryAudits` (recent privileged changes) joined the existing `POSTURE_TEMPLATES`; `LateralMovement-LocalAdmins` enriches host `entity_context` (blast radius). `DirectoryAudits.InitiatedBy` is a display name and lateral-movement account names are sam-style — neither keys off a UPN, hence client-wide rather than entity-scoped.

**Token-scope gate.** Both tools resolve `case_id` → the case's client → `platforms.encore.internal_client_id`, and pin every query to that UUID. The caller cannot supply a client/clientId, and a client without an `internal_client_id` mapping (or read `access`) is refused **before any HTTP call**. So although `ENCORE_EQL_TOKEN` spans all clients, the socai-native path is structurally single-client per case. (The `eql-hosted` MCP server, Path B, is the unrestricted multi-client surface — use it for ad-hoc/cross-client research.)

**Freshness/coverage.** Posture snapshots refresh ~daily; event tables within ~1–2h; `SignInAudits` is a rolling ~7-day window. An empty result is reported as `no_data_for_client` — the product is not ingested for that client; it is **never** evidence of "clean".

## See also

- `config/client_entities.json` — set `platforms.encore.internal_client_id` (gateway UUID from `list_clients`) per client to enable the socai-native tools above; this is the token-scope gate (see `docs/configuration.md`). The standalone `eql-hosted` MCP / `ENCORE_EQL_TOKEN` path is unaffected by this field.
- Memory: `encore-gateway-integration` (operational notes, token rotation, wrapper rationale)
- `scripts/eql_direct.py` — the direct-API helper
