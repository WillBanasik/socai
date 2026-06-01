# Configuration

All settings in `config/settings.py`; secrets in `.env` (git-ignored, auto-loaded).

## General Settings

| Env var | Default | Effect |
|---------|---------|--------|
| `SOCAI_BROWSER` | `playwright` | `playwright` or `requests` |
| `SOCAI_CAPTURE_TIMEOUT` | `20` | Web capture timeout (seconds) |
| `SOCAI_SPA_DWELL` | `5000` | Extra wait (ms) after `networkidle` if page text is empty |
| `SOCAI_STRINGS_MIN` | `6` | Min string length for static analysis |
| `SOCAI_ENRICH_CACHE_TTL` | `24` | Enrichment cache TTL (hours); `0` = disabled |
| `SOCAI_ENRICH_WORKERS` | `25` | Thread pool size for parallel enrichment (all tiers) |
| `MAXMIND_LICENSE_KEY` | — | MaxMind license key for local GeoIP (free at maxmind.com/en/geolite2/signup) |
| `SOCAI_CONF_AUTO_CLOSE` | `0.20` | Confidence threshold; benign cases below this are auto-closed |
| `SOCAI_TRIAGE_ESCALATION_THRESHOLD` | `1` | Known-malicious IOC count to trigger severity escalation |
| `SOCAI_CAMPAIGN_MIN_IOCS` | `2` | Min shared IOCs to form a campaign |
| `SOCAI_SANDBOX_WORKERS` | `3` | Thread pool size for sandbox provider calls |
| `SOCAI_SANDBOX_POLL_INTERVAL` | `30` | Seconds between detonation status polls |
| `SOCAI_SANDBOX_TIMEOUT` | `300` | Seconds before detonation timeout |
| `SOCAI_BUSINESS_HOURS_START` | `8` | Start of business hours (UTC) for anomaly detection |
| `SOCAI_BUSINESS_HOURS_END` | `18` | End of business hours (UTC) for anomaly detection |
| `SOCAI_BRUTE_FORCE_THRESHOLD` | `5` | Failed logins to trigger brute force alert |
| `SOCAI_BRUTE_FORCE_WINDOW` | `300` | Seconds window for brute force detection |
| `SOCAI_TRAVEL_WINDOW` | `3600` | Seconds window for impossible travel detection |
| `SOCAI_LATERAL_WINDOW` | `3600` | Seconds window for lateral movement detection |
| `SOCAI_UA` | Chrome 120 UA string | User-Agent for web capture requests |
| `SOCAI_BROWSER_POOL_MAX_USES` | `50` | Playwright browser recycle threshold (prevents memory leaks) |
| `SOCAI_BROWSER_POOL_IDLE_SECS` | `300` | Auto-close pooled Playwright browser after N seconds of inactivity |

## LLM Reasoning

All LLM reasoning (report generation, analytical judgement, disposition analysis, quality review) is handled by the local Claude Desktop agent via MCP prompts and save tools. No Anthropic API key is needed — the MCP server provides data-gathering tools and persistence, while the analyst's local Claude session does the thinking.

## API Keys

| Key | Provider | IOC types |
|-----|----------|-----------|
| `SOCAI_VT_KEY` | VirusTotal | IPv4, domain, URL, hash |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | IPv4 |
| `SHODAN_API_KEY` | Shodan | IPv4 (paid plan required) |
| `GREYNOISE_API_KEY` | GreyNoise | IPv4 (community = 25/week) |
| `INTEZER_API_KEY` | Intezer | MD5, SHA1, SHA256 |
| `URLSCAN_API_KEY` | URLScan.io | domain, URL |
| `PROXYCHECK_API_KEY` | proxycheck.io | IPv4 |
| `OPENCTI_API_KEY` | OpenCTI | IPv4, domain, URL, hash, email, CVE |
| `OPENCTI_URL` | OpenCTI instance URL | Required if using OpenCTI enrichment |
| `OTX_API_KEY` | AlienVault OTX | IPv4, domain, URL, MD5, SHA1, SHA256 |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis | SHA256 only (overview endpoint) |
| `WHOISXML_API_KEY` | WHOISXML API | domain (age, registrant, newly-registered flag) |
| `CENSYS_TOKEN` | Censys Platform API v3 | IPv4, domain — Bearer PAT |
| `ABUSECH_API_KEY` | URLhaus + ThreatFox + MalwareBazaar | IPv4, domain, URL, MD5, SHA256 |
| `EMAILREP_API_KEY` | EmailRep.io | email (optional; keyless tier rate-limited) |
| — | PhishTank | domain, URL — known-phishing database (keyless, no signup) |
| — | crt.sh | domain — certificate transparency log search (keyless, no signup) |
| `SECURITYTRAILS_API_KEY` | SecurityTrails | domain — subdomains, DNS history (paid; not currently active) |
| `ANYRUN_API_KEY` | Any.Run | SHA256 — sandbox hash lookup + detonation |
| `JOESANDBOX_API_KEY` | Joe Sandbox | SHA256 — sandbox hash lookup + detonation |
| `SOCAI_BRAVE_SEARCH_KEY` | Brave Search | Web search fallback (optional; DuckDuckGo used if unset) |
| `XPOSEDORNOT_API_KEY` | XposedOrNot | domain breaches (optional; email lookups are keyless) |
| `INTELX_API_KEY` | Intelligence X | dark web, pastes, leaks, documents — free tier at intelx.io/account?tab=developer |

### Provider Notes

- **OpenCTI:** StixCyberObservable lookups use `value` filter for IP/domain/URL/email, and `search` param for file hashes. CVE lookups use the `vulnerabilities` query and return `epss_score` and `cisa_kev`. A transport-level circuit breaker opens after 3 consecutive failures (5xx, timeouts, connection errors) and stays open for 300s — subsequent lookups return `status: "circuit_open"` instead of paying the per-IOC timeout cost during platform outages. Any successful response resets the breaker.
- **Censys:** Uses Platform API v3 (`api.platform.censys.io/v3`), **not** old `search.censys.io/api/v2`. Auth is `Authorization: Bearer <token>`. Data nested under `result.resource`.
- **Hybrid Analysis:** `/api/v2/search/hash` POST is broken upstream — use `/api/v2/overview/{sha256}` (GET). MD5/SHA1 not supported.
- **Abuse.ch:** Account registration non-functional as of 2026-03; key cannot be obtained.

### Tiered Enrichment

All IOC types (IPv4, domain, URL, hash) use a tiered enrichment model to reduce API calls. The `depth` parameter on `enrich_iocs` controls escalation:

- **`"auto"`** (default) — Tier 1 first, escalate to Tier 2 only on signal (malicious/suspicious/unknown/newly-registered)
- **`"fast"`** — Tier 1 only, never escalates. Use for obvious FPs, bulk triage, low severity.
- **`"full"`** — All tiers for every IOC. Use for high-severity incidents, targeted attacks, novel IOCs.

Before enrichment, `extract_and_enrich()` automatically runs triage (skips IOCs with 3+ cached providers) and client baseline filtering (skips IOCs routine for the client). Both are best-effort.

**IPv4 tiers:**
- **Tier 0 (ASN pre-screen):** Team Cymru DNS (free, no key) identifies IPs owned by Microsoft, AWS, Google, Cloudflare, Akamai CDN, Fastly, Apple, Meta. Tagged `infra_clean`, skip all enrichment.
- **Tier 1 (Fast):** AbuseIPDB, URLhaus, ThreatFox, OpenCTI.
- **Tier 2 (Deep):** VT, Shodan, GreyNoise, ProxyCheck, Censys, OTX.

**Domain tiers:** Tier 1: URLhaus, ThreatFox, OpenCTI, WhoisXML, PhishTank. Tier 2: VT, URLScan, Censys, OTX, crt.sh.

**URL tiers:** Tier 1: URLhaus, ThreatFox, OpenCTI, PhishTank. Tier 2: VT, URLScan, OTX.

**Hash tiers:** Tier 1: MalwareBazaar, ThreatFox, OpenCTI. Tier 2: VT, Intezer, OTX (+ Hybrid Analysis for SHA256).

Hosting providers (Linode/Akamai hosting, DigitalOcean, OCI) are deliberately **not** pre-screened since attackers use them. Only CDN-specific ASNs are filtered. Requires `dnspython` for ASN resolution (falls back to ipinfo.io free tier if unavailable).

## Authentication & Roles

| Env var | Default | Effect |
|---------|---------|--------|
| `SOCAI_JWT_SECRET` | (insecure default) | JWT signing secret — **must set in production** |
| `SOCAI_JWT_TTL_HOURS` | `8` | Token expiry in hours (`24` = daily, `720` = 30 days) |

Users are managed locally in `config/users.json` (bcrypt-hashed passwords). Roles are defined in `config/roles.json` — they control the assistant's tone, explanation depth, and response style, not which tools are accessible.

| Role | Tone | Severity Ceiling | Response Authority |
|------|------|------------------|-------------------|
| `junior_mdr` | Educational | Medium | Observe & escalate |
| `mdr_analyst` | Professional | Critical | Containment |
| `senior_analyst` | Peer | Critical | Full IR |

Token generation: `python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('analyst@soc.com', 'mdr_analyst'))"`

See `docs/mcp-server.md` for deployment architecture, Claude Desktop configuration, and Entra ID migration path.

## MCP Server

See `docs/mcp-server.md` for env vars, RBAC, tools, resources, prompts, and deployment.

## Client Playbooks

Client-specific response playbooks are stored in `config/clients/<client_name>/playbook.json` (directory layout) or `config/clients/<client_name>.json` (legacy flat layout). These drive the `response_actions` tool, which produces a deterministic response plan based on case evidence.

| Setting | Value |
|---------|-------|
| `CLIENT_PLAYBOOKS_DIR` | `config/clients/` |
| `SOCAI_DEFAULT_CLIENT` | Env var; sets default client when `--client` is not passed |

**CLI flags:** `--client <name>` on applicable subcommands. Falls back to `SOCAI_DEFAULT_CLIENT`.

**Schema:** `client_name`, `response[]`, `crown_jewels` (supports wildcard patterns via fnmatch), `contacts[]`, `escalation_matrix[]` (with `activity_blocked`, `sd_ticket`, `phone_call`, `response_action` fields), `containment_capabilities[]`, `remediation_actions[]`.

**Multi-environment playbooks:** For clients with multiple platforms/environments (e.g. Sentinel + MDE, CrowdStrike workstations, OT), add an `environments` map describing each environment and its platforms. Use `escalation_matrix_ot` for environment-specific escalation overrides (e.g. OT environments where no containment is permitted).

## Client Configuration

Config: `config/client_entities.json` (git-ignored) — unified `clients` list. Schema: `config/client_entities.example.json`.

**Client entity fields:**

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Canonical client name (case-insensitive matching, underscores for spaces) |
| `platforms` | No | Nested object mapping platform → config (see below) |
| `aliases` | No | List of alternative names for fuzzy matching (e.g. `["hbm", "heidelberg cement"]`). `lookup_client` checks these when the exact name doesn't match. |
| `notes` | No | Free-text description for fuzzy matching and context (industry, key domains, subsidiaries) |
| `workspace_id` | No | Legacy; migrated to `platforms.sentinel.workspace_id` |

**Platform scope** (`platforms` object):

```json
{
  "platforms": {
    "sentinel":     { "workspace_id": "<GUID>" },
    "defender_xdr": { "api_enabled": true, "tenant_id": "<GUID>" },
    "crowdstrike":  { "api_enabled": true, "falcon_region": "eu-1", "ngsiem_repo": "<repo>" },
    "encore":       { "internal_client_id": "<gateway-uuid>", "access": "read" }
  }
}
```

The `platforms` object determines which security platforms are available for investigation of that client's incidents. Used by `lookup_client` (MCP tool), `socai://clients` (resource), workspace resolution in `run_kql`, the `hitl_investigation` prompt (Phase 0 client gate), and per-platform query routers (`tools/defender_hunting.py`, `tools/crowdstrike.py`, `tools/eql.py`).

**`platforms.encore`** — `internal_client_id` is the Encore gateway client UUID (from `list_clients` / `eql_direct.py clients`); it is the **token-scope gate** for the socai-native EQL tools (`eql_entity_context`, `eql_query`). Those tools resolve a case → its client → this UUID and pin every query to it; a client with no `internal_client_id` (or `access` not in {`read`, `true`}) is refused before any HTTP call, so the all-client `ENCORE_EQL_TOKEN` can never reach a client the case isn't mapped to. The standalone `eql-hosted` MCP server is unaffected (it takes a `clientId` directly). Gateway is the source of truth for these UUIDs — human-verify the mapping.

**Per-platform credentials** (env vars, see `tools/secrets.py`):

| Platform | Env vars | Notes |
|---|---|---|
| Sentinel | `az` CLI session (`az login`) | Uses user-delegated token, no app reg today |
| Defender XDR | `SOCAI_DEFENDER_APP_CLIENT_ID`, `SOCAI_DEFENDER_APP_CLIENT_SECRET` | One multi-tenant Performanta app reg; admin-consented per client tenant. See `docs/defender-hunting.md`. |
| CrowdStrike | `SOCAI_CROWDSTRIKE_<CLIENT>_CLIENT_ID`, `SOCAI_CROWDSTRIKE_<CLIENT>_CLIENT_SECRET` | Per-client API client created in each client's Falcon console; `<CLIENT>` is the client name uppercased with non-alphanumerics → underscore (e.g. `HEIDELBERG_MATERIALS`, `SE_FIRST`). See `docs/crowdstrike.md`. |
| Encore EQL | `ENCORE_EQL_TOKEN` | Single personal **refresh token** spanning all Encore clients (not per-client). Used by `scripts/eql_direct.py` and the `eql-hosted` MCP server. Kept in `~/.bashrc`, never committed. See `docs/encore-eql.md`. |

## Sentinel Workspace IDs

Workspace IDs for `az monitor log-analytics query -w <ID>` are in `config/client_entities.json`. Table availability per workspace: `config/workspace_tables.json` (git-ignored, keyed by workspace name). Full table schemas (column names and types): `config/sentinel_tables.json` (git-ignored). Discovery script: `scripts/discover_sentinel_schemas.py`. Workspace resolution in `scripts/run_kql.py` tries exact match, then uppercase, then lowercase.

For Defender XDR Advanced Hunting (separate from Sentinel ingestion), per-client table availability + schemas live in `config/defender_tables.json` — populated by `scripts/discover_defender_schemas.py` (probes the fixed Microsoft-defined Advanced Hunting table set per onboarded client). Tables that aren't licenced for a tenant (e.g. Identity* needs MDI, Device* needs MDE) are recorded as unavailable.

### Schema validation

The schema registry (`config/sentinel_tables.json`) is used across the query stack for pre-flight table validation and prompt enrichment:

- **Composite queries** (`tools/sentinel_queries.py`) — `render_query()` validates declared tables and returns `schema_warnings` in the result dict.
- **Stage-based playbooks** (`tools/kql_playbooks.py`) — `validate_playbook_tables()` checks a playbook's declared tables against the registry and optionally against a specific workspace.
- **MCP tools** (`run_kql`, `load_kql_playbook`, `run_kql_batch`) — pre-flight validation before Azure execution; warnings returned alongside results.
- **MCP prompt** (`kql_investigation`) — injects column schemas for the playbook's tables so Claude Desktop sees exact column names and types.
- **CLI** (`scripts/run_kql.py`) — optional pre-flight stderr warnings.

Validation is always non-blocking — warnings only, never errors. If the registry file is missing, validation is silently skipped.

### Regenerating client Sentinel references

```bash
# Regenerate config/clients/{client}/sentinel.md with column schemas from the registry
python3 scripts/generate_sentinel_reference.py performanta

# All clients
python3 scripts/generate_sentinel_reference.py --all

# Preview without writing
python3 scripts/generate_sentinel_reference.py performanta --dry-run
```

## NGSIEM / LogScale Reference

`config/ngsiem/` contains the CrowdStrike LogScale (NGSIEM) query reference system, exposed via four MCP resources:

| File | MCP Resource | Contents |
|------|-------------|----------|
| `config/logscale_syntax.md` | `socai://logscale-syntax` | General CQL syntax: operators, precedence, conditionals, joins, regex, pitfalls |
| `config/ngsiem/ngsiem_rules.md` | `socai://ngsiem-rules` | Detection rule authoring: pipe-per-line, `#Vendor`+`#event.module` tags, ECS fields, anti-patterns, worked examples |
| `config/ngsiem/ngsiem_columns.yaml` | `socai://ngsiem-columns` | Field schema per connector (24 connectors): ECS + vendor fields |
| `config/ngsiem/cql_grammar.json` | `socai://cql-grammar` | Complete function grammar: 194 functions across 12 categories |

These files are loaded on demand by the `load_ngsiem_reference` MCP tool, which Claude Desktop calls before writing any CrowdStrike/LogScale/NGSIEM query. The files are also available as MCP resources for direct reading. Referenced by `generate_queries`, HITL investigation prompt, and FP tuning prompts.

**Adding a new connector:** Follow the template in `ngsiem_columns.yaml` — use the discovery queries in the file header to find connector IDs and field names.

## Confluence (Read-Only — Published ET/EV Articles)

Read-only integration with Confluence Cloud, scoped to the **published ET/EV threat-articles space only**. Used for browsing/searching prior articles and for dedup checking before publishing a new article. Confluence is **not** a SOC knowledge base — process/policy/runbook content lives in `socai://` resources and client playbooks, not here.

| Env var | Purpose |
|---------|---------|
| `CONFLUENCE_URL` | Instance URL (e.g. `https://yourinstance.atlassian.net`) |
| `CONFLUENCE_CLOUD_ID` | Cloud ID (from `{url}/_edge/tenant_info`) |
| `CONFLUENCE_EMAIL` | Account email for basic auth |
| `CONFLUENCE_API_TOKEN` | Fine-grained (scoped) API token — read-only, Confluence only |
| `CONFLUENCE_SPACE_KEY` | Space key to read from (e.g. `MDR1`) |

**Token setup:** Create a fine-grained token at [id.atlassian.com](https://id.atlassian.com/manage-profile/security/api-tokens) → "Create API token with scopes" → product: Confluence on your instance.

Required scopes (all read-only):

| Scope | Grants |
|-------|--------|
| `read:page:confluence` | Pages, children, versions, properties, blogposts |
| `read:space:confluence` | Spaces, space properties |
| `read:label:confluence` | Page and global labels |
| `search:confluence` | CQL search (`title ~`, `text ~`) via v1 search endpoint |
| `read:comment:confluence` | Footer and inline comments on pages |
| `read:attachment:confluence` | Page attachments |
| `read:content.metadata:confluence` | Page ancestors / hierarchy navigation |

Scoped tokens use the `api.atlassian.com/ex/confluence/{cloudId}` base URL. v2 endpoints handle page/space reads; the v1 `/rest/api/search` endpoint handles CQL queries.

**Usage:** `tools/confluence_read.py` provides `list_pages()`, `get_page()`, `search_pages()`, `get_page_by_title()`. The `search_confluence` MCP tool exposes three modes: browse (recent pages), search (CQL title match), and read (full page by ID). Used by `tools/threat_articles.py` for dedup against published articles in the configured space.

## Cyberint (Read-Only CTI Alerts)

Read-only integration with the Cyberint threat intelligence platform for browsing and searching CTI alerts.

| Env var | Purpose |
|---------|---------|
| `CYBERINT_API_KEY` | `access_token` cookie value from an authenticated Cyberint session |
| `CYBERINT_API_URL` | API base URL (set in `.env`) |

**Usage:** `tools/cyberint_read.py` provides `list_alerts()`, `get_alert()`, `get_alert_metadata()`, `get_alert_attachment()`, `get_alert_indicator()`, `get_alert_analysis_report()`, `get_risk_scores()`. MCP tools: `query_cyberint_alerts`, `cyberint_alert_artefact`, `cyberint_metadata`. CLI: `socai.py cyberint`, `socai.py cyberint-metadata`, `socai.py cyberint-risk`.

## Threat Article Sources

`config/article_sources.json` — configurable list of RSS feeds for threat article discovery. Default: 10 feeds (BleepingComputer, The Hacker News, Krebs, CISA, Dark Reading, The Record, Mandiant, Unit 42, Microsoft Security, SecurityWeek). Add new sources with `"type": "rss"` and `"categories": ["ET", "EV"]`.

## Browser Session (Docker)

Disposable browser sessions require Docker installed and accessible.

| Requirement | Detail |
|-------------|--------|
| Docker | Must be installed; current user in `docker` group or sudo |
| Port | 7900 (noVNC) — must be free |
| Image | `socai-browser:latest` — build with `docker build -t socai-browser:latest docker/browser/` |
| Network mode | Bridge with `-p 7900:7900` (default) or `--network=container:gluetun` (VPN) |

tcpdump on the host is **not required** — pcap parsing runs inside the container via `docker exec`.

| Variable | Default | Description |
|---|---|---|
| `SOCAI_BROWSER_IMAGE` | `socai-browser:latest` | Docker image for browser sessions |
| `SOCAI_BROWSER_IDLE_TIMEOUT` | `300` | Seconds of network inactivity before auto-stop |
| `SOCAI_BROWSER_MAX_SESSION` | `3600` | Hard session duration ceiling (seconds) |
| `SOCAI_BROWSER_DISCONNECT_GRACE` | `15` | Seconds after last noVNC viewer disconnects before auto-stop (0 = disabled) |
| `SOCAI_BROWSER_VPN` | `0` | Set `1` to route through gluetun VPN container |
| `SOCAI_VPN_CONTAINER` | `gluetun` | Container name for VPN network namespace |

noVNC access: `http://127.0.0.1:7900` (no password). When using VPN mode, port 7900 must be published on the gluetun container instead.

Session state files are stored in `browser_sessions/<session_id>.json`. Caseless session artefacts are stored in `browser_sessions/<session_id>/artefacts/` and can be imported into a case via `import_browser_session`.

## Sandbox Detonation (Docker)

See `docs/sandbox.md` for env vars, Docker setup, network modes, and safety details.

## OPSEC Proxy (Mullvad VPN)

Routes attacker-facing traffic through a VPN to protect the analyst's source IP. Uses [gluetun](https://github.com/qdm12/gluetun) as a WireGuard sidecar with Mullvad.

### Quick start

```bash
# 1. Configure Mullvad credentials
cp deploy/.env.vpn.example deploy/.env.vpn
# Edit deploy/.env.vpn with your WireGuard private key + address

# 2. Start gluetun
docker compose -f deploy/docker-compose.vpn.yml up -d

# 3. Verify
curl -x http://127.0.0.1:8888 https://am.i.mullvad.net/connected

# 4. Add to .env
echo 'SOCAI_OPSEC_PROXY=http://127.0.0.1:8888' >> .env
```

### What goes through the VPN

| Traffic | Route | Config |
|---------|-------|--------|
| `capture_urls` (Playwright + requests fallback) | VPN proxy | `SOCAI_OPSEC_PROXY` |
| `web_search` (Brave/DDG) | VPN proxy | `SOCAI_OPSEC_PROXY` |
| Sandbox detonation (`--network vpn`) | VPN container network | `SOCAI_VPN_CONTAINER` |
| Browser sessions (`SOCAI_BROWSER_VPN=1`) | VPN container network | `SOCAI_VPN_CONTAINER` |
| Enrichment APIs (VT, AbuseIPDB, Shodan, etc.) | Direct | — |
| Sentinel KQL queries | Direct | — |
| Confluence, OpenCTI | Direct | — |

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SOCAI_OPSEC_PROXY` | _(empty)_ | HTTP proxy URL for Playwright/requests OPSEC traffic |
| `SOCAI_VPN_CONTAINER` | `gluetun` | Docker container name for `--network=container:` mode |
| `SOCAI_BROWSER_VPN` | `0` | Set `1` to route browser sessions through VPN container |
| `SOCAI_SANDBOX_NETWORK` | `monitor` | Sandbox network mode: `monitor`, `isolate`, or `vpn` |

## Secret Config Files

`config/client_entities.json` and `config/workspace_tables.json` are git-ignored (contain real client names and workspace GUIDs). Only `config/client_entities.example.json` is tracked.

`config/users.json` contains bcrypt-hashed passwords — `chmod 600` and git-ignore. `config/roles.json` is safe to commit (no secrets — only role definitions and permission mappings).
