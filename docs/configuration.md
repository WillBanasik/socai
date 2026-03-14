# Configuration

All settings in `config/settings.py`; secrets in `.env` (git-ignored, auto-loaded).

## General Settings

| Env var | Default | Effect |
|---------|---------|--------|
| `SOCAI_BROWSER` | `playwright` | `playwright` or `requests` |
| `SOCAI_CAPTURE_TIMEOUT` | `20` | Web capture timeout (seconds) |
| `SOCAI_SPA_DWELL` | `5000` | Extra wait (ms) after `networkidle` if page text is empty |
| `SOCAI_STRINGS_MIN` | `6` | Min string length for static analysis |
| `SOCAI_LLM_MODEL` | `claude-sonnet-4-6` | Claude model for LLM steps (legacy fallback) |
| `SOCAI_ENRICH_CACHE_TTL` | `24` | Enrichment cache TTL (hours); `0` = disabled |
| `SOCAI_ENRICH_WORKERS` | `10` | Thread pool size for parallel enrichment (all tiers) |
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
| `SOCAI_COMPACTION_ENABLED` | `1` | Enable API-side context compaction for long chats (Opus models) |
| `SOCAI_BATCH_POLL_INTERVAL` | `30` | Seconds between batch status polls |
| `SOCAI_BATCH_TIMEOUT` | `3600` | Seconds before batch polling timeout |
| `SOCAI_BROWSER_POOL_MAX_USES` | `50` | Playwright browser recycle threshold (prevents memory leaks) |
| `SOCAI_BROWSER_POOL_IDLE_SECS` | `300` | Auto-close pooled Playwright browser after N seconds of inactivity |
| `ANTHROPIC_API_KEY` | `""` | Required for LLM-assisted steps and `client-query` |

## Model Tiering

See [model_tiering.md](model_tiering.md) for full details.

| Env var | Default | Purpose |
|---------|---------|---------|
| `SOCAI_MODEL_HEAVY` | `claude-opus-4-6` | Complex reasoning, high-stakes analysis |
| `SOCAI_MODEL_STANDARD` | `claude-sonnet-4-6` | Most analytical tasks |
| `SOCAI_MODEL_FAST` | `claude-haiku-4-5-20251001` | Routing, simple generation, high-volume |

Per-task model assignments: `SOCAI_MODEL_{TASK}` — see `config/settings.py` for full list. Includes `SOCAI_MODEL_ARTICLES` (default `standard`) for threat article generation.

Severity escalation for `{secarch, report, chat_response, evtx, fp_ticket}`: fast->standard, standard->heavy on high/critical. Note: `chat_response` defaults to `standard` (Sonnet), so escalation bumps it to `heavy` (Opus).

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
| `OPENCTI_URL` | `https://opencti.example.com` | Override for different instance |
| `OTX_API_KEY` | AlienVault OTX | IPv4, domain, URL, MD5, SHA1, SHA256 |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis | SHA256 only (overview endpoint) |
| `WHOISXML_API_KEY` | WHOISXML API | domain (age, registrant, newly-registered flag) |
| `CENSYS_TOKEN` | Censys Platform API v3 | IPv4, domain — Bearer PAT |
| `ABUSECH_API_KEY` | URLhaus + ThreatFox + MalwareBazaar | IPv4, domain, URL, MD5, SHA256 — **registration broken as of 2026-03** |
| `EMAILREP_API_KEY` | EmailRep.io | email (optional; keyless tier rate-limited) |
| `ANYRUN_API_KEY` | Any.Run | SHA256 — sandbox hash lookup + detonation |
| `JOESANDBOX_API_KEY` | Joe Sandbox | SHA256 — sandbox hash lookup + detonation |
| `SOCAI_BRAVE_SEARCH_KEY` | Brave Search | Web search fallback (optional; DuckDuckGo used if unset) |

### Provider Notes

- **OpenCTI:** StixCyberObservable lookups use `value` filter for IP/domain/URL/email, and `search` param for file hashes. CVE lookups use the `vulnerabilities` query and return `epss_score` and `cisa_kev`.
- **Censys:** Uses Platform API v3 (`api.platform.censys.io/v3`), **not** old `search.censys.io/api/v2`. Auth is `Authorization: Bearer <token>`. Data nested under `result.resource`.
- **Hybrid Analysis:** `/api/v2/search/hash` POST is broken upstream — use `/api/v2/overview/{sha256}` (GET). MD5/SHA1 not supported.
- **Abuse.ch:** Account registration non-functional as of 2026-03; key cannot be obtained.

### Tiered IPv4 Enrichment

IPv4 addresses use a 3-tier enrichment model to reduce API calls:

- **Tier 0 (ASN pre-screen):** Team Cymru DNS (free, no key) identifies IPs owned by Microsoft, AWS, Google, Cloudflare, Akamai CDN, Fastly, Apple, Meta. These are tagged `infra_clean` and skip all enrichment. Configure via `KNOWN_INFRA_ASNS` and `_INFRA_ORG_KEYWORDS` in `tools/enrich.py`.
- **Tier 1 (Fast):** AbuseIPDB, URLhaus, ThreatFox, OpenCTI. IPs clean after Tier 1 stop here.
- **Tier 2 (Deep):** VT, Shodan, GreyNoise, ProxyCheck, Censys, OTX. Only for IPs showing signal in Tier 1 or returning no data.

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

Client-specific response playbooks are stored in `config/clients/<client_name>.json`. These drive the `response-actions` tool, which produces a deterministic response plan based on case evidence.

| Setting | Value |
|---------|-------|
| `CLIENT_PLAYBOOKS_DIR` | `config/clients/` |
| `SOCAI_DEFAULT_CLIENT` | Env var; sets default client when `--client` is not passed |

**CLI flags:** `--client <name>` on applicable subcommands. Falls back to `SOCAI_DEFAULT_CLIENT`.

**Schema:** See `config/client_playbook.example.json` for documented fields: `client_name`, `response[]`, `crown_jewels`, `contacts[]`, `escalation_matrix[]`.

## Client Aliasing

`SOCAI_ALIAS=1` enables alias/dealias cycle for LLM calls only — local artefacts always contain real names.

Config: `config/client_entities.json` (git-ignored) — unified `clients` list. Schema: `config/client_entities.example.json`.

**Client entity fields:**

| Field | Required | Description |
|---|---|---|
| `name` | Yes | Canonical client name (case-insensitive matching) |
| `alias` | No | LLM alias for data minimisation |
| `root` | No | `true` for prefix matching in alias/dealias |
| `platforms` | No | Nested object mapping platform → config (see below) |
| `workspace_id` | No | Legacy; migrated to `platforms.sentinel.workspace_id` |

**Platform scope** (`platforms` object):

```json
{
  "platforms": {
    "sentinel": { "workspace_id": "..." },
    "xdr": { "tenant_id": "..." },
    "crowdstrike": { "cid": "..." },
    "encore": { "access": true }
  }
}
```

The `platforms` object determines which security platforms are available for investigation of that client's incidents. Used by `lookup_client` (MCP tool), `socai://clients` (resource), workspace resolution in `run_kql`, and the `hitl_investigation` prompt (Phase 0 client gate).

**Root vs exact:** `root: true` does prefix matching. Exact names do whole-word replacement.

**Alias boundary:** Aliasing is an LLM privacy boundary only. All local artefacts contain real names. The alias/dealias cycle runs in: `security_arch_review.py`, `generate_mdr_report.py`, `fp_ticket.py`, `client_query.py`, `executive_summary.py`.

## Sentinel Workspace IDs

Workspace IDs for `az monitor log-analytics query -w <ID>` are in `config/client_entities.json`. Table availability per workspace: `config/workspace_tables.json` (git-ignored, keyed by workspace name e.g. `example-client`). Discovery script: `scripts/discover_sentinel_schemas.py`. Workspace resolution in `scripts/run_kql.py` tries exact match, then uppercase, then lowercase.

## Confluence (Read-Only)

Read-only integration with Confluence Cloud for checking existing articles and (future) process documentation.

| Env var | Purpose |
|---------|---------|
| `CONFLUENCE_URL` | Instance URL (e.g. `https://yourinstance.atlassian.net`) |
| `CONFLUENCE_CLOUD_ID` | Numeric cloud ID (from `{url}/_edge/tenant_info`) |
| `CONFLUENCE_EMAIL` | Account email for basic auth |
| `CONFLUENCE_API_TOKEN` | Scoped API token (read-only, Confluence only) |
| `CONFLUENCE_SPACE_KEY` | Space key to read from (e.g. `MDR1`) |

**Token setup:** Create a scoped token at [id.atlassian.com](https://id.atlassian.com/manage-profile/security/api-tokens) with "Create API token with scopes" → app: Confluence → scopes: `read:page:confluence`, `read:space:confluence`. Scoped tokens use the `api.atlassian.com/ex/confluence/{cloudId}` base URL.

**Usage:** `tools/confluence_read.py` provides `list_pages()`, `get_page()`, `search_pages()`, `get_page_by_title()`. Used by `tools/threat_articles.py` for dedup against recently published articles in the MDR1 space.

## Cyberint (Read-Only CTI Alerts)

Read-only integration with the Cyberint threat intelligence platform for browsing and searching CTI alerts.

| Env var | Purpose |
|---------|---------|
| `CYBERINT_API_KEY` | `access_token` cookie value from an authenticated Cyberint session |
| `CYBERINT_API_URL` | API base URL (default `https://cyberint.example.com`) |

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
| Host tools | `tcpdump` (for pcap parsing on session stop) |
| Network mode | `--network=host` (one session at a time) |

| Variable | Default | Description |
|---|---|---|
| `SOCAI_BROWSER_IMAGE` | `socai-browser:latest` | Docker image for browser sessions |
| `SOCAI_BROWSER_IDLE_TIMEOUT` | `300` | Seconds of network inactivity before auto-stop |
| `SOCAI_BROWSER_MAX_SESSION` | `3600` | Hard session duration ceiling (seconds) |
| `SOCAI_BROWSER_DISCONNECT_GRACE` | `15` | Seconds after last noVNC viewer disconnects before auto-stop (0 = disabled) |

noVNC access: `http://127.0.0.1:7900` (no password).

Session state files are stored in `browser_sessions/<session_id>.json`.

## Sandbox Detonation (Docker)

See `docs/sandbox.md` for env vars, Docker setup, network modes, and safety details.

## Secret Config Files

`config/client_entities.json` and `config/workspace_tables.json` are git-ignored (contain real client names and workspace GUIDs). `registry/alias_map.json` stores runtime alias mappings. Only `config/client_entities.example.json` is tracked.

`config/users.json` contains bcrypt-hashed passwords — `chmod 600` and git-ignore. `config/roles.json` is safe to commit (no secrets — only role definitions and permission mappings).
