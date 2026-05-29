# CrowdStrike Falcon Integration

Query a client's CrowdStrike Falcon platform — classic Falcon APIs (detections, hosts, incidents) and NG-SIEM / Falcon LogScale event hunting (CQL).

## Architecture

| | |
|---|---|
| Falcon API | `https://api.<region>.crowdstrike.com/...` (oauth2 client credentials) |
| NG-SIEM | `https://api.<region>.crowdstrike.com/loggingapi/entities/queries/v1/run` |
| Auth | Per-client OAuth2 API client (created in client's Falcon console) |
| Token TTL | ~30 minutes; cached per-client in-process |

**Important:** unlike Defender XDR, there is **no multi-tenant pattern** with CrowdStrike. Each client tenant requires its own API client created inside their Falcon console with read scopes, and credentials shared back to Performanta.

## Supported regions

| Code | Host |
|---|---|
| `us-1`     | `api.crowdstrike.com` |
| `us-2`     | `api.us-2.crowdstrike.com` |
| `eu-1`     | `api.eu-1.crowdstrike.com` |
| `us-gov-1` | `api.laggar.gcw.crowdstrike.com` |
| `us-gov-2` | `api.us-gov-2.crowdstrike.mil` |

## Per-client onboarding

For each client tenant you want to query:

### 1. Create the Falcon API client (client side)

In the client's Falcon console: **Support and resources → API clients and keys → Add new API client**. Required scopes:

- `Detections: Read`
- `Hosts: Read`
- `Incidents: Read`
- `Real Time Response: Read` (optional — for live host queries)
- `NG SIEM: Read` (or `LogScale: Read` — depends on Falcon version)

Capture: `client_id`, `client_secret`, region (visible in Falcon URL — e.g. `falcon.eu-1.crowdstrike.com` → region is `eu-1`).

### 2. Capture the NG-SIEM repo ID

In Falcon NG-SIEM → **Search**, open any saved query → repo ID is in the URL or top-left repo selector. Typically named like `<client>-ngsiem-prod`.

### 3. Configure `config/client_entities.json`

```json
"platforms": {
  "sentinel": { ... },
  "crowdstrike": {
    "api_enabled": true,
    "falcon_region": "eu-1",
    "ngsiem_repo": "heidelberg-ngsiem-prod"
  }
}
```

### 4. Configure `.env`

Env var names are derived from the client code (uppercase + non-alphanumerics → underscore):

```bash
SOCAI_CROWDSTRIKE_HEIDELBERG_MATERIALS_CLIENT_ID=<falcon_api_client_id>
SOCAI_CROWDSTRIKE_HEIDELBERG_MATERIALS_CLIENT_SECRET=<falcon_api_client_secret>
```

`alex_forbes` → `SOCAI_CROWDSTRIKE_ALEX_FORBES_CLIENT_ID/SECRET`. `se_first` → `SOCAI_CROWDSTRIKE_SE_FIRST_CLIENT_ID/SECRET`. Etc.

### 5. Verify

```python
from tools.crowdstrike import is_falcon_configured
print(is_falcon_configured("heidelberg_materials"))   # True
```

### 6. Capture the connector inventory

Run the discovery query (`DISCOVERY_QUERIES[0]` in `tools/cql_playbooks.py`, also surfaced at `socai://cql-playbooks`) against the client's NGSIEM repo to enumerate every active `@dataConnectionID` with its `#Vendor`, `#event.dataset`, `#event.module`, `observer.vendor`, `observer.product` values. Stow the parsed output at `registry/ngsiem_connectors/<client>.json`.

Why: engineering grammar references drift; only the live discovery output proves which tag values produce hits in that specific repo. Building CQL queries against a stowed connector inventory eliminates the most common zero-hit failure mode (wrong vendor casing, wrong module name, dataset name that exists in docs but not in the repo).

See `config/ngsiem/ngsiem_rules.md` § 4 for the curated cross-client tag mapping — rows marked ✓ are verified against at least one client's discovery output, rows marked ⚠ are engineering reference only and need verification per client before use.

## Usage

### Python — NG-SIEM event hunting (CQL)

```python
from tools.crowdstrike import run_falcon_cql

result = run_falcon_cql(
    "heidelberg_materials",
    """
    #event_simpleName=ProcessRollup2
    | FileName=/powershell\\.exe$/i
    | head(20)
    """,
)
for event in result["rows"]:
    ...
```

### Python — Classic Falcon API (FQL filter)

```python
from tools.crowdstrike import query_detections, query_hosts, query_incidents

dets = query_detections(
    "heidelberg_materials",
    filter_="status:'new'+max_severity_displayname:['High','Critical']",
    limit=50,
)

host = query_hosts("heidelberg_materials", filter_="hostname:'WS01'", limit=1)

incs = query_incidents("heidelberg_materials", filter_="status:20", limit=20)
```

### MCP tools (HITL via Claude Desktop)

Scope required: `crowdstrike:query` (granted to `mdr_analyst`, `senior_analyst`, `admin`).

Tools exposed:

| Tool | Purpose |
|---|---|
| `run_falcon_cql(client, cql, repo?, max_rows?)` | NG-SIEM event hunting |
| `query_falcon_detections(client, filter_fql?, limit?)` | Detection summaries |
| `query_falcon_hosts(client, filter_fql?, limit?)` | Host inventory |
| `query_falcon_incidents(client, filter_fql?, limit?)` | Incidents |

Trigger phrases: *"check CrowdStrike"*, *"Falcon detection"*, *"what did the CS sensor see"*, *"NG-SIEM query"*, *"process tree on CrowdStrike host"*.

### CQL investigation playbooks

All 17 v2 playbooks ship a CrowdStrike NG-SIEM (LogScale/CQL) implementation — select them via the `cql_investigation` prompt or load with `load_cql_playbook(<id>)`. `classify_attack` returns the matching playbook in its `cql_playbook` field. Coverage:

- **Falcon-native** (endpoint telemetry, `#event_simpleName=...`): `malware-execution`, `lateral-movement`, `command-and-control`, `ioc-hunt`, `ransomware`, `credential-access`, `persistence`, `defence-evasion`, `web-shell`, and the endpoint stages of `account-compromise` / `data-exfiltration` / `insider-data-staging`.
- **Microsoft connector-dependent** (email/identity/audit forwarded into NG-SIEM): `phishing`, `bec`, `oauth-consent` and the email/M365 stages of `data-exfiltration` / `insider-data-staging` use `#event.dataset="windows-defender-365.event"` (Defender advanced-hunting; sub-table on `Vendor.Workload`) and `#event.module=m365` / `#event.module=entraid`. These return rows only where the client forwards the M365/Defender connector into NG-SIEM.
- **Sentinel-only**: `reconnaissance` Stage 3 (authoritative-DNS enumeration) has no Falcon equivalent — Falcon `DnsRequest` is endpoint-outbound, not authoritative-inbound.

Some endpoint playbook stages reference Falcon events not yet seen across onboarded clients (e.g. registry-autostart `AsepValueUpdate`, USB device fields); these are flagged in the `.cql` headers with the discovery query to confirm per client, and fall back to `ProcessRollup2` command-line analysis. Always confirm against the stowed connector inventory (Step 6) before relying on a query.

## Limits & gotchas

- **No `union`-style cross-repo queries** — CQL is per-repo. Each client = one repo.
- **30-min token TTL** — refresh handled automatically by the in-process cache.
- **Rate limits** vary by Falcon tier. 429 responses surface `X-Ratelimit-Retryafter` in the error message.
- **403 = scope missing** — the API client in Falcon console needs the relevant read scope; can't be fixed from Performanta side.
- **`run_falcon_cql` is synchronous-only in v1** — large result sets that need the async `start/status/result` pattern aren't supported yet. Practical limit: queries that complete within 30s and return ≤10K rows.
- **Audit trail**: queries appear in the client's Falcon audit log under the API client name (e.g. `Performanta-MDR-Tooling`). Analyst attribution is in socai's own audit + case linkage.

## Artefacts

CrowdStrike query results are returned in-memory to the caller. They are **not** automatically persisted under `cases/<ID>/artefacts/` — the calling tool/prompt is responsible for saving anything material to the case (typically via `save_json` or `write_artefact` from `tools/common.py`). This mirrors the `run_kql` pattern.
