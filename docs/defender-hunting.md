# Defender XDR Advanced Hunting

Query Microsoft Defender XDR data (Device*, Email*, Identity*, CloudApp*, Alert*, Url*) for clients that don't stream the full XDR schema into Sentinel.

## Why this exists

For most clients only the high-signal, low-volume Defender XDR tables (Email*, Identity*, Alert*) are streamed into Sentinel — the bulky Device* tables (DeviceProcessEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceRegistryEvents, DeviceEvents) stay in Defender's own data lake to save on Log Analytics ingestion cost. This module queries that data lake directly via Microsoft's Advanced Hunting API, so investigations don't have to switch tools.

## Architecture

| | |
|---|---|
| Endpoint | `POST https://api.security.microsoft.com/api/advancedhunting/run` |
| Auth | OAuth2 client_credentials (app-only), per-tenant token |
| App reg | Performanta multi-tenant app with `AdvancedHunting.Read.All` |
| Limits | 10,000 rows / 30s / ~100MB / 15 req/min / 1000 req/hour per app |
| Token cache | In-process, per-tenant, ~50min effective TTL |

Identity-agnostic — same code path serves HITL (Claude Desktop → MCP tool) today and is ready for autonomous socai investigations when that comes online. Bearer token is bound to the app reg, not a human user.

## One-time setup

### 1. Create the multi-tenant app registration (Performanta tenant)

```bash
az ad app create \
  --display-name "Performanta-SOCAI-MDR" \
  --sign-in-audience AzureADMultipleOrgs
```

Note the returned `appId` — this is `SOCAI_DEFENDER_APP_CLIENT_ID`.

Create a client secret:

```bash
az ad app credential reset \
  --id <appId> \
  --display-name "socai-mdr-secret-2026" \
  --years 1
```

Capture the `password` — this is `SOCAI_DEFENDER_APP_CLIENT_SECRET`. **Never commit it.**

### 2. Add API permissions

In the app reg, add **application permission** `AdvancedHunting.Read.All` on the **Microsoft Threat Protection** API (resource appId `8ee8fdad-f234-4243-8f3b-15c294843740`). Grant admin consent in the Performanta tenant.

### 3. Configure `.env`

```bash
SOCAI_DEFENDER_APP_CLIENT_ID=<appId from step 1>
SOCAI_DEFENDER_APP_CLIENT_SECRET=<password from step 1>
```

### 4. Per-client onboarding

For each client tenant you want to query:

1. Have a client tenant admin visit:
   ```
   https://login.microsoftonline.com/<client-tenant-id>/adminconsent?client_id=<your-app-id>
   ```
   and grant consent. (Or use the admin-consent URL from the Azure portal.)

2. Update `config/client_entities.json`:
   ```json
   "platforms": {
     "sentinel": { "workspace_id": "..." },
     "defender_xdr": {
       "api_enabled": true,
       "tenant_id": "<client-tenant-guid>"
     }
   }
   ```

3. Confirm with `python3 -c "from tools.defender_hunting import is_defender_configured; print(is_defender_configured('<client>'))"` → should print `True`.

## Usage

### Python (autonomous / scripts)

```python
from tools.defender_hunting import run_defender_kql

result = run_defender_kql(
    "performanta",
    "DeviceProcessEvents | where Timestamp > ago(1h) | take 10",
)
print(result["stats"])   # {'row_count': 10, 'elapsed_ms': 412}
for row in result["rows"]:
    ...
```

### MCP tool (HITL via Claude Desktop)

The `run_defender_kql` MCP tool requires scope `defender_xdr:query` (granted to `mdr_analyst` and `senior_analyst` roles).

Trigger phrases for Claude Desktop: *"check Defender"*, *"Advanced Hunting"*, *"process events for this host"*, *"what ran on the endpoint"*, *"registry changes for this user"*.

### Schema discovery

```bash
python3 scripts/discover_defender_schemas.py
```

Probes each onboarded client for all standard Advanced Hunting tables and writes per-client schemas to `config/defender_tables.json` — the file is **created** by this script, not shipped pre-populated. A table that's not licenced for the client (e.g. Identity* needs MDI, Device* needs MDE) is recorded as unavailable.

## Limits & gotchas

- **No `union withsource=*`** — Advanced Hunting KQL is a subset of full KQL. Cross-table joins are fine; cross-workspace queries are not (single tenant per call).
- **30-second timeout, 10K row cap** — for pattern analysis use `summarize`, not raw rows.
- **No `Usage | distinct DataType`** equivalent — Advanced Hunting tables are a fixed Microsoft-defined set. Discovery probes the known list.
- **401 = consent revoked or secret rotated** — the in-process token cache is cleared automatically on 401; if the failure persists, restart the MCP server (token cache is process-local) and re-grant admin consent.
- **Cross-tenant audit trail** — query appears in the client's M365 audit log under the app reg's display name, not the analyst's UPN. Analyst attribution lives in socai's own audit log + case linkage.

## Artefacts

Defender XDR query results are returned in-memory to the caller. They are **not** automatically persisted under `cases/<ID>/artefacts/` — the calling tool/prompt is responsible for saving anything material to the case (typically via `save_json` or `write_artefact` from `tools/common.py`). This mirrors the `run_kql` pattern.
