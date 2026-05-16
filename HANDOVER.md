# socai — Manager Handover Notes

Will is on annual leave. This doc covers everything you need to run investigations solo.

---

## Setup

Run `bash install.sh` (once only). It will extract the project, create a Python venv, and install all dependencies. See the installer output for the exact install path (`~/socai` by default).

---

## Starting the MCP Server

The MCP server is what Claude Desktop talks to. Start it first:

```bash
cd ~/socai
.venv/bin/python -m mcp_server
```

Leave that terminal open. The server runs on `https://127.0.0.1:8001`.

In a second terminal, tail the audit log to see what's happening:

```bash
cd ~/socai
tail -f registry/audit.jsonl
```

---

## Claude Desktop Config

Add this to your Claude Desktop MCP config so it connects to the running server:

```json
{
  "mcpServers": {
    "socai": {
      "transport": "sse",
      "url": "https://127.0.0.1:8001/sse",
      "headers": {
        "Authorization": "Bearer <JWT_TOKEN>"
      }
    }
  }
}
```

Ask Will for the JWT token over your secure channel — it's in `.env` as `SOCAI_JWT_SECRET` (used to sign tokens) or check `config/users.json` for pre-issued tokens.

---

## Daily Workflow

### 1. Create a case

```bash
./socai create-case --title "Alert title" --severity high --analyst <your-name> --client <client-id> --tags "phishing,credential"
```

Returns a case ID like `IV_CASE_042`.

### 2. Enrich IOCs

Via CLI:
```bash
./socai enrich --case IV_CASE_042
```

Or via Claude Desktop MCP: use the `enrich_iocs` or `quick_enrich` tool.

### 3. Run KQL / triage queries

Use `run_kql` or `run_kql_batch` MCP tools from Claude Desktop. KQL playbooks are in `config/kql_playbooks/`.

### 4. Produce and save a report

Use the `mdr-report` MCP prompt in Claude Desktop → Claude generates the HTML report → use `save_report` tool to persist it. The case auto-closes on save.

### 5. False positive ticket

```bash
./socai fp-ticket --case IV_CASE_042 --alert alert.json
```

---

## Case History

All previous cases are in `cases/`. Each folder is named by case ID and contains:

- `case.json` — metadata, verdict, status
- `artefacts/` — enrichment results, KQL output, screenshots, reports
- `timeline.jsonl` — event timeline

Browse cases:
```bash
./socai list-cases
./socai list-cases --status open
./socai list-cases --client clientname
```

Open a specific case:
```bash
./socai show-case IV_CASE_042
```

---

## Key Config Files

| File | Purpose |
|------|---------|
| `.env` | All API keys and settings |
| `config/clients/` | Per-client config (Sentinel workspace IDs, playbooks) |
| `config/users.json` | MCP user accounts and roles |
| `config/roles.json` | RBAC role definitions |
| `registry/` | Case registry, metrics, audit log |

---

## If Something Breaks

Check errors:
```bash
./socai errors
```

Check the audit log:
```bash
tail -50 registry/audit.jsonl
```

Most enrichment tools degrade gracefully if an API key is missing or a provider is down — check the enrichment artefact JSON for `"status": "error"` entries.

---

## Commands Reference

```bash
./socai --help                          # full subcommand list
./socai create-case --help
./socai enrich --help
./socai list-cases
./socai show-case <ID>
./socai errors
python3 scripts/metrics_report.py       # investigation metrics
python3 scripts/workflow_report.py      # tool usage analytics
```

---

*Will returns [fill in date]. Ping him on Teams if anything critical comes up.*
