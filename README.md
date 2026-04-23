# SOCAI

AI-augmented Security Operations Centre platform. Analyst-driven, human-in-the-loop investigation pipeline powered by Claude Desktop via MCP.

## What It Does

SOC-AI provides a complete investigation toolkit for MDR/XDR analysts:

- **Alert triage and classification** -- deterministic attack-type routing with investigation plans
- **IOC enrichment** -- 15+ threat intelligence providers (VirusTotal, AbuseIPDB, Shodan, etc.) with smart tiering and client-baseline auto-skip
- **SIEM integration** -- KQL queries against Azure Sentinel, LogScale/CQL for CrowdStrike NGSIEM, parameterised playbooks
- **Email and phishing analysis** -- .eml parsing, headless browser capture, brand impersonation detection, credential harvest detection
- **Dynamic analysis** -- sandbox detonation, disposable browser sessions with network capture
- **Forensic ingestion** -- Velociraptor collections, MDE investigation packages, PE analysis, YARA scanning
- **Dark web intelligence** -- infostealer exposure, breach databases, .onion search, paste/leak search
- **Cross-case intelligence** -- BM25 semantic case recall, IOC overlap clustering, campaign detection, threat landscape
- **Report generation** -- MDR reports, PUP reports, FP tickets, executive summaries, threat articles
- **Client playbooks** -- per-client escalation matrices, containment capabilities, crown jewel monitoring, multi-environment support

## Architecture

```
CLI (socai.py)           -- entrypoint for all subcommands
Tools (tools/)           -- stateless functions, no direct LLM calls
MCP Server (mcp_server/) -- HTTPS SSE on port 8001, JWT RBAC
Shared API (api/)        -- auth, actions, timeline, input parsing
```

- **No direct LLM API calls** -- all reasoning is handled by the analyst's local Claude Desktop agent via MCP prompts
- **Human-in-the-loop** -- analyst drives each investigation step; tools gather data, agent reasons
- **Filesystem state** -- no database; cases in `cases/`, registry in `registry/`, articles in `articles/`
- **105 MCP tools**, 44 resources, 22 prompts across 3 permission tiers

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt
playwright install chromium  # optional; falls back to requests

# Run the MCP server
python3 -m mcp_server

# Or use streamable HTTP transport
SOCAI_MCP_TRANSPORT=streamable-http python3 -m mcp_server

# CLI usage
python3 socai.py --help
python3 socai.py create-case --title "Alert title" --severity high --analyst <name> --client <client>
python3 socai.py enrich --case IV_CASE_001

# Run tests
python3 -m pytest tests/ -v
```

## MCP Server

The MCP server exposes the full toolkit to Claude Desktop over HTTPS SSE with JWT RBAC. No LLM calls are made server-side -- the local Claude Desktop agent handles all analytical reasoning via prompts and save tools.

**Tool categories:** Investigation and triage, case management, enrichment, email and phishing, SIEM queries, dynamic analysis, forensic ingestion, dark web intelligence, cross-case intelligence, report delivery, SOC processes.

**Resources:** Case data, client config, playbooks, Sentinel queries, LogScale syntax, NGSIEM references, IOC index, threat articles, landscape, SOC process documentation.

**Prompts:** Guided workflows (HITL investigation, alert triage, KQL playbooks), report writing (MDR, PUP, FP, executive summary, threat articles), analytical prompts (disposition, investigation matrix, quality gate).

See `docs/mcp-server.md` for auth, RBAC, deployment, and Claude Desktop configuration.

## Client Playbooks

Per-client response playbooks in `config/clients/<name>/playbook.json` define:

- **Escalation matrix** -- priority/asset-type/blocked combinations with ticket, phone, and containment actions
- **Containment capabilities** -- what the SOC can execute (EDR isolate, password reset, AV scan)
- **Remediation actions** -- what the client owns (email purge, network blocklist)
- **Crown jewels** -- critical hosts with wildcard pattern matching; auto-escalate to P1 if compromised
- **Multi-environment support** -- separate escalation rules per platform (Sentinel/MDE, CrowdStrike, OT)

## SOC Process Documentation

Local authoritative docs for SOC operational procedures, accessible via the `lookup_soc_process` MCP tool:

- **Incident handling** -- role priorities (L1-L3), SOAR queue workflow, alert sorting, escalation rules
- **Critical incident management** -- P1/P2 checklists, war rooms, IR activation, technical report structure
- **Service requests** -- Service Desk queues, ticket lifecycle, Teams channels
- **Time tracking** -- Kantata categories, overtime logging, on-call hours

## Investigation Metrics

Built-in analytics for investigation lifecycle and workflow patterns:

```bash
python3 scripts/metrics_report.py              # full summary
python3 scripts/metrics_report.py --compare    # analyst comparison
python3 scripts/workflow_report.py             # tool sequence patterns
python3 scripts/workflow_report.py --friction  # friction signal analysis
```

## Documentation

| Doc | Contents |
|-----|----------|
| `docs/pipeline.md` | HITL workflow, tool sequence, auto-disposition, auto-close |
| `docs/tools-reference.md` | All tool details: enrichment, SIEM, phishing, sandbox, forensics |
| `docs/configuration.md` | Env vars, API keys, client config |
| `docs/artefacts.md` | File and artefact path reference |
| `docs/extending.md` | Adding providers, tools, brands, clients |
| `docs/architecture.md` | System overview, data flow, tool contracts |
| `docs/mcp-server.md` | MCP server: auth, RBAC, tools, resources, prompts |
| `docs/sandbox.md` | Sandbox detonation: setup, network modes, safety |
| `docs/incident-handling.md` | SOC incident handling process |
| `docs/critical-incident-management.md` | P1/P2 checklists, war rooms, IR activation |
| `docs/service-requests.md` | Service Desk queues and ticket lifecycle |
| `docs/time-tracking.md` | Kantata time categories and overtime |

## Tests

```bash
python3 -m pytest tests/ -v
python3 -m pytest tests/test_tools.py::test_extract_iocs_from_text -v
```

All tests use case ID `IV_CASE_000` with autouse fixture for setup/teardown. Fixtures in `tests/fixtures/`.
