# Extending the System

## New Enrichment Provider

Add `def my_provider(ioc: str, ioc_type: str) -> dict` in `tools/enrich.py`, register in both `PROVIDERS` and `_PROVIDER_NAMES`. Add key to `config/settings.py` and `.env`.

For IPv4 providers, also add to `PROVIDERS_IP_FAST` (cheap/free, quick signal) or `PROVIDERS_IP_DEEP` (rate-limited, expensive — only runs when Tier 1 shows signal). See the tiered enrichment section in `docs/tools-reference.md`.

To add a new infrastructure ASN for Tier 0 pre-screening, add to `KNOWN_INFRA_ASNS` in `tools/enrich.py`. For org-name keyword matching, add to `_INFRA_ORG_KEYWORDS`. Avoid adding hosting providers that attackers commonly use (e.g. DigitalOcean, Linode, OCI).

## New Tool

Accept `case_id`, use `write_artefact()` / `save_json()` for all outputs, return a manifest dict. Add a CLI sub-command in `socai.py` if needed.

## New IOC TLD

Add to the explicit allowlist in `_RE_DOMAIN` in `tools/extract_iocs.py`.

## New Phishing Brand

Append to `_BRANDS` in `tools/detect_phishing_page.py` with `name`, `patterns` (list of compiled regexes), and `allowed` (set of base domains). Also add to `_BRAND_DOMAINS` in `tools/analyse_email.py` for homoglyph detection.

## New Anomaly Detector

Add a `_detect_*()` function in `tools/detect_anomalies.py` returning `list[dict]` with `type`, `severity`, and `detail` keys. Call it from `detect_anomalies()` main function.

## New Sandbox Provider

Add a `_*_lookup(sha256: str) -> dict` function in `tools/sandbox_analyse.py`, add to `providers` list in `sandbox_analyse()`.

## New Velociraptor Artefact Normaliser

Add a `_norm_*()` function in `tools/velociraptor_ingest.py` that maps VQL field names to the standard fields (`TimeCreated`, `EventID`, `SourceIP`, `TargetUserName`, `ProcessName`, `CommandLine`, etc.). Register it in the `_NORMALISERS` dict with the VQL artefact name as key. Prefix matching is supported (e.g. `Windows.EventLogs.Evtx` matches `Windows.EventLogs.Evtx/Logs`). Unknown artefacts fall through to `_norm_generic`.

## New MDE Artefact Normaliser

Add a `_norm_*()` function in `tools/mde_ingest.py` that maps MDE-specific field names to the standard fields (`TimeCreated`, `EventID`, `SourceIP`, `TargetUserName`, `ProcessName`, `CommandLine`, etc.). Register it in the `_NORMALISERS` dict. MDE uses a mix of CSV, TXT, and registry dump formats — add a corresponding parser (`_parse_*_txt` or `_parse_csv_text`) if the format isn't already handled.

## New Memory Dump Pattern

Add entries to `_SUSPICIOUS_PATTERNS` in `tools/memory_guidance.py` with `pattern` (compiled regex), `name`, and `category`. For suspicious DLLs, add to `_SUSPICIOUS_DLLS`. Risk scoring thresholds are in `_assess_risk()`.

## New MCP Tool

Add a `@mcp.tool()` handler in `mcp_server/tools.py` in the appropriate tier (`_register_tier1/2/3`). Add RBAC via `_require_scope()` at the top of the handler. If the tool needs orchestration (error handling, timeline logging), add a wrapper in `api/actions.py` following the `_run_action()` pattern. Every `except` block in action wrappers must call `log_error(case_id, step, error, *, severity)` from `tools.common` — never silently swallow exceptions with bare `except: pass`.

**Important:** MCP tools must not make LLM API calls. Tools handle data gathering (API calls, file I/O, external integrations) and deterministic logic only. For anything requiring LLM reasoning, add an MCP prompt instead (see "New MCP Prompt" above).

**Workflow analytics registration:** Every new MCP tool must be added to `TOOL_TAXONOMY` in `mcp_server/usage.py` with a `category` (one of: `lookup`, `enrichment`, `triage`, `analysis`, `delivery`, `admin`, `query`, `intel`, `sandbox`, `infra`) and a `goal` (one of: `quick_answer`, `investigate`, `deliver`, `maintain`). Tools not in the taxonomy are logged as `unknown` — workflow analytics won't classify them correctly.

## New Output Schema

Add a Pydantic `BaseModel` subclass to `tools/schemas.py`. The schema is used as a reference by MCP prompts to guide the local Claude agent's output format.

## New MCP Prompt

Add a prompt handler in `mcp_server/prompts.py` that loads system instructions and case data. The prompt should return structured context for the analyst's local Claude session to reason over. Pair it with the appropriate save tool (`save_report`, `save_threat_article`, or `add_finding`) for persistence.

## New Client

1. **Add to `config/client_entities.json`** — name (lowercase, underscores for spaces), optional `aliases` array for fuzzy matching, optional `notes` for context, `platforms.sentinel.workspace_id` (blank if unknown).

2. **Create `config/clients/<name>/`** with three files:
   - **`knowledge.md`** — Sections: Organisation, Identity & Access, Network Topology (DNS, mail flow, IP ranges), Security Stack, Known Legitimate Software, Historical Patterns, Analyst Notes. Populate via OSINT (DNS records, WHOIS, corporate pages).
   - **`playbook.json`** — `client_name`, `response` (procedures), `crown_jewels` (critical hosts; supports wildcard patterns via fnmatch), `contacts`, `escalation_matrix` (with `activity_blocked`, `sd_ticket`, `phone_call`, `response_action` fields), `containment_capabilities`, `remediation_actions`. For multi-environment clients add `environments` (map of env name → description/platforms) and `escalation_matrix_ot` for environment-specific overrides. Mark TBC fields for onboarding.
   - **`sentinel.md`** — Workspace ID, expected tables, key query patterns. Populate fully after Sentinel onboarding; scaffold from M365 deployment indicators.

3. **Sentinel schema** — once workspace ID is known, run `scripts/discover_sentinel_schemas.py` then `scripts/generate_sentinel_reference.py --client <name>` to auto-populate `sentinel.md` with real table schemas.

Files are resolved by name convention: `config/clients/{name}/knowledge.md` (also tries lowercase + underscored variants). `lookup_client` performs fuzzy matching against `name`, `aliases`, and `notes`.

## New Article Source

Add entries to `config/article_sources.json` with `"type": "rss"` and `"categories": ["ET", "EV"]`. Non-RSS source types (e.g. `"api"`, `"confluence"`) are reserved for future integrations — the tool currently only processes `"type": "rss"`.

## MCP Server

`mcp_server/` exposes 100 tools, 36 resources, and 21 prompts over HTTPS SSE with JWT RBAC. The server runs as a separate process on port 8001 (`python -m mcp_server`). The server makes no LLM calls — all reasoning is handled by the analyst's local Claude Desktop agent via prompts. Auth bridges the existing `api/auth.py` JWT system — same tokens, same permission model. Per-tool RBAC enforces `investigations:read`, `investigations:submit`, `campaigns:read`, `sentinel:query`, and `admin` scopes. For stdio transport (Claude Desktop), run `python -m mcp_server.server` with `SOCAI_MCP_TRANSPORT=stdio`.

When adding new analytical capabilities, prefer adding an MCP prompt (in `mcp_server/prompts.py`) + save handler over adding LLM-backed tools. Tools should handle data gathering and persistence only; the local agent handles all reasoning.

## Sentinel Composite Query Template

Create `config/kql_playbooks/sentinel/<scenario>.kql` with the same frontmatter format as stage-based playbooks. Use `composite: true` in the metadata. The query body is a single monolithic KQL with `let` sections and a `union isfuzzy=true` at the end. Parameters use `{{param}}` substitution. Required parameters: `{{upn}}`, `{{lookback_start}}`, `{{lookback_end}}`. Optional: `{{ip}}`, `{{object_id}}`, `{{mailbox_id}}`, `{{additional_upns}}`. Use `isnotempty()` guards for optional parameters so empty values produce valid KQL. Register the scenario in the `_composite_map` in `mcp_server/tools.py` `classify_attack` to link it to attack types.

**Important:** Only reference tables that exist in the target Sentinel workspace. List all referenced tables in the frontmatter `tables:` field — these are validated against `config/sentinel_tables.json` at render time and surfaced as `schema_warnings`. Run `scripts/discover_sentinel_schemas.py` after adding new workspaces to keep the registry current. After updating playbooks, run `python3 scripts/generate_sentinel_reference.py --all` to regenerate client sentinel.md files with column schemas.

## NGSIEM / LogScale Reference

Three reference files in `config/ngsiem/` are exposed as MCP resources for LogScale/CrowdStrike query generation:

- **`ngsiem_rules.md`** (`socai://ngsiem-rules`) — authoring conventions, anti-patterns, worked examples. Update when detection patterns change or new anti-patterns are discovered.
- **`ngsiem_columns.yaml`** (`socai://ngsiem-columns`) — field schema per connector. To add a new connector, copy the template at the bottom of the file and use the discovery queries in the file header to find the connector ID and field names.
- **`cql_grammar.json`** (`socai://cql-grammar`) — 194 CQL function signatures. Update when new CQL functions are released.

Additionally, `config/logscale_syntax.md` (`socai://logscale-syntax`) provides general CQL syntax reference (operators, precedence, conditionals, joins, regex, pitfalls).
