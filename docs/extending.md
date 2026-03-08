# Extending the System

## New Enrichment Provider

Add `def my_provider(ioc: str, ioc_type: str) -> dict` in `tools/enrich.py`, register in both `PROVIDERS` and `_PROVIDER_NAMES`. Add key to `config/settings.py` and `.env`.

For IPv4 providers, also add to `PROVIDERS_IP_FAST` (cheap/free, quick signal) or `PROVIDERS_IP_DEEP` (rate-limited, expensive — only runs when Tier 1 shows signal). See the tiered enrichment section in `docs/tools-reference.md`.

To add a new infrastructure ASN for Tier 0 pre-screening, add to `KNOWN_INFRA_ASNS` in `tools/enrich.py`. For org-name keyword matching, add to `_INFRA_ORG_KEYWORDS`. Avoid adding hosting providers that attackers commonly use (e.g. DigitalOcean, Linode, OCI).

## New Tool

Accept `case_id`, use `write_artefact()` / `save_json()` for all outputs, return a manifest dict. Register in `agents/chief.py` and optionally add a CLI sub-command in `socai.py`.

## New Agent

Inherit `BaseAgent`, implement `run(**kwargs) -> dict`, call tool functions only. Register in `agents/chief.py`.

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

## New Chat Tool

Tool definitions are in `api/tool_schemas.py`; dispatch handlers are in `api/chat.py`.

**Shared tool** (runs identically in case-mode and session-mode):
1. Add the schema to `TOOL_DEFS` (it flows into `SESSION_TOOL_DEFS` automatically via `_SHARED_TOOL_NAMES`)
2. Add the tool name to `_SHARED_TOOL_NAMES` in `api/tool_schemas.py`
3. Add the handler in `_dispatch_shared()` in `api/chat.py`
4. If the tool needs file-based artefact storage in session mode, add it to `_SHARED_BACKING_REQUIRED`

**Case-only tool:**
1. Add the schema to `TOOL_DEFS`
2. Add the handler in `_dispatch_tool()` in `api/chat.py`

**Session-only tool:**
1. Add the schema to `_SESSION_ONLY_DEFS` in `api/tool_schemas.py`
2. Add the handler in `_dispatch_session_tool()` in `api/chat.py`

The handler should map to an existing `api/actions.py` function or a new one following the `_run_action()` pattern.

## New Structured Output Schema

Add a Pydantic `BaseModel` subclass to `tools/schemas.py`, then pass it as `output_schema` to `structured_call()`. No special configuration is needed — `_schema_for_model()` in `tools/structured_llm.py` automatically adds `additionalProperties: false` to all object types (required by the Anthropic API).

## Batch-Capable Tool

To make a tool batch-capable, add a `prepare_*_batch(case_id)` function that returns the `messages.create()` kwargs as a dict (without executing the API call). Register it in `tools/batch.py`'s dispatch table.

## New Article Source

Add entries to `config/article_sources.json` with `"type": "rss"` and `"categories": ["ET", "EV"]`. Non-RSS source types (e.g. `"api"`, `"confluence"`) are reserved for future integrations — the tool currently only processes `"type": "rss"`.

## MCP Server

`mcp_server.py` exposes the pipeline to Claude Desktop via FastMCP (stdio transport): `investigate`, `list_cases`, `get_case`, `read_report`, `generate_weekly`, `generate_queries`, `close_case`. The `investigate` tool supports the full `ChiefAgent.run()` parameter set including `eml_paths` and `detonate`. All imports are deferred inside tool functions to avoid slow startup.
