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

## New Chat Tool

Tool definitions are in `api/tool_schemas.py`:
- Add to `TOOL_DEFS` for case-mode availability
- Add to `SESSION_TOOL_DEFS` for session-mode availability (session tools that need file storage use `_session_ensure_backing_case()`)

Then add the dispatch case in `api/chat.py`:
- `_dispatch_tool()` for case-mode
- `_dispatch_session_tool()` for session-mode

The tool should map to an existing `api/actions.py` function or a new one following the `_run_action()` pattern.

## Batch-Capable Tool

To make a tool batch-capable, add a `prepare_*_batch(case_id)` function that returns the `messages.create()` kwargs as a dict (without executing the API call). Register it in `tools/batch.py`'s dispatch table.

## MCP Server

`mcp_server.py` exposes the pipeline to Claude Desktop via FastMCP (stdio transport): `investigate`, `list_cases`, `get_case`, `read_report`, `generate_weekly`, `generate_queries`, `close_case`. The `investigate` tool supports the full `ChiefAgent.run()` parameter set including `eml_paths` and `detonate`. All imports are deferred inside tool functions to avoid slow startup.
