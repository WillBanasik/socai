# State and Persistence

All persistent state is on the filesystem. There is no database.

## Registry Files

| File | Purpose |
|------|---------|
| `registry/case_index.json` | Master registry; updated by `case_create` and `index_case` |
| `registry/audit.log` | Append-only JSONL; one line per artefact written (never truncate) |
| `registry/error_log.jsonl` | Append-only error log; one JSONL line per error/warning/info |
| `registry/enrichment_cache.json` | Cross-run enrichment cache; keyed by `provider\|ioc`, TTL-controlled |
| `registry/ioc_index.json` | Cross-case IOC index; keyed by IOC value; tracks `first_seen`, `last_seen`, `cases[]`, composite verdict |
| `registry/campaigns.json` | Cross-case campaign clusters; updated by `campaign_cluster` |
| `registry/metrics.jsonl` | Append-only investigation metrics; case phase changes, enrichment duration/coverage, verdict confidence, report completeness, investigation summaries |
| `registry/mcp_usage.jsonl` | Append-only MCP tool invocation log; caller, tool, category, goal, params, duration_ms, session_id |
| `registry/quick_enrichments/<enrichment_id>.json` | Saved caseless enrichment results from `quick_enrich`; import via `enrichment_id` on `create_case` or `import_enrichment` |

## Per-Case Files

| File | Purpose |
|------|---------|
| `cases/<ID>/case_meta.json` | Metadata: status, severity, attack_type, reference_id, report path, IOC totals, phase_timestamps (created_at, triage_at, active_at, closed_at) |
| `cases/<ID>/iocs/iocs.json` | Canonical IOC list; consumed by `enrich` and `correlate` |
| `cases/<ID>/artefacts/enrichment/enrichment.json` | Raw per-provider enrichment results; includes `tiered_enrichment` stats and `asn_prescreen` entries for infra-skipped IPs |
| `cases/<ID>/artefacts/enrichment/verdict_summary.json` | Composite verdict per IOC; `high_priority`, `needs_review`, `clean` |
| `cases/<ID>/artefacts/web/<host>/capture_manifest.json` | Per-URL capture manifest; includes `cloudflare_blocked`, `tls_certificate` |
| `cases/<ID>/artefacts/web/<host>/xhr_responses.json` | JSON/text API responses captured during page load |
| `cases/<ID>/artefacts/phishing_detection/phishing_detection.json` | Brand impersonation findings; includes `form_analysis`, `tls_signals`, `heuristic_analysis`, `purpose_assessments`, `escalation_count` |
| `cases/<ID>/artefacts/triage/triage_summary.json` | Pre-pipeline IOC triage results |
| `cases/<ID>/artefacts/email/email_analysis.json` | Email header analysis, auth results, spoofing signals |
| `cases/<ID>/artefacts/email/attachments/` | Saved email attachments with SHA-256 hashes |
| `cases/<ID>/artefacts/sandbox/sandbox_results.json` | Sandbox provider results per file hash |
| `cases/<ID>/artefacts/sandbox/sandbox_iocs.json` | Supplementary IOCs from sandbox analysis |
| `cases/<ID>/artefacts/anomalies/anomaly_report.json` | Behavioural anomaly detection findings |
| `cases/<ID>/artefacts/darkweb/hudsonrock_results.json` | Hudson Rock infostealer lookup results (credentials REDACTED) |
| `cases/<ID>/artefacts/darkweb/xposedornot_results.json` | XposedOrNot breach exposure results |
| `cases/<ID>/artefacts/darkweb/darkweb_summary.json` | Aggregated dark web exposure summary |
| `cases/<ID>/artefacts/darkweb/ahmia_results.json` | Ahmia.fi dark web search results |
| `cases/<ID>/artefacts/darkweb/intelx_results.json` | Intelligence X search results (credentials REDACTED) |
| `cases/<ID>/artefacts/darkweb/stealer_logs/parsed.json` | Parsed infostealer log output (credentials REDACTED) |
| `cases/<ID>/artefacts/campaign/campaign_links.json` | Per-case campaign membership and shared IOCs |
| `cases/<ID>/artefacts/fp_comms/fp_ticket.html` | FP suppression ticket (platform-specific) |
| `cases/<ID>/artefacts/fp_comms/fp_ticket_manifest.json` | FP ticket generation metadata |
| `cases/<ID>/artefacts/timeline/timeline.json` | Forensic timeline with sorted events + LLM analysis |
| `cases/<ID>/artefacts/analysis/pe_analysis.json` | Deep PE file analysis (imports, entropy, packers) |
| `cases/<ID>/artefacts/yara/yara_results.json` | YARA scan match results |
| `cases/<ID>/artefacts/yara/generated_rules.yar` | LLM-generated case-specific YARA rules |
| `cases/<ID>/artefacts/evtx/evtx_correlation.json` | Windows Event Log attack chain detection |
| `cases/<ID>/artefacts/cve/cve_context.json` | CVE contextualisation (NVD, EPSS, KEV, OpenCTI) |
| `cases/<ID>/artefacts/executive_summary/executive_summary.html` | Plain-English executive summary |
| `cases/<ID>/artefacts/executive_summary/executive_summary_manifest.json` | Executive summary metadata |
| `cases/<ID>/artefacts/security_architecture/security_arch_review.html` | Security architecture review |
| `cases/<ID>/artefacts/security_architecture/security_arch_structured.json` | Structured analysis (TTPs, actions, risk) |
| `cases/<ID>/artefacts/security_architecture/security_arch_manifest.json` | Security arch review metadata |
| `cases/<ID>/artefacts/response_actions/response_actions.json` | Client-specific response plan (machine-readable) |
| `cases/<ID>/artefacts/response_actions/response_actions.md` | Formatted response plan (human-readable) |
| `cases/<ID>/reports/pup_report.html` | PUP/PUA investigation report (lightweight MDR variant) |
| `cases/<ID>/artefacts/velociraptor/ingest_manifest.json` | Velociraptor ingest processing summary |
| `cases/<ID>/artefacts/velociraptor/collection_context.json` | Copied from offline collector ZIP (if present) |
| `cases/<ID>/artefacts/velociraptor/host_info.json` | Host metadata from `Generic.Client.Info` (if present) |
| `cases/<ID>/artefacts/velociraptor/uploads/` | Raw files from collector `uploads/` dir (EVTX, MFT, prefetch, etc.) |
| `cases/<ID>/logs/vr_*.parsed.json` | Normalised VQL artefact data (same schema as `parse_logs` output) |
| `cases/<ID>/logs/vr_*.entities.json` | Extracted entities from Velociraptor artefacts |
| `cases/<ID>/artefacts/mde/ingest_manifest.json` | MDE investigation package ingest processing summary |
| `cases/<ID>/artefacts/mde/security_evtx/` | Raw Security Event Log files from MDE package |
| `cases/<ID>/artefacts/mde/prefetch/` | Raw Prefetch files from MDE package |
| `cases/<ID>/artefacts/mde/wd_support_logs/` | Windows Defender support logs from MDE package |
| `cases/<ID>/logs/mde_*.parsed.json` | Normalised MDE artefact data (same schema as `parse_logs` output) |
| `cases/<ID>/logs/mde_*.entities.json` | Extracted entities from MDE artefacts |
| `cases/<ID>/artefacts/memory/dump_guidance.md` | MDE Live Response ProcDump instructions |
| `cases/<ID>/artefacts/memory/dump_guidance_manifest.json` | Memory dump guidance metadata |
| `cases/<ID>/artefacts/memory/memory_analysis.json` | Memory dump analysis results (strings, PE headers, patterns, risk) |
| `cases/<ID>/artefacts/memory/memory_analysis_manifest.json` | Memory analysis metadata |
| `cases/<ID>/logs/mde_memory_dump.parsed.json` | Normalised memory dump findings for downstream pipeline |
| `cases/<ID>/artefacts/browser_session/session_manifest.json` | Browser session investigation summary (DNS queries, TLS SNI, network stats) |
| `cases/<ID>/artefacts/browser_session/capture.pcap` | Raw packet capture from browser session |
| `cases/<ID>/artefacts/browser_session/network_log.json` | Parsed network telemetry — DNS queries, TCP connections, HTTP requests, TLS SNI |
| `cases/<ID>/artefacts/browser_session/dns_log.json` | DNS queries observed during session |
| `cases/<ID>/artefacts/browser_session/screenshot_final.png` | Final browser state screenshot |
| `cases/<ID>/logs/mde_browser_session.parsed.json` | Normalised browser session data for downstream pipeline (format: `pcap_capture`) |
| `cases/<ID>/logs/mde_browser_session.entities.json` | Extracted entities from browser session (IPs, domains, URLs) |
| `browser_sessions/<SID>/artefacts/session_manifest.json` | Caseless browser session summary (same layout as case-attached) |
| `browser_sessions/<SID>/artefacts/capture.pcap` | Caseless browser session pcap (readable via `read_browser_session_file`) |
| `browser_sessions/<SID>/artefacts/network_log.json` | Caseless browser session parsed network telemetry |
| `browser_sessions/<SID>/artefacts/screenshot_final.png` | Caseless browser session final screenshot |
| `cases/<ID>/artefacts/sandbox_detonation/sandbox_manifest.json` | Sandbox detonation session metadata, sample hashes, duration |
| `cases/<ID>/artefacts/sandbox_detonation/strace_log.json` | Parsed syscall trace (categorised: file/network/process/permission) |
| `cases/<ID>/artefacts/sandbox_detonation/network_capture.pcap` | Raw packet capture from sandbox |
| `cases/<ID>/artefacts/sandbox_detonation/network_log.json` | Parsed network activity (DNS, TCP, HTTP) |
| `cases/<ID>/artefacts/sandbox_detonation/honeypot_log.json` | Honeypot DNS/HTTP interactions |
| `cases/<ID>/artefacts/sandbox_detonation/filesystem_changes.json` | Before/after filesystem diff |
| `cases/<ID>/artefacts/sandbox_detonation/process_tree.json` | All spawned processes with cmdlines |
| `cases/<ID>/artefacts/sandbox_detonation/dns_queries.json` | DNS lookups attempted |
| `cases/<ID>/artefacts/sandbox_detonation/dropped_files/ ` | Files created by the malware |
| `cases/<ID>/artefacts/sandbox_detonation/strings_extracted.json` | Strings from stdout/stderr/dropped files |
| `cases/<ID>/artefacts/sandbox_detonation/interactive_log.json` | Commands sent via sandbox_exec (interactive mode) |
| `cases/<ID>/artefacts/sandbox_detonation/llm_analysis.json` | LLM behavioural analysis (MITRE mapping, risk score) |
| `cases/<ID>/logs/mde_sandbox_detonation.parsed.json` | Normalised sandbox log rows for downstream pipeline |
| `cases/<ID>/logs/mde_sandbox_detonation.entities.json` | Extracted entities (IPs, domains, URLs, hashes) |

## Threat Article Files

| File | Purpose |
|------|---------|
| `articles/YYYY-MM/ART-YYYYMMDD-NNNN/article.md` | Generated article summary (markdown) |
| `articles/YYYY-MM/ART-YYYYMMDD-NNNN/article_manifest.json` | Article metadata: title, category, analyst, sources, fingerprint, Confluence hooks |
| `registry/article_index.json` | Master index of all produced articles (dedup + listing) |
| `registry/.article_candidates_cache.json` | Transient cache of last `search_threat_articles` results for web UI |

## Batch Files

| File | Purpose |
|------|---------|
| `registry/batches/<batch_id>.json` | Batch submission metadata |
| `registry/batches/<batch_id>_results.json` | Collected batch results |

## Client Configuration Files

| File | Purpose |
|------|---------|
| `config/client_entities.json` | Client registry: name, platforms, aliases, notes (git-ignored) |
| `config/clients/<name>/knowledge.md` | Environment context: org, identity, network, security stack, FP patterns (git-ignored) |
| `config/clients/<name>/playbook.json` | Response playbook: escalation matrix, containment, remediation, contacts (git-ignored) |
| `config/clients/<name>/sentinel.md` | Sentinel reference: workspace ID, tables, column types, query patterns (git-ignored) |
| `registry/baselines/<name>.json` | Auto-built client baseline: IOC recurrence, attack types, dispositions |

## Notes

- `extract_iocs` scans **both** `cases/<case_id>/artefacts/` and `cases/<case_id>/logs/` — parsed log files land in `logs/`, not `artefacts/`.
- `generate_queries` accepts both `{"iocs": {"ipv4": [...]}}` (canonical dict) and `{"iocs": [{"type": "ipv4", "value": "..."}]}` (list). All other tools expect the canonical dict format.
