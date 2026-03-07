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

## Per-Case Files

| File | Purpose |
|------|---------|
| `cases/<ID>/case_meta.json` | Metadata: status, severity, report path, IOC totals |
| `cases/<ID>/iocs/iocs.json` | Canonical IOC list; consumed by `enrich` and `correlate` |
| `cases/<ID>/chat_history_{email}.json` | Per-user LLM chat history (Anthropic API message format) |
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
| `cases/<ID>/artefacts/campaign/campaign_links.json` | Per-case campaign membership and shared IOCs |
| `cases/<ID>/artefacts/fp_comms/fp_ticket.md` | FP suppression ticket (platform-specific) |
| `cases/<ID>/artefacts/fp_comms/fp_ticket_manifest.json` | FP ticket generation metadata |
| `cases/<ID>/artefacts/timeline/timeline.json` | Forensic timeline with sorted events + LLM analysis |
| `cases/<ID>/artefacts/analysis/pe_analysis.json` | Deep PE file analysis (imports, entropy, packers) |
| `cases/<ID>/artefacts/yara/yara_results.json` | YARA scan match results |
| `cases/<ID>/artefacts/yara/generated_rules.yar` | LLM-generated case-specific YARA rules |
| `cases/<ID>/artefacts/evtx/evtx_correlation.json` | Windows Event Log attack chain detection |
| `cases/<ID>/artefacts/cve/cve_context.json` | CVE contextualisation (NVD, EPSS, KEV, OpenCTI) |
| `cases/<ID>/artefacts/executive_summary/executive_summary.md` | Plain-English executive summary |
| `cases/<ID>/artefacts/executive_summary/executive_summary_manifest.json` | Executive summary metadata |
| `cases/<ID>/artefacts/security_architecture/security_arch_review.md` | Security architecture review |
| `cases/<ID>/artefacts/security_architecture/security_arch_structured.json` | Structured analysis (TTPs, actions, risk) |
| `cases/<ID>/artefacts/security_architecture/security_arch_manifest.json` | Security arch review metadata |
| `cases/<ID>/artefacts/response_actions/response_actions.json` | Client-specific response plan (machine-readable) |
| `cases/<ID>/artefacts/response_actions/response_actions.md` | Formatted response plan (human-readable) |

## Session Files

| File | Purpose |
|------|---------|
| `sessions/<SID>/session_meta.json` | Session metadata: status, user, expiry, case_id link |
| `sessions/<SID>/history.json` | Conversation history (Anthropic API format) |
| `sessions/<SID>/context.json` | Accumulated IOCs, findings, telemetry summaries, disposition |
| `sessions/<SID>/uploads/` | Analyst-uploaded files |

## Batch Files

| File | Purpose |
|------|---------|
| `registry/batches/<batch_id>.json` | Batch submission metadata |
| `registry/batches/<batch_id>_results.json` | Collected batch results |

## Notes

- `extract_iocs` scans **both** `cases/<case_id>/artefacts/` and `cases/<case_id>/logs/` — parsed log files land in `logs/`, not `artefacts/`.
- `generate_queries` accepts both `{"iocs": {"ipv4": [...]}}` (canonical dict) and `{"iocs": [{"type": "ipv4", "value": "..."}]}` (list). All other tools expect the canonical dict format.
