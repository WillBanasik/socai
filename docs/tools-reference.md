# Tools Reference

## Web Capture

`tools/web_capture.py` exposes two public functions:
- `web_capture(url, case_id)` — single URL; launches and closes its own browser
- `web_capture_batch(urls, case_id)` — multiple URLs sharing one Playwright browser session (one browser launch, N page tabs); falls back to serial `web_capture()` if Playwright is unavailable

`DomainInvestigatorAgent` uses `web_capture_batch` automatically when `len(urls) > 1` and the Playwright backend is active.

Each capture produces: `page.html`, `page.txt`, `screenshot.png`, `redirect_chain.json`, `capture_manifest.json`. The manifest includes a `tls_certificate` object (for HTTPS URLs) with `subject_cn`, `issuer_cn`, `issuer_org`, `san`, `not_before`, `not_after`, `cert_age_days`, `days_remaining`, `self_signed`. Additional outputs when present:
- `xhr_responses.json` — JSON/text API responses intercepted during page load (useful for SPAs that fetch content via XHR; skips analytics/font/image noise)
- `hop_XX/` subdirectories — intermediate redirect hops captured in separate tabs

**SPA handling:** If `page.innerText` is empty after `networkidle`, Playwright waits `SOCAI_SPA_DWELL` ms and re-captures. This handles Ember/React/Vue apps that fetch content after the shell loads.

**Cloudflare detection:** After every capture, `_detect_cloudflare()` checks title, HTML, and body text for challenge/block signals. The `capture_manifest.json` gains `cloudflare_blocked: bool` and `cloudflare_challenge: str` fields. Challenge types: `js_challenge`, `managed_challenge` (Turnstile), `captcha` (hCaptcha), `block` (HTTP 403/1020). Blocked captures are surfaced as a dedicated section in the investigation report.

## Phishing Detection (Tiered)

`tools/detect_phishing_page.py` uses a **three-tier escalation model** — light checks first, deeper analysis only when determination is unclear.

### Tier 1 — Instant Checks (all pages)

- **Brand impersonation**: 17 known brands (Microsoft, Google, Apple, PayPal, DocuSign, Amazon, Facebook, LinkedIn, Dropbox, Adobe, DHL, FedEx, Netflix, Zoom, Salesforce, HMRC, NHS) matched against page title and body text on non-allowlisted domains
- **Credential harvest**: `<form>` elements with `<input type="password">` — flags external-domain form actions as high-confidence phishing
- **TLS signals**: self-signed certs, certs issued <7 days ago, expired certs
- **Domain age**: WHOISXML data — domains <30 days old boost confidence

Confidence levels: `high` (brand in title), `medium` (brand in body + login language). Body-only hits without login language are suppressed.

### Tier 2 — Structural Heuristics (all pages)

Runs on **every** captured page regardless of Tier 1 results. Produces a suspicion score (0.0–1.0) from weighted signals:

**Domain structure signals** (`_domain_structure_signals()`):
- Suspicious TLD (32 TLDs: `.zip`, `.tk`, `.xyz`, `.top`, etc.)
- High Shannon entropy in domain name (>3.5)
- High consonant ratio (>0.7) — detects random/generated domains
- Hyphen abuse (3+ hyphens)
- Brand name embedded in non-brand domain
- Excessive subdomains (>3 levels, with ccTLD awareness — `.co.uk`, `.com.au` etc. don't false-positive)
- Base64-encoded segments in URL path
- Very long URL (>200 chars)

**Redirect chain signals** (`_redirect_chain_signals()`):
- Many redirect hops (>3)
- URL shortener in chain (16 known shorteners)
- Multi-domain redirects
- JavaScript-based redirects

**Page content signals** (`_page_content_signals()`):
- Minimal visible text (<50 chars)
- Generic/missing page title
- Bait language patterns (prize, winner, selected, claim)
- Urgency language (immediately, expires, suspended, verify)
- Hidden iframes
- Data URIs in page
- JavaScript-heavy pages (>5KB script, <100 chars text)
- Cloudflare-blocked pages (escalated for further analysis)
- Password field without clear brand context

### Tier 3 — LLM Purpose Analysis (escalation only)

Pages with a suspicion score >= 0.4 (`_SUSPICION_ESCALATION_THRESHOLD`) that have no clear determination from Tiers 1–2 are escalated to an LLM purpose check.

`_llm_purpose_check()` asks Claude to assess whether the page has a **clear, legitimate purpose**. Uses the `PagePurposeAssessment` structured output schema. Pages with no clear purpose or deceptive intent generate findings.

**Philosophy**: Legitimate pages serve an obvious purpose. If a page has phishing hallmarks but no malicious IOCs or credential harvester, it doesn't mean it's clean — it means you haven't found it yet.

### LLM Vision Scan

When `ANTHROPIC_API_KEY` is set, `_llm_vision_check()` base64-encodes each `screenshot.png` and sends it to Claude Vision (up to 10 pages per run). The model returns a JSON verdict (`brand_impersonation`, `impersonated_brand`, `login_form`, `confidence`, `reasoning`). Vision findings are deduplicated against regex findings by `(brand, hostname)` and printed with a `LLM VISION` prefix. Always-trusted domains are skipped. Failures are caught silently.

### Output

Findings are written to `artefacts/phishing_detection/phishing_detection.json` with:
- `findings` — brand impersonation and credential harvest detections
- `form_analysis` — form action analysis per page
- `tls_signals` — certificate anomalies
- `heuristic_analysis` — per-page Tier 2 signal breakdown and suspicion scores
- `purpose_assessments` — Tier 3 LLM purpose analysis results
- `escalation_count` — number of pages escalated to Tier 3

To add a brand: append to `_BRANDS` in `detect_phishing_page.py` with `name`, `patterns` (compiled regexes), and `allowed` (base domain set).

## Enrichment Pipeline

`tools/enrich.py` uses a **tiered enrichment model** for IPv4 addresses to minimise API calls. All other IOC types use standard parallel enrichment via `ThreadPoolExecutor` (default 10 workers, `SOCAI_ENRICH_WORKERS`). Provider functions have the signature `(ioc: str, ioc_type: str) -> dict`. Results with `status: "ok"` are cached in `registry/enrichment_cache.json` with a configurable TTL (default 24 hours, `SOCAI_ENRICH_CACHE_TTL`; set to `0` to disable).

### IPv4 Tiered Enrichment

| Tier | Name | Providers | Purpose |
|------|------|-----------|---------|
| **0** | ASN pre-screen | Team Cymru DNS (free, no key) | Identify IPs owned by major cloud/CDN infra (Microsoft, AWS, Google, Cloudflare, Akamai CDN, Fastly, Apple, Meta). Tagged `infra_clean`, skip all enrichment. |
| **1** | Fast/free | AbuseIPDB, URLhaus, ThreatFox, OpenCTI | Quick abuse signal. If clean (no reports, no matches), stop here. |
| **2** | Deep OSINT | VirusTotal, Shodan, GreyNoise, ProxyCheck, Censys, OTX | Full investigation. Only for IPs that showed signal in Tier 1 (suspicious/malicious verdict, abuse reports > 0, threat matches) or returned no data. |

**Escalation logic:** An IP reaches Tier 2 only if `_ip_needs_deep_enrichment()` returns True — any fast provider flagged suspicious/malicious, AbuseIPDB reports > 0, or ThreatFox/URLhaus returned matches. Clean IPs after Tier 1 stop there.

**Infrastructure ASNs:** Defined in `KNOWN_INFRA_ASNS` (ASN → owner name) with keyword fallback via `_INFRA_ORG_KEYWORDS`. Hosting providers (Linode/Akamai hosting, DigitalOcean, OCI) are deliberately **not** skipped since attackers use them — only CDN-specific Akamai ASNs are filtered.

### Other IOC Types

Domains, URLs, hashes, emails, and CVEs use standard parallel enrichment — all registered providers for that type run concurrently.

### General

The `enrich()` function accepts an optional `skip_iocs: set[str]` parameter. When provided (typically from triage results), these IOCs are excluded from the enrichment work list.

The Intezer access token is fetched **once per `enrich()` call** and reused across all hash lookups via `functools.partial`. The `_PROVIDER_NAMES` dict maps function objects to canonical provider name strings — used for cache key lookup. When adding a new provider function, register it in `PROVIDERS`, `_PROVIDER_NAMES`, and (for IPv4) in `PROVIDERS_IP_FAST` or `PROVIDERS_IP_DEEP`.

## Verdict Scoring

`tools/score_verdicts.py` runs after `enrich()`. It groups enrichment results by IOC value, only counting results where `status == "ok"`, then applies:
- **malicious** — >=1 provider says malicious AND malicious_count >= suspicious_count
- **suspicious** — >=1 provider says suspicious AND malicious_count == 0
- **clean** — all responsive providers say clean
- **Confidence**: HIGH (>=3 providers, >66% agree), MEDIUM (>=2 providers, strict majority >50%), LOW (otherwise)

`update_ioc_index()` merges the verdict summary into `registry/ioc_index.json` and prints a warning when IOCs have been seen in prior cases.

## Triage

`tools/triage.py` performs pre-pipeline intelligence checks:
- Extracts domains from input URLs
- Checks `ioc_index.json` for known malicious/suspicious/clean IOCs
- Checks `enrichment_cache.json` for IOCs with 3+ fresh provider results (skip-enrichment candidates)
- Recommends severity escalation when known-malicious IOCs exceed `SOCAI_TRIAGE_ESCALATION_THRESHOLD` (default 1)

## Email Analysis

`tools/analyse_email.py` parses `.eml` files (RFC 5322) using Python stdlib `email`:
- Headers: From, Reply-To, Return-Path, Received chain, X-Mailer, Message-ID
- Authentication results: SPF/DKIM/DMARC parsed from Authentication-Results headers
- Spoofing detection: From/Reply-To domain mismatch, display name email mismatch, homoglyph domains (Cyrillic/Latin substitution map)
- URL extraction from HTML body (html.parser + regex fallback) and plain text
- Attachment extraction to `artefacts/email/attachments/` with SHA-256 hashes

## Campaign Clustering

`tools/campaign_cluster.py` groups cases sharing IOCs into campaigns:
- Loads `ioc_index.json` and builds case adjacency graph from shared IOCs
- Union-Find connected components (inline implementation)
- Filter: campaign requires 2+ cases AND `SOCAI_CAMPAIGN_MIN_IOCS` shared IOCs (default 2)
- **Verdict gate:** only IOCs with `malicious` or `suspicious` verdicts form campaign links
- **Noise suppression:** `_BENIGN_DOMAINS` and `_BENIGN_EXACT` sets exclude common benign infrastructure
- Campaign ID: `CAMP-YYYY-XXXXXX` (deterministic from sorted case set hash)
- Confidence: HIGH (3+ shared IOCs with malicious verdict), MEDIUM (2+ mixed), LOW (otherwise)

## Sandbox Analysis

`tools/sandbox_analyse.py` queries sandbox APIs for existing detonation reports by SHA256:
- Collects hashes from `artefacts/analysis/*.analysis.json`
- Three providers (parallel): Any.Run, Joe Sandbox, Hybrid Analysis
- Extracts: network IOCs, MITRE TTPs, C2 beacons
- Writes discovered IOCs to `artefacts/sandbox/sandbox_iocs.json` for downstream enrichment
- `--detonate` flag is accepted but **not yet implemented**

## Log Anomaly Detection

`tools/detect_anomalies.py` runs six behavioural detectors on parsed log data:
1. **Temporal** — logins outside business hours / weekends
2. **Impossible travel** — same user, different IPs within time window
3. **Brute force** — N+ failed logins from same source in window (Event ID 4625 patterns)
4. **First-seen entities** — processes/commands/paths not seen in prior cases
5. **Volume spikes** — events per IP/user exceeding mean + 2*stddev
6. **Lateral movement** — same user from 3+ distinct IPs in time window

Each finding gets severity (high/medium/low) via `_classify_severity()`.

## FP Ticket Generation

`tools/fp_ticket.py` generates platform-specific False Positive suppression tickets:
- Identifies alerting platform from alert data structure (Sentinel, CrowdStrike, Defender, Entra, Cloud Apps) — or accepts `--platform` override
- Uses `request_clarification` Claude tool if platform cannot be identified
- **Live workspace query** (`--live-query`): enables read-only KQL against the alert's Log Analytics workspace via `az monitor log-analytics query`. Max 5 queries per ticket, 50 rows each, 60s timeout.
- Applies alias/dealias cycle
- Outputs: `artefacts/fp_comms/fp_ticket.md` + `fp_ticket_manifest.json`

## Forensic Timeline Reconstruction

`tools/timeline_reconstruct.py` assembles a chronological event timeline from all case artefacts:
- Scans: `case_meta.json`, `capture_manifest.json`, `redirect_chain.json`, `email_analysis.json`, `enrichment.json`, `sandbox_results.json`, `triage_summary.json`, `anomaly_report.json`, `logs/*.parsed.json`, `ioc_index.json`
- Each event: `{timestamp, source, event_type, detail}`, sorted chronologically
- LLM step (optional): attack phase mapping (MITRE ATT&CK), dwell time gap analysis, key event identification, narrative summary
- Output: `artefacts/timeline/timeline.json`

## PE File Analysis

`tools/pe_analysis.py` performs deep static analysis on PE files (`.exe`, `.dll`, `.sys`, `.ocx`, `.scr`):
- Dependency: `pefile` (optional — graceful skip if missing)
- Per-file: Shannon entropy, section anomalies, import table with suspicious API flagging, export table, header anomalies, overlay detection, packer signatures, Rich header hash, file hashes, string extraction
- LLM step (optional): malicious likelihood, likely category, recommended next steps
- Output: `artefacts/analysis/pe_analysis.json`

## YARA Scanning

`tools/yara_scan.py` scans case files against YARA rules:
- Dependency: `yara-python` (optional)
- Built-in rules: SuspiciousPE, PowerShellObfuscation, C2Patterns, Base64PEHeader, CommonRATStrings
- External rules: `config/yara_rules/*.yar` and `*.yara`
- `--generate-rules`: LLM generates case-specific YARA rules, saves to `artefacts/yara/generated_rules.yar`, then re-scans
- Output: `artefacts/yara/yara_results.json`

## EVTX Attack Chain Correlation

`tools/evtx_correlate.py` detects Windows Event Log attack chains from parsed logs:
- Input: `logs/*.parsed.json`
- 7 chain detectors: brute force->success (4625->4624), lateral movement (4624 type 3->4688), persistence (4698/7045 near 4624), privilege escalation (4688 elevation, 4624->4728/4732), account manipulation (4720->4732), Kerberos abuse (4768/4769 RC4), pass-the-hash (4624 type 3 NTLM without 4776)
- LLM step (optional): attack narrative, MITRE ATT&CK mapping, attacker skill assessment, detection rule recommendations
- Output: `artefacts/evtx/evtx_correlation.json`

## CVE Contextualisation

`tools/cve_contextualise.py` enriches CVE identifiers found across case artefacts:
- CVE sources (regex scan): `iocs.json`, `enrichment.json`, `security_arch_review.md`, `reports/*.md`, `sandbox_results.json`
- Data providers (parallel): NVD API v2.0, EPSS API, CISA KEV catalog (cached 24h), OpenCTI (if key set)
- Priority score: `CVSS * 0.4 + EPSS_percentile * 0.3 + (0.3 if KEV else 0)`
- LLM step (optional): exploitability assessment, TTP relevance, patching priority
- Output: `artefacts/cve/cve_context.json`

## Executive Summary

`tools/executive_summary.py` generates a plain-English executive summary for non-technical leadership:
- Aliasing: applies alias/dealias cycle
- LLM produces 6 sections: What happened, Who affected, Risk rating (RAG), What's been done, Next steps, Business risk
- Constraints: no CVE IDs, no IPs, no hashes, no tool names, no unexplained acronyms, reading age 14, max 500 words
- Output: `artefacts/executive_summary/executive_summary.md` + manifest

## Security Architecture Review

`tools/security_arch_review.py` runs an LLM-assisted security architecture review after the main investigation pipeline. Produces a six-section markdown report: Threat Profile (MITRE ATT&CK), Control Gap Analysis, Microsoft Stack Recommendations, CrowdStrike Falcon Recommendations, Prioritised Remediation Table, Detection Engineering Notes.

**Claude API features used:**

| Feature | Behaviour |
|---------|-----------|
| **Prompt caching** | `_SYSTEM_PROMPT` cached with `cache_control: ephemeral` |
| **Adaptive thinking** | Enabled for high/critical severity — `{"type": "adaptive"}` with `output_config: {"effort": "high"}`. Works alongside tool use (no mutual exclusion). |
| **Structured tool use** | `record_structured_analysis` tool captures `ttps`, `top_actions`, `risk_rating` — used with both thinking and non-thinking paths |
| **Files API** | Uploads PDFs from `artefacts/web/**/document.pdf` via `client.beta.files.upload()` |
| **Parallel cluster subagents** | Network + file IOC clusters analysed concurrently when both present |

Outputs: `security_arch_review.md`, `security_arch_structured.json`, `security_arch_manifest.json`

## Response Actions

`tools/response_actions.py` generates a deterministic, client-specific response plan. No LLM call — purely rule-based resolution against the client playbook.

- **Input:** `case_meta.json` (severity, client), `verdict_summary.json` (malicious/suspicious IOCs), `config/clients/<client>.json` (playbook)
- **Skip conditions:** no client field on case, no playbook file, or 0 malicious + 0 suspicious IOCs
- **Resolution:** severity → priority mapping, crown jewel escalation, alert-name override, escalation matrix filtering
- **Output:** `artefacts/response_actions/response_actions.json` + `response_actions.md`
- **Pipeline step:** 13 (between CampaignAgent and auto-disposition)
- **MDR report integration:** `_build_context()` includes "Approved Response Actions" section when present

## Report Generation

`generate_report.py` loads all available artefact JSON files (all optional). Report section order after the executive summary:

1. Triage — Known IOCs Detected (if triage found known-malicious/suspicious)
2. Brand Impersonation Detected (if phishing_detection.json has findings)
3. Cloudflare-Blocked Captures (if any capture has cloudflare_blocked)
4. Email Analysis (if .eml was analysed)
5. Technical Narrative
6. Key IOCs
7. Threat Verdict Summary (per-IOC verdict table + Recurring IOCs)
8. Sandbox Analysis Results (if present)
9. Behavioural Anomalies (if anomaly detection ran)
10. Related Campaigns (if case shares IOCs)
11. Risk Explanation, Recommendations, What Was NOT Observed, Confidence, Artefact Index

Confidence score: +0.20 if malicious IOCs confirmed, +0.10 for suspicious-only.

## KQL Investigation Playbooks

`tools/kql_playbooks.py` loads parameterised, multi-stage KQL queries from `config/kql_playbooks/*.kql`. Each playbook contains expert-crafted queries for a common investigation scenario, with YAML-like frontmatter metadata and `{{param}}` placeholders. The phishing playbook supports multi-ID pivot: pass several NetworkMessageIds as comma-separated quoted strings and Stage 1 returns one row per recipient UPN with aggregated columns across all messages.

**Available playbooks:**

| Playbook | Stages | Key parameters |
|----------|--------|----------------|
| `phishing` | 4 (email core per UPN, post-delivery logon, URL scope + ZAP, attachment execution) | `target_ids` (comma-separated NetworkMessageIds — rendered into `dynamic([...])`); `url` (stage 3); `sha256` (stage 4) |
| `account-compromise` | 3 (sign-in detail + triage, Defender fallback, post-compromise activity) | `upn`, `ip` (optional), `lookback` (default 30d) |
| `ioc-hunt` | 2 (IOC presence sweep, conditional context pivot) | `iocs` (comma-separated), `lookback` (default 30d), `hit_table`/`hit_time`/`hit_device` (stage 2) |
| `malware-execution` | 3 (process ancestry + script content, file delivery chain, initial access vector) | `device_name`, `filename` (or `__NONE__`), `sha256` (or `__NONE__`), `lookback` (default 7d) |
| `privilege-escalation` | 3 (escalation event detail, actor legitimacy check, post-escalation activity) | `actor_upn`, `target_user` (or `__NONE__`), `target_group` (or `__NONE__`), `lookback` (default 14d) |

**API:** `list_playbooks()`, `load_playbook(id)`, `render_stage(pb, stage, params)`

**Chat integration:** The `load_kql_playbook` tool is available in both case-mode and session-mode chat. The LLM loads a playbook, substitutes parameters from the investigation context, and executes each stage via `run_kql`.

**Adding a playbook:** Create `config/kql_playbooks/<name>.kql` with frontmatter between `// ---` markers and stage blocks delimited by `// STAGE N — Title` headers.

## LogScale Query Syntax

`config/logscale_syntax.md` is the authoritative CrowdStrike LogScale (Humio) query language reference. **All agents generating LogScale queries MUST consult this file** for correct syntax. Key pitfalls: OR binds tighter than AND (use parentheses), regex uses `/slashes/` not `=~`, no free-text search after aggregate, array params use `[square brackets]`.

## Structured Outputs

`tools/structured_llm.py` provides a `structured_call()` wrapper that uses Claude's JSON schema output validation instead of fragile `json.loads()` parsing or tool-use-as-schema patterns.

**Helper:** `structured_call(model, system, messages, output_schema, max_tokens, thinking=None)` → `(parsed_dict | None, usage_dict)`

**Pydantic models** in `tools/schemas.py`:
- `BrandImpersonationResult` — phishing detection
- `ExecutiveSummary` — executive summary sections
- `TimelineAnalysis` — forensic timeline
- `CveAssessment` — CVE contextualisation
- `PeAssessment` — PE file analysis
- `EvtxAnalysis` — EVTX attack chain correlation
- `PagePurposeAssessment` — Tier 3 phishing purpose check

**Exception:** `security_arch_review.py` keeps the tool-use pattern since it produces both free-form markdown AND structured data in a single call.

## Batch API

`tools/batch.py` provides infrastructure for bulk LLM processing via the Claude Messages Batch API.

**Core functions:**
- `submit_batch(requests, batch_label)` — creates a batch, saves metadata to `registry/batches/<batch_id>.json`
- `poll_batch(batch_id, poll_interval, timeout)` — polls until `processing_status == "ended"`
- `collect_batch_results(batch_id)` — iterates results, saves to `registry/batches/<batch_id>_results.json`
- `dispatch_batch_results(results)` — parses `custom_id` (format `tool_name:case_id`), delegates to per-tool post-processors

**Batch-capable tools** expose `prepare_*_batch()` functions:
- `tools/generate_mdr_report.py` → `prepare_mdr_report_batch(case_id)`
- `tools/executive_summary.py` → `prepare_executive_summary_batch(case_id)`
- `tools/cve_contextualise.py` → `prepare_cve_batch(case_id, cve_data)`
- `tools/security_arch_review.py` → `prepare_secarch_batch(case_id)`

**CLI subcommands:**
- `socai.py batch-submit --cases C001 C002 --tools mdr-report exec-summary` — prepare and submit
- `socai.py batch-status --batch-id <id>` / `batch-status --list` — check progress
- `socai.py batch-collect --batch-id <id>` — retrieve results and write artefacts

## Analytical Guidelines

`config/analytical_guidelines.md` governs how LLM-assisted steps reason about detections. Loaded by `security_arch_review.py` and `generate_mdr_report.py`. Key principles: evidence-first analysis, mandatory alternative-explanation evaluation, co-occurrence != causation, precise determination language.
