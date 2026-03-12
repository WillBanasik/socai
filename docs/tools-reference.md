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

`update_ioc_index()` merges the verdict summary into `registry/ioc_index.json` and prints a warning when IOCs have been seen in prior cases. Each index entry now includes:
- `tier` — `"global"` (public IPs, domains, hashes, CVEs, URLs, emails) or `"client"` (private IPs, bare hostnames), classified by `tools/ioc_classify.py`
- `case_clients` — `{case_id: client_name}` mapping, tracking which client each case belongs to

## IOC Tier Classification

`tools/ioc_classify.py` classifies IOCs into tiers for cross-case search boundary enforcement:

| IOC Type | Tier | Rationale |
|---|---|---|
| MD5, SHA1, SHA256, CVE, URL | Global | Always publicly observable |
| IPv4 (public) | Global | Routable on the internet |
| IPv4 (private/reserved) | Client | RFC 1918, loopback, link-local — internal only |
| Domain (FQDN with dot) | Global | Publicly resolvable |
| Domain (bare hostname) | Client | Internal name, no DNS context outside the org |
| Email | Global | External addresses (future: internal domain detection) |

**Usage:** Called by `score_verdicts.update_ioc_index()` during enrichment, and by `recall()` during cross-case search to filter results.

## Recall (Cross-Case Intelligence)

`tools/recall.py` searches prior cases and cached intelligence. Accepts an optional `caller_client` parameter for tier-aware filtering:

- **Global IOCs** — cross-client matches are returned, but case details (findings, reports, timeline) are redacted. Only IOC overlap + verdict is visible.
- **Client-scoped IOCs** — only same-client case matches are returned. Other clients' cases are invisible.
- **Case details** (findings, report excerpts, links, external refs) — only returned for same-client cases.

The MCP `recall_cases` tool automatically passes the active client from conversation boundary state.

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
- `--detonate` flag triggers local containerised detonation when cloud sandbox lookups are inconclusive (see pipeline step 6b)

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

`tools/fp_ticket.py` generates a concise False Positive closure comment (max 2 sentences):
- Identifies alerting platform from alert data structure (Sentinel, CrowdStrike, Defender, Entra, Cloud Apps) — or accepts `--platform` override
- Uses `request_clarification` Claude tool if platform cannot be identified
- **Live workspace query** (`--live-query`): enables read-only KQL against the alert's Log Analytics workspace via `az monitor log-analytics query`. Max 1 query per ticket, 50 rows each, 60s timeout.
- Output format: plain-text closure comment tailored to alert type (IOC-based, identity, endpoint, lateral movement, data access) — no markdown, no tuning suggestions
- Applies alias/dealias cycle
- **Auto-closes** the case with disposition `false_positive` on successful generation
- Outputs: `artefacts/fp_comms/fp_ticket.md` + `fp_ticket_manifest.json`

## PUP/PUA Report Generation

`tools/generate_pup_report.py` produces a lightweight investigation report for Potentially Unwanted Programs/Applications (adware, bundleware, browser hijackers, toolbars, grayware).

### Detection

`detect_pup(title, analyst_notes, alert_text, verdict_summary)` uses multi-signal detection:
- **Keyword matching** against `PUP_KEYWORDS` set (adware, bundleware, browser hijack, toolbar, grayware, junkware, etc.)
- **Verdict tag matching** against `PUP_VERDICT_TAGS` from enrichment results (pup, pua, adware, unwanted, low-risk, grayware)
- Returns `{"is_pup": bool, "signals": list, "confidence": str}`

### Report

`generate_pup_report(case_id)` builds context from case artefacts and calls the LLM with a PUP-specific system prompt. The report focuses on software identification, scope assessment, risk level, and removal steps — lighter than a full MDR report.

- Output: `cases/<ID>/reports/pup_report.md` + `pup_report_manifest.json`
- **Auto-closes** the case with disposition `pup_pua` on successful generation
- CLI: `python3 socai.py pup-report --case IV_CASE_001`

### Pipeline Integration

`classify_attack.py` detects PUP/PUA early via keyword matching. `chief.py` also checks post-enrichment verdicts via `detect_pup()`. When PUP is detected, the pipeline short-circuits: enrich → PUP report → done (skipping phishing detection, sandbox, correlation, campaign clustering, etc.). The case auto-closes at pipeline completion since the PUP report (the deliverable) is generated inline.

## Attack-Type Classification

`tools/classify_attack.py` provides deterministic attack-type classification for pipeline routing. No LLM call — pure keyword matching with weighted scoring plus input-shape heuristics.

### Attack Types

`phishing`, `malware`, `account_compromise`, `privilege_escalation`, `pup_pua`, `generic`

### Pipeline Profiles

Each attack type defines a `PIPELINE_PROFILES` entry specifying which steps to skip. For example, `phishing` skips sandbox; `malware` skips phishing detection; `account_compromise` skips domain investigation, phishing detection, and sandbox. `generic` skips nothing.

### Usage

`classify_attack_type(title, analyst_notes, tags, eml_paths, urls, zip_path, log_paths)` returns `{"attack_type", "confidence", "signals", "scores", "profile"}`. `should_skip_step(step_name, attack_type)` checks whether a pipeline step should be skipped.

Classification runs in `chief.py` after case creation (step 1c). Results are stored in `case_meta.json` as `attack_type` and `attack_type_confidence`.

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
| `data-exfiltration` | 3 (volume anomaly + DLP, cloud application access, network exfil indicators) | `target_upn`, `threshold_mb` (default 100), `lookback` (default 7d) |
| `lateral-movement` | 3 (lateral connections RDP/SMB/WMI, credential access, movement chain) | `source_host`, `destination_hosts` (comma-separated), `lookback` (default 7d) |

**API:** `list_playbooks()`, `load_playbook(id)`, `render_stage(pb, stage, params)`

**Chat integration:** The `load_kql_playbook` tool is available in both case-mode and session-mode chat. The LLM loads a playbook, substitutes parameters from the investigation context, and executes each stage via `run_kql`.

**Adding a playbook:** Create `config/kql_playbooks/<name>.kql` with frontmatter between `// ---` markers and stage blocks delimited by `// STAGE N — Title` headers.

## Sentinel Composite Queries

`tools/sentinel_queries.py` loads and renders composite KQL templates from `config/kql_playbooks/sentinel/`. Unlike the multi-stage playbooks above, composite queries produce a **single monolithic KQL string** with multiple `let` sections unioned together — designed for single-execution full-picture investigations using Sentinel-native tables only (OfficeActivity, SigninLogs, SecurityAlert, AlertEvidence).

**Available scenarios:**

| Scenario | Sections | Key focus |
|----------|----------|-----------|
| `mailbox-permission-change` | 9 | Permission grants, inbox rules, forwarding, delegate access, IP footprint, tenant-wide perms, sign-ins, OAuth, alerts |
| `suspicious-signin` | 8 | Interactive sign-ins, patterns, failed sign-ins, IP footprint, post-auth Exchange/SharePoint, directory changes, alerts |
| `inbox-rule-bec` | 8 | Inbox rules, forwarding, permissions, send activity, sign-ins, baseline, OAuth, alerts |
| `email-threat-zap` | 7 | Email alerts, alert evidence, post-delivery Exchange, file activity, sign-ins, IP spread, other alerts |
| `dlp-exfiltration` | 8 | DLP alerts, downloads, volume summary, external sharing, email exfil, OAuth, sign-ins, other alerts |
| `oauth-consent-grant` | 8 | Consent events, AAD activity, service principal sign-ins, Graph API activity, data access, sign-ins, IP activity, alerts |

**API:** `list_scenarios()`, `load_scenario(id)`, `render_query(id, upn=..., ip=..., ...)`

**Parameters:** All scenarios require `upn`. Optional: `ip`, `object_id`, `mailbox_id`, `additional_upns` (comma-separated), `lookback_hours` (default 24, max 720). Empty optional parameters produce valid KQL via `isnotempty()` guards.

**MCP integration:** The `generate_sentinel_query` tool (Tier 3, `sentinel:query` scope) wraps `render_query()`. The `classify_attack` tool includes a `sentinel_composite_queries` field recommending relevant scenarios per attack type. The automated flow is: `classify_attack` → `generate_sentinel_query` → `run_kql`.

**Adding a scenario:** Create `config/kql_playbooks/sentinel/<name>.kql` with frontmatter between `// ---` markers and a single query body using `let`/`union isfuzzy=true` pattern. Register in `_composite_map` in `mcp_server/tools.py` to link to attack types.

## LogScale Query Syntax

`config/logscale_syntax.md` is the authoritative CrowdStrike LogScale (Humio) query language reference. **All agents generating LogScale queries MUST consult this file** for correct syntax. Key pitfalls: OR binds tighter than AND (use parentheses), regex uses `/slashes/` not `=~`, no free-text search after aggregate, array params use `[square brackets]`.

## Structured Outputs

`tools/structured_llm.py` provides a `structured_call()` wrapper that uses Claude's JSON schema output validation instead of fragile `json.loads()` parsing or tool-use-as-schema patterns.

**Helper:** `structured_call(model, system, messages, output_schema, max_tokens, thinking=None)` → `(parsed_dict | None, usage_dict)`

**Schema compliance:** `_schema_for_model()` automatically adds `additionalProperties: false` to all object types in the generated JSON schema (required by the Anthropic API). This is applied recursively, covering nested objects, `$defs`, `anyOf`/`oneOf`/`allOf` combinators, and array items. Pydantic models in `tools/schemas.py` do not need to set this manually.

**Pydantic models** in `tools/schemas.py`:
- `ArticleSummary` — threat article generation
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
- `socai.py batch-submit --cases IV_CASE_001 IV_CASE_002 --tools mdr-report exec-summary` — prepare and submit
- `socai.py batch-status --batch-id <id>` / `batch-status --list` — check progress
- `socai.py batch-collect --batch-id <id>` — retrieve results and write artefacts

## Threat Articles

`tools/threat_articles.py` provides discovery and generation of 60-second-read threat intelligence articles for monthly SOC reporting, categorised as **ET** (Emerging Threat) or **EV** (Emerging Vulnerability).

**Public functions:**
- `fetch_candidates(days, max_candidates, category)` — fetches recent stories from configured RSS feeds, classifies as ET/EV, checks dedup index. Returns candidate dicts with `id`, `title`, `category`, `source_url`, `already_covered`.
- `generate_articles(candidates, analyst, case_id)` — clusters candidates by topic, fetches full content, generates structured article summaries via `ArticleSummary` schema. Writes to `articles/YYYY-MM/ART-YYYYMMDD-NNNN/`.
- `list_articles(month, category)` — lists previously produced articles from `registry/article_index.json`.

**Configuration:**
- `config/article_sources.json` — RSS feed list (extensible; `type` field supports future Confluence/API sources)
- `config/article_prompts.py` — LLM system prompts and user templates
- `config/settings.py` — `ARTICLES_DIR`, `ARTICLE_INDEX_FILE`, `SOCAI_MODEL_ARTICLES`

**Article output format:** Markdown with title, category, date, analyst, sources, anonymised body (~150-180 words), recommendations section, and defanged IOC/CVE list.

**Dedup:** Each topic gets a fingerprint (normalised title hash) stored in `registry/article_index.json`. Already-covered topics are flagged in candidate listings.

**CLI subcommands:**
- `socai.py articles` — interactive discovery workflow (fetch → select → generate)
- `socai.py articles-generate --urls URL1 URL2` — direct URL mode (skip discovery)
- `socai.py articles-list --month 2026-03` — list produced articles

**Chat tools:** `search_threat_articles`, `generate_threat_article`, `list_threat_articles` — available in both case-mode and session-mode. Search results are cached to disk (`registry/.article_candidates_cache.json`) so that `generate_threat_article` can reference candidates by **1-based index** (e.g. `candidate_ids: ["1", "3", "5"]`) without re-fetching RSS feeds. The cache survives server reloads.

**Future:** Confluence integration designed in (manifest includes `confluence_page_id`/`confluence_url` fields; source config supports `"type": "confluence"`).

## Velociraptor Collection Ingest

`tools/velociraptor_ingest.py` ingests Velociraptor offline collector exports and normalises VQL-specific field names into the schema that downstream tools already consume.

### Input Modes

| Mode | Input | Detection |
|------|-------|-----------|
| **A — Offline collector ZIP** | ZIP containing `collection_context.json`, `results/`, `uploads/` | Checks for `collection_context.json` or `results/` directory inside ZIP |
| **B — Individual VQL file** | Single `.json`, `.csv`, or `.jsonl` file | Direct file path |
| **C — Directory** | Directory of VQL result files | Also checks for nested `results/` and `uploads/` subdirectories |

### Artefact Normalisers (13 + generic fallback)

Each Velociraptor VQL artefact type has a dedicated normaliser that maps VQL-specific field names to the standard fields expected by `evtx_correlate`, `detect_anomalies`, `extract_iocs`, and `timeline_reconstruct`:

| VQL Artefact | Normaliser | Key mapped fields | Downstream tool |
|---|---|---|---|
| `Windows.EventLogs.Evtx` | `_norm_evtx` | TimeCreated, EventID, SourceIP, TargetUserName, LogonType, ProcessName, CommandLine | `evtx_correlate`, `detect_anomalies` |
| `Windows.System.Autoruns` | `_norm_autoruns` | TimeCreated, ProcessName, CommandLine, Category | `detect_anomalies` (first-seen) |
| `Windows.Network.Netstat` | `_norm_netstat` | SourceIP, DestIP, SourcePort, DestPort, ProcessName, Status | `extract_iocs`, `detect_anomalies` |
| `Windows.System.Pslist` / `Generic.System.Pstree` | `_norm_processes` | TimeCreated, ProcessName, CommandLine, Pid, Ppid, TargetUserName | `detect_anomalies`, `extract_iocs` |
| `Windows.System.Services` | `_norm_services` | ServiceName, CommandLine, StartMode, State | `detect_anomalies` |
| `Windows.System.TaskScheduler` | `_norm_tasks` | TaskName, CommandLine, TargetUserName | `detect_anomalies`, `evtx_correlate` |
| `Windows.Forensics.Prefetch` | `_norm_prefetch` | TimeCreated, ProcessName, RunCount | `timeline_reconstruct` |
| `Windows.Forensics.Shimcache` | `_norm_shimcache` | TimeCreated, ProcessName, Executed | `timeline_reconstruct` |
| `Windows.Forensics.Amcache` | `_norm_amcache` | TimeCreated, ProcessName, SHA1 | `timeline_reconstruct` |
| `Windows.Forensics.NTFS.MFT` | `_norm_mft` | TimeCreated, Modified, ProcessName (FullPath), Size | `timeline_reconstruct` |
| `Windows.Forensics.USN` | `_norm_usn` | TimeCreated, ProcessName (FullPath), Reason | `timeline_reconstruct` |
| `Windows.Sys.Users` | `_norm_users` | TargetUserName, Uid | Entity context |
| Unknown artefacts | `_norm_generic` | Pass-through with `_source: velociraptor` tag | `extract_iocs` (regex) |

Artefact name matching: exact match first, then prefix match (handles suffixes like `/Logs` or `/All`).

### Nested EVTX Flattening

VQL EVTX output often has nested `System` and `EventData` dicts. The `_flatten_event_data()` helper promotes nested fields to top level before normalisation, handling both `{"EventID": {"Value": 4625}}` and pre-flattened `{"EventID": 4625}` formats.

### Output

Writes to the standard `logs/` directory using the `parse_logs` schema so all downstream tools work without modification:

- `cases/<ID>/logs/vr_<artefact_name>.parsed.json` — contains `rows_sample` (all rows), `entities`, `entity_totals`, `row_count`, `format`
- `cases/<ID>/logs/vr_<artefact_name>.entities.json` — extracted entities (IPs, users, processes, commands, file paths, event IDs, timestamps)
- `cases/<ID>/artefacts/velociraptor/ingest_manifest.json` — processing summary
- `cases/<ID>/artefacts/velociraptor/collection_context.json` — copied from collector ZIP (if present)
- `cases/<ID>/artefacts/velociraptor/host_info.json` — from `Generic.Client.Info` (if present)
- `cases/<ID>/artefacts/velociraptor/uploads/` — raw files from collector `uploads/` directory (EVTX, MFT, prefetch, etc.)

### CLI

```bash
# Full pipeline: ingest → enrich → EVTX correlation → anomalies → timeline → report
python3 socai.py velociraptor /path/to/collection.zip --severity high

# Ingest only (parse + normalise, no analysis)
python3 socai.py velociraptor /path/to/results/ --case IV_CASE_001 --no-analyse

# Single VQL file
python3 socai.py velociraptor Windows.EventLogs.Evtx.json --case IV_CASE_001
```

### Chat Tool

`ingest_velociraptor` is available in both case-mode and session-mode chat. Upload Velociraptor exports via the sidebar, then the tool auto-processes them and optionally chains enrichment, EVTX correlation, anomaly detection, and timeline reconstruction.

## MDE Investigation Package Ingest

`tools/mde_ingest.py` ingests Microsoft Defender for Endpoint investigation packages and normalises MDE-specific formats into the same schema consumed by downstream tools (EVTX correlation, anomaly detection, timeline, IOC extraction).

### Input Modes

| Mode | Input | Detection |
|------|-------|-----------|
| **A — Investigation package ZIP** | ZIP from MDE "Collect investigation package" | Checks for 3+ known MDE folder names (Autoruns, Processes, Network Connections, etc.) |
| **B — Directory** | Extracted MDE package directory | Same folder name detection |

### Artefact Normalisers (13 + generic fallback)

Each MDE data type has a dedicated parser and normaliser:

| MDE Source | Normaliser | Key mapped fields |
|---|---|---|
| Processes (CSV) | `_norm_processes` | TimeCreated, ProcessName, CommandLine, Pid, Ppid, TargetUserName |
| Services (CSV) | `_norm_services` | ServiceName, CommandLine, StartMode, State |
| Scheduled Tasks (CSV) | `_norm_tasks` | TaskName, CommandLine, TargetUserName |
| Installed Programs (CSV) | `_norm_installed_programs` | DisplayName, Publisher, InstallDate |
| Netstat (TXT) | `_norm_netstat` | SourceIP, DestIP, SourcePort, DestPort, ProcessName, Status |
| ARP Cache (TXT) | `_norm_arp` | IP, MAC, InterfaceIndex |
| DNS Cache (TXT) | `_norm_dns_cache` | RecordName, RecordType, Data |
| Autoruns (registry TXT) | `_norm_autoruns` | Category, ProcessName, CommandLine |
| Prefetch (listing) | `_norm_prefetch` | ProcessName, Size, TimeCreated |
| SMB Sessions (TXT) | `_norm_smb_sessions` | TargetUserName, ClientIP, OpenFiles |
| System Info (TXT) | `_norm_system_info` | Hostname, OS, Domain, Patches |
| Users & Groups (TXT) | `_norm_users_groups` | TargetUserName, Groups |
| Temp directories | `_norm_temp_dirs` | FileName, Size, TimeCreated |

Text encoding handling: tries UTF-16, UTF-8-sig, UTF-8, Latin-1 via `_read_zip_text`.

### Entity Extraction

Extracts IPs, domains, MAC addresses, users, processes, commands, and file paths. Includes `domains` and `mac_addresses` fields in addition to the standard entity set.

### Output

- `cases/<ID>/artefacts/mde/ingest_manifest.json` — processing summary
- `cases/<ID>/logs/mde_*.parsed.json` — normalised data (same schema as `parse_logs`)
- `cases/<ID>/artefacts/mde/security_evtx/` — raw Security Event Log files
- `cases/<ID>/artefacts/mde/prefetch/` — raw Prefetch files
- `cases/<ID>/artefacts/mde/wd_support_logs/` — Windows Defender support logs

### CLI

```bash
# Full pipeline: ingest → enrich → EVTX correlation → anomalies → timeline → report
python3 socai.py mde-package /path/to/InvestigationPackage.zip --severity high

# Ingest only (parse + normalise, no analysis)
python3 socai.py mde-package /path/to/mde_export/ --case IV_CASE_001 --no-analyse
```

### Chat Tool

`ingest_mde_package` is available in both case-mode and session-mode chat. Upload MDE investigation packages via the sidebar, then the tool auto-processes them and optionally chains the enrichment pipeline.

## Process Memory Dump Guidance & Analysis

`tools/memory_guidance.py` provides two modes for working with process memory dumps collected via MDE Live Response.

### Guide Mode

`generate_dump_guidance(case_id, *, process_name, pid, alert_title, alert_description, hostname)` generates step-by-step instructions for an analyst to collect a process memory dump using ProcDump via MDE Live Response.

The guidance is contextual to the active alert — includes the specific process to target, the ProcDump command to run, what to look for, and how to handle the collected dump. Output: `artefacts/memory/dump_guidance.md` + `dump_guidance_manifest.json`.

### Analyse Mode

`analyse_memory_dump(dump_path, case_id)` performs read-only analysis of `.dmp`, `.dump`, `.raw`, or `.bin` files:

- **String extraction**: ASCII + UTF-16LE patterns (min length 6)
- **PE header detection**: scans for MZ headers with valid PE signatures
- **Suspicious pattern matching**: 28 signatures covering injection APIs (`VirtualAllocEx`, `WriteProcessMemory`), credential theft (`sekurlsa`, `mimikatz`), shellcode indicators, AMSI/ETW bypass, PowerShell patterns
- **DLL reference scanning**: flags suspicious DLLs (`clrjit.dll`, `amsi.dll`, `dbghelp.dll`, `samlib.dll`, etc.)
- **Risk scoring**: returns level (low/medium/high/critical) with numeric score and reasons

Output: `artefacts/memory/memory_analysis.json` + `memory_analysis_manifest.json` + normalised `logs/mde_memory_dump.parsed.json` for downstream pipeline.

### CLI

```bash
# Generate dump guidance
python3 socai.py memory-guide --case IV_CASE_001 --process lsass.exe --pid 672 \
    --alert "Credential dumping detected" --hostname WORKSTATION01

# Analyse a collected dump
python3 socai.py memory-analyse /path/to/lsass.dmp --case IV_CASE_001
```

### Chat Tools

`memory_dump_guide` and `analyse_memory_dump` are available in both case-mode and session-mode chat.

## Disposable Browser Sessions

`tools/browser_session.py` provides Docker-based disposable Chrome browser sessions with passive tcpdump network capture. Designed for manual phishing page investigation — the analyst drives the browser, not an automation framework. No CDP, no Selenium, no automation markers (`navigator.webdriver === false`).

This avoids analysis-evasion techniques used by sophisticated phishing kits and bot-protection services (Cloudflare Turnstile, DataDome) that detect automated browsers.

### Architecture

- **Container**: `socai-browser:latest` (custom image: Debian + Google Chrome + noVNC + tcpdump) with `--network=host`
- **noVNC**: analyst accesses the browser at `http://localhost:7900` (no password)
- **Chrome**: vanilla launch — no `--remote-debugging-port`, no automation flags
- **tcpdump**: passive packet capture on all interfaces

One session at a time (fixed noVNC port due to `--network=host`). Single-session enforcement: starting a second session gracefully stops the first (preserving telemetry).

### Network Telemetry

Telemetry is captured passively via tcpdump inside the container. On session stop, the pcap is copied to the host and parsed into structured data:

- **DNS queries** — all domain lookups from the browser
- **TCP connections** — SYN packets (connection initiation targets)
- **HTTP requests** — plaintext requests on port 80 (method, path, host)
- **TLS SNI** — Server Name Indication from TLS ClientHello (reveals HTTPS destination domains)

The DNS + TLS SNI combination provides visibility into which domains the browser connected to, even for HTTPS traffic where payloads are encrypted.

### Idle Timeout

`_IdleMonitor` polls the pcap file size inside the container every 2 seconds. When the pcap hasn't grown for `SOCAI_BROWSER_IDLE_TIMEOUT` seconds (default 300), the session auto-stops and preserves telemetry. A hard ceiling (`SOCAI_BROWSER_MAX_SESSION`, default 3600s) prevents sessions from running indefinitely.

### Session Lifecycle

1. `start_session(url, case_id)` — starts Docker container with Chrome navigating to URL, starts idle monitor
2. Analyst browses manually via noVNC at `http://localhost:7900`
3. `stop_session(session_id)` — copies pcap and screenshot from container, destroys container, parses pcap, writes artefacts

### Entity Extraction

`_extract_session_entities()` extracts domains (from DNS + TLS SNI + HTTP), IPs (from TCP connections + TLS SNI), and URLs (from HTTP requests).

### Output

- `artefacts/browser_session/session_manifest.json` — session summary (includes DNS queries, TLS SNI)
- `artefacts/browser_session/capture.pcap` — raw packet capture
- `artefacts/browser_session/network_log.json` — parsed DNS, TCP, HTTP, TLS SNI
- `artefacts/browser_session/dns_log.json` — DNS queries observed
- `artefacts/browser_session/screenshot_final.png` — final browser state (captured on container stop)
- `logs/mde_browser_session.parsed.json` — normalised data for downstream pipeline (format: `pcap_capture`)
- `logs/mde_browser_session.entities.json` — extracted entities (IPs, domains, URLs)

### CLI

```bash
# Start a session (blocks until Ctrl+C or idle timeout, then collects artefacts)
python3 socai.py browser-session "https://suspicious-site.com" --case IV_CASE_001

# Stop a specific session
python3 socai.py browser-stop <session-id>

# List all sessions
python3 socai.py browser-list
```

### MCP Tools

`start_browser_session`, `stop_browser_session`, `list_browser_sessions` — admin-scoped.

### Requirements

- Docker must be installed and accessible (the current user must be in the `docker` group or have sudo)
- `socai-browser:latest` image built: `docker build -t socai-browser:latest docker/browser/`
- Port 7900 must be available
- `tcpdump` installed on the host (for pcap parsing)

## Sandbox Detonation

`tools/sandbox_session.py` provides containerised malware sandbox detonation for dynamic analysis of suspicious files. Executes samples (ELF, scripts, Windows PE via Wine) inside a locked-down Docker container while capturing syscalls, network traffic, filesystem changes, and process creation.

### Architecture

Two Docker images:
- **socai-sandbox:latest** (~150 MB) — Debian slim with strace, ltrace, tcpdump, inotify-tools
- **socai-sandbox-wine:latest** (~450 MB) — extends Linux image with Wine for Windows PE execution

Container configuration:
- `--cap-drop=ALL` + `--cap-add=SYS_PTRACE,NET_RAW`
- `--security-opt=no-new-privileges`, `--read-only` root
- `--cpus=1.0`, `--memory=512m`, `--pids-limit=256`
- `--tmpfs /sandbox/workspace:exec,size=200m`, `--tmpfs /tmp:exec,size=100m`

### Network Modes

- **monitor** (default) — custom bridge network with honeypot DNS/HTTP inside container; malware reveals C2 domains without real egress
- **isolate** — `--network=none`; fully air-gapped

### Session Lifecycle

1. `start_session(sample_path, case_id)` — detects sample type, selects image, starts container
2. Container executes sample under strace with tcpdump + filesystem monitoring + honeypot
3. `wait_for_completion(session_id)` — blocks until container exits or timeout
4. `stop_session(session_id)` — copies telemetry, parses artefacts, extracts entities, tears down container

### Interactive Mode

`start_session(..., interactive=True)` keeps the container running for manual inspection:
- `exec_in_sandbox(session_id, command)` — runs `docker exec` as non-root `sandbox` user, 30s timeout
- Available as `sandbox_exec` chat tool for Claude to send commands into the running container

### Output

- `artefacts/sandbox_detonation/sandbox_manifest.json` — session metadata, sample hashes, duration
- `artefacts/sandbox_detonation/strace_log.json` — parsed syscall trace (categorised)
- `artefacts/sandbox_detonation/network_capture.pcap` — raw packet capture
- `artefacts/sandbox_detonation/network_log.json` — parsed DNS, TCP, HTTP
- `artefacts/sandbox_detonation/honeypot_log.json` — honeypot interactions
- `artefacts/sandbox_detonation/filesystem_changes.json` — before/after diff
- `artefacts/sandbox_detonation/process_tree.json` — spawned processes
- `artefacts/sandbox_detonation/dns_queries.json` — DNS lookups
- `artefacts/sandbox_detonation/dropped_files/` — files created by malware
- `artefacts/sandbox_detonation/llm_analysis.json` — LLM behavioural analysis
- `logs/mde_sandbox_detonation.parsed.json` — normalised log rows
- `logs/mde_sandbox_detonation.entities.json` — extracted entities

### CLI

```bash
python3 socai.py sandbox-session /path/to/sample --case IV_CASE_001
python3 socai.py sandbox-session /path/to/sample --case IV_CASE_001 --interactive
python3 socai.py sandbox-stop --session <session_id>
python3 socai.py sandbox-list
```

### Chat Tools

`start_sandbox_session`, `stop_sandbox_session`, `list_sandbox_sessions`, `sandbox_exec` are available in both case-mode and session-mode chat.

### Requirements

- Docker must be installed and accessible
- Build images first: `docker build -t socai-sandbox:latest -f docker/sandbox/Dockerfile docker/sandbox/`
- For Windows PE: `docker build -t socai-sandbox-wine:latest -f docker/sandbox/Dockerfile.wine docker/sandbox/`

See `docs/sandbox.md` for full setup guide and safety details.

## Analytical Guidelines

`config/analytical_guidelines.md` governs how LLM-assisted steps reason about detections. Loaded by `security_arch_review.py` and `generate_mdr_report.py`. Key principles: evidence-first analysis, mandatory alternative-explanation evaluation, co-occurrence != causation, precise determination language.
