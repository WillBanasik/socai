# Tools Reference

## Case Memory (Semantic Recall)

`tools/case_memory.py` provides BM25-ranked semantic search over all case content — complementing the exact IOC/keyword lookup in `tools/recall.py`.

**Functions:**

- `build_case_memory_index(include_open=True)` — walks all cases in the registry, extracts text (title, tags, IOCs, attack type, report excerpt, analyst notes), tokenises, and writes a BM25-ready index to `registry/case_memory.json`. Returns `{"status": "ok", "indexed": N}`.

- `search_case_memory(query, *, top_k=5, client_filter="")` — runs BM25 ranking over the index and returns the top-K most similar cases. Auto-builds the index if it doesn't exist. Results include `relevance_score` (BM25 score), title, client, severity, status, disposition, and tags.

**When to use:** After `recall_cases` (exact match), use `recall_semantic` to surface similar *context* — e.g. "DocuSign phishing" finds past DocuSign campaigns even if no single IOC overlaps.

**Index freshness:** Rebuilt every 6 hours by the background scheduler (`tools/scheduler.py`). Can be force-rebuilt via the `rebuild_case_memory` MCP tool.

**Implementation:** BM25 is implemented inline in `case_memory.py` — no external dependencies.

**Output:** `registry/case_memory.json` (token lists per case; not a case artefact — no audit entry).

---

## Client Behavioural Baselines

`tools/client_baseline.py` builds per-client profiles from historical case data, providing context when interpreting enrichment results for a client.

**Functions:**

- `build_client_baseline(client)` — scans all cases for the client and builds a profile covering: IOC recurrence (top-50 per type by frequency), confirmed malicious/suspicious IOCs from prior enrichments, attack type distribution, severity distribution, tag frequency, and disposition breakdown. Writes to `registry/baselines/{client_key}.json`.

- `get_client_baseline(client)` — returns the existing baseline or builds it on first call.

- `check_against_baseline(client, ioc_type, value)` — returns `{"known": bool, "seen": N, "cases": [...]}` for a specific IOC value, enabling enrichment context like "this IP appeared 4 times across client cases, always clean".

**Schema** (`registry/baselines/{client}.json`):
```json
{
  "client": "client_key",
  "built_at": "...",
  "case_count": 15,
  "iocs": {
    "ipv4": {"1.2.3.4": {"seen": 3, "cases": ["IV_CASE_001", ...]}},
    "domain": {...}
  },
  "known_malicious": [...],
  "known_suspicious": [...],
  "attack_types": {"phishing": 8, "account_compromise": 4},
  "severity_dist": {"high": 9, "medium": 5, ...},
  "tags": {"identity_protection": 6, ...},
  "dispositions": {"true_positive": 3, "benign_positive": 8, "false_positive": 4}
}
```

**Index freshness:** Rebuilt every 24 hours by the background scheduler for all configured clients.

---

## GeoIP (Local MaxMind)

`tools/geoip.py` provides fast offline IP geolocation via a local MaxMind GeoLite2-City database, avoiding API quota consumption for geographic context during enrichment.

**Functions:**

- `lookup_ip(ip)` — returns `{"available": True, "country": ..., "country_code": ..., "city": ..., "latitude": ..., "longitude": ..., "timezone": ...}`. Returns `{"available": False, "note": "..."}` gracefully when the database is absent or `geoip2` is not installed.

- `bulk_lookup(ips)` — returns `{ip: lookup_result}` for multiple IPs.

- `refresh_geoip_db(force=False)` — downloads the GeoLite2-City database (~70 MB compressed) from MaxMind. Skips if updated within the past 7 days unless `force=True`. Database stored at `registry/geoip/GeoLite2-City.mmdb`.

**Requirements:**
- `MAXMIND_LICENSE_KEY` in `.env` (free at maxmind.com/en/geolite2/signup)
- `pip install geoip2`

Both are optional — `lookup_ip` degrades gracefully with `{"available": False}` if either is missing.

**Index freshness:** Database refreshed weekly by the background scheduler.

---

## Background Scheduler

`tools/scheduler.py` runs periodic maintenance tasks in a daemon thread started at MCP server startup.

**Tasks:**

| Task | Interval | Purpose |
|---|---|---|
| `case_memory_rebuild` | 6 hours | Keep BM25 semantic index fresh as cases are created/closed |
| `geoip_refresh` | 7 days | Update MaxMind GeoLite2-City database |
| `baseline_refresh` | 24 hours | Rebuild per-client baselines for all configured clients |

**API:**
- `start_scheduler()` — starts the daemon thread. Idempotent (safe to call multiple times). Called automatically from MCP server lifespan (`mcp_server/server.py`).
- `stop_scheduler()` — signals the thread to stop at its next 60-second check interval. Called on server shutdown.

Each task run is logged as a `scheduler_task` event in `registry/mcp_server.jsonl`.

---

## Investigation Metrics

`tools/common.py` provides `log_metric()` for structured investigation metrics collection, enabling analyst performance comparison and operational insights.

**Function:**

- `log_metric(event, *, case_id="", **fields)` — append a structured metric event to `registry/metrics.jsonl`. Thread-safe via `_metrics_lock`. Same pattern as `audit()` and `log_error()`.

**Metric event types:**

| Event | Emitted by | Key fields |
|---|---|---|
| `case_phase_change` | `case_create()`, `index_case()` | phase, prev_status, analyst, client, severity |
| `enrichment_complete` | `enrich()` | duration_ms, total_iocs, enriched_iocs, ioc_coverage_pct, cache_hits, tiered stats per IOC type |
| `verdict_scored` | `score_verdicts()` | ioc_count, malicious/suspicious/clean counts, confidence_dist (HIGH/MEDIUM/LOW), conflicting_iocs |
| `report_saved` | `save_report_to_case()` | report_type, auto_closed, disposition, char_count, sections_present, completeness_pct |
| `investigation_summary` | `index_case()` (on close) | disposition, severity, attack_type, analyst, ioc_totals, durations (total/triage/investigation minutes), phase_timestamps |

**Phase timestamps:** Case metadata (`case_meta.json`) now includes a `phase_timestamps` sub-object that accumulates `created_at`, `triage_at`, `active_at`, `closed_at` as the case moves through lifecycle stages. `promote_case()` backfills `triage_at` from `created_at`.

**Query script:** `scripts/metrics_report.py` — standalone CLI for reading `metrics.jsonl`. Supports `--event`, `--case`, `--analyst`, `--since` filters, `--compare` for side-by-side analyst comparison, and `--json` for raw output.

**Workflow analytics:** `workflow_summary` events are auto-captured by the MCP session tracker (`mcp_server/usage.py`). Each event contains the full ordered tool sequence with per-step timing, categories, goals, and friction signals (unnecessary prerequisites, retries after error, long gaps, abandoned workflows, repeated lookups). Query via `scripts/workflow_report.py` — supports `--friction`, `--sequences`, `--tools`, `--trends`, `--json`.

**Tool taxonomy:** Every MCP tool is classified in `TOOL_TAXONOMY` (`mcp_server/usage.py`) by category (`lookup`, `enrichment`, `triage`, `analysis`, `delivery`, `admin`, `query`, `intel`, `sandbox`, `infra`) and goal (`quick_answer`, `investigate`, `deliver`, `maintain`). New tools must be registered here for workflow analytics.

**Output:** `registry/metrics.jsonl` (append-only JSONL; ~7 events per case + workflow_summary events on session expiry)

---

## Web Capture

`tools/web_capture.py` exposes two public functions:
- `web_capture(url, case_id)` — single URL; uses the persistent browser pool
- `web_capture_batch(urls, case_id)` — multiple URLs with concurrent page loads. Tries async Playwright first (up to 4 pages loading concurrently via `asyncio.gather` with semaphore), falls back to sync Playwright (sequential tabs via browser pool), then to serial `web_capture()` if Playwright is unavailable entirely. Handles both CLI (new event loop) and MCP server (existing event loop) contexts.

**Browser pool:** A module-level `_BrowserPool` singleton keeps a sync Playwright browser alive across captures. Each call gets a fresh browser *context* (isolated cookies/storage) from the shared browser. The browser is recycled after `SOCAI_BROWSER_POOL_MAX_USES` (default 50) context creations to prevent memory leaks. This eliminates the 2-3s Playwright startup cost per capture. The pool is thread-safe and cleaned up via `atexit`. The async path (`_async_web_capture_batch`) keeps its own browser lifecycle since async Playwright contexts are tied to their event loop.

`web_capture_batch` is used automatically when `len(urls) > 1` and the Playwright backend is active.

Each capture produces: `page.html`, `page.txt`, `screenshot.png`, `redirect_chain.json`, `capture_manifest.json`. The manifest includes a `tls_certificate` object (for HTTPS URLs) with `subject_cn`, `issuer_cn`, `issuer_org`, `san`, `not_before`, `not_after`, `cert_age_days`, `days_remaining`, `self_signed`. Additional outputs when present:
- `xhr_responses.json` — JSON/text API responses intercepted during page load (useful for SPAs that fetch content via XHR; skips analytics/font/image noise)
- `hop_XX/` subdirectories — intermediate redirect hops captured in separate tabs

**SPA handling:** If `page.innerText` is empty after `networkidle`, Playwright waits `SOCAI_SPA_DWELL` ms and re-captures. This handles Ember/React/Vue apps that fetch content after the shell loads.

**Auto-phishing detection:** The MCP `capture_urls` tool has `detect_phishing=True` by default. After URL capture completes, phishing detection runs automatically on the captured pages — brand impersonation, fake login forms, credential harvesting patterns. Set `detect_phishing=False` to skip (e.g. for non-phishing evidence collection).

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

### Tier 3 — LLM Purpose Analysis (via prompt)

Pages with a suspicion score >= 0.4 (`_SUSPICION_ESCALATION_THRESHOLD`) that have no clear determination from Tiers 1-2 are flagged for LLM assessment. The `write_phishing_verdict` MCP prompt loads the heuristic results and screenshots into the analyst's local Claude session for purpose analysis and brand impersonation assessment.

**Philosophy**: Legitimate pages serve an obvious purpose. If a page has phishing hallmarks but no malicious IOCs or credential harvester, it doesn't mean it's clean — it means you haven't found it yet.

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

`tools/enrich.py` uses a **tiered enrichment model** with **cross-type parallelism**. All four IOC type groups (IPv4, domain, URL, hash) run concurrently via `ThreadPoolExecutor(max_workers=4)`. Within each type group, the tier sequence remains sequential (Tier 1 results inform Tier 2 escalation decisions). Within each tier, individual provider calls run concurrently via a second `ThreadPoolExecutor` (default 25 workers, `SOCAI_ENRICH_WORKERS`). Provider functions have the signature `(ioc: str, ioc_type: str) -> dict`. Results with `status: "ok"` are cached in `registry/enrichment_cache.json` with a configurable TTL (default 24 hours, `SOCAI_ENRICH_CACHE_TTL`; set to `0` to disable).

### Depth Parameter

The `depth` parameter controls tier escalation behaviour:

| Depth | Behaviour | When to use |
|-------|-----------|-------------|
| `"auto"` | Smart tiering — Tier 1 first, escalate to Tier 2 on signal | Default. Most cases. |
| `"fast"` | Tier 1 only, never escalates to Tier 2 | Obvious FP/BP, bulk triage, low severity, quick refresh |
| `"full"` | All tiers for every IOC regardless of Tier 1 results | High-severity incident, targeted attack, novel IOCs, analyst requests deep-dive |

Exposed via the MCP `enrich_iocs` tool, `quick_enrich` tool, and `api/actions.extract_and_enrich()`.

### Caseless Enrichment (`quick_enrich`)

`quick_enrich(iocs, depth="auto")` enriches raw IOC values without a case. Uses the same tiered pipeline as case-bound enrichment. Returns verdicts + an `enrichment_id` persisted to `registry/quick_enrichments/`.

**RFC-1918 short-circuit:** Private IPs (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`) are tagged `verdict="private_internal"` instantly — zero provider calls, zero ASN lookups.

**Import into case:** Pass `enrichment_id` to `create_case(enrichment_id=...)` for auto-import, or call `import_enrichment(enrichment_id, case_id)` separately. Pre-computed verdicts are written directly (no re-scoring). The global IOC index is updated for cross-case recall.

### Triage-First Enrichment

`extract_and_enrich()` automatically runs two pre-enrichment optimisations before calling `enrich()`:

1. **Triage pass** — calls `triage()` to check the enrichment cache. IOCs with 3+ fresh cached provider results are added to the skip set.
2. **Client baseline pass** — loads the client's historical profile via `get_client_baseline()`. IOCs seen in 3+ prior cases for this client and never flagged as malicious are added to the skip set.

Both are best-effort — if either fails, enrichment proceeds normally. The combined skip set is passed to `enrich(skip_iocs=...)`.

### IPv4 Tiered Enrichment

| Tier | Name | Providers | Purpose |
|------|------|-----------|---------|
| **0** | ASN pre-screen | Team Cymru DNS (free, no key) | Identify IPs owned by major cloud/CDN infra (Microsoft, AWS, Google, Cloudflare, Akamai CDN, Fastly, Apple, Meta). Tagged `infra_clean`, skip all enrichment. |
| **1** | Fast/free | AbuseIPDB, URLhaus, ThreatFox, OpenCTI | Quick abuse signal. If clean (no reports, no matches), stop here. |
| **2** | Deep OSINT | VirusTotal, Shodan, GreyNoise, ProxyCheck, Censys, OTX | Full investigation. Only for IPs that showed signal in Tier 1 (suspicious/malicious verdict, abuse reports > 0, threat matches) or returned no data. |

**Escalation logic:** An IP reaches Tier 2 only if `_ip_needs_deep_enrichment()` returns True — any fast provider flagged suspicious/malicious, AbuseIPDB reports > 0, or ThreatFox/URLhaus returned matches. Clean IPs after Tier 1 stop there. Overridden by `depth="fast"` (never escalate) or `depth="full"` (always escalate).

**Infrastructure ASNs:** Defined in `KNOWN_INFRA_ASNS` (ASN → owner name) with keyword fallback via `_INFRA_ORG_KEYWORDS`. Hosting providers (Linode/Akamai hosting, DigitalOcean, OCI) are deliberately **not** skipped since attackers use them — only CDN-specific Akamai ASNs are filtered.

### Domain Tiered Enrichment

| Tier | Providers | Purpose |
|------|-----------|---------|
| **1** | URLhaus, ThreatFox, OpenCTI, WhoisXML, PhishTank | Quick threat intel + domain age + known-phishing check |
| **2** | VirusTotal, URLScan, Censys, OTX, crt.sh | Full investigation + CT log subdomain discovery |

Escalation: newly registered domains (< 30 days), any malicious/suspicious verdict, or no data.

### URL Tiered Enrichment

| Tier | Providers | Purpose |
|------|-----------|---------|
| **1** | URLhaus, ThreatFox, OpenCTI, PhishTank | Quick blocklist + known-phishing check |
| **2** | VirusTotal, URLScan, OTX | Full scan + screenshot |

### Hash Tiered Enrichment

| Tier | Providers | Purpose |
|------|-----------|---------|
| **1** | MalwareBazaar, ThreatFox, OpenCTI | Quick malware DB lookup |
| **2** | VirusTotal, Intezer, OTX (+ Hybrid Analysis for SHA256) | Full analysis + genetic classification |

Hash escalation is **inverted**: unknown files (not in any malware DB) escalate because absence of data is suspicious for a file hash. Known-clean files in fast DBs stop at Tier 1.

### Other IOC Types

Emails (EmailRep, OpenCTI) and CVEs (OpenCTI) use standard parallel enrichment — all registered providers for that type run concurrently. These run after the cross-type parallel block completes.

### General

The Intezer access token is fetched **once per `enrich()` call** and reused across all hash lookups via `functools.partial`. The `_PROVIDER_NAMES` dict maps function objects to canonical provider name strings — used for cache key lookup. When adding a new provider function, register it in `PROVIDERS`, `_PROVIDER_NAMES`, and in the appropriate tier list (`PROVIDERS_*_FAST` / `PROVIDERS_*_DEEP`).

## Dark Web Intelligence

`tools/darkweb.py` provides agent-invocable dark web lookups (NOT automatic enrichment). The agent decides when to invoke these during investigations.

### MCP Tools

| Tool | Trigger phrases | IOC types | Provider |
|------|----------------|-----------|----------|
| `hudsonrock_lookup` | "check Hudson Rock", "infostealer exposure", "stolen credentials" | email, domain, IP | Hudson Rock Cavalier API (free tier) |
| `xposed_breach_check` | "check for breaches", "breach exposure", "has this email been breached" | email, domain | XposedOrNot API (keyless for email) |
| `ahmia_darkweb_search` | "search the dark web", "search onion sites", "dark web search" | any keyword/IOC | Ahmia.fi (no auth, no Tor) |
| `intelx_search_tool` | "search Intelligence X", "search pastes and leaks", "deep web search" | email, domain, IP, URL, phone | Intelligence X (free tier) |
| `parse_stealer_logs_tool` | "parse stealer logs", "analyse infostealer dump" | file archives | lexfo/stealer-parser |
| `darkweb_exposure_summary` | "dark web exposure summary", "full dark web check" | all (auto-extracts from case IOCs) | All providers |

### Credential Sanitisation

Hudson Rock returns credential data including passwords. All passwords are automatically redacted at the tool layer (`_redact_credentials`) before results are saved to artefacts or returned to the agent. Passwords appear as `[REDACTED-Nchars]`. Email local-parts in credential entries are truncated (`j***@example.com`). The full unredacted response is never stored or returned.

### Artefacts

Results are saved to `cases/<ID>/artefacts/darkweb/`:
- `hudsonrock_results.json` — infostealer compromise data (redacted)
- `xposedornot_results.json` — breach exposure data
- `darkweb_summary.json` — aggregated exposure summary
- `stealer_logs/parsed.json` — parsed infostealer log output (redacted)

### Configuration

| Env var | Required | Notes |
|---------|----------|-------|
| `HUDSONROCK_API_KEY` | For Hudson Rock tools | Free tier at hudsonrock.com/free-api-key |
| `XPOSEDORNOT_API_KEY` | For domain breach checks only | Email breach checks are keyless |
| `INTELX_API_KEY` | For Intelligence X (recommended) | Free tier at intelx.io/account?tab=developer; public API (very limited) used if unset |

Ahmia.fi requires no API key or configuration.

### Reference Material

- [deepdarkCTI](https://github.com/fastfire/deepdarkCTI) — curated dark web CTI source lists
- [Credential monitoring comparison](https://github.com/infostealers-stats/Credential-and-breach-monitoring) — breach intel vendor comparison
- [stealer-parser](https://github.com/lexfo/stealer-parser) — Python infostealer log parser (optional dependency)

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

Triage is automatically called by `extract_and_enrich()` before enrichment. Its `skip_enrichment_iocs` list is combined with client baseline filtering and passed to `enrich(skip_iocs=...)` to reduce unnecessary API calls. The client baseline (`get_client_baseline()`) adds IOCs that are routine for the client (seen in 3+ prior cases, never flagged malicious) to the skip set.

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

`tools/fp_ticket.py` collects case context for False Positive closure comments:
- Identifies alerting platform from alert data structure (Sentinel, CrowdStrike, Defender, Entra, Cloud Apps) — or accepts `--platform` override
- **Live workspace query** (`--live-query`): enables read-only KQL against the alert's Log Analytics workspace via `az monitor log-analytics query`. Max 1 query per ticket, 50 rows each, 60s timeout.
- Output format: plain-text closure comment (max 2 sentences) tailored to alert type (IOC-based, identity, endpoint, lateral movement, data access) — no markdown, no tuning suggestions
- **Auto-closes** the case with disposition `false_positive` on successful save
- Use the `write_fp_closure` prompt followed by `save_report` to generate and persist
- Outputs: `artefacts/fp_comms/fp_ticket.md` + `fp_ticket_manifest.json`

## PUP/PUA Report Generation

`tools/generate_pup_report.py` produces a lightweight investigation report for Potentially Unwanted Programs/Applications (adware, bundleware, browser hijackers, toolbars, grayware).

### Detection

`detect_pup(title, analyst_notes, alert_text, verdict_summary)` uses multi-signal detection:
- **Keyword matching** against `PUP_KEYWORDS` set (adware, bundleware, browser hijack, toolbar, grayware, junkware, etc.)
- **Verdict tag matching** against `PUP_VERDICT_TAGS` from enrichment results (pup, pua, adware, unwanted, low-risk, grayware)
- Returns `{"is_pup": bool, "signals": list, "confidence": str}`

### Report

`generate_pup_report(case_id)` collects context from case artefacts for a PUP-specific report. The report focuses on software identification, scope assessment, risk level, and removal steps — lighter than a full MDR report. Use the `write_pup_report` prompt followed by `save_report` to generate and persist.

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

Classification runs early in the investigation (before case creation). Results are stored in `case_meta.json` as `attack_type` and `attack_type_confidence` once a case exists.

## Forensic Timeline Reconstruction

`tools/timeline_reconstruct.py` assembles a chronological event timeline from all case artefacts:
- Scans: `case_meta.json`, `capture_manifest.json`, `redirect_chain.json`, `email_analysis.json`, `enrichment.json`, `sandbox_results.json`, `triage_summary.json`, `anomaly_report.json`, `logs/*.parsed.json`, `ioc_index.json`
- Each event: `{timestamp, source, event_type, detail}`, sorted chronologically
- Analysis via prompt: use `write_timeline` prompt for attack phase mapping (MITRE ATT&CK), dwell time gap analysis, key event identification, narrative summary
- Output: `artefacts/timeline/timeline.json`

## PE File Analysis

`tools/pe_analysis.py` performs deep static analysis on PE files (`.exe`, `.dll`, `.sys`, `.ocx`, `.scr`):
- Dependency: `pefile` (optional — graceful skip if missing)
- Per-file: Shannon entropy, section anomalies, import table with suspicious API flagging, export table, header anomalies, overlay detection, packer signatures, Rich header hash, file hashes, string extraction
- Analysis via prompt: use `write_pe_verdict` prompt for malicious likelihood, likely category, recommended next steps
- Output: `artefacts/analysis/pe_analysis.json`

**Auto-YARA scanning:** The MCP `analyse_pe` tool has `run_yara=True` by default. YARA scanning runs automatically after PE analysis — both results returned in a single tool call. Set `run_yara=False` to skip. Set `generate_yara_rules=True` to create custom rules from PE findings.

## YARA Scanning

`tools/yara_scan.py` scans case files against YARA rules:
- Dependency: `yara-python` (optional)
- Built-in rules: SuspiciousPE, PowerShellObfuscation, C2Patterns, Base64PEHeader, CommonRATStrings
- External rules: `config/yara_rules/*.yar` and `*.yara`
- Output: `artefacts/yara/yara_results.json`
- Also runs automatically via `analyse_pe(run_yara=True)` — separate `yara_scan` call only needed if skipped during PE analysis

## EVTX Attack Chain Correlation

`tools/evtx_correlate.py` detects Windows Event Log attack chains from parsed logs:
- Input: `logs/*.parsed.json`
- 7 chain detectors: brute force->success (4625->4624), lateral movement (4624 type 3->4688), persistence (4698/7045 near 4624), privilege escalation (4688 elevation, 4624->4728/4732), account manipulation (4720->4732), Kerberos abuse (4768/4769 RC4), pass-the-hash (4624 type 3 NTLM without 4776)
- Analysis via prompt: use `write_evtx_analysis` prompt for attack narrative, MITRE ATT&CK mapping, attacker skill assessment, detection rule recommendations
- Output: `artefacts/evtx/evtx_correlation.json`

## CVE Contextualisation

`tools/cve_contextualise.py` enriches CVE identifiers found across case artefacts:
- CVE sources (regex scan): `iocs.json`, `enrichment.json`, `security_arch_review.md`, `reports/*.md`, `sandbox_results.json`
- Data providers (parallel): NVD API v2.0, EPSS API, CISA KEV catalog (cached 24h), OpenCTI (if key set)
- Priority score: `CVSS * 0.4 + EPSS_percentile * 0.3 + (0.3 if KEV else 0)`
- Analysis via prompt: use `write_cve_context` prompt for exploitability assessment, TTP relevance, patching priority
- Output: `artefacts/cve/cve_context.json`

## Executive Summary

`tools/executive_summary.py` collects case context for a plain-English executive summary for non-technical leadership:
- 6 sections: What happened, Who affected, Risk rating (RAG), What's been done, Next steps, Business risk
- Constraints: no CVE IDs, no IPs, no hashes, no tool names, no unexplained acronyms, reading age 14, max 500 words
- Use the `write_executive_summary` prompt followed by `save_report` to generate and persist
- Output: `artefacts/executive_summary/executive_summary.md` + manifest

## Security Architecture Review

`tools/security_arch_review.py` collects case context for a security architecture review. Produces a six-section markdown report: Threat Profile (MITRE ATT&CK), Control Gap Analysis, Microsoft Stack Recommendations, CrowdStrike Falcon Recommendations, Prioritised Remediation Table, Detection Engineering Notes.

Use the `write_security_arch_review` prompt followed by `save_report` to generate and persist. The local Claude session has the full investigation context for better analysis.

Outputs: `security_arch_review.md`, `security_arch_structured.json`, `security_arch_manifest.json`

## Response Actions

`tools/response_actions.py` generates a deterministic, client-specific response plan. No LLM call — purely rule-based resolution against the client playbook.

- **Input:** `case_meta.json` (severity, client), `verdict_summary.json` (malicious/suspicious IOCs), `config/clients/<client>/playbook.json` (playbook; also checks legacy flat layout `<client>.json`)
- **Skip conditions:** no client field on case, no playbook file, or 0 malicious + 0 suspicious IOCs
- **Crown jewel matching:** supports wildcard patterns (e.g. `"karel*chudej*"`) via `fnmatch`
- **Multi-environment playbooks:** clients with multiple environments (e.g. Sentinel/MDE, CrowdStrike workstations, OT) use an `environments` map and optional `escalation_matrix_ot` for environment-specific escalation rules
- **Resolution:** severity → priority mapping, crown jewel escalation, alert-name override, escalation matrix filtering
- **Output:** `artefacts/response_actions/response_actions.json` + `response_actions.md`
- **Pipeline step:** 13 (between CampaignAgent and auto-disposition)
- **MDR report integration:** `_build_context()` includes "Approved Response Actions" section when present

## Report Generation

`generate_report.py` collects all available artefact JSON files (all optional) as context for report generation. Use the `write_mdr_report` prompt followed by `save_report` to generate and persist. Report section order after the executive summary:

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

## LogScale / NGSIEM Query Reference

### `load_ngsiem_reference` tool

The `load_ngsiem_reference` MCP tool loads CQL/LogScale syntax reference material on demand. Call it **before writing any CrowdStrike/NGSIEM query**. Sections:

- `"rules"` — authoring conventions, anti-patterns, tag-based source filtering, ECS field naming, worked examples
- `"columns"` — field schema per connector (ECS + vendor fields)
- `"grammar"` — all 194 CQL function signatures (large — request only when needed)
- `"syntax"` — general CQL syntax reference (operators, precedence, 18 pitfalls)

Default: `["rules", "syntax"]`. Add `"columns"` when building queries for a specific log source.

### Reference files

Four files in `config/` back the tool and are also available as MCP resources:

| Resource | File | Contents |
|----------|------|----------|
| `socai://logscale-syntax` | `config/logscale_syntax.md` | General CQL syntax: operators, field assignment, conditionals, joins, regex, tag field rules, 18 pitfalls |
| `socai://ngsiem-rules` | `config/ngsiem/ngsiem_rules.md` | Detection rule authoring: pipe-per-line, tag-based source filtering (`#Vendor` + `#event.module`), ECS field naming, proven patterns, 13 anti-patterns, DaC template, worked examples |
| `socai://ngsiem-columns` | `config/ngsiem/ngsiem_columns.yaml` | Field schema per connector (24 connectors): ECS + vendor fields for Fortinet, Azure AD, Windows, ClearPass, Check Point, Cisco, Darktrace, Delinea, Netskope, etc. |
| `socai://cql-grammar` | `config/ngsiem/cql_grammar.json` | Complete CQL function grammar: 194 functions across 12 categories with signatures and docs |

### Contextual CrowdStrike queries

`generate_queries` now produces contextual investigation queries alongside IOC-hunt queries when CrowdStrike pivot data is available in the case:

| Query | Pivot field | Template |
|-------|------------|----------|
| Process tree | `aid` + `TreeId` | ProcessRollup2 filtered by TreeId, sorted chronologically |
| Child processes | `aid` + `ParentProcessId` | ProcessRollup2 filtered by parent PID |
| DNS requests | `hostname` or `aid` | DnsRequest with domain, IP4Records, requesting process |
| Network connections | `hostname` or `aid` | NetworkConnectIP4/IP6 with remote IP, port, process |
| File writes | `hostname` or `aid` | NewExecutableWritten, ExecutableDeleted, RansomwareOpenFile |
| Detections | `hostname` or `aid` | DetectionSummaryEvent with tactic, technique, severity |
| User logons | `username` | UserLogon with logon type, domain, remote IP |

Pivot values are extracted from case metadata and evidence text automatically via `_extract_cs_pivots()`.

## Output Schemas

`tools/schemas.py` defines Pydantic models that describe the expected structure of analysis outputs. These are used as reference by MCP prompts to guide the local Claude agent's output format:
- `ArticleSummary` — threat article generation
- `BrandImpersonationResult` — phishing detection
- `ExecutiveSummary` — executive summary sections
- `TimelineAnalysis` — forensic timeline
- `CveAssessment` — CVE contextualisation
- `PeAssessment` — PE file analysis
- `EvtxAnalysis` — EVTX attack chain correlation
- `PagePurposeAssessment` — Tier 3 phishing purpose check

## Threat Articles

`tools/threat_articles.py` provides discovery and generation of 60-second-read threat intelligence articles for monthly SOC reporting, categorised as **ET** (Emerging Threat) or **EV** (Emerging Vulnerability).

**Public functions:**
- `fetch_candidates(days, max_candidates, category)` — fetches recent stories from configured RSS feeds, classifies as ET/EV, checks dedup index. Returns candidate dicts with `id`, `title`, `category`, `source_url`, `already_covered`.
- `generate_articles(candidates, analyst, case_id)` — clusters candidates by topic, fetches full content. Use the `write_threat_article` prompt followed by `save_threat_article` to generate and persist. Writes to `articles/YYYY-MM/ART-YYYYMMDD-NNNN/`.
- `list_articles(month, category)` — lists previously produced articles from `registry/article_index.json`.

**Configuration:**
- `config/article_sources.json` — RSS feed list (extensible; `type` field supports future Confluence/API sources)
- `config/article_prompts.py` — prompt templates for article generation
- `config/settings.py` — `ARTICLES_DIR`, `ARTICLE_INDEX_FILE`

**Article output format:** Markdown with title, category, date, analyst, sources, anonymised body (~150-180 words), recommendations section, and defanged IOC/CVE list.

**Dedup:** Three-store dedup via `check_topic_dedup(title)`:
1. **Local index** — exact fingerprint match against `registry/article_index.json`
2. **Confluence** — stemmed 40% token overlap against recent page titles (returns `page_id` on match)
3. **OpenCTI** — stemmed 40% token overlap against recent report titles

Already-covered topics are flagged in candidate listings. `save_article()` runs the full dedup check before saving (override with `force=True`).

**CLI subcommands:**
- `socai.py articles` — interactive discovery workflow (fetch → select → generate)
- `socai.py articles-generate --urls URL1 URL2` — direct URL mode (skip discovery)
- `socai.py articles-list --month 2026-03` — list produced articles

**Chat tools:** `search_threat_articles`, `generate_threat_article`, `list_threat_articles`, `check_article_dedup`, `save_threat_article` — available in both case-mode and session-mode. Search results are cached to disk (`registry/.article_candidates_cache.json`) so that `generate_threat_article` can reference candidates by **1-based index** (e.g. `candidate_ids: ["1", "3", "5"]`) without re-fetching RSS feeds. The cache survives server reloads. `check_article_dedup` runs the three-store dedup check and returns match details (including Confluence `page_id`) so the analyst can verify before writing.

**Confluence integration:** Manifest includes `confluence_page_id`/`confluence_url` fields for tracking published articles. Source config supports `"type": "confluence"` for future feed sources. CQL search (`title ~`) used for dedup and direct page lookup.

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

`ingest_velociraptor` is available in both case-mode and session-mode chat. Upload Velociraptor exports via the sidebar, then the tool auto-processes them and optionally chains enrichment, EVTX correlation, anomaly detection, and timeline reconstruction. Optional analysis steps (EVTX correlation, anomaly detection, timeline reconstruction) are individually error-resilient — failures are logged via `log_error()` to `registry/error_log.jsonl` without aborting the pipeline.

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

`ingest_mde_package` is available in both case-mode and session-mode chat. Upload MDE investigation packages via the sidebar, then the tool auto-processes them and optionally chains the enrichment pipeline. Optional analysis steps (EVTX correlation, anomaly detection, timeline reconstruction) are individually error-resilient — failures are logged via `log_error()` to `registry/error_log.jsonl` without aborting the pipeline.

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

`memory_dump_guide` and `analyse_memory_dump` are available in both case-mode and session-mode chat. File read failures in guidance retrieval are logged via `log_error()` rather than silently swallowed.

## Disposable Browser Sessions

`tools/browser_session.py` provides Docker-based disposable Chrome browser sessions with passive tcpdump network capture. Designed for manual phishing page investigation — the analyst drives the browser, not an automation framework. No CDP, no Selenium, no automation markers (`navigator.webdriver === false`).

This avoids analysis-evasion techniques used by sophisticated phishing kits and bot-protection services (Cloudflare Turnstile, DataDome) that detect automated browsers.

### Architecture

- **Container**: `socai-browser:latest` (custom image: Debian + Google Chrome + noVNC + tcpdump) with `--network=host`
- **noVNC**: analyst accesses the browser at `http://127.0.0.1:7900` (no password)
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

### Auto-Stop Triggers

The `_IdleMonitor` runs a background thread that polls every 2 seconds and fires auto-stop on any of three conditions:

| Trigger | Env Var | Default | Description |
|---------|---------|---------|-------------|
| **Network idle** | `SOCAI_BROWSER_IDLE_TIMEOUT` | `300` | Pcap file hasn't grown for N seconds |
| **Viewer disconnected** | `SOCAI_BROWSER_DISCONNECT_GRACE` | `15` | All noVNC tabs closed for N seconds (grace period allows reconnects) |
| **Max duration** | `SOCAI_BROWSER_MAX_SESSION` | `3600` | Hard session ceiling |

The disconnect detection is fail-open: if the check errors, the session stays alive. The grace timer only starts after at least one viewer has connected then disconnected.

### Session Lifecycle

1. `start_session(url, case_id)` — starts Docker container with Chrome navigating to URL, starts idle monitor
2. Analyst browses manually via noVNC at `http://127.0.0.1:7900`
3. Session ends via: closing the noVNC tab (auto-stop after grace period), idle timeout, max duration, or manual `stop_session(session_id)`
4. On stop: copies pcap and screenshot from container, destroys container, parses pcap, writes artefacts

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
- `artefacts/sandbox_detonation/analysis.json` — behavioural analysis (via prompt)
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

`config/analytical_guidelines.md` governs analytical reasoning about detections. Referenced by MCP prompts (`write_mdr_report`, `write_security_arch_review`, etc.) to ensure the local Claude agent follows consistent standards. Key principles: evidence-first analysis, mandatory alternative-explanation evaluation, co-occurrence != causation, precise determination language.

## Save Tools (Client-Side Persistence)

Two MCP tools persist output generated by the local Claude agent:

- **`save_report`** — persists a report generated via any `write_*` prompt. Handles IOC defanging, HTML conversion, auto-close (for MDR/PUP/FP deliverables), and audit logging. No LLM call.
- **`save_threat_article`** — persists a threat article to the article index. Handles dedup, markdown + HTML output. No LLM call.
- **`add_finding`** — persists structured analytical output (determination, investigation matrix, quality gate review) to case artefacts. Used as the save mechanism for analysis prompts (`run_determination`, `build_investigation_matrix`, `review_report`, etc.).
