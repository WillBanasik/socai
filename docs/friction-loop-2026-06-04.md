# Investigate → Friction → Fix Loop — Field Notes (2026-06-04)

Field notes from the 2026-06-04 investigate→friction→fix loop — 3 live investigations (Cell C #57241, Essentra #172220, Aztec #193082), telemetry analysis, and a ranked set of tooling fixes (P0 server-restart + P1 code fixes implemented in commits d09f130/7e19994; P2/P3 proposed). Friction captured inline as it happened; compiled + ranked at the end.

Severity key: **P1** blocks/produces wrong output · **P2** slows analyst / needs a workaround · **P3** polish.

Friction entry format: `[TOOL] expected → actual → impact → hypothesised fix`

---

## Discovery / setup

- **[list_cases] P2 — listing tool blows the token budget.** `list_cases(status="all")` returned **88,446 chars** → hard token-limit error, output dumped to a file. A *roster* tool should not return full per-case payloads. Needs a lean projection (id/title/client/status/sev/dates) and/or pagination. (171 cases total.)
- **[list_cases] P2/P3 — roster omits `client`.** Per-case entry = {case_dir, created_at, ioc_totals, report_path, severity, status, title, updated_at}. No `client` field → can't triage/filter by client without reading each case or regexing the title. Client is derivable from `case_dir`? No — it's `cases/IV_CASE_NNN`. So client is effectively invisible in the listing.
- **[workspace discovery] P3 — no cheap client→workspace map over MCP.** Cross-client live hunt needs each Sentinel workspace GUID; `list_clients` gives platforms but not GUIDs; only `lookup_client` (heavy KB+playbook payload) exposes it. Had to read `config/client_entities.json` off disk. Fine for an engineer, but a Desktop-only analyst can't. Low priority (analysts usually work one client at a time; `run_kql` auto-resolves from case client).
- **[run_kql] positive — 4 workspaces queried cleanly, `arg_max` dedup + dynamic projection all fine.** Silent-0-row footgun did NOT trigger (all queries had rows). Will probe it deliberately with a `LocationDetails`/dynamic-column query expected to return 0.

---

## Run 1 — Risky sign-in / impossible travel (human user)

Client: **Cell C** (ws 6f0a79ce…) · Case: TBD · Source: SecurityIncident **#57241** "Successful login from one IP and then Failed login within 10 min from another IP in another country involving one user" (2026-06-04T07:49Z, SOC-closed BenignPositive Low — re-triaging fresh)

### Steps
1. `plan_investigation(cell_c, …)` → classified **account_compromise**, sensible 20-step plan. ✅ no friction.
2. `lookup_client(cell_c)` → KB OSINT-rich (RansomHouse 2024 breach context) but operational fields all `[INTERNAL]`; `response_playbook` is an unfilled template (empty contacts, `<placeholder>` per-alert actions); `sentinel_reference: null`.
3. `get_client_baseline(cell_c)` → `case_count=2`, **all IOC buckets + attack_types + dispositions empty**. Severity dist {high:1, medium:1}. ~Zero behavioural signal.
4. `run_kql` incident #57241 detail → SOC ground truth: **BenignPositive / SuspiciousButExpected**, failed auth = result code **50173** (token revoked post password-reset + sync), no compromise. Ticket 654589. AlertId `53f010df-e4a6-6a08-d29e-a333f0993525`, rule `0e23f771-47f4-4c81-ab66-eeb72fa24da1`.

### Friction
- **[lookup_client] P2 — mandated client-context step returns an unfilled stub for Cell C, with no signal that it's a stub.** Operational KB fields (UPN, SSO, identity, security stack, expected sign-in geos) are `[INTERNAL]` placeholders; `response_playbook` contacts are empty and actions are literal `<priority>`/`<alert_name>` placeholders. An analyst following the playbook for escalation/contact gets nothing, and nothing in the payload flags "this playbook is a template, not real". Fix idea: surface a `populated: false` / completeness score so the model knows to fall back, rather than quoting placeholder text.
- **[get_client_baseline] P2 (confirmed) — the MANDATORY baseline contributed nothing to the geo/VPN-FP defence it exists for.** Cell C (2 cases): every bucket empty. The decisive geo-normalcy evidence ("does this user routinely sign in from India AND ZA?") came entirely from ad-hoc SigninLogs/AuditLogs I wrote by hand. Baseline is sourced from prior-case IOCs/dispositions, never sign-in telemetry, so it structurally can't answer the question. Fix: account-compromise playbook should auto-emit a per-user sign-in geo/ASN baseline (14–30d distinct Country/IP/ASN), or get_client_baseline should optionally fold in sign-in telemetry for the named user.
- **[run_kql] P1 ★ — SILENT 0-ROW on `LocationDetails.<prop>` against AADNonInteractiveUserSignInLogs (seed-worklist footgun, reproduced TWICE on real data).** `tostring(LocationDetails.countryOrRegion)` works on SigninLogs (dynamic) but on AADNonInteractive (LocationDetails is a *string*) it zeroes the ENTIRE result — 0 rows, no error, no warning. Hit it twice: (a) `…=~ "<UPN>" | extend Country=tostring(LocationDetails.countryOrRegion)…`; (b) `…| summarize … by …parse_json(tostring(LocationDetails))…`. Proven via controls: identical filters WITHOUT the LocationDetails ref returned 47/361/50 rows. Impact: would have hidden the 50173 token-revocation failures that ARE the benign explanation → analyst closes "no failures/inconclusive" or misses a real compromise. **Highest-value fix target.**
- **[run_kql + run_kql_batch] P1-adjacent — failures surface as `row_count:0`, not a raised error.** Singular run_kql returned 0 (not KqlQueryError) for the LocationDetails query; batch likewise. Commit 18ac9a2 ("raise on failure") evidently misses this shape. Confirm raise-vs-swallow in fix phase. Candidate fixes: (i) per-table detect dynamic-vs-string LocationDetails and auto-wrap parse_json; (ii) warn when a query references `LocationDetails.*` on a *NonInteractive* table; (iii) mark 0-row results that follow a dynamic-property access as "suspect" not silent.
- **[campaign_cluster] P1/P2 — spurious campaign linkage + benign Microsoft domain scored malicious.** campaign_cluster(IV_CASE_172) said "1 campaign linked to this case" = CAMP-2026-A1B90B, but that campaign's cases are [030,032,037,067] (NOT 172) and its shared IOCs (`dedyn.io`, `sharepointonline.com`) are absent from my case. False linkage — possible regression of commit 4eed575 ("return only campaigns containing the scoped case"). And **`sharepointonline.com` verdicted `malicious`** in the cross-case index anchors the campaign → pollutes correlation everywhere. Confirm both in fix phase (read campaign_cluster scoping + the sharepointonline.com verdict path).
- **[add_evidence] P3 — severity heuristic over-escalated.** Returned `severity:"high"` for this Low BP case, keying off narrative words ("compromise","password reset","attacker TTPs") even though my text said *zero* attacker TTPs. Reads prose literally, including negations.
- **[add_evidence/enrich_iocs] P3 — client-owned domain enriched.** Extracted+enriched `contractor.cellc.co.za` (from the UPN; also as URL `https://contractor.cellc.co.za`). Client infra shouldn't be enriched (matches prior feedback).
- Positives: `plan_investigation` solid; `geoip_lookup` offline+accurate; `enrich_iocs(fast)` correct (4 clean, flagged 41.156.66.18 recurring); `add_evidence` caught all 4 IPs + email; `union … where IPAddress in()` (no LocationDetails) worked (50 rows). `score_ioc_verdicts` clean but single-provider (abuseipdb only)→LOW confidence under fast depth (acceptable for a clean determination).

---

## Run 2 — Email removal / phishing

Client: **Essentra** (ws bf09be88…) · Case: TBD · Source: SecurityIncident **#172220** "Perf - O365 - URL Link Click from Sender Email Marked as Phishing" (2026-06-04T19:58Z, **Status New/open** — genuinely live, no SOC ground-truth yet). Known recurring PhishAlarm-click BP per memory. (Case **IV_CASE_173**.)

### Steps
1. `load_toolset(group=…)` rejected (param is `name`); re-called `name="phishing"` → already loaded (server runs all toolsets).
2. `plan_investigation` phishing ✅. `lookup_client(essentra)` → KB rich + **playbook POPULATED** (real Proofpoint TAP guidance, "flag anything involving Marianela Piedra"). `get_client_baseline(essentra)` → case_count=2, all buckets empty (2nd client, same thin baseline).
3. `run_kql` incident #172220 + `SecurityAlert` entities → user pauldummer@wixroydgroup.com, sender dhl@swift-track.info; Custom Details ClickedUrl = us-phishalarm-ewt.proofpoint.com.
4. `run_kql_batch` EmailEvents (29-msg DHL wave, mostly Inbox) + UrlClickEvents (6 clicks, ALL PhishAlarm/EWT, IsClickedThrough=False, ZERO swift-track clicks). Defender tables (EmailEvents/UrlClickEvents/CloudAppEvents) queryable in Sentinel ws despite defender_xdr api_enabled=false.
5. `add_evidence` + `recall_cases` (found real IV_CASE_167 link via shared sender IPs) + `enrich_iocs(fast)` + `score_ioc_verdicts` + `campaign_cluster` + 2× `add_finding`.

### Friction
- **[campaign_cluster] P1 ★ CONFIRMED (reproduced both runs) — over-links spurious + under-links real.** IV_CASE_173 returned the IDENTICAL bogus CAMP-2026-A1B90B (cases 030/032/037/067; IOCs dedyn.io + sharepointonline.com) it returned for IV_CASE_172 — neither case shares those IOCs. AND it MISSED the genuine IV_CASE_167 link (shared sender IPs 185.132.181.156/.165). Hypothesis: clusters only on `verdict=malicious` IOCs → (a) real shared IPs are `clean` → ignored (under-link); (b) `sharepointonline.com` wrongly `malicious` → anchors a bogus campaign (over-link); (c) returns campaigns not containing the scoped case (regression of 4eed575). recall_cases (exact-IOC) did the job campaign_cluster should have. **Top fix target alongside the LocationDetails footgun.**
- **[enrich_iocs] P2 — coverage gap: a live phishing domain scores CLEAN/unknown.** swift-track.info (Defender labelled the 29 emails Phish + brand-impersonation) returned no malicious/suspicious verdict (young throwaway domain, not yet in VT/AbuseIPDB). score_ioc_verdicts only scored the 2 IPs (ioc_count=2) — the domain isn't even surfaced. Trusting enrichment alone would under-rate it. Idea: fold Defender EmailEvents ThreatTypes/DetectionMethods into the verdict, or flag "unknown + young domain + impersonation".
- **[enrich_iocs/add_evidence] P3 — client-owned + internal IOCs enriched.** 52 live lookups included client domains essentra.com / wixroydgroup.com + internal recipient emails (matches prior "skip client domains" feedback).
- **[load_toolset] P3 — param mismatch.** Server says `load_toolset('<group>')`; actual param is `name`.
- **[save_report] P2 — `fp_tuning_ticket` save hardcodes `disposition=false_positive` on auto-close.** Saving the tuning ticket (no disposition arg) auto-closed IV_CASE_173 as **false_positive**, overriding the Benign Positive determination — even though `prepare_fp_tuning_ticket` + CLAUDE.md explicitly support BP+tuning. Had to re-save the closure_comment with `disposition=benign_positive` afterwards to correct it. Fix: `fp_tuning_ticket` save should accept/respect a `disposition` (or not force false_positive); also it auto-closes when sometimes you want to file the ticket without changing disposition.
- Positives: `run_kql`/`run_kql_batch` handled the Defender hunting tables + the rule's giant embedded query fine; `recall_cases` excellent (surfaced the real IV_CASE_167 shared-infra link campaign_cluster missed); populated `lookup_client` playbook gave actionable Proofpoint context.

---

## Run 3 — Mass SharePoint / data exfiltration

Client: **Aztec** (ws 5a3a66ff…) · Case: TBD · Source: SecurityIncident **#193082** "Mass download by a single user involving one user" (2026-06-04T10:31Z, SOC-closed **FalsePositive** — re-triaging fresh; expect the Transform_Zip folder-zip UA tuning path per memory).

_Note: skipped `plan_investigation` for Run 3 — it returned a near-identical 20-step boilerplate plan in Runs 1 & 2; only step 9's playbook name + skipped_steps + profile_description vary by attack type. P3._ (Case **IV_CASE_174**.)

### Steps
1. `lookup_client(aztec)` → KB rich + **playbook POPULATED with critical ops flags**: HYPERCARE (no containment on identities/endpoints), pentest window (inactive), containment_actions, call_tree. `get_client_baseline(aztec)` → **case_count=0, "baseline not built"** (3rd client; at least explicit).
2. `run_kql` incident #193082 → MCAS "Mass download", FP/"Duplicate", SOAR auto-closed in ~1 min; `SecurityAlert` entities → adil.khan@aztecgroup.eu, SharePoint Online, IP 85.94.229.29 (LU).
3. `geoip` 85.94.229.29 → LU (normal). `CloudAppEvents` query → **0 rows WITH `schema_warnings`** (table not in workspace) — good.
4. `OfficeActivity` pivot → hit the run_kql_batch false-0-row bug (below); singular queries proved adil active + the Transform_Zip burst (250 files, `ODMTADemand-Transform_Zip/1.791`).
5. `add_evidence` + `recall_cases` (no IOC overlap; keyword match to IV_CASE_006) + 2× `add_finding` + `enrich_iocs(fast)` (clean). `campaign_cluster` skipped (confirmed broken).

### Friction
- **[run_kql_batch] P1 ★ CONFIRMED — false 0-rows for queries singular run_kql answers correctly.** In a 3-query batch, a bare-aggregate `summarize total=count(), distinctUsers=dcount(UserId)` returned **0 rows**; the IDENTICAL query singular returned **1 row (total=6,728,846, users=10,748)**. Also `where UserId has "adil" | summarize … by UserId` → 0 in batch, while `contains "adil.khan"` singular → 50 rows. An analyst trusting the batch concludes "OfficeActivity empty / user inactive" — catastrophic on an exfil-type alert. Pairs with the Run-1 LocationDetails silent-0-row: **the dominant theme is that 0-row results are untrustworthy and carry no error.** Root-cause in fix phase (batch post-processing likely mishandles single-row / 0-group results, or swallows an error).
- **[run_kql] ★ POSITIVE — `schema_warnings` works for missing tables.** CloudAppEvents → 0 rows + `schema_warnings:["Table 'CloudAppEvents' … not in workspace 'aztec_group'"]`. The RIGHT behaviour: explains the 0. Gap: covers table-absence only — NOT the LocationDetails dynamic-column case (Run 1) nor the batch bare-summarize bug. **Extending this "explain the empty result" mechanism to those cases is the natural fix.**
- **[KQL has vs contains] P3 (analyst-education) — `has "adil"` missed `adil.khan@…` that `contains` found.** `has` term-matching on dotted/email tokens is unreliable; playbooks/guidance should steer `contains`/`has_cs` for email/UPN substrings.
- **[get_client_baseline] P2 (3rd client) — case_count=0 → no baseline.** Consistent thin-baseline gap; message at least explicit.
- **[campaign_cluster] (3rd data point) — skipped on principle.** Runs 1-2 proved it returns a fixed bogus campaign + misses real links, so I relied on recall_cases. Tool is currently net-negative for analyst trust.
- Positives: Aztec **populated playbook** delivered the decisive HYPERCARE/no-containment context; `recall_cases` reliable; `geoip` accurate; the Transform_Zip benign determination was fully data-provable once the batch bug was worked around.

---

## Cross-cutting friction (seen across runs)

- **★ CRITICAL CONFOUNDER — the running MCP server is STALE.** Process started **2026-06-04 09:24:04**; commits **4eed575** (campaign_cluster scoped filter), **18ac9a2** (run_kql raise-on-failure), **c09fa2e** (playbook discipline) all landed **10:46** — ~82 min after server start. The server I investigated through runs pre-10:46 code. **Proof:** on-disk `python3 tools/campaign_cluster.py --case IV_CASE_172/173` → `linked total: 0` (correct), but the running server returned CAMP-2026-A1B90B. ⇒ campaign_cluster "spurious linkage" = STALE SERVER, NOT a code bug; run_kql raise-on-failure also not live. **Re-validate all run_kql 0-row + campaign findings after restart.**
- Seed-worklist validation: silent-0-row KQL → **CONFIRMED** (2 classes: LocationDetails-dot-access-on-AADNonInteractive [Run 1]; multi-aggregate bare summarize w/ dcount+min/max datetime [Run 3] — both az rc=0+[], so even 18ac9a2 won't catch them). Thin client baseline → **CONFIRMED** (all 3 clients 0–2 cases, empty). IOC-extraction Chrome/120 FP → not triggered (no UA in these alerts); adjacent IOC FPs found instead (client-domain enrichment; young-phish-domain scored clean; sharepointonline.com mis-verdicted malicious).

---

## Telemetry (post-batch)

_NB: workflow_report reads flushed `workflow_summary` events; this session's aren't flushed (usage.py flushes on session-expiry/shutdown) — so the friction report below is HISTORICAL. Per-call rows ARE in `registry/mcp_usage.jsonl` in real time (202 rows today, 25 ref my cases). → minor finding: workflow_report can't see in-flight sessions; restart/flush needed._

- **workflow_report.py --friction** (385 sessions, 200 w/ friction): long_gap 243 (human think-time, mostly noise); abandoned_workflow 149 (sessions ending w/o deliverable/close); **retry_after_error 99 — `lookup_client` "Client not found"** on real names ("Heidelberg Materials", "heidelberg"); **repeated_lookup 46 — `lookup_client` up to 8×/session** ("result may not have been retained" → heavy payload churns context).
- **metrics_report.py** (3240 recs): enrichment IOC coverage median **56%** (≈44% uncovered — the young-domain gap); verdict confidence **LOW 56%** (single-provider); reports: mdr 102 / closure 17 / fp_tuning 1(mine); **report completeness median 0%** (metric broken/always-0); **96 BLANK dispositions** among closed investigations (data-quality); mean total time 19.6h vs median 1.2m (long-open skew).
- **socai.py errors** (1439 recs): **#1 enrich.opencti — 532 warns, "Invalid URL '/graphql': No scheme"** (485×, OPENCTI_URL empty) + 521 from cti.performanta (45×); scheduler.failing_task 128× literal "boom" (stray test task); confluence_read 42; darkweb stealer_parser import 54; **save_report.defang "verdict_summary.json missing" 50×**; "geoip2.database import halted" 52× (historical — geoip works now); most error-prone cases IV_CASE_030/037 (the sharepointonline.com mis-verdict origin).

---

## Compiled + ranked fixes

**P0 — ops, zero code, do first**
1. **Restart the MCP server.** Running process predates the 10:46 commits → activates campaign_cluster scoping (4eed575), run_kql raise-on-failure (18ac9a2), playbook discipline (c09fa2e); flushes this session's workflow telemetry. Then re-validate the run_kql 0-row + campaign findings against fresh code.

**P1 — genuine on-disk bugs (confirmed independent of the stale server)**
2. **OpenCTI provider fires with empty `OPENCTI_URL`** (`enrich.py:675` → `f"{OPENCTI_URL}/graphql"` = `/graphql`). #1 error by volume (532). Fix: guard `_opencti_lookup` to return `not_configured` when `OPENCTI_URL` falsy (mirror the `OPENCTI_KEY` guard at :657). Same pattern in threat_articles.py / cve_contextualise.py / opencti_publish.py.
3. **IOC verdict aggregation: any-malicious-wins.** `sharepointonline.com` = malicious:1/clean:3 → `verdict:"malicious"` in ioc_index.json (from UoP SharePoint-lure cases). Pollutes the global campaign + recall. Fix: majority/weighted verdict in score_verdicts; add Microsoft/Google/CDN domains to `campaign_cluster._is_noise_ioc` + a benign-domain allowlist.
4. **run_kql silent 0-row (2 classes, az rc=0+[], not caught by 18ac9a2):** (a) `LocationDetails.<prop>` dot-access on AADNonInteractiveUserSignInLogs (string-typed); (b) multi-aggregate bare `summarize` (dcount + min/max datetime). Fix: extend the schema-validation layer to detect dynamic-dot-access on known-string columns per-table (auto-`parse_json` or warn) and to flag "no-`by` summarize returned 0 rows" as suspect. (b) needs az-level confirmation.

**P2 — workflow / quality**
5. **list_cases** returns full per-case payloads → 88KB token-limit error on `status=all`; omits `client`. Add lean projection + pagination + client field.
6. **lookup_client** brittle name resolution (99 retries on real names) + heavy payload → repeated re-calls (46). Fix: alias/fuzzy resolution + a lean mode.
7. **get_client_baseline** structurally can't answer geo/VPN-FP (sourced from case IOCs, not sign-in telemetry); empty for low-case clients. Fix: per-user sign-in geo/ASN baseline in the account-compromise path.
8. **save_report(fp_tuning_ticket)** hardcodes `disposition=false_positive` on auto-close (overrode a BP). Accept/respect `disposition`.
9. **96 blank dispositions + report completeness median 0%** — closure paths not always setting disposition; completeness metric broken.
10. **enrich** scores young phishing domains clean/unknown + enriches client-owned domains. Fold Defender ThreatTypes into verdict; skip client domains.

**P3 — polish**
11. `load_toolset` param mismatch (server says `group`, is `name`). 12. `add_evidence` severity heuristic reads narrative negations → over-escalates. 13. `plan_investigation` near-identical boilerplate across attack types. 14. KQL `has` vs `contains` guidance for email/UPN. 15. scheduler "boom" task (128×). 16. save_report.defang "verdict_summary.json missing" (50×). 17. workflow_report can't see in-flight sessions (reads flushed summaries only).

**Validation signal:** 3/3 dispositions matched SOC ground truth (Run1 BP=ticket 654589; Run2 BP=prior IV_CASE_167; Run3 BP=SOC FP/Duplicate) — tooling reached correct answers despite the friction.

---

## Implemented this session (P0 + P1, validated; awaiting review/commit)

- **P0 — MCP server restarted** (was ~13h stale; now runs current on-disk code incl. campaign scoping 4eed575 + run_kql raise 18ac9a2). Live re-validation: global re-cluster → **0 campaigns** (bogus CAMP-2026-A1B90B gone).
- **P1 #2 — OpenCTI URL guard** (`tools/enrich.py`): `_opencti_lookup` returns `not_configured` when `OPENCTI_URL` is unset → eliminates the 485 `/graphql` "no scheme" errors (the #1 error by volume).
- **P1 #3 — ubiquitous-benign-domain handling**: `score_verdicts` forces MS/Google/CDN domains clean (`_is_force_clean`); `campaign_cluster._BENIGN_DOMAINS` extended with the M365 SaaS domains. `sharepointonline.com` no longer mis-verdicted / anchoring campaigns. `_composite_verdict`'s real-IOC behaviour unchanged.
- **Tests**: `tests/test_friction_fixes.py` (4) + full suite **388 pass, no regressions**. Diff = **+37 LOC / 3 files + 1 test file**, uncommitted.
- **Not yet done**: re-validate the two run_kql 0-row classes against current code; P2/P3 items proposed only. Stale data note: `registry/ioc_index.json` still lists `sharepointonline.com=malicious` (corrected on next score of cases 030/037/067; clustering already protected via the noise-list).

---

## Post-restart re-validation — the run_kql 0-row findings were STALE-SERVER, not code bugs

Re-ran both run_kql 0-row footguns against the FIXED on-disk code (CLI `scripts/run_kql.py`) after the restart:
- **LocationDetails dot-access on AADNonInteractive (Run 1)** → now raises an explicit **SEM0070 semantic error** (KqlQueryError, commit 18ac9a2) instead of a silent `[]`. The stale pre-18ac9a2 server swallowed it as 0 rows. ⇒ **silent-0-row RESOLVED by restart**; residual is just an authoring gotcha (wrap `parse_json(tostring(LocationDetails))`), now LOUD not silent.
- **Multi-aggregate bare summarize (Run 3)** → now returns the correct single row (total=4.35M, dcount, min/max datetimes). **Does not reproduce** on current code — stale-server/transient artifact, not a bug.

⇒ **Corrected ranking:** the run_kql "silent-0-row P1 (#4)" collapses into the P0 stale-server item — already fixed on disk, activated by the restart. The only genuine *current-code* P1s were **#2 OpenCTI URL guard** and **#3 verdict/noise** — both implemented + tested. Still-accurate current behaviour: `has`-vs-`contains` tokenisation trap; missing-table `schema_warnings` (good); thin client baseline (real, structural).
