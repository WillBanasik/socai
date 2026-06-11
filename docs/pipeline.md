# Pipeline Flow

## HITL Investigation Workflow

Investigations are human-in-the-loop (HITL). The analyst drives each step via MCP tools or CLI commands. There is no autonomous pipeline — the LLM assistant executes tools on the analyst's direction and presents findings at each stage.

### Typical Tool Sequence

**An incident or alert under investigation belongs in a case.** Open a case (`create_case`, or let the first deliverable tool auto-create one) as soon as the work is clearly an investigation. Caseless tools (`quick_enrich`, `extract_iocs`, `classify_attack`, `plan_investigation`, `lookup_client`, `recall_cases`, `eql_entity_lookup`, `eql_identity_scan`, `eql_vuln_hunt`, `start_browser_session` without `case_id`) exist for **non-incident** work — ad-hoc IOC / user / device / IP lookups, exploratory questions, planning, proactive vuln hunting. Promote caseless work to a case (`create_case(enrichment_id=...)` / `create_case(eql_lookup_id=...)` / `create_case(vuln_hunt_id=...)`) the moment it turns into an investigation. The deferred / auto-create path on deliverable tools is a safety net for the rare case where no case exists by report time, not the default flow.

```
── Caseless tools (no case_id required) ──
1. lookup_client          → confirm client and platform config
2. get_client_baseline    → load behavioural profile for this client
3. classify_attack        → deterministic attack-type classification
4. plan_investigation     → advisory step-by-step plan (optional)
5. quick_enrich           → ad-hoc IOC lookups with tiered enrichment (depth="auto"/"fast"/"full")
                             Returns enrichment_id for later import into a case.
                             RFC-1918 / private IPs tagged "private_internal" instantly (no providers).
6. recall_cases           → exact IOC/keyword search in prior cases
7. recall_semantic        → semantic similarity search
8. extract_iocs_from_text → IOC extraction from raw text
9. run_kql_batch          → Sentinel queries in parallel (prefer over sequential run_kql)

── Case creation (with optional enrichment import) ──
10. create_case            → create case; pass enrichment_id to auto-import quick_enrich results
                             (eliminates separate import_enrichment call)

── Case-bound tools ──
11. enrich_iocs           → extract and enrich IOCs (writes to case); depth="auto"/"fast"/"full";
                             auto-runs triage + client baseline to skip routine IOCs
12. import_enrichment     → import saved quick_enrich results (if not auto-imported via create_case)
12a. eql_identity_assessment → (Encore-enabled clients) lean scoping step: classify the named
                             users internal/external + pull device context; classify hosts as
                             assets + local admins. Soft-capped at 5/list. Run BEFORE
                             eql_entity_context to decide which entities warrant the deep pull.
12b. eql_entity_context   → deep per-entity Encore EQL context for the entities that matter
13. add_evidence          → attach raw alert data to case
14. capture_urls          → capture web evidence + auto-run phishing detection (detect_phishing=True)
15. analyse_email         → email header/content analysis (if email)
16. analyse_file          → tiered static analysis (PE/Office/PDF/LNK/OneNote/MSI/Mach-O) + auto-run YARA on signal (run_yara="auto");
                             precedes any start_sandbox_session detonation
17. load_kql_playbook → run_kql → attack-specific structured Sentinel queries (one playbook per attack type)
18. xposed_breach_check   → dark-web breach exposure (account-compromise / credential-access cases)

── Analysis ──
19. correlate             → cross-reference IOCs across all case artefacts
20. campaign_cluster      → cross-case IOC overlap (MANDATORY when recall_cases surfaced overlapping IOCs)
21. add_finding           → record analyst conclusions tied to evidence IDs (MANDATORY before any report)

── Deliverable phase (verdict-branched; analyst-initiated — NOT auto-generated) ──
22. Conclude with a disposition. The deliverable follows the verdict — do NOT default to an MDR report:
    True Positive    → prepare_mdr_report  (+ response_actions, generate_queries; auto-closes on save)
    Benign Positive  → prepare_closure_comment(bp_suspicious_but_expected | bp_suspicious_not_malicious)
    False Positive   → prepare_closure_comment(fp_incorrect_logic | fp_inaccurate_data)  (+ prepare_fp_tuning_ticket if the rule needs tuning)
    Undetermined     → prepare_closure_comment(undetermined)
    PUP/PUA          → close_case(disposition="pup_pua")  (short-circuits after enrich; PUP report on request only)
```

**Typical analyst flow:** `quick_enrich` (caseless IOC lookup) → if malicious, `create_case(enrichment_id=...)` → case-bound analysis → deliverable. The enrichment results carry over without re-running provider calls.

The exact sequence depends on attack type. `classify_attack` returns the recommended tool order. `plan_investigation` returns a full plan with phases, dependencies, and skip conditions.

## Report & Analysis Generation

All LLM reasoning — report writing, disposition analysis, quality review — is handled by the analyst's local Claude client (Claude Desktop or Claude Code in the terminal). The MCP server provides prompts that load system instructions and case data into the local session, and save tools that persist the output.

**Workflow:** Select MCP prompt (e.g. `write_mdr_report`) -> local Claude generates the report as **markdown** following the template skeleton -> call `save_report` / `save_threat_article` to persist (handles defanging, auto-close, audit). Read `socai://templates/mdr-report` or `socai://templates/pup-report` for the markdown skeleton and analyst instructions.

**Rule-9 gate (hard refusal):** for evidence-bearing types (`mdr_report`, `pup_report`, `executive_summary`, `security_arch_review`) `save_report` refuses to persist until the case has at least one `add_evidence` entry and one `add_finding` entry — a report with no recorded evidence/findings chain is unprovable by definition (Analytical Standards rules 1–4 and 9). Backfill the chain from the data already in context, then retry the save. `closure_comment` and `fp_tuning_ticket` are not gated (their evidence requirement is the alert itself, attached by the `prepare_*` tool).

**Recommended flow for enhanced recommendations:** Run `write_security_arch_review` before `write_mdr_report`. The sec arch review is a preventative-controls / best-practice deliverable: when the client is Encore-enabled it first pulls the live configuration baseline (`eql_posture_context` for the client-wide Secure Score / MFA / compliance / Defender-recommendation / vuln posture, plus `eql_entity_context` for the incident's entities), then analyses control gaps against best practice and produces platform-specific hardening recommendations (CA policies, ASR rules, Sentinel analytics, CrowdStrike prevention) grounded in that real posture. When the MDR report is generated, `_build_context()` automatically loads the sec arch findings, and the prompt instructs Claude Desktop to distil them into the Client-Responsible Remediation subsection. If sec arch hasn't been run, the MDR report still works — it just has standard recommendations.

**Why local:** The analyst's session has the full investigation conversation, producing better output than a cold context-free call. The analyst can iterate ("rewrite section 3") without re-invoking tools.

**All reports are markdown (`.md`).** Prompts instruct markdown output (`##`/`###` headings, bullet lists, markdown tables for IOCs, fenced code blocks for queries). Template resources (`socai://templates/mdr-report`, `socai://templates/pup-report`) provide the markdown skeleton and section structure. `save_report` accepts markdown directly. The Claude Desktop visualiser renders the markdown — no HTML, no inline CSS required. The persisted `.md` file is the analyst's copy-paste source for the customer deliverable; legacy `.html` reports on disk remain readable via `read_report` and the reports HTTP middleware.

**Render in the visualiser.** `save_report` and `save_threat_article` return the persisted (defanged) markdown as `report_md` / `article_md` in their response. The model must render that field as a **markdown artifact** so Claude Desktop opens it in the Artifacts side panel (the visualiser). Do not paste the raw markdown into the chat body, summarise it, truncate it, paraphrase it, or wrap it in a code fence. The on-disk `.md` is the copy-paste source; the visualiser is the review surface.

**Template access fallback:** If `prepare_mdr_report` or `prepare_pup_report` is blocked (e.g. the case is already closed), call `load_report_template(template="mdr_report")` or `load_report_template(template="pup_report")` instead. This tool returns the markdown skeleton and analyst instructions with no case requirement and no business-logic gate — identical content to the `socai://templates/*` resources.

Note: The server-side tool names (`prepare_mdr_report`, `prepare_pup_report`, `prepare_closure_comment`, etc.) still exist as MCP tools but now redirect to the prompt workflow — they collect case data and return it for the local agent to process, rather than making direct API calls.

### Report Prompts

| Prompt | Auto-closes | Disposition | Save tool |
|---|---|---|---|
| `write_mdr_report` | Yes | `true_positive` (default; explicit wins) | `save_report(report_type="mdr_report")` |
| `write_pup_report` | Yes | `pup_pua` | `save_report(report_type="pup_report")` |
| `write_closure_comment` | Yes | **Required** — from `classification` (BP/FP/Undetermined) | `save_report(report_type="closure_comment", disposition=...)` |
| `write_fp_tuning` | Yes | Preserves existing (explicit wins) | `save_report(report_type="fp_tuning_ticket")` |
| `write_executive_summary` | No | — | `save_report` |
| `write_security_arch_review` | No | — | `save_report` |
| `write_vuln_hunt_report` | No | — | `save_report(report_type="vuln_hunt_report")` |
| `write_threat_article` | N/A | — | `save_threat_article` |
| `write_response_plan` | No | — | `save_report` |

### Analysis Prompts

| Prompt | Purpose | Save tool |
|---|---|---|
| `run_determination` | Evidence-chain disposition analysis | `add_finding` |
| `build_investigation_matrix` | Rumsfeld matrix (knowns/unknowns/hypotheses) | `add_finding` |
| `review_report` | Report quality gate review | `add_finding` |

### Design Principle

**The local Claude client (Desktop or Code TUI) does all reasoning. MCP tools provide data and persistence.**

Tools handle: API calls (enrichment, Sentinel, sandbox), file I/O (case management, artefact persistence), external integrations (OpenCTI, Cyberint, and Confluence for the published ET/EV threat-articles archive only), and deterministic logic (attack classification, response matrix resolution).

Prompts handle: report generation, analytical reasoning, disposition analysis, quality review, threat article writing — anything that requires LLM judgement. The local Claude session has the full investigation conversation, so it produces better output than any context-free call could.

## Tool Layer

**Tool layer** (`tools/`) — stateless functions that do the actual work. Every tool (except `client_query.py`):
- Takes `case_id` as a required parameter
- Writes all outputs under `cases/<case_id>/` via `write_artefact()` from `tools/common.py`
- `write_artefact()` and `save_json()` automatically append a SHA-256 + timestamp record to `registry/audit.log` — never call `audit()` separately after these functions (it would create duplicate entries)
- Every `except` block must call `log_error(case_id, step, error, *, severity)` — errors are logged to `registry/error_log.jsonl`
- Returns a JSON-serialisable manifest dict
- Key tools (`enrich`, `score_verdicts`, `save_report`, `index_case`) emit structured metrics to `registry/metrics.jsonl` via `log_metric()` — duration, IOC coverage, verdict confidence, report completeness, investigation phase timing

## Attack-Type Classification

`classify_attack_type()` from `tools/classify_attack.py` analyses the case title, notes, and input shape (URLs, ZIPs, logs, EML) to determine the attack type. This is a deterministic keyword + input-shape scorer — no LLM call.

**Attack types:** `phishing`, `oauth_consent`, `ransomware`, `malware`, `account_compromise`, `credential_access`, `privilege_escalation`, `insider_threat`, `data_exfiltration`, `lateral_movement`, `command_and_control`, `reconnaissance`, `persistence`, `defence_evasion`, `web_shell`, `pup_pua`, `generic`

Each type has a pipeline profile in `PIPELINE_PROFILES` defining which steps to skip, and routes to its matching KQL/CQL playbook. The step names below are **summarised** (e.g. "sandbox" = `sandbox_analyse` + `sandbox_detonate`, "phishing_detection" = `detect_phishing_page`); `socai://pipeline-profiles` is the authoritative source for the exact `skip` sets:

| Type | Skipped steps |
|------|---------------|
| `phishing` | sandbox (`sandbox_analyse`, `sandbox_detonate`) |
| `malware` | phishing_detection |
| `account_compromise` | sandbox, phishing_detection |
| `privilege_escalation` | sandbox, phishing_detection, web_capture |
| `data_exfiltration` | web_capture, phishing_detection, sandbox |
| `lateral_movement` | web_capture, phishing_detection, sandbox |
| `command_and_control` | web_capture, phishing_detection, sandbox, file/static analysis (behavioural — no artefact) |
| `reconnaissance` | web_capture, phishing_detection, sandbox, file/email analysis (behavioural — no artefact) |
| `ransomware` | domain_investigate, recursive_capture, phishing_detection, sandbox (endpoint log-based) |
| `credential_access` | domain_investigate, recursive_capture, phishing_detection, sandbox (endpoint/AD log-based) |
| `persistence` | domain_investigate, recursive_capture, phishing_detection, sandbox |
| `defence_evasion` | domain_investigate, recursive_capture, phishing_detection, sandbox |
| `web_shell` | domain_investigate, recursive_capture, phishing_detection, sandbox |
| `oauth_consent` | domain_investigate, recursive_capture, phishing_detection, sandbox (identity/audit log-based) |
| `insider_threat` | domain_investigate, recursive_capture, phishing_detection, sandbox |
| `pup_pua` | Full short-circuit: enrich → `close_case(disposition="pup_pua")`. PUP report only on analyst request (not auto-generated) |
| `generic` | Nothing skipped (fallback) |

`command_and_control`, `reconnaissance`, and the endpoint/log types added alongside the v2 playbooks — `ransomware`, `credential_access`, `persistence`, `defence_evasion`, `web_shell` — are **behavioural** types: they hunt activity from SIEM/EDR log patterns rather than a supplied file/URL artefact, and route to the matching playbook. `ATTACK_TYPES` is ordered specific-before-broad so ties resolve correctly (e.g. "ransomware dropper" → `ransomware`); AD credential-theft (kerberoast, DCSync, golden/silver ticket) routes to `credential_access` not `lateral_movement`; insider staging routes to `insider_threat` not `data_exfiltration`; the consent-grant investigation is `oauth_consent` while consent-phishing lure delivery stays `phishing`.

**Score threshold:** A single weak signal (score ≤ 1) falls through to `generic` to avoid misrouting on ambiguous input.

The classified `attack_type` and `attack_type_confidence` are stored in `case_meta.json`.

### PUP/PUA Short-Circuit

When classified as `pup_pua`, the workflow short-circuits after enrichment and the case is closed with disposition `pup_pua` via `close_case`. A PUP report is **not** auto-generated. If the analyst requests one, the `write_pup_report` prompt produces a lightweight markdown report (summary, path & file details, access vector, actions taken, recommendations) saved to `cases/<ID>/reports/pup_report.md` via `save_report`, which then auto-closes the case with `pup_pua`.

## Disposition Invariant

This is a HITL platform — there is **no autonomous auto-disposition**. The analyst sets the disposition (via `close_case` / `save_report`), or it is derived from the closure-comment classification. As a safety net, `index_case` guarantees every closed case carries one of the six canonical dispositions (`true_positive`, `benign_positive`, `false_positive`, `benign`, `pup_pua`, `inconclusive`): a close with no resolvable disposition is floored to `inconclusive` and a `close_without_disposition` metric is emitted so leaking close-paths stay visible; non-canonical values are warned on. (`close_case` defaults to `inconclusive`. The legacy `benign_auto_closed` label survives only as a comparison alias in `determination.py` — it is never written to a case.)

## Direct Close from Triage

For clear-cut dispositions that don't need a full investigation cycle (e.g. obvious benign positives, known PUP software, duplicate alerts), the `close_case` MCP tool allows closing directly from triage status. This enables a lightweight two-step flow: `create_case` → `close_case(disposition="benign_positive")` — ideal for straightforward alerts.

Deliverable tools (`prepare_mdr_report`, `prepare_pup_report`, `prepare_closure_comment`) will auto-create and promote a case if none exists at the point the report is requested, but this is a **safety net** — for any investigation, open a case at the start of evidence collection (see "An incident or alert under investigation belongs in a case" above).

## Auto-close on Deliverable Collection

**Deliverables are analyst-initiated, not auto-generated.** A full MDR report is produced only for True Positive cases on analyst request; every other disposition closes via `close_case` (see *Direct Close from Triage* above) with no generated report. When a deliverable *is* saved (because the analyst requested it), it auto-closes the case via `save_report`. Executive summary and security arch review are supplementary outputs that do NOT auto-close. The close logic lives in the tool layer so it works consistently across all entry points (CLI, MCP server, client-side save):

| Deliverable | Client-Side Prompt + Save | Auto-closes | Disposition |
|---|---|---|---|
| MDR report | `write_mdr_report` → `save_report` | Yes | `true_positive` (default; explicit wins) |
| PUP report | `write_pup_report` → `save_report` | Yes | `pup_pua` |
| Closure comment (BP / FP / Undetermined) | `prepare_closure_comment(classification=...)` → `write_closure_comment` → `save_report(report_type="closure_comment", disposition=...)` | Yes | **Required** — from classification (`benign_positive` / `false_positive` / `inconclusive`) |
| Detection tuning ticket | `prepare_fp_tuning_ticket` → `write_fp_tuning` → `save_report(report_type="fp_tuning_ticket")` | Yes | Preserves existing (set by the closure_comment; explicit wins) |
| Executive summary | `write_executive_summary` → `save_report` | No | — |
| Security arch review | `write_security_arch_review` → `save_report` | No | — |
| Vulnerability hunt worklist | `eql_vuln_hunt` → `import_vuln_hunt` → `prepare_vuln_hunt_report` → `write_vuln_hunt_report` → `save_report(report_type="vuln_hunt_report")` | No | — |

Each auto-close path calls `index_case(case_id, status="closed", ...)` on successful save. If the tool fails, the case remains open. On close, `index_case` emits an `investigation_summary` metric with computed durations (total, triage, investigation minutes) from `phase_timestamps`, and enforces the disposition invariant above (a missing disposition is floored to canonical `inconclusive`).

## Client Playbook Resolution

When a case has a `client` field and a matching playbook exists in `config/clients/<client>/playbook.json` (or legacy `<client>.json`), the `response_actions` tool generates a structured response plan:

1. **Severity mapping** — `critical/high` → P1, `medium` → P2, `low` → P3
2. **Crown jewel check** — if any malicious IOC matches a crown jewel host (supports wildcard patterns via fnmatch), escalate to P1
3. **Alert override** — `response[]` entries with `alert_name` matched against case title
4. **Escalation matrix** — filtered by resolved priority; collects permitted actions per asset type
5. **Contact process** — from default `response[]` entry or alert-specific override

Multi-environment clients (e.g. Sentinel/MDE + CrowdStrike + OT) define an `environments` map and optional `escalation_matrix_ot` for environment-specific overrides (e.g. no containment in OT).

The tool is purely deterministic (no LLM call). Output is consumed by the MDR report's "Approved Response Actions" section. The client playbook is also exposed as a resource (`socai://clients/{client_name}/playbook`) so the `write_response_plan` prompt can reference it directly.
