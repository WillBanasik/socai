# Pipeline Flow

## HITL Investigation Workflow

Investigations are human-in-the-loop (HITL). The analyst drives each step via MCP tools or CLI commands. There is no autonomous pipeline — the LLM assistant executes tools on the analyst's direction and presents findings at each stage.

### Typical Tool Sequence

```
1. lookup_client          → confirm client and platform config
2. get_client_baseline    → load behavioural profile for this client (optional, recommended)
3. classify_attack        → deterministic attack-type classification
4. plan_investigation     → advisory step-by-step plan (optional)
5. recall_cases           → exact IOC/keyword search in prior cases
6. recall_semantic        → semantic similarity search (finds similar past investigations by context)
7. add_evidence           → attach raw alert data to case
8. enrich_iocs            → extract and enrich IOCs
9. capture_urls           → screenshot and capture web evidence (if URLs)
10. detect_phishing       → brand impersonation detection (if URLs)
11. analyse_email         → email header/content analysis (if email)
12. run_kql               → Sentinel queries via playbook
13. generate_mdr_report   → MDR report (auto-closes case)
```

The exact sequence depends on attack type. `classify_attack` returns the recommended tool order. `plan_investigation` returns a full plan with phases, dependencies, and skip conditions.

## Client-Side vs Server-Side Generation

The MCP server exposes two modes for report and analysis tasks:

**Server-side tools** (original) — the MCP server calls the Claude API itself:
- `generate_mdr_report`, `generate_pup_report`, `generate_fp_ticket`, etc.
- Useful for CLI usage or when the analyst prefers a one-shot tool call

**Client-side prompts** (preferred for Claude Desktop) — the analyst's local session does the thinking:
- `write_mdr_report`, `write_pup_report`, `write_fp_closure`, etc.
- The prompt loads the system instructions + case data into the local session
- The analyst's Claude generates the report with full conversation context
- `save_report` / `save_threat_article` persists the output (defanging, HTML, auto-close, audit)

The client-side approach is preferred because:
- The local session has the full investigation conversation — better reports
- No redundant server-side Claude API calls (Claude calling Claude)
- Faster iteration — analyst can say "rewrite section 3" without re-invoking the tool

### Client-Side Report Prompts

| Prompt | Replaces | Auto-closes |
|---|---|---|
| `write_mdr_report` | `generate_mdr_report` | Yes (preserves disposition) |
| `write_pup_report` | `generate_pup_report` | Yes (`pup_pua`) |
| `write_fp_closure` | `generate_fp_ticket` | Yes (`false_positive`) |
| `write_fp_tuning` | `generate_fp_tuning_ticket` | No |
| `write_executive_summary` | `generate_executive_summary` | No |
| `write_security_arch_review` | `security_arch_review` | No |
| `write_threat_article` | `generate_threat_article` | N/A |
| `write_response_plan` | `response_actions` (advisory) | No |

### Client-Side Analysis Prompts

| Prompt | Replaces | Purpose |
|---|---|---|
| `run_determination` | `run_determination` tool | Evidence-chain disposition analysis |
| `build_investigation_matrix` | `generate_investigation_matrix` tool | Rumsfeld matrix (knowns/unknowns/hypotheses) |
| `review_report` | `review_report_quality` tool | Report quality gate review |

### Design Principle

**Local Claude does the thinking. MCP tools provide the weapons.**

Tools handle: API calls (enrichment, Sentinel, sandbox), file I/O (case management, artefact persistence), external integrations (Confluence, OpenCTI, Cyberint), and deterministic logic (attack classification, response matrix resolution).

Prompts handle: report generation, analytical reasoning, disposition analysis, quality review, threat article writing — anything that is "read context, produce text".

## Tool Layer

**Tool layer** (`tools/`) — stateless functions that do the actual work. Every tool (except `client_query.py`):
- Takes `case_id` as a required parameter
- Writes all outputs under `cases/<case_id>/` via `write_artefact()` from `tools/common.py`
- Appends a SHA-256 + timestamp record to `registry/audit.log`
- Returns a JSON-serialisable manifest dict

## Attack-Type Classification

`classify_attack_type()` from `tools/classify_attack.py` analyses the case title, notes, and input shape (URLs, ZIPs, logs, EML) to determine the attack type. This is a deterministic keyword + input-shape scorer — no LLM call.

**Attack types:** `phishing`, `malware`, `account_compromise`, `privilege_escalation`, `pup_pua`, `generic`

Each type has a pipeline profile in `PIPELINE_PROFILES` defining which steps to skip:

| Type | Skipped steps |
|------|---------------|
| `phishing` | sandbox, anomaly_detection, evtx |
| `malware` | phishing_detection |
| `account_compromise` | sandbox, phishing_detection |
| `privilege_escalation` | sandbox, phishing_detection, web_capture |
| `pup_pua` | Full short-circuit: enrich → PUP report → done |
| `generic` | Nothing skipped (fallback) |

**Score threshold:** A single weak signal (score ≤ 1) falls through to `generic` to avoid misrouting on ambiguous input.

The classified `attack_type` and `attack_type_confidence` are stored in `case_meta.json`.

### PUP/PUA Short-Circuit

When classified as `pup_pua`, the workflow short-circuits after enrichment. `generate_pup_report()` produces a lightweight PUP-specific report covering: software identification, scope assessment, risk evaluation, and removal steps. The report is saved to `cases/<ID>/reports/pup_report.md`. The case is auto-closed with disposition `pup_pua` when the PUP report is generated (handled inside the tool).

## Auto-disposition

After enrichment, if verdict_summary has 0 malicious and 0 suspicious IOCs, the case is auto-closed with disposition `benign_auto_closed` — unless the report confidence score meets or exceeds `SOCAI_CONF_AUTO_CLOSE` (default 0.20), in which case the auto-close is reverted.

## Direct Close from Triage

For clear-cut dispositions that don't need a full investigation cycle (e.g. obvious benign positives, known PUP software, duplicate alerts), the `close_case` MCP tool allows closing directly from triage status. This enables a lightweight two-step flow: `create_case` → `close_case(disposition="benign_positive")` — zero server-side API credits, ideal for the desktop LLM handling straightforward alerts.

## Auto-close on Deliverable Collection

Cases auto-close when the analyst collects their deliverable. The close logic lives in the tool layer so it works consistently across all entry points (CLI, MCP server, client-side save):

| Deliverable | Server Tool | Client-Side Prompt + Save | Disposition |
|---|---|---|---|
| MDR report | `generate_mdr_report()` | `write_mdr_report` → `save_report` | Preserves existing |
| PUP report | `generate_pup_report()` | `write_pup_report` → `save_report` | `pup_pua` |
| FP ticket | `fp_ticket()` | `write_fp_closure` → `save_report` | `false_positive` |

Each path calls `index_case(case_id, status="closed", ...)` on successful generation/save. If the tool fails, the case remains open.

## Client Playbook Resolution

When a case has a `client` field and a matching playbook exists in `config/clients/<client>.json`, the `response_actions` tool generates a structured response plan:

1. **Severity mapping** — `critical/high` → P1, `medium` → P2, `low` → P3
2. **Crown jewel check** — if any malicious IOC matches a crown jewel host, escalate to P1
3. **Alert override** — `response[]` entries with `alert_name` matched against case title
4. **Escalation matrix** — filtered by resolved priority; collects permitted actions per asset type
5. **Contact process** — from default `response[]` entry or alert-specific override

The tool is purely deterministic (no LLM call). Output is consumed by the MDR report's "Approved Response Actions" section. The client playbook is also exposed as a resource (`socai://clients/{name}/playbook`) so the `write_response_plan` prompt can reference it directly.
