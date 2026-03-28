# Pipeline Flow

## HITL Investigation Workflow

Investigations are human-in-the-loop (HITL). The analyst drives each step via MCP tools or CLI commands. There is no autonomous pipeline — the LLM assistant executes tools on the analyst's direction and presents findings at each stage.

### Typical Tool Sequence

Case creation is **deferred** — the analyst investigates caseless during triage and assessment. The case materialises automatically when a deliverable tool is called (`prepare_mdr_report`, `prepare_pup_report`, `prepare_fp_ticket`). Analysts can still call `create_case` manually at any point.

```
── Caseless tools (no case_id required) ──
1. lookup_client          → confirm client and platform config
2. get_client_baseline    → load behavioural profile for this client (optional, recommended)
3. classify_attack        → deterministic attack-type classification
4. plan_investigation     → advisory step-by-step plan (optional)
5. recall_cases           → exact IOC/keyword search in prior cases
6. recall_semantic        → semantic similarity search (finds similar past investigations by context)
7. quick_enrich           → fast IOC lookups, no case required
8. extract_iocs_from_text → IOC extraction from raw text
9. run_kql                → Sentinel queries via playbook

── Case-bound tools (call create_case first, or defer to deliverable phase) ──
10. enrich_iocs           → extract and enrich IOCs (writes to case)
11. add_evidence          → attach raw alert data to case
12. capture_urls          → screenshot and capture web evidence (if URLs)
13. detect_phishing       → brand impersonation detection (if URLs)
14. analyse_email         → email header/content analysis (if email)

── Deliverable phase (case auto-created + promoted if needed) ──
15. prepare_mdr_report    → MDR report (auto-creates case if needed, auto-closes)
    prepare_pup_report    → PUP report (auto-creates case if needed, auto-closes)
    prepare_fp_ticket     → FP ticket (auto-creates case if needed, auto-closes)
```

The exact sequence depends on attack type. `classify_attack` returns the recommended tool order. `plan_investigation` returns a full plan with phases, dependencies, and skip conditions.

## Report & Analysis Generation

All LLM reasoning — report writing, disposition analysis, quality review — is handled by the analyst's local Claude Desktop agent. The MCP server provides prompts that load system instructions and case data into the local session, and save tools that persist the output.

**Workflow:** Select MCP prompt (e.g. `write_mdr_report`) -> local Claude generates the report with full conversation context -> call `save_report` / `save_threat_article` to persist (handles defanging, HTML conversion, auto-close, audit).

**Why local:** The analyst's session has the full investigation conversation, producing better output than a cold context-free call. The analyst can iterate ("rewrite section 3") without re-invoking tools.

Note: The server-side tool names (`prepare_mdr_report`, `prepare_pup_report`, `prepare_fp_ticket`, etc.) still exist as MCP tools but now redirect to the prompt workflow — they collect case data and return it for the local agent to process, rather than making direct API calls.

### Report Prompts

| Prompt | Auto-closes | Save tool |
|---|---|---|
| `write_mdr_report` | Yes (preserves disposition) | `save_report` |
| `write_pup_report` | Yes (`pup_pua`) | `save_report` |
| `write_fp_closure` | Yes (`false_positive`) | `save_report` |
| `write_fp_tuning` | No | `save_report` |
| `write_executive_summary` | No | `save_report` |
| `write_security_arch_review` | No | `save_report` |
| `write_threat_article` | N/A | `save_threat_article` |
| `write_response_plan` | No | `save_report` |

### Analysis Prompts

| Prompt | Purpose | Save tool |
|---|---|---|
| `run_determination` | Evidence-chain disposition analysis | `add_finding` |
| `build_investigation_matrix` | Rumsfeld matrix (knowns/unknowns/hypotheses) | `add_finding` |
| `review_report` | Report quality gate review | `add_finding` |

### Design Principle

**Claude Desktop agent does all reasoning. MCP tools provide data and persistence.**

Tools handle: API calls (enrichment, Sentinel, sandbox), file I/O (case management, artefact persistence), external integrations (Confluence, OpenCTI, Cyberint), and deterministic logic (attack classification, response matrix resolution).

Prompts handle: report generation, analytical reasoning, disposition analysis, quality review, threat article writing — anything that requires LLM judgement. The local Claude session has the full investigation conversation, so it produces better output than any context-free call could.

## Tool Layer

**Tool layer** (`tools/`) — stateless functions that do the actual work. Every tool (except `client_query.py`):
- Takes `case_id` as a required parameter
- Writes all outputs under `cases/<case_id>/` via `write_artefact()` from `tools/common.py`
- `write_artefact()` and `save_json()` automatically append a SHA-256 + timestamp record to `registry/audit.log` — never call `audit()` separately after these functions (it would create duplicate entries)
- Every `except` block must call `log_error(case_id, step, error, *, severity)` — errors are logged to `registry/error_log.jsonl`
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

For clear-cut dispositions that don't need a full investigation cycle (e.g. obvious benign positives, known PUP software, duplicate alerts), the `close_case` MCP tool allows closing directly from triage status. This enables a lightweight two-step flow: `create_case` → `close_case(disposition="benign_positive")` — ideal for straightforward alerts.

Alternatively, when a deliverable is needed, case creation is deferred entirely — deliverable tools (`prepare_mdr_report`, `prepare_pup_report`, `prepare_fp_ticket`) auto-create and promote a case if one doesn't exist. The analyst can also call `create_case` manually at any point during the investigation.

## Auto-close on Deliverable Collection

Cases auto-close when the analyst collects their deliverable. The close logic lives in the tool layer so it works consistently across all entry points (CLI, MCP server, client-side save):

| Deliverable | Server Tool | Client-Side Prompt + Save | Disposition |
|---|---|---|---|
| MDR report | `prepare_mdr_report()` | `write_mdr_report` → `save_report` | Preserves existing |
| PUP report | `prepare_pup_report()` | `write_pup_report` → `save_report` | `pup_pua` |
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
