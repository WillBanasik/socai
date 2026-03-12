# Pipeline Flow

## HITL Investigation Workflow

Investigations are human-in-the-loop (HITL). The analyst drives each step via MCP tools or CLI commands. There is no autonomous pipeline — the LLM assistant executes tools on the analyst's direction and presents findings at each stage.

### Typical Tool Sequence

```
1. lookup_client          → confirm client and platform config
2. classify_attack        → deterministic attack-type classification
3. plan_investigation     → advisory step-by-step plan (optional)
4. add_evidence           → attach raw alert data to case
5. enrich_iocs            → extract and enrich IOCs
6. capture_urls           → screenshot and capture web evidence (if URLs)
7. detect_phishing        → brand impersonation detection (if URLs)
8. analyse_email          → email header/content analysis (if email)
9. run_kql                → Sentinel queries via playbook
10. generate_mdr_report   → MDR report (auto-closes case)
```

The exact sequence depends on attack type. `classify_attack` returns the recommended tool order. `plan_investigation` returns a full plan with phases, dependencies, and skip conditions.

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

## Auto-close on Deliverable Collection

Cases auto-close when the analyst collects their deliverable. The close logic lives in the tool layer so it works consistently across all entry points (CLI, MCP server):

| Deliverable | Tool | Disposition set |
|---|---|---|
| MDR report | `generate_mdr_report()` | Preserves existing disposition |
| PUP report | `generate_pup_report()` | `pup_pua` |
| FP ticket | `fp_ticket()` | `false_positive` |

Each tool calls `index_case(case_id, status="closed", ...)` on successful generation. If the tool fails (skipped, error, needs_clarification), the case remains open.

## Client Playbook Resolution

When a case has a `client` field and a matching playbook exists in `config/clients/<client>.json`, the `response_actions` tool generates a structured response plan:

1. **Severity mapping** — `critical/high` → P1, `medium` → P2, `low` → P3
2. **Crown jewel check** — if any malicious IOC matches a crown jewel host, escalate to P1
3. **Alert override** — `response[]` entries with `alert_name` matched against case title
4. **Escalation matrix** — filtered by resolved priority; collects permitted actions per asset type
5. **Contact process** — from default `response[]` entry or alert-specific override

The tool is purely deterministic (no LLM call). Output is consumed by the MDR report's "Approved Response Actions" section.
