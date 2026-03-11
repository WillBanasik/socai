# Model Tiering — LLM Call Flow

Every LLM invocation resolves its model through `get_model(task, severity)` in `tools/common.py`, following a 3-step process: task lookup, tier resolution, severity escalation.

## Resolution Flow

```
get_model("secarch", "high")
  |
  +- 1. Lookup: SOCAI_MODEL_SECARCH = "standard"     (from config/settings.py)
  +- 2. Resolve: "standard" -> SOCAI_MODEL_STANDARD -> "claude-sonnet-4-6"
  +- 3. Escalate: task "secarch" IS in escalation set + severity "high"
  |     -> bump standard -> heavy -> "claude-opus-4-6"
  +- Return: "claude-opus-4-6"
```

**Fallback chain:** task setting -> tier map -> `LLM_MODEL` -> `"claude-sonnet-4-6"`

## Default Model Matrix

| Task | Default Tier | Medium Model | High/Critical Model | Escalates? |
|------|-------------|-------------|-------------------|-----------|
| `chat_response` | standard | Sonnet | **Opus** | YES |
| `secarch` | standard | Sonnet | **Opus** | YES |
| `fp_ticket` | standard | Sonnet | **Opus** | YES |
| `evtx` | standard | Sonnet | **Opus** | YES |
| `report` | fast | Haiku | **Sonnet** | YES |
| `exec_summary` | standard | Sonnet | Sonnet | no |
| `mdr_report` | standard | Sonnet | Sonnet | no |
| `pe_analysis` | standard | Sonnet | Sonnet | no |
| `yara` | standard | Sonnet | Sonnet | no |
| `timeline` | fast | Haiku | Haiku | no |
| `cve` | fast | Haiku | Haiku | no |
| `queries` | fast | Haiku | Haiku | no |
| `chat_routing` | fast | Haiku | Haiku | no |
| `articles` | standard | Sonnet | Sonnet | no |
| `report_narrative` | fast | Haiku | Haiku | no |
| `campaign_narrative` | fast | Haiku | Haiku | no |
| `query_refinement` | fast | Haiku | Haiku | no |
| `triage_context` | fast | Haiku | Haiku | no |
| `anomaly_context` | fast | Haiku | Haiku | no |
| `correlation_insight` | fast | Haiku | Haiku | no |
| `response_priority` | fast | Haiku | Haiku | no |
| `verdict_reconcile` | fast | Haiku | Haiku | no |
| `auto_close_review` | fast | Haiku | Haiku | no |

## Per-File Call Site Map

### Severity from `case_meta.json` (9 files)

| File | Call | Task | Severity Source |
|------|------|------|----------------|
| `tools/security_arch_review.py` (main) | `get_model("secarch", severity)` | secarch | `meta.get("severity")` |
| `tools/security_arch_review.py` (cluster) | `get_model("secarch", severity)` | secarch | passed into cluster subagent |
| `tools/fp_ticket.py` | `get_model("fp_ticket", severity)` | fp_ticket | `meta.get("severity")` |
| `tools/generate_mdr_report.py` | `get_model("mdr_report", _severity)` | mdr_report | `_safe_load(case_meta)` |
| `tools/evtx_correlate.py` | `get_model("evtx", _severity)` | evtx | `load_json(case_meta)` |
| `tools/pe_analysis.py` | `get_model("pe_analysis", _severity)` | pe_analysis | `load_json(case_meta)` |
| `tools/yara_scan.py` | `get_model("yara", severity)` | yara | `load_json(case_meta)` |
| `tools/cve_contextualise.py` | `get_model("cve", severity)` | cve | `load_json(case_meta)` |
| `tools/timeline_reconstruct.py` | `get_model("timeline", _severity)` | timeline | `_load_optional(case_meta)` |
| `tools/executive_summary.py` | `get_model("exec_summary", severity)` | exec_summary | `meta.get("severity")` |

### Batch API (3 files — severity loaded from case_meta.json)

| File | Call | Task |
|------|------|------|
| `tools/batch.py` | `get_model("mdr_report", severity)` | mdr_report |
| `tools/batch.py` | `get_model("exec_summary", severity)` | exec_summary |
| `tools/batch.py` | `get_model("secarch", severity)` | secarch |

### No severity (2 files — always medium tier, escalation not triggered)

| File | Call | Why no severity |
|------|------|----------------|
| `tools/client_query.py` | `get_model("chat_response")` | Ad-hoc query, no case exists |
| `tools/detect_phishing_page.py` | `get_model("report")` | Per-screenshot scan, no case context in scope |

### No severity — standalone tools (1 file)

| File | Call | Why no severity |
|------|------|----------------|
| `tools/threat_articles.py` | `get_model("articles")` | Standalone tool, no case context |

### LLM Insight calls via `tools/llm_insight.py` (9 tasks)

All called indirectly through `_call_llm()` which resolves `get_model(task, severity)`.

| File calling llm_insight | Task | Trigger |
|---|---|---|
| `tools/generate_report.py` | `report_narrative` | After all report sections built |
| `tools/campaign_cluster.py` | `campaign_narrative` | Per campaign cluster |
| `tools/generate_queries.py` | `query_refinement` | After template queries generated |
| `tools/triage.py` | `triage_context` | When known malicious/suspicious IOCs found |
| `tools/detect_anomalies.py` | `anomaly_context` | When anomaly findings exist |
| `tools/correlate.py` | `correlation_insight` | When correlation hits exist |
| `tools/response_actions.py` | `response_priority` | After response plan resolved |
| `tools/score_verdicts.py` | `verdict_reconcile` | When providers disagree on verdict |
| `agents/chief.py` | `auto_close_review` | Before auto-closing benign cases |

### Not using `get_model()` (agent layer)

| Area | Status |
|------|--------|
| `agents/*.py` | No direct LLM calls — all go through tool functions |

## Override Examples

```bash
# Force all chat to use Opus instead of Sonnet
SOCAI_MODEL_CHAT_RESPONSE=heavy

# Force secarch to always use Opus regardless of severity
SOCAI_MODEL_SECARCH=heavy

# Use a specific model string for a task
SOCAI_MODEL_FP_TICKET=claude-sonnet-4-6

# Swap the entire "fast" tier to a different model
SOCAI_MODEL_FAST=claude-sonnet-4-6

# Revert everything to single model (legacy behavior)
SOCAI_MODEL_FAST=claude-sonnet-4-6
SOCAI_MODEL_STANDARD=claude-sonnet-4-6
SOCAI_MODEL_HEAVY=claude-sonnet-4-6
```

## Adaptive Thinking

`security_arch_review.py` uses **adaptive thinking** for high/critical severity cases:

```python
call_kwargs["thinking"] = {"type": "adaptive"}
call_kwargs["output_config"] = {"effort": "high"}
```

This replaces the deprecated `budget_tokens` parameter. Adaptive thinking works alongside tool use — the model can both reason deeply and produce structured output via the `record_structured_analysis` tool in a single call.

## Notes

**`report` escalation partially blocked:** The `report` task is in the escalation set, but `detect_phishing_page.py` calls `get_model("report")` without severity — so vision scans always use Haiku even for high-severity cases. This is arguably correct (vision scans are simple yes/no checks) and no code change is recommended.

## Verification

```bash
python3 -c "
from tools.common import get_model
print(get_model('secarch'))                    # claude-sonnet-4-6
print(get_model('secarch', 'high'))            # claude-opus-4-6
print(get_model('chat_response'))              # claude-sonnet-4-6
print(get_model('chat_response', 'critical'))  # claude-opus-4-6
print(get_model('unknown_task'))               # claude-sonnet-4-6 (LLM_MODEL fallback)
"
```
