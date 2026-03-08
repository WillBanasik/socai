"""
Batch API infrastructure for bulk LLM processing.

Submit multiple ``messages.create()`` requests as a single batch, poll for
completion, collect results, and dispatch them to the appropriate tool
post-processors.

Usage (CLI)::

    python3 socai.py batch-submit --cases C001 C002 --tools mdr-report exec-summary
    python3 socai.py batch-status --batch-id <id>
    python3 socai.py batch-collect --batch-id <id>
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import anthropic

from config.settings import ANTHROPIC_KEY, BATCH_DIR, BATCH_POLL_INTERVAL, BATCH_TIMEOUT
from tools.common import log_error, save_json, utcnow


# ---------------------------------------------------------------------------
# Batch submission
# ---------------------------------------------------------------------------

def submit_batch(requests: list[dict], batch_label: str = "") -> dict:
    """Submit a list of batch requests via the Anthropic Batch API.

    Each item in *requests* must have ``custom_id`` and ``params`` keys,
    where ``params`` is a dict of ``messages.create()`` kwargs.

    Returns metadata dict with ``batch_id``, ``status``, and ``request_count``.
    """
    if not ANTHROPIC_KEY:
        return {"status": "error", "reason": "ANTHROPIC_API_KEY not set"}

    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    # Convert to Anthropic batch request format
    batch_requests = []
    for req in requests:
        batch_requests.append({
            "custom_id": req["custom_id"],
            "params": req["params"],
        })

    try:
        batch = client.messages.batches.create(requests=batch_requests)
    except Exception as exc:
        log_error("", "batch.submit", str(exc), severity="error")
        return {"status": "error", "reason": str(exc)}

    batch_id = batch.id
    meta = {
        "batch_id": batch_id,
        "status": batch.processing_status,
        "request_count": len(batch_requests),
        "label": batch_label,
        "submitted_at": utcnow(),
        "custom_ids": [r["custom_id"] for r in requests],
    }

    # Persist metadata
    BATCH_DIR.mkdir(parents=True, exist_ok=True)
    save_json(BATCH_DIR / f"{batch_id}.json", meta)

    print(f"[batch] Submitted batch {batch_id} with {len(batch_requests)} request(s)")
    return meta


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------

def poll_batch(batch_id: str, poll_interval: int = BATCH_POLL_INTERVAL,
               timeout: int = BATCH_TIMEOUT) -> dict:
    """Poll a batch until it reaches ``ended`` status or times out.

    Returns the final batch status dict.
    """
    if not ANTHROPIC_KEY:
        return {"status": "error", "reason": "ANTHROPIC_API_KEY not set"}

    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    start = time.time()

    while True:
        try:
            batch = client.messages.batches.retrieve(batch_id)
        except Exception as exc:
            log_error("", "batch.poll", str(exc), severity="error",
                      context={"batch_id": batch_id})
            return {"status": "error", "reason": str(exc), "batch_id": batch_id}

        status = batch.processing_status
        print(f"[batch] {batch_id}: {status}")

        if status == "ended":
            return {
                "batch_id": batch_id,
                "status": status,
                "ended_at": utcnow(),
            }

        elapsed = time.time() - start
        if elapsed >= timeout:
            return {
                "batch_id": batch_id,
                "status": "timeout",
                "elapsed_seconds": round(elapsed),
            }

        time.sleep(poll_interval)


# ---------------------------------------------------------------------------
# Result collection
# ---------------------------------------------------------------------------

def collect_batch_results(batch_id: str) -> list[dict]:
    """Iterate over batch results and return them as a list.

    Also saves results to ``registry/batches/<batch_id>_results.json``.
    """
    if not ANTHROPIC_KEY:
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    results: list[dict] = []
    try:
        for entry in client.messages.batches.results(batch_id):
            result = {
                "custom_id": entry.custom_id,
                "result_type": entry.result.type,
            }
            if entry.result.type == "succeeded":
                msg = entry.result.message
                # Extract text content
                text_parts = []
                for block in msg.content:
                    if getattr(block, "type", "") == "text":
                        text_parts.append(block.text)
                result["text"] = "\n".join(text_parts)
                result["usage"] = {
                    "input_tokens": msg.usage.input_tokens,
                    "output_tokens": msg.usage.output_tokens,
                }
            elif entry.result.type == "errored":
                result["error"] = str(getattr(entry.result, "error", "unknown"))
            results.append(result)
    except Exception as exc:
        log_error("", "batch.collect", str(exc), severity="error",
                  context={"batch_id": batch_id})
        return []

    # Save results
    BATCH_DIR.mkdir(parents=True, exist_ok=True)
    results_path = BATCH_DIR / f"{batch_id}_results.json"
    save_json(results_path, {"batch_id": batch_id, "collected_at": utcnow(), "results": results})

    print(f"[batch] Collected {len(results)} result(s) for batch {batch_id}")
    return results


# ---------------------------------------------------------------------------
# Result dispatch — route results to per-tool post-processors
# ---------------------------------------------------------------------------

def dispatch_batch_results(results: list[dict]) -> dict:
    """Parse ``custom_id`` (format ``tool_name:case_id``) and delegate
    to per-tool post-processors that write artefacts.

    Returns a summary dict.
    """
    dispatched = 0
    errors = 0

    for result in results:
        custom_id = result.get("custom_id", "")
        if ":" not in custom_id:
            errors += 1
            continue

        tool_name, case_id = custom_id.split(":", 1)
        text = result.get("text", "")

        if result.get("result_type") != "succeeded" or not text:
            errors += 1
            log_error(case_id, f"batch.dispatch.{tool_name}",
                      f"Batch result failed: {result.get('error', 'no text')}",
                      severity="warning")
            continue

        try:
            _dispatch_single(tool_name, case_id, text)
            dispatched += 1
        except Exception as exc:
            errors += 1
            log_error(case_id, f"batch.dispatch.{tool_name}", str(exc),
                      severity="error")

    return {"dispatched": dispatched, "errors": errors, "total": len(results)}


def _dispatch_single(tool_name: str, case_id: str, text: str) -> None:
    """Write a single batch result to the appropriate artefact path."""
    from config.settings import CASES_DIR
    from tools.common import write_artefact

    if tool_name == "mdr-report":
        path = CASES_DIR / case_id / "reports" / "mdr_report.md"
        write_artefact(path, text)
        print(f"[batch] Wrote MDR report for {case_id}")

    elif tool_name == "exec-summary":
        path = CASES_DIR / case_id / "artefacts" / "executive_summary" / "executive_summary.md"
        write_artefact(path, text)
        print(f"[batch] Wrote executive summary for {case_id}")

    elif tool_name == "cve-context":
        # CVE batch results are JSON text from structured output
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {"raw_text": text}
        path = CASES_DIR / case_id / "artefacts" / "cve" / "cve_llm_assessment.json"
        save_json(path, data)
        print(f"[batch] Wrote CVE assessment for {case_id}")

    elif tool_name == "secarch":
        path = CASES_DIR / case_id / "artefacts" / "security_architecture" / "security_arch_review.md"
        write_artefact(path, text)
        print(f"[batch] Wrote security arch review for {case_id}")

    else:
        print(f"[batch] Unknown tool '{tool_name}' for {case_id} — skipped")


# ---------------------------------------------------------------------------
# Batch preparation helpers (per-tool)
# ---------------------------------------------------------------------------

def _case_severity(case_id: str) -> str:
    """Load severity from case_meta.json, defaulting to 'medium'."""
    from tools.common import load_json
    from config.settings import CASES_DIR
    meta_path = CASES_DIR / case_id / "case_meta.json"
    try:
        return load_json(meta_path).get("severity", "medium")
    except (FileNotFoundError, Exception):
        return "medium"


def prepare_mdr_report_batch(case_id: str) -> dict | None:
    """Prepare an MDR report batch request for *case_id*."""
    try:
        from tools.generate_mdr_report import _build_context, _SYSTEM_CACHED
        from tools.common import get_model

        severity = _case_severity(case_id)
        context = _build_context(case_id)
        if not context.strip():
            return None

        return {
            "custom_id": f"mdr-report:{case_id}",
            "params": {
                "model": get_model("mdr_report", severity),
                "system": _SYSTEM_CACHED,
                "messages": [{"role": "user", "content": f"Write an MDR report.\n\n{context}"}],
                "max_tokens": 8192,
            },
        }
    except Exception as exc:
        log_error(case_id, "batch.prepare.mdr_report", str(exc), severity="warning")
        return None


def prepare_executive_summary_batch(case_id: str) -> dict | None:
    """Prepare an executive summary batch request for *case_id*."""
    try:
        from tools.executive_summary import _build_context, _SYSTEM_CACHED
        from tools.schemas import ExecutiveSummary
        from tools.structured_llm import structured_call_params
        from tools.common import get_model

        severity = _case_severity(case_id)
        context = _build_context(case_id)
        if not context.strip():
            return None

        return structured_call_params(
            model=get_model("exec_summary", severity),
            system=_SYSTEM_CACHED,
            messages=[{
                "role": "user",
                "content": f"Produce an executive summary.\n\n{context}",
            }],
            output_schema=ExecutiveSummary,
            max_tokens=4096,
            custom_id=f"exec-summary:{case_id}",
        )
    except Exception as exc:
        log_error(case_id, "batch.prepare.exec_summary", str(exc), severity="warning")
        return None


def prepare_secarch_batch(case_id: str) -> dict | None:
    """Prepare a security architecture review batch request for *case_id*."""
    try:
        from tools.security_arch_review import _build_context, _SYSTEM_CACHED
        from tools.common import get_model

        severity = _case_severity(case_id)
        context = _build_context(case_id)
        if not context.strip():
            return None

        return {
            "custom_id": f"secarch:{case_id}",
            "params": {
                "model": get_model("secarch", severity),
                "system": _SYSTEM_CACHED,
                "messages": [{"role": "user", "content": (
                    f"Please produce a Security Architecture Review for the "
                    f"following investigation.\n\n{context}"
                )}],
                "max_tokens": 8192,
            },
        }
    except Exception as exc:
        log_error(case_id, "batch.prepare.secarch", str(exc), severity="warning")
        return None


# ---------------------------------------------------------------------------
# List batches
# ---------------------------------------------------------------------------

def list_batches() -> list[dict]:
    """List all known batch metadata from the registry."""
    if not BATCH_DIR.exists():
        return []
    batches = []
    for p in sorted(BATCH_DIR.glob("*.json")):
        if p.name.endswith("_results.json"):
            continue
        try:
            with open(p) as f:
                batches.append(json.load(f))
        except Exception:
            pass
    return batches
