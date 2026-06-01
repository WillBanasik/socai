"""
tool: vuln_hunt_report
----------------------
Vulnerability hunt worklist — the deliverable for an Encore EQL vulnerability hunt.

Written by the local Claude Desktop agent via the ``write_vuln_hunt_report`` MCP
prompt, then persisted with ``save_report(report_type="vuln_hunt_report")``.

This module retains ``_SYSTEM_PROMPT`` and ``_build_context()`` which the MCP
prompt imports. The report turns the ranked exposure from ``eql_vuln_hunt``
(imported into the case via ``import_vuln_hunt`` / ``create_case(vuln_hunt_id=)``)
plus any active-exploitation hunt findings into a prioritised, machine-consumable
remediation worklist a downstream (AI) engineering pipeline can action.

Supplementary deliverable — does NOT auto-close the case (a hunt is proactive,
not an incident closure).

Output (via save_report):
  cases/<case_id>/artefacts/vuln_hunt/vuln_hunt_report.md
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import load_json, log_error, utcnow

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a SOC analyst producing a VULNERABILITY HUNT WORKLIST. The input is an
Encore EQL vulnerability hunt (exposed hosts + actively-exploited CVEs, already
prioritised by exploitability — EPSS, KEV, active-exploit/ransomware flags), plus
any active-exploitation hunt findings logged in the case. The output is an
engineering handoff: a prioritised, machine-actionable remediation worklist a
downstream (increasingly AI-driven) pipeline can pick up and act on.

Write the report as markdown with the sections below, in order. Where data is
genuinely absent, write "Unknown — <what is missing>" rather than guessing.

### 1. Exposure summary
Headline posture from the hunt summary: hosts assessed, hosts with active exploits
/ ransomware exploits / imminent threats, actively-exploited CVE count, new KEVs.
State the hunt id and client. One honest paragraph on overall risk.

### 2. Confirmed exploitation (if hunted)
If the case contains active-exploitation hunt results (the `vulnerability-hunting`
playbook run via the live log layer), state per CVE/host whether exploitation was
**Confirmed** (data-level link: vulnerable software present AND exploitation
behaviour on the same host+window), **Not found** (hunted, no evidence), or
**Not hunted**. ANALYTICAL STANDARDS APPLY: temporal proximity is not exploitation;
only call it confirmed when the evidence chain is proven. Anything confirmed should
be escalated to a live incident (a separate case), not just a remediation ticket.

### 3. Prioritised remediation worklist
A ranked table, highest exploitability first. Per row: rank, host(s), CVE, severity,
EPSS, exploit status (active-exploit / ransomware / KEV / exploited-in-wild),
devices impacted, exploitation observed (from §2), recommended control, and the
specific action. Choose the control by what can actually be done:
- **patch** — a security update exists and can be deployed (use the CVE's
  Recommendation / RecommendedSecurityUpdate from the hunt).
- **edr_soar_mitigation** — patch is blocked/unavailable or interim cover is needed;
  use the EDR compensating-control tasks from the hunt. (Mechanism note: Performanta
  can apply EDR suppression/mitigation via SOAR — exact procedure is TBD, context to
  follow; specify the criteria and mark execution steps TBD.)

### 4. Compensating controls
The EDR compensating-control tasks from the hunt (classification, detail, impacted
devices, action) — interim cover for what cannot be patched immediately.

### 5. Machine-readable handoff
End with a SINGLE fenced ```json block (nothing after it) for the downstream
pipeline. Use exactly these keys; null/[] for unknowns; every value must match the
prose above and be grounded in the hunt data (never invented):
```json
{
  "client": "<client>",
  "generated_from_hunt": "<hunt_id>",
  "summary": {"hosts_assessed": 0, "hosts_with_active_exploit": 0,
    "hosts_with_ransomware_exploit": 0, "actively_exploited_cves": 0, "new_kevs_48h": 0},
  "worklist": [
    {
      "rank": 1,
      "hosts": [],
      "cve": null,
      "severity": null,
      "epss": null,
      "exploit_status": {"active_exploit": false, "ransomware": false,
        "kev": false, "exploited_in_wild": false},
      "devices_impacted": null,
      "exploitation_observed": "confirmed | not_found | not_hunted",
      "control_type": "patch | edr_soar_mitigation",
      "recommended_action": "<one line>",
      "compensating_control": null,
      "soar_suppression": {"status": "tbd_pending_procedure", "criteria": null}
    }
  ]
}
```

RULES:
1. Rank by real exploitability (active-exploit / ransomware / KEV / EPSS), NOT raw CVSS.
2. Ground every worklist item in the hunt data; never invent a host, CVE, or control.
3. exploitation_observed is "confirmed" ONLY with a proven data-level link (§2).
4. Tone: technical, direct, structured — an engineering worklist, not a narrative.
5. Output the markdown report only — no preamble; the json block is the last thing.
"""


def _safe_load(path: Path, case_id: str = "") -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error(case_id, "vuln_hunt_report.safe_load", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _fmt_rows(rows: list[dict], cols: list[str], cap: int) -> list[str]:
    out = []
    for r in rows[:cap]:
        bits = [f"{c}={r.get(c)}" for c in cols if r.get(c) not in (None, "")]
        out.append("  - " + " | ".join(bits))
    if len(rows) > cap:
        out.append(f"  - …({len(rows) - cap} more in the hunt artefact)")
    return out


def _build_context(case_id: str) -> str:
    """Assemble context from the imported vuln-hunt artefact(s) + case notes."""
    case_dir = CASES_DIR / case_id
    parts: list[str] = [f"# Case: {case_id}\n"]

    meta = _safe_load(case_dir / "case_meta.json", case_id)
    if meta:
        parts.append("## Case Metadata")
        parts.append(f"- Title: {meta.get('title', 'N/A')}")
        parts.append(f"- Client: {meta.get('client', 'N/A')}")
        parts.append(f"- Severity: {meta.get('severity', 'N/A')}")
        parts.append("")

    # Imported vulnerability hunt artefact(s)
    eql_dir = case_dir / "artefacts" / "eql_context"
    hunts = sorted(eql_dir.glob("vuln_hunt_*.json")) if eql_dir.exists() else []
    if not hunts:
        parts.append("## Vulnerability Hunt")
        parts.append(
            "_No imported vuln-hunt artefact found. Run `eql_vuln_hunt(client)` then "
            "`import_vuln_hunt(hunt_id, case_id)` (or `create_case(vuln_hunt_id=)`) first._")
        parts.append("")
        return "\n".join(parts)

    for hp in hunts:
        hunt = _safe_load(hp, case_id) or {}
        s = hunt.get("summary") or {}
        parts.append(f"## Vulnerability Hunt {hunt.get('hunt_id', hp.stem)} "
                     f"({hunt.get('client', 'N/A')}, {hunt.get('ts', 'N/A')})")
        parts.append(
            f"- Hosts assessed: {s.get('hosts_assessed', 0)} | "
            f"active-exploit: {s.get('hosts_with_active_exploit', 0)} | "
            f"ransomware: {s.get('hosts_with_ransomware_exploit', 0)} | "
            f"imminent-threat: {s.get('hosts_with_imminent_threats', 0)}")
        parts.append(f"- Actively-exploited CVEs: {s.get('actively_exploited_cves', 0)} | "
                     f"new KEVs (48h): {s.get('new_kevs_48h', 0)}")
        parts.append("")
        for d in hunt.get("domains", []):
            tbl = d.get("table", "")
            rows = d.get("rows", [])
            parts.append(f"### {d.get('domain', tbl)} — `{tbl}` "
                         f"({d.get('row_count', len(rows))} row(s), {d.get('coverage', '?')})")
            if not rows:
                parts.append("  - (no rows)")
                parts.append("")
                continue
            if tbl.endswith("-Hosts"):
                parts += _fmt_rows(rows, ["ComputerName", "OperatingSystem", "PrioritizationIndex",
                    "MaxCVSS", "CriticalVulnerabilities", "HasActiveExploit", "IsRansomwareExploit",
                    "HasImminentThreats", "ExposureScore"], 40)
            elif tbl.endswith("-Vulnerabilities"):
                parts += _fmt_rows(rows, ["CVE", "NistSeverity", "Epss", "DevicesImpacted",
                    "HasBeenExploited", "PrioritizationRating", "Recommendation"], 40)
            elif tbl.endswith("-NewKevsIn48Hrs"):
                parts += _fmt_rows(rows, ["CVE", "Severity", "DaysSinceFirstExploit",
                    "IsRansomwareExploit", "DevicesImpacted", "Solution"], 30)
            elif tbl.endswith("-VulnerabilityEdrControlTaskList"):
                parts += _fmt_rows(rows, ["Classification", "Detail", "ImpactedDevices", "Action"], 30)
            else:
                parts += _fmt_rows(rows, list(rows[0].keys()), 10)
            parts.append("")

    # Case notes / logged evidence (active-exploitation hunt results land here)
    notes_path = case_dir / "notes" / "analyst_input.md"
    if notes_path.exists():
        notes = notes_path.read_text(errors="replace").strip()
        if notes:
            if len(notes) > 8000:
                notes = notes[:8000] + "\n\n[...notes truncated...]"
            parts.append("## Case Notes / Logged Evidence (incl. active-exploitation hunt)")
            parts.append(notes)
            parts.append("")

    return "\n".join(parts)


def vuln_hunt_report(case_id: str):
    """Stub — generation runs in Claude Desktop via the ``write_vuln_hunt_report``
    MCP prompt, then ``save_report(report_type="vuln_hunt_report")``."""
    return {
        "status": "use_prompt",
        "prompt": "write_vuln_hunt_report",
        "save_tool": "save_report",
        "save_args": {"report_type": "vuln_hunt_report"},
        "case_id": case_id,
        "ts": utcnow(),
    }
