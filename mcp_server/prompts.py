"""MCP prompt implementations — workflow templates for LLM consumption.

21 prompts in three categories:

**Guided workflows (5):** ``kql_investigation``, ``triage_alert``,
``write_fp_ticket``, ``hitl_investigation``, ``user_security_check``

**Client-side report generation (8):** ``write_mdr_report``,
``write_pup_report``, ``write_fp_closure``, ``write_fp_tuning``,
``write_executive_summary``, ``write_security_arch_review``,
``write_threat_article``, ``write_response_plan``

**Client-side analysis (8):** ``run_determination``,
``build_investigation_matrix``, ``review_report``, ``write_timeline``,
``write_evtx_analysis``, ``write_phishing_verdict``, ``write_pe_verdict``,
``write_cve_context``
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Shared text blocks — single source of truth for content used in multiple prompts
# ---------------------------------------------------------------------------

_CLASSIFICATION_TREE = [
    "```",
    "Did the detection logic fire correctly on real activity?",
    "├─ NO  → False Positive (FP)",
    "└─ YES → Was that activity malicious?",
    "         ├─ YES → True Positive (TP)",
    "         └─ NO  → Benign Positive (BP)",
    "```",
    "",
    "- **True Positive (TP)** — confirmed malicious activity requiring response",
    "- **Benign Positive (BP)** — alert fired correctly on real activity, but that activity is",
    "  expected, authorised, or non-threatening (e.g. new service account from unfamiliar infra,",
    "  authorised pen-test, security tooling triggering behavioural detections, real user travel).",
    "  Sub-classify as: *suspicious but expected* (known/authorised) or *suspicious but not malicious*",
    "  (genuinely unusual, but no threat confirmed).",
    "- **False Positive (FP)** — detection misfired (geo-IP error, benign string match, logic bug)",
    "- **Inconclusive** — insufficient data, escalate or gather more evidence",
    "",
    "**Never combine classifications** — 'True Positive Benign Positive' is invalid.",
    "If the alert was accurate but the activity was authorised, classify as **Benign Positive**.",
]

_ANALYTICAL_STANDARDS = [
    "## Analytical Standards (NON-NEGOTIABLE)",
    "",
    "- Every finding must be provable with supplied data",
    "- Temporal proximity is NEVER causation",
    "- No gap-filling with speculation",
    "- Language: \"Confirmed\" = data proves it. \"Assessed\" = inference. \"Unknown\" = no data",
    "- Never combine Sentinel classifications (TP + BP is invalid)",
    "- Actively seek disconfirming evidence before concluding",
]

_BEHAVIOURAL_ASSESSMENT = [
    "## Behavioural Assessment",
    "",
    "- What the session DID matters more than where it came FROM",
    "- A suspicious IP alone is not proof of compromise — assess the ACTIVITY",
    "- Adversarial IP + benign activity pattern = likely personal VPN, not compromise",
    "- When activity is benign: recommend confirming VPN usage before containment",
]


def _get_kql_playbooks() -> dict[str, str]:
    """Load available KQL playbook IDs and names from disk (cached after first call)."""
    try:
        from tools.kql_playbooks import list_playbooks
        return {p["id"]: p["name"] for p in list_playbooks()}
    except Exception:
        # Fallback if playbook files are missing
        return {}


# Cache on module load for the docstring; refreshed per-call in the prompt body
_KQL_PLAYBOOKS = _get_kql_playbooks()


def register_prompts(mcp: FastMCP) -> None:
    """Register all MCP prompt handlers."""

    # ------------------------------------------------------------------
    # Unified KQL Playbook prompt (replaces 7 individual prompts)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def kql_investigation(
        playbook: str = "",
        target_entity: str = "",
        timeframe: str = "7d",
        extra_params: str = "",
    ) -> str:
        """Multi-stage KQL investigation playbook — select the playbook that matches your attack type.

        Available playbooks:
        - **phishing** — email delivery, URL clicks, credential harvest
        - **account-compromise** — sign-ins, on-prem AD logons, lockouts, MDI, UEBA, post-compromise audit
        - **malware-execution** — process tree, file events, persistence
        - **privilege-escalation** — role changes, actor legitimacy
        - **data-exfiltration** — volume anomalies, cloud access, network transfers
        - **lateral-movement** — RDP/SMB pivots, credential access, blast radius
        - **ioc-hunt** — cross-table IOC sweep + context pivot

        Tip: call `classify_attack` first to determine which playbook to use,
        then select this prompt with the matching playbook ID.

        Parameters
        ----------
        playbook : str
            Playbook ID (e.g. "phishing", "account-compromise", "malware-execution").
        target_entity : str
            Primary target — email address, UPN, hostname, or IOC value depending on playbook.
        timeframe : str
            Lookback period (e.g. "7d", "24h", "30d"). Defaults to 7d.
        extra_params : str
            Additional parameters as key=value pairs, comma-separated
            (e.g. "threshold_mb=500,source_host=DESKTOP-01").
        """
        from tools.kql_playbooks import load_playbook, render_stage

        # Resolve playbook — refresh from disk each call so new playbooks are picked up
        available = _get_kql_playbooks()
        playbook_id = playbook.strip().lower() if playbook else ""
        if playbook_id not in available:
            valid = ", ".join(f"`{k}`" for k in available)
            return (
                f"Unknown playbook `{playbook_id}`. "
                f"Valid playbooks: {valid}.\n\n"
                "Tip: call `classify_attack` to determine which playbook matches your alert."
            )

        pb = load_playbook(playbook_id)
        if not pb:
            return f"Playbook `{playbook_id}` not found on disk."

        display_name = available[playbook_id]

        # Build KQL parameter dict from inputs
        params: dict[str, str] = {}
        if timeframe:
            # Different playbooks use different param names for timeframe
            params["timeframe"] = timeframe
            params["lookback"] = timeframe

        # Map target_entity to the playbook's expected parameter
        if target_entity:
            _entity_map = {
                "phishing": "target_email",
                "account-compromise": "upn",
                "malware-execution": "hostname",
                "privilege-escalation": "target_host",
                "data-exfiltration": "target_upn",
                "lateral-movement": "source_host",
                "ioc-hunt": "ioc_value",
            }
            param_name = _entity_map.get(playbook_id, "target_entity")
            params[param_name] = target_entity
            # Account investigation needs both UPN and sAMAccountName
            if playbook_id == "account-compromise" and "username" not in params:
                # Derive sAMAccountName from UPN (part before @)
                username = target_entity.split("@")[0] if "@" in target_entity else target_entity
                params["username"] = username

        # Parse extra_params (key=value,key=value)
        if extra_params:
            for pair in extra_params.split(","):
                pair = pair.strip()
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k.strip()] = v.strip()

        # Render the playbook
        lines = [
            f"# {display_name} Investigation Playbook",
            "",
            f"**Playbook:** `{playbook_id}`",
            f"**Target entity:** {target_entity or '(not specified)'}",
            f"**Timeframe:** {timeframe}",
            "",
            "**Before proceeding:** Confirm the client via `lookup_client` and register "
            "the alert via `add_evidence`. Call `classify_attack` if you have not already. "
            "The `lookup_client` result includes `knowledge_base`, `response_playbook`, and "
            "`sentinel_reference` — read these to understand the client's environment, "
            "available tables, and escalation procedures before running queries.",
            "",
            "## Overview",
            pb.get("description", ""),
            "",
        ]

        # Inject table schemas so the agent knows correct column names
        if pb.get("tables"):
            try:
                from config.sentinel_schema import get_table_schema_summary, has_registry
                if has_registry():
                    lines.append("## Table Schemas (use these exact column names)")
                    lines.append("")
                    for table_name in pb["tables"]:
                        summary = get_table_schema_summary(table_name, max_columns=20)
                        if summary:
                            lines.append(f"```")
                            lines.append(summary)
                            lines.append(f"```")
                            lines.append("")
            except Exception:
                pass

        if pb.get("parameters"):
            lines.append("## Playbook Parameters")
            for param in pb["parameters"]:
                lines.append(f"- **{param['name']}**: {param.get('description', '')}")
            lines.append("")

        lines.append("## Investigation Stages")
        lines.append("")
        lines.append("**Efficiency:** When you have multiple independent queries "
                      "(e.g. sign-in logs + audit logs + MFA status), submit them "
                      "together via `run_kql_batch` instead of calling `run_kql` "
                      "sequentially — this runs queries in parallel and is 2-3× faster. "
                      "Only use sequential `run_kql` when one query's results inform "
                      "the next query's parameters. "
                      "**Use `max_rows=200` or higher** for stages that "
                      "return summarised data — this minimises round-trips and gives you "
                      "the full analytical picture in a single call.")
        lines.append("")

        for i, stage in enumerate(pb.get("stages", []), 1):
            lines.append(f"### Stage {i} — {stage.get('name', stage.get('title', ''))}")
            if stage.get("description"):
                lines.append(stage["description"])
            lines.append("")

            rendered = render_stage(pb, i, params)
            if rendered:
                lines.append("```kql")
                lines.append(rendered)
                lines.append("```")
                lines.append("")

        if pb.get("definitions"):
            lines.append("## Definitions")
            for defn in pb["definitions"]:
                lines.append(f"- **{defn['term']}**: {defn['definition']}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Workflow prompts
    # ------------------------------------------------------------------

    @mcp.prompt()
    def triage_alert(
        alert_title: str = "",
        severity: str = "",
        raw_alert_json: str = "",
    ) -> str:
        """Guided alert triage workflow.

        Walk through a structured triage process: classify the alert, identify
        key IOCs, check against known intelligence, and recommend next steps.

        Parameters
        ----------
        alert_title : str
            Title of the alert to triage.
        severity : str
            Alert severity (low, medium, high, critical).
        raw_alert_json : str
            Raw alert payload as JSON string.
        """
        lines = [
            "# Alert Triage Workflow",
            "",
            f"**Alert:** {alert_title or '(not specified)'}",
            f"**Severity:** {severity or '(not specified)'}",
            "",
        ]

        if raw_alert_json:
            lines.extend([
                "## Raw Alert Data",
                "```json",
                raw_alert_json,
                "```",
                "",
            ])

        lines.extend([
            "## Triage Steps",
            "",
            "### 1. Classification",
            "- Call `classify_attack` with the alert title and description",
            "- The result tells you the attack type and recommended tool sequence",
            "- Do NOT skip this step, even if the attack type seems obvious",
            "",
            "### 2. Client Identification",
            "- Call `lookup_client` to confirm the client and available platforms",
            "- The result includes `knowledge_base`, `response_playbook`, and `sentinel_reference` "
            "— read these to understand the client's environment, known FP patterns, "
            "escalation procedures, and available Sentinel tables before proceeding",
            "- Do NOT proceed without a confirmed client",
            "",
            "### 3. IOC Extraction & Enrichment",
            "- Call `recall_cases` to check if any IOCs appear in prior investigations",
            "  (historical context only — do not merge into those cases)",
            "- Call `quick_enrich` to query threat intelligence providers (no case required)",
            "",
            "### 4. Contextualisation",
            "- Identify the affected user(s) and asset(s)",
            "- Determine the business impact and data sensitivity",
            "- Check for related alerts in the same timeframe",
            "",
            "### 4.5. Dark Web Exposure (if account compromise suspected)",
            "If the alert involves credential theft, account compromise, or a",
            "compromised user, check dark web sources before reaching a verdict:",
            "- `hudsonrock_lookup` — infostealer exposure for user email",
            "- `xposed_breach_check` — historical breach data for user email",
            "Positive results indicate the compromise may be credential-based",
            "and strengthen a TP determination.",
            "",
            "### 5. Verdict",
            "Determine the Sentinel incident classification using this decision guide:",
            "",
            *_CLASSIFICATION_TREE,
            "",
            "**CRITICAL — Assess behaviour, not just indicators:**",
            "A suspicious IP or impossible-travel alert is a SIGNAL, not a verdict. Before",
            "concluding compromise, check what the session actually did. Attackers perform",
            "attacker actions (inbox rules, mail forwarding, BEC, bulk download, OAuth consent,",
            "MFA registration). Normal users perform normal actions (reading routine emails,",
            "opening shared docs, calendar). If the activity pattern is entirely benign with",
            "zero attacker TTPs, the most likely explanation is a VPN — confirm with the user",
            "before recommending containment.",
            "",
            "### 6. Response Recommendation",
            "- If TP: recommend containment, eradication, and recovery actions",
            "- If BP: document the finding and any tuning recommendations",
            "- If FP: document the finding, generate suppression ticket with `prepare_fp_ticket`",
            "- If Inconclusive: identify what additional data is needed",
            "",
            "### 7. Documentation & Deliverables",
            "- Case creation is **deferred** — deliverable tools (`prepare_mdr_report`,",
            "  `prepare_pup_report`, `prepare_fp_ticket`) auto-create and promote a case",
            "  if one doesn't exist yet. You can also call `create_case` manually at any point.",
            "- Generate the MDR report with `prepare_mdr_report` (auto-creates case)",
            "- If FP, generate suppression ticket with `prepare_fp_ticket` (auto-creates case)",
            "- Once a case exists, register evidence with `add_evidence` and run `enrich_iocs`",
        ])

        return "\n".join(lines)

    @mcp.prompt()
    def write_fp_ticket(
        alert_json: str = "",
        query_text: str = "",
        platform: str = "",
    ) -> str:
        """False-positive ticket generation workflow.

        Guide the LLM through analysing a false-positive alert and generating
        a suppression ticket with tuning recommendations.

        Parameters
        ----------
        alert_json : str
            Raw alert payload.
        query_text : str
            Original detection query.
        platform : str
            Detection platform (e.g. "sentinel", "crowdstrike", "splunk").
            For CrowdStrike/NGSIEM, call ``load_ngsiem_reference`` first
            for correct syntax and field names.
        """
        lines = [
            "# False-Positive Ticket Generation Workflow",
            "",
            f"**Platform:** {platform or '(auto-detect from alert data)'}",
            "",
        ]

        if alert_json:
            lines.extend([
                "## Alert Data",
                "```json",
                alert_json,
                "```",
                "",
            ])

        if query_text:
            lines.extend([
                "## Detection Query",
                "```",
                query_text,
                "```",
                "",
            ])

        lines.extend([
            "## Workflow",
            "",
            "### 1. Validate False Positive",
            "- Confirm the alert is genuinely a false positive (not a benign positive)",
            "- Document the evidence that proves this is not malicious activity",
            "- Identify the specific conditions that triggered the false detection",
            "",
            "### 2. Root Cause Analysis",
            "- Identify why the detection rule fired incorrectly",
            "- Determine if this is a recurring pattern or one-off",
            "- Check if other organisations report similar FPs for this detection",
            "",
            "### 3. Tuning Recommendation",
            "- Propose specific query modifications to suppress this FP class",
            "- Ensure the tuning does not create blind spots for real threats",
            "- Consider allowlisting vs. query refinement vs. threshold adjustment",
            "",
            "### 4. Generate Tickets",
            "- Use `prepare_fp_ticket` with the alert data and platform → 2-sentence closure comment",
            "- Use `prepare_fp_tuning_ticket` with the alert data, platform, and detection query → structured SIEM engineering handoff",
            "- The FP ticket closes the alert; the tuning ticket tells detection engineering how to fix the rule",
            "- Generate BOTH when the analyst wants the alert closed AND the rule tuned",
        ])

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # HITL investigation prompt
    # ------------------------------------------------------------------

    @mcp.prompt()
    def hitl_investigation(
        incident_data: str = "",
        client: str = "",
        severity: str = "",
    ) -> str:
        """Human-in-the-loop investigation workflow with analyst checkpoints.

        A structured investigation workflow where the analyst controls every
        decision point. The LLM pauses at checkpoints and waits for approval
        before proceeding.

        Parameters
        ----------
        incident_data : str
            Raw incident/alert payload (JSON or free text).
        client : str
            Client name. If unknown, the workflow will prompt lookup.
        severity : str
            Alert severity (low, medium, high, critical). Auto-detected if omitted.
        """
        lines = [
            "# HITL Investigation Workflow",
            "",
            f"**Client:** {client or '(MUST BE IDENTIFIED — call lookup_client)'}",
            f"**Severity:** {severity or '(auto-detect from alert data)'}",
            "",
        ]

        if incident_data:
            lines.extend([
                "## Incident Data",
                "```",
                incident_data,
                "```",
                "",
            ])

        lines.extend([
            "## Workflow",
            "",
            "This is a human-in-the-loop workflow. At each checkpoint (CP), summarise your findings,",
            "present your recommendation, and WAIT for analyst approval before proceeding.",
            "",
            "---",
            "",
            "### PHASE 1 — INTAKE (assessment, no case needed)",
            "",
            "1. Call `classify_attack` with the alert data",
            "2. Call `lookup_client` to confirm client and available platforms — the result "
            "includes `knowledge_base`, `response_playbook`, and `sentinel_reference`. "
            "Internalise these: known FP patterns, escalation matrix, available Sentinel tables",
            "3. Call `recall_cases` to check for prior investigations with overlapping IOCs",
            "",
            "**CP1 — PLAN APPROVAL**",
            "Present to the analyst:",
            "- Attack classification and confidence",
            "- Recommended tool sequence (from classify_attack)",
            "- Any prior case overlap",
            "- Proposed case title and severity",
            "",
            "**Wait for analyst approval.** No case is created yet — caseless tools",
            "(`quick_enrich`, `extract_iocs_from_text`, KQL queries, `recall_cases`,",
            "browser sessions) work without a case. Case-bound tools like `enrich_iocs`",
            "and `add_evidence` require a case_id. The case materialises automatically",
            "when a deliverable is generated in Phase 4, or you can call `create_case`",
            "at any point to unlock case-bound tools.",
            "",
            "---",
            "",
            "### PHASE 2 — COLLECT (evidence gathering)",
            "",
            "Follow the tool sequence from classify_attack. Use caseless tools when",
            "no case exists yet, or call `create_case` to unlock case-bound tools.",
            "",
            "Caseless enrichment:",
            "- `quick_enrich` — fast IOC lookups (no case required)",
            "- `extract_iocs_from_text` — IOC extraction (no case required)",
            "- `run_kql_batch` — Sentinel queries in parallel (prefer over sequential `run_kql`)",
            "- `recall_cases` — prior investigation search (no case required)",
            "",
            "Case-bound (call `create_case` first, or defer to Phase 4):",
            "- `enrich_iocs` — extract and enrich all IOCs (writes to case)",
            "- `add_evidence` — attach raw alert data (writes to case)",
            "- `capture_urls` → `detect_phishing` — for URL/phishing cases",
            "- `analyse_email` — for email-based alerts",
            "- `start_sandbox_session` — for file/malware cases (if warranted)",
            "",
            "Dark web intelligence (use when account compromise or credential theft suspected):",
            "- `hudsonrock_lookup` — check infostealer exposure for user email/domain (no case required)",
            "- `xposed_breach_check` — check historical breach databases for email/domain (no case required)",
            "- `intelx_search` — search dark web, pastes, and leaks for indicators (no case required)",
            "- `darkweb_exposure_summary` — aggregate dark web exposure for a case (case-bound)",
            "",
            "**CP2 — EVIDENCE REVIEW**",
            "Present to the analyst:",
            "- IOC verdicts (malicious/suspicious/clean counts)",
            "- Key findings from KQL/Sentinel queries",
            "- Phishing detection results (if applicable)",
            "- Any enrichment gaps or missing data",
            "",
            "**Wait for analyst approval.** The analyst may:",
            "- Approve and proceed to analysis",
            "- Request additional collection (loop back with specific tools)",
            "- Redirect the investigation based on new findings",
            "",
            "Max collect↔analyse loops: 3",
            "",
            "---",
            "",
            "### PHASE 3 — ANALYSE (reasoning and determination)",
            "",
            "1. `generate_investigation_matrix` — build the Rumsfeld matrix",
            "2. `run_determination` — evidence-chain analysis",
            "3. `review_report_quality` — quality gate check (if report exists)",
            "4. If gaps remain, propose follow-up actions (`list_followup_proposals`)",
            "",
            "Determine the Sentinel incident classification:",
            *_CLASSIFICATION_TREE,
            "",
            "**CP3 — DISPOSITION APPROVAL**",
            "Present to the analyst:",
            "- Proposed disposition (TP/BP/FP/inconclusive) with reasoning",
            "- Evidence chain summary (confirmed/assessed/unknown for each link)",
            "- Any remaining gaps",
            "- Recommendation: proceed to deliverable, or discard",
            "",
            "**Wait for analyst approval.** On approval:",
            "- Proceed to Phase 4 — deliverable tools auto-create and promote the case",
            "- Or `discard_case` if a case was manually created and the alert is not worth investigating",
            "",
            "---",
            "",
            "### PHASE 4 — VERIFY (report generation — case auto-created here)",
            "",
            "Deliverable tools auto-create and promote a case if one doesn't exist yet.",
            "You can also call `create_case` manually before this phase if preferred.",
            "",
            "Generate the appropriate report based on disposition:",
            "",
            "- **True Positive:** `prepare_mdr_report` (auto-creates case if needed)",
            "- **Benign Positive:** `prepare_mdr_report` (auto-creates case if needed)",
            "- **False Positive:** `prepare_fp_ticket` (auto-creates case if needed)",
            "  (+ `prepare_fp_tuning_ticket` if tuning needed)",
            "- **PUP/PUA:** `prepare_pup_report` (auto-creates case if needed)",
            "- **Inconclusive:** `create_case` → `generate_report` (mark gaps clearly)",
            "",
            "Additional for high/critical:",
            "- `generate_queries` — SIEM hunt queries",
            "- `response_actions` — containment guidance",
            "- `prepare_executive_summary` — leadership summary",
            "",
            "**CP4 — REPORT APPROVAL**",
            "Present the report summary to the analyst for review.",
            "",
            "**Wait for analyst approval.** The analyst may:",
            "- Approve the report",
            "- Request revisions (loop back to analyse, max 2 times)",
            "",
            "---",
            "",
            "### PHASE 5 — DELIVER (case closure)",
            "",
            "On report approval:",
            "- Report tools auto-close the case (MDR, PUP, FP ticket)",
            "- If not auto-closed, call `close_case` with the confirmed disposition",
            "",
            "---",
            "",
            *_ANALYTICAL_STANDARDS,
            "",
            *_BEHAVIOURAL_ASSESSMENT,
            "",
            "## Rules",
            "",
            "- ONE ALERT = ONE CASE — never reuse existing cases for new alerts",
            "- Always identify the client before running queries",
            "- Always call recall_cases before enrichment",
            "- Reports auto-close cases via save_report (after prepare_mdr_report, prepare_pup_report, prepare_fp_ticket)",
            "- Keep it concise — lead with findings, not process narration",
            "- Before writing or reviewing LogScale/NGSIEM queries, call `load_ngsiem_reference` (sections=[\"rules\", \"syntax\"]) to load authoring conventions, anti-patterns, and correct CQL syntax. Add \"columns\" when you need field names for a specific log source",
        ])

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Analysis prompts (client-side — replace server LLM calls)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def run_determination(case_id: str) -> str:
        """Run evidence-chain disposition analysis locally in Claude Desktop.

        Evaluates all case evidence and proposes a disposition (TP/BP/FP/inconclusive)
        with an evidence chain, confidence level, and gap analysis.

        When done, call ``add_finding`` with the disposition and reasoning,
        or proceed to report generation.

        Parameters
        ----------
        case_id : str
            Case to analyse.
        """
        from tools.determination import _DETERMINATION_SYSTEM_PROMPT as prompt

        # Build the same context the server-side tool would
        from config.settings import CASES_DIR
        from tools.common import load_json
        import json

        case_dir = CASES_DIR / case_id
        parts = [f"# Case: {case_id}\n"]

        for label, path in [
            ("Case Metadata", case_dir / "case_meta.json"),
            ("Verdict Summary", case_dir / "artefacts" / "enrichment" / "verdict_summary.json"),
            ("Enrichment", case_dir / "artefacts" / "enrichment" / "enrichment.json"),
            ("Anomalies", case_dir / "artefacts" / "anomalies" / "anomaly_report.json"),
            ("Correlation", case_dir / "artefacts" / "correlation" / "correlation.json"),
            ("Investigation Matrix", case_dir / "artefacts" / "analysis" / "investigation_matrix.json"),
            ("Email Analysis", case_dir / "artefacts" / "email" / "email_analysis.json"),
        ]:
            if path.exists():
                try:
                    data = load_json(path)
                    text = json.dumps(data, indent=2, default=str)
                    if len(text) > 3000:
                        text = text[:3000] + "\n[...truncated...]"
                    parts.append(f"## {label}\n{text}\n")
                except Exception:
                    pass

        # Web captures
        web_dir = case_dir / "artefacts" / "web"
        if web_dir.is_dir():
            captures = []
            for sub in sorted(web_dir.iterdir()):
                mp = sub / "capture_manifest.json" if sub.is_dir() else None
                if mp and mp.exists():
                    try:
                        m = load_json(mp)
                        captures.append(
                            f"- {sub.name}: title=\"{m.get('title', 'N/A')}\" "
                            f"status={m.get('status_code', 'N/A')} "
                            f"final_url={m.get('final_url', 'N/A')}"
                        )
                    except Exception:
                        pass
            if captures:
                parts.append(f"## Web Captures\n" + "\n".join(captures) + "\n")

        # Analyst notes
        notes_path = case_dir / "notes" / "analyst_input.md"
        if notes_path.exists():
            parts.append(f"## Analyst Notes\n{notes_path.read_text(encoding='utf-8')[:2000]}\n")

        context = "\n".join(parts)

        return (
            f"# Evidence-Chain Disposition Analysis — Instructions\n\n"
            f"{prompt}\n\n"
            f"---\n\n"
            f"# Case Evidence\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Analyse the evidence for case **{case_id}** and produce a structured "
            f"disposition proposal. Include:\n"
            f"- **Disposition:** true_positive / benign_positive / false_positive / inconclusive\n"
            f"- **Confidence:** high / medium / low\n"
            f"- **Evidence chain:** each link with status (confirmed/assessed/unknown)\n"
            f"- **Gaps:** what evidence is missing\n"
            f"- **Disconfirming checks:** what you looked for that could disprove your conclusion\n"
            f"- **Reasoning:** narrative justification\n\n"
            f"Present your analysis, then call `add_finding` with your conclusion.\n"
        )

    @mcp.prompt()
    def build_investigation_matrix(case_id: str) -> str:
        """Build an investigation reasoning matrix locally in Claude Desktop.

        Produces a Rumsfeld-style matrix: known_knowns (facts with evidence),
        known_unknowns (gaps), and hypotheses (testable claims with
        disconfirming checks).

        Parameters
        ----------
        case_id : str
            Case to analyse.
        """
        from tools.investigation_matrix import _MATRIX_SYSTEM_PROMPT as prompt
        from tools.investigation_matrix import _build_query_context

        from config.settings import CASES_DIR
        from tools.common import load_json
        import json

        case_dir = CASES_DIR / case_id
        parts = [f"# Case: {case_id}\n"]

        # Load case metadata for attack type
        try:
            meta = load_json(case_dir / "case_meta.json")
            attack_type = meta.get("attack_type", "generic")
            parts.append(f"## Case Metadata\n{json.dumps(meta, indent=2, default=str)}\n")
        except Exception:
            attack_type = "generic"

        for label, path in [
            ("Verdict Summary", case_dir / "artefacts" / "enrichment" / "verdict_summary.json"),
            ("Enrichment", case_dir / "artefacts" / "enrichment" / "enrichment.json"),
            ("Anomalies", case_dir / "artefacts" / "anomalies" / "anomaly_report.json"),
            ("Correlation", case_dir / "artefacts" / "correlation" / "correlation.json"),
            ("Email Analysis", case_dir / "artefacts" / "email" / "email_analysis.json"),
        ]:
            if path.exists():
                try:
                    data = load_json(path)
                    text = json.dumps(data, indent=2, default=str)
                    if len(text) > 3000:
                        text = text[:3000] + "\n[...truncated...]"
                    parts.append(f"## {label}\n{text}\n")
                except Exception:
                    pass

        # Query context (attack-type specific guidance)
        query_ctx = _build_query_context(attack_type)
        full_prompt = prompt
        if query_ctx:
            full_prompt += f"\n\n{query_ctx}"

        context = "\n".join(parts)

        return (
            f"# Investigation Matrix — Instructions\n\n"
            f"{full_prompt}\n\n"
            f"---\n\n"
            f"# Case Evidence\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Build an investigation reasoning matrix for case **{case_id}**.\n\n"
            f"Structure your output as:\n"
            f"1. **Known Knowns** — facts proved by data (cite specific evidence)\n"
            f"2. **Known Unknowns** — evidence gaps (what data would close each gap)\n"
            f"3. **Hypotheses** — testable claims with disconfirming checks\n"
        )

    @mcp.prompt()
    def review_report(case_id: str) -> str:
        """Review a case report for quality locally in Claude Desktop.

        Checks: unconfirmed claims labelled as confirmed, causal language
        without evidence, speculation, matrix coverage gaps, and analytical
        standard violations.

        Parameters
        ----------
        case_id : str
            Case whose report to review.
        """
        from config.settings import CASES_DIR

        case_dir = CASES_DIR / case_id

        # Load report text
        report_text = ""
        for candidate in [
            case_dir / "reports" / "mdr_report.md",
            case_dir / "reports" / "investigation_report.md",
            case_dir / "reports" / "pup_report.md",
        ]:
            if candidate.exists():
                report_text = candidate.read_text(encoding="utf-8")
                break

        if not report_text:
            return f"No report found for case {case_id}."

        if len(report_text) > 8000:
            report_text = report_text[:8000] + "\n\n[...truncated...]"

        # Load matrix if available
        matrix_text = ""
        matrix_path = case_dir / "artefacts" / "analysis" / "investigation_matrix.json"
        if matrix_path.exists():
            import json
            from tools.common import load_json
            try:
                matrix = load_json(matrix_path)
                matrix_text = json.dumps(matrix, indent=2, default=str)
                if len(matrix_text) > 3000:
                    matrix_text = matrix_text[:3000] + "\n[...truncated...]"
            except Exception:
                pass

        return (
            f"# Report Quality Review — Instructions\n\n"
            f"Review the following report for analytical quality issues.\n\n"
            f"## Check for:\n"
            f"1. **Unconfirmed claims** — findings labelled 'confirmed' without direct data proof\n"
            f"2. **Causal language** — 'led to', 'caused', 'resulted in' without evidence of causation\n"
            f"3. **Speculation** — gap-filling, assumptions presented as findings\n"
            f"4. **Matrix coverage** — if a matrix exists, check all known_unknowns are addressed\n"
            f"5. **Missing sections** — all mandatory report sections present\n"
            f"6. **IOC accuracy** — IOCs in report match enrichment verdicts\n\n"
            f"Rate each issue as: critical (must fix), warning (should fix), info (minor).\n\n"
            f"---\n\n"
            f"## Report\n\n{report_text}\n\n"
            + (f"---\n\n## Investigation Matrix\n\n{matrix_text}\n\n" if matrix_text else "")
            + f"---\n\n"
            f"# Task\n\n"
            f"Review the report for case **{case_id}** and list all quality issues found.\n"
        )

    # ------------------------------------------------------------------
    # Response plan prompt (client-side)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_response_plan(
        case_id: str,
        client: str = "",
    ) -> str:
        """Generate a containment and response plan locally in Claude Desktop.

        Loads the client's response playbook (escalation matrix, containment
        capabilities, remediation actions, crown jewels) and case data, then
        lets your local session produce the response plan.

        The ``response_actions`` tool already does this deterministically on
        the server — use this prompt when you want richer, contextualised
        recommendations that account for the full investigation narrative.

        Parameters
        ----------
        case_id : str
            Case to generate the response plan for.
        client : str
            Client name (used to load playbook). Auto-detected from case if blank.
        """
        from config.settings import CASES_DIR, CLIENT_PLAYBOOKS_DIR
        from tools.common import load_json

        # Load case metadata for context
        case_dir = CASES_DIR / case_id
        try:
            meta = load_json(case_dir / "case_meta.json")
        except Exception:
            meta = {}

        # Auto-detect client from case
        if not client:
            client = meta.get("client", "")

        # Load client playbook
        playbook_text = "No client playbook found."
        if client:
            for candidate in [
                CLIENT_PLAYBOOKS_DIR / f"{client}.json",
                CLIENT_PLAYBOOKS_DIR / f"{client.lower().replace(' ', '_')}.json",
            ]:
                if candidate.exists():
                    try:
                        pb = load_json(candidate)
                        import json
                        playbook_text = json.dumps(pb, indent=2, default=str)
                    except Exception:
                        pass
                    break

        # Build case context (reuse MDR context builder — it's the most comprehensive)
        from tools.generate_mdr_report import _build_context
        context = _build_context(case_id)

        return (
            "# Response Plan Generation — Instructions\n\n"
            "You are a senior MDR analyst generating a containment and response "
            "plan for a security investigation. Use UK English, professional SOC tone.\n\n"
            "## Response Matrix Rules\n\n"
            "The client playbook below defines what actions the SOC can take vs "
            "what the client must do. Follow it exactly:\n"
            "- **Asset Containment** — SOC executes immediately (e.g. EDR isolate, "
            "session revoke, IOC block)\n"
            "- **Confirm Asset Containment** — SOC recommends, client approves first\n"
            "- **Not Required** — activity already blocked by platform\n\n"
            "Split recommendations into:\n"
            "1. **SOC-Executed Containment** — actions within SOC authority per playbook\n"
            "2. **Client-Responsible Remediation** — actions only the client can perform "
            "(password resets, policy changes, user briefings)\n\n"
            "Reference specific technologies, users, hosts, and IOCs from the case data.\n\n"
            "---\n\n"
            f"## Client Playbook\n\n```json\n{playbook_text}\n```\n\n"
            "---\n\n"
            f"## Case Data\n\n{context}\n\n"
            "---\n\n"
            f"# Task\n\n"
            f"Produce a containment and response plan for case **{case_id}**.\n"
        )

    # ------------------------------------------------------------------
    # Threat article generation prompt (client-side)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_threat_article(
        category: str = "ET",
        topic: str = "",
    ) -> str:
        """Generate a threat intelligence article locally in Claude Desktop.

        You search the web, gather source material, and write the article
        yourself. Use ``search_threat_articles`` first to check what's already
        been covered. When done, call ``save_threat_article`` to persist it.

        Parameters
        ----------
        category : str
            "ET" (Emerging Threat) or "EV" (Emerging Vulnerability).
        topic : str
            Topic hint — e.g. a CVE ID, malware name, or campaign name.
            Leave blank for general discovery.
        """
        from config.article_prompts import ARTICLE_SYSTEM_PROMPT, ARTICLE_USER_TEMPLATE

        lines = [
            "# Threat Article Generation — Instructions\n",
            ARTICLE_SYSTEM_PROMPT,
            "",
            "---",
            "",
            "## Output Structure",
            "",
            ARTICLE_USER_TEMPLATE.replace("{category}", category)
                .replace("{title}", "(you decide the title)")
                .replace("{sources}", "(you gather the sources — see workflow below)"),
            "",
            "---",
            "",
            "## Workflow",
            "",
            "1. **Check prior coverage** — call `search_threat_articles` to see what's already written.",
            "   Do not duplicate existing articles.",
        ]

        if topic:
            lines.extend([
                f"2. **Research the topic** — search the web for recent coverage of: **{topic}**",
                "   Read at least 2 sources. Prefer vendor advisories and reputable security outlets.",
            ])
        else:
            lines.extend([
                "2. **Discover recent threats** — search the web for notable cybersecurity news",
                "   from the past 7 days. Focus on enterprise-relevant threats, major CVEs,",
                "   active campaigns, or significant vulnerabilities.",
            ])

        lines.extend([
            "3. **Write the article** following the structure above:",
            "   - Title, Body (~150-180 words, paragraph format), Recommendations (bullet points),",
            "     Indicators (defanged IOCs — use [.] for dots, hxxps:// for URLs)",
            "4. **Save** — call `save_threat_article` with the article markdown, title, category,",
            f"   and source URLs.",
            "",
            f"**Category:** {category}",
        ])

        if topic:
            lines.append(f"**Topic:** {topic}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Report generation prompts (client-side — no server LLM call)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_pup_report(case_id: str) -> str:
        """Generate a PUP/PUA report locally in Claude Desktop.

        Loads the PUP/PUA Analyst Instruction Set and all case data.
        When done, call ``save_report`` with report_type="pup_report".

        Parameters
        ----------
        case_id : str
            Case to generate the report for.
        """
        from tools.generate_pup_report import _SYSTEM_PROMPT as prompt
        from tools.generate_pup_report import _build_context
        context = _build_context(case_id)

        return (
            f"# PUP/PUA Report Generation — Instructions\n\n"
            f"{prompt}\n\n"
            f"---\n\n"
            f"# Case Data\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Produce a PUP/PUA report for case **{case_id}** following the "
            f"PUP/PUA Analyst Instruction Set above exactly.\n\n"
            f"When the report is complete, call `save_report` with:\n"
            f"- `case_id`: \"{case_id}\"\n"
            f"- `report_type`: \"pup_report\"\n"
            f"- `report_text`: the full report markdown\n"
        )

    @mcp.prompt()
    def write_fp_closure(
        case_id: str,
        alert_data: str = "",
        platform: str = "",
        query_text: str = "",
    ) -> str:
        """Generate an FP closure comment locally in Claude Desktop.

        Loads the FP ticket system prompt, case context, and alert data.
        When done, call ``save_report`` with report_type="fp_ticket".

        Parameters
        ----------
        case_id : str
            Case to generate the ticket for.
        alert_data : str
            Raw alert JSON or text.
        platform : str
            Detection platform override (sentinel, crowdstrike, defender, etc.).
        query_text : str
            Original detection query (KQL/SPL).
        """
        from tools.fp_ticket import _SYSTEM_PROMPT as prompt
        from tools.fp_ticket import _build_context
        context = _build_context(case_id)

        parts = [
            f"# FP Closure Comment — Instructions\n\n",
            f"{prompt}\n\n",
            f"---\n\n",
            f"# Case Context\n\n{context}\n\n",
        ]
        if platform:
            parts.append(f"**Platform override:** {platform}\n\n")
        if alert_data:
            parts.append(f"## Alert Data\n\n```\n{alert_data}\n```\n\n")
        if query_text:
            parts.append(f"## Original Detection Query\n\n```kql\n{query_text}\n```\n\n")
        parts.append(
            f"---\n\n"
            f"# Task\n\n"
            f"Write a two-sentence FP closure comment for case **{case_id}**.\n\n"
            f"When done, call `save_report` with:\n"
            f"- `case_id`: \"{case_id}\"\n"
            f"- `report_type`: \"fp_ticket\"\n"
            f"- `report_text`: the closure comment\n"
        )
        return "".join(parts)

    @mcp.prompt()
    def write_fp_tuning(
        case_id: str,
        alert_data: str = "",
        platform: str = "",
        query_text: str = "",
    ) -> str:
        """Generate an FP tuning ticket locally in Claude Desktop.

        Loads the SIEM engineering tuning ticket prompt, case context,
        and alert data. When done, call ``save_report`` with
        report_type="fp_tuning_ticket".

        Parameters
        ----------
        case_id : str
            Case to generate the ticket for.
        alert_data : str
            Raw alert JSON or text.
        platform : str
            Detection platform override (sentinel, crowdstrike, splunk).
            For CrowdStrike/NGSIEM, call ``load_ngsiem_reference`` first
            for correct syntax and field names.
        query_text : str
            Original detection query (KQL/SPL/CQL).
        """
        from tools.fp_tuning_ticket import _SYSTEM_PROMPT as prompt
        from tools.fp_tuning_ticket import _build_context
        context = _build_context(case_id)

        parts = [
            f"# SIEM Tuning Ticket — Instructions\n\n",
            f"{prompt}\n\n",
            f"---\n\n",
            f"# Case Context\n\n{context}\n\n",
        ]
        if platform:
            parts.append(f"**Platform override:** {platform}\n\n")
        if alert_data:
            parts.append(f"## Alert Data\n\n```\n{alert_data}\n```\n\n")
        if query_text:
            parts.append(f"## Original Detection Query\n\n```kql\n{query_text}\n```\n\n")
        parts.append(
            f"---\n\n"
            f"# Task\n\n"
            f"Write a structured SIEM tuning ticket for case **{case_id}**.\n\n"
            f"When done, call `save_report` with:\n"
            f"- `case_id`: \"{case_id}\"\n"
            f"- `report_type`: \"fp_tuning_ticket\"\n"
            f"- `report_text`: the full tuning ticket markdown\n"
        )
        return "".join(parts)

    @mcp.prompt()
    def write_executive_summary(case_id: str) -> str:
        """Generate an executive summary locally in Claude Desktop.

        Loads the executive summary system prompt and case data.
        When done, call ``save_report`` with report_type="executive_summary".

        Parameters
        ----------
        case_id : str
            Case to generate the summary for.
        """
        from tools.executive_summary import _SYSTEM_PROMPT as prompt
        from tools.executive_summary import _build_context
        context = _build_context(case_id)

        return (
            f"# Executive Summary — Instructions\n\n"
            f"{prompt}\n\n"
            f"---\n\n"
            f"# Case Data\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Produce an executive summary for case **{case_id}** following the "
            f"instructions above. Target audience: non-technical business leadership. "
            f"Maximum 500 words. Use RAG (Red/Amber/Green) risk rating.\n\n"
            f"When the summary is complete, call `save_report` with:\n"
            f"- `case_id`: \"{case_id}\"\n"
            f"- `report_type`: \"executive_summary\"\n"
            f"- `report_text`: the full summary markdown\n"
        )

    @mcp.prompt()
    def write_security_arch_review(case_id: str) -> str:
        """Generate a security architecture review locally in Claude Desktop.

        Loads the security architecture system prompt and case data.
        When done, call ``save_report`` with report_type="security_arch_review".

        Parameters
        ----------
        case_id : str
            Case to generate the review for.
        """
        from tools.security_arch_review import _SYSTEM_PROMPT as prompt
        from tools.security_arch_review import _build_context
        context = _build_context(case_id)

        return (
            f"# Security Architecture Review — Instructions\n\n"
            f"{prompt}\n\n"
            f"---\n\n"
            f"# Case Data\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Produce a security architecture review for case **{case_id}** "
            f"following the instructions above exactly.\n\n"
            f"When the review is complete, call `save_report` with:\n"
            f"- `case_id`: \"{case_id}\"\n"
            f"- `report_type`: \"security_arch_review\"\n"
            f"- `report_text`: the full review markdown\n"
        )

    # ------------------------------------------------------------------
    # Analysis prompts (client-side — replace server LLM calls)
    # Additional client-side analysis prompts
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_timeline(case_id: str) -> str:
        """Reconstruct a forensic timeline locally in Claude Desktop.

        Loads all timestamped events extracted from case artefacts and lets
        your local session perform MITRE ATT&CK mapping, gap analysis, and
        narrative reconstruction.

        The ``reconstruct_timeline`` tool does this on the server with an
        API call — use this prompt to avoid that cost.

        Parameters
        ----------
        case_id : str
            Case to reconstruct the timeline for.
        """
        from tools.timeline_reconstruct import _SYSTEM_PROMPT as prompt
        from tools.timeline_reconstruct import _extract_events

        from config.settings import CASES_DIR
        from tools.common import load_json
        import json

        events, sources = _extract_events(case_id)

        # Sort chronologically
        events.sort(key=lambda e: e.get("timestamp", ""))

        context_parts = [f"# Case: {case_id}\n"]
        context_parts.append(f"## Sources Scanned\n{', '.join(sources)}\n")
        context_parts.append(f"## Events ({len(events)} total)\n")
        context_parts.append(f"```json\n{json.dumps(events, indent=2, default=str)}\n```\n")

        context = "\n".join(context_parts)

        return (
            f"# Forensic Timeline Reconstruction — Instructions\n\n"
            f"{prompt}\n\n"
            f"---\n\n"
            f"# Case Events\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Reconstruct the forensic timeline for case **{case_id}**.\n\n"
            f"Structure your output as:\n"
            f"1. **MITRE ATT&CK Mapping** — each event mapped to a tactic\n"
            f"2. **Dwell-Time Gaps** — significant gaps between activity clusters\n"
            f"3. **Key Events** — the 5-10 most forensically important events with reasoning\n"
            f"4. **Narrative** — 2-3 sentence attack timeline summary\n\n"
            f"When done, call `add_finding` with your timeline analysis.\n"
        )

    # ------------------------------------------------------------------
    # EVTX correlation prompt (client-side)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_evtx_analysis(case_id: str) -> str:
        """Analyse Windows Event Log attack chains locally in Claude Desktop.

        Loads parsed EVTX data and detected attack chains, then lets your
        local session perform narrative reconstruction and MITRE mapping.

        The ``correlate_evtx`` tool does this on the server with an API
        call — use this prompt to avoid that cost.

        Parameters
        ----------
        case_id : str
            Case to analyse EVTX data for.
        """
        from tools.evtx_correlate import _SYSTEM_PROMPT as prompt
        from tools.evtx_correlate import _load_parsed_logs

        from config.settings import CASES_DIR
        from tools.common import load_json
        import json

        case_dir = CASES_DIR / case_id
        context_parts = [f"# Case: {case_id}\n"]

        # Load case metadata
        try:
            meta = load_json(case_dir / "case_meta.json")
            context_parts.append(f"## Case Metadata\n{json.dumps(meta, indent=2, default=str)}\n")
        except Exception:
            pass

        # Load parsed logs
        raw_events = _load_parsed_logs(case_id)
        if raw_events:
            # Truncate to avoid context overflow
            events_text = json.dumps(raw_events[:500], indent=2, default=str)
            if len(events_text) > 15000:
                events_text = events_text[:15000] + "\n[...truncated...]"
            context_parts.append(f"## Parsed Windows Events ({len(raw_events)} total)\n```json\n{events_text}\n```\n")
        else:
            context_parts.append("## Parsed Windows Events\nNo parsed EVTX data found. Run `parse_logs` first.\n")

        # Load existing chain detections if available
        chains_path = case_dir / "artefacts" / "evtx" / "evtx_chains.json"
        if chains_path.exists():
            try:
                chains = load_json(chains_path)
                chains_text = json.dumps(chains, indent=2, default=str)
                if len(chains_text) > 5000:
                    chains_text = chains_text[:5000] + "\n[...truncated...]"
                context_parts.append(f"## Previously Detected Chains\n```json\n{chains_text}\n```\n")
            except Exception:
                pass

        context = "\n".join(context_parts)

        return (
            f"# EVTX Attack Chain Analysis — Instructions\n\n"
            f"{prompt}\n\n"
            f"---\n\n"
            f"# Case Data\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Analyse the Windows Event Log data for case **{case_id}** and identify "
            f"attack chains.\n\n"
            f"Structure your output as:\n"
            f"1. **Attack Narrative** — chronological reconstruction of the attack\n"
            f"2. **MITRE ATT&CK Mapping** — techniques observed with evidence\n"
            f"3. **Attacker Sophistication** — assessment based on techniques used\n"
            f"4. **Detection Recommendations** — specific rules for observed patterns\n\n"
            f"When done, call `add_finding` with your analysis.\n"
        )

    # ------------------------------------------------------------------
    # Phishing verdict prompt (client-side)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_phishing_verdict(case_id: str) -> str:
        """Assess captured web pages for phishing locally in Claude Desktop.

        Loads web capture data (page text, URLs, titles, screenshots) and
        phishing detection findings, then lets your local session assess
        brand impersonation and deceptive intent.

        The ``detect_phishing`` tool runs server-side LLM calls for page
        purpose checks and vision analysis — use this prompt to do that
        reasoning locally instead.

        Note: ``capture_urls`` must be run first to capture the pages.
        This prompt handles the analysis, not the capture.

        Parameters
        ----------
        case_id : str
            Case with captured web pages to assess.
        """
        from config.settings import CASES_DIR
        from tools.common import load_json
        import json

        case_dir = CASES_DIR / case_id
        context_parts = [f"# Case: {case_id}\n"]

        # Load case metadata
        try:
            meta = load_json(case_dir / "case_meta.json")
            context_parts.append(f"## Case Metadata\n{json.dumps(meta, indent=2, default=str)}\n")
        except Exception:
            pass

        # Load web captures
        web_dir = case_dir / "artefacts" / "web"
        captures_found = False
        if web_dir.is_dir():
            for sub in sorted(web_dir.iterdir()):
                if not sub.is_dir():
                    continue
                manifest_path = sub / "capture_manifest.json"
                if manifest_path.exists():
                    captures_found = True
                    try:
                        manifest = load_json(manifest_path)
                        context_parts.append(f"### Capture: {sub.name}")
                        context_parts.append(f"- **URL:** {manifest.get('url', 'N/A')}")
                        context_parts.append(f"- **Final URL:** {manifest.get('final_url', 'N/A')}")
                        context_parts.append(f"- **Title:** {manifest.get('title', 'N/A')}")
                        context_parts.append(f"- **Status:** {manifest.get('status_code', 'N/A')}")

                        # Include page text if available
                        body_path = sub / "body.txt"
                        if body_path.exists():
                            body_text = body_path.read_text(encoding="utf-8", errors="replace")[:4000]
                            context_parts.append(f"- **Page text (first 4000 chars):**\n```\n{body_text}\n```")

                        # Include HTML excerpt
                        html_path = sub / "page.html"
                        if html_path.exists():
                            html_text = html_path.read_text(encoding="utf-8", errors="replace")[:6000]
                            context_parts.append(f"- **HTML source (first 6000 chars):**\n```html\n{html_text}\n```")

                        context_parts.append("")
                    except Exception:
                        pass

        if not captures_found:
            context_parts.append("## Web Captures\nNo captures found. Run `capture_urls` first.\n")

        # Load existing phishing findings if any
        phishing_path = case_dir / "artefacts" / "web" / "phishing_findings.json"
        if phishing_path.exists():
            try:
                findings = load_json(phishing_path)
                findings_text = json.dumps(findings, indent=2, default=str)
                if len(findings_text) > 3000:
                    findings_text = findings_text[:3000] + "\n[...truncated...]"
                context_parts.append(f"## Existing Phishing Findings (deterministic)\n```json\n{findings_text}\n```\n")
            except Exception:
                pass

        # Load IOC enrichment for domain context
        enrichment_path = case_dir / "artefacts" / "enrichment.json"
        if not enrichment_path.exists():
            enrichment_path = case_dir / "artefacts" / "enrichment" / "enrichment.json"
        if enrichment_path.exists():
            try:
                enrichment = load_json(enrichment_path)
                # Extract just domain/URL enrichment
                domain_results = [r for r in enrichment.get("results", [])
                                  if r.get("ioc_type") in ("domain", "url")]
                if domain_results:
                    enr_text = json.dumps(domain_results[:20], indent=2, default=str)
                    if len(enr_text) > 3000:
                        enr_text = enr_text[:3000] + "\n[...truncated...]"
                    context_parts.append(f"## Domain/URL Enrichment\n```json\n{enr_text}\n```\n")
            except Exception:
                pass

        context = "\n".join(context_parts)

        return (
            "# Phishing Page Assessment — Instructions\n\n"
            "You are a senior SOC analyst assessing captured web pages for phishing "
            "and brand impersonation. Use UK English.\n\n"
            "## Assessment Criteria\n\n"
            "For each captured page, assess:\n"
            "1. **Brand impersonation** — does the page mimic a known brand (Microsoft, "
            "Google, Apple, PayPal, DocuSign, Amazon, LinkedIn, etc.) on a domain that "
            "does NOT belong to that brand?\n"
            "2. **Page purpose** — does the page have a clear legitimate purpose, or is it "
            "deceptive/purposeless?\n"
            "3. **Login forms** — are there credential harvesting forms?\n"
            "4. **Lure patterns** — 'view shared document', 'verify account', CAPTCHA "
            "gates, fake file previews, tech-support scams?\n"
            "5. **Domain analysis** — newly registered? Typosquatting? Unrelated to content?\n\n"
            "## Confidence Levels\n"
            "- **high** — clear brand impersonation or credential harvesting on wrong domain\n"
            "- **medium** — suspicious elements but ambiguous (e.g. generic login, no clear brand)\n"
            "- **low** — minor indicators, likely benign but worth noting\n\n"
            "---\n\n"
            f"# Case Data\n\n"
            f"{context}\n\n"
            "---\n\n"
            f"# Task\n\n"
            f"Assess each captured page in case **{case_id}** for phishing indicators.\n\n"
            f"For each page, provide:\n"
            f"- **Verdict:** phishing / suspicious / clean\n"
            f"- **Brand impersonated:** (if applicable)\n"
            f"- **Confidence:** high / medium / low\n"
            f"- **Evidence:** specific elements that support your verdict\n"
            f"- **Reasoning:** why you reached this conclusion\n\n"
            f"When done, call `add_finding` with your assessment.\n"
        )

    # ------------------------------------------------------------------
    # PE analysis verdict prompt (client-side)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_pe_verdict(case_id: str) -> str:
        """Assess PE binaries locally in Claude Desktop.

        Loads deterministic PE static analysis results (sections, imports,
        entropy, strings, packer signatures) and lets your local session
        produce the malware assessment verdict.

        The ``analyse_pe`` tool runs a server-side LLM call for this — use
        this prompt to do that reasoning locally instead.

        Note: ``analyse_pe`` must be run first to extract the static data.
        This prompt only handles the LLM verdict, not the extraction.

        Parameters
        ----------
        case_id : str
            Case with PE analysis data to assess.
        """
        from tools.pe_analysis import _LLM_SYSTEM_PROMPT as prompt

        from config.settings import CASES_DIR
        from tools.common import load_json
        import json

        case_dir = CASES_DIR / case_id
        context_parts = [f"# Case: {case_id}\n"]

        # Load PE analysis results
        pe_path = case_dir / "artefacts" / "pe_analysis" / "pe_analysis.json"
        if pe_path.exists():
            try:
                pe_data = load_json(pe_path)
                for i, file_result in enumerate(pe_data.get("files", [])):
                    # Exclude raw strings list, include sample
                    summary = {k: v for k, v in file_result.items() if k != "strings"}
                    summary["strings_sample"] = file_result.get("strings", [])[:50]
                    summary_text = json.dumps(summary, indent=2, default=str)
                    if len(summary_text) > 8000:
                        summary_text = summary_text[:8000] + "\n[...truncated...]"
                    context_parts.append(f"## File {i+1}: {file_result.get('filename', 'unknown')}\n```json\n{summary_text}\n```\n")
            except Exception:
                context_parts.append("## PE Analysis\nFailed to load PE analysis data.\n")
        else:
            context_parts.append("## PE Analysis\nNo PE analysis data found. Run `analyse_pe` first.\n")

        context = "\n".join(context_parts)

        return (
            f"# PE Malware Assessment — Instructions\n\n"
            f"{prompt}\n\n"
            f"---\n\n"
            f"# PE Analysis Data\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Assess each PE binary in case **{case_id}** and provide a structured "
            f"malware assessment.\n\n"
            f"For each file, provide:\n"
            f"- **Verdict:** malicious / suspicious / clean\n"
            f"- **Confidence:** high / medium / low\n"
            f"- **Capabilities:** what the binary can do (based on imports/strings)\n"
            f"- **Packing/Obfuscation:** evidence of evasion techniques\n"
            f"- **IOCs:** any C2 infrastructure, credentials, or tool artefacts found in strings\n"
            f"- **Reasoning:** specific imports, sections, or strings that support your verdict\n\n"
            f"When done, call `add_finding` with your assessment.\n"
        )

    # ------------------------------------------------------------------
    # CVE contextualisation prompt (client-side)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_cve_context(case_id: str) -> str:
        """Contextualise CVEs locally in Claude Desktop.

        Loads CVE data (NVD, EPSS, CISA KEV scores) already fetched by the
        server and lets your local session produce the contextualised
        assessment and patching priorities.

        The ``contextualise_cves`` tool runs a server-side LLM call for
        this — use this prompt to avoid that cost. Note: the tool must be
        run first to fetch the CVE data from APIs.

        Parameters
        ----------
        case_id : str
            Case with CVE data to contextualise.
        """
        from tools.cve_contextualise import _LLM_SYSTEM_PROMPT as prompt

        from config.settings import CASES_DIR
        from tools.common import load_json
        import json

        case_dir = CASES_DIR / case_id
        context_parts = [f"# Case: {case_id}\n"]

        # Load case metadata
        try:
            meta = load_json(case_dir / "case_meta.json")
            context_parts.append(f"## Case Metadata\n{json.dumps(meta, indent=2, default=str)}\n")
        except Exception:
            pass

        # Load CVE contextualisation results
        cve_path = case_dir / "artefacts" / "cve" / "cve_context.json"
        if cve_path.exists():
            try:
                cve_data = load_json(cve_path)
                cve_text = json.dumps(cve_data, indent=2, default=str)
                if len(cve_text) > 12000:
                    cve_text = cve_text[:12000] + "\n[...truncated...]"
                context_parts.append(f"## CVE Data\n```json\n{cve_text}\n```\n")
            except Exception:
                context_parts.append("## CVE Data\nFailed to load CVE data.\n")
        else:
            context_parts.append("## CVE Data\nNo CVE data found. Run `contextualise_cves` first.\n")

        # Load enrichment for additional context
        enrichment_path = case_dir / "artefacts" / "enrichment" / "enrichment.json"
        if not enrichment_path.exists():
            enrichment_path = case_dir / "artefacts" / "enrichment.json"
        if enrichment_path.exists():
            try:
                enrichment = load_json(enrichment_path)
                # Just include summary stats, not full data
                stats = enrichment.get("stats", {})
                if stats:
                    context_parts.append(f"## Enrichment Stats\n{json.dumps(stats, indent=2, default=str)}\n")
            except Exception:
                pass

        context = "\n".join(context_parts)

        return (
            f"# CVE Contextualisation — Instructions\n\n"
            f"{prompt}\n\n"
            f"---\n\n"
            f"# Case Data\n\n"
            f"{context}\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Contextualise the CVEs found in case **{case_id}** within the "
            f"investigation context.\n\n"
            f"For each CVE, provide:\n"
            f"- **Exploitation likelihood** — EPSS score interpretation, active exploitation status\n"
            f"- **Relevance to case** — how this CVE relates to observed TTPs\n"
            f"- **Patching priority** — critical / high / medium / low with reasoning\n"
            f"- **Detection opportunities** — how to detect exploitation attempts\n\n"
            f"Produce an overall patching priority list ordered by risk.\n\n"
            f"When done, call `add_finding` with your assessment.\n"
        )

    # ------------------------------------------------------------------
    # User security check prompt
    # ------------------------------------------------------------------

    @mcp.prompt()
    def user_security_check(
        user_identifier: str = "",
        client: str = "",
        lookback_days: str = "30",
    ) -> str:
        """Broad-scope security review of a specific user account.

        Use when a client is concerned about a particular user but cannot
        provide specific alert details. This workflow validates the account,
        then sweeps sign-ins, alerts, email threats, and activity audit logs
        for anything suspicious.

        Parameters
        ----------
        user_identifier : str
            UPN (user@domain.com) or sAMAccountName (jsmith). If a SAM name
            is provided, it will be resolved to a UPN in Phase 1.
        client : str
            Client name. Required — determines which Sentinel workspace to query.
        lookback_days : str
            How far back to look (default 30 days). Use "7" for a quick check
            or "90" for a deeper historical sweep.
        """
        lookback = lookback_days.strip() or "30"

        # Derive SAM from UPN or vice versa for query flexibility
        if "@" in user_identifier:
            upn_hint = user_identifier
            sam_hint = user_identifier.split("@")[0]
        else:
            upn_hint = user_identifier
            sam_hint = user_identifier

        lines = [
            "# User Security Check",
            "",
            f"**User:** {user_identifier or '(MUST BE PROVIDED)'}",
            f"**Client:** {client or '(MUST BE IDENTIFIED — call lookup_client)'}",
            f"**Lookback:** {lookback} days",
            "",
            "---",
            "",
            "## Purpose",
            "",
            "Broad-scope security review of a specific user account. The client has",
            "expressed concern about this user but has not provided a specific alert or",
            "incident. This workflow validates the identity, then systematically sweeps",
            "all available telemetry for indicators of compromise, policy violation, or",
            "anomalous behaviour.",
            "",
            "**This is a security investigation, not a HR review.** Focus exclusively on:",
            "- Signs of account compromise (credential theft, session hijack, token replay)",
            "- Attacker TTPs performed under this identity (inbox rules, OAuth consent, BEC,",
            "  data exfiltration, lateral movement, privilege escalation)",
            "- Exposure to inbound threats (phish emails, malware delivery, social engineering)",
            "- Anomalous access patterns that deviate from the user's established baseline",
            "",
            "Do NOT report on legitimate work activity, productivity patterns, or",
            "content of communications. If the sweep is clean, say so clearly.",
            "",
            "---",
            "",
            "## PHASE 1 — IDENTITY VALIDATION (MANDATORY GATE)",
            "",
            "**Do not proceed until the user identity is confirmed to exist.**",
            "",
            "Call `lookup_client` to confirm the client and resolve the Sentinel workspace. "
            "The result includes `knowledge_base` and `sentinel_reference` — check for "
            "known FP patterns and available tables before querying.",
            "",
            "Then run this KQL to validate the account:",
            "",
            "```kql",
            f"let upn_search = \"{upn_hint}\";",
            f"let sam_search = \"{sam_hint}\";",
            "SigninLogs",
            f"| where TimeGenerated >= ago({lookback}d)",
            "| where UserPrincipalName has_cs upn_search",
            "    or tolower(UserPrincipalName) startswith tolower(sam_search)",
            "| summarize",
            "    LastSignIn = max(TimeGenerated),",
            "    FirstSignIn = min(TimeGenerated),",
            "    SignInCount = count(),",
            "    DistinctIPs = dcount(IPAddress),",
            "    DistinctApps = dcount(AppDisplayName),",
            "    UPN = take_any(UserPrincipalName),",
            "    DisplayName = take_any(UserDisplayName)",
            "| project UPN, DisplayName, FirstSignIn, LastSignIn, SignInCount,",
            "    DistinctIPs, DistinctApps",
            "```",
            "",
            "**If zero results:** The user has no sign-in activity in the lookback window.",
            "This could mean: (a) the identifier is wrong, (b) the account is disabled/deleted,",
            "or (c) the user hasn't signed in. Ask the analyst to confirm before proceeding.",
            "",
            "**Capture the confirmed UPN** — use it for all subsequent queries.",
            "",
            "---",
            "",
            "## PHASE 2 — PRIOR INVESTIGATIONS",
            "",
            "Call `recall_cases` with the confirmed UPN and any email aliases.",
            "Note any prior cases involving this user — they provide context but do NOT",
            "replace the current sweep. If prior cases exist, mention them in the summary.",
            "",
            "---",
            "",
            "## PHASE 3 — ALERT & INCIDENT HISTORY",
            "",
            "Check for any security alerts or incidents involving this user:",
            "",
            "```kql",
            "let target_upn = \"<CONFIRMED_UPN>\";",
            "SecurityAlert",
            f"| where TimeGenerated >= ago({lookback}d)",
            "| where Entities has target_upn or CompromisedEntity has target_upn",
            "| project TimeGenerated, AlertName, AlertSeverity, Status,",
            "    Description, Tactics, Techniques",
            "| order by TimeGenerated desc",
            "```",
            "",
            "```kql",
            "let target_upn = \"<CONFIRMED_UPN>\";",
            "SecurityIncident",
            f"| where TimeGenerated >= ago({lookback}d)",
            "| where tostring(AdditionalData) has target_upn",
            "    or Description has target_upn",
            "| project TimeGenerated, Title, Severity, Status, Classification,",
            "    Description",
            "| order by TimeGenerated desc",
            "```",
            "",
            "**If alerts exist:** Note severity, status, and whether they were resolved.",
            "Open or unresolved alerts are high priority. Do NOT re-investigate closed",
            "incidents — just note them as context.",
            "",
            "---",
            "",
            "## PHASE 4 — SIGN-IN RISK ANALYSIS",
            "",
            "This is the highest-value phase. Look for:",
            "- Risky sign-ins (RiskLevelDuringSignIn != none)",
            "- Unfamiliar locations or impossible travel",
            "- MFA gaps (single-factor where MFA is expected)",
            "- Sign-ins from anonymiser/VPN/Tor infrastructure",
            "- Non-interactive sign-ins from unexpected apps",
            "",
            "```kql",
            "let target_upn = \"<CONFIRMED_UPN>\";",
            "SigninLogs",
            f"| where TimeGenerated >= ago({lookback}d)",
            "| where UserPrincipalName == target_upn",
            "| where RiskLevelDuringSignIn != \"none\" or RiskState != \"none\"",
            "    or ConditionalAccessStatus == \"failure\"",
            "    or ResultType !in (\"0\", \"50125\", \"50140\")",
            "| project TimeGenerated, IPAddress, Location, AppDisplayName,",
            "    ResourceDisplayName, ResultType, RiskLevelDuringSignIn,",
            "    RiskState, ConditionalAccessStatus,",
            "    AuthenticationRequirement, MfaDetail, UserAgent",
            "| order by TimeGenerated desc",
            "```",
            "",
            "Also check non-interactive sign-ins (service tokens, refresh tokens):",
            "",
            "```kql",
            "let target_upn = \"<CONFIRMED_UPN>\";",
            "AADNonInteractiveUserSignInLogs",
            f"| where TimeGenerated >= ago({lookback}d)",
            "| where UserPrincipalName == target_upn",
            "| where RiskLevelDuringSignIn != \"none\" or ResultType !in (\"0\")",
            "| project TimeGenerated, IPAddress, AppDisplayName,",
            "    ResourceDisplayName, ResultType, RiskLevelDuringSignIn",
            "| order by TimeGenerated desc",
            "```",
            "",
            "**For any suspicious IPs found:** call `quick_enrich` to check reputation,",
            "geo-location, and whether they are VPN/proxy/hosting infrastructure.",
            "",
            "**Behavioural assessment is critical here:** a datacenter IP alone is not",
            "compromise. Assess what the session DID — attacker TTPs (inbox rules, OAuth",
            "consent, BEC) vs normal user behaviour (reading emails, calendar, docs).",
            "",
            "---",
            "",
            "## PHASE 5 — EMAIL THREAT EXPOSURE",
            "",
            "Check for phishing/malware emails targeting this user:",
            "",
            "```kql",
            "let target_email = \"<CONFIRMED_UPN>\";",
            "EmailEvents",
            f"| where Timestamp >= ago({lookback}d)",
            "| where RecipientEmailAddress == target_email",
            "| where ThreatTypes != \"\"",
            "    or DeliveryAction in (\"Delivered\", \"Junked\")",
            "       and LatestDeliveryAction == \"Removed\"",
            "| project Timestamp, SenderFromAddress, SenderMailFromAddress,",
            "    Subject, ThreatTypes, DeliveryAction, LatestDeliveryAction,",
            "    AuthenticationDetails, NetworkMessageId",
            "| order by Timestamp desc",
            "```",
            "",
            "If threats were delivered, check for URL clicks:",
            "",
            "```kql",
            "let target_email = \"<CONFIRMED_UPN>\";",
            "UrlClickEvents",
            f"| where Timestamp >= ago({lookback}d)",
            "| where AccountUpn == target_email",
            "| project Timestamp, Url, ActionType, ThreatTypes,",
            "    IsClickedThrough, NetworkMessageId",
            "| order by Timestamp desc",
            "```",
            "",
            "**Priority signals:** emails that were delivered then ZAP'd (Phish ZAP,",
            "Malware ZAP) — user may have interacted before removal. Clicked-through",
            "URLs with threat classifications are HIGH priority.",
            "",
            "---",
            "",
            "## PHASE 5.5 — CREDENTIAL BREACH EXPOSURE",
            "",
            "Check if the user's credentials have been exposed in dark web sources:",
            "",
            "- Call `hudsonrock_lookup` with the user's email to check for infostealer",
            "  malware exposure (stolen browser credentials, session tokens, cookies).",
            "- Call `xposed_breach_check` with the user's email to check which data",
            "  breaches have exposed their credentials historically.",
            "- If either returns positive results, this significantly increases the",
            "  risk of credential-based compromise and should be prominently noted",
            "  in the summary.",
            "",
            "**Priority signals:** infostealer exposure (credentials actively harvested",
            "by malware) is higher severity than historical breach exposure (may be",
            "stale/rotated). Recent compromise dates (< 90 days) are critical.",
            "",
            "---",
            "",
            "## PHASE 6 — ACTIVITY AUDIT",
            "",
            "Check for suspicious account activity and configuration changes:",
            "",
            "```kql",
            "let target_upn = \"<CONFIRMED_UPN>\";",
            "AuditLogs",
            f"| where TimeGenerated >= ago({lookback}d)",
            "| where InitiatedBy has target_upn",
            "| where OperationName in (",
            "    \"Consent to application\",",
            "    \"Add app role assignment to user\",",
            "    \"Add delegated permission grant\",",
            "    \"Add member to role\",",
            "    \"Update user\",",
            "    \"Add registered owner to device\",",
            "    \"Set-Mailbox\",",
            "    \"New-InboxRule\",",
            "    \"Set-InboxRule\"",
            ")",
            "| project TimeGenerated, OperationName, Result,",
            "    TargetResources, AdditionalDetails",
            "| order by TimeGenerated desc",
            "```",
            "",
            "Check OfficeActivity for inbox rules, mail forwarding, and bulk operations:",
            "",
            "```kql",
            "let target_upn = \"<CONFIRMED_UPN>\";",
            "OfficeActivity",
            f"| where TimeGenerated >= ago({lookback}d)",
            "| where UserId == target_upn",
            "| where Operation in (",
            "    \"New-InboxRule\", \"Set-InboxRule\", \"Enable-InboxRule\",",
            "    \"Set-Mailbox\", \"Set-MailboxJunkEmailConfiguration\",",
            "    \"Add-MailboxPermission\", \"Set-OwaMailboxPolicy\",",
            "    \"UpdateInboxRules\", \"AddFolderPermissions\",",
            "    \"FileDownloaded\", \"FileUploaded\",",
            "    \"FileSyncDownloadedFull\", \"FileSyncUploadedFull\"",
            ")",
            "| project TimeGenerated, Operation, ResultStatus,",
            "    Parameters = tostring(Parameters), ClientIP",
            "| order by TimeGenerated desc",
            "```",
            "",
            "**High-priority indicators:**",
            "- Inbox rules that forward/redirect/delete mail (classic BEC persistence)",
            "- OAuth application consent (especially first-party impersonation apps)",
            "- Mailbox delegation or permission grants to other users",
            "- Bulk file downloads from SharePoint/OneDrive in a short window",
            "- Role or group membership changes initiated BY this user",
            "",
            "---",
            "",
            "## PHASE 7 — SUMMARY & RISK ASSESSMENT",
            "",
            "Compile findings into a structured summary. Use this format:",
            "",
            "### User Security Check — <DisplayName> (<UPN>)",
            "**Client:** <client>  |  **Period:** last <N> days  |  **Date:** <today>",
            "",
            "**Overall Assessment:** Clean / Concerns Noted / Escalate to Investigation",
            "",
            "| Category | Finding | Risk |",
            "|----------|---------|------|",
            "| Identity | Confirmed active, last sign-in <date> | — |",
            "| Prior Cases | <count> prior investigations | <context> |",
            "| Alerts | <count> alerts (<severities>) | Low/Med/High |",
            "| Sign-in Risk | <findings or 'No risky sign-ins'> | Low/Med/High |",
            "| Email Threats | <findings or 'No threats delivered'> | Low/Med/High |",
            "| Activity Audit | <findings or 'No suspicious changes'> | Low/Med/High |",
            "",
            "**Recommended Actions:**",
            "- (list any follow-up actions, or 'No action required')",
            "",
            "---",
            "",
            *_ANALYTICAL_STANDARDS,
            "",
            *_BEHAVIOURAL_ASSESSMENT,
            "",
            "- **Proportionate response:** a clean sweep is a valid and valuable outcome.",
            "  Do not manufacture findings to justify the check. If the user is clean,",
            "  say so clearly and confidently.",
            "",
            "## Case Handling",
            "",
            "- **Create a new case** for this security check (omit case_id to auto-generate)",
            "- Title format: `User Security Check — <DisplayName>`",
            "- Tag with: `security_check`, `user_review`",
            "- If the sweep is clean: close as `benign` with the summary as case notes",
            "- If concerns are found: keep open and recommend a full investigation",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # MDR report prompt (client-side — uses conversation context)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def write_mdr_report(case_id: str) -> str:
        """Generate an MDR incident report locally using your full conversation context.

        Unlike the server-side ``prepare_mdr_report`` tool, this prompt lets
        your local session write the report with access to everything discussed
        in the conversation — KQL results, email traces, enrichment findings,
        analytical reasoning, and analyst decisions.

        When the report is complete, call ``save_report`` with
        ``report_type="mdr_report"`` to persist it (handles defanging, HTML
        conversion, auto-close, and audit).

        Parameters
        ----------
        case_id : str
            Case to generate the MDR report for.
        """
        from tools.generate_mdr_report import _SYSTEM_PROMPT, _build_context

        # Load artefact context (same data the server-side report would see)
        artefact_context = _build_context(case_id)


        return (
            f"# MDR Report Generation — Instructions\n\n"
            f"{_SYSTEM_PROMPT}\n\n"
            f"---\n\n"
            f"# Case Artefacts (from disk)\n\n"
            f"{artefact_context}\n\n"
            f"---\n\n"
            f"# IMPORTANT — Using Conversation Context\n\n"
            f"The artefact data above is supplementary. Your **primary source** for "
            f"this report is the **full conversation history** — every KQL query result, "
            f"email trace, enrichment finding, timeline analysis, and analytical decision "
            f"discussed with the analyst during this investigation.\n\n"
            f"The server-side report generator cannot see conversation context, which is "
            f"why this prompt exists. You MUST incorporate all investigation findings from "
            f"the conversation, not just what is on disk.\n\n"
            f"Where conversation findings contradict or extend the artefact data, the "
            f"conversation findings take precedence (they represent the analyst's live "
            f"investigation).\n\n"
            f"---\n\n"
            f"# Task\n\n"
            f"Write the MDR incident report for case **{case_id}** following the mandatory "
            f"5-section structure from the instructions above.\n\n"
            f"When your report is complete, call `save_report` with:\n"
            f"- `case_id`: `{case_id}`\n"
            f"- `report_type`: `mdr_report`\n"
            f"- `report_text`: the full markdown report\n"
            f"- `disposition`: the appropriate disposition value "
            f"(`true_positive`, `benign_positive`, `false_positive`, `benign`, "
            f"`pup_pua`, `inconclusive`)\n"
        )
