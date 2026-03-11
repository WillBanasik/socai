"""MCP prompt implementations — workflow templates for LLM consumption.

Prompts provide guided investigation workflows that analysts can select from
the Claude Desktop prompt picker. Four prompts cover the full investigation
lifecycle:

- ``kql_investigation`` — parameterised KQL playbook for any attack type
- ``triage_alert`` — structured alert triage process
- ``write_fp_ticket`` — false-positive analysis and suppression ticket
- ``investigate_incident`` — end-to-end investigation orchestration
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP


# Valid KQL playbook IDs and their human-readable names
_KQL_PLAYBOOKS = {
    "phishing": "Phishing",
    "account-compromise": "Account Investigation",
    "malware-execution": "Malware Execution",
    "privilege-escalation": "Privilege Escalation",
    "data-exfiltration": "Data Exfiltration",
    "lateral-movement": "Lateral Movement",
    "ioc-hunt": "IOC Hunt",
}


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

        # Resolve playbook
        playbook_id = playbook.strip().lower() if playbook else ""
        if playbook_id not in _KQL_PLAYBOOKS:
            valid = ", ".join(f"`{k}`" for k in _KQL_PLAYBOOKS)
            return (
                f"Unknown playbook `{playbook_id}`. "
                f"Valid playbooks: {valid}.\n\n"
                "Tip: call `classify_attack` to determine which playbook matches your alert."
            )

        pb = load_playbook(playbook_id)
        if not pb:
            return f"Playbook `{playbook_id}` not found on disk."

        display_name = _KQL_PLAYBOOKS[playbook_id]

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
            "the alert via `add_evidence`. Call `classify_attack` if you have not already.",
            "",
            "## Overview",
            pb.get("description", ""),
            "",
        ]

        if pb.get("parameters"):
            lines.append("## Playbook Parameters")
            for param in pb["parameters"]:
                lines.append(f"- **{param['name']}**: {param.get('description', '')}")
            lines.append("")

        lines.append("## Investigation Stages")
        lines.append("")
        lines.append("Execute each stage using `load_kql_playbook` then `run_kql`. "
                      "Check Stage 1 results before running subsequent stages. "
                      "**Use `max_rows=200` or higher on `run_kql`** for stages that "
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
            "- Do NOT proceed without a confirmed client",
            "",
            "### 3. IOC Extraction & Enrichment",
            "- Call `recall_cases` to check if any IOCs appear in prior investigations",
            "- Call `enrich_iocs` to query threat intelligence providers",
            "",
            "### 4. Contextualisation",
            "- Identify the affected user(s) and asset(s)",
            "- Determine the business impact and data sensitivity",
            "- Check for related alerts in the same timeframe",
            "",
            "### 5. Verdict",
            "- **True Positive** — confirmed malicious activity requiring response",
            "- **Benign True Positive** — legitimate activity triggering the detection",
            "- **False Positive** — detection error, consider `generate_fp_ticket`",
            "- **Inconclusive** — insufficient data, escalate or gather more evidence",
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
            "- If BTP/FP: document the finding and any tuning recommendations",
            "- If Inconclusive: identify what additional data is needed",
            "",
            "### 7. Documentation",
            "- Register evidence with `add_evidence`",
            "- Generate report with `generate_report` or `generate_mdr_report`",
            "- If FP, generate suppression ticket with `generate_fp_ticket`",
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
            "- Confirm the alert is genuinely a false positive (not a benign true positive)",
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
            "- Use `generate_fp_ticket` with the alert data and platform → 2-sentence closure comment (auto-closes case)",
            "- Use `generate_fp_tuning_ticket` with the alert data, platform, and detection query → structured SIEM engineering handoff (does NOT auto-close)",
            "- The FP ticket closes the alert; the tuning ticket tells detection engineering how to fix the rule",
            "- Generate BOTH when the analyst wants the alert closed AND the rule tuned",
        ])

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Master orchestrator prompt
    # ------------------------------------------------------------------

    @mcp.prompt()
    def investigate_incident(
        incident_data: str = "",
        client: str = "",
        severity: str = "",
    ) -> str:
        """End-to-end incident investigation workflow — from raw alert to MDR report or FP closure.

        Paste raw incident data (alert JSON, email headers, MDE alert, CrowdStrike
        detection, etc.) and this workflow will guide you through client identification,
        classification, evidence collection, analysis, and final output.

        Parameters
        ----------
        incident_data : str
            Raw incident/alert data (JSON, text, or pasted from SIEM).
        client : str
            Client name (must match client registry). If omitted, must be identified
            from the incident data or confirmed with the analyst before proceeding.
        severity : str
            Override severity (low, medium, high, critical). Auto-detected if omitted.
        """
        lines = [
            "# Incident Investigation Workflow",
            "",
            f"**Client:** {client or '(MUST BE IDENTIFIED — see Phase 0)'}",
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
            "## Workflow — Follow These Phases In Order",
            "",
            "---",
            "",
            "### PHASE 0 — CLASSIFY & PLAN (DO THIS FIRST)",
            "",
            "**Before doing anything else, call `classify_attack` or `plan_investigation`.**",
            "",
            "These tools instantly classify the attack type (phishing, malware, account_compromise,",
            "privilege_escalation, pup_pua, or generic) and return:",
            "- Which tools to call and in what order",
            "- Which steps to SKIP (saves time — e.g. phishing cases skip sandbox analysis)",
            "- Which KQL playbook to use",
            "- Dependencies between tools",
            "",
            "**`classify_attack`** — lightweight; returns attack type + recommended tools.",
            "**`plan_investigation`** — full plan; returns numbered steps with phases, reasons, and conditions.",
            "",
            "Pass the alert title, notes/description, and any available context (URLs, file names,",
            "whether .eml or logs are available). No case ID needed — works on raw text.",
            "",
            "**Use the returned plan to guide all subsequent phases.** Do not run tools that the",
            "plan says to skip. Follow the recommended order.",
            "",
            "---",
            "",
            "### PHASE 1 — CLIENT IDENTIFICATION (MANDATORY HARD GATE)",
            "",
            "**THIS PHASE IS NON-NEGOTIABLE. No investigation proceeds until the client is confirmed.**",
            "",
            "Every incident belongs to exactly ONE client. Client data must NEVER be mixed across cases.",
            "The client determines which security platforms (Sentinel workspace, XDR tenant, CrowdStrike",
            "CID, Encore) you have access to for this investigation.",
            "",
            "**Step 1 — Identify the client:**",
            "- If the analyst specified a client name, use that",
            "- If not, extract it from the incident data:",
            "  - Sentinel alerts: WorkspaceId or workspace name in DataSources",
            "  - MDE alerts: tenant domain in DeviceName, UserPrincipalName domain",
            "  - CrowdStrike: CID or tenant name in alert metadata",
            "  - Email alerts: recipient domain",
            "  - Manual input: ask the analyst which client this belongs to",
            "",
            "**Step 2 — Validate against the client registry:**",
            "- Call `lookup_client` with the identified client name",
            "- If the client is NOT in the registry, STOP and ask the analyst to confirm",
            "- If the client IS found, note the available platforms — these are your ONLY",
            "  permitted data sources for this investigation",
            "",
            "**Step 3 — Set the scope boundary:**",
            "- ALL subsequent queries (KQL, XDR, CrowdStrike) MUST target ONLY this client's",
            "  platforms and workspace(s)",
            "- Do NOT query other clients' workspaces, even for correlation or context",
            "- Cross-client correlation is only permitted via `recall_cases` (shared IOC index)",
            "",
            "**If the client cannot be determined, DO NOT PROCEED. Ask the analyst.**",
            "",
            "---",
            "",
            "### PHASE 2 — INTAKE & CLASSIFICATION",
            "",
            "Extract from the incident data:",
            "- **Alert name / rule**, **Platform**, **Severity**, **Timestamp**",
            "- **Affected entities** — users (UPN), hosts, IPs, emails",
            "- **IOCs** — all IPs, domains, URLs, hashes, email addresses",
            "- **MITRE ATT&CK technique** if identified",
            "",
            "The attack type was already classified in Phase 0. Use that classification —",
            "do NOT re-classify manually.",
            "",
            "**Action:** Call `add_evidence` with the raw incident data to register it in the case.",
            "",
            "---",
            "",
            "### PHASE 3 — RECALL & ENRICHMENT",
            "",
            "Before running ANY queries:",
            "",
            "1. **`recall_cases`** — search for all extracted IOCs across prior investigations",
            "2. **`enrich_iocs`** — extract and enrich all IOCs (runs extract → enrich → score)",
            "",
            "If prior cases fully cover the investigation, present what is known and ask whether",
            "the analyst wants to re-investigate or build on existing data.",
            "",
            "---",
            "",
            "### PHASE 4 — EVIDENCE COLLECTION (Follow the Plan)",
            "",
            "**SCOPE ENFORCEMENT:** Only query platforms confirmed for this client in Phase 1.",
            "",
            "**Follow the tool sequence from `plan_investigation` (Phase 0).** The plan already",
            "accounts for the attack type, skips irrelevant steps, and orders tools correctly.",
            "",
            "Key tool dependencies to respect:",
            "- `detect_phishing` requires `capture_urls` first",
            "- `run_kql` requires confirmed Sentinel workspace from `lookup_client`",
            "- `start_sandbox_session` is optional and only for file-based investigations",
            "",
            "#### KQL Playbooks (use `load_kql_playbook` then `run_kql`):",
            "- **Phishing:** `phishing` — email delivery, URL clicks, credential harvest",
            "- **Malware:** `malware-execution` — process tree, file events, persistence",
            "- **Account Compromise:** `account-compromise` — sign-ins, MFA, post-compromise audit",
            "- **Privilege Escalation:** `privilege-escalation` — role changes, actor legitimacy",
            "- **Data Exfiltration:** `data-exfiltration` — volume anomalies, cloud access, transfers",
            "- **Lateral Movement:** `lateral-movement` — RDP/SMB pivots, credential access, blast radius",
            "- **IOC Hunt:** `ioc-hunt` — cross-table sweep + context pivot",
            "",
            "Execute playbook stages conditionally — check Stage 1 results before running subsequent stages.",
            "",
            "---",
            "",
            "### PHASE 5 — ANALYSIS & DISPOSITION",
            "",
            "With all evidence collected, determine the disposition:",
            "",
            "**True Positive** — confirmed malicious (complete evidence chain, malicious IOCs, execution evidence)",
            "**False Positive** — no malicious activity (clean IOCs, normal operations, no compromise evidence)",
            "**Inconclusive** — insufficient evidence (state what is confirmed / assessed / unknown)",
            "",
            "**Analytical standards — NON-NEGOTIABLE:**",
            "- Every finding must be provable with supplied data",
            "- Temporal proximity is NEVER causation",
            "- No gap-filling with speculation",
            "- Language: Confirmed (data proves it) / Assessed (inference) / Unknown (no data)",
            "",
            "**Behavioural assessment — what the session DID matters more than where it came FROM:**",
            "- A suspicious IP alone is not proof of compromise. You must assess the ACTIVITY performed",
            "  during the session, not just the access vector indicators (IP reputation, geolocation).",
            "- Attacker TTPs after token theft / credential compromise: inbox rule creation, mail forwarding,",
            "  keyword searching (invoice, payment, password), BEC composition, OAuth app consent, MFA",
            "  registration, bulk mail download, SharePoint/OneDrive mass exfiltration, rapid lateral movement.",
            "- Normal user behaviour: reading routine emails, opening shared docs from colleagues, calendar",
            "  interactions, standard app usage patterns, slow/organic browsing of inbox.",
            "- If the session activity is ENTIRELY consistent with normal user behaviour and shows ZERO",
            "  attacker TTPs, this is strong disconfirming evidence — even if the IP is a datacenter/VPN.",
            "  Adversarial IP + benign activity pattern = likely personal VPN, not compromise.",
            "- Do NOT anchor on IP reputation alone. Assess the complete behavioural picture before",
            "  recommending containment actions that disrupt the user.",
            "- When the activity is benign: recommend confirming VPN usage with the user BEFORE",
            "  revoking sessions or forcing password resets.",
            "",
            "---",
            "",
            "### PHASE 6 — OUTPUT (Follow the Plan)",
            "",
            "The `plan_investigation` output already specifies which report tools to call.",
            "General guidance by disposition:",
            "",
            "#### True Positive → MDR Report",
            "1. `generate_report` → investigation narrative",
            "2. `generate_mdr_report` → client-facing deliverable (auto-closes case)",
            "3. `generate_queries` → SIEM hunt queries",
            "4. `response_actions` → containment/eradication guidance",
            "5. `generate_executive_summary` → if high/critical severity",
            "",
            "#### PUP/PUA → PUP Report",
            "1. `generate_pup_report` → lightweight PUP deliverable (auto-closes case)",
            "2. Skip attack-chain analysis, sandbox, campaign clustering",
            "",
            "#### False Positive → FP Closure + Tuning",
            "1. `generate_fp_ticket` → closure comment with suppression recommendation (auto-closes case)",
            "2. `generate_fp_tuning_ticket` → SIEM engineering tuning ticket with root cause, before/after query, impact assessment (does NOT auto-close)",
            "3. Generate BOTH when the analyst wants the alert closed AND the detection rule tuned",
            "",
            "#### Inconclusive → Partial Report",
            "1. `generate_report` → marks findings as confirmed/assessed/unknown",
            "2. Document what additional evidence is needed",
            "3. Do NOT produce an MDR report on incomplete evidence",
            "",
            "---",
            "",
            "### PHASE 7 — CASE CLOSURE",
            "",
            "Most report tools auto-close the case. If not already closed:",
            "- Call `close_case` with disposition: `true_positive`, `false_positive`,",
            "  `benign_true_positive`, or `inconclusive`",
            "",
            "---",
            "",
            "## Reminders",
            "",
            "- **Classify first** — always call `classify_attack` or `plan_investigation` before starting",
            "- **Follow the plan** — don't run tools the plan says to skip",
            "- **Recall before investigate** — always check prior cases first",
            "- **Playbooks over ad-hoc** — use structured playbooks when they match",
            "- **Evidence chain required** — every link must be proven, not assumed",
            "- **Be autonomous** — exhaust 2-3 approaches before asking the analyst for help",
            "- **Keep it concise** — lead with findings, not process narration",
            "- **Default to open cases** — when listing cases, show open only unless asked otherwise",
        ])

        return "\n".join(lines)
