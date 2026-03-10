"""MCP prompt implementations — workflow templates for LLM consumption.

KQL playbooks map naturally to MCP prompts: they're parameterised templates
with stage-by-stage investigation guidance. Three additional prompts provide
triage, FP-ticket, and end-to-end incident investigation workflows.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP


def register_prompts(mcp: FastMCP) -> None:
    """Register all MCP prompt handlers."""

    # ------------------------------------------------------------------
    # KQL Playbook prompts (5)
    # ------------------------------------------------------------------

    @mcp.prompt()
    def investigate_phishing(
        target_email: str = "",
        suspicious_url: str = "",
        target_ids: str = "",
    ) -> str:
        """Multi-stage KQL phishing investigation playbook.

        Parameters
        ----------
        target_email : str
            Email address of the phishing target.
        suspicious_url : str
            The suspicious URL from the phishing email.
        target_ids : str
            Comma-separated quoted list of target user IDs for KQL queries.
        """
        from tools.kql_playbooks import load_playbook, render_stage

        pb = load_playbook("phishing")
        if not pb:
            return "Phishing playbook not found."

        lines = [
            f"# Phishing Investigation Playbook",
            f"",
            f"**Target email:** {target_email or '(not specified)'}",
            f"**Suspicious URL:** {suspicious_url or '(not specified)'}",
            f"**Target IDs:** {target_ids or '(not specified)'}",
            f"",
            f"## Overview",
            f"{pb.get('description', '')}",
            f"",
            f"## Parameters",
        ]

        for param in pb.get("parameters", []):
            lines.append(f"- **{param['name']}**: {param.get('description', '')}")

        lines.append("")
        lines.append("## Investigation Stages")
        lines.append("")

        params = {}
        if target_ids:
            params["target_ids"] = target_ids
        if suspicious_url:
            params["suspicious_url"] = suspicious_url
        if target_email:
            params["target_email"] = target_email

        for i, stage in enumerate(pb.get("stages", []), 1):
            lines.append(f"### Stage {i} — {stage.get('name', stage.get('title', ''))}")
            if stage.get("description"):
                lines.append(f"{stage['description']}")
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

    @mcp.prompt()
    def investigate_account_compromise(
        target_upn: str = "",
        timeframe: str = "7d",
    ) -> str:
        """Multi-stage KQL account compromise investigation playbook.

        Parameters
        ----------
        target_upn : str
            User Principal Name of the compromised account.
        timeframe : str
            Lookback period (e.g. "7d", "24h").
        """
        from tools.kql_playbooks import load_playbook, render_stage

        pb = load_playbook("account-compromise")
        if not pb:
            return "Account compromise playbook not found."

        params = {}
        if target_upn:
            params["target_upn"] = target_upn
        if timeframe:
            params["timeframe"] = timeframe

        return _render_playbook(pb, "Account Compromise Investigation", params, {
            "target_upn": target_upn,
            "timeframe": timeframe,
        })

    @mcp.prompt()
    def investigate_ioc_hunt(
        ioc_value: str = "",
        ioc_type: str = "",
    ) -> str:
        """Multi-stage KQL IOC hunting playbook.

        Parameters
        ----------
        ioc_value : str
            The IOC value to hunt for.
        ioc_type : str
            IOC type: ip, domain, hash, url.
        """
        from tools.kql_playbooks import load_playbook

        pb = load_playbook("ioc-hunt")
        if not pb:
            return "IOC hunt playbook not found."

        params = {}
        if ioc_value:
            params["ioc_value"] = ioc_value
        if ioc_type:
            params["ioc_type"] = ioc_type

        return _render_playbook(pb, "IOC Hunt", params, {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
        })

    @mcp.prompt()
    def investigate_malware_execution(
        hostname: str = "",
        process_name: str = "",
        hash: str = "",
    ) -> str:
        """Multi-stage KQL malware execution investigation playbook.

        Parameters
        ----------
        hostname : str
            Target hostname.
        process_name : str
            Suspicious process name.
        hash : str
            File hash (SHA256 preferred).
        """
        from tools.kql_playbooks import load_playbook

        pb = load_playbook("malware-execution")
        if not pb:
            return "Malware execution playbook not found."

        params = {}
        if hostname:
            params["hostname"] = hostname
        if process_name:
            params["process_name"] = process_name
        if hash:
            params["hash"] = hash

        return _render_playbook(pb, "Malware Execution Investigation", params, {
            "hostname": hostname,
            "process_name": process_name,
            "hash": hash,
        })

    @mcp.prompt()
    def investigate_privilege_escalation(
        target_host: str = "",
        timeframe: str = "7d",
    ) -> str:
        """Multi-stage KQL privilege escalation investigation playbook.

        Parameters
        ----------
        target_host : str
            Target hostname or IP.
        timeframe : str
            Lookback period.
        """
        from tools.kql_playbooks import load_playbook

        pb = load_playbook("privilege-escalation")
        if not pb:
            return "Privilege escalation playbook not found."

        params = {}
        if target_host:
            params["target_host"] = target_host
        if timeframe:
            params["timeframe"] = timeframe

        return _render_playbook(pb, "Privilege Escalation Investigation", params, {
            "target_host": target_host,
            "timeframe": timeframe,
        })

    # ------------------------------------------------------------------
    # Workflow prompts (2)
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
            "- Identify the alert category (phishing, malware, credential access, lateral movement, etc.)",
            "- Determine if this is a known detection pattern or novel activity",
            "- Check if the alert source and detection logic are reliable",
            "",
            "### 2. IOC Extraction",
            "- Extract all IOCs from the alert: IPs, domains, URLs, hashes, email addresses",
            "- Use `recall_cases` to check if any IOCs appear in prior investigations",
            "- Use `enrich_iocs` to query threat intelligence providers",
            "",
            "### 3. Contextualisation",
            "- Identify the affected user(s) and asset(s)",
            "- Determine the business impact and data sensitivity",
            "- Check for related alerts in the same timeframe",
            "",
            "### 4. Verdict",
            "- **True Positive** — confirmed malicious activity requiring response",
            "- **Benign True Positive** — legitimate activity triggering the detection",
            "- **False Positive** — detection error, consider `generate_fp_ticket`",
            "- **Inconclusive** — insufficient data, escalate or gather more evidence",
            "",
            "### 5. Response Recommendation",
            "- If TP: recommend containment, eradication, and recovery actions",
            "- If BTP/FP: document the finding and any tuning recommendations",
            "- If Inconclusive: identify what additional data is needed",
            "",
            "### 6. Documentation",
            "- Create a case with `investigate` or `quick_investigate_url`",
            "- Generate report with `generate_report`",
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
            "### 4. Generate Ticket",
            "- Use `generate_fp_ticket` with the alert data and platform",
            "- Review the generated ticket for accuracy",
            "- Include the detection query and proposed modifications",
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
            "### PHASE 0 — CLIENT IDENTIFICATION (MANDATORY HARD GATE)",
            "",
            "**THIS PHASE IS NON-NEGOTIABLE. No investigation proceeds until the client is confirmed.**",
            "",
            "Every incident belongs to exactly ONE client. Client data must NEVER be mixed across cases. ",
            "The client determines which security platforms (Sentinel workspace, XDR tenant, CrowdStrike ",
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
            "- If the client IS found, note the available platforms — these are your ONLY ",
            "  permitted data sources for this investigation",
            "",
            "**Step 3 — Set the scope boundary:**",
            "- The case MUST be created with the correct `client` field",
            "- ALL subsequent queries (KQL, XDR, CrowdStrike) MUST target ONLY this client's ",
            "  platforms and workspace(s)",
            "- Do NOT query other clients' workspaces, even for correlation or context",
            "- Do NOT mix IOCs or findings from other clients' cases into this investigation",
            "- Cross-client correlation is only permitted via `recall_cases` (which searches the ",
            "  shared IOC index) — but findings from other clients' cases must be clearly attributed",
            "",
            "**If the client cannot be determined, DO NOT PROCEED. Ask the analyst.**",
            "",
            "---",
            "",
            "### PHASE 1 — INTAKE & CLASSIFICATION",
            "",
            "Extract the following from the incident data:",
            "- **Client** (confirmed in Phase 0)",
            "- **Alert name / rule** that fired",
            "- **Platform** (Sentinel, MDE, CrowdStrike, Entra ID, Cloud Apps)",
            "- **Severity** (use provided override, or derive from alert data)",
            "- **Affected entities** — users (UPN), hosts (hostname/DeviceId), IPs, emails",
            "- **IOCs** — all IPs, domains, URLs, hashes, email addresses present",
            "- **MITRE ATT&CK technique** if identified in the alert",
            "- **Timestamp** of the alert / incident",
            "",
            "Then classify the incident into ONE primary category:",
            "",
            "| Category | Indicators |",
            "|----------|------------|",
            "| **Phishing** | Email alert, suspicious URL/attachment, UrlClickEvents, EmailEvents |",
            "| **Malware / Endpoint** | Process execution, file creation, persistence, MDE alerts |",
            "| **Account Compromise** | Risky sign-in, impossible travel, MFA anomaly, token theft |",
            "| **Privilege Escalation** | Role/group change, PIM elevation, AD event 4728/4732/4756 |",
            "| **Lateral Movement** | Internal RDP/SMB, pass-the-hash, service account misuse |",
            "| **Data Exfiltration** | DLP alert, unusual download volume, Cloud Apps anomaly |",
            "| **IOC Match** | TI Map alert, watchlist hit, known-bad hash/IP/domain |",
            "",
            "**Action:** Call `add_evidence` with the raw incident data to register it in the case.",
            "",
            "---",
            "",
            "### PHASE 2 — RECALL & CONTEXT",
            "",
            "Before running ANY queries or enrichment:",
            "",
            "1. **`recall_cases`** — search for all extracted IOCs and entities across prior investigations",
            "2. **`enrich_iocs`** — extract and enrich all IOCs (runs extract_iocs → enrich → score)",
            "",
            "Review the results. If prior cases fully cover the investigation, present what is known ",
            "and ask whether the analyst wants to re-investigate or build on existing data.",
            "",
            "State explicitly: what is already known vs. what gaps remain.",
            "",
            "---",
            "",
            "### PHASE 3 — EVIDENCE COLLECTION (Playbook-Driven)",
            "",
            "**SCOPE ENFORCEMENT:** Only query platforms confirmed for this client in Phase 0. ",
            "If the client only has Sentinel access, do not attempt XDR or CrowdStrike queries. ",
            "The `lookup_client` result from Phase 0 defines your permitted platform boundary.",
            "",
            "Based on the classification from Phase 1, execute the appropriate KQL playbook. ",
            "Use `load_kql_playbook` to get the parameterised queries, then `run_kql` to execute each stage.",
            "",
            "#### Phishing",
            "- **Playbook:** `phishing` (4 stages)",
            "- **Params:** `target_ids` (NetworkMessageId), `url`, `sha256`",
            "- **Also:** `capture_urls` on any suspicious URLs, then `detect_phishing` on captures",
            "- **Also:** `analyse_email` if .eml file is available",
            "- Check: did the user click? Was the attachment executed? Were credentials entered?",
            "",
            "#### Malware / Endpoint",
            "- **Playbook:** `malware-execution` (3 stages)",
            "- **Params:** `device_name`, `filename`, `sha256`, `lookback`",
            "- **Also:** Consider `start_sandbox_session` for dynamic analysis of suspicious files",
            "- Trace: execution → delivery → initial access vector",
            "",
            "#### Account Compromise",
            "- **Playbook:** `account-compromise` (2 stages)",
            "- **Params:** `upn`, `ip` (optional), `lookback`",
            "- Stage 1: sign-in history with risk signals and triage summary",
            "- Stage 2: post-compromise audit (MFA changes, OAuth consent, mailbox rules)",
            "",
            "#### Privilege Escalation",
            "- **Playbook:** `privilege-escalation` (3 stages)",
            "- **Params:** `actor_upn`, `target_user`, `target_group`, `lookback`",
            "- Stage 1: escalation events + related alerts",
            "- Stage 2: actor legitimacy (sign-in activity, IdentityInfo)",
            "- Stage 3: post-escalation activity (conditional)",
            "",
            "#### IOC Match / Lateral Movement / Data Exfiltration",
            "- **Playbook:** `ioc-hunt` (2 stages)",
            "- **Params:** `iocs` (comma-separated), `lookback`",
            "- Stage 1: union sweep across all tables",
            "- Stage 2: context pivot (30-min window around hits)",
            "- For data exfiltration: also check OfficeActivity, DLP logs",
            "",
            "#### No matching playbook",
            "- Use ad-hoc `run_kql` queries targeting the relevant tables",
            "- Follow the investigation hierarchy: Incidents → Alerts → Events",
            "",
            "**Important:** Execute playbook stages conditionally — check Stage 1 results ",
            "before running subsequent stages. Each stage has run conditions documented in the playbook.",
            "",
            "---",
            "",
            "### PHASE 4 — ANALYSIS & DISPOSITION",
            "",
            "With all evidence collected, determine the disposition:",
            "",
            "**True Positive** — confirmed malicious activity:",
            "- Evidence chain is complete (every link proven with data)",
            "- Enrichment confirms malicious IOCs",
            "- Endpoint telemetry shows execution/impact",
            "",
            "**False Positive** — no malicious activity:",
            "- IOCs are clean across all TI sources",
            "- Activity is consistent with normal operations",
            "- No evidence of compromise, lateral movement, or data loss",
            "",
            "**Inconclusive** — insufficient evidence:",
            "- Some links in the evidence chain are missing",
            "- State what is confirmed, what is assessed, and what is unknown",
            "- Identify what additional data would resolve the ambiguity",
            "",
            "**Analytical standards apply — these are NON-NEGOTIABLE:**",
            "- Every finding must be provable with supplied data",
            "- Temporal proximity is NEVER causation",
            "- No gap-filling with speculation",
            "- Distinguish: Confirmed (data proves it) / Assessed (inference) / Unknown (no data)",
            "",
            "---",
            "",
            "### PHASE 5 — OUTPUT",
            "",
            "Based on the disposition:",
            "",
            "#### True Positive → MDR Report",
            "1. Call `generate_report` to produce the investigation report",
            "2. Call `generate_mdr_report` for the structured MDR deliverable",
            "3. Call `generate_queries` for SIEM hunt queries the client can deploy",
            "4. Optionally call `response_actions` for containment/eradication guidance",
            "5. Call `generate_executive_summary` if this is high/critical severity",
            "",
            "#### False Positive → FP Closure Comment",
            "1. Call `generate_fp_ticket` with the alert data and platform",
            "2. The output is a concise 1-2 sentence closure comment explaining why there is no risk",
            "3. The comment is tailored to the alert type (IOC-based, identity, endpoint, etc.)",
            "",
            "#### Inconclusive → Partial Report",
            "1. Call `generate_report` — it will mark findings as confirmed/assessed/unknown",
            "2. Document what additional evidence is needed to reach a conclusion",
            "3. Do NOT produce an MDR report on incomplete evidence",
            "",
            "---",
            "",
            "### PHASE 6 — CASE CLOSURE",
            "",
            "1. Call `close_case` with the appropriate disposition:",
            "   - `true_positive` — confirmed malicious",
            "   - `false_positive` — confirmed benign",
            "   - `benign_true_positive` — legitimate activity that triggered detection",
            "   - `inconclusive` — insufficient evidence",
            "2. Ensure all artefacts are generated before closing",
            "",
            "---",
            "",
            "## Reminders",
            "",
            "- **Recall before investigate** — always check prior cases first",
            "- **Playbooks over ad-hoc** — use the structured playbooks when they match",
            "- **Evidence chain required** — every link must be proven, not assumed",
            "- **Be autonomous** — exhaust 2-3 approaches before asking the analyst for help",
            "- **Keep it concise** — lead with findings, not process narration",
        ])

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _render_playbook(
    pb: dict,
    title: str,
    kql_params: dict,
    display_params: dict,
) -> str:
    """Render a full playbook into a prompt string."""
    from tools.kql_playbooks import render_stage

    lines = [
        f"# {title} Playbook",
        "",
    ]

    for key, val in display_params.items():
        lines.append(f"**{key}:** {val or '(not specified)'}")
    lines.append("")

    lines.append("## Overview")
    lines.append(pb.get("description", ""))
    lines.append("")

    lines.append("## Parameters")
    for param in pb.get("parameters", []):
        lines.append(f"- **{param['name']}**: {param.get('description', '')}")
    lines.append("")

    lines.append("## Investigation Stages")
    lines.append("")

    for i, stage in enumerate(pb.get("stages", []), 1):
        lines.append(f"### Stage {i} — {stage.get('name', stage.get('title', ''))}")
        if stage.get("description"):
            lines.append(stage["description"])
        lines.append("")

        rendered = render_stage(pb, i, kql_params)
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
