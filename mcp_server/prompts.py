"""MCP prompt implementations — workflow templates for LLM consumption.

KQL playbooks map naturally to MCP prompts: they're parameterised templates
with stage-by-stage investigation guidance. Two additional prompts provide
triage and FP-ticket workflows.
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
