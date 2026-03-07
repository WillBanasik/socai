"""Tool definitions for case-mode and session-mode chat."""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Case-mode tool definitions
# ---------------------------------------------------------------------------

TOOL_DEFS = [
    {
        "name": "assess_landscape",
        "description": (
            "Holistic cross-case intelligence assessment. Analyses ALL cases, IOCs, "
            "links, campaigns, and enrichment data to produce: case statistics, "
            "high-risk cross-case IOCs, link graph clusters, repeat targets, "
            "attack patterns, suggested links, and recommendations. "
            "Use when the analyst asks about trends, patterns, the big picture, "
            "or wants to understand the threat landscape across investigations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "days": {
                    "type": "integer",
                    "description": "Only include cases from the last N days (omit for all time)",
                },
                "client": {
                    "type": "string",
                    "description": "Filter to cases matching this client/org name",
                },
            },
        },
    },
    {
        "name": "link_cases",
        "description": (
            "Link two cases together. Use when cases share IOCs, targets, or campaigns. "
            "Link types: 'duplicate' (same investigation repeated — marks one as canonical), "
            "'related' (same campaign/actor/IOC overlap), 'parent' (case_a is parent of case_b). "
            "For duplicate links, the most recent case becomes canonical by default."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_a": {
                    "type": "string",
                    "description": "First case ID",
                },
                "case_b": {
                    "type": "string",
                    "description": "Second case ID",
                },
                "link_type": {
                    "type": "string",
                    "enum": ["duplicate", "related", "parent"],
                    "description": "Type of relationship",
                    "default": "related",
                },
                "canonical": {
                    "type": "string",
                    "description": "For duplicate links, which case is canonical (optional)",
                },
                "reason": {
                    "type": "string",
                    "description": "Human-readable reason for the link",
                },
            },
            "required": ["case_a", "case_b"],
        },
    },
    {
        "name": "merge_cases",
        "description": (
            "Merge artefacts, IOCs, and findings from source cases into a target (canonical) case. "
            "Source cases are marked as duplicates. Use after recall_cases identifies duplicate investigations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Case IDs to merge FROM",
                },
                "target_id": {
                    "type": "string",
                    "description": "Case ID to merge INTO (becomes canonical)",
                },
            },
            "required": ["source_ids", "target_id"],
        },
    },
    {
        "name": "recall_cases",
        "description": (
            "Search prior cases and cached intelligence for what is ALREADY KNOWN "
            "about given IOCs, email addresses, or keywords. Returns prior case "
            "summaries, verdicts, findings, cached enrichments, and identifies gaps. "
            "MUST be called BEFORE running KQL queries or enrichment for any "
            "investigation — check what we already know first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "iocs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IOC values to search for (IPs, domains, URLs, hashes)",
                },
                "emails": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Email addresses to search for",
                },
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Free-text keywords to match against case titles",
                },
            },
        },
    },
    {
        "name": "capture_urls",
        "description": (
            "Capture web pages — takes screenshots, saves HTML, follows redirect chains. "
            "Use when the analyst wants to investigate URLs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of URLs to capture",
                },
            },
            "required": ["urls"],
        },
    },
    {
        "name": "triage_iocs",
        "description": (
            "Check IOCs against prior case intelligence index. Flags known-malicious "
            "and suspicious IOCs seen in previous investigations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional URLs to triage (omit to triage all case IOCs)",
                },
            },
        },
    },
    {
        "name": "enrich_iocs",
        "description": (
            "Extract IOCs from all case artefacts, enrich via threat intelligence "
            "providers (VirusTotal, AbuseIPDB, Shodan, etc.), and score verdicts. "
            "Returns malicious/suspicious/clean counts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "detect_phishing",
        "description": (
            "Scan captured web pages for brand impersonation (Microsoft, Google, etc.). "
            "Requires URLs to have been captured first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "correlate",
        "description": (
            "Cross-reference IOCs across all case artefacts to find connections "
            "and reconstruct timeline events."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "analyse_email",
        "description": (
            "Parse uploaded .eml files — extract headers, authentication results "
            "(SPF/DKIM/DMARC), spoofing signals, URLs, and attachments."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "generate_report",
        "description": (
            "Generate a full investigation report from all available case artefacts. "
            "Optionally close the case."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "close_case": {
                    "type": "boolean",
                    "description": "Whether to close the case after generating the report",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "generate_mdr_report",
        "description": (
            "Generate an MDR-style incident report using the Gold MDR/XDR Analyst "
            "Instruction Set. Evidence-first, includes confidence statement, "
            "mandatory 'What Was NOT Observed' section, UK English."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "generate_fp_ticket",
        "description": (
            "Create a False Positive suppression ticket from alert data. The analyst "
            "should paste the alert JSON in their message."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_data": {
                    "type": "string",
                    "description": "The alert JSON or text to generate the FP ticket from",
                },
                "platform": {
                    "type": "string",
                    "description": "Alerting platform (sentinel, crowdstrike, defender, entra, cloud_apps). Auto-detected if omitted.",
                },
            },
            "required": ["alert_data"],
        },
    },
    {
        "name": "generate_queries",
        "description": (
            "Generate SIEM hunt queries (KQL for Sentinel, SPL for Splunk, "
            "LogScale for CrowdStrike) based on case IOCs and threat patterns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "platforms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target platforms (e.g. ['kql', 'logscale']). All if omitted.",
                },
            },
        },
    },
    {
        "name": "campaign_cluster",
        "description": (
            "Find cross-case campaigns by clustering cases that share IOCs. "
            "Shows related investigations and shared indicators."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "security_arch_review",
        "description": (
            "Run an LLM security architecture review — analyses the case through "
            "the lens of Microsoft and CrowdStrike security stacks, identifies "
            "control gaps, and recommends detection engineering improvements."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "reconstruct_timeline",
        "description": (
            "Reconstruct a forensic timeline from all case artefacts — web captures, "
            "email headers, enrichment data, logs, sandbox results. Identifies attack "
            "phases, dwell time gaps, and key events."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "analyse_pe_files",
        "description": (
            "Deep analysis of PE files (EXE, DLL, SYS) found in case artefacts. "
            "Examines imports, entropy, sections, packers, and overlays. "
            "Requires pefile to be installed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "yara_scan",
        "description": (
            "Scan case files against YARA rules (built-in + custom). "
            "Detects suspicious PE patterns, PowerShell obfuscation, C2 indicators, "
            "and RAT signatures. Optionally generates case-specific rules via LLM."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "generate_rules": {
                    "type": "boolean",
                    "description": "Generate custom YARA rules for this case using LLM, then re-scan",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "correlate_event_logs",
        "description": (
            "Correlate Windows Event Log entries to detect attack chains: "
            "brute force, lateral movement, persistence, privilege escalation, "
            "Kerberos abuse, pass-the-hash. Works on parsed log files."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "contextualise_cves",
        "description": (
            "Find CVE identifiers across case artefacts and enrich them with "
            "NVD data, EPSS exploitation probability, and CISA KEV status. "
            "Provides patching priority and detection opportunities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "generate_executive_summary",
        "description": (
            "Generate a plain-English executive summary for non-technical leadership. "
            "Uses RAG (Red/Amber/Green) risk rating. No IPs, hashes, or tool names. "
            "Max 500 words, reading age 14."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "add_evidence",
        "description": (
            "Parse and save new IOCs or context from the analyst's message. "
            "Use this when the analyst pastes URLs, IPs, hashes, or other IOCs "
            "that should be added to the case before running other tools."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The analyst's text containing IOCs or context to save",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "read_case_file",
        "description": (
            "Read an artefact file from the case directory. Use to inspect reports, "
            "IOCs, verdicts, enrichment data, or any other case file on demand."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": (
                        "Relative path within the case directory, e.g. "
                        "'reports/investigation_report.md', 'iocs/iocs.json', "
                        "'artefacts/enrichment/verdict_summary.json'"
                    ),
                },
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "run_full_pipeline",
        "description": (
            "Run the entire ChiefAgent investigation pipeline end-to-end. "
            "This captures URLs, enriches IOCs, detects phishing, correlates, "
            "generates a report, and more. Use when the analyst wants a full automated run."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "run_kql",
        "description": (
            "Execute a read-only KQL query against a Microsoft Sentinel / Log Analytics workspace. "
            "Admin-only. Use workspace name (example-client) or a full workspace GUID. "
            "Returns up to 50 rows. Use for live evidence gathering during investigations. "
            "KEY TABLES: SecurityIncident (Title field), SecurityAlert (AlertName field), "
            "CommonSecurityLog, DeviceEvents, DeviceNetworkEvents, SigninLogs. "
            "Use 'startswith' or 'contains' for partial name matches, never '==' for substrings. "
            "Always include a TimeGenerated filter. If no results, try a different table or wider time range."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "The KQL query to execute. Must include a TimeGenerated filter. "
                        "Example: SecurityAlert | where TimeGenerated >= ago(7d) "
                        "| where AlertName startswith \"TI Map\" | sort by TimeGenerated desc | take 10"
                    ),
                },
                "workspace": {
                    "type": "string",
                    "description": "Workspace name (e.g. example-client) or full workspace GUID",
                },
            },
            "required": ["query", "workspace"],
        },
    },
    {
        "name": "load_kql_playbook",
        "description": (
            "Load a pre-built KQL investigation playbook. Playbooks contain expert-crafted, "
            "multi-stage queries for common investigation scenarios (phishing, account compromise, etc.). "
            "Each stage returns ready-to-run KQL with parameter placeholders.\n\n"
            "WORKFLOW: Call with no playbook_id to list available playbooks. Then call with "
            "a playbook_id to load it. Substitute the parameter values from the investigation "
            "context and run each stage via run_kql.\n\n"
            "Available playbooks:\n"
            "- phishing: Multi-stage email investigation (core evidence, post-delivery logon, "
            "URL scope + ZAP timing, attachment endpoint execution)\n"
            "- account-compromise: Sign-in analysis (interactive + non-interactive union), post-compromise activity (MFA, OAuth, mailbox rules)\n"
            "- ioc-hunt: IOC presence sweep across all major Sentinel tables in a single union query, "
            "then conditional context pivot around hits\n"
            "- malware-execution: Malware/script execution traceback — process ancestry + script content, "
            "file delivery chain, initial access vector (USB, email, lateral movement)\n"
            "- privilege-escalation: Privilege escalation / AD group change investigation — escalation event "
            "detail (Entra ID + on-prem AD + alerts), actor legitimacy check (sign-ins + identity), "
            "post-escalation activity (admin portal access, cascading changes, mailbox abuse)"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "string",
                    "description": (
                        "Playbook to load (e.g. 'phishing', 'account-compromise', 'ioc-hunt', "
                        "'malware-execution', 'privilege-escalation'). "
                        "Omit to list all available playbooks."
                    ),
                },
                "stage": {
                    "type": "integer",
                    "description": (
                        "Specific stage number to load. Omit to get the full playbook "
                        "overview with all stages and their run conditions."
                    ),
                },
                "params": {
                    "type": "object",
                    "description": (
                        "Parameter values to substitute into the query. "
                        "E.g. {\"target_id\": \"abc-123-def\"} for phishing stage 1."
                    ),
                },
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Session-mode tool definitions
# ---------------------------------------------------------------------------

SESSION_TOOL_DEFS = [
    {
        "name": "assess_landscape",
        "description": (
            "Holistic cross-case intelligence assessment — case stats, high-risk IOCs, "
            "link clusters, repeat targets, attack patterns, and recommendations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Last N days (omit for all time)"},
                "client": {"type": "string", "description": "Filter to client/org name"},
            },
        },
    },
    {
        "name": "link_cases",
        "description": (
            "Link two cases together. Use when cases share IOCs, targets, or campaigns."
            "Link types: 'duplicate' (same investigation repeated), "
            "'related' (same campaign/actor/IOC overlap), 'parent' (escalation chain)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_a": {"type": "string", "description": "First case ID"},
                "case_b": {"type": "string", "description": "Second case ID"},
                "link_type": {"type": "string", "enum": ["duplicate", "related", "parent"], "default": "related"},
                "canonical": {"type": "string", "description": "For duplicates, which case is canonical"},
                "reason": {"type": "string", "description": "Reason for the link"},
            },
            "required": ["case_a", "case_b"],
        },
    },
    {
        "name": "merge_cases",
        "description": (
            "Merge artefacts, IOCs, and findings from source cases into a target case. "
            "Source cases are marked as duplicates."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "source_ids": {"type": "array", "items": {"type": "string"}, "description": "Cases to merge FROM"},
                "target_id": {"type": "string", "description": "Case to merge INTO"},
            },
            "required": ["source_ids", "target_id"],
        },
    },
    {
        "name": "recall_cases",
        "description": (
            "Search prior cases and cached intelligence for what is ALREADY KNOWN "
            "about given IOCs, email addresses, or keywords. Returns prior case "
            "summaries, verdicts, findings, cached enrichments, and identifies gaps. "
            "MUST be called BEFORE running KQL queries or enrichment for any"
            "investigation — check what we already know first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "iocs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IOC values to search for (IPs, domains, URLs, hashes)",
                },
                "emails": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Email addresses to search for",
                },
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Free-text keywords to match against case titles",
                },
            },
        },
    },
    {
        "name": "analyse_telemetry",
        "description": (
            "Parse an uploaded EDR/SIEM telemetry export file (CrowdStrike CSV, "
            "Defender JSON, generic CSV/NDJSON). Returns structured summary: "
            "event types, processes, tactics, IPs, domains, command lines, key findings."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Name of the uploaded file to analyse",
                },
            },
            "required": ["filename"],
        },
    },
    {
        "name": "read_uploaded_file",
        "description": (
            "Read content from an uploaded file. Supports text-based files. "
            "Use offset/limit for large files."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Name of the uploaded file to read",
                },
                "offset": {
                    "type": "integer",
                    "description": "Line number to start reading from (0-based). Default 0.",
                    "default": 0,
                },
                "limit": {
                    "type": "integer",
                    "description": "Max number of lines to return. Default 200.",
                    "default": 200,
                },
            },
            "required": ["filename"],
        },
    },
    {
        "name": "extract_iocs",
        "description": (
            "Extract IOCs (IPs, domains, hashes, URLs, emails) from text content "
            "and add them to the session investigation context."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to extract IOCs from",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "add_finding",
        "description": (
            "Record a key investigation finding in the session context. "
            "Findings are preserved when the session is materialised into a case."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_type": {
                    "type": "string",
                    "description": "Category: verdict, process_tree, network, lateral_movement, credential_access, etc.",
                },
                "summary": {
                    "type": "string",
                    "description": "One-line summary of the finding",
                },
                "detail": {
                    "type": "string",
                    "description": "Optional detailed explanation",
                    "default": "",
                },
            },
            "required": ["finding_type", "summary"],
        },
    },
    {
        "name": "materialise_case",
        "description": (
            "Convert this investigation session into a full case. "
            "Call this when the analyst is ready for a final output (FP comment or MDR report). "
            "Saves all IOCs, findings, and uploads to the new case."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Case title",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Case severity",
                },
                "disposition": {
                    "type": "string",
                    "enum": ["false_positive", "true_positive", "benign", "suspicious"],
                    "description": "Investigation disposition",
                },
            },
            "required": ["title", "severity", "disposition"],
        },
    },
    {
        "name": "generate_fp_comment",
        "description": (
            "Generate a structured False Positive closure comment from the accumulated "
            "investigation context. Uses the session findings, telemetry analysis, and IOCs. "
            "Optionally uses a per-client template if configured."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "template": {
                    "type": "string",
                    "description": "Optional template name from config/fp_templates/. Auto-detected if omitted.",
                    "default": "",
                },
            },
        },
    },
    {
        "name": "generate_mdr_report",
        "description": (
            "Generate an MDR-style incident report from the accumulated investigation "
            "context. Includes all findings, IOCs, telemetry summary, and recommendations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    # Investigation tools available in session mode
    {
        "name": "capture_urls",
        "description": (
            "Capture web pages — takes screenshots, saves HTML, follows redirect chains. "
            "Use when the analyst provides URLs to investigate. Automatically creates a "
            "temporary case to store the captures."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of URLs to capture",
                },
            },
            "required": ["urls"],
        },
    },
    {
        "name": "detect_phishing",
        "description": (
            "Scan captured web pages for brand impersonation, credential harvest forms, "
            "structural suspicion signals, and deceptive content. Requires URLs to have "
            "been captured first via capture_urls."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "analyse_email",
        "description": (
            "Parse uploaded .eml files — extract headers, authentication results "
            "(SPF/DKIM/DMARC), spoofing signals, URLs, and attachments."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "correlate",
        "description": (
            "Cross-reference IOCs across all case artefacts to find connections "
            "and reconstruct timeline events."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "generate_report",
        "description": (
            "Generate a full investigation report from all available case artefacts. "
            "Optionally close the case."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "close_case": {
                    "type": "boolean",
                    "description": "Whether to close the case after generating the report",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "generate_executive_summary",
        "description": (
            "Generate a plain-English executive summary for non-technical leadership. "
            "Uses RAG (Red/Amber/Green) risk rating. No IPs, hashes, or tool names. "
            "Max 500 words, reading age 14."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "generate_fp_ticket",
        "description": (
            "Create a False Positive suppression ticket from alert data. The analyst "
            "should paste the alert JSON in their message."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_data": {
                    "type": "string",
                    "description": "The alert JSON or text to generate the FP ticket from",
                },
                "platform": {
                    "type": "string",
                    "description": "Alerting platform (sentinel, crowdstrike, defender, entra, cloud_apps). Auto-detected if omitted.",
                },
            },
            "required": ["alert_data"],
        },
    },
    {
        "name": "generate_queries",
        "description": (
            "Generate SIEM hunt queries (KQL for Sentinel, SPL for Splunk, "
            "LogScale for CrowdStrike) based on case IOCs and threat patterns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "platforms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Target platforms (e.g. ['kql', 'logscale']). All if omitted.",
                },
            },
        },
    },
    {
        "name": "reconstruct_timeline",
        "description": (
            "Reconstruct a forensic timeline from all case artefacts — web captures, "
            "email headers, enrichment data, logs, sandbox results. Identifies attack "
            "phases, dwell time gaps, and key events."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "security_arch_review",
        "description": (
            "Run an LLM security architecture review — analyses the case through "
            "the lens of Microsoft and CrowdStrike security stacks, identifies "
            "control gaps, and recommends detection engineering improvements."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "run_full_pipeline",
        "description": (
            "Run the entire ChiefAgent investigation pipeline end-to-end. "
            "This captures URLs, enriches IOCs, detects phishing, correlates, "
            "generates a report, and more. Use when the analyst wants a full automated run."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "contextualise_cves",
        "description": (
            "Find CVE identifiers across case artefacts and enrich them with "
            "NVD data, EPSS exploitation probability, and CISA KEV status. "
            "Provides patching priority and detection opportunities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "analyse_pe_files",
        "description": (
            "Deep analysis of PE files (EXE, DLL, SYS) found in case artefacts. "
            "Examines imports, entropy, sections, packers, and overlays."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "correlate_event_logs",
        "description": (
            "Correlate Windows Event Log entries to detect attack chains: "
            "brute force, lateral movement, persistence, privilege escalation, "
            "Kerberos abuse, pass-the-hash. Works on parsed log files."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "yara_scan",
        "description": (
            "Scan case files against YARA rules (built-in + custom). "
            "Detects suspicious PE patterns, PowerShell obfuscation, C2 indicators, "
            "and RAT signatures. Optionally generates case-specific rules via LLM."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "generate_rules": {
                    "type": "boolean",
                    "description": "Generate custom YARA rules for this case using LLM, then re-scan",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "read_case_file",
        "description": (
            "Read an artefact file from the backing case directory. Use to inspect reports, "
            "IOCs, verdicts, enrichment data, or any other case file on demand."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": (
                        "Relative path within the case directory, e.g. "
                        "'reports/investigation_report.md', 'iocs/iocs.json', "
                        "'artefacts/enrichment/verdict_summary.json'"
                    ),
                },
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "add_evidence",
        "description": (
            "Parse and save new IOCs or context from the analyst's message. "
            "Use this when the analyst pastes URLs, IPs, hashes, or other IOCs "
            "that should be added to the case before running other tools."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The analyst's text containing IOCs or context to save",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "campaign_cluster",
        "description": (
            "Find cross-case campaigns by clustering cases that share IOCs. "
            "Shows related investigations and shared indicators."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "enrich_iocs",
        "description": (
            "Enrich IOCs in the session context via threat intelligence providers "
            "(VirusTotal, AbuseIPDB, Shodan, etc.). Requires IOCs to have been extracted."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "triage_iocs",
        "description": (
            "Check IOCs from the session context against the prior case intelligence index."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "load_case_context",
        "description": (
            "Load an existing case's context into the current session. Returns case summary, "
            "IOCs, findings, and verdicts. Use when the analyst wants to work on a specific case "
            "within a session — e.g. 'load case C310' or 'switch to case C310'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "The case ID to load (e.g. C310)",
                },
            },
            "required": ["case_id"],
        },
    },
    {
        "name": "save_to_case",
        "description": (
            "Save investigation updates back to a case. Use after working on a case in session mode "
            "to persist findings, IOCs, status changes, or notes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "string",
                    "description": "The case ID to save to",
                },
                "updates": {
                    "type": "object",
                    "description": (
                        "Object with optional keys: findings (array of {type, summary, detail}), "
                        "iocs (object with arrays: ips, domains, urls, hashes), "
                        "status (string), disposition (string), notes (string)"
                    ),
                },
            },
            "required": ["case_id", "updates"],
        },
    },
    {
        "name": "run_kql",
        "description": (
            "Execute a read-only KQL query against a Microsoft Sentinel / Log Analytics workspace. "
            "Admin-only. Use workspace name (example-client) or a full workspace GUID. "
            "Returns up to 50 rows. Use for live evidence gathering during investigations. "
            "KEY TABLES: SecurityIncident (Title field), SecurityAlert (AlertName field), "
            "CommonSecurityLog, DeviceEvents, DeviceNetworkEvents, SigninLogs. "
            "Use 'startswith' or 'contains' for partial name matches, never '==' for substrings. "
            "Always include a TimeGenerated filter. If no results, try a different table or wider time range."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "The KQL query to execute. Must include a TimeGenerated filter. "
                        "Example: SecurityAlert | where TimeGenerated >= ago(7d) "
                        "| where AlertName startswith \"TI Map\" | sort by TimeGenerated desc | take 10"
                    ),
                },
                "workspace": {
                    "type": "string",
                    "description": "Workspace name (e.g. example-client) or full workspace GUID",
                },
            },
            "required": ["query", "workspace"],
        },
    },
    {
        "name": "load_kql_playbook",
        "description": (
            "Load a pre-built KQL investigation playbook. Playbooks contain expert-crafted, "
            "multi-stage queries for common investigation scenarios (phishing, account compromise, etc.). "
            "Each stage returns ready-to-run KQL with parameter placeholders.\n\n"
            "WORKFLOW: Call with no playbook_id to list available playbooks. Then call with "
            "a playbook_id to load it. Substitute the parameter values from the investigation "
            "context and run each stage via run_kql.\n\n"
            "Available playbooks:\n"
            "- phishing: Multi-stage email investigation (core evidence, post-delivery logon, "
            "URL scope + ZAP timing, attachment endpoint execution)\n"
            "- account-compromise: Sign-in analysis (interactive + non-interactive union), post-compromise activity (MFA, OAuth, mailbox rules)\n"
            "- ioc-hunt: IOC presence sweep across all major Sentinel tables in a single union query, "
            "then conditional context pivot around hits\n"
            "- malware-execution: Malware/script execution traceback — process ancestry + script content, "
            "file delivery chain, initial access vector (USB, email, lateral movement)\n"
            "- privilege-escalation: Privilege escalation / AD group change investigation — escalation event "
            "detail (Entra ID + on-prem AD + alerts), actor legitimacy check (sign-ins + identity), "
            "post-escalation activity (admin portal access, cascading changes, mailbox abuse)"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "string",
                    "description": (
                        "Playbook to load (e.g. 'phishing', 'account-compromise', 'ioc-hunt', "
                        "'malware-execution', 'privilege-escalation'). "
                        "Omit to list all available playbooks."
                    ),
                },
                "stage": {
                    "type": "integer",
                    "description": (
                        "Specific stage number to load. Omit to get the full playbook "
                        "overview with all stages and their run conditions."
                    ),
                },
                "params": {
                    "type": "object",
                    "description": (
                        "Parameter values to substitute into the query. "
                        "E.g. {\"target_id\": \"abc-123-def\"} for phishing stage 1."
                    ),
                },
            },
        },
    },
]
