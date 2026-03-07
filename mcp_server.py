#!/usr/bin/env python3
"""
MCP Server for socai — exposes the SOC investigation pipeline to Claude Desktop.

Start automatically by Claude Desktop (stdio transport). Can also be tested:
    python3 mcp_server.py                          # blocks on stdin
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 mcp_server.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure repo root is on the path (same pattern as socai.py)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("socai")


# ---------------------------------------------------------------------------
# Tool: investigate
# ---------------------------------------------------------------------------

@mcp.tool()
def investigate(
    case_id: str,
    title: str = "",
    severity: str = "medium",
    analyst: str = "unassigned",
    urls: list[str] | None = None,
    zip_path: str | None = None,
    zip_pass: str | None = None,
    log_paths: list[str] | None = None,
    eml_paths: list[str] | None = None,
    tags: list[str] | None = None,
    close_case: bool = False,
    include_private_ips: bool = False,
    detonate: bool = False,
) -> str:
    """
    Run the full SOC investigation pipeline for a case.

    Parameters
    ----------
    case_id : str
        Unique case identifier, e.g. "C001".
    title : str
        Human-readable case title.
    severity : str
        One of: low, medium, high, critical.
    analyst : str
        Analyst name or ID to assign the case to.
    urls : list[str]
        URLs to capture and investigate.
    zip_path : str
        Absolute path to a ZIP archive (malware sample, evidence, etc.).
    zip_pass : str
        Password for the ZIP archive (commonly "infected").
    log_paths : list[str]
        Absolute paths to log files (CSV, JSON, .log).
    eml_paths : list[str]
        Absolute paths to .eml email files.
    tags : list[str]
        Free-form tags to attach to the case.
    close_case : bool
        If True, mark the case as closed after the pipeline completes.
    include_private_ips : bool
        If True, include RFC-1918 IPs in IOC extraction.
    detonate : bool
        If True, submit file hashes to sandbox for live detonation.

    Returns
    -------
    str
        JSON summary of the pipeline results.
    """
    from agents.chief import ChiefAgent

    chief = ChiefAgent(case_id)
    result = chief.run(
        title=title or f"Investigation {case_id}",
        severity=severity,
        analyst=analyst,
        tags=tags or [],
        urls=urls or [],
        zip_path=zip_path,
        zip_pass=zip_pass,
        log_paths=log_paths or [],
        eml_paths=eml_paths or [],
        close_case=close_case,
        include_private_ips=include_private_ips,
        detonate=detonate,
    )
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: list_cases
# ---------------------------------------------------------------------------

@mcp.tool()
def list_cases() -> str:
    """
    List all registered SOC cases from the case registry.

    Returns
    -------
    str
        JSON object mapping case IDs to their metadata (title, severity, status).
    """
    from config.settings import REGISTRY_FILE
    from tools.common import load_json

    if not REGISTRY_FILE.exists():
        return json.dumps({"cases": {}, "message": "No registry found."})

    registry = load_json(REGISTRY_FILE)
    return json.dumps(registry, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: get_case
# ---------------------------------------------------------------------------

@mcp.tool()
def get_case(case_id: str) -> str:
    """
    Retrieve metadata for a specific case.

    Parameters
    ----------
    case_id : str
        Case identifier, e.g. "C001".

    Returns
    -------
    str
        JSON object with case metadata (status, severity, IOC counts, report path, etc.).
    """
    from config.settings import CASES_DIR
    from tools.common import load_json

    meta_path = CASES_DIR / case_id / "case_meta.json"
    if not meta_path.exists():
        return json.dumps({"error": f"Case {case_id!r} not found."})

    return json.dumps(load_json(meta_path), indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: read_report
# ---------------------------------------------------------------------------

@mcp.tool()
def read_report(case_id: str) -> str:
    """
    Read the investigation Markdown report for a case.

    Parameters
    ----------
    case_id : str
        Case identifier, e.g. "C001".

    Returns
    -------
    str
        Markdown text of the investigation report, or an error message.
    """
    from config.settings import CASES_DIR

    report_path = CASES_DIR / case_id / "investigation_report.md"
    if not report_path.exists():
        return f"No report found for case {case_id!r}. Run `investigate` or `generate_report` first."

    return report_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Tool: generate_weekly
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_weekly(
    year: int | None = None,
    week: int | None = None,
    include_open: bool = False,
) -> str:
    """
    Generate a weekly SOC rollup report.

    Parameters
    ----------
    year : int
        ISO year (e.g. 2026). Defaults to the current year.
    week : int
        ISO week number (1–53). Defaults to the current week.
    include_open : bool
        If True, include cases that are still open in the rollup.

    Returns
    -------
    str
        JSON summary including the path to the generated report.
    """
    from tools.generate_weekly_report import generate_weekly_report

    result = generate_weekly_report(year=year, week=week, include_open=include_open)
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: generate_queries
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_queries(
    case_id: str,
    platforms: list[str] | None = None,
    tables: list[str] | None = None,
) -> str:
    """
    Generate SIEM hunt queries from a case's IOCs and detected threat patterns.

    Parameters
    ----------
    case_id : str
        Case identifier, e.g. "C001".
    platforms : list[str], optional
        SIEM platforms to generate for. Options: "kql", "splunk", "logscale".
        Defaults to all three.
    tables : list[str], optional
        Confirmed KQL tables where IOC data exists. When supplied, KQL queries
        are scoped to only these tables. Example:
        ["DeviceNetworkEvents", "IdentityLogonEvents", "SecurityEvent", "Syslog"]

    Returns
    -------
    str
        JSON summary including the path to the generated hunt_queries.md file.
    """
    from tools.generate_queries import generate_queries as _gen

    result = _gen(case_id, platforms=platforms, tables=tables)
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: close_case
# ---------------------------------------------------------------------------

@mcp.tool()
def close_case(case_id: str) -> str:
    """
    Mark a case as closed in the registry.

    Parameters
    ----------
    case_id : str
        Case identifier, e.g. "C001".

    Returns
    -------
    str
        JSON confirmation of the status update.
    """
    from tools.index_case import index_case

    result = index_case(case_id, status="closed")
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
