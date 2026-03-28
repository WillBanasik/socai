"""
tool: sentinel_queries
----------------------
Loads and renders composite Sentinel KQL query templates from
config/kql_playbooks/sentinel/.

Unlike stage-based playbooks (tools/kql_playbooks.py), composite queries
produce a single monolithic KQL string with multiple ``let`` sections
unioned together — designed for single-execution full-picture queries.

Usage:
    from tools.sentinel_queries import list_scenarios, render_query

    scenarios = list_scenarios()
    result = render_query("mailbox-permission-change", upn="user@domain.com")
    print(result["query"])  # ready-to-run KQL
"""
from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR, CASES_DIR
from tools.kql_playbooks import _parse_frontmatter

SENTINEL_QUERIES_DIR = BASE_DIR / "config" / "kql_playbooks" / "sentinel"


def list_scenarios() -> list[dict]:
    """Return a summary of all available Sentinel composite query scenarios."""
    if not SENTINEL_QUERIES_DIR.exists():
        return []
    result = []
    for path in sorted(SENTINEL_QUERIES_DIR.glob("*.kql")):
        meta = _parse_frontmatter(path.read_text(encoding="utf-8"))
        result.append({
            "id": path.stem,
            "name": meta.get("name", path.stem),
            "description": meta.get("description", ""),
            "parameters": meta.get("parameters", []),
            "tables": meta.get("tables", []),
        })
    return result


def load_scenario(scenario_id: str) -> dict | None:
    """Load a scenario template by ID (filename without extension)."""
    path = SENTINEL_QUERIES_DIR / f"{scenario_id}.kql"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    meta = _parse_frontmatter(text)
    return {
        "id": scenario_id,
        "name": meta.get("name", scenario_id),
        "description": meta.get("description", ""),
        "parameters": meta.get("parameters", []),
        "tables": meta.get("tables", []),
        "query_template": _extract_query_body(text),
    }


def render_query(
    scenario_id: str,
    *,
    upn: str,
    ip: str = "",
    object_id: str = "",
    mailbox_id: str = "",
    additional_upns: str = "",
    lookback_hours: int = 24,
) -> dict:
    """Render a composite Sentinel query with parameter substitution.

    Returns a dict with the ready-to-run KQL and metadata, or an error dict.
    """
    scenario = load_scenario(scenario_id)
    if not scenario:
        available = [s["id"] for s in list_scenarios()]
        return {"error": f"Scenario {scenario_id!r} not found. Available: {available}"}

    now = datetime.now(timezone.utc)
    lookback_start = now - timedelta(hours=lookback_hours)
    lookback_end = now

    # Parse additional UPNs into a KQL dynamic list
    extra_upns = [u.strip() for u in additional_upns.split(",") if u.strip()] if additional_upns else []
    extra_upns_kql = ", ".join(f'"{u}"' for u in extra_upns) if extra_upns else ""

    # Build substitution map
    params = {
        "upn": upn,
        "ip": ip,
        "object_id": object_id,
        "mailbox_id": mailbox_id,
        "additional_upns": extra_upns_kql,
        "lookback_start": lookback_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lookback_end": lookback_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lookback_hours": str(lookback_hours),
    }

    query = scenario["query_template"]
    for key, value in params.items():
        query = query.replace(f"{{{{{key}}}}}", value)

    result = {
        "scenario": scenario_id,
        "name": scenario["name"],
        "description": scenario["description"],
        "tables": scenario["tables"],
        "query": query.strip(),
        "lookback_hours": lookback_hours,
        "parameters_used": {k: v for k, v in params.items() if v},
        "note": (
            "Composite queries use a union of numbered sections. "
            "Missing section numbers in the output mean 0 results for that section."
        ),
    }

    try:
        from config.sentinel_schema import validate_tables
        validation = validate_tables(scenario["tables"])
        if validation.get("warnings"):
            result["schema_warnings"] = validation["warnings"]
    except Exception:
        pass

    return result


def render_queries_parallel(
    scenario_ids: list[str],
    *,
    upn: str,
    ip: str = "",
    object_id: str = "",
    mailbox_id: str = "",
    additional_upns: str = "",
    lookback_hours: int = 24,
    max_workers: int = 4,
) -> list[dict]:
    """Render multiple composite Sentinel queries concurrently.

    Returns a list of rendered query dicts (same format as ``render_query``).
    Errors for individual scenarios are returned inline as ``{error: ...}``.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: list[dict] = []
    common = dict(
        upn=upn, ip=ip, object_id=object_id, mailbox_id=mailbox_id,
        additional_upns=additional_upns, lookback_hours=lookback_hours,
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_id = {
            executor.submit(render_query, sid, **common): sid
            for sid in scenario_ids
        }
        for future in as_completed(future_to_id):
            sid = future_to_id[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"scenario": sid, "error": str(exc)})
    return results


def _extract_query_body(text: str) -> str:
    """Extract the KQL body after the closing frontmatter delimiter."""
    lines = text.split("\n")
    in_fm = False
    body_start = 0
    for i, line in enumerate(lines):
        if line.strip() == "// ---":
            if in_fm:
                body_start = i + 1
                break
            in_fm = True
    return "\n".join(lines[body_start:]).strip()


# ---------------------------------------------------------------------------
# KQL workspace resolution (shared by MCP server)
# ---------------------------------------------------------------------------

_GUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
)


def resolve_kql_workspace(workspace: str, case_id: str | None = None) -> str | None:
    """Resolve workspace name/GUID from explicit value, case client, or env var.

    Resolution order:
      1. Explicit workspace param (name or GUID)
      2. Case client → client_entities.json workspace_id
      3. SOCAI_SENTINEL_WORKSPACE env var
    Returns a workspace GUID, or None if unresolvable.
    """
    import json as _json
    from scripts.run_kql import _resolve_workspace

    # 1. Explicit workspace
    if workspace:
        if _GUID_RE.match(workspace):
            return workspace
        try:
            return _resolve_workspace(None, workspace)
        except SystemExit:
            return None

    # 2. Case client → client_entities.json
    if case_id:
        try:
            meta_path = CASES_DIR / case_id / "case_meta.json"
            if meta_path.exists():
                client = _json.load(open(meta_path)).get("client", "").strip()
                if client:
                    ent_path = BASE_DIR / "config" / "client_entities.json"
                    entities = _json.load(open(ent_path)).get("clients", [])
                    for ent in entities:
                        if ent.get("name", "").lower() == client.lower():
                            # New nested layout: platforms.sentinel.workspace_id
                            platforms = ent.get("platforms", {})
                            if isinstance(platforms, dict):
                                sentinel = platforms.get("sentinel", {})
                                if isinstance(sentinel, dict) and sentinel.get("workspace_id"):
                                    return sentinel["workspace_id"]
                            # Legacy flat layout
                            if ent.get("workspace_id"):
                                return ent["workspace_id"]
                    # Also try workspace_tables.json (client name = workspace code)
                    try:
                        return _resolve_workspace(None, client)
                    except SystemExit:
                        pass
        except (FileNotFoundError, Exception):
            pass

    # 3. Env var fallback
    env_ws = os.environ.get("SOCAI_SENTINEL_WORKSPACE", "").strip()
    if env_ws:
        if _GUID_RE.match(env_ws):
            return env_ws
        try:
            return _resolve_workspace(None, env_ws)
        except SystemExit:
            pass

    return None
