"""
tool: cql_playbooks
--------------------
Loads parameterised CQL (LogScale/NGSIEM) investigation playbooks from
config/cql_playbooks/.

Each .cql file uses the same frontmatter format as KQL playbooks (YAML-like
in ``//`` comments) with stage delimiters.  The parser is shared with
``kql_playbooks.py``.

Usage:
    from tools.cql_playbooks import list_playbooks, load_playbook, render_stage

    playbooks = list_playbooks()
    pb = load_playbook("malware-execution")
    query = render_stage(pb, stage=1, params={"device_name": "DESKTOP-01"})
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR
from tools.kql_playbooks import _parse_frontmatter, _parse_stages

CQL_PLAYBOOKS_DIR = BASE_DIR / "config" / "cql_playbooks"

# ---------------------------------------------------------------------------
# Discovery queries — always returned with playbook data so the analyst can
# quickly identify correct tags, fields, and connector IDs when debugging.
# ---------------------------------------------------------------------------

DISCOVERY_QUERIES = [
    {
        "name": "List all connectors (tags, vendor, product, event count)",
        "query": (
            "*\n"
            "| groupBy(@dataConnectionID, function=[\n"
            "    collect([#Vendor, #event.dataset, #event.module, observer.vendor, observer.product]),\n"
            "    count()\n"
            "  ])"
        ),
    },
    {
        "name": "Get sample event for a connector (all fields)",
        "query": (
            '@dataConnectionID = "CONNECTOR_ID_HERE"\n'
            "| tail(1)"
        ),
    },
]


def list_playbooks() -> list[dict]:
    """Return a summary of all available CQL playbooks."""
    if not CQL_PLAYBOOKS_DIR.exists():
        return []
    result = []
    for path in sorted(CQL_PLAYBOOKS_DIR.glob("*.cql")):
        meta = _parse_frontmatter(path.read_text(encoding="utf-8"))
        result.append({
            "id": path.stem,
            "language": "cql",
            "name": meta.get("name", path.stem),
            "description": meta.get("description", ""),
            "parameters": meta.get("parameters", []),
            "stages": meta.get("stages", []),
            "data_sources": meta.get("data_sources", []),
            "definitions": meta.get("definitions", []),
        })
    return result


def load_playbook(playbook_id: str) -> dict | None:
    """Load a CQL playbook by ID (filename without extension)."""
    path = CQL_PLAYBOOKS_DIR / f"{playbook_id}.cql"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    meta = _parse_frontmatter(text)
    stages = _parse_stages(text)

    # Enrich stages with sub-query info
    for stage in stages:
        stage["sub_queries"] = _parse_sub_queries(stage.get("query", ""))

    return {
        "id": playbook_id,
        "language": "cql",
        "name": meta.get("name", playbook_id),
        "description": meta.get("description", ""),
        "parameters": meta.get("parameters", []),
        "stages": stages,
        "data_sources": meta.get("data_sources", []),
        "definitions": meta.get("definitions", []),
        "discovery_queries": DISCOVERY_QUERIES,
    }


def render_stage(playbook: dict, stage: int, params: dict[str, str]) -> str:
    """Render a specific stage's CQL with parameter substitution.

    Parameters are replaced using ``{{param_name}}`` syntax.
    Returns the ready-to-run CQL query text.
    """
    stages = playbook.get("stages", [])
    for s in stages:
        if s.get("stage") == stage:
            query = s["query"]
            for key, value in params.items():
                query = query.replace(f"{{{{{key}}}}}", value)
            return query.strip()
    return ""


def render_sub_query(
    playbook: dict, stage: int, sub_query: int, params: dict[str, str],
) -> str:
    """Render a specific sub-query within a stage.

    Parameters
    ----------
    sub_query : int
        0-based sub-query index within the stage.
    """
    stages = playbook.get("stages", [])
    for s in stages:
        if s.get("stage") == stage:
            subs = s.get("sub_queries", [])
            if 0 <= sub_query < len(subs):
                query = subs[sub_query]["query"]
                for key, value in params.items():
                    query = query.replace(f"{{{{{key}}}}}", value)
                return query.strip()
    return ""


# ---------------------------------------------------------------------------
# Sub-query parsing
# ---------------------------------------------------------------------------

_SUB_QUERY_RE = re.compile(
    r'^//\s*---\s+(Sub-query\s+\w+:.+?|UNAVAILABLE:.+?)\s*---\s*$',
    re.MULTILINE,
)


def _parse_sub_queries(query_text: str) -> list[dict]:
    """Split a stage's query text into sub-queries.

    Sub-queries are delimited by ``// --- Sub-query X: Title ---`` markers.
    ``// --- UNAVAILABLE: Title ---`` markers produce entries with
    ``available=False``.

    If no markers are found, the entire text is returned as a single
    sub-query.
    """
    matches = list(_SUB_QUERY_RE.finditer(query_text))
    if not matches:
        stripped = query_text.strip()
        if stripped:
            return [{"title": "", "available": True, "query": stripped}]
        return []

    subs: list[dict] = []
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        available = not title.upper().startswith("UNAVAILABLE")

        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(query_text)
        block = query_text[start:end].strip()

        subs.append({
            "title": title,
            "available": available,
            "query": block,
        })

    return subs
