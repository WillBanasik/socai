"""
tool: kql_playbooks
--------------------
Loads parameterised KQL investigation playbooks from config/kql_playbooks/.

Each .kql file contains a YAML-like frontmatter block (in // comments) with
metadata, parameters, and stage descriptions, followed by the actual KQL
queries separated by stage headers.

Usage:
    from tools.kql_playbooks import list_playbooks, load_playbook, render_stage

    playbooks = list_playbooks()
    pb = load_playbook("phishing")
    query = render_stage(pb, stage=1, params={"target_ids": '"id-1","id-2"'})
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR
from tools.common import log_error

KQL_PLAYBOOKS_DIR = BASE_DIR / "config" / "kql_playbooks"


def list_playbooks() -> list[dict]:
    """Return a summary of all available KQL playbooks."""
    if not KQL_PLAYBOOKS_DIR.exists():
        return []
    result = []
    for path in sorted(KQL_PLAYBOOKS_DIR.glob("*.kql")):
        meta = _parse_frontmatter(path.read_text(encoding="utf-8"))
        result.append({
            "id": path.stem,
            "name": meta.get("name", path.stem),
            "description": meta.get("description", ""),
            "parameters": meta.get("parameters", []),
            "stages": meta.get("stages", []),
            "definitions": meta.get("definitions", []),
        })
    return result


def load_playbook(playbook_id: str) -> dict | None:
    """Load a playbook by ID (filename without extension). Returns full parsed structure."""
    path = KQL_PLAYBOOKS_DIR / f"{playbook_id}.kql"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    meta = _parse_frontmatter(text)
    stages = _parse_stages(text)
    return {
        "id": playbook_id,
        "name": meta.get("name", playbook_id),
        "description": meta.get("description", ""),
        "parameters": meta.get("parameters", []),
        "stages": stages,
        "tables": meta.get("tables", []),
        "definitions": meta.get("definitions", []),
    }


def validate_playbook_tables(playbook: dict, workspace: str = "") -> dict:
    """Validate playbook's declared tables against schema registry."""
    try:
        from config.sentinel_schema import validate_tables
        return validate_tables(playbook.get("tables", []), workspace=workspace)
    except Exception as exc:
        log_error("", "kql_playbooks.validate_tables", str(exc),
                  severity="warning", traceback=True,
                  context={"playbook": playbook.get("id", ""), "workspace": workspace})
        return {"valid": True, "warnings": [], "missing_tables": [], "unknown_tables": []}


def _sanitise_kql_value(value: str) -> str:
    """Escape a parameter value for safe inline KQL substitution.

    Rejects newlines/control characters (would let a caller inject extra
    pipeline operators). Escapes backslashes and double-quotes so values
    cannot break out of a ``"..."`` literal.
    """
    if value is None:
        return ""
    value = str(value)
    if any(ord(c) < 0x20 for c in value):
        raise ValueError(
            f"KQL parameter value contains a control character — rejected: {value!r}"
        )
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_stage(playbook: dict, stage: int, params: dict[str, str]) -> str:
    """Render a specific stage's KQL with parameter substitution.

    Parameters are replaced using {{param_name}} syntax. Values are escaped
    via ``_sanitise_kql_value`` to prevent query-structure injection.
    """
    safe = {k: _sanitise_kql_value(v) for k, v in params.items()}
    stages = playbook.get("stages", [])
    for s in stages:
        if s.get("stage") == stage:
            query = s["query"]
            for key, value in safe.items():
                query = query.replace(f"{{{{{key}}}}}", value)
            return query.strip()
    return ""


# ---------------------------------------------------------------------------
# Internal parsing
# ---------------------------------------------------------------------------

def _parse_frontmatter(text: str) -> dict:
    """Parse the YAML-like frontmatter from // comment block between --- markers.

    Supports: top-level scalars, multi-line strings (>), lists of dicts,
    and simple lists of strings.
    """
    # Extract frontmatter lines
    lines = text.split("\n")
    in_fm = False
    fm_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped == "// ---":
            if in_fm:
                break
            in_fm = True
            continue
        if in_fm and stripped.startswith("//"):
            # Remove the // prefix, preserving indentation after it
            after_slashes = line[line.index("//") + 2:]
            # Remove exactly one leading space if present
            if after_slashes.startswith(" "):
                after_slashes = after_slashes[1:]
            fm_lines.append(after_slashes)

    if not fm_lines:
        return {}

    # Measure indent level
    def _indent(s: str) -> int:
        return len(s) - len(s.lstrip())

    meta: dict = {}
    i = 0
    while i < len(fm_lines):
        line = fm_lines[i]

        # Skip blank lines
        if not line.strip():
            i += 1
            continue

        # Top-level key (indent 0)
        if _indent(line) == 0:
            m = re.match(r'^(\w+):\s*(.*)', line)
            if not m:
                i += 1
                continue
            key = m.group(1)
            val = m.group(2).strip()

            if val == ">" or val == "|":
                # Multi-line string — collect indented continuation lines
                parts = []
                i += 1
                while i < len(fm_lines) and (_indent(fm_lines[i]) > 0 or fm_lines[i].strip() == ""):
                    parts.append(fm_lines[i].strip())
                    i += 1
                meta[key] = " ".join(p for p in parts if p)
                continue
            elif val == "" or val is None:
                # List or nested block — collect items
                items: list = []
                i += 1
                current_item: dict | None = None
                while i < len(fm_lines) and (_indent(fm_lines[i]) > 0 or fm_lines[i].strip() == ""):
                    cl = fm_lines[i]
                    stripped_cl = cl.strip()

                    if not stripped_cl:
                        i += 1
                        continue

                    # List item start: "  - key: value" or "  - value"
                    list_item_m = re.match(r'^\s+- (\w+):\s*(.*)', cl)
                    simple_item_m = re.match(r'^\s+- (.+)', cl)

                    if list_item_m:
                        # Flush previous item
                        if current_item is not None:
                            items.append(current_item)
                        current_item = {list_item_m.group(1): list_item_m.group(2).strip().strip('"').strip("'")}
                        i += 1
                        continue
                    elif simple_item_m and current_item is None:
                        # Simple string list item
                        items.append(simple_item_m.group(1).strip())
                        i += 1
                        continue

                    # Nested key within current item: "    key: value"
                    nested_m = re.match(r'^\s+(\w+):\s+(.+)', cl)
                    if nested_m and current_item is not None:
                        current_item[nested_m.group(1)] = nested_m.group(2).strip().strip('"').strip("'")
                        i += 1
                        continue

                    # Unrecognised indented line — stop
                    break

                if current_item is not None:
                    items.append(current_item)
                meta[key] = items
                continue
            else:
                meta[key] = val
                i += 1
                continue

        i += 1

    return meta


def _parse_stages(text: str) -> list[dict]:
    """Parse stage blocks from the KQL file.

    Stages are delimited by:
        // ============================================================================
        // STAGE N — Title
        // ============================================================================
    """
    stage_pattern = re.compile(
        r'//\s*={5,}\n'
        r'//\s*STAGE\s+(\d+\w?)\s*[—–-]\s*(.+?)\n'
        r'//\s*={5,}',
        re.MULTILINE
    )

    matches = list(stage_pattern.finditer(text))
    if not matches:
        return []

    stages = []
    for i, match in enumerate(matches):
        stage_num = match.group(1).strip()
        stage_name = match.group(2).strip()

        # Extract query between this header and the next (or end of file)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end].strip()

        # Extract the comment block (parameters, run condition, purpose)
        comment_lines = []
        query_lines = []
        in_query = False
        for line in block.split("\n"):
            stripped = line.strip()
            if not in_query and stripped.startswith("//"):
                comment_lines.append(stripped[2:].strip())
            else:
                in_query = True
                query_lines.append(line)

        # Parse run condition and description from comments
        run_condition = "always"
        description = ""
        for cl in comment_lines:
            if cl.lower().startswith("run:"):
                run_condition = cl[4:].strip()
            elif cl.lower().startswith("purpose:"):
                description = cl[8:].strip()
            elif cl.lower().startswith("parameters:"):
                pass  # Informational only
            elif cl.lower().startswith("returns:"):
                pass  # Informational only

        # Parse stage number (handle "1b" style)
        try:
            stage_int = int(re.match(r'(\d+)', stage_num).group(1))
        except (AttributeError, ValueError):
            stage_int = 0

        stages.append({
            "stage": stage_int,
            "stage_label": stage_num,
            "name": stage_name,
            "description": description,
            "run": run_condition,
            "query": "\n".join(query_lines).strip(),
        })

    return stages
