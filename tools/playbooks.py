"""Unified playbook loader — vendor-agnostic structure + per-platform queries.

A playbook is described once in ``config/playbooks/<id>.yaml`` (stage names,
descriptions, run conditions, parameters, required_capabilities, definitions).
Per-platform query bodies live at:

    config/playbooks/<id>/<platform.query_dir>/<stage_query_file>.<platform.query_file_ext>

Adding a new SIEM = drop a platform adapter (config/platforms/<new>.yaml),
optionally drop schema references (config/schemas/<new>.json — usually fetched
from the external schema project), then drop per-stage query bodies under
config/playbooks/<id>/<new>/. No SOCAI code changes.

Legacy fallback
---------------
Un-migrated playbooks (still living as monolithic ``config/kql_playbooks/<id>.kql``
or ``config/cql_playbooks/<id>.cql``) continue to load via the existing
``tools.kql_playbooks`` / ``tools.cql_playbooks`` modules. The unified loader
delegates to them when a new-format YAML is not present.

Public API
----------
list_playbooks_unified()                          → [{"id": …, "name": …, "format": …}]
load_playbook_for_platform(id, platform_id)       → playbook dict (with capability gate)
render_stage_for_platform(id, stage, params, platform_id) → rendered query string
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR
from tools.common import log_error
from tools.platforms import get_platform, validate_capabilities

PLAYBOOKS_DIR = BASE_DIR / "config" / "playbooks"


# ---------------------------------------------------------------------------
# New-format (YAML + per-platform query files)
# ---------------------------------------------------------------------------

def _new_format_exists(playbook_id: str) -> bool:
    return (PLAYBOOKS_DIR / f"{playbook_id}.yaml").exists()


def _load_new_format(playbook_id: str) -> dict | None:
    yaml_path = PLAYBOOKS_DIR / f"{playbook_id}.yaml"
    if not yaml_path.exists():
        return None
    try:
        data = yaml.safe_load(yaml_path.read_text())
    except Exception as exc:
        log_error("", "playbooks.load_new",
                  f"Failed to parse {yaml_path.name}: {exc}",
                  severity="error", context={"path": str(yaml_path)})
        return None
    if not isinstance(data, dict):
        return None
    data["_format"] = "v2"
    data["_source"] = str(yaml_path)
    return data


def _resolve_required_capabilities(spec: Any, platform_id: str) -> list[str] | None:
    """Required capabilities can be declared three ways:

    1. Omitted (or None) → empty list (no gate, runs everywhere).
    2. A flat list of strings → applies uniformly to every platform.
    3. A dict keyed by platform id, optionally with a ``default`` key for the
       fallback. e.g.:
           required_capabilities:
             default: [identity_logon, sign_in_events]
             sentinel: [office_activity, windows_security_events]
             logscale: [windows_security_events]

       For each platform the loader returns ``default + <platform>`` (union).
       If neither the platform key nor ``default`` is present, returns None —
       a sentinel meaning "this playbook is not designed for this platform"
       (semantically distinct from "no requirements"). The caller treats that
       as an unsupported-platform refusal.
    """
    if spec is None:
        return []
    if isinstance(spec, list):
        return list(spec)
    if isinstance(spec, dict):
        if platform_id not in spec and "default" not in spec:
            return None  # explicitly unsupported on this platform
        out = list(spec.get("default", []) or [])
        out.extend(spec.get(platform_id, []) or [])
        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped = []
        for c in out:
            if c not in seen:
                seen.add(c)
                deduped.append(c)
        return deduped
    return []


def _resolve_query_filename(stage: dict, platform_id: str) -> str | None:
    """Determine the filename stem (without extension) for *stage* on *platform_id*.

    ``query_file`` may be:
      * a string — same filename across every platform
      * a dict keyed by platform id — per-platform override
      * absent — falls back to ``str(stage_id)``
    """
    qf = stage.get("query_file")
    if isinstance(qf, str) and qf:
        return qf
    if isinstance(qf, dict):
        val = qf.get(platform_id)
        if val:
            return val
    sid = stage.get("id") if stage.get("id") is not None else stage.get("stage")
    return str(sid) if sid is not None else None


def _resolve_query_body(playbook_id: str, stage: dict, platform) -> str | None:
    """Read the query body for *stage* on *platform*. Returns None if missing."""
    stem = _resolve_query_filename(stage, platform.id)
    if not stem:
        return None
    query_path = (
        PLAYBOOKS_DIR
        / playbook_id
        / platform.query_dir
        / f"{stem}.{platform.query_file_ext}"
    )
    # Glob fallback — match <stem>* so a descriptive filename like "3_endpoint_logon_context.cql"
    # is picked up when the YAML only declared "3" or no explicit query_file at all.
    if not query_path.exists():
        platform_dir = PLAYBOOKS_DIR / playbook_id / platform.query_dir
        if platform_dir.exists():
            stem_prefix = f"{stem}"
            for candidate in sorted(platform_dir.glob(f"{stem_prefix}*.{platform.query_file_ext}")):
                # Accept either exact "<stem>.<ext>" or "<stem>_*.<ext>"
                stem_part = candidate.stem
                if stem_part == stem or stem_part.startswith(f"{stem}_"):
                    query_path = candidate
                    break
        if not query_path.exists():
            return None
    try:
        return query_path.read_text()
    except OSError as exc:
        log_error("", "playbooks.read_query", str(exc),
                  severity="warning", context={"path": str(query_path)})
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_playbooks_unified() -> list[dict[str, Any]]:
    """Return a combined list of every playbook the system knows about,
    flagging whether it's new format (per-platform queries) or legacy.
    """
    seen: dict[str, dict[str, Any]] = {}

    # New format
    if PLAYBOOKS_DIR.exists():
        for yp in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
            data = _load_new_format(yp.stem)
            if not data:
                continue
            seen[data["id"]] = {
                "id": data["id"],
                "name": data.get("name", data["id"]),
                "format": "v2",
                "required_capabilities": data.get("required_capabilities", []),
            }

    # Legacy KQL
    from tools.kql_playbooks import list_playbooks as _kql_list
    for entry in _kql_list():
        pid = entry["id"]
        if pid in seen:
            continue
        seen[pid] = {
            "id": pid,
            "name": entry["name"],
            "format": "legacy-kql",
            "required_capabilities": [],
        }

    # Legacy CQL
    from tools.cql_playbooks import list_playbooks as _cql_list
    for entry in _cql_list():
        pid = entry["id"]
        if pid in seen:
            continue
        seen[pid] = {
            "id": pid,
            "name": entry["name"],
            "format": "legacy-cql",
            "required_capabilities": [],
        }

    return sorted(seen.values(), key=lambda r: r["id"])


def load_playbook_for_platform(
    playbook_id: str,
    platform_id: str,
) -> dict[str, Any]:
    """Resolve a playbook for a specific target platform.

    Returns a normalised dict with ``id``, ``name``, ``description``,
    ``parameters``, ``stages`` (each with ``query`` body inlined), ``definitions``,
    ``required_capabilities``, ``platform`` (the Platform object as a dict),
    and ``_format`` tag.

    Returns ``{"error": "...", "code": "..."}`` on failure. Capability mismatches
    return code ``capability_gate``; missing playbook returns ``not_found``.
    """
    platform = get_platform(platform_id)
    if platform is None:
        return {
            "error": f"Unknown platform: {platform_id!r}. "
                     f"Define config/platforms/{platform_id}.yaml.",
            "code": "unknown_platform",
        }

    # --- New format ----------------------------------------------------------
    new_data = _load_new_format(playbook_id)
    if new_data:
        required = _resolve_required_capabilities(
            new_data.get("required_capabilities"),
            platform_id,
        )
        if required is None:
            return {
                "error": (
                    f"Playbook {playbook_id!r} is not designed for platform "
                    f"{platform_id!r} — no required_capabilities declared and "
                    f"no per-platform queries found. Add a "
                    f"`required_capabilities.{platform_id}` block and drop "
                    f"query files at config/playbooks/{playbook_id}/{platform_id}/."
                ),
                "code": "platform_not_supported",
                "playbook_id": playbook_id,
                "platform_id": platform_id,
            }
        ok, missing = validate_capabilities(platform_id, required)
        if not ok:
            return {
                "error": (
                    f"Playbook {playbook_id!r} requires capabilities "
                    f"{missing} that platform {platform_id!r} does not declare. "
                    f"Either use a platform that supports these data sources, "
                    f"or extend the platform adapter's capabilities list once "
                    f"the data is forwarded to it."
                ),
                "code": "capability_gate",
                "playbook_id": playbook_id,
                "platform_id": platform_id,
                "missing_capabilities": missing,
                "required_capabilities": required,
            }

        # Inline query bodies per stage. A stage with no query file for the
        # selected platform is returned with ``query: ""`` and a ``_no_query``
        # flag — useful for stages that only apply to certain platforms.
        stages_out = []
        for stage in new_data.get("stages", []):
            body = _resolve_query_body(playbook_id, stage, platform)
            stages_out.append({
                "stage": stage.get("id"),
                "name": stage.get("name", ""),
                "description": stage.get("description", ""),
                "run": stage.get("run", ""),
                "query": body or "",
                "_no_query": body is None,
            })

        return {
            "id": new_data["id"],
            "name": new_data.get("name", new_data["id"]),
            "description": new_data.get("description", ""),
            "parameters": new_data.get("parameters", []),
            "stages": stages_out,
            "definitions": new_data.get("definitions", []),
            "required_capabilities": required,
            "platform": {
                "id": platform.id,
                "name": platform.name,
                "query_language": platform.query_language,
                "render_only": platform.render_only,
            },
            "_format": "v2",
        }

    # --- Legacy fallback ----------------------------------------------------
    if platform.query_language == "kql":
        from tools.kql_playbooks import load_playbook as _kql_load
        legacy = _kql_load(playbook_id)
        if legacy:
            legacy["_format"] = "legacy-kql"
            legacy["platform"] = {
                "id": platform.id,
                "name": platform.name,
                "query_language": platform.query_language,
                "render_only": platform.render_only,
            }
            return legacy
    if platform.query_language == "cql":
        from tools.cql_playbooks import load_playbook as _cql_load
        legacy = _cql_load(playbook_id)
        if legacy:
            legacy["_format"] = "legacy-cql"
            legacy["platform"] = {
                "id": platform.id,
                "name": platform.name,
                "query_language": platform.query_language,
                "render_only": platform.render_only,
            }
            return legacy

    return {
        "error": (
            f"Playbook {playbook_id!r} not found for platform {platform_id!r}. "
            f"Check config/playbooks/, config/kql_playbooks/, or config/cql_playbooks/."
        ),
        "code": "not_found",
        "playbook_id": playbook_id,
        "platform_id": platform_id,
    }


# Host-scoping convention. A stage may carry an OPTIONAL host filter keyed on
# ``{{device_name}}``; its shared default is the ``__NONE__`` sweep-all sentinel
# (see the ``device_name`` parameter in config/playbooks/*.yaml). KQL stages
# guard this inline — ``let device = "{{device_name}}"; … | where device ==
# "__NONE__" or DeviceName has device`` — so the literal ``__NONE__`` is
# harmless there. CQL/LogScale stages instead apply a bare
# ``| ComputerName = /{{device_name}}/i`` regex with no guard, and
# ``/__NONE__/i`` (or the unsubstituted token when the param is omitted) is an
# unanchored match that hits ZERO real hosts — so an all-host sweep silently
# returns an empty result that reads as "nothing found" rather than "no host
# queried". For CQL we therefore DROP the optional host-filter line in the
# sweep-all case rather than emit a match-nothing regex.
_HOST_SCOPE_PARAM = "device_name"
_SWEEP_ALL_SENTINEL = "__NONE__"


def _strip_sweep_all_host_filter(query: str) -> str:
    """Drop CQL pipeline-filter lines scoped on ``{{device_name}}``.

    Called only for CQL stages when ``device_name`` is the ``__NONE__``
    sweep-all sentinel or was not supplied. Only lines that BOTH start a
    pipeline stage (``|``) AND reference the ``{{device_name}}`` token are
    removed; every other line is preserved verbatim (KQL ``let device = …``
    assignments never start with ``|``, so the KQL path is unaffected — though
    this helper is only invoked for CQL anyway).
    """
    token = f"{{{{{_HOST_SCOPE_PARAM}}}}}"
    kept = [
        line for line in query.splitlines()
        if not (line.lstrip().startswith("|") and token in line)
    ]
    return "\n".join(kept)


def render_stage_for_platform(
    playbook_id: str,
    stage_id: int | str,
    params: dict[str, str],
    platform_id: str,
) -> str | dict:
    """Render a specific stage's query for the given platform.

    Returns the rendered query string on success, or an error dict on failure
    (capability gate, unknown stage, missing query body).
    """
    pb = load_playbook_for_platform(playbook_id, platform_id)
    if "error" in pb:
        return pb

    # Reuse the existing KQL param renderer — same escape rules work for CQL.
    # List values expand to '"a", "b"' (for dynamic([...]) / values=[...]);
    # declared YAML defaults fill any params the caller omitted.
    from tools.kql_playbooks import _merge_declared_defaults, _render_param_value
    merged = _merge_declared_defaults(pb.get("params"), params)
    safe = {k: _render_param_value(v) for k, v in merged.items()}

    query_language = (pb.get("platform") or {}).get("query_language", "")
    sweep_all_hosts = (
        params.get(_HOST_SCOPE_PARAM) in (None, _SWEEP_ALL_SENTINEL)
    )

    for stage in pb.get("stages", []):
        if str(stage.get("stage")) != str(stage_id):
            continue
        if stage.get("_no_query"):
            return {
                "error": (
                    f"Playbook {playbook_id!r} stage {stage_id} has no query "
                    f"defined for platform {platform_id!r}. Drop a file at "
                    f"config/playbooks/{playbook_id}/<platform.query_dir>/<stage>.<ext> "
                    f"to add support."
                ),
                "code": "stage_not_implemented_for_platform",
            }
        query = stage.get("query", "")
        if query_language == "cql" and sweep_all_hosts:
            query = _strip_sweep_all_host_filter(query)
        for key, value in safe.items():
            query = query.replace(f"{{{{{key}}}}}", value)
        return query.strip()

    return {
        "error": f"Stage {stage_id!r} not found in playbook {playbook_id!r}.",
        "code": "stage_not_found",
    }
