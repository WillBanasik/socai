"""Platform registry — load and validate SIEM platform adapters.

A platform adapter (``config/platforms/<id>.yaml``) describes one SIEM:
query language, exposed capabilities, where its query bodies live, and how
to execute rendered queries. The unified playbook loader consults this
registry to choose the right query file and dispatch execution.

Adding a new platform is a config-only operation: drop a YAML at
``config/platforms/<id>.yaml`` (referencing a schema fetched into
``config/schemas/<id>.json``) and the registry picks it up.

Public API
----------
list_platforms()              → [{"id": ..., "name": ...}, ...]
get_platform(platform_id)     → Platform | None
validate_capabilities(platform_id, required) → (ok: bool, missing: list[str])
"""
from __future__ import annotations

import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR
from tools.common import log_error

PLATFORMS_DIR = BASE_DIR / "config" / "platforms"


@dataclass
class Platform:
    """In-memory representation of a platform adapter YAML."""

    id: str
    name: str
    description: str
    query_language: str
    schema_ref: str
    capabilities: list[str]
    parameter_pattern: str
    list_format: str
    query_dir: str
    query_file_ext: str
    executor_mode: str
    executor_module: str
    executor_function: str
    client_config_map: dict[str, str]
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def render_only(self) -> bool:
        return self.executor_mode == "render_only"


_cache_lock = threading.Lock()
_cache: dict[str, Platform] | None = None


def _parse_platform(path: Path) -> Platform | None:
    """Parse a single platform YAML into a Platform object."""
    try:
        data = yaml.safe_load(path.read_text())
    except Exception as exc:
        log_error("", "platforms.parse", f"Failed to parse {path.name}: {exc}",
                  severity="error", context={"path": str(path)})
        return None

    if not isinstance(data, dict):
        log_error("", "platforms.parse", f"{path.name} did not parse as a mapping",
                  severity="error")
        return None

    required = {"id", "query_language", "capabilities"}
    missing = required - set(data.keys())
    if missing:
        log_error("", "platforms.parse",
                  f"{path.name} missing required keys: {sorted(missing)}",
                  severity="error")
        return None

    template = data.get("template_syntax") or {}
    executor = data.get("executor") or {}

    return Platform(
        id=data["id"],
        name=data.get("name", data["id"]),
        description=data.get("description", ""),
        query_language=data["query_language"],
        schema_ref=data.get("schema_ref", data["id"]),
        capabilities=list(data.get("capabilities") or []),
        parameter_pattern=template.get("parameter_pattern", "{{name}}"),
        list_format=template.get("list_format", "comma_quoted"),
        query_dir=data.get("query_dir", data["id"]),
        query_file_ext=data.get("query_file_ext", data["query_language"]),
        executor_mode=executor.get("mode", "render_only"),
        executor_module=executor.get("module", ""),
        executor_function=executor.get("function", ""),
        client_config_map=dict(executor.get("client_config_map") or {}),
        raw=data,
    )


def _load_all() -> dict[str, Platform]:
    """Read every YAML under config/platforms/."""
    platforms: dict[str, Platform] = {}
    if not PLATFORMS_DIR.exists():
        return platforms
    for path in sorted(PLATFORMS_DIR.glob("*.yaml")):
        p = _parse_platform(path)
        if p:
            platforms[p.id] = p
    return platforms


def _ensure_cache() -> dict[str, Platform]:
    global _cache
    with _cache_lock:
        if _cache is None:
            _cache = _load_all()
        return _cache


def reload() -> None:
    """Force a reload from disk on next access. Useful after dropping in a new YAML."""
    global _cache
    with _cache_lock:
        _cache = None


def list_platforms() -> list[dict[str, Any]]:
    """Return a summary list of every registered platform."""
    return [
        {
            "id": p.id,
            "name": p.name,
            "query_language": p.query_language,
            "capabilities": p.capabilities,
            "render_only": p.render_only,
        }
        for p in _ensure_cache().values()
    ]


def get_platform(platform_id: str) -> Platform | None:
    """Return the Platform with the given id, or None if not registered."""
    return _ensure_cache().get(platform_id)


def validate_capabilities(
    platform_id: str,
    required: list[str],
) -> tuple[bool, list[str]]:
    """Return (ok, missing) — ok is True iff every required capability is declared
    by the named platform. ``missing`` lists the capabilities the platform doesn't
    declare. If the platform itself is unknown, returns (False, ["<unknown platform>"]).
    """
    p = get_platform(platform_id)
    if p is None:
        return False, [f"<unknown platform: {platform_id}>"]
    have = set(p.capabilities)
    missing = [c for c in required if c not in have]
    return (not missing), missing
