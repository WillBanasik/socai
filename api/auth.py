"""JWT authentication and user management for socai.

Used by the MCP server (token verification) and user management.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
from jose import jwt

from config.settings import BASE_DIR

USERS_FILE = BASE_DIR / "config" / "users.json"
JWT_SECRET = os.getenv("SOCAI_JWT_SECRET", "change-me-in-production-set-SOCAI_JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_TTL_HOURS = int(os.getenv("SOCAI_JWT_TTL_HOURS", "8"))


# ---------------------------------------------------------------------------
# User store helpers
# ---------------------------------------------------------------------------

def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    with open(USERS_FILE) as f:
        return json.load(f).get("users", {})


def save_users(users: dict) -> None:
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump({"users": users}, f, indent=2)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(email: str, role: str, permissions: list[str]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_TTL_HOURS)
    payload = {
        "sub": email,
        "role": role,
        "permissions": permissions,
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_token_for_role(email: str, role: str) -> str:
    """Create a JWT with permissions resolved from config/roles.json.

    Usage::

        python3 -c "from api.auth import create_token_for_role; print(create_token_for_role('alice@example.com', 'junior_mdr'))"
    """
    perms = resolve_role_permissions(role)
    if not perms:
        raise ValueError(
            f"Unknown role {role!r}. "
            f"Valid roles: {', '.join(load_roles().keys())}"
        )
    return create_access_token(email, role, perms)


def _resolve_permissions(user_data: dict) -> list[str]:
    """Expand the 'admin' shorthand into all concrete permissions."""
    perms = user_data.get("permissions", [])
    if "admin" in perms:
        return [
            "admin",
            "investigations:submit",
            "investigations:read",
            "campaigns:read",
            "ioc_index:read",
            "sentinel:query",
        ]
    return perms


# ---------------------------------------------------------------------------
# Role resolution
# ---------------------------------------------------------------------------

def load_roles() -> dict:
    """Load role definitions from config/roles.json."""
    from config.settings import ROLES_FILE
    if not ROLES_FILE.exists():
        return {}
    with open(ROLES_FILE) as f:
        return json.load(f).get("roles", {})


def get_role(role_name: str) -> dict | None:
    """Return a single role definition, or None if not found."""
    return load_roles().get(role_name)


def resolve_role_permissions(role_name: str) -> list[str]:
    """Resolve a role name to its permission list.

    Falls back to empty list if the role doesn't exist.
    """
    role = get_role(role_name)
    if not role:
        return []
    return role.get("permissions", [])


def get_role_instructions(role_name: str) -> str:
    """Return the analyst-facing instructions for a role.

    These get injected into the MCP server system prompt so that the
    assistant adapts its tone, depth, and behaviour to the analyst's
    experience level.
    """
    role = get_role(role_name)
    if not role:
        return ""
    return role.get("instructions", "")


def get_role_guidance(role_name: str) -> dict:
    """Return the analyst_guidance flags for a role.

    Used by prompts and tools to decide whether to include educational
    context, suggest next steps, auto-escalate, etc.
    """
    role = get_role(role_name)
    if not role:
        return {}
    return role.get("analyst_guidance", {})
