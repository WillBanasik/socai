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
        "exp": expire,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


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
