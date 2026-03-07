"""JWT authentication and user management for the socai REST API."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from config.settings import BASE_DIR

USERS_FILE = BASE_DIR / "config" / "users.json"
JWT_SECRET = os.getenv("SOCAI_JWT_SECRET", "change-me-in-production-set-SOCAI_JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_TTL_HOURS = int(os.getenv("SOCAI_JWT_TTL_HOURS", "8"))

_bearer_scheme = HTTPBearer()

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


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer_scheme)],
) -> dict:
    """Validate the JWT and return the decoded payload."""
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return payload


def require_permission(permission: str):
    """Factory that returns a dependency checking for a specific permission."""

    async def _check(user: Annotated[dict, Depends(get_current_user)]) -> dict:
        perms = user.get("permissions", [])
        if "admin" not in perms and permission not in perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}",
            )
        return user

    return _check
