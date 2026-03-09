"""Authentication bridge — validates socai JWTs for MCP transport-level auth.

The ``SocaiTokenVerifier`` implements the MCP SDK ``TokenVerifier`` protocol so
that the FastMCP SSE transport enforces Bearer-token auth on every connection.

Per-tool RBAC is handled by ``_require_scope()`` which reads the access token
from the MCP context var set by ``AuthContextMiddleware``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from jose import JWTError, jwt

from api.auth import JWT_ALGORITHM, JWT_SECRET
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken

if TYPE_CHECKING:
    pass


class SocaiTokenVerifier:
    """Verify socai self-issued JWTs (same secret as the web UI).

    Implements the ``TokenVerifier`` protocol expected by ``FastMCP``.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        """Decode and validate a socai JWT.

        Returns an ``AccessToken`` with *permissions* mapped to *scopes*,
        or ``None`` if the token is invalid / expired.
        """
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except JWTError:
            return None

        email = payload.get("sub")
        if not email:
            return None

        # Permissions come from the JWT claim itself; we don't re-query the
        # user store on every request (the token is the source of truth for
        # the duration of its validity, same as the web UI).
        scopes = payload.get("permissions", [])

        exp = payload.get("exp")
        expires_at = int(exp) if exp is not None else None

        return AccessToken(
            token=token,
            client_id=email,
            scopes=scopes,
            expires_at=expires_at,
        )


# ---------------------------------------------------------------------------
# Per-tool permission helpers
# ---------------------------------------------------------------------------

def _require_scope(scope: str) -> None:
    """Raise ``PermissionError`` if the current caller lacks *scope*.

    Call at the top of any MCP tool handler that requires fine-grained RBAC.
    ``admin`` always satisfies any scope check.

    In stdio transport mode (local trust) there is no access token — all
    scopes are implicitly granted.
    """
    from mcp_server.config import MCP_TRANSPORT

    # stdio = local trust model, no auth
    if MCP_TRANSPORT == "stdio":
        return

    access_token = get_access_token()
    if access_token is None:
        raise PermissionError("Authentication required")
    if "admin" in access_token.scopes:
        return
    if scope not in access_token.scopes:
        raise PermissionError(f"Missing permission: {scope}")


def _get_caller_email() -> str:
    """Return the email (``client_id``) of the current authenticated caller."""
    from mcp_server.config import MCP_TRANSPORT

    if MCP_TRANSPORT == "stdio":
        return "local"

    access_token = get_access_token()
    if access_token is None:
        return "anonymous"
    return access_token.client_id


def _get_caller_scopes() -> list[str]:
    """Return the permission scopes of the current authenticated caller."""
    from mcp_server.config import MCP_TRANSPORT

    if MCP_TRANSPORT == "stdio":
        return ["admin"]

    access_token = get_access_token()
    if access_token is None:
        return []
    return list(access_token.scopes)
