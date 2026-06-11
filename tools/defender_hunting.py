"""
tool: defender_hunting
----------------------
Query a client's Microsoft Defender XDR Advanced Hunting endpoint.

Auth model: multi-tenant Performanta app registration with application
permission ``AdvancedHunting.Read.All`` on the Microsoft Threat Protection
resource, admin-consented in each client tenant.  Token is fetched per-tenant
via OAuth2 client_credentials flow and cached in-process.

Configuration:
  - App reg credentials come from env (SOCAI_DEFENDER_APP_CLIENT_ID +
    SOCAI_DEFENDER_APP_CLIENT_SECRET) via tools.secrets.get_secret.
  - Per-client tenant_id lives in config/client_entities.json under
    ``platforms.defender_xdr.tenant_id`` with ``api_enabled: true``.

Public API:
    run_defender_kql(client, query, timeout=30) -> dict
    is_defender_configured(client) -> bool
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.common import get_client_config, get_session, log_error
from tools.secrets import get_secret

DEFENDER_API_BASE = "https://api.security.microsoft.com"
DEFENDER_HUNTING_ENDPOINT = f"{DEFENDER_API_BASE}/api/advancedhunting/run"
DEFENDER_SCOPE = f"{DEFENDER_API_BASE}/.default"

_TOKEN_SAFETY_S = 120  # refresh this many seconds before stated expiry

_token_cache: dict[str, tuple[str, float]] = {}
_token_lock = threading.Lock()


class DefenderHuntingError(RuntimeError):
    """Transport, auth, or query-execution failure."""


class DefenderNotConfigured(DefenderHuntingError):
    """Client has no Defender XDR API enabled in client_entities.json."""


def _app_credentials() -> tuple[str, str]:
    client_id = get_secret("SOCAI_DEFENDER_APP_CLIENT_ID", required=True)
    client_secret = get_secret("SOCAI_DEFENDER_APP_CLIENT_SECRET", required=True)
    return client_id, client_secret  # type: ignore[return-value]


def _acquire_token(tenant_id: str) -> str:
    """Return a cached or freshly-minted app-only token for `tenant_id`.

    The lock is held across the OAuth refresh (not just the read/write) so
    concurrent cold-cache callers for this tenant coalesce onto one token
    request instead of each firing a redundant client_credentials grant.
    """
    with _token_lock:
        now = time.time()
        cached = _token_cache.get(tenant_id)
        if cached and cached[1] - _TOKEN_SAFETY_S > now:
            return cached[0]

        client_id, client_secret = _app_credentials()
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        body = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": DEFENDER_SCOPE,
        }
        try:
            resp = get_session().post(token_url, data=body, timeout=15)
        except requests.RequestException as exc:
            raise DefenderHuntingError(f"token request failed: {exc}") from exc

        if resp.status_code != 200:
            raise DefenderHuntingError(
                f"token request returned {resp.status_code}: {resp.text[:300]}"
            )

        try:
            payload = resp.json()
            token = payload["access_token"]
        except (ValueError, KeyError) as exc:
            # 200 with a non-JSON body (proxy interstitial) or a JSON body
            # missing access_token — surface as a DefenderHuntingError, not
            # an unhandled JSONDecodeError/KeyError traceback.
            raise DefenderHuntingError(
                f"token response was not valid JSON with access_token: "
                f"{resp.text[:300]}"
            ) from exc
        expires_in = int(payload.get("expires_in", 3600))
        _token_cache[tenant_id] = (token, now + expires_in)
        return token


def _resolve_tenant(client: str) -> str:
    cfg = get_client_config(client)
    if cfg is None:
        raise DefenderNotConfigured(f"unknown client {client!r}")
    dx = (cfg.get("platforms") or {}).get("defender_xdr") or {}
    if not dx.get("api_enabled"):
        raise DefenderNotConfigured(
            f"client {client!r} Defender XDR API not enabled — "
            f"set platforms.defender_xdr.api_enabled=true and tenant_id"
        )
    tenant_id = dx.get("tenant_id") or ""
    if not tenant_id:
        raise DefenderNotConfigured(
            f"client {client!r} Defender XDR enabled but tenant_id missing"
        )
    return tenant_id


def is_defender_configured(client: str) -> bool:
    """Return True iff `client` can be queried today (config + creds present)."""
    try:
        _resolve_tenant(client)
    except DefenderNotConfigured:
        return False
    try:
        _app_credentials()
    except Exception:
        return False
    return True


def run_defender_kql(client: str, query: str, timeout: int = 30) -> dict[str, Any]:
    """Execute a KQL query against `client`'s Defender XDR Advanced Hunting endpoint.

    Returns:
        {
          "rows":   [{col: val, ...}, ...],
          "schema": [{"Name": str, "Type": str}, ...],
          "stats":  {"row_count": int, "elapsed_ms": int},
        }

    Raises:
        DefenderNotConfigured: client missing config.
        DefenderHuntingError:  any transport/auth/query failure.
    """
    if not query or not query.strip():
        raise DefenderHuntingError("query is empty")

    tenant_id = _resolve_tenant(client)
    token = _acquire_token(tenant_id)
    started = time.time()

    try:
        resp = get_session().post(
            DEFENDER_HUNTING_ENDPOINT,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"Query": query},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        log_error("", "defender_hunting.run", str(exc),
                  severity="error", context={"client": client})
        raise DefenderHuntingError(f"request failed: {exc}") from exc

    elapsed_ms = int((time.time() - started) * 1000)

    if resp.status_code == 401:
        # Clear cached token — consent may have been revoked or secret rotated.
        with _token_lock:
            _token_cache.pop(tenant_id, None)
        raise DefenderHuntingError(
            f"401 Unauthorised — token / consent issue: {resp.text[:200]}"
        )

    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After", "")
        raise DefenderHuntingError(
            f"429 rate-limited (Retry-After={retry_after}): {resp.text[:200]}"
        )

    if resp.status_code != 200:
        log_error("", "defender_hunting.run",
                  f"HTTP {resp.status_code}: {resp.text[:300]}",
                  severity="error",
                  context={"client": client, "query_head": query[:200]})
        raise DefenderHuntingError(
            f"HTTP {resp.status_code}: {resp.text[:300]}"
        )

    try:
        payload = resp.json()
    except ValueError as exc:
        # 200 with a non-JSON body (gateway/proxy HTML error page).
        raise DefenderHuntingError(
            f"hunting response was not valid JSON: {resp.text[:300]}"
        ) from exc
    rows = payload.get("Results") or []
    schema = payload.get("Schema") or []
    return {
        "rows": rows,
        "schema": schema,
        "stats": {"row_count": len(rows), "elapsed_ms": elapsed_ms},
    }
