"""
tool: crowdstrike
-----------------
Query a client's CrowdStrike Falcon platform — both the classic Falcon APIs
(detections, hosts, incidents) and the NG-SIEM / Falcon LogScale event-hunting
endpoint (CQL).

Auth model: each client has their own Falcon API client (created in their
Falcon console). Credentials live in env vars derived from the client code:

    SOCAI_CROWDSTRIKE_<CLIENT_UPPER>_CLIENT_ID
    SOCAI_CROWDSTRIKE_<CLIENT_UPPER>_CLIENT_SECRET

Region + NG-SIEM repo are declared in config/client_entities.json under
``platforms.crowdstrike``. Token is fetched per-client via OAuth2
client_credentials and cached in-process (~30 min TTL).

Public API:
    run_falcon_cql(client, cql, repo=None, timeout=30) -> dict
    query_detections(client, filter_=None, limit=50) -> dict
    query_hosts(client, filter_=None, limit=50) -> dict
    query_incidents(client, filter_=None, limit=50) -> dict
    is_falcon_configured(client) -> bool
"""
from __future__ import annotations

import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.common import get_client_config, get_session, log_error
from tools.secrets import get_secret

# Regional Falcon API hosts.
_FALCON_HOSTS = {
    "us-1":     "api.crowdstrike.com",
    "us-2":     "api.us-2.crowdstrike.com",
    "eu-1":     "api.eu-1.crowdstrike.com",
    "us-gov-1": "api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "api.us-gov-2.crowdstrike.mil",
}

_TOKEN_SAFETY_S = 120  # refresh this many seconds before stated expiry.

_token_cache: dict[str, tuple[str, float]] = {}
_token_lock = threading.Lock()


class FalconError(RuntimeError):
    """Transport, auth, or query-execution failure."""


class FalconNotConfigured(FalconError):
    """Client has no CrowdStrike API enabled / credentials missing."""


# ---------------------------------------------------------------------------
# Config + credentials
# ---------------------------------------------------------------------------

def _env_key(client: str) -> str:
    """Convert client code to a safe ENV-var fragment (uppercase + underscore)."""
    return re.sub(r"[^A-Z0-9_]", "_", client.upper())


def _client_credentials(client: str) -> tuple[str, str]:
    key = _env_key(client)
    cid = get_secret(f"SOCAI_CROWDSTRIKE_{key}_CLIENT_ID", required=True)
    sec = get_secret(f"SOCAI_CROWDSTRIKE_{key}_CLIENT_SECRET", required=True)
    return cid, sec  # type: ignore[return-value]


def _resolve_falcon_config(client: str) -> dict[str, str]:
    cfg = get_client_config(client)
    if cfg is None:
        raise FalconNotConfigured(f"unknown client {client!r}")
    cs = (cfg.get("platforms") or {}).get("crowdstrike") or {}
    if not cs.get("api_enabled"):
        raise FalconNotConfigured(
            f"client {client!r} CrowdStrike API not enabled — "
            f"set platforms.crowdstrike.api_enabled=true and falcon_region"
        )
    region = (cs.get("falcon_region") or "").lower()
    if region not in _FALCON_HOSTS:
        raise FalconNotConfigured(
            f"client {client!r} falcon_region must be one of {sorted(_FALCON_HOSTS)} "
            f"(got {region!r})"
        )
    return {
        "host": _FALCON_HOSTS[region],
        "region": region,
        "ngsiem_repo": cs.get("ngsiem_repo") or "",
    }


def is_falcon_configured(client: str) -> bool:
    """Return True iff `client` can be queried today (config + creds present)."""
    try:
        _resolve_falcon_config(client)
    except FalconNotConfigured:
        return False
    try:
        _client_credentials(client)
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# Token acquisition
# ---------------------------------------------------------------------------

def _acquire_token(client: str) -> tuple[str, str]:
    """Return ``(host, token)`` for `client`, refreshing if necessary."""
    cfg = _resolve_falcon_config(client)
    host = cfg["host"]
    cache_key = f"{client}@{host}"

    # The lock is held across the OAuth refresh (not just the read/write) so
    # concurrent cold-cache callers for this client coalesce onto one token
    # request — Falcon's /oauth2/token rate-limits and can revoke the prior
    # token, so a refresh storm is self-defeating.
    with _token_lock:
        now = time.time()
        cached = _token_cache.get(cache_key)
        if cached and cached[1] - _TOKEN_SAFETY_S > now:
            return host, cached[0]

        cid, sec = _client_credentials(client)
        token_url = f"https://{host}/oauth2/token"
        try:
            resp = get_session().post(
                token_url,
                data={"client_id": cid, "client_secret": sec},
                timeout=15,
            )
        except requests.RequestException as exc:
            raise FalconError(f"token request failed: {exc}") from exc

        if resp.status_code != 200:
            raise FalconError(
                f"token request returned {resp.status_code}: {resp.text[:300]}"
            )
        try:
            payload = resp.json()
            token = payload["access_token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise FalconError(
                f"token response had unexpected body: {resp.text[:300]}"
            ) from exc
        expires_in = int(payload.get("expires_in", 1800))
        _token_cache[cache_key] = (token, now + expires_in)
        return host, token


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _invalidate_token(client: str, host: str) -> None:
    with _token_lock:
        _token_cache.pop(f"{client}@{host}", None)


# ---------------------------------------------------------------------------
# NG-SIEM (Falcon LogScale) — CQL query
# ---------------------------------------------------------------------------

def run_falcon_cql(
    client: str,
    cql: str,
    repo: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Run a CQL query against the client's NG-SIEM / Falcon LogScale repository.

    Synchronous endpoint; for very large result sets use the async pattern
    (``/loggingapi/entities/queries/v1/start`` + status + result) — out of
    scope for v1.

    Parameters
    ----------
    client : str
        Client code (must have ``platforms.crowdstrike.api_enabled=true``).
    cql : str
        CQL query string.
    repo : str | None
        LogScale repository ID. Falls back to ``platforms.crowdstrike.ngsiem_repo``.
    timeout : int
        Per-request HTTP timeout in seconds.

    Returns
    -------
    dict with ``rows`` (list[dict]) and ``stats`` (row_count, elapsed_ms).

    Raises
    ------
    FalconNotConfigured : missing client config / credentials.
    FalconError         : transport / auth / query failure.
    """
    if not cql or not cql.strip():
        raise FalconError("query is empty")

    cfg = _resolve_falcon_config(client)
    repo_id = repo or cfg.get("ngsiem_repo") or ""
    if not repo_id:
        raise FalconNotConfigured(
            f"client {client!r} missing NG-SIEM repo "
            f"(set platforms.crowdstrike.ngsiem_repo or pass repo=)"
        )

    host, token = _acquire_token(client)
    url = f"https://{host}/loggingapi/entities/queries/v1/run"
    body = {"queryString": cql, "repository": repo_id}
    started = time.time()
    try:
        resp = get_session().post(
            url,
            json=body,
            headers={**_auth_headers(token), "Content-Type": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        log_error("", "crowdstrike.run_cql", str(exc),
                  severity="error", context={"client": client})
        raise FalconError(f"request failed: {exc}") from exc

    elapsed_ms = int((time.time() - started) * 1000)
    return _handle_response(client, host, resp, "run_cql", elapsed_ms)


# ---------------------------------------------------------------------------
# Classic Falcon API — detections / hosts / incidents
# ---------------------------------------------------------------------------

def _query_paged(
    client: str,
    queries_path: str,
    summaries_path: str,
    id_key: str,
    filter_: str | None,
    limit: int,
) -> dict[str, Any]:
    """Run a Falcon FQL-filtered "queries + entities" two-step call.

    1. ``GET <queries_path>?filter=...&limit=...`` returns a list of IDs.
    2. ``POST <summaries_path>`` with the IDs returns full entity records.
    """
    host, token = _acquire_token(client)
    params: dict[str, Any] = {"limit": max(1, min(int(limit), 1000))}
    if filter_:
        params["filter"] = filter_

    started = time.time()
    try:
        ids_resp = get_session().get(
            f"https://{host}{queries_path}",
            params=params,
            headers=_auth_headers(token),
            timeout=30,
        )
    except requests.RequestException as exc:
        log_error("", f"crowdstrike{queries_path}", str(exc),
                  severity="error", context={"client": client})
        raise FalconError(f"request failed: {exc}") from exc

    ids_payload = _handle_response(client, host, ids_resp, queries_path,
                                   int((time.time() - started) * 1000))
    resources = ids_payload.get("resources") or []
    if not resources:
        return {"rows": [], "stats": {"row_count": 0, "elapsed_ms": ids_payload["stats"]["elapsed_ms"]}}

    # Fetch entity summaries.
    started2 = time.time()
    try:
        sum_resp = get_session().post(
            f"https://{host}{summaries_path}",
            json={"ids": resources},
            headers={**_auth_headers(token), "Content-Type": "application/json"},
            timeout=30,
        )
    except requests.RequestException as exc:
        log_error("", f"crowdstrike{summaries_path}", str(exc),
                  severity="error", context={"client": client})
        raise FalconError(f"request failed: {exc}") from exc

    sum_payload = _handle_response(client, host, sum_resp, summaries_path,
                                   int((time.time() - started2) * 1000))
    rows = sum_payload.get("resources") or []
    return {
        "rows": rows,
        "stats": {
            "row_count": len(rows),
            "id_count": len(resources),
            "elapsed_ms": ids_payload["stats"]["elapsed_ms"] + sum_payload["stats"]["elapsed_ms"],
        },
    }


def query_detections(client: str, filter_: str | None = None, limit: int = 50) -> dict[str, Any]:
    """Falcon detections (FQL filter, e.g. ``status:'new'+max_severity_displayname:'High'``)."""
    return _query_paged(
        client,
        "/detects/queries/detects/v1",
        "/detects/entities/summaries/GET/v1",
        "id",
        filter_,
        limit,
    )


def query_hosts(client: str, filter_: str | None = None, limit: int = 50) -> dict[str, Any]:
    """Falcon host inventory (FQL filter, e.g. ``hostname:'host-1'``)."""
    return _query_paged(
        client,
        "/devices/queries/devices/v1",
        "/devices/entities/devices/v2",
        "device_id",
        filter_,
        limit,
    )


def query_incidents(client: str, filter_: str | None = None, limit: int = 50) -> dict[str, Any]:
    """Falcon incidents (FQL filter, e.g. ``status:20``)."""
    return _query_paged(
        client,
        "/incidents/queries/incidents/v1",
        "/incidents/entities/incidents/GET/v1",
        "incident_id",
        filter_,
        limit,
    )


# ---------------------------------------------------------------------------
# Response handling
# ---------------------------------------------------------------------------

def _handle_response(
    client: str,
    host: str,
    resp: requests.Response,
    op: str,
    elapsed_ms: int,
) -> dict[str, Any]:
    if resp.status_code == 401:
        _invalidate_token(client, host)
        raise FalconError(f"{op}: 401 Unauthorised — token/scope issue: {resp.text[:200]}")
    if resp.status_code == 403:
        raise FalconError(f"{op}: 403 Forbidden — API client lacks required scope: {resp.text[:200]}")
    if resp.status_code == 429:
        retry_after = resp.headers.get("X-Ratelimit-Retryafter") or resp.headers.get("Retry-After") or ""
        raise FalconError(f"{op}: 429 rate-limited (Retry-After={retry_after}): {resp.text[:200]}")
    if resp.status_code >= 400:
        log_error("", f"crowdstrike.{op}",
                  f"HTTP {resp.status_code}: {resp.text[:300]}",
                  severity="error", context={"client": client})
        raise FalconError(f"{op}: HTTP {resp.status_code}: {resp.text[:300]}")

    try:
        payload = resp.json()
    except ValueError as exc:
        raise FalconError(f"{op}: invalid JSON response: {exc}") from exc

    # CQL endpoint returns events under a different shape than classic FQL.
    if "events" in payload:
        return {
            "events": payload.get("events") or [],
            "rows": payload.get("events") or [],
            "metadata": payload.get("metaData") or payload.get("metadata") or {},
            "stats": {"row_count": len(payload.get("events") or []), "elapsed_ms": elapsed_ms},
        }

    # Classic Falcon "queries" / "entities" responses use { resources, errors, meta }.
    return {
        "resources": payload.get("resources") or [],
        "errors": payload.get("errors") or [],
        "meta": payload.get("meta") or {},
        "stats": {"elapsed_ms": elapsed_ms},
    }
