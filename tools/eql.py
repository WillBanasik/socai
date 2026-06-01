"""
tool: eql (Encore Gateway EQL)
------------------------------
Pull normalised entity context for an investigation case from Encore's
read-only EQL warehouse (identity, device posture, detections, vulnerability
exposure across AD / Entra / Intune / CrowdStrike / Defender ATP / Cloudflare).

This is the socai-native, case-scoped path. It is deliberately NOT a general
EQL client — every query is pinned to the single Encore client mapped to the
case's client via ``platforms.encore.internal_client_id`` in
config/client_entities.json.

**Token scope (hard requirement).** ``ENCORE_EQL_TOKEN`` is a personal token
with access to ALL Encore clients. This module never accepts a free-form
client / clientId from the caller: it resolves the case → client →
``internal_client_id`` and pins the query to it. A client with no
``platforms.encore`` block (or ``access`` not granting read) is refused before
any HTTP call. Cross-client access is therefore structurally impossible here.

**Freshness.** The warehouse is periodically refreshed (posture snapshots
~daily, event tables within ~1–2h). ``AzureActiveDirectory-SignInAudits`` holds
a rolling ~7-day window. Each result carries a ``freshness`` stamp; an empty
result is marked ``no_data_for_client`` — coverage varies per client and
absence is NOT evidence of "clean".

Public API:
    is_eql_configured(client) -> bool
    run_eql(internal_client_id, eql, timeout=30) -> dict
    entity_context(case_id, user=None, host=None, ip=None, depth="auto") -> dict
    posture_context(case_id, depth="auto") -> dict
"""
from __future__ import annotations

import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import (
    eprint,
    get_client_config,
    load_json,
    log_error,
    save_json,
    utcnow,
)
from tools.secrets import get_secret

# Encore gateway (production, read-only, multi-client). Cloudflare sits in
# front and 403s non-browser User-Agents, so a browser UA is mandatory.
_BASE = "https://za.encore.io/gateway/api"
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Event-stream tables can return thousands of rows for one entity over the
# rolling window. Cap what we surface inline (most-recent first); the full set
# is always persisted to the case artefact and the true total is reported.
# Posture/inventory tables (1–few rows per entity) are never capped.
_MAX_ROWS_INLINE = 50
_RAW_QUERY_CAP = 200

_TOKEN_SAFETY_S = 120  # refresh this many seconds before stated expiry.
# Single shared access token — one ENCORE_EQL_TOKEN covers all clients.
_token_cache: dict[str, tuple[str, float]] = {}
_token_lock = threading.Lock()

# Access values on platforms.encore.access that grant read.
_READ_OK = {"read", "readonly", "read-only", True, "true", "yes", 1}

# Date-ish columns used to derive a freshness stamp, in preference order of
# "most event-like" first.
_FRESHNESS_FIELDS = (
    "LastBehaviour", "LastEventTime", "AlertCreationTime", "CreatedDateTime",
    "ActivityDateTime", "DetectedDateTime", "DateTime", "LastSeen",
    "LastCommsDate", "EntryDate",
)


class EqlError(RuntimeError):
    """Transport, auth, or query-execution failure."""


class EqlNotConfigured(EqlError):
    """Client has no Encore EQL mapping / read access — the scope gate."""


# ---------------------------------------------------------------------------
# Curated per-entity query templates. Columns verified via `list columns`.
# Each: (table, key column, operator, [select columns]).
# ---------------------------------------------------------------------------

QUERY_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "user": [
        {"table": "AzureActiveDirectory-Users", "key": "UserPrincipalName", "op": "=",
         "select": ["UserPrincipalName", "DisplayName", "AccountEnabled", "UserType",
                    "Department", "IsMfaRegistered", "RiskLevel", "RiskState", "RiskDetail",
                    "IsElevated", "LastPasswordChangeDateTime", "OnPremisesSamAccountName",
                    "UsageLocation", "Country", "EntryDate"]},
        {"table": "AzureActiveDirectory-SignInAudits", "key": "UserPrincipalName", "op": "=",
         "select": ["CreatedDateTime", "IpAddress", "City", "CountryName",
                    "RiskLevelDuringSignIn", "RiskState", "ConditionalAccessStatus", "Status",
                    "ClientAppUsed", "IsInteractive", "AppDisplayName", "DaysSinceMostRecentData"]},
        {"table": "AzureActiveDirectory-RiskyActivities", "key": "UserPrincipalName", "op": "=",
         "select": ["Activity", "ActivityDateTime", "DetectedDateTime", "IpAddress",
                    "RiskEventType", "RiskLevel", "RiskState", "RiskDetail", "Location", "Source"]},
        {"table": "Intune-ManagedDevices", "key": "UserPrincipalName", "op": "=",
         "select": ["ComputerName", "ManagedDeviceName", "OperatingSystem", "OsVersion",
                    "DeviceComplianceStatus", "IsEncrypted", "Manufacturer", "Model",
                    "LastCommsDate", "JailBroken", "PartnerReportedThreatState", "EnrolledDateTime"]},
    ],
    "host": [
        {"table": "Baseline-Core", "key": "HostName", "op": "LIKE",
         "select": ["HostName", "Domain", "IpAddress", "OperatingSystem", "OsType",
                    "SerialNumber", "LastSeen", "DaysSinceLastSeen", "ManagedInActiveDirectory",
                    "ManagedInAzureActiveDirectory", "ManagedInCrowdStrike",
                    "ManagedInDefenderForEndpoint", "ManagedInMicrosoftIntune"]},
        {"table": "CrowdStrike-Devices", "key": "HostName", "op": "LIKE",
         "select": ["HostName", "MacAddress", "OperatingSystemName", "Domain", "PoliciesApplied",
                    "Quarantined", "ReducedFunctionalityMode", "OutdatedAgent",
                    "FrequentDetections", "IsStale", "AgentVersion"]},
        {"table": "WindowsDefenderAtp-Machines", "key": "ComputerDnsName", "op": "LIKE",
         "select": ["ComputerDnsName", "Domain", "OSPlatform", "OSVersion", "LastSeen",
                    "LastIpAddress", "HealthStatus", "RiskScore", "ExposureLevel",
                    "DefenderAvStatus", "OnboardingStatus", "CriticalVulnerabilities",
                    "HighVulnerabilities", "TotalVulnerabilities"]},
        {"table": "CrowdStrike-Detections", "key": "Hostname", "op": "LIKE",
         "select": ["Hostname", "Username", "Tactic", "Technique", "Objective", "Description",
                    "Risk", "Filename", "ActionsTaken", "Status", "FirstBehaviour", "LastBehaviour"]},
        {"table": "WindowsDefenderAtp-Alerts", "key": "ComputerDnsName", "op": "LIKE",
         "select": ["Title", "Severity", "Status", "Category", "DetectionSource",
                    "ThreatFamilyName", "MitreTechniques", "Classification", "Determination",
                    "RelatedUserName", "AlertCreationTime", "LastEventTime"]},
        {"table": "VulnerabilityPrioritization-Hosts", "key": "ComputerName", "op": "LIKE",
         "select": ["ComputerName", "Domain", "IpAddress", "CriticalVulnerabilities",
                    "HighVulnerabilities", "MaxCVSS", "MaxEpss", "HasActiveExploit",
                    "HasCommunityExploit", "IsRansomwareExploit", "ExposureScore",
                    "PrioritizationIndex", "HasImminentThreats", "HasEmergingThreats", "LastCommsDate"]},
    ],
    "ip": [
        {"table": "AzureActiveDirectory-SignInAudits", "key": "IpAddress", "op": "=",
         "select": ["CreatedDateTime", "UserPrincipalName", "City", "CountryName",
                    "RiskLevelDuringSignIn", "ConditionalAccessStatus", "Status",
                    "ClientAppUsed", "AppDisplayName", "DaysSinceMostRecentData"]},
        {"table": "AzureActiveDirectory-RiskyActivities", "key": "IpAddress", "op": "=",
         "select": ["Activity", "ActivityDateTime", "DetectedDateTime", "UserPrincipalName",
                    "RiskEventType", "RiskLevel", "RiskState", "Location"]},
        {"table": "CloudFlare-Firewall", "key": "ClientIP", "op": "=",
         "select": ["DateTime", "Action", "ClientIP", "ClientCountryName", "ClientASNDescription",
                    "ClientRequestHTTPHost", "ClientRequestPath", "ClientRequestHTTPMethodName",
                    "EdgeResponseStatus", "RuleId", "UserAgent"]},
    ],
}


# ---------------------------------------------------------------------------
# Curated client-wide POSTURE templates — preventative-control / best-practice
# configuration baseline for a security architecture review. These are NOT
# entity-scoped (no WHERE): they pull the tenant's current configuration state.
# Tables/columns verified via `list columns` against the live gateway.
# Time-series snapshot tables carry an ``order_by`` so the most-recent snapshot
# surfaces first (the full history is persisted to the case artefact).
# ---------------------------------------------------------------------------

POSTURE_TEMPLATES: list[dict[str, Any]] = [
    {"domain": "Secure Score (best-practice baseline)",
     "table": "Intune-SecureScore", "order_by": "CreatedDateTime",
     "select": ["CreatedDateTime", "CurrentScore", "MaxScore", "Percentage",
                "ActiveUserCount", "LicensedUserCount"]},
    {"domain": "Identity hygiene & MFA coverage",
     "table": "AzureActiveDirectory-UserSummary", "order_by": "EntryDate",
     "select": ["EntryDate", "TotalUsers", "NotMfaRegistered", "AccountsNoAuthMethod",
                "OldPasswords", "LowRisk", "MediumRisk", "HighRisk", "ElevatedAccounts",
                "AdminAccounts", "AdminAccountsNoMfa", "GlobalAdministrators",
                "GuestAccounts", "AverageUserCompliance", "AverageAdminUserCompliance"]},
    {"domain": "Privileged role assignments",
     "table": "AzureActiveDirectory-RoleAssignments", "order_by": None,
     "select": ["PrincipalName", "PrincipalType", "Role", "Enabled",
                "RegistrationStatus", "SignInAudience", "AssignedToOn"]},
    {"domain": "App credential hygiene (secret/cert expiry)",
     "table": "AzureActiveDirectory-AppCredentials", "order_by": None,
     "select": ["DisplayName", "ParentType", "Type", "Usage", "Status", "EndDateTime"]},
    {"domain": "Device & encryption compliance",
     "table": "Intune-Summary", "order_by": "EntryDate",
     "select": ["EntryDate", "TotalDevices", "TotalCompliant", "TotalNonCompliant",
                "TotalEncryptedDevices", "TotalNonEncryptedDevices", "TotalNoMFAUsers",
                "TotalLaps", "TotalUsers", "TotalGuestUsers"]},
    {"domain": "Defender configuration recommendations (best-practice gaps)",
     "table": "WindowsDefenderAtp-MachineRecommendations", "order_by": "SeverityScore",
     "select": ["RecommendationName", "RecommendationCategory", "SubCategory",
                "SeverityScore", "PublicExploit", "ActiveAlert", "Status",
                "ConfigScoreImpact", "ExposureImpact", "ExposedMachinesCount",
                "TotalMachineCount", "RemediationType", "PolicyName"]},
    {"domain": "Vulnerability exposure (environment)",
     "table": "VulnerabilityPrioritization-VulnerabilitySummary", "order_by": None,
     "select": ["Period", "ExposureScore", "PeerAverage", "ExposureScoreDeviation",
                "TotalThreats", "ImminentThreats", "ImminentInternetExposedThreats",
                "ImminentBusinessCriticalThreats", "EmergingThreats", "LowPriorityThreats"]},
    {"domain": "Security awareness training",
     "table": "AzureActiveDirectory-TrainingStatistics", "order_by": "EntryDate",
     "select": ["EntryDate", "TotalAssignedCount", "TotalCompletedCount",
                "TotalInProgressCount", "TotalOverdueCount", "TotalUnknownCount"]},
]


# ---------------------------------------------------------------------------
# Scope gate + token
# ---------------------------------------------------------------------------

def _resolve_encore_id(client_name: str) -> str:
    """Resolve a socai client name to its pinned Encore ``internal_client_id``.

    Raises EqlNotConfigured (the scope gate) if the client is unknown, has no
    ``platforms.encore`` block, no ``internal_client_id``, or read access is
    not granted. No HTTP is attempted before this passes.
    """
    cfg = get_client_config(client_name)
    if cfg is None:
        raise EqlNotConfigured(f"unknown client {client_name!r}")
    enc = (cfg.get("platforms") or {}).get("encore") or {}
    cid = (enc.get("internal_client_id") or "").strip()
    if not cid:
        raise EqlNotConfigured(
            f"client {client_name!r} not enabled for Encore EQL — "
            f"set platforms.encore.internal_client_id in client_entities.json"
        )
    access = enc.get("access", "read")
    if access not in _READ_OK:
        raise EqlNotConfigured(
            f"client {client_name!r} Encore access {access!r} does not grant read"
        )
    return cid


def is_eql_configured(client: str) -> bool:
    """True iff `client` has a usable Encore EQL mapping (config only)."""
    try:
        _resolve_encore_id(client)
        return True
    except EqlNotConfigured:
        return False


def _get_access_token() -> str:
    """Exchange the refresh token for a ~30-min access token (cached)."""
    now = time.time()
    with _token_lock:
        cached = _token_cache.get("access")
        if cached and cached[1] - _TOKEN_SAFETY_S > now:
            return cached[0]

    refresh = get_secret("ENCORE_EQL_TOKEN", required=True)
    try:
        resp = requests.post(
            f"{_BASE}/auth/refresh",
            json={"refreshToken": refresh},
            headers={"User-Agent": _UA, "Accept": "application/json"},
            timeout=15,
        )
    except requests.RequestException as exc:
        raise EqlError(f"token refresh request failed: {exc}") from exc

    if resp.status_code != 200:
        raise EqlError(f"token refresh returned {resp.status_code}: {resp.text[:300]}")
    try:
        token = resp.json()["accessToken"]
    except (ValueError, KeyError) as exc:
        raise EqlError(f"token refresh returned unexpected body: {resp.text[:300]}") from exc

    # Access tokens are ~30 min; we don't get expiry back, so assume 1800s.
    with _token_lock:
        _token_cache["access"] = (token, now + 1800)
    return token


# ---------------------------------------------------------------------------
# Query execution
# ---------------------------------------------------------------------------

def run_eql(internal_client_id: str, eql: str, timeout: int = 30) -> dict[str, Any]:
    """Run a raw EQL query pinned to ``internal_client_id``.

    Returns ``{"rows", "row_count", "errors", "query"}``. Raises EqlError on
    transport/auth failure; query-level ErrorMessages are surfaced in
    ``errors`` (some are benign, e.g. "unsupported feature of Gateway").
    """
    if not eql or not eql.strip():
        raise EqlError("query is empty")
    token = _get_access_token()
    # The internalClientId is itself a valid client alias on the gateway.
    path = f"/client/request?client={urllib.parse.quote(internal_client_id)}"
    try:
        resp = requests.post(
            _BASE + path,
            data=eql.encode(),
            headers={
                "User-Agent": _UA,
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "text/plain",
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        log_error("", "eql.run", str(exc), severity="error",
                  context={"client_id": internal_client_id})
        raise EqlError(f"request failed: {exc}") from exc

    if resp.status_code != 200:
        raise EqlError(f"query returned {resp.status_code}: {resp.text[:300]}")
    try:
        payload = resp.json()
    except ValueError as exc:
        raise EqlError(f"query returned non-JSON: {resp.text[:200]}") from exc

    rows = payload.get("Data", []) or []
    return {
        "query": eql,
        "rows": rows,
        "row_count": payload.get("RowCount", len(rows)),
        "errors": payload.get("ErrorMessages", []) or [],
    }


# ---------------------------------------------------------------------------
# Freshness / helpers
# ---------------------------------------------------------------------------

def _freshness(rows: list[dict]) -> dict | None:
    """Derive a freshness stamp from the date-ish columns present in `rows`."""
    if not rows:
        return None
    latest: str | None = None
    days: float | None = None
    for r in rows:
        for f in _FRESHNESS_FIELDS:
            v = r.get(f)
            if isinstance(v, str) and v:
                if latest is None or v > latest:
                    latest = v
        d = r.get("DaysSinceMostRecentData")
        if isinstance(d, (int, float)):
            days = d if days is None else min(days, d)
    out: dict[str, Any] = {}
    if latest:
        out["latest_record"] = latest
    if days is not None:
        out["days_since_most_recent_data"] = days
    return out or None


def _cap(rows: list[dict], limit: int) -> tuple[list[dict], bool]:
    """Return (most-recent `limit` rows, truncated?) — non-lossy: caller keeps total."""
    if len(rows) <= limit:
        return rows, False

    def _key(r: dict) -> str:
        for f in _FRESHNESS_FIELDS:
            v = r.get(f)
            if isinstance(v, str) and v:
                return v
        return ""

    return sorted(rows, key=_key, reverse=True)[:limit], True


def _sanitise(value: str) -> str:
    """Strip characters that would break the EQL string literal."""
    return value.replace('"', "").replace("\n", "").replace("\r", "").strip()


def _build_query(tpl: dict[str, Any], value: str) -> str:
    literal = f'"%{value}%"' if tpl["op"] == "LIKE" else f'"{value}"'
    return (
        f'{tpl["table"]} WHERE {tpl["key"]} {tpl["op"]} {literal} '
        f'SELECT {", ".join(tpl["select"])}'
    )


def _build_posture_query(tpl: dict[str, Any]) -> str:
    """Build a client-wide (no-WHERE) posture query, newest snapshot first."""
    q = f'{tpl["table"]} SELECT {", ".join(tpl["select"])}'
    if tpl.get("order_by"):
        q += f' ORDER BY {tpl["order_by"]} DESCENDING'
    return q


# ---------------------------------------------------------------------------
# Entity context — the HITL workhorse
# ---------------------------------------------------------------------------

def entity_context(
    case_id: str,
    user: str | None = None,
    host: str | None = None,
    ip: str | None = None,
    depth: str = "auto",
) -> dict[str, Any]:
    """Pull recent Encore EQL context for the entities named on a case.

    Resolves the case's client → pinned Encore client (scope gate), runs the
    curated query set for each supplied entity, stamps freshness + coverage,
    persists the raw payload as a case artefact, and appends a provenance note
    to the evidence chain. Returns the full payload (no slimming).
    """
    entities = {k: _sanitise(v) for k, v in
                (("user", user), ("host", host), ("ip", ip)) if v and v.strip()}
    if not entities:
        raise EqlError("provide at least one of user, host, ip")

    # Scope gate — case → client → pinned Encore id. Raises before any HTTP.
    meta_path = CASES_DIR / case_id / "case_meta.json"
    if not meta_path.exists():
        raise EqlError(f"case {case_id!r} not found ({meta_path})")
    client_name = (load_json(meta_path) or {}).get("client", "")
    if not client_name:
        raise EqlError(f"case {case_id!r} has no client set")
    internal_client_id = _resolve_encore_id(client_name)

    started = time.time()
    queries: list[dict[str, Any]] = []
    for etype, value in entities.items():
        for tpl in QUERY_TEMPLATES[etype]:
            q = _build_query(tpl, value)
            entry: dict[str, Any] = {
                "entity_type": etype, "entity_value": value,
                "table": tpl["table"], "query": q,
            }
            try:
                res = run_eql(internal_client_id, q)
                rows = res["rows"]
                entry["row_count"] = res["row_count"]
                entry["rows"] = rows
                entry["errors"] = res["errors"]
                entry["freshness"] = _freshness(rows)
                entry["coverage"] = "ok" if rows else "no_data_for_client"
            except EqlError as exc:
                # One bad table must not sink the whole context pull.
                entry["row_count"] = 0
                entry["rows"] = []
                entry["coverage"] = "query_error"
                entry["error"] = str(exc)
                log_error(case_id, "eql.entity_context", str(exc),
                          severity="warning", context={"table": tpl["table"]})
            queries.append(entry)

    output = {
        "case_id": case_id,
        "client": client_name,
        "internal_client_id": internal_client_id,
        "ts": utcnow(),
        "depth": depth,
        "duration_ms": int((time.time() - started) * 1000),
        "entities": entities,
        "queries": queries,
        "_window_note": (
            "SignInAudits is a rolling ~7-day window; posture/inventory tables "
            "are ~daily snapshots. 'no_data_for_client' means the product is not "
            "ingested for this client — it is NOT evidence of clean."
        ),
    }

    # Persist the FULL raw payload as a case artefact (nothing dropped on disk).
    slug = "_".join(sorted(entities.values()))[:60].replace("/", "_") or "entity"
    save_json(CASES_DIR / case_id / "artefacts" / "eql_context" / f"{slug}.json", output)

    # Cap what we surface inline (event tables can return thousands of rows for
    # one entity over the window). row_count keeps the true total; the full set
    # lives in the artefact above. Safe to mutate now — save_json already ran.
    for entry in queries:
        capped, truncated = _cap(entry.get("rows", []), _MAX_ROWS_INLINE)
        entry["rows"] = capped
        entry["rows_returned"] = len(capped)
        entry["truncated"] = truncated

    # Append a concise provenance note to the evidence chain (raw observation).
    _append_evidence(case_id, output)
    return output


def posture_context(case_id: str, depth: str = "auto") -> dict[str, Any]:
    """Pull the client's preventative-control / best-practice configuration baseline.

    Unlike ``entity_context`` (reactive, entity-keyed), this runs the curated
    client-wide POSTURE query set — Secure Score, identity/MFA coverage,
    privileged access, app-credential hygiene, device/encryption compliance,
    Defender config recommendations, vulnerability exposure, and security
    training — for use by the security architecture review. Same scope gate as
    ``entity_context``: pinned to the case's mapped Encore client. Persists the
    full raw payload as a case artefact and appends a provenance note.
    """
    client_name, internal_client_id = _resolve_case_client(case_id)

    started = time.time()
    domains: list[dict[str, Any]] = []
    for tpl in POSTURE_TEMPLATES:
        q = _build_posture_query(tpl)
        entry: dict[str, Any] = {
            "domain": tpl["domain"], "table": tpl["table"], "query": q,
        }
        try:
            res = run_eql(internal_client_id, q)
            rows = res["rows"]
            entry["row_count"] = res["row_count"]
            entry["rows"] = rows
            entry["errors"] = res["errors"]
            entry["freshness"] = _freshness(rows)
            entry["coverage"] = "ok" if rows else "no_data_for_client"
        except EqlError as exc:
            # One bad table must not sink the whole posture pull.
            entry["row_count"] = 0
            entry["rows"] = []
            entry["coverage"] = "query_error"
            entry["error"] = str(exc)
            log_error(case_id, "eql.posture_context", str(exc),
                      severity="warning", context={"table": tpl["table"]})
        domains.append(entry)

    output = {
        "case_id": case_id,
        "client": client_name,
        "internal_client_id": internal_client_id,
        "ts": utcnow(),
        "depth": depth,
        "duration_ms": int((time.time() - started) * 1000),
        "domains": domains,
        "_window_note": (
            "Posture/summary tables are ~daily snapshots ordered newest-first; "
            "the most-recent row is current state. 'no_data_for_client' means "
            "the product is not ingested for this client — it is NOT evidence of "
            "a clean or compliant state."
        ),
    }

    # Persist the FULL raw payload (nothing dropped on disk).
    save_json(CASES_DIR / case_id / "artefacts" / "eql_context" / "posture.json", output)

    # Cap what we surface inline (snapshot histories can be hundreds of rows);
    # row_count keeps the true total, full history lives in the artefact above.
    for entry in domains:
        capped, truncated = _cap(entry.get("rows", []), _MAX_ROWS_INLINE)
        entry["rows"] = capped
        entry["rows_returned"] = len(capped)
        entry["truncated"] = truncated

    _append_posture_evidence(case_id, output)
    return output


def _append_posture_evidence(case_id: str, output: dict[str, Any]) -> None:
    """Summarise the posture pull into the case evidence chain."""
    from api.actions import add_evidence  # lazy: avoids import cycle

    lines = [
        f"**Encore EQL posture baseline** ({output['client']}, "
        f"client {output['internal_client_id']})",
        "",
    ]
    for d in output["domains"]:
        bits = [f"- {d['domain']} — `{d['table']}`: {d['row_count']} row(s)"]
        if d.get("coverage") and d["coverage"] != "ok":
            bits.append(f"[{d['coverage']}]")
        fr = d.get("freshness") or {}
        if fr.get("latest_record"):
            bits.append(f"latest={fr['latest_record']}")
        if d.get("error"):
            bits.append(f"err={d['error'][:80]}")
        lines.append(" ".join(bits))
    lines.append("")
    lines.append("_" + output["_window_note"] + "_")
    try:
        add_evidence(case_id, "\n".join(lines))
    except Exception as exc:  # evidence note is best-effort, never fatal
        log_error(case_id, "eql.append_posture_evidence", str(exc), severity="warning")
        eprint(f"[eql] posture evidence note failed: {exc}")


def _resolve_case_client(case_id: str) -> tuple[str, str]:
    """case_id → (client_name, internal_client_id). Applies the scope gate."""
    meta_path = CASES_DIR / case_id / "case_meta.json"
    if not meta_path.exists():
        raise EqlError(f"case {case_id!r} not found ({meta_path})")
    client_name = (load_json(meta_path) or {}).get("client", "")
    if not client_name:
        raise EqlError(f"case {case_id!r} has no client set")
    return client_name, _resolve_encore_id(client_name)


def run_eql_for_case(case_id: str, eql: str, timeout: int = 30) -> dict[str, Any]:
    """Analyst escape hatch: run a raw EQL string, pinned to the case's client.

    Same scope gate as entity_context — the query is forced onto the case's
    mapped Encore client; the caller cannot target another. Persists the raw
    result as a case artefact and appends a one-line evidence note.
    """
    client_name, internal_client_id = _resolve_case_client(case_id)
    res = run_eql(internal_client_id, eql, timeout=timeout)
    out = {
        "case_id": case_id,
        "client": client_name,
        "internal_client_id": internal_client_id,
        "ts": utcnow(),
        "query": eql,
        "row_count": res["row_count"],
        "rows": res["rows"],
        "errors": res["errors"],
        "freshness": _freshness(res["rows"]),
    }
    stamp = utcnow().replace(":", "").replace("-", "").replace("T", "_").split(".")[0]
    save_json(CASES_DIR / case_id / "artefacts" / "eql_context" / f"adhoc_{stamp}.json", out)
    # Cap inline rows after persisting the full set (row_count keeps the total).
    capped, truncated = _cap(out["rows"], _RAW_QUERY_CAP)
    out["rows"] = capped
    out["rows_returned"] = len(capped)
    out["truncated"] = truncated
    try:
        from api.actions import add_evidence
        fr = (out["freshness"] or {}).get("latest_record", "n/a")
        add_evidence(case_id, f"**Encore EQL query** ({client_name}): `{eql}` → "
                              f"{out['row_count']} row(s), latest={fr}")
    except Exception as exc:
        log_error(case_id, "eql.run_for_case.evidence", str(exc), severity="warning")
    return out


def _append_evidence(case_id: str, output: dict[str, Any]) -> None:
    """Summarise the pull into the case evidence chain via add_evidence."""
    from api.actions import add_evidence  # lazy: avoids import cycle

    lines = [
        f"**Encore EQL entity context** ({output['client']}, "
        f"client {output['internal_client_id']})",
        f"Entities: {', '.join(f'{k}={v}' for k, v in output['entities'].items())}",
        "",
    ]
    for q in output["queries"]:
        bits = [f"- `{q['table']}` ({q['entity_type']}): {q['row_count']} row(s)"]
        if q.get("coverage") and q["coverage"] != "ok":
            bits.append(f"[{q['coverage']}]")
        fr = q.get("freshness") or {}
        if fr.get("latest_record"):
            bits.append(f"latest={fr['latest_record']}")
        if q.get("error"):
            bits.append(f"err={q['error'][:80]}")
        lines.append(" ".join(bits))
    lines.append("")
    lines.append("_" + output["_window_note"] + "_")
    try:
        add_evidence(case_id, "\n".join(lines))
    except Exception as exc:  # evidence note is best-effort, never fatal
        log_error(case_id, "eql.append_evidence", str(exc), severity="warning")
        eprint(f"[eql] evidence note failed: {exc}")
