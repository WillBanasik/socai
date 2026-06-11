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
    identity_assessment(case_id, users=None, hosts=None, cap=5) -> dict
    posture_context(case_id, depth="auto") -> dict
    entity_lookup(client_name, user=None, host=None, ip=None, depth="auto") -> dict   # caseless
    identity_scan(client_name, users=None, hosts=None, cap=5) -> dict                 # caseless
    vuln_hunt(client_name, depth="auto") -> dict        # caseless, proactive
    import_eql_lookup(lookup_id, case_id) -> dict        # promote a lookup/scan into a case
    import_vuln_hunt(hunt_id, case_id) -> dict           # promote a hunt into a case

**Caseless paths.** Three tools run WITHOUT a case — they resolve a client *by
name* (exact match, never fuzzy) through the same ``_resolve_encore_id`` scope
gate (via ``resolve_client_by_name``) and persist the full payload to
``registry/eql_lookups/`` (entity ``EQL_<ts>`` / identity ``EQLID_<ts>``) or
``registry/vuln_hunts/VH_<ts>.json``, mirroring the ``quick_enrich`` caseless
store:
  * ``entity_lookup`` — caseless ``entity_context`` (user / host / ip).
  * ``identity_scan``  — caseless ``identity_assessment`` (internal/external + devices).
  * ``vuln_hunt``      — proactive client-wide vulnerability/exposure sweep.
Promote a lookup/scan into a case with ``import_eql_lookup`` (or
``create_case(..., eql_lookup_id=...)``) and a hunt with ``import_vuln_hunt`` (or
``create_case(..., vuln_hunt_id=...)``). Both imports refuse to cross client
boundaries (the case's Encore id must match the payload's).
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
    get_session,
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
        # Local-admin assignments on this host — blast-radius / lateral-movement reach
        # if the host is compromised. Keyed on the hostname (empty-safe when sparse).
        {"table": "LateralMovement-LocalAdmins", "key": "ComputerName", "op": "LIKE",
         "select": ["ComputerName", "AccountName", "AccountType", "EntryDate"]},
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
    # Enterprise-app / OAuth attack surface (consent-phishing & app-credential abuse).
    # Most-privileged apps first (Scopes DESC); AppCredentials (secret/cert expiry) is
    # already covered above. The raw OauthScopes catalogue (~2k rows, no useful inline
    # ranking) is intentionally left to eql_query for deep-dives.
    {"domain": "Enterprise apps & service principals (privilege/credential inventory)",
     "table": "AzureActiveDirectory-AllServicePrincipals", "order_by": "Scopes",
     "select": ["AppName", "ServicePrincipalAppId", "PublisherDomain", "SignInAudience",
                "AccountEnabled", "CredentialStatus", "Roles", "Scopes", "CreatedOn", "DeletedOn"]},
    # Recent privileged / directory changes (admin-change context). InitiatedBy is a
    # display name, not a UPN — client-wide here, NOT entity-keyed.
    {"domain": "Recent directory / privileged changes",
     "table": "AzureActiveDirectory-DirectoryAudits", "order_by": "ActivityDateTime",
     "select": ["ActivityDateTime", "ActivityDisplayName", "Category", "InitiatedBy",
                "OperationType", "Result", "ResultReason", "LoggedByService"]},
]


# ---------------------------------------------------------------------------
# Curated client-wide VULNERABILITY HUNT templates — proactive exposure sweep.
# Encore has already done the prioritisation (EPSS, KEV / in-the-wild
# correlation, ransomware-exploit flags, a computed PrioritizationIndex), so we
# pull RANKED (ORDER BY PrioritizationIndex DESCENDING — highest risk first) and
# filter the boolean exploit flags client-side (EQL rejects boolean WHERE:
# "Boolean is not compatible with true (Text)"). Same schema as POSTURE_TEMPLATES.
# Columns verified via `list columns` against the live gateway.
# ---------------------------------------------------------------------------

VULN_HUNT_TEMPLATES: list[dict[str, Any]] = [
    {"domain": "Exposed hosts (ranked by exploitability)",
     "table": "VulnerabilityPrioritization-Hosts", "order_by": "PrioritizationIndex",
     "select": ["ComputerName", "Domain", "IpAddress", "OperatingSystem", "OsType",
                "LastCommsDate", "CriticalVulnerabilities", "HighVulnerabilities",
                "PrioritizationIndex", "MaxCVSS", "MaxEpss", "MaxEpssPercentile",
                "HasActiveExploit", "HasCommunityExploit", "IsRansomwareExploit",
                "HasHighExploitProbability", "HasImminentThreats", "HasEmergingThreats",
                "ExposureScore", "IsScanned", "ProductDetections"]},
    # The full table is ~41k rows and PrioritizationIndex saturates (top rows are
    # "Low"/not-exploited), so bound server-side to the actively-exploited subset
    # (a Text column — filterable) and rank by EPSS. This is the core hunt list.
    {"domain": "Actively-exploited vulnerabilities (CVE level)",
     "table": "VulnerabilityPrioritization-Vulnerabilities", "order_by": "Epss",
     "where": 'Classification = "Actively Exploited"',
     "select": ["CVE", "Description", "NistSeverity", "BaseScore", "Epss", "EpssPercentile",
                "ExploitabilityScore", "ImpactScore", "HasBeenExploited", "ExploitedSince",
                "HasBeenInWild", "InTheWildDate", "AgeInDays", "DevicesImpacted",
                "PrioritizationIndex", "PrioritizationRating", "Classification",
                "Recommendation", "ProductDetections"]},
    {"domain": "Newly-weaponised KEVs (last 48h)",
     "table": "VulnerabilityPrioritization-NewKevsIn48Hrs", "order_by": "PrioritizationIndex",
     "select": ["CVE", "Severity", "Status", "AddedToActiveExploitDatabaseOn", "PublishedOn",
                "DaysSinceFirstExploit", "InKev", "InPublicSources", "IsRansomwareExploit",
                "DevicesImpacted", "PrioritizationIndex", "Solution", "Description"]},
    {"domain": "EDR compensating-control tasks (mitigate when patch is blocked)",
     "table": "VulnerabilityPrioritization-VulnerabilityEdrControlTaskList", "order_by": None,
     "select": ["Classification", "Detail", "ImpactedDevices", "Action"]},
    {"domain": "Environment exposure summary",
     "table": "VulnerabilityPrioritization-VulnerabilitySummary", "order_by": None,
     "select": ["Period", "ExposureScore", "PeerAverage", "ExposureScoreDeviation",
                "TotalThreats", "ImminentThreats", "ImminentInternetExposedThreats",
                "ImminentBusinessCriticalThreats", "EmergingThreats", "LowPriorityThreats"]},
]


# ---------------------------------------------------------------------------
# Lean IDENTITY-ASSESSMENT templates — the cheap scoping step that runs BEFORE
# the heavy per-entity ``entity_context`` pull. One identity row per user
# classifies internal/external from authoritative directory data; managed-device
# context is pulled only for users that resolve to a real non-guest record.
# ---------------------------------------------------------------------------

# Single Users record per UPN — the columns the internal/external call needs.
IDENTITY_USER_TEMPLATE: dict[str, Any] = {
    "table": "AzureActiveDirectory-Users", "key": "UserPrincipalName", "op": "=",
    "select": ["UserPrincipalName", "DisplayName", "UserType", "AccountEnabled",
               "OnPremisesSamAccountName", "Department", "IsMfaRegistered",
               "RiskLevel", "RiskState", "UsageLocation", "Country", "EntryDate"],
}
# Lean managed-device context for an internal user — "is this a known managed
# client device + its compliance/encryption posture". Heavier detection/sign-in
# pulls stay in ``entity_context``.
IDENTITY_USER_DEVICES_TEMPLATE: dict[str, Any] = {
    "table": "Intune-ManagedDevices", "key": "UserPrincipalName", "op": "=",
    "select": ["ManagedDeviceName", "ComputerName", "OperatingSystem", "OsVersion",
               "DeviceComplianceStatus", "IsEncrypted", "Manufacturer", "Model",
               "LastCommsDate", "JailBroken", "PartnerReportedThreatState"],
}
# One Baseline-Core identity row per host — which platforms manage it + last-seen.
IDENTITY_HOST_TEMPLATE: dict[str, Any] = {
    "table": "Baseline-Core", "key": "HostName", "op": "LIKE",
    "select": ["HostName", "Domain", "IpAddress", "OperatingSystem", "OsType",
               "LastSeen", "DaysSinceLastSeen", "ManagedInActiveDirectory",
               "ManagedInAzureActiveDirectory", "ManagedInCrowdStrike",
               "ManagedInDefenderForEndpoint", "ManagedInMicrosoftIntune"],
}
# Who can operate / administer a host — the "who is this device assigned to"
# answer for a server or shared device that maps to no single primary user.
IDENTITY_HOST_ADMINS_TEMPLATE: dict[str, Any] = {
    "table": "LateralMovement-LocalAdmins", "key": "ComputerName", "op": "LIKE",
    "select": ["ComputerName", "AccountName", "AccountType", "EntryDate"],
}
# Baseline-Core "ManagedInX" boolean columns → short platform label for the
# ``managed_in`` convenience list.
_MANAGED_IN_COLS: dict[str, str] = {
    "ManagedInActiveDirectory": "ad",
    "ManagedInAzureActiveDirectory": "entra",
    "ManagedInCrowdStrike": "crowdstrike",
    "ManagedInDefenderForEndpoint": "defender",
    "ManagedInMicrosoftIntune": "intune",
}

IDENTITY_DEFAULT_CAP = 5


# ---------------------------------------------------------------------------
# Scope gate + token
# ---------------------------------------------------------------------------

def _resolve_client_config(client_name: str) -> dict | None:
    """Resolve a client *name or declared alias* to its config dict, else None.

    Exact name match first (case-insensitive, via ``get_client_config``). On a
    miss, fall back to an EXACT, UNAMBIGUOUS alias match — mirroring
    ``lookup_client``'s resolution (mcp_server/tools.py): a single alias hit
    resolves, but an alias shared by several clients (e.g. ``"tsogo"``)
    deliberately does NOT (returns None), so the caller fails closed rather than
    silently picking a neighbouring client. Never fuzzy/substring — that path is
    a cross-client leak risk (see ``resolve_client_by_name``).
    """
    cfg = get_client_config(client_name)
    if cfg is not None:
        return cfg
    query = (client_name or "").strip().lower()
    if not query:
        return None
    from config.settings import CLIENT_ENTITIES
    try:
        entities = load_json(CLIENT_ENTITIES).get("clients", [])
    except Exception:
        return None
    matches = [
        ent for ent in entities
        if query in {a.strip().lower() for a in ent.get("aliases", []) if isinstance(a, str)}
    ]
    return matches[0] if len(matches) == 1 else None  # zero or ambiguous → fail closed


def _resolve_encore_id(client_name: str) -> str:
    """Resolve a socai client name (or declared alias) to its pinned Encore
    ``internal_client_id``.

    Raises EqlNotConfigured (the scope gate) if the client is unknown, has no
    ``platforms.encore`` block, no ``internal_client_id``, or read access is
    not granted. An ambiguous shared alias resolves to nothing and is therefore
    treated as unknown (fail closed). No HTTP is attempted before this passes.
    """
    cfg = _resolve_client_config(client_name)
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


def _invalidate_token() -> None:
    """Evict the cached access token (call on a 401 — it may have been
    rotated/revoked server-side before its assumed expiry)."""
    with _token_lock:
        _token_cache.pop("access", None)


def _get_access_token() -> str:
    """Exchange the refresh token for a ~30-min access token (cached).

    The lock is held across the refresh network call (not just the read and
    the write) so concurrent cold-cache callers coalesce onto a single
    refresh instead of each firing their own — the global ``"access"`` key
    means every client's EQL activity shares this slot.
    """
    with _token_lock:
        now = time.time()
        cached = _token_cache.get("access")
        if cached and cached[1] - _TOKEN_SAFETY_S > now:
            return cached[0]

        refresh = get_secret("ENCORE_EQL_TOKEN", required=True)
        try:
            resp = get_session().post(
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
    # The internalClientId is itself a valid client alias on the gateway.
    path = f"/client/request?client={urllib.parse.quote(internal_client_id)}"

    def _post(token: str):
        return get_session().post(
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

    try:
        resp = _post(_get_access_token())
        # A cached token can be rejected if it was rotated/revoked server-side
        # before its assumed expiry — evict and retry once with a fresh token.
        if resp.status_code == 401:
            _invalidate_token()
            resp = _post(_get_access_token())
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


def _apply_coverage(entry: dict[str, Any], rows: list, errors: list) -> None:
    """Set ``entry['coverage']`` for an HTTP-200 EQL response.

    The gateway returns 200 with ``ErrorMessages`` populated and empty
    ``Data`` for a *failed* query — labelling that ``no_data_for_client``
    misreads a broken query on a curated table as "product not onboarded".
    """
    if rows:
        entry["coverage"] = "ok"
    elif errors:
        entry["coverage"] = "query_error"
        entry["error"] = "; ".join(str(e) for e in errors)[:500]
    else:
        entry["coverage"] = "no_data_for_client"


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


def _build_vuln_query(tpl: dict[str, Any]) -> str:
    """Build a client-wide vuln-hunt query with an optional text WHERE.

    Booleans cannot be filtered (EQL rejects ``= "true"``), but Text columns can —
    used to bound large catalogues server-side (e.g. the 41k-row Vulnerabilities
    table filtered to Classification = "Actively Exploited"). ``where`` is a raw
    EQL predicate; ``order_by`` ranks DESCENDING.
    """
    parts = [tpl["table"]]
    if tpl.get("where"):
        parts.append(f'WHERE {tpl["where"]}')
    parts.append("SELECT " + ", ".join(tpl["select"]))
    if tpl.get("order_by"):
        parts.append(f'ORDER BY {tpl["order_by"]} DESCENDING')
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Entity context — the HITL workhorse
# ---------------------------------------------------------------------------

_ENTITY_WINDOW_NOTE = (
    "SignInAudits is a rolling ~7-day window; posture/inventory tables "
    "are ~daily snapshots. 'no_data_for_client' means the product is not "
    "ingested for this client — it is NOT evidence of clean."
)


def _run_entity_queries(
    internal_client_id: str, entities: dict[str, str], log_case_id: str = ""
) -> list[dict[str, Any]]:
    """Run the curated ``QUERY_TEMPLATES`` set for each entity.

    Shared by the case-scoped ``entity_context`` and the caseless ``entity_lookup``
    — both run the identical query set; only the scope resolver and persistence
    differ. Returns the FULL rows (uncapped); the caller persists, then caps
    inline. One bad table never sinks the whole pull. ``log_case_id`` is "" on the
    caseless path (errors are still logged, just not case-attributed).
    """
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
                _apply_coverage(entry, rows, res["errors"])
            except EqlError as exc:
                # One bad table must not sink the whole context pull.
                entry["row_count"] = 0
                entry["rows"] = []
                entry["coverage"] = "query_error"
                entry["error"] = str(exc)
                log_error(log_case_id, "eql.entity_queries", str(exc),
                          severity="warning", context={"table": tpl["table"]})
            queries.append(entry)
    return queries


def _cap_entity_rows_inline(queries: list[dict[str, Any]]) -> None:
    """Cap inline rows per query (event tables can return thousands for one entity
    over the window). ``row_count`` keeps the true total; the full set lives in the
    persisted artefact. Mutates in place — call only AFTER persisting the payload.
    """
    for entry in queries:
        capped, truncated = _cap(entry.get("rows", []), _MAX_ROWS_INLINE)
        entry["rows"] = capped
        entry["rows_returned"] = len(capped)
        entry["truncated"] = truncated


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
    client_name, internal_client_id = _resolve_case_client(case_id)

    started = time.time()
    queries = _run_entity_queries(internal_client_id, entities, log_case_id=case_id)

    output = {
        "case_id": case_id,
        "client": client_name,
        "internal_client_id": internal_client_id,
        "ts": utcnow(),
        "depth": depth,
        "duration_ms": int((time.time() - started) * 1000),
        "entities": entities,
        "queries": queries,
        "_window_note": _ENTITY_WINDOW_NOTE,
    }

    # Persist the FULL raw payload as a case artefact (nothing dropped on disk).
    slug = "_".join(sorted(entities.values()))[:60].replace("/", "_") or "entity"
    save_json(CASES_DIR / case_id / "artefacts" / "eql_context" / f"{slug}.json", output)

    # Cap inline AFTER persisting the full set, then append the evidence note.
    _cap_entity_rows_inline(queries)
    _append_evidence(case_id, output)
    return output


def entity_lookup(
    client_name: str,
    user: str | None = None,
    host: str | None = None,
    ip: str | None = None,
    depth: str = "auto",
) -> dict[str, Any]:
    """Caseless equivalent of ``entity_context`` — pull Encore EQL context for a
    user, host, or IP WITHOUT a case, scoped to a client *by name*.

    Resolves the client through the same ``resolve_client_by_name`` scope gate
    (exact match, read access required — cross-client access is structurally
    impossible), runs the identical curated ``QUERY_TEMPLATES`` set, and persists
    the FULL payload to ``registry/eql_lookups/EQL_<ts>.json`` (mirrors
    ``quick_enrich`` / ``vuln_hunt``). No evidence chain is written — there is no
    case yet. Promote into a case with ``import_eql_lookup`` /
    ``create_case(eql_lookup_id=...)``.
    """
    from config.settings import EQL_LOOKUP_DIR

    entities = {k: _sanitise(v) for k, v in
                (("user", user), ("host", host), ("ip", ip)) if v and v.strip()}
    if not entities:
        raise EqlError("provide at least one of user, host, ip")

    # Same scope gate as the case path, resolved by client name instead of a case.
    canonical, internal_client_id = resolve_client_by_name(client_name)

    started = time.time()
    queries = _run_entity_queries(internal_client_id, entities)

    lookup_id = (
        "EQL_" + utcnow().replace("-", "").replace(":", "").replace("T", "_").split(".")[0]
    )
    output: dict[str, Any] = {
        "lookup_id": lookup_id,
        "kind": "entity_lookup",
        "client": canonical,
        "internal_client_id": internal_client_id,
        "ts": utcnow(),
        "depth": depth,
        "duration_ms": int((time.time() - started) * 1000),
        "entities": entities,
        "queries": queries,
        "_window_note": _ENTITY_WINDOW_NOTE,
    }

    # Persist the FULL raw payload to the caseless store (nothing dropped on disk).
    save_json(EQL_LOOKUP_DIR / f"{lookup_id}.json", output)
    _cap_entity_rows_inline(queries)
    return output


# ---------------------------------------------------------------------------
# Identity assessment — lean batch scoping step (internal/external + devices)
# ---------------------------------------------------------------------------

def _dedupe(values: list[str]) -> list[str]:
    """Sanitise, drop blanks, de-duplicate (case-insensitive), preserve order."""
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        s = _sanitise(v or "")
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _classify_user(upn: str, rows: list[dict], internal_domains: set[str]) -> dict[str, Any]:
    """Classify a user internal/external from their directory record.

    Authoritative signals (from the user's own AzureActiveDirectory-Users row):
    ``UserType`` (Member/Guest), ``OnPremisesSamAccountName`` (hybrid sync), and a
    ``#EXT#`` UPN (B2B guest). ``internal_domains`` is an OPTIONAL zero-cost local
    overlay (client config ``identity.internal_domains``) — when present it flags a
    Member account sitting on an unexpected UPN domain; it never drives the
    classification on its own and triggers no extra query.
    """
    upn_l = upn.lower()
    upn_domain = upn_l.rsplit("@", 1)[-1] if "@" in upn_l else ""
    out: dict[str, Any] = {"upn_domain": upn_domain}
    if internal_domains:
        out["domain_in_config"] = upn_domain in internal_domains

    if not rows:
        out["classification"] = "not_in_directory"
        out["sync"] = None
        return out

    rec = rows[0]
    user_type = (rec.get("UserType") or "").strip().lower()
    on_prem = (rec.get("OnPremisesSamAccountName") or "").strip()
    out["account_enabled"] = rec.get("AccountEnabled")
    out["on_premises_sam"] = on_prem or None
    out["sync"] = "hybrid_on_prem" if on_prem else "cloud_only"
    out["display_name"] = rec.get("DisplayName")
    out["department"] = rec.get("Department")
    out["risk_level"] = rec.get("RiskLevel")

    if user_type == "guest" or "#ext#" in upn_l:
        out["classification"] = "external_guest"
    elif user_type == "member":
        out["classification"] = "internal"
    elif user_type:
        out["classification"] = f"other_{user_type}"
    else:
        out["classification"] = "unknown"  # record present but no UserType

    # Member account on a domain that isn't in the configured owned set — a
    # signal worth surfacing (rogue tenant domain, partner account, typo).
    if (internal_domains and out["classification"] == "internal"
            and not out.get("domain_in_config")):
        out["domain_mismatch"] = True
    return out


_IDENTITY_WINDOW_NOTE = (
    "Users are classified from authoritative directory data (UserType / on-prem "
    "sync / #EXT# UPN); the configured internal_domains overlay only flags "
    "unexpected Member domains. Device context is pulled only for non-guest "
    "principals. Hosts (which need NOT map to a single user — servers/shared "
    "devices) are classified as an ASSET: managed_asset (in a control plane) / "
    "known_unmanaged / not_in_directory; their local admins answer 'who operates "
    "this device'. 'no_data_for_client' / 'not_in_directory' means the entity "
    "isn't in the ingested directory — NOT proof it's external or benign. "
    "Raise `cap` (default 5) to assess more entities; entries beyond the cap "
    "are listed under not_assessed, never silently dropped. This is a scoping "
    "step — follow with eql_entity_context for the entities that matter."
)


def _assess_identities(
    client_name: str,
    internal_client_id: str,
    users: list[str] | None,
    hosts: list[str] | None,
    cap: int,
    depth: str,
    log_case_id: str = "",
) -> dict[str, Any]:
    """Engine shared by the case-scoped ``identity_assessment`` and the caseless
    ``identity_scan``. Resolves nothing (caller supplies the already-gated client +
    Encore id), runs the identity/device/host classification, and returns the FULL
    assessment output WITHOUT an identifier key. The caller adds ``case_id`` /
    ``lookup_id``, persists, caps inline, and (case path only) appends evidence.
    ``internal_domains`` is read from the client config — works on either path.
    """
    cfg = get_client_config(client_name) or {}
    internal_domains = {
        d.strip().lower()
        for d in ((cfg.get("identity") or {}).get("internal_domains") or [])
        if isinstance(d, str) and d.strip()
    }

    cap = max(1, int(cap)) if cap else IDENTITY_DEFAULT_CAP
    all_users = _dedupe(users or [])
    all_hosts = _dedupe(hosts or [])
    if not all_users and not all_hosts:
        raise EqlError("provide at least one user or host")

    assess_users, dropped_users = all_users[:cap], all_users[cap:]
    assess_hosts, dropped_hosts = all_hosts[:cap], all_hosts[cap:]

    started = time.time()
    queries_run = 0
    user_results: list[dict[str, Any]] = []
    host_results: list[dict[str, Any]] = []

    def _run(tpl: dict[str, Any], value: str) -> dict[str, Any]:
        nonlocal queries_run
        q = _build_query(tpl, value)
        queries_run += 1
        try:
            res = run_eql(internal_client_id, q)
            out = {"query": q, "rows": res["rows"], "row_count": res["row_count"],
                   "errors": res["errors"]}
            _apply_coverage(out, res["rows"], res["errors"])
            return out
        except EqlError as exc:
            log_error(log_case_id, "eql.identity_assessment", str(exc),
                      severity="warning", context={"table": tpl["table"], "value": value})
            return {"query": q, "rows": [], "row_count": 0, "coverage": "query_error",
                    "error": str(exc)}

    for upn in assess_users:
        idres = _run(IDENTITY_USER_TEMPLATE, upn)
        cls = _classify_user(upn, idres["rows"], internal_domains)
        entry: dict[str, Any] = {
            "entity_type": "user",
            "upn": upn,
            **cls,
            "identity_query": idres["query"],
            "identity_rows": idres["rows"],
            "identity_coverage": idres["coverage"],
        }
        if idres.get("error"):
            entry["identity_error"] = idres["error"]
        # Only spend a device query on a principal that resolves to a real,
        # non-guest directory record (guests/not-in-directory have no managed
        # devices) — this is the "don't make unneeded requests" guard.
        if cls["classification"] in ("external_guest", "not_in_directory"):
            entry["devices_skipped"] = cls["classification"]
            entry["devices"] = []
            entry["device_count"] = 0
        else:
            dres = _run(IDENTITY_USER_DEVICES_TEMPLATE, upn)
            entry["devices_query"] = dres["query"]
            entry["devices"] = dres["rows"]
            entry["device_count"] = dres["row_count"]
            entry["devices_coverage"] = dres["coverage"]
            entry["freshness"] = _freshness(dres["rows"])
            if dres.get("error"):
                entry["devices_error"] = dres["error"]
        user_results.append(entry)

    for host in assess_hosts:
        hres = _run(IDENTITY_HOST_TEMPLATE, host)
        rows = hres["rows"]
        managed_in = sorted({
            label for r in rows for col, label in _MANAGED_IN_COLS.items()
            if _truthy(r.get(col))
        })
        # Device-side analogue of the user internal/external call. A server has no
        # single user, so we classify the ASSET: known + managed by a control plane
        # → managed_asset; known but no management → known_unmanaged; no directory
        # record at all → not_in_directory (unknown / off-estate / typo).
        if not rows:
            host_class = "not_in_directory"
        elif managed_in:
            host_class = "managed_asset"
        else:
            host_class = "known_unmanaged"

        entry: dict[str, Any] = {
            "entity_type": "host",
            "host": host,
            "classification": host_class,
            "managed_in": managed_in,
            "is_managed": bool(managed_in),
            "query": hres["query"],
            "rows": rows,
            "row_count": hres["row_count"],
            "coverage": hres["coverage"],
            "freshness": _freshness(rows),
            **({"error": hres["error"]} if hres.get("error") else {}),
        }
        # "Who operates this device" — local admins. The right context for a server /
        # shared host that isn't tied to one user. Skip for an unknown device (no
        # directory record → no admin data, no point spending the query).
        if host_class == "not_in_directory":
            entry["admins_skipped"] = "not_in_directory"
            entry["local_admins"] = []
            entry["local_admin_count"] = 0
        else:
            ares = _run(IDENTITY_HOST_ADMINS_TEMPLATE, host)
            entry["local_admins_query"] = ares["query"]
            entry["local_admins"] = ares["rows"]
            entry["local_admin_count"] = ares["row_count"]
            entry["local_admins_coverage"] = ares["coverage"]
            if ares.get("error"):
                entry["local_admins_error"] = ares["error"]
        host_results.append(entry)

    summary = {
        "users_assessed": len(user_results),
        "users_internal": sum(1 for u in user_results if u["classification"] == "internal"),
        "users_external_guest": sum(1 for u in user_results
                                    if u["classification"] == "external_guest"),
        "users_not_in_directory": sum(1 for u in user_results
                                      if u["classification"] == "not_in_directory"),
        "users_other": sum(1 for u in user_results
                           if u["classification"] not in
                           ("internal", "external_guest", "not_in_directory")),
        "users_domain_mismatch": sum(1 for u in user_results if u.get("domain_mismatch")),
        "users_not_assessed_cap": len(dropped_users),
        "hosts_assessed": len(host_results),
        "hosts_managed": sum(1 for h in host_results if h["is_managed"]),
        "hosts_known_unmanaged": sum(1 for h in host_results
                                     if h["classification"] == "known_unmanaged"),
        "hosts_not_in_directory": sum(1 for h in host_results
                                      if h["classification"] == "not_in_directory"),
        "hosts_not_assessed_cap": len(dropped_hosts),
        "eql_queries_run": queries_run,
    }

    output: dict[str, Any] = {
        "client": client_name,
        "internal_client_id": internal_client_id,
        "ts": utcnow(),
        "depth": depth,
        "cap": cap,
        "duration_ms": int((time.time() - started) * 1000),
        "internal_domains_configured": sorted(internal_domains) or None,
        "summary": summary,
        "users": user_results,
        "hosts": host_results,
        "not_assessed": {"users": dropped_users, "hosts": dropped_hosts},
        "_window_note": _IDENTITY_WINDOW_NOTE,
    }
    return output


def _cap_identity_inline(output: dict[str, Any]) -> None:
    """Cap inline rows after persisting the full payload (lean tables, but a heavy
    device user or a multi-row host can still exceed the inline budget). Mutates in
    place — call only AFTER persisting."""
    for u in output["users"]:
        capped, truncated = _cap(u.get("devices", []), _MAX_ROWS_INLINE)
        u["devices"] = capped
        u["devices_truncated"] = truncated
    for h in output["hosts"]:
        capped, truncated = _cap(h.get("rows", []), _MAX_ROWS_INLINE)
        h["rows"] = capped
        h["truncated"] = truncated
        admins_capped, admins_truncated = _cap(h.get("local_admins", []), _MAX_ROWS_INLINE)
        h["local_admins"] = admins_capped
        h["local_admins_truncated"] = admins_truncated


def identity_assessment(
    case_id: str,
    users: list[str] | None = None,
    hosts: list[str] | None = None,
    cap: int = IDENTITY_DEFAULT_CAP,
    depth: str = "auto",
) -> dict[str, Any]:
    """Lean batch triage: classify users internal/external and pull device context.

    The cheap scoping step that runs BEFORE the heavy per-entity ``entity_context``
    pull — it decides which entities are worth the deeper look and brings the exact
    identity + managed-device context into session.

    Per user: one ``AzureActiveDirectory-Users`` query classifies them from
    authoritative directory data (``UserType`` / on-prem sync / ``#EXT#`` UPN), with
    an optional zero-request overlay against the client's configured
    ``identity.internal_domains``. Managed-device context (``Intune-ManagedDevices``)
    is pulled ONLY for users that resolve to a real non-guest record — guests and
    not-in-directory principals therefore cost a single query each. Per host: one
    ``Baseline-Core`` row reporting which platforms manage it.

    Soft cap (``cap``, default 5 per list): users/hosts beyond the cap are returned
    under ``not_assessed`` rather than queried. There is no hard ceiling — raise
    ``cap`` to assess more. Same scope gate as ``entity_context`` (pinned to the
    case's Encore client). Persists the full payload as a case artefact and appends
    a classification summary to the evidence chain.
    """
    client_name, internal_client_id = _resolve_case_client(case_id)
    output = {"case_id": case_id,
              **_assess_identities(client_name, internal_client_id, users, hosts,
                                   cap, depth, log_case_id=case_id)}

    stamp = utcnow().replace(":", "").replace("-", "").replace("T", "_").split(".")[0]
    save_json(CASES_DIR / case_id / "artefacts" / "eql_context"
              / f"identity_assessment_{stamp}.json", output)
    _cap_identity_inline(output)
    _append_identity_evidence(case_id, output)
    return output


def identity_scan(
    client_name: str,
    users: list[str] | None = None,
    hosts: list[str] | None = None,
    cap: int = IDENTITY_DEFAULT_CAP,
    depth: str = "auto",
) -> dict[str, Any]:
    """Caseless equivalent of ``identity_assessment`` — classify users internal vs
    external and pull device/host context WITHOUT a case, scoped to a client *by
    name*.

    Same scope gate as the case path (``resolve_client_by_name``: exact match, read
    access required — cross-client access is structurally impossible) and the
    identical classification engine. Persists the FULL payload to
    ``registry/eql_lookups/EQLID_<ts>.json`` (mirrors ``entity_lookup`` /
    ``vuln_hunt``). No evidence chain is written — there is no case yet. Promote into
    a case with ``import_eql_lookup`` / ``create_case(eql_lookup_id=...)``.
    """
    from config.settings import EQL_LOOKUP_DIR

    canonical, internal_client_id = resolve_client_by_name(client_name)
    lookup_id = (
        "EQLID_" + utcnow().replace("-", "").replace(":", "").replace("T", "_").split(".")[0]
    )
    output = {"lookup_id": lookup_id, "kind": "identity_scan",
              **_assess_identities(canonical, internal_client_id, users, hosts,
                                   cap, depth)}

    save_json(EQL_LOOKUP_DIR / f"{lookup_id}.json", output)
    _cap_identity_inline(output)
    return output


def _append_identity_evidence(case_id: str, output: dict[str, Any]) -> None:
    """Summarise the identity assessment into the case evidence chain."""
    from api.actions import add_evidence  # lazy: avoids import cycle

    s = output["summary"]
    lines = [
        f"**Encore EQL identity assessment** ({output['client']}, "
        f"client {output['internal_client_id']})",
        f"Users: {s['users_assessed']} assessed — internal {s['users_internal']}, "
        f"guest {s['users_external_guest']}, not-in-directory {s['users_not_in_directory']}"
        + (f", domain-mismatch {s['users_domain_mismatch']}" if s['users_domain_mismatch'] else "")
        + (f", capped {s['users_not_assessed_cap']}" if s['users_not_assessed_cap'] else ""),
        "",
    ]
    for u in output["users"]:
        bits = [f"- {u['upn']} → **{u['classification']}**"]
        if u.get("sync"):
            bits.append(f"({u['sync']})")
        if u.get("account_enabled") is False:
            bits.append("[disabled]")
        if u.get("domain_mismatch"):
            bits.append("[domain-mismatch]")
        if u["classification"] not in ("external_guest", "not_in_directory"):
            bits.append(f"— {u.get('device_count', 0)} managed device(s)")
        lines.append(" ".join(bits))
    if output["hosts"]:
        lines.append("")
        lines.append(f"Hosts: {s['hosts_assessed']} assessed — managed_asset {s['hosts_managed']}, "
                     f"known_unmanaged {s['hosts_known_unmanaged']}, "
                     f"not-in-directory {s['hosts_not_in_directory']}"
                     + (f", capped {s['hosts_not_assessed_cap']}"
                        if s['hosts_not_assessed_cap'] else ""))
        for h in output["hosts"]:
            mgd = ", ".join(h["managed_in"]) if h["managed_in"] else "no control plane"
            bits = [f"- {h['host']} → **{h['classification']}** ({mgd})"]
            if h["classification"] != "not_in_directory":
                bits.append(f"— {h.get('local_admin_count', 0)} local admin(s)")
            lines.append(" ".join(bits))
    if output["not_assessed"]["users"] or output["not_assessed"]["hosts"]:
        lines.append("")
        na = output["not_assessed"]
        lines.append("_Not assessed (cap reached — raise `cap` to include):_")
        if na["users"]:
            lines.append(f"- users: {', '.join(na['users'])}")
        if na["hosts"]:
            lines.append(f"- hosts: {', '.join(na['hosts'])}")
    lines.append("")
    lines.append("_" + output["_window_note"] + "_")
    try:
        add_evidence(case_id, "\n".join(lines))
    except Exception as exc:  # evidence note is best-effort, never fatal
        log_error(case_id, "eql.append_identity_evidence", str(exc), severity="warning")
        eprint(f"[eql] identity evidence note failed: {exc}")


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
            _apply_coverage(entry, rows, res["errors"])
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


# ---------------------------------------------------------------------------
# Caseless vulnerability hunt — proactive, client-scoped, no case required
# ---------------------------------------------------------------------------

def resolve_client_by_name(client_name: str) -> tuple[str, str]:
    """client name → (canonical_client_name, internal_client_id), CASELESS.

    Applies the SAME scope gate as the case-bound path via ``_resolve_encore_id``:
    the client must exist, have ``platforms.encore.internal_client_id`` and read
    access, else ``EqlNotConfigured`` is raised before any HTTP. Matches the
    client name OR a declared alias EXACTLY (never fuzzy/substring) — a wrong or
    partial name, or an ambiguous shared alias, must fail rather than silently
    resolve to a neighbouring client (cross-client leak risk; cf. the Sentinel
    workspace fallback). ``canonical`` is taken from the resolved entity, so an
    alias like ``"perf"`` reports back as ``"performanta"``.
    """
    name = (client_name or "").strip()
    if not name:
        raise EqlNotConfigured("client_name is required")
    internal_client_id = _resolve_encore_id(name)          # name/alias + scope gate
    cfg = _resolve_client_config(name) or {}
    canonical = cfg.get("name") or name
    return canonical, internal_client_id


def _truthy(v: Any) -> bool:
    return v in (True, "true", "True", 1, "1", "Yes", "yes")


def _vuln_hunt_summary(domains: list[dict[str, Any]]) -> dict[str, Any]:
    """Headline triage counts across the hunt domains (computed on FULL rows)."""
    by_table = {d["table"]: d.get("rows", []) for d in domains}
    hosts = by_table.get("VulnerabilityPrioritization-Hosts", [])
    vulns = by_table.get("VulnerabilityPrioritization-Vulnerabilities", [])
    kevs = by_table.get("VulnerabilityPrioritization-NewKevsIn48Hrs", [])
    return {
        "hosts_assessed": len(hosts),
        "hosts_with_active_exploit": sum(1 for h in hosts if _truthy(h.get("HasActiveExploit"))),
        "hosts_with_ransomware_exploit": sum(1 for h in hosts if _truthy(h.get("IsRansomwareExploit"))),
        "hosts_with_imminent_threats": sum(1 for h in hosts if _truthy(h.get("HasImminentThreats"))),
        "actively_exploited_cves": len(vulns),
        "new_kevs_48h": len(kevs),
    }


def vuln_hunt(client_name: str, depth: str = "auto") -> dict[str, Any]:
    """Proactive, CASELESS vulnerability hunt for a client.

    Runs the client-wide ``VULN_HUNT_TEMPLATES`` (exposed hosts + prioritised
    CVEs + newly-weaponised KEVs + EDR compensating-control tasks + environment
    exposure), each ranked by Encore's PrioritizationIndex. Persists the FULL
    payload to ``registry/vuln_hunts/VH_<ts>.json`` (mirrors quick_enrich) and
    returns it with inline rows capped to the top ``_MAX_ROWS_INLINE`` (rank
    preserved — NOT date-sorted; the full set is on disk). No case required;
    promote with ``import_vuln_hunt`` / ``create_case(vuln_hunt_id=...)``.
    """
    from config.settings import VULN_HUNT_DIR

    canonical, internal_client_id = resolve_client_by_name(client_name)

    started = time.time()
    domains: list[dict[str, Any]] = []
    for tpl in VULN_HUNT_TEMPLATES:
        q = _build_vuln_query(tpl)
        entry: dict[str, Any] = {"domain": tpl["domain"], "table": tpl["table"], "query": q}
        try:
            res = run_eql(internal_client_id, q, timeout=90)
            rows = res["rows"]
            entry["row_count"] = res["row_count"]
            entry["rows"] = rows
            entry["errors"] = res["errors"]
            entry["freshness"] = _freshness(rows)
            _apply_coverage(entry, rows, res["errors"])
        except EqlError as exc:
            # One bad table must not sink the whole hunt.
            entry["row_count"] = 0
            entry["rows"] = []
            entry["coverage"] = "query_error"
            entry["error"] = str(exc)
            log_error("", "eql.vuln_hunt", str(exc), severity="warning",
                      context={"table": tpl["table"], "client": canonical})
        domains.append(entry)

    hunt_id = f"VH_{utcnow().replace('-', '').replace(':', '').replace('T', '_').split('.')[0]}"
    output: dict[str, Any] = {
        "hunt_id": hunt_id,
        "client": canonical,
        "internal_client_id": internal_client_id,
        "ts": utcnow(),
        "depth": depth,
        "duration_ms": int((time.time() - started) * 1000),
        "summary": _vuln_hunt_summary(domains),   # computed on FULL rows
        "domains": domains,
        "_window_note": (
            "Vulnerability/exposure tables are ~daily snapshots ranked by Encore's "
            "PrioritizationIndex (highest first). Filter the exploit flags "
            "(HasActiveExploit / IsRansomwareExploit / HasImminentThreats / InKev) "
            "client-side — EQL rejects boolean WHERE. 'no_data_for_client' means the "
            "product is not ingested for this client — NOT evidence of zero exposure. "
            "For active-exploitation hunting, pivot the top CVEs/hosts into the live "
            "log layer (run_kql / run_defender_kql / run_falcon_cql) via the "
            "'vulnerability-hunting' playbook."
        ),
    }

    # Persist the FULL raw payload (nothing dropped on disk).
    save_json(VULN_HUNT_DIR / f"{hunt_id}.json", output)

    # Cap inline rows AFTER persisting — HEAD slice to preserve the
    # PrioritizationIndex ranking from the query (do NOT use _cap, which
    # re-sorts by date and would bury the highest-risk rows).
    for entry in domains:
        full = entry.get("rows", [])
        entry["rows"] = full[:_MAX_ROWS_INLINE]
        entry["rows_returned"] = len(entry["rows"])
        entry["truncated"] = len(full) > _MAX_ROWS_INLINE

    return output


def import_vuln_hunt(hunt_id: str, case_id: str) -> dict[str, Any]:
    """Promote a caseless vuln hunt into a case: copy the full hunt payload into
    the case's eql_context artefacts and append an evidence note. Mirrors
    ``import_enrichment``."""
    from config.settings import VULN_HUNT_DIR

    vh_path = VULN_HUNT_DIR / f"{hunt_id}.json"
    if not vh_path.exists():
        return {"error": f"Vuln hunt '{hunt_id}' not found."}
    hunt = load_json(vh_path)
    # Refuse to import a hunt scoped to a DIFFERENT client than the case.
    try:
        _assert_case_client_matches(case_id, hunt.get("internal_client_id", ""),
                                    hunt.get("client", ""))
    except EqlError as exc:
        return {"error": str(exc)}
    dest = CASES_DIR / case_id / "artefacts" / "eql_context" / f"vuln_hunt_{hunt_id}.json"
    save_json(dest, hunt)
    _append_vuln_hunt_evidence(case_id, hunt)
    return {
        "status": "imported",
        "hunt_id": hunt_id,
        "case_id": case_id,
        "client": hunt.get("client"),
        "artefact": str(dest),
        "summary": hunt.get("summary"),
    }


def _append_vuln_hunt_evidence(case_id: str, hunt: dict[str, Any]) -> None:
    """Summarise an imported vuln hunt into the case evidence chain."""
    from api.actions import add_evidence  # lazy: avoids import cycle

    s = hunt.get("summary") or {}
    lines = [
        f"**Encore EQL vulnerability hunt** ({hunt.get('client')}, "
        f"client {hunt.get('internal_client_id')}, hunt {hunt.get('hunt_id')})",
        "",
        f"- Hosts assessed: {s.get('hosts_assessed', 0)} "
        f"(active-exploit: {s.get('hosts_with_active_exploit', 0)}, "
        f"ransomware: {s.get('hosts_with_ransomware_exploit', 0)}, "
        f"imminent-threat: {s.get('hosts_with_imminent_threats', 0)})",
        f"- Actively-exploited CVEs affecting estate: {s.get('actively_exploited_cves', 0)}",
        f"- New KEVs (48h): {s.get('new_kevs_48h', 0)}",
        "",
        "_" + (hunt.get("_window_note") or "") + "_",
    ]
    try:
        add_evidence(case_id, "\n".join(lines))
    except Exception as exc:  # best-effort, never fatal
        log_error(case_id, "eql.append_vuln_hunt_evidence", str(exc), severity="warning")


def _resolve_case_client(case_id: str) -> tuple[str, str]:
    """case_id → (client_name, internal_client_id). Applies the scope gate."""
    meta_path = CASES_DIR / case_id / "case_meta.json"
    if not meta_path.exists():
        raise EqlError(f"case {case_id!r} not found ({meta_path})")
    client_name = (load_json(meta_path) or {}).get("client", "")
    if not client_name:
        raise EqlError(f"case {case_id!r} has no client set")
    return client_name, _resolve_encore_id(client_name)


def _assert_case_client_matches(
    case_id: str, payload_internal_client_id: Any, payload_client: Any
) -> tuple[str, str]:
    """Refuse to import caseless Encore data into a case scoped to a DIFFERENT
    client (cross-client leak guard).

    The Encore ``internal_client_id`` is the real scope boundary — two different
    clients always resolve to different ids, and an alias resolves to the same id
    as its canonical name. Returns the case's ``(client_name, internal_client_id)``
    on a match; raises ``EqlError`` on mismatch (or when the case client cannot be
    resolved / Encore-gated).
    """
    case_client, case_cid = _resolve_case_client(case_id)
    if str(payload_internal_client_id) != str(case_cid):
        raise EqlError(
            "client mismatch — refusing cross-client import. Source is scoped to "
            f"{payload_client!r} (Encore {payload_internal_client_id}); case "
            f"{case_id} is client {case_client!r} (Encore {case_cid})."
        )
    return case_client, case_cid


def import_eql_lookup(lookup_id: str, case_id: str) -> dict[str, Any]:
    """Promote a caseless EQL lookup (``entity_lookup`` or ``identity_scan``) into a
    case: copy the full payload into the case's eql_context artefacts and append the
    matching evidence note. Refuses if the lookup's client != the case's client.
    Mirrors ``import_vuln_hunt`` / ``import_enrichment``."""
    from config.settings import EQL_LOOKUP_DIR

    path = EQL_LOOKUP_DIR / f"{lookup_id}.json"
    if not path.exists():
        return {"error": f"EQL lookup '{lookup_id}' not found."}
    payload = load_json(path)
    # Refuse to import a lookup scoped to a DIFFERENT client than the case.
    try:
        _assert_case_client_matches(case_id, payload.get("internal_client_id", ""),
                                    payload.get("client", ""))
    except EqlError as exc:
        return {"error": str(exc)}

    kind = payload.get("kind", "entity_lookup")
    dest = (CASES_DIR / case_id / "artefacts" / "eql_context"
            / f"{kind}_{lookup_id}.json")
    save_json(dest, payload)

    # The evidence appenders read the case id off the payload — re-key for the case.
    payload_for_case = {"case_id": case_id, **payload}
    if kind == "identity_scan":
        _append_identity_evidence(case_id, payload_for_case)
    else:
        _append_evidence(case_id, payload_for_case)

    return {
        "status": "imported",
        "lookup_id": lookup_id,
        "kind": kind,
        "case_id": case_id,
        "client": payload.get("client"),
        "artefact": str(dest),
        "summary": payload.get("summary"),
    }


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
