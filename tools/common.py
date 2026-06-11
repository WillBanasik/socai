"""
Shared utilities: hashing, audit logging, artefact writing.
"""
# ---------------------------------------------------------------------------
# Known-clean domain skip list
# ---------------------------------------------------------------------------
# Domains that are inherently trustworthy infrastructure — crawling them during
# recursive capture or emitting their URLs/domains as IOCs creates noise and
# wastes enrichment API quota.  Subdomain matching applies everywhere this set
# is consumed (e.g. support.mozilla.org matches "mozilla.org").
KNOWN_CLEAN_DOMAINS: frozenset[str] = frozenset({
    # Browser / open-web vendors
    "mozilla.org", "firefox.com", "mozilla.net", "mozgcp.net",
    # Google / Alphabet
    "google.com", "google.co.uk", "google.com.au", "google.ca",
    "google.de", "google.fr", "gstatic.com",
    "googlesyndication.com",
    # YouTube / Consent
    "youtube.com", "youtu.be", "ytimg.com", "consent.youtube.com",
    # Web standards
    "w3.org", "ietf.org", "rfc-editor.org", "whatwg.org",
    # Microsoft (already in phishing allowlist; include here for IOC/crawl skip)
    "microsoft.com", "microsoftonline.com", "azure.com", "azure.net",
    "windows.com", "office.com", "live.com",
    "bing.com", "msn.com",
    # Apple
    "apple.com", "icloud.com",
    # Amazon (corporate apex only — AWS-hosted content is user-controlled)
    "amazon.com",
    # Cloudflare
    "cloudflare.com", "cloudflare.net",
    # Developer platforms
    "github.com", "githubassets.com",
    "stackoverflow.com", "stackexchange.com",
    # Reference / encyclopaedias ("wikpedia.org" typosquat removed — it was
    # allowlisting an unregistered-lookalike domain as clean)
    "wikipedia.org", "wikimedia.org",
    # News / major media (often crawled via link-following)
    "washingtonpost.com", "nytimes.com", "bbc.com", "bbc.co.uk",
    "theguardian.com", "reuters.com",
    # Schema / structured data
    "schema.org", "json-ld.org",
    # Common CDNs
    "jquery.com", "bootstrapcdn.com", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net",
    # Social media (main domains — NOT link shorteners or hosting sub-services)
    "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
    "reddit.com", "pinterest.com", "tiktok.com",
    # Enterprise / SaaS vendors (corporate domains, not user-hosting)
    "salesforce.com", "cisco.com", "oracle.com", "ibm.com", "intel.com",
    "vmware.com", "dell.com", "hp.com", "hpe.com", "sap.com",
    "adobe.com", "autodesk.com", "atlassian.com",
    "zoom.us", "zoom.com", "slack.com", "okta.com", "crowdstrike.com",
    "paloaltonetworks.com", "fortinet.com", "zscaler.com",
    "splunk.com", "elastic.co", "datadog.com", "sentinelone.com",
    # Collaboration / comms (corporate domains only — NOT file-sharing endpoints)
    "teams.microsoft.com",
    # Payment / finance
    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    # DNS / registrars
    "godaddy.com", "namecheap.com", "cloudflare-dns.com",
    "opendns.com", "quad9.net",
    # Security vendor / threat intel reference sites
    "virustotal.com", "hybrid-analysis.com", "any.run",
    "urlscan.io", "shodan.io", "abuseipdb.com",
    "mitre.org", "attack.mitre.org", "cve.org", "nvd.nist.gov",
    # OS / package repos
    "debian.org", "ubuntu.com", "fedoraproject.org",
    "pypi.org", "npmjs.com", "crates.io", "rubygems.org",
    "nuget.org", "packagist.org", "maven.org",
    # NOTE: Deliberately excluded — hosting/document sites attackers abuse:
    #   dropbox.com, box.com, sharepoint.com, onedrive.live.com,
    #   notion.so, airtable.com, canva.com, trello.com,
    #   firebase.google.com, netlify.app, vercel.app, heroku.com,
    #   pastebin.com, ghostbin.com, transfer.sh, wetransfer.com,
    #   discord.com (CDN abuse), telegram.org
    # Same reason — shared cloud hosting where anyone can serve content under
    # the vendor's domain (phish on phish.s3.amazonaws.com must NOT be
    # auto-cleared):
    #   amazonaws.com, cloudfront.net, azurewebsites.net, googleapis.com,
    #   googleusercontent.com, github.io, githubusercontent.com
})
import hashlib
import json
import os
import threading
import traceback as _tb
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import ipaddress as _ipaddress

from config.settings import AUDIT_LOG, ERROR_LOG


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is a private/reserved/loopback address."""
    try:
        return _ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return False

# Thread-safe lock for audit log appends (used when parallel agents write concurrently)
_audit_lock = threading.Lock()
_error_lock = threading.Lock()

# Once-only makedirs guards — avoids redundant syscalls on every log append
_dirs_ensured: set[str] = set()


# ---------------------------------------------------------------------------
# Pooled HTTP session factory (per-thread, with connection reuse & retry)
# ---------------------------------------------------------------------------

_thread_local = threading.local()

_RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[502, 503, 504],
    allowed_methods=["GET", "HEAD", "OPTIONS"],
    raise_on_status=False,
)

_POOL_CONNECTIONS = 20  # max host pools kept alive
_POOL_MAXSIZE = 20      # max connections per host pool


def get_session() -> requests.Session:
    """Return a per-thread ``requests.Session`` with connection pooling and retry.

    Sessions are cached on ``threading.local()`` so each thread reuses its own
    session across calls — no cookie/header leakage between threads.  Retries
    are limited to GET/HEAD/OPTIONS to avoid duplicating non-idempotent POSTs.
    """
    session: requests.Session | None = getattr(_thread_local, "session", None)
    if session is not None:
        return session
    session = requests.Session()
    adapter = HTTPAdapter(
        max_retries=_RETRY_STRATEGY,
        pool_connections=_POOL_CONNECTIONS,
        pool_maxsize=_POOL_MAXSIZE,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    _thread_local.session = session
    return session


def get_opsec_session() -> requests.Session:
    """Return a per-thread ``requests.Session`` routed through the OPSEC proxy.

    Falls back to a normal session if ``SOCAI_OPSEC_PROXY`` is not set.
    Use this for attacker-facing traffic (web captures, OSINT searches).
    """
    session: requests.Session | None = getattr(_thread_local, "opsec_session", None)
    if session is not None:
        return session
    from config.settings import OPSEC_PROXY
    session = requests.Session()
    adapter = HTTPAdapter(
        max_retries=_RETRY_STRATEGY,
        pool_connections=_POOL_CONNECTIONS,
        pool_maxsize=_POOL_MAXSIZE,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if OPSEC_PROXY:
        session.proxies = {"http": OPSEC_PROXY, "https": OPSEC_PROXY}
    _thread_local.opsec_session = session
    return session


# ---------------------------------------------------------------------------
# IOC defanging — sanitise malicious indicators in customer-facing reports
# ---------------------------------------------------------------------------

import re as _re

def defang_ioc(value: str) -> str:
    """Defang a single IOC string: domains, IPs, URLs."""
    # URLs: http:// -> hxxp://, https:// -> hxxps://
    s = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    s = s.replace("HTTP://", "hxxp://").replace("HTTPS://", "hxxps://")
    # Dots in domains/IPs -> [.]  (skip if already defanged)
    # Only defang if it looks like a domain or IP (not a file path or hash)
    if "[.]" not in s and not s.startswith("\\") and not s.startswith("/"):
        if _re.search(r"[a-zA-Z0-9]\.[a-zA-Z]{2,}", s) or _re.search(r"\d+\.\d+\.\d+\.\d+", s):
            s = s.replace(".", "[.]")
    return s




def _is_fs_path_token(token: str) -> bool:
    """True when *token* looks like a filesystem path (never defanged).

    Web-capture artefacts live under domain-named directories
    (``artefacts/web/<domain>/``), so a blind substring defang turned every
    Artefact Index entry into a nonexistent path. URLs (``scheme://``) are
    explicitly NOT paths — they must still be defanged.
    """
    t = token.strip("\"'`<>()[]{},;*")
    if "://" in t:
        return False
    return (
        t.startswith(("/", "./", "~/"))
        or "cases/" in t or "artefacts/" in t or "reports/" in t
        or _re.match(r"^[A-Za-z]:\\", t) is not None
    )


def defang_report(text: str, malicious_iocs: set[str] | None = None) -> str:
    """Defang all *malicious_iocs* wherever they appear in *text*.

    Only IOCs in the provided set are defanged — clean IOCs are left intact.
    Matches inside filesystem-path tokens (artefact paths) are skipped:
    hashes and file paths are never defanged. Uses a single compiled regex
    pass for O(M) instead of O(N×M).
    """
    if not malicious_iocs:
        return text

    # Build replacement map: original → defanged (longest-first for regex)
    replacements: dict[str, str] = {}
    for ioc in malicious_iocs:
        defanged = defang_ioc(ioc)
        if defanged != ioc:
            replacements[ioc] = defanged

    if not replacements:
        return text

    # Build single regex pattern with alternation, longest-first
    pattern = _re.compile(
        "|".join(_re.escape(k) for k in sorted(replacements, key=len, reverse=True))
    )

    def _replace(m: "_re.Match[str]") -> str:
        s, start, end = m.string, m.start(), m.end()
        ts = start
        while ts > 0 and not s[ts - 1].isspace():
            ts -= 1
        te = end
        while te < len(s) and not s[te].isspace():
            te += 1
        if _is_fs_path_token(s[ts:te]):
            return m.group(0)
        return replacements[m.group(0)]

    return pattern.sub(_replace, text)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_file(path: Path | str) -> str:
    """Return hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_str(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def eprint(*args, **kwargs) -> None:
    """print() to stderr. Use for progress/status — stdout is the JSON-RPC channel in stdio MCP mode."""
    import sys
    kwargs.setdefault("file", sys.stderr)
    kwargs.setdefault("flush", True)
    print(*args, **kwargs)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def _ensure_dir(p: Path | str) -> None:
    """Create parent directory once per path (skips redundant syscalls)."""
    key = str(p)
    if key not in _dirs_ensured:
        os.makedirs(Path(p).parent, exist_ok=True)
        _dirs_ensured.add(key)


def audit(action: str, path: str, sha256: str = "", extra: dict | None = None) -> None:
    """Append a single audit record to the audit log."""
    _ensure_dir(AUDIT_LOG)
    record = {
        "ts": utcnow(),
        "action": action,
        "path": str(path),
        "sha256": sha256,
    }
    if extra:
        record.update(extra)
    with _audit_lock:
        with open(AUDIT_LOG, "a") as fh:
            fh.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Error log
# ---------------------------------------------------------------------------

def log_error(
    case_id: str,
    step: str,
    error: str,
    *,
    severity: str = "error",
    traceback: str | bool = "",
    context: dict | None = None,
) -> None:
    """Append a structured error record to registry/error_log.jsonl.

    Severity levels:
      error   — operation failed entirely
      warning — degraded operation (fallback triggered, single provider failed)
      info    — environment signal (optional import missing, cache miss)

    ``traceback`` accepts a string (explicit traceback text) or ``True``
    to auto-capture the current exception traceback.
    """
    _ensure_dir(ERROR_LOG)
    if traceback is True:
        traceback = _tb.format_exc() or ""
    record: dict = {
        "ts": utcnow(),
        "case_id": case_id,
        "step": step,
        "severity": severity,
        "error": error,
    }
    if traceback:
        record["traceback"] = traceback
    if context:
        record["context"] = context
    with _error_lock:
        with open(ERROR_LOG, "a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")


# ---------------------------------------------------------------------------
# Metrics log
# ---------------------------------------------------------------------------

_metrics_lock = threading.Lock()


def log_metric(event: str, *, case_id: str = "", **fields) -> None:
    """Append a structured metric record to registry/metrics.jsonl.

    Parameters
    ----------
    event : str
        Metric event type.  One of: case_phase_change, enrichment_complete,
        verdict_scored, report_saved, investigation_summary.
    case_id : str
        Case ID (empty for system-level metrics).
    **fields
        Arbitrary key-value pairs specific to the event type.
    """
    from config.settings import METRICS_LOG
    _ensure_dir(METRICS_LOG)
    record: dict = {"ts": utcnow(), "event": event}
    if case_id:
        record["case_id"] = case_id
    record.update(fields)
    with _metrics_lock:
        with open(METRICS_LOG, "a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")


# ---------------------------------------------------------------------------
# Pipeline progress tracking (crash-recoverable state per case)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Artefact writing helper
# ---------------------------------------------------------------------------

def write_artefact(dest: Path, data: bytes | str, encoding: str = "utf-8") -> dict:
    """
    Write *data* to *dest*, compute SHA-256, audit, and return a manifest dict.

    Uses atomic write (tmp + os.replace) to prevent corruption on crash.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode(encoding)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, dest)
    digest = sha256_bytes(data)
    audit("write_artefact", str(dest), sha256=digest)
    return {
        "path": str(dest),
        "sha256": digest,
        "size_bytes": len(data),
        "ts": utcnow(),
    }


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def load_json(path: Path | str) -> dict | list:
    with open(path) as fh:
        return json.load(fh)


_client_entities_cache: dict = {"mtime": 0.0, "data": []}

def get_client_config(client_name: str) -> dict | None:
    """Look up a client's full configuration including platform scope.

    Returns a dict with 'name' and 'platforms' (sentinel, xdr,
    crowdstrike, encore), or None if not found.  Handles both the new nested
    ``platforms.sentinel.workspace_id`` layout and the legacy flat
    ``workspace_id`` field.
    """
    from config.settings import CLIENT_ENTITIES

    try:
        # Mtime-based cache — reload only when file changes
        stat_mtime = CLIENT_ENTITIES.stat().st_mtime if CLIENT_ENTITIES.exists() else 0.0
        if stat_mtime != _client_entities_cache["mtime"]:
            _client_entities_cache["data"] = load_json(CLIENT_ENTITIES).get("clients", [])
            _client_entities_cache["mtime"] = stat_mtime
        entities = _client_entities_cache["data"]
    except (FileNotFoundError, json.JSONDecodeError):
        return None

    for ent in entities:
        if ent.get("name", "").lower() == client_name.lower():
            # Normalise: if legacy flat workspace_id, nest under platforms
            if "platforms" not in ent and ent.get("workspace_id"):
                ent["platforms"] = {
                    "sentinel": {"workspace_id": ent["workspace_id"]}
                }
            return ent

    return None


def save_json(path: Path | str, data: dict | list, indent: int = 2) -> dict:
    path = Path(path)
    raw = json.dumps(data, indent=indent, default=str).encode()
    return write_artefact(path, raw)



# ---------------------------------------------------------------------------
# Model tiering removed — all LLM reasoning handled by local Claude Desktop
# agent via MCP prompts.  get_model() and related config no longer exist.
# ---------------------------------------------------------------------------
