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
    "google.de", "google.fr", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "googlesyndication.com",
    # YouTube / Consent
    "youtube.com", "youtu.be", "ytimg.com", "consent.youtube.com",
    # Web standards
    "w3.org", "ietf.org", "rfc-editor.org", "whatwg.org",
    # Microsoft (already in phishing allowlist; include here for IOC/crawl skip)
    "microsoft.com", "microsoftonline.com", "azure.com", "azure.net",
    "azurewebsites.net", "windows.com", "office.com", "live.com",
    "bing.com", "msn.com",
    # Apple
    "apple.com", "icloud.com",
    # Amazon / AWS (CDN / legitimate infra)
    "amazon.com", "amazonaws.com", "cloudfront.net",
    # Cloudflare
    "cloudflare.com", "cloudflare.net",
    # Developer platforms
    "github.com", "github.io", "githubusercontent.com", "githubassets.com",
    "stackoverflow.com", "stackexchange.com",
    # Reference / encyclopaedias
    "wikipedia.org", "wikimedia.org", "wikpedia.org",
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
})
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from config.settings import ALIAS_ENABLED, ALIAS_MAP_FILE, AUDIT_LOG, CLIENT_ENTITIES, ERROR_LOG

# Thread-safe lock for audit log appends (used when parallel agents write concurrently)
_audit_lock = threading.Lock()
_error_lock = threading.Lock()


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


def md_file_note(file_path) -> str:
    """Return a footer note pointing the analyst to the raw markdown file.

    Appended to report responses so the analyst can open the file in a text
    editor and copy clean markdown without HTML formatting bloat.
    """
    return (
        f"\n\n---\n*Markdown file: `{file_path}` — "
        f"open in a text editor to copy without formatting.*"
    )


def defang_report(text: str, malicious_iocs: set[str] | None = None) -> str:
    """Defang all *malicious_iocs* wherever they appear in *text*.

    Only IOCs in the provided set are defanged — clean IOCs are left intact.
    Replacements are applied longest-first to avoid partial matches.
    """
    if not malicious_iocs:
        return text
    for ioc in sorted(malicious_iocs, key=len, reverse=True):
        defanged = defang_ioc(ioc)
        if defanged != ioc:
            text = text.replace(ioc, defanged)
    return text


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


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def audit(action: str, path: str, sha256: str = "", extra: dict | None = None) -> None:
    """Append a single audit record to the audit log."""
    os.makedirs(Path(AUDIT_LOG).parent, exist_ok=True)
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
    traceback: str = "",
    context: dict | None = None,
) -> None:
    """Append a structured error record to registry/error_log.jsonl.

    Severity levels:
      error   — operation failed entirely
      warning — degraded operation (fallback triggered, single provider failed)
      info    — environment signal (optional import missing, cache miss)
    """
    os.makedirs(Path(ERROR_LOG).parent, exist_ok=True)
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
# Artefact writing helper
# ---------------------------------------------------------------------------

def write_artefact(dest: Path, data: bytes | str, encoding: str = "utf-8") -> dict:
    """
    Write *data* to *dest*, compute SHA-256, audit, and return a manifest dict.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode(encoding)
    dest.write_bytes(data)
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


def get_client_config(client_name: str) -> dict | None:
    """Look up a client's full configuration including platform scope.

    Returns a dict with 'name', 'alias', and 'platforms' (sentinel, xdr,
    crowdstrike, encore), or None if not found.  Handles both the new nested
    ``platforms.sentinel.workspace_id`` layout and the legacy flat
    ``workspace_id`` field.
    """
    from config.settings import CLIENT_ENTITIES

    try:
        entities = load_json(CLIENT_ENTITIES).get("clients", [])
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
# Client domain aliasing for data minimisation
# ---------------------------------------------------------------------------



class AliasMap:
    """Global bidirectional alias map for client name minimisation.

    Supports two kinds of entries:
    - **Roots**: a prefix (e.g. ``heidelberg``) with an alias word
      (``stonebridge``). Any domain name starting with the root is aliased:
      ``heidelbergmaterials.com`` → ``stonebridge-materials.com``.
    - **Names**: exact name → alias word (e.g. ``example-client`` → ``riverton``).

    TLDs and subdomains are preserved in both cases.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._roots: list[dict] = []          # [{"root": ..., "alias": ...}]
        self._names: dict[str, str] = {}      # real_name -> alias_word
        self._reverse_names: dict[str, str] = {}  # alias_word -> real_name

    # -- persistence --------------------------------------------------------

    def load(self) -> None:
        """Load from registry/alias_map.json."""
        try:
            data = load_json(ALIAS_MAP_FILE)
        except FileNotFoundError:
            return
        with self._lock:
            self._roots = data.get("roots", [])
            self._names = data.get("names", {})
            self._reverse_names = {v: k for k, v in self._names.items()}

    def save(self) -> None:
        """Persist to registry/alias_map.json. Audited."""
        with self._lock:
            data = {
                "version": 2,
                "roots": list(self._roots),
                "names": dict(self._names),
            }
        save_json(ALIAS_MAP_FILE, data)

    # -- registration -------------------------------------------------------

    def register_root(self, root: str, alias: str) -> None:
        """Register a hierarchical root prefix with its alias word."""
        root, alias = root.lower().strip(), alias.lower().strip()
        with self._lock:
            if any(r["root"] == root for r in self._roots):
                return
            self._roots.append({"root": root, "alias": alias})

    def register_name(self, name: str, alias: str) -> None:
        """Register an exact client name with its alias word."""
        name, alias = name.lower().strip(), alias.lower().strip()
        with self._lock:
            self._names[name] = alias
            self._reverse_names[alias] = name

    def register_from_config(self) -> None:
        """Bulk-register from config/client_entities.json."""
        try:
            data = load_json(CLIENT_ENTITIES)
        except FileNotFoundError:
            return
        for entry in data.get("clients", []):
            alias = entry.get("alias", "")
            if not alias or alias == "EDIT_ME":
                continue
            if entry.get("root"):
                self.register_root(entry["name"], alias)
            else:
                self.register_name(entry["name"], alias)
        self.save()

    # -- alias / dealias ----------------------------------------------------

    def alias_text(self, text: str) -> str:
        """Replace client names with aliases, preserving TLDs and subdomains."""
        with self._lock:
            roots = list(self._roots)
            names = dict(self._names)
        if not roots and not names:
            return text
        # Root pass — longest root first to avoid partial matches
        for entry in sorted(roots, key=lambda e: len(e["root"]), reverse=True):
            root, alias = entry["root"], entry["alias"]
            pat = _re.compile(
                r'(?<![a-zA-Z0-9])' + _re.escape(root) + r'([a-z]*)'
                + r'(?![a-zA-Z0-9])',
                _re.IGNORECASE,
            )
            def _root_repl(m, _alias=alias):
                suffix = m.group(1)
                if suffix:
                    return _alias + "-" + suffix
                return _alias
            text = pat.sub(_root_repl, text)
        # Exact name pass — longest first
        for name in sorted(names, key=len, reverse=True):
            alias = names[name]
            pat = _re.compile(
                r'(?<![a-zA-Z0-9])' + _re.escape(name)
                + r'(?![a-zA-Z0-9])',
                _re.IGNORECASE,
            )
            text = pat.sub(alias, text)
        return text

    def dealias_text(self, text: str) -> str:
        """Reverse: replace all aliases back to real client names."""
        with self._lock:
            roots = list(self._roots)
            reverse_names = dict(self._reverse_names)
        if not roots and not reverse_names:
            return text
        # Reverse root pass — longest alias first
        for entry in sorted(roots, key=lambda e: len(e["alias"]), reverse=True):
            root, alias = entry["root"], entry["alias"]
            pat = _re.compile(
                r'(?<![a-zA-Z0-9])' + _re.escape(alias)
                + r'(-[a-z]+)?'
                + r'(?![a-zA-Z0-9])',
                _re.IGNORECASE,
            )
            def _root_repl(m, _root=root):
                suffix = m.group(1)
                if suffix:
                    return _root + suffix[1:]   # strip leading dash
                return _root
            text = pat.sub(_root_repl, text)
        # Reverse exact name pass
        for alias_word in sorted(reverse_names, key=len, reverse=True):
            real_name = reverse_names[alias_word]
            pat = _re.compile(
                r'(?<![a-zA-Z0-9])' + _re.escape(alias_word)
                + r'(?![a-zA-Z0-9])',
                _re.IGNORECASE,
            )
            text = pat.sub(real_name, text)
        return text


# ---------------------------------------------------------------------------
# Model tiering — select the right Claude model per task and severity
# ---------------------------------------------------------------------------

_TIER_MAP = {
    "heavy": "SOCAI_MODEL_HEAVY",
    "standard": "SOCAI_MODEL_STANDARD",
    "fast": "SOCAI_MODEL_FAST",
}

_ESCALATE_TASKS = frozenset({
    "secarch", "report", "chat_response", "evtx", "fp_ticket", "fp_tuning_ticket",
})

_TIER_ORDER = ["fast", "standard", "heavy"]

# Thread-local override: when set, get_model() returns the fast model for ALL tasks.
# Used by the web UI to force Haiku during dev/testing.  Activate via
# force_fast_model() context manager — safe for concurrent requests.
_model_override = threading.local()


class force_fast_model:
    """Context manager that forces get_model() to return the fast-tier model.

    Usage (in web UI request handlers):
        with force_fast_model():
            result = some_tool_that_calls_get_model(...)
    """
    def __enter__(self):
        _model_override.active = True
        return self

    def __exit__(self, *exc):
        _model_override.active = False


def get_model(task: str, severity: str = "medium") -> str:
    """Return the Claude model string for *task*, optionally escalated by *severity*.

    Resolution order:
    0. If ``force_fast_model`` context is active, return the fast-tier model immediately
    1. ``SOCAI_MODEL_{TASK}`` setting (may be a tier name or full model string)
    2. Resolve tier name → model string via ``SOCAI_MODEL_{TIER}``
    3. If severity is high/critical AND task is in the escalation set, bump one tier
    4. Fall back to ``LLM_MODEL``
    """
    import config.settings as _s

    # 0. Thread-local override — web UI forces everything to fast tier
    if getattr(_model_override, "active", False):
        return _s.SOCAI_MODEL_FAST

    # 1. Look up task-specific setting
    attr = f"SOCAI_MODEL_{task.upper()}"
    raw = getattr(_s, attr, None) or ""

    # 2. Resolve tier name → model string (or pass through full model string)
    def _resolve(value: str) -> str:
        low = value.lower().strip()
        tier_attr = _TIER_MAP.get(low)
        if tier_attr:
            return getattr(_s, tier_attr, _s.LLM_MODEL)
        # Not a tier name — treat as a full model string if non-empty
        return value if value else _s.LLM_MODEL

    model = _resolve(raw) if raw else _s.LLM_MODEL
    resolved_tier = raw.lower().strip() if raw and raw.lower().strip() in _TIER_MAP else None

    # 3. Severity escalation
    if severity in ("high", "critical") and task.lower() in _ESCALATE_TASKS and resolved_tier:
        idx = _TIER_ORDER.index(resolved_tier) if resolved_tier in _TIER_ORDER else -1
        if 0 <= idx < len(_TIER_ORDER) - 1:
            bumped_tier = _TIER_ORDER[idx + 1]
            model = getattr(_s, _TIER_MAP[bumped_tier], model)

    return model


_alias_map_singleton: AliasMap | None = None
_alias_map_init_lock = threading.Lock()


def get_alias_map() -> AliasMap | None:
    """Return loaded AliasMap if SOCAI_ALIAS=1, else None. Singleton."""
    if not ALIAS_ENABLED:
        return None
    global _alias_map_singleton
    with _alias_map_init_lock:
        if _alias_map_singleton is None:
            _alias_map_singleton = AliasMap()
            _alias_map_singleton.load()
            _alias_map_singleton.register_from_config()
        return _alias_map_singleton
