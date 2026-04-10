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
import traceback as _tb
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import ipaddress as _ipaddress

from config.settings import AUDIT_LOG, CLIENT_ENTITIES, ERROR_LOG


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


def md_file_note(file_path) -> str:
    """Return a footer note pointing the analyst to the HTML report file.

    Appended to report responses so the analyst can open the file in a browser
    and copy formatted content directly.
    """
    html_path = str(file_path).replace(".md", ".html") if str(file_path).endswith(".md") else file_path
    return (
        f"\n\n---\n*HTML report: `{html_path}` — "
        f"open in a browser to copy with formatting.*"
    )


# ---------------------------------------------------------------------------
# Markdown → HTML conversion for report deliverables
# ---------------------------------------------------------------------------

_REPORT_CSS = """\
body {
    font-family: Arial, sans-serif;
    font-size: 16px;
    margin: 40px;
    line-height: 1.6;
    background: #0d1117;
    color: #e6edf3;
}
h1, h2, h3 {
    color: #58a6ff;
}
h1 {
    margin-bottom: 16px;
}
.meta {
    background: #161b22;
    padding: 14px;
    border-left: 4px solid #58a6ff;
    margin-bottom: 24px;
    border-radius: 6px;
    color: #c9d1d9;
}
.section {
    margin-bottom: 28px;
    background: #11161c;
    padding: 18px;
    border-radius: 8px;
    box-shadow: 0 0 0 1px #21262d;
}
ul, ol {
    padding-left: 22px;
}
li {
    margin-bottom: 8px;
}
code {
    background: #21262d;
    color: #f0883e;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: Consolas, monospace;
}
pre {
    background: #161b22;
    padding: 16px;
    border-radius: 6px;
    overflow-x: auto;
    margin: 12px 0;
    border: 1px solid #21262d;
}
pre code {
    background: none;
    color: #e6edf3;
    padding: 0;
}
strong {
    color: #ffffff;
}
em {
    color: #8b949e;
}
blockquote {
    border-left: 4px solid #58a6ff;
    padding: 10px 16px;
    margin: 12px 0;
    background: #161b22;
    color: #c9d1d9;
    border-radius: 0 6px 6px 0;
}
hr {
    border: none;
    border-top: 1px solid #21262d;
    margin: 24px 0;
}
a {
    color: #58a6ff;
    text-decoration: none;
}
a:hover {
    text-decoration: underline;
}
"""


_KV_HEADERS = {"field", "key", "property", "attribute", "name", "parameter",
               "value", "result", "detail", "details", "description", "setting"}


def _tables_to_bullets(md_text: str) -> str:
    """Convert markdown tables to bullet-point lists for cleaner HTML output.

    Rendering rules (2-column tables):
    - Generic key-value headers (Field/Value):  ``- **Case ID:** IV_CASE_002``
    - Label + description (first col is the key): ``- **Email logs** — confirms delivery``

    Multi-column tables:
    - ``- **Col A:** foo — **Col B:** bar``
    """
    lines = md_text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        # Detect table: line starts with | and has at least two |
        if stripped.startswith("|") and stripped.count("|") >= 3:
            # Collect the full table block
            table_lines: list[str] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            # Parse header row
            headers: list[str] = [
                c.strip() for c in table_lines[0].split("|")[1:-1]
            ]
            # Skip separator row (---|---), then process data rows
            data_start = 1
            if len(table_lines) > 1 and _re.match(
                r"^\|[\s\-:|]+\|$", table_lines[1]
            ):
                data_start = 2

            # Detect key-value pattern: exactly 2 columns with generic headers
            is_kv = (
                len(headers) == 2
                and headers[0].lower() in _KV_HEADERS
                and headers[1].lower() in _KV_HEADERS
            )

            # Two-column tables always render as label–description pairs
            is_two_col = len(headers) == 2

            for row_line in table_lines[data_start:]:
                cells = [c.strip() for c in row_line.split("|")[1:-1]]

                if is_kv and len(cells) >= 2 and cells[0]:
                    # Generic key-value: **CellA:** CellB
                    out.append(f"- **{cells[0]}:** {cells[1]}")
                elif is_two_col and len(cells) >= 2 and cells[0]:
                    # Label + description: **CellA** — CellB
                    out.append(f"- **{cells[0]}** — {cells[1]}")
                else:
                    parts: list[str] = []
                    for j, cell in enumerate(cells):
                        if not cell or cell == "—":
                            continue
                        hdr = headers[j] if j < len(headers) else ""
                        if hdr and hdr.lower() not in _KV_HEADERS and hdr != cell:
                            parts.append(f"**{hdr}:** {cell}")
                        else:
                            parts.append(cell)
                    if parts:
                        out.append(f"- {' — '.join(parts)}")
            out.append("")  # blank line after list
        else:
            out.append(line)
            i += 1
    return "\n".join(out)


def _wrap_sections(html_body: str) -> str:
    """Post-process converted HTML to wrap content in structured divs.

    - Detects metadata paragraphs (lines with **Key:** Value near the top)
      and wraps them in ``<div class="meta">``
    - Wraps each h2 section and its following content in ``<div class="section">``
    """
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html_body, "html.parser")

    # --- 1. Detect and wrap metadata block ---
    # Metadata is typically the first <p> after <h1> that contains multiple
    # <strong>Key:</strong> Value patterns (or an italic/em generation line)
    h1 = soup.find("h1")
    meta_candidates: list = []
    if h1:
        sib = h1.next_sibling
        while sib:
            # Skip bare strings / whitespace NavigableStrings
            if isinstance(sib, str):
                sib = sib.next_sibling
                continue
            tag_name = getattr(sib, "name", None)
            # Stop collecting at first heading
            if tag_name in ("h1", "h2", "h3"):
                break
            # Metadata paragraphs: contain <strong> with colon, OR are <em>/_
            if tag_name == "p":
                strongs = sib.find_all("strong")
                has_kv = any(":" in (s.get_text() or "") for s in strongs)
                is_italic = sib.find("em") and not strongs
                if has_kv or is_italic:
                    meta_candidates.append(sib)
                else:
                    break
            elif tag_name == "hr":
                meta_candidates.append(sib)
                # hr after metadata → include it then stop
                sib = sib.next_sibling
                break
            else:
                break
            sib = sib.next_sibling

    if meta_candidates:
        meta_div = soup.new_tag("div", attrs={"class": "meta"})
        # Insert meta div before the first candidate
        meta_candidates[0].insert_before(meta_div)
        for el in meta_candidates:
            # Convert **Key:** Value <p> tags to Key: Value <br> lines
            if getattr(el, "name", None) == "p":
                strongs = el.find_all("strong")
                if any(":" in (s.get_text() or "") for s in strongs):
                    # Rebuild as br-separated lines inside the meta div
                    from bs4 import NavigableString
                    for child in list(el.children):
                        meta_div.append(child.extract() if hasattr(child, "extract") else NavigableString(str(child)))
                    meta_div.append(soup.new_tag("br"))
                    el.decompose()
                else:
                    meta_div.append(el.extract())
            elif getattr(el, "name", None) == "hr":
                el.decompose()  # drop the hr, the meta div replaces it
            else:
                meta_div.append(el.extract())
        # Clean trailing <br> in meta div
        last = meta_div.contents[-1] if meta_div.contents else None
        if last and getattr(last, "name", None) == "br":
            last.decompose()

    # --- 2. Wrap h2 sections in <div class="section"> ---
    h2_tags = soup.find_all("h2")
    for h2 in h2_tags:
        section_div = soup.new_tag("div", attrs={"class": "section"})
        h2.insert_before(section_div)
        section_div.append(h2.extract())
        # Collect siblings until the next h1/h2 or end
        while True:
            sib = section_div.next_sibling
            if sib is None:
                break
            if isinstance(sib, str):
                if sib.strip():
                    section_div.append(sib.extract())
                else:
                    sib.extract()
                continue
            tag_name = getattr(sib, "name", None)
            if tag_name in ("h1", "h2"):
                break
            if tag_name == "div" and "section" in (sib.get("class") or []):
                break
            section_div.append(sib.extract())

    # --- 3. Wrap loose content after every h1 in a section div ---
    # This catches body text between h1 headings and the next h2/section.
    for h1_tag in soup.find_all("h1"):
        loose: list = []
        sib = h1_tag.next_sibling
        while sib:
            if isinstance(sib, str):
                if sib.strip():
                    loose.append(sib)
                sib = sib.next_sibling
                continue
            tag_name = getattr(sib, "name", None)
            if tag_name in ("h1", "h2") or (
                tag_name == "div" and ("section" in (sib.get("class") or [])
                                       or "meta" in (sib.get("class") or []))
            ):
                break
            loose.append(sib)
            sib = sib.next_sibling
        if loose:
            intro_div = soup.new_tag("div", attrs={"class": "section"})
            loose[0].insert_before(intro_div)
            for el in loose:
                intro_div.append(el.extract())

    return str(soup)


def markdown_to_html(md_text: str, title: str = "Report") -> str:
    """Convert markdown text to a styled HTML document.

    Tables are converted to bullet-point lists. The output uses a dark theme
    with structured ``<div class="meta">`` and ``<div class="section">``
    wrappers for clean copy/paste into email, ticketing, or wiki systems.
    """
    md_text = _tables_to_bullets(md_text)
    try:
        import markdown as _markdown
        body = _markdown.markdown(
            md_text,
            extensions=["fenced_code", "codehilite", "toc"],
            extension_configs={"codehilite": {"noclasses": True, "pygments_style": "monokai"}},
        )
    except ImportError:
        from html import escape
        body = f"<pre>{escape(md_text)}</pre>"

    body = _wrap_sections(body)

    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n<head>\n"
        "<meta charset=\"UTF-8\">\n"
        f"<title>{title}</title>\n"
        f"<style>\n{_REPORT_CSS}</style>\n"
        "</head>\n\n<body>\n\n"
        f"{body}\n\n"
        "</body>\n</html>\n"
    )


def write_report(dest: Path, md_text: str, title: str = "Report") -> dict:
    """Write a styled HTML report from markdown source.

    Writes only the HTML file (no separate .md). If *dest* ends with ``.md``
    it is automatically switched to ``.html``.

    Returns the standard manifest dict with the ``html_path`` key.
    """
    html_dest = dest.with_suffix(".html")
    html_text = markdown_to_html(md_text, title=title)
    manifest = write_artefact(html_dest, html_text)
    manifest["html_path"] = str(html_dest)
    return manifest


def defang_report(text: str, malicious_iocs: set[str] | None = None) -> str:
    """Defang all *malicious_iocs* wherever they appear in *text*.

    Only IOCs in the provided set are defanged — clean IOCs are left intact.
    Uses a single compiled regex pass for O(M) instead of O(N×M).
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
    return pattern.sub(lambda m: replacements[m.group(0)], text)


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
