"""
tool: extract_iocs
------------------
Extracts Indicators of Compromise from text artefacts:
  - IPv4 addresses (excluding RFC-1918 / loopback unless --include-private)
  - Domains / FQDNs
  - URLs
  - MD5 / SHA-1 / SHA-256 hashes
  - Email addresses
  - CVE identifiers

Reads every .txt / .html / .strings.txt file under
cases/<case_id>/artefacts/ and writes:
  cases/<case_id>/iocs/iocs.json
  cases/<case_id>/iocs/iocs_summary.txt
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import KNOWN_CLEAN_DOMAINS, log_error, utcnow, write_artefact

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Reject octets with leading zeros (e.g. 002, 012) — not valid in dotted-decimal
# notation and typically arise from document text, not real network addresses.
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|uk|co|gov|edu|info|biz|xyz|top|online|site|store|"
    r"tech|app|dev|cloud|digital|media|news|agency|ru|cn|de|fr|nl|be|au|ca|"
    r"jp|br|in|sg|ph|id|za|mx|ar|cl|pe|vc|cc|pw|tk|ga|ml|cf|gq|md|"
    r"bg|es|it|pt|pl|cz|ro|hu|hr|rs|ua|kz|tr|ke|ng|eg|ae|il|kr|tw|"
    r"th|vn|my|nz|se|no|dk|fi|at|ch|ie|lt|lv|ee|sk|si|gr|cy|"
    r"onion|local|internal|icu|live|click|link|pw|fun|shop|work|space|"
    r"monster|beauty|bar|hair|skin|makeup|lol|world|today|"
    r"pro|ltd|sbs|cyou|buzz|quest|cfd)\b",
    re.IGNORECASE,
)
_RE_URL = re.compile(
    r"https?://[^\s\"'<>\[\]]{4,}",
    re.IGNORECASE,
)
_RE_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_EMAIL  = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_RE_CVE    = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^::1$"),
]

_NOISE_DOMAINS: frozenset[str] = frozenset({
    "example.com", "localhost", "test.com", "domain.com",
    "openssl.org",
}) | KNOWN_CLEAN_DOMAINS


def _domain_from_url(url: str) -> str:
    """Return the hostname from a URL, or '' on failure."""
    try:
        import urllib.parse
        return urllib.parse.urlparse(url).hostname or ""
    except Exception as exc:
        log_error("", "extract_iocs.domain_from_url", str(exc),
                  severity="warning", context={"url": url[:200]})
        return ""


def _hostname_is_noise(hostname: str) -> bool:
    """Return True if hostname is or is a subdomain of any noise/known-clean domain."""
    h = hostname.lower()
    for d in _NOISE_DOMAINS:
        if h == d or h.endswith("." + d):
            return True
    return False


def _read_file_text(fp: Path) -> str:
    """Read text from a file, with PDF support via pymupdf."""
    if fp.suffix.lower() == ".pdf":
        try:
            import fitz  # pymupdf
            doc = fitz.open(str(fp))
            return "\n".join(page.get_text() for page in doc)
        except Exception as exc:
            log_error("", "extract_iocs.read_pdf", str(exc),
                      severity="warning", context={"file": str(fp)})
            return ""
    return fp.read_text(errors="ignore")


def _is_private_ip(ip: str) -> bool:
    return any(r.match(ip) for r in _PRIVATE_RANGES)


def _extract_from_text(text: str, include_private: bool = False) -> dict:
    iocs: dict[str, set] = {
        "ipv4": set(),
        "domain": set(),
        "url": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
        "email": set(),
        "cve": set(),
    }

    # URLs first (superset of domains/IPs)
    for url in _RE_URL.findall(text):
        url = url.rstrip(".,;'\")")
        # Strip trailing unbalanced closing parens (e.g. markdown links)
        while url.endswith(")") and url.count("(") < url.count(")"):
            url = url[:-1]
        # Skip HTML-entity-contaminated matches (JS data blobs)
        if "&quot;" in url or "&amp;" in url or "&lt;" in url or "&gt;" in url:
            continue
        # Skip URLs from known-clean infrastructure domains
        if _hostname_is_noise(_domain_from_url(url)):
            continue
        iocs["url"].add(url)

    for ip in _RE_IPV4.findall(text):
        if include_private or not _is_private_ip(ip):
            iocs["ipv4"].add(ip)

    for dom in _RE_DOMAIN.findall(text):
        dom_lower = dom.lower().rstrip(".")
        if not _hostname_is_noise(dom_lower):
            iocs["domain"].add(dom_lower)

    # Hashes (longest first to avoid subset matches)
    for h in _RE_SHA256.findall(text):
        iocs["sha256"].add(h.lower())
    for h in _RE_SHA1.findall(text):
        if h.lower() not in iocs["sha256"]:
            iocs["sha1"].add(h.lower())
    for h in _RE_MD5.findall(text):
        if h.lower() not in iocs["sha256"] and h.lower() not in iocs["sha1"]:
            iocs["md5"].add(h.lower())

    for e in _RE_EMAIL.findall(text):
        iocs["email"].add(e.lower())
    for c in _RE_CVE.findall(text):
        iocs["cve"].add(c.upper())

    return {k: sorted(v) for k, v in iocs.items()}


def _merge(base: dict, additions: dict) -> None:
    for k, vals in additions.items():
        base.setdefault(k, [])
        for v in vals:
            if v not in base[k]:
                base[k].append(v)


def extract_iocs(
    case_id: str,
    extra_paths: list[str] | None = None,
    include_private: bool = False,
) -> dict:
    """
    Scan artefact text files in the case and write iocs.json.
    *extra_paths*: additional files to scan beyond the artefacts folder.
    """
    case_dir = CASES_DIR / case_id
    artefacts_dir = case_dir / "artefacts"
    iocs_dir = case_dir / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)

    combined: dict[str, list] = {
        "ipv4": [], "domain": [], "url": [],
        "md5": [], "sha1": [], "sha256": [],
        "email": [], "cve": [],
    }
    sources: list[dict] = []

    scan_paths: list[Path] = []
    logs_dir = case_dir / "logs"
    notes_dir = case_dir / "notes"
    for search_dir in (artefacts_dir, logs_dir, notes_dir):
        if search_dir.exists():
            for ext in ("*.txt", "*.html", "*.strings.txt", "*.csv", "*.json", "*.log", "*.ps1", "*.vbs", "*.js", "*.bat", "*.cmd", "*.pdf", "*.md"):
                scan_paths.extend(search_dir.rglob(ext))
    if extra_paths:
        scan_paths.extend(Path(p) for p in extra_paths)

    for fp in scan_paths:
        try:
            text = _read_file_text(fp)
            found = _extract_from_text(text, include_private=include_private)
            _merge(combined, found)
            total = sum(len(v) for v in found.values())
            if total:
                sources.append({"file": str(fp), "ioc_count": total})
        except Exception as e:
            log_error(case_id, "extract_iocs.scan_file", str(e),
                      severity="warning", context={"file": str(fp)})
            sources.append({"file": str(fp), "error": str(e)})

    # Annotate plain HTTP URLs (no TLS)
    combined["_http_urls"] = [u for u in combined.get("url", []) if u.startswith("http://")]

    result = {
        "case_id": case_id,
        "ts": utcnow(),
        "total": {k: len(v) for k, v in combined.items()},
        "iocs": combined,
        "sources": sources,
    }

    write_artefact(iocs_dir / "iocs.json", json.dumps(result, indent=2))

    # Human-readable summary
    lines = [f"IOC Summary – Case {case_id}", "=" * 50, ""]
    for ioc_type, vals in combined.items():
        if vals:
            lines.append(f"{ioc_type.upper()} ({len(vals)})")
            for v in vals[:50]:
                lines.append(f"  {v}")
            if len(vals) > 50:
                lines.append(f"  ... and {len(vals)-50} more")
            lines.append("")
    write_artefact(iocs_dir / "iocs_summary.txt", "\n".join(lines))
    print(f"[extract_iocs] Extracted IOCs from {len(sources)} source(s) for case {case_id}")
    return result


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Extract IOCs from case artefacts.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--include-private", action="store_true")
    args = p.parse_args()

    result = extract_iocs(args.case_id, include_private=args.include_private)
    print(json.dumps(result, indent=2))
