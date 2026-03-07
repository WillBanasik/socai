"""Parse freeform analyst input into structured investigation parameters."""
from __future__ import annotations

import re

# Reuse IOC patterns from extract_iocs (copied to avoid import side-effects)
_RE_URL = re.compile(
    r"(?:hxxps?|https?)://[^\s\"'<>\[\]]{4,}",
    re.IGNORECASE,
)
_RE_DEFANGED_URL = re.compile(
    r"hxxps?://[^\s\"'<>\[\]]{4,}",
    re.IGNORECASE,
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|uk|co|gov|edu|info|biz|xyz|top|online|site|store|"
    r"tech|app|dev|cloud|digital|media|ru|cn|de|fr|nl|za|"
    r"onion|icu|live|click|link|fun|shop|work|space|"
    r"pro|ltd|sbs|cyou|buzz|quest|cfd)\b",
    re.IGNORECASE,
)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b"
)
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_EMAIL_IOC = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_SEVERITY_KEYWORDS = {
    "critical": ["critical", "p1", "sev1", "emergency", "urgent"],
    "high": ["high", "p2", "sev2", "severe", "dangerous", "malware", "ransomware", "compromise"],
    "medium": ["medium", "p3", "sev3", "moderate", "suspicious", "phishing"],
    "low": ["low", "p4", "sev4", "benign", "informational", "false positive"],
}


def refang(text: str) -> str:
    """Undo common IOC defanging."""
    text = text.replace("hxxps://", "https://").replace("hxxp://", "http://")
    text = text.replace("[.]", ".").replace("[:]", ":").replace("(.)", ".")
    return text


def parse_analyst_input(text: str) -> dict:
    """
    Extract structured investigation parameters from freeform text.

    Returns dict with:
      urls, domains, ips, hashes, emails, cves, severity, context_lines
    """
    # Work with a refanged copy for extraction, keep original for context
    clean = refang(text)

    urls = list(dict.fromkeys(_RE_URL.findall(clean)))  # dedupe, preserve order
    domains = list(dict.fromkeys(_RE_DOMAIN.findall(clean)))
    ips = list(dict.fromkeys(_RE_IPV4.findall(clean)))
    md5s = list(dict.fromkeys(_RE_MD5.findall(clean)))
    sha1s = list(dict.fromkeys(_RE_SHA1.findall(clean)))
    sha256s = list(dict.fromkeys(_RE_SHA256.findall(clean)))
    emails = list(dict.fromkeys(_RE_EMAIL_IOC.findall(clean)))
    cves = list(dict.fromkeys(_RE_CVE.findall(clean)))

    # Remove domains that are just hostnames from extracted URLs
    url_hosts = set()
    for u in urls:
        try:
            import urllib.parse
            h = urllib.parse.urlparse(u).hostname
            if h:
                url_hosts.add(h.lower())
        except Exception:
            pass
    domains = [d for d in domains if d.lower() not in url_hosts]

    # Filter private IPs
    private = [re.compile(r"^10\."), re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
               re.compile(r"^192\.168\."), re.compile(r"^127\.")]
    ips = [ip for ip in ips if not any(p.match(ip) for p in private)]

    # Detect severity from keywords
    severity = "medium"
    text_lower = text.lower()
    for sev, keywords in _SEVERITY_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            severity = sev
            break

    # Build context: lines that aren't purely IOCs (analyst notes)
    context_lines = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        # Skip lines that are just a URL or hash
        if _RE_URL.fullmatch(stripped) or _RE_DEFANGED_URL.fullmatch(stripped):
            continue
        if _RE_SHA256.fullmatch(stripped) or _RE_SHA1.fullmatch(stripped) or _RE_MD5.fullmatch(stripped):
            continue
        context_lines.append(stripped)

    # Bare domains without schema → convert to URLs for investigation
    for d in domains:
        urls.append(f"https://{d}")

    hashes = md5s + sha1s + sha256s

    return {
        "urls": urls or None,
        "ips": ips or None,
        "hashes": hashes or None,
        "emails": emails or None,
        "cves": cves or None,
        "severity": severity,
        "context": "\n".join(context_lines) if context_lines else "",
    }


def build_title(parsed: dict, text: str) -> str:
    """Generate a concise investigation title from parsed input."""
    # Use first context line if available
    context = parsed.get("context", "")
    if context:
        first_line = context.split("\n")[0][:120]
        if len(first_line) > 10:
            return first_line

    # Fallback: describe what was found
    parts = []
    if parsed.get("urls"):
        parts.append(f"{len(parsed['urls'])} URL(s)")
    if parsed.get("hashes"):
        parts.append(f"{len(parsed['hashes'])} hash(es)")
    if parsed.get("ips"):
        parts.append(f"{len(parsed['ips'])} IP(s)")
    if parsed.get("emails"):
        parts.append(f"{len(parsed['emails'])} email(s)")
    if parsed.get("cves"):
        parts.append(f"{len(parsed['cves'])} CVE(s)")
    return "Investigation: " + ", ".join(parts) if parts else "Investigation"
