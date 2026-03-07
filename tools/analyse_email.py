"""
tool: analyse_email
-------------------
Parses .eml files (RFC 5322) and extracts security-relevant information:
  - Headers: From, Reply-To, Return-Path, Received chain, X-Mailer, Message-ID
  - Authentication results: SPF, DKIM, DMARC
  - Spoofing indicators: From/Reply-To mismatch, display name email mismatch,
    homoglyph domains
  - URLs from HTML body parts
  - Attachments with SHA-256 hashes

Writes:
  cases/<case_id>/artefacts/email/email_analysis.json
  cases/<case_id>/artefacts/email/attachments/<filename>
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import html.parser
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import audit, log_error, save_json, sha256_bytes, utcnow, write_artefact


# ---------------------------------------------------------------------------
# Homoglyph map (Cyrillic/Latin substitution for brand impersonation)
# ---------------------------------------------------------------------------
_HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0501": "d", "\u051b": "q",
    "\u0261": "g", "\u1d04": "c", "\u1d0f": "o", "\u1d1c": "u",
    "\u0251": "a", "\u025b": "e",
}

# Brand domains for homoglyph comparison
_BRAND_DOMAINS: list[str] = [
    "microsoft.com", "google.com", "apple.com", "paypal.com",
    "amazon.com", "facebook.com", "linkedin.com", "dropbox.com",
    "adobe.com", "netflix.com", "zoom.us", "docusign.com",
    "salesforce.com", "outlook.com", "office.com",
]


def _normalise_homoglyphs(text: str) -> str:
    """Replace known homoglyph characters with ASCII equivalents."""
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def _check_homoglyph_domain(domain: str) -> str | None:
    """Return the impersonated brand domain if homoglyphs are detected, else None."""
    normalised = _normalise_homoglyphs(domain.lower())
    if normalised == domain.lower():
        return None  # No substitutions made
    for brand_domain in _BRAND_DOMAINS:
        if normalised == brand_domain or normalised.endswith("." + brand_domain):
            return brand_domain
    return None


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------

class _LinkExtractor(html.parser.HTMLParser):
    """Extract href values from HTML."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)


def _extract_urls_from_html(html_text: str) -> list[str]:
    """Extract URLs from HTML content via parser + regex fallback."""
    urls: set[str] = set()

    # HTML parser for <a href="...">
    try:
        parser = _LinkExtractor()
        parser.feed(html_text)
        for link in parser.links:
            if link.startswith(("http://", "https://")):
                urls.add(link)
    except Exception as exc:
        log_error("", "analyse_email.extract_urls_html", str(exc), severity="warning",
                  context={"html_length": len(html_text)})

    # Regex fallback for URLs in text
    for m in re.finditer(r'https?://[^\s<>"\']+', html_text):
        urls.add(m.group(0).rstrip(".,;)>"))

    return sorted(urls)


# ---------------------------------------------------------------------------
# Authentication result parsing
# ---------------------------------------------------------------------------

def _parse_auth_results(headers: list[str]) -> dict:
    """Parse Authentication-Results headers for SPF/DKIM/DMARC."""
    results = {"spf": None, "dkim": None, "dmarc": None}

    combined = " ".join(headers)

    spf_match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", combined, re.I)
    if spf_match:
        results["spf"] = spf_match.group(1).lower()

    dkim_match = re.search(r"dkim=(pass|fail|none|temperror|permerror)", combined, re.I)
    if dkim_match:
        results["dkim"] = dkim_match.group(1).lower()

    dmarc_match = re.search(r"dmarc=(pass|fail|none|bestguesspass|temperror|permerror)", combined, re.I)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).lower()

    return results


# ---------------------------------------------------------------------------
# Received chain parsing
# ---------------------------------------------------------------------------

def _parse_received_chain(received_headers: list[str]) -> list[dict]:
    """Parse Received headers into a structured chain."""
    chain = []
    for header in received_headers:
        entry: dict = {"raw": header.strip()}

        from_match = re.search(r"from\s+(\S+)", header, re.I)
        if from_match:
            entry["from"] = from_match.group(1)

        by_match = re.search(r"by\s+(\S+)", header, re.I)
        if by_match:
            entry["by"] = by_match.group(1)

        ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", header)
        if ip_match:
            entry["ip"] = ip_match.group(1)

        date_match = re.search(r";\s*(.+)$", header)
        if date_match:
            entry["date"] = date_match.group(1).strip()

        chain.append(entry)
    return chain


# ---------------------------------------------------------------------------
# Spoofing detection
# ---------------------------------------------------------------------------

def _extract_email_addr(header_value: str) -> str | None:
    """Extract email address from a header value like 'Name <email@domain>'."""
    match = re.search(r"<([^>]+)>", header_value)
    if match:
        return match.group(1).lower()
    # Bare email
    match = re.search(r"[\w.+-]+@[\w.-]+\.\w+", header_value)
    if match:
        return match.group(0).lower()
    return None


def _extract_domain(email_addr: str) -> str:
    """Get domain from email address."""
    return email_addr.split("@")[-1] if "@" in email_addr else ""


def _detect_spoofing(
    from_addr: str | None,
    reply_to: str | None,
    return_path: str | None,
    from_header: str,
) -> list[dict]:
    """Detect spoofing signals."""
    signals: list[dict] = []

    if not from_addr:
        return signals

    from_domain = _extract_domain(from_addr)

    # From/Reply-To domain mismatch
    if reply_to:
        reply_domain = _extract_domain(reply_to)
        if reply_domain and reply_domain != from_domain:
            signals.append({
                "type": "reply_to_mismatch",
                "severity": "high",
                "detail": f"From domain ({from_domain}) differs from Reply-To domain ({reply_domain})",
                "from_domain": from_domain,
                "reply_to_domain": reply_domain,
            })

    # From/Return-Path domain mismatch
    if return_path:
        rp_domain = _extract_domain(return_path)
        if rp_domain and rp_domain != from_domain:
            signals.append({
                "type": "return_path_mismatch",
                "severity": "medium",
                "detail": f"From domain ({from_domain}) differs from Return-Path domain ({rp_domain})",
                "from_domain": from_domain,
                "return_path_domain": rp_domain,
            })

    # Display name containing a different email address
    display_match = re.search(r"^([^<]+)<", from_header)
    if display_match:
        display_name = display_match.group(1).strip()
        embedded_email = re.search(r"[\w.+-]+@[\w.-]+\.\w+", display_name)
        if embedded_email:
            embedded = embedded_email.group(0).lower()
            if embedded != from_addr:
                signals.append({
                    "type": "display_name_email_mismatch",
                    "severity": "high",
                    "detail": f"Display name contains email ({embedded}) different from actual sender ({from_addr})",
                    "display_email": embedded,
                    "actual_email": from_addr,
                })

    # Homoglyph domain check
    homoglyph_target = _check_homoglyph_domain(from_domain)
    if homoglyph_target:
        signals.append({
            "type": "homoglyph_domain",
            "severity": "high",
            "detail": f"From domain ({from_domain}) uses homoglyph characters resembling {homoglyph_target}",
            "from_domain": from_domain,
            "impersonated_domain": homoglyph_target,
        })

    return signals


# ---------------------------------------------------------------------------
# Main tool function
# ---------------------------------------------------------------------------

def analyse_email(eml_path: str | Path, case_id: str) -> dict:
    """
    Parse an .eml file and extract security-relevant information.
    Returns a manifest dict with all findings.
    """
    eml_path = Path(eml_path)
    if not eml_path.exists():
        return {"status": "error", "reason": f"File not found: {eml_path}"}

    case_dir = CASES_DIR / case_id
    email_dir = case_dir / "artefacts" / "email"
    attach_dir = email_dir / "attachments"

    # Parse the email
    raw_bytes = eml_path.read_bytes()
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    # Extract key headers
    from_header = str(msg.get("From", ""))
    from_addr = _extract_email_addr(from_header)
    reply_to_header = str(msg.get("Reply-To", ""))
    reply_to = _extract_email_addr(reply_to_header) if reply_to_header else None
    return_path_header = str(msg.get("Return-Path", ""))
    return_path = _extract_email_addr(return_path_header) if return_path_header else None

    headers = {
        "from": from_header,
        "from_address": from_addr,
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "reply_to": reply_to_header,
        "reply_to_address": reply_to,
        "return_path": return_path_header,
        "return_path_address": return_path,
        "message_id": str(msg.get("Message-ID", "")),
        "x_mailer": str(msg.get("X-Mailer", "")),
    }

    # Authentication results
    auth_headers = msg.get_all("Authentication-Results", [])
    auth_results = _parse_auth_results([str(h) for h in auth_headers])

    # Received chain
    received_headers = msg.get_all("Received", [])
    received_chain = _parse_received_chain([str(h) for h in received_headers])

    # Spoofing detection
    spoofing_signals = _detect_spoofing(from_addr, reply_to, return_path, from_header)

    # Extract URLs from body
    urls: list[str] = []
    body_text = ""
    body_html = ""

    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/html":
            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    body_html = payload
                    urls.extend(_extract_urls_from_html(payload))
            except Exception as exc:
                log_error(case_id, "analyse_email.html_body", str(exc), severity="warning")
        elif content_type == "text/plain":
            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    body_text = payload
                    # Extract URLs from plain text
                    for m in re.finditer(r'https?://[^\s<>"\']+', payload):
                        urls.append(m.group(0).rstrip(".,;)>"))
            except Exception as exc:
                log_error(case_id, "analyse_email.text_body", str(exc), severity="warning")

    urls = sorted(set(urls))

    # Extract and save attachments
    attachments: list[dict] = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment" or (
            part.get_filename() and not part.get_content_type().startswith("text/")
        ):
            filename = part.get_filename()
            if not filename:
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                # Sanitise filename
                safe_name = re.sub(r"[^\w.\-]", "_", filename)
                dest = attach_dir / safe_name
                art = write_artefact(dest, payload)
                attachments.append({
                    "filename": filename,
                    "safe_filename": safe_name,
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "sha256": sha256_bytes(payload),
                    "path": str(dest),
                })
            except Exception as exc:
                log_error(case_id, "analyse_email.attachment", str(exc), severity="warning",
                          context={"filename": filename})

    # Build result
    result = {
        "status": "ok",
        "case_id": case_id,
        "source_file": str(eml_path),
        "headers": headers,
        "auth_results": auth_results,
        "received_chain": received_chain,
        "spoofing_signals": spoofing_signals,
        "urls": urls,
        "attachments": attachments,
        "has_html_body": bool(body_html),
        "has_text_body": bool(body_text),
        "ts": utcnow(),
    }

    # Save analysis
    save_json(email_dir / "email_analysis.json", result)
    audit("analyse_email", str(eml_path), extra={"case_id": case_id})

    # Print summary
    print(f"[analyse_email] Parsed: {eml_path.name}")
    print(f"  From: {from_header}")
    print(f"  Subject: {headers['subject']}")
    print(f"  Auth: SPF={auth_results['spf']}, DKIM={auth_results['dkim']}, DMARC={auth_results['dmarc']}")
    if spoofing_signals:
        for sig in spoofing_signals:
            print(f"  ⚠ SPOOFING: {sig['type']} — {sig['detail']}")
    print(f"  URLs: {len(urls)}, Attachments: {len(attachments)}")

    return result


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="Analyse an .eml file for security indicators.")
    p.add_argument("--eml", required=True, help="Path to .eml file")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = analyse_email(args.eml, args.case_id)
    print(json.dumps(result, indent=2))
