"""
tool: detect_phishing_page
--------------------------
Scans captured web pages for brand impersonation phishing signals.

For every capture_manifest.json under cases/<case_id>/artefacts/web/:
  - Checks the page <title> (from manifest) and visible text (from page.txt)
    against a list of known brand name patterns.
  - Flags pages where a recognised brand appears but the final_url domain is
    NOT on that brand's domain allowlist.
  - Confidence:
      high   — brand found in page title
      medium — brand found in body text only, co-occurring with login language
               ("sign in", "log in", "password", "your account", "email address")

Writes:
  cases/<case_id>/artefacts/phishing_detection/phishing_detection.json
"""
from __future__ import annotations

import base64
import json
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from html.parser import HTMLParser
from config.settings import ANTHROPIC_KEY, CASES_DIR
from tools.common import KNOWN_CLEAN_DOMAINS, get_model, load_json, log_error, utcnow, write_artefact

# ---------------------------------------------------------------------------
# Brand definitions
# ---------------------------------------------------------------------------
# Each entry:
#   name     — display name used in reports
#   patterns — compiled regexes; any match = brand detected
#   allowed  — base domains (eTLD+1); subdomains are accepted automatically
# ---------------------------------------------------------------------------
_BRANDS: list[dict] = [
    {
        "name": "Microsoft",
        "patterns": [
            re.compile(r"\bMicrosoft\b", re.I),
            re.compile(r"\bOffice\s*365\b", re.I),
            re.compile(r"\bOneDrive\b", re.I),
            re.compile(r"\bOutlook\b", re.I),
            re.compile(r"\bMicrosoft\s+Teams\b", re.I),
            re.compile(r"\bSharePoint\b", re.I),
            re.compile(r"\bAzure\s+Active\s+Directory\b", re.I),
        ],
        "allowed": {
            "microsoft.com", "microsoftonline.com", "live.com", "azure.com",
            "office.com", "sharepoint.com", "outlook.com", "windows.com",
            "bing.com", "skype.com", "xbox.com", "msn.com", "microsoft365.com",
            "onenote.com", "onedrive.live.com", "azure.net", "azurewebsites.net",
            "azurefd.net",
        },
    },
    {
        "name": "Google",
        "patterns": [
            re.compile(r"\bGoogle\b", re.I),
            re.compile(r"\bGmail\b", re.I),
            re.compile(r"\bGoogle\s+Drive\b", re.I),
            re.compile(r"\bGoogle\s+Workspace\b", re.I),
        ],
        "allowed": {
            "google.com", "google.co.uk", "google.com.au", "google.ca",
            "google.de", "google.fr", "google.co.jp", "google.co.in",
            "googleapis.com", "gstatic.com", "youtube.com",
            "gmail.com", "googlemail.com", "accounts.google.com",
        },
    },
    {
        "name": "Apple",
        "patterns": [
            re.compile(r"\bApple\s+ID\b", re.I),
            re.compile(r"\biCloud\b", re.I),
            re.compile(r"\bApple\s+Account\b", re.I),
        ],
        "allowed": {
            "apple.com", "icloud.com", "me.com", "mac.com",
        },
    },
    {
        "name": "PayPal",
        "patterns": [re.compile(r"\bPayPal\b", re.I)],
        "allowed": {"paypal.com", "paypal.me", "paypalobjects.com"},
    },
    {
        "name": "DocuSign",
        "patterns": [re.compile(r"\bDocuSign\b", re.I)],
        "allowed": {"docusign.com", "docusign.net"},
    },
    {
        "name": "Amazon",
        "patterns": [
            re.compile(r"\bAmazon\b", re.I),
            re.compile(r"\bAWS\b"),
            re.compile(r"\bAmazon\s+Web\s+Services\b", re.I),
        ],
        "allowed": {
            "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
            "amazon.ca", "amazon.com.au", "amazon.co.jp", "amazon.in",
            "amazon.es", "amazon.it", "amazonaws.com", "amazonpay.com",
            "signin.aws.amazon.com",
        },
    },
    {
        "name": "Facebook / Meta",
        "patterns": [
            re.compile(r"\bFacebook\b", re.I),
            re.compile(r"\bInstagram\b", re.I),
            re.compile(r"\bMeta\b", re.I),
        ],
        "allowed": {
            "facebook.com", "fb.com", "instagram.com",
            "meta.com", "messenger.com", "whatsapp.com",
        },
    },
    {
        "name": "LinkedIn",
        "patterns": [re.compile(r"\bLinkedIn\b", re.I)],
        "allowed": {"linkedin.com", "lnkd.in"},
    },
    {
        "name": "Dropbox",
        "patterns": [re.compile(r"\bDropbox\b", re.I)],
        "allowed": {"dropbox.com", "dropboxusercontent.com"},
    },
    {
        "name": "Adobe",
        "patterns": [
            re.compile(r"\bAdobe\b", re.I),
            re.compile(r"\bAcrobat\b", re.I),
        ],
        "allowed": {"adobe.com", "adobeconnect.com", "typekit.com"},
    },
    {
        "name": "DHL",
        "patterns": [re.compile(r"\bDHL\b")],
        "allowed": {"dhl.com", "dhl.de", "dhl.co.uk", "dhlparcel.nl"},
    },
    {
        "name": "FedEx",
        "patterns": [re.compile(r"\bFedEx\b", re.I)],
        "allowed": {"fedex.com"},
    },
    {
        "name": "Netflix",
        "patterns": [re.compile(r"\bNetflix\b", re.I)],
        "allowed": {"netflix.com", "nflxsuite.com"},
    },
    {
        "name": "Zoom",
        "patterns": [re.compile(r"\bZoom\b", re.I)],
        "allowed": {"zoom.us", "zoom.com"},
    },
    {
        "name": "Salesforce",
        "patterns": [re.compile(r"\bSalesforce\b", re.I)],
        "allowed": {"salesforce.com", "force.com", "salesforceliveagent.com"},
    },
    {
        "name": "HMRC",
        "patterns": [re.compile(r"\bHMRC\b"), re.compile(r"\bHer\s+Majesty'?s\s+Revenue\b", re.I)],
        "allowed": {"hmrc.gov.uk", "gov.uk"},
    },
    {
        "name": "NHS",
        "patterns": [re.compile(r"\bNHS\b"), re.compile(r"\bNational\s+Health\s+Service\b", re.I)],
        "allowed": {"nhs.uk", "nhs.net"},
    },
]

# ---------------------------------------------------------------------------
# Global trusted-domain allowlist
# ---------------------------------------------------------------------------
# Captures from these domains are skipped entirely — they are well-known
# legitimate tech/media/reference sites that routinely mention brand names
# (social-media links in footers, news articles, bug reports, etc.) and
# would otherwise generate constant false positives.
_ALWAYS_TRUSTED: frozenset[str] = KNOWN_CLEAN_DOMAINS | frozenset({
    "bugzilla.mozilla.org",   # covered by mozilla.org but explicit for clarity
    "openssl.org", "apache.org", "debian.org", "ubuntu.com",
    "python.org", "pypi.org", "npmjs.com", "nodejs.org",
    "archive.org", "web.archive.org",
})

# Login-language phrases that elevate body-only hits to medium confidence
_LOGIN_RE = re.compile(
    r"sign\s+in|log\s+in|log\s+on|please\s+enter\s+your\s+password|"
    r"\bpassword\b|your\s+email\s+address|forgot\s+password|"
    r"enter\s+your\s+email|create\s+account|reset\s+password",
    re.I,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hostname(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception as exc:
        log_error("", "detect_phishing_page.hostname", str(exc),
                  severity="warning", context={"url": url[:200]})
        return ""


def _domain_allowed(hostname: str, allowed: set[str]) -> bool:
    """Return True if hostname is or is a subdomain of any allowed base domain."""
    h = hostname.lower().lstrip("www.")
    for d in allowed:
        if h == d or h.endswith("." + d):
            return True
    return False


def _check_brands(title: str, body: str, final_url: str) -> list[dict]:
    """
    Return a list of brand-impersonation findings for a single captured page.
    Each finding: {brand, confidence, matched_pattern, title_hit, body_hit, final_url}
    """
    findings = []
    hostname = _hostname(final_url)

    # Skip captures from known-clean trusted domains entirely
    if _domain_allowed(hostname, _ALWAYS_TRUSTED):
        return []

    for brand in _BRANDS:
        if _domain_allowed(hostname, brand["allowed"]):
            continue  # legitimate domain — skip

        title_hit = any(p.search(title) for p in brand["patterns"])
        body_hit  = any(p.search(body)  for p in brand["patterns"])

        if not title_hit and not body_hit:
            continue

        if title_hit:
            confidence = "high"
        elif _LOGIN_RE.search(body):
            confidence = "medium"
        else:
            # Brand mention in body only, no login language — too noisy, skip
            continue

        matched = next(
            p.pattern for p in brand["patterns"]
            if (title_hit and p.search(title)) or (body_hit and p.search(body))
        )

        findings.append({
            "brand":           brand["name"],
            "confidence":      confidence,
            "matched_pattern": matched,
            "title_hit":       title_hit,
            "body_hit":        body_hit,
            "final_url":       final_url,
            "hostname":        hostname,
        })

    return findings


# ---------------------------------------------------------------------------
# Form action / credential harvest detection
# ---------------------------------------------------------------------------

class _FormParser(HTMLParser):
    """Extract <form> elements with their action URLs and input types."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._in_form = False
        self._current: dict = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._in_form = True
            self._current = {
                "action": a.get("action", ""),
                "method": (a.get("method", "get")).upper(),
                "has_password": False,
                "input_types": [],
            }
        elif self._in_form and tag == "input":
            itype = a.get("type", "text").lower()
            self._current["input_types"].append(itype)
            if itype == "password":
                self._current["has_password"] = True

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form:
            self._in_form = False
            self.forms.append(self._current)
            self._current = {}


def _extract_form_actions(html: str, final_url: str) -> list[dict]:
    """
    Parse HTML for forms, identify credential harvest targets.
    Returns list of form dicts with action URL, password field presence,
    and whether the action posts to an external domain.
    """
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:
        return []

    page_host = _hostname(final_url).lower().lstrip("www.")
    results = []

    for form in parser.forms:
        action = form["action"].strip()
        if not action or action == "#" or action.startswith("javascript:"):
            # Inline/empty action = posts to same page
            action_host = page_host
            resolved_action = final_url
        else:
            resolved_action = urllib.parse.urljoin(final_url, action)
            action_host = _hostname(resolved_action).lower().lstrip("www.")

        # Determine if action is external
        external = bool(action_host and page_host and action_host != page_host
                        and not action_host.endswith("." + page_host)
                        and not page_host.endswith("." + action_host))

        results.append({
            "action_url": resolved_action,
            "action_host": action_host,
            "method": form["method"],
            "has_password": form["has_password"],
            "external_action": external,
            "input_types": form["input_types"],
        })

    return results


def _classify_form_risk(forms: list[dict]) -> dict:
    """
    Classify credential harvest risk from extracted forms.
    Returns {credential_harvest: bool, external_harvest: bool, forms: [...]}
    """
    credential_forms = [f for f in forms if f["has_password"]]
    external_harvest = [f for f in credential_forms if f["external_action"]]

    return {
        "credential_harvest": len(credential_forms) > 0,
        "external_harvest": len(external_harvest) > 0,
        "credential_form_count": len(credential_forms),
        "external_harvest_targets": [f["action_url"] for f in external_harvest],
        "forms": forms,
    }


# ---------------------------------------------------------------------------
# Domain age / TLS enrichment helpers
# ---------------------------------------------------------------------------

def _load_domain_age(case_id: str, hostname: str) -> int | None:
    """
    Look up domain age (days) from enrichment data for this case.
    Returns age in days or None if unavailable.
    """
    enrichment_path = CASES_DIR / case_id / "artefacts" / "enrichment" / "enrichment.json"
    if not enrichment_path.exists():
        return None
    enrichment = load_json(enrichment_path)
    if not enrichment:
        return None

    # Domain to look up (strip www.)
    domain = hostname.lower().lstrip("www.")

    # Check enrichment results for WHOISXML data
    # enrichment.json format: {"results": [list of result dicts], "summary": {...}}
    results_list = enrichment.get("results", [])
    if isinstance(results_list, list):
        for result in results_list:
            if not isinstance(result, dict):
                continue
            if result.get("provider") == "whoisxml" and result.get("status") == "ok":
                ioc_val = result.get("ioc", "").lower().lstrip("www.")
                if ioc_val == domain:
                    age = result.get("domain_age_days")
                    if age is not None:
                        return age
    return None


def _get_tls_info(manifest: dict) -> dict | None:
    """Extract TLS certificate info from capture manifest."""
    return manifest.get("tls_certificate")


# ---------------------------------------------------------------------------
# Tier 2 — Structural / heuristic suspicion scoring
# ---------------------------------------------------------------------------
# Each function returns a list of signal dicts:
#   {"signal": str, "weight": float (0.0-1.0), "detail": str}
# Weights are summed into a composite suspicion score per page.
# ---------------------------------------------------------------------------

import math
import string

# TLDs disproportionately used in phishing (cheap/free registration, lax abuse)
_SUSPICIOUS_TLDS = frozenset({
    ".icu", ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".click", ".link", ".info", ".cam", ".rest", ".surf",
    ".monster", ".sbs", ".cfd", ".lol", ".bond", ".icu", ".support",
    ".help", ".zip", ".mov", ".today", ".life", ".world", ".site",
    ".online", ".fun", ".store", ".shop", ".work", ".space",
})

# Known URL shorteners / redirect services
_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rb.gy", "cutt.ly", "rebrand.ly", "shorturl.at",
    "tiny.cc", "lnkd.in", "bl.ink", "surl.li", "qr.ae",
})

# Bait phrases — "click here to view", "verify your account", etc.
_BAIT_RE = re.compile(
    r"click\s+(?:here\s+)?to\s+(?:view|download|access|verify|confirm|continue|open|unlock|update)|"
    r"verify\s+your\s+(?:account|identity|email|information)|"
    r"confirm\s+your\s+(?:account|identity|email|details)|"
    r"your\s+(?:account|session)\s+(?:has\s+been|will\s+be)\s+(?:suspended|locked|limited|closed)|"
    r"unusual\s+(?:activity|sign-?in|login)|"
    r"update\s+your\s+(?:payment|billing|card)|"
    r"action\s+required|immediate\s+(?:action|attention)\s+(?:required|needed)|"
    r"failure\s+to\s+(?:verify|confirm|update)|"
    r"view\s+(?:shared\s+)?document|"
    r"you\s+have\s+\d+\s+(?:unread\s+)?messages?|"
    r"your\s+package\s+(?:is|has\s+been)|"
    r"call\s+(?:us\s+)?(?:now\s+)?(?:at\s+)?\+?\d[\d\s\-]{6,}",
    re.I,
)

# Fake urgency — countdowns, time pressure
_URGENCY_RE = re.compile(
    r"(?:expires?\s+in|only\s+\d+\s+(?:hours?|minutes?)\s+(?:left|remaining))|"
    r"(?:act\s+now|limited\s+time|don'?t\s+(?:wait|delay|ignore))|"
    r"(?:within\s+\d+\s+(?:hours?|days?)\s+or\s+your)",
    re.I,
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def _extract_sld(hostname: str) -> str:
    """Extract the second-level domain label (e.g. 'evil' from 'login.evil.com')."""
    parts = hostname.lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return hostname


def _consonant_ratio(s: str) -> float:
    """Ratio of consonants to alphabetic characters — high = random-looking."""
    alpha = [c for c in s.lower() if c in string.ascii_lowercase]
    if not alpha:
        return 0.0
    vowels = set("aeiou")
    consonants = [c for c in alpha if c not in vowels]
    return len(consonants) / len(alpha)


def _domain_structure_signals(hostname: str, final_url: str) -> list[dict]:
    """Score domain/URL structural suspicion."""
    signals = []
    h = hostname.lower().rstrip(".")
    parts = h.split(".")
    sld = _extract_sld(h)

    # 1. Suspicious TLD
    tld = "." + parts[-1] if parts else ""
    if tld in _SUSPICIOUS_TLDS:
        signals.append({
            "signal": "suspicious_tld",
            "weight": 0.3,
            "detail": f"TLD '{tld}' is disproportionately used in phishing",
        })

    # 2. High entropy in SLD (random-looking domain)
    sld_entropy = _shannon_entropy(sld)
    if len(sld) >= 6 and sld_entropy > 3.5:
        signals.append({
            "signal": "high_entropy_domain",
            "weight": 0.35,
            "detail": f"SLD '{sld}' has high entropy ({sld_entropy:.2f} bits) — looks random",
        })

    # 3. High consonant ratio (gibberish)
    cr = _consonant_ratio(sld)
    if len(sld) >= 5 and cr > 0.80:
        signals.append({
            "signal": "consonant_heavy_domain",
            "weight": 0.3,
            "detail": f"SLD '{sld}' consonant ratio {cr:.0%} — looks generated",
        })

    # 4. Excessive hyphens (paypal-login-verify-secure.com)
    if sld.count("-") >= 2:
        signals.append({
            "signal": "hyphen_abuse",
            "weight": 0.25,
            "detail": f"SLD '{sld}' contains {sld.count('-')} hyphens — common in phishing",
        })

    # 5. Brand name embedded in non-brand domain
    for brand in _BRANDS:
        for pat in brand["patterns"]:
            if pat.search(sld.replace("-", " ")):
                if not _domain_allowed(h, brand["allowed"]):
                    signals.append({
                        "signal": "brand_in_domain",
                        "weight": 0.5,
                        "detail": f"Brand '{brand['name']}' embedded in domain '{h}'",
                    })
                    break
        else:
            continue
        break

    # 6. Excessive subdomains (login.secure.verify.evil.com)
    # Exclude ccTLD patterns like .co.uk, .com.au, .co.jp where the extra
    # level is part of the TLD structure, not a real subdomain.
    _CCTLD_COMBOS = {"co.uk", "com.au", "co.jp", "co.in", "com.br", "co.za",
                     "co.nz", "com.sg", "com.hk", "co.kr", "com.mx", "com.ar",
                     "org.uk", "net.au", "gov.uk"}
    effective_levels = len(parts)
    suffix = ".".join(parts[-2:]) if len(parts) >= 2 else ""
    if suffix in _CCTLD_COMBOS:
        effective_levels -= 1  # don't count the ccTLD combo as an extra level
    if effective_levels >= 4:
        signals.append({
            "signal": "excessive_subdomains",
            "weight": 0.2,
            "detail": f"{len(parts)} domain levels: {h}",
        })

    # 7. URL path contains Base64
    parsed = urllib.parse.urlparse(final_url)
    path_query = parsed.path + "?" + parsed.query if parsed.query else parsed.path
    b64_match = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", path_query)
    if b64_match:
        signals.append({
            "signal": "base64_in_url",
            "weight": 0.3,
            "detail": f"Possible Base64 blob in URL path/query ({len(b64_match.group())} chars)",
        })

    # 8. Extremely long URL (> 200 chars)
    if len(final_url) > 200:
        signals.append({
            "signal": "very_long_url",
            "weight": 0.15,
            "detail": f"URL length {len(final_url)} chars",
        })

    return signals


def _redirect_chain_signals(manifest: dict) -> list[dict]:
    """Analyse the redirect chain for suspicious patterns."""
    signals = []
    chain = manifest.get("redirect_chain", [])
    if not chain:
        # Try loading from artefact file
        rc_artefact = manifest.get("artefacts", {}).get("redirect_chain", {})
        rc_path = rc_artefact.get("path") if isinstance(rc_artefact, dict) else None
        if rc_path and Path(rc_path).exists():
            try:
                chain = json.loads(Path(rc_path).read_text())
            except Exception:
                pass

    if not chain:
        return signals

    hop_count = len(chain)
    # Exclude the 'final' entry from hop count
    real_hops = [h for h in chain if h.get("type") != "final"]

    # 1. Many redirect hops
    if len(real_hops) >= 3:
        signals.append({
            "signal": "many_redirect_hops",
            "weight": 0.3,
            "detail": f"{len(real_hops)} redirect hops before final page",
        })

    # 2. URL shortener in chain
    for hop in chain:
        hop_host = _hostname(hop.get("url", "")).lower()
        for sd in _SHORTENER_DOMAINS:
            if hop_host == sd or hop_host.endswith("." + sd):
                signals.append({
                    "signal": "shortener_in_chain",
                    "weight": 0.25,
                    "detail": f"URL shortener '{hop_host}' in redirect chain",
                })
                break

    # 3. Multiple different domains in chain (hop through unrelated sites)
    chain_domains = set()
    for hop in chain:
        h = _hostname(hop.get("url", ""))
        if h:
            chain_domains.add(_extract_sld(h))
    if len(chain_domains) >= 3:
        signals.append({
            "signal": "multi_domain_redirect",
            "weight": 0.3,
            "detail": f"Redirects traverse {len(chain_domains)} different domains",
        })

    # 4. JS navigation (not HTTP redirect — harder to trace)
    js_navs = [h for h in chain if h.get("type") == "js_navigation"]
    if js_navs:
        signals.append({
            "signal": "js_redirect",
            "weight": 0.2,
            "detail": f"{len(js_navs)} JavaScript-based redirect(s) in chain",
        })

    return signals


def _page_content_signals(title: str, body: str, html: str, manifest: dict) -> list[dict]:
    """Assess page content for suspicious emptiness, bait language, deceptive patterns."""
    signals = []
    body_stripped = body.strip()
    body_len = len(body_stripped)

    # 1. Very little visible text (page is mostly JS/empty)
    if body_len < 50:
        signals.append({
            "signal": "minimal_visible_text",
            "weight": 0.35,
            "detail": f"Only {body_len} chars of visible text — page may be JS-rendered or empty",
        })

    # 2. No title or generic title
    title_lower = title.strip().lower()
    generic_titles = {"", "untitled", "document", "loading", "loading...",
                      "please wait", "just a moment", "redirecting",
                      "redirecting...", "403 forbidden", "404 not found"}
    if title_lower in generic_titles:
        signals.append({
            "signal": "missing_or_generic_title",
            "weight": 0.2,
            "detail": f"Page title is empty or generic: '{title.strip()[:60]}'",
        })

    # 3. Bait language
    bait_matches = _BAIT_RE.findall(body)
    if bait_matches:
        signals.append({
            "signal": "bait_language",
            "weight": 0.4,
            "detail": f"Bait phrases detected: {', '.join(set(m.strip()[:60] for m in bait_matches[:5]))}",
        })

    # 4. Urgency / pressure tactics
    urgency_matches = _URGENCY_RE.findall(body)
    if urgency_matches:
        signals.append({
            "signal": "urgency_language",
            "weight": 0.3,
            "detail": f"Urgency/pressure language: {', '.join(set(m.strip()[:60] for m in urgency_matches[:3]))}",
        })

    # 5. Hidden iframes (common in phishing kits)
    iframe_re = re.compile(
        r'<iframe[^>]*(?:style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|'
        r'visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)[^"\']*["\']|'
        r'hidden\b)',
        re.I,
    )
    iframe_matches = iframe_re.findall(html)
    if iframe_matches:
        signals.append({
            "signal": "hidden_iframe",
            "weight": 0.4,
            "detail": f"{len(iframe_matches)} hidden iframe(s) detected",
        })

    # 6. Data URIs in HTML (embedded payloads)
    data_uri_count = len(re.findall(r'data:(?:text/html|application/javascript)', html, re.I))
    if data_uri_count:
        signals.append({
            "signal": "data_uri_payload",
            "weight": 0.35,
            "detail": f"{data_uri_count} data: URI(s) with executable content",
        })

    # 7. Excessive JS relative to visible text
    script_blocks = re.findall(r'<script[^>]*>[\s\S]*?</script>', html, re.I)
    total_js_len = sum(len(s) for s in script_blocks)
    if total_js_len > 5000 and body_len < 200:
        signals.append({
            "signal": "js_heavy_minimal_content",
            "weight": 0.3,
            "detail": f"{total_js_len} chars of JS vs {body_len} chars visible text",
        })

    # 8. Cloudflare blocked — we never saw the real page
    if manifest.get("cloudflare_blocked"):
        challenge = manifest.get("cloudflare_challenge", "unknown")
        signals.append({
            "signal": "cloudflare_blocked",
            "weight": 0.15,
            "detail": f"Page behind Cloudflare challenge ({challenge}) — real content not captured",
        })

    # 9. Page has password field but no brand was detected (standalone suspicion)
    if re.search(r'<input[^>]*type\s*=\s*["\']password["\']', html, re.I):
        if not any(p.search(title + " " + body) for brand in _BRANDS for p in brand["patterns"]):
            signals.append({
                "signal": "password_field_no_brand",
                "weight": 0.35,
                "detail": "Password input field present but no recognised brand on page",
            })

    return signals


def _compute_suspicion_score(signals: list[dict]) -> float:
    """Compute a composite suspicion score from weighted signals (0.0 - 1.0 capped)."""
    if not signals:
        return 0.0
    return min(1.0, sum(s["weight"] for s in signals))


# ---------------------------------------------------------------------------
# Tier 3 — LLM page purpose analysis (escalation for indeterminate pages)
# ---------------------------------------------------------------------------

def _llm_purpose_check(body: str, html: str, final_url: str, hostname: str,
                       title: str) -> dict | None:
    """Ask Claude to assess the page's purpose.

    Only called for pages that passed Tier 1 (no brand/form hit) and scored
    above threshold in Tier 2 heuristics, but still lack a clear determination.

    Returns a finding dict or None.
    """
    if not ANTHROPIC_KEY:
        return None

    # Truncate content to avoid excessive token usage
    body_excerpt = body[:4000] if body else "(no visible text captured)"
    html_excerpt = html[:6000] if html else "(no HTML captured)"

    prompt = (
        "You are a senior SOC analyst assessing a captured web page.\n\n"
        "A legitimate page serves an obvious purpose: it sells a product, shows a "
        "news article, provides documentation, hosts a SaaS dashboard, etc. Its "
        "purpose is immediately clear.\n\n"
        "A phishing or malicious page often has NO clear legitimate purpose, or its "
        "stated purpose doesn't match what the page actually does. Common patterns:\n"
        "- 'View shared document' lure with no real document\n"
        "- Fake login page on a domain unrelated to the brand\n"
        "- 'Verify your account' with urgency but no real account system\n"
        "- CAPTCHA or 'click to continue' gate hiding the real payload\n"
        "- Page pretending to be a file preview (PDF, voicemail, fax)\n"
        "- Fake tech-support page with a phone number\n"
        "- Cookie-cutter landing page with no real business behind it\n\n"
        f"**URL:** {final_url}\n"
        f"**Page title:** {title or '(empty)'}\n\n"
        f"**Visible text (first 4000 chars):**\n```\n{body_excerpt}\n```\n\n"
        f"**HTML source (first 6000 chars):**\n```html\n{html_excerpt}\n```\n\n"
        "Assess this page. What is it for? Is its purpose clear and legitimate, "
        "or is it deceptive / purposeless / suspicious?"
    )

    try:
        from tools.structured_llm import structured_call
        from tools.schemas import PagePurposeAssessment

        data, _usage = structured_call(
            model=get_model("report"),
            system=(
                "You are a phishing detection expert. Assess web pages for "
                "deceptive intent. Be sceptical — if you cannot identify a clear, "
                "legitimate purpose for a page, say so. Legitimate pages make their "
                "purpose obvious."
            ),
            messages=[{"role": "user", "content": prompt}],
            output_schema=PagePurposeAssessment,
            max_tokens=512,
        )
    except Exception as exc:
        log_error("", "detect_phishing_page.llm_purpose_check", str(exc),
                  severity="warning", context={"hostname": hostname})
        print(f"[detect_phishing_page] LLM purpose check failed for {hostname}: {exc}")
        return None

    if data is None:
        return None

    # Only generate a finding if the LLM says the page lacks purpose or is deceptive
    if data.has_clear_purpose and not data.deceptive_intent:
        print(
            f"[detect_phishing_page] Purpose check CLEAN: {hostname} — "
            f"{data.stated_purpose[:80]}"
        )
        return None

    confidence = data.confidence if data.confidence in ("high", "medium", "low") else "medium"

    return {
        "brand": "Unknown (no clear purpose)" if not data.deceptive_intent
                 else "Unknown (deceptive intent)",
        "confidence": confidence,
        "matched_pattern": "llm_purpose_check",
        "title_hit": False,
        "body_hit": False,
        "final_url": final_url,
        "hostname": hostname,
        "source": "llm_purpose_check",
        "purpose_assessment": {
            "has_clear_purpose": data.has_clear_purpose,
            "stated_purpose": data.stated_purpose,
            "suspicious_elements": data.suspicious_elements,
            "deceptive_intent": data.deceptive_intent,
            "reasoning": data.reasoning,
        },
    }


# Suspicion threshold — pages scoring above this in Tier 2 heuristics get
# escalated to Tier 3 (LLM purpose check) if they have no Tier 1 findings.
_SUSPICION_ESCALATION_THRESHOLD = 0.4


# ---------------------------------------------------------------------------
# LLM vision phishing check
# ---------------------------------------------------------------------------

def _llm_vision_check(screenshot_path: Path, final_url: str, hostname: str) -> dict | None:
    """
    Send a screenshot to Claude Vision and ask for brand impersonation analysis.
    Returns a finding dict or None on failure / no finding.
    Expected JSON from model:
      {brand_impersonation, impersonated_brand, login_form, confidence, reasoning}
    """
    try:
        import anthropic
    except ImportError as exc:
        log_error("", "detect_phishing_page.llm_vision", str(exc), severity="info",
                  context={"reason": "anthropic not installed"})
        return None

    try:
        img_bytes = screenshot_path.read_bytes()
        img_b64   = base64.standard_b64encode(img_bytes).decode()
    except Exception as exc:
        log_error("", "detect_phishing_page.read_screenshot", str(exc),
                  severity="warning", context={"path": str(screenshot_path)})
        print(f"[detect_phishing_page] LLM vision: could not read {screenshot_path}: {exc}")
        return None

    prompt = (
        "Examine this webpage screenshot carefully. "
        "Determine whether it impersonates a well-known brand (e.g. Microsoft, Google, "
        "Apple, PayPal, DocuSign, Amazon, Facebook, LinkedIn, Dropbox, Adobe, DHL, "
        "FedEx, Netflix, Zoom, Salesforce, HMRC, NHS) on a domain that does NOT "
        "belong to that brand.\n\n"
        f"Final URL: {final_url}\n\n"
        "Analyse the screenshot and provide your assessment."
    )

    try:
        from tools.structured_llm import structured_call
        from tools.schemas import BrandImpersonationResult

        data, _usage = structured_call(
            model=get_model("report"),
            system="You are a phishing detection expert analysing webpage screenshots.",
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type":       "base64",
                            "media_type": "image/png",
                            "data":       img_b64,
                        },
                    },
                    {"type": "text", "text": prompt},
                ],
            }],
            output_schema=BrandImpersonationResult,
            max_tokens=256,
        )
    except Exception as exc:
        log_error("", "detect_phishing_page.llm_vision_call", str(exc),
                  severity="warning", context={"hostname": hostname})
        print(f"[detect_phishing_page] LLM vision call failed for {hostname}: {exc}")
        return None

    if data is None or not data.brand_impersonation:
        return None

    confidence = data.confidence if data.confidence in ("high", "medium", "low") else "medium"

    return {
        "brand":           data.impersonated_brand or "Unknown",
        "confidence":      confidence,
        "matched_pattern": "llm_vision",
        "title_hit":       False,
        "body_hit":        False,
        "login_form":      data.login_form,
        "reasoning":       data.reasoning,
        "final_url":       final_url,
        "hostname":        hostname,
        "source":          "llm_vision",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_phishing_page(case_id: str) -> dict:
    """Tiered phishing detection across all captured web pages.

    Tier 1 (instant) — brand regex, credential harvest forms, TLS certs, domain age.
    Tier 2 (instant) — structural heuristics: domain entropy, URL patterns, redirect
        chain analysis, page content assessment, bait/urgency language.
    Tier 3 (LLM)     — vision brand check + purpose analysis.  Only fires for pages
        that have no Tier 1 finding but scored above the suspicion threshold in Tier 2.

    Principle: legitimate pages serve an obvious purpose.  If we can't explain what
    a page does, it isn't clean — we just haven't found it yet.

    Writes phishing_detection.json and returns a result manifest.
    """
    case_dir = CASES_DIR / case_id
    web_dir = case_dir / "artefacts" / "web"
    out_dir = case_dir / "artefacts" / "phishing_detection"
    out_dir.mkdir(parents=True, exist_ok=True)

    all_findings: list[dict] = []
    form_analysis_results: list[dict] = []
    tls_signals: list[dict] = []
    heuristic_results: list[dict] = []     # Tier 2 per-page signal reports
    purpose_assessments: list[dict] = []   # Tier 3 LLM purpose results
    scanned = 0

    # Pages that need Tier 3 escalation: (manifest_path, hostname, final_url,
    # title, body, html, suspicion_score, signals)
    escalation_queue: list[tuple] = []

    manifest_paths: list[Path] = []
    if web_dir.exists():
        manifest_paths = list(web_dir.rglob("capture_manifest.json"))

    print(f"[detect_phishing_page] Scanning {len(manifest_paths)} page(s) — Tier 1 (brands/forms/TLS)")

    # -----------------------------------------------------------------------
    # TIER 1 — Brand regex, credential harvest, TLS, domain age
    # -----------------------------------------------------------------------
    for manifest_path in manifest_paths:
        manifest = json.loads(manifest_path.read_text())
        title = manifest.get("title", "")
        final_url = manifest.get("final_url", manifest.get("url", ""))
        hostname = _hostname(final_url)

        # Load body text
        body = ""
        text_artefact = manifest.get("artefacts", {}).get("text") or {}
        text_path = text_artefact.get("path") if isinstance(text_artefact, dict) else None
        if text_path:
            p = Path(text_path)
            if p.exists():
                body = p.read_text(errors="ignore")

        # Load HTML
        html = ""
        html_artefact = manifest.get("artefacts", {}).get("html") or {}
        html_path = html_artefact.get("path") if isinstance(html_artefact, dict) else None
        if html_path:
            p = Path(html_path)
            if p.exists():
                html = p.read_text(errors="ignore")

        # Skip trusted domains entirely
        if _domain_allowed(hostname, _ALWAYS_TRUSTED):
            scanned += 1
            continue

        tier1_hit = False

        # --- Brand impersonation ---
        findings = _check_brands(title, body, final_url)
        for f in findings:
            f["capture_manifest"] = str(manifest_path)
        if findings:
            tier1_hit = True

        # --- Form action / credential harvest ---
        if html:
            forms = _extract_form_actions(html, final_url)
            form_risk = _classify_form_risk(forms)
            if form_risk["credential_harvest"]:
                tier1_hit = True
                form_result = {
                    "hostname": hostname,
                    "final_url": final_url,
                    **form_risk,
                }
                form_analysis_results.append(form_result)

                for f in findings:
                    if f["hostname"] == hostname:
                        f["credential_harvest"] = True
                        f["external_harvest"] = form_risk["external_harvest"]
                        f["harvest_targets"] = form_risk["external_harvest_targets"]

                if not findings and form_risk["credential_harvest"]:
                    harvest_finding = {
                        "brand": "Unknown (credential harvest)",
                        "confidence": "high" if form_risk["external_harvest"] else "medium",
                        "matched_pattern": "credential_harvest_form",
                        "title_hit": False,
                        "body_hit": False,
                        "final_url": final_url,
                        "hostname": hostname,
                        "credential_harvest": True,
                        "external_harvest": form_risk["external_harvest"],
                        "harvest_targets": form_risk["external_harvest_targets"],
                        "capture_manifest": str(manifest_path),
                        "source": "form_analysis",
                    }
                    all_findings.append(harvest_finding)
                    print(
                        f"[detect_phishing_page] CREDENTIAL HARVEST "
                        f"[{'EXTERNAL' if form_risk['external_harvest'] else 'LOCAL'}] "
                        f"{hostname}"
                    )

        # --- TLS certificate signals ---
        tls_cert = _get_tls_info(manifest)
        if tls_cert:
            tls_signal = {"hostname": hostname, "final_url": final_url}
            suspicious_tls = False
            reasons = []

            if tls_cert.get("self_signed"):
                suspicious_tls = True
                reasons.append("self-signed certificate")
            cert_age = tls_cert.get("cert_age_days")
            if cert_age is not None and cert_age < 7:
                suspicious_tls = True
                reasons.append(f"certificate issued {cert_age} day(s) ago")
            days_remaining = tls_cert.get("days_remaining")
            if days_remaining is not None and days_remaining < 0:
                suspicious_tls = True
                reasons.append("expired certificate")

            if suspicious_tls:
                tls_signal["reasons"] = reasons
                tls_signal["cert_details"] = tls_cert
                tls_signals.append(tls_signal)

                for f in findings:
                    if f["hostname"] == hostname and f["confidence"] == "medium":
                        f["confidence"] = "high"
                        f["confidence_boosted_by"] = "tls_" + reasons[0].replace(" ", "_")

        # --- Domain age signals ---
        domain_age = _load_domain_age(case_id, hostname)
        if domain_age is not None:
            for f in findings:
                if f["hostname"] == hostname:
                    f["domain_age_days"] = domain_age
                    if domain_age < 30 and f["confidence"] == "medium":
                        f["confidence"] = "high"
                        f["confidence_boosted_by"] = f"newly_registered_{domain_age}d"

        all_findings.extend(findings)

        # -------------------------------------------------------------------
        # TIER 2 — Structural heuristics (run for ALL non-trusted pages)
        # -------------------------------------------------------------------
        domain_signals = _domain_structure_signals(hostname, final_url)
        redirect_signals = _redirect_chain_signals(manifest)
        content_signals = _page_content_signals(title, body, html, manifest)

        all_signals = domain_signals + redirect_signals + content_signals
        suspicion_score = _compute_suspicion_score(all_signals)

        if all_signals:
            page_heuristic = {
                "hostname": hostname,
                "final_url": final_url,
                "suspicion_score": round(suspicion_score, 3),
                "signals": all_signals,
            }
            heuristic_results.append(page_heuristic)

            # Boost existing findings with heuristic context
            for f in findings:
                if f["hostname"] == hostname:
                    f["suspicion_score"] = round(suspicion_score, 3)
                    f["heuristic_signals"] = [s["signal"] for s in all_signals]
                    # Heuristics can escalate medium -> high
                    if suspicion_score >= 0.6 and f["confidence"] == "medium":
                        f["confidence"] = "high"
                        f["confidence_boosted_by"] = "heuristic_score"

            if all_signals:
                signal_names = [s["signal"] for s in all_signals]
                print(
                    f"[detect_phishing_page] Tier 2 heuristics {hostname}: "
                    f"score={suspicion_score:.2f} signals={signal_names}"
                )

        # Standalone heuristic finding — no Tier 1 hit but high suspicion score
        if not tier1_hit and suspicion_score >= 0.6:
            heuristic_finding = {
                "brand": "Unknown (structural suspicion)",
                "confidence": "high" if suspicion_score >= 0.8 else "medium",
                "matched_pattern": "structural_heuristics",
                "title_hit": False,
                "body_hit": False,
                "final_url": final_url,
                "hostname": hostname,
                "suspicion_score": round(suspicion_score, 3),
                "heuristic_signals": [s["signal"] for s in all_signals],
                "capture_manifest": str(manifest_path),
                "source": "heuristic",
            }
            all_findings.append(heuristic_finding)
            print(
                f"[detect_phishing_page] HEURISTIC HIT "
                f"[{'HIGH' if suspicion_score >= 0.8 else 'MEDIUM'}] "
                f"{hostname} (score={suspicion_score:.2f})"
            )

        # Queue for Tier 3 escalation: no Tier 1 finding, but above threshold
        if not tier1_hit and suspicion_score >= _SUSPICION_ESCALATION_THRESHOLD:
            escalation_queue.append((
                manifest_path, hostname, final_url, title, body, html,
                suspicion_score, all_signals,
            ))

        scanned += 1

    # -----------------------------------------------------------------------
    # TIER 3 — LLM escalation (vision + purpose check) for indeterminate pages
    # -----------------------------------------------------------------------
    if ANTHROPIC_KEY and escalation_queue:
        print(
            f"[detect_phishing_page] Tier 3 escalation: {len(escalation_queue)} "
            f"indeterminate page(s) — running LLM checks"
        )

        # Track findings already produced so we can deduplicate
        existing_keys: set[tuple] = {
            (f["brand"], f["hostname"]) for f in all_findings
        }

        llm_vision_count = 0
        llm_purpose_count = 0

        for (manifest_path, hostname, final_url, title, body, html,
             suspicion_score, signals) in escalation_queue:

            page_determined = False

            # 3a. Vision check (if screenshot available, up to 10 total)
            if llm_vision_count < 10:
                screenshot_path = manifest_path.parent / "screenshot.png"
                if screenshot_path.exists():
                    vision_finding = _llm_vision_check(
                        screenshot_path, final_url, hostname,
                    )
                    llm_vision_count += 1

                    if vision_finding is not None:
                        key = (vision_finding["brand"], vision_finding["hostname"])
                        if key not in existing_keys:
                            vision_finding["capture_manifest"] = str(manifest_path)
                            vision_finding["suspicion_score"] = round(suspicion_score, 3)
                            vision_finding["heuristic_signals"] = [
                                s["signal"] for s in signals
                            ]
                            all_findings.append(vision_finding)
                            existing_keys.add(key)
                            page_determined = True
                            print(
                                f"[detect_phishing_page] LLM VISION "
                                f"[{vision_finding['confidence'].upper()}] "
                                f"{vision_finding['brand']} -> {hostname}"
                            )

            # 3b. Purpose check (if vision didn't determine, up to 10 total)
            if not page_determined and llm_purpose_count < 10:
                purpose_finding = _llm_purpose_check(
                    body, html, final_url, hostname, title,
                )
                llm_purpose_count += 1

                if purpose_finding is not None:
                    purpose_finding["capture_manifest"] = str(manifest_path)
                    purpose_finding["suspicion_score"] = round(suspicion_score, 3)
                    purpose_finding["heuristic_signals"] = [
                        s["signal"] for s in signals
                    ]
                    all_findings.append(purpose_finding)
                    purpose_assessments.append(
                        purpose_finding.get("purpose_assessment", {})
                    )
                    print(
                        f"[detect_phishing_page] PURPOSE CHECK "
                        f"[{purpose_finding['confidence'].upper()}] "
                        f"{hostname} — "
                        f"{purpose_finding.get('purpose_assessment', {}).get('stated_purpose', '')[:80]}"
                    )
                elif purpose_finding is None:
                    # LLM said page is clean — record the assessment for audit
                    purpose_assessments.append({
                        "hostname": hostname,
                        "has_clear_purpose": True,
                        "note": "LLM assessed as legitimate",
                    })

    elif escalation_queue and not ANTHROPIC_KEY:
        print(
            f"[detect_phishing_page] {len(escalation_queue)} page(s) need Tier 3 "
            f"escalation but ANTHROPIC_API_KEY is not set — skipping LLM checks"
        )
    elif ANTHROPIC_KEY and web_dir.exists():
        # No escalation queue, but still run LLM vision on pages without findings
        # (original behaviour — catch things regex missed)
        existing_keys: set[tuple] = {
            (f["brand"], f["hostname"]) for f in all_findings
        }
        llm_count = 0
        for manifest_path in manifest_paths:
            if llm_count >= 10:
                break
            manifest = json.loads(manifest_path.read_text())
            final_url = manifest.get("final_url", manifest.get("url", ""))
            hostname = _hostname(final_url)

            if _domain_allowed(hostname, _ALWAYS_TRUSTED):
                continue

            screenshot_path = manifest_path.parent / "screenshot.png"
            if not screenshot_path.exists():
                continue

            finding = _llm_vision_check(screenshot_path, final_url, hostname)
            llm_count += 1

            if finding is None:
                continue

            key = (finding["brand"], finding["hostname"])
            if key in existing_keys:
                continue

            finding["capture_manifest"] = str(manifest_path)
            all_findings.append(finding)
            existing_keys.add(key)
            print(
                f"[detect_phishing_page] LLM VISION [{finding['confidence'].upper()}] "
                f"{finding['brand']} -> {finding['hostname']}"
            )

    # -----------------------------------------------------------------------
    # Deduplicate and summarise
    # -----------------------------------------------------------------------
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for f in all_findings:
        key = (f["brand"], f["hostname"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    high = [f for f in deduped if f["confidence"] == "high"]
    medium = [f for f in deduped if f["confidence"] == "medium"]

    result = {
        "case_id": case_id,
        "ts": utcnow(),
        "scanned": scanned,
        "findings": deduped,
        "form_analysis": form_analysis_results,
        "tls_signals": tls_signals,
        "heuristic_analysis": heuristic_results,
        "purpose_assessments": purpose_assessments,
        "escalation_count": len(escalation_queue),
        "summary": {
            "high_confidence": len(high),
            "medium_confidence": len(medium),
            "total": len(deduped),
            "credential_harvest_pages": len(form_analysis_results),
            "suspicious_tls_certs": len(tls_signals),
            "pages_with_heuristic_signals": len(heuristic_results),
            "pages_escalated_to_llm": len(escalation_queue),
        },
    }

    write_artefact(
        out_dir / "phishing_detection.json",
        json.dumps(result, indent=2),
    )

    # Console output
    if deduped:
        for f in deduped:
            source = f.get("source", "regex")
            if source == "form_analysis":
                continue  # already printed above
            print(
                f"[detect_phishing_page] FINDING [{f['confidence'].upper()}] "
                f"{f['brand']} -> {f['hostname']} (via {source})"
            )
    if tls_signals:
        for ts in tls_signals:
            print(
                f"[detect_phishing_page] SUSPICIOUS TLS: {ts['hostname']} "
                f"— {', '.join(ts['reasons'])}"
            )
    if not deduped and not form_analysis_results and not tls_signals:
        if heuristic_results:
            print(
                f"[detect_phishing_page] No definitive findings, but "
                f"{len(heuristic_results)} page(s) had heuristic signals "
                f"({scanned} page(s) scanned)"
            )
        else:
            print(
                f"[detect_phishing_page] No phishing signals detected "
                f"({scanned} page(s) scanned)"
            )

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Detect brand impersonation in captured pages.")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = detect_phishing_page(args.case_id)
    print(json.dumps(result, indent=2, default=str))
