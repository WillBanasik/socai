"""
tool: enrich
------------
Pluggable enrichment layer.  For each IOC type, calls registered provider
functions and stores structured results.

Active providers:
  - VirusTotal     → IP, domain, URL, hash (MD5/SHA1/SHA256)
  - AbuseIPDB      → IP  (abuse confidence score, report count, ISP, usage type)
  - Shodan         → IP  (open ports, services, CVEs, org/ASN)
  - GreyNoise      → IP  (noise classification, malicious/benign/unknown, actor tags)
  - Intezer        → hash (MD5/SHA1/SHA256) — genetic malware analysis, family name
  - URLScan.io     → URL/domain (searches existing scans; returns verdict, score, screenshot link)
  - Censys         → IP, domain — cert/host infrastructure search (CENSYS_TOKEN)
  - URLhaus        → IP, domain, URL — Abuse.ch malware distribution URL database (free account key: ABUSECH_API_KEY)
  - ThreatFox      → IP, domain, URL, MD5, SHA256 — Abuse.ch C2/malware IOC database (free account key: ABUSECH_API_KEY)
  - MalwareBazaar  → MD5, SHA256 — Abuse.ch malware sample hash database (free account key: ABUSECH_API_KEY)
  - EmailRep.io    → email — reputation, blacklist, breach, disposable check (keyless / optional EMAILREP_API_KEY)
  - crt.sh         → domain — certificate transparency log search, subdomain discovery (keyless)
  - PhishTank       → URL/domain — community phishing URL database, known-phish verdict (keyless)

To add a new provider: implement a function with signature
  def provider_name(ioc: str, ioc_type: str) -> dict
and register it in PROVIDERS.

Writes:
  cases/<case_id>/artefacts/enrichment/enrichment.json
"""
from __future__ import annotations

import base64
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import (
    ABUSEIPDB_KEY, ABUSECH_KEY, CASES_DIR, CENSYS_TOKEN, EMAILREP_KEY,
    ENRICH_CACHE_FILE, ENRICH_CACHE_TTL, ENRICH_WORKERS, GREYNOISE_KEY,
    HYBRID_KEY, INTEZER_KEY, OPENCTI_KEY, OPENCTI_URL, OTX_KEY,
    PROXYCHECK_KEY, SHODAN_KEY,
    URLSCAN_KEY, VIRUSTOTAL_KEY, WHOISXML_KEY,
)
from tools.common import KNOWN_CLEAN_DOMAINS, get_session, load_json, log_error, save_json, utcnow, write_artefact


# ---------------------------------------------------------------------------
# Tier 0 — ASN-based infrastructure pre-screening
# ---------------------------------------------------------------------------

# ASNs belonging to major cloud/CDN providers.  IPs owned by these orgs are
# tagged "infra_clean" and skip expensive Tier 2 enrichment.
KNOWN_INFRA_ASNS: dict[int, str] = {
    # Microsoft
    8075: "Microsoft", 8068: "Microsoft", 8069: "Microsoft",
    12076: "Microsoft", 25459: "Microsoft", 52985: "Microsoft",
    # Amazon / AWS
    16509: "Amazon/AWS", 14618: "Amazon/AWS", 8987: "Amazon/AWS",
    38895: "Amazon/AWS",
    # Google / GCP
    15169: "Google", 36040: "Google", 36384: "Google",
    396982: "Google Cloud",
    # Cloudflare
    13335: "Cloudflare", 209242: "Cloudflare",
    # Akamai (CDN-only ASNs — NOT Linode/hosting ASNs which attackers use)
    20940: "Akamai", 16625: "Akamai", 32787: "Akamai",
    # Fastly
    54113: "Fastly",
    # Apple
    714: "Apple", 6185: "Apple",
    # Meta / Facebook
    32934: "Meta", 63293: "Meta",
    # Oracle Cloud — commented out; OCI is used by attackers
    # 31898: "Oracle Cloud",
    # DigitalOcean (legitimate hosting — not inherently clean, but low-value for enrichment)
    # Uncomment if you want to skip: 14061: "DigitalOcean",
}

# Reverse-lookup map: org name fragments (lowercase) from WHOIS/DNS that
# indicate major infra.  Fallback when ASN isn't in the set above.
_INFRA_ORG_KEYWORDS: frozenset[str] = frozenset({
    "microsoft", "amazon", "aws", "google", "cloudflare",
    "fastly", "apple", "facebook", "meta platforms",
})
# NOTE: Akamai and Oracle deliberately excluded from keyword matching because
# their hosting subsidiaries (Linode, OCI) are commonly used by attackers.
# Only specific CDN ASNs (20940, 16625, 32787) are in KNOWN_INFRA_ASNS.


def _asn_lookup_bulk(ips: list[str]) -> dict[str, dict]:
    """
    Bulk ASN lookup via Team Cymru DNS (free, no API key, RFC-compliant).

    For each IP, queries <reversed-ip>.origin.asn.cymru.com TXT record.
    Returns {ip: {"asn": int, "owner": str, "prefix": str}} or {} on failure.

    Falls back to sequential DNS queries (fast enough for <100 IPs).
    """
    import socket
    results: dict[str, dict] = {}

    for ip in ips:
        try:
            parts = ip.strip().split(".")
            if len(parts) != 4:
                continue
            query = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.origin.asn.cymru.com"
            answers = socket.getaddrinfo(query, None, socket.AF_INET, socket.SOCK_DGRAM)
            # TXT record via DNS — use direct resolution
        except Exception:
            pass

    # Team Cymru DNS TXT records — more reliable approach using dnspython if
    # available, otherwise fall back to a lightweight HTTP API.
    try:
        import dns.resolver
        _use_dnspython = True
    except ImportError:
        _use_dnspython = False

    if _use_dnspython:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        for ip in ips:
            try:
                parts = ip.strip().split(".")
                if len(parts) != 4:
                    continue
                query = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.origin.asn.cymru.com"
                answers = resolver.resolve(query, "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    # Format: "ASN | PREFIX | CC | RIR | DATE"
                    fields = [f.strip() for f in txt.split("|")]
                    if len(fields) >= 2:
                        asn = int(fields[0])
                        prefix = fields[1]
                        results[ip] = {"asn": asn, "prefix": prefix, "owner": ""}
                    break
            except Exception:
                continue

        # Batch ASN-to-name resolution
        asns_to_resolve = {r["asn"] for r in results.values() if r["asn"]}
        asn_names: dict[int, str] = {}
        for asn in asns_to_resolve:
            try:
                answers = resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    fields = [f.strip() for f in txt.split("|")]
                    if len(fields) >= 5:
                        asn_names[asn] = fields[4]
                    break
            except Exception:
                continue
        for ip, info in results.items():
            info["owner"] = asn_names.get(info["asn"], "")
    else:
        # Fallback: use ipinfo.io (no key needed for <1000/day)
        for ip in ips:
            try:
                resp = get_session().get(f"https://ipinfo.io/{ip}/json", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    org = data.get("org", "")
                    asn = 0
                    if org.startswith("AS"):
                        asn_str = org.split()[0][2:]
                        try:
                            asn = int(asn_str)
                        except ValueError:
                            pass
                    results[ip] = {"asn": asn, "prefix": "", "owner": org}
            except Exception:
                continue

    return results


def _classify_ip_infra(ip: str, asn_info: dict) -> str | None:
    """
    Return the infrastructure owner name if the IP belongs to known infra,
    or None if it should proceed to full enrichment.
    """
    asn = asn_info.get("asn", 0)
    if asn in KNOWN_INFRA_ASNS:
        return KNOWN_INFRA_ASNS[asn]

    # Fallback: check org name for known keywords
    owner = asn_info.get("owner", "").lower()
    for kw in _INFRA_ORG_KEYWORDS:
        if kw in owner:
            return owner.title()

    return None


# ---------------------------------------------------------------------------
# Provider stubs
# ---------------------------------------------------------------------------

def _vt_lookup(ioc: str, ioc_type: str) -> dict:
    """VirusTotal API v3 lookup for domains, URLs, IPs, and file hashes."""
    if not VIRUSTOTAL_KEY:
        return {"provider": "virustotal", "status": "no_api_key", "ioc": ioc}

    base = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": VIRUSTOTAL_KEY}

    if ioc_type == "domain":
        url = f"{base}/domains/{ioc}"
    elif ioc_type == "ipv4":
        url = f"{base}/ip_addresses/{ioc}"
    elif ioc_type in ("md5", "sha1", "sha256"):
        url = f"{base}/files/{ioc}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).rstrip(b"=").decode()
        url = f"{base}/urls/{url_id}"
    else:
        return {"provider": "virustotal", "status": "unsupported_type", "ioc": ioc}

    try:
        resp = get_session().get(url, headers=headers, timeout=15)
    except Exception as exc:
        return {"provider": "virustotal", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 404:
        return {"provider": "virustotal", "status": "not_found", "ioc": ioc}
    if resp.status_code == 401:
        return {"provider": "virustotal", "status": "invalid_api_key", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "virustotal", "status": f"http_{resp.status_code}", "ioc": ioc}

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    verdict = "clean"
    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"

    result = {
        "provider": "virustotal",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "vt_link": f"https://www.virustotal.com/gui/{'domain' if ioc_type == 'domain' else 'ip-address' if ioc_type == 'ipv4' else 'file' if ioc_type in ('md5','sha1','sha256') else 'url'}/{ioc}",
    }

    # Pull reputation score if available (domains/IPs)
    if "reputation" in attrs:
        result["reputation"] = attrs["reputation"]

    # Pull categories if available (domains)
    if "categories" in attrs:
        result["categories"] = list(attrs["categories"].values())

    return result


def _abuseipdb_lookup(ioc: str, ioc_type: str) -> dict:
    """AbuseIPDB v2 — abuse confidence score, report count, ISP, usage type."""
    if ioc_type != "ipv4":
        return {"provider": "abuseipdb", "status": "skipped", "ioc": ioc}
    if not ABUSEIPDB_KEY:
        return {"provider": "abuseipdb", "status": "no_api_key", "ioc": ioc}

    try:
        resp = get_session().get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ioc, "maxAgeInDays": 90},
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "abuseipdb", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 401:
        return {"provider": "abuseipdb", "status": "invalid_api_key", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "abuseipdb", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json().get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    verdict = "malicious" if score >= 80 else "suspicious" if score >= 25 else "clean"

    return {
        "provider": "abuseipdb",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "abuse_confidence_score": score,
        "total_reports": d.get("totalReports", 0),
        "distinct_users": d.get("numDistinctUsers", 0),
        "country_code": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "domain": d.get("domain"),
        "last_reported": d.get("lastReportedAt"),
        "is_whitelisted": d.get("isWhitelisted", False),
    }


def _shodan_lookup(ioc: str, ioc_type: str) -> dict:
    """Shodan host lookup — open ports, services, CVEs, org/ASN."""
    if ioc_type != "ipv4":
        return {"provider": "shodan", "status": "skipped", "ioc": ioc}
    if not SHODAN_KEY:
        return {"provider": "shodan", "status": "no_api_key", "ioc": ioc}

    try:
        resp = get_session().get(
            f"https://api.shodan.io/shodan/host/{ioc}",
            params={"key": SHODAN_KEY},
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "shodan", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 404:
        return {"provider": "shodan", "status": "not_found", "ioc": ioc}
    if resp.status_code == 401:
        return {"provider": "shodan", "status": "invalid_api_key", "ioc": ioc}
    if resp.status_code == 403:
        return {"provider": "shodan", "status": "plan_restriction",
                "ioc": ioc, "note": "Host lookups require a Shodan paid plan."}
    if resp.status_code != 200:
        return {"provider": "shodan", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json()
    ports = sorted(d.get("ports", []))
    vulns = list(d.get("vulns", {}).keys())

    # Summarise services from banner data
    services = []
    for item in d.get("data", []):
        svc = item.get("product") or item.get("_shodan", {}).get("module")
        if svc and svc not in services:
            services.append(svc)

    return {
        "provider": "shodan",
        "status": "ok",
        "ioc": ioc,
        "org": d.get("org"),
        "isp": d.get("isp"),
        "asn": d.get("asn"),
        "country": d.get("country_name"),
        "hostnames": d.get("hostnames", []),
        "os": d.get("os"),
        "open_ports": ports,
        "services": services,
        "cves": vulns,
        "last_update": d.get("last_update"),
        "shodan_link": f"https://www.shodan.io/host/{ioc}",
    }


def _greynoise_lookup(ioc: str, ioc_type: str) -> dict:
    """GreyNoise Community API — noise/riot classification for IPs."""
    if ioc_type != "ipv4":
        return {"provider": "greynoise", "status": "skipped", "ioc": ioc}
    if not GREYNOISE_KEY:
        return {"provider": "greynoise", "status": "no_api_key", "ioc": ioc}

    headers = {"key": GREYNOISE_KEY, "Accept": "application/json"}
    result: dict = {"provider": "greynoise", "ioc": ioc}

    try:
        resp = get_session().get(
            f"https://api.greynoise.io/v3/community/{ioc}",
            headers=headers, timeout=15,
        )
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    if resp.status_code in (200, 404):
        c = resp.json()
        classification = c.get("classification", "unknown")
        noise = c.get("noise", False)
        riot = c.get("riot", False)
        result.update({
            "status": "ok",
            "api_tier": "community",
            "verdict": "malicious" if classification == "malicious" else (
                "clean" if classification == "benign" else "unknown"
            ),
            "seen": noise or riot,
            "is_riot": riot,
            "classification": classification,
            "name": c.get("name"),
            "last_seen": c.get("last_seen"),
            "message": c.get("message"),
            "greynoise_link": c.get("link", f"https://viz.greynoise.io/ip/{ioc}"),
        })
        return result

    if resp.status_code == 429:
        result["status"] = "rate_limited"
        result["note"] = "GreyNoise community plan weekly quota exceeded (50/week)."
        return result

    if resp.status_code in (401, 403):
        result["status"] = "invalid_api_key"
        return result

    result["status"] = f"http_{resp.status_code}"
    return result


def _intezer_get_token() -> str | None:
    """Fetch an Intezer access token. Returns None on failure."""
    if not INTEZER_KEY:
        return None
    try:
        tok_resp = get_session().post(
            "https://analyze.intezer.com/api/v2-0/get-access-token",
            json={"api_key": INTEZER_KEY},
            timeout=15,
        )
        if tok_resp.status_code == 200:
            return tok_resp.json().get("result")
    except Exception as exc:
        log_error("", "enrich.intezer_token", str(exc), severity="info")
    return None


def _intezer_lookup(ioc: str, ioc_type: str, _token: str | None = None) -> dict:
    """Intezer Analyze — genetic malware analysis for file hashes.

    *_token*: pre-fetched access token.  When None, a token is fetched
    on-demand (fallback for standalone / test use).
    """
    if ioc_type not in ("md5", "sha1", "sha256"):
        return {"provider": "intezer", "status": "skipped", "ioc": ioc}
    if not INTEZER_KEY:
        return {"provider": "intezer", "status": "no_api_key", "ioc": ioc}

    token = _token
    if not token:
        # Fallback: fetch token now (standalone call or test)
        try:
            tok_resp = get_session().post(
                "https://analyze.intezer.com/api/v2-0/get-access-token",
                json={"api_key": INTEZER_KEY},
                timeout=15,
            )
            if tok_resp.status_code != 200:
                return {"provider": "intezer", "status": f"auth_http_{tok_resp.status_code}", "ioc": ioc}
            token = tok_resp.json().get("result")
        except Exception as exc:
            return {"provider": "intezer", "status": "error", "ioc": ioc, "error": str(exc)}

    if not token:
        return {"provider": "intezer", "status": "auth_failed", "ioc": ioc}

    headers = {"Authorization": f"Bearer {token}"}

    # Hash lookup — returns the latest analysis for this hash if it exists
    try:
        resp = get_session().get(
            f"https://analyze.intezer.com/api/v2-0/files/{ioc}",
            headers=headers,
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "intezer", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code in (404, 410):
        return {"provider": "intezer", "status": "not_found", "ioc": ioc}
    if resp.status_code in (401, 403):
        return {"provider": "intezer", "status": "invalid_api_key", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "intezer", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json().get("result", {})
    verdict = d.get("verdict", "unknown")

    result = {
        "provider": "intezer",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "sub_verdict": d.get("sub_verdict"),
        "family_name": d.get("family_name"),
        "family_type": d.get("family_type"),
        "analysis_id": d.get("analysis_id"),
        "analysis_url": d.get("analysis_url"),
    }
    return result


def _urlscan_lookup(ioc: str, ioc_type: str) -> dict:
    """URLScan.io — search existing scans for a domain or URL."""
    if not URLSCAN_KEY:
        return {"provider": "urlscan", "status": "no_api_key", "ioc": ioc}

    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}

    # Build search query
    if ioc_type == "domain":
        query = f"domain:{ioc}"
    elif ioc_type == "url":
        query = f"page.url:{ioc}"
    else:
        return {"provider": "urlscan", "status": "skipped", "ioc": ioc}

    try:
        resp = get_session().get(
            "https://urlscan.io/api/v1/search/",
            headers=headers,
            params={"q": query, "size": 5},
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "urlscan", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 401:
        return {"provider": "urlscan", "status": "invalid_api_key", "ioc": ioc}
    if resp.status_code == 429:
        return {"provider": "urlscan", "status": "rate_limited", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "urlscan", "status": f"http_{resp.status_code}", "ioc": ioc}

    data = resp.json()
    results = data.get("results", [])
    total = data.get("total", 0)

    if not results:
        return {"provider": "urlscan", "status": "not_found", "ioc": ioc, "total_scans": 0}

    # Use the most recent scan for the verdict
    latest = results[0]
    verdicts = latest.get("verdicts", {}).get("overall", {})
    malicious = verdicts.get("malicious", False)
    score = verdicts.get("score", 0)
    tags = verdicts.get("tags", [])
    brands = verdicts.get("brands", [])

    verdict = "malicious" if malicious else ("suspicious" if score > 0 else "clean")

    return {
        "provider": "urlscan",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "malicious": malicious,
        "score": score,
        "tags": tags,
        "brands": brands,
        "total_scans": total,
        "latest_scan_time": latest.get("task", {}).get("time"),
        "latest_scan_url": f"https://urlscan.io/result/{latest.get('_id')}/",
        "page_status": latest.get("page", {}).get("status"),
        "screenshot": f"https://urlscan.io/screenshots/{latest.get('_id')}.png",
    }


def _proxycheck_lookup(ioc: str, ioc_type: str) -> dict:
    """proxycheck.io — detect proxy, VPN, Tor, and datacenter IPs with risk score."""
    if ioc_type != "ipv4":
        return {"provider": "proxycheck", "status": "skipped", "ioc": ioc}
    if not PROXYCHECK_KEY:
        return {"provider": "proxycheck", "status": "no_api_key", "ioc": ioc}

    try:
        resp = get_session().get(
            f"https://proxycheck.io/v2/{ioc}",
            params={"key": PROXYCHECK_KEY, "vpn": 1, "risk": 1},
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "proxycheck", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code != 200:
        return {"provider": "proxycheck", "status": f"http_{resp.status_code}", "ioc": ioc}

    data = resp.json()
    if data.get("status") == "error":
        return {"provider": "proxycheck", "status": "api_error", "ioc": ioc,
                "message": data.get("message")}

    ip_data = data.get(ioc, {})
    is_proxy = ip_data.get("proxy", "no").lower() == "yes"
    proxy_type = ip_data.get("type")
    risk = ip_data.get("risk", 0)

    verdict = "malicious" if (is_proxy and risk >= 66) else (
              "suspicious" if (is_proxy or risk >= 33) else "clean")

    return {
        "provider": "proxycheck",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "is_proxy": is_proxy,
        "proxy_type": proxy_type,
        "risk_score": risk,
        "country": ip_data.get("country"),
        "isp": ip_data.get("provider"),
    }


def _opencti_lookup(ioc: str, ioc_type: str) -> dict:
    """OpenCTI — query internal threat intel platform for observable + related objects."""
    if not OPENCTI_KEY:
        return {"provider": "opencti", "status": "no_api_key", "ioc": ioc}

    # Map IOC types to GraphQL filter keys and observable types
    _hash_types = {"md5", "sha1", "sha256"}
    _value_types = {"ipv4", "domain", "url", "email"}

    if ioc_type not in _value_types and ioc_type not in _hash_types and ioc_type != "cve":
        return {"provider": "opencti", "status": "skipped", "ioc": ioc}

    headers = {
        "Authorization": f"Bearer {OPENCTI_KEY}",
        "Content-Type": "application/json",
    }
    graphql_url = f"{OPENCTI_URL}/graphql"

    # CVEs are Vulnerabilities, not StixCyberObservables
    if ioc_type == "cve":
        query = """
        {
          vulnerabilities(
            filters: {
              mode: and,
              filters: [{key: "name", values: ["%s"], operator: eq}],
              filterGroups: []
            }
            first: 1
          ) {
            edges {
              node {
                id
                name
                created_at
                x_opencti_epss_score
                x_opencti_cisa_kev
                description
                reports { edges { node { name published } } }
              }
            }
          }
        }
        """ % ioc
        try:
            resp = get_session().post(graphql_url, headers=headers, json={"query": query}, timeout=15)
            resp.raise_for_status()
        except Exception as exc:
            return {"provider": "opencti", "status": "error", "ioc": ioc, "error": str(exc)}

        data = resp.json()
        if "errors" in data:
            return {"provider": "opencti", "status": "api_error", "ioc": ioc,
                    "message": data["errors"][0].get("message")}

        edges = data.get("data", {}).get("vulnerabilities", {}).get("edges", [])
        if not edges:
            return {"provider": "opencti", "status": "not_found", "ioc": ioc}

        node = edges[0]["node"]
        reports = [r["node"]["name"] for r in node.get("reports", {}).get("edges", [])]
        return {
            "provider": "opencti", "status": "ok", "ioc": ioc,
            "entity_type": "Vulnerability",
            "epss_score": node.get("x_opencti_epss_score"),
            "cisa_kev": node.get("x_opencti_cisa_kev", False),
            "description": (node.get("description") or "")[:300] or None,
            "report_count": len(reports),
            "reports": reports[:5],
            "opencti_link": f"{OPENCTI_URL}/dashboard/arsenal/vulnerabilities/{node['id']}",
        }

    # StixCyberObservable lookup
    # Hashes use the `search` param (exact match); IP/domain/URL use the `value` filter key
    is_hash = ioc_type in _hash_types
    if is_hash:
        search_arg = 'search: "%s",' % ioc
        filter_block = """filters: {
          mode: and,
          filters: [{key: "entity_type", values: ["StixFile"], operator: eq}],
          filterGroups: []
        }"""
    else:
        search_arg = ""
        filter_block = """filters: {
          mode: and,
          filters: [{key: "value", values: ["%s"], operator: eq}],
          filterGroups: []
        }""" % ioc

    query = """
    {
      stixCyberObservables(
        first: 1,
        %s
        %s
      ) {
        edges {
          node {
            id
            entity_type
            observable_value
            created_at
            x_opencti_score
            indicators {
              edges { node { name pattern_type x_opencti_score } }
            }
            reports {
              edges { node { name published } }
            }
            stixCoreRelationships {
              edges {
                node {
                  relationship_type
                  to {
                    __typename
                    ... on ThreatActor       { name }
                    ... on ThreatActorGroup  { name }
                    ... on Malware           { name malware_types }
                    ... on AttackPattern     { name x_mitre_id }
                    ... on Campaign          { name }
                    ... on IntrusionSet      { name }
                  }
                }
              }
            }
          }
        }
      }
    }
    """ % (search_arg, filter_block)

    try:
        resp = get_session().post(graphql_url, headers=headers, json={"query": query}, timeout=15)
        resp.raise_for_status()
    except Exception as exc:
        return {"provider": "opencti", "status": "error", "ioc": ioc, "error": str(exc)}

    data = resp.json()
    if "errors" in data:
        return {"provider": "opencti", "status": "api_error", "ioc": ioc,
                "message": data["errors"][0].get("message")}

    edges = data.get("data", {}).get("stixCyberObservables", {}).get("edges", [])
    if not edges:
        return {"provider": "opencti", "status": "not_found", "ioc": ioc}

    node = edges[0]["node"]
    score = node.get("x_opencti_score")
    verdict = ("malicious" if score and score >= 70 else
               "suspicious" if score and score >= 40 else
               "clean" if score is not None else "unknown")

    # Extract related objects
    indicators = [
        {"name": e["node"]["name"], "pattern_type": e["node"]["pattern_type"],
         "score": e["node"]["x_opencti_score"]}
        for e in node.get("indicators", {}).get("edges", [])
    ]
    reports = [e["node"]["name"] for e in node.get("reports", {}).get("edges", [])]

    related: dict[str, list] = {}
    for e in node.get("stixCoreRelationships", {}).get("edges", []):
        rel_node = e["node"]
        typename = rel_node.get("to", {}).get("__typename", "")
        name = rel_node.get("to", {}).get("name")
        if not name:
            continue
        rel_type = rel_node.get("relationship_type", typename)
        related.setdefault(rel_type, [])
        entry = {"type": typename, "name": name}
        if "x_mitre_id" in rel_node.get("to", {}):
            entry["mitre_id"] = rel_node["to"]["x_mitre_id"]
        if "malware_types" in rel_node.get("to", {}):
            entry["malware_types"] = rel_node["to"]["malware_types"]
        if entry not in related[rel_type]:
            related[rel_type].append(entry)

    entity_path = {
        "IPv4-Addr": "observations/observables",
        "Domain-Name": "observations/observables",
        "Url": "observations/observables",
        "StixFile": "observations/observables",
        "Email-Addr": "observations/observables",
    }.get(node["entity_type"], "observations/observables")

    return {
        "provider": "opencti",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "entity_type": node["entity_type"],
        "opencti_score": score,
        "created_at": node.get("created_at"),
        "indicator_count": len(indicators),
        "indicators": indicators[:5],
        "report_count": len(reports),
        "reports": reports[:5],
        "related": related,
        "opencti_link": f"{OPENCTI_URL}/dashboard/{entity_path}/{node['id']}",
    }


# ---------------------------------------------------------------------------
# Free / no-auth providers (Abuse.ch ecosystem + EmailRep)
# ---------------------------------------------------------------------------

def _urlhaus_lookup(ioc: str, ioc_type: str) -> dict:
    """URLhaus (Abuse.ch) — malware distribution URL/host database. Free account key required."""
    if ioc_type not in ("url", "domain", "ipv4"):
        return {"provider": "urlhaus", "status": "skipped", "ioc": ioc}
    if not ABUSECH_KEY:
        return {"provider": "urlhaus", "status": "no_api_key", "ioc": ioc}

    headers = {"Auth-Key": ABUSECH_KEY}
    try:
        if ioc_type == "url":
            resp = get_session().post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                headers=headers,
                data={"url": ioc},
                timeout=15,
            )
        else:
            # domain or ipv4 → host lookup
            resp = get_session().post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                headers=headers,
                data={"host": ioc},
                timeout=15,
            )
    except Exception as exc:
        return {"provider": "urlhaus", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code != 200:
        return {"provider": "urlhaus", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json()
    query_status = d.get("query_status", "")

    if query_status in ("no_results", "invalid_url", "invalid_host"):
        return {"provider": "urlhaus", "status": "not_found", "ioc": ioc}

    if ioc_type == "url":
        url_status = d.get("url_status", "unknown")
        threat = d.get("threat", "")
        tags = d.get("tags") or []
        verdict = "malicious" if url_status == "online" else (
                  "suspicious" if url_status == "unknown" else "clean")
        return {
            "provider": "urlhaus",
            "status": "ok",
            "ioc": ioc,
            "verdict": verdict,
            "url_status": url_status,
            "threat": threat,
            "tags": tags,
            "date_added": d.get("date_added"),
            "urlhaus_link": d.get("urlhaus_reference"),
        }
    else:
        # host response: list of URLs hosted
        urls = d.get("urls", [])
        online = sum(1 for u in urls if u.get("url_status") == "online")
        verdict = "malicious" if online > 0 else "suspicious" if urls else "clean"
        tags = list({t for u in urls for t in (u.get("tags") or [])})
        return {
            "provider": "urlhaus",
            "status": "ok",
            "ioc": ioc,
            "verdict": verdict,
            "urls_total": len(urls),
            "urls_online": online,
            "tags": tags,
            "urlhaus_link": d.get("urlhaus_reference"),
        }


def _threatfox_lookup(ioc: str, ioc_type: str) -> dict:
    """ThreatFox (Abuse.ch) — C2 and malware IOC database. Free account key required."""
    if ioc_type not in ("ipv4", "domain", "url", "md5", "sha256"):
        return {"provider": "threatfox", "status": "skipped", "ioc": ioc}
    if not ABUSECH_KEY:
        return {"provider": "threatfox", "status": "no_api_key", "ioc": ioc}

    try:
        resp = get_session().post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": ABUSECH_KEY},
            json={"query": "search_ioc", "search_term": ioc},
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "threatfox", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code != 200:
        return {"provider": "threatfox", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json()
    if d.get("query_status") == "no_result":
        return {"provider": "threatfox", "status": "not_found", "ioc": ioc}

    iocs = d.get("data", [])
    if not iocs:
        return {"provider": "threatfox", "status": "not_found", "ioc": ioc}

    # Use the most recent / highest-confidence entry
    entry = iocs[0]
    malware_family = entry.get("malware_printable") or entry.get("malware")
    threat_type = entry.get("threat_type")
    confidence = entry.get("confidence_level", 0)
    tags = entry.get("tags") or []

    return {
        "provider": "threatfox",
        "status": "ok",
        "ioc": ioc,
        "verdict": "malicious",
        "malware_family": malware_family,
        "threat_type": threat_type,
        "confidence_level": confidence,
        "tags": tags,
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        "total_matches": len(iocs),
        "threatfox_link": f"https://threatfox.abuse.ch/ioc/{entry.get('id', '')}",
    }


def _malwarebazaar_lookup(ioc: str, ioc_type: str) -> dict:
    """MalwareBazaar (Abuse.ch) — malware sample hash database. Free account key required."""
    if ioc_type not in ("md5", "sha256"):
        return {"provider": "malwarebazaar", "status": "skipped", "ioc": ioc}
    if not ABUSECH_KEY:
        return {"provider": "malwarebazaar", "status": "no_api_key", "ioc": ioc}

    try:
        resp = get_session().post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": ABUSECH_KEY},
            data={"query": "get_info", "hash": ioc},
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "malwarebazaar", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code != 200:
        return {"provider": "malwarebazaar", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json()
    if d.get("query_status") == "hash_not_found":
        return {"provider": "malwarebazaar", "status": "not_found", "ioc": ioc}

    data = d.get("data", [])
    if not data:
        return {"provider": "malwarebazaar", "status": "not_found", "ioc": ioc}

    entry = data[0]
    tags = entry.get("tags") or []
    signature = entry.get("signature")

    return {
        "provider": "malwarebazaar",
        "status": "ok",
        "ioc": ioc,
        "verdict": "malicious",
        "file_name": entry.get("file_name"),
        "file_type": entry.get("file_type"),
        "file_size": entry.get("file_size"),
        "mime_type": entry.get("mime_type"),
        "signature": signature,
        "tags": tags,
        "first_seen": entry.get("first_seen"),
        "last_seen": entry.get("last_seen"),
        "delivery_method": entry.get("delivery_method"),
        "intelligence": entry.get("intelligence", {}),
        "bazaar_link": f"https://bazaar.abuse.ch/sample/{entry.get('sha256_hash', ioc)}/",
    }


def _otx_lookup(ioc: str, ioc_type: str) -> dict:
    """AlienVault OTX — community threat intel pulses, malware, passive DNS."""
    if ioc_type not in ("ipv4", "domain", "url", "md5", "sha1", "sha256"):
        return {"provider": "otx", "status": "skipped", "ioc": ioc}
    if not OTX_KEY:
        return {"provider": "otx", "status": "no_api_key", "ioc": ioc}

    headers = {"X-OTX-API-KEY": OTX_KEY}
    _type_map = {
        "ipv4": "IPv4", "domain": "domain", "url": "url",
        "md5": "file", "sha1": "file", "sha256": "file",
    }
    otx_type = _type_map[ioc_type]
    base = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}"

    try:
        general = get_session().get(f"{base}/general", headers=headers, timeout=15).json()
    except Exception as exc:
        return {"provider": "otx", "status": "error", "ioc": ioc, "error": str(exc)}

    if "detail" in general and "not found" in str(general["detail"]).lower():
        return {"provider": "otx", "status": "not_found", "ioc": ioc}

    pulse_count = general.get("pulse_info", {}).get("count", 0)
    pulses = general.get("pulse_info", {}).get("pulses", [])
    tags = list({t for p in pulses for t in p.get("tags", [])})
    malware_families = list({m.get("display_name") for p in pulses
                             for m in p.get("malware_families", []) if m.get("display_name")})
    adversaries = list({p.get("adversary") for p in pulses if p.get("adversary")})

    verdict = "malicious" if pulse_count >= 3 else "suspicious" if pulse_count >= 1 else "clean"

    result = {
        "provider": "otx",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "pulse_count": pulse_count,
        "tags": tags[:15],
        "malware_families": malware_families[:5],
        "adversaries": adversaries[:5],
        "otx_link": f"https://otx.alienvault.com/indicator/{otx_type}/{ioc}",
    }

    # For IPs/domains also pull passive DNS
    if ioc_type in ("ipv4", "domain"):
        try:
            pdns = get_session().get(f"{base}/passive_dns", headers=headers, timeout=15).json()
            records = pdns.get("passive_dns", [])
            result["passive_dns_count"] = len(records)
            result["passive_dns_sample"] = [
                {"hostname": r.get("hostname"), "address": r.get("address"), "last": r.get("last")}
                for r in records[:5]
            ]
        except Exception as exc:
            log_error("", "enrich.otx_passive_dns", str(exc), severity="info")

    return result


def _hybrid_lookup(ioc: str, ioc_type: str) -> dict:
    """Hybrid Analysis (Falcon Sandbox) — behavioural sandbox verdict for SHA256 hashes.

    Uses the /overview/{sha256} endpoint (SHA256 only; MD5/SHA1 skipped as the
    /search/hash endpoint is currently non-functional upstream).
    """
    if ioc_type not in ("sha256",):
        return {"provider": "hybrid_analysis", "status": "skipped", "ioc": ioc}
    if not HYBRID_KEY:
        return {"provider": "hybrid_analysis", "status": "no_api_key", "ioc": ioc}

    headers = {"api-key": HYBRID_KEY, "User-Agent": "Falcon Sandbox"}

    try:
        resp = get_session().get(
            f"https://www.hybrid-analysis.com/api/v2/overview/{ioc}",
            headers=headers,
            timeout=20,
        )
    except Exception as exc:
        return {"provider": "hybrid_analysis", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 401:
        return {"provider": "hybrid_analysis", "status": "invalid_api_key", "ioc": ioc}
    if resp.status_code == 404:
        return {"provider": "hybrid_analysis", "status": "not_found", "ioc": ioc}
    if resp.status_code == 429:
        return {"provider": "hybrid_analysis", "status": "rate_limited", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "hybrid_analysis", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json()
    verdict_raw = d.get("verdict") or "unknown"
    threat_score = d.get("threat_score") or 0

    verdict = "malicious" if verdict_raw == "malicious" else (
              "suspicious" if verdict_raw == "suspicious" else
              "clean" if verdict_raw in ("no specific threat", "whitelisted") else "unknown")

    return {
        "provider": "hybrid_analysis",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "threat_score": threat_score,
        "verdict_raw": verdict_raw,
        "malware_family": d.get("vx_family"),
        "file_type": d.get("type_short"),
        "file_name": d.get("last_file_name"),
        "av_detect": d.get("av_detect"),
        "report_url": f"https://www.hybrid-analysis.com/sample/{ioc}",
    }


def _whoisxml_lookup(ioc: str, ioc_type: str) -> dict:
    """WHOISXML API — registrant data, domain age, newly registered domain detection."""
    if ioc_type != "domain":
        return {"provider": "whoisxml", "status": "skipped", "ioc": ioc}
    if not WHOISXML_KEY:
        return {"provider": "whoisxml", "status": "no_api_key", "ioc": ioc}

    try:
        resp = get_session().get(
            "https://www.whoisxmlapi.com/whoisserver/WhoisService",
            params={
                "apiKey": WHOISXML_KEY,
                "domainName": ioc,
                "outputFormat": "JSON",
            },
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "whoisxml", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 401:
        return {"provider": "whoisxml", "status": "invalid_api_key", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "whoisxml", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json().get("WhoisRecord", {})
    if not d:
        return {"provider": "whoisxml", "status": "not_found", "ioc": ioc}

    registry = d.get("registryData", {})
    created_str = registry.get("createdDate") or d.get("createdDate")
    expires_str = registry.get("expiresDate") or d.get("expiresDate")
    registrar = d.get("registrarName") or registry.get("registrarName")
    registrant = d.get("registrant", {})

    # Calculate domain age in days
    domain_age_days = None
    newly_registered = False
    try:
        from datetime import datetime, timezone
        created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        from tools.common import utcnow as _utcnow
        _now = datetime.fromisoformat(_utcnow().replace("Z", "+00:00"))
        domain_age_days = (_now - created_dt).days
        newly_registered = domain_age_days < 30
    except Exception as exc:
        log_error("", "enrich.whoisxml_domain_age", str(exc), severity="info")

    # Newly registered domains are a strong phishing signal
    verdict = "suspicious" if newly_registered else "clean"

    return {
        "provider": "whoisxml",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "registrar": registrar,
        "created_date": created_str,
        "expires_date": expires_str,
        "domain_age_days": domain_age_days,
        "newly_registered": newly_registered,
        "registrant_org": registrant.get("organization"),
        "registrant_country": registrant.get("country"),
        "registrant_email": registrant.get("email"),
        "name_servers": d.get("nameServers", {}).get("hostNames", [])[:4],
        "whoisxml_link": f"https://www.whoisxmlapi.com/whois/{ioc}",
    }


def _censys_lookup(ioc: str, ioc_type: str) -> dict:
    """Censys Platform API v3 — host and certificate search using Personal Access Token."""
    if ioc_type not in ("ipv4", "domain"):
        return {"provider": "censys", "status": "skipped", "ioc": ioc}
    if not CENSYS_TOKEN:
        return {"provider": "censys", "status": "no_api_key", "ioc": ioc}

    headers = {
        "Authorization": f"Bearer {CENSYS_TOKEN}",
        "Accept": "application/json",
    }
    base = "https://api.platform.censys.io/v3/global"

    try:
        if ioc_type == "ipv4":
            resp = get_session().get(
                f"{base}/asset/host/{ioc}",
                headers=headers,
                timeout=15,
            )
        else:
            # Domain → search hosts with matching cert SANs
            resp = get_session().get(
                f"{base}/asset/host/search",
                headers=headers,
                params={"q": f"dns.reverse_dns.reverse_dns: {ioc}", "per_page": 5},
                timeout=15,
            )
    except Exception as exc:
        return {"provider": "censys", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 401:
        return {"provider": "censys", "status": "invalid_api_key", "ioc": ioc}
    if resp.status_code == 404:
        return {"provider": "censys", "status": "not_found", "ioc": ioc}
    if resp.status_code == 429:
        return {"provider": "censys", "status": "rate_limited", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "censys", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json().get("result", resp.json()).get("resource", resp.json().get("result", resp.json()))

    if ioc_type == "ipv4":
        services = d.get("services", [])
        ports = sorted({s.get("port") for s in services if s.get("port")})
        service_names = list({s.get("service_name") for s in services if s.get("service_name")})
        labels = d.get("labels", [])
        asn = d.get("autonomous_system", {})

        # Extract cert SANs to spot shared phishing infrastructure
        sans = []
        for svc in services:
            for name in svc.get("tls", {}).get("certificates", {}).get("leaf_data", {}).get("names", []):
                if name not in sans:
                    sans.append(name)

        verdict = "suspicious" if any(l in labels for l in ("malicious", "suspicious")) else "clean"

        return {
            "provider": "censys",
            "status": "ok",
            "ioc": ioc,
            "verdict": verdict,
            "open_ports": ports,
            "services": service_names,
            "labels": labels,
            "asn": asn.get("asn"),
            "org": asn.get("name"),
            "country": d.get("location", {}).get("country"),
            "cert_sans": sans[:10],
            "censys_link": f"https://search.censys.io/hosts/{ioc}",
        }
    else:
        hits = d.get("hits", [])
        if not hits:
            return {"provider": "censys", "status": "not_found", "ioc": ioc}
        ips = [h.get("ip") for h in hits if h.get("ip")]
        return {
            "provider": "censys",
            "status": "ok",
            "ioc": ioc,
            "verdict": "clean",
            "associated_ips": ips[:10],
            "hit_count": len(hits),
            "censys_link": f"https://search.censys.io/search?resource=hosts&q=dns.reverse_dns.reverse_dns%3A{ioc}",
        }


def _emailrep_lookup(ioc: str, ioc_type: str) -> dict:
    """EmailRep.io — email address reputation check. Keyless tier available."""
    if ioc_type != "email":
        return {"provider": "emailrep", "status": "skipped", "ioc": ioc}

    headers = {"User-Agent": "socai/1.0"}
    if EMAILREP_KEY:
        headers["Key"] = EMAILREP_KEY

    try:
        resp = get_session().get(
            f"https://emailrep.io/{ioc}",
            headers=headers,
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "emailrep", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 400:
        return {"provider": "emailrep", "status": "invalid_ioc", "ioc": ioc}
    if resp.status_code == 429:
        return {"provider": "emailrep", "status": "rate_limited", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "emailrep", "status": f"http_{resp.status_code}", "ioc": ioc}

    d = resp.json()
    reputation = d.get("reputation", "none")
    suspicious = d.get("suspicious", False)
    refs = d.get("references", 0)
    details = d.get("details", {})

    verdict = "malicious" if (suspicious and reputation in ("low", "none") and refs > 0) else (
              "suspicious" if suspicious else "clean")

    return {
        "provider": "emailrep",
        "status": "ok",
        "ioc": ioc,
        "verdict": verdict,
        "reputation": reputation,
        "suspicious": suspicious,
        "references": refs,
        "blacklisted": details.get("blacklisted", False),
        "malicious_activity": details.get("malicious_activity", False),
        "malicious_activity_recent": details.get("malicious_activity_recent", False),
        "credentials_leaked": details.get("credentials_leaked", False),
        "data_breach": details.get("data_breach", False),
        "days_since_domain_creation": details.get("days_since_domain_creation"),
        "spam": details.get("spam", False),
        "free_provider": details.get("free_provider", False),
        "disposable": details.get("disposable", False),
        "profiles": details.get("profiles", []),
    }


# ---------------------------------------------------------------------------
# crt.sh — Certificate Transparency log search (keyless)
# ---------------------------------------------------------------------------

def _crtsh_lookup(ioc: str, ioc_type: str) -> dict:
    """crt.sh — certificate transparency log search for subdomains and cert metadata."""
    if ioc_type != "domain":
        return {"provider": "crtsh", "status": "skipped", "ioc": ioc}

    try:
        resp = get_session().get(
            "https://crt.sh/",
            params={"q": f"%.{ioc}", "output": "json"},
            timeout=20,
        )
    except Exception as exc:
        return {"provider": "crtsh", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 429:
        return {"provider": "crtsh", "status": "rate_limited", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "crtsh", "status": f"http_{resp.status_code}", "ioc": ioc}

    try:
        entries = resp.json()
    except Exception:
        return {"provider": "crtsh", "status": "error", "ioc": ioc,
                "error": "Invalid JSON from crt.sh"}

    if not entries:
        return {"provider": "crtsh", "status": "ok", "ioc": ioc, "verdict": "clean",
                "total_certs": 0, "unique_subdomains": [], "issuers": []}

    # Extract unique subdomains from name_value field (may contain wildcard and multi-line)
    subdomains: set[str] = set()
    issuers: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name and name != ioc:
                subdomains.add(name.lower())
        issuer = entry.get("issuer_name", "")
        if issuer:
            issuers.add(issuer)

    sorted_subs = sorted(subdomains)

    return {
        "provider": "crtsh",
        "status": "ok",
        "ioc": ioc,
        "verdict": "informational",
        "total_certs": len(entries),
        "unique_subdomains": sorted_subs[:100],
        "subdomain_count": len(sorted_subs),
        "issuers": sorted(issuers)[:10],
        "crtsh_link": f"https://crt.sh/?q=%.{ioc}",
    }


# ---------------------------------------------------------------------------
# PhishTank — known-phishing URL database (keyless)
# ---------------------------------------------------------------------------

def _phishtank_lookup(ioc: str, ioc_type: str) -> dict:
    """PhishTank — community phishing URL database. Keyless, no signup required."""
    if ioc_type not in ("url", "domain"):
        return {"provider": "phishtank", "status": "skipped", "ioc": ioc}

    # For domains, wrap in a URL so the API can match
    lookup_url = ioc if ioc_type == "url" else f"http://{ioc}/"

    try:
        resp = get_session().post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": lookup_url, "format": "json"},
            headers={"User-Agent": "socai/1.0"},
            timeout=15,
        )
    except Exception as exc:
        return {"provider": "phishtank", "status": "error", "ioc": ioc, "error": str(exc)}

    if resp.status_code == 429:
        return {"provider": "phishtank", "status": "rate_limited", "ioc": ioc}
    if resp.status_code != 200:
        return {"provider": "phishtank", "status": f"http_{resp.status_code}", "ioc": ioc}

    try:
        data = resp.json().get("results", {})
    except Exception:
        return {"provider": "phishtank", "status": "error", "ioc": ioc,
                "error": "Invalid JSON from PhishTank"}

    in_database = data.get("in_database", False)
    is_phish = data.get("valid", False)  # True = confirmed phish by community vote

    if not in_database:
        return {
            "provider": "phishtank",
            "status": "ok",
            "ioc": ioc,
            "verdict": "clean",
            "in_database": False,
        }

    return {
        "provider": "phishtank",
        "status": "ok",
        "ioc": ioc,
        "verdict": "malicious" if is_phish else "suspicious",
        "in_database": True,
        "verified_phish": is_phish,
        "phish_id": data.get("phish_id"),
        "phishtank_link": data.get("phish_detail_page", ""),
    }



# ---------------------------------------------------------------------------
# Provider routing
# ---------------------------------------------------------------------------

# Full provider list (used for non-tiered IOC types: hashes, email, cve, etc.)
PROVIDERS: dict[str, list] = {
    "ipv4":   [_vt_lookup, _abuseipdb_lookup, _shodan_lookup, _greynoise_lookup, _proxycheck_lookup, _urlhaus_lookup, _threatfox_lookup, _censys_lookup, _otx_lookup, _opencti_lookup],
    "domain": [_vt_lookup, _urlscan_lookup, _urlhaus_lookup, _threatfox_lookup, _censys_lookup, _otx_lookup, _whoisxml_lookup, _opencti_lookup, _crtsh_lookup, _phishtank_lookup],
    "url":    [_vt_lookup, _urlscan_lookup, _urlhaus_lookup, _threatfox_lookup, _otx_lookup, _opencti_lookup, _phishtank_lookup],
    "md5":    [_vt_lookup, _intezer_lookup, _malwarebazaar_lookup, _threatfox_lookup, _otx_lookup, _opencti_lookup],
    "sha1":   [_vt_lookup, _intezer_lookup, _otx_lookup, _opencti_lookup],
    "sha256": [_vt_lookup, _intezer_lookup, _malwarebazaar_lookup, _threatfox_lookup, _hybrid_lookup, _otx_lookup, _opencti_lookup],
    "email":  [_emailrep_lookup, _opencti_lookup],
    "cve":    [_opencti_lookup],
}

# Tiered enrichment for IPv4 — cheap/free providers first, expensive only for suspicious
PROVIDERS_IP_FAST: list = [_abuseipdb_lookup, _urlhaus_lookup, _threatfox_lookup, _opencti_lookup]
PROVIDERS_IP_DEEP: list = [_vt_lookup, _shodan_lookup, _greynoise_lookup, _proxycheck_lookup, _censys_lookup, _otx_lookup]

# Tiered enrichment for domains — fast/free first, deep only if signal detected
PROVIDERS_DOMAIN_FAST: list = [_urlhaus_lookup, _threatfox_lookup, _opencti_lookup, _whoisxml_lookup, _phishtank_lookup]
PROVIDERS_DOMAIN_DEEP: list = [_vt_lookup, _urlscan_lookup, _censys_lookup, _otx_lookup, _crtsh_lookup]

# Tiered enrichment for URLs — fast/free first, deep only if signal detected
PROVIDERS_URL_FAST: list = [_urlhaus_lookup, _threatfox_lookup, _opencti_lookup, _phishtank_lookup]
PROVIDERS_URL_DEEP: list = [_vt_lookup, _urlscan_lookup, _otx_lookup]

# Tiered enrichment for hashes — fast/free first, deep only if unknown or suspicious
# NOTE: For hashes, "not_found" in fast tier = unknown file = escalate (inverse of domain logic)
PROVIDERS_HASH_FAST: list = [_malwarebazaar_lookup, _threatfox_lookup, _opencti_lookup]
PROVIDERS_HASH_DEEP: list = [_vt_lookup, _intezer_lookup, _otx_lookup]
# SHA1 has fewer providers
PROVIDERS_HASH_SHA1_DEEP: list = [_vt_lookup, _intezer_lookup, _otx_lookup]
# SHA256 also checks Hybrid Analysis
PROVIDERS_HASH_SHA256_DEEP: list = [_vt_lookup, _intezer_lookup, _hybrid_lookup, _otx_lookup]

# Maps provider function → canonical provider name (must match result["provider"])
_PROVIDER_NAMES: dict = {
    _vt_lookup:             "virustotal",
    _abuseipdb_lookup:      "abuseipdb",
    _shodan_lookup:         "shodan",
    _greynoise_lookup:      "greynoise",
    _intezer_lookup:        "intezer",
    _urlscan_lookup:        "urlscan",
    _proxycheck_lookup:     "proxycheck",
    _opencti_lookup:        "opencti",
    _urlhaus_lookup:        "urlhaus",
    _threatfox_lookup:      "threatfox",
    _malwarebazaar_lookup:  "malwarebazaar",
    _emailrep_lookup:       "emailrep",
    _censys_lookup:         "censys",
    _otx_lookup:            "otx",
    _hybrid_lookup:         "hybrid_analysis",
    _whoisxml_lookup:       "whoisxml",
    _crtsh_lookup:          "crtsh",
    _phishtank_lookup:   "phishtank",
}


# ---------------------------------------------------------------------------
# Enrichment cache helpers
# ---------------------------------------------------------------------------

_cache_lock = threading.Lock()


def _fn_provider_name(fn) -> str:
    """Return the canonical provider name for a function or functools.partial."""
    name = _PROVIDER_NAMES.get(fn)
    if name:
        return name
    # Handle functools.partial wrapping a known function
    underlying = getattr(fn, "func", None)
    if underlying:
        name = _PROVIDER_NAMES.get(underlying)
        if name:
            return name
    return getattr(fn, "__name__", str(fn))


def _cache_load() -> dict:
    if not ENRICH_CACHE_FILE.exists():
        return {}
    try:
        with open(ENRICH_CACHE_FILE) as fh:
            return json.load(fh)
    except Exception as exc:
        log_error("", "enrich.cache_load", str(exc), severity="warning",
                  context={"path": str(ENRICH_CACHE_FILE)})
        return {}


def _cache_save(cache: dict) -> None:
    ENRICH_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ENRICH_CACHE_FILE, "w") as fh:
        json.dump(cache, fh, indent=2, default=str)


def _cache_get(cache: dict, ioc: str, provider: str) -> dict | None:
    """Return cached result if present and fresh, else None."""
    if ENRICH_CACHE_TTL == 0:
        return None
    entry = cache.get(f"{provider}|{ioc}")
    if not entry:
        return None
    try:
        cached_at = datetime.fromisoformat(entry["cached_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) - cached_at < timedelta(hours=ENRICH_CACHE_TTL):
            return entry["result"]
    except Exception as exc:
        log_error("", "enrich.cache_ttl", str(exc), severity="warning",
                  context={"ioc": ioc, "provider": provider})
    return None


def _cache_set(cache: dict, ioc: str, provider: str, result: dict) -> None:
    cache[f"{provider}|{ioc}"] = {"result": result, "cached_at": utcnow()}


def _is_known_clean(ioc: str, ioc_type: str) -> bool:
    """Return True if the IOC belongs to known-clean infrastructure and should be skipped."""
    import urllib.parse
    hostname = ""
    if ioc_type == "domain":
        hostname = ioc.lower()
    elif ioc_type == "url":
        try:
            hostname = urllib.parse.urlparse(ioc).hostname or ""
        except Exception:
            return False
    else:
        return False

    for d in KNOWN_CLEAN_DOMAINS:
        if hostname == d or hostname.endswith("." + d):
            return True
    return False


def _run_tasks_parallel(case_id: str, tasks: list[tuple], cache: dict) -> list[dict]:
    """Execute (fn, ioc, ioc_type) tasks in parallel, return result dicts."""
    results: list[dict] = []

    def _run(task: tuple) -> dict:
        fn, ioc, ioc_type = task
        try:
            res = fn(ioc, ioc_type)
            res["ioc_type"] = ioc_type
            res["ts"] = utcnow()
        except Exception as exc:
            provider_name = _fn_provider_name(fn)
            log_error(case_id, f"enrich.{provider_name}", str(exc),
                      severity="warning", context={"ioc": ioc, "ioc_type": ioc_type,
                                                   "provider": provider_name})
            res = {
                "ioc": ioc, "ioc_type": ioc_type, "provider": provider_name,
                "error": str(exc), "ts": utcnow(), "_logged": True,
            }
        return res

    if tasks:
        with ThreadPoolExecutor(max_workers=ENRICH_WORKERS) as executor:
            futures = {executor.submit(_run, t): t for t in tasks}
            for future in as_completed(futures):
                results.append(future.result())

    # Log provider-returned errors not already caught
    for res in results:
        if res.get("status") == "error" and res.get("error") and not res.get("_logged"):
            log_error(case_id, f"enrich.{res.get('provider', 'unknown')}",
                      res.get("error", "unknown"), severity="warning",
                      context={"ioc": res.get("ioc"), "ioc_type": res.get("ioc_type"),
                               "provider": res.get("provider")})

    # Update shared cache dict in memory (caller flushes to disk once)
    if results:
        with _cache_lock:
            for res in results:
                provider = res.get("provider", "")
                ioc_val = res.get("ioc", "")
                if provider and ioc_val and "error" not in res and res.get("status") == "ok":
                    _cache_set(cache, ioc_val, provider, res)

    return results


def _ip_needs_deep_enrichment(ip: str, fast_results: list[dict]) -> bool:
    """
    Decide whether an IP needs Tier 2 (deep) enrichment based on Tier 1 results.

    Returns True (escalate to deep) if any fast provider flagged it suspicious/malicious,
    or if AbuseIPDB returned reports > 0, or if no fast provider gave a clear verdict.
    """
    ip_results = [r for r in fast_results if r.get("ioc") == ip and r.get("status") == "ok"]
    if not ip_results:
        return True  # No data — escalate

    for r in ip_results:
        verdict = r.get("verdict", "")
        if verdict in ("malicious", "suspicious"):
            return True
        # AbuseIPDB: any reports at all = worth investigating
        if r.get("provider") == "abuseipdb" and (r.get("total_reports", 0) > 0):
            return True
        # ThreatFox / URLhaus: found = escalate
        if r.get("provider") in ("threatfox", "urlhaus") and (r.get("malware") or r.get("threat_type")):
            return True

    return False


def _domain_needs_deep_enrichment(domain: str, fast_results: list[dict]) -> bool:
    """
    Decide whether a domain needs Tier 2 (deep) enrichment based on Tier 1 results.

    Returns True (escalate) if any fast provider flagged it suspicious/malicious,
    if WhoisXML found a newly-registered domain, or if no fast provider gave data.
    """
    dom_results = [r for r in fast_results if r.get("ioc") == domain and r.get("status") == "ok"]
    if not dom_results:
        return True  # No data — escalate

    for r in dom_results:
        verdict = r.get("verdict", "")
        if verdict in ("malicious", "suspicious"):
            return True
        # WhoisXML: newly registered domain = strong phishing signal
        if r.get("provider") == "whoisxml" and r.get("newly_registered"):
            return True
        # ThreatFox / URLhaus: found = escalate
        if r.get("provider") in ("threatfox", "urlhaus") and (r.get("malware") or r.get("threat_type")):
            return True

    return False


def _url_needs_deep_enrichment(url: str, fast_results: list[dict]) -> bool:
    """
    Decide whether a URL needs Tier 2 (deep) enrichment based on Tier 1 results.

    Returns True (escalate) if any fast provider flagged it suspicious/malicious,
    if ThreatFox/URLhaus found a match, or if no fast provider gave data.
    """
    url_results = [r for r in fast_results if r.get("ioc") == url and r.get("status") == "ok"]
    if not url_results:
        return True  # No data — escalate

    for r in url_results:
        verdict = r.get("verdict", "")
        if verdict in ("malicious", "suspicious"):
            return True
        if r.get("provider") in ("threatfox", "urlhaus") and (r.get("malware") or r.get("threat_type")):
            return True

    return False


def _hash_needs_deep_enrichment(hash_val: str, fast_results: list[dict]) -> bool:
    """
    Decide whether a hash needs Tier 2 (deep) enrichment based on Tier 1 results.

    For hashes, the logic is inverted compared to IPs/domains:
      - If fast tier found a definitive malicious verdict → escalate (want full picture)
      - If fast tier found nothing (not_found everywhere) → escalate (unknown file = suspicious)
      - If fast tier found the hash and it's clean → skip deep (known-good in malware DBs)

    Only skip deep enrichment when all fast providers returned not_found with no signal,
    AND at least one provider actually returned a clean/not_found result (i.e. it was checked).
    """
    hash_results = [r for r in fast_results
                    if r.get("ioc") == hash_val and r.get("status") == "ok"]
    if not hash_results:
        return True  # No data at all — escalate

    for r in hash_results:
        verdict = r.get("verdict", "")
        if verdict in ("malicious", "suspicious"):
            return True  # Confirmed bad — get full picture
        if r.get("provider") in ("threatfox", "malwarebazaar") and (r.get("malware") or r.get("threat_type")):
            return True

    # If we reach here: fast providers checked it and nothing was flagged.
    # Hash is known to malware DBs but clean → skip deep.
    return False




def _apply_deterministic_escalation(
    case_id: str,
    escalate_list: list[str],
    candidate_list: list[str],
    tier1_results: list[dict],
    ioc_type: str,
    case_meta: dict | None = None,
) -> list[str]:
    """Rule-based escalation to complement the per-IOC _needs_deep_enrichment checks.

    Catches patterns the individual IOC checks miss:
    - IOCs with ambiguous Tier 1 results (mixed verdicts across providers)
    - IOCs related to the attack type (e.g. domains in phishing cases)
    - IOCs with no Tier 1 data at all (all providers returned nothing)

    Never removes items from escalate_list, only adds.
    """
    attack_type = (case_meta or {}).get("attack_type", "generic")

    # Build a lookup of Tier 1 results per IOC
    results_by_ioc: dict[str, list[dict]] = {}
    for r in tier1_results:
        ioc_val = r.get("ioc", "")
        if ioc_val:
            results_by_ioc.setdefault(ioc_val, []).append(r)

    added = 0
    for ioc in candidate_list:
        if ioc in escalate_list:
            continue

        ioc_results = results_by_ioc.get(ioc, [])

        # Rule 1: No Tier 1 data at all — escalate for visibility
        if not ioc_results:
            escalate_list.append(ioc)
            added += 1
            continue

        # Rule 2: Mixed verdicts across providers (disagreement = ambiguity)
        verdicts = {r.get("verdict") for r in ioc_results if r.get("verdict")}
        verdicts.discard("unknown")
        verdicts.discard("not_found")
        if len(verdicts) > 1:
            escalate_list.append(ioc)
            added += 1
            continue

        # Rule 3: Attack-type boost — in phishing cases, escalate all domains/URLs
        if attack_type == "phishing" and ioc_type in ("domain", "url"):
            escalate_list.append(ioc)
            added += 1
            continue

        # Rule 4: In malware cases, escalate all hashes for full VT report
        if attack_type == "malware" and ioc_type in ("md5", "sha1", "sha256"):
            escalate_list.append(ioc)
            added += 1
            continue

    if added:
        print(f"[enrich] Deterministic escalation added {added} {ioc_type}(s) to Tier 2")

    return escalate_list


def enrich(
    case_id: str,
    max_per_type: int = 20,
    skip_iocs: set[str] | None = None,
    depth: str = "auto",
) -> dict:
    """
    Tiered enrichment pipeline.

    Args:
        depth: Controls tier escalation behaviour.
            "auto" — default smart logic: Tier 1 first, escalate to Tier 2 on
                     signal (malicious/suspicious/unknown/newly-registered).
            "fast" — Tier 1 only, never escalate to Tier 2. Use for low-severity,
                     obvious false positives, or bulk triage.
            "full" — All tiers for every IOC regardless of Tier 1 results.
                     Use for high-severity targeted attacks or novel IOCs.

    For IPv4 addresses:
      Tier 0 — ASN pre-screen: bulk DNS lookup to identify IPs owned by major
               cloud/CDN providers (Microsoft, AWS, Google, Cloudflare, etc.).
               These are tagged as "infra_clean" and skip all enrichment.
      Tier 1 — Fast/free providers: AbuseIPDB, URLhaus, ThreatFox, OpenCTI.
               Quick signal on whether the IP is known-bad.
      Tier 2 — Deep OSINT: VT, Shodan, GreyNoise, ProxyCheck, Censys, OTX.
               Only for IPs that survived Tier 0 AND showed signal in Tier 1
               (suspicious/malicious verdict, abuse reports, or no data).

    For domains:
      Tier 1 — Fast/free providers: URLhaus, ThreatFox, OpenCTI, WhoisXML.
               Quick signal on threat intel hits and domain age.
      Tier 2 — Deep OSINT: VT, URLScan, Censys, OTX.
               Only for domains that showed signal in Tier 1
               (suspicious/malicious verdict, newly registered, or no data).

    For URLs:
      Tier 1 — Fast/free providers: URLhaus, ThreatFox, OpenCTI.
      Tier 2 — Deep OSINT: VT, URLScan, OTX.
               Only for URLs that showed signal in Tier 1.

    For hashes (MD5, SHA1, SHA256):
      Tier 1 — Fast/free malware DBs: MalwareBazaar, ThreatFox, OpenCTI.
      Tier 2 — Deep analysis: VT, Intezer, Hybrid Analysis, OTX.
               Escalates if hash is malicious (want full picture) OR unknown
               (not in any malware DB = investigate). Skips only when fast
               tier confirms the hash is known and clean.

    For all other IOC types (email, CVE):
      Standard enrichment — all registered providers in parallel (unchanged).

    All results are cached in registry/enrichment_cache.json with TTL.
    """
    import time as _time
    _enrich_t0 = _time.monotonic()
    # --- Guard: block enrichment on closed cases ---
    meta_path = CASES_DIR / case_id / "case_meta.json"
    if meta_path.exists():
        try:
            _meta = load_json(meta_path)
            if _meta.get("status") == "closed":
                return {"error": f"Case {case_id} is closed — cannot enrich a closed case.",
                        "case_id": case_id}
        except Exception:
            pass

    iocs_path = CASES_DIR / case_id / "iocs" / "iocs.json"
    if not iocs_path.exists():
        return {"error": f"iocs.json not found at {iocs_path}", "case_id": case_id}

    iocs_data = load_json(iocs_path)
    enrich_dir = CASES_DIR / case_id / "artefacts" / "enrichment"
    enrich_dir.mkdir(parents=True, exist_ok=True)

    # --- Load case metadata for LLM enrichment director ---
    _case_meta: dict | None = None
    meta_path = CASES_DIR / case_id / "case_meta.json"
    if meta_path.exists():
        try:
            _case_meta = load_json(meta_path)
        except Exception:
            pass

    # --- Pre-fetch Intezer token once for all hash lookups ---
    intezer_token: str | None = _intezer_get_token() if INTEZER_KEY else None

    # Build a local provider list with Intezer bound to the pre-fetched token
    import functools
    local_providers: dict[str, list] = {}
    for ioc_type, fns in PROVIDERS.items():
        local_providers[ioc_type] = [
            functools.partial(_intezer_lookup, _token=intezer_token)
            if (fn is _intezer_lookup and intezer_token) else fn
            for fn in fns
        ]

    # Also bind Intezer in the fast/deep IP lists (they don't use Intezer, but
    # keep the pattern consistent for any future additions)
    local_ip_fast = list(PROVIDERS_IP_FAST)
    local_ip_deep = list(PROVIDERS_IP_DEEP)
    local_domain_fast = list(PROVIDERS_DOMAIN_FAST)
    local_domain_deep = list(PROVIDERS_DOMAIN_DEEP)
    local_url_fast = list(PROVIDERS_URL_FAST)
    local_url_deep = list(PROVIDERS_URL_DEEP)

    # Hash tiers — bind Intezer token into deep lists if available
    local_hash_fast = list(PROVIDERS_HASH_FAST)
    local_hash_deep = [
        functools.partial(_intezer_lookup, _token=intezer_token)
        if (fn is _intezer_lookup and intezer_token) else fn
        for fn in PROVIDERS_HASH_DEEP
    ]
    local_hash_sha1_deep = [
        functools.partial(_intezer_lookup, _token=intezer_token)
        if (fn is _intezer_lookup and intezer_token) else fn
        for fn in PROVIDERS_HASH_SHA1_DEEP
    ]
    local_hash_sha256_deep = [
        functools.partial(_intezer_lookup, _token=intezer_token)
        if (fn is _intezer_lookup and intezer_token) else fn
        for fn in PROVIDERS_HASH_SHA256_DEEP
    ]

    # --- Load cache ---
    with _cache_lock:
        cache = _cache_load()

    all_results: list[dict] = []
    cache_hits = 0
    live_calls = 0
    tiered_stats = {"infra_skipped": 0, "tier1_only": 0, "escalated_to_deep": 0}
    domain_tiered_stats = {"tier1_only": 0, "escalated_to_deep": 0}
    url_tiered_stats = {"tier1_only": 0, "escalated_to_deep": 0}
    hash_tiered_stats = {"tier1_only": 0, "escalated_to_deep": 0}

    # =====================================================================
    # Cross-type parallel enrichment
    # =====================================================================
    # Each IOC type (IP, domain, URL, hash) runs its full Tier 1 → 2 chain
    # concurrently with the others via ThreadPoolExecutor.  Within each type
    # the tier sequence remains sequential (Tier 1 informs Tier 2 escalation).
    # =====================================================================

    def _enrich_ips() -> tuple[list[dict], int, int, dict]:
        """Enrich all IPv4 IOCs through Tier 0 → 1 → 2. Returns (results, hits, calls, stats)."""
        results: list[dict] = []
        hits = 0
        calls = 0
        stats = {"infra_skipped": 0, "tier1_only": 0, "escalated_to_deep": 0}

        ip_list_inner = iocs_data.get("iocs", {}).get("ipv4", [])
        if not ip_list_inner:
            return results, hits, calls, stats

        filtered_ips = [i for i in ip_list_inner if not _is_known_clean(i, "ipv4")]
        if skip_iocs:
            filtered_ips = [i for i in filtered_ips if i not in skip_iocs]
        if len(filtered_ips) > max_per_type:
            print(f"[enrich] WARNING: ipv4 has {len(filtered_ips)} IOCs; "
                  f"enriching first {max_per_type}, skipping {len(filtered_ips) - max_per_type}.")
        filtered_ips = filtered_ips[:max_per_type]

        # --- Tier 0: ASN pre-screen ---
        print(f"[enrich] Tier 0: ASN lookup for {len(filtered_ips)} IP(s)...")
        asn_data = _asn_lookup_bulk(filtered_ips)
        infra_ips: list[str] = []
        candidate_ips: list[str] = []

        for ip in filtered_ips:
            info = asn_data.get(ip)
            if info:
                owner = _classify_ip_infra(ip, info)
                if owner:
                    infra_ips.append(ip)
                    results.append({
                        "provider": "asn_prescreen", "status": "infra_clean",
                        "ioc": ip, "ioc_type": "ipv4",
                        "verdict": "infra_clean", "owner": owner,
                        "asn": info.get("asn"), "prefix": info.get("prefix"),
                        "ts": utcnow(),
                    })
                    continue
            candidate_ips.append(ip)

        if infra_ips:
            stats["infra_skipped"] = len(infra_ips)
            print(f"[enrich] Tier 0: Skipped {len(infra_ips)} IP(s) "
                  f"belonging to known infrastructure (MS/AWS/Google/CF/etc.).")

        # --- Tier 1: Fast providers ---
        if candidate_ips:
            print(f"[enrich] Tier 1: Fast enrichment for {len(candidate_ips)} IP(s) "
                  f"across {len(local_ip_fast)} provider(s)...")
            tier1_tasks: list[tuple] = []
            for ip in candidate_ips:
                for fn in local_ip_fast:
                    provider_name = _fn_provider_name(fn)
                    cached = _cache_get(cache, ip, provider_name)
                    if cached is not None:
                        entry = dict(cached)
                        entry["from_cache"] = True
                        entry["ioc_type"] = "ipv4"
                        entry["ts"] = utcnow()
                        results.append(entry)
                        hits += 1
                    else:
                        tier1_tasks.append((fn, ip, "ipv4"))

            tier1_results = _run_tasks_parallel(case_id, tier1_tasks, cache)
            results.extend(tier1_results)
            calls += len(tier1_tasks)

            # --- Tier 2: Deep providers (depth-aware) ---
            if depth == "fast":
                escalate_ips = []
            elif depth == "full":
                escalate_ips = list(candidate_ips)
            else:
                escalate_ips = [ip for ip in candidate_ips
                               if _ip_needs_deep_enrichment(ip, tier1_results + results)]
                escalate_ips = _apply_deterministic_escalation(
                    case_id, escalate_ips, candidate_ips,
                    tier1_results + results, "ipv4", _case_meta,
                )

            tier1_only = len(candidate_ips) - len(escalate_ips)
            stats["tier1_only"] = tier1_only
            stats["escalated_to_deep"] = len(escalate_ips)

            if tier1_only:
                print(f"[enrich] Tier 1: {tier1_only} IP(s) clean — skipping deep enrichment.")

            if escalate_ips:
                print(f"[enrich] Tier 2: Deep enrichment for {len(escalate_ips)} IP(s) "
                      f"across {len(local_ip_deep)} provider(s)...")
                tier2_tasks: list[tuple] = []
                for ip in escalate_ips:
                    for fn in local_ip_deep:
                        provider_name = _fn_provider_name(fn)
                        cached = _cache_get(cache, ip, provider_name)
                        if cached is not None:
                            entry = dict(cached)
                            entry["from_cache"] = True
                            entry["ioc_type"] = "ipv4"
                            entry["ts"] = utcnow()
                            results.append(entry)
                            hits += 1
                        else:
                            tier2_tasks.append((fn, ip, "ipv4"))

                tier2_results = _run_tasks_parallel(case_id, tier2_tasks, cache)
                results.extend(tier2_results)
                calls += len(tier2_tasks)

        return results, hits, calls, stats

    def _enrich_domains() -> tuple[list[dict], int, int, dict]:
        """Enrich all domain IOCs through Tier 1 → 2."""
        results: list[dict] = []
        hits = 0
        calls = 0
        stats = {"tier1_only": 0, "escalated_to_deep": 0}

        domain_list = iocs_data.get("iocs", {}).get("domain", [])
        if not domain_list:
            return results, hits, calls, stats

        filtered_domains = [d for d in domain_list if not _is_known_clean(d, "domain")]
        skipped_clean = len(domain_list) - len(filtered_domains)
        if skipped_clean:
            print(f"[enrich] Skipping {skipped_clean} known-clean domain IOC(s).")
        if skip_iocs:
            pre_skip = len(filtered_domains)
            filtered_domains = [d for d in filtered_domains if d not in skip_iocs]
            triage_skipped = pre_skip - len(filtered_domains)
            if triage_skipped:
                print(f"[enrich] Skipping {triage_skipped} domain IOC(s) per triage (cached).")
        if len(filtered_domains) > max_per_type:
            print(f"[enrich] WARNING: domain has {len(filtered_domains)} IOCs; "
                  f"enriching first {max_per_type}, skipping {len(filtered_domains) - max_per_type}.")
        filtered_domains = filtered_domains[:max_per_type]

        if not filtered_domains:
            return results, hits, calls, stats

        # --- Tier 1 ---
        print(f"[enrich] Domain Tier 1: Fast enrichment for {len(filtered_domains)} domain(s) "
              f"across {len(local_domain_fast)} provider(s)...")
        tier1_tasks: list[tuple] = []
        for domain in filtered_domains:
            for fn in local_domain_fast:
                provider_name = _fn_provider_name(fn)
                cached_entry = _cache_get(cache, domain, provider_name)
                if cached_entry is not None:
                    entry = dict(cached_entry)
                    entry["from_cache"] = True
                    entry["ioc_type"] = "domain"
                    entry["ts"] = utcnow()
                    results.append(entry)
                    hits += 1
                else:
                    tier1_tasks.append((fn, domain, "domain"))

        tier1_results = _run_tasks_parallel(case_id, tier1_tasks, cache)
        results.extend(tier1_results)
        calls += len(tier1_tasks)

        # --- Tier 2 (depth-aware) ---
        if depth == "fast":
            escalate_domains = []
        elif depth == "full":
            escalate_domains = list(filtered_domains)
        else:
            escalate_domains = [d for d in filtered_domains
                                if _domain_needs_deep_enrichment(d, tier1_results + results)]
            escalate_domains = _apply_deterministic_escalation(
                case_id, escalate_domains, filtered_domains,
                tier1_results + results, "domain", _case_meta,
            )

        tier1_only = len(filtered_domains) - len(escalate_domains)
        stats["tier1_only"] = tier1_only
        stats["escalated_to_deep"] = len(escalate_domains)

        if tier1_only:
            print(f"[enrich] Domain Tier 1: {tier1_only} domain(s) clean — skipping deep enrichment.")

        if escalate_domains:
            print(f"[enrich] Domain Tier 2: Deep enrichment for {len(escalate_domains)} domain(s) "
                  f"across {len(local_domain_deep)} provider(s)...")
            tier2_tasks: list[tuple] = []
            for domain in escalate_domains:
                for fn in local_domain_deep:
                    provider_name = _fn_provider_name(fn)
                    cached_entry = _cache_get(cache, domain, provider_name)
                    if cached_entry is not None:
                        entry = dict(cached_entry)
                        entry["from_cache"] = True
                        entry["ioc_type"] = "domain"
                        entry["ts"] = utcnow()
                        results.append(entry)
                        hits += 1
                    else:
                        tier2_tasks.append((fn, domain, "domain"))

            tier2_results = _run_tasks_parallel(case_id, tier2_tasks, cache)
            results.extend(tier2_results)
            calls += len(tier2_tasks)

        return results, hits, calls, stats

    def _enrich_urls() -> tuple[list[dict], int, int, dict]:
        """Enrich all URL IOCs through Tier 1 → 2."""
        results: list[dict] = []
        hits = 0
        calls = 0
        stats = {"tier1_only": 0, "escalated_to_deep": 0}

        url_list = iocs_data.get("iocs", {}).get("url", [])
        if not url_list:
            return results, hits, calls, stats

        filtered_urls = [u for u in url_list if not _is_known_clean(u, "url")]
        skipped_clean = len(url_list) - len(filtered_urls)
        if skipped_clean:
            print(f"[enrich] Skipping {skipped_clean} known-clean URL IOC(s).")
        if skip_iocs:
            pre_skip = len(filtered_urls)
            filtered_urls = [u for u in filtered_urls if u not in skip_iocs]
            triage_skipped = pre_skip - len(filtered_urls)
            if triage_skipped:
                print(f"[enrich] Skipping {triage_skipped} URL IOC(s) per triage (cached).")
        if len(filtered_urls) > max_per_type:
            print(f"[enrich] WARNING: url has {len(filtered_urls)} IOCs; "
                  f"enriching first {max_per_type}, skipping {len(filtered_urls) - max_per_type}.")
        filtered_urls = filtered_urls[:max_per_type]

        if not filtered_urls:
            return results, hits, calls, stats

        # --- Tier 1 ---
        print(f"[enrich] URL Tier 1: Fast enrichment for {len(filtered_urls)} URL(s) "
              f"across {len(local_url_fast)} provider(s)...")
        tier1_tasks: list[tuple] = []
        for url in filtered_urls:
            for fn in local_url_fast:
                provider_name = _fn_provider_name(fn)
                cached_entry = _cache_get(cache, url, provider_name)
                if cached_entry is not None:
                    entry = dict(cached_entry)
                    entry["from_cache"] = True
                    entry["ioc_type"] = "url"
                    entry["ts"] = utcnow()
                    results.append(entry)
                    hits += 1
                else:
                    tier1_tasks.append((fn, url, "url"))

        tier1_results = _run_tasks_parallel(case_id, tier1_tasks, cache)
        results.extend(tier1_results)
        calls += len(tier1_tasks)

        # --- Tier 2 (depth-aware) ---
        if depth == "fast":
            escalate_urls = []
        elif depth == "full":
            escalate_urls = list(filtered_urls)
        else:
            escalate_urls = [u for u in filtered_urls
                             if _url_needs_deep_enrichment(u, tier1_results + results)]
            escalate_urls = _apply_deterministic_escalation(
                case_id, escalate_urls, filtered_urls,
                tier1_results + results, "url", _case_meta,
            )

        tier1_only = len(filtered_urls) - len(escalate_urls)
        stats["tier1_only"] = tier1_only
        stats["escalated_to_deep"] = len(escalate_urls)

        if tier1_only:
            print(f"[enrich] URL Tier 1: {tier1_only} URL(s) clean — skipping deep enrichment.")

        if escalate_urls:
            print(f"[enrich] URL Tier 2: Deep enrichment for {len(escalate_urls)} URL(s) "
                  f"across {len(local_url_deep)} provider(s)...")
            tier2_tasks: list[tuple] = []
            for url in escalate_urls:
                for fn in local_url_deep:
                    provider_name = _fn_provider_name(fn)
                    cached_entry = _cache_get(cache, url, provider_name)
                    if cached_entry is not None:
                        entry = dict(cached_entry)
                        entry["from_cache"] = True
                        entry["ioc_type"] = "url"
                        entry["ts"] = utcnow()
                        results.append(entry)
                        hits += 1
                    else:
                        tier2_tasks.append((fn, url, "url"))

            tier2_results = _run_tasks_parallel(case_id, tier2_tasks, cache)
            results.extend(tier2_results)
            calls += len(tier2_tasks)

        return results, hits, calls, stats

    def _enrich_hashes() -> tuple[list[dict], int, int, dict]:
        """Enrich all hash IOCs (MD5, SHA1, SHA256) through Tier 1 → 2."""
        results: list[dict] = []
        hits = 0
        calls = 0
        stats = {"tier1_only": 0, "escalated_to_deep": 0}

        _HASH_TYPES = ("md5", "sha1", "sha256")
        for hash_type in _HASH_TYPES:
            hash_list = iocs_data.get("iocs", {}).get(hash_type, [])
            if not hash_list:
                continue
            if skip_iocs:
                pre_skip = len(hash_list)
                hash_list = [h for h in hash_list if h not in skip_iocs]
                triage_skipped = pre_skip - len(hash_list)
                if triage_skipped:
                    print(f"[enrich] Skipping {triage_skipped} {hash_type} IOC(s) per triage (cached).")
            if len(hash_list) > max_per_type:
                print(f"[enrich] WARNING: {hash_type} has {len(hash_list)} IOCs; "
                      f"enriching first {max_per_type}, skipping {len(hash_list) - max_per_type}.")
            hash_list = hash_list[:max_per_type]

            if not hash_list:
                continue

            if hash_type == "sha256":
                deep_providers = local_hash_sha256_deep
            elif hash_type == "sha1":
                deep_providers = local_hash_sha1_deep
            else:
                deep_providers = local_hash_deep

            # --- Tier 1 ---
            print(f"[enrich] Hash Tier 1: Fast enrichment for {len(hash_list)} {hash_type}(s) "
                  f"across {len(local_hash_fast)} provider(s)...")
            tier1_tasks = []
            for h in hash_list:
                for fn in local_hash_fast:
                    provider_name = _fn_provider_name(fn)
                    cached_entry = _cache_get(cache, h, provider_name)
                    if cached_entry is not None:
                        entry = dict(cached_entry)
                        entry["from_cache"] = True
                        entry["ioc_type"] = hash_type
                        entry["ts"] = utcnow()
                        results.append(entry)
                        hits += 1
                    else:
                        tier1_tasks.append((fn, h, hash_type))

            tier1_results = _run_tasks_parallel(case_id, tier1_tasks, cache)
            results.extend(tier1_results)
            calls += len(tier1_tasks)

            # --- Tier 2 (depth-aware) ---
            if depth == "fast":
                escalate_hashes = []
            elif depth == "full":
                escalate_hashes = list(hash_list)
            else:
                escalate_hashes = [h for h in hash_list
                                   if _hash_needs_deep_enrichment(h, tier1_results + results)]
                escalate_hashes = _apply_deterministic_escalation(
                    case_id, escalate_hashes, hash_list,
                    tier1_results + results, hash_type, _case_meta,
                )

            tier1_only = len(hash_list) - len(escalate_hashes)
            stats["tier1_only"] += tier1_only
            stats["escalated_to_deep"] += len(escalate_hashes)

            if tier1_only:
                print(f"[enrich] Hash Tier 1: {tier1_only} {hash_type}(s) clean — skipping deep enrichment.")

            if escalate_hashes:
                print(f"[enrich] Hash Tier 2: Deep enrichment for {len(escalate_hashes)} {hash_type}(s) "
                      f"across {len(deep_providers)} provider(s)...")
                tier2_tasks = []
                for h in escalate_hashes:
                    for fn in deep_providers:
                        provider_name = _fn_provider_name(fn)
                        cached_entry = _cache_get(cache, h, provider_name)
                        if cached_entry is not None:
                            entry = dict(cached_entry)
                            entry["from_cache"] = True
                            entry["ioc_type"] = hash_type
                            entry["ts"] = utcnow()
                            results.append(entry)
                            hits += 1
                        else:
                            tier2_tasks.append((fn, h, hash_type))

                tier2_results = _run_tasks_parallel(case_id, tier2_tasks, cache)
                results.extend(tier2_results)
                calls += len(tier2_tasks)

        return results, hits, calls, stats

    # --- Run all IOC types concurrently ---
    print("[enrich] Running IP/domain/URL/hash enrichment in parallel...")
    with ThreadPoolExecutor(max_workers=4) as type_executor:
        f_ips = type_executor.submit(_enrich_ips)
        f_domains = type_executor.submit(_enrich_domains)
        f_urls = type_executor.submit(_enrich_urls)
        f_hashes = type_executor.submit(_enrich_hashes)

        for label, future, stats_target in [
            ("ipv4", f_ips, "ip"),
            ("domain", f_domains, "domain"),
            ("url", f_urls, "url"),
            ("hash", f_hashes, "hash"),
        ]:
            try:
                results, hits, calls, stats = future.result(timeout=600)
                all_results.extend(results)
                cache_hits += hits
                live_calls += calls
                if label == "ipv4":
                    tiered_stats.update(stats)
                elif label == "domain":
                    domain_tiered_stats.update(stats)
                elif label == "url":
                    url_tiered_stats.update(stats)
                elif label == "hash":
                    hash_tiered_stats.update(stats)
            except Exception as exc:
                log_error(case_id, f"enrich.{label}", str(exc),
                          severity="error", traceback=str(exc))

    # Flush cache to disk once after all parallel enrichment threads complete
    with _cache_lock:
        _cache_save(cache)

    # =====================================================================
    # All other IOC types — standard enrichment (email, CVE)
    # =====================================================================
    _HASH_TYPES_OUTER = ("md5", "sha1", "sha256")
    _TIERED_TYPES = {"ipv4", "domain", "url"} | set(_HASH_TYPES_OUTER)
    for ioc_type, ioc_list in iocs_data.get("iocs", {}).items():
        if ioc_type in _TIERED_TYPES:
            continue  # Already handled above
        providers = local_providers.get(ioc_type, [])
        if not providers:
            continue
        # Filter known-clean
        filtered_list = [i for i in ioc_list if not _is_known_clean(i, ioc_type)]
        skipped_clean = len(ioc_list) - len(filtered_list)
        if skipped_clean:
            print(f"[enrich] Skipping {skipped_clean} known-clean {ioc_type} IOC(s).")
        if skip_iocs:
            pre_skip = len(filtered_list)
            filtered_list = [i for i in filtered_list if i not in skip_iocs]
            triage_skipped = pre_skip - len(filtered_list)
            if triage_skipped:
                print(f"[enrich] Skipping {triage_skipped} {ioc_type} IOC(s) per triage (cached).")
        if len(filtered_list) > max_per_type:
            skipped = len(filtered_list) - max_per_type
            print(f"[enrich] WARNING: {ioc_type} has {len(filtered_list)} IOCs; "
                  f"enriching first {max_per_type}, skipping {skipped}.")

        tasks: list[tuple] = []
        for ioc in filtered_list[:max_per_type]:
            for fn in providers:
                provider_name = _fn_provider_name(fn)
                cached = _cache_get(cache, ioc, provider_name)
                if cached is not None:
                    entry = dict(cached)
                    entry["from_cache"] = True
                    entry["ioc_type"] = ioc_type
                    entry["ts"] = utcnow()
                    all_results.append(entry)
                    cache_hits += 1
                else:
                    tasks.append((fn, ioc, ioc_type))

        type_results = _run_tasks_parallel(case_id, tasks, cache)
        all_results.extend(type_results)
        live_calls += len(tasks)

    # Final cache flush (captures entries from "other IOC types" loop above)
    with _cache_lock:
        _cache_save(cache)

    # =====================================================================
    # Output
    # =====================================================================
    output = {
        "case_id": case_id,
        "ts": utcnow(),
        "depth": depth,
        "total_lookups": len(all_results),
        "cache_hits": cache_hits,
        "live_calls": live_calls,
        "tiered_enrichment": tiered_stats,
        "domain_tiered_enrichment": domain_tiered_stats,
        "url_tiered_enrichment": url_tiered_stats,
        "hash_tiered_enrichment": hash_tiered_stats,
        "results": all_results,
    }

    write_artefact(enrich_dir / "enrichment.json", json.dumps(output, indent=2))
    print(f"[enrich] {len(all_results)} result(s) for {case_id} "
          f"({cache_hits} cached, {live_calls} live)")
    if any(v for v in tiered_stats.values()):
        print(f"[enrich] Tiered IP stats: {tiered_stats['infra_skipped']} infra-skipped, "
              f"{tiered_stats['tier1_only']} clean after Tier 1, "
              f"{tiered_stats['escalated_to_deep']} escalated to deep OSINT")
    if any(v for v in domain_tiered_stats.values()):
        print(f"[enrich] Tiered domain stats: {domain_tiered_stats['tier1_only']} clean after Tier 1, "
              f"{domain_tiered_stats['escalated_to_deep']} escalated to deep OSINT")
    if any(v for v in url_tiered_stats.values()):
        print(f"[enrich] Tiered URL stats: {url_tiered_stats['tier1_only']} clean after Tier 1, "
              f"{url_tiered_stats['escalated_to_deep']} escalated to deep OSINT")
    if any(v for v in hash_tiered_stats.values()):
        print(f"[enrich] Tiered hash stats: {hash_tiered_stats['tier1_only']} clean after Tier 1, "
              f"{hash_tiered_stats['escalated_to_deep']} escalated to deep OSINT")
    _enrich_duration_ms = int((_time.monotonic() - _enrich_t0) * 1000)
    _total_iocs = sum(len(v) for v in iocs_data.get("iocs", {}).values() if isinstance(v, list))
    _enriched_iocs = len({r["ioc"] for r in all_results if r.get("status") == "ok"})
    from tools.common import log_metric
    log_metric("enrichment_complete", case_id=case_id,
               duration_ms=_enrich_duration_ms,
               total_iocs=_total_iocs,
               enriched_iocs=_enriched_iocs,
               ioc_coverage_pct=round(_enriched_iocs / _total_iocs * 100, 1) if _total_iocs else 0,
               cache_hits=cache_hits,
               live_calls=live_calls,
               total_lookups=len(all_results),
               tiered_ip=tiered_stats,
               tiered_domain=domain_tiered_stats,
               tiered_url=url_tiered_stats,
               tiered_hash=hash_tiered_stats)
    return output


# ---------------------------------------------------------------------------
# Caseless quick enrichment — single IOC, no case required
# ---------------------------------------------------------------------------

_IOC_TYPE_PATTERNS: list[tuple[str, str]] = [
    # Order matters — check hashes before domain (hex strings could match loosely)
    ("sha256", r"^[0-9a-fA-F]{64}$"),
    ("sha1",   r"^[0-9a-fA-F]{40}$"),
    ("md5",    r"^[0-9a-fA-F]{32}$"),
    ("email",  r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    ("ipv4",   r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    ("url",    r"^https?://"),
    ("domain", r"^(?![\d.]+$)[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$"),
]

import re as _re

_IOC_TYPE_COMPILED = [(name, _re.compile(pat)) for name, pat in _IOC_TYPE_PATTERNS]


def _detect_ioc_type(value: str) -> str | None:
    """Auto-detect IOC type from raw value string."""
    v = value.strip()
    for name, regex in _IOC_TYPE_COMPILED:
        if regex.match(v):
            return name
    return None


# Fast-only provider lists keyed by IOC type
_FAST_PROVIDERS: dict[str, list] = {
    "ipv4":   PROVIDERS_IP_FAST,
    "domain": PROVIDERS_DOMAIN_FAST,
    "url":    PROVIDERS_URL_FAST,
    "sha256": PROVIDERS_HASH_FAST,
    "sha1":   PROVIDERS_HASH_FAST,
    "md5":    PROVIDERS_HASH_FAST,
    "email":  [_emailrep_lookup],
}

# Full (all-tier) provider lists keyed by IOC type
_FULL_PROVIDERS: dict[str, list] = {
    "ipv4":   PROVIDERS_IP_FAST + PROVIDERS_IP_DEEP,
    "domain": PROVIDERS_DOMAIN_FAST + PROVIDERS_DOMAIN_DEEP,
    "url":    PROVIDERS_URL_FAST + PROVIDERS_URL_DEEP,
    "sha256": PROVIDERS_HASH_FAST + PROVIDERS_HASH_SHA256_DEEP,
    "sha1":   PROVIDERS_HASH_FAST + PROVIDERS_HASH_SHA1_DEEP,
    "md5":    PROVIDERS_HASH_FAST + PROVIDERS_HASH_DEEP,
    "email":  [_emailrep_lookup],
}

# Deep-only provider lists keyed by IOC type (for Tier 2 escalation)
_DEEP_PROVIDERS: dict[str, list] = {
    "ipv4":   PROVIDERS_IP_DEEP,
    "domain": PROVIDERS_DOMAIN_DEEP,
    "url":    PROVIDERS_URL_DEEP,
    "sha256": PROVIDERS_HASH_SHA256_DEEP,
    "sha1":   PROVIDERS_HASH_SHA1_DEEP,
    "md5":    PROVIDERS_HASH_DEEP,
}

# Escalation decision functions keyed by IOC type
_NEEDS_DEEP: dict[str, callable] = {
    "ipv4":   _ip_needs_deep_enrichment,
    "domain": _domain_needs_deep_enrichment,
    "url":    _url_needs_deep_enrichment,
    "sha256": _hash_needs_deep_enrichment,
    "sha1":   _hash_needs_deep_enrichment,
    "md5":    _hash_needs_deep_enrichment,
}


def quick_enrich(iocs: list[str], depth: str = "auto") -> dict:
    """Enrich one or more raw IOC values without a case.

    Parameters
    ----------
    iocs : list[str]
        Raw IOC values (IPs, domains, URLs, hashes, emails).
    depth : str
        ``"auto"`` — (default) Tier 0 ASN pre-screen (IPs), then Tier 1 fast
        providers, then selectively escalate to Tier 2 deep OSINT only for
        IOCs that show signal.
        ``"fast"`` — Tier 1 only, no deep OSINT.
        ``"full"`` — All tiers for every IOC.

    Returns
    -------
    dict with keys: ``enrichment_id`` (for later import into a case),
    ``results``, ``verdicts``, ``ioc_count``, ``provider_calls``,
    ``tiered_stats``.
    """
    import time as _time
    from tools.score_verdicts import _composite_verdict
    from config.settings import QUICK_ENRICH_DIR

    _t0 = _time.monotonic()

    if isinstance(iocs, str):
        iocs = [iocs]

    cache = _cache_load()
    all_results: list[dict] = []
    unrecognised: list[dict] = []
    cache_hits = 0
    live_calls = 0
    tiered_stats = {"infra_skipped": 0, "tier1_only": 0, "escalated_to_deep": 0}

    # Classify each IOC by type
    ioc_types: dict[str, str] = {}
    for raw in iocs:
        val = raw.strip()
        if not val:
            continue
        ioc_type = _detect_ioc_type(val)
        if not ioc_type:
            unrecognised.append({"ioc": val, "error": "unrecognised_ioc_type"})
            continue
        ioc_types[val] = ioc_type

    # Short-circuit RFC-1918 / loopback IPs — no providers have data on
    # private addresses, so tag them immediately and skip enrichment.
    from tools.extract_iocs import _is_private_ip
    private_ips: set[str] = set()
    for val, ioc_type in list(ioc_types.items()):
        if ioc_type == "ipv4" and _is_private_ip(val):
            private_ips.add(val)
            all_results.append({
                "provider": "private_ip_check", "status": "ok",
                "ioc": val, "ioc_type": "ipv4",
                "verdict": "private_internal",
                "detail": "RFC-1918 / loopback address — no OSINT data available",
                "ts": utcnow(),
            })
            del ioc_types[val]
    if private_ips:
        print(f"[quick_enrich] Skipped {len(private_ips)} private/internal IP(s)")

    # Group IOCs by type for efficient tiered enrichment
    by_type: dict[str, list[str]] = {}
    for val, ioc_type in ioc_types.items():
        by_type.setdefault(ioc_type, []).append(val)

    # -----------------------------------------------------------------
    # depth="fast" — Tier 1 only, flat parallel
    # -----------------------------------------------------------------
    if depth == "fast":
        tasks: list[tuple] = []
        for val, ioc_type in ioc_types.items():
            for fn in _FAST_PROVIDERS.get(ioc_type, []):
                pname = _fn_provider_name(fn)
                cached = _cache_get(cache, val, pname)
                if cached is not None:
                    entry = dict(cached)
                    entry.update(ioc_type=ioc_type, ts=utcnow(), _cached=True)
                    all_results.append(entry)
                    cache_hits += 1
                else:
                    tasks.append((fn, val, ioc_type))
        results = _run_tasks_parallel("", tasks, cache)
        all_results.extend(results)
        live_calls = len(tasks)

    # -----------------------------------------------------------------
    # depth="full" — All providers, flat parallel
    # -----------------------------------------------------------------
    elif depth == "full":
        tasks = []
        for val, ioc_type in ioc_types.items():
            for fn in _FULL_PROVIDERS.get(ioc_type, []):
                pname = _fn_provider_name(fn)
                cached = _cache_get(cache, val, pname)
                if cached is not None:
                    entry = dict(cached)
                    entry.update(ioc_type=ioc_type, ts=utcnow(), _cached=True)
                    all_results.append(entry)
                    cache_hits += 1
                else:
                    tasks.append((fn, val, ioc_type))
        results = _run_tasks_parallel("", tasks, cache)
        all_results.extend(results)
        live_calls = len(tasks)

    # -----------------------------------------------------------------
    # depth="auto" — Tiered: Tier 0 (ASN) → Tier 1 → selective Tier 2
    # -----------------------------------------------------------------
    else:
        # --- Tier 0: ASN pre-screen for IPs ---
        ip_candidates = by_type.get("ipv4", [])
        infra_ips: set[str] = set()
        if ip_candidates:
            asn_data = _asn_lookup_bulk(ip_candidates)
            for ip in ip_candidates:
                info = asn_data.get(ip)
                if info:
                    owner = _classify_ip_infra(ip, info)
                    if owner:
                        infra_ips.add(ip)
                        all_results.append({
                            "provider": "asn_prescreen", "status": "infra_clean",
                            "ioc": ip, "ioc_type": "ipv4",
                            "verdict": "infra_clean", "owner": owner,
                            "asn": info.get("asn"), "prefix": info.get("prefix"),
                            "ts": utcnow(),
                        })
            if infra_ips:
                tiered_stats["infra_skipped"] = len(infra_ips)
                print(f"[quick_enrich] Tier 0: Skipped {len(infra_ips)} IP(s) "
                      f"belonging to known infrastructure.")
            # Remove infra IPs from candidate list
            by_type["ipv4"] = [ip for ip in ip_candidates if ip not in infra_ips]

        # --- Tier 1: Fast providers for all types ---
        tier1_tasks: list[tuple] = []
        for ioc_type, vals in by_type.items():
            for val in vals:
                for fn in _FAST_PROVIDERS.get(ioc_type, []):
                    pname = _fn_provider_name(fn)
                    cached = _cache_get(cache, val, pname)
                    if cached is not None:
                        entry = dict(cached)
                        entry.update(ioc_type=ioc_type, ts=utcnow(), _cached=True)
                        all_results.append(entry)
                        cache_hits += 1
                    else:
                        tier1_tasks.append((fn, val, ioc_type))

        tier1_results = _run_tasks_parallel("", tier1_tasks, cache)
        all_results.extend(tier1_results)
        live_calls += len(tier1_tasks)

        # --- Tier 2: Selective deep enrichment based on Tier 1 signal ---
        tier2_tasks: list[tuple] = []
        combined = all_results  # includes cached + tier1 live results
        for ioc_type, vals in by_type.items():
            needs_deep_fn = _NEEDS_DEEP.get(ioc_type)
            deep_providers = _DEEP_PROVIDERS.get(ioc_type, [])
            if not needs_deep_fn or not deep_providers:
                continue
            for val in vals:
                if needs_deep_fn(val, combined):
                    tiered_stats["escalated_to_deep"] += 1
                    for fn in deep_providers:
                        pname = _fn_provider_name(fn)
                        cached = _cache_get(cache, val, pname)
                        if cached is not None:
                            entry = dict(cached)
                            entry.update(ioc_type=ioc_type, ts=utcnow(), _cached=True)
                            all_results.append(entry)
                            cache_hits += 1
                        else:
                            tier2_tasks.append((fn, val, ioc_type))
                else:
                    tiered_stats["tier1_only"] += 1

        if tier2_tasks:
            tier2_results = _run_tasks_parallel("", tier2_tasks, cache)
            all_results.extend(tier2_results)
            live_calls += len(tier2_tasks)

        if tiered_stats["tier1_only"]:
            print(f"[quick_enrich] Tier 1: {tiered_stats['tier1_only']} IOC(s) "
                  f"clean — skipped deep enrichment.")
        if tiered_stats["escalated_to_deep"]:
            print(f"[quick_enrich] Tier 2: Escalated {tiered_stats['escalated_to_deep']} "
                  f"IOC(s) to deep OSINT.")

    # Score composite verdicts per IOC
    verdicts: dict[str, dict] = {}
    # Private IPs get a direct verdict (no providers to score)
    for ip in private_ips:
        verdicts[ip] = {
            "ioc": ip,
            "ioc_type": "ipv4",
            "verdict": "private_internal",
            "confidence": "high",
            "providers_checked": 0,
            "provider_verdicts": {"private_ip_check": "private_internal"},
        }
    for ioc_val, ioc_type in ioc_types.items():
        ioc_results = [r for r in all_results
                       if r.get("ioc") == ioc_val and r.get("status") == "ok"]
        provider_verdicts = {}
        for r in ioc_results:
            v = r.get("verdict")
            if v:
                provider_verdicts[r["provider"]] = v
        composite, confidence = _composite_verdict(provider_verdicts)
        verdicts[ioc_val] = {
            "ioc": ioc_val,
            "ioc_type": ioc_type,
            "verdict": composite,
            "confidence": confidence,
            "providers_checked": len(ioc_results),
            "provider_verdicts": provider_verdicts,
        }

    _duration_ms = int((_time.monotonic() - _t0) * 1000)

    # Persist results so they can be imported into a case later
    # Flush cache to disk once after all enrichment
    with _cache_lock:
        _cache_save(cache)

    enrichment_id = f"QE_{utcnow().replace('-', '').replace(':', '').replace('T', '_').split('.')[0]}"
    QUICK_ENRICH_DIR.mkdir(parents=True, exist_ok=True)
    output = {
        "enrichment_id": enrichment_id,
        "ts": utcnow(),
        "depth": depth,
        "duration_ms": _duration_ms,
        "ioc_count": len(ioc_types) + len(private_ips),
        "provider_calls": live_calls,
        "cache_hits": cache_hits,
        "tiered_stats": tiered_stats,
        "results": all_results,
        "verdicts": verdicts,
        "unrecognised": unrecognised,
    }
    save_json(QUICK_ENRICH_DIR / f"{enrichment_id}.json", output)

    print(f"[quick_enrich] {len(all_results)} result(s) for {len(ioc_types)} IOC(s) "
          f"({cache_hits} cached, {live_calls} live, {_duration_ms}ms) — "
          f"saved as {enrichment_id}")

    return output


def import_enrichment(enrichment_id: str, case_id: str) -> dict:
    """Import saved quick_enrich results into a case.

    Copies the enrichment data into the case's enrichment directory,
    writes an iocs.json from the verdicts, then runs score_verdicts
    and update_ioc_index.

    Parameters
    ----------
    enrichment_id : str
        The enrichment ID returned by quick_enrich (e.g. ``QE_20260402_143012``).
    case_id : str
        The case to import into.

    Returns
    -------
    dict with import status, verdict summary counts.
    """
    from config.settings import QUICK_ENRICH_DIR, CASES_DIR
    from tools.score_verdicts import score_verdicts, update_ioc_index

    qe_path = QUICK_ENRICH_DIR / f"{enrichment_id}.json"
    if not qe_path.exists():
        return {"error": f"Quick enrichment '{enrichment_id}' not found."}

    case_dir = CASES_DIR / case_id
    if not case_dir.exists():
        return {"error": f"Case '{case_id}' does not exist."}

    qe_data = load_json(qe_path)

    # Write enrichment.json into case
    enrich_dir = case_dir / "artefacts" / "enrichment"
    enrich_dir.mkdir(parents=True, exist_ok=True)

    # Re-key with case_id
    enrich_output = {
        "case_id": case_id,
        "imported_from": enrichment_id,
        "ts": utcnow(),
        "depth": qe_data.get("depth", "auto"),
        "total_lookups": len(qe_data.get("results", [])),
        "cache_hits": qe_data.get("cache_hits", 0),
        "live_calls": qe_data.get("provider_calls", 0),
        "tiered_enrichment": qe_data.get("tiered_stats", {}),
        "results": qe_data.get("results", []),
    }
    write_artefact(enrich_dir / "enrichment.json",
                   json.dumps(enrich_output, indent=2))

    # Build iocs.json from verdicts so score_verdicts can read it
    iocs_dir = case_dir / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)
    iocs_path = iocs_dir / "iocs.json"

    # Only write iocs.json if it doesn't already exist (don't overwrite
    # IOCs extracted from case artefacts)
    if not iocs_path.exists():
        iocs_by_type: dict[str, list[str]] = {}
        for v in qe_data.get("verdicts", {}).values():
            ioc_type = v.get("ioc_type", "")
            ioc_val = v.get("ioc", "")
            if ioc_type and ioc_val:
                iocs_by_type.setdefault(ioc_type, []).append(ioc_val)
        total = sum(len(v) for v in iocs_by_type.values())
        save_json(iocs_path, {"iocs": iocs_by_type, "total": total,
                              "imported_from": enrichment_id})

    # Write pre-computed verdict summary if available (skip re-scoring)
    qe_verdicts = qe_data.get("verdicts", {})
    imported_depth = qe_data.get("depth", "auto")
    if qe_verdicts:
        # Build verdict_summary.json directly from quick_enrich verdicts
        high_priority = [v["ioc"] for v in qe_verdicts.values()
                         if v.get("verdict") == "malicious"]
        needs_review = [v["ioc"] for v in qe_verdicts.values()
                        if v.get("verdict") == "suspicious"]
        clean_iocs = [v["ioc"] for v in qe_verdicts.values()
                      if v.get("verdict") in ("clean", "infra_clean", "private_internal")]
        verdict_summary = {
            "case_id": case_id,
            "imported_from": enrichment_id,
            "imported_depth": imported_depth,
            "ts": utcnow(),
            "ioc_count": len(qe_verdicts),
            "high_priority": high_priority,
            "needs_review": needs_review,
            "clean": clean_iocs,
            "iocs": {v["ioc"]: {
                "ioc_type": v.get("ioc_type", ""),
                "verdict": v.get("verdict", "unknown"),
                "confidence": v.get("confidence", "LOW"),
                "providers": v.get("provider_verdicts", {}),
            } for v in qe_verdicts.values()},
        }
        # Warn if imported from a shallow enrichment — verdicts may be incomplete
        if imported_depth == "fast":
            verdict_summary["shallow_import_warning"] = (
                "Verdicts imported from depth='fast' quick_enrich (Tier 1 only). "
                "Run enrich_iocs with depth='auto' or 'full' for deeper coverage."
            )
            print(f"[import_enrichment] WARNING: Importing shallow (depth=fast) "
                  f"verdicts into {case_id} — Tier 2 providers were not consulted.")
        save_json(enrich_dir / "verdict_summary.json", verdict_summary)
        verdict_result = verdict_summary
        mal, sus, clean = len(high_priority), len(needs_review), len(clean_iocs)
    else:
        # No pre-computed verdicts — fall back to full scoring
        verdict_result = score_verdicts(case_id)
        mal = len(verdict_result.get("high_priority", [])) if verdict_result else 0
        sus = len(verdict_result.get("needs_review", [])) if verdict_result else 0
        clean = len(verdict_result.get("clean", [])) if verdict_result else 0

    # Always update IOC index for cross-case recall
    idx_result = update_ioc_index(case_id)

    return {
        "status": "imported",
        "enrichment_id": enrichment_id,
        "case_id": case_id,
        "iocs_imported": qe_data.get("ioc_count", 0),
        "malicious": mal,
        "suspicious": sus,
        "clean": clean,
    }


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Enrich IOCs for a case.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--max-per-type", type=int, default=20)
    args = p.parse_args()

    result = enrich(args.case_id, args.max_per_type)
    print(json.dumps(result, indent=2))
