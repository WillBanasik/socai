"""
tool: exposure_test
-------------------
Automated external attack surface assessment for clients.

Discovers the client's web-facing footprint via DNS enumeration, certificate
transparency, subdomain discovery, and OSINT enrichment.  Assesses email
security posture (SPF/DMARC/DKIM), service exposure (open ports, CVEs),
credential leaks (dark web), and typosquat domains.  Compares findings
against the known infrastructure baseline in knowledge.md.

Writes:
  registry/exposure/{client_key}.json
  registry/exposure/{client_key}_exposure.html

Usage:
    from tools.exposure_test import run_exposure_test

    result = run_exposure_test("performanta", domains=["performanta.com"])
"""
from __future__ import annotations

import json
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import EXPOSURE_DIR, BASE_DIR
from tools.common import load_json, log_error, save_json, utcnow, write_artefact

try:
    import dns.resolver
    import dns.exception
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HIGH_RISK_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}

_COMMON_DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "dkim", "k1", "s1", "s2",
    "mail", "email", "protonmail", "mimecast",
]

_TYPOSQUAT_TLDS = [".net", ".org", ".io", ".co", ".xyz", ".info", ".biz", ".app", ".dev", ".tech"]

_KEYBOARD_ADJACENT = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yijh", "i": "uokj", "o": "iplk", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc",
    "g": "ftyhbv", "h": "gyujnb", "j": "huikmn", "k": "jiolm",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}

_HOMOGLYPHS = {
    "o": "0", "l": "1", "i": "1", "a": "4", "e": "3", "s": "5",
    "0": "o", "1": "l",
}

_SCORING_WEIGHTS = {
    "email_security": 20,
    "service_exposure": 25,
    "credential_exposure": 20,
    "certificate_issues": 10,
    "unknown_assets": 15,
    "typosquats": 10,
}


def _client_key(client: str) -> str:
    return client.strip().lower().replace(" ", "_")


# ---------------------------------------------------------------------------
# Phase 1 — DNS Enumeration
# ---------------------------------------------------------------------------

def _dns_query(domain: str, rdtype: str, timeout: float = 10.0) -> list[str]:
    """Safe DNS query that returns list of string answers or empty list."""
    if not _HAS_DNS:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]  # Cloudflare + Google (WSL2 DNS can be slow)
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, rdtype)
        results = []
        for rdata in answers:
            # TXT records: join multi-string records (e.g. SPF split across strings)
            if rdtype == "TXT":
                results.append("".join(s.decode() if isinstance(s, bytes) else s
                                       for s in rdata.strings))
            else:
                results.append(str(rdata))
        return results
    except Exception as exc:
        log_error("", "exposure_test:dns_query", str(exc), severity="warning", traceback=True,
                  context={"domain": domain, "rdtype": rdtype})
        return []


def _parse_spf(txt_records: list[str], domain: str, depth: int = 0) -> dict:
    """Parse SPF record and recursively resolve includes."""
    spf_raw = ""
    for txt in txt_records:
        cleaned = txt.strip('"').strip("'")
        if cleaned.lower().startswith("v=spf1"):
            spf_raw = cleaned
            break

    if not spf_raw:
        return {"raw": "", "policy": "missing", "includes": [], "authorised_ips": [],
                "authorised_networks": [], "dns_lookups": 0, "over_limit": False}

    mechanisms = spf_raw.split()
    ips = []
    networks = []
    includes = []
    dns_lookups = 0

    for mech in mechanisms[1:]:  # skip v=spf1
        m = mech.lower()
        if m.startswith("ip4:"):
            val = mech[4:]
            if "/" in val:
                networks.append(val)
            else:
                ips.append(val)
        elif m.startswith("ip6:"):
            networks.append(mech[4:])
        elif m.startswith("include:"):
            inc_domain = mech[8:]
            includes.append(inc_domain)
            dns_lookups += 1
            if depth < 3:
                sub_txt = _dns_query(inc_domain, "TXT")
                sub_spf = _parse_spf(sub_txt, inc_domain, depth + 1)
                ips.extend(sub_spf.get("authorised_ips", []))
                networks.extend(sub_spf.get("authorised_networks", []))
                dns_lookups += sub_spf.get("dns_lookups", 0)
        elif m.startswith("a:") or m == "a":
            dns_lookups += 1
        elif m.startswith("mx:") or m == "mx":
            dns_lookups += 1
        elif m.startswith("redirect="):
            dns_lookups += 1

    # Determine policy
    policy = "missing"
    if "-all" in spf_raw.lower():
        policy = "-all"
    elif "~all" in spf_raw.lower():
        policy = "~all"
    elif "?all" in spf_raw.lower():
        policy = "?all"
    elif "+all" in spf_raw.lower():
        policy = "+all"

    return {
        "raw": spf_raw,
        "policy": policy,
        "includes": includes,
        "authorised_ips": sorted(set(ips)),
        "authorised_networks": sorted(set(networks)),
        "dns_lookups": dns_lookups,
        "over_limit": dns_lookups > 10,
    }


def _parse_dmarc(domain: str) -> dict:
    """Query and parse DMARC record."""
    records = _dns_query(f"_dmarc.{domain}", "TXT")
    dmarc_raw = ""
    for txt in records:
        cleaned = txt.strip('"').strip("'")
        if cleaned.lower().startswith("v=dmarc1"):
            dmarc_raw = cleaned
            break

    if not dmarc_raw:
        return {"raw": "", "policy": "missing", "subdomain_policy": "",
                "rua": [], "ruf": [], "pct": 100}

    tags = {}
    for part in dmarc_raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    return {
        "raw": dmarc_raw,
        "policy": tags.get("p", "none"),
        "subdomain_policy": tags.get("sp", ""),
        "rua": [u.strip() for u in tags.get("rua", "").split(",") if u.strip()],
        "ruf": [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()],
        "pct": int(tags.get("pct", "100")),
    }


def _check_dkim(domain: str) -> list[dict]:
    """Probe common DKIM selectors."""
    results = []
    for selector in _COMMON_DKIM_SELECTORS:
        records = _dns_query(f"{selector}._domainkey.{domain}", "TXT")
        results.append({"selector": selector, "found": len(records) > 0})
    return results


def discover_dns(domain: str) -> dict:
    """Full DNS enumeration for a domain."""
    if not _HAS_DNS:
        return {"domain": domain, "error": "dnspython not installed"}

    a = _dns_query(domain, "A")
    aaaa = _dns_query(domain, "AAAA")
    mx_raw = _dns_query(domain, "MX")
    ns = _dns_query(domain, "NS")
    txt = _dns_query(domain, "TXT")
    soa_raw = _dns_query(domain, "SOA")

    # Parse MX records into priority + host
    mx = []
    for record in mx_raw:
        parts = str(record).split()
        if len(parts) >= 2:
            try:
                mx.append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
            except ValueError:
                mx.append({"priority": 0, "host": str(record).rstrip(".")})

    # Parse SOA
    soa = {}
    if soa_raw:
        parts = str(soa_raw[0]).split()
        if len(parts) >= 2:
            soa = {"mname": parts[0].rstrip("."), "rname": parts[1].rstrip(".")}

    return {
        "domain": domain,
        "a_records": a,
        "aaaa_records": aaaa,
        "mx_records": sorted(mx, key=lambda x: x.get("priority", 0)),
        "ns_records": [n.rstrip(".") for n in ns],
        "txt_records": [t.strip('"') for t in txt],
        "soa": soa,
        "spf": _parse_spf(txt, domain),
        "dmarc": _parse_dmarc(domain),
        "dkim_selectors": _check_dkim(domain),
    }


# ---------------------------------------------------------------------------
# Phase 2 — Subdomain Discovery
# ---------------------------------------------------------------------------

def _crtsh_subdomains(domain: str) -> list[str]:
    """Query crt.sh certificate transparency logs."""
    try:
        import requests as _req
        # crt.sh can be slow on large domains — generous timeout, no session pooling
        resp = _req.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=60,
            headers={"User-Agent": "socai-exposure-test/1.0"},
        )
        if resp.status_code != 200:
            log_error("", "exposure.crtsh", f"HTTP {resp.status_code}", severity="warning")
            return []

        # crt.sh returns large JSON — parse carefully
        try:
            entries = resp.json()
        except Exception:
            # Sometimes returns HTML error page on rate limit
            log_error("", "exposure.crtsh", "JSON parse failed (possible rate limit)",
                      severity="warning")
            return []

        subdomains = set()
        domain_lower = domain.lower()
        for entry in entries:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lower()
                if line.startswith("*."):
                    line = line[2:]
                if line.endswith(f".{domain_lower}") or line == domain_lower:
                    subdomains.add(line)
        return sorted(subdomains)
    except Exception as exc:
        log_error("", "exposure.crtsh", str(exc), severity="warning")
        return []


def _vt_subdomains(domain: str) -> list[str]:
    """Query VirusTotal for subdomains."""
    try:
        from config.settings import VIRUSTOTAL_KEY
        if not VIRUSTOTAL_KEY:
            return []
        import requests as _req
        resp = _req.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            params={"limit": 100},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [item.get("id", "") for item in data.get("data", []) if item.get("id")]
    except Exception as exc:
        log_error("", "exposure_test:vt_subdomains", str(exc), severity="warning", traceback=True,
                  context={"domain": domain})
        return []


def _resolve_subdomain(subdomain: str) -> list[str]:
    """Resolve a subdomain's A records."""
    return _dns_query(subdomain, "A")


def discover_subdomains(domain: str) -> list[dict]:
    """Discover subdomains from multiple sources and check liveness."""
    all_subs: dict[str, str] = {}  # subdomain -> source

    # crt.sh (usually the richest source)
    for sub in _crtsh_subdomains(domain):
        all_subs.setdefault(sub, "crt.sh")

    # VirusTotal
    for sub in _vt_subdomains(domain):
        all_subs.setdefault(sub, "virustotal")

    # Resolve each subdomain to check liveness (parallel)
    results = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_resolve_subdomain, sub): sub for sub in all_subs}
        for future in as_completed(futures):
            sub = futures[future]
            try:
                a_records = future.result()
            except Exception as exc:
                log_error("", "exposure_test:resolve_subdomain", str(exc), severity="warning",
                          traceback=True, context={"subdomain": sub})
                a_records = []
            results.append({
                "subdomain": sub,
                "source": all_subs[sub],
                "a_records": a_records,
                "live": len(a_records) > 0,
            })

    return sorted(results, key=lambda x: x["subdomain"])


# ---------------------------------------------------------------------------
# Phase 3 — Service Exposure
# ---------------------------------------------------------------------------

def assess_services(ips: list[str]) -> dict:
    """Enrich IPs via quick_enrich and extract service exposure data."""
    if not ips:
        return {"ips_assessed": 0, "results": [], "findings": []}

    try:
        from tools.enrich import quick_enrich
        enrichment = quick_enrich(ips, deep=True)
    except Exception as exc:
        log_error("", "exposure.services", str(exc), severity="warning")
        return {"ips_assessed": len(ips), "results": [], "findings": [],
                "error": str(exc)}

    per_ip: dict[str, dict] = {}
    findings = []

    for result in enrichment.get("results", []):
        ip = result.get("ioc", "")
        provider = result.get("provider", "")
        if not ip:
            continue

        if ip not in per_ip:
            per_ip[ip] = {"ip": ip, "open_ports": [], "services": [], "cves": [],
                          "org": "", "asn": "", "country": ""}

        entry = per_ip[ip]

        if provider == "shodan":
            entry["open_ports"] = result.get("open_ports", [])
            entry["services"] = result.get("services", [])
            entry["cves"] = result.get("cves", [])
            entry["org"] = result.get("org", "")
            entry["asn"] = result.get("asn", "")
            entry["country"] = result.get("country", "")

            # Flag high-risk ports
            for port in entry["open_ports"]:
                if port in _HIGH_RISK_PORTS:
                    findings.append({
                        "severity": "high",
                        "category": "service_exposure",
                        "title": f"High-risk port {port} ({_HIGH_RISK_PORTS[port]}) open on {ip}",
                        "detail": f"{ip} has {_HIGH_RISK_PORTS[port]} (port {port}) exposed to the internet.",
                    })

            # Flag CVEs
            for cve in entry["cves"]:
                findings.append({
                    "severity": "high",
                    "category": "service_exposure",
                    "title": f"Known CVE {cve} on {ip}",
                    "detail": f"Shodan reports {cve} on {ip} ({entry.get('org', '')}).",
                })

        elif provider == "censys":
            if not entry["open_ports"]:
                entry["open_ports"] = result.get("open_ports", [])
            if not entry["services"]:
                entry["services"] = result.get("services", [])

    # TLS cert checks on port-443 IPs
    try:
        from tools.web_capture import _extract_tls_cert
        for ip in list(per_ip.keys()):
            if 443 in per_ip[ip].get("open_ports", []):
                cert = _extract_tls_cert(ip)
                if cert:
                    per_ip[ip]["cert"] = cert
                    if cert.get("self_signed"):
                        findings.append({
                            "severity": "medium",
                            "category": "certificate_issues",
                            "title": f"Self-signed certificate on {ip}",
                            "detail": f"{ip}:443 presents a self-signed certificate (CN: {cert.get('subject_cn', '?')}).",
                        })
                    if cert.get("days_remaining", 999) < 0:
                        findings.append({
                            "severity": "medium",
                            "category": "certificate_issues",
                            "title": f"Expired certificate on {ip}",
                            "detail": f"{ip}:443 certificate expired ({cert.get('not_after', '?')}).",
                        })
    except Exception as exc:
        log_error("", "exposure_test:tls_cert_check", str(exc), severity="warning", traceback=True)

    return {
        "ips_assessed": len(per_ip),
        "results": list(per_ip.values()),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Phase 4 — Email Security Assessment
# ---------------------------------------------------------------------------

def assess_email_security(dns_data: dict) -> dict:
    """Score email security posture from DNS data."""
    findings = []
    spf = dns_data.get("spf", {})
    dmarc = dns_data.get("dmarc", {})
    dkim = dns_data.get("dkim_selectors", [])
    domain = dns_data.get("domain", "")

    score = 100  # start perfect, deduct for issues

    # SPF
    spf_policy = spf.get("policy", "missing")
    if spf_policy == "missing":
        findings.append({"severity": "critical", "category": "email_security",
                         "title": f"No SPF record for {domain}",
                         "detail": "Anyone can send email as this domain. Add an SPF TXT record."})
        score -= 30
    elif spf_policy == "+all":
        findings.append({"severity": "critical", "category": "email_security",
                         "title": f"SPF +all (pass all) on {domain}",
                         "detail": "SPF explicitly allows all senders. This is equivalent to no SPF."})
        score -= 30
    elif spf_policy == "?all":
        findings.append({"severity": "high", "category": "email_security",
                         "title": f"SPF ?all (neutral) on {domain}",
                         "detail": "SPF neutral policy provides no protection against spoofing."})
        score -= 20
    elif spf_policy == "~all":
        findings.append({"severity": "medium", "category": "email_security",
                         "title": f"SPF ~all (soft fail) on {domain}",
                         "detail": "Soft fail means spoofed emails may still be delivered. Consider -all (hard fail)."})
        score -= 10

    if spf.get("over_limit"):
        findings.append({"severity": "medium", "category": "email_security",
                         "title": f"SPF exceeds 10 DNS lookup limit ({spf.get('dns_lookups', 0)} lookups)",
                         "detail": "Receivers may truncate SPF evaluation, causing legitimate mail to fail."})
        score -= 5

    # DMARC
    dmarc_policy = dmarc.get("policy", "missing")
    if dmarc_policy == "missing":
        findings.append({"severity": "critical", "category": "email_security",
                         "title": f"No DMARC record for {domain}",
                         "detail": "Without DMARC, there is no policy for handling SPF/DKIM failures."})
        score -= 25
    elif dmarc_policy == "none":
        findings.append({"severity": "high", "category": "email_security",
                         "title": f"DMARC policy is 'none' (monitoring only) for {domain}",
                         "detail": "DMARC is present but not enforcing. Spoofed emails are still delivered."})
        score -= 15
    elif dmarc_policy == "quarantine":
        score -= 5  # acceptable but not ideal

    if dmarc_policy != "missing":
        pct = dmarc.get("pct", 100)
        if pct < 100:
            findings.append({"severity": "medium", "category": "email_security",
                             "title": f"DMARC pct={pct}% (not fully enforced)",
                             "detail": f"Only {pct}% of failing emails are subject to DMARC policy."})
            score -= 5
        if not dmarc.get("rua"):
            findings.append({"severity": "low", "category": "email_security",
                             "title": "No DMARC aggregate reporting (rua) configured",
                             "detail": "Without rua, you won't receive reports on DMARC failures."})

    # DKIM
    dkim_found = [d for d in dkim if d.get("found")]
    if not dkim_found:
        findings.append({"severity": "medium", "category": "email_security",
                         "title": f"No common DKIM selectors found for {domain}",
                         "detail": "Checked common selectors. DKIM may use non-standard selectors or be absent."})
        score -= 10

    return {
        "score": max(0, score),
        "spf_policy": spf_policy,
        "dmarc_policy": dmarc_policy,
        "dkim_selectors_found": len(dkim_found),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Phase 5 — Credential Exposure
# ---------------------------------------------------------------------------

def assess_credential_exposure(domain: str) -> dict:
    """Check for credential exposure via dark web intelligence."""
    findings = []
    results = {}

    # XposedOrNot
    try:
        from tools.darkweb import xposedornot_domain_check
        xon = xposedornot_domain_check(domain)
        results["xposedornot"] = xon
        if xon.get("breached"):
            findings.append({
                "severity": "medium",
                "category": "credential_exposure",
                "title": f"Breach data found for {domain}",
                "detail": f"XposedOrNot reports breach exposure for {domain}.",
            })
    except Exception as exc:
        log_error("", "exposure_test:xposedornot_domain", str(exc), severity="warning", traceback=True,
                  context={"domain": domain})
        results["xposedornot"] = {"error": str(exc)}

    return {"results": results, "findings": findings}


# ---------------------------------------------------------------------------
# Phase 6 — Typosquat Detection
# ---------------------------------------------------------------------------

def _generate_typosquats(domain: str) -> list[dict]:
    """Generate candidate typosquat domains."""
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return []
    name, tld = parts[0], parts[1]
    candidates = []
    seen = set()

    def _add(variant: str, typ: str):
        full = f"{variant}.{tld}"
        if full != domain and full not in seen and len(variant) > 1:
            seen.add(full)
            candidates.append({"domain": full, "type": typ})

    # Character omission
    for i in range(len(name)):
        _add(name[:i] + name[i + 1:], "omission")

    # Character duplication
    for i in range(len(name)):
        _add(name[:i] + name[i] + name[i:], "duplication")

    # Character transposition
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        _add("".join(swapped), "transposition")

    # Keyboard adjacent substitution (limited to keep count down)
    for i in range(len(name)):
        ch = name[i].lower()
        for adj in _KEYBOARD_ADJACENT.get(ch, ""):
            _add(name[:i] + adj + name[i + 1:], "substitution")

    # Homoglyphs
    for i in range(len(name)):
        ch = name[i].lower()
        if ch in _HOMOGLYPHS:
            _add(name[:i] + _HOMOGLYPHS[ch] + name[i + 1:], "homoglyph")

    # TLD swaps
    for alt_tld in _TYPOSQUAT_TLDS:
        full = f"{name}{alt_tld}"
        if full != domain and full not in seen:
            seen.add(full)
            candidates.append({"domain": full, "type": "tld_swap"})

    return candidates[:250]  # cap


def detect_typosquats(domain: str) -> list[dict]:
    """Generate typosquats and check which resolve."""
    candidates = _generate_typosquats(domain)
    results = []

    def _check(candidate):
        d = candidate["domain"]
        a_records = _dns_query(d, "A")
        return {
            **candidate,
            "resolves": len(a_records) > 0,
            "ips": a_records,
            "risk": "high" if a_records else "none",
        }

    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = {pool.submit(_check, c): c for c in candidates}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result.get("resolves"):
                    results.append(result)
            except Exception as exc:
                log_error("", "exposure_test:typosquat_check", str(exc), severity="warning",
                          traceback=True, context={"domain": futures[future].get("domain", "")})


    return sorted(results, key=lambda x: x["domain"])


# ---------------------------------------------------------------------------
# Phase 7 — Baseline Comparison
# ---------------------------------------------------------------------------

def _load_knowledge_md(client: str) -> str:
    """Load client knowledge.md content."""
    from config.settings import CLIENT_PLAYBOOKS_DIR
    ck = _client_key(client)
    # Try exact key and original name
    for name in [ck, client]:
        path = CLIENT_PLAYBOOKS_DIR / name / "knowledge.md"
        if path.exists():
            return path.read_text(encoding="utf-8")
    return ""


def _extract_known_subdomains(knowledge: str, domain: str) -> set[str]:
    """Extract known subdomains from knowledge.md content."""
    pattern = re.compile(rf"[\w.-]+\.{re.escape(domain)}", re.IGNORECASE)
    return {m.lower() for m in pattern.findall(knowledge)}


def _extract_known_ips(knowledge: str) -> set[str]:
    """Extract known IPs from knowledge.md content."""
    pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    return set(pattern.findall(knowledge))


def compare_to_baseline(client: str, discovered_subdomains: list[dict],
                        discovered_ips: set[str], dns_data: dict) -> dict:
    """Compare discovered assets against knowledge.md baseline."""
    knowledge = _load_knowledge_md(client)
    findings = []

    if not knowledge:
        return {"baseline_available": False, "findings": [],
                "unknown_subdomains": [], "unknown_ips": []}

    domain = dns_data.get("domain", "")
    known_subs = _extract_known_subdomains(knowledge, domain)
    known_ips = _extract_known_ips(knowledge)

    # Unknown subdomains
    unknown_subs = []
    for sub in discovered_subdomains:
        if sub.get("live") and sub["subdomain"].lower() not in known_subs:
            unknown_subs.append(sub["subdomain"])

    if unknown_subs:
        findings.append({
            "severity": "medium",
            "category": "unknown_assets",
            "title": f"{len(unknown_subs)} live subdomain(s) not in baseline",
            "detail": f"Discovered subdomains not documented in knowledge.md: {', '.join(unknown_subs[:10])}",
        })

    # Unknown IPs
    unknown_ips_list = sorted(discovered_ips - known_ips)
    if unknown_ips_list:
        findings.append({
            "severity": "low",
            "category": "unknown_assets",
            "title": f"{len(unknown_ips_list)} IP(s) not in baseline",
            "detail": f"IPs resolved but not in knowledge.md: {', '.join(unknown_ips_list[:10])}",
        })

    return {
        "baseline_available": True,
        "known_subdomains": len(known_subs),
        "known_ips": len(known_ips),
        "unknown_subdomains": unknown_subs,
        "unknown_ips": unknown_ips_list,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _calculate_scores(all_findings: list[dict]) -> dict:
    """Calculate exposure scores from findings."""
    category_scores = {}
    sev_points = {"critical": 25, "high": 15, "medium": 5, "low": 2}

    for cat in _SCORING_WEIGHTS:
        cat_findings = [f for f in all_findings if f.get("category") == cat]
        deductions = sum(sev_points.get(f.get("severity", "low"), 0) for f in cat_findings)
        category_scores[cat] = min(100, deductions)

    overall = 0
    total_weight = sum(_SCORING_WEIGHTS.values())
    for cat, weight in _SCORING_WEIGHTS.items():
        overall += category_scores.get(cat, 0) * weight / total_weight

    return {
        "overall": round(overall, 1),
        "by_category": category_scores,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_exposure_test(client: str, *, domains: list[str] | None = None,
                      include_typosquats: bool = True) -> dict:
    """
    Run a full external exposure assessment for a client.

    Args:
        client:             Client name.
        domains:            Domains to test (auto-detected from knowledge.md if not provided).
        include_typosquats: Whether to run typosquat detection (can be slow).

    Returns:
        {"status": "ok", "client": str, "path": str, "scores": dict, "summary": dict}
    """
    if not client.strip():
        return {"status": "error", "reason": "client name required"}

    if not _HAS_DNS:
        return {"status": "error", "reason": "dnspython is required — pip install dnspython"}

    # Auto-detect domains if not provided
    if not domains:
        knowledge = _load_knowledge_md(client)
        # Look for primary domain patterns in knowledge.md
        domain_pattern = re.compile(r"(?:primary\s+domain|domain)[:\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.IGNORECASE)
        matches = domain_pattern.findall(knowledge)
        if matches:
            domains = list(dict.fromkeys(matches))  # dedupe, preserve order
        else:
            # Fallback: try client name as domain
            ck = _client_key(client)
            domains = [f"{ck}.com"]

    all_findings: list[dict] = []
    phase_results: dict = {}

    # Phase 1 — DNS
    dns_results = {}
    for domain in domains:
        dns_results[domain] = discover_dns(domain)
    phase_results["dns"] = dns_results

    # Phase 2 — Subdomains
    subdomain_results = {}
    all_discovered_ips: set[str] = set()
    all_subdomains: list[dict] = []

    for domain in domains:
        subs = discover_subdomains(domain)
        subdomain_results[domain] = subs
        all_subdomains.extend(subs)
        # Collect IPs from DNS + subdomains
        for a in dns_results.get(domain, {}).get("a_records", []):
            all_discovered_ips.add(a)
        for sub in subs:
            for ip in sub.get("a_records", []):
                all_discovered_ips.add(ip)

    phase_results["subdomains"] = subdomain_results

    # Phase 3 — Service Exposure
    service_data = assess_services(list(all_discovered_ips)[:50])  # cap at 50 IPs
    phase_results["services"] = service_data
    all_findings.extend(service_data.get("findings", []))

    # Phase 4 — Email Security
    email_results = {}
    for domain in domains:
        email = assess_email_security(dns_results.get(domain, {}))
        email_results[domain] = email
        all_findings.extend(email.get("findings", []))
    phase_results["email_security"] = email_results

    # Phase 5 — Credential Exposure
    cred_results = {}
    for domain in domains:
        creds = assess_credential_exposure(domain)
        cred_results[domain] = creds
        all_findings.extend(creds.get("findings", []))
    phase_results["credential_exposure"] = cred_results

    # Phase 6 — Typosquats
    typosquat_results = {}
    if include_typosquats:
        for domain in domains:
            typos = detect_typosquats(domain)
            typosquat_results[domain] = typos
            if typos:
                all_findings.append({
                    "severity": "medium",
                    "category": "typosquats",
                    "title": f"{len(typos)} registered typosquat(s) for {domain}",
                    "detail": f"Domains: {', '.join(t['domain'] for t in typos[:10])}",
                })
    phase_results["typosquats"] = typosquat_results

    # Phase 7 — Baseline Comparison
    baseline_results = {}
    for domain in domains:
        baseline = compare_to_baseline(client, subdomain_results.get(domain, []),
                                       all_discovered_ips, dns_results.get(domain, {}))
        baseline_results[domain] = baseline
        all_findings.extend(baseline.get("findings", []))
    phase_results["baseline_comparison"] = baseline_results

    # Sort findings by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 99))

    # Scoring
    scores = _calculate_scores(all_findings)

    # Summary stats
    total_subs = sum(len(v) for v in subdomain_results.values())
    live_subs = sum(1 for s in all_subdomains if s.get("live"))
    total_typosquats = sum(len(v) for v in typosquat_results.values())

    summary = {
        "domains_tested": len(domains),
        "subdomains_discovered": total_subs,
        "live_subdomains": live_subs,
        "unique_ips": len(all_discovered_ips),
        "open_ports_total": sum(len(s.get("open_ports", [])) for s in service_data.get("results", [])),
        "high_risk_ports": len([f for f in all_findings if f.get("category") == "service_exposure" and "High-risk port" in f.get("title", "")]),
        "cves_found": len([f for f in all_findings if f.get("category") == "service_exposure" and "CVE" in f.get("title", "")]),
        "active_typosquats": total_typosquats,
        "finding_count": len(all_findings),
        "critical_findings": len([f for f in all_findings if f.get("severity") == "critical"]),
        "high_findings": len([f for f in all_findings if f.get("severity") == "high"]),
    }

    # Save
    EXPOSURE_DIR.mkdir(parents=True, exist_ok=True)
    ck = _client_key(client)
    out_path = EXPOSURE_DIR / f"{ck}.json"

    data = {
        "client": ck,
        "tested_at": utcnow(),
        "domains_tested": domains,
        "phases": phase_results,
        "scores": scores,
        "findings": all_findings,
        "summary": summary,
    }

    save_json(out_path, data)

    return {
        "status": "ok",
        "client": client,
        "path": str(out_path),
        "scores": scores,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Read-only access
# ---------------------------------------------------------------------------

def get_exposure_report(client: str) -> dict:
    """Return the latest exposure test data for a client."""
    ck = _client_key(client)
    path = EXPOSURE_DIR / f"{ck}.json"
    if not path.exists():
        return {"status": "error", "reason": f"No exposure data for '{client}' — run run_exposure_test first"}
    return load_json(path)


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

def generate_exposure_html(client: str) -> dict:
    """Generate an interactive HTML exposure report."""
    data = get_exposure_report(client)
    if not isinstance(data, dict) or "scores" not in data:
        return {"status": "error", "reason": data.get("reason", "No data")}

    ck = _client_key(client)
    html = _render_exposure_html(client, data)
    EXPOSURE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EXPOSURE_DIR / f"{ck}_exposure.html"
    manifest = write_artefact(out_path, html)
    return {"status": "ok", "path": str(out_path)}


def _render_exposure_html(client: str, data: dict) -> str:
    """Build self-contained HTML for exposure report."""
    scores = data.get("scores", {})
    findings = data.get("findings", [])
    summary = data.get("summary", {})
    phases = data.get("phases", {})
    domains = data.get("domains_tested", [])

    overall = scores.get("overall", 0)
    if overall <= 20:
        score_colour = "#1e8b4c"
        score_label = "Low Exposure"
    elif overall <= 50:
        score_colour = "#f39c12"
        score_label = "Moderate Exposure"
    else:
        score_colour = "#c0392b"
        score_label = "High Exposure"

    # Category score bars
    cat_bars = ""
    cat_labels = {
        "email_security": "Email Security",
        "service_exposure": "Service Exposure",
        "credential_exposure": "Credential Exposure",
        "certificate_issues": "Certificate Issues",
        "unknown_assets": "Unknown Assets",
        "typosquats": "Typosquats",
    }
    for cat, label in cat_labels.items():
        val = scores.get("by_category", {}).get(cat, 0)
        bar_colour = "#1e8b4c" if val <= 15 else "#f39c12" if val <= 40 else "#c0392b"
        cat_bars += f"""
        <div style="margin:6px 0">
          <div style="display:flex;justify-content:space-between;font-size:0.85em;margin-bottom:2px">
            <span>{label}</span><span style="color:{bar_colour}">{val}</span>
          </div>
          <div style="background:#21262d;border-radius:4px;height:8px">
            <div style="background:{bar_colour};width:{min(val, 100)}%;height:100%;border-radius:4px"></div>
          </div>
        </div>"""

    # Email security per domain
    email_html = ""
    for domain in domains:
        em = phases.get("email_security", {}).get(domain, {})
        spf_p = em.get("spf_policy", "?")
        dmarc_p = em.get("dmarc_policy", "?")
        dkim_n = em.get("dkim_selectors_found", 0)
        spf_c = "#1e8b4c" if spf_p == "-all" else "#f39c12" if spf_p == "~all" else "#c0392b"
        dmarc_c = "#1e8b4c" if dmarc_p == "reject" else "#f39c12" if dmarc_p == "quarantine" else "#c0392b"
        dkim_c = "#1e8b4c" if dkim_n > 0 else "#f39c12"
        email_html += f"""
        <tr>
          <td style="padding:8px;font-family:monospace">{domain}</td>
          <td style="padding:8px;color:{spf_c};font-weight:bold">{spf_p}</td>
          <td style="padding:8px;color:{dmarc_c};font-weight:bold">{dmarc_p}</td>
          <td style="padding:8px;color:{dkim_c}">{dkim_n} selector(s)</td>
          <td style="padding:8px">{em.get('score', '?')}/100</td>
        </tr>"""

    # Subdomain table
    sub_rows = ""
    for domain in domains:
        for sub in phases.get("subdomains", {}).get(domain, [])[:50]:
            live_c = "#1e8b4c" if sub.get("live") else "#555"
            live_t = "live" if sub.get("live") else "dead"
            ips = ", ".join(sub.get("a_records", [])[:3])
            sub_rows += f"""
            <tr>
              <td style="padding:6px;font-family:monospace;font-size:0.85em">{sub['subdomain']}</td>
              <td style="padding:6px;font-size:0.85em">{sub.get('source', '')}</td>
              <td style="padding:6px;color:{live_c}">{live_t}</td>
              <td style="padding:6px;font-family:monospace;font-size:0.8em">{ips}</td>
            </tr>"""

    # Typosquat rows
    typo_rows = ""
    for domain in domains:
        for t in phases.get("typosquats", {}).get(domain, []):
            typo_rows += f"""
            <tr>
              <td style="padding:6px;font-family:monospace">{t['domain']}</td>
              <td style="padding:6px">{t.get('type', '')}</td>
              <td style="padding:6px;font-family:monospace;font-size:0.85em">{', '.join(t.get('ips', []))}</td>
            </tr>"""

    # Findings table
    sev_colours = {"critical": "#c0392b", "high": "#e74c3c", "medium": "#f39c12", "low": "#58a6ff"}
    finding_rows = ""
    for f in findings[:40]:
        sev = f.get("severity", "low")
        finding_rows += f"""
        <tr>
          <td style="color:{sev_colours.get(sev, '#888')};font-weight:bold;text-transform:uppercase;padding:8px">{sev}</td>
          <td style="padding:8px">{f.get('category', '').replace('_', ' ')}</td>
          <td style="padding:8px">{f.get('title', '')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Exposure Assessment — {client}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; padding: 20px 30px; }}
  h1 {{ color: #58a6ff; margin-bottom: 8px; font-size: 1.6em; }}
  h2 {{ color: #58a6ff; margin: 30px 0 15px 0; font-size: 1.2em; border-bottom: 1px solid #21262d; padding-bottom: 8px; }}
  .meta {{ color: #8b949e; font-size: 0.9em; margin-bottom: 20px; }}
  .scorecard {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
  .score-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 20px; text-align: center; min-width: 140px; }}
  .score-big {{ font-size: 2.5em; font-weight: bold; }}
  .score-label {{ font-size: 0.85em; color: #8b949e; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 8px; color: #8b949e; font-size: 0.85em; border-bottom: 1px solid #21262d; }}
  tr:hover {{ background: #161b22; }}
  .categories {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 20px; max-width: 500px; }}
</style>
</head>
<body>

<h1>External Exposure Assessment</h1>
<div class="meta">{client} &mdash; tested {data.get('tested_at', 'unknown')} &mdash; domains: {', '.join(domains)}</div>

<div class="scorecard">
  <div class="score-card">
    <div class="score-big" style="color:{score_colour}">{int(overall)}</div>
    <div class="score-label">{score_label}</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#c0392b">{summary.get('critical_findings', 0)}</div>
    <div class="score-label">Critical</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#e74c3c">{summary.get('high_findings', 0)}</div>
    <div class="score-label">High</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#8b949e">{summary.get('live_subdomains', 0)}</div>
    <div class="score-label">Live Subdomains</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#8b949e">{summary.get('unique_ips', 0)}</div>
    <div class="score-label">Unique IPs</div>
  </div>
  <div class="score-card">
    <div class="score-big" style="color:#f39c12">{summary.get('active_typosquats', 0)}</div>
    <div class="score-label">Typosquats</div>
  </div>
</div>

<div class="categories">{cat_bars}</div>

<h2>Email Security</h2>
<table>
  <tr><th>Domain</th><th>SPF</th><th>DMARC</th><th>DKIM</th><th>Score</th></tr>
  {email_html}
</table>

<h2>Subdomains ({summary.get('subdomains_discovered', 0)} discovered, {summary.get('live_subdomains', 0)} live)</h2>
<table>
  <tr><th>Subdomain</th><th>Source</th><th>Status</th><th>IPs</th></tr>
  {sub_rows if sub_rows else '<tr><td colspan="4" style="padding:12px;color:#8b949e">No subdomains discovered</td></tr>'}
</table>

{"<h2>Registered Typosquats</h2><table><tr><th>Domain</th><th>Type</th><th>IPs</th></tr>" + typo_rows + "</table>" if typo_rows else ""}

<h2>Findings ({len(findings)})</h2>
<table>
  <tr><th>Severity</th><th>Category</th><th>Finding</th></tr>
  {finding_rows if finding_rows else '<tr><td colspan="3" style="padding:12px;color:#8b949e">No findings</td></tr>'}
</table>

</body>
</html>"""

    return html
