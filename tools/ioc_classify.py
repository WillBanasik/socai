"""
IOC tier classification — determines whether an indicator is globally
searchable or client-scoped.

Tier definitions
----------------
  global  — observable on the public internet; safe to correlate across
            all clients (public IPs, domains, hashes, CVEs, URLs, external
            emails).  Cross-client matches reveal *that* an IOC appeared
            elsewhere, but never expose the other client's case details.

  client  — meaningful only within one client's environment; must never
            leak across client boundaries (internal hostnames, private IPs,
            UPNs, device names).

Classification is based on IOC type + value.  All IOC types currently
extracted by extract_iocs.py are public indicators (private IPs are
filtered at extraction), so the default tier is 'global'.  This module
provides the framework for future client-scoped indicator types.
"""
from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Tier constants ───────────────────────────────────────────────────
TIER_GLOBAL = "global"
TIER_CLIENT = "client"

# IOC types that are always global (observable on the public internet)
_ALWAYS_GLOBAL = frozenset({
    "md5", "sha1", "sha256",   # file hashes
    "cve",                      # CVE identifiers
    "url",                      # public URLs
})


def classify_ioc(ioc_type: str, value: str) -> str:
    """Return ``"global"`` or ``"client"`` for the given IOC.

    Rules
    -----
    - Hashes, CVEs, URLs → always global.
    - IPv4: global if public, client if private/reserved.
    - Domains: global if FQDN (contains dot), client if bare hostname.
    - Emails: global (external addresses); future: client if internal domain.
    """
    if ioc_type in _ALWAYS_GLOBAL:
        return TIER_GLOBAL

    if ioc_type == "ipv4":
        try:
            addr = ipaddress.ip_address(value)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return TIER_CLIENT
        except ValueError:
            pass
        return TIER_GLOBAL

    if ioc_type == "domain":
        # Bare hostnames (no dot) are internal; FQDNs are public
        return TIER_GLOBAL if "." in value else TIER_CLIENT

    if ioc_type == "email":
        return TIER_GLOBAL

    # Default: treat unknown types as global
    return TIER_GLOBAL


def get_case_client(case_id: str) -> str:
    """Read the client name from a case's metadata.

    Returns the lowercase client name, or empty string if not set.
    """
    from config.settings import CASES_DIR
    meta_path = CASES_DIR / case_id / "case_meta.json"
    if not meta_path.exists():
        return ""
    try:
        meta = json.loads(meta_path.read_text())
        return (meta.get("client") or "").strip().lower()
    except Exception:
        return ""
