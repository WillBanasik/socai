"""
tool: campaign_cluster
-----------------------
Groups cases sharing IOCs into campaigns using Union-Find connected components.

- Loads ioc_index.json and builds a case adjacency graph from shared IOCs
- Uses Union-Find to find connected components
- Filters: campaign requires 2+ cases AND SOCAI_CAMPAIGN_MIN_IOCS shared IOCs
- Builds infrastructure overlap from enrichment data
- Extracts common MITRE ATT&CK TTPs from security_arch_structured.json

Writes:
  registry/campaigns.json (global campaign registry — retained)

Per-case campaign_links.json is no longer persisted; results are returned to the caller.
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASE_DIR, CASES_DIR, IOC_INDEX_FILE
from tools.common import load_json, log_error, save_json, utcnow

CAMPAIGNS_FILE = BASE_DIR / "registry" / "campaigns.json"
CAMPAIGN_MIN_IOCS = int(os.getenv("SOCAI_CAMPAIGN_MIN_IOCS", "2"))

# ---------------------------------------------------------------------------
# Noise suppression — IOCs that must NEVER form campaign links
# ---------------------------------------------------------------------------

# Domains/FQDNs that appear in virtually every investigation due to crawler
# artefacts, mail headers, common infrastructure, or the org's own domain.
_BENIGN_DOMAINS: set[str] = {
    # Common infrastructure
    "github.com", "google.com", "microsoft.com", "cloudflare.com",
    "amazonaws.com", "azure.com", "office.com", "office365.com",
    "windows.net", "live.com", "outlook.com", "protection.outlook.com",
    # Org's own domain — add yours here or via SOCAI_CLEAN_DOMAINS env var
    # Threat-intel / research platforms (appear when crawler follows links)
    "virustotal.com", "hybrid-analysis.com", "otx.alienvault.com",
    "attack.mitre.org", "malwarebazaar.abuse.ch",
    # Internet governance
    "icann.org", "arin.net", "ripe.net", "apnic.net", "internic.net",
    # CDN / CRL / certificate infra
    "digicert.com", "letsencrypt.org", "cookielaw.org",
    # Social media (footer links scraped from captured pages)
    "twitter.com", "x.com", "facebook.com", "linkedin.com",
}

# Exact IOC values that are never meaningful (XML namespaces, JS artefacts,
# broken URL extractions, common DNS resolvers, etc.)
_BENIGN_EXACT: set[str] = {
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/1999/xlink",
    "http://www.=",
    "e.id", "o.id", "r.id", "t.id",   # JS minification artefacts
    "be.link",
    "window.ga",                         # Google Analytics JS reference
    "8.8.8.8", "8.8.4.4",              # Google DNS
    "1.1.1.1", "1.0.0.1", "1.0.0.2",  # Cloudflare DNS
}


def _is_noise_ioc(ioc_val: str) -> bool:
    """Return True if an IOC should be excluded from campaign linkage."""
    if ioc_val in _BENIGN_EXACT:
        return True
    # Check if domain or any parent domain is benign
    lower = ioc_val.lower().strip()
    for domain in _BENIGN_DOMAINS:
        if lower == domain or lower.endswith("." + domain):
            return True
    # Outlook mail-routing FQDNs (e.g. am9pr03mb7171.eurprd03.prod.outlook.com)
    if "outlook.com" in lower or "mail.protection" in lower:
        return True
    return False


# ---------------------------------------------------------------------------
# Union-Find
# ---------------------------------------------------------------------------

class _UnionFind:
    """Simple Union-Find (disjoint set) implementation."""

    def __init__(self):
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def components(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = defaultdict(list)
        for x in self._parent:
            groups[self.find(x)].append(x)
        return dict(groups)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_optional(path: Path) -> dict | list | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "campaign_cluster.load_optional", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def _generate_campaign_id(case_set: frozenset[str], year: int) -> str:
    """Deterministic campaign ID from sorted case set."""
    import hashlib
    key = "|".join(sorted(case_set))
    digest = hashlib.md5(key.encode()).hexdigest()[:6]
    return f"CAMP-{year}-{digest.upper()}"


def _extract_shared_iocs(ioc_index: dict, cases: frozenset[str]) -> list[dict]:
    """Find IOCs shared by at least 2 cases in the set.

    Only includes IOCs with malicious/suspicious verdicts and excludes
    known-benign infrastructure noise.
    """
    shared = []
    for ioc_val, entry in ioc_index.items():
        if _is_noise_ioc(ioc_val):
            continue
        verdict = entry.get("verdict", "").lower()
        if verdict not in ("malicious", "suspicious"):
            continue
        ioc_cases = set(entry.get("cases", []))
        overlap = ioc_cases & cases
        if len(overlap) >= 2:
            shared.append({
                "ioc": ioc_val,
                "type": entry.get("ioc_type", entry.get("type", "unknown")),
                "verdict": entry.get("verdict", "unknown"),
                "confidence": entry.get("confidence", "UNKNOWN"),
                "cases": sorted(overlap),
            })
    return shared


def _extract_common_ttps(cases: frozenset[str]) -> list[str]:
    """Find MITRE ATT&CK TTPs common across campaign member cases."""
    case_ttps: list[set[str]] = []
    for case_id in cases:
        struct_path = (
            CASES_DIR / case_id / "artefacts" / "security_architecture"
            / "security_arch_structured.json"
        )
        data = _load_optional(struct_path)
        if data and data.get("ttps"):
            case_ttps.append(set(data["ttps"]))

    if len(case_ttps) < 2:
        return []

    # TTPs appearing in 2+ cases
    from collections import Counter
    counter: Counter[str] = Counter()
    for ttp_set in case_ttps:
        for ttp in ttp_set:
            counter[ttp] += 1

    return sorted(ttp for ttp, count in counter.items() if count >= 2)


def _compute_confidence(shared_iocs: list[dict]) -> str:
    """Compute campaign confidence level."""
    malicious_count = sum(1 for i in shared_iocs if i.get("verdict") == "malicious")
    total = len(shared_iocs)

    if total >= 3 and malicious_count >= 1:
        return "HIGH"
    if total >= 2 and malicious_count >= 1:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Main tool function
# ---------------------------------------------------------------------------

def cluster_campaigns(case_id: str | None = None) -> dict:
    """
    Group cases sharing IOCs into campaigns.
    If case_id is provided, also writes per-case campaign links.
    """
    # --- Guard: block clustering on closed cases ---
    if case_id:
        meta_path = CASES_DIR / case_id / "case_meta.json"
        if meta_path.exists():
            try:
                _meta = load_json(meta_path)
                if _meta.get("status") == "closed":
                    return {"error": f"Case {case_id} is closed — cannot cluster a closed case.",
                            "case_id": case_id}
            except Exception:
                pass

    ioc_index = _load_optional(IOC_INDEX_FILE)
    if not ioc_index:
        return {"status": "no_data", "reason": "ioc_index.json not found or empty", "campaigns": []}

    # Build case adjacency via shared IOCs
    uf = _UnionFind()
    ioc_case_map: dict[str, list[str]] = {}  # ioc -> cases

    for ioc_val, entry in ioc_index.items():
        cases = entry.get("cases", [])
        if len(cases) < 2:
            continue
        # Skip noise IOCs that pollute campaign links
        if _is_noise_ioc(ioc_val):
            continue
        # Only link cases on IOCs with a malicious or suspicious verdict
        verdict = entry.get("verdict", "").lower()
        if verdict not in ("malicious", "suspicious"):
            continue
        ioc_case_map[ioc_val] = cases
        # Union all cases that share this IOC
        first = cases[0]
        for other in cases[1:]:
            uf.union(first, other)

    # Extract connected components
    components = uf.components()

    # Build campaigns
    now = datetime.fromisoformat(utcnow().replace("Z", "+00:00"))
    campaigns: list[dict] = []

    for root, members in components.items():
        case_set = frozenset(members)
        if len(case_set) < 2:
            continue

        shared_iocs = _extract_shared_iocs(ioc_index, case_set)
        if len(shared_iocs) < CAMPAIGN_MIN_IOCS:
            continue

        campaign_id = _generate_campaign_id(case_set, now.year)
        common_ttps = _extract_common_ttps(case_set)
        confidence = _compute_confidence(shared_iocs)

        campaign = {
            "campaign_id": campaign_id,
            "cases": sorted(case_set),
            "shared_iocs": shared_iocs,
            "shared_ioc_count": len(shared_iocs),
            "common_ttps": common_ttps,
            "confidence": confidence,
            "first_seen": min(
                (i.get("cases", [""])[0] for i in shared_iocs),
                default="",
            ),
            "updated_at": utcnow(),
        }
        # LLM campaign narrative (advisory)
        try:
            from tools.llm_insight import generate_campaign_narrative
            narrative = generate_campaign_narrative(campaign)
            if narrative:
                campaign["narrative"] = narrative
        except Exception:
            pass
        campaigns.append(campaign)

    # Save global campaigns registry
    campaigns_data = {
        "campaigns": campaigns,
        "total": len(campaigns),
        "updated_at": utcnow(),
    }
    save_json(CAMPAIGNS_FILE, campaigns_data)

    # Print summary
    print(f"[campaign_cluster] Found {len(campaigns)} campaign(s)")
    for c in campaigns:
        print(f"  {c['campaign_id']}: {len(c['cases'])} cases, "
              f"{c['shared_ioc_count']} shared IOCs, confidence={c['confidence']}")

    return {
        "status": "ok",
        "campaigns": campaigns,
        "total": len(campaigns),
        "case_id": case_id,
        "ts": utcnow(),
    }


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="Cluster cases into campaigns by shared IOCs.")
    p.add_argument("--case", default=None, dest="case_id", help="Optional case ID for per-case links")
    args = p.parse_args()

    result = cluster_campaigns(args.case_id)
    print(json.dumps(result, indent=2))
