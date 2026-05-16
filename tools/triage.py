"""
tool: triage
-------------
Pre-pipeline check of input IOCs against ioc_index.json and enrichment_cache.json.

- Extracts domains from input URLs
- Checks against ioc_index.json for known malicious/suspicious/clean
- Checks enrichment cache for IOCs with 3+ fresh provider results (skip-enrichment candidates)
- Recommends severity escalation if known-malicious IOCs found

Returns the triage summary dict in-memory; does NOT write to disk.
"""
from __future__ import annotations

import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import (
    ENRICH_CACHE_FILE, ENRICH_CACHE_TTL, IOC_INDEX_FILE,
)
from tools.common import eprint, load_json, log_error, utcnow

# Threshold for severity escalation: this many known-malicious IOCs triggers it
TRIAGE_ESCALATION_THRESHOLD = int(
    __import__("os").getenv("SOCAI_TRIAGE_ESCALATION_THRESHOLD", "1")
)

# Min providers with fresh cache results to recommend skipping enrichment
_SKIP_ENRICH_MIN_PROVIDERS = 3


def _extract_domains_from_urls(urls: list[str]) -> list[str]:
    """Extract unique domains from a list of URLs."""
    domains: set[str] = set()
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname
            if host:
                domains.add(host.lower())
        except Exception as exc:
            log_error("", "triage.extract_domain", str(exc),
                      severity="warning", context={"url": url[:200]})
    return sorted(domains)


def _load_optional(path: Path) -> dict | None:
    try:
        return load_json(path)
    except FileNotFoundError:
        return None
    except Exception as exc:
        log_error("", "triage.load_optional", str(exc),
                  severity="warning", context={"path": str(path)})
        return None


def triage(case_id: str, urls: list[str] | None = None, severity: str = "medium") -> dict:
    """
    Pre-pipeline triage: check input IOCs against existing intelligence.
    Returns a summary with known hits and recommendations (no disk write).
    """
    # Load intelligence sources
    ioc_index = _load_optional(IOC_INDEX_FILE) or {}
    enrich_cache = _load_optional(ENRICH_CACHE_FILE) or {}

    # Extract domains from input URLs
    domains = _extract_domains_from_urls(urls or [])
    input_iocs = list(set(domains + (urls or [])))

    # Check ioc_index for known IOCs
    known_malicious: list[dict] = []
    known_suspicious: list[dict] = []
    known_clean: list[dict] = []
    skip_enrichment_iocs: list[str] = []

    for ioc in input_iocs:
        entry = ioc_index.get(ioc)
        if entry:
            hit = {
                "ioc": ioc,
                "verdict": entry.get("verdict", "unknown"),
                "confidence": entry.get("confidence", "UNKNOWN"),
                "first_seen": entry.get("first_seen", ""),
                "last_seen": entry.get("last_seen", ""),
                "cases": entry.get("cases", []),
            }
            verdict = entry.get("verdict", "").lower()
            if verdict == "malicious":
                known_malicious.append(hit)
            elif verdict == "suspicious":
                known_suspicious.append(hit)
            elif verdict == "clean":
                known_clean.append(hit)

    # Check enrichment cache for IOCs with sufficient fresh coverage
    cache_ttl = timedelta(hours=ENRICH_CACHE_TTL) if ENRICH_CACHE_TTL > 0 else None
    now = datetime.fromisoformat(utcnow().replace("Z", "+00:00"))

    for ioc in input_iocs:
        fresh_providers = 0
        for cache_key, cached in enrich_cache.items():
            if not cache_key.endswith(f"|{ioc}"):
                continue
            if cached.get("status") != "ok":
                continue
            if cache_ttl:
                try:
                    cached_ts = datetime.fromisoformat(
                        cached.get("cached_at", "2000-01-01T00:00:00Z").replace("Z", "+00:00")
                    )
                    if now - cached_ts > cache_ttl:
                        continue
                except Exception as exc:
                    log_error(case_id, "triage.cache_ttl", str(exc),
                              severity="warning", context={"ioc": ioc})
                    continue
            fresh_providers += 1

        if fresh_providers >= _SKIP_ENRICH_MIN_PROVIDERS:
            skip_enrichment_iocs.append(ioc)

    # Severity escalation recommendation
    escalate_severity = None
    if len(known_malicious) >= TRIAGE_ESCALATION_THRESHOLD:
        severity_order = ["low", "medium", "high", "critical"]
        current_idx = severity_order.index(severity) if severity in severity_order else 1
        if current_idx < 2:  # Escalate to at least "high"
            escalate_severity = "high"

    result = {
        "status": "ok",
        "case_id": case_id,
        "input_urls": urls or [],
        "extracted_domains": domains,
        "known_malicious": known_malicious,
        "known_suspicious": known_suspicious,
        "known_clean": known_clean,
        "skip_enrichment_iocs": skip_enrichment_iocs,
        "escalate_severity": escalate_severity,
        "ts": utcnow(),
    }

    # LLM triage contextualisation (advisory)
    if known_malicious or known_suspicious:
        try:
            from tools.llm_insight import contextualise_triage
            context = contextualise_triage(result, severity)
            if context:
                result["llm_context"] = context
        except Exception:
            pass

    # Print summary
    eprint(f"[triage] Checked {len(input_iocs)} IOC(s) against intelligence")
    if known_malicious:
        eprint(f"  ⚠ {len(known_malicious)} KNOWN MALICIOUS IOC(s): "
               + ", ".join(h["ioc"] for h in known_malicious[:5]))
    if known_suspicious:
        eprint(f"  ⚡ {len(known_suspicious)} known suspicious IOC(s)")
    if known_clean:
        eprint(f"  ✓ {len(known_clean)} known clean IOC(s)")
    if skip_enrichment_iocs:
        eprint(f"  ⏭ {len(skip_enrichment_iocs)} IOC(s) have fresh cache — skip enrichment")
    if escalate_severity:
        eprint(f"  ⬆ Recommending severity escalation to {escalate_severity}")

    return result


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="Pre-pipeline IOC triage.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--url", nargs="*", default=[], help="URLs to triage")
    p.add_argument("--severity", default="medium")
    args = p.parse_args()

    result = triage(args.case_id, urls=args.url, severity=args.severity)
    print(json.dumps(result, indent=2))
