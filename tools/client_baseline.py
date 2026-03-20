"""
tool: client_baseline
---------------------
Build and query per-client behavioural baselines from historical case data.

A baseline captures what is "normal" for a client — recurring IOCs, common
attack patterns, severity distribution, tag frequency — so that enrichment
results and new cases can be contextualised:
  "this domain has appeared 3 times across client cases, always clean"
  "account_compromise is the most common attack type for this client"

Writes:
  registry/baselines/{client_key}.json

Usage:
    from tools.client_baseline import get_client_baseline, check_against_baseline

    # Get or build baseline for a client
    baseline = get_client_baseline("acme_corp")

    # Check whether an IOC has appeared before
    result = check_against_baseline("acme_corp", "ipv4", "1.2.3.4")
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import BASELINES_DIR, CASES_DIR, REGISTRY_FILE
from tools.common import load_json, log_error, utcnow


def _client_key(client: str) -> str:
    return client.strip().lower().replace(" ", "_")


def _get_cases_for_client(client: str) -> list[tuple[str, dict]]:
    """Return [(case_id, meta)] for all cases belonging to client."""
    try:
        registry_data = load_json(REGISTRY_FILE) if REGISTRY_FILE.exists() else {}
        case_registry = registry_data.get("cases", registry_data)
    except Exception:
        return []

    ck = _client_key(client)
    result = []
    for case_id, meta in case_registry.items():
        if case_id.startswith("TEST_"):
            continue
        if _client_key(meta.get("client", "") or "") != ck:
            continue
        result.append((case_id, meta))
    return result


def build_client_baseline(client: str) -> dict:
    """
    Build a behavioural baseline for a client from all historical cases.

    Scans every case for this client and profiles:
    - IOC recurrence (which IPs, domains, hashes appear repeatedly)
    - Verdict history (confirmed malicious / suspicious IOCs)
    - Attack type distribution
    - Severity distribution
    - Tag frequency
    - Disposition breakdown

    Args:
        client: Client name (case-insensitive).

    Returns:
        {"status": "ok", "client": str, "case_count": int, "path": str}
    """
    if not client.strip():
        return {"status": "error", "reason": "client name required"}

    cases = _get_cases_for_client(client)
    if not cases:
        return {
            "status": "ok",
            "client": client,
            "case_count": 0,
            "message": "No cases found for this client — baseline not built.",
        }

    profile: dict = {
        "client": _client_key(client),
        "built_at": utcnow(),
        "case_count": len(cases),
        "iocs": {
            "ipv4": {},
            "domain": {},
            "url": {},
            "md5": {},
            "sha256": {},
            "email": {},
        },
        "known_malicious": [],
        "known_suspicious": [],
        "attack_types": {},
        "severity_dist": {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        },
        "tags": {},
        "dispositions": {},
    }

    for case_id, meta in cases:
        case_dir = CASES_DIR / case_id

        # Severity
        sev = (meta.get("severity") or "").lower()
        if sev in profile["severity_dist"]:
            profile["severity_dist"][sev] += 1

        # Tags
        for tag in (meta.get("tags") or []):
            t = tag.strip().lower()
            if t:
                profile["tags"][t] = profile["tags"].get(t, 0) + 1

        # Attack type
        at = meta.get("attack_type") or ""
        if at:
            profile["attack_types"][at] = profile["attack_types"].get(at, 0) + 1

        # Disposition
        disp = meta.get("disposition") or ""
        if disp:
            profile["dispositions"][disp] = profile["dispositions"].get(disp, 0) + 1

        # IOC recurrence
        iocs_path = case_dir / "iocs" / "iocs.json"
        if iocs_path.exists():
            try:
                iocs_data = load_json(iocs_path)
                ioc_dict = iocs_data.get("iocs", {})
                for ioc_type, values in ioc_dict.items():
                    if ioc_type not in profile["iocs"]:
                        continue
                    for val in values:
                        bucket = profile["iocs"][ioc_type]
                        if val not in bucket:
                            bucket[val] = {"seen": 0, "cases": []}
                        bucket[val]["seen"] += 1
                        if case_id not in bucket[val]["cases"]:
                            bucket[val]["cases"].append(case_id)
            except Exception as exc:
                log_error(case_id, "baseline.iocs", str(exc),
                          severity="warning", context={"client": client})

        # Malicious / suspicious verdicts
        verdict_path = case_dir / "artefacts" / "enrichment" / "verdict_summary.json"
        if verdict_path.exists():
            try:
                verdicts = load_json(verdict_path)
                for ioc in verdicts.get("high_priority", []):
                    if ioc not in profile["known_malicious"]:
                        profile["known_malicious"].append(ioc)
                for ioc in verdicts.get("needs_review", []):
                    if ioc not in profile["known_suspicious"]:
                        profile["known_suspicious"].append(ioc)
            except Exception:
                pass

    # Keep only top-50 IOCs per type by recurrence to cap file size
    for ioc_type in profile["iocs"]:
        bucket = profile["iocs"][ioc_type]
        if len(bucket) > 50:
            top50 = sorted(bucket.items(), key=lambda x: x[1]["seen"], reverse=True)[:50]
            profile["iocs"][ioc_type] = dict(top50)

    try:
        BASELINES_DIR.mkdir(parents=True, exist_ok=True)
        out_path = BASELINES_DIR / f"{_client_key(client)}.json"
        out_path.write_text(json.dumps(profile, default=str, indent=2), encoding="utf-8")
    except Exception as exc:
        log_error("", "baseline.write", str(exc),
                  severity="error", context={"client": client})
        return {"status": "error", "reason": str(exc)}

    return {
        "status": "ok",
        "client": client,
        "case_count": len(cases),
        "path": str(out_path),
    }


def get_client_baseline(client: str) -> dict:
    """
    Return the full baseline profile for a client.

    Builds it automatically if not already present.

    Returns the raw profile dict (with keys: client, built_at, case_count,
    iocs, attack_types, severity_dist, tags, dispositions, known_malicious,
    known_suspicious) or an error/status dict.
    """
    ck = _client_key(client)
    baseline_path = BASELINES_DIR / f"{ck}.json"

    if not baseline_path.exists():
        built = build_client_baseline(client)
        if built.get("status") != "ok":
            return built
        if built.get("case_count", 0) == 0:
            return built
        baseline_path = BASELINES_DIR / f"{ck}.json"

    try:
        return json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log_error("", "baseline.get", str(exc),
                  severity="error", context={"client": client})
        return {"status": "error", "reason": str(exc)}


def check_against_baseline(client: str, ioc_type: str, value: str) -> dict:
    """
    Check whether a specific IOC has been seen in prior cases for this client.

    Args:
        client:   Client name.
        ioc_type: One of: ipv4, domain, url, md5, sha256, email.
        value:    The IOC value to look up.

    Returns:
        {
            "known": bool,
            "seen": int,        # number of cases it appeared in
            "cases": [str],     # case IDs
            "client": str,
        }
    """
    ck = _client_key(client)
    baseline_path = BASELINES_DIR / f"{ck}.json"
    if not baseline_path.exists():
        return {"known": False, "seen": 0, "cases": [],
                "note": "No baseline for this client — run build_client_baseline first."}

    try:
        profile = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log_error("", "baseline.check", str(exc),
                  severity="warning", context={"client": client})
        return {"known": False, "seen": 0, "cases": [], "error": str(exc)}

    entry = profile.get("iocs", {}).get(ioc_type, {}).get(value)
    if not entry:
        return {"known": False, "seen": 0, "cases": [], "client": client}

    return {
        "known": True,
        "seen": entry.get("seen", 0),
        "cases": entry.get("cases", []),
        "client": client,
    }
