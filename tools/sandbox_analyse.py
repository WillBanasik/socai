"""
tool: sandbox_analyse
---------------------
Queries sandbox APIs for existing detonation reports by SHA256.
Optionally submits files for live detonation.

Providers:
  - Any.Run — /v1/analysis/search (hash lookup)
  - Joe Sandbox — /api/v2/analysis/search (hash lookup)
  - Hybrid Analysis — /api/v2/overview/{sha256} (already partially integrated in enrich)

Writes:
  cases/<case_id>/artefacts/sandbox/sandbox_results.json
  cases/<case_id>/artefacts/sandbox/sandbox_iocs.json
"""
from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests as _requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, HYBRID_KEY
from tools.common import load_json, log_error, save_json, utcnow

ANYRUN_KEY = os.getenv("ANYRUN_API_KEY", "")
JOESANDBOX_KEY = os.getenv("JOESANDBOX_API_KEY", "")
SANDBOX_WORKERS = int(os.getenv("SOCAI_SANDBOX_WORKERS", "3"))
SANDBOX_POLL_INTERVAL = int(os.getenv("SOCAI_SANDBOX_POLL_INTERVAL", "30"))
SANDBOX_TIMEOUT = int(os.getenv("SOCAI_SANDBOX_TIMEOUT", "300"))


# ---------------------------------------------------------------------------
# Provider functions
# ---------------------------------------------------------------------------

def _anyrun_lookup(sha256: str) -> dict:
    """Query Any.Run for existing analysis by SHA256."""
    if not ANYRUN_KEY:
        return {"provider": "anyrun", "status": "no_api_key", "sha256": sha256}

    try:
        resp = _requests.get(
            "https://api.any.run/v1/analysis/",
            params={"hash": sha256},
            headers={"Authorization": f"API-Key {ANYRUN_KEY}"},
            timeout=15,
        )
        if resp.status_code == 404:
            return {"provider": "anyrun", "status": "not_found", "sha256": sha256}
        if resp.status_code != 200:
            return {"provider": "anyrun", "status": f"http_{resp.status_code}", "sha256": sha256}

        data = resp.json()
        tasks = data.get("data", {}).get("tasks", [])
        if not tasks:
            return {"provider": "anyrun", "status": "not_found", "sha256": sha256}

        task = tasks[0]
        return {
            "provider": "anyrun",
            "status": "ok",
            "sha256": sha256,
            "verdict": task.get("verdict", "unknown"),
            "score": task.get("scores", {}).get("specs", {}).get("overall", 0),
            "tags": task.get("tags", []),
            "mitre": task.get("mitre", []),
            "network_iocs": _extract_anyrun_network(task),
            "process_tree": task.get("process_tree", []),
            "report_url": task.get("public_url", ""),
        }
    except Exception as exc:
        log_error("", "sandbox.anyrun", str(exc),
                  severity="warning", context={"sha256": sha256})
        return {"provider": "anyrun", "status": "error", "sha256": sha256, "error": str(exc)}


def _extract_anyrun_network(task: dict) -> list[dict]:
    """Extract network IOCs from Any.Run task data."""
    iocs = []
    for conn in task.get("network", {}).get("connections", []):
        if conn.get("ip"):
            iocs.append({"type": "ipv4", "value": conn["ip"]})
        if conn.get("domain"):
            iocs.append({"type": "domain", "value": conn["domain"]})
    return iocs


def _joesandbox_lookup(sha256: str) -> dict:
    """Query Joe Sandbox for existing analysis by SHA256."""
    if not JOESANDBOX_KEY:
        return {"provider": "joesandbox", "status": "no_api_key", "sha256": sha256}

    try:
        resp = _requests.post(
            "https://jbxcloud.joesecurity.org/api/v2/analysis/search",
            data={"q": sha256, "apikey": JOESANDBOX_KEY},
            timeout=15,
        )
        if resp.status_code != 200:
            return {"provider": "joesandbox", "status": f"http_{resp.status_code}", "sha256": sha256}

        data = resp.json()
        analyses = data.get("data", [])
        if not analyses:
            return {"provider": "joesandbox", "status": "not_found", "sha256": sha256}

        analysis = analyses[0]
        return {
            "provider": "joesandbox",
            "status": "ok",
            "sha256": sha256,
            "verdict": analysis.get("detection", "unknown"),
            "score": analysis.get("score", 0),
            "tags": analysis.get("tags", []),
            "mitre": analysis.get("mitre", []),
            "c2_beacons": analysis.get("c2", []),
            "dropped_files": analysis.get("dropped", []),
            "report_url": analysis.get("weburl", ""),
        }
    except Exception as exc:
        log_error("", "sandbox.joesandbox", str(exc),
                  severity="warning", context={"sha256": sha256})
        return {"provider": "joesandbox", "status": "error", "sha256": sha256, "error": str(exc)}


def _hybrid_analysis_lookup(sha256: str) -> dict:
    """Query Hybrid Analysis overview endpoint by SHA256."""
    if not HYBRID_KEY:
        return {"provider": "hybrid_analysis", "status": "no_api_key", "sha256": sha256}

    try:
        resp = _requests.get(
            f"https://www.hybrid-analysis.com/api/v2/overview/{sha256}",
            headers={
                "api-key": HYBRID_KEY,
                "User-Agent": "Falcon Sandbox",
            },
            timeout=15,
        )
        if resp.status_code == 404:
            return {"provider": "hybrid_analysis", "status": "not_found", "sha256": sha256}
        if resp.status_code != 200:
            return {"provider": "hybrid_analysis", "status": f"http_{resp.status_code}", "sha256": sha256}

        data = resp.json()
        return {
            "provider": "hybrid_analysis",
            "status": "ok",
            "sha256": sha256,
            "verdict": data.get("verdict", "unknown"),
            "threat_score": data.get("threat_score", 0),
            "tags": data.get("tags", []),
            "mitre": data.get("mitre_attcks", []),
            "network_iocs": [
                {"type": "domain", "value": d}
                for d in data.get("domains", [])
            ] + [
                {"type": "ipv4", "value": ip}
                for ip in data.get("compromised_hosts", [])
            ],
            "classification_tags": data.get("classification_tags", []),
        }
    except Exception as exc:
        log_error("", "sandbox.hybrid_analysis", str(exc),
                  severity="warning", context={"sha256": sha256})
        return {"provider": "hybrid_analysis", "status": "error", "sha256": sha256, "error": str(exc)}


# ---------------------------------------------------------------------------
# Hash collection
# ---------------------------------------------------------------------------

def _collect_hashes(case_id: str) -> list[str]:
    """Collect SHA256 hashes from static analysis artefacts."""
    analysis_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    hashes: set[str] = set()

    if not analysis_dir.exists():
        return []

    for af in analysis_dir.rglob("*.analysis.json"):
        try:
            data = load_json(af)
            sha = data.get("hashes", {}).get("sha256")
            if sha:
                hashes.add(sha)
        except Exception as exc:
            log_error(case_id, "sandbox.collect_hashes", str(exc),
                      severity="warning", context={"file": str(af)})

    return sorted(hashes)


# ---------------------------------------------------------------------------
# Main tool function
# ---------------------------------------------------------------------------

def _hash_has_definitive_sandbox_verdict(sha256: str, results: list[dict]) -> bool:
    """Return True if any sandbox already gave a definitive verdict for this hash."""
    for r in results:
        if r.get("sha256") != sha256 or r.get("status") != "ok":
            continue
        verdict = r.get("verdict", "").lower()
        if verdict in ("malicious", "suspicious", "no threats detected", "clean"):
            return True
    return False


# Provider tiers: Hybrid Analysis is free/fast; Any.Run and Joe Sandbox are premium
SANDBOX_FAST: list = [_hybrid_analysis_lookup]
SANDBOX_DEEP: list = [_anyrun_lookup, _joesandbox_lookup]


def sandbox_analyse(case_id: str, detonate: bool = False) -> dict:
    """
    Tiered sandbox query for known file analyses.

    Tier 1: Hybrid Analysis (free API, fast).
    Tier 2: Any.Run + Joe Sandbox (premium, only if Tier 1 found the hash
            suspicious/malicious or returned no data).

    Collects SHA256 hashes from artefacts/analysis/*.analysis.json.
    """
    hashes = _collect_hashes(case_id)
    if not hashes:
        return {
            "status": "no_hashes",
            "reason": "No SHA256 hashes found in analysis artefacts",
            "case_id": case_id,
            "results": [],
        }

    sandbox_dir = CASES_DIR / case_id / "artefacts" / "sandbox"
    all_results: list[dict] = []
    tiered_stats = {"tier1_only": 0, "escalated_to_deep": 0}

    # --- Tier 1: Hybrid Analysis (free) ---
    fast_tasks = [(fn, sha) for sha in hashes for fn in SANDBOX_FAST]
    print(f"[sandbox] Tier 1: Querying {len(SANDBOX_FAST)} fast provider(s) "
          f"for {len(hashes)} hash(es)...")

    if fast_tasks:
        with ThreadPoolExecutor(max_workers=SANDBOX_WORKERS) as executor:
            futures = {
                executor.submit(fn, sha): (fn.__name__, sha)
                for fn, sha in fast_tasks
            }
            for future in as_completed(futures):
                try:
                    all_results.append(future.result())
                except Exception as exc:
                    name, sha = futures[future]
                    log_error(case_id, f"sandbox.{name}", str(exc),
                              severity="warning", context={"sha256": sha})
                    all_results.append({
                        "provider": name,
                        "status": "error",
                        "sha256": sha,
                        "error": str(exc),
                    })

    # --- Tier 2: Any.Run + Joe Sandbox — only for hashes that need it ---
    escalate_hashes = [
        sha for sha in hashes
        if not _hash_has_definitive_sandbox_verdict(sha, all_results)
        or any(r.get("sha256") == sha and r.get("status") == "ok"
               and r.get("verdict", "").lower() in ("malicious", "suspicious")
               for r in all_results)
    ]
    tier1_only = len(hashes) - len(escalate_hashes)
    tiered_stats["tier1_only"] = tier1_only
    tiered_stats["escalated_to_deep"] = len(escalate_hashes)

    if tier1_only:
        print(f"[sandbox] Tier 1: {tier1_only} hash(es) resolved — skipping deep sandbox.")

    if escalate_hashes:
        deep_tasks = [(fn, sha) for sha in escalate_hashes for fn in SANDBOX_DEEP]
        print(f"[sandbox] Tier 2: Querying {len(SANDBOX_DEEP)} deep provider(s) "
              f"for {len(escalate_hashes)} hash(es)...")
        if deep_tasks:
            with ThreadPoolExecutor(max_workers=SANDBOX_WORKERS) as executor:
                futures = {
                    executor.submit(fn, sha): (fn.__name__, sha)
                    for fn, sha in deep_tasks
                }
                for future in as_completed(futures):
                    try:
                        all_results.append(future.result())
                    except Exception as exc:
                        name, sha = futures[future]
                        log_error(case_id, f"sandbox.{name}", str(exc),
                                  severity="warning", context={"sha256": sha})
                        all_results.append({
                            "provider": name,
                            "status": "error",
                            "sha256": sha,
                            "error": str(exc),
                        })

    print(f"[sandbox] Tiered stats: {tiered_stats['tier1_only']} resolved at Tier 1, "
          f"{tiered_stats['escalated_to_deep']} escalated to deep sandbox")

    # Extract supplementary IOCs from sandbox results
    sandbox_iocs: list[dict] = []
    mitre_ttps: list[str] = []
    c2_beacons: list[dict] = []

    for r in all_results:
        if r.get("status") != "ok":
            continue
        for nioc in r.get("network_iocs", []):
            sandbox_iocs.append(nioc)
        for ttp in r.get("mitre", []):
            if isinstance(ttp, str):
                mitre_ttps.append(ttp)
            elif isinstance(ttp, dict) and ttp.get("id"):
                mitre_ttps.append(ttp["id"])
        for c2 in r.get("c2_beacons", []):
            c2_beacons.append(c2)

    # Deduplicate
    seen_iocs: set[str] = set()
    unique_iocs: list[dict] = []
    for ioc in sandbox_iocs:
        key = f"{ioc['type']}|{ioc['value']}"
        if key not in seen_iocs:
            seen_iocs.add(key)
            unique_iocs.append(ioc)

    mitre_ttps = sorted(set(mitre_ttps))

    # Group results by hash
    per_hash: dict[str, list[dict]] = {}
    for r in all_results:
        sha = r.get("sha256", "unknown")
        per_hash.setdefault(sha, []).append(r)

    result = {
        "status": "ok",
        "case_id": case_id,
        "hashes_checked": len(hashes),
        "total_lookups": len(all_results),
        "ok_results": sum(1 for r in all_results if r.get("status") == "ok"),
        "tiered_stats": tiered_stats,
        "per_hash": per_hash,
        "sandbox_iocs": unique_iocs,
        "mitre_ttps": mitre_ttps,
        "c2_beacons": c2_beacons,
        "ts": utcnow(),
    }

    save_json(sandbox_dir / "sandbox_results.json", result)

    # Save supplementary IOCs for pickup by extract_iocs
    if unique_iocs:
        save_json(sandbox_dir / "sandbox_iocs.json", {
            "source": "sandbox_analysis",
            "iocs": unique_iocs,
            "ts": utcnow(),
        })

    # Print summary
    ok_count = sum(1 for r in all_results if r.get("status") == "ok")
    provider_count = len(SANDBOX_FAST) + len(SANDBOX_DEEP)
    print(f"[sandbox_analyse] Checked {len(hashes)} hash(es) across {provider_count} provider(s)")
    print(f"  Results: {ok_count} found, {len(all_results) - ok_count} not found / error")
    if unique_iocs:
        print(f"  Supplementary IOCs: {len(unique_iocs)}")
    if mitre_ttps:
        print(f"  MITRE TTPs: {', '.join(mitre_ttps[:10])}")

    return result


if __name__ == "__main__":
    import argparse
    import json

    p = argparse.ArgumentParser(description="Query sandbox APIs for file analysis results.")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--detonate", action="store_true", help="Submit for live detonation (not yet implemented — parameter accepted but ignored)")
    args = p.parse_args()

    result = sandbox_analyse(args.case_id, detonate=args.detonate)
    print(json.dumps(result, indent=2))
