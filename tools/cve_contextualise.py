"""
tool: cve_contextualise
-----------------------
CVE contextualisation tool for completed investigations.

Scans case artefacts for CVE identifiers, fetches context from NVD, EPSS,
CISA KEV, and OpenCTI, computes a priority score, and optionally runs an
LLM assessment of exploitation likelihood and patching priority.

Output:
  cases/<case_id>/artefacts/cve/cve_context.json

Usage (standalone):
  python3 tools/cve_contextualise.py --case C001
"""
from __future__ import annotations

import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests as _requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR, OPENCTI_KEY, OPENCTI_URL
from tools.common import get_model, load_json, log_error, save_json, utcnow

# ---------------------------------------------------------------------------
# CVE regex
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# CISA KEV cache
_KEV_CACHE_PATH = Path(__file__).resolve().parent.parent / "registry" / "cisa_kev_cache.json"
_KEV_CACHE_TTL_HOURS = 24


# ---------------------------------------------------------------------------
# CVE extraction helpers
# ---------------------------------------------------------------------------

def _extract_cves_from_file(path: Path) -> set[str]:
    """Read a file and return all CVE identifiers found via regex."""
    if not path.exists():
        return set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        return set(_CVE_RE.findall(text))
    except Exception:
        return set()


def _extract_cves_from_json_values(path: Path) -> set[str]:
    """Recursively scan all string values in a JSON file for CVE identifiers."""
    if not path.exists():
        return set()
    try:
        data = load_json(path)
    except Exception:
        return set()

    cves: set[str] = set()

    def _walk(obj):
        if isinstance(obj, str):
            cves.update(_CVE_RE.findall(obj))
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    _walk(data)
    return cves


def _collect_cves(case_id: str) -> dict[str, list[str]]:
    """Collect CVEs from all case artefact sources.

    Returns dict mapping CVE ID -> list of source filenames.
    """
    case_dir = CASES_DIR / case_id
    cve_sources: dict[str, list[str]] = {}

    # Source files to scan (path, method, display name)
    scan_targets: list[tuple[Path, str, str]] = [
        (case_dir / "iocs" / "iocs.json", "json", "iocs.json"),
        (case_dir / "artefacts" / "enrichment" / "enrichment.json", "json", "enrichment.json"),
        (case_dir / "artefacts" / "security_architecture" / "security_arch_review.md", "text", "security_arch_review.md"),
        (case_dir / "artefacts" / "sandbox" / "sandbox_results.json", "json", "sandbox_results.json"),
    ]

    # Add all markdown files under reports/
    reports_dir = case_dir / "reports"
    if reports_dir.exists():
        for md_file in reports_dir.glob("*.md"):
            scan_targets.append((md_file, "text", md_file.name))

    for path, method, display_name in scan_targets:
        try:
            if method == "json":
                cves = _extract_cves_from_json_values(path)
            else:
                cves = _extract_cves_from_file(path)

            for cve in cves:
                cve_sources.setdefault(cve, [])
                if display_name not in cve_sources[cve]:
                    cve_sources[cve].append(display_name)
        except Exception as exc:
            log_error(case_id, "cve_contextualise.collect", str(exc),
                      severity="warning", context={"file": str(path)})

    return cve_sources


# ---------------------------------------------------------------------------
# Data source: NVD API v2.0
# ---------------------------------------------------------------------------

def _nvd_lookup(cve_id: str, case_id: str) -> dict:
    """Fetch CVE data from NVD API v2.0."""
    try:
        time.sleep(6)  # Rate limiting: 5 requests per 30 seconds without API key
        resp = _requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=30,
        )
        if resp.status_code != 200:
            return {"source": "nvd", "status": f"http_{resp.status_code}", "cve_id": cve_id}

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"source": "nvd", "status": "not_found", "cve_id": cve_id}

        cve_data = vulns[0].get("cve", {})

        # Description (English)
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS v3.1
        cvss_score = None
        cvss_vector = None
        cvss_severity = None
        metrics = cve_data.get("metrics", {})
        for cvss_key in ("cvssMetricV31", "cvssMetricV30"):
            cvss_list = metrics.get(cvss_key, [])
            if cvss_list:
                cvss_data = cvss_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                cvss_severity = cvss_data.get("baseSeverity")
                break

        # CWE IDs
        cwes: list[str] = []
        for weakness in cve_data.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)

        # CPE matches
        cpe_matches: list[str] = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        cpe_matches.append(criteria)

        return {
            "source": "nvd",
            "status": "ok",
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_severity": cvss_severity,
            "cwes": cwes,
            "cpe_matches": cpe_matches[:20],  # Cap to avoid bloat
        }

    except Exception as exc:
        log_error(case_id, "cve_contextualise.nvd", str(exc),
                  severity="warning", context={"cve_id": cve_id})
        return {"source": "nvd", "status": "error", "cve_id": cve_id, "error": str(exc)}


# ---------------------------------------------------------------------------
# Data source: EPSS API
# ---------------------------------------------------------------------------

def _epss_lookup(cve_id: str, case_id: str) -> dict:
    """Fetch EPSS score from FIRST API."""
    try:
        resp = _requests.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_id},
            timeout=15,
        )
        if resp.status_code != 200:
            return {"source": "epss", "status": f"http_{resp.status_code}", "cve_id": cve_id}

        data = resp.json()
        entries = data.get("data", [])
        if not entries:
            return {"source": "epss", "status": "not_found", "cve_id": cve_id}

        entry = entries[0]
        return {
            "source": "epss",
            "status": "ok",
            "cve_id": cve_id,
            "score": float(entry.get("epss", 0)),
            "percentile": float(entry.get("percentile", 0)),
        }

    except Exception as exc:
        log_error(case_id, "cve_contextualise.epss", str(exc),
                  severity="warning", context={"cve_id": cve_id})
        return {"source": "epss", "status": "error", "cve_id": cve_id, "error": str(exc)}


# ---------------------------------------------------------------------------
# Data source: CISA KEV (cached)
# ---------------------------------------------------------------------------

def _load_kev_catalog(case_id: str) -> list[dict]:
    """Load CISA KEV catalog, refreshing cache if stale or missing."""
    # Check cache
    if _KEV_CACHE_PATH.exists():
        try:
            cached = load_json(_KEV_CACHE_PATH)
            cached_ts = cached.get("_cached_ts", "")
            if cached_ts:
                from datetime import datetime, timezone
                age_hours = (datetime.now(timezone.utc) - datetime.fromisoformat(cached_ts)).total_seconds() / 3600
                if age_hours < _KEV_CACHE_TTL_HOURS:
                    return cached.get("vulnerabilities", [])
        except Exception:
            pass  # Cache corrupt, re-fetch

    # Fetch fresh catalog
    try:
        resp = _requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json",
            timeout=30,
        )
        if resp.status_code != 200:
            log_error(case_id, "cve_contextualise.kev_fetch", f"HTTP {resp.status_code}",
                      severity="warning")
            return []

        catalog = resp.json()
        catalog["_cached_ts"] = utcnow()

        # Write cache (not a case artefact, so use Path.write_text directly)
        _KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _KEV_CACHE_PATH.write_text(json.dumps(catalog), encoding="utf-8")

        return catalog.get("vulnerabilities", [])

    except Exception as exc:
        log_error(case_id, "cve_contextualise.kev_fetch", str(exc), severity="warning")
        return []


def _kev_lookup(cve_id: str, kev_vulns: list[dict]) -> dict | None:
    """Look up a CVE in the pre-loaded KEV catalog."""
    for vuln in kev_vulns:
        if vuln.get("cveID") == cve_id:
            return {
                "source": "cisa_kev",
                "status": "ok",
                "cve_id": cve_id,
                "vendor_project": vuln.get("vendorProject"),
                "product": vuln.get("product"),
                "date_added": vuln.get("dateAdded"),
                "due_date": vuln.get("dueDate"),
                "known_ransomware_campaign_use": vuln.get("knownRansomwareCampaignUse"),
                "required_action": vuln.get("requiredAction"),
            }
    return None


# ---------------------------------------------------------------------------
# Data source: OpenCTI (optional)
# ---------------------------------------------------------------------------

def _opencti_lookup(cve_id: str, case_id: str) -> dict | None:
    """Query OpenCTI GraphQL for vulnerability data."""
    if not OPENCTI_KEY:
        return None

    query = """
    query($search: String) {
        vulnerabilities(search: $search, first: 1) {
            edges {
                node {
                    name
                    description
                    x_opencti_base_score
                    x_opencti_epss_score
                    x_opencti_epss_percentile
                    x_opencti_cisa_kev
                }
            }
        }
    }
    """

    try:
        resp = _requests.post(
            f"{OPENCTI_URL}/graphql",
            headers={
                "Authorization": f"Bearer {OPENCTI_KEY}",
                "Content-Type": "application/json",
            },
            json={"query": query, "variables": {"search": cve_id}},
            timeout=15,
        )
        if resp.status_code != 200:
            return {"source": "opencti", "status": f"http_{resp.status_code}", "cve_id": cve_id}

        data = resp.json()
        edges = data.get("data", {}).get("vulnerabilities", {}).get("edges", [])
        if not edges:
            return {"source": "opencti", "status": "not_found", "cve_id": cve_id}

        node = edges[0].get("node", {})
        return {
            "source": "opencti",
            "status": "ok",
            "cve_id": cve_id,
            "name": node.get("name"),
            "description": node.get("description"),
            "base_score": node.get("x_opencti_base_score"),
            "epss_score": node.get("x_opencti_epss_score"),
            "epss_percentile": node.get("x_opencti_epss_percentile"),
            "cisa_kev": node.get("x_opencti_cisa_kev"),
        }

    except Exception as exc:
        log_error(case_id, "cve_contextualise.opencti", str(exc),
                  severity="warning", context={"cve_id": cve_id})
        return {"source": "opencti", "status": "error", "cve_id": cve_id, "error": str(exc)}


# ---------------------------------------------------------------------------
# Priority score computation
# ---------------------------------------------------------------------------

def _compute_priority(nvd: dict, epss: dict, kev: dict | None) -> float:
    """Compute priority score: CVSS * 0.4 + EPSS_percentile * 0.3 + (0.3 if KEV else 0)."""
    cvss = nvd.get("cvss_score") or 0.0
    epss_pct = epss.get("percentile") or 0.0

    score = (cvss / 10.0) * 0.4 + epss_pct * 0.3 + (0.3 if kev else 0.0)
    return round(score, 4)


# ---------------------------------------------------------------------------
# Per-CVE data collection (parallel across sources)
# ---------------------------------------------------------------------------

def _enrich_single_cve(cve_id: str, sources: list[str], kev_vulns: list[dict], case_id: str) -> dict:
    """Fetch NVD, EPSS, KEV, and OpenCTI data for a single CVE in parallel."""
    nvd_result: dict = {}
    epss_result: dict = {}
    opencti_result: dict | None = None

    def _fetch_nvd():
        return _nvd_lookup(cve_id, case_id)

    def _fetch_epss():
        return _epss_lookup(cve_id, case_id)

    def _fetch_opencti():
        return _opencti_lookup(cve_id, case_id)

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_fetch_nvd): "nvd",
            executor.submit(_fetch_epss): "epss",
            executor.submit(_fetch_opencti): "opencti",
        }
        for future in as_completed(futures):
            source_name = futures[future]
            try:
                result = future.result()
                if source_name == "nvd":
                    nvd_result = result
                elif source_name == "epss":
                    epss_result = result
                elif source_name == "opencti":
                    opencti_result = result
            except Exception as exc:
                log_error(case_id, f"cve_contextualise.{source_name}", str(exc),
                          severity="warning", context={"cve_id": cve_id})

    # KEV lookup (already loaded, no network call)
    kev_result = _kev_lookup(cve_id, kev_vulns)

    priority = _compute_priority(nvd_result, epss_result, kev_result)

    return {
        "cve_id": cve_id,
        "sources_found_in": sources,
        "nvd": nvd_result,
        "epss": epss_result,
        "cisa_kev": kev_result,
        "opencti": opencti_result,
        "priority_score": priority,
    }


# ---------------------------------------------------------------------------
# LLM assessment (optional)
# ---------------------------------------------------------------------------

_LLM_SYSTEM_PROMPT = """\
You are a vulnerability analyst working within an active SOC investigation. \
Assess the provided CVEs in the context of the investigation artefacts. \
Focus on exploitation likelihood, relevance to observed TTPs, patching \
priority, and detection opportunities. Be precise and evidence-based."""

def _llm_assessment(cve_data: list[dict], case_id: str) -> dict | None:
    """Run LLM assessment of CVEs in case context."""
    if not ANTHROPIC_KEY:
        return None

    try:
        from tools.structured_llm import structured_call
        from tools.schemas import CveAssessment

        # Build user message with CVE context
        user_parts: list[str] = [f"## Case: {case_id}\n"]
        user_parts.append(f"Total CVEs found: {len(cve_data)}\n")

        for cve in cve_data:
            user_parts.append(f"### {cve['cve_id']}")
            user_parts.append(f"Found in: {', '.join(cve['sources_found_in'])}")
            user_parts.append(f"Priority score: {cve['priority_score']}")

            nvd = cve.get("nvd", {})
            if nvd.get("status") == "ok":
                user_parts.append(f"NVD description: {nvd.get('description', 'N/A')}")
                user_parts.append(f"CVSS: {nvd.get('cvss_score', 'N/A')} ({nvd.get('cvss_severity', 'N/A')})")
                user_parts.append(f"CWEs: {', '.join(nvd.get('cwes', []))}")

            epss = cve.get("epss", {})
            if epss.get("status") == "ok":
                user_parts.append(f"EPSS score: {epss.get('score', 'N/A')} (percentile: {epss.get('percentile', 'N/A')})")

            kev = cve.get("cisa_kev")
            if kev:
                user_parts.append(f"CISA KEV: YES — {kev.get('vendor_project', '')} {kev.get('product', '')}")
                user_parts.append(f"  Ransomware use: {kev.get('known_ransomware_campaign_use', 'N/A')}")
                user_parts.append(f"  Required action: {kev.get('required_action', 'N/A')}")
            else:
                user_parts.append("CISA KEV: Not listed")

            user_parts.append("")

        user_message = "\n".join(user_parts)

        try:
            _meta = load_json(CASES_DIR / case_id / "case_meta.json")
        except Exception:
            _meta = {}

        result, _usage = structured_call(
            model=get_model("cve", _meta.get("severity", "medium")),
            system=[
                {"type": "text", "text": _LLM_SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}},
            ],
            messages=[{"role": "user", "content": user_message}],
            output_schema=CveAssessment,
            max_tokens=4096,
        )

        return result.model_dump() if result else None

    except Exception as exc:
        log_error(case_id, "cve_contextualise.llm", str(exc), severity="warning")
        return None


# ---------------------------------------------------------------------------
# Main tool function
# ---------------------------------------------------------------------------

def cve_contextualise(case_id: str) -> dict:
    """
    Contextualise CVEs found in case artefacts.

    Scans case files for CVE identifiers, fetches data from NVD, EPSS,
    CISA KEV, and OpenCTI, computes priority scores, and optionally
    runs an LLM assessment.
    """
    # Step 1: Collect CVEs from case artefacts
    cve_sources = _collect_cves(case_id)

    if not cve_sources:
        result = {"status": "no_cves", "reason": "No CVE identifiers found in case artefacts"}
        print("[cve_contextualise] No CVEs found in case artefacts")
        return result

    cve_ids = sorted(cve_sources.keys())
    print(f"[cve_contextualise] Found {len(cve_ids)} unique CVE(s): {', '.join(cve_ids[:10])}")

    # Step 2: Load CISA KEV catalog (cached)
    kev_vulns = _load_kev_catalog(case_id)

    # Step 3: Enrich each CVE (NVD rate-limited, so process sequentially for NVD
    # but parallel across EPSS/OpenCTI/KEV within each CVE)
    cve_results: list[dict] = []
    for cve_id in cve_ids:
        try:
            enriched = _enrich_single_cve(cve_id, cve_sources[cve_id], kev_vulns, case_id)
            cve_results.append(enriched)
        except Exception as exc:
            log_error(case_id, "cve_contextualise.enrich", str(exc),
                      severity="error", context={"cve_id": cve_id})
            cve_results.append({
                "cve_id": cve_id,
                "sources_found_in": cve_sources[cve_id],
                "nvd": {"source": "nvd", "status": "error"},
                "epss": {"source": "epss", "status": "error"},
                "cisa_kev": None,
                "opencti": None,
                "priority_score": 0.0,
            })

    # Step 4: LLM assessment (optional)
    llm_assessment = _llm_assessment(cve_results, case_id)

    # Step 5: Compute summary stats
    cves_in_kev = sum(1 for c in cve_results if c.get("cisa_kev") is not None)
    cvss_scores = [
        c["nvd"]["cvss_score"]
        for c in cve_results
        if c.get("nvd", {}).get("cvss_score") is not None
    ]
    highest_cvss = max(cvss_scores) if cvss_scores else 0.0

    # Sort by priority score descending
    cve_results.sort(key=lambda c: c.get("priority_score", 0), reverse=True)

    output = {
        "status": "ok",
        "case_id": case_id,
        "ts": utcnow(),
        "total_cves": len(cve_results),
        "cves_in_kev": cves_in_kev,
        "highest_cvss": highest_cvss,
        "cves": cve_results,
        "llm_assessment": llm_assessment,
    }

    # Write output
    out_path = CASES_DIR / case_id / "artefacts" / "cve" / "cve_context.json"
    save_json(out_path, output)

    # Print summary
    print(f"[cve_contextualise] Enriched {len(cve_results)} CVE(s)")
    print(f"  CISA KEV hits: {cves_in_kev}")
    print(f"  Highest CVSS: {highest_cvss}")
    if llm_assessment:
        print(f"  LLM assessment: included")
    else:
        print(f"  LLM assessment: skipped (no API key or no CVEs)")
    print(f"  Output: {out_path}")

    return output


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="CVE contextualisation for case artefacts.")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = cve_contextualise(args.case_id)
    print(json.dumps(result, indent=2))
