"""Tiered file analysis — single entry point that replaces the per-format
``analyse_pe`` / ``analyse_office`` / ``analyse_pdf`` / etc. MCP tools.

Tiers (mirrors the IOC enrichment depth model):

* **Tier 1 — Triage** (always): magic-byte file type detection, sha256/md5,
  size, entropy, strings sample, heuristic flags, plus a hash reputation
  lookup against the IOC cache.
* **Tier 2 — Static inspection** (auto-escalated, forced by ``full``):
  format-specific deep parse via the existing specialist analysers
  (PE / Office / PDF / LNK / OneNote / MSI / Mach-O / disk image).
* **Tier 3 — Deep analysis** (auto-escalated on strong signal, forced by
  ``full``): YARA scan + sandbox recommendation.

``depth`` controls the policy:
    ``"fast"`` — Tier 1 only.
    ``"auto"`` — Tier 1; Tier 2 if signal warrants; Tier 3 only on strong signal.
    ``"full"`` — All tiers regardless of signal.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.common import eprint, log_error
from tools.static_file_analyse import dispatch_specialist, static_file_analyse


# File types that have a registered specialist analyser. Tier 2 will only
# fire when the detected type maps onto one of these — the rest get a
# Tier 1-only result.
_SPECIALIST_FILE_TYPES: set[str] = {
    "PDF document",
    "Windows shell link (.lnk)",
    "OneNote section (.one)",
    "OneNote table of contents",
    "MSI installer",
    "Mach-O executable",
    "Mach-O universal binary",
    "ISO 9660 disk image",
    "Raw disk image (.img)",
    "VHD disk image",
    "VHDX disk image",
    "PE/DOS executable",
}


def _is_office_type(file_type: str) -> bool:
    return file_type.startswith("Office OOXML") or file_type.startswith("Office legacy")


def _hash_reputation(sha256: str) -> dict[str, Any]:
    """Cheap reputation check against cached IOC verdicts.

    Uses ``quick_enrich`` in ``fast`` depth so the lookup hits the cache and
    a handful of free providers — no deep OSINT escalation.
    """
    if not sha256:
        return {"status": "skipped", "reason": "no sha256"}
    try:
        from tools.enrich import quick_enrich
        result = quick_enrich([sha256], depth="fast")
        # quick_enrich returns a dict with a per-IOC verdict map; surface
        # just the one we asked for to keep the response compact.
        verdicts = result.get("verdicts", {}) if isinstance(result, dict) else {}
        v = verdicts.get(sha256, {})
        return {
            "sha256": sha256,
            "verdict": v.get("verdict", "unknown"),
            "confidence": v.get("confidence"),
            "providers_checked": v.get("providers_checked", 0),
            "provider_verdicts": v.get("provider_verdicts", {}),
            "enrichment_id": result.get("enrichment_id", "") if isinstance(result, dict) else "",
        }
    except Exception as exc:
        log_error("", "file_analyse.hash_reputation", str(exc),
                  severity="warning", context={"sha256": sha256})
        return {"status": "error", "reason": str(exc)}


def _tier2_should_run(
    depth: str,
    tier1: dict,
    reputation: dict,
) -> tuple[bool, str]:
    """Decide whether to escalate to Tier 2 (format-specific specialist).

    Returns ``(should_run, reason)``. ``reason`` is a short human-readable
    tag included in the result manifest so analysts can see why the tier
    fired (or didn't).
    """
    if depth == "fast":
        return False, "depth=fast"
    if depth == "full":
        return True, "depth=full"

    file_type = tier1.get("file_type", "")
    # Always escalate when the detected type has a dedicated specialist —
    # the marginal cost of static parsing is small compared to the signal
    # uplift on PE imports, Office macros, PDF JS, etc.
    if file_type in _SPECIALIST_FILE_TYPES or _is_office_type(file_type):
        return True, f"specialist available for {file_type!r}"

    # Or escalate on Tier 1 signal even if no specialist matches — strings
    # / entropy / magic alone are enough to warrant a closer look.
    verdict = (reputation or {}).get("verdict", "unknown")
    if verdict in ("malicious", "suspicious"):
        return True, f"reputation={verdict}"
    if verdict == "unknown":
        # No prior knowledge of this hash — worth a closer look.
        if tier1.get("entropy", 0) > 7.2:
            return True, "entropy>7.2 (likely packed)"
        flags = tier1.get("flags", []) or []
        suspicious_flag_prefixes = (
            "STRINGS: PowerShell",
            "STRINGS: cmd.exe",
            "STRINGS: ",  # any URL-bearing string flag
            "HIGH_ENTROPY",
        )
        for f in flags:
            if any(f.startswith(p) for p in suspicious_flag_prefixes):
                return True, f"tier1 flag: {f}"
    return False, "no signal"


def _tier3_should_run(
    depth: str,
    run_yara: str,
    tier1: dict,
    tier2: dict | None,
    reputation: dict,
) -> tuple[bool, str]:
    """Decide whether to escalate to Tier 3 (YARA + sandbox recommendation)."""
    if run_yara == "false":
        return False, "run_yara=false override"
    if run_yara == "true" or depth == "full":
        return True, "run_yara=true / depth=full"
    if depth == "fast":
        return False, "depth=fast"

    # depth=auto, run_yara=auto — escalate only on strong signal
    verdict = (reputation or {}).get("verdict", "unknown")
    if verdict == "malicious":
        return True, "reputation=malicious"

    if tier2:
        # Format-specific signals that justify YARA cost. These must match
        # (lowercased) what the specialists actually append to ``flags`` —
        # invented tokens here meant macro docs / OneNote droppers / MSI
        # payloads never auto-escalated on depth="auto".
        flags = tier2.get("flags", []) or []
        strong_signals = (
            # office_analyse
            "macros:", "autoexec:", "suspicious_keywords:", "dde_links:",
            "external_template:",
            # pdf_analyse (OpenAction JS surfaces under JAVASCRIPT:)
            "javascript:", "launch_action:", "embedded_files:",
            "exploit_vector_keywords:",
            # onenote / msi / disk-image droppers
            "executable_payloads:", "embedded_payloads:", "custom_action:",
            "iso_payloads:",
            # lnk_analyse
            "lolbin_target:", "powershell evasion", "no_target_file:",
            "icon_spoofing:",
            # macho_analyse
            "dylibs_network_or_infostealer:", "encrypted_segments:",
        )
        for f in flags:
            lf = str(f).lower()
            if any(s in lf for s in strong_signals):
                return True, f"tier2 flag: {f}"
        # PE with packing / writable-executable sections
        if tier2.get("any_packed") or tier2.get("any_writable_executable_sections"):
            return True, "PE packed / writable-executable section"

    # Fallback: very high entropy + executable
    file_type = tier1.get("file_type", "")
    if tier1.get("entropy", 0) > 7.4 and "executable" in file_type.lower():
        return True, "entropy>7.4 + executable"
    return False, "no strong signal"


def _run_yara(case_id: str) -> dict:
    """Invoke the case-scoped YARA scan action."""
    try:
        from api import actions
        return actions.yara_scan_action(case_id, generate_rules=False)
    except Exception as exc:
        log_error(case_id, "file_analyse.yara", str(exc), severity="warning")
        return {"status": "error", "reason": str(exc)}


def file_analyse(
    file_path: str | Path,
    case_id: str,
    depth: str = "auto",
    run_yara: str = "auto",
) -> dict:
    """Unified tiered file analysis — see module docstring for tier model."""
    depth = (depth or "auto").lower().strip()
    if depth not in ("auto", "fast", "full"):
        depth = "auto"
    run_yara = (run_yara or "auto").lower().strip()
    if run_yara not in ("auto", "true", "false"):
        run_yara = "auto"

    fp = Path(file_path)
    if not fp.exists():
        return {
            "status": "error",
            "reason": f"file not found: {fp}",
            "file_path": str(fp),
            "case_id": case_id,
        }

    # ---- Tier 1 (always) ----------------------------------------------------
    tier1 = static_file_analyse(fp, case_id, dispatch_specialist=False)
    sha256 = (tier1.get("hashes") or {}).get("sha256", "")
    reputation = _hash_reputation(sha256)

    result: dict[str, Any] = {
        "file_path": str(fp),
        "case_id": case_id,
        "depth": depth,
        "tiers_run": ["tier1"],
        "tier1": tier1,
        "hash_reputation": reputation,
        "tier2": None,
        "tier2_skipped_reason": None,
        "tier3": None,
        "tier3_skipped_reason": None,
    }

    # ---- Tier 2 decision ----------------------------------------------------
    should_t2, t2_reason = _tier2_should_run(depth, tier1, reputation)
    if not should_t2:
        result["tier2_skipped_reason"] = t2_reason
        eprint(f"[file_analyse] {fp.name}: Tier 1 only ({t2_reason})")
        return result

    # ---- Tier 2: specialist dispatch ---------------------------------------
    tier2 = dispatch_specialist(tier1.get("file_type", ""), fp, case_id)
    result["tier2"] = tier2
    result["tiers_run"].append("tier2")
    if tier2 is None:
        result["tier2_skipped_reason"] = "no specialist matched"

    # ---- Tier 3 decision ----------------------------------------------------
    should_t3, t3_reason = _tier3_should_run(depth, run_yara, tier1, tier2, reputation)
    if not should_t3:
        result["tier3_skipped_reason"] = t3_reason
        eprint(f"[file_analyse] {fp.name}: Tier 1+2 ({t3_reason})")
        return result

    # ---- Tier 3: YARA + sandbox hint ---------------------------------------
    yara_result = _run_yara(case_id)
    result["tier3"] = {
        "yara_scan": yara_result,
        "sandbox_recommendation": (
            "Consider sandbox detonation via start_sandbox_session — "
            "strong Tier 2 signal warrants behavioural analysis."
        ),
    }
    result["tiers_run"].append("tier3")
    eprint(f"[file_analyse] {fp.name}: Tier 1+2+3 ({t3_reason})")
    return result
