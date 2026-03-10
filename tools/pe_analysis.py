"""
tool: pe_analysis
-----------------
Deep PE (Portable Executable) analysis for files discovered during
investigation (extracted ZIPs, email attachments).

Requires the optional ``pefile`` library.  When absent the tool logs
an info-level warning and returns a skip manifest.

Analysis per PE file:
  1.  Shannon entropy (per-section + overall)
  2.  Section analysis (W+X, size mismatches, unnamed sections)
  3.  Full import table with suspicious-API flagging
  4.  Export table
  5.  PE header anomalies (timestamp, checksum, subsystem)
  6.  Overlay detection
  7.  Packer signature heuristics
  8.  Rich header hash
  9.  File hashes (MD5, SHA1, SHA256)
  10. Strings extraction (ASCII + Unicode, deduplicated, capped at 500)

Optional LLM step: sends per-file summary to Claude for malware
classification when ANTHROPIC_API_KEY is set.

Output:
  cases/<case_id>/artefacts/analysis/pe_analysis.json

Usage (standalone):
  python3 tools/pe_analysis.py --case IV_CASE_001
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY, CASES_DIR, STRINGS_MIN_LEN
from tools.common import get_model, load_json, log_error, save_json, sha256_file, utcnow

# ---------------------------------------------------------------------------
# Optional dependency
# ---------------------------------------------------------------------------

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

# ---------------------------------------------------------------------------
# PE extensions to scan (case-insensitive)
# ---------------------------------------------------------------------------

_PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".scr"}

# ---------------------------------------------------------------------------
# Suspicious API categories
# ---------------------------------------------------------------------------

_SUSPICIOUS_APIS: dict[str, list[str]] = {
    "process_injection": [
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC",
        "NtCreateThreadEx",
    ],
    "anti_debug": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
    ],
    "process_manipulation": [
        "OpenProcess", "TerminateProcess",
        "CreateProcessA", "CreateProcessW",
    ],
    "keylogging": [
        "SetWindowsHookExA", "SetWindowsHookExW",
        "GetAsyncKeyState", "GetKeyState",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
    ],
    "network": [
        "InternetOpenA", "InternetOpenW",
        "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen",
    ],
    "registry": [
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
    ],
    "file_ops": [
        "DeleteFileA", "DeleteFileW",
        "MoveFileA", "MoveFileW",
    ],
}

# Build a flat lookup: api_name -> category
_API_CATEGORY: dict[str, str] = {}
for _cat, _names in _SUSPICIOUS_APIS.items():
    for _name in _names:
        _API_CATEGORY[_name] = _cat

# ---------------------------------------------------------------------------
# Packer section-name signatures
# ---------------------------------------------------------------------------

_PACKER_SECTIONS: dict[str, str] = {
    "UPX0": "UPX", "UPX1": "UPX",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    ".themida": "Themida",
    ".aspack": "ASPack",
    ".pec": "PECompact",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    freqs = {b: c / n for b, c in freq.items()}
    return -sum(p * math.log2(p) for p in freqs.values() if p > 0)


def _compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _extract_strings(data: bytes, min_len: int) -> list[str]:
    """Extract ASCII + Unicode strings, deduplicated, capped at 500."""
    # ASCII
    ascii_pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    ascii_strings = [m.group().decode("ascii", errors="replace") for m in ascii_pat.finditer(data)]

    # Unicode (UTF-16LE: printable byte + \x00)
    unicode_pat = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    unicode_strings = [
        m.group().decode("utf-16-le", errors="replace")
        for m in unicode_pat.finditer(data)
    ]

    seen: set[str] = set()
    result: list[str] = []
    for s in ascii_strings + unicode_strings:
        if s not in seen:
            seen.add(s)
            result.append(s)
            if len(result) >= 500:
                break
    return result


def _find_pe_files(case_id: str) -> list[Path]:
    """Locate PE files under artefacts/zip/ and artefacts/email/attachments/."""
    case_dir = CASES_DIR / case_id
    search_dirs = [
        case_dir / "artefacts" / "zip",
        case_dir / "artefacts" / "email" / "attachments",
    ]
    pe_files: list[Path] = []
    for d in search_dirs:
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            if f.is_file() and f.suffix.lower() in _PE_EXTENSIONS:
                pe_files.append(f)
    return pe_files


# ---------------------------------------------------------------------------
# Per-file PE analysis
# ---------------------------------------------------------------------------


def _analyse_pe(filepath: Path, case_id: str) -> dict:
    """Run deep PE analysis on a single file.  Returns a result dict."""
    raw = filepath.read_bytes()
    result: dict = {
        "file": str(filepath),
        "filename": filepath.name,
        "file_size": len(raw),
        "hashes": _compute_hashes(raw),
        "overall_entropy": round(_entropy(raw), 4),
    }

    try:
        pe = pefile.PE(data=raw)
    except pefile.PEFormatError as exc:
        result["pe_parse_error"] = str(exc)
        result["strings"] = _extract_strings(raw, STRINGS_MIN_LEN)
        return result
    except Exception as exc:
        log_error(case_id, "pe_analysis", f"pefile parse failed for {filepath.name}: {exc}",
                  severity="warning")
        result["pe_parse_error"] = str(exc)
        result["strings"] = _extract_strings(raw, STRINGS_MIN_LEN)
        return result

    # -- Sections ----------------------------------------------------------
    sections: list[dict] = []
    packer_hits: list[str] = []
    try:
        for sec in pe.sections:
            try:
                sec_name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            except AttributeError:
                sec_name = "<unknown>"

            sec_data = sec.get_data()
            sec_entropy = round(_entropy(sec_data), 4)

            characteristics = getattr(sec, "Characteristics", 0)
            is_wx = bool(
                (characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"])
                and (characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"])
            )

            virtual_size = getattr(sec, "Misc_VirtualSize", 0)
            raw_size = getattr(sec, "SizeOfRawData", 0)
            size_mismatch = (
                raw_size > 0
                and virtual_size > 0
                and (abs(virtual_size - raw_size) / max(virtual_size, raw_size)) > 0.5
            )

            sec_info: dict = {
                "name": sec_name,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "entropy": sec_entropy,
                "high_entropy": sec_entropy > 7.0,
                "characteristics": hex(characteristics),
                "writable_executable": is_wx,
                "unnamed": sec_name.strip() == "" or sec_name == "<unknown>",
                "size_mismatch": size_mismatch,
            }
            sections.append(sec_info)

            # Packer check
            upper = sec_name.strip().upper()
            for sig_name, packer in _PACKER_SECTIONS.items():
                if upper == sig_name.upper():
                    packer_hits.append(packer)
    except AttributeError:
        pass

    result["sections"] = sections
    result["packer_signatures"] = list(set(packer_hits)) if packer_hits else []

    # -- Imports -----------------------------------------------------------
    imports: list[dict] = []
    flagged_apis: list[dict] = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll_name = entry.dll.decode("utf-8", errors="replace")
                except AttributeError:
                    dll_name = "<unknown>"

                functions: list[str] = []
                for imp in entry.imports:
                    try:
                        func_name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    except AttributeError:
                        func_name = f"ord_{getattr(imp, 'ordinal', '?')}"

                    functions.append(func_name)

                    if func_name in _API_CATEGORY:
                        flagged_apis.append({
                            "dll": dll_name,
                            "function": func_name,
                            "category": _API_CATEGORY[func_name],
                        })

                imports.append({"dll": dll_name, "functions": functions})
    except AttributeError:
        pass

    result["imports"] = imports
    result["flagged_apis"] = flagged_apis

    # -- Exports -----------------------------------------------------------
    exports: list[dict] = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    exp_name = exp.name.decode("utf-8", errors="replace") if exp.name else None
                except AttributeError:
                    exp_name = None
                exports.append({
                    "name": exp_name,
                    "ordinal": getattr(exp, "ordinal", None),
                    "mangled": bool(exp_name and ("?" in exp_name or "@" in exp_name)),
                })
    except AttributeError:
        pass

    result["exports"] = exports
    result["sparse_exports"] = len(exports) > 0 and sum(1 for e in exports if e["name"] is None) > len(exports) * 0.5

    # -- Header anomalies --------------------------------------------------
    anomalies: list[str] = []
    try:
        timestamp = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
        result["pe_timestamp"] = timestamp
        if timestamp == 0:
            anomalies.append("epoch_zero_timestamp")
        elif timestamp > time.time():
            anomalies.append("future_timestamp")
    except AttributeError:
        pass

    try:
        declared_checksum = getattr(pe.OPTIONAL_HEADER, "CheckSum", 0)
        computed_checksum = pe.generate_checksum()
        result["checksum_declared"] = declared_checksum
        result["checksum_computed"] = computed_checksum
        if declared_checksum != 0 and declared_checksum != computed_checksum:
            anomalies.append("checksum_mismatch")
    except (AttributeError, Exception):
        pass

    try:
        subsystem = getattr(pe.OPTIONAL_HEADER, "Subsystem", None)
        result["subsystem"] = subsystem
        # IMAGE_SUBSYSTEM_UNKNOWN = 0
        if subsystem is not None and subsystem not in (1, 2, 3, 5, 7, 9, 10):
            # 1=NATIVE, 2=WINDOWS_GUI, 3=WINDOWS_CUI, 5=OS2_CUI, 7=POSIX_CUI,
            # 9=WINDOWS_CE_GUI, 10=EFI_APPLICATION
            anomalies.append(f"unusual_subsystem_{subsystem}")
    except AttributeError:
        pass

    result["anomalies"] = anomalies

    # -- Overlay -----------------------------------------------------------
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            overlay_size = len(raw) - overlay_offset
            result["overlay"] = {
                "offset": overlay_offset,
                "size": overlay_size,
                "entropy": round(_entropy(raw[overlay_offset:]), 4),
            }
        else:
            result["overlay"] = None
    except (AttributeError, Exception):
        result["overlay"] = None

    # -- Rich header -------------------------------------------------------
    try:
        if pe.RICH_HEADER and pe.RICH_HEADER.raw_data:
            result["rich_header_md5"] = hashlib.md5(pe.RICH_HEADER.raw_data).hexdigest()
        else:
            result["rich_header_md5"] = None
    except AttributeError:
        result["rich_header_md5"] = None

    # -- Strings -----------------------------------------------------------
    result["strings"] = _extract_strings(raw, STRINGS_MIN_LEN)

    pe.close()
    return result


# ---------------------------------------------------------------------------
# LLM assessment (optional)
# ---------------------------------------------------------------------------

_LLM_SYSTEM_PROMPT = """\
You are an expert malware reverse-engineer and threat analyst.  You are given \
the output of automated PE (Portable Executable) static analysis for a single \
binary.  Based on the section layout, import table, flagged APIs, header \
anomalies, packer signatures, entropy profile, and strings, provide a \
structured malware assessment.

Focus on:
- Whether the combination of imported APIs suggests malicious capability
- Entropy and packing indicators that suggest obfuscation
- Header anomalies that indicate tampering or non-standard compilation
- Strings that reveal C2 infrastructure, credentials, or tool artefacts
- Overall likelihood this is a legitimate binary vs malware

Be precise and evidence-based.  Cite specific imports, sections, or strings \
that support your assessment."""

def _llm_assess(file_result: dict, case_id: str) -> dict | None:
    """Send per-file analysis to Claude for malware classification."""
    if not ANTHROPIC_KEY:
        return None

    # Prepare a summary dict (exclude raw strings list to stay within token limits)
    summary = {k: v for k, v in file_result.items() if k != "strings"}
    summary["strings_sample"] = file_result.get("strings", [])[:50]
    summary_text = json.dumps(summary, indent=2, default=str)

    try:
        from tools.structured_llm import structured_call
        from tools.schemas import PeAssessment

        try:
            _meta = load_json(CASES_DIR / case_id / "case_meta.json")
        except Exception:
            _meta = {}
        _severity = _meta.get("severity", "medium")

        result, _usage = structured_call(
            model=get_model("pe_analysis", _severity),
            system=[
                {
                    "type": "text",
                    "text": _LLM_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                },
            ],
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Analyse this PE file and provide your structured "
                        f"assessment.\n\n```json\n{summary_text}\n```"
                    ),
                },
            ],
            output_schema=PeAssessment,
            max_tokens=2048,
        )

        return result.model_dump() if result else None

    except Exception as exc:
        log_error(case_id, "pe_analysis_llm", f"LLM assessment failed: {exc}",
                  severity="warning")
        return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def pe_deep_analyse(case_id: str) -> dict:
    """Run deep PE analysis on all PE files in a case.

    Returns a manifest dict with ``files`` (list of per-file results)
    and metadata.
    """
    if not HAS_PEFILE:
        log_error(case_id, "pe_analysis", "pefile not installed", severity="info")
        return {"status": "skipped", "reason": "pefile not installed"}

    pe_files = _find_pe_files(case_id)
    if not pe_files:
        return {
            "status": "no_pe_files",
            "searched": ["artefacts/zip/", "artefacts/email/attachments/"],
            "timestamp": utcnow(),
        }

    file_results: list[dict] = []
    for fp in pe_files:
        try:
            analysis = _analyse_pe(fp, case_id)
        except Exception as exc:
            log_error(case_id, "pe_analysis", f"Failed to analyse {fp.name}: {exc}",
                      severity="error")
            analysis = {
                "file": str(fp),
                "filename": fp.name,
                "error": str(exc),
            }

        # LLM assessment (per file)
        llm_result = _llm_assess(analysis, case_id)
        if llm_result:
            analysis["llm_assessment"] = llm_result

        file_results.append(analysis)

    # -- Summary stats -----------------------------------------------------
    total_flagged = sum(len(r.get("flagged_apis", [])) for r in file_results)
    any_packed = any(bool(r.get("packer_signatures")) for r in file_results)
    any_high_entropy = any(
        any(s.get("high_entropy") for s in r.get("sections", []))
        for r in file_results
    )
    any_wx = any(
        any(s.get("writable_executable") for s in r.get("sections", []))
        for r in file_results
    )

    manifest: dict = {
        "status": "ok",
        "timestamp": utcnow(),
        "case_id": case_id,
        "files_analysed": len(file_results),
        "total_flagged_apis": total_flagged,
        "any_packed": any_packed,
        "any_high_entropy_sections": any_high_entropy,
        "any_writable_executable_sections": any_wx,
        "llm_assessed": any("llm_assessment" in r for r in file_results),
        "files": file_results,
    }

    # Write output
    out_path = CASES_DIR / case_id / "artefacts" / "analysis" / "pe_analysis.json"
    save_json(out_path, manifest)

    print(f"[pe_analysis] Analysed {len(file_results)} PE file(s) for {case_id}")
    if total_flagged:
        print(f"  Flagged APIs: {total_flagged}")
    if any_packed:
        print("  Packer signatures detected")
    if any_wx:
        print("  W+X sections detected")

    return manifest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Deep PE analysis")
    parser.add_argument("--case", required=True, help="Case ID")
    args = parser.parse_args()

    result = pe_deep_analyse(args.case)
    print(json.dumps(result, indent=2, default=str))
