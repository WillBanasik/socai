"""
tool: static_file_analyse
--------------------------
Performs static analysis on a single file:
  - File type detection (magic bytes / python-magic)
  - SHA-256, SHA-1, MD5
  - File size, entropy
  - Embedded strings
  - PE header metadata if applicable (via pefile, optional)
  - Basic YARA scan (optional)

Writes:
  cases/<case_id>/artefacts/analysis/<filename>.analysis.json
"""
from __future__ import annotations

import hashlib
import json
import math
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, STRINGS_MIN_LEN
from tools.common import log_error, utcnow, write_artefact

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _detect_type(data: bytes, filename: str) -> str:
    """Simple magic-byte detection without python-magic dependency."""
    sigs = {
        b"MZ":       "PE/DOS executable",
        b"\x7fELF":  "ELF executable",
        b"PK\x03\x04": "ZIP archive",
        b"\x1f\x8b": "GZip archive",
        b"BZh":      "BZip2 archive",
        b"%PDF":     "PDF document",
        b"\xff\xd8\xff": "JPEG image",
        b"\x89PNG":  "PNG image",
        b"GIF8":     "GIF image",
        b"<!DOCTYPE": "HTML document",
        b"<html":    "HTML document",
        b"#!/":      "Shell script",
    }
    for magic, label in sigs.items():
        if data.startswith(magic):
            return label
    # Fallback: check extension
    ext = Path(filename).suffix.lower()
    ext_map = {
        ".py": "Python script", ".js": "JavaScript",
        ".ps1": "PowerShell script", ".bat": "Windows batch file",
        ".vbs": "VBScript", ".csv": "CSV data",
        ".json": "JSON data", ".xml": "XML document",
        ".txt": "Plain text", ".log": "Log file",
    }
    return ext_map.get(ext, "Unknown/Binary")


def _extract_strings_py(data: bytes, min_len: int) -> list[str]:
    import re
    ascii_strings = re.findall(rb"[ -~]{%d,}" % min_len, data)
    return [s.decode("ascii", errors="ignore") for s in ascii_strings]


def _pe_metadata(data: bytes) -> dict | None:
    """Extract basic PE metadata if pefile is available."""
    try:
        import pefile  # type: ignore
        pe = pefile.PE(data=data)
        sections = [
            {
                "name": s.Name.decode("utf-8", errors="ignore").rstrip("\x00"),
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": s.get_entropy(),
            }
            for s in pe.sections
        ]
        imports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="ignore")
                for imp in entry.imports:
                    name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"ord_{imp.ordinal}"
                    imports.append(f"{dll}!{name}")
        return {
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "num_sections": pe.FILE_HEADER.NumberOfSections,
            "sections": sections,
            "imports_sample": imports[:50],
            "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        }
    except Exception as exc:
        log_error("", "static_file_analyse.pe_metadata", str(exc), severity="warning")
        return None


def _pdf_metadata(data: bytes) -> dict | None:
    """Extract PDF metadata and detect suspicious features via pymupdf."""
    try:
        import fitz  # pymupdf
        doc = fitz.open(stream=data, filetype="pdf")
        meta = doc.metadata
        # Check for suspicious features in raw PDF stream
        raw = data.decode("latin-1", errors="ignore")
        suspicious = []
        for keyword in ("/JavaScript", "/JS", "/OpenAction", "/AA",
                        "/Launch", "/EmbeddedFile", "/ObjStm", "/XFA"):
            if keyword in raw:
                suspicious.append(keyword)
        return {
            "page_count": len(doc),
            "author": meta.get("author", ""),
            "creator": meta.get("creator", ""),
            "producer": meta.get("producer", ""),
            "creation_date": meta.get("creationDate", ""),
            "suspicious_keywords": suspicious,
        }
    except Exception as exc:
        log_error("", "static_file_analyse.pdf_metadata", str(exc), severity="warning")
        return None


def static_file_analyse(file_path: str | Path, case_id: str) -> dict:
    """
    Run static analysis on *file_path* and save results under the case.
    """
    file_path = Path(file_path)
    data = file_path.read_bytes()
    filename = file_path.name

    analysis_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    strings_list = _extract_strings_py(data, STRINGS_MIN_LEN)
    file_type = _detect_type(data, filename)

    result = {
        "filename": filename,
        "source_path": str(file_path),
        "case_id": case_id,
        "ts": utcnow(),
        "file_type": file_type,
        "size_bytes": len(data),
        "entropy": round(_entropy(data), 4),
        "hashes": _compute_hashes(data),
        "strings_count": len(strings_list),
        "strings_sample": strings_list[:200],
        "pe_metadata": _pe_metadata(data) if data[:2] == b"MZ" else None,
        "pdf_metadata": _pdf_metadata(data) if file_type == "PDF document" else None,
        "flags": [],
    }

    # Heuristic flags
    if result["entropy"] > 7.2:
        result["flags"].append("HIGH_ENTROPY: possible packing or encryption")
    if file_type in ("PE/DOS executable", "ELF executable"):
        result["flags"].append(f"EXECUTABLE: {file_type}")
    if any("powershell" in s.lower() for s in strings_list):
        result["flags"].append("STRINGS: PowerShell reference found")
    if any("cmd.exe" in s.lower() for s in strings_list):
        result["flags"].append("STRINGS: cmd.exe reference found")

    # HTTP vs HTTPS URL differentiation
    http_urls = [s for s in strings_list if s.startswith("http://")]
    https_urls = [s for s in strings_list if s.startswith("https://")]
    if http_urls:
        result["flags"].append(f"STRINGS: {len(http_urls)} plain HTTP URL(s) found (no TLS)")
    if https_urls:
        result["flags"].append(f"STRINGS: {len(https_urls)} HTTPS URL(s) found")
    if not http_urls and not https_urls and any(s.startswith("http") for s in strings_list):
        result["flags"].append("STRINGS: HTTP/HTTPS URL(s) found")

    # PDF-specific flags
    if result["pdf_metadata"]:
        pdf_meta = result["pdf_metadata"]
        for kw in pdf_meta.get("suspicious_keywords", []):
            result["flags"].append(f"PDF_SUSPICIOUS_KEYWORD: {kw} found")

    out_path = analysis_dir / f"{filename}.analysis.json"
    write_artefact(out_path, json.dumps(result, indent=2))
    print(f"[static_file_analyse] {filename}: {result['file_type']}, "
          f"entropy={result['entropy']}, flags={result['flags']}")
    return result


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Static analysis on a file.")
    p.add_argument("file_path")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = static_file_analyse(args.file_path, args.case_id)
    print(json.dumps(result, indent=2))
