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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, STRINGS_MIN_LEN
from tools.common import eprint, log_error, utcnow, write_artefact

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


_OFFICE_OOXML_EXTS = {".docx", ".docm", ".xlsx", ".xlsm", ".xlsb",
                      ".pptx", ".pptm", ".potm", ".dotm", ".vsdm"}
_OFFICE_LEGACY_EXTS = {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot",
                       ".vsd"}
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LNK_MAGIC = b"L\x00\x00\x00\x01\x14\x02\x00"
_ONENOTE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")  # OneNote section
_MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
)
_VHD_FOOTER_COOKIE = b"conectix"
_VHDX_HEADER_COOKIE = b"vhdxfile"
_RTF_MAGIC = b"{\\rtf"


def _ole2_is_msi(data: bytes) -> bool:
    """Heuristic — MSI compound docs include a 'DigitalProductID' or
    '!_Tables' stream. Cheap proxy: look for the 'msi' creator string."""
    return b"Microsoft.Windows.Installer" in data[:65536] or \
           b"intel;1033" in data[:65536]


def _detect_type(data: bytes, filename: str, file_path: Path | None = None) -> str:
    """Magic-byte + extension detection covering executables, archives,
    Office (modern + legacy), PDF, OneNote, LNK, MSI, ISO/IMG/VHD/VHDX,
    Mach-O variants, and memory-dump containers."""
    head = data[:64]
    ext = Path(filename).suffix.lower()

    # ---- Mach-O variants (check before generic MZ) -----------------------
    if head[:4] in _MACHO_MAGICS:
        head4 = head[:4]
        if head4 in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                     b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
            return "Mach-O universal binary"
        return "Mach-O executable"

    sigs = [
        (b"MZ",            "PE/DOS executable"),
        (b"\x7fELF",       "ELF executable"),
        (b"PK\x03\x04",    "ZIP archive"),
        (b"\x1f\x8b",      "GZip archive"),
        (b"BZh",           "BZip2 archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07",  "RAR archive"),
        (b"%PDF",          "PDF document"),
        (b"\xff\xd8\xff",  "JPEG image"),
        (b"\x89PNG",       "PNG image"),
        (b"GIF8",          "GIF image"),
        (b"<!DOCTYPE",     "HTML document"),
        (b"<html",         "HTML document"),
        (b"#!/",           "Shell script"),
        (_RTF_MAGIC,       "RTF document"),
        (_LNK_MAGIC,       "Windows shell link (.lnk)"),
        (b"MSCF",          "Microsoft Cabinet (.cab)"),
        (b"PAGEDU64",      "Windows kernel memory dump"),
        (b"PAGEDUMP",      "Windows kernel memory dump"),
        (b"MDMP",          "Windows minidump"),
        (b"HIBR",          "Windows hibernation file"),
        (_VHDX_HEADER_COOKIE, "VHDX disk image"),
    ]
    for magic, label in sigs:
        if data.startswith(magic):
            return label

    # OneNote section file (.one) — 16-byte file-type GUID at offset 0
    if data.startswith(_ONENOTE_MAGIC):
        return "OneNote section (.one)"

    # ISO 9660 — Volume Descriptor identifier at LBA 16 (offset 32768)
    if len(data) > 32768 + 6:
        if data[32769:32774] in (b"CD001", b"BEA01", b"NSR02", b"NSR03"):
            return "ISO 9660 disk image"

    # VHD — footer cookie 'conectix' in last 512 bytes
    if len(data) >= 512 and data[-512:].startswith(_VHD_FOOTER_COOKIE):
        return "VHD disk image"

    # OLE2 compound — could be DOC/XLS/PPT/MSI/VSD; differentiate by extension
    if data.startswith(_OLE2_MAGIC):
        if ext == ".msi" or _ole2_is_msi(data):
            return "MSI installer"
        if ext in _OFFICE_LEGACY_EXTS:
            return f"Office legacy ({ext.lstrip('.').upper()})"
        return "OLE2 compound document"

    # OOXML packages — these are ZIPs, but caught earlier as ZIP unless we
    # check extension to refine the label.
    if ext in _OFFICE_OOXML_EXTS:
        return f"Office OOXML ({ext.lstrip('.').upper()})"

    # Fallback: check extension for scripts / data
    ext_map = {
        ".py": "Python script", ".js": "JavaScript",
        ".ps1": "PowerShell script", ".bat": "Windows batch file",
        ".cmd": "Windows batch file", ".vbs": "VBScript",
        ".vbe": "VBScript (encoded)", ".jse": "JScript (encoded)",
        ".hta": "HTML Application (HTA)",
        ".csv": "CSV data", ".json": "JSON data",
        ".xml": "XML document", ".txt": "Plain text", ".log": "Log file",
        ".one": "OneNote section (.one)",
        ".onetoc2": "OneNote table of contents",
        ".img": "Raw disk image (.img)",
        ".iso": "ISO 9660 disk image",
        ".vhd": "VHD disk image",
        ".vhdx": "VHDX disk image",
        ".dmp": "Memory/crash dump (.dmp)",
        ".mem": "Memory dump (.mem)",
        ".vmem": "VMware memory dump (.vmem)",
        ".raw": "Raw memory dump (.raw)",
        ".eml": "Email message (.eml)",
        ".msg": "Outlook message (.msg)",
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


_SPECIALIST_DISPATCH: dict[str, tuple[str, str]] = {
    # file_type label -> (module name, function name)
    "PDF document":              ("tools.pdf_analyse",         "pdf_analyse"),
    "Windows shell link (.lnk)": ("tools.lnk_analyse",         "lnk_analyse"),
    "OneNote section (.one)":    ("tools.onenote_analyse",     "onenote_analyse"),
    "OneNote table of contents": ("tools.onenote_analyse",     "onenote_analyse"),
    "MSI installer":             ("tools.msi_analyse",         "msi_analyse"),
    "Mach-O executable":         ("tools.macho_analyse",       "macho_analyse"),
    "Mach-O universal binary":   ("tools.macho_analyse",       "macho_analyse"),
    "ISO 9660 disk image":       ("tools.disk_image_analyse",  "disk_image_analyse"),
    "Raw disk image (.img)":     ("tools.disk_image_analyse",  "disk_image_analyse"),
    "VHD disk image":            ("tools.disk_image_analyse",  "disk_image_analyse"),
    "VHDX disk image":           ("tools.disk_image_analyse",  "disk_image_analyse"),
}


def dispatch_specialist(file_type: str, file_path: Path | str, case_id: str) -> dict | None:
    """Public wrapper for specialist routing — used by the tiered
    ``file_analyse`` orchestrator. Returns ``None`` when no specialist
    matches the detected file type."""
    return _dispatch_specialist(file_type, Path(file_path), case_id)


def _dispatch_specialist(file_type: str, file_path: Path, case_id: str) -> dict | None:
    """Route OOXML / legacy Office / specialist types to dedicated analysers."""
    if file_type.startswith("Office OOXML") or file_type.startswith("Office legacy"):
        target = ("tools.office_analyse", "office_analyse")
    else:
        target = _SPECIALIST_DISPATCH.get(file_type)
    if target is None:
        return None
    module_name, func_name = target
    try:
        mod = __import__(module_name, fromlist=[func_name])
        fn = getattr(mod, func_name)
    except Exception as exc:
        log_error(case_id, "static_file_analyse.dispatch",
                  f"failed to load {module_name}.{func_name}: {exc}",
                  severity="warning")
        return None
    try:
        return fn(file_path, case_id)
    except Exception as exc:
        log_error(case_id, "static_file_analyse.dispatch",
                  f"{module_name}.{func_name} raised: {exc}",
                  severity="warning",
                  context={"file": str(file_path), "file_type": file_type})
        return None


def static_file_analyse(
    file_path: str | Path,
    case_id: str,
    dispatch_specialist: bool = True,
) -> dict:
    """
    Run static analysis on *file_path* and save results under the case.

    Detection routes specialist file types (Office, PDF, LNK, OneNote, MSI,
    Mach-O, ISO/IMG/VHD/VHDX) to their dedicated analysers; the deep manifest
    is returned under ``specialist_analysis`` and key flags are merged in.

    Pass ``dispatch_specialist=False`` to run only the magic-byte / hash /
    entropy / strings triage — used by the tiered ``file_analyse`` orchestrator
    so it can decide whether the specialist parse is worth the cost.
    """
    file_path = Path(file_path)
    data = file_path.read_bytes()
    filename = file_path.name

    analysis_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    strings_list = _extract_strings_py(data, STRINGS_MIN_LEN)
    file_type = _detect_type(data, filename, file_path)

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
        "specialist_analysis": None,
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

    # ---- Specialist dispatch --------------------------------------------
    if dispatch_specialist:
        specialist = _dispatch_specialist(file_type, file_path, case_id)
        if specialist is not None:
            result["specialist_analysis"] = specialist
            for sf in specialist.get("flags", []) or []:
                result["flags"].append(f"SPECIALIST: {sf}")
            if specialist.get("status") not in ("ok", None):
                result["flags"].append(
                    f"SPECIALIST_STATUS: {specialist.get('status')}"
                    + (f" — {specialist.get('reason')}" if specialist.get('reason') else "")
                )

    out_path = analysis_dir / f"{filename}.analysis.json"
    write_artefact(out_path, json.dumps(result, indent=2))
    eprint(f"[static_file_analyse] {filename}: {result['file_type']}, "
           f"entropy={result['entropy']}, flags={len(result['flags'])}")
    return result


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Static analysis on a file.")
    p.add_argument("file_path")
    p.add_argument("--case", required=True, dest="case_id")
    args = p.parse_args()

    result = static_file_analyse(args.file_path, args.case_id)
    print(json.dumps(result, indent=2))
