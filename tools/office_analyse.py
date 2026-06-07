"""
tool: office_analyse
--------------------
Static analysis of Microsoft Office documents (modern OOXML and legacy OLE2):
extracts embedded VBA macros, XLM/Excel 4.0 macros, suspicious keyword flags,
external relationships, and DDE links.

Targets: .doc .docm .docx .dot .dotm .xls .xlsm .xlsx .xlt .xltm .ppt .pptm
         .pptx .rtf .vsd .vsdm

Writes:
  cases/<case_id>/artefacts/analysis/<filename>.office_analysis.json
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import eprint, log_error, save_json, utcnow

try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
    HAS_OLEVBA = True
except ImportError:
    HAS_OLEVBA = False

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False


_LLM_SYSTEM_PROMPT = (
    "You are a malware analyst reviewing static analysis of a Microsoft Office "
    "document. Given extracted VBA/XLM macros, autoexec triggers, suspicious "
    "keywords, and external relationships, assess:\n"
    "- Verdict: malicious / suspicious / clean\n"
    "- Confidence: high / medium / low\n"
    "- Macro purpose: dropper, downloader, credential theft, lure, other\n"
    "- IOCs: URLs, domains, file paths, command lines, registry keys\n"
    "- Evasion techniques: obfuscation, anti-analysis, sandbox checks\n"
    "Only make claims supported by the supplied data."
)

_OFFICE_EXTENSIONS = {
    ".doc", ".docm", ".docx", ".dot", ".dotm",
    ".xls", ".xlsb", ".xlsm", ".xlsx", ".xlt", ".xltm",
    ".ppt", ".pptm", ".pptx", ".pot", ".potm",
    ".rtf", ".vsd", ".vsdm",
}


_OOXML_RELS_RE = re.compile(
    rb'Target="([^"]+)"\s+TargetMode="External"',
    re.IGNORECASE,
)


def _external_relationships(file_path: Path) -> list[str]:
    """For OOXML packages, list any external relationship targets (template
    injection / remote payload pivots)."""
    if not zipfile.is_zipfile(file_path):
        return []
    out: list[str] = []
    try:
        with zipfile.ZipFile(file_path) as zf:
            for name in zf.namelist():
                if not name.endswith(".rels"):
                    continue
                try:
                    blob = zf.read(name)
                except Exception:
                    continue
                for m in _OOXML_RELS_RE.finditer(blob):
                    out.append(m.group(1).decode("utf-8", errors="replace"))
    except (zipfile.BadZipFile, KeyError):
        return []
    return sorted(set(out))


def _dde_links(file_path: Path) -> list[str]:
    """Look for DDE/DDEAUTO field codes in OOXML document body."""
    if not zipfile.is_zipfile(file_path):
        return []
    hits: list[str] = []
    pattern = re.compile(rb"DDEAUTO?\s+[^<]+", re.IGNORECASE)
    try:
        with zipfile.ZipFile(file_path) as zf:
            for name in zf.namelist():
                if not name.endswith(".xml"):
                    continue
                try:
                    blob = zf.read(name)
                except Exception:
                    continue
                for m in pattern.finditer(blob):
                    snippet = m.group(0).decode("utf-8", errors="replace")
                    hits.append(snippet[:200])
    except (zipfile.BadZipFile, KeyError):
        return []
    return list(dict.fromkeys(hits))[:20]


def _ole_streams(file_path: Path) -> list[dict]:
    """Enumerate OLE2 streams (legacy Office / RTF / MSI). Useful even when
    olevba reports no macros."""
    if not HAS_OLEFILE:
        return []
    try:
        if not olefile.isOleFile(str(file_path)):
            return []
    except Exception:
        return []
    streams: list[dict] = []
    try:
        ole = olefile.OleFileIO(str(file_path))
        for parts in ole.listdir(streams=True, storages=False):
            try:
                size = ole.get_size("/".join(parts))
            except Exception:
                size = 0
            streams.append({"path": "/".join(parts), "size": size})
        ole.close()
    except Exception as exc:
        log_error("", "office_analyse.ole_streams", str(exc), severity="warning")
    return streams[:200]


def _summarise_macros(vbp: "VBA_Parser") -> dict:
    """Pull macros + scan results from VBA_Parser."""
    macros: list[dict] = []
    total_chars = 0
    for filename, stream_path, vba_filename, vba_code in vbp.extract_macros():
        code = vba_code or ""
        total_chars += len(code)
        macros.append({
            "container": filename,
            "ole_stream": stream_path,
            "vba_name": vba_filename,
            "code_chars": len(code),
            # Full macro source — the artefact is the analyst's source of truth;
            # truncating dropped evidence (no-slimming tool-return convention).
            "code": code,
        })

    # scan_results: list of tuples (kw_type, keyword, description)
    scan_findings: list[dict] = []
    try:
        results = vbp.analyze_macros(show_decoded_strings=True, deobfuscate=True)
    except Exception as exc:
        log_error("", "office_analyse.analyze_macros", str(exc), severity="warning")
        results = []

    autoexec: list[str] = []
    suspicious: list[str] = []
    iocs: list[str] = []
    hex_strings: list[str] = []
    base64_strings: list[str] = []

    for entry in results or []:
        try:
            kw_type, keyword, description = entry[0], entry[1], entry[2]
        except (IndexError, TypeError):
            continue
        scan_findings.append({
            "type": kw_type,
            "keyword": keyword,
            "description": description,
        })
        kt = (kw_type or "").lower()
        if "autoexec" in kt:
            autoexec.append(keyword)
        elif "suspicious" in kt:
            suspicious.append(keyword)
        elif "ioc" in kt:
            iocs.append(keyword)
        elif "hex" in kt:
            hex_strings.append(keyword)
        elif "base64" in kt:
            base64_strings.append(keyword)

    return {
        "macros": macros,
        "macro_count": len(macros),
        "total_macro_chars": total_chars,
        "autoexec_triggers": sorted(set(autoexec)),
        "suspicious_keywords": sorted(set(suspicious)),
        "iocs": sorted(set(iocs)),
        "hex_strings_sample": hex_strings[:25],
        "base64_strings_sample": base64_strings[:25],
        "scan_findings": scan_findings,
    }


def office_analyse(file_path: str | Path, case_id: str) -> dict:
    """Run static analysis on an Office document and persist the manifest.

    Args:
        file_path: Path to an Office document.
        case_id:   Case identifier; output lands under the case's analysis dir.

    Returns:
        Manifest dict with macros, suspicious indicators, external relationships,
        DDE links, hashes and flags.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return {"status": "error", "reason": f"file not found: {file_path}"}

    data = file_path.read_bytes()
    filename = file_path.name

    out_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    result: dict = {
        "status": "ok",
        "filename": filename,
        "source_path": str(file_path),
        "case_id": case_id,
        "ts": utcnow(),
        "file_size": len(data),
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "external_relationships": _external_relationships(file_path),
        "dde_links": _dde_links(file_path),
        "ole_streams": _ole_streams(file_path),
        "macros": [],
        "macro_count": 0,
        "autoexec_triggers": [],
        "suspicious_keywords": [],
        "iocs": [],
        "flags": [],
    }

    if not HAS_OLEVBA:
        result["status"] = "skipped"
        result["reason"] = "oletools not installed"
        log_error(case_id, "office_analyse", "oletools missing", severity="warning")
    else:
        try:
            vbp = VBA_Parser(str(file_path))
            try:
                result["container_type"] = {
                    TYPE_OLE: "OLE2",
                    TYPE_OpenXML: "OOXML",
                    TYPE_Word2003_XML: "Word2003XML",
                    TYPE_MHTML: "MHTML",
                }.get(vbp.type, str(vbp.type))
                result["detected_vba"] = bool(vbp.detect_vba_macros())
                result["detected_xlm"] = bool(vbp.detect_xlm_macros())
                if vbp.detect_vba_macros() or vbp.detect_xlm_macros():
                    result.update(_summarise_macros(vbp))
            finally:
                vbp.close()
        except Exception as exc:
            log_error(case_id, "office_analyse.vba_parser", str(exc),
                      severity="warning",
                      context={"file": str(file_path)})
            result["parse_error"] = str(exc)

    # ---- Heuristic flags -------------------------------------------------
    flags = result["flags"]
    if result.get("macro_count"):
        flags.append(f"MACROS: {result['macro_count']} macro container(s)")
    if result.get("autoexec_triggers"):
        flags.append(
            f"AUTOEXEC: {len(result['autoexec_triggers'])} trigger(s) "
            f"(e.g. {result['autoexec_triggers'][0]})"
        )
    if result.get("suspicious_keywords"):
        flags.append(
            f"SUSPICIOUS_KEYWORDS: {len(result['suspicious_keywords'])} hit(s)"
        )
    if result.get("dde_links"):
        flags.append(f"DDE_LINKS: {len(result['dde_links'])} field(s) detected")
    if result.get("external_relationships"):
        flags.append(
            "EXTERNAL_TEMPLATE: remote relationship target(s) — possible "
            "template injection"
        )

    out_path = out_dir / f"{filename}.office_analysis.json"
    save_json(out_path, result)
    eprint(f"[office_analyse] {filename}: macros={result.get('macro_count', 0)}, "
           f"autoexec={len(result.get('autoexec_triggers', []))}, "
           f"flags={len(flags)}")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Static analysis of an Office document.")
    parser.add_argument("file_path")
    parser.add_argument("--case", required=True, dest="case_id")
    args = parser.parse_args()

    out = office_analyse(args.file_path, args.case_id)
    print(json.dumps(out, indent=2, default=str))
