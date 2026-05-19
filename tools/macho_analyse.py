"""
tool: macho_analyse
-------------------
Static analysis of Mach-O (macOS) binaries using macholib.

Detects FAT (universal) binaries, parses each slice's header, lists load
commands and linked dylibs, flags absence of a code signature, and surfaces
common malicious indicators (network frameworks, dynamic-loading APIs,
encrypted segments).

Writes:
  cases/<case_id>/artefacts/analysis/<filename>.macho_analysis.json
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import eprint, log_error, save_json, utcnow

try:
    from macholib.MachO import MachO
    from macholib.mach_o import (
        CPU_TYPE_NAMES,
        MH_FILETYPE_NAMES,
        LC_LOAD_DYLIB,
        LC_LOAD_WEAK_DYLIB,
        LC_REEXPORT_DYLIB,
        LC_LAZY_LOAD_DYLIB,
        LC_LOAD_UPWARD_DYLIB,
        LC_CODE_SIGNATURE,
        LC_ENCRYPTION_INFO,
        LC_ENCRYPTION_INFO_64,
        LC_RPATH,
        LC_MAIN,
        LC_UUID,
    )
    HAS_MACHOLIB = True
except ImportError:
    HAS_MACHOLIB = False


_LLM_SYSTEM_PROMPT = (
    "You are a malware analyst reviewing static analysis of a Mach-O binary. "
    "Given architecture, linked dylibs, load commands, code signature status, "
    "and segment entropy, assess:\n"
    "- Verdict: malicious / suspicious / clean\n"
    "- Confidence: high / medium / low\n"
    "- Capabilities: networking, dynamic code loading, persistence, anti-analysis\n"
    "- IOCs: hardcoded URLs/hosts in strings\n"
    "Only make claims supported by the supplied data."
)


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": "MH_MAGIC (32-bit BE)",
    b"\xce\xfa\xed\xfe": "MH_CIGAM (32-bit LE)",
    b"\xfe\xed\xfa\xcf": "MH_MAGIC_64 (64-bit BE)",
    b"\xcf\xfa\xed\xfe": "MH_CIGAM_64 (64-bit LE)",
    b"\xca\xfe\xba\xbe": "FAT_MAGIC (universal)",
    b"\xbe\xba\xfe\xca": "FAT_CIGAM (universal)",
    b"\xca\xfe\xba\xbf": "FAT_MAGIC_64 (universal-64)",
    b"\xbf\xba\xfe\xca": "FAT_CIGAM_64 (universal-64)",
}


_RISKY_DYLIBS = {
    "/usr/lib/libnetwork.dylib", "/usr/lib/libcurl.dylib",
    "/system/library/frameworks/network.framework/network",
    "/system/library/frameworks/cfnetwork.framework/cfnetwork",
    "/system/library/frameworks/javascriptcore.framework/javascriptcore",
    "/usr/lib/libsqlite3.dylib",  # often used by infostealers
}


def is_macho(data: bytes) -> str | None:
    head = data[:4]
    return _MACHO_MAGICS.get(head)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _cpu_name(cputype: int, cpusubtype: int) -> str:
    try:
        sub = CPU_TYPE_NAMES.get(cputype, str(cputype))
        return f"{sub} (sub={cpusubtype})"
    except Exception:
        return f"cpu_{cputype}_{cpusubtype}"


def _filetype_name(filetype: int) -> str:
    return MH_FILETYPE_NAMES.get(filetype, f"unknown_{filetype}")


def _decode_lc_str(blob: bytes) -> str:
    return blob.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _summarise_header(header) -> dict:
    """Pull useful info from a single MachOHeader slice."""
    hdr = header.header
    info: dict = {
        "cputype": _cpu_name(hdr.cputype, hdr.cpusubtype),
        "filetype": _filetype_name(hdr.filetype),
        "ncmds": hdr.ncmds,
        "sizeofcmds": hdr.sizeofcmds,
        "flags": hex(hdr.flags),
        "uuid": None,
        "code_signature_present": False,
        "encrypted_segments": [],
        "load_dylibs": [],
        "rpaths": [],
        "main_entry": None,
        "segments": [],
    }

    for lc, cmd, lcdata in header.commands:
        try:
            cmd_id = lc.cmd
        except AttributeError:
            continue
        if cmd_id in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
                      LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB,
                      LC_LOAD_UPWARD_DYLIB):
            try:
                name = _decode_lc_str(lcdata) if isinstance(lcdata, bytes) \
                    else lcdata.decode("utf-8", errors="replace") if hasattr(lcdata, "decode") \
                    else str(lcdata)
            except Exception:
                name = "<dylib-name-error>"
            info["load_dylibs"].append(name)
        elif cmd_id == LC_CODE_SIGNATURE:
            info["code_signature_present"] = True
        elif cmd_id in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            try:
                cryptid = getattr(cmd, "cryptid", 0)
                cryptoff = getattr(cmd, "cryptoff", 0)
                cryptsize = getattr(cmd, "cryptsize", 0)
                if cryptid:
                    info["encrypted_segments"].append({
                        "cryptid": cryptid,
                        "offset": cryptoff,
                        "size": cryptsize,
                    })
            except Exception:
                pass
        elif cmd_id == LC_RPATH:
            try:
                rp = _decode_lc_str(lcdata) if isinstance(lcdata, bytes) else str(lcdata)
            except Exception:
                rp = ""
            if rp:
                info["rpaths"].append(rp)
        elif cmd_id == LC_MAIN:
            try:
                info["main_entry"] = {
                    "entryoff": getattr(cmd, "entryoff", None),
                    "stacksize": getattr(cmd, "stacksize", None),
                }
            except Exception:
                pass
        elif cmd_id == LC_UUID:
            try:
                uuid_bytes = bytes(cmd.uuid)
                info["uuid"] = uuid_bytes.hex()
            except Exception:
                pass

        # Segments + sections
        segname = getattr(cmd, "segname", None)
        if segname:
            try:
                seg = {
                    "segname": _decode_lc_str(segname) if isinstance(segname, bytes) else str(segname),
                    "vmaddr": getattr(cmd, "vmaddr", None),
                    "vmsize": getattr(cmd, "vmsize", None),
                    "fileoff": getattr(cmd, "fileoff", None),
                    "filesize": getattr(cmd, "filesize", None),
                    "nsects": getattr(cmd, "nsects", None),
                }
                info["segments"].append(seg)
            except Exception:
                pass

    return info


def macho_analyse(file_path: str | Path, case_id: str) -> dict:
    """Parse a Mach-O binary and persist a manifest under the case."""
    file_path = Path(file_path)
    if not file_path.exists():
        return {"status": "error", "reason": f"file not found: {file_path}"}

    data = file_path.read_bytes()
    filename = file_path.name

    out_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    magic = is_macho(data)
    result: dict = {
        "status": "ok",
        "filename": filename,
        "source_path": str(file_path),
        "case_id": case_id,
        "ts": utcnow(),
        "file_size": len(data),
        "entropy": round(_entropy(data), 4),
        "magic": magic,
        "is_fat": bool(magic and magic.startswith("FAT")),
        "slices": [],
        "flags": [],
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    }

    if magic is None:
        result["status"] = "not_macho"
        result["reason"] = "no Mach-O magic bytes"
        save_json(out_dir / f"{filename}.macho_analysis.json", result)
        return result

    if not HAS_MACHOLIB:
        result["status"] = "skipped"
        result["reason"] = "macholib not installed"
        log_error(case_id, "macho_analyse", "macholib missing", severity="warning")
        save_json(out_dir / f"{filename}.macho_analysis.json", result)
        return result

    try:
        m = MachO(str(file_path))
        for header in m.headers:
            result["slices"].append(_summarise_header(header))
    except Exception as exc:
        log_error(case_id, "macho_analyse.parse", str(exc),
                  severity="warning", context={"file": str(file_path)})
        result["parse_error"] = str(exc)

    # ---- Flags -----------------------------------------------------------
    flags = result["flags"]
    if result["is_fat"]:
        flags.append(f"UNIVERSAL_BINARY: {len(result['slices'])} architectures")
    for sl in result["slices"]:
        if not sl["code_signature_present"]:
            flags.append(
                f"UNSIGNED: slice ({sl.get('cputype')}) has no LC_CODE_SIGNATURE"
            )
        if sl["encrypted_segments"]:
            flags.append(
                f"ENCRYPTED_SEGMENTS: slice ({sl.get('cputype')}) has "
                f"{len(sl['encrypted_segments'])} encrypted segment(s)"
            )
        risky_hits = [d for d in sl["load_dylibs"]
                      if d.lower() in _RISKY_DYLIBS]
        if risky_hits:
            flags.append(
                f"DYLIBS_NETWORK_OR_INFOSTEALER: {sorted(set(risky_hits))}"
            )
        if any("dlopen" in d.lower() for d in sl["load_dylibs"]):
            flags.append("DLOPEN_DYLIB: dynamic loader present")
        if sl["rpaths"]:
            flags.append(f"RPATH: {len(sl['rpaths'])} runtime search path(s)")
    if result["entropy"] > 7.2:
        flags.append("HIGH_ENTROPY: possible packing/encryption")

    out_path = out_dir / f"{filename}.macho_analysis.json"
    save_json(out_path, result)
    eprint(f"[macho_analyse] {filename}: slices={len(result['slices'])}, "
           f"fat={result['is_fat']}, flags={len(flags)}")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Static analysis of a Mach-O binary.")
    parser.add_argument("file_path")
    parser.add_argument("--case", required=True, dest="case_id")
    args = parser.parse_args()

    out = macho_analyse(args.file_path, args.case_id)
    print(json.dumps(out, indent=2, default=str))
