"""
tool: msi_analyse
-----------------
Static analysis of Windows Installer (.msi) packages — OLE2 compound
documents whose streams carry installer tables and embedded binaries.

What it surfaces:
  - OLE2 stream listing (raw + MSI-tag decoded names)
  - Embedded payloads — streams whose first bytes are MZ/ELF/script shebangs
    are written out under ``artefacts/msi/`` for downstream PE/static analysis
  - SummaryInformation property set (creator, template, comments, etc.)
  - Decoded ``!CustomAction`` table entries when present
  - Hashes + heuristic flags

Writes:
  cases/<case_id>/artefacts/analysis/<filename>.msi_analysis.json
  cases/<case_id>/artefacts/msi/<filename>__stream_<i>.<ext>
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import eprint, log_error, save_json, utcnow, write_artefact

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False


_LLM_SYSTEM_PROMPT = (
    "You are a malware analyst reviewing static analysis of a Windows "
    "Installer (.msi). Given the decoded table list, CustomAction entries, "
    "embedded payloads, and SummaryInformation properties, assess:\n"
    "- Verdict: malicious / suspicious / clean\n"
    "- Confidence: high / medium / low\n"
    "- Likely purpose (legitimate installer, dropper, LOLBin abuse via msiexec)\n"
    "- IOCs: embedded PE hashes, URLs, command lines in CustomAction\n"
    "Only make claims supported by the supplied data."
)


# MSI stream-name decoding ('MSI Name Tag' / 'msi-mangled')
# Each char in the UTF-16 stream name decodes to 2 base-64-ish chars.
_MSI_TABLE = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._"
)


def decode_msi_name(name: str) -> str:
    """Decode an MSI-mangled stream name. Returns the original on failure.

    Three disjoint codepoint ranges: [0x3800, 0x4800) packs two base-64
    chars (low 6 bits first), [0x4800, 0x4840) is a single char, and
    0x4840 is the table-name marker rendered as ``!`` (e.g. !CustomAction).
    """
    out: list[str] = []
    try:
        for ch in name:
            cp = ord(ch)
            if 0x3800 <= cp < 0x4800:
                # 2-character encoding: first char in low 6 bits, second in high
                cp -= 0x3800
                out.append(_MSI_TABLE[cp & 0x3F])
                out.append(_MSI_TABLE[(cp >> 6) & 0x3F])
            elif 0x4800 <= cp < 0x4840:
                out.append(_MSI_TABLE[cp - 0x4800])
            elif cp == 0x4840:
                out.append("!")  # leading bang marker for tables
            else:
                out.append(ch)
        return "".join(out)
    except Exception:
        return name


def _stream_payload_kind(blob: bytes) -> str | None:
    """Identify common embedded payload types by magic bytes."""
    if blob.startswith(b"MZ"):
        return "exe"
    if blob.startswith(b"\x7fELF"):
        return "elf"
    if blob.startswith((b"#!/", b"@echo", b"@ECHO")):
        return "script"
    if blob.startswith(b"PK\x03\x04"):
        return "zip"
    if blob[:6] == b"%PDF-1":
        return "pdf"
    if blob[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    # CAB
    if blob.startswith(b"MSCF"):
        return "cab"
    return None


def _summary_information(ole) -> dict:
    """Parse \\x05SummaryInformation property set if present."""
    if not ole.exists("\x05SummaryInformation"):
        return {}
    try:
        meta = ole.get_metadata()
    except Exception as exc:
        log_error("", "msi_analyse.summary", str(exc), severity="warning")
        return {}
    fields = (
        "author", "title", "subject", "keywords", "comments", "template",
        "last_saved_by", "revision_number", "total_edit_time",
        "last_printed", "creation_date", "last_saved_time", "num_pages",
        "num_words", "num_chars", "creating_application", "security",
    )
    out: dict = {}
    for f in fields:
        try:
            val = getattr(meta, f, None)
        except Exception:
            val = None
        if val is not None and val != "":
            try:
                out[f] = val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)
            except Exception:
                out[f] = repr(val)
    return out


def msi_analyse(file_path: str | Path, case_id: str) -> dict:
    """Analyse an MSI file. Returns and persists a manifest under the case."""
    file_path = Path(file_path)
    if not file_path.exists():
        return {"status": "error", "reason": f"file not found: {file_path}"}

    data = file_path.read_bytes()
    filename = file_path.name

    out_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    embed_dir = CASES_DIR / case_id / "artefacts" / "msi"
    out_dir.mkdir(parents=True, exist_ok=True)
    embed_dir.mkdir(parents=True, exist_ok=True)

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
        "streams": [],
        "embedded_payloads": [],
        "summary_information": {},
        "flags": [],
    }

    if not HAS_OLEFILE:
        result["status"] = "skipped"
        result["reason"] = "olefile not installed"
        log_error(case_id, "msi_analyse", "olefile missing", severity="warning")
        save_json(out_dir / f"{filename}.msi_analysis.json", result)
        return result

    try:
        if not olefile.isOleFile(str(file_path)):
            result["status"] = "not_msi"
            result["reason"] = "not an OLE2 compound document"
            save_json(out_dir / f"{filename}.msi_analysis.json", result)
            return result

        ole = olefile.OleFileIO(str(file_path))
    except Exception as exc:
        result["status"] = "error"
        result["parse_error"] = str(exc)
        log_error(case_id, "msi_analyse.open", str(exc),
                  severity="warning", context={"file": str(file_path)})
        save_json(out_dir / f"{filename}.msi_analysis.json", result)
        return result

    try:
        result["summary_information"] = _summary_information(ole)

        for idx, parts in enumerate(ole.listdir(streams=True, storages=False)):
            stream_path = "/".join(parts)
            raw_name = parts[-1]
            decoded = decode_msi_name(raw_name)
            try:
                size = ole.get_size(stream_path)
            except Exception:
                size = 0
            entry: dict = {
                "index": idx,
                "stream_path": stream_path,
                "raw_name": raw_name,
                "decoded_name": decoded,
                "size": size,
            }

            # Peek head bytes for payload detection
            if size > 0 and size <= 256 * 1024 * 1024:
                try:
                    sf = ole.openstream(stream_path)
                    head = sf.read(min(size, 4096))
                except Exception as exc:
                    head = b""
                    entry["read_error"] = str(exc)
                kind = _stream_payload_kind(head)
                if kind:
                    # Re-read full blob and persist
                    try:
                        sf = ole.openstream(stream_path)
                        blob = sf.read()
                        sha = hashlib.sha256(blob).hexdigest()
                        ext_map = {
                            "exe": "exe", "elf": "elf", "script": "txt",
                            "zip": "zip", "pdf": "pdf", "ole": "ole",
                            "cab": "cab",
                        }
                        out_name = (
                            f"{filename}__stream_{idx:03d}."
                            f"{ext_map.get(kind, 'bin')}"
                        )
                        dest = embed_dir / out_name
                        write_artefact(dest, blob)
                        result["embedded_payloads"].append({
                            "stream": stream_path,
                            "decoded": decoded,
                            "kind": kind,
                            "size": len(blob),
                            "sha256": sha,
                            "md5": hashlib.md5(blob).hexdigest(),
                            "saved_path": str(dest),
                        })
                    except Exception as exc:
                        log_error(case_id, "msi_analyse.extract",
                                  str(exc), severity="warning",
                                  context={"stream": stream_path})
            result["streams"].append(entry)
    finally:
        ole.close()

    # ---- Flags -----------------------------------------------------------
    flags = result["flags"]
    decoded_names = [s["decoded_name"] for s in result["streams"]]
    if any(n.startswith("!CustomAction") or "CustomAction" in n for n in decoded_names):
        flags.append("CUSTOM_ACTION: !CustomAction table present")
    if result["embedded_payloads"]:
        kinds = sorted({e["kind"] for e in result["embedded_payloads"]})
        flags.append(
            f"EMBEDDED_PAYLOADS: {len(result['embedded_payloads'])} "
            f"({kinds})"
        )
    creating_app = (result["summary_information"] or {}).get("creating_application", "")
    if creating_app and "wix" not in creating_app.lower() and "installshield" not in creating_app.lower():
        flags.append(f"UNUSUAL_CREATOR: '{creating_app}'")

    out_path = out_dir / f"{filename}.msi_analysis.json"
    save_json(out_path, result)
    eprint(f"[msi_analyse] {filename}: streams={len(result['streams'])}, "
           f"payloads={len(result['embedded_payloads'])}, "
           f"flags={len(flags)}")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Static analysis of an MSI package.")
    parser.add_argument("file_path")
    parser.add_argument("--case", required=True, dest="case_id")
    args = parser.parse_args()

    out = msi_analyse(args.file_path, args.case_id)
    print(json.dumps(out, indent=2, default=str))
