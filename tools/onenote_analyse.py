"""
tool: onenote_analyse
---------------------
Extract embedded files from Microsoft OneNote (.one / .onetoc2) documents.
Attackers abuse OneNote attachments as a delivery vector because attached
files (HTA, BAT, JS, LNK, EXE) execute without the Office VBA gate.

Implementation: walks the binary for the OneNote ``FileDataStoreObject``
GUID and lifts each embedded payload. No external dependency.

Reference: [MS-ONESTORE] §2.6.13 FileDataStoreObject

Writes:
  cases/<case_id>/artefacts/analysis/<filename>.onenote_analysis.json
  cases/<case_id>/artefacts/onenote/<filename>__embed_<idx>.<ext>
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import eprint, log_error, save_json, utcnow, write_artefact


_FILEDATASTORE_GUID = bytes.fromhex("e716e3bd652611" "45a4c48d4d0b7a9eac")
_HEADER_SIZE = 16 + 8 + 4 + 8  # GUID + cbLength + unused + reserved

_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024  # 64 MB safety cap per embed

_MAGIC_EXT = [
    (b"MZ", "exe"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"#!/bin/", "sh"),
    (b"<?xml", "xml"),
    (b"{\\rtf", "rtf"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (b"<html", "html"),
    (b"<HTML", "html"),
    (b"<!DOCTYPE", "html"),
    (b"BM", "bmp"),
    (b"GIF8", "gif"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3"),
    (b"\x00\x01\x00\x00", "ttf"),
    (b"OTTO", "otf"),
    (b"D0CF11E0", "ole"),
]


_LLM_SYSTEM_PROMPT = (
    "You are a malware analyst reviewing embedded attachments extracted "
    "from a OneNote (.one) document. Given per-attachment file type, hash, "
    "size, and a peek at the head bytes, assess the page's purpose:\n"
    "- Verdict: malicious / suspicious / clean\n"
    "- Likely role: dropper, downloader, decoy, legitimate content\n"
    "- Recommended next step (analyse_pe, yara_scan, sandbox detonation)\n"
    "Only make claims supported by the supplied data."
)


def _guess_ext(blob: bytes) -> str:
    head = blob[:16]
    for sig, ext in _MAGIC_EXT:
        if head.startswith(sig):
            return ext
    # OLE2 (D0 CF 11 E0 A1 B1 1A E1) — DOC/XLS/PPT/MSI legacy
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    return "bin"


def _iter_embeds(data: bytes):
    """Yield (offset, header_offset, blob) for each FileDataStoreObject."""
    pos = 0
    while True:
        idx = data.find(_FILEDATASTORE_GUID, pos)
        if idx == -1:
            return
        cb_offset = idx + 16
        if cb_offset + 12 > len(data):
            return
        try:
            (cb_length,) = struct.unpack_from("<Q", data, cb_offset)
        except struct.error:
            return
        data_start = idx + _HEADER_SIZE
        if cb_length == 0 or cb_length > _MAX_PAYLOAD_BYTES:
            pos = idx + len(_FILEDATASTORE_GUID)
            continue
        data_end = data_start + cb_length
        if data_end > len(data):
            return
        blob = data[data_start:data_end]
        yield idx, data_start, blob
        pos = data_end


def onenote_analyse(file_path: str | Path, case_id: str) -> dict:
    """Walk a OneNote document for embedded files and persist results."""
    file_path = Path(file_path)
    if not file_path.exists():
        return {"status": "error", "reason": f"file not found: {file_path}"}

    data = file_path.read_bytes()
    filename = file_path.name

    out_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    embed_dir = CASES_DIR / case_id / "artefacts" / "onenote"
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
        "embeds": [],
        "flags": [],
    }

    try:
        for idx, (guid_off, data_off, blob) in enumerate(_iter_embeds(data)):
            ext = _guess_ext(blob)
            sha = hashlib.sha256(blob).hexdigest()
            embed_name = f"{filename}__embed_{idx:02d}.{ext}"
            embed_path = embed_dir / embed_name
            write_artefact(embed_path, blob)
            result["embeds"].append({
                "index": idx,
                "guid_offset": guid_off,
                "data_offset": data_off,
                "size": len(blob),
                "sha256": sha,
                "md5": hashlib.md5(blob).hexdigest(),
                "extension_guess": ext,
                "saved_path": str(embed_path),
                "head_hex": blob[:32].hex(),
            })
    except Exception as exc:
        log_error(case_id, "onenote_analyse.iter", str(exc),
                  severity="warning", context={"file": str(file_path)})
        result["parse_error"] = str(exc)

    # ---- Flags -----------------------------------------------------------
    flags = result["flags"]
    if result["embeds"]:
        flags.append(f"EMBEDDED_FILES: {len(result['embeds'])} attachment(s)")
    risky_exts = {"exe", "elf", "lnk", "rtf", "ole", "zip", "rar", "7z", "html", "sh"}
    risky = [e for e in result["embeds"] if e["extension_guess"] in risky_exts]
    if risky:
        flags.append(
            f"EXECUTABLE_PAYLOADS: {len(risky)} embedded file(s) flagged "
            f"({sorted({e['extension_guess'] for e in risky})})"
        )

    out_path = out_dir / f"{filename}.onenote_analysis.json"
    save_json(out_path, result)
    eprint(f"[onenote_analyse] {filename}: embeds={len(result['embeds'])}, "
           f"flags={len(flags)}")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Extract embeds from OneNote (.one).")
    parser.add_argument("file_path")
    parser.add_argument("--case", required=True, dest="case_id")
    args = parser.parse_args()

    out = onenote_analyse(args.file_path, args.case_id)
    print(json.dumps(out, indent=2, default=str))
