"""
tool: disk_image_analyse
------------------------
Container-format analysis for disk images often used as malware carriers:
ISO 9660 (Joliet / Rock Ridge / UDF), IMG, VHD, VHDX.

ISO/IMG (when ISO 9660) are fully walked via pycdlib — every file listed
with size + SHA-256, and small files (<8 MiB) are extracted to
``cases/<case_id>/artefacts/disk_images/<image>/``.

VHD / VHDX are identified by footer/header cookies; metadata (disk size,
type, sector size) is surfaced, but the embedded filesystem is not mounted
— mount/parse externally if the contents need triage.

Writes:
  cases/<case_id>/artefacts/analysis/<filename>.disk_image_analysis.json
"""
from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import eprint, log_error, save_json, utcnow, write_artefact

try:
    import pycdlib
    HAS_PYCDLIB = True
except ImportError:
    HAS_PYCDLIB = False


_LLM_SYSTEM_PROMPT = (
    "You are a malware analyst reviewing a disk-image carrier (ISO, IMG, "
    "VHD, VHDX). Given the file listing, embedded executables, and any LNK "
    "shortcuts, assess:\n"
    "- Verdict: malicious / suspicious / clean\n"
    "- Likely role: ISO smuggling, USB drop, sandbox-evasion delivery\n"
    "- Recommended next step (analyse_pe / lnk_analyse on contained files)\n"
    "Only make claims supported by the supplied data."
)


_VHD_FOOTER_COOKIE = b"conectix"
_VHDX_HEADER_COOKIE = b"vhdxfile"
_ISO_SYNCS = (b"CD001", b"BEA01", b"NSR02", b"NSR03")

_EXTRACT_THRESHOLD_BYTES = 8 * 1024 * 1024  # 8 MiB cap per extracted file
_RISKY_EXTS = {".exe", ".dll", ".scr", ".sys", ".ocx", ".lnk", ".js", ".vbs",
               ".ps1", ".bat", ".cmd", ".hta", ".jar", ".msi", ".com",
               ".chm", ".cpl"}


class _HashingSink(io.RawIOBase):
    """Write-only sink that hashes a stream and retains only its head.

    pycdlib's ``get_file_from_iso_fp`` writes member data into a file-like
    object; collecting it in a BytesIO pulled every member — including
    multi-GB payloads — fully into RAM just to hash it. This sink hashes in
    flight and keeps at most ``keep_limit`` bytes (the extraction cap), so
    members that qualify for extraction are still written out intact.
    """

    def __init__(self, keep_limit: int) -> None:
        super().__init__()
        self.sha256 = hashlib.sha256()
        self.md5 = hashlib.md5()
        self.size = 0
        self._keep_limit = keep_limit
        self.head = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:
        chunk = bytes(b)
        self.sha256.update(chunk)
        self.md5.update(chunk)
        self.size += len(chunk)
        if len(self.head) < self._keep_limit:
            self.head.extend(chunk[: self._keep_limit - len(self.head)])
        return len(chunk)


def _detect_format(data_head: bytes, data_tail: bytes, ext: str) -> str:
    """Pick the right container format using head/tail bytes + extension."""
    if data_head.startswith(_VHDX_HEADER_COOKIE):
        return "vhdx"
    if data_tail[-512:].startswith(_VHD_FOOTER_COOKIE):
        return "vhd"
    # ISO 9660 / UDF Volume Descriptors sit at LBA 16 (offset 32768) and
    # carry an identifier in bytes 1..6.
    for off in (32768, 32768 + 2048, 32768 + 2048 * 2):
        if len(data_head) >= off + 7:
            ident = data_head[off + 1: off + 6]
            if ident in _ISO_SYNCS:
                return "iso"
    if ext in (".iso", ".img"):
        return "iso"  # speculative — let pycdlib confirm
    return "unknown"


def _vhd_metadata(footer: bytes) -> dict:
    """Parse the 512-byte VHD footer."""
    if len(footer) < 512 or not footer.startswith(_VHD_FOOTER_COOKIE):
        return {}
    try:
        cookie       = footer[0:8].decode("ascii", "replace")
        features     = struct.unpack(">I", footer[8:12])[0]
        ff_version   = struct.unpack(">I", footer[12:16])[0]
        data_offset  = struct.unpack(">Q", footer[16:24])[0]
        timestamp    = struct.unpack(">I", footer[24:28])[0]
        creator_app  = footer[28:32].decode("ascii", "replace")
        creator_ver  = struct.unpack(">I", footer[32:36])[0]
        creator_host = footer[36:40].decode("ascii", "replace")
        original_size = struct.unpack(">Q", footer[40:48])[0]
        current_size  = struct.unpack(">Q", footer[48:56])[0]
        cyl, heads, spt = struct.unpack(">HBB", footer[56:60])
        disk_type    = struct.unpack(">I", footer[60:64])[0]
        unique_id    = uuid.UUID(bytes=footer[68:84])
        disk_types = {0: "None", 2: "Fixed", 3: "Dynamic",
                      4: "Differencing"}
        return {
            "cookie": cookie,
            "features": hex(features),
            "format_version": hex(ff_version),
            "data_offset": data_offset,
            "epoch_seconds_since_2000": timestamp,
            "creator_application": creator_app.strip(),
            "creator_version": hex(creator_ver),
            "creator_host_os": creator_host.strip(),
            "original_size": original_size,
            "current_size": current_size,
            "disk_geometry": {"cylinders": cyl, "heads": heads, "sectors_per_track": spt},
            "disk_type_code": disk_type,
            "disk_type": disk_types.get(disk_type, f"unknown_{disk_type}"),
            "unique_id": str(unique_id),
        }
    except Exception as exc:
        log_error("", "disk_image_analyse.vhd", str(exc), severity="warning")
        return {}


def _vhdx_metadata(head: bytes) -> dict:
    """Parse the VHDX file identifier (offset 0) + creator string."""
    if not head.startswith(_VHDX_HEADER_COOKIE):
        return {}
    try:
        # Bytes 8..520 hold creator UTF-16LE
        creator_raw = head[8: 8 + 512]
        creator = creator_raw.decode("utf-16-le", "replace").rstrip("\x00")
        return {
            "cookie": "vhdxfile",
            "creator": creator.strip(),
        }
    except Exception as exc:
        log_error("", "disk_image_analyse.vhdx", str(exc), severity="warning")
        return {}


def _iso_volume_descriptor(data: bytes) -> dict:
    """Read the Primary Volume Descriptor at LBA 16 for quick metadata."""
    pvd_offset = 32768
    if len(data) < pvd_offset + 2048:
        return {}
    pvd = data[pvd_offset: pvd_offset + 2048]
    if pvd[1:6] != b"CD001":
        return {}
    try:
        system_id   = pvd[8:40].decode("ascii", "replace").strip()
        volume_id   = pvd[40:72].decode("ascii", "replace").strip()
        publisher   = pvd[318:446].decode("ascii", "replace").strip()
        data_prep   = pvd[446:574].decode("ascii", "replace").strip()
        application = pvd[574:702].decode("ascii", "replace").strip()
        return {
            "system_id": system_id,
            "volume_id": volume_id,
            "publisher_id": publisher,
            "data_preparer_id": data_prep,
            "application_id": application,
        }
    except Exception:
        return {}


def _list_iso(file_path: Path, case_id: str, image_name: str) -> dict:
    """Walk an ISO with pycdlib and return file list + extracted artefacts."""
    if not HAS_PYCDLIB:
        return {"status": "skipped", "reason": "pycdlib not installed", "entries": []}

    iso = pycdlib.PyCdlib()
    try:
        iso.open(str(file_path))
    except Exception as exc:
        return {"status": "error", "reason": str(exc), "entries": []}

    extract_root = (
        CASES_DIR / case_id / "artefacts" / "disk_images" / image_name
    )
    extract_root.mkdir(parents=True, exist_ok=True)

    entries: list[dict] = []

    facade = None
    for attr in ("get_udf_facade", "get_rock_ridge_facade",
                 "get_joliet_facade", "get_iso9660_facade"):
        try:
            facade = getattr(iso, attr)()
            break
        except Exception:
            facade = None
            continue
    if facade is None:
        try:
            iso.close()
        except Exception:
            pass
        return {"status": "error", "reason": "no usable ISO facade", "entries": []}

    try:
        for dirname, _subdirs, files in facade.walk("/"):
            for fname in files:
                iso_path = f"{dirname.rstrip('/')}/{fname}" if dirname != "/" else f"/{fname}"
                try:
                    sink = _HashingSink(_EXTRACT_THRESHOLD_BYTES)
                    facade.get_file_from_iso_fp(sink, iso_path=iso_path)
                except Exception as exc:
                    entries.append({
                        "iso_path": iso_path,
                        "error": str(exc),
                    })
                    continue

                ext = Path(fname).suffix.lower()
                entry = {
                    "iso_path": iso_path,
                    "size": sink.size,
                    "sha256": sink.sha256.hexdigest(),
                    "md5": sink.md5.hexdigest(),
                    "extension": ext,
                }
                # Extract small/interesting files only. Members within the
                # threshold are fully retained in the sink's head buffer.
                if sink.size <= _EXTRACT_THRESHOLD_BYTES and (
                    ext in _RISKY_EXTS or sink.size <= 1024 * 1024
                ):
                    safe_name = iso_path.lstrip("/").replace("/", "_") or "root"
                    dest = extract_root / safe_name
                    try:
                        write_artefact(dest, bytes(sink.head))
                        entry["extracted_path"] = str(dest)
                    except Exception as exc:
                        entry["extract_error"] = str(exc)
                entries.append(entry)
    finally:
        try:
            iso.close()
        except Exception:
            pass

    return {"status": "ok", "entries": entries}


def disk_image_analyse(file_path: str | Path, case_id: str) -> dict:
    """Analyse a disk-image carrier (.iso/.img/.vhd/.vhdx)."""
    file_path = Path(file_path)
    if not file_path.exists():
        return {"status": "error", "reason": f"file not found: {file_path}"}

    out_dir = CASES_DIR / case_id / "artefacts" / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    size = file_path.stat().st_size
    # Read just head + tail for format detection (full-load only when we walk it)
    with open(file_path, "rb") as fh:
        head = fh.read(min(size, 64 * 1024))
        if size > 1024:
            fh.seek(max(0, size - 1024))
            tail = fh.read()
        else:
            tail = head

    ext = file_path.suffix.lower()
    fmt = _detect_format(head, tail, ext)

    sha = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)

    result: dict = {
        "status": "ok",
        "filename": file_path.name,
        "source_path": str(file_path),
        "case_id": case_id,
        "ts": utcnow(),
        "file_size": size,
        "sha256": sha.hexdigest(),
        "format": fmt,
        "flags": [],
    }

    if fmt == "iso":
        # Need full data only for pycdlib; pass path directly
        iso_result = _list_iso(file_path, case_id, file_path.name)
        result["iso_listing"] = iso_result
        # Optionally surface PVD metadata
        # (read only the PVD slice — cheaper than the full file)
        with open(file_path, "rb") as fh:
            fh.seek(0)
            sample = fh.read(64 * 1024)
        result["iso_metadata"] = _iso_volume_descriptor(sample)

        risky_entries = [
            e for e in iso_result.get("entries", [])
            if e.get("extension") in _RISKY_EXTS
        ]
        if risky_entries:
            exts = sorted({e["extension"] for e in risky_entries})
            result["flags"].append(
                f"ISO_PAYLOADS: {len(risky_entries)} risky file(s) "
                f"{exts}"
            )
        if not iso_result.get("entries"):
            result["flags"].append("ISO_EMPTY_OR_UNREADABLE")

    elif fmt == "vhd":
        result["vhd_metadata"] = _vhd_metadata(tail[-512:])
        result["flags"].append("VHD_CONTAINER: filesystem must be mounted to inspect")
    elif fmt == "vhdx":
        result["vhdx_metadata"] = _vhdx_metadata(head[:8 + 512])
        result["flags"].append("VHDX_CONTAINER: filesystem must be mounted to inspect")
    else:
        result["status"] = "unsupported"
        result["reason"] = (
            f"unable to identify disk-image format from head/tail; "
            f"head_magic={head[:8].hex()}"
        )

    out_path = out_dir / f"{file_path.name}.disk_image_analysis.json"
    save_json(out_path, result)
    eprint(f"[disk_image_analyse] {file_path.name}: format={fmt}, "
           f"flags={len(result['flags'])}")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Disk-image carrier analysis.")
    parser.add_argument("file_path")
    parser.add_argument("--case", required=True, dest="case_id")
    args = parser.parse_args()

    out = disk_image_analyse(args.file_path, args.case_id)
    print(json.dumps(out, indent=2, default=str))
