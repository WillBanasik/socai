"""
tool: extract_zip
-----------------
Extracts a (optionally password-protected) ZIP archive into
cases/<case_id>/artefacts/zip/<zip_stem>/

Produces:
  - hash_manifest.json  – SHA-256 of every extracted file
  - strings/            – raw strings output for each extracted file
  - extraction_log.json – timing, entry count, errors
"""
from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR, STRINGS_MIN_LEN
from tools.common import log_error, sha256_file, utcnow, write_artefact


def _extract_strings(file_path: Path, min_len: int = STRINGS_MIN_LEN) -> str:
    """
    Extract printable ASCII/Unicode strings from a binary file.
    Uses the system 'strings' command if available, else Python fallback.
    """
    try:
        result = subprocess.run(
            ["strings", f"-n{min_len}", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout
    except FileNotFoundError:
        # Python fallback
        import re

        raw = file_path.read_bytes()
        ascii_str = re.findall(rb"[ -~]{%d,}" % min_len, raw)
        uni_str = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, raw)
        parts = [s.decode("ascii", errors="ignore") for s in ascii_str]
        parts += [s.decode("utf-16-le", errors="ignore") for s in uni_str]
        return "\n".join(parts)


def extract_zip(
    zip_path: str | Path,
    case_id: str,
    password: str | None = None,
) -> dict:
    """
    Extract *zip_path* into the case artefacts folder.
    Returns a manifest dict.
    """
    zip_path = Path(zip_path)
    stem = zip_path.stem
    out_dir = CASES_DIR / case_id / "artefacts" / "zip" / stem
    strings_dir = out_dir / "strings"
    out_dir.mkdir(parents=True, exist_ok=True)
    strings_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "source_zip": str(zip_path),
        "source_sha256": sha256_file(zip_path) if zip_path.exists() else "N/A",
        "case_id": case_id,
        "ts": utcnow(),
        "files": [],
        "errors": [],
    }

    pwd_bytes = password.encode() if password else None

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for entry in zf.infolist():
                if entry.is_dir():
                    continue
                dest = out_dir / entry.filename
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    data = zf.read(entry.filename, pwd=pwd_bytes)
                    dest.write_bytes(data)
                    digest = sha256_file(dest)
                    audit("extract_file", str(dest), sha256=digest,
                          extra={"case_id": case_id, "source_zip": str(zip_path)})

                    # Strings extraction
                    str_out = _extract_strings(dest)
                    str_path = strings_dir / (entry.filename.replace("/", "_") + ".strings.txt")
                    write_artefact(str_path, str_out)

                    manifest["files"].append({
                        "name": entry.filename,
                        "size_bytes": len(data),
                        "sha256": digest,
                        "strings_path": str(str_path),
                    })
                except Exception as e:
                    log_error(case_id, "extract_zip.entry", str(e),
                              severity="warning", context={"entry": entry.filename, "zip": str(zip_path)})
                    manifest["errors"].append({"entry": entry.filename, "error": str(e)})

    except zipfile.BadZipFile as e:
        log_error(case_id, "extract_zip.bad_zip", str(e),
                  context={"zip": str(zip_path)})
        manifest["errors"].append({"entry": str(zip_path), "error": f"BadZipFile: {e}"})

    write_artefact(out_dir / "hash_manifest.json", json.dumps(manifest, indent=2))
    print(f"[extract_zip] Extracted {len(manifest['files'])} file(s) to {out_dir}")
    return manifest


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Extract a ZIP for a case.")
    p.add_argument("zip_path")
    p.add_argument("--case", required=True, dest="case_id")
    p.add_argument("--password", default=None)
    args = p.parse_args()

    result = extract_zip(args.zip_path, args.case_id, args.password)
    print(json.dumps(result, indent=2))
