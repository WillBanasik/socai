"""
tool: lnk_analyse
-----------------
Parse Windows shell link (.lnk) files. LNK abuse is a common initial-access
technique (ISO/ZIP delivery, drive-by, USB) — the parsed target path,
command-line arguments, and host metadata (machine ID, MAC, drive serial)
are usually enough on their own to characterise the lure.

Writes:
  cases/<case_id>/artefacts/analysis/<filename>.lnk_analysis.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import eprint, log_error, save_json, utcnow

try:
    import LnkParse3
    HAS_LNKPARSE = True
except ImportError:
    HAS_LNKPARSE = False


_LLM_SYSTEM_PROMPT = (
    "You are a malware analyst reviewing a parsed Windows shell link (.lnk). "
    "Given target path, arguments, working directory, icon, and host metadata, "
    "assess:\n"
    "- Verdict: malicious / suspicious / clean\n"
    "- Confidence: high / medium / low\n"
    "- Likely role: living-off-the-land launcher, payload pointer, USB lure, decoy\n"
    "- IOCs: launched binary, arguments containing URLs/commands\n"
    "Only make claims supported by the supplied data."
)


_LOLBINS = {
    "powershell.exe", "powershell_ise.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "msiexec.exe", "installutil.exe", "bitsadmin.exe", "certutil.exe",
    "curl.exe", "wget.exe", "forfiles.exe", "schtasks.exe",
    "wmic.exe", "wmiprvse.exe", "msbuild.exe",
}


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _pick(d: dict, *paths: tuple[str, ...]) -> str:
    """Pluck nested dict values; returns first non-empty as str."""
    for path in paths:
        cur = d
        ok = True
        for key in path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                ok = False
                break
        if ok and cur not in (None, "", [], {}):
            return str(cur)
    return ""


def lnk_analyse(file_path: str | Path, case_id: str) -> dict:
    """Parse a .lnk file and persist the manifest under the case."""
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
        "flags": [],
    }

    if not HAS_LNKPARSE:
        result["status"] = "skipped"
        result["reason"] = "LnkParse3 not installed"
        log_error(case_id, "lnk_analyse", "LnkParse3 missing", severity="warning")
        save_json(out_dir / f"{filename}.lnk_analysis.json", result)
        return result

    try:
        with open(file_path, "rb") as fh:
            parsed = LnkParse3.lnk_file(fh).get_json()
    except Exception as exc:
        log_error(case_id, "lnk_analyse.parse", str(exc),
                  severity="warning", context={"file": str(file_path)})
        result["status"] = "error"
        result["parse_error"] = str(exc)
        save_json(out_dir / f"{filename}.lnk_analysis.json", result)
        return result

    result["parsed"] = parsed

    # ---- Common fields surfaced for analyst convenience ------------------
    data_block = parsed.get("data", {}) if isinstance(parsed, dict) else {}
    link_info = parsed.get("link_info", {}) if isinstance(parsed, dict) else {}
    target = parsed.get("target", {}) if isinstance(parsed, dict) else {}
    header = parsed.get("header", {}) if isinstance(parsed, dict) else {}
    extra = parsed.get("extra", {}) if isinstance(parsed, dict) else {}

    command_line = _pick(parsed, ("data", "command_line_arguments"))
    relative_path = _pick(parsed, ("data", "relative_path"))
    working_dir = _pick(parsed, ("data", "working_directory"))
    icon = _pick(parsed, ("data", "icon_location"))
    description = _pick(parsed, ("data", "description"))
    local_base = _pick(parsed, ("link_info", "local_base_path"))
    common_path = _pick(parsed, ("link_info", "common_path_suffix"))
    target_path = local_base or relative_path or _pick(parsed, ("link_info", "local_base_path_unicode"))

    result["target"] = {
        "path": target_path,
        "arguments": command_line,
        "working_directory": working_dir,
        "icon_location": icon,
        "description": description,
        "common_path_suffix": common_path,
    }

    # Tracker / distributed link metadata (machine ID, MAC, droid IDs)
    tdb = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") if isinstance(extra, dict) else None
    if isinstance(tdb, dict):
        result["distributed_link_tracker"] = {
            "machine_id": tdb.get("machine_identifier"),
            "droid_birth_volume": tdb.get("droid_birth_volume"),
            "droid_birth_file": tdb.get("droid_birth_file"),
            "droid_volume": tdb.get("droid_volume"),
            "droid_file": tdb.get("droid_file"),
        }

    # Volume metadata (drive type / serial)
    vol_info = link_info.get("volume_information") if isinstance(link_info, dict) else None
    if isinstance(vol_info, dict):
        result["volume"] = {
            "drive_type": vol_info.get("drive_type"),
            "drive_serial": vol_info.get("drive_serial_number"),
            "volume_label": vol_info.get("volume_label"),
        }

    # Header timestamps
    result["header_timestamps"] = {
        "creation": header.get("creation_time"),
        "access":   header.get("access_time"),
        "write":    header.get("write_time"),
        "target_file_size": header.get("file_size"),
    }

    # ---- Flags -----------------------------------------------------------
    flags = result["flags"]
    basename = _basename(target_path)
    if basename in _LOLBINS:
        flags.append(f"LOLBIN_TARGET: launches {basename}")
    if command_line:
        flags.append(
            f"ARGUMENTS: {len(command_line)} chars of command-line input"
        )
        low = command_line.lower()
        if any(ind in low for ind in ("http://", "https://", "ftp://")):
            flags.append("ARGUMENTS: contains URL")
        if any(ind in low for ind in (
                "-enc", "-encodedcommand", "-nop", "-w hidden",
                "frombase64string", "downloadstring", "iex ", "invoke-expression",
        )):
            flags.append("ARGUMENTS: PowerShell evasion / download cradle")
        if any(ind in low for ind in ("cmd /c", "cmd.exe /c", "/c ")):
            flags.append("ARGUMENTS: invokes cmd /c (chained command)")
    if icon and any(ext in icon.lower()
                    for ext in (".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt")):
        flags.append(f"ICON_SPOOFING: icon path suggests document ({icon})")
    if isinstance(target, dict) and target.get("size") == 0 and command_line:
        flags.append("NO_TARGET_FILE: shortcut runs args without a real target")

    out_path = out_dir / f"{filename}.lnk_analysis.json"
    save_json(out_path, result)
    eprint(f"[lnk_analyse] {filename}: target={basename or '?'}, "
           f"args={'yes' if command_line else 'no'}, flags={len(flags)}")
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parse a Windows shell link (.lnk).")
    parser.add_argument("file_path")
    parser.add_argument("--case", required=True, dest="case_id")
    args = parser.parse_args()

    out = lnk_analyse(args.file_path, args.case_id)
    print(json.dumps(out, indent=2, default=str))
