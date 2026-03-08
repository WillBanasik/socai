"""
tool: memory_guidance
---------------------
Generate process memory dump collection guidance for analysts and analyse
dump files once collected.

Two modes:
  A) Guide — given alert context (process name, PID, alert details),
     produce step-by-step instructions for the analyst to collect a
     process memory dump via MDE Live Response.

  B) Analyse — read-only analysis of a collected procdump (.dmp) file.
     Extracts strings, IOCs (IPs, URLs, domains, hashes), DLL references,
     suspicious patterns (injection markers, shellcode signatures, encoded
     payloads), and produces a structured report.

Writes:
  cases/<case_id>/artefacts/memory/dump_guidance.md         (guide mode)
  cases/<case_id>/artefacts/memory/<dump_name>.analysis.json (analyse mode)
  cases/<case_id>/logs/mde_memory_dump.parsed.json          (analyse mode)
  cases/<case_id>/logs/mde_memory_dump.entities.json        (analyse mode)

Usage (standalone):
  python3 tools/memory_guidance.py guide --case C001 --process svchost.exe --pid 1234
  python3 tools/memory_guidance.py analyse --case C001 /path/to/process.dmp
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import log_error, save_json, utcnow, write_artefact

# ---------------------------------------------------------------------------
# IOC regex patterns
# ---------------------------------------------------------------------------

_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_URL = re.compile(r"https?://[^\s\"'<>]{5,}")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|top|"
    r"ru|cn|tk|ml|ga|cf|gq|cc|pw|club|online|site|icu|uk|de|fr|au|ca|in|br)\b",
    re.IGNORECASE,
)
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_RE_PATH_WIN = re.compile(r"[A-Za-z]:\\[\w\\\-. ]{4,}")
_RE_REGISTRY = re.compile(r"HKEY_[A-Z_]+\\[\w\\]+", re.IGNORECASE)

# Suspicious string patterns in memory dumps
_SUSPICIOUS_PATTERNS = [
    (re.compile(rb"VirtualAlloc", re.IGNORECASE), "VirtualAlloc (memory allocation)"),
    (re.compile(rb"VirtualProtect", re.IGNORECASE), "VirtualProtect (memory protection change)"),
    (re.compile(rb"CreateRemoteThread", re.IGNORECASE), "CreateRemoteThread (thread injection)"),
    (re.compile(rb"NtCreateThreadEx", re.IGNORECASE), "NtCreateThreadEx (thread injection)"),
    (re.compile(rb"WriteProcessMemory", re.IGNORECASE), "WriteProcessMemory (process injection)"),
    (re.compile(rb"ReadProcessMemory", re.IGNORECASE), "ReadProcessMemory (process memory read)"),
    (re.compile(rb"NtQueueApcThread", re.IGNORECASE), "NtQueueApcThread (APC injection)"),
    (re.compile(rb"RtlCreateUserThread", re.IGNORECASE), "RtlCreateUserThread (thread creation)"),
    (re.compile(rb"SetWindowsHookEx", re.IGNORECASE), "SetWindowsHookEx (hook injection)"),
    (re.compile(rb"LoadLibrary[AW]?", re.IGNORECASE), "LoadLibrary (DLL loading)"),
    (re.compile(rb"GetProcAddress", re.IGNORECASE), "GetProcAddress (API resolution)"),
    (re.compile(rb"WinExec", re.IGNORECASE), "WinExec (command execution)"),
    (re.compile(rb"ShellExecute[AW]?", re.IGNORECASE), "ShellExecute (command execution)"),
    (re.compile(rb"cmd\.exe", re.IGNORECASE), "cmd.exe reference"),
    (re.compile(rb"powershell", re.IGNORECASE), "PowerShell reference"),
    (re.compile(rb"mimikatz", re.IGNORECASE), "Mimikatz reference"),
    (re.compile(rb"Invoke-", re.IGNORECASE), "PowerShell Invoke- cmdlet"),
    (re.compile(rb"IEX\s*\(", re.IGNORECASE), "PowerShell IEX (Invoke-Expression)"),
    (re.compile(rb"FromBase64String", re.IGNORECASE), "Base64 decode operation"),
    (re.compile(rb"AmsiScanBuffer", re.IGNORECASE), "AMSI bypass indicator"),
    (re.compile(rb"EtwEventWrite", re.IGNORECASE), "ETW tampering indicator"),
    (re.compile(rb"\\\\\.\\pipe\\", re.IGNORECASE), "Named pipe access"),
    (re.compile(rb"net\s+user", re.IGNORECASE), "net user command"),
    (re.compile(rb"whoami", re.IGNORECASE), "whoami command"),
    (re.compile(rb"sekurlsa", re.IGNORECASE), "Mimikatz sekurlsa module"),
    (re.compile(rb"kerberos::", re.IGNORECASE), "Mimikatz kerberos module"),
    (re.compile(rb"lsadump::", re.IGNORECASE), "Mimikatz lsadump module"),
    (re.compile(rb"privilege::debug", re.IGNORECASE), "Mimikatz privilege escalation"),
    (re.compile(rb"\xfc\xe8", re.DOTALL), "Potential shellcode (call dword prologue)"),
    (re.compile(rb"\x4d\x5a"), "MZ header (embedded PE)"),
]

# DLL patterns of interest
_DLL_PATTERN = re.compile(rb"[\w\-]+\.dll", re.IGNORECASE)

# Known suspicious DLLs
_SUSPICIOUS_DLLS = {
    "clrjit.dll", "mscoree.dll",  # .NET — suspicious in non-.NET processes
    "amsi.dll",  # AMSI (may indicate bypass attempts)
    "dbghelp.dll", "dbgcore.dll",  # Debug (may indicate dump/injection)
    "winhttp.dll", "wininet.dll", "ws2_32.dll",  # Network (suspicious in non-network processes)
    "vaultcli.dll",  # Credential vault
    "samlib.dll",  # SAM access
    "ntdsapi.dll",  # Active Directory
    "winscard.dll",  # Smart card (credential theft)
}


# ---------------------------------------------------------------------------
# Guide generation
# ---------------------------------------------------------------------------

def generate_dump_guidance(
    case_id: str,
    *,
    process_name: str = "",
    pid: str | int = "",
    alert_title: str = "",
    alert_description: str = "",
    hostname: str = "",
) -> dict:
    """Generate analyst guidance for collecting a process memory dump.

    Args:
        case_id: Target case ID.
        process_name: Name of the suspicious process (e.g. svchost.exe).
        pid: Process ID to dump.
        alert_title: Title of the triggering alert.
        alert_description: Description of the triggering alert.
        hostname: Target hostname (for Live Response connection).

    Returns:
        Manifest dict with guidance file path.
    """
    mem_dir = CASES_DIR / case_id / "artefacts" / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)

    pid_str = str(pid) if pid else "<PID>"
    proc = process_name or "<process_name>"
    host = hostname or "<hostname>"

    guidance = f"""# Process Memory Dump Collection Guide

**Case:** {case_id}
**Generated:** {utcnow()}
"""

    if alert_title:
        guidance += f"**Alert:** {alert_title}\n"
    if alert_description:
        guidance += f"**Context:** {alert_description}\n"
    if process_name:
        guidance += f"**Target Process:** {process_name}\n"
    if pid:
        guidance += f"**Target PID:** {pid}\n"
    if hostname:
        guidance += f"**Target Host:** {hostname}\n"

    guidance += f"""
---

## Prerequisites

1. Ensure you have **Live Response** access enabled in your MDE tenant
2. Confirm the device is **online** and **connected** to Defender
3. Upload `procdump64.exe` to the Live Response library (if not already present)

## Option A: Using ProcDump via Live Response

### Step 1: Connect to the device

1. Navigate to **Devices** in the Microsoft Defender portal
2. Find device: **{host}**
3. Click **Initiate Live Response Session**

### Step 2: Upload ProcDump (first time only)

```
putfile procdump64.exe
```

### Step 3: Collect the process dump

**By PID** (recommended — more precise):
```
run procdump64.exe -ma {pid_str} -accepteula C:\\Windows\\Temp\\{proc}_{pid_str}.dmp
```

**By process name** (if PID is unknown or has changed):
```
run procdump64.exe -ma {proc} -accepteula C:\\Windows\\Temp\\{proc}.dmp
```

### Step 4: Verify and download

```
dir C:\\Windows\\Temp\\{proc}*.dmp
getfile C:\\Windows\\Temp\\{proc}_{pid_str}.dmp
```

### Step 5: Clean up

```
remediate file C:\\Windows\\Temp\\{proc}_{pid_str}.dmp
```

## Option B: Using built-in `memdump` (if available)

Some MDE tenants provide a built-in memory dump command:

```
memdump {pid_str} C:\\Windows\\Temp\\{proc}_{pid_str}.dmp
getfile C:\\Windows\\Temp\\{proc}_{pid_str}.dmp
```

> **Note:** The `memdump` command may not be available in all tenants.

## Option C: Investigation package (triage data, no full memory)

If Live Response is unavailable or you need a broader triage:

1. Go to the device page in the Microsoft Defender portal
2. Click **Collect investigation package**
3. Wait for collection to complete (check **Action center**)
4. Download the ZIP package

Then ingest it into socai:
```bash
python3 socai.py mde-package /path/to/investigation_package.zip --case {case_id}
```

## Important Notes

- **Dump size:** Full process dumps can be large (100 MB – several GB for memory-intensive processes). Ensure sufficient disk space on the target.
- **Impact:** ProcDump briefly suspends the target process during dump creation. For critical services, coordinate with the system owner.
- **Evidence handling:** Record the SHA-256 hash of the dump file before analysis. socai will do this automatically during ingest.
- **Time sensitivity:** Memory is volatile — collect the dump as soon as possible after the alert fires. Process restarts will lose all in-memory evidence.

## After Collection

Once you have the .dmp file, analyse it with socai:

```bash
python3 socai.py memory-analyse /path/to/{proc}_{pid_str}.dmp --case {case_id}
```

This will extract strings, IOCs, DLL references, and flag suspicious patterns
(injection markers, shellcode, credential theft indicators).
"""

    write_artefact(mem_dir / "dump_guidance.md", guidance.encode("utf-8"))

    manifest = {
        "status": "ok",
        "case_id": case_id,
        "ts": utcnow(),
        "guidance_path": str(mem_dir / "dump_guidance.md"),
        "target_process": process_name,
        "target_pid": str(pid),
        "target_host": hostname,
    }

    save_json(mem_dir / "guidance_manifest.json", manifest)

    print(f"[memory] Guidance written: {mem_dir / 'dump_guidance.md'}")
    return manifest


# ---------------------------------------------------------------------------
# Dump analysis
# ---------------------------------------------------------------------------

def _extract_strings(data: bytes, min_length: int = 6) -> list[str]:
    """Extract ASCII and wide (UTF-16LE) strings from binary data."""
    strings = set()

    # ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    for match in ascii_pattern.finditer(data):
        try:
            s = match.group().decode("ascii")
            strings.add(s)
        except Exception:
            continue

    # UTF-16LE strings (Windows wide strings)
    wide_pattern = re.compile(
        rb"(?:[\x20-\x7e]\x00){%d,}" % min_length
    )
    for match in wide_pattern.finditer(data):
        try:
            s = match.group().decode("utf-16-le").rstrip("\x00")
            if s and len(s) >= min_length:
                strings.add(s)
        except Exception:
            continue

    return sorted(strings)


def _find_pe_headers(data: bytes) -> list[dict]:
    """Find embedded PE (MZ) headers in the dump — potential injected executables."""
    headers = []
    offset = 0
    while True:
        idx = data.find(b"\x4d\x5a", offset)
        if idx == -1:
            break
        # Check for valid PE signature
        try:
            if idx + 0x40 < len(data):
                pe_offset = struct.unpack_from("<I", data, idx + 0x3c)[0]
                if idx + pe_offset + 4 < len(data):
                    sig = data[idx + pe_offset:idx + pe_offset + 4]
                    if sig == b"PE\x00\x00":
                        headers.append({
                            "offset": hex(idx),
                            "pe_offset": hex(pe_offset),
                            "valid_pe_signature": True,
                        })
        except (struct.error, IndexError):
            pass
        offset = idx + 2
        # Limit to first 50 to avoid noise
        if len(headers) >= 50:
            break
    return headers


def analyse_memory_dump(
    dump_path: str | Path,
    case_id: str,
) -> dict:
    """Analyse a process memory dump file (read-only).

    Extracts strings, IOCs, DLL references, and suspicious patterns.

    Args:
        dump_path: Path to the .dmp file.
        case_id: Target case ID.

    Returns:
        Analysis manifest dict.
    """
    source = Path(dump_path)
    if not source.exists():
        return {"status": "error", "reason": f"Dump file not found: {dump_path}"}

    mem_dir = CASES_DIR / case_id / "artefacts" / "memory"
    logs_dir = CASES_DIR / case_id / "logs"
    mem_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    print(f"[memory] Analysing {source.name} ({source.stat().st_size / (1024*1024):.1f} MB)...")

    try:
        data = source.read_bytes()
    except Exception as exc:
        log_error(case_id, "memory_analyse.read", str(exc), severity="error",
                  context={"file": str(source)})
        return {"status": "error", "reason": f"Failed to read dump: {exc}"}

    # Extract strings
    print("[memory] Extracting strings...")
    strings = _extract_strings(data)

    # Extract IOCs from strings
    all_text = "\n".join(strings)
    ips = sorted(set(_RE_IP.findall(all_text)))
    urls = sorted(set(_RE_URL.findall(all_text)))
    domains = sorted(set(_RE_DOMAIN.findall(all_text)))
    emails = sorted(set(_RE_EMAIL.findall(all_text)))
    file_paths = sorted(set(_RE_PATH_WIN.findall(all_text)))
    registry_keys = sorted(set(_RE_REGISTRY.findall(all_text)))

    # Hashes (only if they look like standalone hashes, not substrings)
    sha256_candidates = set(_RE_SHA256.findall(all_text))
    sha1_candidates = set(_RE_SHA1.findall(all_text)) - sha256_candidates
    md5_candidates = set(_RE_MD5.findall(all_text)) - sha1_candidates - sha256_candidates

    # DLL references
    print("[memory] Scanning for DLL references...")
    dll_matches = set()
    for m in _DLL_PATTERN.finditer(data):
        try:
            dll_name = m.group().decode("ascii").lower()
            dll_matches.add(dll_name)
        except Exception:
            continue

    suspicious_dlls = sorted(dll_matches & _SUSPICIOUS_DLLS)
    all_dlls = sorted(dll_matches)

    # Suspicious patterns
    print("[memory] Scanning for suspicious patterns...")
    suspicious_findings = []
    for pattern, description in _SUSPICIOUS_PATTERNS:
        matches = list(pattern.finditer(data))
        if matches:
            suspicious_findings.append({
                "pattern": description,
                "count": len(matches),
                "first_offset": hex(matches[0].start()),
            })

    # Embedded PE headers
    print("[memory] Scanning for embedded PE headers...")
    pe_headers = _find_pe_headers(data)

    # Build analysis result
    analysis = {
        "status": "ok",
        "case_id": case_id,
        "ts": utcnow(),
        "source": str(source),
        "dump_size_bytes": len(data),
        "dump_size_mb": round(len(data) / (1024 * 1024), 2),
        "strings_extracted": len(strings),
        "iocs": {
            "ips": ips,
            "urls": urls,
            "domains": domains,
            "emails": emails,
            "md5": sorted(md5_candidates),
            "sha1": sorted(sha1_candidates),
            "sha256": sorted(sha256_candidates),
            "file_paths": file_paths[:200],  # cap to avoid noise
            "registry_keys": registry_keys[:100],
        },
        "dlls": {
            "all": all_dlls,
            "suspicious": suspicious_dlls,
            "total": len(all_dlls),
        },
        "suspicious_patterns": suspicious_findings,
        "embedded_pe_headers": pe_headers,
        "risk_indicators": _assess_risk(suspicious_findings, pe_headers, suspicious_dlls),
    }

    # Write analysis JSON
    save_json(mem_dir / f"{source.stem}.analysis.json", analysis)

    # Write normalised log for downstream tools
    log_rows = []
    for finding in suspicious_findings:
        log_rows.append({
            "TimeCreated": utcnow(),
            "ProcessName": source.stem,
            "Pattern": finding["pattern"],
            "Count": finding["count"],
            "Offset": finding["first_offset"],
            "_source": "mde",
            "_artefact": "memory_dump",
        })

    entities = {
        "ips": ips,
        "urls": urls,
        "domains": domains,
        "processes": [source.stem],
        "file_paths": file_paths[:50],
        "commands": [],
        "users": [],
        "timestamps": [],
    }

    log_result = {
        "source_file": f"mde:memory_dump:{source.name}",
        "case_id": case_id,
        "format": "binary_analysis",
        "ts": utcnow(),
        "row_count": len(log_rows),
        "entities": entities,
        "entity_totals": {k: len(v) for k, v in entities.items()},
        "rows_sample": log_rows,
    }

    write_artefact(logs_dir / "mde_memory_dump.parsed.json",
                   json.dumps(log_result, indent=2, default=str))
    write_artefact(logs_dir / "mde_memory_dump.entities.json",
                   json.dumps(entities, indent=2))

    # Print summary
    print(f"[memory] Strings: {len(strings)}")
    print(f"[memory] IPs: {len(ips)}, URLs: {len(urls)}, Domains: {len(domains)}")
    print(f"[memory] DLLs: {len(all_dlls)} total, {len(suspicious_dlls)} suspicious")
    print(f"[memory] Suspicious patterns: {len(suspicious_findings)}")
    print(f"[memory] Embedded PE headers: {len(pe_headers)}")

    risk = analysis["risk_indicators"]
    if risk["level"] != "low":
        print(f"[memory] Risk: {risk['level'].upper()} — {'; '.join(risk['reasons'])}")

    return analysis


def _assess_risk(
    suspicious_findings: list[dict],
    pe_headers: list[dict],
    suspicious_dlls: list[str],
) -> dict:
    """Assess overall risk level from memory analysis findings."""
    score = 0
    reasons = []

    # Injection indicators
    injection_patterns = {
        "CreateRemoteThread", "WriteProcessMemory", "NtCreateThreadEx",
        "NtQueueApcThread", "RtlCreateUserThread", "SetWindowsHookEx",
    }
    found_injection = [f for f in suspicious_findings
                       if any(p in f["pattern"] for p in injection_patterns)]
    if found_injection:
        score += 3
        reasons.append(f"{len(found_injection)} injection indicator(s)")

    # Credential theft
    cred_patterns = {"Mimikatz", "sekurlsa", "kerberos::", "lsadump::", "privilege::debug"}
    found_cred = [f for f in suspicious_findings
                  if any(p in f["pattern"] for p in cred_patterns)]
    if found_cred:
        score += 4
        reasons.append(f"{len(found_cred)} credential theft indicator(s)")

    # Shellcode / embedded PE
    if pe_headers:
        score += 2
        reasons.append(f"{len(pe_headers)} embedded PE header(s)")

    shellcode = [f for f in suspicious_findings if "shellcode" in f["pattern"].lower()]
    if shellcode:
        score += 3
        reasons.append("Potential shellcode detected")

    # AMSI/ETW bypass
    bypass = [f for f in suspicious_findings
              if "AMSI" in f["pattern"] or "ETW" in f["pattern"]]
    if bypass:
        score += 2
        reasons.append("Defence evasion indicators (AMSI/ETW)")

    # Suspicious DLLs
    if suspicious_dlls:
        score += 1
        reasons.append(f"{len(suspicious_dlls)} suspicious DLL(s): {', '.join(suspicious_dlls[:5])}")

    # PowerShell
    ps_patterns = {"PowerShell", "Invoke-", "IEX", "FromBase64String"}
    found_ps = [f for f in suspicious_findings
                if any(p in f["pattern"] for p in ps_patterns)]
    if found_ps:
        score += 1
        reasons.append("PowerShell execution indicators")

    if score >= 5:
        level = "critical"
    elif score >= 3:
        level = "high"
    elif score >= 1:
        level = "medium"
    else:
        level = "low"

    return {"level": level, "score": score, "reasons": reasons}


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Memory dump guidance and analysis.")
    sub = p.add_subparsers(dest="mode", required=True)

    # Guide mode
    p_guide = sub.add_parser("guide", help="Generate collection guidance.")
    p_guide.add_argument("--case", required=True, dest="case_id")
    p_guide.add_argument("--process", default="", help="Target process name")
    p_guide.add_argument("--pid", default="", help="Target PID")
    p_guide.add_argument("--alert", default="", help="Alert title for context")
    p_guide.add_argument("--host", default="", help="Target hostname")

    # Analyse mode
    p_analyse = sub.add_parser("analyse", help="Analyse a memory dump.")
    p_analyse.add_argument("target", help="Path to .dmp file")
    p_analyse.add_argument("--case", required=True, dest="case_id")

    args = p.parse_args()

    if args.mode == "guide":
        result = generate_dump_guidance(
            args.case_id,
            process_name=args.process,
            pid=args.pid,
            alert_title=args.alert,
            hostname=args.host,
        )
    else:
        result = analyse_memory_dump(args.target, args.case_id)

    print(json.dumps(result, indent=2, default=str))
