"""
tool: memory_volatility
-----------------------
Volatility3 wrapper for deep memory-dump analysis.

Runs a curated set of plugins (pslist, psscan, netscan/netstat, cmdline,
malfind, svcscan) against the dump, normalises their JSON output, and
collates IOCs / suspicious findings into one manifest.

OS detection is automatic: Windows plugins are tried first; if they all
produce no rows, Linux and macOS plugin families are attempted.

The Volatility3 CLI (`vol`) is invoked via subprocess — this is the most
robust way to call Volatility3 from another process because Volatility3
itself imports plugins lazily and mutates the process-wide framework
state. Subprocess isolation avoids polluting the MCP server's runtime.

Writes:
  cases/<case_id>/artefacts/memory/<dump>.volatility.json
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import eprint, log_error, save_json, utcnow


_LLM_SYSTEM_PROMPT = (
    "You are a memory-forensics analyst reviewing Volatility3 output. Given "
    "process lists, network connections, command lines, service info, and "
    "injection findings (malfind), assess:\n"
    "- Verdict: malicious / suspicious / clean\n"
    "- Active threats: which PIDs / processes look hostile and why\n"
    "- Lateral / C2 evidence: external connections, named-pipe abuse\n"
    "- Recommended next step (kill PID, isolate host, deeper plugin)\n"
    "Only make claims supported by the supplied data."
)


# Default plugin set, grouped by OS. Order matters — pslist first so we can
# bail out early if the dump is the wrong OS.
PLUGIN_SETS: dict[str, list[str]] = {
    "windows": [
        "windows.pslist.PsList",
        "windows.psscan.PsScan",
        "windows.cmdline.CmdLine",
        "windows.netscan.NetScan",
        "windows.netstat.NetStat",
        "windows.malfind.Malfind",
        "windows.svcscan.SvcScan",
        "windows.dlllist.DllList",
        "windows.modules.Modules",
    ],
    "linux": [
        "linux.pslist.PsList",
        "linux.pstree.PsTree",
        "linux.bash.Bash",
        "linux.lsof.Lsof",
        "linux.malfind.Malfind",
    ],
    "mac": [
        "mac.pslist.PsList",
        "mac.psaux.Psaux",
        "mac.lsof.Lsof",
        "mac.malfind.Malfind",
    ],
}


# Plugins that are large/slow; skip unless full=True.
_HEAVY_PLUGINS = {
    "windows.dlllist.DllList",
    "windows.modules.Modules",
    "windows.handles.Handles",
}


def _vol_executable() -> str | None:
    """Locate the Volatility3 CLI."""
    return shutil.which("vol") or shutil.which("vol.py") or shutil.which("volatility")


def _run_plugin(
    vol: str, dump_path: str, plugin: str, timeout: int
) -> dict:
    """Run a single Volatility plugin, return its parsed JSON output."""
    cmd = [vol, "-q", "-f", dump_path, "-r", "json", plugin]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "plugin": plugin, "timeout_seconds": timeout}
    except Exception as exc:
        return {"status": "error", "plugin": plugin, "error": str(exc)}

    if proc.returncode != 0:
        return {
            "status": "error",
            "plugin": plugin,
            "returncode": proc.returncode,
            "stderr": proc.stderr.strip()[:1000],
        }

    raw = (proc.stdout or "").strip()
    if not raw:
        return {"status": "ok", "plugin": plugin, "rows": []}

    try:
        rows = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "status": "parse_error",
            "plugin": plugin,
            "error": str(exc),
            "stdout_head": raw[:500],
        }

    return {"status": "ok", "plugin": plugin, "row_count": len(rows), "rows": rows}


def _has_rows(plugin_result: dict) -> bool:
    return plugin_result.get("status") == "ok" and plugin_result.get("row_count", 0) > 0


def _detect_os(vol: str, dump_path: str, timeout: int) -> str | None:
    """Try each OS family's pslist; return the OS that returns rows."""
    for os_name in ("windows", "linux", "mac"):
        plugin = PLUGIN_SETS[os_name][0]
        eprint(f"[memory_vol] OS probe: {plugin}")
        result = _run_plugin(vol, dump_path, plugin, timeout)
        if _has_rows(result):
            return os_name
    return None


def _summarise_findings(plugin_results: dict[str, dict]) -> dict:
    """Pull headline IOCs / risk indicators across the plugin output."""
    process_count = plugin_results.get("windows.pslist.PsList", {}).get("row_count", 0) \
        or plugin_results.get("linux.pslist.PsList", {}).get("row_count", 0) \
        or plugin_results.get("mac.pslist.PsList", {}).get("row_count", 0)

    # Network connections
    network_endpoints: list[dict] = []
    for plugin in ("windows.netscan.NetScan", "windows.netstat.NetStat"):
        for row in plugin_results.get(plugin, {}).get("rows", []) or []:
            ent = {
                "pid": row.get("PID"),
                "process": row.get("Owner") or row.get("Process"),
                "local": f"{row.get('LocalAddr', '')}:{row.get('LocalPort', '')}",
                "remote": f"{row.get('ForeignAddr', '')}:{row.get('ForeignPort', '')}",
                "state": row.get("State"),
                "proto": row.get("Proto"),
            }
            network_endpoints.append(ent)

    # Malfind hits — injected/suspicious memory regions
    malfind_hits: list[dict] = []
    for plugin in ("windows.malfind.Malfind", "linux.malfind.Malfind", "mac.malfind.Malfind"):
        for row in plugin_results.get(plugin, {}).get("rows", []) or []:
            malfind_hits.append({
                "pid": row.get("PID"),
                "process": row.get("Process"),
                "start_vpn": row.get("Start VPN"),
                "protection": row.get("Protection"),
                "tag": row.get("Tag"),
                "notes": row.get("Notes"),
            })

    # Suspicious command lines (PowerShell encoded, rundll32, mshta, certutil)
    suspicious_cmd: list[dict] = []
    cmdline_rows = plugin_results.get("windows.cmdline.CmdLine", {}).get("rows", []) or []
    triggers = (
        "powershell -enc", "powershell -e ", "-encodedcommand",
        "rundll32", "mshta", "certutil -urlcache", "bitsadmin", "regsvr32 /i",
        "frombase64string", "downloadstring", "iex(", "iex ",
        "schtasks /create", "wmic process call create",
    )
    for row in cmdline_rows:
        cmd = (row.get("Args") or "").lower()
        if any(t in cmd for t in triggers):
            suspicious_cmd.append({
                "pid": row.get("PID"),
                "process": row.get("Process"),
                "args": row.get("Args"),
            })

    return {
        "process_count": process_count,
        "network_endpoints": network_endpoints,
        "external_connections": [
            e for e in network_endpoints
            if (e["remote"] or "").split(":")[0]
            not in ("", "0.0.0.0", "127.0.0.1", "::", "::1")
        ],
        "malfind_hits": malfind_hits,
        "suspicious_cmdlines": suspicious_cmd,
    }


def analyse_memory_volatility(
    dump_path: str | Path,
    case_id: str,
    *,
    full: bool = False,
    per_plugin_timeout_seconds: int = 600,
) -> dict:
    """Run Volatility3 plugins against ``dump_path`` and persist results.

    Args:
        dump_path: Path to the memory dump.
        case_id:   Target case (output is stored under the case).
        full:      Include heavy plugins (DllList, Modules) too.
        per_plugin_timeout_seconds: Kill any single plugin after this long.

    Returns:
        Manifest dict containing per-plugin output + summarised IOCs.
    """
    dump = Path(dump_path)
    if not dump.exists():
        return {"status": "error", "reason": f"dump not found: {dump_path}"}

    vol = _vol_executable()
    if vol is None:
        log_error(case_id, "memory_volatility",
                  "volatility3 CLI ('vol') not found on PATH",
                  severity="warning")
        return {
            "status": "skipped",
            "reason": "volatility3 not installed (no 'vol' on PATH)",
        }

    out_dir = CASES_DIR / case_id / "artefacts" / "memory"
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict = {
        "status": "ok",
        "case_id": case_id,
        "ts": utcnow(),
        "dump_path": str(dump),
        "dump_size_bytes": dump.stat().st_size,
        "vol_executable": vol,
        "per_plugin_timeout_seconds": per_plugin_timeout_seconds,
        "full": full,
        "detected_os": None,
        "plugin_results": {},
        "summary": {},
    }

    detected_os = _detect_os(vol, str(dump), per_plugin_timeout_seconds)
    if detected_os is None:
        manifest["status"] = "os_unknown"
        manifest["reason"] = (
            "could not identify OS family — pslist returned no rows for "
            "Windows, Linux or macOS. The dump may be corrupted, encrypted, "
            "or in an unsupported format."
        )
        save_json(out_dir / f"{dump.stem}.volatility.json", manifest)
        return manifest

    manifest["detected_os"] = detected_os
    plugins = PLUGIN_SETS[detected_os]
    if not full:
        plugins = [p for p in plugins if p not in _HEAVY_PLUGINS]

    for plugin in plugins:
        eprint(f"[memory_vol] running {plugin}…")
        result = _run_plugin(vol, str(dump), plugin, per_plugin_timeout_seconds)
        manifest["plugin_results"][plugin] = result

    manifest["summary"] = _summarise_findings(manifest["plugin_results"])

    # ---- Flags -----------------------------------------------------------
    flags: list[str] = []
    summary = manifest["summary"]
    if summary["malfind_hits"]:
        flags.append(
            f"MALFIND: {len(summary['malfind_hits'])} injected region(s)"
        )
    if summary["suspicious_cmdlines"]:
        flags.append(
            f"LOLBIN_CMDLINES: {len(summary['suspicious_cmdlines'])} "
            f"suspicious command line(s)"
        )
    if len(summary["external_connections"]) > 0:
        flags.append(
            f"EXTERNAL_CONNECTIONS: {len(summary['external_connections'])} "
            f"outbound endpoint(s)"
        )
    manifest["flags"] = flags

    out_path = out_dir / f"{dump.stem}.volatility.json"
    save_json(out_path, manifest)

    eprint(f"[memory_vol] OS={detected_os}, "
           f"plugins={len(manifest['plugin_results'])}, "
           f"processes={summary.get('process_count', 0)}, "
           f"malfind={len(summary['malfind_hits'])}, "
           f"flags={len(flags)}")
    return manifest


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Volatility3 memory analysis.")
    parser.add_argument("dump_path")
    parser.add_argument("--case", required=True, dest="case_id")
    parser.add_argument("--full", action="store_true",
                        help="Include heavy plugins (DllList, Modules).")
    parser.add_argument("--plugin-timeout", type=int, default=600,
                        help="Per-plugin timeout in seconds (default 600).")
    args = parser.parse_args()

    out = analyse_memory_volatility(
        args.dump_path,
        args.case_id,
        full=args.full,
        per_plugin_timeout_seconds=args.plugin_timeout,
    )
    print(json.dumps(out, indent=2, default=str))
