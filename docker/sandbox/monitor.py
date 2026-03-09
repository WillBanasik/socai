#!/usr/bin/env python3
"""
monitor.py — in-container telemetry daemon for socai sandbox.

Produces structured telemetry from:
  - Process tree polling (/proc)
  - Filesystem event watching (inotifywait)
  - Strace log parsing (post-execution)
  - Network capture parsing (post-execution)
  - System change detection (post-execution)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

TELEMETRY = Path("/sandbox/telemetry")
WORKSPACE = Path("/sandbox/workspace")
POLL_INTERVAL = 0.5  # seconds for process tree polling


def utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Process tree polling
# ---------------------------------------------------------------------------

def poll_process_tree(output_path: Path) -> None:
    """Poll /proc every POLL_INTERVAL and record process creation/state."""
    seen_pids: set = set()
    with open(output_path, "a") as fh:
        while not (TELEMETRY / "execution_complete").exists():
            try:
                for entry in os.listdir("/proc"):
                    if not entry.isdigit():
                        continue
                    pid = int(entry)
                    if pid in seen_pids:
                        continue
                    seen_pids.add(pid)
                    try:
                        cmdline_raw = Path(f"/proc/{pid}/cmdline").read_bytes()
                        cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                        exe = os.readlink(f"/proc/{pid}/exe")
                    except (FileNotFoundError, PermissionError, OSError):
                        cmdline = ""
                        exe = ""
                    if not cmdline:
                        continue
                    try:
                        ppid_line = Path(f"/proc/{pid}/status").read_text()
                        ppid_match = re.search(r"PPid:\s+(\d+)", ppid_line)
                        ppid = int(ppid_match.group(1)) if ppid_match else 0
                    except (FileNotFoundError, PermissionError, OSError):
                        ppid = 0
                    record = {
                        "ts": utcnow(),
                        "pid": pid,
                        "ppid": ppid,
                        "exe": exe,
                        "cmdline": cmdline,
                    }
                    fh.write(json.dumps(record) + "\n")
                    fh.flush()
            except Exception:
                pass
            time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Filesystem watching
# ---------------------------------------------------------------------------

def watch_filesystem(events_path: Path, dropped_dir: Path) -> None:
    """Watch /sandbox/workspace for file creation/modification using inotifywait."""
    dropped_dir.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.Popen(
            ["inotifywait", "-m", "-r", "--format", "%T %e %w%f", "--timefmt", "%Y-%m-%dT%H:%M:%SZ",
             "-e", "create,modify,moved_to,attrib",
             str(WORKSPACE)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        return  # inotifywait not installed

    with open(events_path, "a") as fh:
        while proc.poll() is None:
            if (TELEMETRY / "execution_complete").exists():
                proc.terminate()
                break
            line = proc.stdout.readline()
            if not line:
                continue
            parts = line.strip().split(" ", 2)
            if len(parts) < 3:
                continue
            ts, event, filepath = parts
            record = {"ts": ts, "event": event, "path": filepath}

            # Copy dropped files
            try:
                src = Path(filepath)
                if src.is_file() and "CREATE" in event:
                    import hashlib
                    data = src.read_bytes()
                    sha = hashlib.sha256(data).hexdigest()[:16]
                    dest = dropped_dir / f"{sha}_{src.name}"
                    if not dest.exists():
                        shutil.copy2(src, dest)
                        record["dropped_as"] = str(dest)
                        record["size_bytes"] = len(data)
            except Exception:
                pass

            fh.write(json.dumps(record) + "\n")
            fh.flush()

    proc.wait()


# ---------------------------------------------------------------------------
# Strace parser (post-execution)
# ---------------------------------------------------------------------------

_SYSCALL_RE = re.compile(
    r"^(\d+)\s+(\w+)\((.*)\)\s*=\s*(.*)$"
)

_CATEGORIES = {
    "file": {"open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat",
             "mkdir", "rmdir", "chmod", "chown", "readlink", "stat", "lstat",
             "access", "truncate", "link", "symlink"},
    "network": {"socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom",
                "sendmsg", "recvmsg", "send", "recv", "setsockopt", "getsockopt",
                "getpeername", "getsockname"},
    "process": {"fork", "vfork", "clone", "clone3", "execve", "execveat", "wait4",
                "waitpid", "kill", "tkill", "tgkill", "prctl"},
    "permission": {"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
                   "capset", "capget"},
}


def parse_strace(strace_path: Path, output_path: Path) -> None:
    """Parse raw strace log into categorised structured JSONL."""
    if not strace_path.exists():
        return

    counts: dict[str, int] = {}
    with open(strace_path, "r", errors="replace") as inf, open(output_path, "a") as outf:
        for line in inf:
            if len(line) > 2000:
                line = line[:2000]
            m = _SYSCALL_RE.match(line.strip())
            if not m:
                continue
            pid, syscall, args, retval = m.groups()
            category = "other"
            for cat, syscalls in _CATEGORIES.items():
                if syscall in syscalls:
                    category = cat
                    break

            counts[syscall] = counts.get(syscall, 0) + 1

            # Only emit interesting syscalls (skip boring ones like read/write/mmap)
            if category != "other" or syscall in ("ioctl", "ptrace"):
                record = {
                    "pid": int(pid),
                    "syscall": syscall,
                    "category": category,
                    "args": args[:500],
                    "return": retval.strip()[:200],
                }
                outf.write(json.dumps(record) + "\n")

    # Write syscall summary
    summary = {"total_syscalls": sum(counts.values()), "syscall_counts": counts}
    (TELEMETRY / "strace_summary.json").write_text(json.dumps(summary, indent=2))


# ---------------------------------------------------------------------------
# Network parser (post-execution)
# ---------------------------------------------------------------------------

def parse_network(pcap_path: Path, output_path: Path) -> None:
    """Parse pcap into DNS queries, TCP connections, HTTP requests."""
    if not pcap_path.exists():
        return

    result = {"dns_queries": [], "tcp_connections": [], "http_requests": []}

    # DNS queries
    try:
        out = subprocess.run(
            ["tcpdump", "-r", str(pcap_path), "-n", "port 53", "-l"],
            capture_output=True, text=True, timeout=30,
        )
        for line in out.stdout.splitlines():
            # Match DNS query lines
            dns_match = re.search(r"(\S+)\s+>\s+\S+:\s+.*\?\s+(\S+)", line)
            if dns_match:
                result["dns_queries"].append({
                    "src": dns_match.group(1),
                    "query": dns_match.group(2).rstrip("."),
                })
    except Exception:
        pass

    # TCP connections (SYN packets)
    try:
        out = subprocess.run(
            ["tcpdump", "-r", str(pcap_path), "-n", "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0"],
            capture_output=True, text=True, timeout=30,
        )
        for line in out.stdout.splitlines():
            conn_match = re.search(r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)", line)
            if conn_match:
                result["tcp_connections"].append({
                    "src_ip": conn_match.group(1),
                    "src_port": int(conn_match.group(2)),
                    "dst_ip": conn_match.group(3),
                    "dst_port": int(conn_match.group(4)),
                })
    except Exception:
        pass

    # HTTP requests (port 80)
    try:
        out = subprocess.run(
            ["tcpdump", "-r", str(pcap_path), "-n", "-A", "tcp port 80"],
            capture_output=True, text=True, timeout=30,
        )
        for match in re.finditer(r"(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP", out.stdout):
            result["http_requests"].append({
                "method": match.group(1),
                "path": match.group(2),
            })
    except Exception:
        pass

    output_path.write_text(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# System change detection (post-execution)
# ---------------------------------------------------------------------------

def detect_system_changes(output_path: Path) -> None:
    """Diff filesystem before/after, check crontab/passwd/services."""
    changes: dict = {"new_files": [], "modified_system_files": [], "crontab_changes": [], "user_changes": []}

    # Filesystem diff
    before_path = TELEMETRY / "fs_before.txt"
    after_path = TELEMETRY / "fs_after.txt"
    if before_path.exists() and after_path.exists():
        before = set(before_path.read_text().splitlines())
        after = set(after_path.read_text().splitlines())
        new_files = sorted(after - before)
        changes["new_files"] = new_files[:500]  # Cap

    # Check system files
    system_files = ["/etc/passwd", "/etc/shadow", "/etc/crontab", "/etc/hosts",
                    "/etc/resolv.conf", "/etc/ld.so.preload"]
    for sf in system_files:
        try:
            p = Path(sf)
            if p.exists():
                stat = p.stat()
                changes["modified_system_files"].append({
                    "path": sf,
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                })
        except Exception:
            pass

    # User crontabs
    try:
        out = subprocess.run(["crontab", "-u", "sandbox", "-l"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            changes["crontab_changes"] = out.stdout.strip().splitlines()
    except Exception:
        pass

    output_path.write_text(json.dumps(changes, indent=2))


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    import threading

    process_log = TELEMETRY / "process_tree.jsonl"
    fs_events = TELEMETRY / "fs_events.jsonl"
    dropped_dir = TELEMETRY / "dropped_files"
    strace_raw = TELEMETRY / "strace_raw.log"
    strace_parsed = TELEMETRY / "strace_parsed.jsonl"
    network_raw = TELEMETRY / "capture.pcap"
    network_parsed = TELEMETRY / "network_parsed.json"
    system_changes = TELEMETRY / "system_changes.json"

    # Start polling threads
    proc_thread = threading.Thread(target=poll_process_tree, args=(process_log,), daemon=True)
    fs_thread = threading.Thread(target=watch_filesystem, args=(fs_events, dropped_dir), daemon=True)
    proc_thread.start()
    fs_thread.start()

    # Wait for execution to complete
    while not (TELEMETRY / "execution_complete").exists():
        time.sleep(0.5)

    # Give threads a moment to finish
    time.sleep(1)

    # Post-execution parsing
    parse_strace(strace_raw, strace_parsed)
    parse_network(network_raw, network_parsed)
    detect_system_changes(system_changes)

    print("Monitor: telemetry collection complete")


if __name__ == "__main__":
    main()
