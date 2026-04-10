"""
tool: browser_session
---------------------
Spin up a disposable Docker-based Chrome browser session for manual
phishing page investigation.  The analyst gets a live browser via noVNC
and drives it manually — no automation markers, no CDP, no Selenium.

Network telemetry is captured passively via tcpdump inside the container.
This avoids analysis-evasion techniques that detect automation frameworks
(navigator.webdriver, CDP variables, Selenium WebDriver signatures).

Architecture:
  socai-browser container (--network=host)
    ├── noVNC on :7900       → analyst opens in their browser
    ├── Chrome (vanilla)     → no remote-debugging-port, no automation flags
    └── tcpdump              → passive packet capture (pcap)

Writes:
  cases/<case_id>/artefacts/browser_session/
    ├── session_manifest.json        (metadata + summary)
    ├── network_log.json             (parsed DNS, TCP, HTTP, TLS SNI)
    ├── capture.pcap                 (raw packet capture)
    ├── dns_log.json                 (DNS queries from pcap)
    ├── screenshot_final.png         (screenshot at session close)
  cases/<case_id>/logs/mde_browser_session.parsed.json
  cases/<case_id>/logs/mde_browser_session.entities.json

Usage (CLI):
  python3 socai.py browser-session https://phish.com --case IV_CASE_001
  python3 socai.py browser-stop --session <session_id>

Usage (standalone):
  python3 tools/browser_session.py start https://phish.com --case IV_CASE_001
  python3 tools/browser_session.py stop --session <session_id>
  python3 tools/browser_session.py list
"""
from __future__ import annotations

import atexit
import json
import os
import re
import signal
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import log_error, save_json, utcnow, write_artefact

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DOCKER_IMAGE = os.environ.get("SOCAI_BROWSER_IMAGE", "socai-browser:latest")
CONTAINER_PREFIX = "socai_browser_"
SHM_SIZE = "2g"
BROWSER_VPN_CONTAINER = os.environ.get("SOCAI_VPN_CONTAINER", "gluetun")
BROWSER_USE_VPN = os.environ.get("SOCAI_BROWSER_VPN", "0") == "1"

# noVNC port — only port needed (no Selenium, no CDP)
NOVNC_PORT = 7900

# Session state directory
SESSIONS_DIR = Path(__file__).resolve().parent.parent / "browser_sessions"

# IOC regex patterns
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|top|"
    r"ru|cn|tk|ml|ga|cf|gq|cc|pw|club|online|site|icu|uk|de|fr|au|ca|in|br)\b",
    re.IGNORECASE,
)
_RE_URL = re.compile(r"https?://[^\s\"'<>]{5,}")

# Idle timeout — auto-stop sessions after N seconds of network inactivity
IDLE_TIMEOUT_SECS = int(os.environ.get("SOCAI_BROWSER_IDLE_TIMEOUT", "300"))

# Hard ceiling for session duration (default 1 hour)
MAX_SESSION_SECS = int(os.environ.get("SOCAI_BROWSER_MAX_SESSION", "3600"))

# Grace period after last noVNC client disconnects before auto-stop (seconds)
# Allows for brief tab refreshes / reconnects without killing the session
DISCONNECT_GRACE_SECS = int(os.environ.get("SOCAI_BROWSER_DISCONNECT_GRACE", "15"))

# Interval for polling pcap file size (idle detection)
_PCAP_POLL_INTERVAL = 2.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _relative_artefact_paths(case_id: str, paths: dict) -> dict | None:
    """Convert absolute artefact paths to case-relative paths for MCP clients.

    Returns a dict of {label: relative_path} suitable for ``read_case_file``,
    or None when there is no case_id (session-only mode).
    """
    if not case_id:
        return None
    case_root = CASES_DIR / case_id
    result = {}
    for label, p in paths.items():
        if p is None:
            continue
        try:
            result[label] = Path(p).relative_to(case_root).as_posix()
        except ValueError as exc:
            log_error(case_id, "browser_session:relative_artefact_paths", str(exc),
                      severity="info", traceback=True,
                      context={"label": label, "path": str(p)})
            continue
    return result or None


def _relative_session_paths(session_id: str, paths: dict) -> dict | None:
    """Convert absolute paths to session-relative paths for ``read_browser_session_file``."""
    session_root = SESSIONS_DIR / session_id
    result = {}
    for label, p in paths.items():
        if p is None:
            continue
        try:
            result[label] = Path(p).relative_to(session_root).as_posix()
        except ValueError:
            continue
    return result or None


# ---------------------------------------------------------------------------
# Docker management
# ---------------------------------------------------------------------------

def _container_name(session_id: str) -> str:
    return f"{CONTAINER_PREFIX}{session_id}"


def _is_port_available(port: int) -> bool:
    """Check if a port is available on localhost."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def _check_novnc_port() -> int:
    """Ensure the noVNC port is available."""
    if not _is_port_available(NOVNC_PORT):
        raise RuntimeError(
            f"Port {NOVNC_PORT} (noVNC) is already in use. "
            f"Is another browser session running? Check with: python3 socai.py browser-list"
        )
    return NOVNC_PORT


def _start_container(session_id: str, url: str, telemetry_dir: Path | None = None) -> str:
    """Start the browser container with bridge networking.

    Args:
        session_id: Unique session identifier.
        url: Starting URL to navigate to.
        telemetry_dir: Host directory to bind-mount as /telemetry.
            When provided, tcpdump writes the pcap directly to the host
            filesystem — surviving container crashes and OOM kills.

    Returns container ID.

    Network modes:
        - Default (bridge): container gets its own network namespace.
          noVNC published via -p.  tcpdump only sees Chrome's traffic.
        - VPN: --network=container:<gluetun> for Mullvad routing.
    """
    name = _container_name(session_id)

    # VPN mode: route through gluetun container.
    # Bridge mode (default): own namespace, publish noVNC port.  tcpdump
    # captures only Chrome traffic — no host noise.
    if BROWSER_USE_VPN:
        network_args = [f"--network=container:{BROWSER_VPN_CONTAINER}"]
    else:
        network_args = ["-p", f"{NOVNC_PORT}:{NOVNC_PORT}"]

    cmd = [
        "docker", "run", "--rm", "-d",
        "--name", name,
        "--shm-size", SHM_SIZE,
        *network_args,
        "--cap-add=NET_RAW",   # tcpdump needs raw socket access
        "--cap-add=SYS_ADMIN", # Chrome sandbox needs user namespaces
        "-e", f"START_URL={url}",
        "-e", "SCREEN_WIDTH=1920",
        "-e", "SCREEN_HEIGHT=1080",
    ]

    if telemetry_dir:
        telemetry_dir.mkdir(parents=True, exist_ok=True)
        cmd += ["-v", f"{telemetry_dir.resolve()}:/telemetry"]

    cmd.append(DOCKER_IMAGE)

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Docker start failed: {result.stderr.strip()}")

    return result.stdout.strip()


def _stop_container(session_id: str) -> bool:
    """Stop and remove the container.  Returns True on success."""
    name = _container_name(session_id)
    try:
        result = subprocess.run(
            ["docker", "stop", name], capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            # Container may already be gone (--rm auto-removed, or manually killed)
            inspect = subprocess.run(
                ["docker", "inspect", name],
                capture_output=True, text=True, timeout=5,
            )
            if inspect.returncode != 0:
                # Container doesn't exist — already cleaned up, that's fine
                return True
            print(f"[browser] Warning: docker stop failed for {name}: {result.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired as exc:
        log_error("", "browser_session:stop_container_timeout", str(exc),
                  severity="warning", traceback=True,
                  context={"session_id": session_id})
        print(f"[browser] Warning: docker stop timed out for {name} — forcing kill")
        try:
            subprocess.run(["docker", "kill", name], capture_output=True, timeout=10)
        except Exception as exc_kill:
            log_error("", "browser_session:kill_container", str(exc_kill),
                      severity="warning", traceback=True,
                      context={"session_id": session_id})
        return False
    except Exception as exc:
        log_error("", "browser_session:stop_container", str(exc),
                  severity="warning", traceback=True,
                  context={"session_id": session_id})
        print(f"[browser] Warning: failed to stop container {name}: {exc}")
        return False


def _copy_from_container(session_id: str, src: str, dest: Path) -> bool:
    """Copy a file from the container to the host."""
    name = _container_name(session_id)
    try:
        result = subprocess.run(
            ["docker", "cp", f"{name}:{src}", str(dest)],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0 and dest.exists()
    except Exception as exc:
        log_error("", "browser_session:copy_from_container", str(exc),
                  severity="warning", traceback=True,
                  context={"session_id": session_id, "src": src, "dest": str(dest)})
        return False


def _get_pcap_size(session_id: str) -> int:
    """Get the current pcap file size inside the container."""
    name = _container_name(session_id)
    try:
        result = subprocess.run(
            ["docker", "exec", name, "stat", "-c", "%s", "/telemetry/capture.pcap"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except Exception as exc:
        log_error("", "browser_session:get_pcap_size", str(exc),
                  severity="info", traceback=True,
                  context={"session_id": session_id})
    return -1


def _has_vnc_clients(session_id: str) -> bool:
    """Check if any noVNC WebSocket clients are connected to the container.

    Uses ss inside the container to count ESTABLISHED connections on the
    noVNC port.  Returns True if at least one viewer is connected.
    Returns True on errors (fail-open: don't kill session on check failure).
    """
    name = _container_name(session_id)
    try:
        result = subprocess.run(
            ["docker", "exec", name, "ss", "-t", "state", "established",
             f"sport = :{NOVNC_PORT}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return True  # fail-open
        # ss prints a header line + one line per connection
        lines = [l for l in result.stdout.strip().splitlines() if l.strip()]
        return len(lines) > 1  # more than just the header
    except Exception as exc:
        log_error("", "browser_session:has_vnc_clients", str(exc),
                  severity="info", traceback=True,
                  context={"session_id": session_id})
        return True  # fail-open


# ---------------------------------------------------------------------------
# Pcap parsing (host-side, after copying pcap from container)
# ---------------------------------------------------------------------------

def _parse_pcap(pcap_path: Path) -> dict:
    """Parse a pcap file into structured network telemetry.

    Extracts DNS queries, TCP connections, HTTP requests, and TLS SNI.
    Uses tcpdump for DNS/TCP/HTTP and raw binary parsing for TLS SNI.
    """
    if not pcap_path.exists():
        return {"dns_queries": [], "tcp_connections": [], "http_requests": [],
                "tls_sni": [], "pcap_stats": {}}

    result: dict = {
        "dns_queries": [],
        "tcp_connections": [],
        "http_requests": [],
        "tls_sni": [],
    }

    # DNS queries
    try:
        out = subprocess.run(
            ["tcpdump", "-r", str(pcap_path), "-n", "port 53", "-l"],
            capture_output=True, text=True, timeout=30,
        )
        seen_dns: set[str] = set()
        for line in out.stdout.splitlines():
            dns_match = re.search(r"(\S+)\s+>\s+\S+:\s+.*\?\s+(\S+)", line)
            if dns_match:
                query = dns_match.group(2).rstrip(".")
                if query not in seen_dns:
                    seen_dns.add(query)
                    result["dns_queries"].append({
                        "query": query,
                        "src": dns_match.group(1),
                    })
    except Exception as exc:
        log_error("", "browser_session:parse_pcap_dns", str(exc),
                  severity="warning", traceback=True,
                  context={"pcap": str(pcap_path)})

    # TCP connections (SYN packets)
    try:
        out = subprocess.run(
            ["tcpdump", "-r", str(pcap_path), "-n",
             "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0"],
            capture_output=True, text=True, timeout=30,
        )
        for line in out.stdout.splitlines():
            conn_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)",
                line,
            )
            if conn_match:
                result["tcp_connections"].append({
                    "src_ip": conn_match.group(1),
                    "src_port": int(conn_match.group(2)),
                    "dst_ip": conn_match.group(3),
                    "dst_port": int(conn_match.group(4)),
                })
    except Exception as exc:
        log_error("", "browser_session:parse_pcap_tcp", str(exc),
                  severity="warning", traceback=True,
                  context={"pcap": str(pcap_path)})

    # HTTP requests (plaintext port 80)
    try:
        out = subprocess.run(
            ["tcpdump", "-r", str(pcap_path), "-n", "-A", "tcp port 80"],
            capture_output=True, text=True, timeout=30,
        )
        seen_http: set[str] = set()
        for match in re.finditer(
            r"(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP/\d\.\d\r?\nHost:\s*(\S+)",
            out.stdout,
        ):
            key = f"{match.group(1)} {match.group(3)}{match.group(2)}"
            if key not in seen_http:
                seen_http.add(key)
                result["http_requests"].append({
                    "method": match.group(1),
                    "path": match.group(2),
                    "host": match.group(3),
                    "url": f"http://{match.group(3)}{match.group(2)}",
                })
    except Exception as exc:
        log_error("", "browser_session:parse_pcap_http", str(exc),
                  severity="warning", traceback=True,
                  context={"pcap": str(pcap_path)})

    # TLS SNI extraction (Server Name Indication from ClientHello)
    try:
        result["tls_sni"] = _extract_tls_sni(pcap_path)
    except Exception as exc:
        log_error("", "browser_session:parse_pcap_tls_sni", str(exc),
                  severity="warning", traceback=True,
                  context={"pcap": str(pcap_path)})

    # Pcap stats
    try:
        stat = pcap_path.stat()
        result["pcap_stats"] = {
            "file_size_bytes": stat.st_size,
        }
    except Exception as exc:
        log_error("", "browser_session:pcap_stats", str(exc),
                  severity="info", traceback=True,
                  context={"pcap": str(pcap_path)})
        result["pcap_stats"] = {}

    return result


def _extract_tls_sni(pcap_path: Path) -> list[dict]:
    """Extract TLS SNI (Server Name Indication) from ClientHello messages.

    Reads raw pcap and parses TLS handshake records to find the SNI
    extension (type 0x0000) in ClientHello messages.
    """
    sni_entries: list[dict] = []
    seen: set[str] = set()

    try:
        # Use tcpdump to dump raw hex of TLS ClientHello packets
        out = subprocess.run(
            ["tcpdump", "-r", str(pcap_path), "-n", "-x",
             "tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16)"],
            capture_output=True, text=True, timeout=30,
        )

        # Parse hex dump for SNI extensions
        current_hex = ""
        current_dst = ""
        for line in out.stdout.splitlines():
            # tcpdump hex lines start with whitespace + offset
            hex_match = re.match(r"\s+0x[\da-f]+:\s+([\da-f ]+)", line)
            if hex_match:
                current_hex += hex_match.group(1).replace(" ", "")
            else:
                # New packet header — extract dst IP
                if current_hex:
                    sni = _parse_sni_from_hex(current_hex)
                    if sni and sni not in seen:
                        seen.add(sni)
                        sni_entries.append({"domain": sni, "dst_ip": current_dst})
                    current_hex = ""
                ip_match = re.search(
                    r">\s+(\d+\.\d+\.\d+\.\d+)\.443:", line
                )
                if ip_match:
                    current_dst = ip_match.group(1)

        # Process last packet
        if current_hex:
            sni = _parse_sni_from_hex(current_hex)
            if sni and sni not in seen:
                seen.add(sni)
                sni_entries.append({"domain": sni, "dst_ip": current_dst})

    except Exception as exc:
        log_error("", "browser_session:extract_tls_sni", str(exc),
                  severity="warning", traceback=True,
                  context={"pcap": str(pcap_path)})

    return sni_entries


def _parse_sni_from_hex(hex_str: str) -> str | None:
    """Parse SNI domain from raw TLS ClientHello hex bytes."""
    try:
        data = bytes.fromhex(hex_str)
    except ValueError as exc:
        log_error("", "browser_session:parse_sni_hex_decode", str(exc),
                  severity="info", traceback=True)
        return None

    # Find TLS handshake record (content type 0x16, handshake type 0x01 = ClientHello)
    # Search for the SNI extension (type 0x0000) in the extensions block
    idx = data.find(b"\x00\x00")  # Extension type: server_name
    while idx >= 0 and idx < len(data) - 9:
        # Validate this looks like an SNI extension
        try:
            ext_len = struct.unpack("!H", data[idx + 2 : idx + 4])[0]
            if ext_len < 5 or ext_len > 500:
                idx = data.find(b"\x00\x00", idx + 1)
                continue

            # SNI list length
            list_len = struct.unpack("!H", data[idx + 4 : idx + 6])[0]
            if list_len < 3 or list_len > ext_len:
                idx = data.find(b"\x00\x00", idx + 1)
                continue

            # Name type should be 0x00 (host_name)
            name_type = data[idx + 6]
            if name_type != 0:
                idx = data.find(b"\x00\x00", idx + 1)
                continue

            # Name length and value
            name_len = struct.unpack("!H", data[idx + 7 : idx + 9])[0]
            if name_len < 1 or idx + 9 + name_len > len(data):
                idx = data.find(b"\x00\x00", idx + 1)
                continue

            name = data[idx + 9 : idx + 9 + name_len]
            try:
                domain = name.decode("ascii")
                # Sanity: must look like a domain
                if "." in domain and all(
                    c.isalnum() or c in "-." for c in domain
                ):
                    return domain
            except (UnicodeDecodeError, ValueError) as exc:
                log_error("", "browser_session:parse_sni_domain_decode", str(exc),
                          severity="info", traceback=True)
        except (struct.error, IndexError) as exc:
            log_error("", "browser_session:parse_sni_struct", str(exc),
                      severity="info", traceback=True)

        idx = data.find(b"\x00\x00", idx + 1)

    return None


# ---------------------------------------------------------------------------
# Container-side pcap parsing (runs tcpdump via docker exec)
# ---------------------------------------------------------------------------

_NOISE_PORTS = {5900, 7900}


def _parse_pcap_in_container(
    session_id: str,
    pcap_path: str = "/telemetry/capture.pcap",
) -> dict:
    """Parse pcap inside the running container via ``docker exec``.

    Same extraction logic as ``_parse_pcap`` but avoids requiring tcpdump
    on the host.  Must be called BEFORE ``_stop_container``.
    """
    name = _container_name(session_id)
    result: dict = {
        "dns_queries": [],
        "tcp_connections": [],
        "http_requests": [],
        "tls_sni": [],
    }

    def _exec(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "exec", name, *args],
            capture_output=True, text=True, timeout=timeout,
        )

    # DNS queries
    try:
        out = _exec(["tcpdump", "-r", pcap_path, "-n", "port 53", "-l"])
        seen_dns: set[str] = set()
        for line in out.stdout.splitlines():
            dns_match = re.search(r"(\S+)\s+>\s+\S+:\s+.*\?\s+(\S+)", line)
            if dns_match:
                query = dns_match.group(2).rstrip(".")
                if query and query not in seen_dns:
                    seen_dns.add(query)
                    result["dns_queries"].append({
                        "query": query,
                        "src": dns_match.group(1),
                    })
    except Exception as exc:
        log_error("", "browser_session:container_parse_dns", str(exc),
                  severity="warning", traceback=True,
                  context={"session_id": session_id})

    # TCP connections (SYN packets)
    try:
        out = _exec([
            "tcpdump", "-r", pcap_path, "-n",
            "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0",
        ])
        for line in out.stdout.splitlines():
            conn_match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)",
                line,
            )
            if conn_match:
                dst_port = int(conn_match.group(4))
                dst_ip = conn_match.group(3)
                if dst_port not in _NOISE_PORTS and not dst_ip.startswith("127."):
                    result["tcp_connections"].append({
                        "src_ip": conn_match.group(1),
                        "src_port": int(conn_match.group(2)),
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                    })
    except Exception as exc:
        log_error("", "browser_session:container_parse_tcp", str(exc),
                  severity="warning", traceback=True,
                  context={"session_id": session_id})

    # HTTP requests (plaintext port 80)
    try:
        out = _exec(["tcpdump", "-r", pcap_path, "-n", "-A", "tcp port 80"])
        seen_http: set[str] = set()
        for match in re.finditer(
            r"(GET|POST|PUT|DELETE|HEAD)\s+(\S+)\s+HTTP/\d\.\d\r?\nHost:\s*(\S+)",
            out.stdout,
        ):
            key = f"{match.group(1)} {match.group(3)}{match.group(2)}"
            if key not in seen_http:
                seen_http.add(key)
                result["http_requests"].append({
                    "method": match.group(1),
                    "path": match.group(2),
                    "host": match.group(3),
                    "url": f"http://{match.group(3)}{match.group(2)}",
                })
    except Exception as exc:
        log_error("", "browser_session:container_parse_http", str(exc),
                  severity="warning", traceback=True,
                  context={"session_id": session_id})

    # TLS SNI extraction via hex dump
    try:
        out = _exec([
            "tcpdump", "-r", pcap_path, "-n", "-x",
            "tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16)",
        ])
        seen_sni: set[str] = set()
        current_hex = ""
        current_dst = ""
        for line in out.stdout.splitlines():
            hex_match = re.match(r"\s+0x[\da-f]+:\s+([\da-f ]+)", line)
            if hex_match:
                current_hex += hex_match.group(1).replace(" ", "")
            else:
                if current_hex:
                    sni = _parse_sni_from_hex(current_hex)
                    if sni and sni not in seen_sni:
                        seen_sni.add(sni)
                        result["tls_sni"].append({"domain": sni, "dst_ip": current_dst})
                    current_hex = ""
                ip_match = re.search(r">\s+(\d+\.\d+\.\d+\.\d+)\.443:", line)
                if ip_match:
                    current_dst = ip_match.group(1)
        # Last packet
        if current_hex:
            sni = _parse_sni_from_hex(current_hex)
            if sni and sni not in seen_sni:
                seen_sni.add(sni)
                result["tls_sni"].append({"domain": sni, "dst_ip": current_dst})
    except Exception as exc:
        log_error("", "browser_session:container_parse_tls_sni", str(exc),
                  severity="warning", traceback=True,
                  context={"session_id": session_id})

    return result


# ---------------------------------------------------------------------------
# Session state management
# ---------------------------------------------------------------------------

def _save_session_state(session_id: str, state: dict) -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    save_json(SESSIONS_DIR / f"{session_id}.json", state)


def _load_session_state(session_id: str) -> dict | None:
    path = SESSIONS_DIR / f"{session_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        log_error("", "browser_session:load_session_state", str(exc),
                  severity="warning", traceback=True,
                  context={"session_id": session_id})
        return None


def _delete_session_state(session_id: str) -> None:
    path = SESSIONS_DIR / f"{session_id}.json"
    if path.exists():
        path.unlink()


def _list_session_states() -> list[dict]:
    if not SESSIONS_DIR.exists():
        return []
    sessions = []
    for f in sorted(SESSIONS_DIR.glob("*.json")):
        try:
            sessions.append(json.loads(f.read_text()))
        except Exception as exc:
            log_error("", "browser_session:list_session_states", str(exc),
                      severity="warning", traceback=True,
                      context={"session_file": str(f)})
            continue
    return sessions


# ---------------------------------------------------------------------------
# Idle timeout monitor (background thread polling pcap size)
# ---------------------------------------------------------------------------

class _IdleMonitor:
    """Track session activity by polling pcap size and noVNC client connections.

    Fires ``idle_event`` when any of these conditions are met:
    - pcap hasn't grown for ``idle_timeout`` seconds (network inactivity)
    - all noVNC clients disconnected for ``disconnect_grace`` seconds (tab closed)
    - hard ``max_duration`` ceiling reached

    The disconnect detection is fail-open: if the check errors, the session
    stays alive (we don't kill a session because of a transient docker exec
    failure).
    """

    # Which condition triggered the event
    stop_reason: str = ""

    def __init__(self, session_id: str, *, idle_timeout: float = 0,
                 max_duration: float = 0, disconnect_grace: float = 0):
        self._session_id = session_id
        self._idle_timeout = idle_timeout
        self._max_duration = max_duration
        self._disconnect_grace = disconnect_grace
        self._running = False
        self._thread: threading.Thread | None = None
        self.idle_event = threading.Event()
        self._last_pcap_size: int = 0
        self._last_change_at: float = time.monotonic()
        self._started_at: float = time.monotonic()
        self._disconnected_since: float | None = None
        self._had_client: bool = False  # True once at least one client connected

    def start(self) -> None:
        self._running = True
        self._started_at = time.monotonic()
        self._last_change_at = time.monotonic()
        self._thread = threading.Thread(target=self._poll, daemon=True,
                                        name=f"idle-monitor-{self._session_id}")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _poll(self) -> None:
        while self._running:
            now = time.monotonic()

            # Hard ceiling
            if self._max_duration > 0 and now - self._started_at >= self._max_duration:
                self.stop_reason = "max_duration"
                self.idle_event.set()
                break

            # Check pcap size
            size = _get_pcap_size(self._session_id)
            if size >= 0 and size != self._last_pcap_size:
                self._last_pcap_size = size
                self._last_change_at = now

            # Idle timeout (network inactivity)
            if (self._idle_timeout > 0
                    and now - self._last_change_at >= self._idle_timeout):
                self.stop_reason = "idle_timeout"
                self.idle_event.set()
                break

            # noVNC client disconnect detection
            if self._disconnect_grace > 0:
                has_clients = _has_vnc_clients(self._session_id)
                if has_clients:
                    self._had_client = True
                    self._disconnected_since = None
                elif self._had_client:
                    # Only start grace timer after we've had at least one client
                    if self._disconnected_since is None:
                        self._disconnected_since = now
                        print(f"[browser] No viewers connected — "
                              f"auto-stop in {int(self._disconnect_grace)}s "
                              f"unless tab is reopened")
                    elif now - self._disconnected_since >= self._disconnect_grace:
                        self.stop_reason = "viewer_disconnected"
                        self.idle_event.set()
                        break

            time.sleep(_PCAP_POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

# Idle-timeout plumbing: done events and cached stop results
_session_done_events: dict[str, threading.Event] = {}
_session_results: dict[str, dict] = {}
_stop_locks: dict[str, threading.Lock] = {}
_active_monitors: dict[str, _IdleMonitor] = {}


_shutdown_in_progress = False


def _shutdown_active_sessions() -> None:
    """Gracefully stop all active browser sessions.

    Called on process exit (atexit) or signal (SIGTERM/SIGINT) to ensure
    containers are torn down and artefacts collected even if the MCP server
    crashes or is killed.
    """
    global _shutdown_in_progress
    if _shutdown_in_progress:
        return
    _shutdown_in_progress = True

    active = [s for s in _list_session_states()
              if s.get("status") == "active"]
    if not active:
        return

    print(f"\n[browser] Process shutting down — stopping {len(active)} active session(s)...")
    for s in active:
        sid = s["session_id"]
        try:
            stop_session(sid, stop_reason="process_exit")
            print(f"[browser] Session {sid} stopped cleanly on shutdown")
        except Exception as exc:
            log_error("", "browser_session:shutdown_stop_session", str(exc),
                      severity="error", traceback=True,
                      context={"session_id": sid})
            print(f"[browser] Warning: failed to stop {sid} on shutdown: {exc}")
            # Last resort: force-kill the container
            _stop_container(sid)


# Register atexit cleanup — runs on normal exit and sys.exit().
# This is the primary safety net; signal handlers in the MCP server or CLI
# will trigger atexit on their way out, so we don't install our own signal
# handlers here (which would break the MCP server's handler chain).
atexit.register(_shutdown_active_sessions)


def _idle_watchdog(session_id: str, monitor: _IdleMonitor,
                   done_event: threading.Event) -> None:
    """Background thread: auto-stop session when idle timeout fires."""
    monitor.idle_event.wait()
    if not monitor._running:
        return  # Monitor stopped for other reasons (manual stop)

    elapsed = int(time.monotonic() - monitor._started_at)
    reason = monitor.stop_reason or "idle_timeout"

    _reason_messages = {
        "max_duration": f"Session {session_id} hit max duration ({elapsed}s) — auto-stopping...",
        "idle_timeout": f"Session {session_id} idle for {int(monitor._idle_timeout)}s — auto-stopping...",
        "viewer_disconnected": f"Session {session_id} — all viewers disconnected — auto-stopping...",
    }
    print(f"\n[browser] {_reason_messages.get(reason, f'Session {session_id} — {reason}')}")

    try:
        result = stop_session(session_id, stop_reason=reason)
        _session_results[session_id] = result
    except Exception as exc:
        log_error("", "browser_session:idle_watchdog_stop", str(exc),
                  severity="error", traceback=True,
                  context={"session_id": session_id, "reason": reason})
        print(f"[browser] Auto-stop error: {exc}")
        _session_results[session_id] = {"status": "error", "reason": str(exc)}
    done_event.set()


def start_session(
    url: str,
    case_id: str = "",
    *,
    session_id: str = "",
    idle_timeout: float = IDLE_TIMEOUT_SECS,
) -> dict:
    """Start a disposable browser session for manual investigation.

    Args:
        url: Starting URL to navigate to.
        case_id: Optional case ID.  When empty, artefacts are stored under
                 browser_sessions/<session_id>/artefacts/ (no case created).
        session_id: Optional custom session ID (auto-generated if empty).
        idle_timeout: Seconds of network inactivity before auto-stop (0 = disabled).

    Returns:
        Session manifest with connection details.
    """
    if not session_id:
        import hashlib
        session_id = hashlib.sha256(
            f"{case_id}:{url}:{time.time()}".encode()
        ).hexdigest()[:12]

    # Enforce single-session: stop any existing active session before starting
    existing = _list_session_states()
    for s in [s for s in existing if s.get("status") == "active"]:
        prev_id = s["session_id"]
        container = _container_name(prev_id)
        check = subprocess.run(
            ["docker", "inspect", container, "--format", "{{.State.Running}}"],
            capture_output=True, text=True,
        )
        if check.returncode != 0 or "true" not in check.stdout:
            s["status"] = "orphaned"
            _save_session_state(prev_id, s)
        else:
            print(f"[browser] Stopping previous session {prev_id} (case {s.get('case_id', '?')})...")
            try:
                stop_session(prev_id, stop_reason="replaced")
                print(f"[browser] Previous session {prev_id} stopped — telemetry preserved")
            except Exception as exc:
                log_error(case_id, "browser_session:stop_previous_session", str(exc),
                          severity="warning", traceback=True,
                          context={"prev_session_id": prev_id})
                print(f"[browser] Warning: failed to stop previous session {prev_id}: {exc}")
                _stop_container(prev_id)
                s["status"] = "orphaned"
                _save_session_state(prev_id, s)

    # Pre-flight: check Docker image exists
    img_check = subprocess.run(
        ["docker", "image", "inspect", DOCKER_IMAGE],
        capture_output=True, text=True,
    )
    if img_check.returncode != 0:
        return {
            "status": "error",
            "reason": (
                f"Browser image '{DOCKER_IMAGE}' not found. "
                f"Build it with: docker build -t {DOCKER_IMAGE} docker/browser/  "
                f"— or use capture_urls for automated (non-interactive) URL capture."
            ),
        }

    # Check noVNC port
    novnc_port = _check_novnc_port()

    # Create host-side telemetry directory so pcap survives container death
    telemetry_dir = SESSIONS_DIR / session_id / "telemetry"
    telemetry_dir.mkdir(parents=True, exist_ok=True)

    print(f"[browser] Starting session {session_id}...")

    # Start Docker container
    try:
        container_id = _start_container(session_id, url, telemetry_dir=telemetry_dir)
    except RuntimeError as exc:
        log_error(case_id, "browser_session:start_container", str(exc),
                  severity="error", traceback=True,
                  context={"session_id": session_id, "url": url})
        return {"status": "error", "reason": str(exc)}

    print(f"[browser] Container started: {container_id[:12]}")

    # Wait for noVNC to be ready
    print("[browser] Waiting for Chrome to start...")
    ready = False
    for _ in range(30):
        try:
            import urllib.request
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{novnc_port}/", timeout=3
            )
            if resp.status == 200:
                ready = True
                break
        except Exception as exc:
            log_error(case_id, "browser_session:novnc_readiness_poll", str(exc),
                      severity="info", traceback=True,
                      context={"session_id": session_id, "port": novnc_port})
            time.sleep(1)

    if not ready:
        _stop_container(session_id)
        return {"status": "error", "reason": "Browser failed to start within 30 seconds"}

    # Allow initial page load to generate some pcap data
    time.sleep(2)

    # Start idle monitor
    monitor = _IdleMonitor(session_id, idle_timeout=idle_timeout,
                           max_duration=MAX_SESSION_SECS,
                           disconnect_grace=DISCONNECT_GRACE_SECS)
    monitor.start()
    _active_monitors[session_id] = monitor

    # Start idle watchdog thread
    done_event = threading.Event()
    _session_done_events[session_id] = done_event
    if idle_timeout > 0 or MAX_SESSION_SECS > 0 or DISCONNECT_GRACE_SECS > 0:
        threading.Thread(
            target=_idle_watchdog, args=(session_id, monitor, done_event),
            daemon=True, name=f"idle-watchdog-{session_id}",
        ).start()

    # Save session state
    state = {
        "session_id": session_id,
        "case_id": case_id,
        "status": "active",
        "start_url": url,
        "container_id": container_id[:12],
        "novnc_port": novnc_port,
        "started_at": utcnow(),
        "novnc_url": f"http://127.0.0.1:{novnc_port}",
        "idle_timeout": idle_timeout,
        "max_duration": MAX_SESSION_SECS,
    }
    _save_session_state(session_id, state)

    manifest = {
        "status": "ok",
        "session_id": session_id,
        "case_id": case_id,
        "novnc_url": f"http://127.0.0.1:{novnc_port}",
        "start_url": url,
        "started_at": state["started_at"],
        "message": (
            f"Browser session started. Open in your browser:\n"
            f"  {state['novnc_url']}\n\n"
            f"Passive network capture active — no automation markers.\n"
            + (f"Idle timeout: {int(idle_timeout)}s — session auto-stops on network inactivity.\n"
               if idle_timeout > 0 else "")
            + (f"Max session duration: {MAX_SESSION_SECS}s\n"
               if MAX_SESSION_SECS > 0 else "")
            + (f"Close the noVNC tab to end the session (clean stop after {DISCONNECT_GRACE_SECS}s grace period).\n"
               if DISCONNECT_GRACE_SECS > 0 else "")
            + f"Or stop manually:\n"
            f"  python3 socai.py browser-stop --session {session_id}"
        ),
        "idle_timeout": idle_timeout,
    }

    print(f"\n[browser] {'='*60}")
    print(f"[browser] Session {session_id} is LIVE")
    print(f"[browser] Open in your browser: {state['novnc_url']}")
    print(f"[browser] Passive network capture active — no automation markers")
    if idle_timeout > 0:
        print(f"[browser] Idle timeout: {int(idle_timeout)}s (auto-stop on network inactivity)")
    if DISCONNECT_GRACE_SECS > 0:
        print(f"[browser] Close tab to stop: {DISCONNECT_GRACE_SECS}s grace period before clean shutdown")
    if MAX_SESSION_SECS > 0:
        print(f"[browser] Max duration: {MAX_SESSION_SECS}s")
    print(f"[browser] {'='*60}\n")

    return manifest


def stop_session(
    session_id: str,
    *,
    stop_reason: str = "manual",
) -> dict:
    """Stop a browser session, collect all captured data, and tear down.

    Args:
        session_id: Session ID to stop.
        stop_reason: Why the session is stopping ("manual", "idle_timeout",
                     "max_duration", "replaced").

    Returns:
        Session results manifest.
    """
    lock = _stop_locks.setdefault(session_id, threading.Lock())
    acquired = lock.acquire(timeout=60)
    if not acquired:
        # Another thread is stopping this session — wait for its result
        cached = _session_results.get(session_id)
        if cached:
            return cached
        return {"status": "ok", "reason": "Session stopped by concurrent caller",
                "session_id": session_id}

    try:
        result = _stop_session_inner(session_id, stop_reason=stop_reason)
        _session_results[session_id] = result
        return result
    finally:
        lock.release()


def _stop_session_inner(
    session_id: str,
    *,
    stop_reason: str = "manual",
) -> dict:
    state = _load_session_state(session_id)
    if not state:
        return {"status": "error", "reason": f"Session not found: {session_id}"}

    if state.get("status") == "completed":
        return {"status": "ok", "reason": "Session already stopped",
                "session_id": session_id}

    case_id = state.get("case_id", "")

    print(f"[browser] Stopping session {session_id}...")

    # Stop idle monitor
    monitor = _active_monitors.pop(session_id, None)
    if monitor:
        monitor.stop()

    # Determine output directory
    if case_id:
        out_dir = CASES_DIR / case_id / "artefacts" / "browser_session"
        logs_dir = CASES_DIR / case_id / "logs"
    else:
        session_artefacts = SESSIONS_DIR / session_id / "artefacts"
        out_dir = session_artefacts
        logs_dir = session_artefacts
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Parse pcap INSIDE the container (tcpdump is there, not on the host)
    print("[browser] Parsing network capture...")
    network_data = _parse_pcap_in_container(session_id)
    _has_container_results = any(
        network_data.get(k) for k in ("dns_queries", "tcp_connections", "http_requests", "tls_sni")
    )

    # Collect artefacts — prefer host-mounted telemetry (survives container
    # death), fall back to docker cp for sessions started before the mount.
    pcap_path = out_dir / "capture.pcap"
    screenshot_path = out_dir / "screenshot_final.png"

    host_telemetry = SESSIONS_DIR / session_id / "telemetry"
    host_pcap = host_telemetry / "capture.pcap"
    host_screenshot = host_telemetry / "screenshot_final.png"

    import shutil

    # Pcap
    if host_pcap.exists() and host_pcap.stat().st_size > 0:
        shutil.copy2(host_pcap, pcap_path)
        pcap_ok = True
        print(f"[browser] Pcap recovered from host mount ({pcap_path.stat().st_size:,} bytes)")
    else:
        pcap_ok = _copy_from_container(session_id, "/telemetry/capture.pcap", pcap_path)
        if pcap_ok:
            print(f"[browser] Pcap captured via docker cp ({pcap_path.stat().st_size:,} bytes)")
        else:
            print("[browser] Warning: no pcap captured")

    # Screenshot
    if host_screenshot.exists() and host_screenshot.stat().st_size > 0:
        shutil.copy2(host_screenshot, screenshot_path)
        screenshot_ok = True
        print("[browser] Final screenshot recovered from host mount")
    else:
        screenshot_ok = _copy_from_container(
            session_id, "/telemetry/screenshot_final.png", screenshot_path)
        if screenshot_ok:
            print("[browser] Final screenshot captured via docker cp")

    # Stop container
    container_stopped = _stop_container(session_id)
    if container_stopped:
        print("[browser] Container destroyed")
    else:
        log_error(case_id or session_id, "browser_session.stop",
                  f"Container stop failed for {session_id}",
                  severity="warning", context={"stop_reason": stop_reason})

    # Host-side fallback: if container parsing returned nothing, try host
    # (works when tcpdump/tshark is installed on the host)
    if not _has_container_results and pcap_ok:
        host_data = _parse_pcap(pcap_path)
        if any(host_data.get(k) for k in ("dns_queries", "tcp_connections", "http_requests", "tls_sni")):
            network_data = host_data

    # Add pcap_stats from host-side stat
    if pcap_ok:
        try:
            network_data["pcap_stats"] = {"file_size_bytes": pcap_path.stat().st_size}
        except Exception:
            network_data.setdefault("pcap_stats", {})

    # Write parsed network data
    if network_data:
        write_artefact(
            out_dir / "network_log.json",
            json.dumps(network_data, indent=2, default=str),
        )

    # Write DNS log
    dns_queries = network_data.get("dns_queries", [])
    if dns_queries:
        write_artefact(
            out_dir / "dns_log.json",
            json.dumps(dns_queries, indent=2, default=str),
        )

    # Extract entities for downstream tools
    entities = _extract_session_entities(network_data)

    # Build normalised log rows for downstream pipeline
    log_rows = _build_log_rows(network_data)

    log_result = {
        "source_file": f"browser_session:{session_id}",
        "case_id": case_id,
        "format": "pcap_capture",
        "ts": utcnow(),
        "row_count": len(log_rows),
        "entities": entities,
        "entity_totals": {k: len(v) for k, v in entities.items()},
        "rows_sample": log_rows,
    }

    write_artefact(
        logs_dir / "mde_browser_session.parsed.json",
        json.dumps(log_result, indent=2, default=str),
    )
    write_artefact(
        logs_dir / "mde_browser_session.entities.json",
        json.dumps(entities, indent=2),
    )

    # Build network summary
    network_summary = _build_network_summary(network_data)

    # Compute duration
    duration_sec = 0
    try:
        from datetime import datetime, timezone
        started = datetime.fromisoformat(state["started_at"].replace("Z", "+00:00"))
        duration_sec = int((datetime.now(timezone.utc) - started).total_seconds())
    except Exception as exc:
        log_error(case_id, "browser_session:compute_duration", str(exc),
                  severity="info", traceback=True,
                  context={"session_id": session_id})

    # Cap inline lists for MCP response size
    _DNS_CAP, _SNI_CAP, _HTTP_CAP, _TCP_CAP = 50, 50, 50, 100
    all_tcp = network_data.get("tcp_connections", [])
    all_http = network_data.get("http_requests", [])
    all_sni = network_data.get("tls_sni", [])
    truncated = (
        len(dns_queries) > _DNS_CAP
        or len(all_sni) > _SNI_CAP
        or len(all_http) > _HTTP_CAP
        or len(all_tcp) > _TCP_CAP
    )

    _artefact_map = {
        "capture_pcap": pcap_path if pcap_ok else None,
        "network_log": (out_dir / "network_log.json") if network_data else None,
        "dns_log": (out_dir / "dns_log.json") if dns_queries else None,
        "screenshot": screenshot_path if screenshot_ok else None,
        "parsed_log": logs_dir / "mde_browser_session.parsed.json",
        "entities": logs_dir / "mde_browser_session.entities.json",
    }

    manifest = {
        "status": "ok",
        "session_id": session_id,
        "case_id": case_id,
        "start_url": state.get("start_url", ""),
        "started_at": state.get("started_at", ""),
        "stopped_at": utcnow(),
        "stop_reason": stop_reason,
        "duration_seconds": duration_sec,
        "network_summary": network_summary,
        "entities": {k: len(v) for k, v in entities.items()},
        "dns_queries": dns_queries[:_DNS_CAP],
        "tls_sni": all_sni[:_SNI_CAP],
        "http_requests": all_http[:_HTTP_CAP],
        "tcp_connections": all_tcp[:_TCP_CAP],
        "truncated": truncated,
        "artefacts": {
            "capture_pcap": str(pcap_path) if pcap_ok else None,
            "network_log": str(out_dir / "network_log.json") if network_data else None,
            "dns_log": str(out_dir / "dns_log.json") if dns_queries else None,
            "screenshot": str(screenshot_path) if screenshot_ok else None,
        },
        "case_files": _relative_artefact_paths(case_id, _artefact_map),
        "session_files": _relative_session_paths(session_id, _artefact_map) if not case_id else None,
    }

    save_json(out_dir / "session_manifest.json", manifest)

    # Update session state
    state["status"] = "completed"
    state["stopped_at"] = utcnow()
    state["stop_reason"] = stop_reason
    _save_session_state(session_id, state)
    _session_done_events.pop(session_id, None)

    # Print summary
    print(f"\n[browser] {'='*60}")
    print(f"[browser] Session {session_id} COMPLETE")
    print(f"[browser] Duration: {duration_sec}s | Stop reason: {stop_reason}")
    print(f"[browser] Start URL: {state.get('start_url', 'N/A')}")
    if network_summary:
        print(f"[browser] DNS queries: {network_summary.get('dns_queries', 0)}")
        print(f"[browser] TCP connections: {network_summary.get('tcp_connections', 0)}")
        print(f"[browser] HTTP requests: {network_summary.get('http_requests', 0)}")
        print(f"[browser] TLS SNI domains: {network_summary.get('tls_sni_domains', 0)}")
        print(f"[browser] Unique domains: {len(network_summary.get('unique_domains', []))}")
        print(f"[browser] Unique IPs: {len(network_summary.get('unique_ips', []))}")
    if dns_queries:
        print(f"[browser] DNS queries observed:")
        for entry in dns_queries[:20]:
            print(f"  {entry['query']}")
    if all_sni:
        print(f"[browser] TLS connections (SNI):")
        for entry in all_sni[:20]:
            print(f"  {entry['domain']} → {entry.get('dst_ip', '?')}")
    if all_http:
        print(f"[browser] HTTP requests:")
        for entry in all_http[:20]:
            print(f"  {entry.get('method', '?')} {entry.get('url', '?')}")
    if all_tcp:
        # Unique dst_ip:dst_port pairs
        seen_dst: set[str] = set()
        for conn in all_tcp:
            key = f"{conn.get('dst_ip', '?')}:{conn.get('dst_port', '?')}"
            seen_dst.add(key)
        print(f"[browser] TCP destinations ({len(seen_dst)} unique):")
        for dst in sorted(seen_dst)[:20]:
            print(f"  {dst}")
    print(f"[browser] Artefacts: {out_dir}")
    print(f"[browser] {'='*60}\n")

    return manifest


def list_sessions() -> list[dict]:
    """List all known browser sessions."""
    sessions = _list_session_states()

    # Verify active session containers are actually running
    for s in sessions:
        if s.get("status") == "active":
            container = _container_name(s["session_id"])
            check = subprocess.run(
                ["docker", "inspect", container, "--format", "{{.State.Running}}"],
                capture_output=True, text=True,
            )
            if check.returncode != 0 or "true" not in check.stdout:
                s["status"] = "orphaned"
                _save_session_state(s["session_id"], s)

    return sessions


def cleanup_orphaned() -> int:
    """Stop any orphaned session containers, collecting artefacts first.

    Attempts a graceful stop via ``stop_session`` so that pcap/screenshot
    are copied out before the container is destroyed.  Falls back to a raw
    ``docker stop`` if the graceful path fails.
    """
    cleaned = 0
    for s in _list_session_states():
        if s.get("status") not in ("orphaned", "active"):
            continue
        sid = s["session_id"]
        # Try graceful stop (copies artefacts, parses pcap, writes manifest)
        try:
            result = stop_session(sid, stop_reason="cleanup")
            if result.get("status") == "ok":
                print(f"[browser] Cleaned session {sid} — artefacts preserved")
                cleaned += 1
                continue
        except Exception as exc:
            log_error("", "browser_session:cleanup_orphaned", str(exc),
                      severity="warning", traceback=True,
                      context={"session_id": sid})
            print(f"[browser] Graceful cleanup failed for {sid}: {exc}")
        # Fallback: force-kill the container, mark state
        _stop_container(sid)
        s["status"] = "cleaned"
        _save_session_state(sid, s)
        cleaned += 1
    return cleaned


def import_session(session_id: str, case_id: str) -> dict:
    """Import a caseless browser session's artefacts into an existing case.

    Copies all artefacts from ``browser_sessions/<session_id>/artefacts/``
    into ``cases/<case_id>/artefacts/browser_session/`` and updates the
    session state to reference the case.

    Args:
        session_id: Completed browser session ID.
        case_id: Target case identifier.

    Returns:
        Manifest with ``case_files`` paths for ``read_case_file``.
    """
    import re as _re
    import shutil

    if not _re.match(r"^[a-f0-9]{8,40}$", session_id):
        return {"status": "error", "reason": "Invalid session_id."}
    if not case_id:
        return {"status": "error", "reason": "case_id is required."}

    case_dir = CASES_DIR / case_id
    if not case_dir.is_dir():
        return {"status": "error", "reason": f"Case not found: {case_id}"}

    state = _load_session_state(session_id)
    if not state:
        return {"status": "error", "reason": f"Session not found: {session_id}"}

    if state.get("case_id"):
        return {"status": "error",
                "reason": f"Session already attached to case {state['case_id']}"}

    session_artefacts = SESSIONS_DIR / session_id / "artefacts"
    if not session_artefacts.is_dir():
        return {"status": "error", "reason": "No artefacts found for this session."}

    # Destination directories
    out_dir = case_dir / "artefacts" / "browser_session"
    logs_dir = case_dir / "logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Copy artefacts
    copied = []
    for src in session_artefacts.iterdir():
        if not src.is_file():
            continue
        dest = out_dir / src.name
        # Parsed log and entities go to logs/
        if src.name in ("mde_browser_session.parsed.json",
                        "mde_browser_session.entities.json"):
            dest = logs_dir / src.name
        shutil.copy2(src, dest)
        copied.append(src.name)

    # Update session state
    state["case_id"] = case_id
    state["imported_at"] = utcnow()
    _save_session_state(session_id, state)

    # Build case_files paths for read_case_file
    case_files = _relative_artefact_paths(case_id, {
        "capture_pcap": out_dir / "capture.pcap" if (out_dir / "capture.pcap").exists() else None,
        "network_log": out_dir / "network_log.json" if (out_dir / "network_log.json").exists() else None,
        "dns_log": out_dir / "dns_log.json" if (out_dir / "dns_log.json").exists() else None,
        "screenshot": out_dir / "screenshot_final.png" if (out_dir / "screenshot_final.png").exists() else None,
        "session_manifest": out_dir / "session_manifest.json" if (out_dir / "session_manifest.json").exists() else None,
        "parsed_log": logs_dir / "mde_browser_session.parsed.json" if (logs_dir / "mde_browser_session.parsed.json").exists() else None,
        "entities": logs_dir / "mde_browser_session.entities.json" if (logs_dir / "mde_browser_session.entities.json").exists() else None,
    })

    print(f"[browser] Imported session {session_id} into {case_id} ({len(copied)} files)")

    return {
        "status": "ok",
        "session_id": session_id,
        "case_id": case_id,
        "files_copied": copied,
        "case_files": case_files,
    }


# ---------------------------------------------------------------------------
# Entity extraction & log building
# ---------------------------------------------------------------------------

def _extract_session_entities(network_data: dict) -> dict:
    """Extract IOC entities from parsed pcap data."""
    entities: dict[str, set] = {
        "ips": set(),
        "domains": set(),
        "urls": set(),
    }

    # From TCP connections
    for conn in network_data.get("tcp_connections", []):
        dst_ip = conn.get("dst_ip", "")
        if dst_ip and not dst_ip.startswith("127."):
            entities["ips"].add(dst_ip)

    # From DNS queries
    for dns in network_data.get("dns_queries", []):
        query = dns.get("query", "")
        if query:
            entities["domains"].add(query)

    # From HTTP requests
    for req in network_data.get("http_requests", []):
        url = req.get("url", "")
        if url:
            entities["urls"].add(url)
        host = req.get("host", "")
        if host:
            entities["domains"].add(host)

    # From TLS SNI
    for sni in network_data.get("tls_sni", []):
        domain = sni.get("domain", "")
        if domain:
            entities["domains"].add(domain)
        dst_ip = sni.get("dst_ip", "")
        if dst_ip:
            entities["ips"].add(dst_ip)

    return {k: sorted(v) for k, v in entities.items()}


def _build_log_rows(network_data: dict) -> list[dict]:
    """Build normalised log rows for the downstream pipeline."""
    rows: list[dict] = []

    for dns in network_data.get("dns_queries", []):
        rows.append({
            "TimeCreated": "",
            "Domain": dns.get("query", ""),
            "_source": "browser_session",
            "_artefact": "dns_query",
        })

    for conn in network_data.get("tcp_connections", []):
        rows.append({
            "TimeCreated": "",
            "SrcIP": conn.get("src_ip", ""),
            "DstIP": conn.get("dst_ip", ""),
            "DstPort": conn.get("dst_port", ""),
            "_source": "browser_session",
            "_artefact": "tcp_connection",
        })

    for req in network_data.get("http_requests", []):
        rows.append({
            "TimeCreated": "",
            "Method": req.get("method", ""),
            "URL": req.get("url", ""),
            "Host": req.get("host", ""),
            "_source": "browser_session",
            "_artefact": "http_request",
        })

    for sni in network_data.get("tls_sni", []):
        rows.append({
            "TimeCreated": "",
            "Domain": sni.get("domain", ""),
            "DstIP": sni.get("dst_ip", ""),
            "_source": "browser_session",
            "_artefact": "tls_sni",
        })

    return rows


def _build_network_summary(network_data: dict) -> dict:
    """Build a summary dict from parsed network data."""
    unique_domains: set[str] = set()
    unique_ips: set[str] = set()

    for dns in network_data.get("dns_queries", []):
        q = dns.get("query", "")
        if q:
            unique_domains.add(q)

    for conn in network_data.get("tcp_connections", []):
        ip = conn.get("dst_ip", "")
        if ip and not ip.startswith("127."):
            unique_ips.add(ip)

    for sni in network_data.get("tls_sni", []):
        d = sni.get("domain", "")
        if d:
            unique_domains.add(d)
        ip = sni.get("dst_ip", "")
        if ip:
            unique_ips.add(ip)

    for req in network_data.get("http_requests", []):
        h = req.get("host", "")
        if h:
            unique_domains.add(h)

    return {
        "dns_queries": len(network_data.get("dns_queries", [])),
        "tcp_connections": len(network_data.get("tcp_connections", [])),
        "http_requests": len(network_data.get("http_requests", [])),
        "tls_sni_domains": len(network_data.get("tls_sni", [])),
        "unique_domains": sorted(unique_domains),
        "unique_ips": sorted(unique_ips),
        "pcap_stats": network_data.get("pcap_stats", {}),
    }


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Disposable browser session management.")
    sub = p.add_subparsers(dest="mode", required=True)

    p_start = sub.add_parser("start", help="Start a browser session.")
    p_start.add_argument("url", help="Starting URL")
    p_start.add_argument("--case", default="", dest="case_id",
                         help="Optional case ID (no case created if omitted)")

    p_stop = sub.add_parser("stop", help="Stop a browser session.")
    p_stop.add_argument("--session", required=True, dest="session_id")

    p_list = sub.add_parser("list", help="List active sessions.")

    args = p.parse_args()

    if args.mode == "start":
        result = start_session(args.url, args.case_id or "")
        if result["status"] == "ok":
            session_id = result["session_id"]
            idle_timeout = result.get("idle_timeout", 300)
            done_event = _session_done_events.get(session_id)
            print(f"\nSession ID: {session_id}")
            try:
                if idle_timeout > 0:
                    print(f"Press Ctrl+C to stop, or wait — auto-stops after {int(idle_timeout)}s of network inactivity")
                else:
                    print("Press Ctrl+C to stop the session and collect artefacts...")
                if done_event:
                    done_event.wait()
                else:
                    signal.pause()
            except KeyboardInterrupt:
                log_error("", "browser_session:cli_keyboard_interrupt",
                          "User interrupted session via Ctrl+C",
                          severity="info", traceback=False,
                          context={"session_id": session_id})
                print("\n")
            # Stop (idempotent if watchdog already handled it)
            state = _load_session_state(session_id)
            if state and state.get("status") == "completed":
                stop_result = _session_results.get(session_id, {"status": "ok"})
            else:
                stop_result = stop_session(session_id)
            print(json.dumps(stop_result, indent=2, default=str))
        else:
            print(f"Error: {result['reason']}")
            sys.exit(1)

    elif args.mode == "stop":
        result = stop_session(args.session_id)
        print(json.dumps(result, indent=2, default=str))

    elif args.mode == "list":
        sessions = list_sessions()
        if not sessions:
            print("No sessions found.")
        for s in sessions:
            status = s.get("status", "unknown")
            sid = s.get("session_id", "?")
            url = s.get("start_url", "")
            started = s.get("started_at", "")
            print(f"  [{status.upper():10s}] {sid}  {url}  (started {started})")
