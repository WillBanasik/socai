"""
tool: sandbox_session
---------------------
Containerised malware sandbox for dynamic detonation of suspicious files.
Executes samples (ELF, scripts, Windows PE via Wine) inside a locked-down
Docker container while capturing syscalls, network traffic, filesystem
changes, and process creation.

Supports two modes:
  - Automated (default): execute sample, wait for completion, collect artefacts
  - Interactive (--interactive): keep container running for manual inspection
    via exec_in_sandbox()

Network modes:
  - monitor (default): custom bridge with honeypot DNS/HTTP (no real egress)
  - isolate: --network=none (fully air-gapped)

Architecture:
  Docker container (socai-sandbox / socai-sandbox-wine)
    ├── entrypoint.sh       → bootstrap monitoring + execute sample
    ├── monitor.py          → process tree, filesystem, strace, network parsing
    ├── honeypot.py         → fake DNS/HTTP for C2 domain discovery
    └── telemetry/          → all captured data

Writes:
  cases/<case_id>/artefacts/sandbox_detonation/
    ├── sandbox_manifest.json
    ├── strace_log.json
    ├── network_capture.pcap
    ├── network_log.json
    ├── honeypot_log.json
    ├── filesystem_changes.json
    ├── process_tree.json
    ├── dns_queries.json
    ├── dropped_files/
    ├── strings_extracted.json
    └── interactive_log.json
  cases/<case_id>/logs/
    ├── mde_sandbox_detonation.parsed.json
    └── mde_sandbox_detonation.entities.json

Usage (CLI):
  python3 socai.py sandbox-session /path/to/sample --case IV_CASE_001
  python3 socai.py sandbox-stop --session <session_id>
  python3 socai.py sandbox-list

Usage (standalone):
  python3 tools/sandbox_session.py start /path/to/sample --case IV_CASE_001
  python3 tools/sandbox_session.py stop --session <session_id>
  python3 tools/sandbox_session.py list
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import log_error, save_json, sha256_file, utcnow, write_artefact

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SANDBOX_IMAGE = os.getenv("SOCAI_SANDBOX_IMAGE", "socai-sandbox:latest")
SANDBOX_WINE_IMAGE = os.getenv("SOCAI_SANDBOX_WINE_IMAGE", "socai-sandbox-wine:latest")
SANDBOX_DEFAULT_TIMEOUT = int(os.getenv("SOCAI_SANDBOX_TIMEOUT_LOCAL", "120"))
SANDBOX_MAX_TIMEOUT = int(os.getenv("SOCAI_SANDBOX_MAX_TIMEOUT", "600"))
SANDBOX_MEMORY_LIMIT = os.getenv("SOCAI_SANDBOX_MEMORY", "512m")
SANDBOX_CPU_LIMIT = os.getenv("SOCAI_SANDBOX_CPUS", "1.0")
SANDBOX_DEFAULT_NETWORK = os.getenv("SOCAI_SANDBOX_NETWORK", "monitor")
SANDBOX_NETWORK_NAME = os.getenv("SOCAI_SANDBOX_NETWORK_NAME", "socai_sandbox_net")

CONTAINER_PREFIX = "socai_sandbox_"
SESSIONS_DIR = Path(__file__).resolve().parent.parent / "sandbox_sessions"

# Case ID pattern: C001-style or TEST_AUTOMATED_001-style (alphanumeric + underscore)
_RE_CASE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")

# Size caps for artefacts
STRACE_MAX_BYTES = 50 * 1024 * 1024   # 50 MB
PCAP_MAX_BYTES = 100 * 1024 * 1024    # 100 MB

# IOC regex patterns (reused from browser_session / memory_guidance)
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|top|"
    r"ru|cn|tk|ml|ga|cf|gq|cc|pw|club|online|site|icu|uk|de|fr|au|ca|in|br)\b",
    re.IGNORECASE,
)
_RE_URL = re.compile(r"https?://[^\s\"'<>]{5,}")
_RE_HASH_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_RE_HASH_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)

# Magic bytes for PE detection
_PE_MAGIC = b"MZ"


# ---------------------------------------------------------------------------
# Sample type detection
# ---------------------------------------------------------------------------

def _detect_sample_type(sample_path: Path) -> str:
    """Detect sample type from magic bytes and file extension."""
    try:
        with open(sample_path, "rb") as f:
            header = f.read(16)
    except (FileNotFoundError, PermissionError):
        return "unknown"

    sigs = {
        b"MZ": "pe",
        b"\x7fELF": "elf",
        b"PK\x03\x04": "archive_zip",
        b"\x1f\x8b": "archive_gzip",
        b"BZh": "archive_bzip2",
        b"#!/": "script",
    }
    for magic, label in sigs.items():
        if header.startswith(magic):
            return label

    ext = sample_path.suffix.lower()
    ext_map = {
        ".py": "script", ".sh": "script", ".bash": "script",
        ".pl": "script", ".ps1": "script", ".bat": "script",
        ".vbs": "script", ".js": "script",
        ".exe": "pe", ".dll": "pe", ".scr": "pe",
        ".zip": "archive_zip", ".tar": "archive_tar",
        ".gz": "archive_gzip", ".tgz": "archive_gzip",
    }
    return ext_map.get(ext, "unknown")


def _needs_wine(sample_path: Path) -> bool:
    """Return True if the sample is a Windows PE requiring Wine."""
    return _detect_sample_type(sample_path) == "pe"


# ---------------------------------------------------------------------------
# Docker management
# ---------------------------------------------------------------------------

def _container_name(session_id: str) -> str:
    return f"{CONTAINER_PREFIX}{session_id}"


def _is_container_running(session_id: str) -> bool:
    """Check if the sandbox container is currently running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", _container_name(session_id)],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip().lower() == "true"
    except Exception:
        return False


def _ensure_network() -> None:
    """Create the sandbox bridge network if it doesn't exist (no external gateway)."""
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", SANDBOX_NETWORK_NAME],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return  # Already exists
    except Exception:
        pass

    try:
        subprocess.run(
            ["docker", "network", "create",
             "--driver", "bridge",
             "--internal",  # No external gateway
             "--subnet", "10.99.99.0/24",
             SANDBOX_NETWORK_NAME],
            capture_output=True, text=True, timeout=30,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Failed to create sandbox network: {exc.stderr}") from exc


def _start_container(
    session_id: str,
    sample_path: Path,
    *,
    timeout: int = SANDBOX_DEFAULT_TIMEOUT,
    network_mode: str = SANDBOX_DEFAULT_NETWORK,
    interactive: bool = False,
) -> str:
    """Start the sandbox Docker container with the sample mounted."""
    name = _container_name(session_id)
    use_wine = _needs_wine(sample_path)
    image = SANDBOX_WINE_IMAGE if use_wine else SANDBOX_IMAGE

    # Network configuration
    if network_mode == "isolate":
        network_args = ["--network=none"]
    else:
        _ensure_network()
        network_args = [f"--network={SANDBOX_NETWORK_NAME}"]

    # Build docker run command
    cmd = [
        "docker", "run",
        "--name", name,
        "--detach",
        # Resource limits
        f"--cpus={SANDBOX_CPU_LIMIT}",
        f"--memory={SANDBOX_MEMORY_LIMIT}",
        "--pids-limit=256",
        # Security
        "--cap-drop=ALL",
        "--cap-add=SYS_PTRACE",   # Required for strace
        "--cap-add=NET_RAW",      # Required for tcpdump
        "--security-opt=no-new-privileges",
        # Read-only root with writable tmpfs for workspace and tmp
        "--read-only",
        "--tmpfs", "/tmp:exec,size=100m",
        "--tmpfs", "/sandbox/workspace:exec,size=200m",
        "--tmpfs", "/sandbox/telemetry:exec,size=300m",
        # Mount sample
        "-v", f"{sample_path.resolve()}:/sandbox/input/{sample_path.name}:ro",
        # Environment
        "-e", f"SANDBOX_TIMEOUT={timeout}",
        "-e", f"SANDBOX_SAMPLE={sample_path.name}",
        "-e", f"SANDBOX_NETWORK_MODE={network_mode}",
        *network_args,
        image,
    ]

    if interactive:
        # For interactive mode, override entrypoint to just copy sample and idle
        cmd = [
            "docker", "run",
            "--name", name,
            "--detach",
            f"--cpus={SANDBOX_CPU_LIMIT}",
            f"--memory={SANDBOX_MEMORY_LIMIT}",
            "--pids-limit=256",
            "--cap-drop=ALL",
            "--cap-add=SYS_PTRACE",
            "--cap-add=NET_RAW",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--tmpfs", "/tmp:exec,size=100m",
            "--tmpfs", "/sandbox/workspace:exec,size=200m",
            "--tmpfs", "/sandbox/telemetry:exec,size=300m",
            "-v", f"{sample_path.resolve()}:/sandbox/input/{sample_path.name}:ro",
            "-e", f"SANDBOX_TIMEOUT={timeout}",
            "-e", f"SANDBOX_SAMPLE={sample_path.name}",
            "-e", f"SANDBOX_NETWORK_MODE={network_mode}",
            *network_args,
            "--entrypoint", "/bin/bash",
            image,
            "-c",
            # Copy sample to workspace and idle (wait for exec commands or timeout)
            f"cp /sandbox/input/{sample_path.name} /sandbox/workspace/{sample_path.name} && "
            f"chmod +x /sandbox/workspace/{sample_path.name} 2>/dev/null; "
            f"sleep {timeout}",
        ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, check=True,
        )
        container_id = result.stdout.strip()[:12]
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Failed to start sandbox container: {exc.stderr}"
        ) from exc

    # For automated mode: copy sample into workspace (tmpfs)
    if not interactive:
        try:
            subprocess.run(
                ["docker", "exec", name, "cp",
                 f"/sandbox/input/{sample_path.name}",
                 f"/sandbox/workspace/{sample_path.name}"],
                capture_output=True, text=True, timeout=10,
            )
        except Exception:
            pass

    return container_id


def _stop_container(session_id: str) -> None:
    """Stop and remove the sandbox container."""
    name = _container_name(session_id)
    try:
        subprocess.run(
            ["docker", "stop", "--time", "10", name],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        pass
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True, text=True, timeout=15,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Session state management
# ---------------------------------------------------------------------------

def _session_path(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.json"


def _save_session(state: dict) -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    save_json(_session_path(state["session_id"]), state)


def _load_session(session_id: str) -> dict | None:
    p = _session_path(session_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        return None


# ---------------------------------------------------------------------------
# Telemetry collection
# ---------------------------------------------------------------------------

def _copy_telemetry_from_container(session_id: str, dest_dir: Path) -> dict:
    """Copy telemetry files from the container's /sandbox/telemetry/ to host."""
    name = _container_name(session_id)
    dest_dir.mkdir(parents=True, exist_ok=True)

    files_copied = {}
    telemetry_files = [
        "strace_raw.log", "strace_parsed.jsonl", "strace_summary.json",
        "capture.pcap", "network_parsed.json",
        "process_tree.jsonl", "fs_events.jsonl",
        "system_changes.json", "honeypot_log.jsonl",
        "file_type.txt", "sample_category.txt",
        "stdout.log", "stderr.log",
        "execution_error.txt", "started_at.txt", "completed_at.txt",
        "fs_before.txt", "fs_after.txt",
    ]

    for filename in telemetry_files:
        try:
            result = subprocess.run(
                ["docker", "cp", f"{name}:/sandbox/telemetry/{filename}", str(dest_dir / filename)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and (dest_dir / filename).exists():
                files_copied[filename] = (dest_dir / filename).stat().st_size
        except Exception:
            pass

    # Copy dropped files directory
    dropped_dest = dest_dir / "dropped_files"
    try:
        subprocess.run(
            ["docker", "cp", f"{name}:/sandbox/telemetry/dropped_files", str(dropped_dest)],
            capture_output=True, text=True, timeout=30,
        )
        if dropped_dest.exists():
            files_copied["dropped_files"] = sum(
                f.stat().st_size for f in dropped_dest.iterdir() if f.is_file()
            )
    except Exception:
        pass

    return files_copied


# ---------------------------------------------------------------------------
# Artefact writing
# ---------------------------------------------------------------------------

def _collect_artefacts(session_id: str, case_id: str, telemetry_dir: Path) -> dict:
    """Parse raw telemetry into structured artefacts and write via write_artefact/save_json."""
    art_dir = CASES_DIR / case_id / "artefacts" / "sandbox_detonation"
    art_dir.mkdir(parents=True, exist_ok=True)
    artefacts: dict = {}

    # Strace log (parsed JSONL → JSON array)
    strace_parsed = telemetry_dir / "strace_parsed.jsonl"
    if strace_parsed.exists():
        records = []
        for line in strace_parsed.read_text(errors="replace").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        # Cap at 50 MB equivalent
        strace_data = records[:50000]
        artefacts["strace_log"] = save_json(art_dir / "strace_log.json", strace_data)

    # Network capture (raw pcap, copy if within size limit)
    pcap_src = telemetry_dir / "capture.pcap"
    if pcap_src.exists():
        size = pcap_src.stat().st_size
        if size <= PCAP_MAX_BYTES:
            artefacts["network_capture"] = write_artefact(
                art_dir / "network_capture.pcap",
                pcap_src.read_bytes(),
            )
        else:
            artefacts["network_capture"] = {
                "path": str(art_dir / "network_capture.pcap"),
                "truncated": True,
                "original_size": size,
            }

    # Network log (parsed)
    net_parsed = telemetry_dir / "network_parsed.json"
    if net_parsed.exists():
        try:
            net_data = json.loads(net_parsed.read_text())
            artefacts["network_log"] = save_json(art_dir / "network_log.json", net_data)
        except json.JSONDecodeError:
            pass

    # Honeypot log
    hp_log = telemetry_dir / "honeypot_log.jsonl"
    if hp_log.exists():
        records = []
        for line in hp_log.read_text(errors="replace").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        if records:
            artefacts["honeypot_log"] = save_json(art_dir / "honeypot_log.json", records)

    # Filesystem changes
    sys_changes = telemetry_dir / "system_changes.json"
    if sys_changes.exists():
        try:
            changes = json.loads(sys_changes.read_text())
            artefacts["filesystem_changes"] = save_json(
                art_dir / "filesystem_changes.json", changes,
            )
        except json.JSONDecodeError:
            pass

    # Process tree (JSONL → JSON array)
    proc_tree = telemetry_dir / "process_tree.jsonl"
    if proc_tree.exists():
        records = []
        for line in proc_tree.read_text(errors="replace").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        if records:
            artefacts["process_tree"] = save_json(art_dir / "process_tree.json", records)

    # DNS queries (extract from network + honeypot logs)
    dns_queries = _extract_dns_queries(telemetry_dir)
    if dns_queries:
        artefacts["dns_queries"] = save_json(art_dir / "dns_queries.json", dns_queries)

    # Dropped files (copy directory)
    dropped_src = telemetry_dir / "dropped_files"
    dropped_dest = art_dir / "dropped_files"
    if dropped_src.exists() and any(dropped_src.iterdir()):
        dropped_dest.mkdir(parents=True, exist_ok=True)
        dropped_manifest = []
        for f in sorted(dropped_src.iterdir()):
            if f.is_file():
                dest = dropped_dest / f.name
                shutil.copy2(f, dest)
                dropped_manifest.append({
                    "filename": f.name,
                    "size_bytes": f.stat().st_size,
                    "sha256": sha256_file(f),
                })
        artefacts["dropped_files"] = save_json(
            art_dir / "dropped_files_manifest.json", dropped_manifest,
        )

    # Strings extracted from stdout/stderr/dropped files
    strings = _extract_strings(telemetry_dir)
    if strings:
        artefacts["strings_extracted"] = save_json(art_dir / "strings_extracted.json", strings)

    return artefacts


def _extract_dns_queries(telemetry_dir: Path) -> list[dict]:
    """Extract DNS queries from network_parsed.json and honeypot_log.jsonl."""
    queries = []
    seen = set()

    # From network parse
    net_parsed = telemetry_dir / "network_parsed.json"
    if net_parsed.exists():
        try:
            data = json.loads(net_parsed.read_text())
            for q in data.get("dns_queries", []):
                domain = q.get("query", "")
                if domain and domain not in seen:
                    seen.add(domain)
                    queries.append({"domain": domain, "source": "pcap"})
        except json.JSONDecodeError:
            pass

    # From honeypot log
    hp_log = telemetry_dir / "honeypot_log.jsonl"
    if hp_log.exists():
        for line in hp_log.read_text(errors="replace").splitlines():
            try:
                event = json.loads(line)
                if event.get("type") == "dns":
                    domain = event.get("domain", "")
                    if domain and domain not in seen:
                        seen.add(domain)
                        queries.append({
                            "domain": domain,
                            "source": "honeypot",
                            "ts": event.get("ts"),
                        })
            except json.JSONDecodeError:
                pass

    return queries


def _extract_strings(telemetry_dir: Path) -> dict:
    """Extract interesting strings from stdout, stderr, and dropped files."""
    result: dict = {"interesting": [], "urls": [], "ips": [], "domains": []}
    all_text = ""

    for filename in ["stdout.log", "stderr.log"]:
        p = telemetry_dir / filename
        if p.exists():
            all_text += p.read_text(errors="replace")[:500000]

    # Dropped files
    dropped = telemetry_dir / "dropped_files"
    if dropped.exists():
        for f in dropped.iterdir():
            if f.is_file() and f.stat().st_size < 1_000_000:
                try:
                    all_text += f.read_text(errors="replace")[:200000]
                except Exception:
                    pass

    if not all_text:
        return result

    result["urls"] = list(set(_RE_URL.findall(all_text)))[:100]
    result["ips"] = list(set(_RE_IP.findall(all_text)))[:100]
    result["domains"] = list(set(_RE_DOMAIN.findall(all_text)))[:100]

    return result


# ---------------------------------------------------------------------------
# Entity extraction (normalised output for downstream IOC extraction)
# ---------------------------------------------------------------------------

def _extract_session_entities(case_id: str, artefacts: dict, telemetry_dir: Path) -> dict:
    """Extract entities (IPs, domains, URLs, hashes) and write normalised log rows."""
    entities: dict = {
        "ips": set(), "domains": set(), "urls": set(),
        "hashes_sha256": set(), "hashes_md5": set(),
    }

    # Scan all JSON artefacts for IOCs
    art_dir = CASES_DIR / case_id / "artefacts" / "sandbox_detonation"
    for json_file in art_dir.glob("*.json"):
        try:
            text = json_file.read_text(errors="replace")
            entities["ips"].update(_RE_IP.findall(text))
            entities["domains"].update(_RE_DOMAIN.findall(text))
            entities["urls"].update(_RE_URL.findall(text))
            entities["hashes_sha256"].update(_RE_HASH_SHA256.findall(text))
            entities["hashes_md5"].update(_RE_HASH_MD5.findall(text))
        except Exception:
            pass

    # Convert sets to sorted lists
    entity_dict = {k: sorted(v) for k, v in entities.items()}

    # Write normalised entities
    logs_dir = CASES_DIR / case_id / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    save_json(logs_dir / "mde_sandbox_detonation.entities.json", entity_dict)

    # Write normalised parsed log (process tree + network events)
    parsed_rows = []

    # Process tree events
    proc_tree = telemetry_dir / "process_tree.jsonl"
    if proc_tree.exists():
        for line in proc_tree.read_text(errors="replace").splitlines():
            try:
                rec = json.loads(line)
                parsed_rows.append({
                    "ts": rec.get("ts", ""),
                    "source": "sandbox_detonation",
                    "event_type": "process_create",
                    "pid": rec.get("pid"),
                    "ppid": rec.get("ppid"),
                    "exe": rec.get("exe", ""),
                    "cmdline": rec.get("cmdline", ""),
                })
            except json.JSONDecodeError:
                pass

    # Network connection events
    net_parsed = telemetry_dir / "network_parsed.json"
    if net_parsed.exists():
        try:
            data = json.loads(net_parsed.read_text())
            for conn in data.get("tcp_connections", []):
                parsed_rows.append({
                    "ts": "",
                    "source": "sandbox_detonation",
                    "event_type": "network_connection",
                    "src_ip": conn.get("src_ip", ""),
                    "src_port": conn.get("src_port"),
                    "dst_ip": conn.get("dst_ip", ""),
                    "dst_port": conn.get("dst_port"),
                })
            for q in data.get("dns_queries", []):
                parsed_rows.append({
                    "ts": "",
                    "source": "sandbox_detonation",
                    "event_type": "dns_query",
                    "domain": q.get("query", ""),
                })
        except json.JSONDecodeError:
            pass

    save_json(logs_dir / "mde_sandbox_detonation.parsed.json", parsed_rows)

    return entity_dict


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_session(
    sample_path: str | Path,
    case_id: str,
    *,
    timeout: int = SANDBOX_DEFAULT_TIMEOUT,
    network_mode: str = SANDBOX_DEFAULT_NETWORK,
    interactive: bool = False,
) -> dict:
    """Start a sandbox detonation session.

    Returns a dict with session_id, status, and metadata.
    """
    sample_path = Path(sample_path)
    if not sample_path.exists():
        return {"status": "error", "reason": f"Sample not found: {sample_path}"}

    # Validate case_id (prevent path traversal and empty values)
    if not case_id or not _RE_CASE_ID.match(case_id):
        return {"status": "error", "reason": f"Invalid case_id: {case_id!r}. Must be alphanumeric (e.g. IV_CASE_001)."}

    # Validate timeout
    timeout = min(max(timeout, 10), SANDBOX_MAX_TIMEOUT)

    # Generate session ID
    import uuid
    session_id = f"sbx_{uuid.uuid4().hex[:12]}"

    # Compute sample hash
    try:
        sample_hash = sha256_file(sample_path)
    except Exception as exc:
        return {"status": "error", "reason": f"Cannot hash sample: {exc}"}

    sample_type = _detect_sample_type(sample_path)
    use_wine = sample_type == "pe"

    try:
        container_id = _start_container(
            session_id, sample_path,
            timeout=timeout,
            network_mode=network_mode,
            interactive=interactive,
        )
    except RuntimeError as exc:
        return {"status": "error", "reason": str(exc)}

    state = {
        "session_id": session_id,
        "case_id": case_id,
        "status": "active",
        "container_id": container_id,
        "sample_path": str(sample_path),
        "sample_name": sample_path.name,
        "sample_sha256": sample_hash,
        "sample_type": sample_type,
        "image": SANDBOX_WINE_IMAGE if use_wine else SANDBOX_IMAGE,
        "timeout": timeout,
        "network_mode": network_mode,
        "interactive": interactive,
        "started_at": utcnow(),
        "interactive_log": [],
    }
    _save_session(state)

    message = (
        f"Sandbox session **{session_id}** started.\n"
        f"Sample: {sample_path.name} ({sample_type})\n"
        f"Image: {'Wine' if use_wine else 'Linux'} | "
        f"Network: {network_mode} | Timeout: {timeout}s"
    )
    if interactive:
        message += "\nInteractive mode — use `sandbox_exec` to send commands."
    else:
        message += "\nAutomated mode — execution will complete within the timeout."

    return {
        "status": "ok",
        "session_id": session_id,
        "case_id": case_id,
        "sample_type": sample_type,
        "sample_sha256": sample_hash,
        "image": state["image"],
        "network_mode": network_mode,
        "interactive": interactive,
        "started_at": state["started_at"],
        "message": message,
    }


def stop_session(session_id: str) -> dict:
    """Stop a sandbox session, collect artefacts, and tear down the container.

    Returns a manifest dict with all collected artefact paths and summary.
    """
    state = _load_session(session_id)
    if not state:
        return {"status": "error", "reason": f"Session {session_id} not found."}

    case_id = state["case_id"]
    started_at = state.get("started_at", "")

    # Create temp dir for telemetry collection
    telemetry_dir = Path(f"/tmp/socai_sandbox_{session_id}")
    telemetry_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Collect telemetry from container before stopping
        files_copied = _copy_telemetry_from_container(session_id, telemetry_dir)

        # Stop container
        _stop_container(session_id)

        # Write artefacts
        artefacts = _collect_artefacts(session_id, case_id, telemetry_dir)

        # Extract entities
        entities = _extract_session_entities(case_id, artefacts, telemetry_dir)

        # Write interactive log if any
        interactive_log = state.get("interactive_log", [])
        if interactive_log:
            art_dir = CASES_DIR / case_id / "artefacts" / "sandbox_detonation"
            artefacts["interactive_log"] = save_json(
                art_dir / "interactive_log.json", interactive_log,
            )

        # Read execution metadata
        file_type = ""
        sample_category = ""
        execution_error = ""
        try:
            ft = telemetry_dir / "file_type.txt"
            if ft.exists():
                file_type = ft.read_text().strip()
        except Exception:
            pass
        try:
            sc = telemetry_dir / "sample_category.txt"
            if sc.exists():
                sample_category = sc.read_text().strip()
        except Exception:
            pass
        try:
            ee = telemetry_dir / "execution_error.txt"
            if ee.exists():
                execution_error = ee.read_text().strip()
        except Exception:
            pass

        # Calculate duration
        duration = 0
        try:
            from datetime import datetime, timezone
            start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            from tools.common import utcnow as _utcnow
            _now = datetime.fromisoformat(_utcnow().replace("Z", "+00:00"))
            duration = int((_now - start).total_seconds())
        except Exception:
            pass

        # Write sandbox manifest
        manifest = {
            "session_id": session_id,
            "case_id": case_id,
            "sample_name": state.get("sample_name", ""),
            "sample_sha256": state.get("sample_sha256", ""),
            "sample_type": state.get("sample_type", ""),
            "detected_file_type": file_type,
            "sample_category": sample_category,
            "image": state.get("image", ""),
            "network_mode": state.get("network_mode", ""),
            "interactive": state.get("interactive", False),
            "timeout": state.get("timeout", 0),
            "duration_seconds": duration,
            "started_at": started_at,
            "stopped_at": utcnow(),
            "execution_error": execution_error,
            "telemetry_files": files_copied,
            "artefact_count": len(artefacts),
            "entities_summary": {k: len(v) for k, v in entities.items()},
        }
        art_dir = CASES_DIR / case_id / "artefacts" / "sandbox_detonation"
        artefacts["sandbox_manifest"] = save_json(
            art_dir / "sandbox_manifest.json", manifest,
        )

        # Update session state
        state["status"] = "completed"
        state["stopped_at"] = manifest["stopped_at"]
        state["duration_seconds"] = duration
        _save_session(state)

        # Clean up temp telemetry
        shutil.rmtree(telemetry_dir, ignore_errors=True)

        return {
            "status": "ok",
            "session_id": session_id,
            "case_id": case_id,
            "duration_seconds": duration,
            "sample_type": state.get("sample_type", ""),
            "execution_error": execution_error,
            "artefacts": {k: v.get("path", str(v)) if isinstance(v, dict) else str(v)
                          for k, v in artefacts.items()},
            "entities_summary": manifest["entities_summary"],
            "_message": (
                f"Sandbox session **{session_id}** stopped.\n"
                f"Duration: {duration}s | Sample: {state.get('sample_name', '')}\n"
                f"Artefacts: {len(artefacts)} | "
                f"IPs: {manifest['entities_summary'].get('ips', 0)}, "
                f"Domains: {manifest['entities_summary'].get('domains', 0)}, "
                f"URLs: {manifest['entities_summary'].get('urls', 0)}"
                + (f"\nExecution error: {execution_error}" if execution_error else "")
            ),
        }

    except Exception as exc:
        log_error(case_id, "sandbox_session.stop", str(exc),
                  severity="error", traceback=__import__("traceback").format_exc(),
                  context={"session_id": session_id})
        _stop_container(session_id)
        shutil.rmtree(telemetry_dir, ignore_errors=True)
        state["status"] = "error"
        _save_session(state)
        return {"status": "error", "reason": str(exc)}


def list_sessions() -> list[dict]:
    """List all sandbox sessions (active and completed)."""
    if not SESSIONS_DIR.exists():
        return []
    sessions = []
    for p in sorted(SESSIONS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            state = json.loads(p.read_text())
            # Update status for containers that have stopped unexpectedly
            if state.get("status") == "active" and not _is_container_running(state["session_id"]):
                state["status"] = "stopped_unclean"
                state["stopped_at"] = utcnow()
                # Persist the updated status so we don't re-check Docker every call
                try:
                    p.write_text(json.dumps(state, indent=2, default=str))
                except OSError:
                    pass
            sessions.append({
                "session_id": state.get("session_id", "?"),
                "case_id": state.get("case_id", ""),
                "status": state.get("status", "unknown"),
                "sample_name": state.get("sample_name", ""),
                "sample_type": state.get("sample_type", ""),
                "network_mode": state.get("network_mode", ""),
                "interactive": state.get("interactive", False),
                "started_at": state.get("started_at", ""),
                "stopped_at": state.get("stopped_at", ""),
            })
        except (json.JSONDecodeError, FileNotFoundError):
            pass
    return sessions


def exec_in_sandbox(session_id: str, command: str, *, timeout: int = 30) -> dict:
    """Execute a command inside a running sandbox container (interactive mode).

    Returns dict with stdout, stderr, return_code.
    """
    state = _load_session(session_id)
    if not state:
        return {"status": "error", "reason": f"Session {session_id} not found."}

    if state.get("status") != "active":
        return {"status": "error", "reason": f"Session is not active (status: {state.get('status')})."}

    if not state.get("interactive"):
        return {"status": "error", "reason": "Session is not in interactive mode. Start with --interactive."}

    if not _is_container_running(session_id):
        return {"status": "error", "reason": "Container is not running."}

    # Guard: cap timeout
    timeout = min(max(timeout, 1), 60)

    name = _container_name(session_id)
    try:
        result = subprocess.run(
            ["docker", "exec", "--user", "sandbox", name, "/bin/bash", "-c", command],
            capture_output=True, text=True, timeout=timeout,
        )
        output = {
            "status": "ok",
            "stdout": result.stdout[:10000],
            "stderr": result.stderr[:5000],
            "return_code": result.returncode,
            "_message": result.stdout[:3000] if result.stdout else result.stderr[:3000],
        }
    except subprocess.TimeoutExpired:
        output = {"status": "error", "reason": f"Command timed out after {timeout}s.",
                  "_message": f"Command timed out after {timeout}s."}
    except Exception as exc:
        output = {"status": "error", "reason": str(exc), "_message": f"Exec failed: {exc}"}

    # Log the command
    log_entry = {
        "ts": utcnow(),
        "command": command,
        "status": output.get("status"),
        "return_code": output.get("return_code"),
    }
    state.setdefault("interactive_log", []).append(log_entry)
    _save_session(state)

    return output


def wait_for_completion(session_id: str, *, poll_interval: float = 2.0, grace: int = 10) -> bool:
    """Block until the sandbox container exits. Returns True if completed normally."""
    state = _load_session(session_id)
    if not state:
        # Session file missing — stop any orphaned container rather than leaving it running
        _stop_container(session_id)
        return False

    timeout = state.get("timeout", SANDBOX_DEFAULT_TIMEOUT)
    deadline = time.time() + timeout + grace

    while time.time() < deadline:
        if not _is_container_running(session_id):
            return True
        time.sleep(poll_interval)

    # Force stop
    _stop_container(session_id)
    return False


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Sandbox session management")
    sub = parser.add_subparsers(dest="action")

    p_start = sub.add_parser("start", help="Start a sandbox session")
    p_start.add_argument("sample", help="Path to sample file")
    p_start.add_argument("--case", required=True, help="Case ID")
    p_start.add_argument("--timeout", type=int, default=SANDBOX_DEFAULT_TIMEOUT)
    p_start.add_argument("--network", default=SANDBOX_DEFAULT_NETWORK,
                         choices=["monitor", "isolate"])
    p_start.add_argument("--interactive", action="store_true")

    p_stop = sub.add_parser("stop", help="Stop a sandbox session")
    p_stop.add_argument("--session", required=True, help="Session ID")

    sub.add_parser("list", help="List sandbox sessions")

    args = parser.parse_args()

    if args.action == "start":
        result = start_session(
            args.sample, args.case,
            timeout=args.timeout,
            network_mode=args.network,
            interactive=args.interactive,
        )
        print(json.dumps(result, indent=2, default=str))

    elif args.action == "stop":
        result = stop_session(args.session)
        print(json.dumps(result, indent=2, default=str))

    elif args.action == "list":
        sessions = list_sessions()
        if not sessions:
            print("No sandbox sessions found.")
        else:
            for s in sessions:
                print(f"  [{s['status'].upper():15s}] {s['session_id']}  "
                      f"case={s['case_id']}  {s['sample_name']} ({s['sample_type']})")

    else:
        parser.print_help()
