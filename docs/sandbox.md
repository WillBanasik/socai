# Sandbox Detonation

Containerised malware sandbox for dynamic analysis of suspicious files. Executes samples inside a locked-down Docker container while capturing syscalls, network traffic, filesystem changes, and process creation.

## Setup

### Build Docker Images

```bash
# Linux sandbox (~150 MB)
docker build -t socai-sandbox:latest -f docker/sandbox/Dockerfile docker/sandbox/

# Wine-enabled Windows PE sandbox (~450 MB) — layered on Linux image
docker build -t socai-sandbox-wine:latest -f docker/sandbox/Dockerfile.wine docker/sandbox/
```

### Configuration

Environment variables (set in `.env` or shell):

| Variable | Default | Description |
|---|---|---|
| `SOCAI_SANDBOX_IMAGE` | `socai-sandbox:latest` | Linux sandbox Docker image |
| `SOCAI_SANDBOX_WINE_IMAGE` | `socai-sandbox-wine:latest` | Wine sandbox Docker image |
| `SOCAI_SANDBOX_TIMEOUT_LOCAL` | `120` | Default execution timeout (seconds) |
| `SOCAI_SANDBOX_MAX_TIMEOUT` | `600` | Maximum allowed timeout |
| `SOCAI_SANDBOX_MEMORY` | `512m` | Container memory limit |
| `SOCAI_SANDBOX_CPUS` | `1.0` | Container CPU limit |
| `SOCAI_SANDBOX_NETWORK` | `monitor` | Default network mode (`monitor`, `isolate`, or `vpn`) |
| `SOCAI_SANDBOX_NETWORK_NAME` | `socai_sandbox_net` | Docker bridge network name |
| `SOCAI_VPN_CONTAINER` | `gluetun` | Container name for `vpn` network mode |

## Usage

### CLI

```bash
# Automated detonation (default)
python3 socai.py sandbox-session /path/to/sample --case IV_CASE_001

# With options
python3 socai.py sandbox-session /path/to/sample --case IV_CASE_001 \
    --timeout 180 --network isolate --severity high

# Interactive mode (keep container running for manual inspection)
python3 socai.py sandbox-session /path/to/sample --case IV_CASE_001 --interactive

# Session management
python3 socai.py sandbox-stop --session <session-id>
python3 socai.py sandbox-list
```

### MCP Tools

Four tools available via MCP:

- **start_sandbox_session** — start detonation (auto-selects Linux or Wine image)
- **stop_sandbox_session** — stop session, collect artefacts
- **list_sandbox_sessions** — list active/completed sessions
- **sandbox_exec** — execute a command inside a running sandbox (interactive mode only)

### Investigation Integration

Cloud sandbox lookups (Hybrid Analysis, Any.Run, Joe Sandbox) run via `sandbox_api_lookup`. If no definitive cloud results, the analyst can start a local detonation session. Collected telemetry feeds into enrichment, correlation, and reporting.

## Network Modes

### Monitor (default)

- Custom Docker bridge network `socai_sandbox_net` with `--internal` flag (no external gateway)
- Honeypot DNS/HTTP server runs inside the container:
  - **Fake DNS** (UDP 53) — responds to all queries with a honeypot IP, logs every domain queried
  - **Fake HTTP/HTTPS** (TCP 80, 443) — accepts all requests, logs method/path/headers/body
- Malware reveals C2 domains and beacon patterns without real egress

### Isolate

- Uses `--network=none` — fully air-gapped, no network stack at all
- Use for samples known to be destructive or when honeypot responses could influence behaviour

## Artefacts

All artefacts are written via `write_artefact()`/`save_json()` to:

```
cases/<case_id>/artefacts/sandbox_detonation/
  sandbox_manifest.json        # Session metadata, sample hashes, duration, image
  strace_log.json              # Parsed syscall trace (categorised: file/network/process/permission)
  network_capture.pcap         # Raw packet capture
  network_log.json             # Parsed network activity (DNS, TCP, HTTP)
  honeypot_log.json            # Honeypot DNS/HTTP interactions
  filesystem_changes.json      # Before/after filesystem diff
  process_tree.json            # All spawned processes with cmdlines
  dns_queries.json             # DNS lookups attempted (combined pcap + honeypot)
  dropped_files/               # Files created by the malware (hash-prefixed)
  dropped_files_manifest.json  # Manifest of dropped files with hashes
  strings_extracted.json       # Strings from stdout/stderr/dropped files
  interactive_log.json         # Commands sent via sandbox_exec (if interactive)
  llm_analysis.json            # LLM behavioural analysis (MITRE mapping, risk score)
```

Normalised output for downstream IOC extraction:

```
cases/<case_id>/logs/
  mde_sandbox_detonation.parsed.json    # Normalised log rows
  mde_sandbox_detonation.entities.json  # Extracted entities (IPs, domains, URLs, hashes)
```

## Interactive Mode

Interactive mode keeps the container running and allows Claude (or the analyst) to exec commands:

```python
# Via Web UI tool
sandbox_exec(session_id="sbx_abc123", command="cat /proc/1/maps")
sandbox_exec(session_id="sbx_abc123", command="lsof -i")
sandbox_exec(session_id="sbx_abc123", command="ss -tlnp")
```

Guard rails:
- Commands execute as the `sandbox` user (non-root)
- 30-second per-command timeout (max 60s)
- All commands are logged in `interactive_log.json`

## Safety & Isolation

| Risk | Mitigation |
|---|---|
| Container escape | `--cap-drop=ALL` (only SYS_PTRACE + NET_RAW added), `--security-opt=no-new-privileges`, non-root user, default seccomp profile |
| Network egress | Custom bridge with no gateway (honeypot mode); `--network=none` (isolate); `--network=container:gluetun` (vpn — routes through Mullvad VPN) |
| Disk exhaustion | `--tmpfs` with size limits: workspace 200 MB, tmp 100 MB, telemetry 300 MB |
| Fork bomb | `--pids-limit=256` |
| Resource exhaustion | `--cpus=1.0`, `--memory=512m` |
| Timeout failure | `timeout` command in container + host-side `wait_for_completion()` + `docker stop` with 10s grace |
| Strace/pcap bloat | Capped at 50 MB / 100 MB respectively |
| Interactive abuse | Commands exec as non-root `sandbox` user, per-command timeout |

## Sample Type Detection

The sandbox auto-detects sample types and routes execution accordingly:

| Type | Detection | Execution |
|---|---|---|
| ELF | `\x7fELF` magic bytes | Direct execution under strace |
| PE (Windows) | `MZ` magic bytes or `.exe`/`.dll`/`.scr` extension | Wine64/Wine under strace (requires Wine image) |
| Shell script | `#!/` shebang or `.sh` extension | `/bin/bash` under strace |
| Python script | `.py` extension | `python3` under strace |
| ZIP/tar/gzip | Magic bytes or extension | Extract, find first executable, execute |
| Unknown | Fallback | Attempt direct execution |
