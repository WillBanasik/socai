"""
tool: browser_session
---------------------
Spin up a disposable Docker-based Chrome browser session for manual
phishing page investigation.  The analyst gets a live browser via noVNC
while socai monitors all network activity via Chrome DevTools Protocol.

The session captures every HTTP request, response, redirect, and cookie
— giving full visibility into phishing kit behaviour even when automated
web capture fails (e.g. Cloudflare challenges, CAPTCHAs, JS-gated pages).

Architecture:
  selenium/standalone-chrome container (--network=host)
    ├── noVNC on :7900   → analyst opens in their browser
    ├── Selenium on :4444 → session management
    └── CDP on :9222      → network monitoring (page-level WebSocket)

Writes:
  cases/<case_id>/artefacts/browser_session/
    ├── session_manifest.json        (metadata + summary)
    ├── network_log.json             (full request/response log)
    ├── redirect_chains.json         (all redirect chains observed)
    ├── cookies.json                 (all cookies set during session)
    ├── console_log.json             (browser console output)
    ├── screenshot_final.png         (screenshot at session close)
    └── responses/                   (response bodies for HTML pages)
  cases/<case_id>/logs/mde_browser_session.parsed.json
  cases/<case_id>/logs/mde_browser_session.entities.json

Usage (CLI):
  python3 socai.py browser-session https://phish.com --case C001
  python3 socai.py browser-stop --session <session_id>

Usage (standalone):
  python3 tools/browser_session.py start https://phish.com --case C001
  python3 tools/browser_session.py stop --session <session_id>
  python3 tools/browser_session.py list
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import CASES_DIR
from tools.common import log_error, save_json, utcnow, write_artefact

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DOCKER_IMAGE = "selenium/standalone-chrome:latest"
CONTAINER_PREFIX = "socai_browser_"
SHM_SIZE = "2g"

# Port allocation — use --network=host so all container ports are on localhost
# We use Selenium to create a session with CDP enabled, then monitor via CDP
SELENIUM_PORT = 4444
NOVNC_PORT = 7900
CDP_PORT = 9222

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


def _find_available_ports() -> dict:
    """Check that required ports are available (host networking mode).

    With --network=host, the container uses the host's network stack directly,
    so ports must be free on the host.
    """
    ports = {"novnc": NOVNC_PORT, "selenium": SELENIUM_PORT, "cdp": CDP_PORT}
    for name, port in ports.items():
        if not _is_port_available(port):
            raise RuntimeError(
                f"Port {port} ({name}) is already in use. "
                f"Is another browser session running? Check with: python3 socai.py browser-list"
            )
    return ports


def _start_container(session_id: str, ports: dict) -> str:
    """Start the Selenium Chrome container with --network=host.

    Uses host networking so CDP (bound to 127.0.0.1 inside the container)
    is accessible from the host without port forwarding tricks.

    Returns container ID.
    """
    name = _container_name(session_id)

    cmd = [
        "docker", "run", "--rm", "-d",
        "--name", name,
        "--shm-size", SHM_SIZE,
        "--network=host",
        # noVNC password is 'secret' by default — disable it
        "-e", "SE_VNC_NO_PASSWORD=1",
        "-e", "SE_SCREEN_WIDTH=1920",
        "-e", "SE_SCREEN_HEIGHT=1080",
        DOCKER_IMAGE,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Docker start failed: {result.stderr.strip()}")

    return result.stdout.strip()


def _create_chrome_session(selenium_port: int, start_url: str = "") -> dict:
    """Create a Chrome session via Selenium with CDP enabled.

    Returns session info including session_id and debugger address.
    """
    payload = {
        "capabilities": {
            "alwaysMatch": {
                "browserName": "chrome",
                "goog:chromeOptions": {
                    "args": [
                        "--no-sandbox",
                        "--remote-debugging-port=9222",
                        "--disable-infobars",
                        "--disable-extensions",
                        "--disable-dev-shm-usage",
                        "--window-size=1920,1080",
                        # Don't restore previous session
                        "--no-first-run",
                        "--no-default-browser-check",
                    ],
                },
            },
        },
    }

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"http://localhost:{selenium_port}/session",
        data=data,
        headers={"Content-Type": "application/json"},
    )

    resp = urllib.request.urlopen(req, timeout=30)
    result = json.loads(resp.read())

    session_data = result["value"]
    chrome_opts = session_data.get("capabilities", {}).get("goog:chromeOptions", {})

    return {
        "selenium_session_id": session_data["sessionId"],
        "debugger_address": chrome_opts.get("debuggerAddress", "localhost:9222"),
        "browser_version": session_data.get("capabilities", {}).get("browserVersion", ""),
    }


def _navigate_to_url(selenium_port: int, selenium_session_id: str, url: str) -> None:
    """Navigate the browser to a URL via Selenium."""
    payload = json.dumps({"url": url}).encode()
    req = urllib.request.Request(
        f"http://localhost:{selenium_port}/session/{selenium_session_id}/url",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=30)


def _take_screenshot(selenium_port: int, selenium_session_id: str) -> bytes | None:
    """Take a screenshot via Selenium."""
    try:
        req = urllib.request.Request(
            f"http://localhost:{selenium_port}/session/{selenium_session_id}/screenshot",
        )
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        import base64
        return base64.b64decode(data["value"])
    except Exception:
        return None


def _get_cookies(selenium_port: int, selenium_session_id: str) -> list[dict]:
    """Get all cookies from the browser session."""
    try:
        req = urllib.request.Request(
            f"http://localhost:{selenium_port}/session/{selenium_session_id}/cookie",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        return data.get("value", [])
    except Exception:
        return []


def _get_current_url(selenium_port: int, selenium_session_id: str) -> str:
    """Get the current URL from the browser."""
    try:
        req = urllib.request.Request(
            f"http://localhost:{selenium_port}/session/{selenium_session_id}/url",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        return data.get("value", "")
    except Exception:
        return ""


def _stop_container(session_id: str) -> None:
    """Stop and remove the container."""
    name = _container_name(session_id)
    subprocess.run(["docker", "stop", name], capture_output=True, timeout=30)


# ---------------------------------------------------------------------------
# CDP monitoring (runs in background thread)
# ---------------------------------------------------------------------------

class CDPMonitor:
    """Background CDP monitor that captures network events, console logs, etc."""

    def __init__(self, cdp_port: int = CDP_PORT, flush_path: Path | None = None):
        self.cdp_port = cdp_port
        self.requests: list[dict] = []
        self.responses: list[dict] = []
        self.redirects: list[dict] = []
        self.cookies_set: list[dict] = []
        self.console_logs: list[dict] = []
        self.dns_resolutions: dict[str, dict] = {}  # domain -> {ips, first_seen, last_seen}
        self.response_bodies: dict[str, str] = {}  # requestId -> body
        self._running = False
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ws_url: str = ""
        self._flush_path = flush_path  # periodic flush for cross-process recovery
        self._flush_lock = threading.Lock()

    def start(self) -> None:
        """Start monitoring in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def wait_ready(self, timeout: float = 30) -> bool:
        """Wait until CDP monitoring is connected and listening."""
        return self._ready.wait(timeout=timeout)

    def stop(self) -> None:
        """Stop monitoring and wait for thread to finish."""
        self._running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        """Main monitoring loop (runs in thread)."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._monitor())
        except Exception:
            pass  # Expected when stopping
        finally:
            # Clean up pending tasks to avoid warnings
            try:
                pending = asyncio.all_tasks(self._loop)
                for task in pending:
                    task.cancel()
                if pending:
                    self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                self._loop.close()
            except Exception:
                pass

    async def _monitor(self) -> None:
        """Connect to CDP and listen for events."""
        import websockets

        # Get page target WebSocket URL
        retries = 0
        while self._running and retries < 30:
            try:
                data = urllib.request.urlopen(
                    f"http://localhost:{self.cdp_port}/json", timeout=5
                ).read()
                targets = json.loads(data)
                page_targets = [t for t in targets if t.get("type") == "page"]
                if page_targets:
                    self._ws_url = page_targets[0]["webSocketDebuggerUrl"]
                    break
            except Exception:
                retries += 1
                await asyncio.sleep(1)

        if not self._ws_url:
            return

        try:
            async with websockets.connect(
                self._ws_url, max_size=50 * 1024 * 1024
            ) as ws:
                # Enable all the domains we want to monitor
                msg_id = 1
                for method in [
                    "Network.enable",
                    "Page.enable",
                    "Runtime.enable",
                    "Security.enable",
                ]:
                    await ws.send(json.dumps({"id": msg_id, "method": method}))
                    msg_id += 1
                    try:
                        await asyncio.wait_for(ws.recv(), timeout=5)
                    except asyncio.TimeoutError:
                        pass

                # Signal that monitoring is ready
                self._ready.set()

                # Listen for events with periodic disk flush
                _flush_counter = 0
                while self._running:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=1)
                        evt = json.loads(raw)
                        if "method" in evt:
                            self._handle_event(evt)
                            _flush_counter += 1
                            # Flush to disk every 50 events
                            if _flush_counter >= 50:
                                self.flush_to_disk()
                                _flush_counter = 0
                    except asyncio.TimeoutError:
                        # Flush on idle too
                        if _flush_counter > 0:
                            self.flush_to_disk()
                            _flush_counter = 0
                        continue
                    except Exception:
                        if not self._running:
                            break
                        await asyncio.sleep(0.5)
                # Final flush before exit
                self.flush_to_disk()

        except Exception:
            pass  # Connection closed

    def _handle_event(self, evt: dict) -> None:
        """Process a CDP event."""
        method = evt["method"]
        params = evt.get("params", {})
        ts = utcnow()

        if method == "Network.requestWillBeSent":
            request = params.get("request", {})
            entry = {
                "ts": ts,
                "requestId": params.get("requestId", ""),
                "method": request.get("method", ""),
                "url": request.get("url", ""),
                "headers": request.get("headers", {}),
                "postData": request.get("postData", ""),
                "type": params.get("type", ""),
                "initiator": params.get("initiator", {}).get("type", ""),
                "redirectResponse": None,
            }

            # Track redirects
            redirect_resp = params.get("redirectResponse")
            if redirect_resp:
                entry["redirectResponse"] = {
                    "status": redirect_resp.get("status", 0),
                    "url": redirect_resp.get("url", ""),
                    "headers": redirect_resp.get("headers", {}),
                }
                self.redirects.append({
                    "ts": ts,
                    "from_url": redirect_resp.get("url", ""),
                    "to_url": request.get("url", ""),
                    "status": redirect_resp.get("status", 0),
                })

            self.requests.append(entry)

        elif method == "Network.responseReceived":
            response = params.get("response", {})
            entry = {
                "ts": ts,
                "requestId": params.get("requestId", ""),
                "url": response.get("url", ""),
                "status": response.get("status", 0),
                "statusText": response.get("statusText", ""),
                "mimeType": response.get("mimeType", ""),
                "headers": response.get("headers", {}),
                "remoteIPAddress": response.get("remoteIPAddress", ""),
                "remotePort": response.get("remotePort", 0),
                "protocol": response.get("protocol", ""),
                "securityState": response.get("securityState", ""),
            }
            self.responses.append(entry)

            # Track DNS resolutions (domain → IP mapping)
            remote_ip = response.get("remoteIPAddress", "")
            if remote_ip:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(response.get("url", ""))
                    domain = parsed.hostname
                    if domain and domain != remote_ip:
                        if domain not in self.dns_resolutions:
                            self.dns_resolutions[domain] = {
                                "ips": set(),
                                "first_seen": ts,
                                "last_seen": ts,
                                "request_count": 0,
                            }
                        self.dns_resolutions[domain]["ips"].add(remote_ip)
                        self.dns_resolutions[domain]["last_seen"] = ts
                        self.dns_resolutions[domain]["request_count"] += 1
                except Exception:
                    pass

            # Track cookies from Set-Cookie headers
            set_cookies = response.get("headers", {}).get("set-cookie", "")
            if set_cookies:
                self.cookies_set.append({
                    "ts": ts,
                    "url": response.get("url", ""),
                    "set_cookie": set_cookies,
                })

        elif method == "Runtime.consoleAPICalled":
            args = params.get("args", [])
            text = " ".join(
                a.get("value", a.get("description", str(a))) for a in args
            )
            self.console_logs.append({
                "ts": ts,
                "type": params.get("type", "log"),
                "text": text[:2000],
            })

    def get_summary(self) -> dict:
        """Return a summary of captured data."""
        unique_domains = set()
        unique_ips = set()
        all_urls = set()
        methods_seen = set()

        for req in self.requests:
            url = req.get("url", "")
            all_urls.add(url)
            methods_seen.add(req.get("method", ""))
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.hostname:
                    unique_domains.add(parsed.hostname)
            except Exception:
                pass

        for resp in self.responses:
            ip = resp.get("remoteIPAddress", "")
            if ip:
                unique_ips.add(ip)

        return {
            "total_requests": len(self.requests),
            "total_responses": len(self.responses),
            "total_redirects": len(self.redirects),
            "unique_domains": sorted(unique_domains),
            "unique_ips": sorted(unique_ips),
            "unique_urls": sorted(all_urls),
            "http_methods": sorted(methods_seen),
            "cookies_set": len(self.cookies_set),
            "console_entries": len(self.console_logs),
            "dns_resolutions": len(self.dns_resolutions),
        }

    def get_dns_log(self) -> list[dict]:
        """Return DNS resolution table (domain → resolved IPs)."""
        entries = []
        for domain, info in sorted(self.dns_resolutions.items()):
            entries.append({
                "domain": domain,
                "resolved_ips": sorted(info["ips"]),
                "first_seen": info["first_seen"],
                "last_seen": info["last_seen"],
                "request_count": info["request_count"],
            })
        return entries

    def flush_to_disk(self) -> None:
        """Persist captured data to disk for cross-process recovery."""
        if not self._flush_path:
            return
        with self._flush_lock:
            data = {
                "requests": self.requests,
                "responses": self.responses,
                "redirects": self.redirects,
                "cookies_set": self.cookies_set,
                "console_logs": self.console_logs,
                "dns_resolutions": {
                    d: {**info, "ips": sorted(info["ips"])}
                    for d, info in self.dns_resolutions.items()
                },
                "flushed_at": utcnow(),
            }
            try:
                self._flush_path.parent.mkdir(parents=True, exist_ok=True)
                self._flush_path.write_text(json.dumps(data, default=str))
            except Exception:
                pass


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
    except Exception:
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
        except Exception:
            continue
    return sessions


# ---------------------------------------------------------------------------
# Session lifecycle (in-process monitor registry)
# ---------------------------------------------------------------------------

# Active monitors keyed by session_id — only valid within the current process
_active_monitors: dict[str, CDPMonitor] = {}


def _flush_path_for(session_id: str) -> Path:
    """Return the disk flush path for a session's CDP data."""
    return SESSIONS_DIR / f"{session_id}_cdp.json"


def _recover_cdp_data(session_id: str) -> dict | None:
    """Load CDP data from disk flush file (cross-process recovery)."""
    path = _flush_path_for(session_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        # Reconstruct dns_resolutions sets from sorted lists
        for domain, info in data.get("dns_resolutions", {}).items():
            if isinstance(info.get("ips"), list):
                info["ips"] = set(info["ips"])
        return data
    except Exception:
        return None


def _cleanup_flush_file(session_id: str) -> None:
    """Remove the CDP flush file after collection."""
    path = _flush_path_for(session_id)
    if path.exists():
        try:
            path.unlink()
        except Exception:
            pass


def start_session(
    url: str,
    case_id: str,
    *,
    session_id: str = "",
) -> dict:
    """Start a disposable browser session for manual investigation.

    Args:
        url: Starting URL to navigate to.
        case_id: Target case ID.
        session_id: Optional custom session ID (auto-generated if empty).

    Returns:
        Session manifest with connection details.
    """
    if not session_id:
        import hashlib
        session_id = hashlib.sha256(
            f"{case_id}:{url}:{time.time()}".encode()
        ).hexdigest()[:12]

    # Check for existing active sessions
    existing = _list_session_states()
    active = [s for s in existing if s.get("status") == "active"]
    if active:
        # Verify they're actually running
        for s in active:
            container = _container_name(s["session_id"])
            check = subprocess.run(
                ["docker", "inspect", container, "--format", "{{.State.Running}}"],
                capture_output=True, text=True,
            )
            if check.returncode != 0 or "true" not in check.stdout:
                s["status"] = "orphaned"
                _save_session_state(s["session_id"], s)

    # Find available ports
    ports = _find_available_ports()

    print(f"[browser] Starting session {session_id}...")
    print(f"[browser] Ports: noVNC={ports['novnc']}, Selenium={ports['selenium']}")

    # Start Docker container
    try:
        container_id = _start_container(session_id, ports)
    except RuntimeError as exc:
        return {"status": "error", "reason": str(exc)}

    print(f"[browser] Container started: {container_id[:12]}")

    # Wait for Selenium to be ready
    print("[browser] Waiting for Chrome to start...")
    ready = False
    for _ in range(30):
        try:
            resp = urllib.request.urlopen(
                f"http://localhost:{ports['selenium']}/status", timeout=3
            )
            status = json.loads(resp.read())
            if status.get("value", {}).get("ready"):
                ready = True
                break
        except Exception:
            time.sleep(1)

    if not ready:
        _stop_container(session_id)
        return {"status": "error", "reason": "Chrome failed to start within 30 seconds"}

    # Create Chrome session with CDP enabled
    try:
        chrome_session = _create_chrome_session(ports["selenium"], url)
    except Exception as exc:
        _stop_container(session_id)
        return {"status": "error", "reason": f"Failed to create Chrome session: {exc}"}

    print(f"[browser] Chrome {chrome_session['browser_version']} ready")

    # Start CDP monitor
    # Parse the CDP port from the debugger address
    debugger_addr = chrome_session.get("debugger_address", "localhost:9222")
    cdp_port = int(debugger_addr.split(":")[-1])

    monitor = CDPMonitor(cdp_port=cdp_port, flush_path=_flush_path_for(session_id))
    monitor.start()
    _active_monitors[session_id] = monitor

    # Wait for CDP monitoring to be connected before navigating
    if not monitor.wait_ready(timeout=15):
        print("[browser] Warning: CDP monitor not ready — traffic capture may be incomplete")

    # Navigate to target URL
    if url:
        try:
            _navigate_to_url(ports["selenium"], chrome_session["selenium_session_id"], url)
            print(f"[browser] Navigated to: {url}")
        except Exception as exc:
            print(f"[browser] Navigation warning: {exc}")

    # Allow monitor to capture initial page load
    time.sleep(2)

    # Save session state
    state = {
        "session_id": session_id,
        "case_id": case_id,
        "status": "active",
        "start_url": url,
        "container_id": container_id[:12],
        "ports": ports,
        "cdp_port": cdp_port,
        "selenium_session_id": chrome_session["selenium_session_id"],
        "browser_version": chrome_session["browser_version"],
        "started_at": utcnow(),
        "novnc_url": f"http://localhost:{ports['novnc']}",
    }
    _save_session_state(session_id, state)

    manifest = {
        "status": "ok",
        "session_id": session_id,
        "case_id": case_id,
        "novnc_url": f"http://localhost:{ports['novnc']}",
        "start_url": url,
        "browser_version": chrome_session["browser_version"],
        "started_at": state["started_at"],
        "message": (
            f"Browser session started. Open in your browser:\n"
            f"  {state['novnc_url']}\n\n"
            f"CDP monitoring active — all network traffic is being captured.\n"
            f"When done, stop the session:\n"
            f"  python3 socai.py browser-stop --session {session_id}"
        ),
    }

    print(f"\n[browser] {'='*60}")
    print(f"[browser] Session {session_id} is LIVE")
    print(f"[browser] Open in your browser: {state['novnc_url']}")
    print(f"[browser] CDP monitoring active — all traffic being captured")
    print(f"[browser] {'='*60}\n")

    return manifest


def stop_session(
    session_id: str,
    *,
    take_screenshot: bool = True,
) -> dict:
    """Stop a browser session, collect all captured data, and tear down.

    Args:
        session_id: Session ID to stop.
        take_screenshot: Whether to capture a final screenshot before stopping.

    Returns:
        Session results manifest.
    """
    state = _load_session_state(session_id)
    if not state:
        return {"status": "error", "reason": f"Session not found: {session_id}"}

    case_id = state["case_id"]
    ports = state.get("ports", {})
    selenium_session_id = state.get("selenium_session_id", "")
    selenium_port = ports.get("selenium", SELENIUM_PORT)

    print(f"[browser] Stopping session {session_id}...")

    # Get final URL
    final_url = _get_current_url(selenium_port, selenium_session_id)

    # Take final screenshot
    screenshot_bytes = None
    if take_screenshot:
        screenshot_bytes = _take_screenshot(selenium_port, selenium_session_id)
        if screenshot_bytes:
            print(f"[browser] Final screenshot captured ({len(screenshot_bytes)} bytes)")

    # Get cookies
    cookies = _get_cookies(selenium_port, selenium_session_id)

    # Stop CDP monitor and collect data
    monitor = _active_monitors.pop(session_id, None)
    dns_log = []
    if monitor:
        monitor.stop()
        network_summary = monitor.get_summary()
        requests_log = monitor.requests
        responses_log = monitor.responses
        redirects = monitor.redirects
        cookies_from_headers = monitor.cookies_set
        console_logs = monitor.console_logs
        dns_log = monitor.get_dns_log()
    else:
        # Monitor not in this process — recover from disk flush
        recovered = _recover_cdp_data(session_id)
        if recovered:
            print("[browser] Recovered CDP data from disk flush")
            requests_log = recovered.get("requests", [])
            responses_log = recovered.get("responses", [])
            redirects = recovered.get("redirects", [])
            cookies_from_headers = recovered.get("cookies_set", [])
            console_logs = recovered.get("console_logs", [])
            # Rebuild DNS log from recovered data
            dns_res = recovered.get("dns_resolutions", {})
            dns_log = [
                {
                    "domain": d,
                    "resolved_ips": sorted(info["ips"]) if isinstance(info["ips"], set) else info["ips"],
                    "first_seen": info.get("first_seen", ""),
                    "last_seen": info.get("last_seen", ""),
                    "request_count": info.get("request_count", 0),
                }
                for d, info in sorted(dns_res.items())
            ]
            # Build summary from recovered data
            unique_domains = set()
            unique_ips = set()
            for req in requests_log:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(req.get("url", ""))
                    if parsed.hostname:
                        unique_domains.add(parsed.hostname)
                except Exception:
                    pass
            for resp in responses_log:
                ip = resp.get("remoteIPAddress", "")
                if ip:
                    unique_ips.add(ip)
            network_summary = {
                "total_requests": len(requests_log),
                "total_responses": len(responses_log),
                "total_redirects": len(redirects),
                "unique_domains": sorted(unique_domains),
                "unique_ips": sorted(unique_ips),
                "cookies_set": len(cookies_from_headers),
                "console_entries": len(console_logs),
                "dns_resolutions": len(dns_log),
                "recovered_from_disk": True,
            }
        else:
            print("[browser] Warning: no CDP monitor and no flush file — network data lost")
            network_summary = {}
            requests_log = []
            responses_log = []
            redirects = []
            cookies_from_headers = []
            console_logs = []

    _cleanup_flush_file(session_id)

    # Stop container
    _stop_container(session_id)
    print("[browser] Container destroyed")

    # Write artefacts
    out_dir = CASES_DIR / case_id / "artefacts" / "browser_session"
    out_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = CASES_DIR / case_id / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Network log
    write_artefact(
        out_dir / "network_log.json",
        json.dumps({"requests": requests_log, "responses": responses_log}, indent=2, default=str),
    )

    # Redirect chains
    write_artefact(
        out_dir / "redirect_chains.json",
        json.dumps(redirects, indent=2, default=str),
    )

    # Cookies (merged from Selenium + CDP)
    all_cookies = {
        "selenium_cookies": cookies,
        "set_cookie_headers": cookies_from_headers,
    }
    write_artefact(
        out_dir / "cookies.json",
        json.dumps(all_cookies, indent=2, default=str),
    )

    # Console log
    if console_logs:
        write_artefact(
            out_dir / "console_log.json",
            json.dumps(console_logs, indent=2, default=str),
        )

    # DNS resolution log
    if dns_log:
        write_artefact(
            out_dir / "dns_log.json",
            json.dumps(dns_log, indent=2, default=str),
        )

    # Screenshot
    if screenshot_bytes:
        write_artefact(out_dir / "screenshot_final.png", screenshot_bytes)

    # Extract entities for downstream tools
    entities = _extract_session_entities(requests_log, responses_log, redirects, cookies)

    # Write normalised log for downstream pipeline
    log_rows = []
    for req in requests_log:
        log_rows.append({
            "TimeCreated": req.get("ts", ""),
            "Method": req.get("method", ""),
            "URL": req.get("url", ""),
            "Type": req.get("type", ""),
            "Initiator": req.get("initiator", ""),
            "PostData": (req.get("postData", "") or "")[:500],
            "_source": "browser_session",
            "_artefact": "network_request",
        })
    for resp in responses_log:
        log_rows.append({
            "TimeCreated": resp.get("ts", ""),
            "URL": resp.get("url", ""),
            "Status": resp.get("status", ""),
            "MimeType": resp.get("mimeType", ""),
            "RemoteIP": resp.get("remoteIPAddress", ""),
            "RemotePort": resp.get("remotePort", ""),
            "Protocol": resp.get("protocol", ""),
            "_source": "browser_session",
            "_artefact": "network_response",
        })
    for dns_entry in dns_log:
        log_rows.append({
            "TimeCreated": dns_entry.get("first_seen", ""),
            "Domain": dns_entry.get("domain", ""),
            "ResolvedIPs": ", ".join(dns_entry.get("resolved_ips", [])),
            "RequestCount": dns_entry.get("request_count", 0),
            "_source": "browser_session",
            "_artefact": "dns_resolution",
        })

    log_result = {
        "source_file": f"browser_session:{session_id}",
        "case_id": case_id,
        "format": "cdp_capture",
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

    # Build session manifest
    duration_sec = 0
    try:
        from datetime import datetime, timezone
        started = datetime.fromisoformat(state["started_at"].replace("Z", "+00:00"))
        duration_sec = int((datetime.now(timezone.utc) - started).total_seconds())
    except Exception:
        pass

    manifest = {
        "status": "ok",
        "session_id": session_id,
        "case_id": case_id,
        "start_url": state.get("start_url", ""),
        "final_url": final_url,
        "started_at": state.get("started_at", ""),
        "stopped_at": utcnow(),
        "duration_seconds": duration_sec,
        "browser_version": state.get("browser_version", ""),
        "network_summary": network_summary,
        "cookies_count": len(cookies),
        "console_entries": len(console_logs),
        "redirect_count": len(redirects),
        "entities": {k: len(v) for k, v in entities.items()},
        "dns_resolutions": dns_log,
        "artefacts": {
            "network_log": str(out_dir / "network_log.json"),
            "redirect_chains": str(out_dir / "redirect_chains.json"),
            "cookies": str(out_dir / "cookies.json"),
            "dns_log": str(out_dir / "dns_log.json") if dns_log else None,
            "screenshot": str(out_dir / "screenshot_final.png") if screenshot_bytes else None,
            "console_log": str(out_dir / "console_log.json") if console_logs else None,
        },
    }

    save_json(out_dir / "session_manifest.json", manifest)

    # Update session state
    state["status"] = "completed"
    state["stopped_at"] = utcnow()
    _save_session_state(session_id, state)

    # Print summary
    print(f"\n[browser] {'='*60}")
    print(f"[browser] Session {session_id} COMPLETE")
    print(f"[browser] Duration: {duration_sec}s")
    print(f"[browser] Start URL: {state.get('start_url', 'N/A')}")
    print(f"[browser] Final URL: {final_url}")
    if network_summary:
        print(f"[browser] Requests: {network_summary.get('total_requests', 0)}")
        print(f"[browser] Responses: {network_summary.get('total_responses', 0)}")
        print(f"[browser] Redirects: {network_summary.get('total_redirects', 0)}")
        print(f"[browser] Domains: {len(network_summary.get('unique_domains', []))}")
        print(f"[browser] IPs: {len(network_summary.get('unique_ips', []))}")
        print(f"[browser] Cookies: {len(cookies)}")
    if dns_log:
        print(f"[browser] DNS resolutions: {len(dns_log)}")
        for entry in dns_log:
            ips = ", ".join(entry["resolved_ips"])
            print(f"  {entry['domain']} → {ips}  ({entry['request_count']} reqs)")
    if redirects:
        print(f"[browser] Redirect chain:")
        for r in redirects:
            print(f"  {r['status']} {r['from_url']}")
            print(f"    → {r['to_url']}")
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
    """Stop any orphaned session containers and clean up state."""
    cleaned = 0
    for s in _list_session_states():
        if s.get("status") in ("orphaned", "active"):
            container = _container_name(s["session_id"])
            subprocess.run(["docker", "stop", container], capture_output=True, timeout=10)
            s["status"] = "cleaned"
            _save_session_state(s["session_id"], s)
            cleaned += 1
    return cleaned


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------

def _extract_session_entities(
    requests_log: list[dict],
    responses_log: list[dict],
    redirects: list[dict],
    cookies: list[dict],
) -> dict:
    """Extract IOC entities from the session data."""
    from urllib.parse import urlparse

    entities: dict[str, set] = {
        "ips": set(),
        "domains": set(),
        "urls": set(),
        "users": set(),
        "cookies": set(),
        "post_data_fields": set(),
    }

    for req in requests_log:
        url = req.get("url", "")
        if url:
            entities["urls"].add(url)
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    entities["domains"].add(parsed.hostname)
            except Exception:
                pass

        # Extract form field names from POST data (credential harvesting indicator)
        post_data = req.get("postData", "")
        if post_data:
            # URL-encoded form data
            for field in re.findall(r"([a-zA-Z_][\w]*)=", post_data):
                entities["post_data_fields"].add(field.lower())

    for resp in responses_log:
        ip = resp.get("remoteIPAddress", "")
        if ip:
            entities["ips"].add(ip)
        url = resp.get("url", "")
        if url:
            entities["urls"].add(url)
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    entities["domains"].add(parsed.hostname)
            except Exception:
                pass

    for r in redirects:
        for key in ("from_url", "to_url"):
            url = r.get(key, "")
            if url:
                entities["urls"].add(url)

    for cookie in cookies:
        name = cookie.get("name", "")
        if name:
            entities["cookies"].add(name)

    return {k: sorted(v) for k, v in entities.items()}


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Disposable browser session management.")
    sub = p.add_subparsers(dest="mode", required=True)

    p_start = sub.add_parser("start", help="Start a browser session.")
    p_start.add_argument("url", help="Starting URL")
    p_start.add_argument("--case", required=True, dest="case_id")

    p_stop = sub.add_parser("stop", help="Stop a browser session.")
    p_stop.add_argument("--session", required=True, dest="session_id")

    p_list = sub.add_parser("list", help="List active sessions.")

    args = p.parse_args()

    if args.mode == "start":
        result = start_session(args.url, args.case_id)
        if result["status"] == "ok":
            print(f"\nSession ID: {result['session_id']}")
            # Block until Ctrl+C
            try:
                print("Press Ctrl+C to stop the session and collect artefacts...")
                signal.pause()
            except KeyboardInterrupt:
                print("\n")
                stop_result = stop_session(result["session_id"])
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
