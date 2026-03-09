#!/usr/bin/env python3
"""
honeypot.py — lightweight fake DNS/HTTP service for monitored network mode.

Runs inside the sandbox container alongside the sample. Responds to all DNS
queries with a honeypot IP and logs every request. Accepts all HTTP/HTTPS
requests, logs them, and returns generic responses.

Encourages malware to reveal C2 domains and beacon patterns without real egress.
"""
import json
import socket
import struct
import threading
import time
from pathlib import Path

TELEMETRY = Path("/sandbox/telemetry")
LOG_PATH = TELEMETRY / "honeypot_log.jsonl"
HONEYPOT_IP = "10.99.99.1"  # IP returned for all DNS queries
DNS_PORT = 53
HTTP_PORT = 80
HTTPS_PORT = 443


def utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_event(event: dict) -> None:
    """Append event to honeypot log."""
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_PATH, "a") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Fake DNS server
# ---------------------------------------------------------------------------

def _parse_dns_query(data: bytes) -> str | None:
    """Extract queried domain from DNS packet."""
    try:
        # Skip header (12 bytes)
        pos = 12
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) if labels else None
    except Exception:
        return None


def _build_dns_response(query_data: bytes, ip: str) -> bytes:
    """Build a DNS response for the given query, resolving to ip."""
    try:
        # Transaction ID + flags (standard response, no error)
        response = bytearray(query_data[:2])  # copy transaction ID
        response += b"\x81\x80"  # flags: response, recursion available
        response += query_data[4:6]  # questions count
        response += b"\x00\x01"  # answers count = 1
        response += b"\x00\x00"  # authority RRs
        response += b"\x00\x00"  # additional RRs

        # Copy question section
        pos = 12
        while pos < len(query_data) and query_data[pos] != 0:
            pos += 1 + query_data[pos]
        pos += 5  # null byte + qtype(2) + qclass(2)
        response += query_data[12:pos]

        # Answer: pointer to name + A record
        response += b"\xc0\x0c"  # pointer to name in question
        response += b"\x00\x01"  # type A
        response += b"\x00\x01"  # class IN
        response += struct.pack(">I", 300)  # TTL 300s
        response += b"\x00\x04"  # data length 4
        response += socket.inet_aton(ip)

        return bytes(response)
    except Exception:
        return b""


def run_dns_server() -> None:
    """UDP DNS server on port 53."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", DNS_PORT))
        sock.settimeout(1.0)
    except Exception:
        return

    complete = TELEMETRY / "execution_complete"
    while not complete.exists():
        try:
            data, addr = sock.recvfrom(4096)
            domain = _parse_dns_query(data)
            if domain:
                _log_event({
                    "ts": utcnow(),
                    "type": "dns",
                    "src": f"{addr[0]}:{addr[1]}",
                    "domain": domain,
                    "resolved_to": HONEYPOT_IP,
                })
                response = _build_dns_response(data, HONEYPOT_IP)
                if response:
                    sock.sendto(response, addr)
        except socket.timeout:
            continue
        except Exception:
            continue

    sock.close()


# ---------------------------------------------------------------------------
# Fake HTTP server
# ---------------------------------------------------------------------------

def _handle_http_client(conn: socket.socket, addr: tuple, port: int) -> None:
    """Handle a single HTTP client connection."""
    try:
        conn.settimeout(10)
        data = conn.recv(8192)
        if not data:
            return

        request_text = data.decode("utf-8", errors="replace")
        lines = request_text.split("\r\n")
        first_line = lines[0] if lines else ""

        # Parse method/path
        parts = first_line.split(" ", 2)
        method = parts[0] if parts else "UNKNOWN"
        path = parts[1] if len(parts) > 1 else "/"

        # Extract headers
        headers = {}
        body = ""
        header_done = False
        for line in lines[1:]:
            if not header_done:
                if line == "":
                    header_done = True
                    continue
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()
            else:
                body += line

        _log_event({
            "ts": utcnow(),
            "type": "http",
            "src": f"{addr[0]}:{addr[1]}",
            "port": port,
            "method": method,
            "path": path,
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
            "content_type": headers.get("content-type", ""),
            "body_preview": body[:500] if body else "",
        })

        # Generic HTTP response
        response_body = "<html><body>OK</body></html>"
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(response_body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{response_body}"
        )
        conn.sendall(response.encode())
    except Exception:
        pass
    finally:
        conn.close()


def run_http_server(port: int) -> None:
    """TCP HTTP server on specified port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(16)
        sock.settimeout(1.0)
    except Exception:
        return

    complete = TELEMETRY / "execution_complete"
    while not complete.exists():
        try:
            conn, addr = sock.accept()
            threading.Thread(
                target=_handle_http_client,
                args=(conn, addr, port),
                daemon=True,
            ).start()
        except socket.timeout:
            continue
        except Exception:
            continue

    sock.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    threads = [
        threading.Thread(target=run_dns_server, daemon=True),
        threading.Thread(target=run_http_server, args=(HTTP_PORT,), daemon=True),
        threading.Thread(target=run_http_server, args=(HTTPS_PORT,), daemon=True),
    ]
    for t in threads:
        t.start()

    # Wait for execution to complete
    while not (TELEMETRY / "execution_complete").exists():
        time.sleep(0.5)

    print("Honeypot: shutting down")


if __name__ == "__main__":
    main()
