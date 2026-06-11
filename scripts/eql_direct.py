#!/usr/bin/env python3
"""Direct EQL gateway client (bypasses the MCP layer).

Reads the Encore *refresh* token from $ENCORE_EQL_TOKEN, exchanges it for a
30-minute access token via /auth/refresh, then runs requests against the
gateway. A browser User-Agent is required — the default urllib/curl UA is
blocked by Cloudflare (403) before reaching the app.

Usage:
    python3 scripts/eql_direct.py clients
    python3 scripts/eql_direct.py query "list tables" --client <name>
    python3 scripts/eql_direct.py query "list version" --client <name>
    python3 scripts/eql_direct.py query "list labels" --client <name>
    python3 scripts/eql_direct.py query "list tables label:<label>" --client <name>

--client is mandatory for queries — there is deliberately no default tenant.

The refresh token is never printed. Guard it — it has access to all Encore clients.

$ENCORE_EQL_TOKEN is read from the repo `.env` (preferred, single source of
truth) or the shell environment.
"""
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Load the repo .env so creds live in one place (matches config/settings.py).
# Best-effort: fall back to the shell environment if python-dotenv is absent.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

BASE = "https://za.encore.io/gateway/api"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


def _req(method, path, *, token=None, body=None, accept="application/json"):
    url = BASE + path
    data = None
    headers = {"User-Agent": UA, "Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        else:
            data = str(body).encode()
            headers["Content-Type"] = "text/plain"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, raw
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def get_access_token():
    refresh = os.environ.get("ENCORE_EQL_TOKEN", "").strip()
    if not refresh:
        sys.exit("ENCORE_EQL_TOKEN is not set in the environment.")
    status, raw = _req("POST", "/auth/refresh", body={"refreshToken": refresh})
    if status != 200:
        sys.exit(f"Refresh failed (HTTP {status}): {raw[:300]}")
    try:
        return json.loads(raw)["accessToken"]
    except (ValueError, KeyError):
        sys.exit(f"Refresh returned unexpected body: {raw[:300]}")


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    cmd = args[0]
    token = get_access_token()

    if cmd == "clients":
        status, raw = _req("GET", "/system/clients", token=token)
        print(f"HTTP {status}")
        try:
            print(json.dumps(json.loads(raw), indent=2))
        except ValueError:
            print(raw)
        return

    if cmd == "query":
        if len(args) < 2:
            sys.exit('Usage: query "<eql>" --client <name>')
        eql = args[1]
        # No default tenant: an unscoped query silently runs against the
        # MSSP's own client (the 2026-06-01 workspace-leak class). Require
        # explicit scoping every time.
        if "--client" not in args or args.index("--client") + 1 >= len(args):
            sys.exit("Error: --client <name> is required (no default tenant; "
                     "run 'clients' to list valid names).")
        client = args[args.index("--client") + 1]
        path = f"/client/request?client={urllib.parse.quote(client)}"
        status, raw = _req("POST", path, token=token, body=eql, accept="application/json")
        print(f"HTTP {status}  (client={client})  query={eql!r}")
        try:
            print(json.dumps(json.loads(raw), indent=2))
        except ValueError:
            print(raw)
        return

    sys.exit(f"Unknown command: {cmd}\n{__doc__}")


if __name__ == "__main__":
    import urllib.parse  # noqa: E402
    main()
