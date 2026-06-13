#!/usr/bin/env bash
# Refresh the Mullvad WireGuard key in deploy/.env.vpn from a downloaded .conf.
# Keeps the private key out of the terminal/chat — reads it straight from the file.
#
# Usage:  ./refresh_mullvad_key.sh /path/to/mullvad-XX.conf
#
# Gets PrivateKey + Address from the Mullvad WireGuard .conf, updates the two
# WIREGUARD_* lines in .env.vpn (with a timestamped backup), and recreates gluetun.
set -euo pipefail

CONF="${1:?usage: refresh_mullvad_key.sh <mullvad-wireguard.conf>}"
cd "$(dirname "$0")"
ENV_FILE=".env.vpn"
COMPOSE="docker-compose.vpn.yml"

[ -f "$CONF" ]      || { echo "no such file: $CONF" >&2; exit 1; }
[ -f "$ENV_FILE" ]  || { echo "missing $ENV_FILE (run from socai repo)" >&2; exit 1; }

backup=".env.vpn.bak.$(date -u +%Y%m%dT%H%M%SZ)"
cp -a "$ENV_FILE" "$backup"
echo "backed up $ENV_FILE -> $backup"

# Python does the rewrite so base64 chars (/ + =) in the key never hit a shell substitution.
python3 - "$CONF" "$ENV_FILE" <<'PY'
import re, sys
conf, envf = sys.argv[1], sys.argv[2]
text = open(conf).read()

def grab(key):
    m = re.search(rf'^\s*{key}\s*=\s*(.+?)\s*$', text, re.M)
    if not m:
        sys.exit(f"{key} not found in {conf} — is this a Mullvad WireGuard .conf?")
    return m.group(1).strip()

priv = grab("PrivateKey")
addr = grab("Address")

lines = open(envf).read().splitlines()
seen = {"WIREGUARD_PRIVATE_KEY": False, "WIREGUARD_ADDRESSES": False}
out = []
for ln in lines:
    if ln.startswith("WIREGUARD_PRIVATE_KEY="):
        out.append(f"WIREGUARD_PRIVATE_KEY={priv}"); seen["WIREGUARD_PRIVATE_KEY"] = True
    elif ln.startswith("WIREGUARD_ADDRESSES="):
        out.append(f"WIREGUARD_ADDRESSES={addr}"); seen["WIREGUARD_ADDRESSES"] = True
    else:
        out.append(ln)
for k, present in seen.items():
    if not present:
        out.append(f"{k}={priv if k == 'WIREGUARD_PRIVATE_KEY' else addr}")
open(envf, "w").write("\n".join(out) + "\n")
print(f"updated WIREGUARD_PRIVATE_KEY (hidden) + WIREGUARD_ADDRESSES={addr}")
PY

echo "recreating gluetun..."
docker compose -f "$COMPOSE" up -d
echo "done. Give it ~15-30s, then ask Claude to verify (web_search probe + tun0 RX), or:"
echo "  docker exec gluetun ip -s link show tun0   # RX bytes should climb above 0"
