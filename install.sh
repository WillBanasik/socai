#!/usr/bin/env bash
# install.sh — one-shot setup for socai on a new WSL machine
# Place this file and socai-handover.tar.gz in the same directory, then run:
#   bash install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARBALL="$SCRIPT_DIR/socai-handover.tar.gz"
INSTALL_DIR="$HOME/socai"

echo "======================================"
echo "  socai handover installer"
echo "======================================"
echo ""

# --- Preflight ---
if [[ ! -f "$TARBALL" ]]; then
  echo "ERROR: socai-handover.tar.gz not found next to install.sh"
  echo "Expected: $TARBALL"
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Install it with: sudo apt install python3 python3-venv python3-pip"
  exit 1
fi

PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Python $PYVER detected."

# --- Extract ---
echo ""
echo "--> Extracting to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
tar -xzf "$TARBALL" -C "$INSTALL_DIR"
echo "    Done."

# --- Virtual environment ---
echo ""
echo "--> Creating Python virtual environment ..."
cd "$INSTALL_DIR"
python3 -m venv .venv
echo "    Done."

# --- Dependencies ---
echo ""
echo "--> Installing Python dependencies ..."
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install -r requirements.txt
echo "    Done."

# --- Playwright ---
echo ""
echo "--> Installing Playwright (Chromium) ..."
if .venv/bin/python -c "import playwright" 2>/dev/null; then
  .venv/bin/playwright install chromium 2>&1 | tail -3
  echo "    Done."
else
  echo "    Playwright not in requirements — skipping."
fi

# --- Convenience wrapper ---
echo ""
echo "--> Writing 'socai' launcher to $INSTALL_DIR/socai ..."
cat > "$INSTALL_DIR/socai" <<'EOF'
#!/usr/bin/env bash
cd "$(dirname "$0")"
.venv/bin/python socai.py "$@"
EOF
chmod +x "$INSTALL_DIR/socai"
echo "    Done."

# --- Final instructions ---
echo ""
echo "======================================"
echo "  Installation complete!"
echo "======================================"
echo ""
echo "Location:  $INSTALL_DIR"
echo ""
echo "Quick start:"
echo "  cd $INSTALL_DIR"
echo ""
echo "  # Run the MCP server (for Claude Desktop):"
echo "  .venv/bin/python -m mcp_server"
echo ""
echo "  # Or use the CLI directly:"
echo "  ./socai --help"
echo "  ./socai create-case --title 'Test' --severity medium --analyst manager --client clientname"
echo ""
echo "  # Tail logs (open a second terminal):"
echo "  tail -f registry/audit.jsonl | python3 -c \\"
echo "    \"import sys,json,time; [print(json.loads(l).get('message','')) for l in sys.stdin]\""
echo ""
echo "See HANDOVER.md in $INSTALL_DIR for full usage notes."
