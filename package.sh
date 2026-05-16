#!/usr/bin/env bash
# package.sh — bundle socai for handover
# Run from the repo root on Will's machine before sending.
#
# Usage:
#   ./package.sh              # code + config + .env + cases/ (full handover)
#   ./package.sh --lean       # exclude cases/ (~370 MB) for a smaller bundle
#
# Output: socai-handover.tar.gz in the current directory

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT_TMP="/tmp/socai-handover.tar.gz"
OUT="$REPO_ROOT/socai-handover.tar.gz"
INCLUDE_CASES=true

for arg in "$@"; do
  [[ "$arg" == "--lean" ]] && INCLUDE_CASES=false
done

echo "==> Packaging socai from $REPO_ROOT"
[[ "$INCLUDE_CASES" == true ]] && echo "    Mode: full (cases/ included)" || echo "    Mode: lean (cases/ excluded)"

# Always-excluded patterns
EXCLUDES=(
  "./.venv"
  "./.git"
  "./__pycache__"
  "./tools/__pycache__"
  "./mcp_server/__pycache__"
  "./api/__pycache__"
  "./config/__pycache__"
  "./agents/__pycache__"
  "./scripts/__pycache__"
  "./*.pyc"
  "./**/*.pyc"
  "./browser_sessions"
  "./sandbox_sessions"
  "./sessions"
  "./articles_*.zip"
  "./socai-handover.tar.gz"
  "./package.sh"
)

# Build --exclude flags
EXCLUDE_FLAGS=()
for e in "${EXCLUDES[@]}"; do
  EXCLUDE_FLAGS+=(--exclude="$e")
done

if [[ "$INCLUDE_CASES" == false ]]; then
  EXCLUDE_FLAGS+=(--exclude="./cases")
  echo "    (Pass no flags for full handover including case history)"
fi

cd "$REPO_ROOT"

tar -czf "$OUT_TMP" \
  "${EXCLUDE_FLAGS[@]}" \
  --exclude-vcs-ignores \
  . && mv "$OUT_TMP" "$OUT"

SIZE=$(du -sh "$OUT" | cut -f1)
echo "==> Done: $OUT ($SIZE)"
echo ""
echo ""
echo "Send both files to your manager:"
echo "  - socai-handover.tar.gz"
echo "  - install.sh"
echo ""
echo "They place both in the same directory (e.g. ~/Downloads) and run:"
echo "  bash install.sh"
