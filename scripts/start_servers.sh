#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Kill any existing MCP server on port 8001
if lsof -ti:8001 &>/dev/null; then
    echo "Stopping existing MCP server on port 8001..."
    kill $(lsof -ti:8001) 2>/dev/null || true
    sleep 1
fi

echo "Starting MCP server (SSE on 127.0.0.1:8001)..."
python3 -m mcp_server &
MCP_PID=$!

# Wait briefly then confirm it started
sleep 2
if kill -0 "$MCP_PID" 2>/dev/null; then
    echo "MCP server running (PID $MCP_PID)"
else
    echo "MCP server failed to start" >&2
    exit 1
fi

# Tail logs until interrupted
echo "Tailing logs — Ctrl+C to stop..."
trap "echo 'Shutting down...'; kill $MCP_PID 2>/dev/null; exit 0" INT TERM
tail -f mcp_server.log 2>/dev/null || wait "$MCP_PID"
