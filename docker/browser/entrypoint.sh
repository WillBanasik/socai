#!/usr/bin/env bash
# entrypoint.sh — stealth browser session bootstrap
# Starts Xvfb + openbox + Chrome + noVNC + tcpdump.
# No Selenium, no CDP, no automation markers.
set -euo pipefail

TELEMETRY="/telemetry"
START_URL="${START_URL:-about:blank}"
SCREEN_W="${SCREEN_WIDTH:-1920}"
SCREEN_H="${SCREEN_HEIGHT:-1080}"

date -u +"%Y-%m-%dT%H:%M:%SZ" > "$TELEMETRY/started_at.txt"

# -------------------------------------------------------------------------
# 1. Virtual display
# -------------------------------------------------------------------------
Xvfb :99 -screen 0 "${SCREEN_W}x${SCREEN_H}x24" -ac +extension GLX &
XVFB_PID=$!
sleep 1

# -------------------------------------------------------------------------
# 2. Window manager (lightweight, unobtrusive)
# -------------------------------------------------------------------------
openbox &
sleep 0.5

# -------------------------------------------------------------------------
# 3. Packet capture (runs as root for raw socket access)
# -------------------------------------------------------------------------
tcpdump -i any -w "$TELEMETRY/capture.pcap" -s 0 -q 'not (port 5900 or port 7900)' 2>/dev/null &
TCPDUMP_PID=$!

# -------------------------------------------------------------------------
# 4. VNC server (no password, localhost-bound — noVNC handles external access)
# -------------------------------------------------------------------------
x11vnc -display :99 -forever -shared -nopw -rfbport 5900 -q &
VNC_PID=$!
sleep 0.5

# -------------------------------------------------------------------------
# 5. noVNC (WebSocket → VNC bridge, serves the HTML5 client)
# -------------------------------------------------------------------------
websockify --web /usr/share/novnc ${NOVNC_PORT:-7900} localhost:5900 &
NOVNC_PID=$!

# -------------------------------------------------------------------------
# 6. Chrome (vanilla — no automation flags, no remote debugging)
# -------------------------------------------------------------------------
# Run as the analyst user with a fresh profile
su -s /bin/bash analyst -c "
    DISPLAY=:99 google-chrome-stable \
        --no-first-run \
        --no-default-browser-check \
        --disable-background-networking \
        --disable-sync \
        --disable-translate \
        --metrics-recording-only \
        --password-store=basic \
        --use-mock-keychain \
        --window-size=${SCREEN_W},${SCREEN_H} \
        --user-data-dir=/tmp/chrome-profile \
        '$START_URL' \
        &>/dev/null
" &
CHROME_PID=$!

echo "Browser session ready — noVNC on port ${NOVNC_PORT:-7900}"

# -------------------------------------------------------------------------
# 7. Wait for stop signal
# -------------------------------------------------------------------------
# Container stays alive until docker stop is called.
# Trap SIGTERM to clean up gracefully.
cleanup() {
    echo "Stopping browser session..."
    # Take a final screenshot if scrot is available
    DISPLAY=:99 scrot "$TELEMETRY/screenshot_final.png" 2>/dev/null || true
    kill $CHROME_PID $VNC_PID $NOVNC_PID $TCPDUMP_PID $XVFB_PID 2>/dev/null || true
    wait 2>/dev/null || true
    echo "Browser session stopped"
}
trap cleanup SIGTERM SIGINT

# Keep container alive
wait $CHROME_PID 2>/dev/null || true
# If Chrome exits (user closed it), keep container up for screenshot/cleanup
sleep infinity &
wait $! 2>/dev/null || true
