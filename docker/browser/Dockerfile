# socai-browser — stealth browser session for phishing investigation
#
# No Selenium, no CDP, no automation markers.  Chrome runs as a normal
# desktop app via noVNC.  Network telemetry via tcpdump.
#
# Build:  docker build -t socai-browser:latest docker/browser/
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:99 \
    SCREEN_WIDTH=1920 \
    SCREEN_HEIGHT=1080 \
    VNC_PORT=5900 \
    NOVNC_PORT=7900

# System packages: Xvfb, VNC, window manager, tcpdump, utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb x11vnc openbox dbus-x11 \
        tcpdump net-tools procps \
        python3-minimal python3-websockify \
        novnc \
        wget gnupg2 ca-certificates fonts-liberation \
        libgbm1 libnss3 libxss1 libasound2 libatk-bridge2.0-0 \
        libgtk-3-0 xdg-utils scrot \
    && rm -rf /var/lib/apt/lists/*

# Install Google Chrome stable (real browser, not chromium — maximises fingerprint authenticity)
RUN wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && apt-get update && apt-get install -y --no-install-recommends /tmp/chrome.deb \
    && rm /tmp/chrome.deb && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -u 1000 -s /bin/bash analyst
RUN mkdir -p /telemetry && chown analyst:analyst /telemetry

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && ln -s vnc.html /usr/share/novnc/index.html

EXPOSE 7900

ENTRYPOINT ["/entrypoint.sh"]
