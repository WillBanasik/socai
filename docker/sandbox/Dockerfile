# socai-sandbox:latest — Linux malware detonation sandbox
# Debian slim base (not Alpine — musl causes subtle behavioural differences in malware)

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    ltrace \
    tcpdump \
    inotify-tools \
    procps \
    net-tools \
    python3-minimal \
    file \
    binutils \
    unzip \
    tar \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root sandbox user
RUN useradd -m -u 1000 -s /bin/bash sandbox

# Directory layout
RUN mkdir -p /sandbox/workspace /sandbox/telemetry /sandbox/monitor \
    && chown -R sandbox:sandbox /sandbox

# Copy monitoring scripts
COPY monitor.py /sandbox/monitor/monitor.py
COPY honeypot.py /sandbox/monitor/honeypot.py
COPY entrypoint.sh /sandbox/entrypoint.sh
RUN chmod +x /sandbox/entrypoint.sh

WORKDIR /sandbox/workspace

ENTRYPOINT ["/sandbox/entrypoint.sh"]
