#!/usr/bin/env bash
# entrypoint.sh — sandbox bootstrap: monitoring + sample execution
set -euo pipefail

TELEMETRY="/sandbox/telemetry"
WORKSPACE="/sandbox/workspace"
TIMEOUT="${SANDBOX_TIMEOUT:-120}"
SAMPLE="${SANDBOX_SAMPLE:-sample}"
NETWORK_MODE="${SANDBOX_NETWORK_MODE:-monitor}"

# -------------------------------------------------------------------------
# 1. Record filesystem baseline
# -------------------------------------------------------------------------
find /sandbox/workspace -xdev -type f 2>/dev/null > "$TELEMETRY/fs_before.txt" || true
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$TELEMETRY/started_at.txt"

# -------------------------------------------------------------------------
# 2. Start monitoring processes in background
# -------------------------------------------------------------------------

# Packet capture (runs as root for raw socket access)
tcpdump -i any -w "$TELEMETRY/capture.pcap" -s 0 -q 2>/dev/null &
TCPDUMP_PID=$!

# Honeypot DNS/HTTP (only in monitored network mode)
if [ "$NETWORK_MODE" = "monitor" ]; then
    python3 /sandbox/monitor/honeypot.py &
    HONEYPOT_PID=$!
fi

# Main monitoring daemon
python3 /sandbox/monitor/monitor.py &
MONITOR_PID=$!

# Give monitors a moment to start
sleep 0.5

# -------------------------------------------------------------------------
# 3. Detect sample type and execute under strace
# -------------------------------------------------------------------------

SAMPLE_PATH="$WORKSPACE/$SAMPLE"
STRACE_LOG="$TELEMETRY/strace_raw.log"

if [ ! -f "$SAMPLE_PATH" ]; then
    echo "ERROR: Sample not found at $SAMPLE_PATH" > "$TELEMETRY/execution_error.txt"
    echo "execution_error" > "$TELEMETRY/execution_complete"
    kill $TCPDUMP_PID $MONITOR_PID 2>/dev/null || true
    [ -n "${HONEYPOT_PID:-}" ] && kill "$HONEYPOT_PID" 2>/dev/null || true
    exit 1
fi

# Make sample executable
chmod +x "$SAMPLE_PATH" 2>/dev/null || true

# Detect type via magic bytes / file command
FILE_TYPE=$(file -b "$SAMPLE_PATH" 2>/dev/null || echo "unknown")
echo "$FILE_TYPE" > "$TELEMETRY/file_type.txt"

run_strace() {
    # Execute with strace, timeout, as sandbox user
    timeout --signal=KILL "$TIMEOUT" \
        strace -f -e trace=all -o "$STRACE_LOG" -s 256 \
        su -s /bin/bash sandbox -c "$*" \
        > "$TELEMETRY/stdout.log" 2> "$TELEMETRY/stderr.log" || true
}

case "$FILE_TYPE" in
    *ELF*)
        echo "elf" > "$TELEMETRY/sample_category.txt"
        run_strace "$SAMPLE_PATH"
        ;;
    *PE32*|*PE32+*|*MS-DOS*|*Windows*)
        echo "pe" > "$TELEMETRY/sample_category.txt"
        if command -v wine64 &>/dev/null; then
            run_strace "wine64 $SAMPLE_PATH"
        elif command -v wine &>/dev/null; then
            run_strace "wine $SAMPLE_PATH"
        else
            echo "No Wine installed — use socai-sandbox-wine image for PE files" \
                > "$TELEMETRY/execution_error.txt"
        fi
        ;;
    *shell*|*bash*|*Bourne*)
        echo "script_sh" > "$TELEMETRY/sample_category.txt"
        run_strace "/bin/bash $SAMPLE_PATH"
        ;;
    *Python*)
        echo "script_py" > "$TELEMETRY/sample_category.txt"
        run_strace "python3 $SAMPLE_PATH"
        ;;
    *Perl*)
        echo "script_perl" > "$TELEMETRY/sample_category.txt"
        run_strace "perl $SAMPLE_PATH"
        ;;
    *Zip*|*gzip*|*tar*)
        echo "archive" > "$TELEMETRY/sample_category.txt"
        # Extract and attempt to find/execute inner files
        mkdir -p "$WORKSPACE/extracted"
        case "$FILE_TYPE" in
            *Zip*)  unzip -o "$SAMPLE_PATH" -d "$WORKSPACE/extracted" 2>/dev/null || true ;;
            *gzip*) tar xzf "$SAMPLE_PATH" -C "$WORKSPACE/extracted" 2>/dev/null || true ;;
            *tar*)  tar xf "$SAMPLE_PATH" -C "$WORKSPACE/extracted" 2>/dev/null || true ;;
        esac
        # Find first executable
        INNER=$(find "$WORKSPACE/extracted" -type f -executable 2>/dev/null | head -1)
        if [ -z "$INNER" ]; then
            INNER=$(find "$WORKSPACE/extracted" -type f 2>/dev/null | head -1)
        fi
        if [ -n "$INNER" ]; then
            chmod +x "$INNER" 2>/dev/null || true
            INNER_TYPE=$(file -b "$INNER" 2>/dev/null || echo "unknown")
            if echo "$INNER_TYPE" | grep -qiE "ELF|executable"; then
                run_strace "$INNER"
            elif echo "$INNER_TYPE" | grep -qiE "shell|bash|Bourne"; then
                run_strace "/bin/bash $INNER"
            else
                run_strace "$INNER"
            fi
        else
            echo "No executable found in archive" > "$TELEMETRY/execution_error.txt"
        fi
        ;;
    *)
        echo "unknown" > "$TELEMETRY/sample_category.txt"
        # Try to execute directly
        run_strace "$SAMPLE_PATH"
        ;;
esac

# -------------------------------------------------------------------------
# 4. Post-execution: record filesystem state, signal completion
# -------------------------------------------------------------------------

find /sandbox/workspace -xdev -type f 2>/dev/null > "$TELEMETRY/fs_after.txt" || true
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$TELEMETRY/completed_at.txt"

# Signal monitor to finalise
echo "done" > "$TELEMETRY/execution_complete"

# Give monitor time to parse strace/pcap
sleep 2

# Stop background processes
kill $TCPDUMP_PID 2>/dev/null || true
kill $MONITOR_PID 2>/dev/null || true
[ -n "${HONEYPOT_PID:-}" ] && kill "$HONEYPOT_PID" 2>/dev/null || true

# Wait for children
wait 2>/dev/null || true

echo "Sandbox execution complete"
