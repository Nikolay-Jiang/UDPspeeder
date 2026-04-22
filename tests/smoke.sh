#!/usr/bin/env bash
# smoke.sh — end-to-end regression for UDPspeeder
#
# Runs two test rounds:
#   Round 1: no packet loss  → expect 100% delivery
#   Round 2: --random-drop 1500 (≈15% loss) with -f20:10 FEC → expect ≥99%
#
# Usage:
#   bash tests/smoke.sh [/path/to/speederv2]
#
# Exit 0 on pass, non-zero on failure.

set -euo pipefail

BINARY="${1:-./speederv2}"
PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMEOUT_CMD="timeout"

# Verify binary exists
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: binary not found or not executable: $BINARY"
    exit 1
fi

# Pick random unprivileged ports to avoid CI runner conflicts
BASE_PORT=$(( (RANDOM % 20000) + 30000 ))
ECHO_PORT=$(( BASE_PORT ))
CLIENT_PORT=$(( BASE_PORT + 1 ))
TUNNEL_PORT=$(( BASE_PORT + 2 ))

KEY="smoketest_key_$$"

PIDS=()

cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

start_echo_server() {
    "$PYTHON" "$SCRIPT_DIR/udp_echo.py" "$ECHO_PORT" &
    PIDS+=($!)
}

start_tunnel() {
    local drop="${1:-0}"
    local drop_args=()
    [[ "$drop" -gt 0 ]] && drop_args=(--random-drop "$drop")

    "$BINARY" -s -l "0.0.0.0:$TUNNEL_PORT" -r "127.0.0.1:$ECHO_PORT" \
              -f20:10 -k "$KEY" "${drop_args[@]}" \
              >/dev/null 2>&1 &
    PIDS+=($!)

    "$BINARY" -c -l "0.0.0.0:$CLIENT_PORT" -r "127.0.0.1:$TUNNEL_PORT" \
              -f20:10 -k "$KEY" "${drop_args[@]}" \
              >/dev/null 2>&1 &
    PIDS+=($!)

    sleep 1   # let processes bind and connect
}

stop_tunnel() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    PIDS=()
    sleep 0.3
}

run_round() {
    local label="$1"
    local total="$2"
    local min_ok="$3"

    local ok=0
    local sock
    sock=$(python3 - <<'PYEOF'
import socket, random
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PYEOF
)

    # Use python to send/receive (bash UDP is unreliable with raw /dev/udp)
    ok=$("$PYTHON" - "$CLIENT_PORT" "$total" <<'PYEOF'
import socket, sys, time

client_port = int(sys.argv[1])
total       = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4.0)

ok = 0
for i in range(total):
    msg = f"pkt{i:04d}".encode()
    s.sendto(msg, ("127.0.0.1", client_port))
    try:
        data, _ = s.recvfrom(65536)
        if data == b"ECHO:" + msg:
            ok += 1
    except socket.timeout:
        pass   # loss — FEC should recover most of these

print(ok)
PYEOF
)

    echo "  [${label}] delivered ${ok}/${total}"
    if [[ "$ok" -lt "$min_ok" ]]; then
        echo "FAIL: expected at least ${min_ok}, got ${ok}"
        return 1
    fi
    return 0
}

echo "=== UDPspeeder smoke test ==="
echo "  binary  : $BINARY"
echo "  ports   : echo=$ECHO_PORT  client=$CLIENT_PORT  tunnel=$TUNNEL_PORT"
echo ""

# ---- Round 1: no loss -------------------------------------------------------
echo "Round 1: no packet loss (expect 100/100)"
start_echo_server
start_tunnel 0
run_round "no-loss" 100 100
stop_tunnel

# ---- Round 2: 15% loss with FEC ---------------------------------------------
echo "Round 2: ~15% loss + FEC -f20:10 (expect ≥99/100)"
start_echo_server
start_tunnel 1500
run_round "15pct-loss-fec" 100 99
stop_tunnel

echo ""
echo "=== PASSED ==="
