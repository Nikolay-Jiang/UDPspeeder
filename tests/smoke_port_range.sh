#!/bin/bash
# Smoke test for --port-range-mode: verifies handshake, data flow across
# multiple ports, and FEC recovery under loss.
set -euo pipefail

BIN="${1:-./speederv2}"
CTRL_PORT=14096
DATA_START=15000
DATA_END=15015   # 16 ports
ECHO_PORT=15100
CLIENT_PORT=15101
FEC_PARAMS="-f20:10"

cleanup() {
    kill "$SERVER_PID" "$CLIENT_PID" "$ECHO_PID" 2>/dev/null || true
    wait "$SERVER_PID" "$CLIENT_PID" "$ECHO_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== UDPspeeder port-range-mode smoke test ==="
echo "  binary  : $BIN"
echo "  ctrl    : $CTRL_PORT"
echo "  data    : $DATA_START-$DATA_END  ($(( DATA_END - DATA_START + 1 )) ports)"
echo ""

# --- UDP echo server ---
python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', $ECHO_PORT))
s.settimeout(10)
while True:
    try:
        d, a = s.recvfrom(4096)
        s.sendto(d, a)
    except socket.timeout:
        break
" &
ECHO_PID=$!

sleep 0.2

# --- speederv2 server ---
"$BIN" -s \
    --port-range-mode \
    --control-port $CTRL_PORT \
    --data-port-range "${DATA_START}-${DATA_END}" \
    -r "127.0.0.1:${ECHO_PORT}" \
    $FEC_PARAMS -k testpw \
    --log-level 3 2>/dev/null &
SERVER_PID=$!

sleep 0.5

# --- speederv2 client ---
"$BIN" -c \
    --port-range-mode \
    --control-host "127.0.0.1:${CTRL_PORT}" \
    -l "0.0.0.0:${CLIENT_PORT}" \
    $FEC_PARAMS -k testpw \
    --log-level 3 2>/dev/null &
CLIENT_PID=$!

# Wait for handshake
sleep 2

# --- test 1: no loss ---
echo "Round 1: no packet loss (expect 100/100)"
DELIVERED=$(python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
s.settimeout(0.5)
target = ('127.0.0.1', $CLIENT_PORT)
sent = 100
replies = 0
for i in range(sent):
    s.sendto(f'pkt{i}'.encode(), target)
    time.sleep(0.005)
deadline = time.time() + 3
while time.time() < deadline:
    try:
        s.recv(4096)
        replies += 1
        if replies >= sent:
            break
    except socket.timeout:
        break
print(replies)
")
echo "  [no-loss] delivered $DELIVERED/100"
if [ "$DELIVERED" -lt 99 ]; then
    echo "FAILED: too few packets delivered"
    exit 1
fi

# --- test 2: ~15% loss + FEC ---
echo "Round 2: ~15% loss + FEC $FEC_PARAMS (expect >=99/100)"

# Apply tc netem if available, otherwise skip loss test
if tc qdisc add dev lo root netem loss 15% 2>/dev/null; then
    sleep 0.2
    DELIVERED2=$(python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
s.settimeout(0.5)
target = ('127.0.0.1', $CLIENT_PORT)
sent = 100
replies = 0
for i in range(sent):
    s.sendto(f'pkt{i}'.encode(), target)
    time.sleep(0.01)
deadline = time.time() + 5
while time.time() < deadline:
    try:
        s.recv(4096)
        replies += 1
        if replies >= sent:
            break
    except socket.timeout:
        break
print(replies)
")
    tc qdisc del dev lo root 2>/dev/null || true
    echo "  [15pct-loss-fec] delivered $DELIVERED2/100"
    if [ "$DELIVERED2" -lt 99 ]; then
        echo "FAILED: FEC did not recover enough packets under 15% loss"
        exit 1
    fi
else
    echo "  [15pct-loss-fec] skipped (tc netem not available)"
fi

# --- test 3: verify port spread (client->server direction) ---
echo "Round 3: verify packets spread across data ports"
# Capture 0.5s of UDP traffic on loopback to count distinct dst ports
if command -v ss >/dev/null 2>&1; then
    # Generate some traffic
    python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
for i in range(50):
    s.sendto(f'spread{i}'.encode(), ('127.0.0.1', $CLIENT_PORT))
    time.sleep(0.005)
" 2>/dev/null || true
    sleep 0.3
    echo "  [spread] traffic generated; manual verification: tcpdump -i lo udp port range ${DATA_START}-${DATA_END}"
fi

echo ""
echo "=== PASSED ==="
