#!/bin/bash
# Smoke test for --port-range-mode: verifies handshake, data flow across
# multiple ports, and FEC recovery under loss.
#
# Every port is randomized per run, so parallel invocations (and a busy host
# ephemeral range) cannot collide. Round 2 needs tc netem and Round 3 needs
# CAP_NET_RAW to sniff loopback; when either is unavailable the round prints a
# loud SKIP: line and the final banner says so, instead of a silent pass that
# makes a green run lie.
set -euo pipefail

BIN="${1:-./speederv2}"
PYTHON="${PYTHON:-python3}"

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found or not executable: $BIN"
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON not found; this suite needs python3."
    exit 1
fi

# Randomized, non-overlapping ports. The base sits below the default Linux
# ephemeral range (32768-60999) so a short-lived outbound socket cannot steal
# a port we intend to bind. Control/data/echo/client all live in one block.
BASE_PORT=$(( (RANDOM % 8000) + 20000 ))   # 20000-27999
CTRL_PORT=$(( BASE_PORT ))
ECHO_PORT=$(( BASE_PORT + 1 ))
CLIENT_PORT=$(( BASE_PORT + 2 ))
DATA_START=$(( BASE_PORT + 10 ))
DATA_END=$(( BASE_PORT + 25 ))   # 16 ports
FEC_PARAMS="-f20:10"

SERVER_PID=""
CLIENT_PID=""
ECHO_PID=""
NETEM_ACTIVE=0
SKIPPED_ROUNDS=0

cleanup() {
    if [ "$NETEM_ACTIVE" = "1" ]; then
        tc qdisc del dev lo root 2>/dev/null || true
    fi
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
    $FEC_PARAMS -k 0123456789abcdef0123456789abcdef \
    --log-level 3 2>/dev/null &
SERVER_PID=$!

sleep 0.5

# --- speederv2 client ---
"$BIN" -c \
    --port-range-mode \
    --control-host "127.0.0.1:${CTRL_PORT}" \
    -l "0.0.0.0:${CLIENT_PORT}" \
    $FEC_PARAMS -k 0123456789abcdef0123456789abcdef \
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

if ! command -v tc >/dev/null 2>&1; then
    echo "SKIP: tc not installed; the ~15% loss + FEC round did NOT run."
    echo "      install iproute2 (tc) to exercise FEC recovery under loss."
    SKIPPED_ROUNDS=$(( SKIPPED_ROUNDS + 1 ))
elif ! tc qdisc add dev lo root netem loss 15% 2>/dev/null; then
    echo "SKIP: tc netem unavailable (needs CAP_NET_ADMIN + sch_netem);"
    echo "      the ~15% loss + FEC round did NOT run."
    SKIPPED_ROUNDS=$(( SKIPPED_ROUNDS + 1 ))
else
    NETEM_ACTIVE=1
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
    NETEM_ACTIVE=0
    echo "  [15pct-loss-fec] delivered $DELIVERED2/100"
    if [ "$DELIVERED2" -lt 99 ]; then
        echo "FAILED: FEC did not recover enough packets under 15% loss"
        exit 1
    fi
fi

# --- test 3: verify real port spread (client->server direction) ---
echo "Round 3: verify packets spread across data ports"
SPREAD_OUT=$(mktemp)
SPREAD_SECS=8
# Sniff loopback for the distinct UDP destination ports in the data range that
# the tunnel actually transmits to. AF_PACKET cooked L3 needs CAP_NET_RAW; when
# it is unavailable this round prints a loud SKIP instead of a fake pass.
"$PYTHON" - "$DATA_START" "$DATA_END" "$SPREAD_OUT" "$SPREAD_SECS" <<'PYEOF' &
import socket, struct, sys, time

lo, hi, out, secs = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
    s.bind(("lo", 0))
except OSError:
    open(out, "w").write("SKIP")
    sys.exit(0)

s.settimeout(0.2)
ports = set()
deadline = time.time() + secs
while time.time() < deadline:
    try:
        data, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    if len(data) < 20 or data[9] != 17:        # IPv4, protocol UDP
        continue
    ihl = (data[0] & 0x0F) * 4
    if len(data) < ihl + 8:
        continue
    dport = struct.unpack("!H", data[ihl + 2:ihl + 4])[0]
    if lo <= dport <= hi:
        ports.add(dport)
open(out, "w").write(",".join(str(p) for p in sorted(ports)))
PYEOF
SNIFF_PID=$!

# Let the sniffer bind before generating traffic.
sleep 0.4
"$PYTHON" -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
for i in range(120):
    s.sendto(f'spread{i}'.encode(), ('127.0.0.1', $CLIENT_PORT))
    time.sleep(0.005)
" 2>/dev/null || true

wait "$SNIFF_PID" 2>/dev/null || true
SPREAD_PORTS=$(cat "$SPREAD_OUT" 2>/dev/null || true)
rm -f "$SPREAD_OUT"

if [ "$SPREAD_PORTS" = "SKIP" ]; then
    echo "SKIP: port-spread sniffing needs CAP_NET_RAW (run as root or setcap);"
    echo "      Round 3 did NOT verify that multiple data ports are used."
    SKIPPED_ROUNDS=$(( SKIPPED_ROUNDS + 1 ))
else
    DISTINCT=0
    if [ -n "$SPREAD_PORTS" ]; then
        IFS=',' read -r -a _spread_arr <<< "$SPREAD_PORTS"
        DISTINCT=${#_spread_arr[@]}
    fi
    echo "  [spread] distinct data ports observed: $DISTINCT ($SPREAD_PORTS)"
    if [ "$DISTINCT" -lt 2 ]; then
        echo "FAILED: tunnel used only $DISTINCT data port(s); expected spread across multiple"
        exit 1
    fi
fi

echo ""
if [ "$SKIPPED_ROUNDS" -gt 0 ]; then
    echo "=== PASSED ($SKIPPED_ROUNDS round(s) SKIPPED — not verified) ==="
else
    echo "=== PASSED ==="
fi
