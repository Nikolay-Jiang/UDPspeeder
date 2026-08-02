#!/usr/bin/env bash
# smoke_ipv6.sh — IPv6 regression suite, all rounds over ::1
#
# Round 1: base tunnel. THIS IS THE REGRESSION GUARD. The base tunnel has
#          supported ipv6 all along, with no test and no docs -- which is
#          exactly why two later features broke it unnoticed, and why the
#          symptom looked like a firewall drop.
# Round 2: port-range mode over ipv6.
# Round 3: test mode over ipv6 (prober reaches responder, report renders).
#
# Usage: bash tests/smoke_ipv6.sh [/path/to/speederv2]
# Exit 0 on pass or on a loud skip; non-zero on failure.

set -euo pipefail

BINARY="${1:-./speederv2}"
PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: binary not found or not executable: $BINARY"
    exit 1
fi

# A silently-skipped test is worse than no test: it makes a green CI lie.
# Say plainly that the ipv6 rounds did not run.
if ! "$PYTHON" - <<'PYEOF' 2>/dev/null
import socket, sys
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("::1", 0))
except OSError:
    sys.exit(1)
PYEOF
then
    echo "SKIP: ipv6 loopback (::1) is unavailable on this host."
    echo "      the ipv6 rounds did NOT run. this is a skip, not a pass."
    exit 0
fi

BASE_PORT=$(( (RANDOM % 20000) + 34000 ))
ECHO_PORT=$BASE_PORT
CLIENT_PORT=$(( BASE_PORT + 1 ))
TUNNEL_PORT=$(( BASE_PORT + 2 ))
CTRL_PORT=$(( BASE_PORT + 3 ))
DATA_LO=$(( BASE_PORT + 10 ))
DATA_HI=$(( BASE_PORT + 13 ))
TEST_PORT=$(( BASE_PORT + 20 ))
KEY="smoke_ipv6_$$"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    # Belt-and-braces: Round 3's test-mode reports land here, and its client
    # probe runs in the foreground (no &), so a non-zero exit there triggers
    # `set -e` before any per-branch `rm -f` runs. Clean up unconditionally
    # on every exit path rather than relying on each branch to remember.
    rm -f "/tmp/smoke_ipv6_resp.$$" "/tmp/smoke_ipv6_prober.$$"
}
trap cleanup EXIT

stop_all() {
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    PIDS=()
    sleep 0.3
}

send_and_count() {
    local port="$1" total="$2"
    "$PYTHON" - "$port" "$total" <<'PYEOF'
import socket, sys, time
port, total = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(4.0)
ok = 0
for i in range(total):
    msg = b"pkt%04d" % i
    s.sendto(msg, ("::1", port))
    try:
        data, _ = s.recvfrom(65536)
        if data == b"ECHO:" + msg:
            ok += 1
    except socket.timeout:
        pass
print(ok)
PYEOF
}

echo "=== UDPspeeder IPv6 smoke test ==="
echo "  binary : $BINARY"
echo "  base   : $BASE_PORT"
echo

echo "Round 1: base tunnel over ::1 (regression guard, expect 100/100)"
"$PYTHON" "$SCRIPT_DIR/udp_echo.py" "::1" "$ECHO_PORT" & PIDS+=($!)
sleep 0.5
"$BINARY" -s -l"[::1]:$TUNNEL_PORT" -r "[::1]:$ECHO_PORT" -f20:10 -k "$KEY" \
    >/dev/null 2>&1 & PIDS+=($!)
"$BINARY" -c -l"[::1]:$CLIENT_PORT" -r "[::1]:$TUNNEL_PORT" -f20:10 -k "$KEY" \
    >/dev/null 2>&1 & PIDS+=($!)
sleep 1.5
OK=$(send_and_count "$CLIENT_PORT" 100)
stop_all
echo "  [base-v6] delivered $OK/100"
if [[ "$OK" -lt 100 ]]; then echo "  FAIL: expected 100"; exit 1; fi
echo "  [base-v6] ok"
echo

echo "Round 2: port-range mode over ::1 (expect >=95/100)"
"$PYTHON" "$SCRIPT_DIR/udp_echo.py" "::1" "$ECHO_PORT" & PIDS+=($!)
sleep 0.5
"$BINARY" -s --port-range-mode --control-port "$CTRL_PORT" \
    --data-port-range "$DATA_LO-$DATA_HI" -l"[::1]:0" -r "[::1]:$ECHO_PORT" \
    -f20:10 -k "$KEY" >/dev/null 2>&1 & PIDS+=($!)
sleep 1
"$BINARY" -c --port-range-mode --control-host "[::1]:$CTRL_PORT" \
    --data-port-range "$DATA_LO-$DATA_HI" -l"[::1]:$CLIENT_PORT" \
    -r "[::1]:$CTRL_PORT" -f20:10 -k "$KEY" >/dev/null 2>&1 & PIDS+=($!)
sleep 2.5
OK=$(send_and_count "$CLIENT_PORT" 100)
stop_all
echo "  [port-range-v6] delivered $OK/100"
if [[ "$OK" -lt 95 ]]; then echo "  FAIL: expected at least 95"; exit 1; fi
echo "  [port-range-v6] ok"
echo

echo "Round 3: test mode over ::1"
"$BINARY" -s --test-mode -l"[::1]:$TEST_PORT" -k "$KEY" --log-level 4 \
    > /tmp/smoke_ipv6_resp.$$ 2>&1 & PIDS+=($!)
sleep 1
"$BINARY" -c --test-mode -r"[::1]:$TEST_PORT" -k "$KEY" \
    --test-duration 1 --test-pps 20 > /tmp/smoke_ipv6_prober.$$ 2>&1
stop_all
if grep -q "no response from" /tmp/smoke_ipv6_prober.$$; then
    echo "  FAIL: prober could not reach the responder over ipv6"
    rm -f /tmp/smoke_ipv6_resp.$$ /tmp/smoke_ipv6_prober.$$
    exit 1
fi
if ! grep -q "client -> server, 单端口" /tmp/smoke_ipv6_prober.$$; then
    echo "  FAIL: no report section rendered"
    sed -n '1,40p' /tmp/smoke_ipv6_prober.$$
    rm -f /tmp/smoke_ipv6_resp.$$ /tmp/smoke_ipv6_prober.$$
    exit 1
fi
rm -f /tmp/smoke_ipv6_resp.$$ /tmp/smoke_ipv6_prober.$$
echo "  [test-mode-v6] ok"
echo

echo "=== PASSED ==="
