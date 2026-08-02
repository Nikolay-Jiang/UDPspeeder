#!/usr/bin/env bash
# smoke_ipv6.sh — IPv6 regression suite, all rounds over ::1
#
# Round 1: base tunnel. THIS IS THE REGRESSION GUARD. The base tunnel has
#          supported ipv6 all along, with no test and no docs -- which is
#          exactly why two later features broke it unnoticed, and why the
#          symptom looked like a firewall drop.
# Round 2: port-range mode over ipv6.
# Round 3: test mode over ipv6 (prober reaches responder, report renders).
# Round 4: --out-addr family mismatch is refused at startup.
# Round 5: a non-zero --out-addr port is refused where >1 outbound socket
#          is opened (server, port-range client).
# Round 6: ...and is NOT refused for a test-mode prober, which opens one.
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
OUT_PORT=$(( BASE_PORT + 21 ))
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

# --- Rounds 4-6: --out-addr startup validation -------------------------------
#
# The validator is a four-branch, mode-dependent peer selection, and it has
# already shipped one real bug (a missing working_mode test that silently
# accepted a mismatched config). Rounds 4 and 5 pin the two refusals; Round 6
# pins a case that must NOT be refused, so the validator cannot regress into
# always-firing -- which is how a "passing" refusal test would otherwise hide
# a validator that rejects everything.

# Asserts BOTH a non-zero exit and the specific message. Exit status alone
# would also be satisfied by a crash or an unrelated failure, and the whole
# point here is that the refusal fires for the right reason.
expect_refusal() {
    local label="$1" want="$2"; shift 2
    local out rc
    set +e
    out=$(timeout 10 "$BINARY" "$@" 2>&1)
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then
        echo "  FAIL [$label]: expected a non-zero exit, got 0"
        printf '%s\n' "$out" | tail -6
        exit 1
    fi
    if ! printf '%s\n' "$out" | grep -qa "$want"; then
        echo "  FAIL [$label]: exited $rc but without the expected message"
        echo "         wanted: $want"
        printf '%s\n' "$out" | tail -6
        exit 1
    fi
    echo "  [$label] refused as expected (exit $rc)"
}

echo "Round 4: --out-addr family mismatch is refused"
expect_refusal "family-mismatch-client" "different address families" \
    -c -l"[::1]:$CLIENT_PORT" -r "[::1]:$TUNNEL_PORT" -k "$KEY" --out-addr "127.0.0.1:0"
expect_refusal "family-mismatch-server" "different address families" \
    -s -l"[::1]:$TUNNEL_PORT" -r "[::1]:$ECHO_PORT" -k "$KEY" --out-addr "127.0.0.1:0"
echo

echo "Round 5: non-zero --out-addr port is refused where >1 outbound socket is opened"
# The server opens one outbound socket per connected client. Before this was
# checked, the server started fine, served the first client, and then died
# with EADDRINUSE when a second one appeared -- taking every client with it.
expect_refusal "nonzero-port-server" "must use port 0" \
    -s -l"[::1]:$TUNNEL_PORT" -r "[::1]:$ECHO_PORT" -k "$KEY" --out-addr "[::1]:$OUT_PORT"
# The port-range client opens two (data + control).
expect_refusal "nonzero-port-port-range-client" "must use port 0" \
    -c --port-range-mode --control-host "[::1]:$CTRL_PORT" \
    --data-port-range "$DATA_LO-$DATA_HI" -l"[::1]:$CLIENT_PORT" \
    -r "[::1]:$CTRL_PORT" -k "$KEY" --out-addr "[::1]:$OUT_PORT"
echo

echo "Round 6: a test-mode prober is NOT refused a non-zero --out-addr port"
# This is the exemption the earlier bug got wrong: a test-mode client is
# dispatched to test_mode_prober_loop() and opens ONE outbound socket, so
# neither refusal applies -- even with --port-range-mode set, which is the
# combination that previously mis-selected --control-host as the peer and
# refused on both counts. Run it for real against a live responder rather
# than merely checking that it starts.
"$BINARY" -s --test-mode -l"[::1]:$TEST_PORT" -k "$KEY" --log-level 4 \
    > /tmp/smoke_ipv6_resp.$$ 2>&1 & PIDS+=($!)
sleep 1
set +e
"$BINARY" -c --test-mode --port-range-mode --control-host "[::1]:$CTRL_PORT" \
    -r"[::1]:$TEST_PORT" -k "$KEY" --out-addr "[::1]:$OUT_PORT" \
    --test-duration 1 --test-pps 20 > /tmp/smoke_ipv6_prober.$$ 2>&1
PROBER_RC=$?
set -e
stop_all
if grep -qa "must use port 0\|different address families" /tmp/smoke_ipv6_prober.$$; then
    echo "  FAIL: the prober was refused, but it opens only one outbound socket"
    sed -n '1,20p' /tmp/smoke_ipv6_prober.$$
    exit 1
fi
if [[ "$PROBER_RC" -ne 0 ]]; then
    echo "  FAIL: prober exited $PROBER_RC"
    sed -n '1,40p' /tmp/smoke_ipv6_prober.$$
    exit 1
fi
if ! grep -qa "client -> server, 单端口" /tmp/smoke_ipv6_prober.$$; then
    echo "  FAIL: prober was allowed to start but rendered no report"
    sed -n '1,40p' /tmp/smoke_ipv6_prober.$$
    exit 1
fi
# Prove the pinned port was actually honoured, not silently ignored.
if ! grep -qa "\[::1\]:$OUT_PORT" /tmp/smoke_ipv6_resp.$$; then
    echo "  FAIL: responder never saw the pinned source port $OUT_PORT"
    sed -n '1,40p' /tmp/smoke_ipv6_resp.$$
    exit 1
fi
rm -f /tmp/smoke_ipv6_resp.$$ /tmp/smoke_ipv6_prober.$$
echo "  [test-mode-out-addr-allowed] ok"
echo

echo "=== PASSED ==="
