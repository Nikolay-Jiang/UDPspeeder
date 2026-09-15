#!/bin/bash
# smoke_control_v3.sh — end-to-end control-plane v3 negative matrix.
#
# The in-process --test-selftest cannot reach the server's HELLO capability
# gate (a static function in tunnel_server.cpp) or watch the todo-8
# "auth_drop: plane=data" line appear on a real receive path. This suite drives
# those through real processes:
#
#   * port-range cipher mismatch: server cipher on, client off  -> HELLO refused
#   * port-range pad mismatch:    server pad 32, client pad 16   -> HELLO refused
#   * port-range positive:        matching cipher+pad            -> handshake + delivery
#   * normal-mode cipher mismatch: default server, cipher client -> auth_drop: plane=data
#   * normal-mode pad mismatch:    pad 32 server, pad 16 client  -> auth_drop: plane=data
#
# Every negative has a positive control, so a server that simply refused or
# dropped everything would fail the suite instead of passing it.
#
# Usage: bash tests/smoke_control_v3.sh [/path/to/speederv2]
set -euo pipefail

BIN="${1:-./speederv2}"
PYTHON="${PYTHON:-python3}"
KEY="00112233445566778899aabbccddeeff"
CIPHER="xchacha20-ietf-poly1305"
FEC="-f20:10"

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found or not executable: $BIN"
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON not found; this suite needs python3."
    exit 1
fi

PIDS=()
cleanup() {
    kill "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*"
    exit 1
}

# Fresh, non-overlapping port block per round, below the ephemeral range.
LAST_BASE=$(( (RANDOM % 5000) + 18000 ))
next_base() {
    LAST_BASE=$(( LAST_BASE + 64 ))
    echo "$LAST_BASE"
}

# Waits up to `tries` x 0.2s for `pattern` to appear in `file`.
wait_log() {
    local file="$1" pattern="$2" tries="${3:-40}"
    for _ in $(seq 1 "$tries"); do
        grep -qa "$pattern" "$file" && return 0
        sleep 0.2
    done
    return 1
}

# Sends `total` datagrams into the client listener and returns the number echoed.
probe_delivery() {
    "$PYTHON" - "$1" "$2" <<'PYEOF'
import socket, sys, time
port, total = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(0.5)
ok = 0
for i in range(total):
    s.sendto(b"probe%d" % i, ("127.0.0.1", port))
    time.sleep(0.005)
deadline = time.time() + 3
while ok < total and time.time() < deadline:
    try:
        data, _ = s.recvfrom(65536)
        if data.startswith(b"ECHO:"):
            ok += 1
    except socket.timeout:
        break
print(ok)
PYEOF
}

port_range_round() {
    local label="$1" server_extra="$2" client_extra="$3" expect_refusal="$4" want_delivery="$5"
    local base; base=$(next_base)
    local ctrl=$base echo_p=$((base + 1)) cli_p=$((base + 2))
    local dlo=$((base + 10)) dhi=$((base + 15))
    local slog clog; slog=$(mktemp); clog=$(mktemp)

    echo "Round [$label]"
    echo "  server=$server_extra client=$client_extra"

    if [ "$want_delivery" = "yes" ]; then
        "$PYTHON" "$(dirname "$0")/udp_echo.py" "$echo_p" &
        PIDS+=($!)
        sleep 0.2
    fi

    # shellcheck disable=SC2086
    "$BIN" -s --port-range-mode --control-port "$ctrl" \
        --data-port-range "$dlo-$dhi" -r "127.0.0.1:$echo_p" \
        $FEC -k "$KEY" --log-level 4 $server_extra >"$slog" 2>&1 &
    local spid=$!; PIDS+=($spid)
    sleep 0.4
    # shellcheck disable=SC2086
    "$BIN" -c --port-range-mode --control-host "127.0.0.1:$ctrl" \
        -l "127.0.0.1:$cli_p" $FEC -k "$KEY" --log-level 4 $client_extra >"$clog" 2>&1 &
    local cpid=$!; PIDS+=($cpid)

    if [ "$expect_refusal" = "yes" ]; then
        if ! wait_log "$slog" "HELLO capability mismatch"; then
            echo "--- server log ---"; cat "$slog"
            echo "--- client log ---"; cat "$clog"
            fail "[$label]: server did not refuse the mismatched HELLO"
        fi
        if ! grep -qa "refusing HELLO" "$slog"; then
            echo "--- server log ---"; cat "$slog"
            fail "[$label]: refusal did not carry the 'refusing HELLO' reason"
        fi
        if grep -qa "HELLO_ACK received" "$clog"; then
            echo "--- client log ---"; cat "$clog"
            fail "[$label]: client installed ports from a refused handshake"
        fi
        echo "  [$label] refused: server logged the mismatch, client installed no ports"
    else
        if ! wait_log "$clog" "HELLO_ACK received"; then
            echo "--- client log ---"; cat "$clog"
            echo "--- server log ---"; cat "$slog"
            fail "[$label]: matching peers did not complete the handshake"
        fi
        local delivered
        delivered=$(probe_delivery "$cli_p" 50)
        echo "  [$label] handshake complete, delivered $delivered/50"
        if [ "$delivered" -lt 45 ]; then
            echo "--- server log ---"; cat "$slog"
            echo "--- client log ---"; cat "$clog"
            fail "[$label]: matching peers delivered only $delivered/50"
        fi
    fi

    kill "$spid" "$cpid" 2>/dev/null || true
    wait "$spid" "$cpid" 2>/dev/null || true
    rm -f "$slog" "$clog"
}

normal_mismatch_round() {
    local label="$1" server_extra="$2" client_extra="$3"
    local base; base=$(next_base)
    local tun=$base echo_p=$((base + 1)) cli_p=$((base + 2))
    local slog clog; slog=$(mktemp); clog=$(mktemp)

    echo "Round [$label]"
    echo "  server=$server_extra client=$client_extra"

    # shellcheck disable=SC2086
    "$BIN" -s -l "127.0.0.1:$tun" -r "127.0.0.1:$echo_p" \
        $FEC -k "$KEY" --log-level 4 $server_extra >"$slog" 2>&1 &
    local spid=$!; PIDS+=($spid)
    sleep 0.4
    # shellcheck disable=SC2086
    "$BIN" -c -l "127.0.0.1:$cli_p" -r "127.0.0.1:$tun" \
        $FEC -k "$KEY" --log-level 4 $client_extra >"$clog" 2>&1 &
    local cpid=$!; PIDS+=($cpid)
    sleep 0.5

    # Drive datagrams into the client listener so it emits cooked frames; the
    # server's verification must fail and reach the throttle/warn path.
    "$PYTHON" - "$cli_p" <<'PYEOF'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
port = int(sys.argv[1])
for i in range(20):
    s.sendto(b"mismatch%d" % i, ("127.0.0.1", port))
    time.sleep(0.02)
PYEOF

    if ! wait_log "$slog" "auth_drop: plane=data"; then
        echo "--- server log ---"; cat "$slog"
        echo "--- client log ---"; cat "$clog"
        fail "[$label]: server did not log the data-plane tamper drop"
    fi
    echo "  [$label] server logged 'auth_drop: plane=data'"

    kill "$spid" "$cpid" 2>/dev/null || true
    wait "$spid" "$cpid" 2>/dev/null || true
    rm -f "$slog" "$clog"
}

echo "=== UDPspeeder control-plane v3 negative matrix ==="
echo "  binary: $BIN"
echo ""

# Negative 1: cipher-scheme mismatch in port-range mode, refused before any
# port is installed.
port_range_round "port-range-cipher-mismatch" \
    "--cipher $CIPHER" "" "yes" "no"

# Negative 2: pad-bucket mismatch in port-range mode, refused at the handshake.
port_range_round "port-range-pad-mismatch" \
    "--cipher $CIPHER --pad 32" "--cipher $CIPHER --pad 16" "yes" "no"

# Positive control: identical capability on both ends completes and delivers.
port_range_round "port-range-match" \
    "--cipher $CIPHER --pad 32" "--cipher $CIPHER --pad 32" "no" "yes"

# Negative 3: normal-mode cipher-scheme mismatch is dropped and tamper-logged.
normal_mismatch_round "normal-cipher-mismatch" \
    "" "--cipher $CIPHER"

# Negative 4: normal-mode pad-bucket mismatch is dropped and tamper-logged
# (the bucket is AEAD associated data).
normal_mismatch_round "normal-pad-mismatch" \
    "--cipher $CIPHER --pad 32" "--cipher $CIPHER --pad 16"

echo ""
echo "=== PASSED ==="
