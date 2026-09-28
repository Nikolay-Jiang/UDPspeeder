#!/usr/bin/env bash
# smoke_examples.sh — executable examples from docs/examples-v3.md
#
# Drives the three documented positive configurations against a real loopback
# tunnel, then the one documented startup failure:
#
#   1. default mode: XOR/obscure obfuscation + SipHash authentication, no cipher
#   2. --cipher xchacha20-ietf-poly1305 on both ends
#   3. --cipher xchacha20-ietf-poly1305 --pad 32 on both ends
#   4. negative: --pad 32 without --cipher must exit non-zero, print the
#      requires-cipher reason, and bind no socket
#
# Each positive round sends 50 uniquely-payloaded datagrams into the client
# listener and requires at least MIN_OK exact `ECHO:<payload>` replies.
#
# Cipher/pad *mismatch* control cases (port-range refusals and the normal-mode
# auth_drop path) are not duplicated here: tests/smoke_control_v3.sh owns that
# matrix, including its positive controls.
#
# Usage:
#   bash tests/smoke_examples.sh [/path/to/speederv3]
#
# Exit 0 on pass, non-zero on failure. All spawned server/client/echo PIDs are
# tracked and killed by an EXIT trap; the suite port block is randomized below
# the Linux ephemeral range and disjoint from smoke_port_range.sh's block.

set -euo pipefail

BIN="${1:-./speederv3}"
PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ECHO_SCRIPT="$SCRIPT_DIR/udp_echo.py"
KEY="00112233445566778899aabbccddeeff"
CIPHER="xchacha20-ietf-poly1305"
FEC_PARAMS="-f20:10"
TOTAL=50
MIN_OK=45
COLLECT_SECS=4

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found or not executable: $BIN"
    echo "       usage: bash tests/smoke_examples.sh [/path/to/speederv3]"
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON not found; this suite needs python3."
    exit 1
fi
if [ ! -f "$ECHO_SCRIPT" ]; then
    echo "ERROR: echo server not found: $ECHO_SCRIPT"
    exit 1
fi

PIDS=()

cleanup() {
    if [ "${#PIDS[@]}" -gt 0 ]; then
        kill "${PIDS[@]}" 2>/dev/null || true
        wait "${PIDS[@]}" 2>/dev/null || true
    fi
    PIDS=()
}
trap cleanup EXIT

# Strips ANSI color codes so captured logs stay readable in CI output.
dump_log() {
    sed -e 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null || true
}

# Rebinds every listed port on 127.0.0.1; exits 0 only if all are free.
ports_free() {
    "$PYTHON" - "$@" <<'PYEOF'
import socket, sys

busy = []
for arg in sys.argv[1:]:
    port = int(arg)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        busy.append(port)
    finally:
        s.close()
if busy:
    print("busy ports: " + ",".join(str(p) for p in busy))
    sys.exit(1)
sys.exit(0)
PYEOF
}

# One randomized block of 64 ports, all verified bindable at once. The block
# lives in 28000-30463: below the default ephemeral range (32768+), and
# disjoint from smoke_port_range.sh's 20000-27999 and smoke_control_v3.sh's
# 18000-22999 ranges.
pick_port_base() {
    "$PYTHON" - <<'PYEOF'
import random, socket

for _ in range(50):
    base = random.randint(28000, 30400)
    socks = []
    ok = True
    try:
        for port in range(base, base + 64):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", port))
            socks.append(s)
    except OSError:
        ok = False
    finally:
        for s in socks:
            s.close()
    if ok:
        print(base)
        break
else:
    raise SystemExit("could not find a free 64-port block")
PYEOF
}

# Sends TOTAL unique datagrams and counts exact `ECHO:<payload>` replies until
# every one arrived or COLLECT_SECS elapsed. Prints the count.
probe_delivery() {
    "$PYTHON" - "$1" "$TOTAL" "$COLLECT_SECS" <<'PYEOF'
import socket, sys, time

port    = int(sys.argv[1])
total   = int(sys.argv[2])
collect = float(sys.argv[3])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(0.25)

expected = set()
for i in range(total):
    msg = ("ex%03d" % i).encode()
    expected.add(msg)
    s.sendto(msg, ("127.0.0.1", port))
    time.sleep(0.002)

received = set()
deadline = time.time() + collect
while len(received) < total and time.time() < deadline:
    try:
        data, _ = s.recvfrom(65536)
    except socket.timeout:
        continue
    if data.startswith(b"ECHO:"):
        payload = data[5:]
        if payload in expected:
            received.add(payload)

s.close()
print(len(received))
PYEOF
}

# Waits up to 10s for both processes to report a listening socket.
# Returns 2 if the server exited, 3 if the client exited, 4 on a fatal/error
# line, 1 on timeout, 0 once both are up.
wait_ready() {
    local spid="$1" cpid="$2" slog="$3" clog="$4"
    local _i
    for _i in $(seq 1 50); do
        if ! kill -0 "$spid" 2>/dev/null; then
            return 2
        fi
        if ! kill -0 "$cpid" 2>/dev/null; then
            return 3
        fi
        if grep -qaE '\[(FATAL|ERROR)\]' "$slog" "$clog"; then
            return 4
        fi
        if grep -qa "now listening at" "$slog" && grep -qa "now listening at" "$clog"; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Positive round: echo app + server + client, then a delivery probe.
run_positive_round() {
    local label="$1" extra_args="$2" base="$3"
    local echo_p=$((base + 1)) tun_p=$((base + 2)) cli_p=$((base + 3))
    local slog clog
    slog=$(mktemp)
    clog=$(mktemp)

    echo "Round [$label]"
    if [ -n "$extra_args" ]; then
        echo "  args: $FEC_PARAMS -k <32-hex> $extra_args"
    else
        echo "  args: $FEC_PARAMS -k <32-hex> (default: obfuscation + SipHash auth, no cipher)"
    fi
    echo "  ports: echo=$echo_p tunnel=$tun_p client=$cli_p"

    "$PYTHON" "$ECHO_SCRIPT" "$echo_p" >/dev/null 2>&1 &
    local epid=$!
    PIDS+=("$epid")
    sleep 0.2

    # shellcheck disable=SC2086
    "$BIN" -s -l "127.0.0.1:$tun_p" -r "127.0.0.1:$echo_p" \
        $FEC_PARAMS -k "$KEY" --log-level 4 $extra_args >"$slog" 2>&1 &
    local spid=$!
    PIDS+=("$spid")

    # shellcheck disable=SC2086
    "$BIN" -c -l "127.0.0.1:$cli_p" -r "127.0.0.1:$tun_p" \
        $FEC_PARAMS -k "$KEY" --log-level 4 $extra_args >"$clog" 2>&1 &
    local cpid=$!
    PIDS+=("$cpid")

    local ready=0
    wait_ready "$spid" "$cpid" "$slog" "$clog" || ready=$?
    if [ "$ready" -ne 0 ]; then
        case "$ready" in
            2) echo "FAIL: [$label] server exited during startup" ;;
            3) echo "FAIL: [$label] client exited during startup" ;;
            4) echo "FAIL: [$label] a process logged a FATAL/ERROR line during startup" ;;
            *) echo "FAIL: [$label] server/client did not report a listening socket in time" ;;
        esac
        echo "--- server log ---"; dump_log "$slog"
        echo "--- client log ---"; dump_log "$clog"
        kill "$spid" "$cpid" "$epid" 2>/dev/null || true
        wait "$spid" "$cpid" "$epid" 2>/dev/null || true
        rm -f "$slog" "$clog"
        return 1
    fi

    local ok
    ok=$(probe_delivery "$cli_p")

    local bad=""
    grep -qa '\[FATAL\]' "$slog" "$clog" && bad="FATAL in a log"
    grep -qa '\[ERROR\]' "$slog" "$clog" && bad="ERROR in a log"
    grep -qa 'auth_drop' "$slog" "$clog" && bad="auth_drop on a positive round"
    if [ -n "$bad" ]; then
        echo "FAIL: [$label] $bad"
        echo "--- server log ---"; dump_log "$slog"
        echo "--- client log ---"; dump_log "$clog"
        kill "$spid" "$cpid" "$epid" 2>/dev/null || true
        wait "$spid" "$cpid" "$epid" 2>/dev/null || true
        rm -f "$slog" "$clog"
        return 1
    fi

    kill "$spid" "$cpid" "$epid" 2>/dev/null || true
    wait "$spid" "$cpid" "$epid" 2>/dev/null || true
    rm -f "$slog" "$clog"

    if [ "$ok" -lt "$MIN_OK" ]; then
        echo "FAIL: [$label] delivered only $ok/$TOTAL (need >= $MIN_OK exact echoes)"
        return 1
    fi
    echo "  [$label] PASS: delivered $ok/$TOTAL exact echoes"
    return 0
}

# Negative round: documented fatal startup for --pad without --cipher.
run_negative_round() {
    local base="$1"
    local tun_p=$((base + 1)) app_p=$((base + 2)) cli_p=$((base + 3))
    local out rc
    out=$(mktemp)

    echo "Round [negative-pad-without-cipher]"
    echo "  args: -s -l 127.0.0.1:$tun_p -r 127.0.0.1:$app_p $FEC_PARAMS -k <32-hex> --pad 32"
    echo "  expect: non-zero exit, 'requires --cipher' message, no socket bound"

    set +e
    timeout 10 "$BIN" -s -l "127.0.0.1:$tun_p" -r "127.0.0.1:$app_p" \
        $FEC_PARAMS -k "$KEY" --log-level 4 --pad 32 >"$out" 2>&1
    rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
        echo "FAIL: [negative-pad-without-cipher] exited 0; expected a fatal startup error"
        dump_log "$out"
        rm -f "$out"
        return 1
    fi
    if [ "$rc" -eq 124 ]; then
        echo "FAIL: [negative-pad-without-cipher] did not exit; timeout killed it after 10s"
        dump_log "$out"
        rm -f "$out"
        return 1
    fi
    if ! grep -qa "requires --cipher" "$out"; then
        echo "FAIL: [negative-pad-without-cipher] exit was $rc but the requires-cipher message is missing"
        dump_log "$out"
        rm -f "$out"
        return 1
    fi
    if ! ports_free "$tun_p" "$app_p" "$cli_p"; then
        echo "FAIL: [negative-pad-without-cipher] a socket is still bound after the fatal run"
        dump_log "$out"
        rm -f "$out"
        return 1
    fi

    echo "  [negative-pad-without-cipher] PASS: exit=$rc, requires-cipher printed, no socket bound"
    rm -f "$out"
    return 0
}

PORT_BASE=$(pick_port_base)
R1_BASE=$PORT_BASE
R2_BASE=$((PORT_BASE + 16))
R3_BASE=$((PORT_BASE + 32))
NEG_BASE=$((PORT_BASE + 48))

echo "=== UDPspeeder documented-examples smoke suite (docs/examples-v3.md) ==="
echo "  binary : $BIN"
echo "  python : $PYTHON"
echo "  ports  : randomized block $PORT_BASE-$((PORT_BASE + 63)) (no fixed-port collisions)"
echo "  note   : cipher/pad *mismatch* control cases are owned by"
echo "           tests/smoke_control_v3.sh and are intentionally not duplicated here."
echo ""

run_positive_round "default-obfuscation-siphash" "" "$R1_BASE"
run_positive_round "cipher-xchacha20-poly1305" "--cipher $CIPHER" "$R2_BASE"
run_positive_round "cipher-pad32" "--cipher $CIPHER --pad 32" "$R3_BASE"
run_negative_round "$NEG_BASE"

# Every tracked PID has been killed and waited on by now; prove it by rebinding
# the whole block and reporting clearly if anything still holds a socket.
mapfile -t SUITE_PORTS < <(seq "$PORT_BASE" "$((PORT_BASE + 63))")
if ! ports_free "${SUITE_PORTS[@]}"; then
    echo "FAIL: suite ports are still bound after cleanup"
    exit 1
fi
echo "  [cleanup] server/client/echo PIDs exited; no listener on suite ports $PORT_BASE-$((PORT_BASE + 63))"

echo ""
echo "=== PASSED: documented V3 examples ==="
