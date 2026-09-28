#!/bin/bash
# smoke_v3_e2e.sh - end-to-end V3 anti-interference suite.
#
# Plan: .omo/plans/udpspeeder-v3-antiinterference.md todo 14 (G7, G9, G19).
#
# One server/client lifecycle, three assertion phases:
#
#   1. Rotation (G7). With --port-rotate-sec 1 and app traffic flowing, the
#      client must emit >= 2 `port-rotate: window base=<n> first_dest_port=<p>
#      ports=<n>` lines; the base must advance by exactly 1 every window (and
#      first_dest_port must track it), while delivery stays >= 90%.
#
#   2. Interference recovery (G9). SIGSTOP the server for ~6s (blackhole).
#      With --heartbeat-interval 1 the client must arm a re-handshake
#      (`ctrl: <reason>, re-handshaking` then `ctrl: starting fresh handshake`)
#      exactly once (the 30s cooldown forbids a second trigger), and delivery
#      must resume after SIGCONT.
#
#   3. Tamper-log rate (G19). Two wrong-key normal-mode clients flood the
#      server's control port and one data port for FLOOD_SECS. The server must
#      emit at most one `auth_drop: plane=<p> ...` line per plane per 10s (plus
#      the shutdown force-flush), with strictly growing `total=` counters and
#      growing `auth_drop: data=<n> control=<m>` counters in its `--report 1`
#      lines. The healthy client's report line must carry the same counters.
#
# No root and no tc/netem: the only interference primitives are SIGSTOP/SIGCONT
# and wrong-key floods. All ports are randomized below the ephemeral range.
#
# Usage:
#   bash tests/smoke_v3_e2e.sh [/path/to/speederv3]
#
# Env:
#   SMOKE_E2E_KEEP=1    keep the log directory for inspection.
#   PYTHON=python3      interpreter override.
#   Debug hooks (they intentionally weaken one gate so the matching negative can
#   be demonstrated; runs that set them are NOT acceptance evidence):
#   SMOKE_E2E_ROTATE_SEC=0          pin rotation off -> rotation phase fails.
#   SMOKE_E2E_BLACKHOLE_SECS=0      skip interference -> recovery phase fails.
#   SMOKE_E2E_AUTH_BUDGET_PER_10=0  budget a single line -> tamper phase fails.
#   SMOKE_E2E_FLOOD_SECS=<n>        flood window, default 21.
#
# Exit: 0 = PASS; 1 = at least one assertion FAILED; 2 = a required tool is
#       missing (loud SKIP, never a silent pass).
set -uo pipefail

BIN="${1:-./speederv3}"
PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ROTATE_SEC="${SMOKE_E2E_ROTATE_SEC:-1}"
BLACKHOLE_SECS="${SMOKE_E2E_BLACKHOLE_SECS:-6}"
FLOOD_SECS="${SMOKE_E2E_FLOOD_SECS:-21}"
AUTH_BUDGET_PER_10="${SMOKE_E2E_AUTH_BUDGET_PER_10:-1}"
KEEP_LOGS="${SMOKE_E2E_KEEP:-0}"

# Exactly 32 hex chars (misc.cpp -k gate).
KEY="00112233445566778899aabbccddeeff"
WRONG_KEY="fedcba9876543210fedcba9876543210"
FEC_PARAMS="-f20:10"

ROTATION_WARMUP=1     # let the traffic driver write its first status sample
ROTATION_WINDOW=6     # traffic window used for the rotation assertions
RECOVERY_WAIT=25      # max seconds to wait for the re-handshake + delivery
RECOVERY_MIN_OK=20    # echoes needed to call delivery "resumed"
FLOOD_POST_MIN_OK=200 # echoes expected over the 21s flood phase that follow
HEARTBEAT_SEC=1       # client heartbeat interval; threshold 3 -> fast trigger
TRAFFIC_DURATION=120  # traffic driver hard stop (killed earlier anyway)

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found or not executable: $BIN"
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "SKIP: $PYTHON not found; this suite needs python3 and did NOT run."
    exit 2
fi

HAVE_SS=0
command -v ss >/dev/null 2>&1 && HAVE_SS=1

# Randomized, non-overlapping ports below the ephemeral range (as in
# smoke_port_range.sh), re-rolled until the whole block is free.
port_block_free() {
    local p
    for p in "$@"; do
        if ss -lun 2>/dev/null | grep -qE "[:.]${p}[[:space:]]"; then
            return 1
        fi
    done
    return 0
}

BASE_PORT=0
CTRL_PORT=0
for _try in 1 2 3 4 5 6 7 8 9 10; do
    CAND=$(( (RANDOM % 7000) + 20000 ))
    CTRL_PORT=$CAND
    ECHO_PORT=$(( CAND + 1 ))
    CLIENT_PORT=$(( CAND + 2 ))
    WK_CTRL_PORT=$(( CAND + 3 ))
    WK_DATA_PORT=$(( CAND + 4 ))
    DATA_START=$(( CAND + 10 ))
    DATA_END=$(( CAND + 17 ))
    DATA_COUNT=$(( DATA_END - DATA_START + 1 ))
    PORTS_ALL=("$CTRL_PORT" "$ECHO_PORT" "$CLIENT_PORT" "$WK_CTRL_PORT" "$WK_DATA_PORT")
    for (( p = DATA_START; p <= DATA_END; p++ )); do
        PORTS_ALL+=("$p")
    done
    if [ "$HAVE_SS" = "0" ] || port_block_free "${PORTS_ALL[@]}"; then
        BASE_PORT=$CAND
        break
    fi
done
if [ "$BASE_PORT" = "0" ]; then
    echo "ERROR: could not find a free UDP port block after 10 tries"
    exit 1
fi

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/smoke_v3_e2e.XXXXXX")"
SERVER_PID=""
CLIENT_PID=""
ECHO_PID=""
TRAFFIC_PID=""
WKC_PID=""
WKD_PID=""
FLOOD_PID=""
FAILURES=0
SKIPPED=0

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILURES=$(( FAILURES + 1 )); }
note() { echo "  info: $*"; }

# Terminate everything and reap it. The tunnel ends get SIGTERM first so
# myexit() flushes the `--report` line and the auth_drop counters. Idempotent.
kill_all() {
    local pid any=0
    for pid in "$TRAFFIC_PID" "$FLOOD_PID" "$WKC_PID" "$WKD_PID" "$ECHO_PID" \
               "$CLIENT_PID" "$SERVER_PID"; do
        [ -n "$pid" ] && any=1
    done
    if [ "$any" = "0" ]; then
        return 0
    fi
    for pid in "$TRAFFIC_PID" "$FLOOD_PID" "$WKC_PID" "$WKD_PID" "$ECHO_PID"; do
        [ -n "$pid" ] && kill -KILL "$pid" 2>/dev/null
    done
    for pid in "$CLIENT_PID" "$SERVER_PID"; do
        [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
    done
    sleep 1
    for pid in "$TRAFFIC_PID" "$FLOOD_PID" "$WKC_PID" "$WKD_PID" "$ECHO_PID" \
               "$CLIENT_PID" "$SERVER_PID"; do
        if [ -n "$pid" ]; then
            kill -KILL "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null || true
        fi
    done
    SERVER_PID=""
    CLIENT_PID=""
    ECHO_PID=""
    TRAFFIC_PID=""
    WKC_PID=""
    WKD_PID=""
    FLOOD_PID=""
}

on_exit() {
    local rc=$?
    kill_all
    if [ "$KEEP_LOGS" = "1" ]; then
        echo "logs kept in $LOG_DIR"
    else
        rm -rf "$LOG_DIR"
    fi
    exit "$rc"
}
trap on_exit EXIT INT TERM

wait_for_log() {  # wait_for_log <file> <regex> <max deciseconds>
    local file="$1" pattern="$2" tries="$3" i
    for (( i = 0; i < tries; i++ )); do
        grep -q "$pattern" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

status_field() {  # status_field <status-file> <sent|ok>
    local file="$1" field="$2" v
    if [ ! -f "$file" ]; then
        echo 0
        return 0
    fi
    v="$(sed -n "s/.* ${field}=\([0-9][0-9]*\).*/\1/p" "$file" 2>/dev/null | tail -1)"
    echo "${v:-0}"
}

check_no_listeners() {
    if [ "$HAVE_SS" != "1" ]; then
        echo "SKIP: ss not installed; the listener-leak check DID NOT run."
        SKIPPED=$(( SKIPPED + 1 ))
        return
    fi
    local out p leaks=0
    out="$(ss -lun 2>/dev/null || true)"
    for p in "${PORTS_ALL[@]}"; do
        if grep -qE "[:.]${p}[[:space:]]" <<<"$out"; then
            fail "listener still bound to UDP port $p after cleanup"
            leaks=$(( leaks + 1 ))
        fi
    done
    if [ "$leaks" = "0" ]; then
        pass "no listeners remain on the suite ports (ss -lun)"
    fi
}

finalize() {  # finalize <exit-code>
    local code="$1"
    kill_all
    check_no_listeners
    echo ""
    if [ "$code" = "0" ] && [ "$FAILURES" = "0" ]; then
        if [ "$SKIPPED" = "0" ]; then
            echo "=== PASSED: rotation, interference recovery, tamper-log rate limit ==="
        else
            echo "=== PASSED ($SKIPPED check(s) SKIPPED - not verified) ==="
        fi
        exit 0
    fi
    echo "=== FAILED: $FAILURES assertion(s) failed ==="
    exit 1
}

die() {
    fail "$*"
    finalize 1
}

echo "=== UDPspeeder V3 anti-interference e2e suite (todo 14) ==="
echo "  binary : $BIN"
echo "  rotate : ${ROTATE_SEC}s  blackhole: ${BLACKHOLE_SECS}s  flood: ${FLOOD_SECS}s"
echo "  ports  : ctrl=$CTRL_PORT echo=$ECHO_PORT client=$CLIENT_PORT"
echo "           wrong-key lis=$WK_CTRL_PORT/$WK_DATA_PORT data=$DATA_START-$DATA_END"
echo "  logs   : $LOG_DIR"
echo ""

# ---- phase 0: echo + port-range server + client -----------------------------
"$PYTHON" "$SCRIPT_DIR/udp_echo.py" "$ECHO_PORT" >"$LOG_DIR/echo.log" 2>&1 &
ECHO_PID=$!
disown "$ECHO_PID" 2>/dev/null || true
sleep 0.3

"$BIN" -s --port-range-mode \
    --control-port "$CTRL_PORT" \
    --data-port-range "${DATA_START}-${DATA_END}" \
    -r "127.0.0.1:${ECHO_PORT}" \
    $FEC_PARAMS -k "$KEY" --report 1 --heartbeat-interval "$HEARTBEAT_SEC" \
    --log-level 4 --disable-color >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
disown "$SERVER_PID" 2>/dev/null || true

sleep 0.3

"$BIN" -c --port-range-mode \
    --control-host "127.0.0.1:${CTRL_PORT}" \
    -l "0.0.0.0:${CLIENT_PORT}" \
    $FEC_PARAMS -k "$KEY" \
    --port-rotate-sec "$ROTATE_SEC" \
    --report 1 --heartbeat-interval "$HEARTBEAT_SEC" \
    --log-level 4 --disable-color >"$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
disown "$CLIENT_PID" 2>/dev/null || true

if ! wait_for_log "$LOG_DIR/client.log" "HELLO_ACK received" 100; then
    echo "--- client log (tail) ---"
    tail -20 "$LOG_DIR/client.log" || true
    die "client never completed the control handshake (HELLO_ACK) within 10s"
fi
pass "control handshake established (HELLO_ACK received)"

# ---- continuous app traffic for the whole run -------------------------------
cat > "$LOG_DIR/traffic.py" <<'PYEOF'
import os, socket, sys, time

port = int(sys.argv[1])
status = sys.argv[2]
duration = float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.05)
sent = 0
ok = 0
t0 = time.monotonic()
last_write = 0.0


def write_status():
    tmp = status + ".tmp"
    with open(tmp, "w") as f:
        f.write("STATUS t=%.1f sent=%d ok=%d\n" % (time.monotonic() - t0, sent, ok))
    os.replace(tmp, status)


while time.monotonic() - t0 < duration:
    sent += 1
    msg = b"E2E%06d" % sent
    try:
        s.sendto(msg, ("127.0.0.1", port))
        data, _ = s.recvfrom(65536)
        if data.startswith(b"ECHO:E2E"):
            ok += 1
    except (socket.timeout, OSError):
        pass
    now = time.monotonic()
    if now - last_write >= 0.25:
        last_write = now
        write_status()
    time.sleep(0.02)

write_status()
PYEOF

STATUS_FILE="$LOG_DIR/traffic.status"
"$PYTHON" "$LOG_DIR/traffic.py" "$CLIENT_PORT" "$STATUS_FILE" "$TRAFFIC_DURATION" \
    >"$LOG_DIR/traffic.log" 2>&1 &
TRAFFIC_PID=$!
disown "$TRAFFIC_PID" 2>/dev/null || true

# ---- phase 1: rotation ------------------------------------------------------
sleep "$ROTATION_WARMUP"
s0="$(status_field "$STATUS_FILE" sent)"
o0="$(status_field "$STATUS_FILE" ok)"
note "rotation window start: sent=$s0 ok=$o0"

sleep "$ROTATION_WINDOW"
s1="$(status_field "$STATUS_FILE" sent)"
o1="$(status_field "$STATUS_FILE" ok)"
ROT_SENT=$(( s1 - s0 ))
ROT_OK=$(( o1 - o0 ))
note "rotation window end: sent=$s1 ok=$o1 (delta sent=$ROT_SENT ok=$ROT_OK)"

ROT_LINES="$(grep -a 'port-rotate: window base=' "$LOG_DIR/client.log" || true)"
ROT_COUNT="$(printf '%s\n' "$ROT_LINES" | grep -c 'port-rotate: window base=' || true)"
echo "--- port-rotate lines (client) ---"
printf '%s\n' "$ROT_LINES"
echo "---------------------------------"

if [ "$ROT_SENT" -lt 100 ]; then
    die "traffic driver did not run (sent delta $ROT_SENT < 100); the rotation check would be vacuous"
fi
if [ "$ROT_COUNT" -lt 2 ]; then
    die "rotation: only $ROT_COUNT port-rotate line(s) with --port-rotate-sec=$ROTATE_SEC; expected >= 2 with traffic flowing"
fi

bases=()
fds=()
counts=()
while read -r b p c; do
    if [ -n "$b" ]; then
        bases+=("$b")
        fds+=("$p")
        counts+=("$c")
    fi
done < <(printf '%s\n' "$ROT_LINES" | sed -n 's/.*port-rotate: window base=\([0-9][0-9]*\) first_dest_port=\([0-9][0-9]*\) ports=\([0-9][0-9]*\).*/\1 \2 \3/p')

rot_ok=1
for (( i = 0; i < ${#bases[@]}; i++ )); do
    if [ "${counts[$i]}" != "$DATA_COUNT" ]; then
        fail "rotation: line $i advertises ${counts[$i]} ports, expected $DATA_COUNT"
        rot_ok=0
    fi
    want_fd=$(( DATA_START + ${bases[$i]} ))
    if [ "${fds[$i]}" != "$want_fd" ]; then
        fail "rotation: line $i first_dest_port=${fds[$i]}, expected $want_fd for base=${bases[$i]}"
        rot_ok=0
    fi
done
for (( i = 1; i < ${#bases[@]}; i++ )); do
    want=$(( (${bases[$i-1]} + 1) % DATA_COUNT ))
    if [ "${bases[$i]}" != "$want" ]; then
        fail "rotation: base did not advance by 1: ${bases[$i-1]} -> ${bases[$i]} (expected $want)"
        rot_ok=0
    fi
done
if [ "$rot_ok" = "1" ]; then
    pass "rotation: $ROT_COUNT windows, base advanced +1 each window over $DATA_COUNT ports, first_dest_port tracked the base"
fi
if [ $(( ROT_OK * 10 )) -lt $(( ROT_SENT * 9 )) ]; then
    fail "rotation: delivery dropped during the rotation window ($ROT_OK/$ROT_SENT < 90%)"
else
    pass "rotation: delivery intact during rotation ($ROT_OK/$ROT_SENT echoes)"
fi

# ---- phase 2: interference recovery ----------------------------------------
if [ "$BLACKHOLE_SECS" -le 0 ]; then
    die "interference recovery not exercised (SMOKE_E2E_BLACKHOLE_SECS=$BLACKHOLE_SECS); no re-handshake can be demonstrated"
fi

o_stop="$(status_field "$STATUS_FILE" ok)"
if ! kill -STOP "$SERVER_PID" 2>/dev/null; then
    die "could not SIGSTOP the server (pid=$SERVER_PID)"
fi
note "server blackholed with SIGSTOP for ${BLACKHOLE_SECS}s"
sleep "$BLACKHOLE_SECS"
if ! kill -CONT "$SERVER_PID" 2>/dev/null; then
    die "could not SIGCONT the server (pid=$SERVER_PID)"
fi
o_cont="$(status_field "$STATUS_FILE" ok)"
note "server resumed with SIGCONT; ok delta while blackholed: $(( o_cont - o_stop ))"

deadline=$(( SECONDS + RECOVERY_WAIT ))
acks=1
o_now="$o_cont"
recovered=0
while [ "$SECONDS" -lt "$deadline" ]; do
    acks="$(grep -ac 'HELLO_ACK received' "$LOG_DIR/client.log" || true)"
    acks="${acks:-0}"
    o_now="$(status_field "$STATUS_FILE" ok)"
    if [ "$acks" -ge 2 ] && [ $(( o_now - o_cont )) -ge "$RECOVERY_MIN_OK" ]; then
        recovered=1
        break
    fi
    sleep 0.5
done

echo "--- interference evidence (client) ---"
grep -a 're-handshaking\|starting fresh handshake\|HELLO_ACK received' "$LOG_DIR/client.log" || true
echo "--------------------------------------"

RH_COUNT="$(grep -ac 're-handshaking' "$LOG_DIR/client.log" || true)"
RH_COUNT="${RH_COUNT:-0}"
FRESH_COUNT="$(grep -ac 'starting fresh handshake' "$LOG_DIR/client.log" || true)"
FRESH_COUNT="${FRESH_COUNT:-0}"

if [ "$RH_COUNT" -ge 1 ]; then
    pass "interference: client armed a re-handshake ($RH_COUNT trigger(s) for the ${BLACKHOLE_SECS}s blackhole)"
else
    fail "interference: client never logged 're-handshaking' after the ${BLACKHOLE_SECS}s blackhole"
fi
if [ "$FRESH_COUNT" -ge 1 ]; then
    pass "interference: client started a fresh handshake"
else
    fail "interference: client never logged 'starting fresh handshake'"
fi
if [ "$RH_COUNT" -le 1 ]; then
    pass "interference: at most one re-handshake trigger in the run (30s cooldown respected)"
else
    fail "interference: $RH_COUNT re-handshake triggers; the 30s cooldown was violated"
fi
if [ "$recovered" = "1" ]; then
    pass "interference: delivery resumed after the server returned (HELLO_ACK #$acks, ok $o_cont -> $o_now)"
else
    fail "interference: no recovery within ${RECOVERY_WAIT}s (acks=$acks, ok $o_cont -> $o_now)"
fi

# ---- phase 3: tamper-log rate limit ----------------------------------------
"$BIN" -c -l "127.0.0.1:${WK_CTRL_PORT}" -r "127.0.0.1:${CTRL_PORT}" \
    $FEC_PARAMS -k "$WRONG_KEY" --disable-color >"$LOG_DIR/wrong_ctrl.log" 2>&1 &
WKC_PID=$!
disown "$WKC_PID" 2>/dev/null || true
"$BIN" -c -l "127.0.0.1:${WK_DATA_PORT}" -r "127.0.0.1:${DATA_START}" \
    $FEC_PARAMS -k "$WRONG_KEY" --disable-color >"$LOG_DIR/wrong_data.log" 2>&1 &
WKD_PID=$!
disown "$WKD_PID" 2>/dev/null || true
sleep 0.5

cat > "$LOG_DIR/flood.py" <<'PYEOF'
import socket, sys, time

ctrl_port = int(sys.argv[1])
data_port = int(sys.argv[2])
secs = float(sys.argv[3])
status = sys.argv[4]

targets = [("127.0.0.1", ctrl_port), ("127.0.0.1", data_port)]
socks = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in targets]
t0 = time.monotonic()
nxt = t0
sent = 0
while time.monotonic() - t0 < secs:
    now = time.monotonic()
    if now < nxt:
        time.sleep(min(nxt - now, 0.02))
        continue
    nxt += 0.01  # 100 pps per target
    for s, t in zip(socks, targets):
        try:
            s.sendto(b"WRONGKEYFLOOD" + bytes(64), t)
        except OSError:
            pass
    sent += 1

with open(status, "w") as f:
    f.write("FLOOD sent_per_target=%d secs=%.1f\n" % (sent, secs))
PYEOF

FLOOD_STATUS="$LOG_DIR/flood.status"
"$PYTHON" "$LOG_DIR/flood.py" "$WK_CTRL_PORT" "$WK_DATA_PORT" "$FLOOD_SECS" "$FLOOD_STATUS" &
FLOOD_PID=$!
disown "$FLOOD_PID" 2>/dev/null || true
echo ""
echo "Flooding the wrong-key planes for ${FLOOD_SECS}s ..."
# The driver is disowned (to keep bash from printing "Killed" job notices), so
# `wait` cannot synchronize it: poll its result file instead.
FLOOD_DEADLINE=$(( SECONDS + FLOOD_SECS + 10 ))
while [ ! -s "$FLOOD_STATUS" ] && [ "$SECONDS" -lt "$FLOOD_DEADLINE" ]; do
    kill -0 "$FLOOD_PID" 2>/dev/null || break
    sleep 0.2
done
wait "$FLOOD_PID" 2>/dev/null || true
FLOOD_PID=""

FLOOD_SENT="$(sed -n 's/.*sent_per_target=\([0-9][0-9]*\).*/\1/p' "$FLOOD_STATUS" 2>/dev/null | tail -1)"
FLOOD_SENT="${FLOOD_SENT:-0}"
o_final="$(status_field "$STATUS_FILE" ok)"

# Graceful tunnel shutdown: emits the final --report line and the
# auth_drop_flush() line used by the budget check.
kill_all

if [ "$FLOOD_SENT" -lt $(( FLOOD_SECS * 50 )) ]; then
    fail "tamper: wrong-key flood did not run (sent/target=$FLOOD_SENT)"
else
    pass "tamper: wrong-key flood ran ($FLOOD_SENT packets/target over ${FLOOD_SECS}s)"
fi

DELTA_FLOOD=$(( o_final - o_cont ))
if [ "$DELTA_FLOOD" -ge "$FLOOD_POST_MIN_OK" ]; then
    pass "interference: delivery sustained after recovery ($DELTA_FLOOD echoes during the flood phase)"
else
    fail "interference: delivery stalled after recovery ($DELTA_FLOOD echoes < $FLOOD_POST_MIN_OK)"
fi

echo "--- auth_drop lines (server) ---"
grep -aE 'auth_drop: plane=(data|control)' "$LOG_DIR/server.log" || echo "(none)"
echo "--------------------------------"

# Allowed per plane: one line per 10s of flood plus the shutdown force-flush.
# SMOKE_E2E_AUTH_BUDGET_PER_10=0 shrinks this to the flush line only, which is
# how the "budget exceeded" negative is demonstrated.
window_tens=$(( FLOOD_SECS / 10 ))
allowed=$(( AUTH_BUDGET_PER_10 * (window_tens + 1) + 1 ))

for plane in data control; do
    plane_lines="$(grep -aE "auth_drop: plane=${plane} " "$LOG_DIR/server.log" || true)"
    plane_count="$(printf '%s\n' "$plane_lines" | grep -c 'auth_drop' || true)"
    plane_count="${plane_count:-0}"
    if [ "$plane_count" -lt 1 ]; then
        fail "tamper[${plane}]: no auth_drop line; the wrong-key flood was not detected on this plane"
        continue
    fi
    pass "tamper[${plane}]: $plane_count throttled auth_drop line(s) in ${FLOOD_SECS}s"

    if printf '%s\n' "$plane_lines" | grep -aqE 'src=127\.0\.0\.1:[0-9][0-9]*'; then
        pass "tamper[${plane}]: lines carry the offending source ip:port"
    else
        fail "tamper[${plane}]: auth_drop lines lack a source ip:port"
    fi

    if [ "$plane_count" -le "$allowed" ]; then
        pass "tamper[${plane}]: $plane_count <= $allowed line budget (1 per 10s + shutdown flush)"
    else
        fail "tamper[${plane}]: $plane_count lines exceed the $allowed budget for ${FLOOD_SECS}s"
    fi

    prev_total=0
    grew=1
    have_prev=0
    while read -r t; do
        [ -z "$t" ] && continue
        if [ "$have_prev" = "1" ] && [ "$t" -le "$prev_total" ]; then
            grew=0
        fi
        prev_total="$t"
        have_prev=1
    done < <(printf '%s\n' "$plane_lines" | sed -n 's/.*total=\([0-9][0-9]*\).*/\1/p')
    if [ "$grew" = "1" ] && [ "$prev_total" -gt 0 ]; then
        pass "tamper[${plane}]: counter grew monotonically to total=$prev_total"
    else
        fail "tamper[${plane}]: counter did not grow monotonically (last=$prev_total)"
    fi

    short_gaps=0
    prev_s=""
    while read -r hms; do
        [ -z "$hms" ] && continue
        h="${hms%%:*}"; rest="${hms#*:}"; m="${rest%%:*}"; s="${rest#*:}"
        cur=$(( 10#$h * 3600 + 10#$m * 60 + 10#$s ))
        if [ -n "$prev_s" ]; then
            gap=$(( (cur - prev_s + 86400) % 86400 ))
            if [ "$gap" -lt 10 ]; then
                short_gaps=$(( short_gaps + 1 ))
            fi
        fi
        prev_s="$cur"
    done < <(printf '%s\n' "$plane_lines" | sed -n 's/^\[[0-9-]* \([0-9][0-9]*:[0-9][0-9]*:[0-9][0-9]*\)\].*/\1/p')
    if [ "$short_gaps" -le 1 ]; then
        pass "tamper[${plane}]: <= 1 sub-10s gap between lines ($short_gaps), i.e. at most 1 line per 10s"
    else
        fail "tamper[${plane}]: $short_gaps gaps under 10s - the 10s throttle is broken"
    fi
done

# --report 1 must expose and grow the per-plane counters (server side).
echo "--- --report auth_drop counters (server) ---"
grep -aE '^\[[^]]*\]\[INFO\]\[report' "$LOG_DIR/server.log" | grep -a 'auth_drop:' | tail -3
echo "-------------------------------------------"

rep_lines="$(grep -aE '^\[[^]]*\]\[INFO\]\[report' "$LOG_DIR/server.log" | grep -a 'auth_drop: data=[0-9][0-9]* control=[0-9][0-9]*' || true)"
rep_data=()
rep_ctrl=()
while read -r d c; do
    if [ -n "$d" ]; then
        rep_data+=("$d")
        rep_ctrl+=("$c")
    fi
done < <(printf '%s\n' "$rep_lines" | sed -n 's/.*auth_drop: data=\([0-9][0-9]*\) control=\([0-9][0-9]*\).*/\1 \2/p')
nrep=${#rep_data[@]}

if [ "$nrep" -ge 2 ]; then
    d_first="${rep_data[0]}"
    d_last="${rep_data[$(( nrep - 1 ))]}"
    c_first="${rep_ctrl[0]}"
    c_last="${rep_ctrl[$(( nrep - 1 ))]}"
    note "server report counters: data $d_first -> $d_last, control $c_first -> $c_last over $nrep report lines"
    if [ "$d_last" -gt "$d_first" ] || [ "$c_last" -gt "$c_first" ]; then
        pass "tamper: server --report 1 counters grew (data=$d_last control=$c_last)"
    else
        fail "tamper: server --report 1 counters did not grow"
    fi
    if [ "$d_last" -gt 0 ] && [ "$c_last" -gt 0 ]; then
        pass "tamper: both planes are counted in --report 1 (data=$d_last control=$c_last)"
    else
        fail "tamper: a plane has zero counted drops in --report 1 (data=$d_last control=$c_last)"
    fi
else
    fail "tamper: fewer than 2 server report lines carry auth_drop counters (got $nrep)"
fi

client_rep="$(grep -aE '^\[[^]]*\]\[INFO\]\[report' "$LOG_DIR/client.log" | grep -ac 'auth_drop: data=[0-9][0-9]* control=[0-9][0-9]*' || true)"
client_rep="${client_rep:-0}"
echo "--- client --report sample ---"
grep -aE '^\[[^]]*\]\[INFO\]\[report' "$LOG_DIR/client.log" | grep -a 'auth_drop:' | tail -1
echo "------------------------------"
if [ "$client_rep" -ge 1 ]; then
    pass "tamper: the client --report 1 line includes auth_drop: data=<n> control=<m> ($client_rep line(s))"
else
    fail "tamper: the client --report 1 line never carried auth_drop: data=<n> control=<m>"
fi

finalize 0
