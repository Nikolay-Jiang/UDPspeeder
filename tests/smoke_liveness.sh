#!/usr/bin/env bash
# smoke_liveness.sh - event-loop liveness/order + bounded auth-failure logging
#
# Plan: .omo/plans/udpspeeder-siphash-hardening.md todo 20 (findings 22, 24, 25).
#
# Scenario: a healthy authenticated tunnel (udp_echo.py app flow) runs for
# SMOKE_LIVENESS_SECS (default 60) while a concurrent wrong-key ./speederv2
# client is flooded through the same server receive socket. Nothing in the
# production send/drain path is modified by this test.
#
# Assertions:
#   1. Liveness: the healthy flow keeps delivering for the whole window.
#      No run of >= 3 consecutive seconds with zero delivered replies, at
#      least one reply in the final 5s, and >= 90% of sent probes echoed.
#   2. Fail-closed: the wrong-key flood source receives zero tunneled replies.
#   3. Bounded auth-failure logging: the per-plane tamper-drop warn line is
#      rate-limited to one data-plane line per 10s, plus one shutdown
#      force-flush, for the 60s wrong-key data flood (G19); the budget is 8/60s.
#      Per-packet detail is debug-gated, so a regression that logs each
#      rejected packet at warn/info blows this budget. A short --log-level 5
#      positive control proves rejected packets are detected, so a zero count
#      is not vacuous.
#   4. Counters: `delay: pool=<n> fallback_malloc=<m> queue_high_water=<h>
#      short_send_drop=<d>` is emitted by both ends at shutdown and h <= n.
#   5. --report 1: no event-loop stall. Log timestamps have 1s resolution and
#      the actual report cadence is 1.2s (report when now-last > 1000ms; the
#      conn timer ticks every 400ms, `timer_interval` in common.h), so
#      consecutive whole-second stamps legitimately alternate 1,1,1,1,2.
#      The check therefore asserts max gap <= 2s (a real stall pushes it to
#      >= 3s), that at most a quarter of the gaps exceed 1s, and that reports
#      keep arriving at >= 1 per 1.7s on average.
#
# Usage:
#   bash tests/smoke_liveness.sh [/path/to/speederv2]
#
# Env:
#   SMOKE_LIVENESS_SECS  window length; default 60. Values < 60 are a debug
#                        hook and are not valid acceptance evidence.
#   SMOKE_LIVENESS_KEEP  1 = keep the log directory for inspection.
#   PYTHON               python3 interpreter (default: python3).
#
# Exit: 0 = every assertion PASS; 1 = at least one FAIL.

set -uo pipefail

BIN="${1:-./speederv2}"
PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SECS="${SMOKE_LIVENESS_SECS:-60}"

# Wire contract: exactly 32 hex characters (see misc.cpp -k handler).
KEY="00112233445566778899aabbccddeeff"
WRONG_KEY="fedcba9876543210fedcba9876543210"

REPORT_INTERVAL=1          # --report 1
HEALTHY_PPS=10             # healthy probe rate
FLOOD_PPS=500              # wrong-key flood rate
FEC_PARAMS="-f20:10"
JITTER_MS=100
AUTH_FAIL_RE="auth_drop: plane=|siphash tag check failed|de_obscure fail|de_cook error"
AUTH_BUDGET_PER_60=8

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: binary not found or not executable: $BIN"
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ERROR: $PYTHON not found; this suite needs python3."
    exit 1
fi

# Randomized ports below the ephemeral range (as in smoke_port_range.sh) so a
# short-lived outbound socket cannot steal a port we intend to bind.
BASE=$(( (RANDOM % 8000) + 20000 ))
ECHO_PORT=$BASE
TUNNEL_PORT=$(( BASE + 1 ))
CLIENT_PORT=$(( BASE + 2 ))
WRONG_PORT=$(( BASE + 3 ))
PROBE_PORT=$(( BASE + 4 ))

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/smoke_liveness.XXXXXX")"
SERVER_PID=""
CLIENT_PID=""
WRONG_PID=""
ECHO_PID=""
PROBE_PID=""
FAILURES=0

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILURES=$(( FAILURES + 1 )); }

cleanup() {
    trap - EXIT INT TERM
    local pid
    for pid in "$SERVER_PID" "$CLIENT_PID" "$WRONG_PID" "$ECHO_PID" "$PROBE_PID"; do
        [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null
    done
    sleep 0.3
    for pid in "$SERVER_PID" "$CLIENT_PID" "$WRONG_PID" "$ECHO_PID" "$PROBE_PID"; do
        [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    if [[ "${SMOKE_LIVENESS_KEEP:-0}" == "1" ]]; then
        echo "logs kept in $LOG_DIR"
    else
        rm -rf "$LOG_DIR"
    fi
}
trap cleanup EXIT INT TERM

wait_for_log() {  # wait_for_log <file> <regex> <max deciseconds>
    local file="$1" pattern="$2" tries="$3" i
    for (( i = 0; i < tries; i++ )); do
        grep -q "$pattern" "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

echo "=== UDPspeeder liveness smoke test ==="
echo "  binary : $BIN"
echo "  window : ${SECS}s   report: ${REPORT_INTERVAL}s   jitter: ${JITTER_MS}ms"
echo "  ports  : echo=$ECHO_PORT tunnel=$TUNNEL_PORT client=$CLIENT_PORT wrong=$WRONG_PORT probe=$PROBE_PORT"
echo "  logs   : $LOG_DIR"
echo ""

# ---- positive control: unauthenticated traffic is detected and dropped ------
"$BIN" -s -l "127.0.0.1:$PROBE_PORT" -r "127.0.0.1:$ECHO_PORT" \
        $FEC_PARAMS -k "$KEY" --log-level 5 --disable-color \
        >"$LOG_DIR/probe.log" 2>&1 &
PROBE_PID=$!
if wait_for_log "$LOG_DIR/probe.log" "now listening" 50; then
    "$PYTHON" - "$PROBE_PORT" <<'PYEOF'
import os, socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.5)
for i in range(40):
    s.sendto(os.urandom(64), ("127.0.0.1", port))
try:
    data, _ = s.recvfrom(65536)
    print("PROBE_REPLY %r" % data)
except socket.timeout:
    print("PROBE_REPLY none")
PYEOF
    sleep 0.3
    probe_fails=$(grep -cE "$AUTH_FAIL_RE" "$LOG_DIR/probe.log" || true)
    if (( probe_fails >= 1 )); then
        pass "positive control: $probe_fails unauthenticated datagrams detected and dropped (--log-level 5)"
    else
        fail "positive control: no auth-failure line for 40 unauthenticated datagrams; the drop path is not observable"
    fi
else
    fail "positive control: probe server never started listening"
fi
kill -TERM "$PROBE_PID" 2>/dev/null
sleep 0.3
wait "$PROBE_PID" 2>/dev/null
PROBE_PID=""

# ---- healthy tunnel + concurrent wrong-key flood ---------------------------
"$PYTHON" "$SCRIPT_DIR/udp_echo.py" "$ECHO_PORT" >"$LOG_DIR/echo.log" 2>&1 &
ECHO_PID=$!
sleep 0.3

"$BIN" -s -l "127.0.0.1:$TUNNEL_PORT" -r "127.0.0.1:$ECHO_PORT" \
        $FEC_PARAMS -j "$JITTER_MS" -k "$KEY" \
        --report "$REPORT_INTERVAL" --disable-color >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

"$BIN" -c -l "127.0.0.1:$CLIENT_PORT" -r "127.0.0.1:$TUNNEL_PORT" \
        $FEC_PARAMS -j "$JITTER_MS" -k "$KEY" \
        --report "$REPORT_INTERVAL" --disable-color >"$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!

"$BIN" -c -l "127.0.0.1:$WRONG_PORT" -r "127.0.0.1:$TUNNEL_PORT" \
        $FEC_PARAMS -j "$JITTER_MS" -k "$WRONG_KEY" \
        --disable-color >"$LOG_DIR/wrong.log" 2>&1 &
WRONG_PID=$!

ready=0
wait_for_log "$LOG_DIR/server.log" "now listening" 50 \
    && wait_for_log "$LOG_DIR/client.log" "now listening" 50 \
    && wait_for_log "$LOG_DIR/wrong.log" "now listening" 50 \
    && ready=1
if [[ "$ready" != "1" ]]; then
    echo "ERROR: a tunnel process did not start listening within 5s"
    exit 1
fi

echo "Driving ${SECS}s of healthy traffic + wrong-key flood ..."
timeout -k 5 "$(( SECS + 30 ))" "$PYTHON" - "$CLIENT_PORT" "$WRONG_PORT" "$SECS" "$HEALTHY_PPS" "$FLOOD_PPS" \
    >"$LOG_DIR/liveness.txt" 2>&1 <<'PYEOF'
import socket, sys, threading, time

cli_port = int(sys.argv[1])
wk_port = int(sys.argv[2])
secs = float(sys.argv[3])
healthy_interval = 1.0 / float(sys.argv[4])
flood_burst = 10
flood_tick = flood_burst / float(sys.argv[5])

state = {"sent": 0, "ok": 0, "flood_sent": 0, "flood_replies": 0}

def one_round(sock, msg, timeout):
    sock.settimeout(timeout)
    sock.sendto(msg, ("127.0.0.1", cli_port))
    try:
        data, _ = sock.recvfrom(65536)
        return data == b"ECHO:" + msg
    except socket.timeout:
        return False

# Warm up: the report window must measure steady state, not init latency.
warm = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
warm_ok = False
deadline = time.monotonic() + 8.0
i = 0
while time.monotonic() < deadline and not warm_ok:
    i += 1
    warm_ok = one_round(warm, b"W%05d" % i, 1.0)
    if not warm_ok:
        time.sleep(0.1)
warm.close()
if not warm_ok:
    print("LIVENESS warmup_failed=1")
    sys.exit(3)

t0 = time.monotonic()
per_sec = [0] * (int(secs) + 1)

def healthy():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    n = 0
    while True:
        now = time.monotonic()
        if now - t0 >= secs:
            break
        n += 1
        msg = b"H%06d" % n
        try:
            s.sendto(msg, ("127.0.0.1", cli_port))
        except OSError:
            continue
        state["sent"] = n
        try:
            s.settimeout(1.0)
            data, _ = s.recvfrom(65536)
        except socket.timeout:
            data = None
        except OSError:
            data = None
        if data == b"ECHO:" + msg:
            idx = min(int(time.monotonic() - t0), len(per_sec) - 1)
            per_sec[idx] += 1
            state["ok"] += 1
        sleep_for = healthy_interval - (time.monotonic() - now)
        if sleep_for > 0:
            time.sleep(sleep_for)
    s.close()

def flood():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    n = 0
    next_tick = t0
    while True:
        now = time.monotonic()
        if now - t0 >= secs:
            break
        if now < next_tick:
            time.sleep(min(next_tick - now, 0.05))
            continue
        next_tick += flood_tick
        for _ in range(flood_burst):
            n += 1
            try:
                s.sendto(b"F%08d" % n, ("127.0.0.1", wk_port))
            except OSError:
                pass
        while True:  # any reply here means the wrong-key stream was accepted
            try:
                s.recvfrom(65536)
                state["flood_replies"] += 1
            except (BlockingIOError, OSError):
                break
    state["flood_sent"] = n
    s.close()

h = threading.Thread(target=healthy)
f = threading.Thread(target=flood)
h.start()
f.start()
h.join()
f.join()

buckets = per_sec[:int(secs)]
max_zero_streak = 0
streak = 0
for v in buckets:
    streak = streak + 1 if v == 0 else 0
    if streak > max_zero_streak:
        max_zero_streak = streak
last5_ok = sum(buckets[-5:]) if len(buckets) >= 5 else sum(buckets)
print("LIVENESS sent=%d ok=%d max_zero_streak=%d last5_ok=%d flood_sent=%d flood_replies=%d elapsed=%.1f"
      % (state["sent"], state["ok"], max_zero_streak, last5_ok,
         state["flood_sent"], state["flood_replies"], time.monotonic() - t0))
PYEOF

# Stop the data-plane processes gracefully so myexit() emits the delay summary.
kill -TERM "$SERVER_PID" "$CLIENT_PID" "$WRONG_PID" "$ECHO_PID" 2>/dev/null
sleep 1
wait "$SERVER_PID" "$CLIENT_PID" "$WRONG_PID" "$ECHO_PID" 2>/dev/null
SERVER_PID=""
CLIENT_PID=""
WRONG_PID=""
ECHO_PID=""

echo ""
echo "--- liveness driver raw output ---"
cat "$LOG_DIR/liveness.txt"

# ---- assertion 1/2: healthy delivery + fail-closed flood -------------------
liveness_line="$(grep '^LIVENESS ' "$LOG_DIR/liveness.txt" | tail -1)"
if [[ -z "$liveness_line" ]]; then
    fail "liveness driver produced no result (timeout or crash)"
else
    extract() { sed -n "s/.*[[:space:]]$1=\([0-9][0-9]*\).*/\1/p" <<<"$liveness_line"; }
    sent="$(extract sent)"; ok="$(extract ok)"
    zero_streak="$(extract max_zero_streak)"; last5="$(extract last5_ok)"
    flood_sent="$(extract flood_sent)"; flood_replies="$(extract flood_replies)"
    echo "  info: sent=$sent ok=$ok max_zero_streak=$zero_streak last5_ok=$last5 flood_sent=$flood_sent flood_replies=$flood_replies"
    if [[ -z "$sent" || -z "$ok" || -z "$zero_streak" || -z "$last5" || -z "$flood_sent" || -z "$flood_replies" ]]; then
        fail "could not parse the liveness metrics"
    else
        if (( sent > 0 && ok * 10 >= sent * 9 )); then
            pass "healthy tunnel delivered $ok/$sent during the wrong-key flood (>= 90%)"
        else
            fail "healthy tunnel delivered only $ok/$sent during the wrong-key flood (< 90%)"
        fi
        if (( zero_streak <= 2 )); then
            pass "no zero-delivery second streak longer than 2s (observed $zero_streak)"
        else
            fail "healthy delivery stalled for $zero_streak consecutive seconds"
        fi
        if (( last5 >= 1 )); then
            pass "healthy tunnel still delivering in the final 5s (last5_ok=$last5)"
        else
            fail "no healthy delivery in the final 5s"
        fi
        if (( flood_replies == 0 )); then
            pass "wrong-key flood received no tunneled replies (fail-closed)"
        else
            fail "wrong-key flood received $flood_replies replies - auth is not fail-closed"
        fi
        if (( flood_sent >= FLOOD_PPS * SECS / 2 )); then
            pass "wrong-key flood was actually concurrent (flood_sent=$flood_sent)"
        else
            fail "wrong-key flood did not run (flood_sent=$flood_sent)"
        fi
    fi
fi

# ---- assertion 3: bounded auth-failure logging at the operational level ----
auth_lines="$(grep -cE "$AUTH_FAIL_RE" "$LOG_DIR/server.log" || true)"
auth_budget=$(( AUTH_BUDGET_PER_60 * SECS / 60 ))
if (( auth_lines <= auth_budget )); then
    pass "auth-failure log lines <= budget: $auth_lines <= $auth_budget over ${SECS}s (budget $AUTH_BUDGET_PER_60/60s)"
else
    fail "auth-failure log flood: $auth_lines lines over ${SECS}s exceeds $auth_budget"
fi

# ---- assertion 4: delay counters emitted and high-water <= pool ------------
check_delay_summary() {
    local name="$1" log="$2" line n m h d
    line="$(grep -a 'delay: pool=' "$log" | tail -1)"
    if [[ -z "$line" ]]; then
        fail "$name: delay summary was not emitted at shutdown"
        return
    fi
    n="$(sed -n 's/.*pool=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    m="$(sed -n 's/.*fallback_malloc=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    h="$(sed -n 's/.*queue_high_water=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    d="$(sed -n 's/.*short_send_drop=\([0-9][0-9]*\).*/\1/p' <<<"$line")"
    echo "  info: $name summary: $line"
    if [[ -z "$n" || -z "$h" ]]; then
        fail "$name: delay summary is malformed"
        return
    fi
    if (( h <= n )); then
        pass "$name: queue_high_water $h <= pool $n (fallback_malloc=$m short_send_drop=$d)"
    else
        fail "$name: queue_high_water $h > pool $n (fallback_malloc=$m)"
    fi
}
check_delay_summary "server" "$LOG_DIR/server.log"
check_delay_summary "client" "$LOG_DIR/client.log"

# ---- assertion 5: no event-loop stall in the periodic reports --------------
echo ""
echo "--- periodic [report] gap check ---"
while read -r rfile rcount rmax rfirst rlast rgaps; do
    rname="$(basename "$rfile")"
    echo "  info: $rname reports=$rcount first=$rfirst last=$rlast max_gap=${rmax}s gaps=$rgaps"
    if (( rcount < 2 )); then
        fail "$rname: fewer than 2 periodic reports; cannot measure event-loop liveness"
        continue
    fi
    if (( rmax <= 2 )); then
        pass "$rname: max report gap ${rmax}s <= 2s (1s log resolution; steady cadence 1.2s)"
    else
        fail "$rname: max report gap ${rmax}s > 2s - event loop stalled"
    fi
    over=0
    IFS=',' read -r -a rarr <<<"$rgaps"
    for g in "${rarr[@]}"; do
        (( g > 1 )) && over=$(( over + 1 ))
    done
    if (( over <= rcount / 4 + 2 )); then
        pass "$rname: only $over/$((rcount-1)) gaps exceed 1s (steady 1.2s cadence pattern)"
    else
        fail "$rname: $over gaps exceed 1s - report cadence drifted or the loop stalled"
    fi
    if (( rcount >= SECS * 6 / 10 )); then
        pass "$rname: $rcount reports in ${SECS}s (>= 1 per 1.7s)"
    else
        fail "$rname: only $rcount reports in ${SECS}s (< 1 per 1.7s)"
    fi
done < <("$PYTHON" - "$LOG_DIR/server.log" "$LOG_DIR/client.log" <<'PYEOF'
import datetime, re, sys

stamp = re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\[INFO\]\[report')
for path in sys.argv[1:]:
    times = []
    with open(path, errors='replace') as fh:
        for line in fh:
            m = stamp.match(line)
            if m:
                times.append(datetime.datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S'))
    if len(times) < 2:
        print("%s %d 999 - - -" % (path, len(times)))
        continue
    gaps = [int((b - a).total_seconds()) for a, b in zip(times, times[1:])]
    print("%s %d %d %s %s %s" % (path, len(times), max(gaps),
                                 times[0].strftime('%H:%M:%S'), times[-1].strftime('%H:%M:%S'),
                                 ','.join(str(x) for x in gaps)))
PYEOF
)

# ---- verdict ---------------------------------------------------------------
echo ""
if (( FAILURES == 0 )); then
    echo "=== PASSED: liveness, fail-closed auth, bounded logging, counters, report cadence ==="
    exit 0
fi
echo "=== FAILED: ${FAILURES} assertion(s) failed ==="
exit 1
