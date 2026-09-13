#!/usr/bin/env bash
# bench.sh — reproducible authenticated-tunnel benchmark harness
#
# Runs a real speederv2 tunnel (client + server + UDP echo) over loopback
# across a compact matrix that varies PPS, packet size, FEC on/off, delay and
# packet loss, then writes a machine-readable metrics summary containing
# throughput, CPU, RSS, tail latency and FEC recovery.
#
# The full tunnel path is exercised: application UDP -> client FEC encoder ->
# wire (authenticated with the 32-hex key) -> server FEC decoder -> echo
# server, and back. Nothing here needs root; the only root-requiring row is
# the tc(8)/netem loss row, and it is replaced by a LOUD SKIP when tc is not
# usable. An in-binary --random-drop loss pair runs unconditionally and is
# what the FEC recovery figure is derived from.
#
# Reproducibility gate: consecutive summaries on the same host are compared.
# If aggregate throughput or aggregate CPU differ by more than
# BENCH_VARIANCE_PCT (default 25), the harness prints a LOUD VARIANCE banner
# and exits non-zero, because a variable run is not admissible as evidence.
# The comparison only happens between runs with the same binary hash and the
# same matrix signature; otherwise it says so and skips the gate.
#
# Usage:
#   bash tests/bench.sh [/path/to/speederv2] [--runs N] [--out-dir DIR]
#
#   --runs N        run the whole matrix N times in this invocation and
#                   compare each pass against the previous one (default 1;
#                   even with 1, the run is compared against the previous
#                   invocation's stored summary when one exists).
#   --out-dir DIR   where run summaries are written
#                   (default $BENCH_STATE_DIR/runs).
#
# Environment knobs (all optional):
#   BENCH_DURATION       seconds of offered traffic per row (default 2)
#   BENCH_VARIANCE_PCT   max allowed throughput/CPU delta in percent (default 25)
#   BENCH_STATE_DIR      persistent state dir holding last-summary.txt
#                        (default /tmp/udpspeeder-bench)
#   BENCH_OUT_DIR        same as --out-dir (--out-dir wins)
#   BENCH_NO_TC=1        never attempt the tc netem loss rows
#   PYTHON               python3 interpreter to use (default python3)
#
# Summary format: one KEY=VALUE per line, stable keys. Lines whose key starts
# with metric. are per-matrix-row, aggregate. are run-wide, derived. are
# computed from multiple rows, variance. describe the reproducibility gate,
# and skip. record loudly-skipped measurements. Human commentary lives in
# lines starting with '#'.
#
# Exit status:
#   0  matrix completed (LOUD SKIPs for unavailable tools are allowed)
#   1  a row failed at runtime, or the LOUD VARIANCE gate tripped
#   2  usage error / bad binary argument
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
KEY="00112233445566778899aabbccddeeff"

die() {
    printf 'ERROR: bench: %s\n' "$*" >&2
    exit 2
}

usage() {
    sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------- arguments
BINARY="./speederv2"
if [[ $# -gt 0 && "$1" != -* ]]; then
    BINARY="$1"
    shift
fi
RUNS=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs)
            [[ $# -ge 2 ]] || die "--runs needs a value"
            RUNS="$2"
            shift 2
            ;;
        --out-dir)
            [[ $# -ge 2 ]] || die "--out-dir needs a value"
            BENCH_OUT_DIR="$2"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1 (try --help)"
            ;;
    esac
done

[[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || die "--runs must be a positive integer, got '$RUNS'"

DURATION="${BENCH_DURATION:-2}"
TOL="${BENCH_VARIANCE_PCT:-25}"
STATE_DIR="${BENCH_STATE_DIR:-/tmp/udpspeeder-bench}"
OUT_DIR="${BENCH_OUT_DIR:-$STATE_DIR/runs}"

[[ "$DURATION" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "BENCH_DURATION must be a number, got '$DURATION'"
[[ "$TOL" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "BENCH_VARIANCE_PCT must be a number, got '$TOL'"

command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found (set PYTHON=...)"

# ------------------------------------------------------- binary validation
# A bogus binary argument must fail here with a clear message, before any
# tunnel is started. Checking -x alone is not enough: /bin/false is
# executable, so the binary is also asked to identify itself.
if [[ ! -e "$BINARY" ]]; then
    die "binary not found: $BINARY
       usage: bash tests/bench.sh [/path/to/speederv2] [--runs N] [--out-dir DIR]"
fi
if [[ ! -x "$BINARY" ]]; then
    die "binary is not executable: $BINARY"
fi
if command -v timeout >/dev/null 2>&1; then
    help_out="$(timeout 5 "$BINARY" --help 2>&1 || true)"
else
    help_out="$("$BINARY" --help 2>&1 || true)"
fi
case "$help_out" in
    *UDPspeeder*) ;;
    *)
        die "not a UDPspeeder binary (no 'UDPspeeder' in --help output): $BINARY"
        ;;
esac
BINARY_SHA="$(sha256sum "$BINARY" | awk '{print $1}')"

mkdir -p "$OUT_DIR/logs" || die "cannot create output dir: $OUT_DIR"
LOGDIR="$OUT_DIR/logs"

# ------------------------------------------------------------- matrix rows
# name:pps:pkt_size:fec(on|off):jitter_ms:random_drop(0.01%%):loss_kind
# One dimension moves per row from a shared baseline so a full pass stays
# short enough to repeat. loss_kind=none rows always run. loss_kind=tc rows
# are appended only when a netem qdisc can actually be installed.
ROWS=(
    "baseline:100:100:off:0:0:none"
    "pps-1000:1000:100:off:0:0:none"
    "size-1200:100:1200:off:0:0:none"
    "fec-on:100:200:on:0:0:none"
    "delay-jitter20:100:100:off:20:0:none"
    "loss-rd-nofec:100:200:off:0:500:random-drop"
    "loss-rd-fec:100:200:on:0:500:random-drop"
)

# ----------------------------------------------------------- tc/netem rows
TC_ACTIVE=0
TC_SKIP_REASON=""
tc_probe() {
    command -v tc >/dev/null 2>&1 || {
        TC_SKIP_REASON="tc(8) is not installed"
        return 1
    }
    [[ "$(id -u)" == "0" ]] || {
        TC_SKIP_REASON="root is required to install a netem qdisc"
        return 1
    }
    # Install then remove one qdisc now: if this fails, fail before touching
    # the matrix. If a foreign root qdisc already exists the add fails and we
    # leave it alone.
    tc qdisc add dev lo root netem loss 1% 2>/dev/null || {
        TC_SKIP_REASON="tc qdisc add on lo failed (existing root qdisc or no CAP_NET_ADMIN)"
        return 1
    }
    TC_ACTIVE=1
    tc qdisc del dev lo root 2>/dev/null || true
    TC_ACTIVE=0
    return 0
}
tc_loss_on() {
    tc qdisc add dev lo root netem loss "$1%" 2>/dev/null && TC_ACTIVE=1
}
tc_loss_off() {
    if [[ "$TC_ACTIVE" == "1" ]]; then
        tc qdisc del dev lo root 2>/dev/null || true
        TC_ACTIVE=0
    fi
}

if [[ "${BENCH_NO_TC:-0}" == "1" ]]; then
    TC_SKIP_REASON="disabled by BENCH_NO_TC=1"
elif tc_probe; then
    ROWS+=(
        "loss-tc-nofec:100:200:off:0:0:tc"
        "loss-tc-fec:100:200:on:0:0:tc"
    )
fi

print_tc_skip() {
    cat <<EOF
##############################################################################
# LOUD SKIP: tc(8) netem loss rows did NOT run -- $TC_SKIP_REASON
#            Packet loss under real netem conditions is UNMEASURED by this
#            summary. The in-binary --random-drop loss rows DID run (root is
#            not required for them) and are what FEC recovery is derived from.
##############################################################################
EOF
}

MATRIX_SIG="$(printf '%s\n' "${ROWS[@]}" | sha256sum | awk '{print $1}')"

# ------------------------------------------------------------ lifecycle
PIDS=()
cleanup_all() {
    stop_all
    tc_loss_off
}
trap cleanup_all EXIT

stop_all() {
    local p
    for p in "${PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
    done
    sleep 0.15
    for p in "${PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    PIDS=()
}

# --------------------------------------------------------------- helpers
cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }
rss_kb() { awk '/^VmHWM:/{print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }

# Normalize a value for the summary: only plain numbers survive, anything
# else (empty, nan, missing) becomes n/a so parsers never see garbage.
norm() {
    case "${1:-}" in
        '' | nan | NaN | *[!0-9.eE+-]*) echo "n/a" ;;
        *) echo "$1" ;;
    esac
}

gen_val() { # $1 = key, reads $gen_out
    printf '%s\n' "$gen_out" | sed -n "s/^$1=//p" | head -n 1
}

key_val() { # $1 = file, $2 = key
    awk -F= -v k="$2" '$1 == k {sub(/^[^=]*=/, ""); print; exit}' "$1"
}

# ---------------------------------------------------------- row runner
# Returns 0 on a measured row, 3 when the row was skipped (tc unavailable).
run_row() {
    local idx="$1" name="$2" pps="$3" size="$4" fec="$5" jitter="$6" drop="$7" lossmode="$8"

    local base=$(((RANDOM % 15000) + 30000))
    local echo_port="$base" tunnel_port=$((base + 1)) client_port=$((base + 2))
    local clog="$LOGDIR/$name.client.log" slog="$LOGDIR/$name.server.log" elog="$LOGDIR/$name.echo.log"
    local flags=()
    if [[ "$fec" == "on" ]]; then
        flags+=(-f20:10)
    else
        flags+=(--disable-fec)
    fi
    if [[ "$jitter" != "0" ]]; then
        flags+=(-j "$jitter")
    fi
    if [[ "$drop" != "0" ]]; then
        flags+=(--random-drop "$drop")
    fi

    printf -- '--- row %s: %s (pps=%s size=%s fec=%s jitter=%sms random_drop=%s loss=%s)\n' \
        "$idx" "$name" "$pps" "$size" "$fec" "$jitter" "$drop" "$lossmode"

    if [[ "$lossmode" == "tc" ]]; then
        if ! tc_loss_on 5; then
            printf 'metric.%s.status=SKIP\ntc_row.%s.reason=%s\n' "$name" "$name" "$TC_SKIP_REASON"
            return 3
        fi
    fi

    "$PYTHON" "$SCRIPT_DIR/udp_echo.py" "127.0.0.1" "$echo_port" >"$elog" 2>&1 &
    PIDS+=($!)
    "$BINARY" -s -l "127.0.0.1:$tunnel_port" -r "127.0.0.1:$echo_port" \
        -k "$KEY" --report 1 "${flags[@]}" >"$slog" 2>&1 &
    local spid=$!
    PIDS+=("$spid")
    "$BINARY" -c -l "127.0.0.1:$client_port" -r "127.0.0.1:$tunnel_port" \
        -k "$KEY" --report 1 "${flags[@]}" >"$clog" 2>&1 &
    local cpid=$!
    PIDS+=("$cpid")

    # Readiness probe: one echo round-trip through the whole tunnel.
    local ready=0
    if "$PYTHON" - "$client_port" 5 <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.2)
probe = b"READY?"
while time.time() < deadline:
    s.sendto(probe, ("127.0.0.1", port))
    try:
        data, _ = s.recvfrom(2048)
        if data == b"ECHO:" + probe:
            sys.exit(0)
    except socket.timeout:
        pass
sys.exit(1)
PYEOF
    then
        ready=1
    fi
    if [[ "$ready" != "1" ]]; then
        printf 'FAIL: row %s: tunnel did not become ready within 5s\n' "$name" >&2
        tail -n 5 "$slog" "$clog" >&2 || true
        tc_loss_off
        stop_all
        return 1
    fi

    local hz t0_s t0_c t1_s t1_c rss_s rss_c gen_out
    hz="$(getconf CLK_TCK)"
    t0_s="$(cpu_ticks "$spid")"
    t0_c="$(cpu_ticks "$cpid")"

    if ! gen_out="$("$PYTHON" - "$client_port" "$pps" "$size" "$DURATION" <<'PYEOF'
import socket, sys, threading, time

port = int(sys.argv[1])
pps = float(sys.argv[2])
size = int(sys.argv[3])
dur = float(sys.argv[4])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("127.0.0.1", port))

n = max(1, int(round(pps * dur)))
pad = max(0, size - 8)
send_at = {}
lock = threading.Lock()
done = threading.Event()
start = time.perf_counter()
window = n / pps
drain_end = start + window + 0.75


def sender():
    try:
        next_t = start
        for seq in range(n):
            payload = seq.to_bytes(8, "little") + b"\x5a" * pad
            # Timestamp BEFORE send: the echo can arrive before the sender
            # thread regains the GIL, and a reply with no recorded send time
            # would otherwise be miscounted as loss.
            with lock:
                send_at[seq] = time.perf_counter()
            try:
                s.send(payload)
            except OSError:
                pass
            next_t = start + (seq + 1) / pps
            d = next_t - time.perf_counter()
            if d > 0.0012:
                time.sleep(d - 0.0006)
            while time.perf_counter() < next_t:
                pass
    finally:
        done.set()


t = threading.Thread(target=sender)
t.start()
s.settimeout(0.05)
delivered = set()
rtt = {}
recv_bytes = 0
while True:
    try:
        data = s.recv(65536)
    except socket.timeout:
        data = None
    except OSError:
        data = None
    if data and len(data) >= 13 and data[:5] == b"ECHO:":
        seq = int.from_bytes(data[5:13], "little")
        if 0 <= seq < n and seq not in delivered:
            delivered.add(seq)
            recv_bytes += len(data) - 5
            with lock:
                t0 = send_at.get(seq)
            if t0 is not None:
                rtt[seq] = (time.perf_counter() - t0) * 1000.0
    if time.perf_counter() >= drain_end:
        break

t.join()
vals = sorted(rtt.values())


def pct(p):
    if not vals:
        return float("nan")
    idx = int(round((p / 100.0) * (len(vals) - 1)))
    return vals[min(len(vals) - 1, max(0, idx))]


def emit(k, v):
    print("%s=%s" % (k, v))


emit("sent", n)
emit("recv", len(rtt))
emit("sent_bytes", n * size)
emit("recv_bytes", recv_bytes)
emit("wall_s", "%.6f" % window)
emit("pps_target", "%.3f" % pps)
emit("pps_recv", "%.3f" % (len(rtt) / window))
emit("delivery_pct", "%.3f" % (100.0 * len(rtt) / n))
emit("lat_mean_ms", "%.4f" % (sum(vals) / len(vals) if vals else float("nan")))
emit("lat_p50_ms", "%.4f" % pct(50))
emit("lat_p95_ms", "%.4f" % pct(95))
emit("lat_p99_ms", "%.4f" % pct(99))
emit("lat_max_ms", "%.4f" % (vals[-1] if vals else float("nan")))
PYEOF
    )"; then
        printf 'FAIL: row %s: traffic generator failed\n' "$name" >&2
        tc_loss_off
        stop_all
        return 1
    fi

    t1_s="$(cpu_ticks "$spid")"
    t1_c="$(cpu_ticks "$cpid")"
    rss_s="$(rss_kb "$spid")"
    rss_c="$(rss_kb "$cpid")"

    tc_loss_off
    stop_all

    local sent recv recv_bytes wall r_delivery
    sent="$(gen_val sent)"
    recv="$(gen_val recv)"
    recv_bytes="$(gen_val recv_bytes)"
    wall="$(gen_val wall_s)"
    r_delivery="$(gen_val delivery_pct)"

    local thr cpu_s cpu_c cpu_t rss_t loss_pct
    thr="$(awk -v b="$recv_bytes" -v w="$wall" 'BEGIN{if (w <= 0) w = 1; printf "%.4f", b * 8 / w / 1e6}')"
    cpu_s="$(awk -v d="$((t1_s - t0_s))" -v hz="$hz" -v w="$wall" 'BEGIN{if (w <= 0) w = 1; printf "%.3f", d / hz / w * 100}')"
    cpu_c="$(awk -v d="$((t1_c - t0_c))" -v hz="$hz" -v w="$wall" 'BEGIN{if (w <= 0) w = 1; printf "%.3f", d / hz / w * 100}')"
    cpu_t="$(awk -v a="$cpu_s" -v b="$cpu_c" 'BEGIN{printf "%.3f", a + b}')"
    rss_t=$((rss_s + rss_c))
    loss_pct="$(awk -v d="$r_delivery" 'BEGIN{printf "%.3f", 100 - d}')"

    # Wire-level counters from the client's periodic [report] line.
    local rline="" nums=()
    rline="$(grep -a -F '[report]' "$clog" 2>/dev/null | tail -n 1 | sed -r 's/\x1b\[[0-9;]*m//g' || true)"
    if [[ -n "$rline" ]]; then
        mapfile -t nums < <(grep -oE '[0-9]+ (pkt|byte)' <<<"$rline" | grep -oE '^[0-9]+' || true)
    fi
    local wire_orig_pkt="n/a" wire_orig_byte="n/a" wire_fec_pkt="n/a" wire_fec_byte="n/a" wire_overhead="n/a"
    if ((${#nums[@]} == 8)); then
        wire_orig_pkt=$((nums[0] + nums[4]))
        wire_orig_byte=$((nums[1] + nums[5]))
        wire_fec_pkt=$((nums[2] + nums[6]))
        wire_fec_byte=$((nums[3] + nums[7]))
        wire_overhead="$(awk -v o="$wire_orig_byte" -v f="$wire_fec_byte" 'BEGIN{if (o > 0) printf "%.3f", 100 * (f - o) / o; else print "n/a"}')"
    fi

    # short_send_drop_count from the packet.cpp batch-send path, logged at
    # exit by delay_manager_t::log_stats(). n/a when the process was killed
    # before it could log.
    local short_drop="n/a"
    if grep -qa 'short_send_drop=' "$clog" "$slog" 2>/dev/null; then
        short_drop="$(grep -ah -o 'short_send_drop=[0-9]*' "$clog" "$slog" | cut -d= -f2 | awk '{s += $1} END{print s + 0}')"
    fi

    {
        printf 'metric.%s.status=ok\n' "$name"
        printf 'metric.%s.pps_target=%s\n' "$name" "$(norm "$(gen_val pps_target)")"
        printf 'metric.%s.pps_recv=%s\n' "$name" "$(norm "$(gen_val pps_recv)")"
        printf 'metric.%s.throughput_mbps=%s\n' "$name" "$thr"
        printf 'metric.%s.sent_pkts=%s\n' "$name" "$(norm "$sent")"
        printf 'metric.%s.recv_pkts=%s\n' "$name" "$(norm "$recv")"
        printf 'metric.%s.recv_bytes=%s\n' "$name" "$(norm "$recv_bytes")"
        printf 'metric.%s.delivery_pct=%s\n' "$name" "$(norm "$r_delivery")"
        printf 'metric.%s.loss_pct=%s\n' "$name" "$loss_pct"
        printf 'metric.%s.lat_p50_ms=%s\n' "$name" "$(norm "$(gen_val lat_p50_ms)")"
        printf 'metric.%s.lat_p95_ms=%s\n' "$name" "$(norm "$(gen_val lat_p95_ms)")"
        printf 'metric.%s.lat_p99_ms=%s\n' "$name" "$(norm "$(gen_val lat_p99_ms)")"
        printf 'metric.%s.lat_max_ms=%s\n' "$name" "$(norm "$(gen_val lat_max_ms)")"
        printf 'metric.%s.cpu_client_pct=%s\n' "$name" "$(norm "$cpu_c")"
        printf 'metric.%s.cpu_server_pct=%s\n' "$name" "$(norm "$cpu_s")"
        printf 'metric.%s.cpu_total_pct=%s\n' "$name" "$(norm "$cpu_t")"
        printf 'metric.%s.rss_client_kb=%s\n' "$name" "$(norm "$rss_c")"
        printf 'metric.%s.rss_server_kb=%s\n' "$name" "$(norm "$rss_s")"
        printf 'metric.%s.rss_total_kb=%s\n' "$name" "$(norm "$rss_t")"
        printf 'metric.%s.wire_orig_pkts=%s\n' "$name" "$wire_orig_pkt"
        printf 'metric.%s.wire_fec_pkts=%s\n' "$name" "$wire_fec_pkt"
        printf 'metric.%s.wire_orig_bytes=%s\n' "$name" "$wire_orig_byte"
        printf 'metric.%s.wire_fec_bytes=%s\n' "$name" "$wire_fec_byte"
        printf 'metric.%s.wire_fec_overhead_pct=%s\n' "$name" "$wire_overhead"
        printf 'metric.%s.short_send_drop=%s\n' "$name" "$short_drop"
    } >>"$SUMMARY"

    printf '    throughput=%s Mbps  cpu_total=%s%%  rss=%s kB  p95=%sms  delivery=%s%%\n' \
        "$thr" "$cpu_t" "$rss_t" "$(norm "$(gen_val lat_p95_ms)")" "$(norm "$r_delivery")"

    ROW_DELIVERY["$name"]="$(norm "$r_delivery")"
    ROW_SENT["$name"]="$(norm "$sent")"
    ROW_RECV["$name"]="$(norm "$recv")"

    AGG_BYTES="$(awk -v a="$AGG_BYTES" -v b="$recv_bytes" 'BEGIN{printf "%.0f", a + b}')"
    AGG_WALL="$(awk -v a="$AGG_WALL" -v b="$wall" 'BEGIN{printf "%.6f", a + b}')"
    AGG_CPU_SUM="$(awk -v a="$AGG_CPU_SUM" -v b="$cpu_t" 'BEGIN{printf "%.6f", a + b}')"
    AGG_CPU_N=$((AGG_CPU_N + 1))
    AGG_RSS_SUM=$((AGG_RSS_SUM + rss_t))
    AGG_ROWS=$((AGG_ROWS + 1))
    return 0
}

# ------------------------------------------------------- variance gate
# Compare $2 against $1. Prints variance.* lines; returns 1 on a violation.
compare_summaries() {
    local prev="$1" cur="$2"
    local psig csig pbin cbin
    psig="$(key_val "$prev" bench.matrix_sig)"
    csig="$(key_val "$cur" bench.matrix_sig)"
    pbin="$(key_val "$prev" bench.binary_sha256)"
    cbin="$(key_val "$cur" bench.binary_sha256)"
    if [[ -z "$psig" || "$psig" != "$csig" || -z "$pbin" || "$pbin" != "$cbin" ]]; then
        printf 'variance.status=SKIPPED\n'
        printf 'variance.reason=previous summary is not comparable (matrix signature or binary hash changed)\n'
        return 0
    fi
    local fail=0 m pa pb dp
    for m in aggregate.throughput_mbps aggregate.cpu_total_pct; do
        pa="$(key_val "$prev" "$m")"
        pb="$(key_val "$cur" "$m")"
        dp="$(awk -v a="$pa" -v b="$pb" 'BEGIN{
            if (a < 0 || b < 0 || a == "" || b == "") {print "err"; exit}
            hi = (a > b ? a : b); lo = (a > b ? b : a)
            if (hi == 0) {print (lo == 0 ? 0 : 100)} else {printf "%.3f", (hi - lo) * 100 / hi}
        }')"
        printf 'variance.%s.previous=%s\n' "$m" "$(norm "$pa")"
        printf 'variance.%s.current=%s\n' "$m" "$(norm "$pb")"
        printf 'variance.%s.delta_pct=%s\n' "$m" "$dp"
        printf 'variance.%s.tolerance_pct=%s\n' "$m" "$TOL"
        if [[ "$dp" == "err" ]] || awk -v d="$dp" -v t="$TOL" 'BEGIN{exit !(d > t)}'; then
            fail=1
        fi
    done
    if ((fail)); then
        printf 'variance.status=FAIL\n'
    else
        printf 'variance.status=PASS\n'
    fi
    return "$fail"
}

# --------------------------------------------------------------- main
STAMP="$(date +%Y%m%d-%H%M%S)-$$"
VARIANCE_FAIL=0
VARIANCE_DETAILS=""

printf '=== UDPspeeder bench ===\n'
printf 'binary   : %s (sha256 %s)\n' "$BINARY" "$BINARY_SHA"
printf 'matrix   : %s rows, %ss per row, %s pass(es)\n' "${#ROWS[@]}" "$DURATION" "$RUNS"
printf 'state dir: %s\n' "$STATE_DIR"
if [[ -n "$TC_SKIP_REASON" ]]; then
    print_tc_skip
fi
printf '\n'

COMPARE_FILE=""
if [[ -f "$STATE_DIR/last-summary.txt" ]]; then
    COMPARE_FILE="$STATE_DIR/last-summary.txt"
fi

PASS=1
while ((PASS <= RUNS)); do
    SUMMARY="$OUT_DIR/bench-summary-${STAMP}-pass${PASS}.txt"
    AGG_BYTES=0
    AGG_WALL=0
    AGG_CPU_SUM=0
    AGG_CPU_N=0
    AGG_RSS_SUM=0
    AGG_ROWS=0
    declare -A ROW_DELIVERY=() ROW_SENT=() ROW_RECV=()

    {
        printf '# UDPspeeder bench summary\n'
        printf '# machine-readable KEY=VALUE lines only below; see tests/bench.sh\n'
        printf 'bench.version=1\n'
        printf 'bench.timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'bench.host=%s\n' "$(hostname 2>/dev/null || echo unknown)"
        printf 'bench.kernel=%s\n' "$(uname -r)"
        printf 'bench.binary_path=%s\n' "$BINARY"
        printf 'bench.binary_sha256=%s\n' "$BINARY_SHA"
        printf 'bench.matrix_sig=%s\n' "$MATRIX_SIG"
        printf 'bench.duration_s=%s\n' "$DURATION"
        printf 'bench.variance_tolerance_pct=%s\n' "$TOL"
        printf 'bench.pass=%s\n' "$PASS"
        if [[ -n "$TC_SKIP_REASON" ]]; then
            printf 'skip.tc_loss=SKIP (%s)\n' "$TC_SKIP_REASON"
        else
            printf 'skip.tc_loss=none\n'
        fi
    } >"$SUMMARY"

    if ((PASS > 1)); then
        printf -- '--- pass %s/%s ---\n' "$PASS" "$RUNS"
    fi

    IDX=0
    for row in "${ROWS[@]}"; do
        IFS=':' read -r name pps size fec jitter drop lossmode <<<"$row"
        IDX=$((IDX + 1))
        rc=0
        run_row "$IDX" "$name" "$pps" "$size" "$fec" "$jitter" "$drop" "$lossmode" || rc=$?
        if ((rc == 3)); then
            printf 'metric.%s.status=SKIP\n' "$name" >>"$SUMMARY"
            printf 'row.%s.skipped=%s\n' "$name" "$TC_SKIP_REASON" >>"$SUMMARY"
        elif ((rc != 0)); then
            printf 'FAIL: row %s failed; summary left at %s\n' "$name" "$SUMMARY" >&2
            exit 1
        fi
    done

    AGG_THR="$(awk -v b="$AGG_BYTES" -v w="$AGG_WALL" 'BEGIN{if (w <= 0) w = 1; printf "%.4f", b * 8 / w / 1e6}')"
    AGG_CPU="$(awk -v s="$AGG_CPU_SUM" -v n="$AGG_CPU_N" 'BEGIN{printf "%.3f", (n > 0 ? s / n : 0)}')"
    AGG_RSS="$(awk -v s="$AGG_RSS_SUM" -v n="$AGG_CPU_N" 'BEGIN{printf "%.0f", (n > 0 ? s / n : 0)}')"

    # Derived FEC recovery: percentage points of delivery recovered by FEC
    # under the same in-binary random-drop loss, relative to FEC off. 0 means
    # FEC recovered nothing; positive means it recovered packets the FEC-off
    # run lost.
    for pair in "loss-rd-fec loss-rd-nofec random_drop" "loss-tc-fec loss-tc-nofec tc"; do
        read -r d_fec d_ref d_label <<<"$pair"
        d_fec="${ROW_DELIVERY[$d_fec]:-}"
        d_ref="${ROW_DELIVERY[$d_ref]:-}"
        if [[ -n "$d_fec" && "$d_fec" != "n/a" && -n "$d_ref" && "$d_ref" != "n/a" ]]; then
            d_gain="$(awk -v a="$d_fec" -v b="$d_ref" 'BEGIN{printf "%.3f", a - b}')"
            printf 'derived.fec_recovery_%s_pp=%s\n' "$d_label" "$d_gain"
            printf 'derived.fec_recovery_%s_delivered_fec_pct=%s\n' "$d_label" "$d_fec"
            printf 'derived.fec_recovery_%s_delivered_nofec_pct=%s\n' "$d_label" "$d_ref"
        else
            printf 'derived.fec_recovery_%s_pp=n/a\n' "$d_label"
        fi
    done

    {
        printf 'aggregate.throughput_mbps=%s\n' "$AGG_THR"
        printf 'aggregate.cpu_total_pct=%s\n' "$AGG_CPU"
        printf 'aggregate.rss_total_kb=%s\n' "$AGG_RSS"
        printf 'aggregate.rows_measured=%s\n' "$AGG_ROWS"
        printf 'aggregate.duration_s=%s\n' "$AGG_WALL"
        printf 'aggregate.recv_bytes=%s\n' "$AGG_BYTES"
    } >>"$SUMMARY"

    if [[ -n "$COMPARE_FILE" ]]; then
        var_out=""
        if ! var_out="$(compare_summaries "$COMPARE_FILE" "$SUMMARY")"; then
            VARIANCE_FAIL=1
            VARIANCE_DETAILS="$(printf '%s\n' "$var_out" | grep -E '^variance\.aggregate\.(throughput_mbps|cpu_total_pct)\.(previous|current|delta_pct)=' | sed 's/^/!!   /' || true)"
        fi
        printf '%s\n' "$var_out" | tee -a "$SUMMARY"
    else
        printf 'variance.status=NO_PREVIOUS_RUN\n' | tee -a "$SUMMARY"
    fi
    printf '    aggregate: throughput=%s Mbps  cpu_total=%s%%  rss=%s kB\n' "$AGG_THR" "$AGG_CPU" "$AGG_RSS"

    COMPARE_FILE="$SUMMARY"
    PASS=$((PASS + 1))
done

mkdir -p "$STATE_DIR"
cp -f "$SUMMARY" "$STATE_DIR/last-summary.txt.tmp"
mv -f "$STATE_DIR/last-summary.txt.tmp" "$STATE_DIR/last-summary.txt"

printf '\n'
if ((VARIANCE_FAIL)); then
    cat >&2 <<EOF
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! LOUD VARIANCE: consecutive bench runs differ by more than ${TOL}%          !!
!! Aggregate throughput and/or CPU are not reproducible on this host, so     !!
!! this run is NOT ADMISSIBLE AS EVIDENCE.                                   !!
${VARIANCE_DETAILS}
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
    printf 'BENCH SUMMARY (variance failed): %s\n' "$SUMMARY"
    exit 1
fi

printf 'BENCH SUMMARY: %s\n' "$SUMMARY"
printf 'BENCH LAST SUMMARY: %s\n' "$STATE_DIR/last-summary.txt"
exit 0
