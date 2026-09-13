#!/usr/bin/env bash
# smoke_test_mode.sh — end-to-end check for --test-mode
#
# Round 1: --test-selftest (pure-function regression, expects 0 failures).
#          Also asserts the emitted parent-harness check count has not dropped
#          below EXPECTED_SELFTEST_MIN, and that no -k is required.
# Round 1a-1d: reverse-path negatives driven through the real responder
#          callback in-process (wrong cookie, missing cookie, duplicate
#          PHASE_BEGIN, idle expiry); each must be rejected or the suite fails.
# Round 2: loopback probe with no injected loss   -> reported loss < 1%
# Round 3: loopback probe with --random-drop 1000 (~10% injected) -> reported
#          loss lands in a 5-16% band (injection is pseudo-random per run, so
#          we assert a band rather than a point value), a recommendation
#          section is rendered, and all three tier rows carry a real -f value.
# Round 4: reverse (server -> client) phase on a clean loopback -> a real
#          "server -> client" section is rendered, with reported loss <1% and
#          neither "not measured" nor "no packets" text.
# Round 5: --test-no-reverse suppresses the reverse phase -> the report says
#          the direction was disabled and prints no downstream recommendation.
# Round 6: --data-port-range on both ends -> the responder spreads the reverse
#          (S4) phase across all 4 data ports (each fd answers the address it
#          itself observed during S3, per Task 6's nat design), and the report
#          renders a downstream port-range comparison line.
# Round 7: --random-drop 1000 on the RESPONDER only (~10% injected downstream,
#          nothing injected upstream) -> upstream loss stays <1% while the
#          downstream figure lands in the same 5-16% band Round 3 asserts for
#          the upstream direction. This is the only round that proves the
#          downstream measurement tracks real loss rather than merely being
#          non-zero: rounds 4 and 6 only ever see a clean loopback, against
#          which a systematically-understating downstream path would still
#          look perfect.
# Round 8: wrong-key prober against a keyed responder -> the responder rejects
#          the MAC and the prober exits without a report (test-plane rekey).
#
# Timing note: the rate-scan phase is a fixed 10s x 3 sub-phases regardless of
# --test-duration/--test-pps, so each prober run still pays ~36s minimum in
# addition to its S1/S2 (and, for round 6, S3/S4) phases. The whole script
# (selftest + 6 full prober runs, one per Round 2-7) takes roughly 3 minutes.
#
# Usage: bash tests/smoke_test_mode.sh [/path/to/speederv2]
# Exit 0 on pass, non-zero on failure.

set -euo pipefail

BINARY="${1:-./speederv2}"
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: binary not found or not executable: $BINARY"
    exit 1
fi

# Random high port to avoid CI collisions with other suites/runs.
BASE_PORT=$(( (RANDOM % 20000) + 34000 ))
RESP_PORT=$BASE_PORT
KEY="fedcba9876543210fedcba9876543210"

# Floor for the parent-harness check count emitted as
# "test_mode selftest: N checks, F failures". Set by the exact procedure in the
# plan (todo 15), run on a build where todos 1/6/13 have landed:
#   N=$(./speederv2 --test-selftest 2>&1 | sed -n 's/.*selftest: \([0-9]*\) checks.*/\1/p')
# A future change that silently deletes checks would otherwise keep passing.
# When checks are added, raise this literal deliberately; never lower it.
EXPECTED_SELFTEST_MIN=194

WORKDIR=$(mktemp -d)
PIDS=()
RESP_PID=""

cleanup() {
    if [[ -n "$RESP_PID" ]]; then
        kill "$RESP_PID" 2>/dev/null || true
    fi
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "=== UDPspeeder --test-mode smoke test ==="
echo "  binary : $BINARY"
echo "  port   : $RESP_PORT"
echo "  note   : rate-scan is a fixed 10s x 3 phases per prober run (~36s);"
echo "           expect roughly ~2 minutes total for this script"
echo

echo "Round 1: --test-selftest (no -k) + check-count floor"
SELFTEST_OUT=$("$BINARY" --test-selftest 2>&1) || {
    echo "  FAIL: selftest reported failures with no -k"
    printf '%s\n' "$SELFTEST_OUT" | grep -E "FAIL|failures" | head -20 || true
    exit 1
}
N=$(printf '%s\n' "$SELFTEST_OUT" | sed -n 's/.*selftest: \([0-9]*\) checks.*/\1/p')
if [[ ! "$N" =~ ^[0-9]+$ ]]; then
    echo "  FAIL: could not parse 'test_mode selftest: N checks' from selftest output"
    exit 1
fi
if (( N < EXPECTED_SELFTEST_MIN )); then
    echo "  FAIL: selftest emitted ${N} checks, below the ${EXPECTED_SELFTEST_MIN}-check floor"
    echo "        (a check was removed, or the harness stopped counting)"
    exit 1
fi
echo "  [selftest] passed with no -k; ${N} checks >= floor ${EXPECTED_SELFTEST_MIN}"
echo

# Reverse-phase negatives. Each case drives the REAL responder_cb in-process
# through the --test-selftest hook (UDPSPEEDER_SELFTEST_REVERSE), so no network
# peer, root, or tc is needed and the network paths are untouched. The harness
# asserts the production rejection path and prints a marker line; a case that is
# not rejected prints nothing and exits non-zero here.
echo "Round 1a: reverse negative - wrong cookie must be rejected"
OUT_1A=$(UDPSPEEDER_SELFTEST_REVERSE=wrong-cookie "$BINARY" --test-selftest 2>&1) || {
    echo "  FAIL: selftest failed while driving the wrong-cookie case"; exit 1; }
printf '%s\n' "$OUT_1A" | grep -q "refusing reverse phase" || {
    echo "  FAIL: wrong-cookie PHASE_BEGIN was not rejected"; exit 1; }
if printf '%s\n' "$OUT_1A" | grep -q "trace-stats:"; then
    echo "  FAIL: wrong-cookie case still produced a probe/trace line"; exit 1; fi
echo "  [reverse-neg] wrong cookie rejected, no probe/trace line"

echo "Round 1b: reverse negative - missing cookie must be rejected"
OUT_1B=$(UDPSPEEDER_SELFTEST_REVERSE=missing-cookie "$BINARY" --test-selftest 2>&1) || {
    echo "  FAIL: selftest failed while driving the missing-cookie case"; exit 1; }
printf '%s\n' "$OUT_1B" | grep -q "refusing reverse phase" || {
    echo "  FAIL: missing-cookie PHASE_BEGIN was not rejected"; exit 1; }
if printf '%s\n' "$OUT_1B" | grep -q "trace-stats:"; then
    echo "  FAIL: missing-cookie case still produced a probe/trace line"; exit 1; fi
echo "  [reverse-neg] missing cookie rejected, no probe/trace line"

echo "Round 1c: reverse negative - duplicate PHASE_BEGIN must re-ACK, not reset"
OUT_1C=$(UDPSPEEDER_SELFTEST_REVERSE=duplicate "$BINARY" --test-selftest 2>&1) || {
    echo "  FAIL: selftest failed while driving the duplicate-PHASE_BEGIN case"; exit 1; }
printf '%s\n' "$OUT_1C" | grep -q "duplicate PHASE_BEGIN for open phase" || {
    echo "  FAIL: duplicate PHASE_BEGIN did not take the re-ACK path"; exit 1; }
TS_COUNT=$(printf '%s\n' "$OUT_1C" | grep -c "^trace-stats:" || true)
TS_FIRST=$(printf '%s\n' "$OUT_1C" | grep -m1 "^trace-stats:" || true)
TS_LAST=$(printf '%s\n' "$OUT_1C" | grep "^trace-stats:" | tail -n1 || true)
if [[ "$TS_COUNT" -ne 2 || -z "$TS_FIRST" || "$TS_FIRST" != "$TS_LAST" ]]; then
    echo "  FAIL: duplicate PHASE_BEGIN changed the trace (${TS_COUNT} stats line(s):"
    echo "        first='${TS_FIRST}' last='${TS_LAST}')"
    exit 1
fi
echo "  [reverse-neg] duplicate re-ACKed; trace-stats byte-identical (${TS_FIRST})"

echo "Round 1d: reverse negative - idle expiry must drop the session"
OUT_1D=$(UDPSPEEDER_SELFTEST_REVERSE=idle-expiry "$BINARY" --test-selftest 2>&1) || {
    echo "  FAIL: selftest failed while driving the idle-expiry case"; exit 1; }
printf '%s\n' "$OUT_1D" | grep -q "res.rc_expired" || {
    echo "  FAIL: idle expiry did not fire (no res.rc_expired line)"; exit 1; }
echo "  [reverse-neg] idle session expired; res.rc_expired emitted"
echo

start_responder() {
    "$BINARY" -s --test-mode -l "0.0.0.0:$RESP_PORT" -k "$KEY" \
        --log-level 4 --disable-color \
        > "$WORKDIR/responder.log" 2>&1 &
    RESP_PID=$!
    PIDS+=("$RESP_PID")
    sleep 1
}

stop_responder() {
    kill "$RESP_PID" 2>/dev/null || true
    wait "$RESP_PID" 2>/dev/null || true
    RESP_PID=""
}

run_prober() {
    # Extra args (e.g. --random-drop 1000) are passed as real positional
    # arguments, not a string blob, so there is no word-splitting hazard.
    timeout 120 "$BINARY" -c --test-mode -r "127.0.0.1:$RESP_PORT" -k "$KEY" \
        --test-duration 2 --test-pps 100 --disable-color "$@" 2>&1
}

# Extracts the first "NN.NNNN" figure that immediately follows a "丢包率"
# label's colon, e.g. from:
#   "  丢包率               : 2.0500%  (123/6000)"
# -> 2.0500
#
# Anchored on ": <number>" right after the label, rather than "first decimal
# number on the line" or positional (head -1) luck, for two reasons verified
# by hand against actual --test-mode output:
#   1. The report itself is rendered with plain printf (test_render_report in
#      test_mode.cpp), not through the mylog()/log_bare() color-coded logging
#      path, so the report lines carry no ANSI escapes in practice today —
#      but --disable-color is still passed to the prober as a defense against
#      that changing, and the anchor makes the extraction indifferent to
#      color codes appearing anywhere outside the ": <number>" match.
#   2. Today only the up-direction (client -> server) is implemented, so only
#      one "丢包率" line ever appears; if a second (down) direction is added
#      later, `grep -m1` keeps this taking the first one deterministically
#      rather than becoming ambiguous.
# The trailing "(123/6000)" fraction never confuses this: those integers have
# no decimal point, so they can't match "[0-9]+\.[0-9]+".
extract_loss() {
    grep -m1 "丢包率" | grep -oE ': *[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+'
}

# Fail loudly (rather than silently pass) if extraction came back empty or
# malformed -- e.g. because a run timed out and produced no report line.
# Without this check, an empty $val compares as 0 in awk's numeric context,
# which would make the Round 2 "<1%" assertion pass on a run that actually
# produced no data at all.
assert_is_number() {
    local val="$1" what="$2"
    if [[ ! "$val" =~ ^[0-9]+\.[0-9]+$ ]]; then
        echo "  FAIL: could not parse ${what} loss figure (got: '${val}')"
        exit 1
    fi
}

# Every tier row must carry a real "-f x:y" recommendation.
#
# A tier whose target could not be met renders "目标不可达" in place of the
# whole row, so this assertion is what catches the class of bug where a tier
# never reaches the prober at all and is therefore declared unreachable on
# every single run -- which is exactly how a report showing the balanced tier
# meeting its target while the other two rows claimed the link could not reach
# theirs got past an earlier "推荐配置 appears" check.
#
# Only "<digits>:<digits>" can match the -f cell: the residual and overhead
# cells are percentages, the bandwidth cell is "N.NN Mbps", and -i is "Nms".
# ~10% isolated loss makes all three targets comfortably feasible, so any
# "目标不可达" row on this round is a real defect and not a hard link.
assert_all_tiers_have_fec() {
    local out="$1" tier row
    for tier in 省流 均衡 激进; do
        row=$(echo "$out" | grep -m1 "^  ${tier} ") || true
        if [[ -z "$row" ]]; then
            echo "  FAIL: no '${tier}' tier row found in the report"
            exit 1
        fi
        if [[ ! "$row" =~ [0-9]+:[0-9]+ ]]; then
            echo "  FAIL: '${tier}' tier row carries no -f value: ${row}"
            exit 1
        fi
    done
}

echo "Round 2: clean loopback (expect <1% loss)"
start_responder
OUT2=$(run_prober)
stop_responder
echo "$OUT2" | grep -q "UDPspeeder FEC 测试报告" || { echo "  FAIL: no report produced"; exit 1; }
LOSS2=$(echo "$OUT2" | extract_loss)
assert_is_number "$LOSS2" "clean-loopback"
echo "  [clean] reported loss = ${LOSS2}%"
awk -v l="$LOSS2" 'BEGIN{ exit !(l < 1.0) }' \
    || { echo "  FAIL: clean run reported ${LOSS2}% loss (expected <1%)"; exit 1; }
echo "  [clean] ok"
echo

echo "Round 3: --random-drop 1000 (~10% injected)"
start_responder
OUT3=$(run_prober --random-drop 1000)
stop_responder
echo "$OUT3" | grep -q "UDPspeeder FEC 测试报告" || { echo "  FAIL: no report produced"; exit 1; }
LOSS3=$(echo "$OUT3" | extract_loss)
assert_is_number "$LOSS3" "drop-injected"
echo "  [drop] reported loss = ${LOSS3}%"
# Pseudo-random injection varies run to run; assert a band, not an exact value.
awk -v l="$LOSS3" 'BEGIN{ exit !(l > 5.0 && l < 16.0) }' \
    || { echo "  FAIL: injected ~10% but reported ${LOSS3}% (expected band 5-16%)"; exit 1; }
echo "$OUT3" | grep -q "推荐配置" || { echo "  FAIL: no recommendation section"; exit 1; }
assert_all_tiers_have_fec "$OUT3"
echo "  [drop] all three tier rows carry an -f value"
echo "  [drop] ok"
echo

echo "Round 4: reverse phase on a clean loopback"
"$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" --log-level 4 \
    > "$WORKDIR/r4_resp.log" 2>&1 &
RESP_PID=$!
PIDS+=("$RESP_PID")
sleep 1
"$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$KEY" \
    --test-duration 2 --test-pps 100 > "$WORKDIR/r4_prober.log" 2>&1
kill "$RESP_PID" 2>/dev/null || true; wait "$RESP_PID" 2>/dev/null || true; RESP_PID=""

if ! grep -q "server -> client, 单端口" "$WORKDIR/r4_prober.log"; then
    echo "  FAIL: no server -> client section in the report"
    sed -n '1,80p' "$WORKDIR/r4_prober.log"
    exit 1
fi
if grep -q "未测出结果\|未测量" "$WORKDIR/r4_prober.log"; then
    echo "  FAIL: reverse direction reported as unmeasured on a clean loopback"
    exit 1
fi
DOWN_LOSS=$(sed -n '/server -> client, 单端口/,/推荐配置/p' "$WORKDIR/r4_prober.log" \
    | grep "丢包率" | grep -oE '[0-9]+\.[0-9]+' | head -1)
if [[ -z "$DOWN_LOSS" ]]; then
    echo "  FAIL: could not parse downstream loss"
    exit 1
fi
if awk -v v="$DOWN_LOSS" 'BEGIN{exit !(v > 1.0)}'; then
    echo "  FAIL: downstream loss $DOWN_LOSS% too high on clean loopback"
    exit 1
fi
echo "  [reverse-clean] downstream loss = $DOWN_LOSS%"
echo "  [reverse-clean] ok"
echo

echo "Round 5: --test-no-reverse suppresses the reverse phase"
"$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" --log-level 4 \
    > "$WORKDIR/r5_resp.log" 2>&1 &
RESP_PID=$!
PIDS+=("$RESP_PID")
sleep 1
"$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$KEY" \
    --test-duration 2 --test-pps 100 --test-no-reverse \
    > "$WORKDIR/r5_prober.log" 2>&1
kill "$RESP_PID" 2>/dev/null || true; wait "$RESP_PID" 2>/dev/null || true; RESP_PID=""

if ! grep -q "已通过 --test-no-reverse 关闭该方向" "$WORKDIR/r5_prober.log"; then
    echo "  FAIL: --test-no-reverse did not report the direction as disabled"
    exit 1
fi
if grep -q "推荐配置 (server -> client" "$WORKDIR/r5_prober.log"; then
    echo "  FAIL: --test-no-reverse still produced a downstream recommendation"
    exit 1
fi
echo "  [no-reverse] ok"
echo

echo "Round 6: multi-port reverse (--data-port-range on both ends)"
DP_LO=$(( RESP_PORT + 100 ))
DP_HI=$(( DP_LO + 3 ))
"$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" \
    --data-port-range $DP_LO-$DP_HI --log-level 4 \
    > "$WORKDIR/r6_resp.log" 2>&1 &
RESP_PID=$!
PIDS+=("$RESP_PID")
sleep 1
"$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$KEY" \
    --data-port-range $DP_LO-$DP_HI --test-duration 2 --test-pps 100 \
    > "$WORKDIR/r6_prober.log" 2>&1
kill "$RESP_PID" 2>/dev/null || true; wait "$RESP_PID" 2>/dev/null || true; RESP_PID=""

if ! grep -q "下行  单端口" "$WORKDIR/r6_prober.log"; then
    echo "  FAIL: no downstream port-range comparison line"
    sed -n '1,120p' "$WORKDIR/r6_prober.log"
    exit 1
fi
if ! grep -q "reverse phase 4 will use 4 data port(s)" "$WORKDIR/r6_resp.log"; then
    echo "  FAIL: responder did not spread the reverse phase across 4 data ports"
    grep -i "reverse phase" "$WORKDIR/r6_resp.log" || true
    exit 1
fi
echo "  [reverse-spread] ok"
echo

echo "Round 7: --random-drop 1000 on the RESPONDER (~10% injected downstream only)"
# --random-drop on the responder is implemented only for TEST_PROBE in the
# reverse sender (rev_tick_cb), so it injects loss into the server -> client
# direction and leaves client -> server untouched. That asymmetry is the point:
# it separates "the downstream number moves with real loss" from "the
# downstream number is just a copy of the upstream one".
"$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" --random-drop 1000 \
    --log-level 4 --disable-color > "$WORKDIR/r7_resp.log" 2>&1 &
RESP_PID=$!
PIDS+=("$RESP_PID")
sleep 1
timeout 120 "$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$KEY" \
    --test-duration 2 --test-pps 100 --disable-color \
    > "$WORKDIR/r7_prober.log" 2>&1
kill "$RESP_PID" 2>/dev/null || true; wait "$RESP_PID" 2>/dev/null || true; RESP_PID=""

if ! grep -q "server -> client, 单端口" "$WORKDIR/r7_prober.log"; then
    echo "  FAIL: no server -> client section in the report"
    sed -n '1,120p' "$WORKDIR/r7_prober.log"
    exit 1
fi

# Upstream: the prober injects nothing, so this must stay clean. If it does not,
# the downstream figure below cannot be attributed to the injected loss.
UP_LOSS7=$(extract_loss < "$WORKDIR/r7_prober.log")
assert_is_number "$UP_LOSS7" "round-7 upstream"
echo "  [down-drop] upstream loss = ${UP_LOSS7}%"
awk -v l="$UP_LOSS7" 'BEGIN{ exit !(l < 1.0) }' \
    || { echo "  FAIL: upstream reported ${UP_LOSS7}% but nothing was injected upstream"; exit 1; }

# Downstream: same band as Round 3, for the same reason (pseudo-random
# injection varies run to run). Anchored on the same section range Round 4 uses.
DOWN_LOSS7=$(sed -n '/server -> client, 单端口/,/推荐配置/p' "$WORKDIR/r7_prober.log" \
    | grep "丢包率" | grep -oE '[0-9]+\.[0-9]+' | head -1)
assert_is_number "$DOWN_LOSS7" "round-7 downstream"
echo "  [down-drop] downstream loss = ${DOWN_LOSS7}%"
awk -v l="$DOWN_LOSS7" 'BEGIN{ exit !(l > 5.0 && l < 16.0) }' \
    || { echo "  FAIL: injected ~10% downstream but reported ${DOWN_LOSS7}% (expected band 5-16%)"; exit 1; }
echo "  [down-drop] ok"
echo

echo "Round 8: wrong-key peer is rejected (test-plane rekey)"
# The prober's HELLO is MAC'd with its own -k. A responder holding a different
# key must drop it silently and the prober must give up without a report. This
# is the end-to-end proof that the test plane is keyed by the shared PSK, not
# merely by "some key was supplied".
WRONG_KEY="00112233445566778899aabbccddeeff"
"$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" --log-level 4 --disable-color \
    > "$WORKDIR/r8_resp.log" 2>&1 &
RESP_PID=$!
PIDS+=("$RESP_PID")
sleep 1
set +e
timeout 60 "$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$WRONG_KEY" \
    --test-duration 1 --test-pps 5 --test-no-reverse --disable-color \
    > "$WORKDIR/r8_prober.log" 2>&1
RK_RC=$?
set -e
kill "$RESP_PID" 2>/dev/null || true; wait "$RESP_PID" 2>/dev/null || true; RESP_PID=""

if [[ "$RK_RC" -eq 0 || "$RK_RC" -eq 124 ]]; then
    echo "  FAIL: wrong-key prober exit status ${RK_RC} (expected a failure, not success/timeout)"
    exit 1
fi
if grep -q "UDPspeeder FEC 测试报告" "$WORKDIR/r8_prober.log"; then
    echo "  FAIL: wrong-key prober produced a report"
    exit 1
fi
if ! grep -q "mac/format check failed" "$WORKDIR/r8_resp.log"; then
    echo "  FAIL: responder did not reject the wrong-key peer"
    exit 1
fi
echo "  [wrong-key] prober rc=${RK_RC}, no report; responder logged mac/format check failed"
echo

echo "=== PASSED ==="
