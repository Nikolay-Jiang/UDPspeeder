#!/usr/bin/env bash
# smoke_test_mode.sh — end-to-end check for --test-mode
#
# Round 1: --test-selftest (pure-function regression, expects 75 checks/0 fail)
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
#
# Timing note: the rate-scan phase is a fixed 10s x 3 sub-phases regardless of
# --test-duration/--test-pps, so each prober run still pays ~36s minimum in
# addition to its S1 (and now S2) phases. The whole script (selftest + 4 full
# prober runs) takes roughly 3-4 minutes.
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
KEY="smoke_testmode_$$"

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

echo "Round 1: --test-selftest"
if ! "$BINARY" --test-selftest; then
    echo "  FAIL: selftest reported failures"
    exit 1
fi
echo "  [selftest] passed"
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

echo "=== PASSED ==="
