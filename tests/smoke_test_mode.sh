#!/usr/bin/env bash
# smoke_test_mode.sh — end-to-end check for --test-mode
#
# Round 1: --test-selftest (pure-function regression, expects 75 checks/0 fail)
# Round 2: loopback probe with no injected loss   -> reported loss < 1%
# Round 3: loopback probe with --random-drop 1000 (~10% injected) -> reported
#          loss lands in a 5-16% band (injection is pseudo-random per run, so
#          we assert a band rather than a point value), a recommendation
#          section is rendered, and all three tier rows carry a real -f value.
#
# Timing note: the rate-scan phase is a fixed 10s x 3 sub-phases regardless of
# --test-duration/--test-pps, so each prober run takes ~36s minimum. The whole
# script (selftest + 2 full prober runs) takes roughly ~2 minutes.
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

echo "=== PASSED ==="
