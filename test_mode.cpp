#include "test_mode.h"
#include "log.h"
#include "packet.h"  // key_string
#include "siphash.h"
#include <algorithm>
#include <math.h>
#include <stdio.h>
#include <string.h>

// ---------------- wire protocol codec ----------------
static void test_mac_key(uint8_t k[16]) {
    memset(k, 0, 16);
    int klen = (int)strlen(key_string);
    if (klen > 16) klen = 16;
    memcpy(k, key_string, klen);
}

static void test_mac_compute(const char *body, int body_len, char out[TEST_MAC_LEN]) {
    uint8_t k[16];
    test_mac_key(k);
    uint64_t h = siphash24(body, (size_t)body_len, k);
    memcpy(out, &h, TEST_MAC_LEN);
}

int test_encode(int msg_type, int phase, uint32_t seq,
                const void *payload, int payload_len,
                char *out, int out_cap, int pad_to) {
    if (payload_len < 0) return -1;
    int body = TEST_HDR_LEN + payload_len;
    int total = body + TEST_MAC_LEN;
    if (pad_to > total) {
        body = pad_to - TEST_MAC_LEN;
        total = pad_to;
    }
    if (total > out_cap || total > TEST_BUF_MAX) return -1;

    out[0] = 1;                    // version
    out[1] = (char)(uint8_t)msg_type;
    out[2] = (char)(uint8_t)phase;
    out[3] = 0;                    // reserved
    write_u32(out + 4, seq);
    write_u64(out + 8, get_current_time_us());
    if (payload_len > 0) memcpy(out + TEST_HDR_LEN, payload, payload_len);
    int pad = body - TEST_HDR_LEN - payload_len;
    if (pad > 0) memset(out + TEST_HDR_LEN + payload_len, 0, pad);

    test_mac_compute(out, body, out + body);
    return total;
}

int test_decode(char *buf, int len, test_hdr_t *hdr_out,
                uint8_t **payload_out, int *payload_len_out) {
    if (len < TEST_HDR_LEN + TEST_MAC_LEN || len > TEST_BUF_MAX) return -1;
    int body_len = len - TEST_MAC_LEN;

    char expected[TEST_MAC_LEN];
    test_mac_compute(buf, body_len, expected);
    if (memcmp(expected, buf + body_len, TEST_MAC_LEN) != 0) return -1;

    if ((uint8_t)buf[0] != 1) return -1;   // version
    if ((uint8_t)buf[3] != 0) return -1;   // reserved

    hdr_out->version    = (uint8_t)buf[0];
    hdr_out->msg_type   = (uint8_t)buf[1];
    hdr_out->phase      = (uint8_t)buf[2];
    hdr_out->reserved   = 0;
    hdr_out->seq        = read_u32(buf + 4);
    hdr_out->send_ts_us = read_uu64(buf + 8);

    *payload_out     = (uint8_t *)(buf + TEST_HDR_LEN);
    *payload_len_out = body_len - TEST_HDR_LEN;
    return (int)hdr_out->msg_type;
}

// ---------------- loss trace + statistics ----------------
void trace_t::init(uint32_t n, uint32_t pps_) {
    if (n > TEST_MAX_EXPECTED_N) {
        mylog(log_fatal, "trace size %u exceeds cap %u\n", n, TEST_MAX_EXPECTED_N);
        myexit(-1);
    }
    expected_n = n;
    pps = pps_;
    arrived.assign(n, 0);
    recv_ts_rel_us.assign(n, 0);
    first_arrival_us = 0;
}

void trace_t::record(uint32_t seq, my_time_t now_us) {
    if (seq >= expected_n) return;   // out of range, ignore
    if (arrived[seq]) return;        // duplicate, ignore
    if (first_arrival_us == 0) first_arrival_us = now_us;
    arrived[seq] = 1;
    my_time_t rel = (now_us >= first_arrival_us) ? (now_us - first_arrival_us) : 0;
    if (rel > 0xffffffffULL) rel = 0xffffffffULL;
    recv_ts_rel_us[seq] = (uint32_t)rel;
}

static uint32_t percentile_u32(std::vector<uint32_t> &v, double q) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    size_t idx = (size_t)(q * (double)(v.size() - 1) + 0.5);
    if (idx >= v.size()) idx = v.size() - 1;
    return v[idx];
}

trace_stats_t trace_analyze(const trace_t &t) {
    trace_stats_t st;
    memset(&st, 0, sizeof(st));
    st.n = t.expected_n;
    if (st.n == 0) return st;

    std::vector<uint32_t> runs;
    uint32_t cur = 0;
    for (uint32_t s = 0; s < t.expected_n; s++) {
        if (t.arrived[s]) {
            st.arrived_n++;
            if (cur > 0) { runs.push_back(cur); cur = 0; }
        } else {
            st.lost_n++;
            cur++;
        }
    }
    if (cur > 0) runs.push_back(cur);

    st.loss_rate  = (double)st.lost_n / (double)st.n;
    st.resolution = 1.0 / (double)st.n;

    if (!runs.empty()) {
        st.run_max = *std::max_element(runs.begin(), runs.end());
        std::vector<uint32_t> tmp = runs;
        st.run_p50 = percentile_u32(tmp, 0.50);
        tmp = runs;
        st.run_p95 = percentile_u32(tmp, 0.95);
    }
    if (t.pps > 0) {
        st.burst_p95_ms = (double)st.run_p95 / (double)t.pps * 1000.0;
    }
    return st;
}

double test_residual(const trace_t &t, int x, int y) {
    if (x < 1 || y < 0) return -1.0;
    int w = x + y;
    if (w <= 0 || (uint32_t)w > t.expected_n) return -1.0;

    // prefix[k] = number of losses in [0, k)
    std::vector<uint32_t> prefix(t.expected_n + 1, 0);
    for (uint32_t s = 0; s < t.expected_n; s++) {
        prefix[s + 1] = prefix[s] + (t.arrived[s] ? 0u : 1u);
    }

    uint32_t windows = t.expected_n - (uint32_t)w + 1;
    uint32_t failed = 0;
    for (uint32_t s = 0; s < windows; s++) {
        uint32_t losses = prefix[s + w] - prefix[s];
        if ((int)losses > y) failed++;
    }
    return (double)failed / (double)windows;
}

// ---------------- -i derivation and three-tier selection ----------------
int test_derive_interval_ms(const trace_stats_t &st, int x, int y) {
    if (st.run_p95 <= 1) return 0;          // losses are isolated; scattering buys nothing
    if (y <= 0) return 0;                    // no redundancy to protect
    if (st.burst_p95_ms <= 0.0) return 0;
    double need = st.burst_p95_ms * (double)(x + y) / (double)y;
    return (int)ceil(need);
}

tier_t test_pick_tier(const trace_t &t, const trace_stats_t &st, double target) {
    tier_t best;
    memset(&best, 0, sizeof(best));
    best.feasible = false;

    for (int x = 1; x <= TEST_X_MAX; x++) {
        int y_max = 3 * x;
        if (y_max > 254 - x) y_max = 254 - x;
        for (int y = 0; y <= y_max; y++) {
            if ((uint32_t)(x + y) > t.expected_n) continue;
            double r = test_residual(t, x, y);
            if (r < 0.0 || r > target) continue;

            // Scattering requirement; if it exceeds the cap, prefer more y
            // (i.e. reject this candidate) per spec section 6.4.
            int i_ms = test_derive_interval_ms(st, x, y);
            if (i_ms > TEST_I_CAP_MS) continue;

            double overhead = (double)y / (double)x;
            bool better = !best.feasible || overhead < best.overhead - 1e-12;
            if (!better && fabs(overhead - best.overhead) <= 1e-12) {
                if (i_ms < best.i_ms) better = true;
                else if (i_ms == best.i_ms && x > best.x) better = true;
            }
            if (better) {
                best.feasible = true;
                best.x = x;
                best.y = y;
                best.i_ms = i_ms;
                best.residual = r;
                best.overhead = overhead;
            }
        }
    }
    best.extrapolated = (target < st.resolution);
    return best;
}

recommendation_t test_evaluate(const trace_t &t, double app_mbps, int pkt_size) {
    recommendation_t rec;
    rec.stats = trace_analyze(t);

    rec.thrifty    = test_pick_tier(t, rec.stats, TIER_THRIFTY_TARGET);
    rec.balanced   = test_pick_tier(t, rec.stats, TIER_BALANCED_TARGET);
    rec.aggressive = test_pick_tier(t, rec.stats, TIER_AGGRESSIVE_TARGET);

    double hdr_factor = 1.0;
    if (pkt_size > 0) hdr_factor = 1.0 + 16.0 / (double)pkt_size;

    tier_t *tiers[3] = {&rec.thrifty, &rec.balanced, &rec.aggressive};
    for (int k = 0; k < 3; k++) {
        if (tiers[k]->feasible) {
            tiers[k]->actual_mbps = app_mbps * (1.0 + tiers[k]->overhead) * hdr_factor;
        } else {
            tiers[k]->actual_mbps = 0.0;
        }
    }
    return rec;
}

// ---------------- selftest harness ----------------
static int g_checks = 0;
static int g_failures = 0;

#define TCHECK(cond, ...)                            \
    do {                                             \
        g_checks++;                                   \
        if (!(cond)) {                               \
            g_failures++;                             \
            printf("FAIL [%s:%d]: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                     \
            printf("\n");                            \
        }                                            \
    } while (0)

// placeholder loops, implemented in later tasks
int test_mode_prober_loop() {
    mylog(log_fatal, "test-mode prober not implemented yet\n");
    myexit(-1);
    return 0;
}

int test_mode_responder_loop() {
    mylog(log_fatal, "test-mode responder not implemented yet\n");
    myexit(-1);
    return 0;
}

int test_mode_selftest() {
    g_checks = 0;
    g_failures = 0;

    // Harness self-check. Every later task's assertions are only as trustworthy
    // as TCHECK's ability to actually FAIL, so exercise the failure path once
    // against scratch counters, then restore them.
    {
        int saved_checks = g_checks;
        int saved_failures = g_failures;
        g_checks = 0;
        g_failures = 0;
        printf("---- selftest: one deliberate FAIL line follows, it is expected ----\n");
        TCHECK(1 == 0, "deliberate failure proving the harness counts failures");
        bool harness_ok = (g_checks == 1 && g_failures == 1);
        g_checks = saved_checks;
        g_failures = saved_failures;
        printf("---- selftest: end of deliberate failure ----\n");
        TCHECK(harness_ok, "TCHECK must count a failing check exactly once");
    }

    // ---- codec ----
    {
        strcpy(key_string, "selftest_key");
        char buf[TEST_BUF_MAX];
        const char pl[4] = {'a', 'b', 'c', 'd'};

        my_time_t ts_before = get_current_time_us();
        int n = test_encode(TEST_PROBE, 3, 12345, pl, 4, buf, sizeof(buf), 1200);
        my_time_t ts_after = get_current_time_us();
        TCHECK(n == 1200, "padded encode must return 1200, got %d", n);

        test_hdr_t h;
        uint8_t *p = 0;
        int plen = 0;
        int mt = test_decode(buf, n, &h, &p, &plen);
        TCHECK(mt == TEST_PROBE, "decode msg_type must be TEST_PROBE, got %d", mt);
        TCHECK(h.phase == 3, "decode phase must be 3, got %d", (int)h.phase);
        TCHECK(h.seq == 12345, "decode seq must be 12345, got %u", h.seq);
        TCHECK(plen == 1200 - TEST_HDR_LEN - TEST_MAC_LEN,
               "payload len must include padding, got %d", plen);
        TCHECK(p != 0 && memcmp(p, pl, 4) == 0, "payload bytes must round-trip");

        // The only coverage of write_u64/read_uu64 in the tree. Epoch microseconds
        // exceed 2^32, so this genuinely exercises the high/low word split.
        TCHECK(h.send_ts_us >= ts_before && h.send_ts_us <= ts_after,
               "send_ts_us must round-trip: got %llu, expected within [%llu, %llu]",
               (unsigned long long)h.send_ts_us,
               (unsigned long long)ts_before, (unsigned long long)ts_after);
        TCHECK(h.send_ts_us > 0xffffffffULL,
               "epoch microseconds must exceed 2^32 so the high word is actually exercised");

        // unpadded control message
        int n2 = test_encode(TEST_HELLO, 0, 0, pl, 4, buf, sizeof(buf), 0);
        TCHECK(n2 == TEST_HDR_LEN + 4 + TEST_MAC_LEN,
               "unpadded encode must be hdr+payload+mac, got %d", n2);

        // MAC must reject a flipped byte
        buf[TEST_HDR_LEN] ^= 0xff;
        TCHECK(test_decode(buf, n2, &h, &p, &plen) == -1, "flipped byte must fail MAC");

        // MAC must reject a wrong key
        int n3 = test_encode(TEST_HELLO, 0, 0, pl, 4, buf, sizeof(buf), 0);
        strcpy(key_string, "different_key");
        TCHECK(test_decode(buf, n3, &h, &p, &plen) == -1, "wrong key must fail MAC");
        strcpy(key_string, "selftest_key");

        // too-short packet must be rejected, not read out of bounds
        TCHECK(test_decode(buf, TEST_HDR_LEN + TEST_MAC_LEN - 1, &h, &p, &plen) == -1,
               "short packet must be rejected");

        // over-capacity request must be refused
        TCHECK(test_encode(TEST_PROBE, 0, 0, pl, 4, buf, 32, 1200) == -1,
               "encode must refuse when out_cap too small");
    }

    // ---- trace + stats ----
    {
        trace_t t;
        t.init(1000, 200);
        TCHECK(t.arrived.size() == 1000, "init must size arrived to n");

        // all arrive
        for (uint32_t s = 0; s < 1000; s++) t.record(s, 1000000ULL + s * 5000ULL);
        trace_stats_t st = trace_analyze(t);
        TCHECK(st.arrived_n == 1000, "all-arrive: arrived_n must be 1000, got %u", st.arrived_n);
        TCHECK(st.lost_n == 0, "all-arrive: lost_n must be 0, got %u", st.lost_n);
        TCHECK(st.loss_rate == 0.0, "all-arrive: loss_rate must be 0");
        TCHECK(st.run_max == 0, "all-arrive: run_max must be 0, got %u", st.run_max);

        // duplicate must not double-count
        t.record(0, 9999999ULL);
        st = trace_analyze(t);
        TCHECK(st.arrived_n == 1000, "duplicate must be ignored, got %u", st.arrived_n);

        // out-of-order must not count as loss
        trace_t t2;
        t2.init(4, 200);
        t2.record(3, 1000);
        t2.record(1, 2000);
        t2.record(0, 3000);
        t2.record(2, 4000);
        trace_stats_t st2 = trace_analyze(t2);
        TCHECK(st2.lost_n == 0, "out-of-order must not count as loss, got %u", st2.lost_n);

        // fixed burst pattern: every 100th block loses exactly 5 in a row
        trace_t t3;
        t3.init(1000, 200);
        for (uint32_t s = 0; s < 1000; s++) {
            bool lost = (s % 100) < 5;
            if (!lost) t3.record(s, 1000000ULL + s * 5000ULL);
        }
        trace_stats_t st3 = trace_analyze(t3);
        TCHECK(st3.lost_n == 50, "burst trace must lose 50, got %u", st3.lost_n);
        TCHECK(st3.run_max == 5, "burst run_max must be 5, got %u", st3.run_max);
        TCHECK(st3.run_p95 == 5, "burst run_p95 must be 5, got %u", st3.run_p95);
        // 5 packets at 200pps == 25ms
        TCHECK(fabs(st3.burst_p95_ms - 25.0) < 0.001,
               "burst_p95_ms must be 25.0, got %f", st3.burst_p95_ms);
        TCHECK(fabs(st3.resolution - 0.001) < 1e-9,
               "resolution must be 1/1000, got %f", st3.resolution);

        // isolated losses -> run_p95 == 1
        trace_t t4;
        t4.init(1000, 200);
        for (uint32_t s = 0; s < 1000; s++) {
            if (s % 50 != 0) t4.record(s, 1000000ULL + s * 5000ULL);
        }
        trace_stats_t st4 = trace_analyze(t4);
        TCHECK(st4.run_max == 1, "isolated losses: run_max must be 1, got %u", st4.run_max);

        // Heterogeneous run lengths: runs are 1,2,3,4 packets long, so the
        // nearest-rank percentile formula is actually distinguishable from
        // "return any element". Layout below is explicit rather than modular
        // so the expected percentiles can be read straight off it.
        // seq:      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19
        // lost:     .  X  .  X  X  .  X  X  X  .  X  X  X  X  .  .  .  .  .  .
        // runs:        1     2        3           4
        {
            trace_t th;
            th.init(20, 200);
            const bool lost[20] = {false, true,  false, true,  true,
                                   false, true,  true,  true,  false,
                                   true,  true,  true,  true,  false,
                                   false, false, false, false, false};
            for (uint32_t s = 0; s < 20; s++) {
                if (!lost[s]) th.record(s, 1000000ULL + s * 5000ULL);
            }
            trace_stats_t sh = trace_analyze(th);
            TCHECK(sh.lost_n == 10, "heterogeneous: lost_n must be 10, got %u", sh.lost_n);
            TCHECK(sh.run_max == 4, "heterogeneous: run_max must be 4, got %u", sh.run_max);
            // sorted run lengths [1,2,3,4]: p50 -> idx = 0.50*3+0.5 = 2 -> 3
            TCHECK(sh.run_p50 == 3, "heterogeneous: run_p50 must be 3, got %u", sh.run_p50);
            // p95 -> idx = 0.95*3+0.5 = 3.35 -> 3 -> 4
            TCHECK(sh.run_p95 == 4, "heterogeneous: run_p95 must be 4, got %u", sh.run_p95);
            // 4 packets at 200pps == 20ms
            TCHECK(fabs(sh.burst_p95_ms - 20.0) < 0.001,
                   "heterogeneous: burst_p95_ms must be 20.0, got %f", sh.burst_p95_ms);
        }

        // Single run: size-1 == 0, so the percentile index must not go out of
        // bounds and both percentiles must land on the only run.
        {
            trace_t ts;
            ts.init(10, 200);
            for (uint32_t s = 0; s < 10; s++) {
                if (s < 3 || s > 5) ts.record(s, 1000000ULL + s * 5000ULL);
            }
            trace_stats_t ss = trace_analyze(ts);
            TCHECK(ss.lost_n == 3, "single-run: lost_n must be 3, got %u", ss.lost_n);
            TCHECK(ss.run_p50 == 3 && ss.run_p95 == 3 && ss.run_max == 3,
                   "single-run: all run stats must be 3, got p50=%u p95=%u max=%u",
                   ss.run_p50, ss.run_p95, ss.run_max);
        }

        // A loss run that reaches the final sequence number must still be
        // counted: a loop that only closes runs on seeing an arrival drops it.
        {
            trace_t te;
            te.init(10, 200);
            for (uint32_t s = 0; s < 5; s++) te.record(s, 1000000ULL + s * 5000ULL);
            trace_stats_t se = trace_analyze(te);
            TCHECK(se.lost_n == 5, "trailing run: lost_n must be 5, got %u", se.lost_n);
            TCHECK(se.run_max == 5,
                   "trailing run reaching the last seq must be counted, got run_max=%u",
                   se.run_max);
            TCHECK(se.run_p50 == 5 && se.run_p95 == 5,
                   "trailing run: percentiles must be 5, got p50=%u p95=%u",
                   se.run_p50, se.run_p95);
        }
    }

    // ---- residual ----
    {
        // zero loss -> residual 0 for any candidate
        trace_t t;
        t.init(1000, 200);
        for (uint32_t s = 0; s < 1000; s++) t.record(s, 1000000ULL + s * 5000ULL);
        TCHECK(test_residual(t, 20, 6) == 0.0, "zero-loss trace must give residual 0");

        // total loss -> every window fails
        trace_t t2;
        t2.init(1000, 200);
        TCHECK(fabs(test_residual(t2, 20, 6) - 1.0) < 1e-9,
               "total-loss trace must give residual 1.0");

        // window larger than trace -> -1
        trace_t t3;
        t3.init(10, 200);
        TCHECK(test_residual(t3, 20, 6) == -1.0, "oversized window must return -1");

        // exact burst pattern: 5 lost every 100.
        // window 26 (=20+6) with y=6 tolerates 6 losses; max losses in any
        // 26-wide window here is 5, so no window may fail.
        trace_t t4;
        t4.init(1000, 200);
        for (uint32_t s = 0; s < 1000; s++) {
            if ((s % 100) >= 5) t4.record(s, 1000000ULL + s * 5000ULL);
        }
        TCHECK(test_residual(t4, 20, 6) == 0.0,
               "burst of 5 must be fully covered by y=6, got %f", test_residual(t4, 20, 6));
        // y=4 cannot cover a burst of 5 -> some windows must fail
        TCHECK(test_residual(t4, 20, 4) > 0.0, "y=4 must fail against a burst of 5");

        // determinism
        TCHECK(test_residual(t4, 20, 4) == test_residual(t4, 20, 4),
               "residual must be deterministic");
    }

    // ---- interval derivation ----
    {
        trace_stats_t st;
        memset(&st, 0, sizeof(st));

        // isolated losses -> no scattering
        st.run_p95 = 1;
        st.burst_p95_ms = 5.0;
        TCHECK(test_derive_interval_ms(st, 20, 6) == 0,
               "isolated losses must give -i 0, got %d", test_derive_interval_ms(st, 20, 6));

        // y == 0 -> scattering cannot help
        st.run_p95 = 3;
        st.burst_p95_ms = 10.0;
        TCHECK(test_derive_interval_ms(st, 20, 0) == 0, "y=0 must give -i 0");

        // D=10ms, x=20, y=6 -> 10*26/6 = 43.33 -> 44
        TCHECK(test_derive_interval_ms(st, 20, 6) == 44,
               "D=10 x=20 y=6 must give 44, got %d", test_derive_interval_ms(st, 20, 6));
        // D=10ms, x=20, y=3 -> 10*23/3 = 76.67 -> 77 (over the 50ms cap)
        TCHECK(test_derive_interval_ms(st, 20, 3) == 77,
               "D=10 x=20 y=3 must give 77, got %d", test_derive_interval_ms(st, 20, 3));
    }

    // ---- tier selection ----
    {
        // isolated 2% loss, no bursts
        trace_t t;
        t.init(2000, 200);
        for (uint32_t s = 0; s < 2000; s++) {
            if (s % 50 != 0) t.record(s, 1000000ULL + s * 5000ULL);
        }
        trace_stats_t st = trace_analyze(t);
        tier_t bal = test_pick_tier(t, st, TIER_BALANCED_TARGET);
        TCHECK(bal.feasible, "balanced tier must be feasible on isolated 2%% loss");
        TCHECK(bal.residual <= TIER_BALANCED_TARGET,
               "balanced residual %f must meet target", bal.residual);
        TCHECK(bal.y >= 1, "balanced tier must use redundancy, got y=%d", bal.y);
        TCHECK(bal.i_ms == 0, "isolated losses must give -i 0, got %d", bal.i_ms);

        // bursts of 5 -> chosen y must cover the burst
        trace_t t2;
        t2.init(2000, 200);
        for (uint32_t s = 0; s < 2000; s++) {
            if ((s % 100) >= 5) t2.record(s, 1000000ULL + s * 5000ULL);
        }
        trace_stats_t st2 = trace_analyze(t2);
        tier_t bal2 = test_pick_tier(t2, st2, TIER_BALANCED_TARGET);
        TCHECK(bal2.feasible, "balanced tier must be feasible on burst-5 trace");
        TCHECK(bal2.y >= 5, "burst of 5 needs y>=5, got y=%d", bal2.y);
        TCHECK(bal2.i_ms > 0 && bal2.i_ms <= TEST_I_CAP_MS,
               "burst trace must give 0 < -i <= cap, got %d", bal2.i_ms);

        // Pin the tie-break. ~26 candidates tie here at overhead 1.0 / i_ms 50
        // (x == y, 5..30); the rule "larger x wins on equal overhead" must pick 30.
        // A reversed tie-break would satisfy every other assertion in this block.
        TCHECK(bal2.x == 30 && bal2.y == 30,
               "tie-break must pick the largest x on equal overhead: expected x=30 y=30, got x=%d y=%d",
               bal2.x, bal2.y);
        TCHECK(bal2.i_ms == 50,
               "burst-5 fixture: i_ms must be exactly the 50ms cap, got %d", bal2.i_ms);
        TCHECK(fabs(bal2.overhead - 1.0) < 1e-9,
               "burst-5 fixture: minimum feasible overhead must be 1.0, got %f", bal2.overhead);

        // total loss -> infeasible, no fabricated numbers
        trace_t t3;
        t3.init(2000, 200);
        trace_stats_t st3 = trace_analyze(t3);
        tier_t bad = test_pick_tier(t3, st3, TIER_BALANCED_TARGET);
        TCHECK(!bad.feasible, "total-loss trace must report infeasible");

        // bandwidth conversion: 20:6 on 10 Mbps payload, 1200B packets
        // 10 * 1.30 * (1 + 16/1200) = 13.173...
        recommendation_t rec = test_evaluate(t, 10.0, 1200);
        TCHECK(rec.balanced.feasible, "evaluate must produce a feasible balanced tier");
        double expect = 10.0 * (1.0 + (double)rec.balanced.y / rec.balanced.x)
                             * (1.0 + 16.0 / 1200.0);
        TCHECK(fabs(rec.balanced.actual_mbps - expect) < 0.01,
               "actual_mbps %f must match %f", rec.balanced.actual_mbps, expect);

        // extrapolation flag. n=2000 -> resolution 0.0005.
        // aggressive target 0.0001 < 0.0005  -> must be flagged
        // balanced   target 0.0010 > 0.0005  -> must NOT be flagged
        TCHECK(rec.aggressive.extrapolated,
               "aggressive target 0.01%% is below the 0.05%% resolution of a 2000-sample "
               "trace, so it must be flagged extrapolated");
        TCHECK(!rec.balanced.extrapolated,
               "balanced target 0.1%% is above the 0.05%% resolution, so it must not be "
               "flagged extrapolated");

        // determinism
        recommendation_t rec2 = test_evaluate(t, 10.0, 1200);
        TCHECK(rec.balanced.x == rec2.balanced.x && rec.balanced.y == rec2.balanced.y
                   && rec.balanced.i_ms == rec2.balanced.i_ms,
               "evaluate must be deterministic");
    }

    printf("test_mode selftest: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
