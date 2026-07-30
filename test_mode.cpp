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

    printf("test_mode selftest: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
