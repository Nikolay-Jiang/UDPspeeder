#include "test_mode.h"
#include "log.h"
#include "packet.h"  // key_string
#include "siphash.h"
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

        int n = test_encode(TEST_PROBE, 3, 12345, pl, 4, buf, sizeof(buf), 1200);
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

    printf("test_mode selftest: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
