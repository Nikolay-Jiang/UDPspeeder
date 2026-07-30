#ifndef TEST_MODE_H_
#define TEST_MODE_H_

#include "common.h"
#include <stdint.h>

// ---- CLI-configured globals (defined in misc.cpp) ----
extern int    test_mode;          // 0/1
extern int    test_duration_sec;  // default 30, max 600
extern int    test_pps;           // default 200, max 20000
extern int    test_pkt_size;      // default 1200, max 1400
extern double test_app_mbps;      // 0 => derive from probe rate

const int TEST_DURATION_MAX = 600;
const int TEST_PPS_MAX      = 20000;
const int TEST_PKT_SIZE_MAX = 1400;
const int TEST_PKT_SIZE_MIN = 64;

// ---- wire protocol ----
enum test_msg_t {
    TEST_HELLO = 1,
    TEST_HELLO_ACK,
    TEST_PHASE_BEGIN,
    TEST_PHASE_ACK,
    TEST_PROBE,
    TEST_PHASE_END,
    TEST_REQUEST_RESULT,
    TEST_RESULT,
    TEST_BYE
};

const int TEST_HDR_LEN = 16;
const int TEST_MAC_LEN = 8;
const int TEST_BUF_MAX = 1500;

struct test_hdr_t {
    uint8_t  version;
    uint8_t  msg_type;
    uint8_t  phase;
    uint8_t  reserved;
    uint32_t seq;
    uint64_t send_ts_us;
};

// pad_to: desired total packet size INCLUDING mac; 0 = no padding.
int test_encode(int msg_type, int phase, uint32_t seq,
                const void *payload, int payload_len,
                char *out, int out_cap, int pad_to);

int test_decode(char *buf, int len, test_hdr_t *hdr_out,
                uint8_t **payload_out, int *payload_len_out);

// ---- entry points ----
int test_mode_prober_loop();
int test_mode_responder_loop();
int test_mode_selftest();  // 0 = all checks passed

#endif /* TEST_MODE_H_ */
