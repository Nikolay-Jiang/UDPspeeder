#ifndef TEST_MODE_H_
#define TEST_MODE_H_

#include "common.h"
#include <stdint.h>
#include <vector>

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

// Each of the three rate-scan sub-phases runs for this long.
const int TEST_RATE_SCAN_SEC = 10;

// Cap on probes in a single phase, enforced at parse time (misc.cpp).
//
// The responder blocks its whole ev loop inside responder_finalize_phase()
// while test_pick_tiers() sweeps ~1425 FEC candidates over an n-sample trace.
// Measured on this tree, all three tiers together: n=200k -> 0.31s,
// n=500k -> 0.78s, n=600k -> 0.78s (cost is trace-shape independent). The
// prober allows 5 x 2s for REQUEST_RESULT, so 500k leaves >12x margin, while
// the previously-legal 600k combination (--test-pps 20000 at the default
// --test-duration 30) used to cost ~13s and killed the run outright.
//
// There is no measurement value above this either: 500k samples resolve loss
// to 0.0002%, already 50x finer than the tightest tier target (0.01%).
const long long TEST_MAX_TOTAL_PROBES = 500000;

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

const uint32_t TEST_MAX_EXPECTED_N = 10000000;

struct trace_t {
    uint32_t              expected_n = 0;
    uint32_t              pps = 0;
    std::vector<uint8_t>  arrived;         // 0 = lost, 1 = arrived
    std::vector<uint32_t> recv_ts_rel_us;  // relative to first arrival; 0 if lost
    my_time_t             first_arrival_us = 0;

    void init(uint32_t n, uint32_t pps_);
    void record(uint32_t seq, my_time_t now_us);
};

// Re-base the pacer rather than paying out the backlog when it has fallen this
// far behind (load spike, vm pause). Releasing a backlog as a burst would
// manufacture the time-correlated loss that the -i recommendation is measured
// from -- the sender would be measuring its own scheduling, not the link.
const my_time_t PACER_SLIP_US = 50000;

// Token-bucket pacer, shared by the prober's blocking send loop and the
// responder's ev_timer. Deliberately clock-free: `now_us` is injected so the
// selftest can drive it with synthetic time.
struct pacer_t {
    double    pps = 0.0;
    double    credit = 0.0;
    my_time_t last_us = 0;

    void init(double pps_, my_time_t now_us);
    // How many packets to send right now. Advances internal state.
    int  tick(my_time_t now_us);
};

// Compares the ip only, ignoring the port. Needed because a symmetric nat
// assigns a different external source port per destination port, so probes to
// the data ports arrive from an address that address_t::operator== (a memcmp
// over the whole sockaddr, common.h:301) reports as a different peer.
bool test_addr_same_ip(address_t a, address_t b);

// Capability bits advertised by the responder in HELLO_ACK's accept path.
const u32_t TEST_CAP_REVERSE = 1u << 0;   // supports dir=1 (server -> client) phases

// PHASE_BEGIN payload: expected_n, pps, dir, spread -- four big-endian u32s.
// An old responder validates `pl_len < 12`, so appending the fourth word is
// backward compatible in both directions.
const int TEST_PHASE_BEGIN_PL_LEN = 16;

void test_phase_begin_pack(char *out, uint32_t expected_n, uint32_t pps,
                           uint32_t dir, uint32_t spread);
// 0 on success, -1 if shorter than 12 bytes. `spread` is set to 0 for a
// 12-byte (legacy) payload.
int  test_phase_begin_unpack(const uint8_t *pl, int pl_len, uint32_t *expected_n,
                             uint32_t *pps, uint32_t *dir, uint32_t *spread);

// HELLO_ACK accept path: reject code 0 followed by a capability word. The
// reject path keeps the old layout (code + reason string) precisely because an
// old prober prints everything from offset 4 as text -- putting caps there
// would surface as garbage in an operator-facing error message.
int   test_hello_ack_accept_pack(char *out, u32_t caps);
u32_t test_hello_ack_caps(const uint8_t *pl, int pl_len);

struct trace_stats_t {
    uint32_t n;
    uint32_t arrived_n;
    uint32_t lost_n;
    double   loss_rate;     // 0..1
    uint32_t run_p50;       // loss run length, packets
    uint32_t run_p95;
    uint32_t run_max;
    double   burst_p95_ms;  // run_p95 / pps * 1000
    double   resolution;    // 1.0 / n
};

trace_stats_t trace_analyze(const trace_t &t);

// Fraction of sliding windows of size (x+y) containing more than y losses.
// Returns -1.0 if the window does not fit the trace.
//
// Rebuilds an O(n) prefix-sum on every call. Fine for one-off use (and for the
// selftest, which calls it directly); the tier sweep must NOT call it in a loop
// -- use test_pick_tiers(), which builds the prefix once. See test_mode.cpp.
double test_residual(const trace_t &t, int x, int y);

const int TEST_I_CAP_MS = 50;
const int TEST_X_MAX    = 30;
const double TIER_THRIFTY_TARGET    = 0.01;    // 1%
const double TIER_BALANCED_TARGET   = 0.001;   // 0.1%
const double TIER_AGGRESSIVE_TARGET = 0.0001;  // 0.01%

struct tier_t {
    bool   feasible;
    int    x, y, i_ms;
    double residual;      // 0..1
    double overhead;      // y/x
    double actual_mbps;
    bool   extrapolated;  // target below sampling resolution
};

struct recommendation_t {
    trace_stats_t stats;
    tier_t thrifty, balanced, aggressive;
};

// 0 when losses are isolated (run_p95 <= 1); else ceil(D*(x+y)/y).
int test_derive_interval_ms(const trace_stats_t &st, int x, int y);

tier_t test_pick_tier(const trace_t &t, const trace_stats_t &st, double target);

// Picks all three tiers in a single candidate sweep sharing one prefix-sum.
// Equivalent to three test_pick_tier() calls but ~6x cheaper; the candidate
// enumeration order -- and therefore every tie-break outcome -- is identical.
void test_pick_tiers(const trace_t &t, const trace_stats_t &st,
                     tier_t *thrifty, tier_t *balanced, tier_t *aggressive);

recommendation_t test_evaluate(const trace_t &t, double app_mbps, int pkt_size);

enum rate_verdict_t { RATE_RANDOM = 0, RATE_POLICED, RATE_UNCERTAIN };

// Significant iff the rise exceeds 3x the combined binomial standard error.
rate_verdict_t test_rate_verdict(double p_half, uint32_t n_half,
                                 double p_nom, uint32_t n_nom,
                                 double p_double, uint32_t n_double);

struct test_report_t {
    // probe parameters
    int    duration_sec;
    int    pps;
    int    pkt_size;
    double probe_mbps;
    double app_mbps;
    char   peer[128];
    double rtt_ms;

    // rate scan
    bool           have_rate_scan;
    double         p_half, p_nom, p_dbl;
    uint32_t       n_half, n_nom, n_dbl;
    rate_verdict_t verdict;

    // per-direction recommendations (single port)
    bool             have_up, have_down;
    recommendation_t up, down;

    // Probes the local stack refused to send (ENOBUFS/EWOULDBLOCK etc.),
    // summed over every phase. These are counted as lost by the responder but
    // are local backpressure, not link loss, so the report flags them rather
    // than silently adjusting the loss figure.
    uint32_t send_fail_n;
    uint32_t send_total_n;

    // port-range comparison
    bool   have_spread;
    double spread_loss_up;   // loss rate on N ports, up direction
    int    spread_ports;
};

void test_render_report(const test_report_t &r);

// True when a direction saw zero loss. Consulted by both the recommendation
// table and the suggested-command-line summary so the two cannot disagree.
bool test_link_is_clean(const recommendation_t &rec);

// Display width in terminal columns (CJK glyphs count as 2), used for the
// report's column padding.
int test_display_width(const char *s);

// ---- entry points ----
int test_mode_prober_loop();
int test_mode_responder_loop();
int test_mode_selftest();  // 0 = all checks passed

#endif /* TEST_MODE_H_ */
