// Network event loops for --test-mode: responder (this task) and prober
// (Task 9). Pure protocol/statistics logic stays in test_mode.cpp; this file
// only wires that logic to sockets and a libev loop.
#include "test_mode.h"
#include "log.h"
#include "misc.h"
#include "port_range_manager.h"
#include <vector>

// ---------------- TEST_RESULT wire payload ----------------
// 40 bytes, little-endian via write_u32. File-static: Task 9's prober packs
// nothing but unpacks this same layout with read_u32 in this same file.
static const int TEST_RESULT_WIRE_LEN = 40;

static void result_wire_pack(char *out, const trace_stats_t &st, const tier_t &tr) {
    write_u32(out + 0,  st.n);
    write_u32(out + 4,  st.arrived_n);
    write_u32(out + 8,  st.lost_n);
    write_u32(out + 12, st.run_p50);
    write_u32(out + 16, st.run_p95);
    write_u32(out + 20, st.run_max);
    write_u32(out + 24, tr.feasible ? (u32_t)tr.x : 0u);
    write_u32(out + 28, tr.feasible ? (u32_t)tr.y : 0u);
    write_u32(out + 32, tr.feasible ? (u32_t)tr.i_ms : 0u);
    write_u32(out + 36, tr.feasible ? (u32_t)(tr.residual * 1e6) : 0u);
}

// ---------------- responder session state ----------------
struct responder_state_t {
    bool               active = false;
    address_t          peer;              // source-pinned to the HELLO sender
    int                phase = 0;
    trace_t            trace;
    trace_stats_t      stats;
    tier_t             balanced;
    bool               phase_open = false;
    my_time_t          last_probe_us = 0;
    uint32_t           cur_pps = 0;
    my_time_t          last_mac_warn_ms = 0;
};

static responder_state_t g_resp;
static std::vector<int> g_resp_fds;

static void responder_finalize_phase() {
    if (!g_resp.phase_open) return;
    g_resp.phase_open = false;
    g_resp.stats = trace_analyze(g_resp.trace);
    g_resp.balanced = test_pick_tier(g_resp.trace, g_resp.stats, TIER_BALANCED_TARGET);
    mylog(log_info, "test: phase %d finalized, loss %.4f%% (%u/%u)\n",
          g_resp.phase, g_resp.stats.loss_rate * 100.0,
          g_resp.stats.lost_n, g_resp.stats.n);
}

static void responder_send(int fd, const address_t &to, int msg_type, int phase,
                           const void *payload, int payload_len) {
    char out[TEST_BUF_MAX];
    int n = test_encode(msg_type, phase, 0, payload, payload_len, out, sizeof(out), 0);
    if (n < 0) return;
    address_t dst = to;
    sendto(fd, out, n, 0, (struct sockaddr *)&dst.inner, dst.get_len());
}

static void responder_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    assert(!(revents & EV_ERROR));
    (void)loop;

    char buf[TEST_BUF_MAX];
    address_t::storage_t src_stor;
    socklen_t src_len = sizeof(src_stor);
    int len = recvfrom(w->fd, buf, sizeof(buf), 0, (struct sockaddr *)&src_stor, &src_len);
    if (len <= 0) return;

    address_t src;
    src.from_sockaddr((struct sockaddr *)&src_stor, src_len);

    test_hdr_t h;
    uint8_t *pl = 0;
    int pl_len = 0;
    int mt = test_decode(buf, len, &h, &pl, &pl_len);
    if (mt < 0) {
        // Rate-limited so a wrong key is visible to the operator: to the prober,
        // a bad key and a blocked port look identical.
        my_time_t now = get_current_time();
        if (now - g_resp.last_mac_warn_ms > 1000) {
            g_resp.last_mac_warn_ms = now;
            mylog(log_info, "test: dropped packet from %s: mac/format check failed "
                            "(wrong -k on the other side?)\n", src.get_str());
        }
        return;
    }

    // Source pinning: once a session exists, only its peer may drive it.
    if (g_resp.active && mt != TEST_HELLO && !(src == g_resp.peer)) {
        mylog(log_debug, "test: ignoring %d from non-session source %s\n", mt, src.get_str());
        return;
    }

    if (mt == TEST_HELLO) {
        if (g_resp.active && !(src == g_resp.peer)) {
            mylog(log_info, "test: rejecting concurrent session from %s\n", src.get_str());
            return;
        }
        g_resp.active = true;
        g_resp.peer = src;
        g_resp.phase_open = false;
        mylog(log_info, "test: session from %s\n", src.get_str());
        responder_send(w->fd, src, TEST_HELLO_ACK, 0, NULL, 0);

    } else if (mt == TEST_PHASE_BEGIN) {
        if (pl_len < 12) return;
        uint32_t expected_n = read_u32((char *)pl + 0);
        uint32_t pps        = read_u32((char *)pl + 4);
        uint32_t dir        = read_u32((char *)pl + 8);  // 0 = prober->responder
        if (expected_n == 0 || expected_n > TEST_MAX_EXPECTED_N) {
            mylog(log_warn, "test: refusing expected_n=%u (cap %u)\n",
                  expected_n, TEST_MAX_EXPECTED_N);
            return;
        }
        if (dir != 0) {
            // Reverse-direction phases are driven by Task 9's prober asking us to
            // send; not supported until then. ACK so the prober can proceed.
            responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);
            return;
        }
        g_resp.phase = h.phase;
        g_resp.cur_pps = pps;
        g_resp.trace.init(expected_n, pps);
        g_resp.phase_open = true;
        g_resp.last_probe_us = get_current_time_us();
        mylog(log_info, "test: phase %d begin, expect %u probes at %u pps\n",
              h.phase, expected_n, pps);
        responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);

    } else if (mt == TEST_PROBE) {
        if (!g_resp.phase_open) return;
        g_resp.last_probe_us = get_current_time_us();
        g_resp.trace.record(h.seq, g_resp.last_probe_us);

    } else if (mt == TEST_PHASE_END) {
        responder_finalize_phase();

    } else if (mt == TEST_REQUEST_RESULT) {
        responder_finalize_phase();
        char wire[TEST_RESULT_WIRE_LEN];
        result_wire_pack(wire, g_resp.stats, g_resp.balanced);
        responder_send(w->fd, src, TEST_RESULT, g_resp.phase, wire, sizeof(wire));

    } else if (mt == TEST_BYE) {
        mylog(log_info, "test: session closed by %s\n", src.get_str());
        g_resp.active = false;
        g_resp.phase_open = false;
    }
}

// Fallback: if all three PHASE_END copies were lost, finalize on silence.
static void responder_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    assert(!(revents & EV_ERROR));
    (void)loop; (void)w;
    if (!g_resp.phase_open) return;
    my_time_t idle_us = get_current_time_us() - g_resp.last_probe_us;
    my_time_t limit_us = 2000000ULL;   // 2s floor
    if (g_resp.cur_pps > 0) {
        my_time_t five_gaps = (my_time_t)(5.0 / (double)g_resp.cur_pps * 1000000.0);
        if (five_gaps > limit_us) limit_us = five_gaps;
    }
    if (idle_us > limit_us) {
        mylog(log_info, "test: phase %d finalized by idle timeout\n", g_resp.phase);
        responder_finalize_phase();
    }
}

int test_mode_responder_loop() {
    struct ev_loop *loop = ev_default_loop(0);
    assert(loop != NULL);

    std::vector<address_t> binds;
    binds.push_back(local_addr);
    if (port_range_mgr.count() > 0) {
        for (int k = 0; k < port_range_mgr.count(); k++) {
            address_t a = local_addr;
            a.set_port(port_range_mgr.ports[k]);
            binds.push_back(a);
        }
    }

    std::vector<ev_io *> watchers;
    g_resp_fds.clear();
    for (size_t k = 0; k < binds.size(); k++) {
        int fd;
        if (new_listen_socket2(fd, binds[k]) != 0) {
            mylog(log_fatal, "test: failed to bind %s\n", binds[k].get_str());
            myexit(-1);
        }
        g_resp_fds.push_back(fd);
        ev_io *w = new ev_io;
        ev_io_init(w, responder_cb, fd, EV_READ);
        ev_io_start(loop, w);
        watchers.push_back(w);
        mylog(log_info, "test: responder listening at %s\n", binds[k].get_str());
    }

    ev_timer t;
    ev_init(&t, responder_timer_cb);
    ev_timer_set(&t, 0.5, 0.5);
    ev_timer_start(loop, &t);

    mylog(log_info, "test: responder ready (%d socket(s))\n", (int)g_resp_fds.size());
    ev_run(loop, 0);
    return 0;
}
