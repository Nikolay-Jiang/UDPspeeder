// Network event loops for --test-mode: responder (this task) and prober
// (Task 9). Pure protocol/statistics logic stays in test_mode.cpp; this file
// only wires that logic to sockets and a libev loop.
#include "test_mode.h"
#include "log.h"
#include "misc.h"
#include "port_range_manager.h"
#include <sys/select.h>
#include <unistd.h>
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

    // Every session must start with HELLO. Without this, a peer holding the key
    // could drive PHASE_BEGIN/PROBE/REQUEST_RESULT with no handshake and no
    // pinning, letting two such peers clobber each other's in-flight trace.
    // Design doc section 9.3 requires source pinning and a single active session.
    if (mt != TEST_HELLO && (!g_resp.active || !(src == g_resp.peer))) {
        mylog(log_debug, "test: ignoring msg_type %d from %s (no active session, or not the pinned peer)\n",
              mt, src.get_str());
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

// ---------------- prober (this task) ----------------
//
// Deliberately blocking (select + usleep), not libev: unlike the responder,
// which must serve many ports concurrently, the prober runs one sequential
// script (handshake -> rate scan -> S1 -> S3) with no concurrent sessions to
// multiplex, so a plain blocking structure is simpler than a state machine
// spanning handshake/phase/retry/result-collection and buys nothing here.
struct prober_ctx_t {
    int           fd = -1;
    address_t     peer;
    my_time_t     rtt_us = 0;
    trace_stats_t result_stats;
    tier_t        result_tier;
};

static prober_ctx_t g_pr;

static int prober_sendto(int msg_type, int phase, uint32_t seq,
                          const void *payload, int payload_len,
                          const address_t &dst, int pad_to) {
    char out[TEST_BUF_MAX];
    int n = test_encode(msg_type, phase, seq, payload, payload_len,
                         out, sizeof(out), pad_to);
    if (n < 0) return -1;
    address_t d = dst;
    int ret = (int)sendto(g_pr.fd, out, n, 0, (struct sockaddr *)&d.inner, d.get_len());
    if (ret < 0) {
        // Not fatal: at probe pps this can be a transient local buffer-full
        // condition, which is itself a form of loss and gets reflected in the
        // trace like any other dropped probe. Control messages are covered by
        // prober_exchange's retry loop.
        mylog(log_debug, "test: sendto(%s) failed: %s\n", d.get_str(), get_sock_error());
    }
    return ret;
}

// Blocking helper: send msg and wait up to timeout_ms for want_type, retrying
// up to `retries` times (bounded — never spins forever if the peer vanished).
static bool prober_exchange(int msg_type, int phase, const void *payload, int payload_len,
                             int want_type, int timeout_ms, int retries,
                             uint8_t *out_payload, int *out_payload_len) {
    for (int attempt = 0; attempt < retries; attempt++) {
        my_time_t t0 = get_current_time_us();
        prober_sendto(msg_type, phase, 0, payload, payload_len, g_pr.peer, 0);
        for (;;) {
            my_time_t elapsed_ms = (get_current_time_us() - t0) / 1000;
            if ((int)elapsed_ms >= timeout_ms) break;

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 50 * 1000;
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(g_pr.fd, &rf);
            int sr = select(g_pr.fd + 1, &rf, NULL, NULL, &tv);
            if (sr < 0) {
                if (errno == EINTR) continue;
                mylog(log_debug, "test: select() failed: %s\n", get_sock_error());
                continue;
            }
            if (sr == 0) continue;

            char buf[TEST_BUF_MAX];
            int len = recv(g_pr.fd, buf, sizeof(buf), 0);
            if (len <= 0) continue;
            test_hdr_t h;
            uint8_t *pl = 0;
            int pl_len = 0;
            int mt = test_decode(buf, len, &h, &pl, &pl_len);
            if (mt != want_type) continue;
            g_pr.rtt_us = get_current_time_us() - t0;
            if (out_payload && out_payload_len && pl_len > 0) {
                int cp = pl_len < *out_payload_len ? pl_len : *out_payload_len;
                memcpy(out_payload, pl, (size_t)cp);
                *out_payload_len = cp;
            }
            return true;
        }
        mylog(log_debug, "test: no msg_type %d after attempt %d\n", want_type, attempt + 1);
    }
    return false;
}

// Uniform pacing: 1ms tick with a fractional accumulator (token-bucket
// style), so e.g. --test-pps 200 sends exactly one packet every 5 ticks. A
// bursty sender would manufacture its own time-correlated loss and
// contaminate the very burst-length measurement the -i recommendation is
// derived from, so sends are never batched per tick.
static void prober_run_phase(int phase, uint32_t pps, int duration_sec,
                              const std::vector<address_t> &dests) {
    uint32_t total = pps * (uint32_t)duration_sec;
    char begin_pl[12];
    write_u32(begin_pl + 0, total);
    write_u32(begin_pl + 4, pps);
    write_u32(begin_pl + 8, 0);   // dir 0 = prober -> responder

    if (!prober_exchange(TEST_PHASE_BEGIN, phase, begin_pl, sizeof(begin_pl),
                          TEST_PHASE_ACK, 1000, 5, NULL, NULL)) {
        mylog(log_fatal, "test: responder did not ack phase %d\n", phase);
        myexit(-1);
    }

    mylog(log_info, "test: phase %d running -- %u pps x %ds (%u probes) to %d port(s)\n",
          phase, pps, duration_sec, total, (int)dests.size());

    double per_tick = (double)pps / 1000.0;
    double acc = 0.0;
    uint32_t sent = 0;
    size_t rr = 0;
    my_time_t next_tick = get_current_time_us();
    uint32_t progress_step = pps * 5;
    if (progress_step == 0) progress_step = 1;
    uint32_t next_progress = progress_step;

    while (sent < total) {
        next_tick += 1000;   // 1ms
        my_time_t now = get_current_time_us();
        if (next_tick > now) usleep((useconds_t)(next_tick - now));

        acc += per_tick;
        while (acc >= 1.0 && sent < total) {
            acc -= 1.0;
            const address_t &d = dests[rr % dests.size()];
            rr++;
            prober_sendto(TEST_PROBE, phase, sent, NULL, 0, d, test_pkt_size);
            sent++;
            // Print once per threshold crossing, not once per tick -- at low
            // pps many ticks elapse with sent unchanged, and a per-tick check
            // here would reprint the same "sent/total" line on every one of
            // them until the next packet finally goes out.
            if (sent >= next_progress) {
                mylog(log_info, "test: phase %d progress %u/%u\n", phase, sent, total);
                next_progress += progress_step;
            }
        }
    }

    // PHASE_END x3 (it can be lost too, and there is no ACK for it).
    for (int k = 0; k < 3; k++) {
        prober_sendto(TEST_PHASE_END, phase, 0, NULL, 0, g_pr.peer, 0);
        usleep(20 * 1000);
    }

    // Grace period before asking for the result, so in-flight probes land.
    my_time_t grace_us = g_pr.rtt_us * 2;
    if (grace_us < 500000ULL) grace_us = 500000ULL;
    usleep((useconds_t)grace_us);

    uint8_t wire[TEST_RESULT_WIRE_LEN];
    int wire_len = (int)sizeof(wire);
    if (!prober_exchange(TEST_REQUEST_RESULT, phase, NULL, 0,
                          TEST_RESULT, 2000, 5, wire, &wire_len)) {
        mylog(log_fatal, "test: no result for phase %d\n", phase);
        myexit(-1);
    }
    if (wire_len < TEST_RESULT_WIRE_LEN) {
        mylog(log_fatal, "test: short result payload (%d bytes, want %d)\n",
              wire_len, TEST_RESULT_WIRE_LEN);
        myexit(-1);
    }

    memset(&g_pr.result_stats, 0, sizeof(g_pr.result_stats));
    g_pr.result_stats.n         = read_u32((char *)wire + 0);
    g_pr.result_stats.arrived_n = read_u32((char *)wire + 4);
    g_pr.result_stats.lost_n    = read_u32((char *)wire + 8);
    g_pr.result_stats.run_p50   = read_u32((char *)wire + 12);
    g_pr.result_stats.run_p95   = read_u32((char *)wire + 16);
    g_pr.result_stats.run_max   = read_u32((char *)wire + 20);
    if (g_pr.result_stats.n > 0) {
        g_pr.result_stats.loss_rate  = (double)g_pr.result_stats.lost_n / g_pr.result_stats.n;
        g_pr.result_stats.resolution = 1.0 / (double)g_pr.result_stats.n;
    }
    if (pps > 0)
        g_pr.result_stats.burst_p95_ms = (double)g_pr.result_stats.run_p95 / (double)pps * 1000.0;

    memset(&g_pr.result_tier, 0, sizeof(g_pr.result_tier));
    uint32_t rx = read_u32((char *)wire + 24);
    g_pr.result_tier.feasible = (rx != 0);
    g_pr.result_tier.x        = (int)rx;
    g_pr.result_tier.y        = (int)read_u32((char *)wire + 28);
    g_pr.result_tier.i_ms     = (int)read_u32((char *)wire + 32);
    g_pr.result_tier.residual = (double)read_u32((char *)wire + 36) / 1e6;
    if (g_pr.result_tier.x > 0)
        g_pr.result_tier.overhead = (double)g_pr.result_tier.y / g_pr.result_tier.x;

    mylog(log_info, "test: phase %d result -- loss %.4f%% (%u/%u)\n",
          phase, g_pr.result_stats.loss_rate * 100.0,
          g_pr.result_stats.lost_n, g_pr.result_stats.n);
}

int test_mode_prober_loop() {
    address_t ephemeral;
    ephemeral.from_str((char *)"0.0.0.0:0");
    if (new_listen_socket2(g_pr.fd, ephemeral) != 0) {
        mylog(log_fatal, "test: failed to create prober socket\n");
        myexit(-1);
    }
    g_pr.peer = remote_addr;

    if (!prober_exchange(TEST_HELLO, 0, NULL, 0, TEST_HELLO_ACK, 1000, 10, NULL, NULL)) {
        // A wrong -k is dropped silently by the responder (it only logs
        // locally), so from here a bad key and a blocked/unreachable port
        // are indistinguishable -- name both causes rather than guessing.
        mylog(log_fatal,
              "test: no response from %s after repeated attempts.\n"
              "      possible causes: (1) the UDP port is unreachable or firewalled, or\n"
              "                       (2) -k does not match on both sides (a wrong key is\n"
              "                           dropped silently by the responder; check its log).\n",
              g_pr.peer.get_str());
        myexit(-1);
    }
    mylog(log_info, "test: responder reachable, RTT %.0f ms\n", g_pr.rtt_us / 1000.0);

    std::vector<address_t> single;
    single.push_back(remote_addr);

    std::vector<address_t> spread;
    for (int k = 0; k < port_range_mgr.count(); k++) {
        address_t a = remote_addr;
        a.set_port(port_range_mgr.ports[k]);
        spread.push_back(a);
    }

    test_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.duration_sec = test_duration_sec;
    rep.pps          = test_pps;
    rep.pkt_size     = test_pkt_size;
    rep.probe_mbps   = (double)test_pps * test_pkt_size * 8.0 / 1e6;
    rep.app_mbps     = (test_app_mbps > 0.0) ? test_app_mbps : rep.probe_mbps;
    rep.rtt_ms       = g_pr.rtt_us / 1000.0;
    snprintf(rep.peer, sizeof(rep.peer), "%s", remote_addr.get_str());
    rep.have_down = false;  // S2/S4 not implemented yet; do not fabricate.

    // ---- rate scan first: if loss rises with offered rate it is
    // ---- policing/congestion-induced and the whole FEC premise collapses,
    // ---- so the user should see that warning before sinking time into the
    // ---- rest of the run (the remaining phases still run; the data still
    // ---- has value even under that warning).
    const int SCAN_SEC = 10;
    int scan_pps[3] = {test_pps / 2, test_pps, test_pps * 2};
    if (scan_pps[0] < 1) scan_pps[0] = 1;
    double scan_p[3];
    uint32_t scan_n[3];
    for (int k = 0; k < 3; k++) {
        prober_run_phase(90 + k, (uint32_t)scan_pps[k], SCAN_SEC, single);
        scan_p[k] = g_pr.result_stats.loss_rate;
        scan_n[k] = g_pr.result_stats.n;
    }
    rep.have_rate_scan = true;
    rep.p_half = scan_p[0]; rep.n_half = scan_n[0];
    rep.p_nom  = scan_p[1]; rep.n_nom  = scan_n[1];
    rep.p_dbl  = scan_p[2]; rep.n_dbl  = scan_n[2];
    rep.verdict = test_rate_verdict(scan_p[0], scan_n[0],
                                     scan_p[1], scan_n[1],
                                     scan_p[2], scan_n[2]);

    // ---- S1: single port, upstream ----
    prober_run_phase(1, (uint32_t)test_pps, test_duration_sec, single);
    rep.have_up = true;
    memset(&rep.up, 0, sizeof(rep.up));
    rep.up.stats    = g_pr.result_stats;
    rep.up.balanced = g_pr.result_tier;
    double hdr_factor = 1.0 + 16.0 / (double)test_pkt_size;
    if (rep.up.balanced.feasible)
        rep.up.balanced.actual_mbps =
            rep.app_mbps * (1.0 + rep.up.balanced.overhead) * hdr_factor;

    // ---- S3: N ports, upstream (only when --data-port-range was given) ----
    if (!spread.empty()) {
        prober_run_phase(3, (uint32_t)test_pps, test_duration_sec, spread);
        rep.have_spread    = true;
        rep.spread_ports   = (int)spread.size();
        rep.spread_loss_up = g_pr.result_stats.loss_rate;
    }

    prober_sendto(TEST_BYE, 0, 0, NULL, 0, g_pr.peer, 0);

    test_render_report(rep);
    return 0;
}
