// Network event loops for --test-mode: responder (this task) and prober
// (Task 9). Pure protocol/statistics logic stays in test_mode.cpp; this file
// only wires that logic to sockets and a libev loop.
#include "test_mode.h"
#include "log.h"
#include "misc.h"
#include "port_range_manager.h"
#include <signal.h>
#include <sys/select.h>
#include <unistd.h>
#include <vector>

// ---------------- TEST_RESULT wire payload ----------------
//
// 84 bytes of big-endian u32 words (write_u32/read_u32 in common.cpp are
// big-endian). The responder packs, the prober unpacks; the two halves are
// kept adjacent below so a future reader always sees both at once.
//
//   off  0..23 : 6 trace_stats_t words  -- n, arrived_n, lost_n,
//                run_p50, run_p95, run_max
//   off 24..83 : 3 tiers x 20 bytes, in TIER order {thrifty, balanced,
//                aggressive}; per tier: x, y, i_ms, residual_ppm, flags
//
// All three tiers must cross the wire: with only the balanced tier, the report
// renders the other two rows as "target unreachable" on every run, which is a
// flat lie whenever the balanced row on the same table shows a met target.
// Derived fields (loss_rate, resolution, burst_p95_ms, overhead, actual_mbps)
// are recomputed by the prober rather than sent.
static const int TEST_RESULT_TIER_LEN  = 20;
static const int TEST_RESULT_NTIERS    = 3;
static const int TEST_RESULT_STATS_LEN = 24;
static const int TEST_RESULT_WIRE_LEN =
    TEST_RESULT_STATS_LEN + TEST_RESULT_NTIERS * TEST_RESULT_TIER_LEN;   // 84

// tier flag bits
static const u32_t TIER_FLAG_FEASIBLE     = 1u << 0;
static const u32_t TIER_FLAG_EXTRAPOLATED = 1u << 1;

static void result_wire_pack(char *out, const trace_stats_t &st,
                             const tier_t *tiers /* [TEST_RESULT_NTIERS] */) {
    write_u32(out + 0,  st.n);
    write_u32(out + 4,  st.arrived_n);
    write_u32(out + 8,  st.lost_n);
    write_u32(out + 12, st.run_p50);
    write_u32(out + 16, st.run_p95);
    write_u32(out + 20, st.run_max);
    for (int k = 0; k < TEST_RESULT_NTIERS; k++) {
        const tier_t &tr = tiers[k];
        char *p = out + TEST_RESULT_STATS_LEN + k * TEST_RESULT_TIER_LEN;
        u32_t flags = 0;
        if (tr.feasible)     flags |= TIER_FLAG_FEASIBLE;
        if (tr.extrapolated) flags |= TIER_FLAG_EXTRAPOLATED;
        write_u32(p + 0,  tr.feasible ? (u32_t)tr.x : 0u);
        write_u32(p + 4,  tr.feasible ? (u32_t)tr.y : 0u);
        write_u32(p + 8,  tr.feasible ? (u32_t)tr.i_ms : 0u);
        // residual is 0..1; parts-per-million keeps it well inside u32 and is
        // 100x finer than the tightest tier target (0.01%).
        write_u32(p + 12, tr.feasible ? (u32_t)(tr.residual * 1e6) : 0u);
        write_u32(p + 16, flags);
    }
}

// Inverse of result_wire_pack. `wire` must hold at least TEST_RESULT_WIRE_LEN
// bytes (checked by the caller). Fills the derived fields the sender omitted.
static void result_wire_unpack(const char *wire, uint32_t pps, double app_mbps,
                               int pkt_size, trace_stats_t *st_out,
                               tier_t *tiers_out /* [TEST_RESULT_NTIERS] */) {
    char *p0 = (char *)wire;   // read_u32 takes char*, but never writes
    trace_stats_t &st = *st_out;
    memset(&st, 0, sizeof(st));
    st.n         = read_u32(p0 + 0);
    st.arrived_n = read_u32(p0 + 4);
    st.lost_n    = read_u32(p0 + 8);
    st.run_p50   = read_u32(p0 + 12);
    st.run_p95   = read_u32(p0 + 16);
    st.run_max   = read_u32(p0 + 20);
    if (st.n > 0) {
        st.loss_rate  = (double)st.lost_n / (double)st.n;
        st.resolution = 1.0 / (double)st.n;
    }
    if (pps > 0)
        st.burst_p95_ms = (double)st.run_p95 / (double)pps * 1000.0;

    double hdr_factor = 1.0;
    if (pkt_size > 0) hdr_factor = 1.0 + 16.0 / (double)pkt_size;

    for (int k = 0; k < TEST_RESULT_NTIERS; k++) {
        char *p = p0 + TEST_RESULT_STATS_LEN + k * TEST_RESULT_TIER_LEN;
        tier_t &tr = tiers_out[k];
        memset(&tr, 0, sizeof(tr));
        u32_t flags   = read_u32(p + 16);
        tr.feasible     = (flags & TIER_FLAG_FEASIBLE) != 0;
        tr.extrapolated = (flags & TIER_FLAG_EXTRAPOLATED) != 0;
        tr.x        = (int)read_u32(p + 0);
        tr.y        = (int)read_u32(p + 4);
        tr.i_ms     = (int)read_u32(p + 8);
        tr.residual = (double)read_u32(p + 12) / 1e6;
        if (tr.feasible && tr.x > 0) {
            tr.overhead    = (double)tr.y / (double)tr.x;
            tr.actual_mbps = app_mbps * (1.0 + tr.overhead) * hdr_factor;
        }
    }
}

// ---------------- responder session state ----------------
//
// A session is normally closed by TEST_BYE, which the prober only sends on the
// success path. A prober that was interrupted, killed or crashed never sends
// it, and since the prober binds an ephemeral port every run, the retry
// presents a different address_t and is rejected by the source-pinning gate --
// permanently. So the session must also expire on silence.
//
// 45s: the longest legitimate gap between two messages from a live prober is a
// phase boundary where every control message needs retrying (REQUEST_RESULT
// 5x2s plus PHASE_BEGIN 5x1s, ~15s), and those retries are themselves traffic
// the responder sees. 45s leaves ~3x margin over that while still freeing an
// abandoned session inside a minute. An idle --test-mode responder has nothing
// to protect, so erring long costs only recovery time.
static const my_time_t TEST_SESSION_IDLE_LIMIT_US = 45ULL * 1000000ULL;

struct responder_state_t {
    bool               active = false;
    address_t          peer;              // source-pinned to the HELLO sender
    int                phase = 0;
    trace_t            trace;
    trace_stats_t      stats;
    tier_t             tiers[TEST_RESULT_NTIERS];   // thrifty, balanced, aggressive
    bool               phase_open = false;
    my_time_t          last_probe_us = 0;
    my_time_t          last_rx_us = 0;    // any accepted msg from the pinned peer

    uint32_t           cur_pps = 0;
    my_time_t          last_mac_warn_ms = 0;
};

static responder_state_t g_resp;
static std::vector<int> g_resp_fds;

// Round-trip hint, measured as the gap between the HELLO we answered and the
// first message that came back. Only used to size the reverse phase's grace
// period, so a rough figure is fine.
static my_time_t g_pr_rtt_hint_us = 0;
static my_time_t g_hello_ack_sent_us = 0;

// The source address most recently seen on each responder fd, parallel to
// g_resp_fds (index 0 = control fd, 1..N = data fds). Task 6's reverse
// multi-port phase must send from fd k back to the address that fd actually
// saw: under a symmetric nat that is a different external port per fd, and
// replying to the control-plane address instead would be silently dropped.
// Refreshed on every accepted packet -- a nat can rebind mid-run.
struct data_ep_t {
    bool      seen = false;
    address_t addr;
};
static std::vector<data_ep_t> g_data_eps;

// ---------------- responder reverse-phase sender ----------------
//
// The responder is a traffic source only here. Two independent deadlines guard
// it: the 45s session idle limit (unchanged, whole-session) and the dead-man
// switch below, which applies ONLY while a reverse phase is running. The
// prober is silent during a reverse phase apart from its 1s keepalives, so
// without the keepalives the 45s limit would kill a legitimate long phase --
// and without the dead-man switch a kill -9'd prober would leave the responder
// blasting a dead address at full rate for up to --test-duration (600s).
static const my_time_t REV_DEADMAN_US = 5000000ULL;   // 5s
static const int       REV_END_COPIES = 3;
static const double    REV_TICK_SEC   = 0.001;

struct rev_send_t {
    bool      active = false;
    int       phase = 0;
    uint32_t  total = 0;
    uint32_t  sent = 0;
    uint32_t  send_fail = 0;
    uint32_t  pps = 0;
    pacer_t   pacer;
    my_time_t last_peer_rx_us = 0;
    // fds[k] is paired with dsts[k]: each fd must reply to the address that fd
    // itself saw, or a symmetric nat drops it.
    std::vector<int>       fds;
    std::vector<address_t> dsts;
    size_t    rr = 0;
    int       end_copies_left = 0;
};

static rev_send_t   g_rev;
static struct ev_timer g_rev_tick;
static struct ev_timer g_rev_end;

// Like responder_send(), but lets the caller set seq and padding -- reverse
// probes need both, and responder_send() hardcodes them to 0.
static void responder_send_ex(int fd, const address_t &to, int msg_type, int phase,
                              uint32_t seq, const void *payload, int payload_len,
                              int pad_to) {
    char out[TEST_BUF_MAX];
    int n = test_encode(msg_type, phase, seq, payload, payload_len, out, sizeof(out), pad_to);
    if (n < 0) return;
    address_t dst = to;
    if (sendto(fd, out, n, 0, (struct sockaddr *)&dst.inner, dst.get_len()) < 0) {
        // Local backpressure, not link loss. The prober counts the missing seq
        // as lost either way, so it is reported over PHASE_END rather than
        // silently corrected -- surfacing the caveat is honest, quietly
        // adjusting a number the peer actually measured is not.
        if (msg_type == TEST_PROBE) g_rev.send_fail++;
        mylog(log_debug, "test: reverse sendto(%s) failed: %s\n",
              dst.get_str(), get_sock_error());
    }
}

// Records `src` as the peer most recently seen on watcher `w`'s fd. Callers
// must only reach this once the packet is already known-accepted (mac-valid
// and pinned) -- see the two call sites in responder_cb for why each of them
// qualifies.
static void note_fd_ep(ev_io *w, const address_t &src) {
    size_t fd_idx = (size_t)(intptr_t)w->data;
    if (fd_idx < g_data_eps.size()) {
        g_data_eps[fd_idx].seen = true;
        g_data_eps[fd_idx].addr = src;
    }
}

// ---------------- HELLO / HELLO_ACK payloads ----------------
//
// HELLO carries the prober's --data-port-range as {count, first, last}, three
// big-endian u32s. Spec section 9.2 requires a mismatch to be refused: if only
// one end has the flag, the S3 probes land on ports nobody is bound to, the
// responder's trace shows ~100% loss, and the report concludes "multiple ports
// did not reduce loss, port-range brings no benefit for this link" -- the exact
// inverse of the truth, produced by the very misconfiguration this catches.
//
// HELLO_ACK carries a u32 reject code (0 = accepted) followed by an optional
// reason string, which the prober prints verbatim.
static const int TEST_HELLO_PL_LEN = 12;

enum test_reject_t {
    TEST_REJECT_NONE = 0,
    TEST_REJECT_PORT_RANGE,
    TEST_REJECT_VERSION
};

static void hello_pl_pack(char *out) {
    int n = port_range_mgr.count();
    write_u32(out + 0, (u32_t)n);
    write_u32(out + 4, n > 0 ? (u32_t)port_range_mgr.ports[0] : 0u);
    write_u32(out + 8, n > 0 ? (u32_t)port_range_mgr.ports[n - 1] : 0u);
}

// Returns TEST_REJECT_NONE when the peer's range matches ours, else fills
// `reason` with an operator-facing explanation. count+first+last is enough to
// separate every realistic misconfiguration (absent on one side, different
// base, different width) without shipping the whole table.
static int hello_pl_check(const uint8_t *pl, int pl_len, char *reason, size_t reason_cap) {
    int n = port_range_mgr.count();
    u32_t mine_count = (u32_t)n;
    u32_t mine_first = n > 0 ? (u32_t)port_range_mgr.ports[0] : 0u;
    u32_t mine_last  = n > 0 ? (u32_t)port_range_mgr.ports[n - 1] : 0u;

    if (pl_len < TEST_HELLO_PL_LEN) {
        snprintf(reason, reason_cap,
                 "HELLO payload is %d bytes, expected %d -- the two ends are running "
                 "different speederv2 builds. use the same build on both.",
                 pl_len, TEST_HELLO_PL_LEN);
        return TEST_REJECT_VERSION;
    }

    u32_t peer_count = read_u32((char *)pl + 0);
    u32_t peer_first = read_u32((char *)pl + 4);
    u32_t peer_last  = read_u32((char *)pl + 8);
    if (peer_count == mine_count && peer_first == mine_first && peer_last == mine_last)
        return TEST_REJECT_NONE;

    char peer_desc[48], mine_desc[48];
    if (peer_count == 0) snprintf(peer_desc, sizeof(peer_desc), "no --data-port-range");
    else snprintf(peer_desc, sizeof(peer_desc), "%u ports (%u-%u)",
                  peer_count, peer_first, peer_last);
    if (mine_count == 0) snprintf(mine_desc, sizeof(mine_desc), "no --data-port-range");
    else snprintf(mine_desc, sizeof(mine_desc), "%u ports (%u-%u)",
                  mine_count, mine_first, mine_last);

    snprintf(reason, reason_cap,
             "--data-port-range mismatch: prober has %s, responder has %s. "
             "pass an identical --data-port-range to both ends, or to neither. "
             "(left undetected this would send the multi-port probes to unbound "
             "ports and report port-range as useless.)",
             peer_desc, mine_desc);
    return TEST_REJECT_PORT_RANGE;
}

static void responder_finalize_phase() {
    if (!g_resp.phase_open) return;
    g_resp.phase_open = false;
    g_resp.stats = trace_analyze(g_resp.trace);
    test_pick_tiers(g_resp.trace, g_resp.stats,
                    &g_resp.tiers[0], &g_resp.tiers[1], &g_resp.tiers[2]);
    mylog(log_info, "test: phase %d finalized, loss %.4f%% (%u/%u)\n",
          g_resp.phase, g_resp.stats.loss_rate * 100.0,
          g_resp.stats.lost_n, g_resp.stats.n);
}

static void responder_send(int fd, const address_t &to, int msg_type, int phase,
                           const void *payload, int payload_len) {
    responder_send_ex(fd, to, msg_type, phase, 0, payload, payload_len, 0);
}

static void rev_stop(struct ev_loop *loop) {
    // g_rev.active stays true for the whole reverse phase, including the
    // grace wait and the three PHASE_END retries driven by g_rev_end, not
    // just the probe-sending window driven by g_rev_tick. Callers outside
    // rev_tick_cb/rev_end_cb (TEST_BYE, idle expiry, a fresh HELLO) can land
    // in either window, so both timers must be stopped here or the one not
    // covered is left armed against a session that no longer matches its
    // stale g_rev state. ev_timer_stop is a no-op on a timer that is not
    // currently active -- including one that was never ev_init'd, since a
    // static ev_timer is zero-initialized and so starts inactive -- so
    // stopping both unconditionally is safe from every call site.
    ev_timer_stop(loop, &g_rev_tick);
    ev_timer_stop(loop, &g_rev_end);
    g_rev.active = false;
}

static void rev_end_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    assert(!(revents & EV_ERROR));
    // PHASE_END is unacked and can be lost, so send three copies 20ms apart --
    // the same belt-and-braces the prober uses on the upstream path.
    char pl[8];
    write_u32(pl + 0, g_rev.sent);
    write_u32(pl + 4, g_rev.send_fail);
    responder_send_ex(g_resp_fds[0], g_resp.peer, TEST_PHASE_END, g_rev.phase,
                      0, pl, sizeof(pl), 0);
    g_rev.end_copies_left--;
    if (g_rev.end_copies_left > 0) {
        ev_timer_set(w, 0.02, 0.0);
        ev_timer_start(loop, w);
    } else {
        mylog(log_info, "test: reverse phase %d done, sent %u/%u (%u refused locally)\n",
              g_rev.phase, g_rev.sent, g_rev.total, g_rev.send_fail);
        rev_stop(loop);
    }
}

static void rev_tick_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    assert(!(revents & EV_ERROR));
    (void)w;
    if (!g_rev.active) return;

    my_time_t now = get_current_time_us();
    if (now - g_rev.last_peer_rx_us > REV_DEADMAN_US) {
        mylog(log_warn, "test: reverse phase %d aborted -- no keepalive from %s for %llu ms "
                        "(prober interrupted?)\n",
              g_rev.phase, g_resp.peer.get_str(),
              (unsigned long long)((now - g_rev.last_peer_rx_us) / 1000));
        rev_stop(loop);
        return;
    }

    int budget = g_rev.pacer.tick(now);
    for (int b = 0; b < budget && g_rev.sent < g_rev.total; b++) {
        size_t k = g_rev.rr % g_rev.fds.size();
        g_rev.rr++;
        // Mirrors prober_sendto: --random-drop is implemented here too, and
        // only for probes, so smoke tests can inject a known reverse loss rate.
        // Dropping control messages would break the handshake instead.
        bool drop = (random_drop != 0 &&
                     get_fake_random_number() % 10000 < (u32_t)random_drop);
        if (!drop)
            responder_send_ex(g_rev.fds[k], g_rev.dsts[k], TEST_PROBE, g_rev.phase,
                              g_rev.sent, NULL, 0, test_pkt_size);
        g_rev.sent++;
    }

    if (g_rev.sent >= g_rev.total) {
        ev_timer_stop(loop, &g_rev_tick);
        // Grace before PHASE_END: probes and PHASE_END travel on different
        // sockets (data fds vs the control fd), so nothing orders the last
        // probe ahead of PHASE_END, and the prober finalizes on PHASE_END.
        double grace = g_pr_rtt_hint_us > 0 ? (double)g_pr_rtt_hint_us * 2 / 1e6 : 0.5;
        if (grace < 0.5) grace = 0.5;
        g_rev.end_copies_left = REV_END_COPIES;
        ev_init(&g_rev_end, rev_end_cb);
        ev_timer_set(&g_rev_end, grace, 0.0);
        ev_timer_start(loop, &g_rev_end);
    }
}

static void responder_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    assert(!(revents & EV_ERROR));

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
    //
    // Probes are matched by ip only. A symmetric nat gives the peer a different
    // external source port per destination port, so a data-port probe arrives
    // from an address that is not byte-equal to the control-plane peer -- and
    // dropping those made S3 report ~100% loss and conclude that port-range is
    // useless, on precisely the links it helps most. Control messages keep the
    // exact (ip,port) match: they only ever travel on the single control
    // mapping, so tightening them costs nothing.
    if (mt != TEST_HELLO) {
        bool ok = g_resp.active &&
                  (mt == TEST_PROBE ? test_addr_same_ip(src, g_resp.peer)
                                    : src == g_resp.peer);
        if (!ok) {
            mylog(log_debug, "test: ignoring msg_type %d from %s (no active session, "
                             "or not the pinned peer)\n", mt, src.get_str());
            return;
        }
    }

    // Past the gate, a non-HELLO message is by definition from the pinned peer
    // of an active session: it is proof of life, so it holds off idle expiry.
    if (mt != TEST_HELLO) {
        g_resp.last_rx_us = get_current_time_us();
        if (g_pr_rtt_hint_us == 0 && g_hello_ack_sent_us != 0)
            g_pr_rtt_hint_us = get_current_time_us() - g_hello_ack_sent_us;

        // Refresh this fd's view of the peer. Only from an accepted (mac-valid,
        // pinned) packet, so an off-path sender cannot redirect the reverse
        // phase. HELLO is refreshed separately below, only once it is actually
        // accepted -- doing it here unconditionally would let a mac-valid HELLO
        // from a non-pinned sender (e.g. aimed at a data fd, or one that fails
        // hello_pl_check) overwrite the table before its own rejection checks run.
        note_fd_ep(w, src);
    }

    if (mt == TEST_HELLO) {
        if (g_resp.active && !(src == g_resp.peer)) {
            mylog(log_info, "test: rejecting concurrent session from %s\n", src.get_str());
            return;
        }
        char reason[512];
        reason[0] = 0;
        int reject = hello_pl_check(pl, pl_len, reason, sizeof(reason));
        if (reject != TEST_REJECT_NONE) {
            // Refuse without activating: a mismatched peer must not be able to
            // pin the session, and must be told why rather than left to time out.
            char ack[4 + sizeof(reason)];
            write_u32(ack, (u32_t)reject);
            int rlen = (int)strlen(reason);
            memcpy(ack + 4, reason, (size_t)rlen);
            mylog(log_warn, "test: refusing session from %s: %s\n", src.get_str(), reason);
            responder_send(w->fd, src, TEST_HELLO_ACK, 0, ack, 4 + rlen);
            return;
        }
        g_resp.active = true;
        g_resp.peer = src;
        g_resp.phase_open = false;
        // A fresh HELLO re-establishes the session from scratch, same as
        // phase_open above: a reverse phase left running from a stale session
        // would otherwise keep ticking against whatever the new session does
        // next, with no prober watching for its PHASE_END. Ordinarily this
        // path is only reached once per prober run; it also covers the
        // pathological case of a same-address reconnect while our reverse
        // phase to the old session is still in flight.
        if (g_rev.active) rev_stop(loop);
        g_resp.last_rx_us = get_current_time_us();
        note_fd_ep(w, src);
        mylog(log_info, "test: session from %s\n", src.get_str());
        char ack[8];
        int ack_len = test_hello_ack_accept_pack(ack, TEST_CAP_REVERSE);
        responder_send(w->fd, src, TEST_HELLO_ACK, 0, ack, ack_len);
        g_hello_ack_sent_us = get_current_time_us();

    } else if (mt == TEST_PHASE_BEGIN) {
        uint32_t expected_n = 0, pps = 0, dir = 0, spread = 0;
        if (test_phase_begin_unpack(pl, pl_len, &expected_n, &pps, &dir, &spread) != 0)
            return;

        // A duplicate or delayed PHASE_BEGIN for the phase already running must
        // NOT re-init the trace: that discards every probe recorded so far and
        // reports all of them as lost, manufacturing massive phantom loss in
        // exactly the way this feature has been bitten by twice before. The
        // prober re-sends PHASE_BEGIN whenever its PHASE_ACK went missing, so
        // this is a live path, not a theoretical one. Re-ACK and ignore.
        if (dir == 0 && g_resp.phase_open && h.phase == g_resp.phase) {
            mylog(log_debug, "test: duplicate PHASE_BEGIN for open phase %d, "
                             "re-acking without resetting the trace\n", g_resp.phase);
            responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);
            return;
        }

        if (expected_n == 0 || expected_n > TEST_MAX_EXPECTED_N) {
            mylog(log_warn, "test: refusing expected_n=%u (cap %u)\n",
                  expected_n, TEST_MAX_EXPECTED_N);
            return;
        }
        if (dir != 0) {
            // A duplicate PHASE_BEGIN is the prober's keepalive during a
            // reverse phase (it is otherwise silent). Re-ACK and return
            // WITHOUT touching the pacer or the counters: restarting them
            // would replay the whole phase and manufacture huge phantom loss.
            if (g_rev.active && g_rev.phase == h.phase) {
                g_rev.last_peer_rx_us = get_current_time_us();
                responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);
                return;
            }
            // The responder is a traffic source here, so it bounds rate and
            // volume itself instead of trusting the peer. TEST_MAX_EXPECTED_N
            // is a memory bound for recording a trace and is far too loose to
            // double as "how much may I transmit".
            if (expected_n > (uint32_t)TEST_MAX_TOTAL_PROBES || pps == 0 ||
                pps > (uint32_t)TEST_PPS_MAX) {
                mylog(log_warn, "test: refusing reverse phase: expected_n=%u (cap %lld), "
                                "pps=%u (cap %d)\n",
                      expected_n, TEST_MAX_TOTAL_PROBES, pps, TEST_PPS_MAX);
                return;
            }

            // A PHASE_BEGIN for a NEW phase number (not the duplicate caught
            // above) while a previous reverse phase's timers are still armed
            // must stop them first: ev_init() below unconditionally clears
            // libev's internal "active" flag without unlinking the watcher
            // from its timer heap, so re-initializing a still-running
            // g_rev_tick/g_rev_end in place would corrupt libev's heap
            // rather than just leaking a stale phase. Not expected in normal
            // operation (the prober runs one phase at a time), but cheap to
            // make safe regardless.
            if (g_rev.active) rev_stop(loop);

            g_rev = rev_send_t();
            g_rev.active = true;
            g_rev.phase  = h.phase;
            g_rev.total  = expected_n;
            g_rev.pps    = pps;
            g_rev.last_peer_rx_us = get_current_time_us();
            g_rev.pacer.init((double)pps, get_current_time_us());
            // Task 6 fills this from g_data_eps when spread != 0. Single-port
            // reverse always answers on the control fd, to the pinned peer.
            g_rev.fds.push_back(g_resp_fds[0]);
            g_rev.dsts.push_back(g_resp.peer);

            mylog(log_info, "test: reverse phase %d begin, sending %u probes at %u pps\n",
                  h.phase, expected_n, pps);
            responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);
            ev_init(&g_rev_tick, rev_tick_cb);
            ev_timer_set(&g_rev_tick, REV_TICK_SEC, REV_TICK_SEC);
            ev_timer_start(loop, &g_rev_tick);
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
        result_wire_pack(wire, g_resp.stats, g_resp.tiers);
        responder_send(w->fd, src, TEST_RESULT, g_resp.phase, wire, sizeof(wire));

    } else if (mt == TEST_BYE) {
        mylog(log_info, "test: session closed by %s\n", src.get_str());
        g_resp.active = false;
        g_resp.phase_open = false;
        if (g_rev.active) rev_stop(loop);
        for (size_t k = 0; k < g_data_eps.size(); k++) g_data_eps[k] = data_ep_t();
    }
}

// Fallback: if all three PHASE_END copies were lost, finalize on silence.
static void responder_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    assert(!(revents & EV_ERROR));
    (void)w;

    // Expire an abandoned session (interrupted/killed prober -- no TEST_BYE).
    // phase_open must be cleared with it, or a stale half-open phase would leak
    // its trace into the next session's first PHASE_BEGIN.
    if (g_resp.active) {
        my_time_t silent_us = get_current_time_us() - g_resp.last_rx_us;
        if (silent_us > TEST_SESSION_IDLE_LIMIT_US) {
            mylog(log_info, "test: session with %s expired after %llu s of silence "
                            "(prober interrupted or gone); accepting new sessions again\n",
                  g_resp.peer.get_str(), (unsigned long long)(silent_us / 1000000ULL));
            g_resp.active = false;
            g_resp.phase_open = false;
            if (g_rev.active) rev_stop(loop);
            for (size_t k = 0; k < g_data_eps.size(); k++) g_data_eps[k] = data_ep_t();
            return;
        }
    }

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
        w->data = (void *)(intptr_t)k;   // index into g_resp_fds / g_data_eps
        ev_io_start(loop, w);
        watchers.push_back(w);
        mylog(log_info, "test: responder listening at %s\n", binds[k].get_str());
    }
    g_data_eps.assign(g_resp_fds.size(), data_ep_t());

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
    // Set once before the phases run; result_wire_unpack needs them to fill in
    // the bandwidth column the responder does not know about.
    double        app_mbps = 0.0;
    int           pkt_size = 0;
    trace_stats_t result_stats;
    tier_t        result_tiers[TEST_RESULT_NTIERS];
    // Probes rejected by the local stack. Reset per phase, accumulated for the
    // report; see the note on test_report_t::send_fail_n.
    uint32_t      phase_send_fail = 0;
    uint32_t      run_send_fail = 0;
    uint32_t      run_send_total = 0;
    u32_t         peer_caps = 0;
};

static prober_ctx_t g_pr;

static int prober_sendto(int msg_type, int phase, uint32_t seq,
                          const void *payload, int payload_len,
                          const address_t &dst, int pad_to) {
    // The tunnel's --random-drop lives in my_send() behind dest.cook, which
    // test mode does not use. Reimplement it here so smoke tests can inject a
    // known loss rate. Only TEST_PROBE is dropped: dropping control messages
    // (HELLO/PHASE_BEGIN/PHASE_END/REQUEST_RESULT) would break the handshake
    // or result collection instead of simulating link loss.
    if (random_drop != 0 && msg_type == TEST_PROBE) {
        if (get_fake_random_number() % 10000 < (u32_t)random_drop) return 0;
    }
    char out[TEST_BUF_MAX];
    int n = test_encode(msg_type, phase, seq, payload, payload_len,
                         out, sizeof(out), pad_to);
    if (n < 0) return -1;
    address_t d = dst;
    int ret = (int)sendto(g_pr.fd, out, n, 0, (struct sockaddr *)&d.inner, d.get_len());
    if (ret < 0) {
        // Not fatal, but not link loss either: the socket is non-blocking, so
        // at high pps this is usually a full send buffer (ENOBUFS/EWOULDBLOCK),
        // i.e. LOCAL backpressure. The responder still counts the sequence
        // number as lost, so the measurement is overstated by exactly these.
        // Count them so the report can say so. Deliberately not subtracted from
        // the loss figure: surfacing the caveat is honest, quietly adjusting a
        // number the responder actually measured is not. Control messages are
        // covered by prober_exchange's retry loop and are not counted here.
        if (msg_type == TEST_PROBE) g_pr.phase_send_fail++;
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
            if (h.phase != (uint8_t)phase) {
                // Every reply in this protocol echoes the request's phase. A
                // stale one (e.g. a RESULT for the previous phase, arriving
                // late) mis-attributed to this phase is a silently wrong
                // number in the report -- the worst failure mode here.
                mylog(log_debug, "test: dropping msg_type %d carrying phase %d "
                                 "while waiting on phase %d\n",
                      mt, (int)h.phase, phase);
                continue;
            }
            g_pr.rtt_us = get_current_time_us() - t0;
            if (out_payload && out_payload_len) {
                // Always assign *out_payload_len, including the zero case: it
                // is the caller's capacity on entry (e.g. sizeof(wire)), and a
                // caller that checks "did I get a full-size reply?" against a
                // stale capacity value -- rather than the actual received
                // length -- would validate uninitialized memory as if it were
                // a real payload.
                int cp = pl_len < *out_payload_len ? pl_len : *out_payload_len;
                if (cp < 0) cp = 0;
                if (cp > 0) memcpy(out_payload, pl, (size_t)cp);
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
    char begin_pl[TEST_PHASE_BEGIN_PL_LEN];
    test_phase_begin_pack(begin_pl, total, pps, 0, dests.size() > 1 ? 1 : 0);

    if (!prober_exchange(TEST_PHASE_BEGIN, phase, begin_pl, sizeof(begin_pl),
                          TEST_PHASE_ACK, 1000, 5, NULL, NULL)) {
        mylog(log_fatal, "test: responder did not ack phase %d\n", phase);
        myexit(-1);
    }

    mylog(log_info, "test: phase %d running -- %u pps x %ds (%u probes) to %d port(s)\n",
          phase, pps, duration_sec, total, (int)dests.size());

    g_pr.phase_send_fail = 0;
    pacer_t pacer;
    pacer.init((double)pps, get_current_time_us());
    uint32_t sent = 0;
    size_t rr = 0;
    my_time_t next_tick = get_current_time_us();
    uint32_t progress_step = pps * 5;
    if (progress_step == 0) progress_step = 1;
    uint32_t next_progress = progress_step;

    while (sent < total) {
        next_tick += 1000;   // 1ms
        my_time_t now = get_current_time_us();
        if (next_tick > now) {
            usleep((useconds_t)(next_tick - now));
        } else if (now - next_tick > PACER_SLIP_US) {
            // Stretching the phase is harmless -- the responder waits for
            // PHASE_END, not a clock -- whereas dropping probes would be
            // counted as loss.
            mylog(log_warn, "test: pacing slipped %llu ms behind, phase will run long\n",
                  (unsigned long long)((now - next_tick) / 1000));
            next_tick = now;
        }

        int budget = pacer.tick(get_current_time_us());
        for (int b = 0; b < budget && sent < total; b++) {
            const address_t &d = dests[rr % dests.size()];
            rr++;
            prober_sendto(TEST_PROBE, phase, sent, NULL, 0, d, test_pkt_size);
            sent++;
            // Print once per threshold crossing, not once per tick -- at low
            // pps many ticks elapse with sent unchanged.
            if (sent >= next_progress) {
                mylog(log_info, "test: phase %d progress %u/%u\n", phase, sent, total);
                next_progress += progress_step;
            }
        }
    }

    g_pr.run_send_fail  += g_pr.phase_send_fail;
    g_pr.run_send_total += total;
    if (g_pr.phase_send_fail > 0) {
        mylog(log_warn, "test: phase %d -- %u/%u probes were refused by the local "
                        "socket (send buffer full?); the responder counts them as "
                        "lost, so this phase's loss is overstated\n",
              phase, g_pr.phase_send_fail, total);
    }

    // Grace period to drain in-flight probes before the responder finalizes.
    // The responder finalizes the instant PHASE_END arrives, so this sleep
    // must happen BEFORE PHASE_END is sent, not after: probes and PHASE_END
    // travel on different sockets (data ports vs. the control address), so
    // there is no cross-socket ordering guarantee that the last probe is
    // dequeued before PHASE_END lands, especially with multiple data ports
    // (S3) or over a real link where probes are still genuinely in flight
    // for ~RTT. Sleeping here first, then sending PHASE_END, ensures the
    // probes have actually landed before the responder stops counting.
    my_time_t grace_us = g_pr.rtt_us * 2;
    if (grace_us < 500000ULL) grace_us = 500000ULL;
    usleep((useconds_t)grace_us);

    // PHASE_END x3 (it can be lost too, and there is no ACK for it). The
    // REQUEST_RESULT retry loop below covers a lost RESULT reply.
    for (int k = 0; k < 3; k++) {
        prober_sendto(TEST_PHASE_END, phase, 0, NULL, 0, g_pr.peer, 0);
        usleep(20 * 1000);
    }

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

    result_wire_unpack((const char *)wire, pps, g_pr.app_mbps, g_pr.pkt_size,
                       &g_pr.result_stats, g_pr.result_tiers);

    mylog(log_info, "test: phase %d result -- loss %.4f%% (%u/%u)\n",
          phase, g_pr.result_stats.loss_rate * 100.0,
          g_pr.result_stats.lost_n, g_pr.result_stats.n);
}

int test_mode_prober_loop() {
    // main() installs SIGINT/SIGTERM as libev signal watchers, whose handlers
    // only set a pending flag and defer the real callback to ev_run(). The
    // prober is deliberately blocking (select + usleep) and never enters
    // ev_run, so both signals would be swallowed outright -- leaving kill -9 as
    // the only way to stop a foreground tool that runs for 1-2.5 minutes (and
    // SIGKILL is exactly what wedges the responder's pinned session). Restore
    // the default disposition for the duration of the blocking phases. The
    // responder is untouched: it does run ev_run, so its watchers work.
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    address_t ephemeral;
    ephemeral.from_str((char *)"0.0.0.0:0");
    if (new_listen_socket2(g_pr.fd, ephemeral) != 0) {
        mylog(log_fatal, "test: failed to create prober socket\n");
        myexit(-1);
    }
    g_pr.peer = remote_addr;

    char hello_pl[TEST_HELLO_PL_LEN];
    hello_pl_pack(hello_pl);

    uint8_t ack_pl[640];
    int ack_len = (int)sizeof(ack_pl);
    if (!prober_exchange(TEST_HELLO, 0, hello_pl, sizeof(hello_pl),
                          TEST_HELLO_ACK, 1000, 10, ack_pl, &ack_len)) {
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
    if (ack_len >= 4 && read_u32((char *)ack_pl) != (u32_t)TEST_REJECT_NONE) {
        // Print the responder's reason verbatim rather than letting this look
        // like a timeout. The reason is only reachable by a peer that already
        // holds -k, but it still reaches a terminal, so strip anything that is
        // not printable ASCII instead of forwarding escape sequences.
        char reason[640];
        int rlen = ack_len - 4;
        if (rlen > (int)sizeof(reason) - 1) rlen = (int)sizeof(reason) - 1;
        for (int k = 0; k < rlen; k++) {
            unsigned char c = ack_pl[4 + k];
            reason[k] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
        }
        reason[rlen] = 0;
        mylog(log_fatal, "test: responder refused the session.\n"
                         "      reason: %s\n", reason);
        myexit(-1);
    }
    g_pr.peer_caps = test_hello_ack_caps(ack_pl, ack_len);
    mylog(log_info, "test: responder reachable, RTT %.0f ms, caps 0x%x\n",
          g_pr.rtt_us / 1000.0, (unsigned)g_pr.peer_caps);

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

    // result_wire_unpack fills each tier's bandwidth column from these.
    g_pr.app_mbps = rep.app_mbps;
    g_pr.pkt_size = rep.pkt_size;

    // ---- rate scan first: if loss rises with offered rate it is
    // ---- policing/congestion-induced and the whole FEC premise collapses,
    // ---- so the user should see that warning before sinking time into the
    // ---- rest of the run (the remaining phases still run; the data still
    // ---- has value even under that warning).
    const int SCAN_SEC = TEST_RATE_SCAN_SEC;
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
    rep.up.stats      = g_pr.result_stats;
    rep.up.thrifty    = g_pr.result_tiers[0];
    rep.up.balanced   = g_pr.result_tiers[1];
    rep.up.aggressive = g_pr.result_tiers[2];

    // ---- S3: N ports, upstream (only when --data-port-range was given) ----
    if (!spread.empty()) {
        prober_run_phase(3, (uint32_t)test_pps, test_duration_sec, spread);
        rep.have_spread    = true;
        rep.spread_ports   = (int)spread.size();
        rep.spread_loss_up = g_pr.result_stats.loss_rate;
    }

    prober_sendto(TEST_BYE, 0, 0, NULL, 0, g_pr.peer, 0);

    rep.send_fail_n  = g_pr.run_send_fail;
    rep.send_total_n = g_pr.run_send_total;

    test_render_report(rep);
    return 0;
}
