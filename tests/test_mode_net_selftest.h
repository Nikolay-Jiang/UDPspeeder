// Included only by test_mode_net.cpp to exercise its private codecs/callbacks.
// Invoked exclusively by --test-selftest, never by either network entry point.
// New checks have a separate counter so they cannot mask loss of baseline checks.
static int net_checks, net_failures;
#define NCHECK(cond) do { ++net_checks; if (!(cond)) { ++net_failures; \
    printf("FAIL net [%d]: %s\n", __LINE__, #cond); } } while (0)

static void net_codec_checks() {
    trace_stats_t st = {};
    st.n = 100; st.arrived_n = 90; st.lost_n = 10;
    st.run_p50 = 1; st.run_p95 = 2; st.run_max = 3;
    tier_t tiers[3] = {};
    tiers[0] = {true, 10, 2, 4, 0.125, 0, 0, false};
    tiers[1] = {true, 20, 5, 6, 0.0625, 0, 0, true};
    tiers[2] = {false, 7, 8, 9, 0.5, 0, 0, true};
    const unsigned char expected[84] = {
        0,0,0,100, 0,0,0,90, 0,0,0,10, 0,0,0,1, 0,0,0,2, 0,0,0,3,
        0,0,0,10, 0,0,0,2, 0,0,0,4, 0,1,232,72, 0,0,0,1,
        0,0,0,20, 0,0,0,5, 0,0,0,6, 0,0,244,36, 0,0,0,3,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2
    };
    char wire[86];
    memset(wire, 0x5a, sizeof(wire));
    result_wire_pack(wire + 1, st, tiers);
    NCHECK(TEST_RESULT_WIRE_LEN == 84);
    NCHECK(memcmp(wire + 1, expected, 84) == 0);
    NCHECK(wire[0] == 0x5a && wire[85] == 0x5a);
    trace_stats_t got;
    tier_t out[3];
    result_wire_unpack((const char *)expected, 200, 5, 400, &got, out);
    NCHECK(got.n == 100 && got.arrived_n == 90 && got.lost_n == 10);
    NCHECK(got.run_p50 == 1 && got.run_p95 == 2 && got.run_max == 3);
    NCHECK(got.loss_rate == 0.1 && got.resolution == 0.01 && got.burst_p95_ms == 10);
    for (int k = 0; k < 2; ++k) {
        NCHECK(out[k].feasible && out[k].extrapolated == tiers[k].extrapolated);
        NCHECK(out[k].x == tiers[k].x && out[k].y == tiers[k].y && out[k].i_ms == tiers[k].i_ms);
        NCHECK(out[k].residual == tiers[k].residual);
        NCHECK(out[k].overhead == (double)tiers[k].y / tiers[k].x);
        NCHECK(out[k].actual_mbps == 5 * (1 + out[k].overhead) * 1.04);
    }
    NCHECK(!out[2].feasible && out[2].extrapolated && out[2].x == 0 && out[2].y == 0);
    NCHECK(out[2].i_ms == 0 && out[2].residual == 0 && out[2].actual_mbps == 0 && out[2].overhead == 0);
    memset(wire, 0, sizeof(wire));
    result_wire_unpack(wire, 0, 0, 0, &got, out);
    NCHECK(got.loss_rate == 0 && got.resolution == 0 && got.burst_p95_ms == 0);

    const auto saved_ports = port_range_mgr.ports;
    port_range_mgr.ports.clear();
    char hello[12] = {}, reason[512] = {};
    NCHECK(hello_pl_check((uint8_t *)hello, 12, reason, sizeof(reason)) == TEST_REJECT_NONE);
    for (int n = 0; n < 12; ++n)
        NCHECK(hello_pl_check((uint8_t *)hello, n, reason, sizeof(reason)) == TEST_REJECT_VERSION);
    port_range_mgr.ports = {15000, 15001};
    NCHECK(hello_pl_check((uint8_t *)hello, 12, reason, sizeof(reason)) == TEST_REJECT_PORT_RANGE);
    write_u32(hello, 2); write_u32(hello + 4, 15000); write_u32(hello + 8, 15001);
    NCHECK(hello_pl_check((uint8_t *)hello, 12, reason, sizeof(reason)) == TEST_REJECT_NONE);
    for (int offset = 0; offset < 12; offset += 4) {
        hello[offset + 3] ^= 1;
        NCHECK(hello_pl_check((uint8_t *)hello, 12, reason, sizeof(reason)) == TEST_REJECT_PORT_RANGE);
        NCHECK(strstr(reason, "mismatch") != NULL);
        hello[offset + 3] ^= 1;
    }
    port_range_mgr.ports = saved_ports;
}

// A local UDP datagram is queued before directly invoking the real callback.
// No ev_run, sleeps, root, tc, shortened production deadlines or wire hooks.
static void net_reverse_checks(const char *which) {
    int rx = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    int tx = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    NCHECK(rx >= 0 && tx >= 0);
    if (rx < 0 || tx < 0) { if (rx >= 0) close(rx); if (tx >= 0) close(tx); return; }
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    NCHECK(bind(rx, (sockaddr *)&addr, sizeof(addr)) == 0);
    socklen_t size = sizeof(addr);
    NCHECK(getsockname(rx, (sockaddr *)&addr, &size) == 0);
    NCHECK(connect(tx, (sockaddr *)&addr, size) == 0);
    struct ev_loop *loop = ev_loop_new(0);
    NCHECK(loop != NULL);
    if (!loop) { close(rx); close(tx); return; }
    ev_io watcher;
    ev_io_init(&watcher, responder_cb, rx, EV_READ);
    watcher.data = NULL;
    g_resp = responder_state_t();
    g_rev = rev_send_t();
    g_resp_fds = {rx};
    g_data_eps.resize(1);
    const auto saved_ports = port_range_mgr.ports;
    port_range_mgr.ports.clear();
    auto deliver = [&](int type, const char *payload, int length, uint32_t seq = 0) {
        char packet[TEST_BUF_MAX];
        int n = test_encode(type, 1, seq, payload, length, packet, sizeof(packet), 0);
        NCHECK(n > 0 && send(tx, packet, n, 0) == n);
        responder_cb(loop, &watcher, EV_READ);
    };
    auto receive = [&](int expected_type) {
        char packet[TEST_BUF_MAX];
        int n = recv(tx, packet, sizeof(packet), 0);
        test_hdr_t hdr; uint8_t *pl; int len;
        NCHECK(n > 0 && test_decode(packet, n, &hdr, &pl, &len) == expected_type);
    };
    char hello[12] = {};
    deliver(TEST_HELLO, hello, sizeof(hello));
    receive(TEST_HELLO_ACK);
    NCHECK(g_resp.active && g_resp.cookie != 0);
    test_phase_begin_t begin;
    begin.expected_n = 10; begin.pps = 10; begin.dir = 1;
    begin.cookie = g_resp.cookie; begin.pkt_size = 64;
    char pl[TEST_PHASE_BEGIN_PL_LEN];
    if (!strcmp(which, "wrong-cookie") || !strcmp(which, "missing-cookie")) {
        begin.cookie ^= 1;
        test_phase_begin_pack(pl, begin);
        deliver(TEST_PHASE_BEGIN, pl, !strcmp(which, "missing-cookie") ? 16 : sizeof(pl));
        char packet[TEST_BUF_MAX];
        NCHECK(recv(tx, packet, sizeof(packet), 0) == -1 && errno == EAGAIN);
        NCHECK(!g_rev.active && !g_resp.phase_open && g_rev.sent == 0);
    } else if (!strcmp(which, "duplicate")) {
        begin.dir = 0;
        test_phase_begin_pack(pl, begin);
        deliver(TEST_PHASE_BEGIN, pl, sizeof(pl)); receive(TEST_PHASE_ACK);
        deliver(TEST_PROBE, NULL, 0, 2);
        trace_t before = g_resp.trace;
        trace_stats_t stats = trace_analyze(before);
        char a[84], b[84]; tier_t tiers[3] = {};
        result_wire_pack(a, stats, tiers);
        printf("trace-stats: %u/%u/%u\n", stats.n, stats.arrived_n, stats.lost_n);
        deliver(TEST_PHASE_BEGIN, pl, sizeof(pl)); receive(TEST_PHASE_ACK);
        stats = trace_analyze(g_resp.trace);
        result_wire_pack(b, stats, tiers);
        printf("trace-stats: %u/%u/%u\n", stats.n, stats.arrived_n, stats.lost_n);
        NCHECK(memcmp(a, b, sizeof(a)) == 0 && stats.arrived_n == 1);
        NCHECK(before.arrived == g_resp.trace.arrived && before.recv_ts_rel_us == g_resp.trace.recv_ts_rel_us);
        NCHECK(before.first_arrival_us == g_resp.trace.first_arrival_us && g_resp.phase_open);
    } else if (!strcmp(which, "idle-expiry")) {
        test_phase_begin_pack(pl, begin);
        deliver(TEST_PHASE_BEGIN, pl, sizeof(pl)); receive(TEST_PHASE_ACK);
        NCHECK(g_rev.active);
        // Only the harness writes synthetic time; execute the production expiry path.
        g_resp.last_rx_us = get_current_time_us() - TEST_SESSION_IDLE_LIMIT_US - 1;
        responder_timer_cb(loop, NULL, 0);
        NCHECK(!g_resp.active && !g_resp.phase_open && !g_rev.active);
        NCHECK(g_resp.cookie == 0 && g_resp.last_rev_phase_done == -1 && !g_data_eps[0].seen);
        NCHECK(!ev_is_active(&g_rev_tick) && !ev_is_active(&g_rev_end));
        if (!g_resp.active && g_resp.cookie == 0) printf("res.rc_expired\n");
    } else {
        NCHECK(false);
    }
    if (g_rev.active) rev_stop(loop);
    ev_loop_destroy(loop);
    close(rx); close(tx);
    g_resp = responder_state_t(); g_rev = rev_send_t();
    g_resp_fds.clear(); g_data_eps.clear();
    port_range_mgr.ports = saved_ports;
}

int test_mode_net_selftest() {
    net_checks = net_failures = 0;
    net_codec_checks();
    // Opt-in only inside --test-selftest; normal network mode never reads this.
    const char *which = getenv("UDPSPEEDER_SELFTEST_REVERSE");
    if (which) {
        int saved_level = log_level, saved_color = enable_log_color;
        log_level = log_debug; enable_log_color = 0;
        net_reverse_checks(which);
        log_level = saved_level; enable_log_color = saved_color;
    }
    printf("test_mode net checks: %d, failures: %d\n", net_checks, net_failures);
    return net_failures;
}
#undef NCHECK
