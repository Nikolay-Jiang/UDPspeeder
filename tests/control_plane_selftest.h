// Included only by tunnel_client.cpp. Exercises the control-plane rejections
// with the real code: ctrl_encode/ctrl_decode, the bounded replay API, and the
// client's own ACK gate (ctrl_remote_cb). Invoked exclusively from
// test_mode_selftest(); the network entry points never call it. It touches no
// socket the tunnel uses and restores every global it borrows, mirroring
// tests/test_mode_net_selftest.h.
//
// Each negative is paired with a positive control that uses a byte-identical
// (or otherwise valid) packet, so a rejection can only come from the gate under
// test -- not from a malformed input that would be dropped anyway.

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "auth.h"
#include "control_proto.h"
#include "crypto/crypto_cfg.h"

// Counts into the caller's running totals so the new checks appear on the
// single "test_mode selftest: N checks" line and cannot hide behind a separate
// counter.
#define CTRLCHECK(cond)                                                        \
    do {                                                                       \
        ++checks;                                                              \
        if (!(cond)) {                                                         \
            ++failures;                                                        \
            printf("FAIL control [%s:%d]: %s\n", __FILE__, __LINE__, #cond);   \
        }                                                                      \
    } while (0)

// Build a v3 HELLO_ACK with an explicit nonce so acceptance is deterministic:
// ctrl_encode draws a random nonce, which would make the positive control
// (and therefore the whole matrix) flaky if that draw ever hit 0.
//
// Payload layout matches the server: ack_hdr + port_count*2 ports + the 2-byte
// capability the server echoes. The cap is emitted from the local config (zero
// by default under --test-selftest), exactly as the real server does.
static int control_build_hello_ack(char *out, const uint8_t session[16],
                                   uint16_t port, uint64_t nonce) {
    ctrl_hdr_t hdr = {};
    hdr.version      = 3;
    hdr.msg_type     = CTRL_HELLO_ACK;
    hdr.nonce        = nonce;
    hdr.timestamp_ms = get_current_time();
    memcpy(out, &hdr, CTRL_HDR_LEN);

    ctrl_hello_ack_hdr_t ack = {};
    memcpy(ack.session_id, session, 16);
    ack.port_count            = 1;
    ack.heartbeat_interval_ms = 1000;
    memcpy(out + CTRL_HDR_LEN, &ack, sizeof(ack));
    memcpy(out + CTRL_HDR_LEN + sizeof(ack), &port, 2);

    ctrl_cap_t cap = {};
    cap.cipher     = (uint8_t)g_crypto_cfg.cipher;
    cap.pad_bucket = (uint8_t)g_crypto_cfg.pad_bucket;
    memcpy(out + CTRL_HDR_LEN + sizeof(ack) + 2, &cap, sizeof(cap));

    int body = (int)(CTRL_HDR_LEN + sizeof(ack) + 2 + sizeof(cap));
    auth_tag(DOMAIN_CTRL, (const uint8_t *)out, (size_t)body,
             (uint8_t *)(out + body));
    return body + (int)CTRL_MAC_LEN;
}

// Bind a loopback UDP socket and copy the *bound* address back out (ephemeral
// port resolved), matching how the receive path constructs its source address.
static int control_bind_loopback(address_t &out, uint32_t ip_be) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = ip_be;
    if (bind(fd, (sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return -1; }
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (sockaddr *)&addr, &len) != 0) { close(fd); return -1; }
    out.from_sockaddr((sockaddr *)&addr, len);
    return fd;
}

// ---- cases 1-3: header/version/MAC/length gates in ctrl_decode ----
static void control_protocol_checks(int &checks, int &failures) {
    uint8_t hello[sizeof(ctrl_hello_payload_t)];
    memset(hello, 0x33, sizeof(hello));
    // v3 HELLO payload = struct + 2-byte capability, matching ctrl_send_hello.
    uint8_t hello_payload[sizeof(ctrl_hello_payload_t) + sizeof(ctrl_cap_t)];
    memcpy(hello_payload, hello, sizeof(hello));
    ctrl_cap_t cap = {};
    cap.cipher     = (uint8_t)g_crypto_cfg.cipher;
    cap.pad_bucket = (uint8_t)g_crypto_cfg.pad_bucket;
    memcpy(hello_payload + sizeof(hello), &cap, sizeof(cap));

    // Positive control: a v3 HELLO round-trips, so the rejections below cannot
    // be explained by an unusable key or a broken encoder.
    int wire_len = 0;
    char *wire = ctrl_encode(CTRL_HELLO, hello_payload, sizeof(hello_payload), &wire_len);
    CTRLCHECK(wire != NULL &&
              wire_len == (int)(CTRL_HDR_LEN + sizeof(hello_payload) + CTRL_MAC_LEN));
    uint8_t *payload = NULL;
    int payload_len = 0;
    ctrl_hdr_t hdr;
    CTRLCHECK(ctrl_decode(wire, wire_len, &payload, &payload_len, &hdr) == CTRL_HELLO);
    CTRLCHECK(hdr.version == 3 && payload_len == (int)(sizeof(ctrl_hello_payload_t) + sizeof(ctrl_cap_t)) &&
              memcmp(payload, hello_payload, sizeof(hello_payload)) == 0);

    // Case 1: only version 3 is accepted. The MAC is recomputed over each
    // forged header, so a rejection must come from the version gate.
    for (int version = 0; version <= 5; version++) {
        if (version == 3) continue;
        char pkt[CTRL_BUF_MAX];
        ctrl_hdr_t forged = {};
        forged.version      = (uint8_t)version;
        forged.msg_type     = CTRL_HELLO;
        forged.nonce        = 7;
        forged.timestamp_ms = get_current_time();
        memcpy(pkt, &forged, CTRL_HDR_LEN);
        memcpy(pkt + CTRL_HDR_LEN, hello, sizeof(hello));
        int body = (int)(CTRL_HDR_LEN + sizeof(hello));
        auth_tag(DOMAIN_CTRL, (const uint8_t *)pkt, (size_t)body,
                 (uint8_t *)(pkt + body));
        CTRLCHECK(ctrl_decode(pkt, body + (int)CTRL_MAC_LEN, &payload,
                              &payload_len, &hdr) == -1);
    }

    // Case 2: any one-bit change in the body or in a MAC byte is rejected.
    {
        char tampered[CTRL_BUF_MAX];
        memcpy(tampered, wire, wire_len);
        tampered[CTRL_HDR_LEN] ^= 1;
        CTRLCHECK(ctrl_decode(tampered, wire_len, &payload, &payload_len, &hdr) == -1);
        for (int i = 0; i < (int)CTRL_MAC_LEN; i++) {
            memcpy(tampered, wire, wire_len);
            tampered[wire_len - (int)CTRL_MAC_LEN + i] ^= 1;
            CTRLCHECK(ctrl_decode(tampered, wire_len, &payload, &payload_len,
                                  &hdr) == -1);
        }
    }

    // Case 3 (truncated): anything that cannot carry header + full MAC is
    // refused before any field is read.
    for (int len = 0; len < (int)(CTRL_HDR_LEN + CTRL_MAC_LEN); len++)
        CTRLCHECK(ctrl_decode(wire, len, &payload, &payload_len, &hdr) == -1);
    CTRLCHECK(ctrl_decode(wire, wire_len - 1, &payload, &payload_len, &hdr) == -1);

    // Case 3 (oversized): ctrl_encode refuses a payload that does not fit the
    // fixed control buffer; the largest legal packet still encodes, decodes,
    // and does not overflow.
    {
        static char big[CTRL_BUF_MAX + 1];
        memset(big, 0, sizeof(big));
        const int max_payload = (int)(CTRL_BUF_MAX - CTRL_HDR_LEN - CTRL_MAC_LEN);
        int n = 0;
        char *max_pkt = ctrl_encode(CTRL_HELLO, big, max_payload, &n);
        CTRLCHECK(max_pkt != NULL && n == CTRL_BUF_MAX);
        CTRLCHECK(ctrl_decode(max_pkt, n, &payload, &payload_len, &hdr) == CTRL_HELLO &&
                  payload_len == max_payload);
        CTRLCHECK(ctrl_encode(CTRL_HELLO, big, max_payload + 1, &n) == NULL);
    }
}

// ---- cases 4-5: bounded per-session replay ----
static void control_replay_checks(int &checks, int &failures) {
    uint8_t sid[16];
    memset(sid, 0x5a, sizeof(sid));
    // ctrl_replay_reset() both before and after, so static state cannot leak
    // into another case or into a later run.
    ctrl_replay_reset();
    uint64_t now = (uint64_t)get_current_time();

    // Case 4: the same nonce twice is rejected; nonce 0 never enters the window.
    CTRLCHECK(ctrl_replay_accept(sid, 12345, now));
    CTRLCHECK(!ctrl_replay_accept(sid, 12345, now));
    CTRLCHECK(!ctrl_replay_accept(sid, 0, now));
    CTRLCHECK(ctrl_replay_accept(sid, 12346, now));
    ctrl_replay_reset();
    CTRLCHECK(ctrl_replay_accept(sid, 12345, now));  // reset clears the ring

    // Case 5: timestamps clearly outside the 60s window are rejected; a fresh
    // in-window timestamp is still accepted after them. ctrl_replay_accept()
    // samples its own clock (>= `now`), so a 1ms margin races the acquisition;
    // 120s keeps the future case unambiguously outside the window.
    const uint64_t out_of_window = 120000;  // 2x the 60s tolerance
    ctrl_replay_reset();
    CTRLCHECK(!ctrl_replay_accept(sid, 1, now - out_of_window));
    CTRLCHECK(!ctrl_replay_accept(sid, 2, now + out_of_window));
    CTRLCHECK(!ctrl_replay_accept(sid, 3, now - 3600000));
    CTRLCHECK(!ctrl_replay_accept(sid, 4, now + 3600000));
    CTRLCHECK(ctrl_replay_accept(sid, 5, now));
    ctrl_replay_reset();
}

// ---- cases 6-7: the client ACK source/session gate ----
static void control_client_checks(int &checks, int &failures) {
    address_t server_addr, client_addr, wrong_port_addr, wrong_ip_addr;
    int server_fd     = control_bind_loopback(server_addr, htonl(INADDR_LOOPBACK));
    int wrong_port_fd = control_bind_loopback(wrong_port_addr, htonl(INADDR_LOOPBACK));
    int wrong_ip_fd   = control_bind_loopback(wrong_ip_addr, htonl(0x7f000002));
    int client_fd     = control_bind_loopback(client_addr, htonl(INADDR_LOOPBACK));
    CTRLCHECK(server_fd >= 0 && wrong_port_fd >= 0 && wrong_ip_fd >= 0 && client_fd >= 0);
    if (server_fd < 0 || wrong_port_fd < 0 || wrong_ip_fd < 0 || client_fd < 0) {
        if (server_fd >= 0) close(server_fd);
        if (wrong_port_fd >= 0) close(wrong_port_fd);
        if (wrong_ip_fd >= 0) close(wrong_ip_fd);
        if (client_fd >= 0) close(client_fd);
        return;
    }

    struct ev_loop *loop = ev_loop_new(0);
    CTRLCHECK(loop != NULL);
    if (loop == NULL) {
        close(server_fd); close(wrong_port_fd); close(wrong_ip_fd); close(client_fd);
        return;
    }

    ctrl_addr         = server_addr;
    g_ctrl_fd         = client_fd;
    g_ctrl_server_len = ctrl_addr.get_len();
    memcpy(&g_ctrl_server_stor, &ctrl_addr.inner, g_ctrl_server_len);
    memset(g_session_id, 0x42, 16);
    g_ctrl_state = CTRL_HANDSHAKING;
    g_hello_retry_sec = 7;
    heartbeat_interval_sec = 10;

    ev_timer timer;
    ev_timer_init(&timer, ctrl_timer_cb, 1.0, 0.0);
    ev_io watcher = {};
    watcher.data = &timer;  // ctrl_remote_cb uses watcher->data as the timer

    const uint16_t port = 25001;
    char ack[CTRL_HDR_LEN + sizeof(ctrl_hello_ack_hdr_t) + 2 + 2 + CTRL_MAC_LEN];
    int ack_len = control_build_hello_ack(ack, g_session_id, port, 424242);
    auto deliver = [&](int fd, const char *packet, int len) {
        CTRLCHECK(sendto(fd, packet, len, 0, (sockaddr *)&client_addr.inner,
                         client_addr.get_len()) == len);
        ctrl_remote_cb(loop, &watcher, 0);
    };

    // Case 6: an authenticated, correctly-sessioned HELLO_ACK from the wrong
    // source must be dropped and must not install ports or advance the state.
    deliver(wrong_port_fd, ack, ack_len);
    CTRLCHECK(g_ctrl_state == CTRL_HANDSHAKING && g_hello_retry_sec == 7 &&
              !port_range_mgr.ready);
    deliver(wrong_ip_fd, ack, ack_len);
    CTRLCHECK(g_ctrl_state == CTRL_HANDSHAKING && g_hello_retry_sec == 7 &&
              !port_range_mgr.ready);
    // Positive control: the identical bytes from the configured server are
    // accepted, so the two drops above were the source gate, not the packet.
    deliver(server_fd, ack, ack_len);
    CTRLCHECK(g_ctrl_state == CTRL_RUNNING && g_hello_retry_sec == 1 &&
              port_range_mgr.ready && port_range_mgr.ports.size() == 1);

    // Case 7: a valid MAC from the right source but with a mismatched
    // session_id is rejected; the real session id round-trips.
    uint8_t wrong_session[16];
    memcpy(wrong_session, g_session_id, 16);
    wrong_session[0] ^= 1;
    g_ctrl_state = CTRL_HANDSHAKING;
    g_hello_retry_sec = 7;
    port_range_mgr.ready = false;
    ack_len = control_build_hello_ack(ack, wrong_session, port, 424243);
    deliver(server_fd, ack, ack_len);
    CTRLCHECK(g_ctrl_state == CTRL_HANDSHAKING && g_hello_retry_sec == 7 &&
              !port_range_mgr.ready);
    ack_len = control_build_hello_ack(ack, g_session_id, port, 424244);
    deliver(server_fd, ack, ack_len);
    CTRLCHECK(g_ctrl_state == CTRL_RUNNING && g_hello_retry_sec == 1 &&
              port_range_mgr.ready);

    ev_timer_stop(loop, &timer);
    ev_loop_destroy(loop);
    close(server_fd);
    close(wrong_port_fd);
    close(wrong_ip_fd);
    close(client_fd);
}

// Called from test_mode_selftest() (see test_mode.cpp). Returns the number of
// failures and adds its checks to the caller's totals.
int control_plane_selftest(int &checks, int &failures) {
    // Borrowed client control state; restored before returning so nothing that
    // runs later can observe it.
    ctrl_state_t saved_state = g_ctrl_state;
    int saved_fd = g_ctrl_fd;
    int saved_retry = g_hello_retry_sec;
    address_t::storage_t saved_server = g_ctrl_server_stor;
    socklen_t saved_server_len = g_ctrl_server_len;
    address_t saved_ctrl_addr = ctrl_addr;
    int saved_heartbeat = heartbeat_interval_sec;
    uint8_t saved_session[16];
    memcpy(saved_session, g_session_id, 16);
    address_t saved_base = port_range_mgr.server_base_addr;
    std::vector<uint16_t> saved_ports = port_range_mgr.ports;
    size_t saved_rr = port_range_mgr.rr_counter;
    bool saved_ready = port_range_mgr.ready;

    // This block installs its own key: the surrounding selftest restores
    // whichever key it ran with, and a leftover vector must not decide whether
    // a control MAC verifies.
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(0x80 + i);
    auth_key_set(key);

    int before = failures;
    control_protocol_checks(checks, failures);
    control_replay_checks(checks, failures);
    control_client_checks(checks, failures);

    g_ctrl_state = saved_state;
    g_ctrl_fd = saved_fd;
    g_hello_retry_sec = saved_retry;
    g_ctrl_server_stor = saved_server;
    g_ctrl_server_len = saved_server_len;
    ctrl_addr = saved_ctrl_addr;
    heartbeat_interval_sec = saved_heartbeat;
    memcpy(g_session_id, saved_session, 16);
    port_range_mgr.server_base_addr = saved_base;
    port_range_mgr.ports = saved_ports;
    port_range_mgr.rr_counter = saved_rr;
    port_range_mgr.ready = saved_ready;
    return failures - before;
}

#undef CTRLCHECK
