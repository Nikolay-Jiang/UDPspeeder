#include "tunnel.h"
#include "control_proto.h"
#include "crypto/crypto_cfg.h"

// --- port-range-mode client state machine ---
enum ctrl_state_t { CTRL_IDLE, CTRL_HANDSHAKING, CTRL_RUNNING, CTRL_LOST };
static ctrl_state_t g_ctrl_state = CTRL_IDLE;
static int g_ctrl_fd = -1;
static address_t::storage_t g_ctrl_server_stor;
static socklen_t g_ctrl_server_len = 0;
static int g_hello_retry_sec = 1;  // capped exponential HELLO retry interval
static int g_hb_miss = 0;

static my_time_t g_rotate_next_ms = 0;  // next data-port rotation boundary (0 = unarmed)

static uint8_t g_session_id[16];  // random, set on first HELLO

// --- interference detection (G9) ---

// Anti-flap floor between re-handshakes, in ms, for every trigger: an isolated
// event inside the cooldown is ignored instead of stacking a handshake on top
// of a live one.
static const my_time_t rehandshake_min_interval_ms = 30 * 1000;
static my_time_t g_last_rehandshake_ms = 0;

// Live control timer (created in tunnel_client_event_loop). A trigger re-arms
// it to 1s so the CTRL_LOST branch of ctrl_timer_cb starts the fresh handshake
// immediately instead of waiting out the current heartbeat interval.
static struct ev_timer *g_ctrl_timer = 0;

const int fec_loss_min_expected_shards = 20;  // G9 window floor
const double loss_trigger_ratio = 0.20;       // >20% loss / short-send share

// short_send_drop_count and the outbound shard total are cumulative, so the
// windowed ratio needs a baseline sample: 14 samples on the 400ms conn tick
// span ~5.2s, i.e. the oldest entry is at least 5s old.
const int short_send_window_samples = 14;
struct short_send_sample_t {
    my_time_t t_ms;
    u64_t drops;
    u64_t outbound_shards;
};
static short_send_sample_t g_short_send_samples[short_send_window_samples];
static int g_short_send_sample_count = 0;

static void short_send_window_reset() {
    g_short_send_sample_count = 0;
}

static void short_send_window_note(my_time_t now_ms, u64_t drops, u64_t outbound_shards) {
    if (g_short_send_sample_count < short_send_window_samples) {
        short_send_sample_t &slot = g_short_send_samples[g_short_send_sample_count++];
        slot.t_ms = now_ms;
        slot.drops = drops;
        slot.outbound_shards = outbound_shards;
        return;
    }
    memmove(g_short_send_samples, g_short_send_samples + 1,
            sizeof(short_send_sample_t) * (short_send_window_samples - 1));
    short_send_sample_t &slot = g_short_send_samples[short_send_window_samples - 1];
    slot.t_ms = now_ms;
    slot.drops = drops;
    slot.outbound_shards = outbound_shards;
}

// Short-send drop fraction over the last >=5s, or negative while the window is
// not yet covered or no shard was sent in it.
static double short_send_window_ratio(my_time_t now_ms, u64_t drops, u64_t outbound_shards) {
    short_send_window_note(now_ms, drops, outbound_shards);
    if (g_short_send_sample_count < short_send_window_samples) return -1.0;
    const short_send_sample_t &base = g_short_send_samples[0];
    if (now_ms - base.t_ms < 5000) return -1.0;
    u64_t dropped = drops - base.drops;
    if (dropped == 0) return 0.0;
    u64_t sent_shards = outbound_shards - base.outbound_shards;
    if (sent_shards == 0) return -1.0;
    return (double)dropped / (double)sent_shards;
}

// Arm a re-handshake. CTRL_LOST is assigned here and consumed by ctrl_timer_cb,
// which resets the hello backoff to 1s and sends a fresh HELLO; the data path
// stops using the stale port list until the new HELLO_ACK installs one.
static void ctrl_enter_lost(struct ev_loop *loop, const char *reason) {
    if (g_ctrl_state != CTRL_RUNNING) return;

    my_time_t now = get_current_time();
    if (g_last_rehandshake_ms != 0 && now - g_last_rehandshake_ms < rehandshake_min_interval_ms) {
        mylog(log_debug, "ctrl: %s inside re-handshake cooldown (%llu ms), not re-entering\n",
              reason, (unsigned long long)(now - g_last_rehandshake_ms));
        return;
    }

    mylog(log_warn, "ctrl: %s, re-handshaking\n", reason);
    g_last_rehandshake_ms = now;
    g_ctrl_state = CTRL_LOST;
    g_hb_miss = 0;
    port_range_mgr.ready = false;
    short_send_window_reset();
    g_hello_retry_sec = 1;
    if (loop && g_ctrl_timer) {
        ev_timer_stop(loop, g_ctrl_timer);
        ev_timer_set(g_ctrl_timer, 1.0, 0.0);
        ev_timer_start(loop, g_ctrl_timer);
    }
}

void data_from_local_or_fec_timeout(conn_info_t &conn_info, int is_time_out) {
    fd64_t &remote_fd64 = conn_info.remote_fd64;
    int &local_listen_fd = conn_info.local_listen_fd;

    char data[buf_len];
    int data_len;
    address_t addr;
    u32_t conv;
    int out_n;
    char **out_arr;
    int *out_len;
    my_time_t *out_delay;
    dest_t dest;
    bool can_send = true;
    if (port_range_mode && port_range_mgr.is_ready()) {
        dest.type = type_fd_addr;
        dest.inner.fd_addr.fd   = conn_info.remote_fd;
        dest.inner.fd_addr.addr = port_range_mgr.next_dest();
        dest.cook = 1;
    } else if (port_range_mode) {
        // Handshake not complete yet — we have no valid dest, so the output will
        // be dropped below. But we must NOT early-return: the local_listen fd is
        // level-triggered, so returning without recvfrom-draining it busy-loops at
        // 100% CPU; and the FEC timeout timer is one-shot, so skipping its flush
        // strands the half-filled encode group. Fall through, process input, drop
        // output.
        can_send = false;
    } else {
        dest.type = type_fd64;
        dest.inner.fd64 = remote_fd64;
        dest.cook = 1;
    }

    if (is_time_out) {
        // fd64_t fd64=events[idx].data.u64;
        mylog(log_trace, "events[idx].data.u64 == conn_info.fec_encode_manager.get_timer_fd64()\n");

        // uint64_t value;
        // if(!fd_manager.exist(fd64))   //fd64 has been closed
        //{
        //	mylog(log_trace,"!fd_manager.exist(fd64)");
        //	continue;
        // }
        // if((ret=read(fd_manager.to_fd(fd64), &value, 8))!=8)
        //{
        //	mylog(log_trace,"(ret=read(fd_manager.to_fd(fd64), &value, 8))!=8,ret=%d\n",ret);
        //	continue;
        // }
        // if(value==0)
        //{
        //	mylog(log_debug,"value==0\n");
        //	continue;
        // }
        // assert(value==1);
        from_normal_to_fec(conn_info, 0, 0, out_n, out_arr, out_len, out_delay);
    } else  // events[idx].data.u64 == (u64_t)local_listen_fd
    {
        mylog(log_trace, "events[idx].data.u64 == (u64_t)local_listen_fd\n");
        address_t::storage_t udp_new_addr_in = {0};
        socklen_t udp_new_addr_len = sizeof(address_t::storage_t);
        if ((data_len = recvfrom(local_listen_fd, data, max_data_len + 1, 0,
                                 (struct sockaddr *)&udp_new_addr_in, &udp_new_addr_len)) == -1) {
            mylog(log_debug, "recv_from error,this shouldnt happen,err=%s,but we can try to continue\n", get_sock_error());
            return;
        };

        if (data_len == max_data_len + 1) {
            mylog(log_warn, "huge packet from upper level, data_len > %d, packet truncated, dropped\n", max_data_len);
            return;
        }

        if (!disable_mtu_warn && data_len >= mtu_warn) {
            mylog(log_warn, "huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ", data_len, mtu_warn);
        }

        addr.from_sockaddr((struct sockaddr *)&udp_new_addr_in, udp_new_addr_len);

        mylog(log_trace, "Received packet from %s, len: %d\n", addr.get_str(), data_len);

        // u64_t u64=ip_port.to_u64();

        if (!conn_info.conv_manager.c.is_data_used(addr)) {
            if (conn_info.conv_manager.c.get_size() >= max_conv_num) {
                mylog(log_warn, "ignored new udp connect bc max_conv_num exceed\n");
                return;
            }
            conv = conn_info.conv_manager.c.get_new_conv();
            conn_info.conv_manager.c.insert_conv(conv, addr);
            mylog(log_info, "new packet from %s,conv_id=%x\n", addr.get_str(), conv);
        } else {
            conv = conn_info.conv_manager.c.find_conv_by_data(addr);
            mylog(log_trace, "conv=%d\n", conv);
        }
        conn_info.conv_manager.c.update_active_time(conv);
        char *new_data;
        int new_len;
        put_conv(conv, data, data_len, new_data, new_len);

        mylog(log_trace, "data_len=%d new_len=%d\n", data_len, new_len);
        from_normal_to_fec(conn_info, new_data, new_len, out_n, out_arr, out_len, out_delay);
    }
    mylog(log_trace, "out_n=%d\n", out_n);
    if (can_send) {
        for (int i = 0; i < out_n; i++) {
            delay_send(out_delay[i], dest, out_arr[i], out_len[i]);
        }
    }
}
static void local_listen_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    data_from_local_or_fec_timeout(conn_info, 0);
}

static void remote_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    if (!fd_manager.exist(watcher->u64))  // fd64 has been closed
    {
        mylog(log_trace, "!fd_manager.exist(events[idx].data.u64)");
        return;
    }
    fd64_t &remote_fd64 = conn_info.remote_fd64;
    int &remote_fd = conn_info.remote_fd;

    assert(watcher->u64 == remote_fd64);

    int fd = fd_manager.to_fd(remote_fd64);

    static char batch_bufs[IO_BATCH_MAX][buf_len];
    static struct iovec batch_iov[IO_BATCH_MAX];
    static struct mmsghdr batch_msgs[IO_BATCH_MAX];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < IO_BATCH_MAX; i++) {
            batch_iov[i].iov_base = batch_bufs[i];
            batch_iov[i].iov_len = buf_len;
            memset(&batch_msgs[i], 0, sizeof(batch_msgs[i]));
            batch_msgs[i].msg_hdr.msg_iov = &batch_iov[i];
            batch_msgs[i].msg_hdr.msg_iovlen = 1;
        }
        init = true;
    }

    int nrecv = recvmmsg(fd, batch_msgs, io_batch_size, MSG_DONTWAIT, NULL);
    if (nrecv <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            if (get_sock_errno() == ECONNREFUSED) {
                mylog(log_debug, "recvmmsg ECONNREFUSED fd%d\n", remote_fd);
            } else {
                mylog(log_warn, "recvmmsg failed fd%d errno:%s\n", remote_fd, get_sock_error());
            }
        }
        return;
    }

    my_send_batch_begin();
    for (int p = 0; p < nrecv; p++) {
        int data_len = (int)batch_msgs[p].msg_len;
        char *data = batch_bufs[p];

        if (data_len == buf_len) {
            mylog(log_warn, "huge packet, data_len >= %d, packet truncated, dropped\n", buf_len);
            continue;
        }
        mylog(log_trace, "received data from udp fd %d, len=%d\n", remote_fd, data_len);
        if (!disable_mtu_warn && data_len > mtu_warn) {
            mylog(log_warn, "huge packet,data len=%d (>%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ", data_len, mtu_warn);
        }
        // The data socket is connected in normal mode, so the source of an
        // inbound datagram is the configured -r peer. In port-range mode it is
        // unconnected and replies arrive from varying server data ports with
        // no per-datagram name here (recvmmsg is called without msg_name), so
        // we log the configured server address (ctrl_addr) as an accepted
        // approximation rather than invent a source.
        const address_t &tamper_src = port_range_mode ? ctrl_addr : remote_addr;
        if (de_cook(data, data_len, &tamper_src) != 0) {
            mylog(log_debug, "de_cook error");
            continue;
        }

        int out_n;
        char **out_arr;
        int *out_len;
        my_time_t *out_delay;
        from_fec_to_normal(conn_info, data, data_len, out_n, out_arr, out_len, out_delay);

        mylog(log_trace, "out_n=%d\n", out_n);

        for (int i = 0; i < out_n; i++) {
            u32_t conv;
            char *new_data;
            int new_len;
            if (get_conv(conv, out_arr[i], out_len[i], new_data, new_len) != 0) {
                mylog(log_debug, "get_conv(conv,out_arr[i],out_len[i],new_data,new_len)!=0");
                continue;
            }
            if (!conn_info.conv_manager.c.is_conv_used(conv)) {
                mylog(log_trace, "!conn_info.conv_manager.is_conv_used(conv)");
                continue;
            }

            conn_info.conv_manager.c.update_active_time(conv);

            address_t addr = conn_info.conv_manager.c.find_data_by_conv(conv);
            dest_t dest;
            dest.inner.fd_addr.fd = conn_info.local_listen_fd;
            dest.inner.fd_addr.addr = addr;
            dest.type = type_fd_addr;

            delay_send(out_delay[i], dest, new_data, new_len);
        }
    }
    my_send_flush();
}

static void fifo_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));
    int fifo_fd = watcher->fd;

    char buf[buf_len];
    int len = read(fifo_fd, buf, sizeof(buf));
    if (len < 0) {
        mylog(log_warn, "fifo read failed len=%d,errno=%s\n", len, get_sock_error());
        return;
    }
    buf[len] = 0;
    handle_command(buf);
}

static void delay_manager_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    // uint64_t value;
    // read(delay_manager.get_timer_fd(), &value, 8);
    // mylog(log_trace,"events[idx].data.u64 == (u64_t)delay_manager.get_timer_fd()\n");

    // do nothing
}

static void fec_encode_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    data_from_local_or_fec_timeout(conn_info, 1);
}

static void conn_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    uint64_t value;

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    // read(conn_info.timer.get_timer_fd(), &value, 8);
    conn_info.conv_manager.c.clear_inactive();
    mylog(log_trace, "events[idx].data.u64==(u64_t)conn_info.timer.get_timer_fd()\n");

    conn_info.stat.report_as_client();
    ctrl_replay_report(false);

    // Rotate the data-port round-robin base within the HELLO_ACK-installed
    // list. Index bookkeeping only: no socket is opened/closed and fd_idx is
    // untouched. Boundaries are quantized to this 400ms tick.
    if (port_range_mode && g_crypto_cfg.rotate_sec > 0 && port_range_mgr.is_ready()) {
        my_time_t now_ms = get_current_time();
        my_time_t rotate_ms = (my_time_t)g_crypto_cfg.rotate_sec * 1000;
        if (g_rotate_next_ms == 0) {
            g_rotate_next_ms = now_ms + rotate_ms;
        } else if (now_ms >= g_rotate_next_ms) {
            port_range_mgr.rotate_step();
            g_rotate_next_ms += rotate_ms;
            if (g_rotate_next_ms <= now_ms) g_rotate_next_ms = now_ms + rotate_ms;
        }
    }

    // Interference detection (G9). Port-range mode only (normal mode has no
    // control handshake to redo) and only while RUNNING, so a handshake already
    // in flight is never re-entered; the 30s floor lives in ctrl_enter_lost().
    if (port_range_mode && g_ctrl_state == CTRL_RUNNING) {
        my_time_t now = get_current_time();

        // Sampled every tick so the window stays continuous even when this
        // tick triggers on the FEC signal.
        double short_ratio = short_send_window_ratio(
            now, short_send_drop_count, conn_info.stat.normal_to_fec.output_packet_num);

        u64_t expected = 0, received = 0;
        fec_loss_window_get(expected, received);
        if (expected >= (u64_t)fec_loss_min_expected_shards &&
            received * 5 < expected * 4) {  // pre-recovery loss > 20%
            mylog(log_debug, "ctrl: inbound FEC loss %llu/%llu shards over 5s\n",
                  (unsigned long long)received, (unsigned long long)expected);
            ctrl_enter_lost(loop, "sustained inbound FEC loss > 20% over 5s");
        } else if (short_ratio > loss_trigger_ratio) {
            mylog(log_debug, "ctrl: short-send drop ratio %.1f%% over 5s\n", short_ratio * 100.0);
            ctrl_enter_lost(loop, "short-send drops > 20% over 5s");
        }
    }

    if (debug_force_flush_fec) {
        int out_n;
        char **out_arr;
        int *out_len;
        my_time_t *out_delay;
        dest_t dest;
        dest.type = type_fd64;
        dest.inner.fd64 = conn_info.remote_fd64;
        dest.cook = 1;
        from_normal_to_fec(conn_info, 0, 0, out_n, out_arr, out_len, out_delay);
        for (int i = 0; i < out_n; i++) {
            delay_send(out_delay[i], dest, out_arr[i], out_len[i]);
        }
    }
}

static void prepare_cb(struct ev_loop *loop, struct ev_prepare *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    delay_manager.check();
}

static void ctrl_send_hello() {
    ctrl_hello_payload_t hello;
    memcpy(hello.session_id, g_session_id, 16);
    // v3 HELLO payload = struct + 2-byte capability, inside the MAC range.
    char payload[sizeof(ctrl_hello_payload_t) + sizeof(ctrl_cap_t)];
    memcpy(payload, &hello, sizeof(hello));
    ctrl_cap_t cap;
    cap.cipher     = (uint8_t)g_crypto_cfg.cipher;
    cap.pad_bucket = (uint8_t)g_crypto_cfg.pad_bucket;
    memcpy(payload + sizeof(hello), &cap, sizeof(cap));
    int out_len;
    char *pkt = ctrl_encode(CTRL_HELLO, payload, sizeof(payload), &out_len);
    if (!pkt) return;
    sendto(g_ctrl_fd, pkt, out_len, 0,
           (struct sockaddr *)&g_ctrl_server_stor, g_ctrl_server_len);
    mylog(log_debug, "ctrl: sent HELLO (cipher=%d pad_bucket=%d)\n",
          cap.cipher, cap.pad_bucket);
}

static void ctrl_send_heartbeat() {
    ctrl_hb_payload_t hb;
    memcpy(hb.session_id, g_session_id, 16);
    int out_len;
    char *pkt = ctrl_encode(CTRL_HEARTBEAT, &hb, sizeof(hb), &out_len);
    if (!pkt) return;
    sendto(g_ctrl_fd, pkt, out_len, 0,
           (struct sockaddr *)&g_ctrl_server_stor, g_ctrl_server_len);
    mylog(log_debug, "ctrl: sent HEARTBEAT\n");
}

// ev_timer callback: single-shot hello retry / periodic heartbeat
static void ctrl_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    ctrl_replay_expire(get_current_time());

    if (g_ctrl_state == CTRL_HANDSHAKING) {
        ctrl_send_hello();
        // Double without overflowing, including when the configured cap is INT_MAX.
        g_hello_retry_sec = g_hello_retry_sec > hello_retry_max_sec / 2
                                ? hello_retry_max_sec : g_hello_retry_sec * 2;
        ev_timer_stop(loop, watcher);
        ev_timer_set(watcher, (double)g_hello_retry_sec, 0.0);
        ev_timer_start(loop, watcher);
        mylog(log_debug, "ctrl: next HELLO retry in %d seconds\n", g_hello_retry_sec);
    } else if (g_ctrl_state == CTRL_RUNNING) {
        ctrl_send_heartbeat();
        g_hb_miss++;
        if (g_hb_miss >= heartbeat_loss_threshold) {
            static char hb_reason[64];
            snprintf(hb_reason, sizeof(hb_reason), "%d heartbeats missed", g_hb_miss);
            ctrl_enter_lost(loop, hb_reason);
        }
    } else if (g_ctrl_state == CTRL_LOST) {
        mylog(log_info, "ctrl: starting fresh handshake (hello backoff reset to 1s)\n");
        g_ctrl_state = CTRL_HANDSHAKING;
        g_hb_miss = 0;
        port_range_mgr.ready = false;
        g_hello_retry_sec = 1;
        ev_timer_stop(loop, watcher);
        ev_timer_set(watcher, 1.0, 0.0);
        ev_timer_start(loop, watcher);
        ctrl_send_hello();
    }
}

// ev_io callback: receive on control socket
static void ctrl_remote_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));
    (void)watcher;

    static char buf[CTRL_BUF_MAX];
    address_t::storage_t src_stor;
    socklen_t src_len = sizeof(src_stor);
    int len = recvfrom(g_ctrl_fd, buf, sizeof(buf) - 1, 0,
                       (struct sockaddr *)&src_stor, &src_len);
    if (len <= 0) return;

    address_t src;
    src.from_sockaddr((struct sockaddr *)&src_stor, src_len);

    uint8_t *payload;
    int payload_len;
    ctrl_hdr_t hdr;
    int msg_type = ctrl_decode(buf, len, &payload, &payload_len, &hdr);
    if (msg_type < 0) {
        auth_drop_note(auth_plane_control, &src);
        return;
    }

    if (msg_type == CTRL_HELLO_ACK || msg_type == CTRL_HEARTBEAT_ACK) {
        if (msg_type == CTRL_HELLO_ACK && payload_len < (int)sizeof(ctrl_hello_ack_hdr_t)) return;
        if (msg_type == CTRL_HEARTBEAT_ACK && payload_len < 16) return;
        if (!(src == ctrl_addr) || memcmp(payload, g_session_id, 16) != 0) {
            static my_time_t last_ack_drop_log = 0;
            my_time_t now = get_current_time();
            if (now - last_ack_drop_log > 1000) {  // rate-limit to 1/s
                last_ack_drop_log = now;
                mylog(log_debug, "ctrl: dropped ACK with unexpected source or session\n");
            }
            return;
        }
        if (!ctrl_replay_accept(g_session_id, hdr.nonce, hdr.timestamp_ms)) return;
    }

    if (msg_type == CTRL_HELLO_ACK && g_ctrl_state == CTRL_HANDSHAKING) {
        int min_sz = (int)(sizeof(ctrl_hello_ack_hdr_t));
        if (payload_len < min_sz) return;
        ctrl_hello_ack_hdr_t *ack = (ctrl_hello_ack_hdr_t *)payload;
        int n = (int)ack->port_count;
        if (n < 1 || n > 256) return;
        // v3 payload = ack_hdr + n*2 ports + 2-byte cap, all inside the MAC
        // range; one shared length gates both the ports and the cap reads.
        int expect = min_sz + n * 2 + (int)sizeof(ctrl_cap_t);
        if (payload_len != expect) return;

        uint16_t *ports = (uint16_t *)(payload + sizeof(ctrl_hello_ack_hdr_t));
        ctrl_cap_t srv_cap;
        memcpy(&srv_cap, payload + sizeof(ctrl_hello_ack_hdr_t) + n * 2, sizeof(srv_cap));
        if (srv_cap.cipher != (uint8_t)g_crypto_cfg.cipher ||
            srv_cap.pad_bucket != (uint8_t)g_crypto_cfg.pad_bucket) {
            static my_time_t last_cap_mismatch_log = 0;
            my_time_t now = get_current_time();
            if (now - last_cap_mismatch_log > 1000) {  // rate-limit to 1/s
                last_cap_mismatch_log = now;
                mylog(log_warn,
                      "ctrl: server capability mismatch (server cipher=%d pad_bucket=%d, "
                      "local cipher=%d pad_bucket=%d); refusing ports\n",
                      srv_cap.cipher, srv_cap.pad_bucket,
                      (int)g_crypto_cfg.cipher, (int)g_crypto_cfg.pad_bucket);
            }
            return;
        }

        // base addr = server's ctrl addr but we just need the IP
        address_t base = ctrl_addr;
        port_range_mgr.set_from_ack(ports, n, base);

        if (g_crypto_cfg.rotate_sec > 0) {
            g_rotate_next_ms = get_current_time() + (my_time_t)g_crypto_cfg.rotate_sec * 1000;
            mylog(log_info, "port-range: data-port rotation every %d s over %d advertised ports\n",
                  g_crypto_cfg.rotate_sec, n);
        } else {
            g_rotate_next_ms = 0;
        }

        g_ctrl_state = CTRL_RUNNING;
        g_hello_retry_sec = 1;
        g_hb_miss = 0;
        mylog(log_info, "ctrl: HELLO_ACK received — %d data ports, port-range-mode active\n", n);

        // Switch timer to heartbeat interval
        ev_timer *t = (ev_timer *)loop;  // need handle — passed via watcher->data
        ev_timer *ht = (ev_timer *)watcher->data;
        if (ht) {
            ev_timer_stop(loop, ht);
            ev_timer_set(ht, (double)heartbeat_interval_sec, (double)heartbeat_interval_sec);
            ev_timer_start(loop, ht);
        }

    } else if (msg_type == CTRL_HEARTBEAT_ACK && g_ctrl_state == CTRL_RUNNING) {
        g_hb_miss = 0;
        mylog(log_debug, "ctrl: HEARTBEAT_ACK received\n");
    }
}

int tunnel_client_event_loop() {
    int i, j, k;
    int ret;
    int yes = 1;
    // int epoll_fd;

    conn_info_t *conn_info_p = new conn_info_t;
    conn_info_t &conn_info = *conn_info_p;  // huge size of conn_info,do not allocate on stack

    int &local_listen_fd = conn_info.local_listen_fd;
    new_listen_socket2(local_listen_fd, local_addr);

    // epoll_fd = epoll_create1(0);
    // assert(epoll_fd>0);

    // const int max_events = 4096;
    // struct epoll_event ev, events[max_events];
    // if (epoll_fd < 0) {
    //	mylog(log_fatal,"epoll return %d\n", epoll_fd);
    //	myexit(-1);
    // }

    struct ev_loop *loop = ev_default_loop(0);
    assert(loop != NULL);

    conn_info.loop = loop;

    // ev.events = EPOLLIN;
    // ev.data.u64 = local_listen_fd;
    // ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, local_listen_fd, &ev);
    // if (ret!=0) {
    //	mylog(log_fatal,"add  udp_listen_fd error\n");
    //	myexit(-1);
    // }
    struct ev_io local_listen_watcher;
    local_listen_watcher.data = &conn_info;

    ev_io_init(&local_listen_watcher, local_listen_cb, local_listen_fd, EV_READ);
    ev_io_start(loop, &local_listen_watcher);

    int &remote_fd = conn_info.remote_fd;
    fd64_t &remote_fd64 = conn_info.remote_fd64;

    struct ev_io remote_watcher;
    ev_io ctrl_watcher_client;
    ev_timer ctrl_timer;

    if (port_range_mode) {
        // The family comes from --control-host, NOT from -r. set_from_ack()
        // below builds every data-port destination from ctrl_addr as its base,
        // and remote_addr is not used on this path in port-range mode -- a
        // reader will assume -r is the source of truth, and it is not.
        address_t bind_addr;
        outbound_bind_addr(bind_addr, ctrl_addr);

        // Unconnected data socket — sendto with varying dst port
        assert(new_listen_socket2(remote_fd, bind_addr, out_interface) == 0);
        remote_fd64 = fd_manager.create(remote_fd);

        // Control socket. Both sockets are outbound to the same server, so
        // both take --out-addr and --out-interface; restricting only one would
        // be meaningless. Binding both to the same address is safe because
        // --out-addr's port is required to be 0 in port-range mode (validated
        // in process_arg); a fixed port would fail here with EADDRINUSE.
        assert(new_listen_socket2(g_ctrl_fd, bind_addr, out_interface) == 0);
        memset(&g_ctrl_server_stor, 0, sizeof(g_ctrl_server_stor));
        g_ctrl_server_len = ctrl_addr.get_len();
        memcpy(&g_ctrl_server_stor, &ctrl_addr.inner, g_ctrl_server_len);

        // Seed session_id
        uint64_t r1 = get_fake_random_number_64();
        uint64_t r2 = get_fake_random_number_64();
        memcpy(g_session_id,     &r1, 8);
        memcpy(g_session_id + 8, &r2, 8);

        // Register control recv watcher
        ctrl_watcher_client.data = &ctrl_timer;
        ev_io_init(&ctrl_watcher_client, ctrl_remote_cb, g_ctrl_fd, EV_READ);
        ev_io_start(loop, &ctrl_watcher_client);

        // Handshake timer (1s initial interval)
        ev_init(&ctrl_timer, ctrl_timer_cb);
        g_ctrl_timer = &ctrl_timer;
        g_hello_retry_sec = 1;
        ev_timer_set(&ctrl_timer, 1.0, 0.0);
        ev_timer_start(loop, &ctrl_timer);

        g_ctrl_state = CTRL_HANDSHAKING;
        ctrl_send_hello();
        mylog(log_info, "port-range-mode: sent initial HELLO to %s\n", ctrl_addr.get_str());
    } else {
        assert(new_connected_socket2(remote_fd, remote_addr, out_addr, out_interface) == 0);
        remote_fd64 = fd_manager.create(remote_fd);
        mylog(log_debug, "remote_fd64=%llu\n", remote_fd64);
    }

    remote_watcher.data = &conn_info;
    remote_watcher.u64 = remote_fd64;
    ev_io_init(&remote_watcher, remote_cb, remote_fd, EV_READ);
    ev_io_start(loop, &remote_watcher);

    // ev.events = EPOLLIN;
    // ev.data.u64 = delay_manager.get_timer_fd();

    // mylog(log_debug,"delay_manager.get_timer_fd()=%d\n",delay_manager.get_timer_fd());
    // ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, delay_manager.get_timer_fd(), &ev);
    // if (ret!= 0) {
    //	mylog(log_fatal,"add delay_manager.get_timer_fd() error\n");
    //	myexit(-1);
    // }

    delay_manager.set_loop_and_cb(loop, delay_manager_cb);

    conn_info.fec_encode_manager.set_data(&conn_info);
    conn_info.fec_encode_manager.set_loop_and_cb(loop, fec_encode_cb);

    // u64_t tmp_fd64=conn_info.fec_encode_manager.get_timer_fd64();
    // ev.events = EPOLLIN;
    // ev.data.u64 = tmp_fd64;

    // mylog(log_debug,"conn_info.fec_encode_manager.get_timer_fd64()=%llu\n",conn_info.fec_encode_manager.get_timer_fd64());
    // ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd_manager.to_fd(tmp_fd64), &ev);
    // if (ret!= 0) {
    //	mylog(log_fatal,"add fec_encode_manager.get_timer_fd64() error\n");
    //	myexit(-1);
    // }

    conn_info.timer.data = &conn_info;
    ev_init(&conn_info.timer, conn_timer_cb);
    ev_timer_set(&conn_info.timer, 0, timer_interval / 1000.0);
    ev_timer_start(loop, &conn_info.timer);
    // conn_info.timer.add_fd_to_epoll(epoll_fd);
    // conn_info.timer.set_timer_repeat_us(timer_interval*1000);

    // mylog(log_debug,"conn_info.timer.get_timer_fd()=%d\n",conn_info.timer.get_timer_fd());

    struct ev_io fifo_watcher;

    int fifo_fd = -1;

    if (fifo_file[0] != 0) {
        fifo_fd = create_fifo(fifo_file);
        // ev.events = EPOLLIN;
        // ev.data.u64 = fifo_fd;

        // ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fifo_fd, &ev);
        // if (ret!= 0) {
        //	mylog(log_fatal,"add fifo_fd to epoll error %s\n",strerror(errno));
        //	myexit(-1);
        // }
        mylog(log_info, "fifo_file=%s\n", fifo_file);

        ev_io_init(&fifo_watcher, fifo_cb, fifo_fd, EV_READ);
        ev_io_start(loop, &fifo_watcher);
    }

    ev_prepare prepare_watcher;
    ev_init(&prepare_watcher, prepare_cb);
    ev_prepare_start(loop, &prepare_watcher);

    mylog(log_info, "now listening at %s\n", local_addr.get_str());

    ev_run(loop, 0);

    mylog(log_warn, "ev_run returned\n");
    ctrl_replay_report(true);
    auth_drop_flush();
    myexit(0);

    /*
    while(1)////////////////////////
    {
            if(about_to_exit) myexit(0);

            int nfds = epoll_wait(epoll_fd, events, max_events, 180 * 1000);
            if (nfds < 0) {  //allow zero
                    if(errno==EINTR  )
                    {
                            mylog(log_info,"epoll interrupted by signal continue\n");
                    }
                    else
                    {
                            mylog(log_fatal,"epoll_wait return %d,%s\n", nfds,strerror(errno));
                            myexit(-1);
                    }
            }
            int idx;
            for (idx = 0; idx < nfds; ++idx) {
                    if(events[idx].data.u64==(u64_t)conn_info.timer.get_timer_fd())
                    {

                    }

                    else if (events[idx].data.u64 == (u64_t)fifo_fd)
                    {

                    }
                    else if (events[idx].data.u64 == (u64_t)local_listen_fd||events[idx].data.u64 == conn_info.fec_encode_manager.get_timer_fd64())
                    {

                    }
                else if (events[idx].data.u64 == (u64_t)delay_manager.get_timer_fd()) {

                    }
                    else if(events[idx].data.u64>u32_t(-1) )
                    {

                    }
                    else
                    {
                            mylog(log_fatal,"unknown fd,this should never happen\n");
                            myexit(-1);
                    }
            }
            //delay_manager.check();
    }*/
    return 0;
}

// Control-plane negative matrix. Included here (not in test_mode.cpp) because
// it drives this file's static ACK gate and client control state; only
// --test-selftest ever calls control_plane_selftest().
#include "tests/control_plane_selftest.h"
