#include "tunnel.h"
#include "control_proto.h"

// --- port-range-mode client state machine ---
enum ctrl_state_t { CTRL_IDLE, CTRL_HANDSHAKING, CTRL_RUNNING, CTRL_LOST };
static ctrl_state_t g_ctrl_state = CTRL_IDLE;
static int g_ctrl_fd = -1;
static address_t::storage_t g_ctrl_server_stor;
static socklen_t g_ctrl_server_len = 0;
static int g_hello_miss = 0;     // consecutive heartbeat misses (reused for hello retries)
static int g_hb_miss = 0;

static uint8_t g_session_id[16];  // random, set on first HELLO

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
    if (port_range_mode && port_range_mgr.is_ready()) {
        dest.type = type_fd_addr;
        dest.inner.fd_addr.fd   = conn_info.remote_fd;
        dest.inner.fd_addr.addr = port_range_mgr.next_dest();
        dest.cook = 1;
    } else if (port_range_mode) {
        // Handshake not complete yet — drop
        return;
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
    for (int i = 0; i < out_n; i++) {
        delay_send(out_delay[i], dest, out_arr[i], out_len[i]);
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
            batch_iov[i].iov_len = max_data_len + 1;
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

        if (data_len == max_data_len + 1) {
            mylog(log_warn, "huge packet, data_len > %d, packet truncated, dropped\n", max_data_len);
            continue;
        }
        mylog(log_trace, "received data from udp fd %d, len=%d\n", remote_fd, data_len);
        if (!disable_mtu_warn && data_len > mtu_warn) {
            mylog(log_warn, "huge packet,data len=%d (>%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ", data_len, mtu_warn);
        }
        if (de_cook(data, data_len) != 0) {
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
    int out_len;
    char *pkt = ctrl_encode(CTRL_HELLO, &hello, sizeof(hello), &out_len);
    if (!pkt) return;
    sendto(g_ctrl_fd, pkt, out_len, 0,
           (struct sockaddr *)&g_ctrl_server_stor, g_ctrl_server_len);
    mylog(log_debug, "ctrl: sent HELLO\n");
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

// ev_timer callback: periodic hello retry / heartbeat
static void ctrl_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));
    (void)loop;

    if (g_ctrl_state == CTRL_HANDSHAKING) {
        ctrl_send_hello();
        // Cap retry interval at hello_retry_max_sec via doubling in the caller
    } else if (g_ctrl_state == CTRL_RUNNING) {
        ctrl_send_heartbeat();
        g_hb_miss++;
        if (g_hb_miss >= heartbeat_loss_threshold) {
            mylog(log_warn, "ctrl: %d heartbeats missed, re-handshaking\n", g_hb_miss);
            g_ctrl_state = CTRL_HANDSHAKING;
            g_hb_miss = 0;
            port_range_mgr.ready = false;
            // Reset timer to 1s retry
            ev_timer_stop(loop, watcher);
            ev_timer_set(watcher, 1.0, 1.0);
            ev_timer_start(loop, watcher);
            ctrl_send_hello();
        }
    } else if (g_ctrl_state == CTRL_LOST) {
        g_ctrl_state = CTRL_HANDSHAKING;
        g_hb_miss = 0;
        port_range_mgr.ready = false;
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

    uint8_t *payload;
    int payload_len;
    int msg_type = ctrl_decode(buf, len, &payload, &payload_len);
    if (msg_type < 0) return;

    if (msg_type == CTRL_HELLO_ACK && g_ctrl_state == CTRL_HANDSHAKING) {
        int min_sz = (int)(sizeof(ctrl_hello_ack_hdr_t));
        if (payload_len < min_sz) return;
        ctrl_hello_ack_hdr_t *ack = (ctrl_hello_ack_hdr_t *)payload;
        int n = (int)ack->port_count;
        if (n < 1 || n > 256) return;
        if (payload_len < min_sz + n * 2) return;

        uint16_t *ports = (uint16_t *)(payload + sizeof(ctrl_hello_ack_hdr_t));

        // base addr = server's ctrl addr but we just need the IP
        address_t base = ctrl_addr;
        port_range_mgr.set_from_ack(ports, n, base);

        g_ctrl_state = CTRL_RUNNING;
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
        // Unconnected data socket — sendto with varying dst port
        address_t ephemeral;
        ephemeral.from_str((char *)"0.0.0.0:0");
        assert(new_listen_socket2(remote_fd, ephemeral) == 0);
        remote_fd64 = fd_manager.create(remote_fd);

        // Control socket
        assert(new_listen_socket2(g_ctrl_fd, ephemeral) == 0);
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
        ev_timer_set(&ctrl_timer, 0.0, 1.0);
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
