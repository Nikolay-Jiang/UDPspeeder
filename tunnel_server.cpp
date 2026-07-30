/*
 * tunnel.cpp
 *
 *  Created on: Oct 26, 2017
 *      Author: root
 */

#include "tunnel.h"
#include "control_proto.h"
#include <vector>

// port-range-mode: server data fds indexed by fd_idx
static std::vector<int> g_data_fds;

static void conn_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
static void fec_encode_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);
static void remote_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

enum tmp_mode_t { is_from_remote = 0,
                  is_fec_timeout,
                  is_conn_timer };

void data_from_remote_or_fec_timeout_or_conn_timer(conn_info_t &conn_info, fd64_t fd64, tmp_mode_t mode) {
    int ret;

    char data[buf_len];
    int data_len;
    u32_t conv;
    // fd64_t fd64=events[idx].data.u64;
    // mylog(log_trace,"events[idx].data.u64 >u32_t(-1),%llu\n",(u64_t)events[idx].data.u64);

    // assert(fd_manager.exist_info(fd64));
    // ip_port_t ip_port=fd_manager.get_info(fd64).ip_port;

    // conn_info_t &conn_info=conn_manager.find(ip_port);
    address_t &addr = conn_info.addr;
    assert(conn_manager.exist(addr));

    int &local_listen_fd = conn_info.local_listen_fd;

    int out_n = -2;
    char **out_arr;
    int *out_len;
    my_time_t *out_delay;

    dest_t dest;
    if (port_range_mode && !conn_info.active_endpoints.empty()) {
        conn_info_t::nat_endpoint_t *ep = conn_info.pick_next_endpoint(nat_keepalive_sec);
        dest.inner.fd_addr.fd  = g_data_fds[ep->fd_idx];
        dest.inner.fd_addr.addr = ep->addr;
    } else {
        dest.inner.fd_addr.fd  = local_listen_fd;
        dest.inner.fd_addr.addr = addr;
    }
    dest.type = type_fd_addr;
    dest.cook = 1;

    if (mode == is_fec_timeout) {
        assert(fd64 == 0);
        // uint64_t value;
        // if((ret=read(fd_manager.to_fd(fd64), &value, 8))!=8)
        //{
        //	mylog(log_trace,"fd_manager.to_fd(fd64), &value, 8)!=8 ,%d\n",ret);
        //	continue;
        // }
        // if(value==0)
        //{
        //	mylog(log_trace,"value==0\n");
        //	continue;
        // }
        // assert(value==1);
        from_normal_to_fec(conn_info, 0, 0, out_n, out_arr, out_len, out_delay);
    } else if (mode == is_conn_timer) {
        assert(fd64 == 0);
        // uint64_t value;
        // read(conn_info.timer.get_timer_fd(), &value, 8);
        conn_info.conv_manager.s.clear_inactive();
        if (debug_force_flush_fec) {
            from_normal_to_fec(conn_info, 0, 0, out_n, out_arr, out_len, out_delay);
        }

        conn_info.stat.report_as_server(addr);
        return;
    } else if (mode == is_from_remote) {
        if (!fd_manager.exist(fd64))  // fd64 has been closed
        {
            mylog(log_warn, "!fd_manager.exist(fd64)\n");
            return;
        }

        // fd64_t &fd64 =conn_info.remote_fd64;
        assert(conn_info.conv_manager.s.is_data_used(fd64));

        conv = conn_info.conv_manager.s.find_conv_by_data(fd64);
        conn_info.conv_manager.s.update_active_time(conv);
        conn_info.update_active_time();

        int fd = fd_manager.to_fd(fd64);
        data_len = recv(fd, data, max_data_len + 1, 0);

        if (data_len == max_data_len + 1) {
            mylog(log_warn, "huge packet from upper level, data_len > %d, packet truncated, dropped\n", max_data_len);
            return;
        }

        mylog(log_trace, "received a packet from udp_fd,len:%d,conv=%d\n", data_len, conv);

        if (data_len < 0) {
            mylog(log_debug, "udp fd,recv_len<0 continue,%s\n", get_sock_error());

            return;
        }

        if (!disable_mtu_warn && data_len >= mtu_warn) {
            mylog(log_warn, "huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ", data_len, mtu_warn);
        }

        char *new_data;
        int new_len;
        put_conv(conv, data, data_len, new_data, new_len);

        from_normal_to_fec(conn_info, new_data, new_len, out_n, out_arr, out_len, out_delay);
    } else {
        assert(0 == 1);
    }

    mylog(log_trace, "out_n=%d\n", out_n);
    for (int i = 0; i < out_n; i++) {
        delay_send(out_delay[i], dest, out_arr[i], out_len[i]);
    }
}

static void local_listen_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    int local_listen_fd = watcher->fd;
    int ret;

    mylog(log_trace, "events[idx].data.u64 == (u64_t)local_listen_fd\n");

    static char batch_bufs[IO_BATCH_MAX][buf_len];
    static struct iovec batch_iov[IO_BATCH_MAX];
    static struct mmsghdr batch_msgs[IO_BATCH_MAX];
    static address_t::storage_t batch_addrs[IO_BATCH_MAX];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < IO_BATCH_MAX; i++) {
            batch_iov[i].iov_base = batch_bufs[i];
            batch_iov[i].iov_len = max_data_len + 1;
            memset(&batch_msgs[i], 0, sizeof(batch_msgs[i]));
            batch_msgs[i].msg_hdr.msg_iov = &batch_iov[i];
            batch_msgs[i].msg_hdr.msg_iovlen = 1;
            batch_msgs[i].msg_hdr.msg_name = &batch_addrs[i];
            batch_msgs[i].msg_hdr.msg_namelen = sizeof(address_t::storage_t);
        }
        init = true;
    }

    // Cap drain rounds so a sustained sender can't keep recvmmsg returning full
    // batches forever and starve the FEC-timeout/delay/heartbeat/other watchers.
    // Up to max_drain_rounds*io_batch_size packets per callback before we yield.
    const int max_drain_rounds = 16;
    for (int drain_round = 0; drain_round < max_drain_rounds; drain_round++) {
    for (int i = 0; i < io_batch_size; i++)
        batch_msgs[i].msg_hdr.msg_namelen = sizeof(address_t::storage_t);

    int nrecv = recvmmsg(local_listen_fd, batch_msgs, io_batch_size, MSG_DONTWAIT, NULL);
    if (nrecv <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            mylog(log_error, "recvmmsg error,err=%s,but we can try to continue\n", get_sock_error());
        break;
    }

    my_send_batch_begin();
    for (int p = 0; p < nrecv; p++) {
        int data_len = (int)batch_msgs[p].msg_len;
        char *data = batch_bufs[p];

        if (data_len == max_data_len + 1) {
            mylog(log_warn, "huge packet, data_len > %d, packet truncated, dropped\n", max_data_len);
            continue;
        }

        address_t addr;
        addr.from_sockaddr((struct sockaddr *)&batch_addrs[p], batch_msgs[p].msg_hdr.msg_namelen);

        mylog(log_trace, "Received packet from %s,len: %d\n", addr.get_str(), data_len);

        if (!disable_mtu_warn && data_len >= mtu_warn)  ///////////////////////delete this for type 0 in furture
        {
            mylog(log_warn, "huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ", data_len, mtu_warn);
        }

        if (de_cook(data, data_len) != 0) {
            mylog(log_debug, "de_cook error");
            continue;
        }

        // Session key. In port-range mode the client sprays one stream across N
        // destination ports; a symmetric nat then hands out a different external
        // source port per destination port, so keying on (ip,port) would split one
        // client into up to N conn_info objects -- fragmenting its fec groups across
        // N decoders and opening N sockets to '-r'. Key on client ip only. The true
        // per-fd source address is kept in active_endpoints and used for replies.
        address_t conn_key = addr;
        if (port_range_mode) conn_key.set_port(0);

        if (!conn_manager.exist(conn_key)) {
            if (conn_manager.mp.size() >= max_conn_num) {
                mylog(log_warn, "new connection %s ignored bc max_conn_num exceed\n", addr.get_str());
                continue;
            }

            conn_info_t &new_conn_info = conn_manager.find_insert(conn_key);
            new_conn_info.addr = conn_key;
            new_conn_info.loop = ev_default_loop(0);
            new_conn_info.local_listen_fd = local_listen_fd;

            new_conn_info.timer.data = &new_conn_info;
            ev_init(&new_conn_info.timer, conn_timer_cb);
            ev_timer_set(&new_conn_info.timer, 0, timer_interval / 1000.0);
            ev_timer_start(loop, &new_conn_info.timer);

            new_conn_info.fec_encode_manager.set_data(&new_conn_info);
            new_conn_info.fec_encode_manager.set_loop_and_cb(loop, fec_encode_cb);

            mylog(log_info, "new connection from %s\n", addr.get_str());
        }

        conn_info_t &conn_info = conn_manager.find_insert(conn_key);
        conn_info.update_active_time();

        if (port_range_mode) {
            int fd_idx = (int)(intptr_t)watcher->data;
            conn_info.record_endpoint(addr, fd_idx);
        }

        int out_n;
        char **out_arr;
        int *out_len;
        my_time_t *out_delay;
        from_fec_to_normal(conn_info, data, data_len, out_n, out_arr, out_len, out_delay);

        mylog(log_trace, "out_n= %d\n", out_n);
        for (int i = 0; i < out_n; i++) {
            u32_t conv;
            char *new_data;
            int new_len;
            if (get_conv(conv, out_arr[i], out_len[i], new_data, new_len) != 0) {
                mylog(log_debug, "get_conv failed");
                continue;
            }

            if (!conn_info.conv_manager.s.is_conv_used(conv)) {
                if (conn_info.conv_manager.s.get_size() >= max_conv_num) {
                    mylog(log_warn, "ignored new udp connect bc max_conv_num exceed\n");
                    continue;
                }

                int new_udp_fd;
                ret = new_connected_socket2(new_udp_fd, remote_addr, out_addr, out_interface);

                if (ret != 0) {
                    mylog(log_warn, "[%s]new_connected_socket failed\n", addr.get_str());
                    continue;
                }

                fd64_t fd64 = fd_manager.create(new_udp_fd);

                conn_info.conv_manager.s.insert_conv(conv, fd64);
                // must be the conn_manager key: server_clear_function() looks the
                // conn_info back up by this address when the conv expires.
                fd_manager.get_info(fd64).addr = conn_key;

                ev_io &io_watcher = fd_manager.get_info(fd64).io_watcher;
                io_watcher.u64 = fd64;
                io_watcher.data = &conn_info;

                ev_init(&io_watcher, remote_cb);
                ev_io_set(&io_watcher, new_udp_fd, EV_READ);
                ev_io_start(conn_info.loop, &io_watcher);

                mylog(log_info, "[%s]new conv %x,fd %d created,fd64=%llu\n", addr.get_str(), conv, new_udp_fd, fd64);
            }
            conn_info.conv_manager.s.update_active_time(conv);
            fd64_t fd64 = conn_info.conv_manager.s.find_data_by_conv(conv);
            dest_t dest;
            dest.type = type_fd64;
            dest.inner.fd64 = fd64;
            delay_send(out_delay[i], dest, new_data, new_len);
        }
    }
    my_send_flush();
    if (nrecv < io_batch_size) break;
    } // drain loop
}

static void remote_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);
    fd64_t fd64 = watcher->u64;

    data_from_remote_or_fec_timeout_or_conn_timer(conn_info, fd64, is_from_remote);
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

    data_from_remote_or_fec_timeout_or_conn_timer(conn_info, 0, is_fec_timeout);
}

static void conn_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    data_from_remote_or_fec_timeout_or_conn_timer(conn_info, 0, is_conn_timer);
}

static void prepare_cb(struct ev_loop *loop, struct ev_prepare *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    delay_manager.check();
}

static void global_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    assert(!(revents & EV_ERROR));

    // uint64_t value;
    // read(timer.get_timer_fd(), &value, 8);
    conn_manager.clear_inactive();
    mylog(log_trace, "events[idx].data.u64==(u64_t)timer.get_timer_fd()\n");
}

static void control_listen_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    assert(!(revents & EV_ERROR));
    (void)loop;

    int ctrl_fd = watcher->fd;
    static char buf[CTRL_BUF_MAX];
    address_t::storage_t src_stor;
    socklen_t src_len = sizeof(src_stor);

    int len = recvfrom(ctrl_fd, buf, sizeof(buf) - 1, 0,
                       (struct sockaddr *)&src_stor, &src_len);
    if (len <= 0) return;

    uint8_t *payload;
    int payload_len;
    int msg_type = ctrl_decode(buf, len, &payload, &payload_len);
    if (msg_type < 0) return;

    address_t src;
    src.from_sockaddr((struct sockaddr *)&src_stor, src_len);

    if (msg_type == CTRL_HELLO) {
        if (payload_len < (int)sizeof(ctrl_hello_payload_t)) return;
        ctrl_hello_payload_t *hello = (ctrl_hello_payload_t *)payload;

        ctrl_hello_ack_hdr_t ack_hdr;
        memcpy(ack_hdr.session_id, hello->session_id, 16);
        ack_hdr.port_count            = (uint16_t)port_range_mgr.count();
        ack_hdr.heartbeat_interval_ms = (uint32_t)(heartbeat_interval_sec * 1000);
        ack_hdr.session_lifetime_ms   = 0;  // unused in v1

        // Build payload: ack_hdr + ports array
        static char ack_payload[sizeof(ctrl_hello_ack_hdr_t) + 256 * 2];
        memcpy(ack_payload, &ack_hdr, sizeof(ack_hdr));
        for (int i = 0; i < port_range_mgr.count(); i++) {
            uint16_t p = port_range_mgr.ports[i];
            memcpy(ack_payload + sizeof(ack_hdr) + i * 2, &p, 2);
        }
        int ack_payload_len = (int)sizeof(ack_hdr) + port_range_mgr.count() * 2;

        int out_len;
        char *pkt = ctrl_encode(CTRL_HELLO_ACK, ack_payload, ack_payload_len, &out_len);
        if (!pkt) return;

        sendto(ctrl_fd, pkt, out_len, 0,
               (struct sockaddr *)&src_stor, src_len);
        mylog(log_info, "ctrl: HELLO from %s, sent HELLO_ACK (%d ports)\n",
              src.get_str(), port_range_mgr.count());

    } else if (msg_type == CTRL_HEARTBEAT) {
        if (payload_len < (int)sizeof(ctrl_hb_payload_t)) return;
        ctrl_hb_payload_t *hb = (ctrl_hb_payload_t *)payload;

        ctrl_hb_payload_t hb_ack;
        memcpy(hb_ack.session_id, hb->session_id, 16);

        int out_len;
        char *pkt = ctrl_encode(CTRL_HEARTBEAT_ACK, &hb_ack, sizeof(hb_ack), &out_len);
        if (!pkt) return;

        sendto(ctrl_fd, pkt, out_len, 0,
               (struct sockaddr *)&src_stor, src_len);
        mylog(log_debug, "ctrl: HEARTBEAT from %s\n", src.get_str());

    } else if (msg_type == CTRL_BYE) {
        mylog(log_info, "ctrl: BYE from %s\n", src.get_str());
    }
}

int tunnel_server_event_loop() {
    int i, j, k;
    int ret;
    int yes = 1;
    // int epoll_fd;
    // int remote_fd;

    struct ev_loop *loop = ev_default_loop(0);
    assert(loop != NULL);

    // Dynamically allocated watchers for port-range-mode data + control fds.
    std::vector<ev_io *> data_watchers;
    ev_io ctrl_watcher;
    int local_listen_fd = -1;
    struct ev_io local_listen_watcher;

    if (port_range_mode) {
        // Build a valid 0.0.0.0 base address for binding; local_addr may be
        // unset when -l is omitted in port-range-mode server.
        address_t bind_base;
        if (local_addr.is_vaild()) {
            bind_base = local_addr;
        } else {
            u32_t any = INADDR_ANY;
            bind_base.from_ip_port_new(AF_INET, &any, 0);
        }

        // Bind control socket
        int ctrl_fd;
        address_t ctrl_bind_addr = bind_base;
        ctrl_bind_addr.set_port(ctrl_port);
        if (new_listen_socket2(ctrl_fd, ctrl_bind_addr) != 0) {
            mylog(log_fatal, "failed to bind control port %d\n", ctrl_port);
            myexit(-1);
        }
        ev_io_init(&ctrl_watcher, control_listen_cb, ctrl_fd, EV_READ);
        ev_io_start(loop, &ctrl_watcher);
        mylog(log_info, "port-range-mode: control port %d listening\n", ctrl_port);

        // Bind N data sockets
        g_data_fds.clear();
        for (int i = 0; i < port_range_mgr.count(); i++) {
            int dfd;
            address_t data_bind = bind_base;
            data_bind.set_port(port_range_mgr.ports[i]);
            if (new_listen_socket2(dfd, data_bind) != 0) {
                mylog(log_fatal, "failed to bind data port %d\n", port_range_mgr.ports[i]);
                myexit(-1);
            }
            g_data_fds.push_back(dfd);

            ev_io *dw = new ev_io;
            dw->data = (void *)(intptr_t)i;  // fd_idx
            ev_io_init(dw, local_listen_cb, dfd, EV_READ);
            ev_io_start(loop, dw);
            data_watchers.push_back(dw);
        }
        mylog(log_info, "port-range-mode: %d data ports listening (%s)\n",
              port_range_mgr.count(), data_port_range_str);
    } else {
        new_listen_socket2(local_listen_fd, local_addr);
        ev_io_init(&local_listen_watcher, local_listen_cb, local_listen_fd, EV_READ);
        ev_io_start(loop, &local_listen_watcher);
        mylog(log_info, "now listening at %s\n", local_addr.get_str());
    }

    delay_manager.set_loop_and_cb(loop, delay_manager_cb);

    // my_timer_t timer;
    // timer.add_fd_to_epoll(epoll_fd);
    // timer.set_timer_repeat_us(timer_interval*1000);

    ev_timer global_timer;
    ev_init(&global_timer, global_timer_cb);
    ev_timer_set(&global_timer, 0, timer_interval / 1000.0);
    ev_timer_start(loop, &global_timer);

    // mylog(log_debug," timer.get_timer_fd() =%d\n",timer.get_timer_fd());

    struct ev_io fifo_watcher;

    int fifo_fd = -1;

    if (fifo_file[0] != 0) {
        fifo_fd = create_fifo(fifo_file);
        // ev.events = EPOLLIN;
        // ev.data.u64 = fifo_fd;

        // ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fifo_fd, &ev);
        // if (ret!= 0) {
        // mylog(log_fatal,"add fifo_fd to epoll error %s\n",strerror(errno));
        // myexit(-1);
        //}
        ev_io_init(&fifo_watcher, fifo_cb, fifo_fd, EV_READ);
        ev_io_start(loop, &fifo_watcher);

        mylog(log_info, "fifo_file=%s\n", fifo_file);
    }

    ev_prepare prepare_watcher;
    ev_init(&prepare_watcher, prepare_cb);
    ev_prepare_start(loop, &prepare_watcher);

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
                            mylog(log_info,"epoll interrupted by signal,continue\n");
                    }
                    else
                    {
                            mylog(log_fatal,"epoll_wait return %d,%s\n", nfds,strerror(errno));
                            myexit(-1);
                    }
            }
            int idx;
            for (idx = 0; idx < nfds; ++idx)
            {
                    if(events[idx].data.u64==(u64_t)timer.get_timer_fd())
                    {

                    }

                    else if (events[idx].data.u64 == (u64_t)fifo_fd)
                    {

                    }

                    else if (events[idx].data.u64 == (u64_t)local_listen_fd)
                    {


                    }
                else if (events[idx].data.u64 == (u64_t)delay_manager.get_timer_fd()) {

                    }
                    else if (events[idx].data.u64 >u32_t(-1))
                    {


                    }
                    else
                    {
                            mylog(log_fatal,"unknown fd,this should never happen\n");
                            myexit(-1);
                    }
            }

    }*/

    return 0;
}
