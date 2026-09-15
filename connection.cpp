/*
 * connection.cpp
 *
 *  Created on: Sep 23, 2017
 *      Author: root
 */

#include "connection.h"

// const int disable_conv_clear=0;//a udp connection in the multiplexer is called conversation in this program,conv for short.

const int disable_conn_clear = 0;  // a raw connection is called conn.

int report_interval = 0;

auth_drop_stat_t g_auth_drop = {0, 0};

// Per-plane throttle state. last_log_ms == 0 means "no line emitted yet", so
// the first failure on a plane always logs instead of being swallowed by the
// initial 10 s window.
struct auth_drop_plane_state_t {
    my_time_t last_log_ms;
    u64_t last_logged_total;
    address_t last_src;
    bool have_src;
};
static auth_drop_plane_state_t g_auth_drop_plane[auth_plane_count];
static const my_time_t auth_drop_interval_ms = 10 * 1000;

static u64_t &auth_drop_total(auth_plane_t plane) {
    return plane == auth_plane_control ? g_auth_drop.control : g_auth_drop.data;
}

static const char *auth_plane_label(auth_plane_t plane) {
    return plane == auth_plane_control ? "control" : "data";
}

static void auth_drop_log(auth_plane_t plane, const address_t *src, my_time_t now) {
    auth_drop_plane_state_t &st = g_auth_drop_plane[plane];
    if (src != 0) {
        st.last_src = *src;
        st.have_src = st.last_src.is_vaild();
    }
    u64_t total = auth_drop_total(plane);
    st.last_log_ms = now;
    st.last_logged_total = total;
    mylog(log_warn, "auth_drop: plane=%s src=%s total=%llu\n", auth_plane_label(plane),
          st.have_src ? st.last_src.get_str() : "?", (unsigned long long)total);
}

void auth_drop_note(auth_plane_t plane, const address_t *src) {
    auth_drop_total(plane)++;
    my_time_t now = get_current_time();
    auth_drop_plane_state_t &st = g_auth_drop_plane[plane];
    if (st.last_log_ms != 0 && now - st.last_log_ms < auth_drop_interval_ms) return;
    auth_drop_log(plane, src, now);
}

void auth_drop_flush() {
    my_time_t now = get_current_time();
    for (int p = 0; p < auth_plane_count; p++) {
        auth_plane_t plane = (auth_plane_t)p;
        u64_t total = auth_drop_total(plane);
        if (total == 0) continue;
        if (g_auth_drop_plane[p].last_logged_total == total) continue;
        auth_drop_log(plane, 0, now);
    }
}

void server_clear_function(u64_t u64)  // used in conv_manager in server mode.for server we have to use one udp fd for one conv(udp connection),
// so we have to close the fd when conv expires
{
    fd64_t fd64 = u64;
    assert(fd_manager.exist(fd64));
    ev_io &watcher = fd_manager.get_info(fd64).io_watcher;

    address_t &addr = fd_manager.get_info(fd64).addr;            //
    assert(conn_manager.exist(addr));                            //
    struct ev_loop *loop = conn_manager.find_insert(addr).loop;  // overkill ? should we just use ev_default_loop(0)?

    ev_io_stop(loop, &watcher);

    fd_manager.fd64_close(fd64);
}

////////////////////////////////////////////////////////////////////

conn_manager_t::conn_manager_t() {
    mp.reserve(10007);
    last_clear_time = 0;
}
int conn_manager_t::exist(address_t addr) {
    if (mp.find(addr) != mp.end()) {
        return 1;
    }
    return 0;
}

conn_info_t *&conn_manager_t::find_insert_p(address_t addr)  // be aware,the adress may change after rehash
{
    // u64_t u64=0;
    // u64=ip;
    // u64<<=32u;
    // u64|=port;
    unordered_map<address_t, conn_info_t *>::iterator it = mp.find(addr);
    if (it == mp.end()) {
        mp[addr] = new conn_info_t;
        // lru.new_key(addr);
    } else {
        // lru.update(addr);
    }
    return mp[addr];
}
conn_info_t &conn_manager_t::find_insert(address_t addr)  // be aware,the adress may change after rehash
{
    // u64_t u64=0;
    // u64=ip;
    // u64<<=32u;
    // u64|=port;
    unordered_map<address_t, conn_info_t *>::iterator it = mp.find(addr);
    if (it == mp.end()) {
        mp[addr] = new conn_info_t;
        // lru.new_key(addr);
    } else {
        // lru.update(addr);
    }
    return *mp[addr];
}
int conn_manager_t::erase(unordered_map<address_t, conn_info_t *>::iterator erase_it) {
    delete (erase_it->second);
    mp.erase(erase_it->first);
    return 0;
}
int conn_manager_t::clear_inactive() {
    if (get_current_time() - last_clear_time > conn_clear_interval) {
        last_clear_time = get_current_time();
        return clear_inactive0();
    }
    return 0;
}

int conn_manager_t::clear_inactive0() {
    // mylog(log_info,"called\n");
    unordered_map<address_t, conn_info_t *>::iterator it;
    unordered_map<address_t, conn_info_t *>::iterator old_it;

    if (disable_conn_clear) return 0;

    // map<uint32_t,uint64_t>::iterator it;
    int cnt = 0;
    it = clear_it;  // TODO,write it back
    int size = mp.size();
    int num_to_clean = size / conn_clear_ratio + conn_clear_min;  // clear 1/10 each time,to avoid latency glitch

    // mylog(log_trace,"mp.size() %d\n", size);

    num_to_clean = min(num_to_clean, (int)mp.size());
    u64_t current_time = get_current_time();

    // mylog(log_info,"here size=%d\n",(int)mp.size());
    for (;;) {
        if (cnt >= num_to_clean) break;
        if (mp.begin() == mp.end()) break;
        if (it == mp.end()) {
            it = mp.begin();
        }

        if (it->second->conv_manager.s.get_size() > 0) {
            // mylog(log_info,"[%s:%d]size %d \n",my_ntoa(get_u64_h(it->first)),get_u64_l(it->first),(int)it->second->conv_manager.get_size());
            it++;
        } else if (current_time < it->second->last_active_time + server_conn_timeout) {
            it++;
        } else {
            address_t tmp_addr = it->first;  // avoid making get_str() const;
            mylog(log_info, "{%s} inactive conn cleared \n", tmp_addr.get_str());
            old_it = it;
            it++;
            erase(old_it);
        }
        cnt++;
    }
    clear_it = it;
    return 0;
}
