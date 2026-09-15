#ifndef PORT_RANGE_MANAGER_H_
#define PORT_RANGE_MANAGER_H_

#include "common.h"
#include <stdint.h>
#include <vector>

struct port_range_manager_t {
    std::vector<uint16_t> ports;
    address_t server_base_addr;   // server IP; port is varied per packet
    size_t rr_counter = 0;   // unsigned: wraps cleanly, never goes negative
    // Rotation base, independent of rr_counter. The first destination of the
    // first send in a rotation window is ports[rotate_base]; next_dest() still
    // round-robins across every advertised port starting there. Advanced only
    // by rotate_step(), which touches no socket and no fd index.
    size_t rotate_base = 0;
    // One-shot flag: next_dest() logs the first destination of the current
    // rotation window once, then clears it. Armed by set_from_ack() and
    // rotate_step().
    bool window_log_pending = false;
    bool ready = false;

    // Parse "a-b" string; returns 0 on success, -1 on error.
    int parse_range(const char *s);

    // Called by client on receiving HELLO_ACK.
    // base_addr: server's address (IP only; port will be overridden per packet).
    void set_from_ack(const uint16_t *p, int n, const address_t &base_addr);

    // Advance rotate_base by one (mod port count), re-align the round-robin
    // cursor to it and arm the one-shot first-destination log. Never opens or
    // closes sockets and never changes fd_idx; it only moves the round-robin
    // base within the installed list.
    void rotate_step();

    // Returns next destination address (round-robin through ports).
    // Caller must ensure is_ready() before calling.
    address_t next_dest();

    bool is_ready() const { return ready; }
    int count() const { return (int)ports.size(); }
};

#endif /* PORT_RANGE_MANAGER_H_ */
