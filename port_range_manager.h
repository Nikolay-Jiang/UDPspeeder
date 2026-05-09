#ifndef PORT_RANGE_MANAGER_H_
#define PORT_RANGE_MANAGER_H_

#include "common.h"
#include <stdint.h>
#include <vector>

struct port_range_manager_t {
    std::vector<uint16_t> ports;
    address_t server_base_addr;   // server IP; port is varied per packet
    int rr_counter = 0;
    bool ready = false;

    // Parse "a-b" string; returns 0 on success, -1 on error.
    int parse_range(const char *s);

    // Called by client on receiving HELLO_ACK.
    // base_addr: server's address (IP only; port will be overridden per packet).
    void set_from_ack(const uint16_t *p, int n, const address_t &base_addr);

    // Returns next destination address (round-robin through ports).
    // Caller must ensure is_ready() before calling.
    address_t next_dest();

    bool is_ready() const { return ready; }
    int count() const { return (int)ports.size(); }
};

#endif /* PORT_RANGE_MANAGER_H_ */
