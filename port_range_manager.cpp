#include "port_range_manager.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int port_range_manager_t::parse_range(const char *s) {
    int a = 0, b = 0;
    if (sscanf(s, "%d-%d", &a, &b) != 2) {
        mylog(log_fatal, "--data-port-range: expected format a-b, got '%s'\n", s);
        return -1;
    }
    if (a < 1 || b > 65535 || a > b) {
        mylog(log_fatal, "--data-port-range: invalid range %d-%d\n", a, b);
        return -1;
    }
    int n = b - a + 1;
    if (n > 256) {
        mylog(log_fatal, "--data-port-range: range size %d exceeds maximum 256\n", n);
        return -1;
    }
    ports.clear();
    for (int p = a; p <= b; p++)
        ports.push_back((uint16_t)p);
    return 0;
}

void port_range_manager_t::set_from_ack(const uint16_t *p, int n, const address_t &base_addr) {
    ports.clear();
    for (int i = 0; i < n; i++)
        ports.push_back(p[i]);
    server_base_addr = base_addr;
    rr_counter = 0;
    ready = true;
}

address_t port_range_manager_t::next_dest() {
    address_t addr = server_base_addr;
    addr.set_port(ports[rr_counter % (int)ports.size()]);
    rr_counter++;
    return addr;
}
