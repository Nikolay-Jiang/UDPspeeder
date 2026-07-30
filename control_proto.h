#ifndef CONTROL_PROTO_H_
#define CONTROL_PROTO_H_

#include "common.h"
#include <stdint.h>

// msg_type values
enum ctrl_msg_type_t {
    CTRL_HELLO         = 1,
    CTRL_HELLO_ACK     = 2,
    CTRL_HEARTBEAT     = 3,
    CTRL_HEARTBEAT_ACK = 4,
    CTRL_BYE           = 5,
};

// --control-mac values
enum ctrl_mac_mode_t {
    CTRL_MAC_LEGACY  = 0,
    CTRL_MAC_SIPHASH = 1,
};

// Fixed header (20 bytes) present in every control packet.
#pragma pack(push, 1)
struct ctrl_hdr_t {
    uint8_t  version;       // = 1
    uint8_t  msg_type;
    uint16_t reserved;      // must be 0
    uint64_t nonce;
    uint64_t timestamp_ms;
};
#pragma pack(pop)

#define CTRL_HDR_LEN   sizeof(ctrl_hdr_t)   // 20
#define CTRL_MAC_LEN   8

// MAC_LEGACY appended size: variable due to obscure IV; handled transparently.
// MAC_SIPHASH appended size: CTRL_MAC_LEN bytes.

// HELLO payload
#pragma pack(push, 1)
struct ctrl_hello_payload_t {
    uint8_t session_id[16];
};

// HELLO_ACK payload (variable-length: ports array)
struct ctrl_hello_ack_hdr_t {
    uint8_t  session_id[16];
    uint16_t port_count;
    uint32_t heartbeat_interval_ms;
    uint32_t session_lifetime_ms;
    // followed by port_count * uint16_t
};

// HEARTBEAT / HEARTBEAT_ACK / BYE payload
struct ctrl_hb_payload_t {
    uint8_t session_id[16];
};
#pragma pack(pop)

// Maximum encoded control packet size (conservatively sized).
#define CTRL_BUF_MAX 1024

// Encode a control packet into static buffer; returns pointer and sets *out_len.
// Applies MAC according to global ctrl_mac_mode.
// Returns NULL on error.
char *ctrl_encode(int msg_type, const void *payload, int payload_len, int *out_len);

// Decode a control packet received in buf[0..len).
// On success: returns msg_type (>0), *payload_out points into buf, *payload_len_out is payload size.
// On failure: returns -1 (silently, caller should log at trace).
int ctrl_decode(char *buf, int len, uint8_t **payload_out, int *payload_len_out);

// Nonce/timestamp anti-replay check (combined); returns 1 if valid, 0 if should reject.
int ctrl_check_replay(uint64_t nonce, uint64_t timestamp_ms);

// Initialize nonce window.
void ctrl_nonce_init();

#endif /* CONTROL_PROTO_H_ */
