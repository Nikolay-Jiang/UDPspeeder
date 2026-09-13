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

// Fixed header (20 bytes) present in every control packet.
#pragma pack(push, 1)
struct ctrl_hdr_t {
    uint8_t  version;       // = 2
    uint8_t  msg_type;
    uint16_t reserved;      // must be 0
    uint64_t nonce;
    uint64_t timestamp_ms;
};
#pragma pack(pop)

#define CTRL_HDR_LEN   sizeof(ctrl_hdr_t)   // 20
#define CTRL_MAC_LEN   8

// Every control packet carries an 8-byte SipHash-2-4 tag (DOMAIN_CTRL) over
// the header plus payload, serialized big-endian. The MAC length is fixed.

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
// Applies the SipHash-2-4 control MAC. Returns NULL on error.
char *ctrl_encode(int msg_type, const void *payload, int payload_len, int *out_len);

// Decode a control packet received in buf[0..len).
// On success: returns msg_type (>0), *payload_out points into buf, *payload_len_out
// is payload size, and *hdr_out receives the MAC-verified header.
// On failure: returns -1 (silently, caller should log at trace).
int ctrl_decode(char *buf, int len, uint8_t **payload_out, int *payload_len_out,
                ctrl_hdr_t *hdr_out);

// Bounded per-session anti-replay for control messages.
// State is a per-session table (at most max_conn_num sessions, each capped at
// 1024 nonces) with a 60s timestamp window; entries are evicted oldest-first.
void ctrl_replay_reset(void);
bool ctrl_replay_accept(const uint8_t session_id[16], uint64_t nonce, uint64_t timestamp_ms);
void ctrl_replay_expire(uint64_t now_ms);

// Emit "ctrl_replay: sessions=... entries=... max_per_session=...".
// force=false is rate-limited to the --report interval and does nothing when
// reporting is disabled; force=true always emits (clean shutdown).
void ctrl_replay_report(bool force);

#endif /* CONTROL_PROTO_H_ */
