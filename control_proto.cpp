#include "control_proto.h"
#include "siphash.h"
#include "packet.h"
#include "crc32/Crc32.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// Declared in misc.cpp / misc.h
extern int ctrl_mac_mode;
extern char key_string[1000];

// --- Nonce / timestamp anti-replay ---

#define NONCE_WINDOW 1024
#define TIMESTAMP_TOLERANCE_MS 60000ULL

static uint64_t nonce_ring[NONCE_WINDOW];
static int nonce_pos = 0;
static bool nonce_init_done = false;

void ctrl_nonce_init() {
    memset(nonce_ring, 0, sizeof(nonce_ring));
    nonce_pos = 0;
    nonce_init_done = true;
}

int ctrl_check_replay(uint64_t nonce, uint64_t timestamp_ms) {
    uint64_t now = get_current_time();  // ms
    if (now > timestamp_ms + TIMESTAMP_TOLERANCE_MS || timestamp_ms > now + TIMESTAMP_TOLERANCE_MS) {
        mylog(log_trace, "ctrl: timestamp out of window: pkt=%llu now=%llu\n",
              (unsigned long long)timestamp_ms, (unsigned long long)now);
        return 0;
    }
    if (nonce == 0) return 0;  // zero nonce is sentinel
    for (int i = 0; i < NONCE_WINDOW; i++) {
        if (nonce_ring[i] == nonce) {
            mylog(log_trace, "ctrl: replayed nonce %llu\n", (unsigned long long)nonce);
            return 0;
        }
    }
    nonce_ring[nonce_pos % NONCE_WINDOW] = nonce;
    nonce_pos++;
    return 1;
}

// --- MAC helpers ---

static void mac_compute_siphash(const char *body, int body_len, char mac_out[CTRL_MAC_LEN]) {
    uint8_t k[16] = {0};
    int klen = strlen(key_string);
    if (klen > 16) klen = 16;
    memcpy(k, key_string, klen);
    uint64_t h = siphash24(body, (size_t)body_len, k);
    memcpy(mac_out, &h, CTRL_MAC_LEN);
}

static int mac_verify_siphash(const char *body, int body_len, const char mac[CTRL_MAC_LEN]) {
    char expected[CTRL_MAC_LEN];
    mac_compute_siphash(body, body_len, expected);
    return memcmp(expected, mac, CTRL_MAC_LEN) == 0 ? 1 : 0;
}

// Legacy MAC: CRC32(body || key_string) repeated to fill 8 bytes.
static void mac_compute_legacy(const char *body, int body_len, char mac_out[CTRL_MAC_LEN]) {
    uint32_t c = crc32_fast(body, (size_t)body_len);
    int klen = strlen(key_string);
    c = crc32_fast(key_string, klen, c);
    uint32_t c2 = ~c;  // second word: bitwise complement for trivial differentiation
    memcpy(mac_out, &c, 4);
    memcpy(mac_out + 4, &c2, 4);
}

static int mac_verify_legacy(const char *body, int body_len, const char mac[CTRL_MAC_LEN]) {
    char expected[CTRL_MAC_LEN];
    mac_compute_legacy(body, body_len, expected);
    return memcmp(expected, mac, CTRL_MAC_LEN) == 0 ? 1 : 0;
}

// --- Encode ---

static char g_ctrl_enc_buf[CTRL_BUF_MAX];

char *ctrl_encode(int msg_type, const void *payload, int payload_len, int *out_len) {
    int total = (int)CTRL_HDR_LEN + payload_len + CTRL_MAC_LEN;
    if (total > CTRL_BUF_MAX) {
        mylog(log_warn, "ctrl_encode: payload too large (%d)\n", payload_len);
        return NULL;
    }

    ctrl_hdr_t hdr;
    hdr.version      = 1;
    hdr.msg_type     = (uint8_t)msg_type;
    hdr.reserved     = 0;
    hdr.nonce        = get_fake_random_number_64();
    hdr.timestamp_ms = get_current_time();

    char *p = g_ctrl_enc_buf;
    memcpy(p, &hdr, CTRL_HDR_LEN);
    if (payload_len > 0)
        memcpy(p + CTRL_HDR_LEN, payload, payload_len);

    int body_len = (int)CTRL_HDR_LEN + payload_len;
    char *mac_ptr = p + body_len;

    if (ctrl_mac_mode == CTRL_MAC_SIPHASH)
        mac_compute_siphash(p, body_len, mac_ptr);
    else
        mac_compute_legacy(p, body_len, mac_ptr);

    *out_len = total;
    return g_ctrl_enc_buf;
}

// --- Decode ---

int ctrl_decode(char *buf, int len, uint8_t **payload_out, int *payload_len_out) {
    int min_len = (int)CTRL_HDR_LEN + CTRL_MAC_LEN;
    if (len < min_len) {
        mylog(log_trace, "ctrl_decode: too short (%d)\n", len);
        return -1;
    }

    int body_len = len - CTRL_MAC_LEN;
    char *mac_ptr = buf + body_len;

    int mac_ok;
    if (ctrl_mac_mode == CTRL_MAC_SIPHASH)
        mac_ok = mac_verify_siphash(buf, body_len, mac_ptr);
    else
        mac_ok = mac_verify_legacy(buf, body_len, mac_ptr);

    if (!mac_ok) {
        mylog(log_trace, "ctrl_decode: mac mismatch\n");
        return -1;
    }

    ctrl_hdr_t hdr;
    memcpy(&hdr, buf, CTRL_HDR_LEN);

    if (hdr.version != 1) {
        mylog(log_trace, "ctrl_decode: unknown version %d\n", hdr.version);
        return -1;
    }
    if (hdr.reserved != 0) {
        mylog(log_trace, "ctrl_decode: reserved != 0\n");
        return -1;
    }
    if (!ctrl_check_replay(hdr.nonce, hdr.timestamp_ms))
        return -1;

    *payload_out    = (uint8_t *)(buf + CTRL_HDR_LEN);
    *payload_len_out = body_len - (int)CTRL_HDR_LEN;

    return (int)hdr.msg_type;
}
