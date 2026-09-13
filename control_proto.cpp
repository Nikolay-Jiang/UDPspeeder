#include "control_proto.h"
#include "auth.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

// Defined in connection.cpp. Non-zero enables the periodic report.
extern int report_interval;

// --- Bounded per-session nonce / timestamp anti-replay ---

#define TIMESTAMP_TOLERANCE_MS 60000ULL
#define REPLAY_MAX_PER_SESSION 1024

struct ctrl_replay_session_t {
    bool     used;
    uint8_t  session_id[16];
    uint64_t nonces[REPLAY_MAX_PER_SESSION];
    int      count;  // valid entries, always <= REPLAY_MAX_PER_SESSION
    int      next;   // next ring slot to overwrite
    uint64_t last_seen_ms;
};

// One slot per possible connection, so the session count can never exceed
// max_conn_num. Entries per session are bounded by the fixed-size ring above.
static ctrl_replay_session_t g_replay_sessions[max_conn_num];
static uint64_t g_replay_last_report_ms = 0;
static bool     g_replay_report_armed = false;

static ctrl_replay_session_t *replay_find(const uint8_t session_id[16]) {
    for (int i = 0; i < max_conn_num; i++) {
        if (g_replay_sessions[i].used &&
            memcmp(g_replay_sessions[i].session_id, session_id, 16) == 0)
            return &g_replay_sessions[i];
    }
    return NULL;
}

static void replay_init_session(ctrl_replay_session_t *s, const uint8_t session_id[16]) {
    memset(s, 0, sizeof(*s));
    s->used = true;
    memcpy(s->session_id, session_id, 16);
}

static ctrl_replay_session_t *replay_alloc(const uint8_t session_id[16]) {
    for (int i = 0; i < max_conn_num; i++) {
        if (!g_replay_sessions[i].used) {
            replay_init_session(&g_replay_sessions[i], session_id);
            return &g_replay_sessions[i];
        }
    }
    // Table full: evict the least-recently-seen session.
    int oldest = 0;
    for (int i = 1; i < max_conn_num; i++) {
        if (g_replay_sessions[i].last_seen_ms < g_replay_sessions[oldest].last_seen_ms)
            oldest = i;
    }
    replay_init_session(&g_replay_sessions[oldest], session_id);
    return &g_replay_sessions[oldest];
}

void ctrl_replay_reset(void) {
    memset(g_replay_sessions, 0, sizeof(g_replay_sessions));
    g_replay_last_report_ms = 0;
    g_replay_report_armed = false;
}

bool ctrl_replay_accept(const uint8_t session_id[16], uint64_t nonce, uint64_t timestamp_ms) {
    if (nonce == 0) return false;

    uint64_t now = get_current_time();  // ms
    if (now > timestamp_ms + TIMESTAMP_TOLERANCE_MS ||
        timestamp_ms > now + TIMESTAMP_TOLERANCE_MS) {
        mylog(log_trace, "ctrl: timestamp out of window: pkt=%llu now=%llu\n",
              (unsigned long long)timestamp_ms, (unsigned long long)now);
        return false;
    }

    ctrl_replay_session_t *s = replay_find(session_id);
    if (s == NULL) s = replay_alloc(session_id);

    for (int i = 0; i < s->count; i++) {
        if (s->nonces[i] == nonce) {
            mylog(log_trace, "ctrl: replayed nonce %llu\n", (unsigned long long)nonce);
            return false;
        }
    }

    s->nonces[s->next] = nonce;
    s->next = (s->next + 1) % REPLAY_MAX_PER_SESSION;
    if (s->count < REPLAY_MAX_PER_SESSION) s->count++;
    s->last_seen_ms = now;
    return true;
}

void ctrl_replay_expire(uint64_t now_ms) {
    for (int i = 0; i < max_conn_num; i++) {
        if (g_replay_sessions[i].used &&
            now_ms > g_replay_sessions[i].last_seen_ms + TIMESTAMP_TOLERANCE_MS)
            g_replay_sessions[i].used = false;
    }
}

void ctrl_replay_report(bool force) {
    if (!force && report_interval == 0) return;

    uint64_t now = get_current_time();
    if (!force && g_replay_report_armed &&
        now - g_replay_last_report_ms < (uint64_t)report_interval * 1000)
        return;
    g_replay_last_report_ms = now;
    g_replay_report_armed = true;

    int sessions = 0, entries = 0, max_per_session = 0;
    for (int i = 0; i < max_conn_num; i++) {
        if (!g_replay_sessions[i].used) continue;
        sessions++;
        entries += g_replay_sessions[i].count;
        if (g_replay_sessions[i].count > max_per_session)
            max_per_session = g_replay_sessions[i].count;
    }
    mylog(log_info, "ctrl_replay: sessions=%d entries=%d max_per_session=%d\n",
          sessions, entries, max_per_session);
}

// --- MAC: SipHash-2-4 over header+payload, DOMAIN_CTRL, 8 bytes big-endian ---

// --- Encode ---

static char g_ctrl_enc_buf[CTRL_BUF_MAX];

char *ctrl_encode(int msg_type, const void *payload, int payload_len, int *out_len) {
    if (payload_len < 0 ||
        payload_len > CTRL_BUF_MAX - (int)CTRL_HDR_LEN - CTRL_MAC_LEN) {
        mylog(log_warn, "ctrl_encode: payload too large (%d)\n", payload_len);
        return NULL;
    }
    int total = (int)CTRL_HDR_LEN + payload_len + CTRL_MAC_LEN;

    ctrl_hdr_t hdr;
    hdr.version      = 2;
    hdr.msg_type     = (uint8_t)msg_type;
    hdr.reserved     = 0;
    hdr.nonce        = get_fake_random_number_64();
    hdr.timestamp_ms = get_current_time();

    char *p = g_ctrl_enc_buf;
    memcpy(p, &hdr, CTRL_HDR_LEN);
    if (payload_len > 0)
        memcpy(p + CTRL_HDR_LEN, payload, payload_len);

    int body_len = (int)CTRL_HDR_LEN + payload_len;
    auth_tag(DOMAIN_CTRL, (const uint8_t *)p, (size_t)body_len,
             (uint8_t *)(p + body_len));

    *out_len = total;
    return g_ctrl_enc_buf;
}

// --- Decode ---

int ctrl_decode(char *buf, int len, uint8_t **payload_out, int *payload_len_out,
                ctrl_hdr_t *hdr_out) {
    if (len < (int)CTRL_HDR_LEN + CTRL_MAC_LEN) {
        mylog(log_trace, "ctrl_decode: too short (%d)\n", len);
        return -1;
    }

    int payload_len = len - (int)CTRL_HDR_LEN - CTRL_MAC_LEN;
    if (payload_len < 0 ||
        (int)CTRL_HDR_LEN + payload_len + CTRL_MAC_LEN != len) {
        mylog(log_trace, "ctrl_decode: bad length (%d)\n", len);
        return -1;
    }

    int body_len = (int)CTRL_HDR_LEN + payload_len;
    const uint8_t *mac_ptr = (const uint8_t *)(buf + body_len);
    if (!auth_verify(DOMAIN_CTRL, (const uint8_t *)buf, (size_t)body_len, mac_ptr)) {
        mylog(log_trace, "ctrl_decode: mac mismatch\n");
        return -1;
    }

    ctrl_hdr_t hdr;
    memcpy(&hdr, buf, CTRL_HDR_LEN);

    if (hdr.version != 2) {
        mylog(log_trace, "ctrl_decode: unknown version %d\n", hdr.version);
        return -1;
    }
    if (hdr.reserved != 0) {
        mylog(log_trace, "ctrl_decode: reserved != 0\n");
        return -1;
    }

    *payload_out     = (uint8_t *)(buf + CTRL_HDR_LEN);
    *payload_len_out = payload_len;
    *hdr_out         = hdr;

    return (int)hdr.msg_type;
}
