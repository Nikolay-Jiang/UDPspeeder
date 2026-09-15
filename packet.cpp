/*
 * packet.cpp
 *
 *  Created on: Sep 15, 2017
 *      Author: root
 */

#include "common.h"
#include "log.h"
#include "packet.h"
#include "connection.h"
#include "misc.h"
#include "auth.h"
#include "crypto/crypto_cfg.h"
#include "crypto/kdf.h"
#include "crypto/wrap.h"
#include <algorithm>

int iv_min = 4;
int iv_max = 32;  //< 256;
u64_t packet_send_count = 0;
u64_t dup_packet_send_count = 0;
u64_t packet_recv_count = 0;
u64_t dup_packet_recv_count = 0;
u64_t short_send_drop_count = 0;

typedef u64_t anti_replay_seq_t;
int disable_replay_filter = 0;

int disable_obscure = 0;
int disable_xor = 0;

int random_drop = 0;

char key_string[1000] = "";

struct send_batch_entry_t {
    char buf[buf_len];
    int len;
    int fd;
    address_t addr;
};

static send_batch_entry_t s_send_batch[IO_BATCH_MAX];
static int s_send_n = 0;
static bool s_batching = false;

void my_send_batch_begin() {
    s_send_n = 0;
    s_batching = true;
}

void my_send_flush() {
    static struct mmsghdr msgvec[IO_BATCH_MAX];
    static struct iovec iov[IO_BATCH_MAX];
    static int idx[IO_BATCH_MAX];

    // Sort by fd so same-fd entries are contiguous → one sendmmsg call per fd.
    // Must be stable: same-fd packets (e.g. a whole FEC group) have to keep their
    // original order, otherwise std::sort can near-reverse them and reorder the wire.
    for (int k = 0; k < s_send_n; k++) idx[k] = k;
    std::stable_sort(idx, idx + s_send_n, [](int a, int b) {
        return s_send_batch[a].fd < s_send_batch[b].fd;
    });

    int i = 0;
    while (i < s_send_n) {
        int fd = s_send_batch[idx[i]].fd;
        int count = 0;
        int j = i;
        while (j < s_send_n && s_send_batch[idx[j]].fd == fd) {
            send_batch_entry_t &e = s_send_batch[idx[j]];
            iov[count].iov_base = e.buf;
            iov[count].iov_len = e.len;
            memset(&msgvec[count], 0, sizeof(msgvec[count]));
            msgvec[count].msg_hdr.msg_iov = &iov[count];
            msgvec[count].msg_hdr.msg_iovlen = 1;
            msgvec[count].msg_hdr.msg_name = (void *)&e.addr.inner;
            msgvec[count].msg_hdr.msg_namelen = e.addr.get_len();
            count++;
            j++;
        }
        int sent = sendmmsg(fd, msgvec, count, 0);
        if (sent < 0) {
            short_send_drop_count += count;
            static my_time_t last_err_log = 0;
            my_time_t now = get_current_time();
            if (now - last_err_log > 1000) {  // rate-limit to 1/s
                last_err_log = now;
                mylog(log_warn, "sendmmsg(fd=%d,count=%d) failed: %s\n", fd, count, get_sock_error());
            }
        } else if (sent < count) {
            short_send_drop_count += count - sent;
            static my_time_t last_short_log = 0;
            my_time_t now = get_current_time();
            if (now - last_short_log > 1000) {  // rate-limit to 1/s
                last_short_log = now;
                mylog(log_warn, "sendmmsg(fd=%d) short send: %d/%d, %d packets dropped\n", fd, sent, count, count - sent);
            }
        }
        i = j;
    }

    s_send_n = 0;
    s_batching = false;
}


// int local_listen_fd=-1;

void encrypt_0(char *input, int &len, char *key) {
    int i, j;
    if (key[0] == 0) return;
    for (i = 0, j = 0; i < len; i++, j++) {
        if (key[j] == 0) j = 0;
        input[i] ^= key[j];
    }
}

void decrypt_0(char *input, int &len, char *key) {
    int i, j;
    if (key[0] == 0) return;
    for (i = 0, j = 0; i < len; i++, j++) {
        if (key[j] == 0) j = 0;
        input[i] ^= key[j];
    }
}

int do_obscure(char *data, int &len) {
    assert(len >= 0);

    int iv_len = random_between(iv_min, iv_max);
    if (len + iv_len + 1 > buf_len) return -1;
    get_fake_random_chars(data + len, iv_len);
    data[iv_len + len] = (uint8_t)iv_len;
    for (int i = 0, j = 0; i < len; i++, j++) {
        if (j == iv_len) j = 0;
        data[i] ^= data[len + j];
    }

    len = len + iv_len + 1;
    return 0;
}

int de_obscure(char *data, int &len) {
    if (len < 1) return -1;
    int iv_len = int((uint8_t)data[len - 1]);

    if (len < 1 + iv_len) return -1;

    len = len - 1 - iv_len;
    for (int i = 0, j = 0; i < len; i++, j++) {
        if (j == iv_len) j = 0;
        data[i] ^= data[len + j];
    }

    return 0;
}

/*
int sendto_fd_ip_port (int fd,u32_t ip,int port,char * buf, int len,int flags)
{

        sockaddr_in tmp_sockaddr;

        memset(&tmp_sockaddr,0,sizeof(tmp_sockaddr));
        tmp_sockaddr.sin_family = AF_INET;
        tmp_sockaddr.sin_addr.s_addr = ip;
        tmp_sockaddr.sin_port = htons(uint16_t(port));

        return sendto(fd, buf,
                        len , 0,
                        (struct sockaddr *) &tmp_sockaddr,
                        sizeof(tmp_sockaddr));
}*/

int sendto_fd_addr(int fd, address_t addr, char *buf, int len, int flags) {
    return sendto(fd, buf,
                  len, 0,
                  (struct sockaddr *)&addr.inner,
                  addr.get_len());
}
/*
int sendto_ip_port (u32_t ip,int port,char * buf, int len,int flags)
{
        return sendto_fd_ip_port(local_listen_fd,ip,port,buf,len,flags);
}*/

int send_fd(int fd, char *buf, int len, int flags) {
    return send(fd, buf, len, flags);
}

int my_send(const dest_t &dest, char *data, int len) {
    if (dest.cook) {
        if (do_cook(data, len) != 0) {
            return -1;
        }
    }
    if (s_batching && s_send_n == IO_BATCH_MAX) {
        // Batch full: flush it before handling this packet so it stays behind the
        // already-buffered ones. Otherwise it would fall through to an immediate
        // sendto and overtake the still-buffered batch, reordering the wire.
        my_send_flush();
        my_send_batch_begin();
    }
    if (s_batching && s_send_n < IO_BATCH_MAX) {
        int fd = -1;
        address_t addr;
        bool batchable = false;
        switch (dest.type) {
            case type_fd_addr:
                fd = dest.inner.fd_addr.fd;
                addr = dest.inner.fd_addr.addr;
                batchable = true;
                break;
            case type_fd64_addr:
                if (!fd_manager.exist(dest.inner.fd64)) return -1;
                fd = fd_manager.to_fd(dest.inner.fd64);
                addr = dest.inner.fd64_addr.addr;
                batchable = true;
                break;
            default:
                break;
        }
        if (batchable) {
            send_batch_entry_t &e = s_send_batch[s_send_n++];
            memcpy(e.buf, data, len);
            e.len = len;
            e.fd = fd;
            e.addr = addr;
            return 0;
        }
    }
    switch (dest.type) {
        case type_fd_addr: {
            return sendto_fd_addr(dest.inner.fd, dest.inner.fd_addr.addr, data, len, 0);
            break;
        }
        case type_fd64_addr: {
            if (!fd_manager.exist(dest.inner.fd64)) return -1;
            int fd = fd_manager.to_fd(dest.inner.fd64);

            return sendto_fd_addr(fd, dest.inner.fd64_addr.addr, data, len, 0);
            break;
        }
        case type_fd: {
            return send_fd(dest.inner.fd, data, len, 0);
            break;
        }
        case type_write_fd: {
            return write(dest.inner.fd, data, len);
            break;
        }
        case type_fd64: {
            if (!fd_manager.exist(dest.inner.fd64)) return -1;
            int fd = fd_manager.to_fd(dest.inner.fd64);

            return send_fd(fd, data, len, 0);
            break;
        }
        /*
        case type_fd64_ip_port_conv:
        {
                if(!fd_manager.exist(dest.inner.fd64)) return -1;
                int fd=fd_manager.to_fd(dest.inner.fd64);

                char *new_data;
                int new_len;

                put_conv(dest.conv,data,len,new_data,new_len);
                return sendto_fd_ip_port(fd,dest.inner.fd64_ip_port.ip_port.ip,dest.inner.fd64_ip_port.ip_port.port,new_data,new_len,0);
                break;
        }*/

        /*
        case type_fd64_conv:
        {
                char *new_data;
                int new_len;
                put_conv(dest.conv,data,len,new_data,new_len);

                if(!fd_manager.exist(dest.inner.fd64)) return -1;
                int fd=fd_manager.to_fd(dest.inner.fd64);
                return send_fd(fd,new_data,new_len,0);
        }*/
        /*
        case type_fd:
        {
                send_fd(dest.inner.fd,data,len,0);
                break;
        }*/
        default:
            assert(0 == 1);
    }
    return 0;
}

int put_siphtag(char *s, int &len) {
    assert(len >= 0);
    if (len + SIPHASH_TAG_LEN > buf_len) return -1;
    uint8_t tag[SIPHASH_TAG_LEN];
    auth_tag(DOMAIN_DATA, (const uint8_t *)s, (size_t)len, tag);
    memcpy(s + len, tag, sizeof(tag));
    len += SIPHASH_TAG_LEN;
    return 0;
}

int cook_overhead() {
    int base = (g_crypto_cfg.cipher != CRYPTO_CIPHER_NONE) ? (AEAD_NONCE_LEN + AEAD_TAG_LEN) : (SIPHASH_TAG_LEN + iv_max + 1);
    int pad = (g_crypto_cfg.pad_bucket > 0) ? (1 + PAD_MAX) : 0;
    return base + pad;
}

// Fill a fresh 24-byte nonce from the kernel CSPRNG (G13). my_random (mt19937)
// is invertible and must never produce an AEAD nonce: recovering its state
// would let an observer predict every nonce. 6 u32 draws cover 24 bytes.
static void aead_fill_nonce(uint8_t nonce[AEAD_NONCE_LEN]) {
    for (int i = 0; i < AEAD_NONCE_LEN; i += (int)sizeof(u32_t)) {
        u32_t r = get_secure_random_number_nz();
        memcpy(nonce + i, &r, sizeof(r));
    }
}

// The 2 serialized capability bytes {cipher_id, pad_bucket} bound as AEAD
// associated data (G1/G2). A peer configured with a different cipher or pad
// bucket authenticates the same bytes differently, so the mismatch fails
// verification and the packet is dropped rather than silently delivered.
static void aead_capability_ad(uint8_t ad[2]) {
    ad[0] = (uint8_t)g_crypto_cfg.cipher;
    ad[1] = (uint8_t)g_crypto_cfg.pad_bucket;
}

// Cipher-mode bucket padding (todo 6 / G6). Appends `pad_len` fresh random
// filler bytes then the single byte `pad_len`, so the padded region
// (shard + filler + pad_len byte) is an exact multiple of the negotiated
// bucket. The padding lives inside the AEAD plaintext, so the tag covers it,
// and the bucket itself is bound as associated data (G1). Returns 0 on
// success, or -1 when the padded region would not fit in buf_len.
//
// A bucket of 0 is a strict no-op: no computation and no byte is added, so the
// wire stays byte-identical to cipher mode without padding. The filler uses the
// kernel CSPRNG for consistency with the nonce; the tag already authenticates
// the frame, so its content is not security-critical.
static int pad_apply(char *data, int &len) {
    int bucket = g_crypto_cfg.pad_bucket;
    if (bucket <= 0) return 0;

    int pad_len = (bucket - 1 - (len % bucket) + bucket) % bucket;
    if (len + pad_len + 1 > buf_len) return -1;

    for (int i = 0; i < pad_len; i += (int)sizeof(u32_t)) {
        u32_t r = get_secure_random_number_nz();
        int chunk = pad_len - i;
        if (chunk > (int)sizeof(u32_t)) chunk = (int)sizeof(u32_t);
        memcpy(data + len + i, &r, chunk);
    }
    data[len + pad_len] = (uint8_t)pad_len;
    len += pad_len + 1;
    return 0;
}

// Cipher-mode bucket strip. The pad_len byte is the last byte of the
// authenticated plaintext; a bucket of 0 carries no such byte and reads
// nothing. An out-of-range pad_len (or a frame too short for the strip it
// declares) is a hard drop: -1 makes the existing receive path discard the
// shard. Tamper-drop logging is todo 8's job, not this function's.
static int pad_strip(char *data, int &len) {
    int bucket = g_crypto_cfg.pad_bucket;
    if (bucket <= 0) return 0;
    if (len < 1) return -1;

    int pad_len = (int)(uint8_t)data[len - 1];
    if (pad_len > bucket - 1) return -1;
    if (len < 1 + pad_len) return -1;

    len -= 1 + pad_len;
    return 0;
}

// Cipher-mode SEND (G12): [nonce(24)][ciphertext][tag(16)]. The plaintext is
// shifted forward by the nonce length, then the wrapper writes the nonce and
// encrypts in place, appending the 16-byte tag. The key is the
// 'udpspeeder/data' KDF output; no SipHash tag and no obscure/XOR layer are
// applied. Bucket padding (todo 6) is applied first, so it sits inside the
// plaintext and the tag covers it automatically.
static int do_cook_aead(char *data, int &len) {
    if (pad_apply(data, len) != 0) return -1;
    if (len + AEAD_NONCE_LEN + AEAD_TAG_LEN > buf_len) return -1;

    uint8_t key[CRYPTO_KDF_KEY_LEN];
    if (!crypto_kdf(key, CRYPTO_KDF_LABEL_DATA)) return -1;

    uint8_t ad[2];
    aead_capability_ad(ad);

    uint8_t nonce[AEAD_NONCE_LEN];
    aead_fill_nonce(nonce);

    memmove(data + AEAD_NONCE_LEN, data, len);
    size_t out_len = 0;
    if (crypto_wrap_aead_encrypt((uint8_t *)data, (size_t)buf_len, &out_len,
                                 key, nonce, ad, sizeof(ad),
                                 (const uint8_t *)(data + AEAD_NONCE_LEN), (size_t)len) != 0) {
        return -1;
    }
    len = (int)out_len;
    return 0;
}

// Cipher-mode RECV: verify the AEAD first and fail closed, returning non-zero
// so the caller drops the packet. A successful decrypt writes the recovered
// plaintext to offset 0 of the shard buffer, which is exactly what
// from_fec_normal/from_fec_to_normal consume. The replay filter is untouched.
static int de_cook_aead(char *data, int &len) {
    if (len < AEAD_NONCE_LEN + AEAD_TAG_LEN) return -1;
    // With bucket padding (todo 6) the frame carries one more authenticated
    // byte, so a frame too short to hold it can never be valid.
    if (g_crypto_cfg.pad_bucket > 0 && len < AEAD_NONCE_LEN + AEAD_TAG_LEN + 1) return -1;

    uint8_t key[CRYPTO_KDF_KEY_LEN];
    if (!crypto_kdf(key, CRYPTO_KDF_LABEL_DATA)) return -1;

    uint8_t ad[2];
    aead_capability_ad(ad);

    size_t out_len = 0;
    if (crypto_wrap_aead_decrypt((uint8_t *)data, (size_t)buf_len, &out_len,
                                 key, ad, sizeof(ad),
                                 (const uint8_t *)data, (size_t)len) != 0) {
        return -1;
    }
    len = (int)out_len;
    // Strip the authenticated pad frame only when a bucket was negotiated.
    // A bad pad_len fails here and the caller drops the shard.
    if (pad_strip(data, len) != 0) return -1;
    return 0;
}

int do_cook(char *data, int &len) {
    if (g_crypto_cfg.cipher != CRYPTO_CIPHER_NONE) return do_cook_aead(data, len);

    int ret = put_siphtag(data, len);
    if (ret != 0) return ret;
    if (!disable_obscure) {
        ret = do_obscure(data, len);
        if (ret != 0) return ret;
    }
    if (!disable_xor) encrypt_0(data, len, key_string);
    return 0;
}

int de_cook(char *s, int &len, const address_t *src) {
    if (g_crypto_cfg.cipher != CRYPTO_CIPHER_NONE) {
        int ret = de_cook_aead(s, len);
        if (ret != 0) auth_drop_note(auth_plane_data, src);
        return ret;
    }

    if (!disable_xor) decrypt_0(s, len, key_string);
    if (!disable_obscure) {
        int ret = de_obscure(s, len);
        if (ret != 0) {
            mylog(log_debug, "de_obscure fail\n");
            auth_drop_note(auth_plane_data, src);
            return ret;
        }
    }
    int ret = rm_siphtag(s, len);
    if (ret != 0) {
        mylog(log_debug, "siphash tag check failed\n");
        auth_drop_note(auth_plane_data, src);
        return ret;
    }
    return 0;
}
int rm_siphtag(char *s, int &len) {
    if (len < (int)sizeof(uint64_t)) return -1;
    if (!auth_verify(DOMAIN_DATA, (const uint8_t *)s, (size_t)(len - (int)sizeof(uint64_t)),
                     (const uint8_t *)(s + len - (int)sizeof(uint64_t)))) {
        return -1;
    }
    len -= (int)sizeof(uint64_t);
    return 0;
}
/*
int do_obs()
{

}
int de_obs()*/
int put_conv(u32_t conv, const char *input, int len_in, char *&output, int &len_out) {
    static char buf[buf_len];
    output = buf;
    u32_t n_conv = htonl(conv);
    memcpy(output, &n_conv, sizeof(n_conv));
    memcpy(output + sizeof(n_conv), input, len_in);
    len_out = len_in + (int)(sizeof(n_conv));

    return 0;
}
int get_conv(u32_t &conv, const char *input, int len_in, char *&output, int &len_out) {
    u32_t n_conv;
    memcpy(&n_conv, input, sizeof(n_conv));
    conv = ntohl(n_conv);
    output = (char *)input + sizeof(n_conv);
    len_out = len_in - (int)sizeof(n_conv);
    if (len_out < 0) {
        mylog(log_debug, "len_out<0\n");
        return -1;
    }
    return 0;
}
