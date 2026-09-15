// Included by test_mode.cpp after TCHECK; exercises production packet/FEC paths.
#include "packet.h"
#include "fec_manager.h"
#include "misc.h"
#include "crypto/crypto_cfg.h"
#include "crypto/kdf.h"
#include "crypto/wrap.h"
#include <sys/wait.h>
#include <getopt.h>

static void data_plane_auth_checks(char *plain, int plain_len) {
    const int saved_obscure = disable_obscure, saved_xor = disable_xor;
    uint8_t key[16];
    memcpy(key, g_psk, sizeof(key));
    // Check both the bare authenticated range and the actual obscured/XOR wire.
    for (int wrapped = 0; wrapped <= 1; wrapped++) {
        disable_obscure = disable_xor = !wrapped;
        char wire[buf_len], received[buf_len];
        memcpy(wire, plain, plain_len);
        int wire_len = plain_len;
        TCHECK(do_cook(wire, wire_len) == 0, "data-plane cook");
        TCHECK(wire_len == plain_len + 8 + (wrapped ? 33 : 0), "data-plane exact tag/maximum obscure overhead: %d", wire_len);
        memcpy(received, wire, wire_len);
        int len = wire_len;
        TCHECK(de_cook(received, len) == 0 && len == plain_len && memcmp(received, plain, plain_len) == 0,
               "data-plane same-key round trip, wrapped=%d", wrapped);
        // Obscure and XOR preserve byte positions in the authenticated prefix.
        // Flip one bit at EVERY byte: FEC seq/type/count/index, length, conv,
        // payload, and all eight trailer bytes. Do not recompute the tag.
        for (int byte = 0; byte < plain_len + 8; byte++) {
            memcpy(received, wire, wire_len);
            received[byte] ^= 1;
            len = wire_len;
            TCHECK(de_cook(received, len) != 0, "data-plane tamper accepted at byte=%d wrapped=%d", byte, wrapped);
        }
        uint8_t wrong[16];
        memcpy(wrong, key, sizeof(wrong));
        wrong[0] ^= 1;
        auth_key_set(wrong);
        memcpy(received, wire, wire_len);
        len = wire_len;
        TCHECK(de_cook(received, len) != 0, "data-plane wrong key accepted, wrapped=%d", wrapped);
        auth_key_set(key);
        if (!wrapped) {
            for (int short_len = 0; short_len < 8; short_len++) {
                len = short_len;
                TCHECK(de_cook(received, len) != 0, "data-plane short trailer accepted: %d", short_len);
            }
        }
    }
    disable_obscure = saved_obscure;
    disable_xor = saved_xor;
}

static int data_plane_batch_len(int sequence) {
    int slot = sequence % IO_BATCH_MAX;
    // Large packets immediately before AND after each full-batch boundary,
    // interspersed with distinct short lengths to detect stale iovec lengths.
    return slot == 0 || slot == IO_BATCH_MAX - 1 ? max_data_len + 14 : 14 + sequence % 31;
}

static void data_plane_batch_checks(const char *plain) {
    int receiver = socket(AF_INET, SOCK_DGRAM, 0);
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    TCHECK(receiver >= 0 && sender >= 0, "batch UDP sockets");
    if (receiver < 0 || sender < 0) {
        if (receiver >= 0) close(receiver);
        if (sender >= 0) close(sender);
        return;
    }
    address_t addr;
    addr.clear();
    addr.inner.ipv4.sin_family = AF_INET;
    addr.inner.ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int ret = bind(receiver, (sockaddr *)&addr.inner, addr.get_len());
    TCHECK(ret == 0, "batch bind ephemeral loopback port");
    socklen_t addr_len = addr.get_len();
    ret |= getsockname(receiver, (sockaddr *)&addr.inner, &addr_len);
    int capacity = 1024 * 1024;
    ret |= setsockopt(receiver, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof(capacity));
    timeval timeout = {2, 0};
    ret |= setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    TCHECK(ret == 0, "batch socket setup");
    if (ret == 0) {
        dest_t dest;
        dest.type = type_fd_addr;
        dest.inner.fd_addr.fd = sender;
        dest.inner.fd_addr.addr = addr;
        dest.cook = 1;
        const int count = 2 * IO_BATCH_MAX + 1;
        u64_t drops = short_send_drop_count;
        my_send_batch_begin();
        for (int sequence = 0; sequence < count; sequence++) {
            char packet[buf_len];
            int len = data_plane_batch_len(sequence);
            memcpy(packet, plain, len);
            write_u32(packet, sequence);
            TCHECK(my_send(dest, packet, len) >= 0, "batch send sequence=%d", sequence);
            // No manual flush at either boundary: only my_send may flush.
        }
        my_send_flush();
        TCHECK(short_send_drop_count == drops, "batch must not drop a short send");
        for (int sequence = 0; sequence < count; sequence++) {
            char packet[buf_len], expected[buf_len];
            int expected_len = data_plane_batch_len(sequence);
            int len = recv(receiver, packet, sizeof(packet), MSG_TRUNC);
            TCHECK(len == expected_len + 41, "batch wire length sequence=%d got=%d expected=%d", sequence, len, expected_len + 41);
            if (len < 0 || len >= buf_len) break;
            TCHECK(de_cook(packet, len) == 0, "batch authentication sequence=%d", sequence);
            memcpy(expected, plain, expected_len);
            write_u32(expected, sequence);
            TCHECK(len == expected_len && memcmp(packet, expected, expected_len) == 0,
                   "batch order/content sequence=%d got=%u len=%d", sequence, read_u32(packet), len);
        }
        char extra[buf_len];
        TCHECK(recv(receiver, extra, sizeof(extra), MSG_DONTWAIT) == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
               "batch must deliver exactly 2*IO_BATCH_MAX+1 packets");
    }
    close(sender);
    close(receiver);
}

static void data_plane_selftest() {
    // process_arg's early --test-selftest dispatch skips normal parsing. Fork
    // to exercise the REAL deprecated flag and MTU parser without leaking its
    // globals/getopt state or the test key into the remaining selftests.
    fflush(NULL);
    for (int checksum_disabled = 0; checksum_disabled <= 1; checksum_disabled++) {
        pid_t child = fork();
        TCHECK(child >= 0, "data-plane fork");
        if (child == 0) {
            g_checks = g_failures = 0;
            char name[] = "data-plane-selftest", client[] = "-c";
            char local[] = "-l127.0.0.1:0", remote[] = "-r127.0.0.1:9";
            char key[] = "-k000102030405060708090a0b0c0d0e0f";
            char mtu[] = "--mtu", size[] = "2000", mode[] = "--mode", one[] = "1";
            char fec[] = "-f1:0", deprecated[] = "--disable-checksum";
            char *args[] = {name, client, local, remote, key, mtu, size, mode, one, fec, deprecated, NULL};
            optind = 0;
            process_arg(checksum_disabled ? 11 : 10, args);
            TCHECK(g_fec_par.mtu == 2000 && g_fec_par.mode == 1, "data-plane --mtu 2000 --mode 1 parsed");
            TCHECK(!disable_obscure && !disable_xor && key_string[0], "data-plane obscure and XOR enabled");
            iv_min = iv_max = 32;  // Force worst-case obscure padding, not luck.
            char payload[max_data_len];
            for (int i = 0; i < max_data_len; i++) payload[i] = (char)(i * 37);
            char *conv_packet = NULL;
            int conv_len = 0;
            TCHECK(put_conv(0x12345678, payload, sizeof(payload), conv_packet, conv_len) == 0 && conv_len == max_data_len + 4,
                   "data-plane max payload conv framing");
            struct ev_loop *loop = ev_loop_new(0);
            TCHECK(loop != NULL, "data-plane FEC loop");
            if (loop != NULL) {
                fec_encode_manager_t *encoder = new fec_encode_manager_t;
                encoder->set_loop_and_cb(loop, [](struct ev_loop *, ev_timer *, int) {});
                TCHECK(encoder->input(conv_packet, conv_len) == 0, "data-plane worst-case FEC input");
                int count = 0, *lengths = NULL;
                char **shards = NULL;
                TCHECK(encoder->output(count, shards, lengths) == 0 && count == 1, "data-plane FEC output");
                if (count == 1) {
                    TCHECK(lengths[0] == max_data_len + 14, "data-plane maximum pre-tag length must be 3614");
                    data_plane_auth_checks(shards[0], lengths[0]);
                    data_plane_batch_checks(shards[0]);
                }
                delete encoder;
                ev_loop_destroy(loop);
            }
            printf("data-plane selftest (--disable-checksum=%d, mtu=2000): %d checks, %d failures\n",
                   checksum_disabled, g_checks, g_failures);
            exit(g_failures ? 1 : 0);
        }
        if (child > 0) {
            int status = 0;
            pid_t waited;
            do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
            TCHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                   "data-plane child --disable-checksum=%d status=%d", checksum_disabled, status);
        }
    }
}

// In-process cipher-mode (--cipher) regression: the AEAD data plane, the bucket
// padding frame, the G18 key separation, and the proof that cipher mode emits
// no SipHash tag and no obscure/XOR layer. `shard` is a cooked-ready FEC shard;
// the function drives the real do_cook/de_cook entry points and restores every
// global it touches, so it can run twice (short shard and worst case) and the
// rest of the selftest sees the configuration it started with.
static void data_plane_cipher_checks(const char *shard, int shard_len) {
    crypto_cfg_t saved_cfg = g_crypto_cfg;
    const int saved_obscure = disable_obscure, saved_xor = disable_xor;
    uint8_t saved_key[16];
    char saved_xor_key[sizeof(key_string)];
    memcpy(saved_key, g_psk, sizeof(saved_key));
    memcpy(saved_xor_key, key_string, sizeof(saved_xor_key));

    uint8_t psk[16];
    for (int i = 0; i < 16; i++) psk[i] = (uint8_t)(0x30 + i);
    auth_key_set(psk);

    uint8_t kdf_key[CRYPTO_KDF_KEY_LEN];
    TCHECK(crypto_kdf(kdf_key, CRYPTO_KDF_LABEL_DATA),
           "cipher: KDF derives the data key");

    const uint8_t cipher_id = (uint8_t)CRYPTO_CIPHER_XCHACHA20_IETF_POLY1305;
    uint8_t ad[2] = {cipher_id, 0};
    g_crypto_cfg.cipher = CRYPTO_CIPHER_XCHACHA20_IETF_POLY1305;
    g_crypto_cfg.pad_bucket = 0;
    g_crypto_cfg.rotate_sec = 0;

    char wire[buf_len], second[buf_len], received[buf_len];
    memcpy(wire, shard, shard_len);
    int wire_len = shard_len;
    TCHECK(do_cook(wire, wire_len) == 0, "cipher: do_cook succeeds");
    TCHECK(wire_len == shard_len + AEAD_NONCE_LEN + AEAD_TAG_LEN,
           "cipher: wire is exactly nonce+ciphertext+tag, got %d", wire_len);
    TCHECK(wire_len <= buf_len,
           "cipher: frame stays within buf_len (%d <= %d)", wire_len, buf_len);
    TCHECK(cook_overhead() == AEAD_NONCE_LEN + AEAD_TAG_LEN,
           "cipher: cook_overhead is the bare AEAD frame (%d)", cook_overhead());

    memcpy(received, wire, wire_len);
    int len = wire_len;
    TCHECK(de_cook(received, len) == 0 && len == shard_len &&
               memcmp(received, shard, shard_len) == 0,
           "cipher: same-key round trip");

    // The G12 frame authenticates under the KDF data key and unwraps to the
    // original shard byte-for-byte with no pad strip, no SipHash and no
    // obscure/XOR: any XOR or obscure trailer would mis-decrypt. This is the
    // operational proof that cipher mode emits zero XOR/obscure bytes.
    uint8_t plain_out[buf_len];
    size_t plain_out_len = 0;
    TCHECK(crypto_wrap_aead_decrypt(plain_out, sizeof(plain_out), &plain_out_len,
                                    kdf_key, ad, sizeof(ad),
                                    (const uint8_t *)wire, (size_t)wire_len) == 0 &&
               plain_out_len == (size_t)shard_len &&
               memcmp(plain_out, shard, shard_len) == 0,
           "cipher: wire unwraps under the KDF key with no XOR/obscure layer");

    // Nonce uniqueness: the same plaintext must not yield the same wire twice.
    memcpy(second, shard, shard_len);
    int second_len = shard_len;
    TCHECK(do_cook(second, second_len) == 0 && second_len == wire_len,
           "cipher: a second do_cook succeeds at the same length");
    TCHECK(memcmp(wire, second, wire_len) != 0,
           "cipher: two encrypts of the same plaintext differ (fresh nonce)");
    TCHECK(memcmp(wire, second, AEAD_NONCE_LEN) != 0,
           "cipher: a fresh 24-byte nonce is drawn per frame");

    // 1-byte tamper and wrong-key must both be dropped.
    memcpy(received, wire, wire_len);
    received[AEAD_NONCE_LEN + 2] ^= 0x01;
    len = wire_len;
    TCHECK(de_cook(received, len) != 0, "cipher: one flipped ciphertext byte is dropped");

    uint8_t wrong[16];
    memcpy(wrong, psk, sizeof(wrong));
    wrong[0] ^= 0x01;
    auth_key_set(wrong);
    memcpy(received, wire, wire_len);
    len = wire_len;
    TCHECK(de_cook(received, len) != 0, "cipher: a wrong key is dropped");
    auth_key_set(psk);

    // G18: the data key is the KDF output, not key_string, and cannot be
    // reconstructed from key_string.
    TCHECK(memcmp(kdf_key, key_string, CRYPTO_KDF_KEY_LEN) != 0,
           "G18: the data key is not key_string");
    uint8_t ks_key[CRYPTO_KDF_KEY_LEN];
    memcpy(ks_key, key_string, CRYPTO_KDF_KEY_LEN);
    plain_out_len = 0;
    TCHECK(crypto_wrap_aead_decrypt(plain_out, sizeof(plain_out), &plain_out_len,
                                    ks_key, ad, sizeof(ad),
                                    (const uint8_t *)wire, (size_t)wire_len) == -1,
           "G18: key_string cannot unwrap the cipher frame");
    uint8_t ks_derived[CRYPTO_KDF_KEY_LEN];
    crypto_wrap_blake2b_keyed(ks_derived, sizeof(ks_derived),
                              (const uint8_t *)key_string, CRYPTO_KDF_KEY_LEN,
                              (const uint8_t *)CRYPTO_KDF_LABEL_DATA,
                              strlen(CRYPTO_KDF_LABEL_DATA));
    TCHECK(memcmp(ks_derived, kdf_key, CRYPTO_KDF_KEY_LEN) != 0,
           "G18: the data key is not a BLAKE2b derivation keyed by key_string");

    // Cipher mode ignores the obscure/XOR switches: the frame layout is the same
    // with them disabled, because there is no XOR/obscure layer at all.
    disable_obscure = disable_xor = 1;
    memcpy(received, shard, shard_len);
    len = shard_len;
    TCHECK(do_cook(received, len) == 0 &&
               len == shard_len + AEAD_NONCE_LEN + AEAD_TAG_LEN,
           "cipher: layout is unchanged with obscure/XOR disabled");
    disable_obscure = saved_obscure;
    disable_xor = saved_xor;

    // ---- bucket padding ----
    const int buckets[4] = {0, 16, 32, 64};
    for (int i = 0; i < 4; i++) {
        const int bucket = buckets[i];
        g_crypto_cfg.pad_bucket = bucket;
        memcpy(received, shard, shard_len);
        len = shard_len;
        TCHECK(do_cook(received, len) == 0, "pad bucket=%d: do_cook succeeds", bucket);
        TCHECK(len <= buf_len, "pad bucket=%d: frame stays within buf_len (%d)", bucket, len);
        if (bucket > 0) {
            int plain_region = len - AEAD_NONCE_LEN - AEAD_TAG_LEN;
            TCHECK(plain_region % bucket == 0,
                   "pad bucket=%d: authenticated region %d is bucket-aligned",
                   bucket, plain_region);
        }
        char recovered[buf_len];
        memcpy(recovered, received, len);
        int rlen = len;
        TCHECK(de_cook(recovered, rlen) == 0 && rlen == shard_len &&
                   memcmp(recovered, shard, shard_len) == 0,
               "pad bucket=%d: round trip", bucket);
    }

    // Bucket 0 adds nothing: rebuild the bare G12 frame with the very nonce the
    // cipher path drew and require byte-for-byte equality. A pad_len byte would
    // make the two differ.
    g_crypto_cfg.pad_bucket = 0;
    memcpy(received, shard, shard_len);
    len = shard_len;
    TCHECK(do_cook(received, len) == 0 &&
               len == shard_len + AEAD_NONCE_LEN + AEAD_TAG_LEN,
           "pad bucket=0: no pad_len byte is added");
    uint8_t used_nonce[AEAD_NONCE_LEN];
    memcpy(used_nonce, received, AEAD_NONCE_LEN);
    char manual[buf_len];
    size_t manual_len = 0;
    TCHECK(crypto_wrap_aead_encrypt((uint8_t *)manual, sizeof(manual), &manual_len,
                                    kdf_key, used_nonce, ad, sizeof(ad),
                                    (const uint8_t *)shard, (size_t)shard_len) == 0,
           "pad bucket=0: rebuild the no-pad G12 frame");
    TCHECK(manual_len == (size_t)len && memcmp(manual, received, len) == 0,
           "pad bucket=0: wire is byte-identical to the no-pad cipher frame");

    // A validly-authenticated frame whose trailing pad_len is out of range must
    // be dropped by the strip step, never accepted. The frame is built directly
    // so the AEAD is correct and only the pad_len is bad.
    {
        const int bucket = 64;
        g_crypto_cfg.pad_bucket = bucket;
        uint8_t bad_plain[128];
        memset(bad_plain, 0x5a, sizeof(bad_plain));
        bad_plain[sizeof(bad_plain) - 1] = 0xff;  // 255 > bucket-1
        uint8_t bad_nonce[AEAD_NONCE_LEN];
        for (int i = 0; i < AEAD_NONCE_LEN; i++) bad_nonce[i] = (uint8_t)(0x90 + i);
        uint8_t bad_ad[2] = {cipher_id, (uint8_t)bucket};
        char bad_frame[buf_len];
        size_t bad_frame_len = 0;
        TCHECK(crypto_wrap_aead_encrypt((uint8_t *)bad_frame, sizeof(bad_frame),
                                        &bad_frame_len, kdf_key, bad_nonce,
                                        bad_ad, sizeof(bad_ad), bad_plain,
                                        sizeof(bad_plain)) == 0,
               "pad: build an authenticated frame with an out-of-range pad_len");
        char bad_recv[buf_len];
        memcpy(bad_recv, bad_frame, bad_frame_len);
        int bad_recv_len = (int)bad_frame_len;
        TCHECK(de_cook(bad_recv, bad_recv_len) != 0,
               "pad: an out-of-range trailing pad_len is dropped");
    }

    memcpy(g_psk, saved_key, sizeof(saved_key));
    memcpy(key_string, saved_xor_key, sizeof(saved_xor_key));
    g_crypto_cfg = saved_cfg;
}

static void data_plane_cipher_selftest() {
    // Short shard, in-process: 100 is not a multiple of any bucket, so a missing
    // pad step cannot satisfy the alignment check by luck.
    char shard[100];
    for (int i = 0; i < (int)sizeof(shard); i++) shard[i] = (char)(i * 53);
    data_plane_cipher_checks(shard, (int)sizeof(shard));

    // Worst case (ASan/UBSan): fork so the REAL --mtu 2000 / --mode 1 parser
    // builds the 3614-byte maximum-length shard, then run the same cipher/pad
    // checks against max_data_len + mtu2000 + bucket 64 + cipher.
    fflush(NULL);
    pid_t child = fork();
    TCHECK(child >= 0, "cipher worst-case fork");
    if (child == 0) {
        g_checks = g_failures = 0;
        char name[] = "cipher-worst-case";
        char client[] = "-c";
        char local[] = "-l127.0.0.1:0", remote[] = "-r127.0.0.1:9";
        char key[] = "-k000102030405060708090a0b0c0d0e0f";
        char mtu[] = "--mtu", size[] = "2000", mode[] = "--mode", one[] = "1";
        char fec[] = "-f1:0";
        char cipher[] = "--cipher", scheme[] = "xchacha20-ietf-poly1305";
        char pad[] = "--pad", bucket[] = "64";
        char *args[] = {name, client, local, remote, key, mtu, size, mode, one,
                        fec, cipher, scheme, pad, bucket, NULL};
        optind = 0;
        process_arg(14, args);
        TCHECK(g_crypto_cfg.cipher == CRYPTO_CIPHER_XCHACHA20_IETF_POLY1305 &&
                   g_crypto_cfg.pad_bucket == 64,
               "cipher worst case: --cipher/--pad 64 parsed");
        TCHECK(g_fec_par.mtu == 2000 && g_fec_par.mode == 1,
               "cipher worst case: --mtu 2000 --mode 1 parsed");

        char payload[max_data_len];
        for (int i = 0; i < max_data_len; i++) payload[i] = (char)(i * 37);
        char *conv_packet = NULL;
        int conv_len = 0;
        TCHECK(put_conv(0x12345678, payload, sizeof(payload), conv_packet, conv_len) == 0 &&
                   conv_len == max_data_len + 4,
               "cipher worst case: max payload conv framing");

        struct ev_loop *loop = ev_loop_new(0);
        TCHECK(loop != NULL, "cipher worst case: FEC loop");
        if (loop != NULL) {
            fec_encode_manager_t *encoder = new fec_encode_manager_t;
            encoder->set_loop_and_cb(loop, [](struct ev_loop *, ev_timer *, int) {});
            TCHECK(encoder->input(conv_packet, conv_len) == 0, "cipher worst case: FEC input");
            int count = 0, *lengths = NULL;
            char **shards = NULL;
            TCHECK(encoder->output(count, shards, lengths) == 0 && count == 1,
                   "cipher worst case: FEC output");
            if (count == 1) {
                TCHECK(lengths[0] == max_data_len + 14,
                       "cipher worst case: maximum pre-tag length must be 3614");
                data_plane_cipher_checks(shards[0], lengths[0]);
            }
            delete encoder;
            ev_loop_destroy(loop);
        }
        printf("cipher worst-case selftest (mtu=2000, pad=64): %d checks, %d failures\n",
               g_checks, g_failures);
        exit(g_failures ? 1 : 0);
    }
    if (child > 0) {
        int status = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        TCHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
               "cipher worst-case child status=%d", status);
    }
}
