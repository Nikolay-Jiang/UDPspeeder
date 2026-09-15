#include "wrap.h"
#include "monocypher.h"

#include <string.h>

int crypto_wrap_aead_encrypt(uint8_t *out, size_t out_cap, size_t *out_len,
                             const uint8_t key[32], const uint8_t nonce[24],
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t *plain, size_t plain_len) {
    if (out == 0 || out_len == 0 || key == 0 || nonce == 0 || plain == 0) {
        return -1;
    }
    if (ad == 0 && ad_len != 0) return -1;

    const size_t frame_len = CRYPTO_WRAP_NONCE_LEN + plain_len + CRYPTO_WRAP_TAG_LEN;
    if (frame_len < plain_len) return -1;  // size_t overflow guard
    if (out_cap < frame_len) return -1;

    memcpy(out, nonce, CRYPTO_WRAP_NONCE_LEN);
    uint8_t *cipher = out + CRYPTO_WRAP_NONCE_LEN;
    uint8_t *mac = cipher + plain_len;
    crypto_aead_lock(cipher, mac, key, nonce, ad, ad_len, plain, plain_len);

    *out_len = frame_len;
    return 0;
}

int crypto_wrap_aead_decrypt(uint8_t *out, size_t out_cap, size_t *out_len,
                             const uint8_t key[32],
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t *in, size_t in_len) {
    if (out == 0 || out_len == 0 || key == 0 || in == 0) return -1;
    if (ad == 0 && ad_len != 0) return -1;
    if (in_len < CRYPTO_WRAP_NONCE_LEN + CRYPTO_WRAP_TAG_LEN) return -1;

    const size_t plain_len = in_len - CRYPTO_WRAP_NONCE_LEN - CRYPTO_WRAP_TAG_LEN;
    if (out_cap < plain_len) return -1;

    const uint8_t *nonce = in;
    const uint8_t *cipher = in + CRYPTO_WRAP_NONCE_LEN;
    const uint8_t *mac = cipher + plain_len;
    if (crypto_aead_unlock(out, mac, key, nonce, ad, ad_len, cipher, plain_len) != 0) {
        return -1;
    }

    *out_len = plain_len;
    return 0;
}

void crypto_wrap_blake2b(uint8_t *out, size_t out_len,
                         const uint8_t *msg, size_t msg_len) {
    crypto_blake2b(out, out_len, msg, msg_len);
}

void crypto_wrap_blake2b_keyed(uint8_t *out, size_t out_len,
                               const uint8_t *key, size_t key_len,
                               const uint8_t *msg, size_t msg_len) {
    crypto_blake2b_keyed(out, out_len, key, key_len, msg, msg_len);
}
