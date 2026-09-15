#ifndef UDP_SPEEDER_CRYPTO_WRAP_H
#define UDP_SPEEDER_CRYPTO_WRAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Thin in-house bridge over the vendored Monocypher 4.0.2 primitives. The
// names here are deliberately our own; no borrowed third-party AEAD alias is
// exported.

// Data-plane AEAD frame (G12): [nonce(24)][ciphertext][tag(16)].
#define CRYPTO_WRAP_NONCE_LEN 24
#define CRYPTO_WRAP_TAG_LEN 16

// Encrypt plain[0..plain_len) into the G12 frame [nonce||ciphertext||tag],
// using the caller-supplied 24-byte nonce (whoever draws it is responsible for
// uniqueness). `out` must hold CRYPTO_WRAP_NONCE_LEN + plain_len +
// CRYPTO_WRAP_TAG_LEN bytes. A non-NULL `ad` with `ad_len == 0`, or a NULL
// `ad` with `ad_len == 0`, both mean "no associated data".
//
// Returns 0 and stores the frame length in *out_len on success, or -1 if a
// pointer is NULL or out_cap is too small.
int crypto_wrap_aead_encrypt(uint8_t *out, size_t out_cap, size_t *out_len,
                             const uint8_t key[32], const uint8_t nonce[24],
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t *plain, size_t plain_len);

// Verify and decrypt a G12 frame in[0..in_len). The nonce is read from the
// frame prefix. On success the recovered plaintext is written to `out` (which
// must hold in_len - CRYPTO_WRAP_NONCE_LEN - CRYPTO_WRAP_TAG_LEN bytes) and
// its length is stored in *out_len.
//
// Returns 0 on success, or -1 on a malformed/short frame, insufficient
// out_cap, or authentication failure. A failed frame writes nothing to `out`.
int crypto_wrap_aead_decrypt(uint8_t *out, size_t out_cap, size_t *out_len,
                             const uint8_t key[32],
                             const uint8_t *ad, size_t ad_len,
                             const uint8_t *in, size_t in_len);

// Unkeyed BLAKE2b. out_len is the desired digest size (1..64).
void crypto_wrap_blake2b(uint8_t *out, size_t out_len,
                         const uint8_t *msg, size_t msg_len);

// Keyed BLAKE2b, the KDF primitive: key is the 16-byte PSK, message is the
// domain label. out_len is the desired digest size (1..64).
void crypto_wrap_blake2b_keyed(uint8_t *out, size_t out_len,
                               const uint8_t *key, size_t key_len,
                               const uint8_t *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif /* UDP_SPEEDER_CRYPTO_WRAP_H */
