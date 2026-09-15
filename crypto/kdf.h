#ifndef UDP_SPEEDER_CRYPTO_KDF_H
#define UDP_SPEEDER_CRYPTO_KDF_H

#include <stdint.h>

// Domain-separated key derivation (design G14/G15).
//
// Each plane gets its own 32-byte key derived from the 16-byte PSK with keyed
// BLAKE2b (Monocypher, bridged by crypto/wrap.h): the PSK is the key, the
// ASCII label below is the message, and the digest is exactly 32 bytes --
// Monocypher honors the requested digest size, so never assume a 64-byte
// output. The labels are fixed, NUL-free strings, so no two planes share key
// material. Only CRYPTO_KDF_LABEL_DATA is consumed in this version; the
// control and test planes keep authenticating with SipHash (G15), so a derived
// control/test key must never be fed into a MAC path.
#define CRYPTO_KDF_LABEL_DATA "udpspeeder/data"
#define CRYPTO_KDF_LABEL_CONTROL "udpspeeder/control"
#define CRYPTO_KDF_LABEL_TEST "udpspeeder/test"

#define CRYPTO_KDF_KEY_LEN 32

// Derive the 32-byte key for `label` from the live PSK into `out`.
//
// Returns false without touching `out` if `out` or `label` is NULL, or if no
// key has been installed yet. The static PSK buffer is all-zero until the -k
// gate accepts a key, and a key derived from that would be publicly
// computable, so this fails closed instead; an explicitly configured all-zero
// PSK is the operator's choice and is not an error. Derivation is lazy and
// deterministic: callers just call this after process_arg() (the -k gate) has
// run, and must never receive the PSK itself back.
bool crypto_kdf(uint8_t out[CRYPTO_KDF_KEY_LEN], const char *label);

#endif /* UDP_SPEEDER_CRYPTO_KDF_H */
