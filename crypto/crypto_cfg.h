/*
 * crypto_cfg.h
 *
 * CLI-selected crypto capability configuration. Parsed exactly once in
 * process_arg() (misc.cpp), then treated as immutable global state by the
 * data and control planes. This header declares only the capability surface;
 * the crypto behavior itself lives in the data plane (todos 5/6/7).
 */

#ifndef CRYPTO_CRYPTO_CFG_H_
#define CRYPTO_CRYPTO_CFG_H_

// crypto_cfg_t.cipher values. --cipher accepts exactly these two names.
enum crypto_cipher_id_t {
    CRYPTO_CIPHER_NONE = 0,
    CRYPTO_CIPHER_XCHACHA20_IETF_POLY1305 = 1
};

struct crypto_cfg_t {
    int cipher;      // crypto_cipher_id_t; CRYPTO_CIPHER_NONE unless --cipher is given
    int pad_bucket;  // 0 = off, otherwise 16, 32 or 64; non-zero requires a cipher
    int rotate_sec;  // --port-rotate-sec; 0 = rotation off
};

extern crypto_cfg_t g_crypto_cfg;

#endif /* CRYPTO_CRYPTO_CFG_H_ */
