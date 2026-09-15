#include "crypto/kdf.h"

#include <string.h>

#include "auth.h"
#include "crypto/wrap.h"

bool crypto_kdf(uint8_t out[CRYPTO_KDF_KEY_LEN], const char *label) {
    if (out == 0 || label == 0) return false;

    // Fail closed while the PSK is still unset: g_psk is all-zero until the -k
    // gate accepts a key, and a key derived from that is publicly computable.
    // auth_key_is_set() distinguishes "never configured" from an operator who
    // deliberately chose an all-zero PSK, which is accepted and not an error.
    if (!auth_key_is_set()) return false;

    // Keyed BLAKE2b: PSK as the key, the fixed ASCII domain label as the
    // message, exactly 32 bytes of output (G14). The wrapper is the only
    // Monocypher entry point used here; no third-party name leaks out.
    crypto_wrap_blake2b_keyed(out, CRYPTO_KDF_KEY_LEN, g_psk, 16,
                              (const uint8_t *)label, strlen(label));
    return true;
}
