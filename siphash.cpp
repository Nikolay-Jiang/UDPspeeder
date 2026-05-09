// SipHash-2-4 reference implementation (public domain / CC0)
// https://131002.net/siphash/

#include "siphash.h"
#include <string.h>

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define U8TO64_LE(p)                              \
    (((uint64_t)((p)[0]))       |                 \
     ((uint64_t)((p)[1]) <<  8) |                 \
     ((uint64_t)((p)[2]) << 16) |                 \
     ((uint64_t)((p)[3]) << 24) |                 \
     ((uint64_t)((p)[4]) << 32) |                 \
     ((uint64_t)((p)[5]) << 40) |                 \
     ((uint64_t)((p)[6]) << 48) |                 \
     ((uint64_t)((p)[7]) << 56))

#define SIPROUND                                   \
    do {                                           \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0;   \
        v0 = ROTL(v0, 32);                         \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;   \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;   \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2;   \
        v2 = ROTL(v2, 32);                         \
    } while (0)

uint64_t siphash24(const void *in, size_t inlen, const uint8_t k[16]) {
    const uint8_t *ni = (const uint8_t *)in;
    uint64_t k0 = U8TO64_LE(k);
    uint64_t k1 = U8TO64_LE(k + 8);
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    const size_t blocks = inlen / 8;
    for (size_t i = 0; i < blocks; i++) {
        uint64_t m = U8TO64_LE(ni + i * 8);
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
    }

    const uint8_t *tail = ni + blocks * 8;
    uint64_t last = (uint64_t)(inlen & 0xff) << 56;
    switch (inlen & 7) {
        case 7: last |= (uint64_t)tail[6] << 48; /* fall through */
        case 6: last |= (uint64_t)tail[5] << 40; /* fall through */
        case 5: last |= (uint64_t)tail[4] << 32; /* fall through */
        case 4: last |= (uint64_t)tail[3] << 24; /* fall through */
        case 3: last |= (uint64_t)tail[2] << 16; /* fall through */
        case 2: last |= (uint64_t)tail[1] <<  8; /* fall through */
        case 1: last |= (uint64_t)tail[0];        /* fall through */
        default: break;
    }

    v3 ^= last;
    SIPROUND; SIPROUND;
    v0 ^= last;
    v2 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
