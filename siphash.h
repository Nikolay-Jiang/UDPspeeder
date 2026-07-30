#ifndef SIPHASH_H_
#define SIPHASH_H_

#include <stddef.h>
#include <stdint.h>

// SipHash-2-4: 16-byte key, arbitrary input, 8-byte output.
uint64_t siphash24(const void *in, size_t inlen, const uint8_t k[16]);

#endif /* SIPHASH_H_ */
