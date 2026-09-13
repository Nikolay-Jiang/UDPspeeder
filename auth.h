#ifndef AUTH_H_
#define AUTH_H_

#include <stddef.h>
#include <stdint.h>

extern uint8_t g_psk[16];

const uint8_t DOMAIN_DATA = 0x01;
const uint8_t DOMAIN_CTRL = 0x02;
const uint8_t DOMAIN_TEST = 0x03;

bool auth_key_set_hex(const char *hex);
void auth_key_set(const uint8_t key[16]);
// Domain 0x00 is reserved for raw SipHash vectors. Tags are big-endian.
void auth_tag(uint8_t domain, const uint8_t *msg, size_t len, uint8_t out[8]);
bool auth_verify(uint8_t domain, const uint8_t *msg, size_t len, const uint8_t tag[8]);
void auth_selftest(int &checks, int &failures);

#endif /* AUTH_H_ */
