#include "auth.h"
#include "packet.h"  // key_string
#include "siphash.h"
#include <stdio.h>
#include <string.h>

uint8_t g_psk[16] = {};

static int hex_value(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void auth_key_set(const uint8_t key[16]) {
    memmove(g_psk, key, sizeof(g_psk));
    // Include the terminating NUL in each 12-byte label. Extract SipHash's
    // conventional little-endian output bytes explicitly, not in host order.
    const uint64_t a = siphash24("UDPSPD-XOR-A", 12, g_psk);
    const uint64_t b = siphash24("UDPSPD-XOR-B", 12, g_psk);
    uint8_t xk[16];
    for (int i = 0; i < 8; i++) {
        xk[i] = (uint8_t)(a >> (8 * i));
        xk[i + 8] = (uint8_t)(b >> (8 * i));
    }
    const char digits[] = "0123456789abcdef";
    memset(key_string, 0, sizeof(key_string));
    for (int i = 0; i < 16; i++) {
        key_string[2 * i] = digits[xk[i] >> 4];
        key_string[2 * i + 1] = digits[xk[i] & 0x0f];
    }
}

bool auth_key_set_hex(const char *hex) {
    if (hex == NULL || strlen(hex) != 32) return false;
    uint8_t key[16];
    for (int i = 0; i < 16; i++) {
        int hi = hex_value((unsigned char)hex[2 * i]);
        int lo = hex_value((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        key[i] = (uint8_t)((hi << 4) | lo);
    }
    auth_key_set(key);
    return true;
}

void auth_tag(uint8_t domain, const uint8_t *msg, size_t len, uint8_t out[8]) {
    uint8_t key[16];
    memcpy(key, g_psk, sizeof(key));
    key[0] ^= domain;
    const uint64_t tag = siphash24(msg, len, key);
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(tag >> (56 - 8 * i));
}

bool auth_verify(uint8_t domain, const uint8_t *msg, size_t len, const uint8_t tag[8]) {
    uint8_t expected[8];
    auth_tag(domain, msg, len, expected);
    // Volatile accumulator keeps all eight comparisons, with no early exit.
    volatile uint8_t difference = 0;
    for (int i = 0; i < 8; i++) difference |= expected[i] ^ tag[i];
    return difference == 0;
}

void auth_selftest(int &checks, int &failures) {
    uint8_t saved_key[16];
    char saved_xor[sizeof(key_string)];
    memcpy(saved_key, g_psk, sizeof(saved_key));
    memcpy(saved_xor, key_string, sizeof(saved_xor));
    const auto check = [&](bool ok, const char *description) {
        checks++;
        if (!ok) failures++;
        printf("%s [auth]: %s\n", ok ? "PASS" : "FAIL", description);
    };

    const char key_hex[] = "000102030405060708090a0b0c0d0e0f";
    uint8_t key[16], msg[15];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 15; i++) msg[i] = (uint8_t)i;
    check(auth_key_set_hex(key_hex), "accept exactly 32 lowercase hex characters");
    check(memcmp(g_psk, key, 16) == 0, "hex setter decodes the PSK");
    char derived[33];
    memcpy(derived, key_string, sizeof(derived));
    check(auth_key_set_hex("000102030405060708090A0b0C0d0E0F"), "accept mixed-case ASCII hex");
    check(memcmp(g_psk, key, 16) == 0 && strcmp(derived, key_string) == 0,
          "hex decoding is case-insensitive");
    const char *invalid[] = {NULL, "", "0", "000102030405060708090a0b0c0d0e0",
                             "000102030405060708090a0b0c0d0e0ff", "000102030405060708090a0b0c0d0e0g",
                             "000102030405060708090a0b0c0d0e0 ", "000102030405060708090a0b0c0d0e0\x80"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        check(!auth_key_set_hex(invalid[i]), "reject invalid hex input");
        check(memcmp(g_psk, key, 16) == 0 && strcmp(derived, key_string) == 0,
              "invalid input leaves both keys unchanged");
    }
    auth_key_set(key);
    check(strcmp(derived, key_string) == 0, "direct setter derives the same XOR key");

    uint8_t tag[8], again[8];
    auth_tag(DOMAIN_DATA, msg, sizeof(msg), tag);
    auth_tag(DOMAIN_DATA, msg, sizeof(msg), again);
    check(memcmp(tag, again, 8) == 0 && auth_verify(DOMAIN_DATA, msg, sizeof(msg), tag),
          "(a) same key, domain and message give equal valid tags");
    msg[7] ^= 1;
    check(!auth_verify(DOMAIN_DATA, msg, sizeof(msg), tag), "(b) one-bit message flip fails verification");
    msg[7] ^= 1;
    key[0] ^= 1;
    auth_key_set(key);
    check(!auth_verify(DOMAIN_DATA, msg, sizeof(msg), tag), "(c) different key fails verification");
    key[0] ^= 1;
    auth_key_set(key);
    const uint8_t domains[] = {DOMAIN_DATA, DOMAIN_CTRL, DOMAIN_TEST};
    for (int i = 0; i < 3; i++) {
        auth_tag(domains[i], msg, sizeof(msg), tag);
        for (int j = 0; j < 3; j++) {
            check(auth_verify(domains[j], msg, sizeof(msg), tag) == (i == j),
                  "(d) tags verify only in their own domain");
        }
    }
    check(memcmp(g_psk, key, 16) == 0, "domain tweaks never mutate the shared PSK");
    const uint8_t vector[8] = {0xa1, 0x29, 0xca, 0x61, 0x49, 0xbe, 0x45, 0xe5};
    auth_tag(0x00, msg, sizeof(msg), tag);
    check(memcmp(tag, vector, 8) == 0, "(e) published 15-byte SipHash vector serialized big-endian");
    for (int i = 0; i < 8; i++) {
        tag[i] ^= 1;
        check(!auth_verify(0x00, msg, sizeof(msg), tag), "verify checks every tag byte");
        tag[i] ^= 1;
    }

    // Check the label-derived bytes independently of the setter's hex encoding.
    const uint64_t a = siphash24("UDPSPD-XOR-A", 12, key);
    const uint64_t b = siphash24("UDPSPD-XOR-B", 12, key);
    uint8_t decoded[16];
    bool derived_ok = strlen(key_string) == 32;
    for (int i = 0; i < 16; i++) {
        int hi = hex_value((unsigned char)key_string[2 * i]);
        int lo = hex_value((unsigned char)key_string[2 * i + 1]);
        decoded[i] = (uint8_t)((hi < 0 ? 0 : hi) * 16 + (lo < 0 ? 0 : lo));
        uint8_t expected = (uint8_t)((i < 8 ? a : b) >> (8 * (i % 8)));
        derived_ok = derived_ok && hi >= 0 && lo >= 0 && decoded[i] == expected &&
                     !(key_string[2 * i] >= 'A' && key_string[2 * i] <= 'F') &&
                     !(key_string[2 * i + 1] >= 'A' && key_string[2 * i + 1] <= 'F');
    }
    check(derived_ok, "(f) XOR key is lowercase hex of the two label-derived SipHash outputs");
    check(strcmp(key_string, key_hex) != 0 && memcmp(decoded, g_psk, 16) != 0,
          "(f) XOR key is neither PSK hex nor PSK bytes after decoding");
    bool absent = true;
    for (size_t i = 0; i + sizeof(g_psk) <= sizeof(key_string); i++) {
        if (memcmp(key_string + i, g_psk, sizeof(g_psk)) == 0) absent = false;
    }
    check(absent, "(g) raw PSK is absent from the entire XOR buffer");

    memcpy(g_psk, saved_key, sizeof(saved_key));
    memcpy(key_string, saved_xor, sizeof(saved_xor));
}
