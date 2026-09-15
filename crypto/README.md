# Vendored crypto

## Monocypher 4.0.2

`crypto/monocypher.c` and `crypto/monocypher.h` are the upstream Monocypher
4.0.2 `src/` files, copied **byte-for-byte** and never reformatted.

- Upstream: https://github.com/LoupVaillant/Monocypher
- Release tag: `4.0.2`
- Release asset: https://github.com/LoupVaillant/Monocypher/releases/download/4.0.2/monocypher-4.0.2.tar.gz
- Tarball size: 939996 bytes
- Tarball sha256 (computed from the asset downloaded from the URL above):
  `38d07179738c0c90677dba3ceb7a7b8496bcfea758ba1a53e803fed30ae0879c`

Upstream publishes no separate `.sha256`/checksum asset for this release (a
request for `monocypher-4.0.2.tar.gz.sha256` returns HTTP 404 and the GitHub
release lists only the tarball), so the sha256 above is recorded as the pin
for the exact asset this vendoring was taken from. The two extracted files
also hash as:

- `crypto/monocypher.c` sha256: `afe2b098c8569577a84488e0b98d276d1fba6506adea68bb9241a52111734c59`
- `crypto/monocypher.h` sha256: `f78bb31255cfb7beba66afd2137f5194c8a025cf40488b6cc1e295234d43f374`

## Licence

Dual-licensed, choose either: 2-clause BSD **or** CC0-1.0, exactly as stated
in the file headers (`SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0`) and in
the upstream `LICENCE.md`.

## What we use

Only the AEAD and hash entry points are bridged; no libsodium-style name is
exported anywhere in this tree:

- `crypto_aead_lock` / `crypto_aead_unlock` (separate 16-byte `mac`)
- `crypto_blake2b` / `crypto_blake2b_keyed`

`crypto/wrap.c` / `crypto/wrap.h` expose our own thin wrappers
(`crypto_wrap_aead_encrypt` / `crypto_wrap_aead_decrypt` /
`crypto_wrap_blake2b` / `crypto_wrap_blake2b_keyed`). The AEAD wrapper
assembles the data-plane frame `[nonce(24)][ciphertext][tag(16)]` described by
design decision G12.
