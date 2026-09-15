# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

UDPspeeder V3 (`speederv2`) — a UDP tunnel that reduces packet loss on lossy links by applying Reed-Solomon Forward Error Correction, optionally combined with a UDP-based VPN to accelerate arbitrary traffic. C++11, event-loop based (libev), Linux x86 / x86_64 only.

## Build

The canonical build system is `makefile`. CMake exists only to generate `compile_commands.json` for clangd (see `CMakeLists.txt` note).

Common targets:
- `make` — native Linux static build with `-O2` (produces `speederv2`).
- `make debug` — defines `MY_DEBUG`, no `-O2`, includes `-Wformat-nonliteral`. Use this when iterating on protocol/state logic.
- `make fast` — optimized build with debug symbols, no `MY_DEBUG`.
- `make amd64`, `make x86` — static cross-compiles via the bundled OpenWRT x86 musl toolchains; paths are hard-coded at the top of the makefile and must be adjusted for your environment.
- `make release` — builds all cross targets and tarballs them.
- `make clean` — removes binaries and `git_version.h`.

Every target depends on `git_version`, which regenerates `git_version.h` from `git rev-parse HEAD`. That file is consumed by `main.cpp`'s `--version`/help output; don't commit it.

Verification is a mix of an in-process C++ selftest (`./speederv2 --test-selftest`, no network) and shell smoke suites under `tests/`. The makefile exposes `test` (selftest + base IPv4 smoke), `test-selftest`, `test-mode`, `test-port-range`, and `sanitize` (ASan/UBSan build that reruns the selftest and smoke test). `AGENTS.md` has the full matrix. `--random-drop` still simulates loss locally, in units of `0.01%`.

## Running

```
# server:
./speederv2 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 -f20:10 -k 00112233445566778899aabbccddeeff
# client:
./speederv2 -c -l0.0.0.0:3333 -r<server_ip>:4096 -f20:10 -k 00112233445566778899aabbccddeeff
```

`-f x:y` = send `y` redundant packets per `x` data packets. Common options must match on both sides. Full option list is in `main.cpp:print_help`.

Add `--cipher xchacha20-ietf-poly1305` to **both** commands above to switch the data plane to AEAD encryption; add `--pad 32` to both to also bucket the plaintext. Neither flag is needed for the default obfuscation + SipHash mode.

## Key and authentication

`-k`/`--key` takes **exactly 32 ASCII hex characters** (16 bytes, case-insensitive) and is **required in every network mode**; anything else fails before a socket is opened. Both ends must use the identical key.

The key is a SipHash-2-4 authentication key. It authenticates packets on all four wire planes (ordinary data, port-range data, port-range control, test mode); a peer with a different key, including an old build that used a passphrase, is rejected fail-closed. It does **not** provide confidentiality. The existing obscure/XOR layer is obfuscation only: it changes the wire pattern, and its keystream is derived one-way from the PSK, but it is never encryption. Do not describe SipHash or XOR as encryption anywhere.

## Data-plane encryption (V3)

Encryption is opt-in and off by default. The default mode is obfuscation + SipHash authentication and does **not** encrypt.

- `--cipher xchacha20-ietf-poly1305` turns on real data-plane AEAD (XChaCha20-Poly1305) via the vendored crypto in `crypto/`. `--cipher none` or omitting the flag keeps the default. Both ends must set the same value; a mismatch is refused at the port-range handshake, and in normal mode it surfaces as dropped, tamper-logged packets (`auth_drop: plane=...`).
- In cipher mode the wire frame is `nonce(24) + ciphertext + tag(16)`, replacing the 8-byte SipHash data-plane tag and the obscure layer, i.e. **+40 bytes per packet**. Note this wording: only `--cipher` encrypts; the default authenticates and obfuscates.
- `--pad <0|16|32|64>` pads the plaintext into a size bucket before AEAD. Non-zero requires `--cipher` (otherwise a fatal startup error) and must match on both ends; it adds a 1-byte `pad_len` plus up to 64 authenticated pad bytes.
- `--port-rotate-sec <sec>` (client, port-range mode only; default 0 = off) advances the round-robin data-port send base every `<sec>` seconds within the server-advertised list. It never opens or closes sockets.
- The control plane stays SipHash-authenticated (not encryption) at header version 3; the test plane stays version 1.

## Architecture

The program is a single process running one libev event loop, with two entry points distinguished by `-c`/`-s`:

- `main.cpp` — argument parsing (`process_arg`), then dispatches to `tunnel_client_event_loop()` or `tunnel_server_event_loop()`.
- `tunnel_client.cpp` / `tunnel_server.cpp` — the two roles. They register libev watchers on the local-listen fd and remote-send fd, and wire up callbacks for timers (FEC flush, delay manager, reporting).
- `fec_manager.*` — the FEC scheduler. Accumulates incoming packets into a group, runs the Reed-Solomon encoder from `lib/rs.cpp` / `lib/fec.cpp` when the group fills or `--timeout` expires, and emits encoded packets. On receive, it reassembles groups and attempts correction. Supports both a single `-f x:y` and the fine-grained `-f x1:y1,x2:y2,...` form.
- `packet.*` — per-packet framing: obscure, XOR obfuscation, SipHash-2-4 authentication (`auth.*`, `siphash.*`), sequence numbers, headers. In `--cipher` mode it instead builds the AEAD frame (`nonce + ciphertext + tag`) and, with `--pad`, the authenticated bucket-padding frame.
- `auth.*` / `siphash.*` — SipHash-2-4 MAC over all four wire planes, keyed by the 32-hex PSK with a per-plane domain tweak; also derives the XOR obfuscation keystream one-way from the PSK.
- `crypto/` — vendored Monocypher (XChaCha20-Poly1305 + BLAKE2b) plus `kdf.*` (domain-separated 32-byte key derivation from the PSK) and a thin wrapper. Compiled as C with `-x c` into per-target objects; never reformat the vendored source.
- `control_proto.*` / `port_range_manager.*` — port-range control handshake (version 3), routing, and per-session bounded replay.
- `delay_manager.*` — implements `--jitter` (random delay of first packet) and `--interval` (scattering a FEC group across a time interval to defend against burst loss).
- `connection.*` — tracks client-side connection state keyed by source address, used on the server to route decoded packets back to the originating client.
- `fd_manager.*` — thin socket helpers (bind, connect, non-blocking setup).
- `common.{h,cpp}`, `misc.{h,cpp}`, `log.{h,cpp}` — shared utilities, sockaddr helpers, logging (note: `log.cpp` is tiny; most logging macros live in `log.h`).
- `my_ev.{h,cpp}`, `my_ev_common.h` — wrapper around the embedded libev in `libev/`. libev is always embedded via `-isystem libev`.
- `crc32/Crc32.cpp` — Stephan Brumme's fast CRC32 (third-party). Retained in the makefile source list as dead code; it is no longer on the wire path, which now authenticates with SipHash-2-4.
- `lib/rs.cpp`, `lib/fec.cpp` — Reed-Solomon / Vandermonde FEC core (third-party, don't reformat).

### Data flow (client → server, FEC mode 0)

1. Application UDP packet arrives on client's `-l` socket → read in the libev read callback.
2. Packet handed to `fec_manager` which appends it to the current group and arms/resets the timeout timer. In mode 0, large packets are split below `--mtu`.
3. When the group is full (`x` packets) or the timer fires, `fec_manager` computes `y` redundant packets and hands all `x+y` to `packet` for SipHash tagging plus obscure/XOR obfuscation, then writes each to the remote socket, optionally scattered by `delay_manager` over `--interval` ms.
4. On the server, incoming packets are de-obfuscated, authenticated (SipHash tag verified; failures are dropped), grouped by sequence, and once enough of a group arrives, the original `x` packets are reconstructed and forwarded to the `-r` target. Reverse path is symmetric using `connection` state.

Mode 1 (`--mode 1`) skips fragmentation — a single input packet becomes a single FEC group — which trades bandwidth efficiency for latency and relies on the caller to respect MTU.

## Conventions / gotchas

- C++11 only. No RTTI or exceptions in hot paths.
- Many files use global state (see `common.h`, `misc.h`) for options parsed once in `main`. Treat these as read-only after `process_arg`.
- `-Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers` are intentionally suppressed; don't gate changes on fixing those warnings repo-wide.
- CI is in-repo (`.github/workflows/ci.yml`): it builds `all` and `fast` and runs the selftest plus the base and IPv6 smoke suites. Releases are produced by running `make release` with the toolchain paths at the top of the makefile pointing at local installs.
