# Repository Guide

## Build

- Use the root `makefile` as the build source of truth. `CMakeLists.txt` is experimental and exists only to generate `compile_commands.json` for clangd.
- `make` builds the native static `speederv3` with `-O2` and debug symbols.
- Despite its name, `make fast` has debug symbols but no `-O2`; `make debug` also has no `-O2` and adds `MY_DEBUG` plus `-Wformat-nonliteral`.
- `make amd64`, `make x86`, and `make release` depend on the hard-coded OpenWRT toolchain paths at the top of `makefile`; they are not portable native builds.
- Build and test targets regenerate the untracked `git_version.h` from `git rev-parse HEAD`; `make clean` removes it. Do not commit generated binaries or `git_version.h`.
- `CMakeLists.txt` lists the full source set (including `crc32/Crc32.cpp`, `siphash.cpp`, `control_proto.cpp`, `port_range_manager.cpp`, `test_mode.cpp`, and `test_mode_net.cpp`), but it stays experimental and clangd-oriented; it hard-codes sanitizer flags inline. `make sanitize` remains the authoritative ASan/UBSan route.

## Verification

The root `makefile` is the source of truth for verification. Prefer its targets; they already rebuild `speederv3` first.

```bash
make test              # selftest + base IPv4 smoke test
make test-selftest     # in-process evaluator/auth self-checks; no network
make test-mode         # end-to-end test-mode suite; roughly 3 minutes
make test-port-range   # port-range suite
make sanitize          # ASan/UBSan build, then selftest + base smoke test
bash tests/smoke_ipv6.sh ./speederv3   # IPv6 / port-range / --out-addr regressions; not part of `make test`
```

- Every network mode needs a **32-hex PSK** (`-k`); the suites pass one internally. A missing or non-hex key fails before any socket is opened, and a wrong key is rejected by the SipHash authentication tag.
- CI runs a `build-and-test` matrix over `all` and `fast` (selftest plus `smoke.sh` and `smoke_ipv6.sh`), and a separate `extended-suites` job that wires `make test-mode` and `make test-port-range`.
- The shell suites require `python3` and accept an alternate binary as their first argument.
- `smoke_port_range.sh` randomizes every port per run (a base in 20000-27999 plus control/data/echo/client offsets), so parallel runs don't collide. Its loss round needs `tc netem` and its sniffing round needs `CAP_NET_RAW`; when either is unavailable the round prints a loud `SKIP:` line and the final banner reports it, rather than passing silently.
- `smoke_ipv6.sh` exits successfully with a loud skip when `::1` is unavailable; check its output rather than treating exit 0 alone as IPv6 coverage.

## Execution Map

- `main.cpp` handles help and dispatch; `misc.cpp:process_arg` owns option parsing. Test mode goes to the prober/responder loops in `test_mode_net.cpp`; normal mode goes to `tunnel_client.cpp` or `tunnel_server.cpp`.
- The **default** data plane is xor/obscure obfuscation + SipHash authentication, keyed by the 32-hex PSK; it does **not** encrypt and is not confidentiality. `--cipher xchacha20-ietf-poly1305` is the only encryption switch: real data-plane AEAD (`crypto/`, XChaCha20-Poly1305), opt-in, off by default, and it must be set identically on both ends (as must `--pad`). `--cipher` replaces the 8-byte SipHash data-plane tag and the obscure layer with a 24-byte nonce + 16-byte tag (+40 bytes per packet).
- `--pad <0|16|32|64>` requires `--cipher` and buckets the padded plaintext (1-byte `pad_len` + up to 64 pad bytes); `--port-rotate-sec <sec>` is client-side, port-range only, default 0 (off). In port-range mode a `--cipher`/`--pad` mismatch is refused at the handshake; in normal mode it is dropped and logged as `auth_drop: plane=...`.
- Normal traffic flows through `auth`/`siphash` (SipHash-2-4 authentication over all planes, keyed by the 32-hex PSK), `fec_manager` (grouping/recovery), `packet` (wire framing/obscure/XOR obfuscation, or the AEAD/pad frame under `--cipher`), `delay_manager` (jitter/scattering), and `connection` (per-peer state).
- Port-range mode adds `control_proto`, `port_range_manager`, and `siphash` for handshake/routing while retaining the normal packet/FEC data format.
- `test_mode.cpp` evaluates traces and renders recommendations; network phase/state handling is in `test_mode_net.cpp`.
- `lib/rs.cpp` is the local Reed-Solomon wrapper. `lib/fec.cpp`, `libev/`, and `crc32/Crc32.cpp` are third-party code; avoid incidental reformatting there.

## Repository Quirks

- Target C++11 on Linux x86/x86_64; the embedded libev is always compiled via `-isystem libev`.
- Build first and use `./speederv3 --help` for the current CLI contract.
- `--random-drop` is expressed in units of `0.01%`: `1500` means about 15% loss.
- `-k`/`--key` is exactly 32 ASCII hex characters (16 bytes) and nothing else; there is no key file, passphrase KDF, or auto key exchange. The default mode does not encrypt; only `--cipher xchacha20-ietf-poly1305` does.
- Formatting is Google-derived with 4-space indentation, unlimited line length, and include sorting disabled (`.clang-format`).
