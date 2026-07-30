# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

UDPspeeder V2 (`speederv2`) — a UDP tunnel that reduces packet loss on lossy links by applying Reed-Solomon Forward Error Correction, optionally combined with a UDP-based VPN to accelerate arbitrary traffic. C++11, event-loop based (libev), Linux x86 / x86_64 only.

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

There are no unit tests. Verification is done by running the binary against a real or simulated lossy link (see `--random-drop` option for local testing).

## Running

```
# server:
./speederv2 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 -f20:10 -k "passwd"
# client:
./speederv2 -c -l0.0.0.0:3333 -r<server_ip>:4096 -f20:10 -k "passwd"
```

`-f x:y` = send `y` redundant packets per `x` data packets. Common options must match on both sides. Full option list is in `main.cpp:print_help`.

## Architecture

The program is a single process running one libev event loop, with two entry points distinguished by `-c`/`-s`:

- `main.cpp` — argument parsing (`process_arg`), then dispatches to `tunnel_client_event_loop()` or `tunnel_server_event_loop()`.
- `tunnel_client.cpp` / `tunnel_server.cpp` — the two roles. They register libev watchers on the local-listen fd and remote-send fd, and wire up callbacks for timers (FEC flush, delay manager, reporting).
- `fec_manager.*` — the FEC scheduler. Accumulates incoming packets into a group, runs the Reed-Solomon encoder from `lib/rs.cpp` / `lib/fec.cpp` when the group fills or `--timeout` expires, and emits encoded packets. On receive, it reassembles groups and attempts correction. Supports both a single `-f x:y` and the fine-grained `-f x1:y1,x2:y2,...` form.
- `packet.*` — per-packet framing: obscure, XOR encryption (`-k`), sequence numbers, headers.
- `delay_manager.*` — implements `--jitter` (random delay of first packet) and `--interval` (scattering a FEC group across a time interval to defend against burst loss).
- `connection.*` — tracks client-side connection state keyed by source address, used on the server to route decoded packets back to the originating client.
- `fd_manager.*` — thin socket helpers (bind, connect, non-blocking setup).
- `common.{h,cpp}`, `misc.{h,cpp}`, `log.{h,cpp}` — shared utilities, sockaddr helpers, logging (note: `log.cpp` is tiny; most logging macros live in `log.h`).
- `my_ev.{h,cpp}`, `my_ev_common.h` — wrapper around the embedded libev in `libev/`. libev is always embedded via `-isystem libev`.
- `crc32/Crc32.cpp` — Stephan Brumme's fast CRC32, used for packet integrity.
- `lib/rs.cpp`, `lib/fec.cpp` — Reed-Solomon / Vandermonde FEC core (third-party, don't reformat).

### Data flow (client → server, FEC mode 0)

1. Application UDP packet arrives on client's `-l` socket → read in the libev read callback.
2. Packet handed to `fec_manager` which appends it to the current group and arms/resets the timeout timer. In mode 0, large packets are split below `--mtu`.
3. When the group is full (`x` packets) or the timer fires, `fec_manager` computes `y` redundant packets and hands all `x+y` to `packet` for obscuring/XOR-encryption, then writes each to the remote socket, optionally scattered by `delay_manager` over `--interval` ms.
4. On the server, incoming packets are decrypted/decoded, grouped by sequence, and once enough of a group arrives, the original `x` packets are reconstructed and forwarded to the `-r` target. Reverse path is symmetric using `connection` state.

Mode 1 (`--mode 1`) skips fragmentation — a single input packet becomes a single FEC group — which trades bandwidth efficiency for latency and relies on the caller to respect MTU.

## Conventions / gotchas

- C++11 only. No RTTI or exceptions in hot paths.
- Many files use global state (see `common.h`, `misc.h`) for options parsed once in `main`. Treat these as read-only after `process_arg`.
- `-Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers` are intentionally suppressed; don't gate changes on fixing those warnings repo-wide.
- CI/infra: none in-repo. Releases are produced by running `make release` with the toolchain paths at the top of the makefile pointing at local installs.
