# UDPspeeder V3 examples and manual test recipes

Copy-pasteable configurations for the `speederv3` binary, plus the observable
each one should produce. Every command uses `./speederv3`, the current V3 CLI,
and a throwaway 32-hex pre-shared key.

This document is examples and manual QA only. It does not restate the full
option list; run `./speederv3 --help` for the authoritative contract.

## Conventions used below

- **Binary:** `./speederv3` (the V3 rename). Replace with an absolute path if
  you run from another directory.
- **Key:** `-k` takes **exactly 32 ASCII hex characters** (16 bytes), nothing
  else. The examples use `00112233445566778899aabbccddeeff`. There is no key
  file, passphrase, or KDF. Use your own key in real deployments.
- **Key must match on both ends.** A peer with a different key is rejected.
- **Authentication and obfuscation are not encryption.** The default data
  plane is XOR plus obscure obfuscation with a SipHash-2-4 authentication tag.
  It authenticates packets and changes the wire pattern, but the payload is
  **not confidential**. Real encryption exists only with
  `--cipher xchacha20-ietf-poly1305`, described in section 2.
- **Example ports** (change them if they collide on your host):
  app echo `7777`, tunnel server `4096`, client listen `3333`,
  port-range control `14096`, port-range data `15000-15015`.
- **Server address** in the client commands is `44.55.66.77`; substitute your
  own. On one host, use `127.0.0.1`.
- **`-f20:10`** is FEC: 10 redundant packets for every 20 data packets. FEC
  parameters are per direction and do not have to match the peer, though
  matching them is the common case.
- **IPv6** addresses use brackets wherever an address is accepted, for example
  `-l"[::1]:4096"`. See section 4.

## 1. Default mode: obfuscation plus SipHash authentication (not encryption)

The default mode (`--cipher none`) keeps the XOR plus obscure obfuscation and
the 8-byte SipHash-2-4 data-plane tag. It authenticates and obfuscates. It
does **not** encrypt.

Start a UDP echo app on the server host:

```bash
python3 tests/udp_echo.py 7777
```

Server (forwards tunnel traffic to the echo app):

```bash
./speederv3 -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff
```

Client (listens on 3333 for your application):

```bash
./speederv3 -c -l 0.0.0.0:3333 -r 44.55.66.77:4096 \
    -f20:10 -k 00112233445566778899aabbccddeeff
```

**Flags that must match on both ends:** `-k` (always, in every network mode).
`-f` is per direction and may differ, but `-f20:10` on both sides is the
recommended starting point.

**Observable:** send datagrams to UDP port 3333 on the client host and you get
`ECHO:<payload>` back. With the automated suite the line is:

```
  [no-loss] delivered 100/100
...
=== PASSED ===
```

If no echo comes back, check that both ends share the same 32-hex key and that
the tunnel-facing addresses agree (client `-r` versus server `-l`).

## 2. Real encryption with XChaCha20-Poly1305

Real encryption is **off by default**. It exists only when both ends pass
`--cipher xchacha20-ietf-poly1305`. With that option the data plane uses a
fresh 24-byte random nonce, the ciphertext, and a 16-byte Poly1305 tag. That is
**+40 bytes per packet**: it replaces the 8-byte SipHash tag and the obscure
layer. The control plane stays SipHash-authenticated, not encrypted, and the
test plane is unchanged.

Server:

```bash
./speederv3 -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305
```

Client:

```bash
./speederv3 -c -l 0.0.0.0:3333 -r 44.55.66.77:4096 \
    -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305
```

**Flags that must match on both ends:** `-k` and `--cipher`. A peer that does
not use the same `--cipher` cannot be decrypted and is rejected.

**Observable:** the same echo behavior as section 1, but the payload on the
wire is ciphertext. A one-shot run of the smoke suite with the cipher applied
to both ends uses `SMOKE_EXTRA_ARGS`:

```bash
SMOKE_EXTRA_ARGS="--cipher xchacha20-ietf-poly1305" bash tests/smoke.sh ./speederv3
```

## 3. Encryption plus size-bucket padding (`--cipher --pad 32`)

`--pad` buckets the padded plaintext (a 1-byte `pad_len` plus up to 64
authenticated pad bytes). It requires `--cipher`, else startup fails before any
socket is opened.

Server:

```bash
./speederv3 -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305 --pad 32
```

Client:

```bash
./speederv3 -c -l 0.0.0.0:3333 -r 44.55.66.77:4096 \
    -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305 --pad 32
```

**Flags that must match on both ends:** `-k`, `--cipher`, and `--pad`.

**Observable:** echo works as before. In port-range mode the handshake refuses
a pad mismatch (section 7). In normal mode a pad mismatch is dropped packet by
packet and logged as `auth_drop: plane=...`.

`--pad 32` without `--cipher` must fail before sockets are opened:

```bash
./speederv3 -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 \
    -k 00112233445566778899aabbccddeeff --pad 32
# [FATAL]--pad 32 requires --cipher: a non-zero pad bucket is only meaningful in
# cipher mode (xchacha20-ietf-poly1305)
# exit status 255, no socket bound
```

Only `0`, `16`, `32`, and `64` are valid buckets.

## 4. IPv6 in bracket form

IPv6 is accepted everywhere IPv4 is. Each socket derives its family from the
argument that describes it, so a v4-only application can be carried over a
v6-only path with one instance per end and no gateway.

Echo app over v6:

```bash
python3 tests/udp_echo.py ::1 7777
```

Server and client over an IPv6 tunnel:

```bash
# server: v6 tunnel in, v6 app out
./speederv3 -s -l"[::1]:4096" -r "[::1]:7777" \
    -f20:10 -k 00112233445566778899aabbccddeeff

# client: v6 app in, v6 tunnel out
./speederv3 -c -l"[::1]:3333" -r "[::1]:4096" \
    -f20:10 -k 00112233445566778899aabbccddeeff
```

Mixed families, v6 tunnel with a v4 backend and a v4 application:

```bash
# server: v6 tunnel in, v4 app out
./speederv3 -s -l"[::1]:4096" -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff

# client: v4 app in, v6 tunnel out
./speederv3 -c -l 127.0.0.1:3333 -r "[::1]:4096" \
    -f20:10 -k 00112233445566778899aabbccddeeff
```

**Flags that must match:** `-k`. The tunnel-facing pair (client `-r` and server
`-l`) must be in the same family; the app-facing sockets are independent.
Pointing a v6 `-r` at a server bound to `0.0.0.0` fails silently with no
delivery.

**Observable:** echo works exactly as in section 1. The IPv6 suite round prints:

```
  [base-v6] delivered 100/100
  [base-v6] ok
```

A `[::]` listener also accepts IPv4 clients because UDPspeeder never sets
`IPV6_V6ONLY`; those arrive logged as v4-mapped addresses such as
`[::ffff:127.0.0.1]:53372`. If a host has no `::1`, `smoke_ipv6.sh` prints a
loud `SKIP:` and exits 0; treat that as unverified, not passing.

## 5. Port-range mode

Port-range mode spreads the tunnel across N UDP data ports to defeat per-flow
ISP rate limiting. The server binds a fixed control port plus a range of data
ports; the client handshakes on the control port, learns the list, and then
round-robins data across it. Both ends must set `--port-range-mode`; there is
no fallback.

Server (`--control-port` and `--data-port-range` are required here):

```bash
./speederv3 -s --port-range-mode \
    --control-port 14096 --data-port-range 15000-15015 \
    -r 127.0.0.1:7777 -f20:10 \
    -k 00112233445566778899aabbccddeeff --log-level 4
```

Client (`--control-host` and `-l` are required here; `-l` is the application
listener and must be present):

```bash
./speederv3 -c --port-range-mode \
    --control-host 127.0.0.1:14096 \
    -l 0.0.0.0:3333 -f20:10 \
    -k 00112233445566778899aabbccddeeff --log-level 4
```

**Flags that must match on both ends:** `-k` and `--port-range-mode`. The
server must set `--data-port-range`; the client does not, because it learns the
advertised ports from the handshake (passing the same range on the client is
accepted but not required). `--cipher` and `--pad` must also match; a mismatch
is refused at the handshake (section 7).

**Observable:** the client logs the handshake and then echoes work:

```
ctrl: HELLO_ACK received ... 16 data ports, port-range-mode active
```

The stable substring is `HELLO_ACK received`, followed by the number of data
ports and `port-range-mode active`.

The automated suite prints delivery counts such as `[no-loss] delivered
100/100`. Note the server identifies a client by **source IP only** (the source
port is ignored), so only one client per public IP is supported. Give each
client its own IP or run a separate server instance.

## 6. Port-range rotation

`--port-rotate-sec` is client-side, port-range only, and default `0` (off). It
advances the base of the round-robin send across the server-advertised ports
every N seconds. It never opens or closes sockets: all advertised ports stay
active, only the starting port moves. The two ends may use different values.

Server: same as section 5.

Client, with a 30-second rotation window:

```bash
./speederv3 -c --port-range-mode \
    --control-host 127.0.0.1:14096 \
    -l 0.0.0.0:3333 -f20:10 \
    -k 00112233445566778899aabbccddeeff \
    --port-rotate-sec 30 --log-level 4
```

**Flags that must match on both ends:** `-k` and `--port-range-mode`, as in
section 5. `--port-rotate-sec` is client-only.

**Observable:** with traffic flowing, the client logs one line per rotation
window:

```
port-rotate: window base=0 first_dest_port=15000 ports=16
port-rotate: window base=1 first_dest_port=15001 ports=16
...
```

`base` advances by one each window (modulo the port count) and
`first_dest_port` tracks it. `ports=` stays at the number of advertised ports,
confirming no socket was dropped. The e2e suite runs `--port-rotate-sec 1` to
observe this quickly and requires at least two windows with delivery above 90%.
Use `1` instead of `30` in a lab if you do not want to wait.

## 7. Mismatched cipher or pad

In **port-range mode** a `--cipher`/`--pad` mismatch is refused at the
handshake. Here the server runs the default (no cipher) and the client asks for
encryption:

```bash
# server: default mode, no --cipher
./speederv3 -s --port-range-mode \
    --control-port 14096 --data-port-range 15000-15015 \
    -r 127.0.0.1:7777 -f20:10 \
    -k 00112233445566778899aabbccddeeff --log-level 4

# client: requests AEAD encryption -> handshake refused
./speederv3 -c --port-range-mode \
    --control-host 127.0.0.1:14096 \
    -l 0.0.0.0:3333 -f20:10 \
    -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305 --log-level 4
```

A pad mismatch is the same kind of refusal, for example server `--cipher
xchacha20-ietf-poly1305 --pad 32` against client `... --pad 16`.

**Observable:** the server logs the mismatch and refuses:

```
ctrl: HELLO capability mismatch from ... ; refusing HELLO
```

The client never logs `HELLO_ACK received` and installs no port list.

In **normal (non-port-range) mode** there is no negotiation, so a mismatched
client is dropped packet by packet. Server stays default, client requests
encryption:

```bash
# server: default mode
./speederv3 -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff --log-level 4

# client: cipher on, server has none -> each packet is dropped
./speederv3 -c -l 0.0.0.0:3333 -r 127.0.0.1:4096 \
    -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305 --log-level 4
```

**Observable:** no echo comes back, and the server's receive path logs the
tamper drop, throttled to at most one line per plane per 10 seconds:

```
auth_drop: plane=data src=127.0.0.1:53372 total=20
```

`tests/smoke_control_v3.sh` pins both behaviors, including a positive control
so a server that drops or refuses everything does not pass.

## 8. Test mode responder/prober and `--test-selftest`

Test mode measures the link and recommends FEC parameters, then exits. Both
sides need `--test-mode` and `-k`; probes are MAC-authenticated. The server to
client phases also need a per-session cookie, so a spoofed source cannot aim
them at a third party.

Responder (far end, answers probes):

```bash
./speederv3 -s --test-mode -l 0.0.0.0:4096 \
    -k 00112233445566778899aabbccddeeff --log-level 4
```

Prober (drives the measurement, prints the report):

```bash
./speederv3 -c --test-mode -r 127.0.0.1:4096 \
    -k 00112233445566778899aabbccddeeff \
    --test-duration 2 --test-pps 100
```

**Flags that must match on both ends:** `-k`, `--test-mode`, and, if set,
`--data-port-range` (identical or absent on both sides, else the handshake
refuses). `--test-duration`, `--test-pps`, `--test-pkt-size`, and
`--test-no-reverse` are prober-side knobs.

**Observable:** the prober prints a report headed `UDPspeeder FEC 测试报告`
with a `client -> server, 单端口` section and `推荐配置` (recommended config)
rows. A clean loopback reports loss under 1%. Default `--test-duration` is 30,
and the full run is roughly 90 seconds. There is a fixed 30-second rate scan
regardless of `--test-duration`, so lowering `--test-duration` to 1 still
leaves that scan: the minimum practical run is roughly 32-36 seconds. For a
quick smoke, `--test-duration 1 --test-pps 20` keeps it short.

`--test-selftest` runs the evaluator's built-in checks against synthetic traces
and exits with no network and no `-k`:

```bash
./speederv3 --test-selftest
# test_mode selftest: 343 checks, 0 failures
# test_mode net checks: 40, failures: 0
```

`tests/smoke_test_mode.sh` also checks a floor on the reported check count and
drives the reverse-phase negatives through this hook. The full suite takes
about three minutes.

## 9. Manual QA recipes

**Echo app.** The bundled echo server replies with an `ECHO:` prefix, which is
how the suites tell real echoes from stray traffic:

```bash
# IPv4
python3 tests/udp_echo.py 7777
# IPv6
python3 tests/udp_echo.py ::1 7777
```

**Send and receive from Python** (target the client listener, not the tunnel
port):

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
s.sendto(b"hello", ("127.0.0.1", 3333))
try:
    data, addr = s.recvfrom(65536)
    print("got", data)          # got b'ECHO:hello'
except socket.timeout:
    print("no reply: check key, tunnel addresses, and FEC")
```

**Port spread observation** (optional; needs tcpdump and usually root):

```bash
sudo tcpdump -i lo -n 'udp portrange 15000-15015' -c 20
```

You should see destination ports spread across the range, not stuck on one.
`ss` lists the bound sockets:

```bash
ss -lun
```

Both tools may be absent or need extra privileges. `smoke_port_range.sh` prints
a loud `SKIP:` for the loss round when `tc`/netem is unavailable and for the
port-spread round without `CAP_NET_RAW`, and its final banner says a round was
skipped rather than silently passing.

**Wrong key is rejected.** Server with key A, client with key B:

```bash
# server, key A
./speederv3 -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff --log-level 4

# client, key B
./speederv3 -c -l 0.0.0.0:3333 -r 127.0.0.1:4096 \
    -f20:10 -k fedcba9876543210fedcba9876543210 --log-level 4
```

No echo comes back. The server logs throttled `auth_drop: plane=data` lines for
the data plane (and `auth_drop: plane=control` in port-range mode). In test
mode the responder logs `mac/format check failed` and the wrong-key prober
exits non-zero with no report.

**`--disable-checksum` deprecation.** The flag is accepted and ignored; packet
authentication is always on. The parser treats it as a flag, even though
`--help` prints it with a `<number>` placeholder, so do not pass a value:

```bash
./speederv3 -s -l 0.0.0.0:4096 -r 127.0.0.1:7777 \
    -k 00112233445566778899aabbccddeeff --disable-checksum
# [WARN]--disable-checksum is deprecated and ignored; packets are always authenticated
```

The warning is logged once, and the tunnel behaves exactly like default mode.

## 10. Quick verification

These commands need no root. The makefile test targets rebuild `speederv3`
first; each `bash` suite runs whichever binary you pass as its first argument,
and the key is supplied internally by the suite.

```bash
make test-selftest
bash tests/smoke.sh ./speederv3
bash tests/smoke_ipv6.sh ./speederv3
bash tests/smoke_control_v3.sh ./speederv3
bash tests/smoke_v3_e2e.sh ./speederv3
```

- `make test-selftest` runs the in-process evaluator and authentication
  self-checks; no network.
- `bash tests/smoke.sh ./speederv3` is the base IPv4 tunnel smoke test
  (100/100 no loss, then FEC recovery under ~15% loss).
- `bash tests/smoke_ipv6.sh ./speederv3` covers IPv6, port-range, test-mode,
  and `--out-addr` validation. It exits 0 with a loud `SKIP:` when `::1` is
  unavailable, so read the output rather than trusting exit 0 alone.
- `bash tests/smoke_control_v3.sh ./speederv3` is the cipher/pad mismatch
  matrix with positive controls.
- `bash tests/smoke_v3_e2e.sh ./speederv3` exercises rotation, SIGSTOP
  recovery, and the auth-drop throttle. It needs no `tc`; `ss` absence only
  skips the listener-leak check, with a loud skip notice.

Optional longer suites: `bash tests/smoke_test_mode.sh ./speederv3` (about
three minutes) and `bash tests/smoke_port_range.sh ./speederv3` (needs `tc` and
`CAP_NET_RAW` for full coverage; otherwise it loud-SKIPs those rounds).
