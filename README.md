# UDPspeeder

A Tunnel which Improves your Network Quality on a High-latency Lossy Link by using Forward Error Correction.

When used alone, UDPspeeder improves only UDP connection. Nevertheless, if you used UDPspeeder + any UDP-based VPN together,
you can improve any traffic(include TCP/UDP/ICMP), currently OpenVPN/L2TP/ShadowVPN are confirmed to be supported。

![](/images/en/udpspeeder.PNG)

or

![image_vpn](/images/en/udpspeeder+openvpn3.PNG)

Assume your local network to your server is lossy. Just establish a VPN connection to your server with UDPspeeder + any UDP-based VPN, access your server via this VPN connection, then your connection quality will be significantly improved. With well-tuned parameters , you can easily reduce IP or UDP/ICMP packet-loss-rate to less than 0.01% . Besides reducing packet-loss-rate, UDPspeeder can also significantly improve your TCP latency and TCP single-thread download speed.

[UDPspeeder Wiki](https://github.com/wangyu-/UDPspeeder/wiki)

[简体中文](/doc/README.zh-cn.md)

# Efficacy
tested on a link with 100ms latency and 10% packet loss at both direction

### Ping Packet Loss
![](/images/en/ping_compare_mode1.png)

### SCP Copy Speed
![](/images/en/scp_compare2.PNG)

# Supported Platforms
Linux x86 / x86_64 only.

# How does it work

UDPspeeder uses FEC(Forward Error Correction) to reduce packet loss rate, at the cost of addtional bandwidth. The algorithm for FEC is called Reed-Solomon.

![image0](/images/en/fec.PNG)

### Reed-Solomon

`
In coding theory, the Reed–Solomon code belongs to the class of non-binary cyclic error-correcting codes. The Reed–Solomon code is based on univariate polynomials over finite fields.
`

`
It is able to detect and correct multiple symbol errors. By adding t check symbols to the data, a Reed–Solomon code can detect any combination of up to t erroneous symbols, or correct up to ⌊t/2⌋ symbols. As an erasure code, it can correct up to t known erasures, or it can detect and correct combinations of errors and erasures. Reed–Solomon codes are also suitable as multiple-burst bit-error correcting codes, since a sequence of b + 1 consecutive bit errors can affect at most two symbols of size b. The choice of t is up to the designer of the code, and may be selected within wide limits.
`

![](/images/en/rs.png)

Check wikipedia for more info, https://en.wikipedia.org/wiki/Reed–Solomon_error_correction

# Getting Started

### Installing
Download binary release from https://github.com/wangyu-/UDPspeeder/releases

### Building from Source

Requires g++ with C++11 support.

```bash
make          # native Linux static build with -O2, produces ./speederv3
make debug    # debug build with MY_DEBUG defined, no -O2
make fast     # debug-symbol build; OPT is empty, so no -O2 (not optimized)
```

Static cross-compile targets using the bundled OpenWRT x86 musl toolchains (toolchain paths must be set in `makefile`):

```bash
make amd64
make x86
```

### Running (improves UDP traffic only)
Assume your server ip is 44.55.66.77, you have a service listening on udp port 7777.

```bash
# Run at server side:
./speederv3 -s -l0.0.0.0:4096 -r 127.0.0.1:7777  -f20:10 -k 00112233445566778899aabbccddeeff

# Run at client side
./speederv3 -c -l0.0.0.0:3333  -r44.55.66.77:4096 -f20:10 -k 00112233445566778899aabbccddeeff
```

Now connecting to UDP port 3333 at the client side is equivalent to connecting to port 7777 at the server side, and the connection has been boosted by UDPspeeder.

##### Note

`-f20:10` means sending 10 redundant packets for every 20 original packets.

`-k`/`--key` takes **exactly 32 ASCII hex characters** (16 bytes), for example
`00112233445566778899aabbccddeeff`. It is **required in every network mode**
and must be **identical on both ends**. The key **authenticates** packets: a
peer with a different key, including an old build that used a passphrase, is
rejected. It does **not encrypt**. The existing XOR and obscure layer is
obfuscation only, so it changes the wire pattern but is never confidentiality.


# Encryption and Obfuscation (V3)

UDPspeeder V3 keeps two things separate that are easy to conflate:

- **Obfuscation** is on by default. The data plane randomizes packet length,
  fills and XORs bytes, and appends an 8-byte SipHash-2-4 authentication tag.
  This changes the wire pattern and authenticates every packet, but it does
  **not encrypt** anything: the payload is not confidential. The default mode
  does not encrypt, and none of these docs claim otherwise.
- **Real encryption** is off by default; it exists only when both ends are
  started with `--cipher xchacha20-ietf-poly1305`. With that flag the data
  plane uses XChaCha20-Poly1305: a fresh 24-byte random nonce, the ciphertext,
  and a 16-byte Poly1305 tag, replacing the 8-byte SipHash data-plane tag and
  the obscure layer. That is **+40 bytes per packet**. A peer that does not use
  the same `--cipher` and the same `--pad` cannot be decrypted and is rejected:
  in port-range mode the control handshake refuses the mismatch; in normal mode
  there is no negotiation, so mismatched packets are dropped and logged as
  `auth_drop: plane=...`. Old or otherwise incompatible peers are always
  rejected.

The control plane stays SipHash-authenticated (not encryption) in both modes,
and the test plane is unchanged.

| Option | Default | Meaning |
|---|---|---|
| `--cipher <name>` | `none` | `none` (the default) = obfuscation + SipHash authentication only, not encryption. `xchacha20-ietf-poly1305` = real AEAD encryption on the data plane; must match on both ends. |
| `--pad <0\|16\|32\|64>` | `0` | Pad the plaintext into a fixed-size bucket before AEAD. Requires `--cipher`; must match on both ends. Adds a 1-byte `pad_len` plus up to 64 authenticated pad bytes per packet. |
| `--port-rotate-sec <sec>` | `0` | Client, port-range mode only. Every `<sec>` seconds the client advances the base of its round-robin data-port rotation within the server-advertised list. `0` disables rotation. |

## Runnable examples

Every example uses a throwaway 32-hex key; replace it with your own. `-k` accepts
exactly 32 ASCII hex characters and nothing else.

A fuller, copy-pasteable set covering IPv6, port-range mode and test mode
lives in [`docs/examples-v3.md`](docs/examples-v3.md).

### Default mode (obfuscation + SipHash authentication, no encryption)

```bash
# server
./speederv3 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff

# client
./speederv3 -c -l0.0.0.0:3333 -r 44.55.66.77:4096 \
    -f20:10 -k 00112233445566778899aabbccddeeff
```

### Real AEAD encryption on both ends (`--cipher`)

Both commands must carry the exact same `--cipher` value:

```bash
# server
./speederv3 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305

# client
./speederv3 -c -l0.0.0.0:3333 -r 44.55.66.77:4096 \
    -f20:10 -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305
```

### AEAD encryption + size-bucket padding (`--cipher --pad 32`)

`--pad` requires `--cipher`, and the bucket must match on both ends.

```bash
# server
./speederv3 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 -f20:10 \
    -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305 --pad 32

# client
./speederv3 -c -l0.0.0.0:3333 -r 44.55.66.77:4096 -f20:10 \
    -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305 --pad 32
```

`--pad 32` without `--cipher` is a fatal startup error:

```bash
./speederv3 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 \
    -k 00112233445566778899aabbccddeeff --pad 32
# fatal: --pad 32 requires --cipher: a non-zero pad bucket is only meaningful in cipher mode
```

### Port rotation in port-range mode (`--port-rotate-sec`)

`--port-rotate-sec` is client-side and only meaningful with `--port-range-mode`.
It changes which advertised data port the round-robin send starts from; it never
opens or closes sockets. The two ends may use different rotation values.

```bash
# server: control port 14096, data ports 15000-15015
./speederv3 -s --port-range-mode --control-port 14096 \
    --data-port-range 15000-15015 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305

# client: rotate the send base every 30 seconds
./speederv3 -c --port-range-mode --control-host 44.55.66.77:14096 \
    -l 0.0.0.0:3333 -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305 --pad 32 --port-rotate-sec 30
```

### Cipher/pad mismatch is refused

In port-range mode the server refuses a HELLO whose capability differs from its
own, so the client never installs a port list. Here the server runs the default
(no `--cipher`) and the client asks for AEAD encryption:

```bash
# server: default mode, no --cipher
./speederv3 -s --port-range-mode --control-port 14096 \
    --data-port-range 15000-15015 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff

# client: requests AEAD encryption -> handshake refused
./speederv3 -c --port-range-mode --control-host 44.55.66.77:14096 \
    -l 0.0.0.0:3333 -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305
```

The two ends also have to agree on `--pad`: a server running `--pad 32` and a
client running `--pad 64` (or no `--pad`) is the same kind of mismatch. In normal
(non-port-range) mode there is no handshake, so a mismatched client is dropped
packet by packet and each drop is logged as `auth_drop: plane=data ...`.


# Improves all traffic with OpenVPN + UDPspeeder

See [UDPspeeder + openvpn config guide](https://github.com/wangyu-/UDPspeeder/wiki/UDPspeeder-openvpn-config-guide).

# Advanced Topic

### IPv6

UDPspeeder speaks IPv6 everywhere it speaks IPv4. Write IPv6 addresses in
brackets, the same way you would in a URL:

```bash
# server
./speederv3 -s -l"[::]:4096" -r "[::1]:7777" -f20:10 -k 00112233445566778899aabbccddeeff

# client
./speederv3 -c -l"[::1]:3333" -r "[2001:db8::1]:4096" -f20:10 -k 00112233445566778899aabbccddeeff
```

Each socket takes its family from the argument that describes it, and the
sockets are **independent of each other**. An instance is not locked to one
family: a client may listen for its application on IPv4 while carrying the
tunnel over IPv6, and a server may accept an IPv6 tunnel while forwarding to
an IPv4 application. So a v4-only application can be carried over a v6-only
path, with no second instance and no gateway in between:

```bash
# server: v6 tunnel in, v4 application out
./speederv3 -s -l"[::1]:4096" -r "127.0.0.1:7777" -f20:10 -k 00112233445566778899aabbccddeeff

# client: v4 application in, v6 tunnel out
./speederv3 -c -l"127.0.0.1:3333" -r "[::1]:4096" -f20:10 -k 00112233445566778899aabbccddeeff
```

The one pair that is **not** independent is the tunnel-facing pair — a
client's `-r` and the server's `-l` — because those are the two ends of one
socket conversation. The client's `-r` has to be an address the server's
listening socket actually accepts: the same family always works, and pointing
a v6 `-r` at a server bound to `0.0.0.0`, or a v4 `-r` at a server bound to a
specific v6 address, silently delivers nothing.

Which argument each socket derives its family from:

| Socket | Derived from |
|---|---|
| Client, tunnel-facing, normal mode | `-r` |
| Client, tunnel-facing, port-range mode | `--control-host` (**not** `-r`) |
| Client, application-facing | `-l` |
| Server, tunnel-facing | `-l` |
| Server, application-facing | `-r` |
| Test mode prober | `-r` |
| Test mode responder | `-l` |

**A `[::]` listener also accepts IPv4 clients.** UDPspeeder never sets
`IPV6_V6ONLY`, so on a default Linux host (`net.ipv6.bindv6only=0`) a server
started with `-l"[::]:4096"` accepts IPv4 clients as well, and logs them as
v4-mapped addresses:

```
new connection from [::ffff:127.0.0.1]:53372
```

Binding `[::]` therefore does **not** exclude IPv4. If you intend to serve
only IPv6, bind a specific IPv6 address rather than the wildcard, or block
IPv4 at the firewall — do not rely on `[::]` to do it for you.

**Port-range server without `-l`.** `-l` is optional for a port-range server,
and without it there is nothing to derive a family from, so it binds the IPv4
wildcard address `0.0.0.0` and says so in its log. Pass `-l"[::]:0"` to listen
on IPv6 instead.

**`--out-addr` must match.** Its address family has to match the peer's, or
startup is refused with both addresses printed. Its **port** must be `0`
wherever the instance opens more than one outbound socket, since a non-zero
port pins one specific local port and the second bind would fail with
`EADDRINUSE`:

| Role | Outbound sockets | Non-zero port allowed? |
|---|---|---|
| Client, normal mode | 1 | yes |
| Client, port-range mode | 2 (data + control) | no |
| Client, test mode (prober) | 1 | yes |
| Server (either mode) | one per connected client | no |
| Server, test mode (responder) | 0 — `--out-addr` is unused | n/a |

Both conditions are checked at startup, so a bad combination is refused
immediately rather than surfacing later as a bind failure — which, on a
server, would otherwise happen only once a *second* client connected.

### Port-Range Mode (Defeat Per-Flow ISP Rate Limiting)

**Note:** This feature is optional and disabled by default.

#### Motivation

Some ISPs implement per-5-tuple flow-level rate limiting or QoS: a single UDP 5-tuple (source IP, source port, dest IP, dest port, protocol) is throttled to a lower bandwidth. UDPspeeder's default mode uses a single UDP socket, concentrating all tunnel traffic onto one 5-tuple—allowing the ISP to apply the per-flow limit to the entire tunnel.

**Port-range mode** spreads tunnel traffic across N different UDP ports on the server and client, creating N distinct 5-tuples. ISP per-flow limits are now applied per-port, so the total tunnel capacity is multiplied by N.

#### How It Works

- **Server:** Binds to a fixed **control port** + a range of **data ports** (up to 256).
- **Client:** Establishes a handshake on the control port, learns the list of available data ports, then round-robin distributes all outbound packets across the N data ports.
- **NAT traversal:** The server tracks the NAT endpoint (source port + which data fd received the packet) for each client and uses those to reverse-route packets back through the correct data fd—compatible with symmetric NAT.

Data packets still use the same on-wire format (obscure, XOR, FEC, etc.); only the socket routing changes. Session management is kept lightweight: a separate control-plane protocol carries the handshake and keepalive, while data packets flow over data ports unchanged.

#### Limitations

**Only one client per public IP address.** The data plane carries no session id, so in port-range mode the server identifies a client by its source **IP only**, ignoring the source port. Two distinct clients sharing one public IP would therefore collapse into a single connection — mixing their FEC sequence streams into one decoder and their NAT endpoints into one reply set. Give each client its own public IP, or run separate server instances on separate control ports.

Ignoring the source port is what makes **symmetric NAT** work. A symmetric NAT assigns a *different* external source port per destination port, so a client sending to N data ports arrives from N different source addresses. Keying on `(ip, port)` would split that one logical client into N separate connections — fragmenting its FEC groups across N decoders and opening N sockets to the `-r` target, which breaks stateful applications (a TLS handshake would see N apparent clients and never converge). Keying on the IP alone collapses those back into one session; the true per-port source address is tracked separately and used for replies, so return traffic still follows each NAT mapping correctly.

Public clients, cone NATs (full-cone / restricted-cone / port-restricted-cone), and symmetric / carrier-grade NATs are therefore all supported. Session-id-based data-plane routing, which would also lift the one-client-per-IP restriction, is planned for a future revision.

#### Example

Enable port-range mode with 16 data ports:

```bash
# Server: listen on control port 14096 and data ports 15000–15015
./speederv3 -s \
    --port-range-mode \
    --control-port 14096 \
    --data-port-range 15000-15015 \
    -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff

# Client: dial control port 14096, get data port list, tunnel via those ports
./speederv3 -c \
    --port-range-mode \
    --control-host 44.55.66.77:14096 \
    -l 0.0.0.0:3333 \
    -f20:10 -k 00112233445566778899aabbccddeeff
```

Client and server **must both specify `--port-range-mode`**; there is no automatic fallback. If only one side enables it, the handshake will fail.

#### Verification

To verify that traffic is spreading across ports, capture a sample on loopback:

```bash
sudo tcpdump -i lo udp port range 15000-15015 -c 100 | awk '{print $NF}' | sort | uniq -c
```

You should see packets distributed across multiple destination ports in the range.

#### Control-Plane Protocol

The control plane uses an independent version-3 packet structure (version, msg_type, nonce, timestamp, payload, MAC).

- **MAC algorithm:** `siphash` only (SipHash-2-4 keyed by the shared PSK). The old `legacy` algorithm and the version-1 header were removed; `--control-mac legacy` is a fatal startup error.
- **Messages:** `HELLO` (client → server), `HELLO_ACK` (server → client, carries session_id and port list), `HEARTBEAT` + `HEARTBEAT_ACK` (keepalive), `BYE` (teardown).
- **Anti-replay:** Sliding window ±60s on timestamp, 1024-entry LRU nonce cache per session.

Use `--control-mac siphash` to select the MAC algorithm; it is the only accepted value and the default on both sides. Like the data plane, it authenticates the control packets (it is not encryption), and both sides must use the same PSK or the handshake is refused.

### Test Mode (Measure the Link, Recommend FEC Parameters)

**Note:** This feature is optional. It turns the program into a one-shot link
prober instead of a tunnel, then exits.

#### What it does

`--test-mode` measures real packet loss on the link and recommends `-f x:y -i n`
settings from what it measured, instead of you guessing. Both directions are
measured. The report gives a separate `-f`/`-i` for each end, because `-f` is
per-direction — the receiver reads `data_num`/`redundant_num` off the wire
rather than from its own config, so the two ends need not match — and real
links are routinely asymmetric. The server → client probes travel back
through the NAT mapping the client already punched, so the client needs no
inbound port.

- **Responder** (far end, just answers probes): `-s --test-mode -l <ip:port>`
- **Prober** (drives the measurement, prints the report): `-c --test-mode -r <ip:port>`
- `-k` is **mandatory** on both sides: probes are MAC-authenticated, so an
  open responder cannot be driven by an unauthenticated party.
- The server → client phases are additionally gated on a **per-session cookie**
  that the responder mints at random and returns only in its handshake reply.
  The prober must echo it in every reverse-phase request. MAC authentication
  alone was not enough there: `-k` is shared with every tunnel client on the
  server, and the reverse phase is the one path on which the responder becomes
  a traffic *source*, so without the cookie anyone holding the key could forge
  a handshake with a victim's source address and turn the responder into a UDP
  amplifier aimed at that victim. The cookie only ever travels back to the
  address the handshake reply was sent to, so a party that cannot receive that
  address's traffic never learns it, and a request without it is dropped in
  silence.

#### How to run it

```bash
# responder (far end)
./speederv3 -s --test-mode -l0.0.0.0:4096 -k 00112233445566778899aabbccddeeff

# prober (drives the test, prints the report)
./speederv3 -c --test-mode -r<server_ip>:4096 -k 00112233445566778899aabbccddeeff \
    --test-duration 30 --test-pps 200 --test-pkt-size 1200 --test-app-mbps 5
```

Add `--data-port-range a-b` on **both** sides to also compare single-port vs.
N-port loss in each direction. It is the same flag documented under
[Port-Range Mode](#port-range-mode-defeat-per-flow-isp-rate-limiting) above;
`--port-range-mode` itself is not required in test mode.

The range must be **identical on both ends, or absent from both**. The
handshake compares them and the responder refuses the session with an
explicit reason if they disagree — otherwise the multi-port probes would land
on ports nobody is bound to and the report would confidently conclude that
port-range brings no benefit, which is the opposite of what such a run shows.

`--test-pps × --test-duration` must not exceed **500,000 probes per phase**;
the combination is checked at startup. The responder evaluates a phase
synchronously, and larger traces push that past the prober's
result-collection timeout. 500,000 samples already resolve loss to 0.0002%,
far finer than the tightest recommendation tier needs.

| Option | Default | Range | Meaning |
|---|---|---|---|
| `--test-duration <sec>` | 30 | 1–600 | duration of each full-length measurement pass |
| `--test-pps <number>` | 200 | 1–20000 | probe packet rate |
| `--test-pkt-size <number>` | 1200 | 64–1400 | probe packet size, **both** directions; prober-side only — it is carried in the handshake, so the responder pads its server → client probes to it too (clamped to the responder's own 64–1400 range) |
| `--test-app-mbps <number>` | probe rate | — | your real payload rate; used only to convert redundancy overhead into an absolute Mbps figure |
| `--test-no-reverse` | off (reverse runs) | — | skip the server → client phases; prober-side only, the responder always supports them |
| `--test-selftest` | — | — | run the evaluator's self-checks against synthetic traces and exit; touches no network |

Total runtime is the fixed 30-second rate scan (3 × 10s, independent of
`--test-duration`) plus one `--test-duration` pass per direction, plus
another pair if `--data-port-range` is set. With the default
`--test-duration 30`:

| Scenario | Runtime |
|---|---|
| single-port | 90s |
| multi-port (`--data-port-range`) | 150s |
| single-port with `--test-no-reverse` | 60s |
| multi-port with `--test-no-reverse` | 90s |

Even a minimal run (`--test-duration 1`) still pays the 30-second fixed scan.

**Known limitation:** the rate scan probes client → server only. A link that is
policed *only* on the server → client direction will not be flagged as policed,
and the server → client table will still print FEC recommendations whose premise
does not hold. Widening the scan to both directions would double the fixed 30s
scan, which was judged not worth it; if you suspect downstream policing, run the
tool a second time with the roles reversed.

#### Reading the report

The report currently prints its section headings and labels in Chinese (for
example the three tiers are named 省流 / 均衡 / 激进 — thrifty / balanced /
aggressive). This section explains its content and structure in English so
the numbers can be interpreted regardless of the label language.

The report contains, in order:

1. **Loss-nature verdict.** The rate scan runs the probe at 0.5×, 1× and 2×
   the nominal `--test-pps`. If loss rises significantly with rate, the loss
   is policing- or congestion-induced: FEC will not help there, and adding
   redundancy makes it *worse*, because the extra packets consume more of the
   throttled capacity. The report says so explicitly instead of recommending
   more redundancy — the right remedy for that case is spreading traffic
   (`--data-port-range`), not a bigger `-f`.
2. **Link characteristics** for the client → server direction: loss rate,
   loss run-length p50/p95/max, p95 burst duration, and this run's sampling
   resolution (`1/n`).
3. **Three candidate configs** — thrifty (residual loss ≤1%), balanced
   (≤0.1%, the default recommendation), aggressive (≤0.01%) — each with
   predicted residual loss, redundancy overhead and absolute bandwidth. A
   tier whose target is below this run's sampling resolution is marked as
   extrapolated; a target no candidate can reach is reported as unreachable
   rather than a fabricated number.
4. **Link characteristics and three candidate configs** for the
   `server -> client` direction, mirroring section 2/3 above but for the
   reverse phase. If that direction wasn't measured — `--test-no-reverse` was
   given, the peer is an older build that doesn't support it, or the peer
   claimed support but no probes arrived — the section says so explicitly
   (with the reason) and prints no loss figure; it is never rendered as 100%
   loss.
5. **Port-range comparison**, only when `--data-port-range` was given:
   single-port vs. N-port loss for each direction, and whether port-range
   mode would help on this link. For the server → client row the port count
   shown is the number of ports the responder reports it *actually* sent
   from, which can be lower than the number requested — a data port that
   never saw this client has no NAT mapping to answer through and is left
   out. When it is lower, or when the responder never reported it, the report
   says so and withholds the "port-range helps" conclusion rather than
   crediting a difference that may have been measured over a single port.
6. **A suggested command line** for the balanced tier of each measured
   direction.

#### How the recommendation is derived

One probe pass records a timestamped loss trace (arrived/lost per sequence
number). That trace is then replayed against roughly 1500 candidate `x:y`
pairs. Because Reed-Solomon is a maximum-distance-separable (MDS) code, a
group of `x` data shards plus `y` redundant shards recovers if and only if at
least `x` of the `x+y` shards arrive — so residual loss is simply the
fraction of `(x+y)`-wide sliding windows in the trace containing more than
`y` losses. This makes no assumption about the loss distribution, which
matters because bursty loss badly breaks the binomial models a purely
analytical (non-replay) estimate would need.

`-i` is derived from the trace's measured p95 burst duration
(`i >= burst_p95_ms * (x+y)/y`, capped at 50ms), but is deliberately
**excluded** from the residual-loss figure above, because scattering changes
send timing and the trace was captured unscattered. Recommendations are
therefore conservative: the real result after applying the recommended `-i`
should be better than shown, never worse.

Run `--test-selftest` to verify the evaluator's replay logic against
synthetic traces (isolated loss, bursty loss, total loss, etc.) without
touching the network.

### Full Options

Run `./speederv3 --help` for the complete, always-current option list. The
option tables above cover the V3-specific flags (`--cipher`, `--pad`,
`--port-rotate-sec`, port-range mode and test mode); the help output also lists
the FEC, delay and logging options carried over from earlier versions.

#### `--fifo` option
Use a fifo(named pipe) for sending commands to the running program. For example `--fifo fifo.file`, you can use following commands to change parameters dynamically:
```
echo fec 19:9 > fifo.file
echo mtu 1100 > fifo.file
echo timeout 5 > fifo.file
echo queue-len 100 > fifo.file
echo mode 0 > fifo.file
```


# wiki
Check wiki for more info:

https://github.com/wangyu-/UDPspeeder/wiki

# Related repo

You can also try tinyfecVPN, a lightweight high-performance VPN with UDPspeeder's function built-in, repo:

https://github.com/wangyu-/tinyfecVPN

You can use udp2raw with UDPspeeder together to get better speed on some ISP with UDP QoS(UDP throttling), repo: 

https://github.com/wangyu-/udp2raw-tunnel
