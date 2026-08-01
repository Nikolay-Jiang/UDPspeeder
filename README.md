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
make          # native Linux build, produces ./speederv2
make debug    # debug build with MY_DEBUG defined, no -O2
make fast     # optimized build with debug symbols
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
./speederv2 -s -l0.0.0.0:4096 -r 127.0.0.1:7777  -f20:10 -k "passwd"

# Run at client side
./speederv2 -c -l0.0.0.0:3333  -r44.55.66.77:4096 -f20:10 -k "passwd"
```

Now connecting to UDP port 3333 at the client side is equivalent to connecting to port 7777 at the server side, and the connection has been boosted by UDPspeeder.

##### Note

`-f20:10` means sending 10 redundant packets for every 20 original packets.

`-k` enables simple XOR encryption


# Improves all traffic with OpenVPN + UDPspeeder

See [UDPspeeder + openvpn config guide](https://github.com/wangyu-/UDPspeeder/wiki/UDPspeeder-openvpn-config-guide).

# Advanced Topic

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
./speederv2 -s \
    --port-range-mode \
    --control-port 14096 \
    --data-port-range 15000-15015 \
    -r 127.0.0.1:7777 \
    -f20:10 -k "passwd"

# Client: dial control port 14096, get data port list, tunnel via those ports
./speederv2 -c \
    --port-range-mode \
    --control-host 44.55.66.77:14096 \
    -l 0.0.0.0:3333 \
    -f20:10 -k "passwd"
```

Client and server **must both specify `--port-range-mode`**; there is no automatic fallback. If only one side enables it, the handshake will fail.

#### Verification

To verify that traffic is spreading across ports, capture a sample on loopback:

```bash
sudo tcpdump -i lo udp port range 15000-15015 -c 100 | awk '{print $NF}' | sort | uniq -c
```

You should see packets distributed across multiple destination ports in the range.

#### Control-Plane Protocol

The control plane uses an independent packet structure (version, msg_type, nonce, timestamp, payload, MAC). 

- **MAC algorithms:** `legacy` (default; uses existing `do_obscure` + `encrypt_0`) or `siphash` (SipHash-2-4 HMAC).
- **Messages:** `HELLO` (client → server), `HELLO_ACK` (server → client, carries session_id and port list), `HEARTBEAT` + `HEARTBEAT_ACK` (keepalive), `BYE` (teardown).
- **Anti-replay:** Sliding window ±60s on timestamp, 1024-entry LRU nonce cache per session.

Use `--control-mac {legacy|siphash}` to choose the MAC algorithm (both sides must match). Defaults to `legacy` for zero additional overhead.

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
./speederv2 -s --test-mode -l0.0.0.0:4096 -k "passwd"

# prober (drives the test, prints the report)
./speederv2 -c --test-mode -r<server_ip>:4096 -k "passwd" \
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
```
UDPspeeder V2
git version: 3e248b414c    build date: Aug  5 2018 21:59:52
repository: https://github.com/wangyu-/UDPspeeder

usage:
    run as client: ./this_program -c -l local_listen_ip:local_port -r server_ip:server_port  [options]
    run as server: ./this_program -s -l server_listen_ip:server_port -r remote_ip:remote_port  [options]

common options, must be same on both sides:
    -k,--key              <string>        key for simple xor encryption. if not set, xor is disabled
main options:
    -f,--fec              x:y             forward error correction, send y redundant packets for every x packets
    --timeout             <number>        how long could a packet be held in queue before doing fec, unit: ms, default: 8ms
    --report              <number>        turn on send/recv report, and set a period for reporting, unit: s
advanced options:
    --mode                <number>        fec-mode,available values: 0,1; mode 0(default) costs less bandwidth,no mtu problem.
                                          mode 1 usually introduces less latency, but you have to care about mtu.
    --mtu                 <number>        mtu. for mode 0, the program will split packet to segment smaller than mtu value.
                                          for mode 1, no packet will be split, the program just check if the mtu is exceed.
                                          default value: 1250. you typically shouldnt change this value.
    -q,--queue-len        <number>        fec queue len, only for mode 0, fec will be performed immediately after queue is full.
                                          default value: 200. 
    -j,--jitter           <number>        simulated jitter. randomly delay first packet for 0~<number> ms, default value: 0.
                                          do not use if you dont know what it means.
    -i,--interval         <number>        scatter each fec group to a interval of <number> ms, to protect burst packet loss.
                                          default value: 0. do not use if you dont know what it means.
    -f,--fec              x1:y1,x2:y2,..  similiar to -f/--fec above,fine-grained fec parameters,may help save bandwidth.
                                          example: "-f 1:3,2:4,10:6,20:10". check repo for details
    --random-drop         <number>        simulate packet loss, unit: 0.01%. default value: 0.
    --disable-obscure     <number>        disable obscure, to save a bit bandwidth and cpu.
developer options:
    --fifo                <string>        use a fifo(named pipe) for sending commands to the running program, so that you
                                          can change fec encode parameters dynamically, check readme.md in repository for
                                          supported commands.
    -j ,--jitter          jmin:jmax       similiar to -j above, but create jitter randomly between jmin and jmax
    -i,--interval         imin:imax       similiar to -i above, but scatter randomly between imin and imax
    --decode-buf          <number>        size of buffer of fec decoder,u nit: packet, default: 2000
    --fix-latency         <number>        try to stabilize latency, only for mode 0
    --delay-capacity      <number>        max number of delayed packets
    --disable-fec         <number>        completely disable fec, turn the program into a normal udp tunnel
    --sock-buf            <number>        buf size for socket, >=10 and <=10240, unit: kbyte, default: 1024
    --io-batch            <number>        batch size for recvmmsg/sendmmsg, 1..64, default: 32. set to 1 to disable batching.
log and help options:
    --log-level           <number>        0: never    1: fatal   2: error   3: warn 
                                          4: info (default)      5: debug   6: trace
    --log-position                        enable file name, function name, line number in log
    --disable-color                       disable log color
    -h,--help                             print this help message

```
#### `--fifo` option
Use a fifo(named pipe) for sending commands to the running program. For example `--fifo fifo.file`, you can use following commands to change parameters dynamically:
```
echo fec 19:9 > fifo.file
echo mtu 1100 > fifo.file
echo timeout 5 > fifo.file
echo queue-len 100 > fifo.file
echo mode 0 > fifo.file
```


# Recent Changes (branch_libev)

Recent performance and maintenance work on `branch_libev`:

- **Linux x86/x86_64 only.** Windows, macOS, ARM and MIPS build paths were removed; the tree now targets Linux x86 / x86_64 only, simplifying the source and the makefile.
- **Zero-malloc hot path in `delay_manager`.** Per-packet `malloc`/`free` on the outbound delay/jitter path was replaced with a pre-allocated object pool (`packet_pool_t`, LIFO free list, ~800 slots). Falls back to `malloc` with a warning only if the pool is exhausted.
- **Batch I/O via `recvmmsg` / `sendmmsg`.** Both the client remote callback and the server local-listen callback now drain up to `--io-batch` packets per libev wakeup with a single `recvmmsg` syscall. Outbound packets produced while decoding a batch are coalesced and flushed with `sendmmsg`, grouped by fd. At 32-packet batches this cuts receive/send syscall counts by roughly 32×, materially lowering CPU at high pps. New `--io-batch N` CLI option (1..64, default 32; set to 1 to disable).
- **CI + loopback smoke test.** A GitHub Actions workflow (`.github/workflows/ci.yml`) now builds on `ubuntu-latest` and runs `tests/smoke.sh`, which spins up a server, client, and a small Python UDP echo, and verifies FEC recovery under both lossless and `--random-drop 1500` (15% loss) conditions using `-f20:10`.

All of the above is on `branch_libev`; no CLI compatibility was broken (every new flag is additive with sensible defaults).

# wiki
Check wiki for more info:

https://github.com/wangyu-/UDPspeeder/wiki

# Related repo

You can also try tinyfecVPN, a lightweight high-performance VPN with UDPspeeder's function built-in, repo:

https://github.com/wangyu-/tinyfecVPN

You can use udp2raw with UDPspeeder together to get better speed on some ISP with UDP QoS(UDP throttling), repo: 

https://github.com/wangyu-/udp2raw-tunnel
