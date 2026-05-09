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
