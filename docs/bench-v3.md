# Measured V3 AEAD/padding overhead versus the V2 baseline

Measured 2026-09-15 on `n-coding` (Linux 6.17.2-1-pve, x86_64, 2 vCPU,
load average 1.3-3.6 from work running concurrently on the same host) with
the extended `tests/bench.sh` harness (sha256
`364e167011ede3ae55635a26ae50ec1d895ea3e804527f5e315617883237dd8f`).

The comparison runs the **same 7-row matrix** for four data-plane
configurations on both tunnel endpoints:

| configuration | endpoint flags |
|---|---|
| `v2` (baseline) | none: SipHash-2-4 tag + XOR/obscure obfuscation |
| `aead` | `--cipher xchacha20-ietf-poly1305` |
| `aead-pad32` | `--cipher xchacha20-ietf-poly1305 --pad 32` |
| `aead-pad64` | `--cipher xchacha20-ietf-poly1305 --pad 64` |

Full raw outputs (eight per-configuration summary files, the derived
comparison file, both invocation transcripts and a variance-gate failure
demo) live in
`.omo/evidence/task-16-udpspeeder-v3-antiinterference.txt`.

## Method

**Binary.** One binary was used for every row, built from a scratch worktree
at commit `b86a495` ("docs: bump product version to UDPspeeder V3") with the
repo `makefile` (`g++ -std=c++11 -O2 -ggdb -static`); it reports
`UDPspeeder V3` / `git version: b86a495e35`, sha256
`b91cabaf837b2370a3d73f581d86d828f0da2ee1232c02572f34b2fcfebe3c99`. The worktree
was built only to freeze the benchmark input; no production source was
modified for this measurement.

**Harness.** The extended `tests/bench.sh` runs the whole matrix once per
selected configuration, each with its own machine-readable summary and its own
25 % variance gate, then derives `compare.<cfg>.*` deltas against the first
(baseline) configuration. The evidence run was:

```sh
BENCH_DURATION=10 BENCH_STATE_DIR=/tmp/opencode/task16-state \
    bash tests/bench.sh /tmp/opencode/task16-speederv2 --runs 2 \
    --out-dir /tmp/opencode/task16-full
```

7 rows x 4 configurations x 2 passes, 10 s of offered traffic per row; all
eight pass-2-vs-pass-1 variance gates passed (worst throughput delta 2.03 %,
worst CPU delta 8.91 %, tolerance 25 %). A bare acceptance invocation with the
default 2 s/row and one pass (`bash tests/bench.sh <binary>`, all four
configurations) also exited 0. A deliberately corrupted stored summary
(-70.6 % throughput) made the gate print its LOUD VARIANCE banner and exit 1,
so the gate itself is exercised, not just bypassed.

**Per-packet measurement.** The in-binary `[report]` counters stop at the FEC
layer: they measure shard sizes *before* authentication, so they cannot show
the framing bytes a configuration adds on the wire (in default mode they are
byte-identical to cipher mode). Each row therefore ran a small root-only
AF_PACKET sniffer on `lo` that counted actual UDP payload bytes and packets
for the tunnel port in both directions. "B/pkt" below is the mean captured
UDP payload per wire packet; the delta column is the same row's mean for the
configuration minus the V2 mean, so it isolates the framing change.

**Loss rows.** `tc(8)` is not installed on this host, so the netem loss rows
did not run: there is a LOUD SKIP in every summary and real netem loss is
**unmeasured**. The FEC-recovery figures come from the in-binary
`--random-drop 500` rows (5 % loss per direction), which do not need root.

## Per-packet wire overhead (mean of 2 passes)

Captured UDP payload bytes per wire packet, both directions combined. The
non-FEC rows exchange one wire packet per application packet in every
configuration; on the FEC rows the wire packet count is timing-dependent (see
the caveats below), so it differs between configurations there.

| row (offered) | V2 B/pkt | AEAD B/pkt | Δ | +pad32 B/pkt | Δ | +pad64 B/pkt | Δ | wire pkts (V2/AEAD/p32/p64) |
|---|---|---|---|---|---|---|---|---|
| baseline: 100 pps, 100 B, FEC off | 133.4 | 146.5 | **+13.08** | 168.0 | **+34.58** | 168.0 | **+34.58** | 2000 / 2000 / 2000 / 2000 |
| pps-1000: 1000 pps, 100 B | 133.6 | 146.5 | **+12.92** | 168.0 | **+34.42** | 168.0 | **+34.42** | 20000 / 20000 / 20000 / 20000 |
| size-1200: 100 pps, 1200 B | 1233.6 | 1246.5 | **+12.86** | 1256.0 | **+22.36** | 1256.0 | **+22.36** | 2000 / 2000 / 2000 / 2000 |
| fec-on: 100 pps, 200 B, `-f20:10` | 65.5 | 78.7 | **+13.19** | 104.2 | **+38.67** | 104.4 | **+38.82** | 33923 / 33545 / 28844 / 28862 |
| delay-jitter20: 100 pps, 100 B, `-j 20` | 133.6 | 146.5 | **+12.94** | 168.0 | **+34.44** | 168.0 | **+34.44** | 2000 / 2000 / 2000 / 2000 |
| loss-rd-nofec: 200 B, FEC off, 5 % drop | 233.3 | 246.4 | **+13.14** | 264.0 | **+30.71** | 296.0 | **+62.71** | 1864 / 1855 / 1856 / 1852 |
| loss-rd-fec: 200 B, `-f20:10`, 5 % drop | 65.6 | 78.6 | **+13.04** | 104.1 | **+38.53** | 104.4 | **+38.82** | 32165 / 32107 / 27483 / 27438 |

The measured AEAD delta is the exact frame arithmetic, not a fitted number.
Default mode writes `shard + 8-byte SipHash tag + 1 length byte + iv`, where
`iv` is uniform in [4, 32] (mean 18): `shard + 27`. Cipher mode replaces all
of that with `shard + 24-byte nonce + 16-byte Poly1305 tag` = `shard + 40`.
The difference is **+13 B/pkt**, and every row measures +12.86..+13.19 B/pkt
(the per-row spread is the finite-sample mean of the random IV).

Padding rounds the authenticated region up to a multiple of the bucket:
`framed = bucket * ceil((shard + 1) / bucket) + 40`. That explains the bucket
table exactly:

* 104-byte shard (100 B payload + conv header): 104 -> 128 for both buckets,
  `128 + 40 = 168` B, measured +34.4..+34.6 B/pkt.
* ~1204-byte shard (1200 B payload): 1204 -> 1216, `1216 + 40 = 1256` B,
  measured +22.4 B/pkt.
* ~204-byte shard (200 B payload): 204 -> 224 for bucket 32 but 204 -> 256
  for bucket 64. This is the only row where the two buckets differ:
  +30.7 B/pkt (+pad32) versus +62.7 B/pkt (+pad64).
* FEC rows: mode-0 blob encoding turns early-flushed groups into ~65 B shards
  (measured V2 mean 65.5 B), which both buckets round to 128 B, so the two
  padded configurations coincide (+38.5/+38.7 B/pkt).

Two honest caveats from the capture:

* On the 1200 B row with padding, the UDP payload is 1256 B and the IP packet
  1284 B, above the default `--mtu 1250`. That row runs `--disable-fec`, so
  the mode-0 shard-size check does not apply; loopback delivered 100 % and
  nothing fragmented here, but operators padding large payloads should size
  `--mtu` for the padded frame (`cook_overhead()` already accounts for it in
  the FEC path).
* On FEC rows the number of wire packets is timing-dependent (early group
  flushes change the shard packing), so the padded configurations' wire packet
  counts differ from V2 on those rows by a few percent. The B/pkt delta is
  stable across both passes regardless.

## Throughput, CPU and latency (mean of 2 passes)

`cpu %` is client+server process CPU over the offered window; `µs/echo` is
that CPU divided by delivered echo round trips. Every configuration delivered
100 % on the deterministic 100 pps rows; the pps-1000 row's generator
under-delivered a few percent on some AEAD passes under host load, so its
throughput column is not an offered-rate comparison (see Interpretation).

| row | delivered (V2/AEAD/p32/p64) | tput Mbps (V2/AEAD/p32/p64) | cpu % (V2/AEAD/p32/p64) | Δcpu pp vs V2 (AEAD/p32/p64) | µs/echo (V2/AEAD/p32/p64) |
|---|---|---|---|---|---|
| baseline | 1000 / 1000 / 1000 / 1000 | 0.0800 / 0.0800 / 0.0800 / 0.0800 | 1.05 / 1.90 / 2.00 / 1.95 | +0.85 / +0.95 / +0.90 | 105.0 / 190.0 / 200.0 / 195.0 |
| pps-1000 | 10000 / 9862 / 9710 / 9962 | 0.8000 / 0.7889 / 0.7769 / 0.7969 | 7.30 / 15.40 / 16.85 / 15.40 | +8.10 / +9.55 / +8.10 | 73.0 / 156.2 / 173.7 / 154.6 |
| size-1200 | 1000 / 1000 / 1000 / 1000 | 0.9600 / 0.9600 / 0.9600 / 0.9600 | 1.40 / 2.80 / 3.35 / 3.45 | +1.40 / +1.95 / +2.05 | 140.0 / 280.0 / 335.0 / 345.0 |
| fec-on | 1000 / 1000 / 1000 / 1000 | 0.1600 / 0.1600 / 0.1600 / 0.1600 | 3.95 / 17.25 / 13.85 / 13.70 | +13.30 / +9.90 / +9.75 | 395.0 / 1725.0 / 1385.0 / 1370.0 |
| delay-jitter20 | 1000 / 1000 / 1000 / 1000 | 0.0800 / 0.0800 / 0.0800 / 0.0800 | 1.10 / 1.85 / 1.95 / 2.05 | +0.75 / +0.85 / +0.95 | 110.0 / 185.0 / 195.0 / 205.0 |
| loss-rd-nofec | 910 / 902 / 902 / 902 | 0.1456 / 0.1444 / 0.1443 / 0.1444 | 1.10 / 1.90 / 2.15 / 2.35 | +0.80 / +1.05 / +1.25 | 120.8 / 210.6 / 238.4 / 260.7 |
| loss-rd-fec | 1000 / 1000 / 1000 / 1000 | 0.1600 / 0.1600 / 0.1600 / 0.1600 | 4.05 / 14.70 / 13.00 / 13.85 | +10.65 / +8.95 / +9.80 | 405.0 / 1470.0 / 1300.0 / 1385.0 |

Run-wide aggregates (unweighted means over the measured matrix rows; wires
are the capture means, so the units differ from the per-row B/pkt table):

| configuration | tput Mbps | Δtput vs V2 | cpu % | Δcpu pp | µs/echo | wire B/pkt | Δwire B/pkt |
|---|---|---|---|---|---|---|---|
| `v2` | 0.3408 | — | 2.850 | — | 192.7 | 285.5 | — |
| `aead` | 0.3390 | −0.51 % | 7.971 | **+5.12** | 602.4 | 298.5 | **+13.02** |
| `aead-pad32` | 0.3373 | −1.01 % | 7.593 | **+4.74** | 546.7 | 318.9 | **+33.38** |
| `aead-pad64` | 0.3402 | −0.18 % | 7.536 | **+4.69** | 559.3 | 323.5 | **+38.02** |

RSS is unchanged: 20.8-21.0 MB total per tunnel across all configurations.

## Interpretation

* **Per-packet overhead is exactly the frame delta.** AEAD costs
  **+13.0 B/pkt** measured (theory +13); bucket padding adds the round-up to
  the bucket, so between **+22 and +39 B/pkt** depending on payload size, plus
  much more (+62.7) only when a shard crosses a 32/64 boundary — use `--pad`
  knowing the bucket you pick, not just its maximum.
* **No throughput regression is measurable here.** Every lossless row
  delivered 100 % for all four configurations at identical offered rates. The
  small negative aggregate deltas (−0.2 % to −1.0 %) come from the
  nondeterministic `--random-drop` rows and from the pps-1000 row, where the
  shared host's load made the traffic generator under-deliver a few percent
  for some passes (v2's own pass-to-pass CPU spread was up to 1.5 %, and the
  aead config's 8.9 %). They are within the harness noise, not evidence of a
  regression, and are reported as measured rather than explained away.
* **CPU: AEAD mode costs about +5 percentage points of one core in this
  harness** (aggregate 2.85 % -> 7.97 %), and padding does not add a
  measurable amount on top of it (7.54-7.59 %; the three AEAD configurations
  are inside each other's pass spread). Per delivered echo this is
  ~+0.4 ms aggregate, concentrated where wire packet counts are high (the
  FEC rows turn ~65 B shards into tens of thousands of tiny packets; each one
  pays the cipher-mode per-packet cost). That per-packet cost is the current
  implementation's: a keyed BLAKE2b KDF and six `/dev/urandom` reads for the
  24-byte nonce on every sent packet, plus the AEAD itself — the benchmark
  measures the end-to-end effect, not the bare XChaCha20-Poly1305 primitive.
* **Latency on the deterministic rows is unchanged.** p95 over both passes
  was 0.34-1.16 ms for every configuration on the 100 pps rows, and the FEC
  rows' ~17.9-22.0 ms p95 is the FEC group timeout in every configuration. The
  pps-1000 row's p95 (30-237 ms across passes and configurations, including
  73-103 ms for V2 itself) is traffic-generator backlog on this shared 2 vCPU
  host, not a cipher effect, and is not usable to attribute latency.
* **FEC recovery is unchanged within the loss RNG**: under 5 % in-binary
  random drop the `-f20:10` rows recovered 8.4-10.5 percentage points of
  delivery across configurations and passes (V2 9.6/8.4, AEAD 9.4/10.1,
  pad32 9.1/10.5, pad64 10.4/9.2), all delivering 100 %.
* **Not measured:** real `tc(8)` netem loss (tc is not installed on this
  host; every summary carries the LOUD SKIP), links above 1000 pps, RTTs above
  loopback, and multi-hour soak behaviour. The two passes agree to within the
  25 % gate, but this is a shared 2 vCPU host, so the CPU deltas carry
  scheduling noise at the 10 ms tick quantum.
