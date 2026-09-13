# Measured data-plane overhead: CRC32 baseline vs SipHash-2-4

Measured 2026-09-13 on `n-coding` (Linux 6.17.2-1-pve, x86_64) with the
`tests/bench.sh` harness, comparing the current SipHash-2-4 data-plane tag
(8 bytes) against the pre-change CRC32 data plane (4 bytes) at commit
`fb31d86`, the parent of the SipHash module commit `d5c4a91`.

Full raw outputs, the per-row derived table and a supplementary primitive
microbenchmark live in
`.omo/evidence/task-18-udpspeeder-siphash-hardening.txt`.

## Method

Binaries (both built with the repo `makefile`: `-O2 -ggdb -static`, C++11):

| Binary | Provenance | sha256 |
|---|---|---|
| SipHash | `/tmp/opencode/siphash-speederv2`, copied from the main-tree build of HEAD `d92cff5` | `6b05af7920f78eb59ee9acebc9405f9aa93a35bcf26ca2c412ce81c2b99947f8` |
| CRC32 baseline | `git worktree add /tmp/opencode/crc-baseline fb31d86` + `make` in the scratch worktree only | `88b60398f338709e58ef645d0a55ba7ad14bac6263b055a5fb19c5af11ea2459` |

The baseline is a throwaway scratch build; no CRC/legacy runtime mode exists
at HEAD and `--disable-checksum` is a deprecated no-op.

Each binary was run twice through the same 7-row matrix (PPS, packet size, FEC
on/off, jitter, in-binary random-drop FEC pair; the optional `tc` netem rows
were skipped loudly because `tc(8)` is not installed):

```sh
BENCH_DURATION=10 BENCH_STATE_DIR=/tmp/opencode/bench-18-siphash  bash tests/bench.sh /tmp/opencode/siphash-speederv2 --runs 2
BENCH_DURATION=10 BENCH_STATE_DIR=/tmp/opencode/bench-18-crc      bash tests/bench.sh /tmp/opencode/crc-baseline/speederv2 --runs 2
BENCH_DURATION=10 BENCH_STATE_DIR=/tmp/opencode/bench-18-siphash-b bash tests/bench.sh /tmp/opencode/siphash-speederv2 --runs 2
BENCH_DURATION=10 BENCH_STATE_DIR=/tmp/opencode/bench-18-crc-b     bash tests/bench.sh /tmp/opencode/crc-baseline/speederv2 --runs 2
```

All four invocations exited 0 and every pass-2-vs-pass-1 variance gate passed
(throughput deltas <= 0.06%, CPU deltas <= 3.1%, against the 25% tolerance).
The table below is the mean over the resulting 4 passes per binary.

## Measured end-to-end results

`echo pkts` = delivered echo round trips; CPU is client+server process ticks,
`[min..max]` over the 4 passes; `us/echo` is CPU seconds per delivered echo.
Δtput and Δcpu are SipHash − CRC32.

| row | echo pkts | tput sip | tput crc | Δtput | cpu sip % | cpu crc % | Δcpu pp | Δ µs/echo |
|---|---|---|---|---|---|---|---|---|
| baseline (100 pps, 100 B) | 1000 | 0.0800 | 0.0800 | +0.00% | 1.050 [1.0..1.1] | 1.075 [1.0..1.2] | −0.025 | −2.5 |
| pps-1000 (1000 pps, 100 B) | 10000 | 0.8000 | 0.8000 | +0.00% | 6.325 [5.6..6.7] | 5.700 [4.9..6.3] | +0.625 | +6.3 |
| size-1200 (100 pps, 1200 B) | 1000 | 0.9600 | 0.9600 | +0.00% | 1.125 [1.1..1.2] | 1.100 [1.0..1.2] | +0.025 | +2.5 |
| fec-on (100 pps, `-f20:10`) | 1000 | 0.1600 | 0.1600 | +0.00% | 3.525 [3.4..3.7] | 3.475 [3.2..3.7] | +0.050 | +5.0 |
| delay-jitter20 (100 pps, `-j 20`) | 1000 | 0.0800 | 0.0800 | +0.00% | 1.025 [1.0..1.1] | 1.050 [1.0..1.1] | −0.025 | −2.5 |
| loss-rd-nofec (50% random drop) | 904 | 0.1438 | 0.1447 | −0.66% | 1.075 [0.9..1.2] | 1.000 [0.9..1.1] | +0.075 | +9.1 |
| loss-rd-fec (50% random drop) | 1000 | 0.1600 | 0.1600 | +0.00% | 3.375 [3.3..3.5] | 3.375 [3.0..3.6] | +0.000 | +0.0 |
| **aggregate (7-row mean)** | — | **0.3405** | **0.3407** | **−0.051%** | **2.500** | **2.397** | **+0.103** | — |

## Interpretation

* **Throughput: no measurable regression.** Every deterministic row delivers
  the offered rate exactly (identical Mbps both builds); the only difference is
  the random-drop loss row, where `--random-drop` RNG makes run-to-run delivery
  vary by a few percent in either direction. At these offered rates the tunnel
  is not CPU-saturated, so this harness cannot measure a capacity ceiling.
* **CPU: the aggregate difference is +0.103 pp (+4.3% relative), inside the
  run-to-run spread.** Per-pass aggregate CPU ranges overlap (SipHash
  2.343–2.586%, CRC32 2.243–2.529%). At the highest offered rate (1000 pps) the
  mean delta is +0.625 pp (≈ +6.25 µs per delivered echo, ≈ +3.1 µs per tunnel
  packet), but the per-pass spread there is 1.1–1.4 pp (11–14 µs/echo) — larger
  than the delta — and the one-tick measurement quantum is 1 µs/echo. The
  end-to-end difference is therefore **not resolvable above noise**.
* **Primitive cost is far below the harness floor.** A throwaway microbenchmark
  linked against the unmodified production sources (`crc32_fast`,
  `siphash24`, `auth_tag`, `auth_verify`; min of 3 × 3 M iterations, two runs
  agreeing within ~10%) shows the per-tunnel-packet hash-cost difference
  (`tag + verify − 2 × crc32`):

  | payload | crc32 | siphash24 | tag | verify | Δ per tunnel pkt |
  |---|---|---|---|---|---|
  | 100 B (bench baseline/pps-1000) | 106 ns | 73 ns | 83 ns | 96 ns | **−63 ns (SipHash faster)** |
  | 200 B (fec rows) | 76 ns | 138 ns | 147 ns | 160 ns | +155 ns |
  | 1200 B (size-1200 row) | 496 ns | 795 ns | 831 ns | 834 ns | +674 ns |
  | 1400 B | 562 ns | 958 ns | 953 ns | 915 ns | +744 ns |

  CRC32 slicing-by-16 is fast in 64-byte blocks but processes its 1..63-byte
  tail bytewise (`crc32/Crc32.cpp:392-395`), so at the bench's ~108-byte wire
  packet SipHash is actually the cheaper primitive; at 1200–1400 B it costs
  ~0.6–0.7 µs more per tunnel packet. Four hash operations per echo puts the
  whole effect below ~3 µs/echo at any size here — below or at the noise floor.
* **Caveats.** Loopback only, 100–1000 pps, 2 vCPU host with external load;
  real `tc(8)` loss and multi-hour soak are unmeasured; the two builds differ
  by the whole `fb31d86..HEAD` range, though the only data-plane change is the
  tag algorithm/width (4 → 8 bytes).
