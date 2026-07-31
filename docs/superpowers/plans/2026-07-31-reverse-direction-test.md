# Reverse-Direction Measurement (server → client) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `--test-mode` measure the server → client direction (spec phases S2 and S4) so the report recommends a separate `-f`/`-i` for the server end, reusing the NAT mapping the client already punched.

**Architecture:** The responder gains a paced `ev_timer` sender driven by a new pure `pacer_t`; the prober records the reverse trace locally and evaluates it locally, so no trace and no new result payload crosses the wire. Source pinning becomes layered (control messages match `(ip,port)`, probes match IP only), which also fixes an existing S3 defect on symmetric NATs. Capability negotiation in `HELLO_ACK` prevents a new prober from reporting a fabricated 100% loss against an old responder.

**Tech Stack:** C++11, libev (embedded, `-isystem libev`), no exceptions/RTTI in hot paths, `make` / `make debug`, bash smoke tests. No unit-test framework — pure-logic assertions live in the `--test-selftest` harness in `test_mode.cpp`.

**Spec:** `docs/superpowers/specs/2026-07-31-reverse-direction-test-design.md`

## Global Constraints

- C++11 only. No RTTI, no exceptions in hot paths.
- Both `make` and `make debug` must finish with **zero** warnings and zero errors. Verify with `make clean && make 2>&1 | grep -Ei "warning|error"` producing no output.
- `git_version.h` is generated and **must never be committed**.
- Globals parsed in `process_arg` are read-only afterwards.
- Pure protocol/statistics logic goes in `test_mode.cpp`; socket and libev wiring goes in `test_mode_net.cpp`. This boundary is stated at the top of `test_mode_net.cpp:1-3` and must be preserved.
- Do **not** reuse `ctrl_encode`/`ctrl_decode` — their 1024-slot replay ring would drop legitimate probes. Use `test_encode`/`test_decode`.
- Every new pure function gets `TCHECK` assertions in `test_mode_selftest()`. The selftest must end with `0 failures`.
- `tests/smoke.sh` (tunnel regression) and `tests/smoke_port_range.sh` must still pass after every task.
- Chinese report text uses `test_print_cell` for column padding — `printf %-Ns` pads by **bytes** and cannot align CJK. Never introduce byte-padded columns.
- Commit after each task. Commit messages end with:
  `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `test_mode.h` | modify | New: `pacer_t`, `test_addr_same_ip`, PHASE_BEGIN/HELLO_ACK codec decls, `TEST_CAP_REVERSE`, `test_no_reverse`, `down_status_t`, extra `test_report_t` fields |
| `test_mode.cpp` | modify | `pacer_t` impl, `test_addr_same_ip`, payload codecs, report rendering for the down direction, all new selftest assertions |
| `test_mode_net.cpp` | modify | Layered pinning, per-fd endpoint table, responder reverse sender, prober reverse receiver |
| `misc.cpp` | modify | `test_no_reverse` global + `--test-no-reverse` parsing |
| `main.cpp` | modify | Help text |
| `README.md` | modify | Test-mode docs |
| `tests/smoke_test_mode.sh` | modify | Rounds 4–6 |

---

### Task 1: `pacer_t` — extract pacing into a testable pure struct

The pacing logic is currently inlined in `prober_run_phase()` where the selftest cannot reach it, and it is where this feature has produced silently-wrong output twice. The reverse sender needs a second copy; extract instead of duplicating.

**Files:**
- Modify: `test_mode.h` (add after the `trace_t` declaration block, near line 82)
- Modify: `test_mode.cpp` (impl near the other pure helpers; assertions in `test_mode_selftest()`)
- Modify: `test_mode_net.cpp:575-618` (rewire `prober_run_phase`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `struct pacer_t { double pps; double credit; my_time_t last_us; void init(double pps_, my_time_t now_us); int tick(my_time_t now_us); }` and `const my_time_t PACER_SLIP_US = 50000;` — Task 4's responder sender uses both.

- [ ] **Step 1: Write the failing test**

Add to `test_mode_selftest()` in `test_mode.cpp`, immediately after the `// ---- codec ----` block:

```c
    // ---- pacer ----
    {
        // Exact rate: 200pps over 1000 x 1ms ticks must emit exactly 200.
        pacer_t p;
        p.init(200.0, 0);
        int total = 0;
        for (int k = 1; k <= 1000; k++) total += p.tick((my_time_t)k * 1000);
        TCHECK(total == 200, "200pps over 1000 ticks must emit exactly 200, got %d", total);

        // High rate must not be throttled by the burst cap: 20000pps at a 1ms
        // tick legitimately owes 20 packets per tick.
        pacer_t hp;
        hp.init(20000.0, 0);
        int hi = hp.tick(1000);
        TCHECK(hi == 20, "20000pps at 1ms tick must emit 20, got %d", hi);

        // Burst cap: a 200ms stall must NOT pay out the whole backlog. At
        // 200pps that would be 40 packets in one go, manufacturing exactly the
        // time-correlated loss the -i recommendation is derived from.
        pacer_t b;
        b.init(200.0, 0);
        int burst = b.tick(200000);
        TCHECK(burst == 1, "a 200ms stall at 200pps must emit 1, not a backlog, got %d", burst);

        // ...and the stall must not leave banked credit behind that pays out on
        // the next tick either.
        int after = b.tick(201000);
        TCHECK(after <= 1, "tick after a stall must not release a backlog, got %d", after);

        // Low rate: 1pps must emit its first packet at t=1s, not before.
        pacer_t lo;
        lo.init(1.0, 0);
        int early = 0;
        for (int k = 1; k <= 999; k++) early += lo.tick((my_time_t)k * 1000);
        TCHECK(early == 0, "1pps must emit nothing in the first 999ms, got %d", early);
        int at_one_sec = lo.tick(1000000);
        TCHECK(at_one_sec == 1, "1pps must emit exactly 1 at t=1s, got %d", at_one_sec);

        // Non-monotonic clock must not produce negative or bogus budgets.
        pacer_t nm;
        nm.init(200.0, 1000000);
        TCHECK(nm.tick(999000) == 0, "a backwards clock must emit 0");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make clean >/dev/null && make 2>&1 | tail -5`
Expected: FAIL — compile error, `'pacer_t' was not declared in this scope`.

- [ ] **Step 3: Write minimal implementation**

In `test_mode.h`, after the `trace_t` struct (around line 82):

```c
// Re-base the pacer rather than paying out the backlog when it has fallen this
// far behind (load spike, vm pause). Releasing a backlog as a burst would
// manufacture the time-correlated loss that the -i recommendation is measured
// from -- the sender would be measuring its own scheduling, not the link.
const my_time_t PACER_SLIP_US = 50000;

// Token-bucket pacer, shared by the prober's blocking send loop and the
// responder's ev_timer. Deliberately clock-free: `now_us` is injected so the
// selftest can drive it with synthetic time.
struct pacer_t {
    double    pps = 0.0;
    double    credit = 0.0;
    my_time_t last_us = 0;

    void init(double pps_, my_time_t now_us);
    // How many packets to send right now. Advances internal state.
    int  tick(my_time_t now_us);
};
```

In `test_mode.cpp`, next to the other pure helpers (put it directly above `trace_t::init`, around line 78):

```c
void pacer_t::init(double pps_, my_time_t now_us) {
    pps = pps_;
    credit = 0.0;
    last_us = now_us;
}

int pacer_t::tick(my_time_t now_us) {
    // my_time_t is unsigned; a backwards clock would underflow into a huge
    // elapsed value and dump a burst.
    if (now_us <= last_us) return 0;
    my_time_t elapsed = now_us - last_us;
    if (elapsed > PACER_SLIP_US) elapsed = PACER_SLIP_US;
    last_us = now_us;

    credit += (double)elapsed * pps / 1e6;
    // Cap banked credit so a single tick cannot emit a long backlog. The cap is
    // one tick's worth plus one, which is >= the legitimate per-tick budget at
    // every supported rate (20000pps -> 21 >= 20), so it never throttles.
    double cap = pps / 1000.0 + 1.0;
    if (credit > cap) credit = cap;

    int n = (int)credit;
    credit -= (double)n;
    return n;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"; ./speederv2 --test-selftest | tail -2`
Expected: no warning/error output; last line reports `0 failures` and a check count higher than 75.

- [ ] **Step 5: Rewire the prober to use it**

In `test_mode_net.cpp`, replace the pacing block inside `prober_run_phase()` (currently `double per_tick = ...` through the closing brace of the `while (sent < total)` loop, lines ~575-618) with:

```c
    g_pr.phase_send_fail = 0;
    pacer_t pacer;
    pacer.init((double)pps, get_current_time_us());
    uint32_t sent = 0;
    size_t rr = 0;
    my_time_t next_tick = get_current_time_us();
    uint32_t progress_step = pps * 5;
    if (progress_step == 0) progress_step = 1;
    uint32_t next_progress = progress_step;

    while (sent < total) {
        next_tick += 1000;   // 1ms
        my_time_t now = get_current_time_us();
        if (next_tick > now) {
            usleep((useconds_t)(next_tick - now));
        } else if (now - next_tick > PACER_SLIP_US) {
            // Stretching the phase is harmless -- the responder waits for
            // PHASE_END, not a clock -- whereas dropping probes would be
            // counted as loss.
            mylog(log_warn, "test: pacing slipped %llu ms behind, phase will run long\n",
                  (unsigned long long)((now - next_tick) / 1000));
            next_tick = now;
        }

        int budget = pacer.tick(get_current_time_us());
        for (int b = 0; b < budget && sent < total; b++) {
            const address_t &d = dests[rr % dests.size()];
            rr++;
            prober_sendto(TEST_PROBE, phase, sent, NULL, 0, d, test_pkt_size);
            sent++;
            // Print once per threshold crossing, not once per tick -- at low
            // pps many ticks elapse with sent unchanged.
            if (sent >= next_progress) {
                mylog(log_info, "test: phase %d progress %u/%u\n", phase, sent, total);
                next_progress += progress_step;
            }
        }
    }
```

- [ ] **Step 6: Verify the rewire changed no behaviour**

Run: `make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"; bash tests/smoke_test_mode.sh`
Expected: no warning/error output; script prints `=== PASSED ===`. Round 3's reported loss must still land in the 5–16% band — a pacing regression shows up there as an inflated figure.

- [ ] **Step 7: Commit**

```bash
git add test_mode.h test_mode.cpp test_mode_net.cpp
git commit -m "test-mode: extract pacing into a testable pacer_t

The token-bucket pacing was inlined in prober_run_phase() where the
selftest could not reach it, and it is where this feature produced
silently-wrong output twice. The reverse sender needs a second pacer;
extract rather than duplicate, and pin the behaviour with assertions:
exact rate, no backlog burst after a stall, no throttling at 20000pps.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Layered source pinning + per-fd endpoint table

Fixes an existing defect. `address_t::operator==` is a `memcmp` over the whole sockaddr **including the port** (`common.h:301`). A symmetric NAT hands out a different external source port per destination port, so every S3 data-port probe currently fails the pinning gate at `test_mode_net.cpp:259` and is dropped. The responder's trace then shows ~100% loss and the report states "多端口未降低丢包,port-range 对该链路无收益" — the inverse of the truth, on exactly the links port-range exists for.

**Files:**
- Modify: `test_mode.h` (declare `test_addr_same_ip`)
- Modify: `test_mode.cpp` (impl + selftest)
- Modify: `test_mode_net.cpp` (gate at :259, per-fd table, watcher indices at :404-418, `TEST_BYE`/idle-expiry cleanup)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `bool test_addr_same_ip(address_t a, address_t b);` and, in `test_mode_net.cpp`, `static std::vector<data_ep_t> g_data_eps;` where `struct data_ep_t { bool seen; address_t addr; };` indexed **parallel to `g_resp_fds`** (index 0 = control fd, 1..N = data fds). Task 6 round-robins over it.

Note: `address_t::get_type()`/`is_vaild()` are non-const inline members, so the helper takes its arguments **by value**, matching the existing idiom (`address_t dst = to;` at `test_mode_net.cpp:222`).

- [ ] **Step 1: Write the failing test**

Add to `test_mode_selftest()` in `test_mode.cpp`, after the `// ---- pacer ----` block:

```c
    // ---- address comparison ----
    {
        char s1[] = "127.0.0.1:1000";
        char s2[] = "127.0.0.1:2000";
        char s3[] = "127.0.0.2:1000";
        address_t a, b, c;
        a.from_str(s1);
        b.from_str(s2);
        c.from_str(s3);

        // Documents the root cause: operator== includes the port, which is why
        // a symmetric nat's per-destination source ports split one peer.
        TCHECK(!(a == b), "operator== must treat differing ports as different addresses");
        TCHECK(test_addr_same_ip(a, b),
               "same ip with different ports must compare equal by ip");
        TCHECK(!test_addr_same_ip(a, c), "different ips must not compare equal by ip");
        TCHECK(test_addr_same_ip(a, a), "an address must compare equal to itself");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make clean >/dev/null && make 2>&1 | tail -5`
Expected: FAIL — `'test_addr_same_ip' was not declared in this scope`.

- [ ] **Step 3: Write minimal implementation**

In `test_mode.h`, below the `pacer_t` block:

```c
// Compares the ip only, ignoring the port. Needed because a symmetric nat
// assigns a different external source port per destination port, so probes to
// the data ports arrive from an address that address_t::operator== (a memcmp
// over the whole sockaddr, common.h:301) reports as a different peer.
bool test_addr_same_ip(address_t a, address_t b);
```

In `test_mode.cpp`, next to `pacer_t`:

```c
bool test_addr_same_ip(address_t a, address_t b) {
    if (!a.is_vaild() || !b.is_vaild()) return false;
    if (a.get_type() != b.get_type()) return false;
    if (a.get_type() == AF_INET)
        return memcmp(&a.inner.ipv4.sin_addr, &b.inner.ipv4.sin_addr,
                      sizeof(a.inner.ipv4.sin_addr)) == 0;
    return memcmp(&a.inner.ipv6.sin6_addr, &b.inner.ipv6.sin6_addr,
                  sizeof(a.inner.ipv6.sin6_addr)) == 0;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"; ./speederv2 --test-selftest | tail -2`
Expected: no warning/error output; `0 failures`.

- [ ] **Step 5: Apply the layered gate**

In `test_mode_net.cpp`, replace the gate at line ~259:

```c
    // Every session must start with HELLO. Without this, a peer holding the key
    // could drive PHASE_BEGIN/PROBE/REQUEST_RESULT with no handshake and no
    // pinning, letting two such peers clobber each other's in-flight trace.
    //
    // Probes are matched by ip only. A symmetric nat gives the peer a different
    // external source port per destination port, so a data-port probe arrives
    // from an address that is not byte-equal to the control-plane peer -- and
    // dropping those made S3 report ~100% loss and conclude that port-range is
    // useless, on precisely the links it helps most. Control messages keep the
    // exact (ip,port) match: they only ever travel on the single control
    // mapping, so tightening them costs nothing.
    if (mt != TEST_HELLO) {
        bool ok = g_resp.active &&
                  (mt == TEST_PROBE ? test_addr_same_ip(src, g_resp.peer)
                                    : src == g_resp.peer);
        if (!ok) {
            mylog(log_debug, "test: ignoring msg_type %d from %s (no active session, "
                             "or not the pinned peer)\n", mt, src.get_str());
            return;
        }
    }
```

- [ ] **Step 6: Record the per-fd endpoint**

In `test_mode_net.cpp`, next to `g_resp_fds` (line ~137):

```c
// The source address most recently seen on each responder fd, parallel to
// g_resp_fds (index 0 = control fd, 1..N = data fds). Task 6's reverse
// multi-port phase must send from fd k back to the address that fd actually
// saw: under a symmetric nat that is a different external port per fd, and
// replying to the control-plane address instead would be silently dropped.
// Refreshed on every accepted packet -- a nat can rebind mid-run.
struct data_ep_t {
    bool      seen = false;
    address_t addr;
};
static std::vector<data_ep_t> g_data_eps;
```

Tag each watcher with its index in `test_mode_responder_loop()` (line ~413), so the callback needs no lookup:

```c
        ev_io *w = new ev_io;
        ev_io_init(w, responder_cb, fd, EV_READ);
        w->data = (void *)(intptr_t)k;   // index into g_resp_fds / g_data_eps
        ev_io_start(loop, w);
```

and size the table right after the bind loop:

```c
    g_data_eps.assign(g_resp_fds.size(), data_ep_t());
```

In `responder_cb`, immediately after the gate added in Step 5 (and after the existing `last_rx_us` refresh at line ~267):

```c
    // Refresh this fd's view of the peer. Only from an accepted (mac-valid,
    // pinned) packet, so an off-path sender cannot redirect the reverse phase.
    {
        size_t fd_idx = (size_t)(intptr_t)w->data;
        if (fd_idx < g_data_eps.size()) {
            g_data_eps[fd_idx].seen = true;
            g_data_eps[fd_idx].addr = src;
        }
    }
```

Clear the table wherever the session ends — in the `TEST_BYE` branch (line ~350) and in the idle-expiry branch of `responder_timer_cb` (line ~369), add:

```c
        for (size_t k = 0; k < g_data_eps.size(); k++) g_data_eps[k] = data_ep_t();
```

- [ ] **Step 7: Reproduce the defect and prove the fix**

Loopback cannot exercise a symmetric NAT: the prober uses one socket, so its source port is identical to every destination. Build a scratch driver (do **not** commit it) that reproduces the split directly.

Create `/tmp/rev_pin_driver.cpp`:

```c
// Scratch driver: HELLO from socket A, then a valid TEST_PROBE from socket B
// (same ip, different source port) -- what a symmetric nat produces.
#include "test_mode.h"
#include "log.h"
#include "misc.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    int port = atoi(argv[1]);
    strcpy(key_string, argv[2]);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.s_addr = inet_addr("127.0.0.1");

    char buf[TEST_BUF_MAX];
    int a = socket(AF_INET, SOCK_DGRAM, 0);
    char hpl[12]; memset(hpl, 0, sizeof(hpl));
    int n = test_encode(TEST_HELLO, 0, 0, hpl, sizeof(hpl), buf, sizeof(buf), 0);
    sendto(a, buf, n, 0, (struct sockaddr *)&to, sizeof(to));
    usleep(300 * 1000);

    char bpl[12];
    write_u32(bpl + 0, 100); write_u32(bpl + 4, 100); write_u32(bpl + 8, 0);
    n = test_encode(TEST_PHASE_BEGIN, 1, 0, bpl, sizeof(bpl), buf, sizeof(buf), 0);
    sendto(a, buf, n, 0, (struct sockaddr *)&to, sizeof(to));
    usleep(300 * 1000);

    int b = socket(AF_INET, SOCK_DGRAM, 0);   // different source port
    n = test_encode(TEST_PROBE, 1, 0, NULL, 0, buf, sizeof(buf), 200);
    sendto(b, buf, n, 0, (struct sockaddr *)&to, sizeof(to));
    usleep(300 * 1000);

    n = test_encode(TEST_PHASE_END, 1, 0, NULL, 0, buf, sizeof(buf), 0);
    sendto(a, buf, n, 0, (struct sockaddr *)&to, sizeof(to));
    printf("driver done\n");
    return 0;
}
```

Build it against the project's own objects (so the MAC is byte-identical to the responder's) and run it against a responder started with `--log-level 5`. Confirm:

- **Before the fix** (`git stash` the `test_mode_net.cpp` gate change, rebuild): the log shows `ignoring msg_type 5` for the probe, and the finalize line reports `1/1` lost.
- **After the fix**: no `ignoring msg_type 5` line, and the finalize line reports `0/1` lost.

Record both logs verbatim in the task report. Then `rm /tmp/rev_pin_driver.cpp` and any scratch objects.

- [ ] **Step 8: Commit**

```bash
git add test_mode.h test_mode.cpp test_mode_net.cpp
git commit -m "test-mode: match probes by ip only, record per-fd peer endpoint

address_t::operator== memcmps the whole sockaddr including the port
(common.h:301). A symmetric nat assigns a different external source port
per destination port, so every S3 data-port probe failed the pinning gate
and was dropped -- the responder then reported ~100% loss and the report
concluded port-range brings no benefit, the inverse of the truth on
exactly the links port-range exists for.

Control messages keep the exact (ip,port) match; only probes relax to ip.
Also records the source address each fd last saw, which the reverse
multi-port phase needs to send back through the right nat mapping.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Wire format for reverse phases + capability negotiation

Protocol plumbing only — nothing sends reverse probes yet. Keeping this separate means the codec is reviewable against the spec before any timer logic exists.

**Files:**
- Modify: `test_mode.h` (codec decls, `TEST_CAP_REVERSE`)
- Modify: `test_mode.cpp` (codec impl + selftest)
- Modify: `test_mode_net.cpp` (use the codecs in `responder_cb` and the prober handshake)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `const u32_t TEST_CAP_REVERSE = 1u << 0;`
  - `const int TEST_PHASE_BEGIN_PL_LEN = 16;`
  - `void test_phase_begin_pack(char *out, uint32_t expected_n, uint32_t pps, uint32_t dir, uint32_t spread);`
  - `int test_phase_begin_unpack(const uint8_t *pl, int pl_len, uint32_t *expected_n, uint32_t *pps, uint32_t *dir, uint32_t *spread);` → 0 ok, -1 too short. When `pl_len == 12` (old peer) `*spread` is set to 0.
  - `int test_hello_ack_accept_pack(char *out, u32_t caps);` → returns bytes written (8).
  - `u32_t test_hello_ack_caps(const uint8_t *pl, int pl_len);` → 0 when `pl_len < 8` (old responder).

- [ ] **Step 1: Write the failing test**

Add to `test_mode_selftest()` after the address block:

```c
    // ---- phase_begin / hello_ack payload codecs ----
    {
        char pl[TEST_PHASE_BEGIN_PL_LEN];
        test_phase_begin_pack(pl, 1234, 200, 1, 1);
        uint32_t n = 0, pps = 0, dir = 0, spread = 0;
        TCHECK(test_phase_begin_unpack((const uint8_t *)pl, sizeof(pl),
                                       &n, &pps, &dir, &spread) == 0,
               "16-byte phase_begin payload must unpack");
        TCHECK(n == 1234 && pps == 200 && dir == 1 && spread == 1,
               "phase_begin fields must round-trip: got n=%u pps=%u dir=%u spread=%u",
               n, pps, dir, spread);

        // An old peer sends 12 bytes with no spread word. It must decode, and
        // spread must default to 0 rather than reading past the payload.
        uint32_t n2 = 0, pps2 = 0, dir2 = 0, spread2 = 7;
        TCHECK(test_phase_begin_unpack((const uint8_t *)pl, 12,
                                       &n2, &pps2, &dir2, &spread2) == 0,
               "12-byte legacy phase_begin payload must still unpack");
        TCHECK(spread2 == 0, "legacy payload must default spread to 0, got %u", spread2);

        TCHECK(test_phase_begin_unpack((const uint8_t *)pl, 11,
                                       &n2, &pps2, &dir2, &spread2) == -1,
               "a payload shorter than 12 bytes must be rejected");

        // HELLO_ACK: accept path carries caps; the reject path is unchanged, so
        // an old prober reading a reason string from offset 4 is unaffected.
        char ack[16];
        int alen = test_hello_ack_accept_pack(ack, TEST_CAP_REVERSE);
        TCHECK(alen == 8, "accept ack must be 8 bytes, got %d", alen);
        TCHECK(read_u32(ack) == 0, "accept ack must carry reject code 0");
        TCHECK(test_hello_ack_caps((const uint8_t *)ack, alen) == TEST_CAP_REVERSE,
               "caps word must round-trip");

        // An old responder's 4-byte accept must read as "no capabilities"
        // rather than as garbage -- this is the guard that stops a new prober
        // from reporting a fabricated 100% loss against an old peer.
        char old_ack[4];
        write_u32(old_ack, 0);
        TCHECK(test_hello_ack_caps((const uint8_t *)old_ack, 4) == 0,
               "a 4-byte legacy accept must report no capabilities");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make clean >/dev/null && make 2>&1 | tail -5`
Expected: FAIL — `'test_phase_begin_pack' was not declared in this scope`.

- [ ] **Step 3: Write minimal implementation**

In `test_mode.h`, below `test_addr_same_ip`:

```c
// Capability bits advertised by the responder in HELLO_ACK's accept path.
const u32_t TEST_CAP_REVERSE = 1u << 0;   // supports dir=1 (server -> client) phases

// PHASE_BEGIN payload: expected_n, pps, dir, spread -- four big-endian u32s.
// An old responder validates `pl_len < 12`, so appending the fourth word is
// backward compatible in both directions.
const int TEST_PHASE_BEGIN_PL_LEN = 16;

void test_phase_begin_pack(char *out, uint32_t expected_n, uint32_t pps,
                           uint32_t dir, uint32_t spread);
// 0 on success, -1 if shorter than 12 bytes. `spread` is set to 0 for a
// 12-byte (legacy) payload.
int  test_phase_begin_unpack(const uint8_t *pl, int pl_len, uint32_t *expected_n,
                             uint32_t *pps, uint32_t *dir, uint32_t *spread);

// HELLO_ACK accept path: reject code 0 followed by a capability word. The
// reject path keeps the old layout (code + reason string) precisely because an
// old prober prints everything from offset 4 as text -- putting caps there
// would surface as garbage in an operator-facing error message.
int   test_hello_ack_accept_pack(char *out, u32_t caps);
u32_t test_hello_ack_caps(const uint8_t *pl, int pl_len);
```

In `test_mode.cpp`:

```c
void test_phase_begin_pack(char *out, uint32_t expected_n, uint32_t pps,
                           uint32_t dir, uint32_t spread) {
    write_u32(out + 0,  expected_n);
    write_u32(out + 4,  pps);
    write_u32(out + 8,  dir);
    write_u32(out + 12, spread);
}

int test_phase_begin_unpack(const uint8_t *pl, int pl_len, uint32_t *expected_n,
                            uint32_t *pps, uint32_t *dir, uint32_t *spread) {
    if (pl_len < 12) return -1;
    char *p = (char *)pl;   // read_u32 takes char*, but never writes
    *expected_n = read_u32(p + 0);
    *pps        = read_u32(p + 4);
    *dir        = read_u32(p + 8);
    *spread     = (pl_len >= TEST_PHASE_BEGIN_PL_LEN) ? read_u32(p + 12) : 0u;
    return 0;
}

int test_hello_ack_accept_pack(char *out, u32_t caps) {
    write_u32(out + 0, 0u);   // TEST_REJECT_NONE
    write_u32(out + 4, caps);
    return 8;
}

u32_t test_hello_ack_caps(const uint8_t *pl, int pl_len) {
    if (pl_len < 8) return 0u;   // old responder: accept was 4 bytes
    return read_u32((char *)pl + 4);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"; ./speederv2 --test-selftest | tail -2`
Expected: no warning/error output; `0 failures`.

- [ ] **Step 5: Use the codecs on both sides**

In `test_mode_net.cpp`:

1. In the `TEST_HELLO` accept branch (line ~293), replace the 4-byte ack with:

```c
        char ack[8];
        int ack_len = test_hello_ack_accept_pack(ack, TEST_CAP_REVERSE);
        responder_send(w->fd, src, TEST_HELLO_ACK, 0, ack, ack_len);
```

2. In the `TEST_PHASE_BEGIN` branch (line ~297), replace the manual reads:

```c
        uint32_t expected_n = 0, pps = 0, dir = 0, spread = 0;
        if (test_phase_begin_unpack(pl, pl_len, &expected_n, &pps, &dir, &spread) != 0)
            return;
```

3. In `prober_run_phase()` (line ~560), replace the manual `begin_pl` build:

```c
    char begin_pl[TEST_PHASE_BEGIN_PL_LEN];
    test_phase_begin_pack(begin_pl, total, pps, 0, dests.size() > 1 ? 1 : 0);
```

4. In `test_mode_prober_loop()`, after the reject check (line ~725), record the peer's capabilities:

```c
    g_pr.peer_caps = test_hello_ack_caps(ack_pl, ack_len);
    mylog(log_info, "test: responder reachable, RTT %.0f ms, caps 0x%x\n",
          g_pr.rtt_us / 1000.0, (unsigned)g_pr.peer_caps);
```

and add `u32_t peer_caps = 0;` to `prober_ctx_t` (line ~437). Delete the old `responder reachable` log line it replaces.

- [ ] **Step 6: Verify nothing regressed**

Run: `make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"; make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"; ./speederv2 --test-selftest | tail -2; bash tests/smoke_test_mode.sh 2>&1 | tail -3`
Expected: no warning/error output from either build; `0 failures`; `=== PASSED ===`.

- [ ] **Step 7: Commit**

```bash
git add test_mode.h test_mode.cpp test_mode_net.cpp
git commit -m "test-mode: add reverse-phase wire fields and capability negotiation

PHASE_BEGIN gains a spread word (12 -> 16 bytes; an old responder checks
pl_len < 12, so appending is safe). HELLO_ACK's accept path gains a
capability word (4 -> 8 bytes); the reject path keeps its old layout
because an old prober prints everything from offset 4 as text.

The capability word exists to stop a specific silently-wrong result: a
new prober asking an old responder for a reverse phase would get an ACK,
no probes, and would report 'server -> client loss 100.0000%' -- a
concrete-looking number that is entirely fabricated.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Responder-side reverse sender (S2, single port)

**Files:**
- Modify: `test_mode_net.cpp` (reverse send state, pacing timer, end timer, `TEST_PHASE_BEGIN` dir=1 branch, dead-man switch, `--random-drop`)

**Interfaces:**
- Consumes: `pacer_t`/`PACER_SLIP_US` (Task 1), `g_data_eps` (Task 2), `test_phase_begin_unpack` (Task 3).
- Produces: a responder that, on `TEST_PHASE_BEGIN` with `dir==1`, sends `total` padded `TEST_PROBE`s at `pps` with seq `0..total-1`, then after a grace delay sends three `TEST_PHASE_END` copies 20ms apart carrying `{sent_n, send_fail_n}`. Task 5's prober consumes that.

- [ ] **Step 1: Add the reverse send state and helpers**

In `test_mode_net.cpp`, after `g_data_eps`:

```c
// ---------------- responder reverse-phase sender ----------------
//
// The responder is a traffic source only here. Two independent deadlines guard
// it: the 45s session idle limit (unchanged, whole-session) and the dead-man
// switch below, which applies ONLY while a reverse phase is running. The
// prober is silent during a reverse phase apart from its 1s keepalives, so
// without the keepalives the 45s limit would kill a legitimate long phase --
// and without the dead-man switch a kill -9'd prober would leave the responder
// blasting a dead address at full rate for up to --test-duration (600s).
static const my_time_t REV_DEADMAN_US = 5000000ULL;   // 5s
static const int       REV_END_COPIES = 3;
static const double    REV_TICK_SEC   = 0.001;

struct rev_send_t {
    bool      active = false;
    int       phase = 0;
    uint32_t  total = 0;
    uint32_t  sent = 0;
    uint32_t  send_fail = 0;
    uint32_t  pps = 0;
    pacer_t   pacer;
    my_time_t last_peer_rx_us = 0;
    // fds[k] is paired with dsts[k]: each fd must reply to the address that fd
    // itself saw, or a symmetric nat drops it.
    std::vector<int>       fds;
    std::vector<address_t> dsts;
    size_t    rr = 0;
    int       end_copies_left = 0;
};

static rev_send_t   g_rev;
static struct ev_timer g_rev_tick;
static struct ev_timer g_rev_end;

// Like responder_send(), but lets the caller set seq and padding -- reverse
// probes need both, and responder_send() hardcodes them to 0.
static void responder_send_ex(int fd, const address_t &to, int msg_type, int phase,
                              uint32_t seq, const void *payload, int payload_len,
                              int pad_to) {
    char out[TEST_BUF_MAX];
    int n = test_encode(msg_type, phase, seq, payload, payload_len, out, sizeof(out), pad_to);
    if (n < 0) return;
    address_t dst = to;
    if (sendto(fd, out, n, 0, (struct sockaddr *)&dst.inner, dst.get_len()) < 0) {
        // Local backpressure, not link loss. The prober counts the missing seq
        // as lost either way, so it is reported over PHASE_END rather than
        // silently corrected -- surfacing the caveat is honest, quietly
        // adjusting a number the peer actually measured is not.
        if (msg_type == TEST_PROBE) g_rev.send_fail++;
        mylog(log_debug, "test: reverse sendto(%s) failed: %s\n",
              dst.get_str(), get_sock_error());
    }
}
```

Change `responder_send()` to delegate:

```c
static void responder_send(int fd, const address_t &to, int msg_type, int phase,
                           const void *payload, int payload_len) {
    responder_send_ex(fd, to, msg_type, phase, 0, payload, payload_len, 0);
}
```

- [ ] **Step 2: Add the pacing and end timers**

Still in `test_mode_net.cpp`, above `responder_cb`:

```c
static void rev_stop(struct ev_loop *loop) {
    ev_timer_stop(loop, &g_rev_tick);
    g_rev.active = false;
}

static void rev_end_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    assert(!(revents & EV_ERROR));
    // PHASE_END is unacked and can be lost, so send three copies 20ms apart --
    // the same belt-and-braces the prober uses on the upstream path.
    char pl[8];
    write_u32(pl + 0, g_rev.sent);
    write_u32(pl + 4, g_rev.send_fail);
    responder_send_ex(g_resp_fds[0], g_resp.peer, TEST_PHASE_END, g_rev.phase,
                      0, pl, sizeof(pl), 0);
    g_rev.end_copies_left--;
    if (g_rev.end_copies_left > 0) {
        ev_timer_set(w, 0.02, 0.0);
        ev_timer_start(loop, w);
    } else {
        mylog(log_info, "test: reverse phase %d done, sent %u/%u (%u refused locally)\n",
              g_rev.phase, g_rev.sent, g_rev.total, g_rev.send_fail);
        rev_stop(loop);
    }
}

static void rev_tick_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    assert(!(revents & EV_ERROR));
    (void)w;
    if (!g_rev.active) return;

    my_time_t now = get_current_time_us();
    if (now - g_rev.last_peer_rx_us > REV_DEADMAN_US) {
        mylog(log_warn, "test: reverse phase %d aborted -- no keepalive from %s for %llu ms "
                        "(prober interrupted?)\n",
              g_rev.phase, g_resp.peer.get_str(),
              (unsigned long long)((now - g_rev.last_peer_rx_us) / 1000));
        rev_stop(loop);
        return;
    }

    int budget = g_rev.pacer.tick(now);
    for (int b = 0; b < budget && g_rev.sent < g_rev.total; b++) {
        size_t k = g_rev.rr % g_rev.fds.size();
        g_rev.rr++;
        // Mirrors prober_sendto: --random-drop is implemented here too, and
        // only for probes, so smoke tests can inject a known reverse loss rate.
        // Dropping control messages would break the handshake instead.
        bool drop = (random_drop != 0 &&
                     get_fake_random_number() % 10000 < (u32_t)random_drop);
        if (!drop)
            responder_send_ex(g_rev.fds[k], g_rev.dsts[k], TEST_PROBE, g_rev.phase,
                              g_rev.sent, NULL, 0, test_pkt_size);
        g_rev.sent++;
    }

    if (g_rev.sent >= g_rev.total) {
        ev_timer_stop(loop, &g_rev_tick);
        // Grace before PHASE_END: probes and PHASE_END travel on different
        // sockets (data fds vs the control fd), so nothing orders the last
        // probe ahead of PHASE_END, and the prober finalizes on PHASE_END.
        double grace = g_pr_rtt_hint_us > 0 ? (double)g_pr_rtt_hint_us * 2 / 1e6 : 0.5;
        if (grace < 0.5) grace = 0.5;
        g_rev.end_copies_left = REV_END_COPIES;
        ev_init(&g_rev_end, rev_end_cb);
        ev_timer_set(&g_rev_end, grace, 0.0);
        ev_timer_start(loop, &g_rev_end);
    }
}
```

The responder has no RTT measurement of its own. Add, next to `g_resp`:

```c
// Round-trip hint, measured as the gap between the HELLO we answered and the
// first message that came back. Only used to size the reverse phase's grace
// period, so a rough figure is fine.
static my_time_t g_pr_rtt_hint_us = 0;
static my_time_t g_hello_ack_sent_us = 0;
```

Set `g_hello_ack_sent_us = get_current_time_us();` right after sending HELLO_ACK, and in the `last_rx_us` refresh block add:

```c
        if (g_pr_rtt_hint_us == 0 && g_hello_ack_sent_us != 0)
            g_pr_rtt_hint_us = get_current_time_us() - g_hello_ack_sent_us;
```

- [ ] **Step 3: Handle `dir == 1` in `TEST_PHASE_BEGIN`**

Replace the stub at `test_mode_net.cpp:321-326`:

```c
        if (dir != 0) {
            // A duplicate PHASE_BEGIN is the prober's keepalive during a
            // reverse phase (it is otherwise silent). Re-ACK and return
            // WITHOUT touching the pacer or the counters: restarting them
            // would replay the whole phase and manufacture huge phantom loss.
            if (g_rev.active && g_rev.phase == h.phase) {
                g_rev.last_peer_rx_us = get_current_time_us();
                responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);
                return;
            }
            // The responder is a traffic source here, so it bounds rate and
            // volume itself instead of trusting the peer. TEST_MAX_EXPECTED_N
            // is a memory bound for recording a trace and is far too loose to
            // double as "how much may I transmit".
            if (expected_n > (uint32_t)TEST_MAX_TOTAL_PROBES || pps == 0 ||
                pps > (uint32_t)TEST_PPS_MAX) {
                mylog(log_warn, "test: refusing reverse phase: expected_n=%u (cap %lld), "
                                "pps=%u (cap %d)\n",
                      expected_n, TEST_MAX_TOTAL_PROBES, pps, TEST_PPS_MAX);
                return;
            }

            g_rev = rev_send_t();
            g_rev.active = true;
            g_rev.phase  = h.phase;
            g_rev.total  = expected_n;
            g_rev.pps    = pps;
            g_rev.last_peer_rx_us = get_current_time_us();
            g_rev.pacer.init((double)pps, get_current_time_us());
            // Task 6 fills this from g_data_eps when spread != 0. Single-port
            // reverse always answers on the control fd, to the pinned peer.
            g_rev.fds.push_back(g_resp_fds[0]);
            g_rev.dsts.push_back(g_resp.peer);

            mylog(log_info, "test: reverse phase %d begin, sending %u probes at %u pps\n",
                  h.phase, expected_n, pps);
            responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);
            ev_init(&g_rev_tick, rev_tick_cb);
            ev_timer_set(&g_rev_tick, REV_TICK_SEC, REV_TICK_SEC);
            ev_timer_start(loop, &g_rev_tick);
            return;
        }
```

`responder_cb` currently discards `loop` with `(void)loop;` — remove that line, the timers need it.

Also stop a running reverse phase in the `TEST_BYE` branch and in the idle-expiry branch:

```c
        if (g_rev.active) rev_stop(loop);
```

(`responder_timer_cb` already receives `loop`; remove its `(void)loop;` too.)

- [ ] **Step 4: Verify it builds and sends**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
./speederv2 --test-selftest | tail -2
bash tests/smoke_test_mode.sh 2>&1 | tail -3
```
Expected: no warning/error output from either build; `0 failures`; `=== PASSED ===` (nothing yet drives a reverse phase, so the existing suites must be untouched).

- [ ] **Step 5: Commit**

```bash
git add test_mode_net.cpp
git commit -m "test-mode: responder-side reverse probe sender

On PHASE_BEGIN with dir=1 the responder now paces TEST_PROBEs back to the
pinned peer via an ev_timer, then sends three PHASE_END copies carrying
{sent_n, send_fail_n} after a grace delay -- probes and PHASE_END travel
on different sockets, so nothing orders the last probe ahead of the end
marker.

The responder becomes a traffic source for the first time, so it bounds
expected_n and pps itself rather than trusting the peer, and a 5s
dead-man switch stops it blasting a dead address for up to 600s if the
prober is killed. A duplicate PHASE_BEGIN is the prober's keepalive and
must not restart the pacer.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Prober-side reverse receiver, `--test-no-reverse`, and report wiring (S2 end-to-end)

**Files:**
- Modify: `misc.cpp` (global + long option + parsing)
- Modify: `test_mode.h` (`test_no_reverse`, `down_status_t`, `test_report_t` fields)
- Modify: `test_mode.cpp` (render the down status and the peer-send-fail warning)
- Modify: `test_mode_net.cpp` (`prober_run_reverse_phase`, call it from `test_mode_prober_loop`)
- Modify: `tests/smoke_test_mode.sh` (Rounds 4 and 5)

**Interfaces:**
- Consumes: `pacer_t` (T1), `test_phase_begin_pack` / `test_hello_ack_caps` / `TEST_CAP_REVERSE` (T3), the responder sender (T4).
- Produces: `bool prober_run_reverse_phase(int phase, uint32_t pps, int duration_sec, bool spread, trace_t *trace_out, uint32_t *peer_send_fail_out);` → `false` when no probe arrived at all. Task 6 calls it with `spread = true`.

- [ ] **Step 1: Add the CLI flag**

In `misc.cpp`, next to the other test globals (line ~72):

```c
int    test_no_reverse = 0;
```

In the long options table (line ~617, after `test-app-mbps`):

```c
            {"test-no-reverse", no_argument, 0, 1},
```

In the parsing chain (after the `test-app-mbps` branch, line ~870):

```c
                } else if (strcmp(long_options[option_index].name, "test-no-reverse") == 0) {
                    test_no_reverse = 1;
                    mylog(log_info, "--test-mode: reverse (server -> client) phases disabled\n");
```

In `test_mode.h`, next to the other externs:

```c
extern int test_no_reverse;   // 1 => skip the server -> client phases
```

- [ ] **Step 2: Add the report fields**

In `test_mode.h`, inside `test_report_t`, replace `bool have_up, have_down;` with:

```c
    bool             have_up, have_down;
    recommendation_t up, down;

    // Why the down direction is missing, so the report can say so instead of
    // rendering a fabricated 100% loss.
    enum down_status_t {
        DOWN_OK = 0,
        DOWN_DISABLED,      // --test-no-reverse
        DOWN_UNSUPPORTED,   // peer did not advertise TEST_CAP_REVERSE
        DOWN_NO_PACKETS     // peer said it would send, nothing arrived
    };
    down_status_t down_status;

    // Probes the RESPONDER's local stack refused to send, reported over
    // PHASE_END. Counted as loss by this end, so the report flags them --
    // and must name the peer, or the operator will tune their own --test-pps.
    uint32_t down_peer_send_fail_n;
    uint32_t down_peer_send_total_n;
```

(delete the now-duplicated `recommendation_t up, down;` line that followed).

- [ ] **Step 3: Write the reverse receiver**

In `test_mode_net.cpp`, after `prober_run_phase()`:

```c
// Drives one server -> client phase: ask the responder to send, then record
// arrivals locally. Unlike the upstream phases, the trace never crosses the
// wire -- the recorder is the evaluator.
//
// Returns false when not a single probe arrived, which the caller must render
// as "direction not measured" rather than as 100% loss: a fabricated
// concrete-looking number is the worst failure mode this feature has.
static bool prober_run_reverse_phase(int phase, uint32_t pps, int duration_sec,
                                      bool spread, trace_t *trace_out,
                                      uint32_t *peer_send_fail_out) {
    uint32_t total = pps * (uint32_t)duration_sec;
    char begin_pl[TEST_PHASE_BEGIN_PL_LEN];
    test_phase_begin_pack(begin_pl, total, pps, 1, spread ? 1 : 0);

    // Unlike an upstream phase, a missing ACK here is NOT fatal: the responder
    // deliberately withholds it when it cannot run the phase (Task 6 refuses a
    // spread phase when no data port has seen this peer). Treat it as "this
    // direction was not measured" and let the caller say so, rather than
    // killing a run that has already produced good upstream data.
    if (!prober_exchange(TEST_PHASE_BEGIN, phase, begin_pl, sizeof(begin_pl),
                          TEST_PHASE_ACK, 1000, 5, NULL, NULL)) {
        mylog(log_warn, "test: responder did not ack reverse phase %d; "
                        "treating this direction as not measured\n", phase);
        trace_out->init(1, pps);   // caller may still read it; keep it valid
        *peer_send_fail_out = 0;
        return false;
    }

    mylog(log_info, "test: reverse phase %d running -- expecting %u probes at %u pps\n",
          phase, total, pps);

    trace_out->init(total, pps);
    *peer_send_fail_out = 0;

    my_time_t start_us       = get_current_time_us();
    my_time_t last_probe_us  = 0;
    my_time_t last_keepalive = start_us;
    uint32_t  arrived        = 0;
    bool      got_end        = false;

    // Hard ceiling so a peer that ACKs and then stalls cannot hang the run.
    // The phase itself may legitimately run long (the responder re-bases its
    // pacer rather than dropping probes), so allow generous slack.
    my_time_t deadline_us = start_us +
        (my_time_t)(duration_sec + 30) * 1000000ULL;
    // If nothing at all arrives this soon after the ACK, the peer is not
    // sending -- bail early rather than waiting out the whole duration.
    const my_time_t FIRST_PROBE_LIMIT_US = 5000000ULL;

    while (get_current_time_us() < deadline_us) {
        my_time_t now = get_current_time_us();

        if (arrived == 0 && now - start_us > FIRST_PROBE_LIMIT_US) break;
        if (got_end) break;
        // Idle finalize, mirroring the responder's fallback: five inter-packet
        // gaps, floored at 2s, in case all three PHASE_END copies were lost.
        if (arrived > 0 && last_probe_us != 0) {
            my_time_t limit = 2000000ULL;
            if (pps > 0) {
                my_time_t five = (my_time_t)(5.0 / (double)pps * 1000000.0);
                if (five > limit) limit = five;
            }
            if (now - last_probe_us > limit) break;
        }

        // Keepalive: a re-sent PHASE_BEGIN for the running phase. The
        // responder's duplicate guard re-ACKs it without touching the pacer,
        // and it refreshes both the session idle timer and the 5s dead-man
        // switch. The prober is otherwise silent for the whole phase.
        if (now - last_keepalive > 1000000ULL) {
            last_keepalive = now;
            prober_sendto(TEST_PHASE_BEGIN, phase, 0, begin_pl, sizeof(begin_pl),
                          g_pr.peer, 0);
        }

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(g_pr.fd, &rf);
        int sr = select(g_pr.fd + 1, &rf, NULL, NULL, &tv);
        if (sr <= 0) continue;

        for (;;) {
            char buf[TEST_BUF_MAX];
            int len = recv(g_pr.fd, buf, sizeof(buf), 0);
            if (len <= 0) break;
            test_hdr_t h;
            uint8_t *pl = 0;
            int pl_len = 0;
            int mt = test_decode(buf, len, &h, &pl, &pl_len);
            if (mt < 0 || h.phase != (uint8_t)phase) continue;
            if (mt == TEST_PROBE) {
                last_probe_us = get_current_time_us();
                trace_out->record(h.seq, last_probe_us);
                arrived++;
            } else if (mt == TEST_PHASE_END) {
                if (pl_len >= 8) *peer_send_fail_out = read_u32((char *)pl + 4);
                got_end = true;
            }
        }
    }

    if (arrived == 0) {
        mylog(log_warn, "test: reverse phase %d -- no probes arrived at all\n", phase);
        return false;
    }
    mylog(log_info, "test: reverse phase %d received %u/%u\n", phase, arrived, total);
    return true;
}
```

`prober_exchange` uses a non-blocking `recv` loop already; the inner `for(;;)` above drains the socket the same way so a burst is not left queued between `select` calls.

- [ ] **Step 4: Call it from the prober loop**

In `test_mode_prober_loop()`, immediately after the S1 block (line ~783), insert:

```c
    // ---- S2: single port, downstream ----
    rep.down_status = test_report_t::DOWN_OK;
    if (test_no_reverse) {
        rep.down_status = test_report_t::DOWN_DISABLED;
    } else if (!(g_pr.peer_caps & TEST_CAP_REVERSE)) {
        rep.down_status = test_report_t::DOWN_UNSUPPORTED;
        mylog(log_warn, "test: peer does not advertise reverse-phase support; "
                        "skipping the server -> client measurement\n");
    } else {
        trace_t down_trace;
        uint32_t peer_fail = 0;
        if (prober_run_reverse_phase(2, (uint32_t)test_pps, test_duration_sec,
                                      false, &down_trace, &peer_fail)) {
            rep.have_down = true;
            rep.down = test_evaluate(down_trace, rep.app_mbps, rep.pkt_size);
            rep.down_peer_send_fail_n  = peer_fail;
            rep.down_peer_send_total_n = (uint32_t)test_pps * (uint32_t)test_duration_sec;
        } else {
            rep.down_status = test_report_t::DOWN_NO_PACKETS;
        }
    }
```

and delete `rep.have_down = false;` at line ~747 (the `memset` already zeroes it).

- [ ] **Step 5: Render the down status**

In `test_mode.cpp`, replace line ~458:

```c
    if (r.have_down) {
        render_direction("server -> client, 单端口", r.down);
        if (r.down_peer_send_fail_n > 0) {
            printf("\n--- 警告: 对端发送失败 ---\n");
            printf("  对端有 %u/%u 个探测包未能发出(对端本地发送缓冲区满等)。\n",
                   r.down_peer_send_fail_n, r.down_peer_send_total_n);
            printf("  本端会把它们计为丢包,因此上方 server -> client 丢包率可能被高估;\n");
            printf("  这部分并非链路丢包。注意需要调整的是**对端**的负载,而非本端 --test-pps。\n");
        }
    } else {
        printf("\n--- 链路特征 (server -> client, 单端口) ---\n");
        switch (r.down_status) {
            case test_report_t::DOWN_DISABLED:
                printf("  未测量: 已通过 --test-no-reverse 关闭该方向。\n");
                break;
            case test_report_t::DOWN_UNSUPPORTED:
                printf("  未测量: 对端为较早的构建,不支持反向探测。\n");
                printf("  两端升级到同一版本后可测出该方向。\n");
                break;
            case test_report_t::DOWN_NO_PACKETS:
                printf("  未测出结果: 对端声称支持反向探测,但一个探测包也没有到达。\n");
                printf("  可能原因: 对端到本端的 UDP 路径被阻断,或 NAT 映射已失效。\n");
                printf("  注意这里不报 100%% 丢包 —— 没有收到数据与测得全丢是两回事。\n");
                break;
            default:
                break;
        }
    }
```

- [ ] **Step 6: Add smoke rounds**

Append to `tests/smoke_test_mode.sh`, before the final `=== PASSED ===`:

```bash
echo "Round 4: reverse phase on a clean loopback"
"$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" --log-level 4 \
    > "$WORKDIR/r4_resp.log" 2>&1 &
RESP_PID=$!
sleep 1
"$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$KEY" \
    --test-duration 2 --test-pps 100 > "$WORKDIR/r4_prober.log" 2>&1
kill "$RESP_PID" 2>/dev/null || true; wait "$RESP_PID" 2>/dev/null || true; RESP_PID=""

if ! grep -q "server -> client, 单端口" "$WORKDIR/r4_prober.log"; then
    echo "  FAIL: no server -> client section in the report"
    sed -n '1,80p' "$WORKDIR/r4_prober.log"
    exit 1
fi
if grep -q "未测出结果\|未测量" "$WORKDIR/r4_prober.log"; then
    echo "  FAIL: reverse direction reported as unmeasured on a clean loopback"
    exit 1
fi
DOWN_LOSS=$(sed -n '/server -> client, 单端口/,/推荐配置/p' "$WORKDIR/r4_prober.log" \
    | grep "丢包率" | grep -oE '[0-9]+\.[0-9]+' | head -1)
if [[ -z "$DOWN_LOSS" ]]; then
    echo "  FAIL: could not parse downstream loss"
    exit 1
fi
if awk -v v="$DOWN_LOSS" 'BEGIN{exit !(v > 1.0)}'; then
    echo "  FAIL: downstream loss $DOWN_LOSS% too high on clean loopback"
    exit 1
fi
echo "  [reverse-clean] downstream loss = $DOWN_LOSS%"
echo "  [reverse-clean] ok"
echo

echo "Round 5: --test-no-reverse suppresses the reverse phase"
"$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" --log-level 4 \
    > "$WORKDIR/r5_resp.log" 2>&1 &
RESP_PID=$!
sleep 1
"$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$KEY" \
    --test-duration 2 --test-pps 100 --test-no-reverse \
    > "$WORKDIR/r5_prober.log" 2>&1
kill "$RESP_PID" 2>/dev/null || true; wait "$RESP_PID" 2>/dev/null || true; RESP_PID=""

if ! grep -q "已通过 --test-no-reverse 关闭该方向" "$WORKDIR/r5_prober.log"; then
    echo "  FAIL: --test-no-reverse did not report the direction as disabled"
    exit 1
fi
if grep -q "推荐配置 (server -> client" "$WORKDIR/r5_prober.log"; then
    echo "  FAIL: --test-no-reverse still produced a downstream recommendation"
    exit 1
fi
echo "  [no-reverse] ok"
echo
```

- [ ] **Step 7: Run everything**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
./speederv2 --test-selftest | tail -2
bash tests/smoke_test_mode.sh
bash tests/smoke.sh 2>&1 | tail -3
```
Expected: no warning/error output; `0 failures`; both smoke scripts print `=== PASSED ===`.

- [ ] **Step 8: Commit**

```bash
git add misc.cpp test_mode.h test_mode.cpp test_mode_net.cpp tests/smoke_test_mode.sh
git commit -m "test-mode: measure the server -> client direction (S2)

The prober now asks the responder to send a paced probe stream back
through the nat mapping the client already punched, records the trace
locally, and evaluates it locally -- no trace and no new result payload
crosses the wire. The report gains a server -> client section and a
second suggested command line, which is the point: -f is per-direction
(the receiver reads data_num/redundant_num off the wire), and links are
routinely asymmetric.

A direction with no data is reported as unmeasured, never as 100% loss,
and the peer's own send failures are surfaced as the peer's rather than
being quietly subtracted.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: S4 — multi-port reverse

**Files:**
- Modify: `test_mode_net.cpp` (fill `g_rev.fds`/`g_rev.dsts` from `g_data_eps`; call S4 from the prober)
- Modify: `test_mode.h` (`have_spread_down`, `spread_loss_down`, `spread_ports_down`)
- Modify: `test_mode.cpp` (port-range comparison gains a downstream line)

**Interfaces:**
- Consumes: `g_data_eps` (T2), `rev_send_t` (T4), `prober_run_reverse_phase` (T5).
- Produces: no new symbols; extends existing behaviour.

- [ ] **Step 1: Populate the reverse destination list from the per-fd table**

In `test_mode_net.cpp`, in the `dir != 0` branch of `TEST_PHASE_BEGIN` (Task 4, Step 3), replace the two `push_back` lines with:

```c
            if (spread != 0 && g_data_eps.size() > 1) {
                // Each data fd replies to the address IT saw during S3. Under a
                // symmetric nat that is a different external port per fd, so
                // replying to the control-plane address instead would be
                // dropped -- and S4 would report ~100% loss and conclude that
                // port-range is useless, the inverse of the truth.
                for (size_t k = 1; k < g_data_eps.size(); k++) {
                    if (!g_data_eps[k].seen) continue;
                    g_rev.fds.push_back(g_resp_fds[k]);
                    g_rev.dsts.push_back(g_data_eps[k].addr);
                }
                if (g_rev.fds.empty()) {
                    // No data port ever saw this peer, so no nat mapping exists
                    // to reply through. Refuse rather than fall back to the
                    // control port, which would silently measure single-port
                    // loss and label it a multi-port result.
                    //
                    // Withholding the PHASE_ACK is the signal: Task 5's
                    // prober_run_reverse_phase() treats a missing ACK for a
                    // reverse phase as "not measured" and moves on, rather than
                    // aborting a run that already has good upstream data.
                    mylog(log_warn, "test: refusing spread reverse phase %d: no data port "
                                    "has seen this peer\n", h.phase);
                    g_rev.active = false;
                    return;
                }
                mylog(log_info, "test: reverse phase %d will use %d data port(s)\n",
                      h.phase, (int)g_rev.fds.size());
            } else {
                g_rev.fds.push_back(g_resp_fds[0]);
                g_rev.dsts.push_back(g_resp.peer);
            }
```

Note the `g_rev.active = false;` before the refusal `return`: `g_rev` was already reset and marked active above, and leaving it active with an empty `fds` vector would divide by zero in `rev_tick_cb`. The timer is not started on this path, but the flag must not be left set for the dead-man check either.

- [ ] **Step 2: Add the report fields**

In `test_mode.h`, in `test_report_t`, extend the port-range block:

```c
    // port-range comparison
    bool   have_spread;
    double spread_loss_up;   // loss rate on N ports, up direction
    int    spread_ports;
    bool   have_spread_down;
    double spread_loss_down;
    int    spread_ports_down;   // ports that actually carried traffic, may be < N
```

- [ ] **Step 3: Drive S4 from the prober**

In `test_mode_prober_loop()`, inside the existing `if (!spread.empty())` block, after the S3 lines:

```c
        // ---- S4: N ports, downstream ----
        if (rep.down_status == test_report_t::DOWN_OK && rep.have_down) {
            trace_t d4;
            uint32_t fail4 = 0;
            if (prober_run_reverse_phase(4, (uint32_t)test_pps, test_duration_sec,
                                          true, &d4, &fail4)) {
                trace_stats_t s4 = trace_analyze(d4);
                rep.have_spread_down  = true;
                rep.spread_loss_down  = s4.loss_rate;
                rep.spread_ports_down = (int)spread.size();
            } else {
                mylog(log_warn, "test: multi-port reverse phase produced no data; "
                                "skipping the downstream port-range comparison\n");
            }
        }
```

- [ ] **Step 4: Render the downstream comparison**

In `test_mode.cpp`, replace the `if (r.have_spread)` block body so each direction gets its own line and its own conclusion:

```c
    if (r.have_spread || r.have_spread_down) {
        printf("\n--- port-range 对比 ---\n");
        if (r.have_spread) {
            double base = r.have_up ? r.up.stats.loss_rate : 0.0;
            printf("  上行  单端口 %.4f%%  |  %d 端口 %.4f%%\n",
                   base * 100.0, r.spread_ports, r.spread_loss_up * 100.0);
            if (base > 0.0 && r.spread_loss_up < base)
                printf("    结论: 多端口降低上行丢包 %.0f%%,port-range 对该方向有效\n",
                       (base - r.spread_loss_up) / base * 100.0);
            else if (base > 0.0)
                printf("    结论: 多端口未降低上行丢包,port-range 对该方向无收益\n");
            else
                printf("    结论: 上行单端口已无丢包,无法判断 port-range 收益\n");
        }
        if (r.have_spread_down) {
            double base = r.have_down ? r.down.stats.loss_rate : 0.0;
            printf("  下行  单端口 %.4f%%  |  %d 端口 %.4f%%\n",
                   base * 100.0, r.spread_ports_down, r.spread_loss_down * 100.0);
            if (base > 0.0 && r.spread_loss_down < base)
                printf("    结论: 多端口降低下行丢包 %.0f%%,port-range 对该方向有效\n",
                       (base - r.spread_loss_down) / base * 100.0);
            else if (base > 0.0)
                printf("    结论: 多端口未降低下行丢包,port-range 对该方向无收益\n");
            else
                printf("    结论: 下行单端口已无丢包,无法判断 port-range 收益\n");
        }
    }
```

- [ ] **Step 5: Add the multi-port smoke round**

Append to `tests/smoke_test_mode.sh` after Round 5:

```bash
echo "Round 6: multi-port reverse (--data-port-range on both ends)"
DP_LO=$(( RESP_PORT + 100 ))
DP_HI=$(( DP_LO + 3 ))
"$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" \
    --data-port-range $DP_LO-$DP_HI --log-level 4 \
    > "$WORKDIR/r6_resp.log" 2>&1 &
RESP_PID=$!
sleep 1
"$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$KEY" \
    --data-port-range $DP_LO-$DP_HI --test-duration 2 --test-pps 100 \
    > "$WORKDIR/r6_prober.log" 2>&1
kill "$RESP_PID" 2>/dev/null || true; wait "$RESP_PID" 2>/dev/null || true; RESP_PID=""

if ! grep -q "下行  单端口" "$WORKDIR/r6_prober.log"; then
    echo "  FAIL: no downstream port-range comparison line"
    sed -n '1,120p' "$WORKDIR/r6_prober.log"
    exit 1
fi
if ! grep -q "reverse phase 4 will use 4 data port(s)" "$WORKDIR/r6_resp.log"; then
    echo "  FAIL: responder did not spread the reverse phase across 4 data ports"
    grep -i "reverse phase" "$WORKDIR/r6_resp.log" || true
    exit 1
fi
echo "  [reverse-spread] ok"
echo
```

- [ ] **Step 6: Run everything**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
./speederv2 --test-selftest | tail -2
bash tests/smoke_test_mode.sh
bash tests/smoke_port_range.sh 2>&1 | tail -3
```
Expected: no warning/error output; `0 failures`; both smoke scripts pass.

- [ ] **Step 7: Commit**

```bash
git add test_mode.h test_mode.cpp test_mode_net.cpp tests/smoke_test_mode.sh
git commit -m "test-mode: spread the reverse phase across data ports (S4)

Each data fd replies to the source address that fd itself observed during
S3. Under a symmetric nat that is a different external port per fd, so
replying to the control-plane address would be dropped and S4 would
report ~100% loss and conclude port-range is useless -- the inverse of
the truth on the links it helps most.

A spread reverse phase with no data port that has seen the peer is
refused outright rather than falling back to the control port, which
would measure single-port loss and label it a multi-port result.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: Backward-compatibility verification and documentation

**Files:**
- Modify: `main.cpp:87-112` (help text)
- Modify: `README.md` (test-mode section, lines ~170-250)
- Modify: `tests/smoke_test_mode.sh` (header comment)

**Interfaces:**
- Consumes: everything above. Produces: no code symbols.

- [ ] **Step 1: Prove the old-responder path**

Build the pre-change tree as an "old responder" and confirm a new prober degrades gracefully instead of fabricating a 100% loss. `eb718fa` is the spec commit — the last commit before any code change in this plan.

```bash
mkdir -p /tmp/oldresp && git archive eb718fa | tar -x -C /tmp/oldresp
make -C /tmp/oldresp 2>&1 | tail -2
/tmp/oldresp/speederv2 -s --test-mode -l0.0.0.0:34999 -k pd --log-level 4 > /tmp/old_resp.log 2>&1 &
sleep 1
./speederv2 -c --test-mode -r127.0.0.1:34999 -k pd --test-duration 2 --test-pps 100 > /tmp/new_prober.log 2>&1
kill %1 2>/dev/null || true
grep -c "100.0000%" /tmp/new_prober.log        # must print 0
grep "不支持反向探测" /tmp/new_prober.log       # must print the line
```

Expected: `0` occurrences of `100.0000%`, and the "对端为较早的构建,不支持反向探测" line present. Record both outputs verbatim in the task report. Then `rm -rf /tmp/oldresp`.

- [ ] **Step 2: Update the help text**

In `main.cpp`, in the test-mode block: add the flag line after `--test-app-mbps`,

```c
    printf("    --test-no-reverse                     skip the server -> client phases. only needed on the prober;\n");
    printf("                                          the responder always supports them.\n");
```

and replace the NOTE that begins `only the client -> server direction is measured` with:

```c
    printf("      NOTE: both directions are measured; the report gives a separate -f/-i for each\n");
    printf("            end, because -f is per-direction and links are often asymmetric. total\n");
    printf("            runtime is the fixed 30s rate scan plus two --test-duration passes, plus\n");
    printf("            two more if --data-port-range is set (about 30s + 2x or 4x). the rate\n");
    printf("            scan itself only probes client -> server, so a link policed ONLY on the\n");
    printf("            server -> client direction will not be detected as policed.\n");
```

- [ ] **Step 3: Update the README**

In `README.md`'s test-mode section:

1. Replace "Currently only the client → server direction is measured; the report has no server → client section (a future revision may add it)." with, verbatim:

> Both directions are measured. The report gives a separate `-f`/`-i` for each
> end, because `-f` is per-direction — the receiver reads `data_num`/`redundant_num`
> off the wire rather than from its own config, so the two ends need not match —
> and real links are routinely asymmetric. The server → client probes travel back
> through the NAT mapping the client already punched, so the client needs no
> inbound port.
2. Add `--test-no-reverse` to the options table with default "off (reverse runs)" and the note that it is prober-side only.
3. Replace the runtime paragraph with the table from spec §1: single-port 90s, multi-port 150s at the defaults; 60s/90s with `--test-no-reverse`.
4. Add a **Known limitation** paragraph, verbatim:

> **Known limitation:** the rate scan probes client → server only. A link that is
> policed *only* on the server → client direction will not be flagged as policed,
> and the server → client table will still print FEC recommendations whose premise
> does not hold. Widening the scan to both directions would double the fixed 30s
> scan, which was judged not worth it; if you suspect downstream policing, run the
> tool a second time with the roles reversed.
5. In the "Reading the report" list, add the `server -> client` section and note that a direction with no data is reported as unmeasured, never as 100% loss.
6. Update the two-run workaround in the earlier docs (the "跑两次、角色对调" advice) if present — it is now obsolete.

- [ ] **Step 4: Update the smoke script header**

In `tests/smoke_test_mode.sh`, update the header comment to describe Rounds 4–6 and the new expected selftest check count (run `./speederv2 --test-selftest | tail -1` to get the exact number), and update the "~2 minutes" estimate to reflect the three added rounds.

- [ ] **Step 5: Final verification**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
make clean >/dev/null && make
./speederv2 --test-selftest | tail -2
bash tests/smoke_test_mode.sh
bash tests/smoke.sh 2>&1 | tail -3
bash tests/smoke_port_range.sh 2>&1 | tail -3
git status --short           # git_version.h must NOT be staged
```
Expected: no warning/error output from either build; `0 failures`; all three smoke scripts print `=== PASSED ===`.

- [ ] **Step 6: Commit**

```bash
git add main.cpp README.md tests/smoke_test_mode.sh
git commit -m "docs: document bidirectional test mode and --test-no-reverse

Records the known limitation that the rate scan probes client -> server
only, so a link policed only on the downstream is not flagged as policed
while the downstream table still prints recommendations whose premise may
not hold. Verified that a new prober against a pre-change responder
reports 'peer does not support reverse probing' rather than a fabricated
100% loss.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Traceability

| Spec section | Task |
|---|---|
| §1 范围 / S2 / S4 | 5, 6 |
| §1 `--test-no-reverse` + CLI 全局 | 5 |
| §1 明确不做(扫描仅上行) | 7 (documented as a limitation) |
| §2.1 `pacer_t` | 1 |
| §2.2 responder 发送侧 (ev_timer, seq, padding, PHASE_END ×3 @20ms, `responder_send_ex`) | 4 |
| §2.3 prober 接收侧 | 5 |
| §2.4 谁收包谁出结论 | 5 (down evaluated locally; no wire change) |
| §3.1 PHASE_BEGIN 16 字节 | 3 |
| §3.2 PHASE_END 载荷 | 4 (send), 5 (receive + render) |
| §3.3 HELLO_ACK 能力位 | 3 |
| §3.4 两道闸 | 3 (caps), 5 (`DOWN_NO_PACKETS`) |
| §3.5 responder 自限 | 4 |
| §4.1 S3 对称 NAT 缺陷 | 2 |
| §4.2 分层 pinning | 2 |
| §4.3 per-fd 源地址表 + S4 约束 | 2 (table), 6 (use + refusal) |
| §5 失败模式表 | 4 (duplicate PHASE_BEGIN, peer send fail), 5 (PHASE_END lost → idle finalize) |
| §5.1 死人开关 + keepalive | 4 (responder side), 5 (prober side) |
| §5.2 grace period | 4 |
| §6 报告 | 5 (down section, peer-fail warning, statuses), 6 (port-range down line) |
| §7.1 selftest | 1, 2, 3 |
| §7.2 smoke | 5 (rounds 4–5), 6 (round 6) |
| §7.3 向后兼容 | 7 |
| §8 文档 | 7 |
