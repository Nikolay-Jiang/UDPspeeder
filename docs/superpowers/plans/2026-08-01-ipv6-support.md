# IPv6 Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore IPv6 support in port-range mode and test mode — both broken by hardcoded IPv4 literals — and lock the base tunnel's already-working IPv6 support behind a regression test.

**Architecture:** One pure `address_t` helper derives a wildcard bind address from a peer's address family; the unconnected socket path gains the `--out-interface` support its connected sibling already has; three call sites stop using string literals and start deriving the family from the peer. Startup validation catches `--out-addr` family mismatches before they surface as an unattributable `bind()` failure.

**Tech Stack:** C++11, libev (embedded via `-isystem libev`), `make` / `make debug`, bash smoke tests, GitHub Actions CI.

**Spec:** `docs/superpowers/specs/2026-08-01-ipv6-support-design.md`

## Global Constraints

- C++11 only. No RTTI, no exceptions in hot paths.
- Both `make` and `make debug` must finish with **zero** warnings and zero errors. Verify with `make clean && make 2>&1 | grep -Ei "warning|error"` producing no output.
- `git_version.h` is generated and **must never be committed**. `core`, `speederv2`, `speederv2-0265e2c` and `docs/code-review-2026-06-10.md` are pre-existing untracked artifacts that must never be staged. Check `git status` before `git add`.
- `-Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers` are intentionally suppressed repo-wide; do not chase unrelated warnings.
- Pure address/protocol/statistics logic lives in `common.{h,cpp}` and `test_mode.cpp`; socket and libev wiring lives in the tunnel/test-mode `*_net`-style files. The boundary is stated at `test_mode_net.cpp:1-3`.
- The only assertion harness in this repo is `test_mode_selftest()` in `test_mode.cpp`, run via `./speederv2 --test-selftest`. It is currently at **134 checks** and must always end with `0 failures`. The RED state for a new function is a compile error — that is correct here, not a defect.
- Globals parsed in `process_arg` are read-only afterwards.
- **`address_t::get_str()` returns a pointer to a single `static char` buffer.** Two `get_str()` calls in one `printf`/`mylog` argument list both print the *second* address. Use `to_str(char *)` into separate local buffers whenever a message names two addresses.
- `tests/smoke.sh`, `tests/smoke_port_range.sh`, `tests/smoke_test_mode.sh` must all keep passing. `smoke_test_mode.sh` takes ~6 minutes; run it in the **foreground**.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `common.h` | modify | `address_t::wildcard_like`; `new_listen_socket2` declaration gains a defaulted `interface_string` |
| `common.cpp` | modify | `new_listen_socket2` honours `interface_string` |
| `test_mode.cpp` | modify | selftest assertions for `wildcard_like` |
| `tunnel_client.cpp` | modify | port-range client sockets: family from `ctrl_addr`, plus `--out-addr` / `--out-interface` |
| `tunnel_server.cpp` | modify | port-range bind base: family from `local_addr`, explicit log when defaulting to IPv4 |
| `test_mode_net.cpp` | modify | prober socket: family from `remote_addr`, plus `--out-addr` / `--out-interface` |
| `misc.cpp` | modify | startup validation of `--out-addr` family and port |
| `tests/udp_echo.py` | modify | accept a bind address, derive family from it |
| `tests/smoke_ipv6.sh` | create | three IPv6 rounds with a loud skip when `::1` is unavailable |
| `.github/workflows/ci.yml` | modify | run the IPv6 suite |
| `README.md`, `main.cpp` | modify | document IPv6 |

---

### Task 1: `address_t::wildcard_like`

The three defects all share one missing step: deriving the address family from the peer. Making that step a named pure function is what stops a fourth site repeating it, and it is the only part of this work the selftest can reach directly.

**Files:**
- Modify: `common.h` (inside `struct address_t`, directly after `from_ip_port_new`, around line 232)
- Modify: `test_mode.cpp` (assertions in `test_mode_selftest()`)

**Interfaces:**
- Consumes: nothing.
- Produces: `void address_t::wildcard_like(u32_t family, int port);` — Tasks 2, 3 and 4 all call it.

- [ ] **Step 1: Write the failing test**

Add to `test_mode_selftest()` in `test_mode.cpp`, immediately after the `// ---- address comparison ----` block:

```c
    // ---- wildcard_like ----
    {
        address_t w4;
        w4.wildcard_like(AF_INET, 1234);
        TCHECK(w4.is_vaild(), "wildcard_like(AF_INET) must produce a valid address");
        TCHECK(w4.get_type() == AF_INET, "wildcard_like(AF_INET) family must be AF_INET");
        TCHECK(w4.get_port() == 1234, "wildcard_like must carry the port, got %u", w4.get_port());
        TCHECK(w4.inner.ipv4.sin_addr.s_addr == INADDR_ANY,
               "wildcard_like(AF_INET) address must be 0.0.0.0");

        address_t w6;
        w6.wildcard_like(AF_INET6, 4321);
        TCHECK(w6.is_vaild(), "wildcard_like(AF_INET6) must produce a valid address");
        TCHECK(w6.get_type() == AF_INET6, "wildcard_like(AF_INET6) family must be AF_INET6");
        TCHECK(w6.get_port() == 4321, "wildcard_like must carry the port, got %u", w6.get_port());
        TCHECK(memcmp(&w6.inner.ipv6.sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0,
               "wildcard_like(AF_INET6) address must be ::");

        // The bug class this helper exists to prevent is an ipv4 literal being
        // used for an ipv6 peer, so pin that the two families are distinguishable.
        TCHECK(!test_addr_same_ip(w4, w6),
               "the two wildcard families must not compare equal by ip");

        // A non-zero port must survive; using 0 for both would let a helper that
        // silently ignored `port` pass every other assertion here.
        address_t w0;
        w0.wildcard_like(AF_INET6, 0);
        TCHECK(w0.get_port() == 0, "wildcard_like(port 0) must give port 0, got %u", w0.get_port());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make clean >/dev/null && make 2>&1 | tail -5`
Expected: FAIL — a compile error along the lines of `'struct address_t' has no member named 'wildcard_like'`.

- [ ] **Step 3: Write minimal implementation**

In `common.h`, inside `struct address_t`, directly after `from_ip_port_new`:

```c
    // Wildcard bind address in a given family: 0.0.0.0:port or [::]:port.
    //
    // The family must come from the peer, never from a string literal. Three
    // sites once built an ephemeral socket from a hardcoded "0.0.0.0:0" and
    // silently broke ipv6 for the features that used them -- and the symptom
    // was "cannot connect", indistinguishable from a firewall drop or a key
    // mismatch. Deriving the family through a named function makes the next
    // person adding a socket confront the question.
    void wildcard_like(u32_t family, int port) {
        clear();
        if (family == AF_INET) {
            // INADDR_ANY is a macro constant, so it has no address of its own.
            u32_t any = INADDR_ANY;
            from_ip_port_new(AF_INET, &any, port);
        } else if (family == AF_INET6) {
            // in6addr_any is a real object provided by libc; the const cast is
            // only needed because from_ip_port_new takes void* and never writes.
            from_ip_port_new(AF_INET6, (void *)&in6addr_any, port);
        } else {
            assert(0 == 1);
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"; ./speederv2 --test-selftest | tail -2`
Expected: no warning/error output; last line reports `0 failures` with a check count above 134.

- [ ] **Step 5: Commit**

```bash
git add common.h test_mode.cpp
git commit -m "common: add address_t::wildcard_like

Deriving a bind address's family from the peer is the step all three
ipv6 defects are missing -- each replaced it with a hardcoded
\"0.0.0.0:0\". A named pure function makes the omission visible and is
the only part of this work the selftest can reach directly.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Unconnected socket path honours `--out-interface`; port-range client fixed

`new_connected_socket2` already takes a bind address and an interface and derives the family from its target. Its unconnected sibling `new_listen_socket2` takes neither — **that, not a forgotten argument, is why `--out-addr` and `--out-interface` are silently ignored in port-range mode.**

**Files:**
- Modify: `common.h:406` (declaration)
- Modify: `common.cpp:756-772` (`new_listen_socket2`)
- Modify: `tunnel_client.cpp:444-453`

**Interfaces:**
- Consumes: `address_t::wildcard_like` (Task 1).
- Produces: `int new_listen_socket2(int &fd, address_t &addr, char *interface_string = NULL);` — Tasks 3 and 4 call the three-argument form.

- [ ] **Step 1: Extend the declaration**

In `common.h`, replace line 406:

```c
// interface_string, when non-NULL, applies SO_BINDTODEVICE -- the same
// treatment new_connected_socket2 already gives its socket. It is defaulted so
// the existing call sites need no change.
int new_listen_socket2(int &fd, address_t &addr, char *interface_string = NULL);
```

A defaulted parameter is used deliberately rather than a new function name: six call sites exist and only two of them care, so a default keeps the diff to the sites that actually changed behaviour.

- [ ] **Step 2: Implement it**

In `common.cpp`, replace `new_listen_socket2`:

```c
int new_listen_socket2(int &fd, address_t &addr, char *interface_string) {
    fd = socket(addr.get_type(), SOCK_DGRAM, IPPROTO_UDP);

    int yes = 1;

    if (::bind(fd, (struct sockaddr *)&addr.inner, addr.get_len()) == -1) {
        mylog(log_fatal, "socket bind error=%s\n", get_sock_error());
        myexit(1);
    }

#ifdef __linux__
    if (interface_string && ::setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_string, strlen(interface_string)) < 0) {
        mylog(log_fatal, "socket interface bind error=%s\n", get_sock_error());
        myexit(1);
    }
#endif

    setnonblocking(fd);
    set_buf_size(fd, socket_buf_size);

    mylog(log_debug, "local_listen_fd=%d\n", fd);

    return 0;
}
```

- [ ] **Step 3: Fix the port-range client**

In `tunnel_client.cpp`, replace lines 444-453 (from `if (port_range_mode) {` through the control-socket `assert`):

```c
    if (port_range_mode) {
        // The family comes from --control-host, NOT from -r. set_from_ack()
        // below builds every data-port destination from ctrl_addr as its base,
        // and remote_addr is not used on this path in port-range mode -- a
        // reader will assume -r is the source of truth, and it is not.
        address_t bind_addr;
        if (out_addr) {
            bind_addr = *out_addr;
        } else {
            bind_addr.wildcard_like(ctrl_addr.get_type(), 0);
        }

        // Unconnected data socket — sendto with varying dst port
        assert(new_listen_socket2(remote_fd, bind_addr, out_interface) == 0);
        remote_fd64 = fd_manager.create(remote_fd);

        // Control socket. Both sockets are outbound to the same server, so
        // both take --out-addr and --out-interface; restricting only one would
        // be meaningless. Binding both to the same address is safe because
        // --out-addr's port is required to be 0 in port-range mode (validated
        // in process_arg); a fixed port would fail here with EADDRINUSE.
        assert(new_listen_socket2(g_ctrl_fd, bind_addr, out_interface) == 0);
```

- [ ] **Step 4: Verify the build and the existing suites**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
./speederv2 --test-selftest | tail -2
bash tests/smoke.sh 2>&1 | tail -3
bash tests/smoke_port_range.sh 2>&1 | tail -3
```
Expected: no warning/error output from either build; `0 failures`; both smoke scripts print `=== PASSED ===`. The IPv4 port-range path must be completely unaffected.

- [ ] **Step 5: Verify IPv6 port-range end to end**

The server side is not fixed until Task 3, but passing `-l` explicitly gives it a valid IPv6 `local_addr`, so the client fix can be verified now. Run this manually (adjust the scratch paths as needed):

```bash
python3 - <<'EOF' &
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::1", 25011))
while True:
    d, a = s.recvfrom(65536); s.sendto(b"ECHO:" + d, a)
EOF
sleep 0.5
./speederv2 -s --port-range-mode --control-port 25010 --data-port-range 25020-25023 \
    -l"[::1]:0" -r "[::1]:25011" -f2:1 -k v6 --log-level 4 > /tmp/s6.log 2>&1 &
sleep 1
./speederv2 -c --port-range-mode --control-host "[::1]:25010" -l"[::1]:25012" \
    -r "[::1]:25010" --data-port-range 25020-25023 -f2:1 -k v6 --log-level 4 > /tmp/c6.log 2>&1 &
sleep 2.5
python3 - <<'EOF'
import socket, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.settimeout(3.0)
ok = 0
for i in range(30):
    s.sendto(b"pkt%04d" % i, ("::1", 25012)); time.sleep(0.01)
s.settimeout(2.0)
try:
    while True:
        d, _ = s.recvfrom(65536)
        if d.startswith(b"ECHO:"): ok += 1
except socket.timeout: pass
print("delivered %d/30" % ok)
EOF
```

Expected: close to 30/30 after your change.

To capture the "before" half honestly, `git stash` your `tunnel_client.cpp` edit, rebuild, run the same script (it should print `delivered 0/30` — this was measured during design), then `git stash pop` and rebuild. **Paste both outputs in your report.** Kill the background processes and the echo server afterwards.

- [ ] **Step 6: Commit**

```bash
git add common.h common.cpp tunnel_client.cpp
git commit -m "port-range: derive the client socket family from --control-host

The client built both outbound sockets from a hardcoded \"0.0.0.0:0\", so
port-range mode could not reach an ipv6 server at all -- measured 0/30
over ::1 before this change. The family now comes from ctrl_addr, which
is already the base every data-port destination is derived from.

new_listen_socket2 also gains the SO_BINDTODEVICE support its connected
sibling has had all along. That absence, not a forgotten argument, is why
--out-addr and --out-interface were silently ignored in port-range mode.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Port-range server bind base

**Files:**
- Modify: `tunnel_server.cpp:449-457`

**Interfaces:**
- Consumes: `address_t::wildcard_like` (Task 1).
- Produces: nothing new.

- [ ] **Step 1: Replace the bind base construction**

In `tunnel_server.cpp`, replace lines 449-457:

```c
        // Bind base for the control and data ports. With -l given the family
        // follows it; without -l there is nothing to derive it from.
        address_t bind_base;
        if (local_addr.is_vaild()) {
            bind_base = local_addr;
        } else {
            // Keep the historical ipv4 default so existing deployments are
            // unaffected -- but say so out loud. This is the only place in the
            // program that guesses an address family, and a wrong guess looks
            // exactly like a firewall drop or a key mismatch from the client
            // side, with both logs otherwise clean.
            bind_base.wildcard_like(AF_INET, 0);
            mylog(log_info, "port-range-mode: -l was not given, binding the ipv4 wildcard "
                            "address (0.0.0.0). pass -l\"[::]:0\" to listen on ipv6 instead.\n");
        }
```

- [ ] **Step 2: Verify the log fires and the default is unchanged**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
timeout 3 ./speederv2 -s --port-range-mode --control-port 25040 \
    --data-port-range 25050-25051 -r 127.0.0.1:25041 -k v6 --log-level 4 2>&1 \
    | grep -E "was not given|listening"
```
Expected: the new `-l was not given, binding the ipv4 wildcard address` line appears, followed by the normal control/data listening lines. Then confirm the IPv6 path still needs no guess:

```bash
timeout 3 ./speederv2 -s --port-range-mode --control-port 25040 \
    --data-port-range 25050-25051 -l"[::]:0" -r "[::1]:25041" -k v6 --log-level 4 2>&1 \
    | grep -E "was not given|listening"
```
Expected: the `was not given` line does **not** appear, and the listening lines do.

- [ ] **Step 3: Run the suites**

Run:
```bash
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
./speederv2 --test-selftest | tail -2
bash tests/smoke_port_range.sh 2>&1 | tail -3
```
Expected: no warning/error output; `0 failures`; `=== PASSED ===`.

- [ ] **Step 4: Commit**

```bash
git add tunnel_server.cpp
git commit -m "port-range: derive the server bind family from -l, and say when it cannot

Without -l there is no address to derive a family from, so the ipv4
default stays for compatibility -- but it is now announced. This is the
only place the program guesses an address family, and a wrong guess is
invisible: the client simply cannot connect, which is what a firewall
drop and a key mismatch also look like.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: Test-mode prober socket

**Files:**
- Modify: `test_mode_net.cpp:1304-1310`

**Interfaces:**
- Consumes: `address_t::wildcard_like` (Task 1), the three-argument `new_listen_socket2` (Task 2).
- Produces: nothing new.

The test-mode **responder needs no change** — it binds `local_addr` and derives its data ports with `set_port()`, so its family already follows `-l`. It was measured listening correctly on `[::1]:25030` while the prober could not reach it. Do not modify it.

- [ ] **Step 1: Replace the prober's socket construction**

In `test_mode_net.cpp`, replace lines 1304-1310:

```c
    // The family comes from -r, the peer this prober is measuring against.
    // --out-addr / --out-interface are honoured because the point of test mode
    // is to measure the path the tunnel will actually use: if the tunnel is
    // pinned to an interface and the probe goes out the default route, the
    // report describes a different link than the one being configured.
    address_t bind_addr;
    if (out_addr) {
        bind_addr = *out_addr;
    } else {
        bind_addr.wildcard_like(remote_addr.get_type(), 0);
    }
    if (new_listen_socket2(g_pr.fd, bind_addr, out_interface) != 0) {
        mylog(log_fatal, "test: failed to create prober socket\n");
        myexit(-1);
    }
```

`test_mode_net.cpp` already includes `misc.h`, which declares `out_addr` and `out_interface`; no new include is needed.

- [ ] **Step 2: Verify test mode over IPv6**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
./speederv2 -s --test-mode -l"[::1]:25030" -k v6 --log-level 4 > /tmp/tm6s.log 2>&1 &
sleep 1
./speederv2 -c --test-mode -r"[::1]:25030" -k v6 --test-duration 1 --test-pps 20 \
    --log-level 4 > /tmp/tm6c.log 2>&1
grep -E "responder reachable|no response" /tmp/tm6c.log
grep -c "server -> client" /tmp/tm6c.log
kill %1 2>/dev/null
```
Expected after your change: `responder reachable`, and the report contains a `server -> client` section.

For the "before" half, `git stash` your `test_mode_net.cpp` edit, rebuild, and re-run — the prober should print `no response from [::1]:25030` (measured during design) — then `git stash pop` and rebuild. **Paste both outputs in your report.**

- [ ] **Step 3: Run the suites**

Run:
```bash
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
./speederv2 --test-selftest | tail -2
bash tests/smoke_test_mode.sh
```
Expected: no warning/error output; `0 failures`; `=== PASSED ===`. Run the smoke script in the foreground; it takes ~6 minutes.

- [ ] **Step 4: Commit**

```bash
git add test_mode_net.cpp
git commit -m "test-mode: derive the prober socket family from -r

The prober built its socket from a hardcoded \"0.0.0.0:0\", so it could
not reach an ipv6 responder -- it reported the same 'no response' as a
firewalled port. The responder was never broken; it derives its family
from -l already.

The prober also now honours --out-addr / --out-interface: test mode
exists to measure the path the tunnel will use, and a probe leaving by a
different route describes a different link.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Startup validation for `--out-addr`

**Files:**
- Modify: `misc.cpp` (in `process_arg`, after the existing `port-range-mode validation` block that ends around line 1076)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: nothing new.

- [ ] **Step 1: Add the validation**

In `misc.cpp`, immediately after the closing brace of the `// port-range-mode validation` block:

```c
    // --out-addr must be in the same family as the peer we will be talking to.
    // Without this the mismatch surfaces as a bind() failure whose message
    // ("socket bind error=...") names neither option, leaving the operator no
    // way to see which two arguments conflict.
    if (out_addr != 0) {
        address_t *peer = 0;
        const char *peer_opt = 0;
        if (program_mode == client_mode && port_range_mode) {
            // Data destinations are derived from ctrl_addr, not remote_addr.
            peer = &ctrl_addr;
            peer_opt = "--control-host";
        } else if (working_mode == test_working_mode && program_mode == server_mode) {
            // The test responder opens no outbound socket, so --out-addr is
            // inert for it and there is nothing to compare against.
            peer = 0;
        } else {
            peer = &remote_addr;
            peer_opt = "-r";
        }

        if (peer != 0 && peer->is_vaild() && out_addr->get_type() != peer->get_type()) {
            // get_str() returns a single static buffer, so two calls in one
            // argument list would print the same address twice -- in the very
            // message whose job is to show the operator both sides.
            char out_buf[max_addr_len];
            char peer_buf[max_addr_len];
            out_addr->to_str(out_buf);
            peer->to_str(peer_buf);
            mylog(log_fatal,
                  "--out-addr %s and %s %s are different address families.\n"
                  "       both must be ipv4, or both ipv6.\n",
                  out_buf, peer_opt, peer_buf);
            myexit(-1);
        }

        if (port_range_mode && program_mode == client_mode && out_addr->get_port() != 0) {
            mylog(log_fatal,
                  "--out-addr must use port 0 in --port-range-mode.\n"
                  "       the client opens two outbound sockets (data and control), and\n"
                  "       binding both to port %u would fail with EADDRINUSE.\n",
                  out_addr->get_port());
            myexit(-1);
        }
    }
```

- [ ] **Step 2: Verify both refusals fire, with readable messages**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"

# family mismatch — must name BOTH addresses, and they must differ
./speederv2 -c --port-range-mode --control-host "[::1]:4096" -l 0.0.0.0:3333 \
    -r "[::1]:4096" -k v6 --out-addr 1.2.3.4:0 2>&1 | grep -A1 "different address families"

# non-zero out-addr port in port-range mode
./speederv2 -c --port-range-mode --control-host "[::1]:4096" -l 0.0.0.0:3333 \
    -r "[::1]:4096" -k v6 --out-addr "[::1]:5555" 2>&1 | grep -A2 "must use port 0"

# a matching pair must NOT be refused (guards against a validator that always fires)
./speederv2 -c --port-range-mode --control-host "[::1]:4096" -l"[::1]:3333" \
    -r "[::1]:4096" -k v6 --out-addr "[::1]:0" --log-level 4 2>&1 | grep -ci "different address families"
```
Expected: the first prints the fatal naming **two different addresses** — confirm `1.2.3.4:0` and `[::1]:4096` both appear, which is the `get_str()` static-buffer trap the code avoids. The second prints the port refusal. The third prints `0`.

- [ ] **Step 3: Run the suites**

Run:
```bash
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
./speederv2 --test-selftest | tail -2
bash tests/smoke.sh 2>&1 | tail -3
bash tests/smoke_port_range.sh 2>&1 | tail -3
```
Expected: no warning/error output; `0 failures`; both print `=== PASSED ===`.

- [ ] **Step 4: Commit**

```bash
git add misc.cpp
git commit -m "args: refuse --out-addr that cannot work, at startup

A family mismatch used to surface as 'socket bind error=...' at bind
time, naming neither of the two options that actually conflict. It is now
refused at startup with both addresses printed -- via to_str() into
separate buffers, since get_str() returns one static buffer and two calls
in one argument list print the same address twice.

A non-zero --out-addr port is also refused in port-range mode: the client
opens two outbound sockets and binding both to a fixed port fails with
EADDRINUSE.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: IPv6 regression suite

The base tunnel has worked over IPv6 all along, with no test and no documentation. That is precisely why two later features could break it unnoticed, and why the symptom was indistinguishable from a firewall drop. **This regression guard is arguably worth more than the fixes.**

**Files:**
- Modify: `tests/udp_echo.py`
- Create: `tests/smoke_ipv6.sh`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the fixes from Tasks 2, 3 and 4.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Make the echo helper family-aware**

Replace `tests/udp_echo.py` entirely:

```python
#!/usr/bin/env python3
"""Minimal UDP echo server. Prefixes every reply with b'ECHO:' so the
client can distinguish echoed packets from stray traffic.

Usage:
    udp_echo.py <port>              # legacy form, binds 127.0.0.1
    udp_echo.py <bind_addr> <port>  # family is derived from bind_addr
"""
import socket
import sys

def main():
    if len(sys.argv) >= 3:
        host, port = sys.argv[1], int(sys.argv[2])
    else:
        host = "127.0.0.1"
        port = int(sys.argv[1]) if len(sys.argv) > 1 else 7777

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((host, port))
    while True:
        data, addr = s.recvfrom(65536)
        s.sendto(b"ECHO:" + data, addr)

if __name__ == "__main__":
    main()
```

The single-argument form is kept working so `tests/smoke.sh:45` needs no change. (The spec anticipated updating that call site; keeping the old form valid is strictly less disruptive and achieves the same thing.)

- [ ] **Step 2: Write the IPv6 suite**

Create `tests/smoke_ipv6.sh`:

```bash
#!/usr/bin/env bash
# smoke_ipv6.sh — IPv6 regression suite, all rounds over ::1
#
# Round 1: base tunnel. THIS IS THE REGRESSION GUARD. The base tunnel has
#          supported ipv6 all along, with no test and no docs -- which is
#          exactly why two later features broke it unnoticed, and why the
#          symptom looked like a firewall drop.
# Round 2: port-range mode over ipv6.
# Round 3: test mode over ipv6 (prober reaches responder, report renders).
#
# Usage: bash tests/smoke_ipv6.sh [/path/to/speederv2]
# Exit 0 on pass or on a loud skip; non-zero on failure.

set -euo pipefail

BINARY="${1:-./speederv2}"
PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: binary not found or not executable: $BINARY"
    exit 1
fi

# A silently-skipped test is worse than no test: it makes a green CI lie.
# Say plainly that the ipv6 rounds did not run.
if ! "$PYTHON" - <<'PYEOF' 2>/dev/null
import socket, sys
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("::1", 0))
except OSError:
    sys.exit(1)
PYEOF
then
    echo "SKIP: ipv6 loopback (::1) is unavailable on this host."
    echo "      the ipv6 rounds did NOT run. this is a skip, not a pass."
    exit 0
fi

BASE_PORT=$(( (RANDOM % 20000) + 34000 ))
ECHO_PORT=$BASE_PORT
CLIENT_PORT=$(( BASE_PORT + 1 ))
TUNNEL_PORT=$(( BASE_PORT + 2 ))
CTRL_PORT=$(( BASE_PORT + 3 ))
DATA_LO=$(( BASE_PORT + 10 ))
DATA_HI=$(( BASE_PORT + 13 ))
TEST_PORT=$(( BASE_PORT + 20 ))
KEY="smoke_ipv6_$$"

PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

stop_all() {
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    PIDS=()
    sleep 0.3
}

send_and_count() {
    local port="$1" total="$2"
    "$PYTHON" - "$port" "$total" <<'PYEOF'
import socket, sys, time
port, total = int(sys.argv[1]), int(sys.argv[2])
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.settimeout(4.0)
ok = 0
for i in range(total):
    msg = b"pkt%04d" % i
    s.sendto(msg, ("::1", port))
    try:
        data, _ = s.recvfrom(65536)
        if data == b"ECHO:" + msg:
            ok += 1
    except socket.timeout:
        pass
print(ok)
PYEOF
}

echo "=== UDPspeeder IPv6 smoke test ==="
echo "  binary : $BINARY"
echo "  base   : $BASE_PORT"
echo

echo "Round 1: base tunnel over ::1 (regression guard, expect 100/100)"
"$PYTHON" "$SCRIPT_DIR/udp_echo.py" "::1" "$ECHO_PORT" & PIDS+=($!)
sleep 0.5
"$BINARY" -s -l"[::1]:$TUNNEL_PORT" -r "[::1]:$ECHO_PORT" -f20:10 -k "$KEY" \
    >/dev/null 2>&1 & PIDS+=($!)
"$BINARY" -c -l"[::1]:$CLIENT_PORT" -r "[::1]:$TUNNEL_PORT" -f20:10 -k "$KEY" \
    >/dev/null 2>&1 & PIDS+=($!)
sleep 1.5
OK=$(send_and_count "$CLIENT_PORT" 100)
stop_all
echo "  [base-v6] delivered $OK/100"
if [[ "$OK" -lt 100 ]]; then echo "  FAIL: expected 100"; exit 1; fi
echo "  [base-v6] ok"
echo

echo "Round 2: port-range mode over ::1 (expect >=95/100)"
"$PYTHON" "$SCRIPT_DIR/udp_echo.py" "::1" "$ECHO_PORT" & PIDS+=($!)
sleep 0.5
"$BINARY" -s --port-range-mode --control-port "$CTRL_PORT" \
    --data-port-range "$DATA_LO-$DATA_HI" -l"[::1]:0" -r "[::1]:$ECHO_PORT" \
    -f20:10 -k "$KEY" >/dev/null 2>&1 & PIDS+=($!)
sleep 1
"$BINARY" -c --port-range-mode --control-host "[::1]:$CTRL_PORT" \
    --data-port-range "$DATA_LO-$DATA_HI" -l"[::1]:$CLIENT_PORT" \
    -r "[::1]:$CTRL_PORT" -f20:10 -k "$KEY" >/dev/null 2>&1 & PIDS+=($!)
sleep 2.5
OK=$(send_and_count "$CLIENT_PORT" 100)
stop_all
echo "  [port-range-v6] delivered $OK/100"
if [[ "$OK" -lt 95 ]]; then echo "  FAIL: expected at least 95"; exit 1; fi
echo "  [port-range-v6] ok"
echo

echo "Round 3: test mode over ::1"
"$BINARY" -s --test-mode -l"[::1]:$TEST_PORT" -k "$KEY" --log-level 4 \
    > /tmp/smoke_ipv6_resp.$$ 2>&1 & PIDS+=($!)
sleep 1
"$BINARY" -c --test-mode -r"[::1]:$TEST_PORT" -k "$KEY" \
    --test-duration 1 --test-pps 20 > /tmp/smoke_ipv6_prober.$$ 2>&1
stop_all
if grep -q "no response from" /tmp/smoke_ipv6_prober.$$; then
    echo "  FAIL: prober could not reach the responder over ipv6"
    rm -f /tmp/smoke_ipv6_resp.$$ /tmp/smoke_ipv6_prober.$$
    exit 1
fi
if ! grep -q "client -> server, 单端口" /tmp/smoke_ipv6_prober.$$; then
    echo "  FAIL: no report section rendered"
    sed -n '1,40p' /tmp/smoke_ipv6_prober.$$
    rm -f /tmp/smoke_ipv6_resp.$$ /tmp/smoke_ipv6_prober.$$
    exit 1
fi
rm -f /tmp/smoke_ipv6_resp.$$ /tmp/smoke_ipv6_prober.$$
echo "  [test-mode-v6] ok"
echo

echo "=== PASSED ==="
```

- [ ] **Step 3: Prove every round can fail**

A round that passes on both correct and broken code is worse than no round. For each, break the target, capture the failure, then restore:

- **Round 1:** temporarily change its `-r "[::1]:$ECHO_PORT"` to a port nothing listens on → must FAIL on delivery count.
- **Round 2:** `git stash` the `tunnel_client.cpp` change from Task 2, rebuild → must FAIL (this is the exact pre-fix state, measured at 0/30 during design).
- **Round 3:** `git stash` the `test_mode_net.cpp` change from Task 4, rebuild → must FAIL with `no response from`.

Record each failing output in your report, then restore and show the suite green.

- [ ] **Step 4: Wire it into CI**

In `.github/workflows/ci.yml`, after the existing `Smoke test` step:

```yaml
      - name: IPv6 smoke test
        run: bash tests/smoke_ipv6.sh ./speederv2
        timeout-minutes: 3
```

- [ ] **Step 5: Run everything**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
bash tests/smoke_ipv6.sh
bash tests/smoke.sh 2>&1 | tail -3
bash tests/smoke_port_range.sh 2>&1 | tail -3
```
Expected: no warning/error output; all print `=== PASSED ===`. `smoke.sh` must still pass unchanged, which confirms the single-argument `udp_echo.py` form still works.

- [ ] **Step 6: Commit**

```bash
git add tests/udp_echo.py tests/smoke_ipv6.sh .github/workflows/ci.yml
git commit -m "tests: ipv6 regression suite

Round 1 guards the base tunnel, which has supported ipv6 all along with
no test and no docs -- which is exactly why two later features could break
it unnoticed, and why the symptom was indistinguishable from a firewall
drop. Rounds 2 and 3 cover the two paths this branch fixes.

A missing ::1 produces a loud SKIP rather than a silent pass: a test that
quietly stops running makes a green CI lie.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: Documentation

**Files:**
- Modify: `README.md`
- Modify: `main.cpp` (help text)

**Interfaces:**
- Consumes: everything above. Produces: no code symbols.

- [ ] **Step 1: Add the README section**

Add a top-level `### IPv6` section to `README.md`, placed after the basic usage section and before Port-Range Mode. Use this text:

```markdown
### IPv6

UDPspeeder speaks IPv6 everywhere it speaks IPv4. Write IPv6 addresses in
brackets, the same way you would in a URL:

```bash
# server
./speederv2 -s -l"[::]:4096" -r "[::1]:7777" -f20:10 -k "passwd"

# client
./speederv2 -c -l"[::1]:3333" -r "[2001:db8::1]:4096" -f20:10 -k "passwd"
```

> **AMENDED 2026-08-02, post-review.** The two paragraphs originally mandated
> here — "Each instance is **single-family** … one instance cannot serve IPv4
> and IPv6 clients at the same time" — were **false**, and were shipped to
> `README.md` verbatim because this step prescribed them. Both halves were
> disproven by running the binary:
>
> - `-l` and `-r` families are fully independent on both roles; nothing in the
>   code compares them. A v4 local socket with a v6 tunnel socket delivered 20/20.
> - `IPV6_V6ONLY` is never set anywhere in the tree, so a `[::]` listener
>   accepts IPv4 clients as v4-mapped on a default Linux host. Verified 20/20,
>   logged as `new connection from [::ffff:127.0.0.1]:53372`.
>
> The corrected text below replaces it. See the amendment in spec §1 for the
> ruling that `IPV6_V6ONLY` must **not** be set to make the original claim true.

Each socket takes its family from the argument that describes it, and the
sockets are **independent of each other**. An instance is not locked to one
family: a client may listen for its application on IPv4 while carrying the
tunnel over IPv6, and a server may accept an IPv6 tunnel while forwarding to
an IPv4 application.

The one pair that is **not** independent is the tunnel-facing pair — a
client's `-r` and the server's `-l` — because those are the two ends of one
socket conversation.

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

**A `[::]` listener also accepts IPv4 clients**, as v4-mapped addresses, since
`IPV6_V6ONLY` is never set. Binding `[::]` does not exclude IPv4.

**Port-range server without `-l`.** `-l` is optional for a port-range server,
and without it there is nothing to derive a family from, so it binds the IPv4
wildcard address `0.0.0.0` and says so in its log. Pass `-l"[::]:0"` to listen
on IPv6 instead.

**`--out-addr` must match.** Its address family has to match the peer's, or
startup is refused with both addresses printed. In port-range mode its port
must be `0`: the client opens two outbound sockets, and binding both to a fixed
port would fail with `EADDRINUSE`.
```

- [ ] **Step 2: Update the help text**

In `main.cpp`, in the options where an address is accepted, note the bracket form. Change the `--out-addr` line to:

```c
    printf("    --out-addr            ip:port         force all output packets of '-r' end to go through this address, port 0 for random port.\n");
    printf("                                          for ipv6 use bracket form, e.g. [::1]:0. must be the same address family as the peer.\n");
    printf("                                          the port must be 0 wherever more than one outbound socket is opened: on a server (one\n");
    printf("                                          per connected client), and on a --port-range-mode client (data + control).\n");
```

and add one line to the usage block near the top of `print_help`, after the two `run as` lines:

```c
    printf("    ipv6 addresses use bracket form everywhere an address is accepted, e.g. -l\"[::]:4096\" -r\"[2001:db8::1]:4096\"\n");
```

- [ ] **Step 3: Verify the help renders**

Run: `make clean >/dev/null && make >/dev/null 2>&1 && ./speederv2 --help | grep -A2 "out-addr"; ./speederv2 --help | grep -i "bracket"`
Expected: the new lines appear, and their description column lines up with the surrounding options (compare against `--out-interface` immediately below).

- [ ] **Step 4: Final verification**

Run:
```bash
make clean >/dev/null && make 2>&1 | grep -Ei "warning|error"
make clean >/dev/null && make debug 2>&1 | grep -Ei "warning|error"
make clean >/dev/null && make
./speederv2 --test-selftest | tail -2
bash tests/smoke.sh 2>&1 | tail -3
bash tests/smoke_port_range.sh 2>&1 | tail -3
bash tests/smoke_ipv6.sh 2>&1 | tail -3
bash tests/smoke_test_mode.sh 2>&1 | tail -3
git status --short          # git_version.h must NOT be staged
```
Expected: no warning/error output from either build; `0 failures`; all four smoke scripts print `=== PASSED ===`.

- [ ] **Step 5: Commit**

```bash
git add README.md main.cpp
git commit -m "docs: document ipv6

The bracket syntax has been supported since address_t was written and was
never written down anywhere, which is part of why nobody noticed when two
features stopped honouring it. Records the per-side family derivation --
including that a port-range client takes its family from --control-host
rather than -r -- and that a [::] listener still accepts v4-mapped clients.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Traceability

| Spec section | Task |
|---|---|
| §0 根因(三处站点) | 2, 3, 4 |
| §1 范围:不做双栈 | 7 (documented as a limit) |
| §1 范围:服务端省略 `-l` 不改默认 | 3 |
| §2.1 `wildcard_like` | 1 |
| §2.2 未连接路径补 `out_interface` | 2 |
| §2.3 三个调用点收敛成同一形状 | 2, 3, 4 |
| §3.1 客户端真相源是 `--control-host` | 2 (code comment), 7 (README table) |
| §3.2 responder 不需改动 | 4 (stated as a do-not-touch) |
| §3.3 服务端省略 `-l` 时主动声明 | 3 |
| §4 `--out-addr` / `--out-interface` 语义 | 2 (client), 4 (prober) |
| §4.1 族不匹配启动时拦截 | 5 |
| §4.2 port-range 下端口须为 0 | 5 |
| §5.1 selftest | 1 |
| §5.2 `smoke_ipv6.sh` + `udp_echo.py` | 6 |
| §5.3 显式跳过且跳过要吵 | 6 |
| §5.4 CI 接线 | 6 |
| §6 文档 | 7 |
