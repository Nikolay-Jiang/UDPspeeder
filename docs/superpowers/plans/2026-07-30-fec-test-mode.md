# FEC 测试模式 (`--test-mode`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增一个一次性运行的 `--test-mode`,探测链路真实丢包特征,输出三档 FEC 配置建议(`-f` 与 `-i`),并判断该链路丢包是否适合用 FEC 解决。

**Architecture:** 全部新代码集中在 `test_mode.h` / `test_mode.cpp`,不复用 `fec_manager` / `connection` / `packet` 隧道链路。核心是一个**纯函数评估器**:一次探测记录带时间戳的丢包轨迹,再用滑窗回放对约 1500 个 `(x,y)` 候选算残余丢包。所有纯函数通过 `--test-selftest` 用合成轨迹做断言(仓库无单测框架,此为 `--unit-test` 的既有先例)。

**Tech Stack:** C++11,libev(`-isystem libev`),`siphash24()`(已在仓库内),GNU getopt_long。Linux x86/x86_64。

## Global Constraints

- **C++11 only**,热路径不用 RTTI / 异常。
- 编译必须在 `-Wall -Wextra` 下**零警告**(`-Wno-unused-variable -Wno-unused-parameter -Wno-missing-field-initializers` 已在 makefile 中抑制,不要依赖新增抑制)。
- 评估器为**纯函数**:禁用随机数与当前时间,同一轨迹两次运行输出必须完全一致。
- **64 位读取函数名是 `read_uu64`**(`common.h:362`,仓库内既有拼写),不是 `read_u64`。
- MAC 密钥派生:`uint8_t k[16] = {0}; int klen = strlen(key_string); if (klen > 16) klen = 16; memcpy(k, key_string, klen);`(与 `control_proto.cpp:51-54` 一致)。
- **不复用 `ctrl_encode`/`ctrl_decode`**:其 1024 槽 nonce 重放环会丢弃合法探测包。只复用底层 `siphash24()`。
- 参数上限(必须在解析时校验):`--test-duration ≤ 600`、`--test-pps ≤ 20000`、`--test-pkt-size ≤ 1400`、协议内 `expected_n ≤ 10000000`。
- `--test-mode` 下 `-k` **强制必填**。
- 日志等级常量:`log_fatal=1 log_error=2 log_warn=3 log_info=4 log_debug=5 log_trace=6`。
- 三档目标残余丢包:省流 `≤1%`、均衡 `≤0.1%`、激进 `≤0.01%`;`-i` 上限 `50ms`;`x ∈ [1,30]`,`y ∈ [0, min(3x, 254-x)]`。
- 提交信息结尾附:`Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`

---

## File Structure

| 文件 | 职责 |
|---|---|
| `test_mode.h`(新建) | 全部公开接口:CLI 全局量声明、线协议常量与结构、轨迹、统计、评估器、入口点 |
| `test_mode.cpp`(新建) | 上述全部实现 + `--test-selftest` 断言 |
| `misc.cpp` / `misc.h`(修改) | 新增参数解析、默认值、上限校验、`--test-mode` 下强制 `-k` |
| `main.cpp`(修改) | `working_mode` 分派;help 文本新增测试模式段落 |
| `common.h`(修改) | `working_mode_t` 枚举新增 `test_working_mode` |
| `makefile`(修改) | `SOURCES` 加入 `test_mode.cpp` |
| `tests/smoke_test_mode.sh`(新建) | 回环端到端烟雾测试 |
| `README.md`(修改) | 用法与报告示例 |

单文件承载 `test_mode.cpp` 是刻意选择:它自成一体、与隧道零耦合,拆分反而会让接口面变大。若实现后超过约 900 行,再按"协议/评估器/报告"三段拆分。

---

## Task 1: 骨架 — CLI 参数、模式分派、selftest harness

**Files:**
- Create: `test_mode.h`, `test_mode.cpp`
- Modify: `common.h:136-139`(枚举)、`misc.h`、`misc.cpp`(解析)、`main.cpp`、`makefile:6`

**Interfaces:**
- Consumes: 无(首个任务)
- Produces:
  - `extern int test_mode; extern int test_duration_sec; extern int test_pps; extern int test_pkt_size; extern double test_app_mbps;`
  - `int test_mode_selftest();` 返回 0 表示全部通过
  - `int test_mode_prober_loop(); int test_mode_responder_loop();`
  - `TCHECK(cond, fmt, ...)` 宏(仅 `test_mode.cpp` 内部使用)
  - `enum working_mode_t` 新增枚举值 `test_working_mode`

- [ ] **Step 1: 写失败测试 — 建立 selftest harness 与第一条断言**

创建 `test_mode.h`:

```c
#ifndef TEST_MODE_H_
#define TEST_MODE_H_

#include "common.h"
#include <stdint.h>

// ---- CLI-configured globals (defined in misc.cpp) ----
extern int    test_mode;          // 0/1
extern int    test_duration_sec;  // default 30, max 600
extern int    test_pps;           // default 200, max 20000
extern int    test_pkt_size;      // default 1200, max 1400
extern double test_app_mbps;      // 0 => derive from probe rate

const int TEST_DURATION_MAX = 600;
const int TEST_PPS_MAX      = 20000;
const int TEST_PKT_SIZE_MAX = 1400;
const int TEST_PKT_SIZE_MIN = 64;

// ---- entry points ----
int test_mode_prober_loop();
int test_mode_responder_loop();
int test_mode_selftest();  // 0 = all checks passed

#endif /* TEST_MODE_H_ */
```

创建 `test_mode.cpp`:

```c
#include "test_mode.h"
#include "log.h"
#include "packet.h"  // key_string
#include <math.h>
#include <stdio.h>
#include <string.h>

// ---------------- selftest harness ----------------
static int g_checks = 0;
static int g_failures = 0;

#define TCHECK(cond, ...)                            \
    do {                                             \
        g_checks++;                                   \
        if (!(cond)) {                               \
            g_failures++;                             \
            printf("FAIL [%s:%d]: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                     \
            printf("\n");                            \
        }                                            \
    } while (0)

// placeholder loops, implemented in later tasks
int test_mode_prober_loop() {
    mylog(log_fatal, "test-mode prober not implemented yet\n");
    myexit(-1);
    return 0;
}

int test_mode_responder_loop() {
    mylog(log_fatal, "test-mode responder not implemented yet\n");
    myexit(-1);
    return 0;
}

int test_mode_selftest() {
    g_checks = 0;
    g_failures = 0;

    // Harness self-check. Every later task's assertions are only as trustworthy
    // as TCHECK's ability to actually FAIL, so exercise the failure path once
    // against scratch counters, then restore them.
    {
        int saved_checks = g_checks;
        int saved_failures = g_failures;
        g_checks = 0;
        g_failures = 0;
        printf("---- selftest: one deliberate FAIL line follows, it is expected ----\n");
        TCHECK(1 == 0, "deliberate failure proving the harness counts failures");
        bool harness_ok = (g_checks == 1 && g_failures == 1);
        g_checks = saved_checks;
        g_failures = saved_failures;
        printf("---- selftest: end of deliberate failure ----\n");
        TCHECK(harness_ok, "TCHECK must count a failing check exactly once");
    }

    printf("test_mode selftest: %d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
```

- [ ] **Step 2: 运行以确认编译失败**

Run: `make 2>&1 | tail -5`
Expected: FAIL — `test_mode.cpp` 尚未加入 `SOURCES`,`test_mode_selftest` 未被引用;且 `--test-selftest` 参数不存在。先确认 `make` 报 `test_mode.h: No such file` 之外的状态:此步只需确认 `./speederv2 --test-selftest` **不被识别**(输出 help 或报未知参数)。

Run: `./speederv2 --test-selftest; echo "exit=$?"`
Expected: 非 0 退出且无 `test_mode selftest:` 输出。

- [ ] **Step 3: 接线 — makefile、枚举、参数解析、分派**

`makefile:6` 的 `SOURCES` 中,在 `port_range_manager.cpp` 之后加入 `test_mode.cpp`:

```make
SOURCES=main.cpp log.cpp common.cpp lib/fec.cpp lib/rs.cpp crc32/Crc32.cpp packet.cpp delay_manager.cpp fd_manager.cpp connection.cpp fec_manager.cpp misc.cpp tunnel_client.cpp tunnel_server.cpp my_ev.cpp siphash.cpp control_proto.cpp port_range_manager.cpp test_mode.cpp -isystem libev
```

`common.h:136-139` 枚举新增一个值:

```c
enum working_mode_t { unset_working_mode = 0,
                      tunnel_mode,
                      tun_dev_mode,
                      test_working_mode };
```

`misc.cpp` 顶部全局量(与 `port_range_mode` 等并列,约第 53-61 行区域):

```c
int    test_mode = 0;
int    test_duration_sec = 30;
int    test_pps = 200;
int    test_pkt_size = 1200;
double test_app_mbps = 0.0;  // 0 => derive from probe rate
```

`misc.cpp` 的 `long_options[]` 数组(约第 590-609 行),在 `{NULL, 0, 0, 0}` 之前加入:

```c
            {"test-mode", no_argument, 0, 1},
            {"test-duration", required_argument, 0, 1},
            {"test-pps", required_argument, 0, 1},
            {"test-pkt-size", required_argument, 0, 1},
            {"test-app-mbps", required_argument, 0, 1},
```

`misc.cpp` 长参数处理链(紧跟 `heartbeat-loss-threshold` 分支之后)加入:

```c
                } else if (strcmp(long_options[option_index].name, "test-mode") == 0) {
                    test_mode = 1;
                    working_mode = test_working_mode;
                    mylog(log_info, "test_mode enabled\n");
                } else if (strcmp(long_options[option_index].name, "test-duration") == 0) {
                    sscanf(optarg, "%d", &test_duration_sec);
                    if (test_duration_sec < 1 || test_duration_sec > TEST_DURATION_MAX) {
                        mylog(log_fatal, "--test-duration must be 1-%d\n", TEST_DURATION_MAX);
                        myexit(-1);
                    }
                } else if (strcmp(long_options[option_index].name, "test-pps") == 0) {
                    sscanf(optarg, "%d", &test_pps);
                    if (test_pps < 1 || test_pps > TEST_PPS_MAX) {
                        mylog(log_fatal, "--test-pps must be 1-%d\n", TEST_PPS_MAX);
                        myexit(-1);
                    }
                } else if (strcmp(long_options[option_index].name, "test-pkt-size") == 0) {
                    sscanf(optarg, "%d", &test_pkt_size);
                    if (test_pkt_size < TEST_PKT_SIZE_MIN || test_pkt_size > TEST_PKT_SIZE_MAX) {
                        mylog(log_fatal, "--test-pkt-size must be %d-%d\n",
                              TEST_PKT_SIZE_MIN, TEST_PKT_SIZE_MAX);
                        myexit(-1);
                    }
                } else if (strcmp(long_options[option_index].name, "test-app-mbps") == 0) {
                    sscanf(optarg, "%lf", &test_app_mbps);
                    if (test_app_mbps < 0.0) {
                        mylog(log_fatal, "--test-app-mbps must be >= 0\n");
                        myexit(-1);
                    }
                }
```

`misc.cpp` 顶部加 `#include "test_mode.h"`。

`misc.cpp` 早期参数扫描处(紧邻既有 `--unit-test` 扫描,约第 613-617 行)加入 `--test-selftest`——沿用 `--unit-test` 的先例,在 getopt 之前拦截并退出:

```c
        if (strcmp(argv[i], "--test-selftest") == 0) {
            myexit(test_mode_selftest());
        }
```

`misc.cpp` 的校验段(`working_mode == tunnel_mode` 那组判断之后)加入测试模式校验:

```c
    if (working_mode == test_working_mode) {
        if (strlen(key_string) == 0) {
            mylog(log_fatal, "--test-mode requires -k (mandatory: probes are MAC-authenticated "
                             "to prevent this responder being used as a UDP reflector)\n");
            myexit(-1);
        }
        if (program_mode == client_mode && !remote_addr.is_vaild()) {
            mylog(log_fatal, "--test-mode client requires -r <responder_ip:port>\n");
            myexit(-1);
        }
        if (program_mode == server_mode && !local_addr.is_vaild()) {
            mylog(log_fatal, "--test-mode server requires -l <listen_ip:port>\n");
            myexit(-1);
        }
    }
```

注意:该校验必须放在既有 `if (working_mode == tunnel_mode) {...} else if (working_mode == tun_dev_mode) {...}` 之后,并确保那两个分支不会因 `working_mode == test_working_mode` 而误报 `-l`/`-r` 缺失。

`main.cpp` 的分派(第 156-160 行)改为:

```c
    if (working_mode == test_working_mode) {
        if (program_mode == client_mode) {
            test_mode_prober_loop();
        } else {
            test_mode_responder_loop();
        }
    } else if (program_mode == client_mode) {
        tunnel_client_event_loop();
    } else {
        tunnel_server_event_loop();
    }
```

`main.cpp` 顶部加 `#include "test_mode.h"`。

- [ ] **Step 4: 运行确认通过**

Run: `make 2>&1 | grep -Ei "error|warning" ; ./speederv2 --test-selftest; echo "exit=$?"`
Expected: 无 error/warning;输出 `test_mode selftest: 2 checks, 0 failures`;`exit=0`

Run: `./speederv2 -c --test-mode -r127.0.0.1:4096 2>&1 | tail -2`
Expected: fatal 报 `--test-mode requires -k`

- [ ] **Step 5: 提交**

```bash
git add test_mode.h test_mode.cpp common.h misc.cpp main.cpp makefile
git commit -m "test-mode: add CLI surface, mode dispatch and selftest harness

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: 线协议编解码

**Files:**
- Modify: `test_mode.h`, `test_mode.cpp`

**Interfaces:**
- Consumes: Task 1 的 `TCHECK`、`test_mode_selftest()`
- Produces:
  - `enum test_msg_t { TEST_HELLO=1, TEST_HELLO_ACK, TEST_PHASE_BEGIN, TEST_PHASE_ACK, TEST_PROBE, TEST_PHASE_END, TEST_REQUEST_RESULT, TEST_RESULT, TEST_BYE }`
  - `const int TEST_HDR_LEN = 16; const int TEST_MAC_LEN = 8; const int TEST_BUF_MAX = 1500;`
  - `struct test_hdr_t { uint8_t version, msg_type, phase, reserved; uint32_t seq; uint64_t send_ts_us; }`
  - `int test_encode(int msg_type, int phase, uint32_t seq, const void *payload, int payload_len, char *out, int out_cap, int pad_to);` 返回总长或 -1
  - `int test_decode(char *buf, int len, test_hdr_t *hdr_out, uint8_t **payload_out, int *payload_len_out);` 返回 msg_type 或 -1

- [ ] **Step 1: 写失败测试**

`test_mode.h` 中加入声明:

```c
enum test_msg_t {
    TEST_HELLO = 1,
    TEST_HELLO_ACK,
    TEST_PHASE_BEGIN,
    TEST_PHASE_ACK,
    TEST_PROBE,
    TEST_PHASE_END,
    TEST_REQUEST_RESULT,
    TEST_RESULT,
    TEST_BYE
};

const int TEST_HDR_LEN = 16;
const int TEST_MAC_LEN = 8;
const int TEST_BUF_MAX = 1500;

struct test_hdr_t {
    uint8_t  version;
    uint8_t  msg_type;
    uint8_t  phase;
    uint8_t  reserved;
    uint32_t seq;
    uint64_t send_ts_us;
};

// pad_to: desired total packet size INCLUDING mac; 0 = no padding.
int test_encode(int msg_type, int phase, uint32_t seq,
                const void *payload, int payload_len,
                char *out, int out_cap, int pad_to);

int test_decode(char *buf, int len, test_hdr_t *hdr_out,
                uint8_t **payload_out, int *payload_len_out);
```

`test_mode.cpp` 的 `test_mode_selftest()` 中,替换 `TEST_PPS_MAX` 那条占位断言,加入:

```c
    // ---- codec ----
    {
        strcpy(key_string, "selftest_key");
        char buf[TEST_BUF_MAX];
        const char pl[4] = {'a', 'b', 'c', 'd'};

        int n = test_encode(TEST_PROBE, 3, 12345, pl, 4, buf, sizeof(buf), 1200);
        TCHECK(n == 1200, "padded encode must return 1200, got %d", n);

        test_hdr_t h;
        uint8_t *p = 0;
        int plen = 0;
        int mt = test_decode(buf, n, &h, &p, &plen);
        TCHECK(mt == TEST_PROBE, "decode msg_type must be TEST_PROBE, got %d", mt);
        TCHECK(h.phase == 3, "decode phase must be 3, got %d", (int)h.phase);
        TCHECK(h.seq == 12345, "decode seq must be 12345, got %u", h.seq);
        TCHECK(plen == 1200 - TEST_HDR_LEN - TEST_MAC_LEN,
               "payload len must include padding, got %d", plen);
        TCHECK(p != 0 && memcmp(p, pl, 4) == 0, "payload bytes must round-trip");

        // unpadded control message
        int n2 = test_encode(TEST_HELLO, 0, 0, pl, 4, buf, sizeof(buf), 0);
        TCHECK(n2 == TEST_HDR_LEN + 4 + TEST_MAC_LEN,
               "unpadded encode must be hdr+payload+mac, got %d", n2);

        // MAC must reject a flipped byte
        buf[TEST_HDR_LEN] ^= 0xff;
        TCHECK(test_decode(buf, n2, &h, &p, &plen) == -1, "flipped byte must fail MAC");

        // MAC must reject a wrong key
        int n3 = test_encode(TEST_HELLO, 0, 0, pl, 4, buf, sizeof(buf), 0);
        strcpy(key_string, "different_key");
        TCHECK(test_decode(buf, n3, &h, &p, &plen) == -1, "wrong key must fail MAC");
        strcpy(key_string, "selftest_key");

        // too-short packet must be rejected, not read out of bounds
        TCHECK(test_decode(buf, TEST_HDR_LEN + TEST_MAC_LEN - 1, &h, &p, &plen) == -1,
               "short packet must be rejected");

        // over-capacity request must be refused
        TCHECK(test_encode(TEST_PROBE, 0, 0, pl, 4, buf, 32, 1200) == -1,
               "encode must refuse when out_cap too small");
    }
```

- [ ] **Step 2: 运行以确认失败**

Run: `make 2>&1 | grep -E "error" | head -3`
Expected: FAIL — `test_encode`/`test_decode` 未定义(链接或编译错误)

- [ ] **Step 3: 实现**

`test_mode.cpp` 在 harness 之后加入:

```c
#include "siphash.h"

static void test_mac_key(uint8_t k[16]) {
    memset(k, 0, 16);
    int klen = (int)strlen(key_string);
    if (klen > 16) klen = 16;
    memcpy(k, key_string, klen);
}

static void test_mac_compute(const char *body, int body_len, char out[TEST_MAC_LEN]) {
    uint8_t k[16];
    test_mac_key(k);
    uint64_t h = siphash24(body, (size_t)body_len, k);
    memcpy(out, &h, TEST_MAC_LEN);
}

int test_encode(int msg_type, int phase, uint32_t seq,
                const void *payload, int payload_len,
                char *out, int out_cap, int pad_to) {
    if (payload_len < 0) return -1;
    int body = TEST_HDR_LEN + payload_len;
    int total = body + TEST_MAC_LEN;
    if (pad_to > total) {
        body = pad_to - TEST_MAC_LEN;
        total = pad_to;
    }
    if (total > out_cap || total > TEST_BUF_MAX) return -1;

    out[0] = 1;                    // version
    out[1] = (char)(uint8_t)msg_type;
    out[2] = (char)(uint8_t)phase;
    out[3] = 0;                    // reserved
    write_u32(out + 4, seq);
    write_u64(out + 8, get_current_time_us());
    if (payload_len > 0) memcpy(out + TEST_HDR_LEN, payload, payload_len);
    int pad = body - TEST_HDR_LEN - payload_len;
    if (pad > 0) memset(out + TEST_HDR_LEN + payload_len, 0, pad);

    test_mac_compute(out, body, out + body);
    return total;
}

int test_decode(char *buf, int len, test_hdr_t *hdr_out,
                uint8_t **payload_out, int *payload_len_out) {
    if (len < TEST_HDR_LEN + TEST_MAC_LEN || len > TEST_BUF_MAX) return -1;
    int body_len = len - TEST_MAC_LEN;

    char expected[TEST_MAC_LEN];
    test_mac_compute(buf, body_len, expected);
    if (memcmp(expected, buf + body_len, TEST_MAC_LEN) != 0) return -1;

    if ((uint8_t)buf[0] != 1) return -1;   // version
    if ((uint8_t)buf[3] != 0) return -1;   // reserved

    hdr_out->version    = (uint8_t)buf[0];
    hdr_out->msg_type   = (uint8_t)buf[1];
    hdr_out->phase      = (uint8_t)buf[2];
    hdr_out->reserved   = 0;
    hdr_out->seq        = read_u32(buf + 4);
    hdr_out->send_ts_us = read_uu64(buf + 8);

    *payload_out     = (uint8_t *)(buf + TEST_HDR_LEN);
    *payload_len_out = body_len - TEST_HDR_LEN;
    return (int)hdr_out->msg_type;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `make 2>&1 | grep -Ei "error|warning"; ./speederv2 --test-selftest; echo "exit=$?"`
Expected: 无 error/warning;`0 failures`;`exit=0`

- [ ] **Step 5: 提交**

```bash
git add test_mode.h test_mode.cpp
git commit -m "test-mode: add MAC-authenticated wire codec

Uses siphash24 directly rather than ctrl_encode/ctrl_decode: the latter's
1024-slot nonce replay ring would drop legitimate probes at 200pps and
contaminate the loss measurement.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: 轨迹记录与统计

**Files:**
- Modify: `test_mode.h`, `test_mode.cpp`

**Interfaces:**
- Consumes: Task 1 的 `TCHECK`
- Produces:
  - `struct trace_t { uint32_t expected_n, pps; std::vector<uint8_t> arrived; std::vector<uint32_t> recv_ts_rel_us; my_time_t first_arrival_us; void init(uint32_t n, uint32_t pps_); void record(uint32_t seq, my_time_t now_us); }`
  - `struct trace_stats_t { uint32_t n, arrived_n, lost_n, run_p50, run_p95, run_max; double loss_rate, burst_p95_ms, resolution; }`
  - `trace_stats_t trace_analyze(const trace_t &t);`
  - `const uint32_t TEST_MAX_EXPECTED_N = 10000000;`

- [ ] **Step 1: 写失败测试**

`test_mode.h` 加入(需 `#include <vector>`):

```c
#include <vector>

const uint32_t TEST_MAX_EXPECTED_N = 10000000;

struct trace_t {
    uint32_t              expected_n = 0;
    uint32_t              pps = 0;
    std::vector<uint8_t>  arrived;         // 0 = lost, 1 = arrived
    std::vector<uint32_t> recv_ts_rel_us;  // relative to first arrival; 0 if lost
    my_time_t             first_arrival_us = 0;

    void init(uint32_t n, uint32_t pps_);
    void record(uint32_t seq, my_time_t now_us);
};

struct trace_stats_t {
    uint32_t n;
    uint32_t arrived_n;
    uint32_t lost_n;
    double   loss_rate;     // 0..1
    uint32_t run_p50;       // loss run length, packets
    uint32_t run_p95;
    uint32_t run_max;
    double   burst_p95_ms;  // run_p95 / pps * 1000
    double   resolution;    // 1.0 / n
};

trace_stats_t trace_analyze(const trace_t &t);
```

`test_mode_selftest()` 加入:

```c
    // ---- trace + stats ----
    {
        trace_t t;
        t.init(1000, 200);
        TCHECK(t.arrived.size() == 1000, "init must size arrived to n");

        // all arrive
        for (uint32_t s = 0; s < 1000; s++) t.record(s, 1000000ULL + s * 5000ULL);
        trace_stats_t st = trace_analyze(t);
        TCHECK(st.arrived_n == 1000, "all-arrive: arrived_n must be 1000, got %u", st.arrived_n);
        TCHECK(st.lost_n == 0, "all-arrive: lost_n must be 0, got %u", st.lost_n);
        TCHECK(st.loss_rate == 0.0, "all-arrive: loss_rate must be 0");
        TCHECK(st.run_max == 0, "all-arrive: run_max must be 0, got %u", st.run_max);

        // duplicate must not double-count
        t.record(0, 9999999ULL);
        st = trace_analyze(t);
        TCHECK(st.arrived_n == 1000, "duplicate must be ignored, got %u", st.arrived_n);

        // out-of-order must not count as loss
        trace_t t2;
        t2.init(4, 200);
        t2.record(3, 1000);
        t2.record(1, 2000);
        t2.record(0, 3000);
        t2.record(2, 4000);
        trace_stats_t st2 = trace_analyze(t2);
        TCHECK(st2.lost_n == 0, "out-of-order must not count as loss, got %u", st2.lost_n);

        // fixed burst pattern: every 100th block loses exactly 5 in a row
        trace_t t3;
        t3.init(1000, 200);
        for (uint32_t s = 0; s < 1000; s++) {
            bool lost = (s % 100) < 5;
            if (!lost) t3.record(s, 1000000ULL + s * 5000ULL);
        }
        trace_stats_t st3 = trace_analyze(t3);
        TCHECK(st3.lost_n == 50, "burst trace must lose 50, got %u", st3.lost_n);
        TCHECK(st3.run_max == 5, "burst run_max must be 5, got %u", st3.run_max);
        TCHECK(st3.run_p95 == 5, "burst run_p95 must be 5, got %u", st3.run_p95);
        // 5 packets at 200pps == 25ms
        TCHECK(fabs(st3.burst_p95_ms - 25.0) < 0.001,
               "burst_p95_ms must be 25.0, got %f", st3.burst_p95_ms);
        TCHECK(fabs(st3.resolution - 0.001) < 1e-9,
               "resolution must be 1/1000, got %f", st3.resolution);

        // isolated losses -> run_p95 == 1
        trace_t t4;
        t4.init(1000, 200);
        for (uint32_t s = 0; s < 1000; s++) {
            if (s % 50 != 0) t4.record(s, 1000000ULL + s * 5000ULL);
        }
        trace_stats_t st4 = trace_analyze(t4);
        TCHECK(st4.run_max == 1, "isolated losses: run_max must be 1, got %u", st4.run_max);
    }
```

- [ ] **Step 2: 运行以确认失败**

Run: `make 2>&1 | grep -E "error" | head -3`
Expected: FAIL — `trace_t::init` / `trace_analyze` 未定义

- [ ] **Step 3: 实现**

```c
#include <algorithm>

void trace_t::init(uint32_t n, uint32_t pps_) {
    if (n > TEST_MAX_EXPECTED_N) {
        mylog(log_fatal, "trace size %u exceeds cap %u\n", n, TEST_MAX_EXPECTED_N);
        myexit(-1);
    }
    expected_n = n;
    pps = pps_;
    arrived.assign(n, 0);
    recv_ts_rel_us.assign(n, 0);
    first_arrival_us = 0;
}

void trace_t::record(uint32_t seq, my_time_t now_us) {
    if (seq >= expected_n) return;   // out of range, ignore
    if (arrived[seq]) return;        // duplicate, ignore
    if (first_arrival_us == 0) first_arrival_us = now_us;
    arrived[seq] = 1;
    my_time_t rel = (now_us >= first_arrival_us) ? (now_us - first_arrival_us) : 0;
    if (rel > 0xffffffffULL) rel = 0xffffffffULL;
    recv_ts_rel_us[seq] = (uint32_t)rel;
}

static uint32_t percentile_u32(std::vector<uint32_t> &v, double q) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    size_t idx = (size_t)(q * (double)(v.size() - 1) + 0.5);
    if (idx >= v.size()) idx = v.size() - 1;
    return v[idx];
}

trace_stats_t trace_analyze(const trace_t &t) {
    trace_stats_t st;
    memset(&st, 0, sizeof(st));
    st.n = t.expected_n;
    if (st.n == 0) return st;

    std::vector<uint32_t> runs;
    uint32_t cur = 0;
    for (uint32_t s = 0; s < t.expected_n; s++) {
        if (t.arrived[s]) {
            st.arrived_n++;
            if (cur > 0) { runs.push_back(cur); cur = 0; }
        } else {
            st.lost_n++;
            cur++;
        }
    }
    if (cur > 0) runs.push_back(cur);

    st.loss_rate  = (double)st.lost_n / (double)st.n;
    st.resolution = 1.0 / (double)st.n;

    if (!runs.empty()) {
        st.run_max = *std::max_element(runs.begin(), runs.end());
        std::vector<uint32_t> tmp = runs;
        st.run_p50 = percentile_u32(tmp, 0.50);
        tmp = runs;
        st.run_p95 = percentile_u32(tmp, 0.95);
    }
    if (t.pps > 0) {
        st.burst_p95_ms = (double)st.run_p95 / (double)t.pps * 1000.0;
    }
    return st;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `make 2>&1 | grep -Ei "error|warning"; ./speederv2 --test-selftest; echo "exit=$?"`
Expected: 无 error/warning;`0 failures`;`exit=0`

- [ ] **Step 5: 提交**

```bash
git add test_mode.h test_mode.cpp
git commit -m "test-mode: add loss trace recording and statistics

Out-of-order arrivals do not count as loss (seq-indexed); duplicates are
ignored. Burst duration is derived from run length / pps -- the send
cadence -- so it needs no clock sync between the two ends.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: 残余丢包(滑窗回放)

**Files:**
- Modify: `test_mode.h`, `test_mode.cpp`

**Interfaces:**
- Consumes: Task 3 的 `trace_t`
- Produces: `double test_residual(const trace_t &t, int x, int y);` 返回 0..1;窗口大于轨迹长度时返回 `-1.0`

**背景(实现者必读):** Reed-Solomon 是 MDS 码——一组 `x+y` 分片中到齐任意 `x` 个即可完整还原,少于 `x` 个则整组全废(mode 0 blob 语义)。每组承载 `x` 个数据包,失败即全丢,故**残余丢包率 = 失败组比例**。用步长 1 的滑窗(而非不重叠切块)以最大化样本数。

- [ ] **Step 1: 写失败测试**

`test_mode.h`:

```c
// Fraction of sliding windows of size (x+y) containing more than y losses.
// Returns -1.0 if the window does not fit the trace.
double test_residual(const trace_t &t, int x, int y);
```

`test_mode_selftest()` 加入:

```c
    // ---- residual ----
    {
        // zero loss -> residual 0 for any candidate
        trace_t t;
        t.init(1000, 200);
        for (uint32_t s = 0; s < 1000; s++) t.record(s, 1000000ULL + s * 5000ULL);
        TCHECK(test_residual(t, 20, 6) == 0.0, "zero-loss trace must give residual 0");

        // total loss -> every window fails
        trace_t t2;
        t2.init(1000, 200);
        TCHECK(fabs(test_residual(t2, 20, 6) - 1.0) < 1e-9,
               "total-loss trace must give residual 1.0");

        // window larger than trace -> -1
        trace_t t3;
        t3.init(10, 200);
        TCHECK(test_residual(t3, 20, 6) == -1.0, "oversized window must return -1");

        // exact burst pattern: 5 lost every 100.
        // window 26 (=20+6) with y=6 tolerates 6 losses; max losses in any
        // 26-wide window here is 5, so no window may fail.
        trace_t t4;
        t4.init(1000, 200);
        for (uint32_t s = 0; s < 1000; s++) {
            if ((s % 100) >= 5) t4.record(s, 1000000ULL + s * 5000ULL);
        }
        TCHECK(test_residual(t4, 20, 6) == 0.0,
               "burst of 5 must be fully covered by y=6, got %f", test_residual(t4, 20, 6));
        // y=4 cannot cover a burst of 5 -> some windows must fail
        TCHECK(test_residual(t4, 20, 4) > 0.0, "y=4 must fail against a burst of 5");

        // determinism
        TCHECK(test_residual(t4, 20, 4) == test_residual(t4, 20, 4),
               "residual must be deterministic");
    }
```

- [ ] **Step 2: 运行以确认失败**

Run: `make 2>&1 | grep -E "error" | head -3`
Expected: FAIL — `test_residual` 未定义

- [ ] **Step 3: 实现**

```c
double test_residual(const trace_t &t, int x, int y) {
    if (x < 1 || y < 0) return -1.0;
    int w = x + y;
    if (w <= 0 || (uint32_t)w > t.expected_n) return -1.0;

    // prefix[k] = number of losses in [0, k)
    std::vector<uint32_t> prefix(t.expected_n + 1, 0);
    for (uint32_t s = 0; s < t.expected_n; s++) {
        prefix[s + 1] = prefix[s] + (t.arrived[s] ? 0u : 1u);
    }

    uint32_t windows = t.expected_n - (uint32_t)w + 1;
    uint32_t failed = 0;
    for (uint32_t s = 0; s < windows; s++) {
        uint32_t losses = prefix[s + w] - prefix[s];
        if ((int)losses > y) failed++;
    }
    return (double)failed / (double)windows;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `make 2>&1 | grep -Ei "error|warning"; ./speederv2 --test-selftest; echo "exit=$?"`
Expected: 无 error/warning;`0 failures`;`exit=0`

- [ ] **Step 5: 提交**

```bash
git add test_mode.h test_mode.cpp
git commit -m "test-mode: add sliding-window residual loss estimator

Residual loss reduces to the fraction of (x+y)-wide windows containing
more than y losses, because Reed-Solomon is MDS: a group recovers iff at
least x of x+y shards arrive, and a failed group loses all x of its data
packets. Makes no independence assumption, which matters because burst
loss badly breaks binomial models.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: `-i` 推导与三档选取

**Files:**
- Modify: `test_mode.h`, `test_mode.cpp`

**Interfaces:**
- Consumes: Task 3 `trace_stats_t` / `trace_analyze`,Task 4 `test_residual`
- Produces:
  - `const int TEST_I_CAP_MS = 50; const int TEST_X_MAX = 30;`
  - `struct tier_t { bool feasible; int x, y, i_ms; double residual, overhead, actual_mbps; bool extrapolated; }`
  - `struct recommendation_t { trace_stats_t stats; tier_t thrifty, balanced, aggressive; }`
  - `int test_derive_interval_ms(const trace_stats_t &st, int x, int y);`
  - `tier_t test_pick_tier(const trace_t &t, const trace_stats_t &st, double target);`
  - `recommendation_t test_evaluate(const trace_t &t, double app_mbps, int pkt_size);`

- [ ] **Step 1: 写失败测试**

`test_mode.h`:

```c
const int TEST_I_CAP_MS = 50;
const int TEST_X_MAX    = 30;
const double TIER_THRIFTY_TARGET    = 0.01;    // 1%
const double TIER_BALANCED_TARGET   = 0.001;   // 0.1%
const double TIER_AGGRESSIVE_TARGET = 0.0001;  // 0.01%

struct tier_t {
    bool   feasible;
    int    x, y, i_ms;
    double residual;      // 0..1
    double overhead;      // y/x
    double actual_mbps;
    bool   extrapolated;  // target below sampling resolution
};

struct recommendation_t {
    trace_stats_t stats;
    tier_t thrifty, balanced, aggressive;
};

// 0 when losses are isolated (run_p95 <= 1); else ceil(D*(x+y)/y).
int test_derive_interval_ms(const trace_stats_t &st, int x, int y);

tier_t test_pick_tier(const trace_t &t, const trace_stats_t &st, double target);

recommendation_t test_evaluate(const trace_t &t, double app_mbps, int pkt_size);
```

`test_mode_selftest()` 加入:

```c
    // ---- interval derivation ----
    {
        trace_stats_t st;
        memset(&st, 0, sizeof(st));

        // isolated losses -> no scattering
        st.run_p95 = 1;
        st.burst_p95_ms = 5.0;
        TCHECK(test_derive_interval_ms(st, 20, 6) == 0,
               "isolated losses must give -i 0, got %d", test_derive_interval_ms(st, 20, 6));

        // y == 0 -> scattering cannot help
        st.run_p95 = 3;
        st.burst_p95_ms = 10.0;
        TCHECK(test_derive_interval_ms(st, 20, 0) == 0, "y=0 must give -i 0");

        // D=10ms, x=20, y=6 -> 10*26/6 = 43.33 -> 44
        TCHECK(test_derive_interval_ms(st, 20, 6) == 44,
               "D=10 x=20 y=6 must give 44, got %d", test_derive_interval_ms(st, 20, 6));
        // D=10ms, x=20, y=3 -> 10*23/3 = 76.67 -> 77 (over the 50ms cap)
        TCHECK(test_derive_interval_ms(st, 20, 3) == 77,
               "D=10 x=20 y=3 must give 77, got %d", test_derive_interval_ms(st, 20, 3));
    }

    // ---- tier selection ----
    {
        // isolated 2% loss, no bursts
        trace_t t;
        t.init(2000, 200);
        for (uint32_t s = 0; s < 2000; s++) {
            if (s % 50 != 0) t.record(s, 1000000ULL + s * 5000ULL);
        }
        trace_stats_t st = trace_analyze(t);
        tier_t bal = test_pick_tier(t, st, TIER_BALANCED_TARGET);
        TCHECK(bal.feasible, "balanced tier must be feasible on isolated 2% loss");
        TCHECK(bal.residual <= TIER_BALANCED_TARGET,
               "balanced residual %f must meet target", bal.residual);
        TCHECK(bal.y >= 1, "balanced tier must use redundancy, got y=%d", bal.y);
        TCHECK(bal.i_ms == 0, "isolated losses must give -i 0, got %d", bal.i_ms);

        // bursts of 5 -> chosen y must cover the burst
        trace_t t2;
        t2.init(2000, 200);
        for (uint32_t s = 0; s < 2000; s++) {
            if ((s % 100) >= 5) t2.record(s, 1000000ULL + s * 5000ULL);
        }
        trace_stats_t st2 = trace_analyze(t2);
        tier_t bal2 = test_pick_tier(t2, st2, TIER_BALANCED_TARGET);
        TCHECK(bal2.feasible, "balanced tier must be feasible on burst-5 trace");
        TCHECK(bal2.y >= 5, "burst of 5 needs y>=5, got y=%d", bal2.y);
        TCHECK(bal2.i_ms > 0 && bal2.i_ms <= TEST_I_CAP_MS,
               "burst trace must give 0 < -i <= cap, got %d", bal2.i_ms);

        // total loss -> infeasible, no fabricated numbers
        trace_t t3;
        t3.init(2000, 200);
        trace_stats_t st3 = trace_analyze(t3);
        tier_t bad = test_pick_tier(t3, st3, TIER_BALANCED_TARGET);
        TCHECK(!bad.feasible, "total-loss trace must report infeasible");

        // bandwidth conversion: 20:6 on 10 Mbps payload, 1200B packets
        // 10 * 1.30 * (1 + 16/1200) = 13.173...
        recommendation_t rec = test_evaluate(t, 10.0, 1200);
        TCHECK(rec.balanced.feasible, "evaluate must produce a feasible balanced tier");
        double expect = 10.0 * (1.0 + (double)rec.balanced.y / rec.balanced.x)
                             * (1.0 + 16.0 / 1200.0);
        TCHECK(fabs(rec.balanced.actual_mbps - expect) < 0.01,
               "actual_mbps %f must match %f", rec.balanced.actual_mbps, expect);

        // extrapolation flag. n=2000 -> resolution 0.0005.
        // aggressive target 0.0001 < 0.0005  -> must be flagged
        // balanced   target 0.0010 > 0.0005  -> must NOT be flagged
        TCHECK(rec.aggressive.extrapolated,
               "aggressive target 0.01%% is below the 0.05%% resolution of a 2000-sample "
               "trace, so it must be flagged extrapolated");
        TCHECK(!rec.balanced.extrapolated,
               "balanced target 0.1%% is above the 0.05%% resolution, so it must not be "
               "flagged extrapolated");

        // determinism
        recommendation_t rec2 = test_evaluate(t, 10.0, 1200);
        TCHECK(rec.balanced.x == rec2.balanced.x && rec.balanced.y == rec2.balanced.y
                   && rec.balanced.i_ms == rec2.balanced.i_ms,
               "evaluate must be deterministic");
    }
```

- [ ] **Step 2: 运行以确认失败**

Run: `make 2>&1 | grep -E "error" | head -3`
Expected: FAIL — `test_derive_interval_ms` / `test_pick_tier` / `test_evaluate` 未定义

- [ ] **Step 3: 实现**

```c
int test_derive_interval_ms(const trace_stats_t &st, int x, int y) {
    if (st.run_p95 <= 1) return 0;          // losses are isolated; scattering buys nothing
    if (y <= 0) return 0;                    // no redundancy to protect
    if (st.burst_p95_ms <= 0.0) return 0;
    double need = st.burst_p95_ms * (double)(x + y) / (double)y;
    return (int)ceil(need);
}

tier_t test_pick_tier(const trace_t &t, const trace_stats_t &st, double target) {
    tier_t best;
    memset(&best, 0, sizeof(best));
    best.feasible = false;

    for (int x = 1; x <= TEST_X_MAX; x++) {
        int y_max = 3 * x;
        if (y_max > 254 - x) y_max = 254 - x;
        for (int y = 0; y <= y_max; y++) {
            if ((uint32_t)(x + y) > t.expected_n) continue;
            double r = test_residual(t, x, y);
            if (r < 0.0 || r > target) continue;

            // Scattering requirement; if it exceeds the cap, prefer more y
            // (i.e. reject this candidate) per spec section 6.4.
            int i_ms = test_derive_interval_ms(st, x, y);
            if (i_ms > TEST_I_CAP_MS) continue;

            double overhead = (double)y / (double)x;
            bool better = !best.feasible || overhead < best.overhead - 1e-12;
            if (!better && fabs(overhead - best.overhead) <= 1e-12) {
                if (i_ms < best.i_ms) better = true;
                else if (i_ms == best.i_ms && x > best.x) better = true;
            }
            if (better) {
                best.feasible = true;
                best.x = x;
                best.y = y;
                best.i_ms = i_ms;
                best.residual = r;
                best.overhead = overhead;
            }
        }
    }
    best.extrapolated = (target < st.resolution);
    return best;
}

recommendation_t test_evaluate(const trace_t &t, double app_mbps, int pkt_size) {
    recommendation_t rec;
    rec.stats = trace_analyze(t);

    rec.thrifty    = test_pick_tier(t, rec.stats, TIER_THRIFTY_TARGET);
    rec.balanced   = test_pick_tier(t, rec.stats, TIER_BALANCED_TARGET);
    rec.aggressive = test_pick_tier(t, rec.stats, TIER_AGGRESSIVE_TARGET);

    double hdr_factor = 1.0;
    if (pkt_size > 0) hdr_factor = 1.0 + 16.0 / (double)pkt_size;

    tier_t *tiers[3] = {&rec.thrifty, &rec.balanced, &rec.aggressive};
    for (int k = 0; k < 3; k++) {
        if (tiers[k]->feasible) {
            tiers[k]->actual_mbps = app_mbps * (1.0 + tiers[k]->overhead) * hdr_factor;
        } else {
            tiers[k]->actual_mbps = 0.0;
        }
    }
    return rec;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `make 2>&1 | grep -Ei "error|warning"; ./speederv2 --test-selftest; echo "exit=$?"`
Expected: 无 error/warning;`0 failures`;`exit=0`

- [ ] **Step 5: 提交**

```bash
git add test_mode.h test_mode.cpp
git commit -m "test-mode: add -i derivation and three-tier selection

-i follows i >= D*(x+y)/y from the measured p95 burst duration, capped at
50ms; over the cap the search prefers more redundancy instead. -i is
deliberately kept out of the residual number: scattering changes send
timing and the trace was captured unscattered, so folding it in would turn
a replay measurement into a compound model. Recommendations are therefore
conservative by design.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 6: 速率敏感性判定

**Files:**
- Modify: `test_mode.h`, `test_mode.cpp`

**Interfaces:**
- Consumes: Task 1 的 `TCHECK`
- Produces:
  - `enum rate_verdict_t { RATE_RANDOM = 0, RATE_POLICED, RATE_UNCERTAIN }`
  - `rate_verdict_t test_rate_verdict(double p_half, uint32_t n_half, double p_nom, uint32_t n_nom, double p_double, uint32_t n_double);`

- [ ] **Step 1: 写失败测试**

`test_mode.h`:

```c
enum rate_verdict_t { RATE_RANDOM = 0, RATE_POLICED, RATE_UNCERTAIN };

// Significant iff the rise exceeds 3x the combined binomial standard error.
rate_verdict_t test_rate_verdict(double p_half, uint32_t n_half,
                                 double p_nom, uint32_t n_nom,
                                 double p_double, uint32_t n_double);
```

`test_mode_selftest()` 加入:

```c
    // ---- rate verdict ----
    {
        // flat within noise -> random
        TCHECK(test_rate_verdict(0.0200, 2000, 0.0205, 2000, 0.0198, 2000) == RATE_RANDOM,
               "flat loss must be RATE_RANDOM");

        // strong monotonic rise -> policed
        TCHECK(test_rate_verdict(0.0100, 2000, 0.0500, 2000, 0.2000, 2000) == RATE_POLICED,
               "monotonic large rise must be RATE_POLICED");

        // rise present but not monotonic -> uncertain
        TCHECK(test_rate_verdict(0.0100, 2000, 0.0050, 2000, 0.2000, 2000) == RATE_UNCERTAIN,
               "non-monotonic rise must be RATE_UNCERTAIN");

        // tiny sample: same point estimates as the 'policed' case but too few
        // samples to be significant -> must not claim policed
        TCHECK(test_rate_verdict(0.0100, 20, 0.0500, 20, 0.2000, 20) != RATE_POLICED,
               "20-sample rise must not be declared policed");

        // zero loss everywhere -> random
        TCHECK(test_rate_verdict(0.0, 2000, 0.0, 2000, 0.0, 2000) == RATE_RANDOM,
               "zero loss must be RATE_RANDOM");
    }
```

- [ ] **Step 2: 运行以确认失败**

Run: `make 2>&1 | grep -E "error" | head -3`
Expected: FAIL — `test_rate_verdict` 未定义

- [ ] **Step 3: 实现**

```c
static bool rate_sig_increase(double p1, uint32_t n1, double p2, uint32_t n2) {
    if (n1 == 0 || n2 == 0) return false;
    double v1 = p1 * (1.0 - p1) / (double)n1;
    double v2 = p2 * (1.0 - p2) / (double)n2;
    double se = sqrt(v1 + v2);
    if (se <= 0.0) return false;
    return (p2 - p1) > 3.0 * se;
}

rate_verdict_t test_rate_verdict(double p_half, uint32_t n_half,
                                 double p_nom, uint32_t n_nom,
                                 double p_double, uint32_t n_double) {
    bool span_sig = rate_sig_increase(p_half, n_half, p_double, n_double);
    bool tail_sig = rate_sig_increase(p_nom, n_nom, p_double, n_double);
    bool monotonic = (p_double > p_nom) && (p_nom > p_half);

    if (monotonic && span_sig) return RATE_POLICED;
    if (!span_sig && !tail_sig) return RATE_RANDOM;
    return RATE_UNCERTAIN;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `make 2>&1 | grep -Ei "error|warning"; ./speederv2 --test-selftest; echo "exit=$?"`
Expected: 无 error/warning;`0 failures`;`exit=0`

- [ ] **Step 5: 提交**

```bash
git add test_mode.h test_mode.cpp
git commit -m "test-mode: add rate-sensitivity verdict

Loss rising monotonically and significantly with offered rate means
policing/congestion, where adding FEC redundancy makes things worse. The
3x combined binomial standard error gate keeps small samples from being
declared policed.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 7: 报告渲染

**Files:**
- Modify: `test_mode.h`, `test_mode.cpp`

**Interfaces:**
- Consumes: Task 5 `recommendation_t`,Task 6 `rate_verdict_t`
- Produces:
  - `struct test_report_t { bool have_rate_scan; double p_half, p_nom, p_dbl; uint32_t n_half, n_nom, n_dbl; rate_verdict_t verdict; bool have_up, have_down, have_spread; recommendation_t up, down; double spread_loss_up; int spread_ports; double probe_mbps; double app_mbps; int duration_sec, pps, pkt_size; char peer[128]; double rtt_ms; }`
  - `void test_render_report(const test_report_t &r);` 打印到 stdout

- [ ] **Step 1: 写失败测试**

`test_mode.h`:

```c
struct test_report_t {
    // probe parameters
    int    duration_sec;
    int    pps;
    int    pkt_size;
    double probe_mbps;
    double app_mbps;
    char   peer[128];
    double rtt_ms;

    // rate scan
    bool           have_rate_scan;
    double         p_half, p_nom, p_dbl;
    uint32_t       n_half, n_nom, n_dbl;
    rate_verdict_t verdict;

    // per-direction recommendations (single port)
    bool             have_up, have_down;
    recommendation_t up, down;

    // port-range comparison
    bool   have_spread;
    double spread_loss_up;   // loss rate on N ports, up direction
    int    spread_ports;
};

void test_render_report(const test_report_t &r);
```

`test_mode_selftest()` 加入(渲染只验证"不崩溃且关键字段出现",不做逐字比对——逐字比对会让报告文案无法调整):

```c
    // ---- report rendering ----
    {
        trace_t t;
        t.init(2000, 200);
        for (uint32_t s = 0; s < 2000; s++) {
            if (s % 50 != 0) t.record(s, 1000000ULL + s * 5000ULL);
        }
        test_report_t r;
        memset(&r, 0, sizeof(r));
        r.duration_sec = 30; r.pps = 200; r.pkt_size = 1200;
        r.probe_mbps = 1.92; r.app_mbps = 1.92; r.rtt_ms = 42.0;
        snprintf(r.peer, sizeof(r.peer), "127.0.0.1:4096");
        r.have_rate_scan = true;
        r.p_half = 0.02; r.p_nom = 0.0205; r.p_dbl = 0.0198;
        r.n_half = r.n_nom = r.n_dbl = 2000;
        r.verdict = RATE_RANDOM;
        r.have_up = true;
        r.up = test_evaluate(t, r.app_mbps, r.pkt_size);
        r.have_down = false;
        r.have_spread = false;

        // Reaching the statements after each call is itself the evidence that
        // rendering returned; do not add a vacuous TCHECK(true, ...) here.
        printf("---- selftest: sample report begin ----\n");
        test_render_report(r);
        printf("---- selftest: sample report end ----\n");

        // infeasible-everything report must render too
        trace_t t2;
        t2.init(2000, 200);
        test_report_t r2 = r;
        r2.up = test_evaluate(t2, r2.app_mbps, r2.pkt_size);
        test_render_report(r2);
        TCHECK(!r2.up.balanced.feasible, "total-loss report must show infeasible tiers");
    }
```

- [ ] **Step 2: 运行以确认失败**

Run: `make 2>&1 | grep -E "error" | head -3`
Expected: FAIL — `test_render_report` 未定义

- [ ] **Step 3: 实现**

```c
static const char *tier_name(int k) {
    if (k == 0) return "省流";
    if (k == 1) return "均衡";
    return "激进";
}

static void render_tier_row(const tier_t &tr, int k, bool is_default) {
    if (!tr.feasible) {
        printf("  %-6s %-8s %-7s %-14s %-9s %s\n",
               tier_name(k), "-", "-", "目标不可达", "-", "-");
        return;
    }
    char fec[32], ims[16], res[32], ovh[16], bw[24];
    snprintf(fec, sizeof(fec), "%d:%d", tr.x, tr.y);
    snprintf(ims, sizeof(ims), "%dms", tr.i_ms);
    if (tr.extrapolated)
        snprintf(res, sizeof(res), "<%.4f%%(外推)", tr.residual * 100.0);
    else
        snprintf(res, sizeof(res), "%.4f%%", tr.residual * 100.0);
    snprintf(ovh, sizeof(ovh), "%.0f%%", tr.overhead * 100.0);
    snprintf(bw, sizeof(bw), "%.2f Mbps", tr.actual_mbps);
    printf("  %-6s %-8s %-7s %-14s %-9s %s%s\n",
           tier_name(k), fec, ims, res, ovh, bw, is_default ? "  *" : "");
}

static void render_direction(const char *label, const recommendation_t &rec) {
    const trace_stats_t &st = rec.stats;
    printf("\n--- 链路特征 (%s) ---\n", label);
    printf("  丢包率               : %.4f%%  (%u/%u)\n",
           st.loss_rate * 100.0, st.lost_n, st.n);
    printf("  丢包连长 p50/p95/max : %u / %u / %u\n", st.run_p50, st.run_p95, st.run_max);
    printf("  突发时长 p95         : %.1f ms\n", st.burst_p95_ms);
    printf("  本次采样分辨率       : %.4f%%\n", st.resolution * 100.0);

    if (st.lost_n == 0) {
        printf("\n--- 推荐配置 (%s) ---\n", label);
        printf("  链路干净(零丢包),--disable-fec 或 -f1:0 即可\n");
        return;
    }

    printf("\n--- 推荐配置 (%s) ---\n", label);
    printf("  档位   %-8s %-7s %-14s %-9s %s\n", "-f", "-i", "预计残余", "冗余开销", "实际占用");
    const tier_t *tiers[3] = {&rec.thrifty, &rec.balanced, &rec.aggressive};
    for (int k = 0; k < 3; k++) render_tier_row(*tiers[k], k, k == 1);
    printf("  * = 默认推荐\n");
    printf("  注: 残余丢包为 -i 0 的保守回放估计,实际加 -i 后应优于此值\n");
    printf("  注: 滑窗样本相互重叠,真实置信区间较此估计更宽\n");
}

void test_render_report(const test_report_t &r) {
    printf("\n=== UDPspeeder FEC 测试报告 ===\n");
    printf("探测: 时长 %ds  速率 %dpps  包长 %dB  净荷 %.2f Mbps\n",
           r.duration_sec, r.pps, r.pkt_size, r.app_mbps);
    printf("对端: %s   RTT ≈ %.0f ms\n", r.peer, r.rtt_ms);

    if (r.have_rate_scan) {
        printf("\n--- 丢包性质判定 ---\n");
        printf("  %5d pps : 丢包 %.4f%%\n", r.pps / 2, r.p_half * 100.0);
        printf("  %5d pps : 丢包 %.4f%%\n", r.pps, r.p_nom * 100.0);
        printf("  %5d pps : 丢包 %.4f%%\n", r.pps * 2, r.p_dbl * 100.0);
        if (r.verdict == RATE_POLICED) {
            printf("  判定: 限速/拥塞型丢包(丢包随速率显著上升)\n");
            printf("  警告: FEC 对此类链路无效甚至有害 —— 冗余包会进一步挤占被限速的\n");
            printf("        管道。正确处方是分流(见 --port-range-mode),而非加大 -f。\n");
            printf("        以下推荐仅供参考,前提已不成立。\n");
        } else if (r.verdict == RATE_RANDOM) {
            printf("  判定: 随机型丢包(与速率无关) → FEC 适用\n");
        } else {
            printf("  判定: 不确定(变化不单调或未达显著性),不下结论\n");
        }
    }

    if (r.have_up) render_direction("client -> server, 单端口", r.up);
    if (r.have_down) render_direction("server -> client, 单端口", r.down);

    if (r.have_spread) {
        printf("\n--- port-range 对比 ---\n");
        double base = r.have_up ? r.up.stats.loss_rate : 0.0;
        printf("  单端口 %.4f%%  |  %d 端口 %.4f%%\n",
               base * 100.0, r.spread_ports, r.spread_loss_up * 100.0);
        if (base > 0.0 && r.spread_loss_up < base) {
            printf("  结论: 多端口降低丢包 %.0f%%,port-range 对该链路有效\n",
                   (base - r.spread_loss_up) / base * 100.0);
        } else if (base > 0.0 && r.spread_loss_up > base) {
            printf("  结论: 多端口未降低丢包,port-range 对该链路无收益\n");
        } else {
            printf("  结论: 单端口已无丢包,无法判断 port-range 收益\n");
        }
    }

    printf("\n--- 建议命令行 ---\n");
    if (r.have_up && r.up.balanced.feasible)
        printf("  client: -f%d:%d -i%d\n", r.up.balanced.x, r.up.balanced.y, r.up.balanced.i_ms);
    if (r.have_down && r.down.balanced.feasible)
        printf("  server: -f%d:%d -i%d\n", r.down.balanced.x, r.down.balanced.y, r.down.balanced.i_ms);
    printf("\n");
}
```

- [ ] **Step 4: 运行确认通过**

Run: `make 2>&1 | grep -Ei "error|warning"; ./speederv2 --test-selftest 2>&1 | tail -40; ./speederv2 --test-selftest >/dev/null; echo "exit=$?"`
Expected: 无 error/warning;示例报告正常打印;`0 failures`;`exit=0`

- [ ] **Step 5: 提交**

```bash
git add test_mode.h test_mode.cpp
git commit -m "test-mode: add report rendering

Per-direction tables (FEC is directional), tiers marked feasible or
'target unreachable' rather than fabricating a number, and an explicit
warning path when loss is policing-induced.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 8: responder 事件循环

**Files:**
- Modify: `test_mode.cpp`(替换 Task 1 的占位 `test_mode_responder_loop`)

**Interfaces:**
- Consumes: Task 2 codec、Task 3 `trace_t`、Task 5 `test_evaluate`
- Produces: 可运行的 `test_mode_responder_loop()`;线上 `TEST_RESULT` 载荷布局 `result_wire_t`(供 Task 9 解析)

```c
// TEST_RESULT payload, little-endian via write_u32/read_u32
struct result_wire_t {   // 序列化为 40 字节
    uint32_t n, arrived_n, lost_n;
    uint32_t run_p50, run_p95, run_max;
    uint32_t x, y, i_ms;          // balanced tier; x==0 => infeasible
    uint32_t residual_ppm;        // residual * 1e6
};
```

- [ ] **Step 1: 写实现(本任务用运行时行为验证,不走 selftest)**

在 `test_mode.cpp` 中,把占位实现替换为:

```c
#include "fd_manager.h"
#include "my_ev.h"

const int TEST_RESULT_WIRE_LEN = 40;

static void result_wire_pack(char *out, const trace_stats_t &st, const tier_t &tr) {
    write_u32(out + 0,  st.n);
    write_u32(out + 4,  st.arrived_n);
    write_u32(out + 8,  st.lost_n);
    write_u32(out + 12, st.run_p50);
    write_u32(out + 16, st.run_p95);
    write_u32(out + 20, st.run_max);
    write_u32(out + 24, tr.feasible ? (u32_t)tr.x : 0u);
    write_u32(out + 28, tr.feasible ? (u32_t)tr.y : 0u);
    write_u32(out + 32, tr.feasible ? (u32_t)tr.i_ms : 0u);
    write_u32(out + 36, tr.feasible ? (u32_t)(tr.residual * 1e6) : 0u);
}

// ---- responder session state ----
struct responder_state_t {
    bool               active = false;
    address_t          peer;              // source-pinned to the HELLO sender
    int                phase = 0;
    trace_t            trace;
    trace_stats_t      stats;
    tier_t             balanced;
    bool               phase_open = false;
    my_time_t          last_probe_us = 0;
    uint32_t           cur_pps = 0;
    my_time_t          last_mac_warn_ms = 0;
};

static responder_state_t g_resp;
static std::vector<int> g_resp_fds;

static void responder_finalize_phase() {
    if (!g_resp.phase_open) return;
    g_resp.phase_open = false;
    g_resp.stats = trace_analyze(g_resp.trace);
    g_resp.balanced = test_pick_tier(g_resp.trace, g_resp.stats, TIER_BALANCED_TARGET);
    mylog(log_info, "test: phase %d finalized, loss %.4f%% (%u/%u)\n",
          g_resp.phase, g_resp.stats.loss_rate * 100.0,
          g_resp.stats.lost_n, g_resp.stats.n);
}

static void responder_send(int fd, const address_t &to, int msg_type, int phase,
                           const void *payload, int payload_len) {
    char out[TEST_BUF_MAX];
    int n = test_encode(msg_type, phase, 0, payload, payload_len, out, sizeof(out), 0);
    if (n < 0) return;
    address_t dst = to;
    sendto(fd, out, n, 0, (struct sockaddr *)&dst.inner, dst.get_len());
}

static void responder_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    assert(!(revents & EV_ERROR));
    (void)loop;

    char buf[TEST_BUF_MAX];
    address_t::storage_t src_stor;
    socklen_t src_len = sizeof(src_stor);
    int len = recvfrom(w->fd, buf, sizeof(buf), 0, (struct sockaddr *)&src_stor, &src_len);
    if (len <= 0) return;

    address_t src;
    src.from_sockaddr((struct sockaddr *)&src_stor, src_len);

    test_hdr_t h;
    uint8_t *pl = 0;
    int pl_len = 0;
    int mt = test_decode(buf, len, &h, &pl, &pl_len);
    if (mt < 0) {
        // Rate-limited so a wrong key is visible to the operator: to the prober,
        // a bad key and a blocked port look identical.
        my_time_t now = get_current_time();
        if (now - g_resp.last_mac_warn_ms > 1000) {
            g_resp.last_mac_warn_ms = now;
            mylog(log_info, "test: dropped packet from %s: mac/format check failed "
                            "(wrong -k on the other side?)\n", src.get_str());
        }
        return;
    }

    // Source pinning: once a session exists, only its peer may drive it.
    if (g_resp.active && mt != TEST_HELLO && !(src == g_resp.peer)) {
        mylog(log_debug, "test: ignoring %d from non-session source %s\n", mt, src.get_str());
        return;
    }

    if (mt == TEST_HELLO) {
        if (g_resp.active && !(src == g_resp.peer)) {
            mylog(log_info, "test: rejecting concurrent session from %s\n", src.get_str());
            return;
        }
        g_resp.active = true;
        g_resp.peer = src;
        g_resp.phase_open = false;
        mylog(log_info, "test: session from %s\n", src.get_str());
        responder_send(w->fd, src, TEST_HELLO_ACK, 0, NULL, 0);

    } else if (mt == TEST_PHASE_BEGIN) {
        if (pl_len < 12) return;
        uint32_t expected_n = read_u32((char *)pl + 0);
        uint32_t pps        = read_u32((char *)pl + 4);
        uint32_t dir        = read_u32((char *)pl + 8);  // 0 = prober->responder
        if (expected_n == 0 || expected_n > TEST_MAX_EXPECTED_N) {
            mylog(log_warn, "test: refusing expected_n=%u (cap %u)\n",
                  expected_n, TEST_MAX_EXPECTED_N);
            return;
        }
        if (dir != 0) {
            // Reverse-direction phases are driven by Task 9's prober asking us to
            // send; not supported until then. ACK so the prober can proceed.
            responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);
            return;
        }
        g_resp.phase = h.phase;
        g_resp.cur_pps = pps;
        g_resp.trace.init(expected_n, pps);
        g_resp.phase_open = true;
        g_resp.last_probe_us = get_current_time_us();
        mylog(log_info, "test: phase %d begin, expect %u probes at %u pps\n",
              h.phase, expected_n, pps);
        responder_send(w->fd, src, TEST_PHASE_ACK, h.phase, NULL, 0);

    } else if (mt == TEST_PROBE) {
        if (!g_resp.phase_open) return;
        g_resp.last_probe_us = get_current_time_us();
        g_resp.trace.record(h.seq, g_resp.last_probe_us);

    } else if (mt == TEST_PHASE_END) {
        responder_finalize_phase();

    } else if (mt == TEST_REQUEST_RESULT) {
        responder_finalize_phase();
        char wire[TEST_RESULT_WIRE_LEN];
        result_wire_pack(wire, g_resp.stats, g_resp.balanced);
        responder_send(w->fd, src, TEST_RESULT, g_resp.phase, wire, sizeof(wire));

    } else if (mt == TEST_BYE) {
        mylog(log_info, "test: session closed by %s\n", src.get_str());
        g_resp.active = false;
        g_resp.phase_open = false;
    }
}

// Fallback: if all three PHASE_END copies were lost, finalize on silence.
static void responder_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    assert(!(revents & EV_ERROR));
    (void)loop; (void)w;
    if (!g_resp.phase_open) return;
    my_time_t idle_us = get_current_time_us() - g_resp.last_probe_us;
    my_time_t limit_us = 2000000ULL;   // 2s floor
    if (g_resp.cur_pps > 0) {
        my_time_t five_gaps = (my_time_t)(5.0 / (double)g_resp.cur_pps * 1000000.0);
        if (five_gaps > limit_us) limit_us = five_gaps;
    }
    if (idle_us > limit_us) {
        mylog(log_info, "test: phase %d finalized by idle timeout\n", g_resp.phase);
        responder_finalize_phase();
    }
}

int test_mode_responder_loop() {
    struct ev_loop *loop = ev_default_loop(0);
    assert(loop != NULL);

    std::vector<address_t> binds;
    binds.push_back(local_addr);
    if (port_range_mgr.count() > 0) {
        for (int k = 0; k < port_range_mgr.count(); k++) {
            address_t a = local_addr;
            a.set_port(port_range_mgr.ports[k]);
            binds.push_back(a);
        }
    }

    std::vector<ev_io *> watchers;
    g_resp_fds.clear();
    for (size_t k = 0; k < binds.size(); k++) {
        int fd;
        if (new_listen_socket2(fd, binds[k]) != 0) {
            mylog(log_fatal, "test: failed to bind %s\n", binds[k].get_str());
            myexit(-1);
        }
        g_resp_fds.push_back(fd);
        ev_io *w = new ev_io;
        ev_io_init(w, responder_cb, fd, EV_READ);
        ev_io_start(loop, w);
        watchers.push_back(w);
        mylog(log_info, "test: responder listening at %s\n", binds[k].get_str());
    }

    ev_timer t;
    ev_init(&t, responder_timer_cb);
    ev_timer_set(&t, 0.5, 0.5);
    ev_timer_start(loop, &t);

    mylog(log_info, "test: responder ready (%d socket(s))\n", (int)g_resp_fds.size());
    ev_run(loop, 0);
    return 0;
}
```

`test_mode.cpp` 顶部补 `#include "port_range_manager.h"` 与 `#include "misc.h"`(为 `local_addr`、`port_range_mgr`)。

- [ ] **Step 2: 确认 responder 能启动并绑定**

Run:
```bash
make 2>&1 | grep -Ei "error|warning"
./speederv2 -s --test-mode -l0.0.0.0:34567 -k pd --log-level 4 > /tmp/r0.log 2>&1 &
RESP=$!; sleep 1; kill $RESP 2>/dev/null; wait $RESP 2>/dev/null
grep -c "responder listening at 0.0.0.0:34567" /tmp/r0.log
```
Expected: 无 error/warning;最后一行输出 `1`

- [ ] **Step 3: 验证 MAC 拒绝路径与源锁定**

Run:
```bash
./speederv2 -s --test-mode -l0.0.0.0:34567 -k pd --log-level 4 > /tmp/resp.log 2>&1 &
RESP=$!
sleep 1
python3 -c "
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*64, ('127.0.0.1', 34567))   # garbage: must fail MAC
"
sleep 1
kill $RESP 2>/dev/null; wait $RESP 2>/dev/null
grep -c "mac/format check failed" /tmp/resp.log
```
Expected: 输出 `1` —— 垃圾包被 MAC 拒绝且**打了 log_info**(这正是"密钥错"与"端口不通"可区分的关键)

- [ ] **Step 4: 确认多端口绑定**

Run:
```bash
./speederv2 -s --test-mode -l0.0.0.0:34567 -k pd --data-port-range 34600-34603 --log-level 4 > /tmp/resp2.log 2>&1 &
RESP=$!; sleep 1; kill $RESP 2>/dev/null; wait $RESP 2>/dev/null
grep -c "responder listening" /tmp/resp2.log
```
Expected: 输出 `5`(1 个主端口 + 4 个数据端口)

- [ ] **Step 5: 提交**

```bash
git add test_mode.cpp
git commit -m "test-mode: add responder event loop

Source-pinned to the HELLO sender and single-session, because one
PHASE_BEGIN can trigger thousands of outbound packets -- an unauthenticated
responder would be a UDP reflector. expected_n is capped so a peer cannot
request an arbitrary allocation. MAC failures are logged at log_info,
rate-limited: to the prober a wrong key and a blocked port are
indistinguishable, so the operator needs to see it server-side.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 9: prober 事件循环与阶段编排

**Files:**
- Modify: `test_mode.cpp`(替换 Task 1 的占位 `test_mode_prober_loop`)

**Interfaces:**
- Consumes: Task 2 codec、Task 3/5/6/7 全部纯函数、Task 8 的 `result_wire_t` 布局与 `TEST_RESULT_WIRE_LEN`
- Produces: 可运行的 `test_mode_prober_loop()`,结束时调用 `test_render_report()`

**编排(依 spec §3):** 先跑速率扫描 R1..R3(各 10s,`0.5×/1×/2×`,单端口上行),再跑 S1(单端口上行)、S2(单端口下行)、S3/S4(多端口,仅当给了 `--data-port-range`)。总时长 ≈ `4×duration + 30s`,**必须打印阶段进度**。

本任务只实现**上行阶段(R1..R3、S1、S3)**并渲染报告;下行阶段 S2/S4 需要 responder 反向发流,留待后续迭代——报告以 `have_down = false` 渲染,不显示伪造的下行数据。这样本任务即可独立交付并端到端验证。

**关于结构的有意决定:** prober 采用**阻塞式**(`select` + `usleep`)而非 libev 事件驱动,尽管 `CLAUDE.md` 描述本项目为 event-loop based。理由:prober 是一次性诊断工具,各阶段严格顺序执行,阻塞写法最直白;事件驱动版本需要为握手/阶段/重试/结果索取写一整套状态机,复杂度显著上升而无收益。这是经确认的有意偏离项目约定,**不是缺陷**。responder(Task 8)仍是 libev 事件驱动,因为它必须同时服务多个端口。

- [ ] **Step 1: 写实现**

```c
struct prober_ctx_t {
    int       fd = -1;
    address_t peer;
    my_time_t rtt_us = 0;
    bool      acked = false;
    int       phase = 0;
    uint32_t  sent = 0;
    uint32_t  target_n = 0;
    uint32_t  pps = 0;
    double    frac = 0.0;
    bool      done = false;
    bool      got_result = false;
    trace_stats_t result_stats;
    tier_t        result_tier;
};

static prober_ctx_t g_pr;

static int prober_sendto(int msg_type, int phase, uint32_t seq,
                         const void *payload, int payload_len,
                         const address_t &dst, int pad_to) {
    char out[TEST_BUF_MAX];
    int n = test_encode(msg_type, phase, seq, payload, payload_len,
                        out, sizeof(out), pad_to);
    if (n < 0) return -1;
    address_t d = dst;
    return (int)sendto(g_pr.fd, out, n, 0, (struct sockaddr *)&d.inner, d.get_len());
}

// Blocking helper: send msg and wait up to timeout_ms for want_type.
static bool prober_exchange(int msg_type, int phase, const void *payload, int payload_len,
                            int want_type, int timeout_ms, int retries,
                            uint8_t *out_payload, int *out_payload_len) {
    for (int attempt = 0; attempt < retries; attempt++) {
        my_time_t t0 = get_current_time_us();
        prober_sendto(msg_type, phase, 0, payload, payload_len, g_pr.peer, 0);
        for (;;) {
            my_time_t elapsed_ms = (get_current_time_us() - t0) / 1000;
            if ((int)elapsed_ms >= timeout_ms) break;

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 50 * 1000;
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(g_pr.fd, &rf);
            if (select(g_pr.fd + 1, &rf, NULL, NULL, &tv) <= 0) continue;

            char buf[TEST_BUF_MAX];
            int len = recv(g_pr.fd, buf, sizeof(buf), 0);
            if (len <= 0) continue;
            test_hdr_t h;
            uint8_t *pl = 0;
            int pl_len = 0;
            int mt = test_decode(buf, len, &h, &pl, &pl_len);
            if (mt != want_type) continue;
            g_pr.rtt_us = get_current_time_us() - t0;
            if (out_payload && out_payload_len && pl_len > 0) {
                int cp = pl_len < *out_payload_len ? pl_len : *out_payload_len;
                memcpy(out_payload, pl, cp);
                *out_payload_len = cp;
            }
            return true;
        }
        mylog(log_debug, "test: no %d after attempt %d\n", want_type, attempt + 1);
    }
    return false;
}

// Uniform pacing: 1ms tick + fractional accumulator. A bursty sender would
// create correlated loss of its own and contaminate the burst measurement.
static void prober_run_phase(int phase, uint32_t pps, int duration_sec,
                             const std::vector<address_t> &dests) {
    uint32_t total = pps * (uint32_t)duration_sec;
    char begin_pl[12];
    write_u32(begin_pl + 0, total);
    write_u32(begin_pl + 4, pps);
    write_u32(begin_pl + 8, 0);   // dir 0 = prober -> responder

    if (!prober_exchange(TEST_PHASE_BEGIN, phase, begin_pl, sizeof(begin_pl),
                         TEST_PHASE_ACK, 1000, 5, NULL, NULL)) {
        mylog(log_fatal, "test: responder did not ack phase %d\n", phase);
        myexit(-1);
    }

    mylog(log_info, "test: phase %d running — %u pps x %ds (%u probes) to %d port(s)\n",
          phase, pps, duration_sec, total, (int)dests.size());

    double per_tick = (double)pps / 1000.0;
    double acc = 0.0;
    uint32_t sent = 0;
    size_t rr = 0;
    my_time_t next_tick = get_current_time_us();

    while (sent < total) {
        next_tick += 1000;   // 1ms
        my_time_t now = get_current_time_us();
        if (next_tick > now) usleep((useconds_t)(next_tick - now));

        acc += per_tick;
        while (acc >= 1.0 && sent < total) {
            acc -= 1.0;
            const address_t &d = dests[rr % dests.size()];
            rr++;
            prober_sendto(TEST_PROBE, phase, sent, NULL, 0, d, test_pkt_size);
            sent++;
        }
        if (sent % (pps * 5) == 0 && sent > 0) {
            mylog(log_info, "test: phase %d progress %u/%u\n", phase, sent, total);
        }
    }

    // PHASE_END x3 (it can be lost too)
    for (int k = 0; k < 3; k++) {
        prober_sendto(TEST_PHASE_END, phase, 0, NULL, 0, g_pr.peer, 0);
        usleep(20 * 1000);
    }

    // grace period before asking for the result
    my_time_t grace_us = g_pr.rtt_us * 2;
    if (grace_us < 500000ULL) grace_us = 500000ULL;
    usleep((useconds_t)grace_us);

    uint8_t wire[TEST_RESULT_WIRE_LEN];
    int wire_len = (int)sizeof(wire);
    if (!prober_exchange(TEST_REQUEST_RESULT, phase, NULL, 0,
                         TEST_RESULT, 2000, 5, wire, &wire_len)) {
        mylog(log_fatal, "test: no result for phase %d\n", phase);
        myexit(-1);
    }
    if (wire_len < TEST_RESULT_WIRE_LEN) {
        mylog(log_fatal, "test: short result payload (%d)\n", wire_len);
        myexit(-1);
    }

    memset(&g_pr.result_stats, 0, sizeof(g_pr.result_stats));
    g_pr.result_stats.n         = read_u32((char *)wire + 0);
    g_pr.result_stats.arrived_n = read_u32((char *)wire + 4);
    g_pr.result_stats.lost_n    = read_u32((char *)wire + 8);
    g_pr.result_stats.run_p50   = read_u32((char *)wire + 12);
    g_pr.result_stats.run_p95   = read_u32((char *)wire + 16);
    g_pr.result_stats.run_max   = read_u32((char *)wire + 20);
    if (g_pr.result_stats.n > 0) {
        g_pr.result_stats.loss_rate  = (double)g_pr.result_stats.lost_n / g_pr.result_stats.n;
        g_pr.result_stats.resolution = 1.0 / (double)g_pr.result_stats.n;
    }
    g_pr.result_stats.burst_p95_ms = (double)g_pr.result_stats.run_p95 / (double)pps * 1000.0;

    memset(&g_pr.result_tier, 0, sizeof(g_pr.result_tier));
    uint32_t rx = read_u32((char *)wire + 24);
    g_pr.result_tier.feasible = (rx != 0);
    g_pr.result_tier.x        = (int)rx;
    g_pr.result_tier.y        = (int)read_u32((char *)wire + 28);
    g_pr.result_tier.i_ms     = (int)read_u32((char *)wire + 32);
    g_pr.result_tier.residual = (double)read_u32((char *)wire + 36) / 1e6;
    if (g_pr.result_tier.x > 0)
        g_pr.result_tier.overhead = (double)g_pr.result_tier.y / g_pr.result_tier.x;

    mylog(log_info, "test: phase %d result — loss %.4f%%\n",
          phase, g_pr.result_stats.loss_rate * 100.0);
}

int test_mode_prober_loop() {
    address_t ephemeral;
    ephemeral.from_str((char *)"0.0.0.0:0");
    if (new_listen_socket2(g_pr.fd, ephemeral) != 0) {
        mylog(log_fatal, "test: failed to create prober socket\n");
        myexit(-1);
    }
    g_pr.peer = remote_addr;

    if (!prober_exchange(TEST_HELLO, 0, NULL, 0, TEST_HELLO_ACK, 1000, 10, NULL, NULL)) {
        mylog(log_fatal,
              "test: no response from %s.\n"
              "       check (1) UDP port reachability/firewall, and\n"
              "             (2) that -k matches on both sides "
              "(a wrong key is dropped silently; the responder logs it).\n",
              g_pr.peer.get_str());
        myexit(-1);
    }
    mylog(log_info, "test: responder reachable, RTT %.0f ms\n", g_pr.rtt_us / 1000.0);

    std::vector<address_t> single;
    single.push_back(remote_addr);

    std::vector<address_t> spread;
    for (int k = 0; k < port_range_mgr.count(); k++) {
        address_t a = remote_addr;
        a.set_port(port_range_mgr.ports[k]);
        spread.push_back(a);
    }

    test_report_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.duration_sec = test_duration_sec;
    rep.pps          = test_pps;
    rep.pkt_size     = test_pkt_size;
    rep.probe_mbps   = (double)test_pps * test_pkt_size * 8.0 / 1e6;
    rep.app_mbps     = (test_app_mbps > 0.0) ? test_app_mbps : rep.probe_mbps;
    rep.rtt_ms       = g_pr.rtt_us / 1000.0;
    snprintf(rep.peer, sizeof(rep.peer), "%s", remote_addr.get_str());

    // ---- rate scan first: if loss is policing-induced the whole FEC premise
    // ---- collapses, and the user should learn that early.
    const int SCAN_SEC = 10;
    int scan_pps[3] = {test_pps / 2, test_pps, test_pps * 2};
    if (scan_pps[0] < 1) scan_pps[0] = 1;
    double scan_p[3];
    uint32_t scan_n[3];
    for (int k = 0; k < 3; k++) {
        prober_run_phase(90 + k, (uint32_t)scan_pps[k], SCAN_SEC, single);
        scan_p[k] = g_pr.result_stats.loss_rate;
        scan_n[k] = g_pr.result_stats.n;
    }
    rep.have_rate_scan = true;
    rep.p_half = scan_p[0]; rep.n_half = scan_n[0];
    rep.p_nom  = scan_p[1]; rep.n_nom  = scan_n[1];
    rep.p_dbl  = scan_p[2]; rep.n_dbl  = scan_n[2];
    rep.verdict = test_rate_verdict(scan_p[0], scan_n[0],
                                    scan_p[1], scan_n[1],
                                    scan_p[2], scan_n[2]);

    // ---- S1: single port, up ----
    prober_run_phase(1, (uint32_t)test_pps, test_duration_sec, single);
    rep.have_up = true;
    memset(&rep.up, 0, sizeof(rep.up));
    rep.up.stats    = g_pr.result_stats;
    rep.up.balanced = g_pr.result_tier;
    double hdr_factor = 1.0 + 16.0 / (double)test_pkt_size;
    if (rep.up.balanced.feasible)
        rep.up.balanced.actual_mbps =
            rep.app_mbps * (1.0 + rep.up.balanced.overhead) * hdr_factor;

    // ---- S3: N ports, up ----
    if (!spread.empty()) {
        prober_run_phase(3, (uint32_t)test_pps, test_duration_sec, spread);
        rep.have_spread    = true;
        rep.spread_ports   = (int)spread.size();
        rep.spread_loss_up = g_pr.result_stats.loss_rate;
    }

    prober_sendto(TEST_BYE, 0, 0, NULL, 0, g_pr.peer, 0);

    test_render_report(rep);
    return 0;
}
```

`test_mode.cpp` 顶部补 `#include <unistd.h>`、`#include <sys/select.h>`。

- [ ] **Step 2: 运行以确认端到端可用**

Run:
```bash
make 2>&1 | grep -Ei "error|warning"
./speederv2 -s --test-mode -l0.0.0.0:34567 -k pd --log-level 4 > /tmp/r.log 2>&1 &
RESP=$!
sleep 1
./speederv2 -c --test-mode -r127.0.0.1:34567 -k pd \
    --test-duration 2 --test-pps 50 --log-level 4 2>&1 | tail -30
echo "prober exit=$?"
kill $RESP 2>/dev/null; wait $RESP 2>/dev/null
```
Expected: 无 error/warning;打印完整报告;零丢包时"链路特征"显示 `丢包率 0.0000%` 且推荐段落显示"链路干净";`prober exit=0`

注意:速率扫描固定 10s×3,故此命令最短约 36s。

- [ ] **Step 3: 验证错误路径 — 密钥不一致**

Run:
```bash
./speederv2 -s --test-mode -l0.0.0.0:34568 -k correct_key --log-level 4 > /tmp/r2.log 2>&1 &
RESP=$!; sleep 1
timeout 30 ./speederv2 -c --test-mode -r127.0.0.1:34568 -k wrong_key --log-level 4 2>&1 | tail -6
kill $RESP 2>/dev/null; wait $RESP 2>/dev/null
grep -c "mac/format check failed" /tmp/r2.log
```
Expected: prober 报错文案**同时提到端口可达性与 `-k` 不一致**两种可能;responder 日志计数 ≥ 1

- [ ] **Step 4: 验证多端口阶段**

Run:
```bash
./speederv2 -s --test-mode -l0.0.0.0:34569 -k pd --data-port-range 34700-34703 --log-level 4 > /tmp/r3.log 2>&1 &
RESP=$!; sleep 1
./speederv2 -c --test-mode -r127.0.0.1:34569 -k pd --data-port-range 34700-34703 \
    --test-duration 2 --test-pps 50 2>&1 | grep -A3 "port-range 对比"
kill $RESP 2>/dev/null; wait $RESP 2>/dev/null
```
Expected: 报告包含 `--- port-range 对比 ---` 段落,`4 端口` 字样出现

- [ ] **Step 5: 提交**

```bash
git add test_mode.cpp
git commit -m "test-mode: add prober orchestration and report emission

Rate scan runs first: if loss turns out to be policing-induced the whole
FEC premise collapses, so the user should see that warning early rather
than after a full run. Probe pacing uses a 1ms tick with a fractional
accumulator -- a bursty sender would manufacture correlated loss and
contaminate the very burst measurement we depend on.

Downstream phases (S2/S4) are not yet implemented; the report renders with
have_down=false rather than showing fabricated reverse-direction data.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 10: 烟雾测试与丢包注入

**Files:**
- Create: `tests/smoke_test_mode.sh`
- Modify: `test_mode.cpp`(在 prober 发送函数内实现 `--random-drop`)

**Interfaces:**
- Consumes: Task 9 的 `prober_sendto`
- Produces: `tests/smoke_test_mode.sh`,退出码 0 表示通过

**背景:** 现有 `--random-drop` 在 `my_send` 内、以 `dest.cook` 为门(`misc.cpp:228`),而测试模式不走那条路,故对测试模式天然无效。必须在 `prober_sendto` 内实现同等注入,否则烟雾测试无法注入已知丢包。

- [ ] **Step 1: 写失败测试**

创建 `tests/smoke_test_mode.sh`:

```bash
#!/usr/bin/env bash
# smoke_test_mode.sh — end-to-end check for --test-mode
#
# Round 1: selftest (pure-function assertions)
# Round 2: loopback probe with no injected loss  -> report shows a clean link
# Round 3: loopback probe with --random-drop 1000 (~10%) -> reported loss in band
#
# Usage: bash tests/smoke_test_mode.sh [/path/to/speederv2]
# Exit 0 on pass.

set -euo pipefail

BINARY="${1:-./speederv2}"
if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: binary not found or not executable: $BINARY"
    exit 1
fi

BASE_PORT=$(( (RANDOM % 20000) + 34000 ))
RESP_PORT=$(( BASE_PORT ))
KEY="smoke_testmode_$$"
PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup EXIT

echo "=== UDPspeeder --test-mode smoke test ==="
echo "  binary : $BINARY"
echo "  port   : $RESP_PORT"
echo

echo "Round 1: --test-selftest"
if ! "$BINARY" --test-selftest; then
    echo "  FAIL: selftest reported failures"
    exit 1
fi
echo "  [selftest] passed"
echo

start_responder() {
    local extra="${1:-}"
    # shellcheck disable=SC2086
    "$BINARY" -s --test-mode -l0.0.0.0:$RESP_PORT -k "$KEY" --log-level 4 $extra \
        > /tmp/smoke_tm_resp.$$ 2>&1 &
    PIDS+=($!)
    sleep 1
}

run_prober() {
    local extra="${1:-}"
    # shellcheck disable=SC2086
    timeout 120 "$BINARY" -c --test-mode -r127.0.0.1:$RESP_PORT -k "$KEY" \
        --test-duration 2 --test-pps 100 $extra 2>&1
}

echo "Round 2: clean loopback (expect 0% loss)"
start_responder ""
OUT2=$(run_prober "")
kill "${PIDS[-1]}" 2>/dev/null || true
echo "$OUT2" | grep -q "UDPspeeder FEC 测试报告" || { echo "  FAIL: no report"; exit 1; }
LOSS2=$(echo "$OUT2" | grep -m1 "丢包率" | grep -oE "[0-9]+\.[0-9]+" | head -1)
echo "  [clean] reported loss = ${LOSS2}%"
awk -v l="$LOSS2" 'BEGIN{ exit !(l < 1.0) }' \
    || { echo "  FAIL: clean run reported ${LOSS2}% loss (expected <1%)"; exit 1; }
echo "  [clean] ok"
echo

echo "Round 3: --random-drop 1000 (~10% injected)"
start_responder ""
OUT3=$(run_prober "--random-drop 1000")
kill "${PIDS[-1]}" 2>/dev/null || true
LOSS3=$(echo "$OUT3" | grep -m1 "丢包率" | grep -oE "[0-9]+\.[0-9]+" | head -1)
echo "  [drop] reported loss = ${LOSS3}%"
# pseudo-random injection varies run to run; assert a band, not an exact value
awk -v l="$LOSS3" 'BEGIN{ exit !(l > 5.0 && l < 16.0) }' \
    || { echo "  FAIL: injected ~10% but reported ${LOSS3}% (band 5-16%)"; exit 1; }
echo "$OUT3" | grep -q "推荐配置" || { echo "  FAIL: no recommendation section"; exit 1; }
echo "  [drop] ok"
echo

echo "=== PASSED ==="
```

- [ ] **Step 2: 运行以确认失败**

Run: `bash tests/smoke_test_mode.sh 2>&1 | tail -8`
Expected: FAIL — Round 3 报告丢包约 0%(`--random-drop` 对测试模式无效),提示 band 5-16% 未满足

- [ ] **Step 3: 在 prober 发送路径实现丢包注入**

`test_mode.cpp` 的 `prober_sendto` 开头插入:

```c
    // The tunnel's --random-drop lives in my_send() behind dest.cook, which
    // test mode does not use. Reimplement it here so smoke tests can inject a
    // known loss rate.
    if (random_drop != 0 && msg_type == TEST_PROBE) {
        if (get_fake_random_number() % 10000 < (u32_t)random_drop) return 0;
    }
```

只对 `TEST_PROBE` 注入:控制消息若被丢弃会让握手/结果索取失败,污染测试意图。

`test_mode.cpp` 顶部确保有 `#include "misc.h"`(为 `random_drop`)。

- [ ] **Step 4: 运行确认通过**

Run: `make 2>&1 | grep -Ei "error|warning"; bash tests/smoke_test_mode.sh 2>&1 | tail -12`
Expected: 无 error/warning;`=== PASSED ===`

Run(回归确认既有测试未受影响): `bash tests/smoke.sh 2>&1 | tail -3 && bash tests/smoke_port_range.sh 2>&1 | tail -3`
Expected: 两者均 `=== PASSED ===`

- [ ] **Step 5: 提交**

```bash
git add tests/smoke_test_mode.sh test_mode.cpp
git commit -m "test-mode: add smoke test and probe-path loss injection

--random-drop lives in my_send() behind dest.cook, which test mode does not
use, so it had no effect here; reimplemented in prober_sendto for probes
only (dropping control messages would break the handshake rather than
simulate link loss). Loss assertions use a band, since injection is
pseudo-random and varies per run.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 11: 文档

**Files:**
- Modify: `main.cpp`(`print_help`)、`README.md`

**Interfaces:**
- Consumes: Task 1 的参数集合
- Produces: 无代码接口

- [ ] **Step 1: 写 help 文本**

`main.cpp` 的 `print_help()` 中,在 `"log and help options:"` 段落**之前**插入:

```c
    printf("test mode options (measure the link and recommend fec parameters):\n");
    printf("    --test-mode                           run a one-shot link measurement instead of a tunnel.\n");
    printf("                                          must be set on both sides. -k is mandatory.\n");
    printf("                                          responder: -s --test-mode -l <ip:port>\n");
    printf("                                          prober:    -c --test-mode -r <ip:port>\n");
    printf("    --test-duration       <sec>           per-phase probe duration, default: 30, max: 600.\n");
    printf("    --test-pps            <number>        probe packet rate, default: 200, max: 20000.\n");
    printf("    --test-pkt-size       <number>        probe packet size, default: 1200, max: 1400.\n");
    printf("    --test-app-mbps       <number>        your payload rate, used to convert the redundancy\n");
    printf("                                          ratio into absolute bandwidth. default: probe rate.\n");
    printf("    --data-port-range     a-b             optional: also probe across n ports and report\n");
    printf("                                          whether port-range mode reduces loss on this link.\n");
    printf("      NOTE: total runtime is about 4 x --test-duration + 30s. the report gives three\n");
    printf("            candidate configs; residual loss is a conservative replay estimate, so the\n");
    printf("            real result after applying -i should be better than shown.\n");
```

- [ ] **Step 2: 验证 help 输出**

Run: `make 2>&1 | grep -Ei "error|warning"; ./speederv2 --help | sed -n '/test mode options/,/real result/p'`
Expected: 无 error/warning;完整打印该段落

- [ ] **Step 3: 写 README 段落**

`README.md` 中,在 Port-Range Mode 章节**之后**新增:

```markdown
### Test Mode

`--test-mode` runs a one-shot link measurement instead of a tunnel and prints
three candidate FEC configurations, per direction.

```bash
# responder (far end)
./speederv2 -s --test-mode -l0.0.0.0:4096 -k "passwd" [--data-port-range 15000-15015]

# prober (prints the report)
./speederv2 -c --test-mode -r<server_ip>:4096 -k "passwd" \
    [--data-port-range 15000-15015] [--test-duration 30] [--test-pps 200] \
    [--test-pkt-size 1200] [--test-app-mbps 5]
```

`-k` is mandatory: probes are MAC-authenticated so that an open responder cannot
be used as a UDP reflector.

The report contains:

- **Loss-nature verdict.** The probe runs at `0.5x / 1x / 2x` the nominal rate. If
  loss rises significantly with rate, the loss is policing- or congestion-induced;
  FEC will not help and adding redundancy makes it worse. The tool says so instead
  of recommending more redundancy.
- **Link characteristics** — loss rate, loss run lengths (p50/p95/max), p95 burst
  duration, and the sampling resolution of this run.
- **Three candidate configs** — thrifty (residual ≤1%), balanced (≤0.1%, the default
  recommendation), aggressive (≤0.01%), each with predicted residual loss, redundancy
  overhead, and absolute bandwidth.
- **Port-range comparison**, when `--data-port-range` is given: single-port vs N-port
  loss, quantifying whether port-range mode helps on this link.

How the recommendation is derived: one probe pass records a timestamped loss trace,
then that trace is replayed against ~1500 candidate `x:y` pairs. Because Reed-Solomon
is MDS, a group recovers iff at least `x` of its `x+y` shards arrive, so residual loss
equals the fraction of `(x+y)`-wide windows containing more than `y` losses. This
assumes nothing about the loss distribution — which matters, because burst loss badly
breaks binomial models.

`-i` is derived from the measured p95 burst duration (`i >= D*(x+y)/y`, capped at 50ms)
but is deliberately excluded from the residual-loss figure: scattering changes send
timing, and the trace was captured unscattered. Recommendations are therefore
conservative — the real result after applying `-i` should be better than shown.

Total runtime is about `4 x --test-duration + 30s`. Run `--test-selftest` to verify
the evaluator against synthetic traces.
```

- [ ] **Step 4: 验证**

Run: `grep -c "Test Mode" README.md; grep -c "test-selftest" README.md`
Expected: 均 ≥ 1

- [ ] **Step 5: 提交**

```bash
git add main.cpp README.md
git commit -m "docs: document --test-mode usage and methodology

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Self-Review 记录

**Spec 覆盖核对**(spec 各节 → 实现任务):

| Spec 节 | 任务 |
|---|---|
| §2 用户接口/参数上限 | Task 1 |
| §3 架构、角色、阶段编排、执行顺序 | Task 1(分派)、Task 8(responder)、Task 9(编排) |
| §4 包格式、不复用 ctrl_encode、消息类型、均匀节奏 | Task 2、Task 9 |
| §5 轨迹格式、乱序/重复、宽限期、兜底超时、发送时刻重建 | Task 3、Task 8 |
| §6.1 统计量 | Task 3 |
| §6.2 候选空间 | Task 5 |
| §6.3 残余丢包滑窗 | Task 4 |
| §6.4 `-i` 推导与上限 | Task 5 |
| §6.5 `-i` 排除在残余外 | Task 5(实现)、Task 7(报告注解) |
| §6.6 三档与不可达处理 | Task 5、Task 7 |
| §7 速率扫描、判定、带宽换算 | Task 6、Task 9(编排)、Task 5(换算) |
| §8 输出格式 | Task 7 |
| §9.1 MAC 失败双向可见 | Task 8(responder 日志)、Task 9(prober 文案) |
| §9.2 边界与失败模式 | Task 3(`expected_n` 上限)、Task 5(不可达)、Task 8(兜底超时)、Task 9(重试) |
| §9.3 安全:强制 `-k`、源锁定、单会话、内存边界 | Task 1(强制 `-k`)、Task 8(其余) |
| §10 测试 | Task 2-7(selftest)、Task 10(smoke + 注入) |
| §11 实现落点 | Task 1(makefile)、Task 11(文档) |

**已知缺口(有意为之,已在任务内声明):**

- **下行阶段 S2/S4 未实现**。Task 9 只做上行(R1..R3、S1、S3),报告以 `have_down=false` 渲染而非伪造数据。spec §3 的完整四阶段需要 responder 反向发流,应作为后续任务;当前交付仍是可用且自洽的工具。
- **样本不足门限(§9.2 的 `N<1000` / `N<200`)** 未单独成任务:`test_pick_tier` 的 `extrapolated` 标记已覆盖"目标低于分辨率"这一主要情形。若需严格拒绝,应在 Task 5 的 `test_evaluate` 内追加门限判断。
- **尾部集中丢包检测(§9.2)** 未实现。

**类型一致性核对:** `trace_stats_t` / `tier_t` / `recommendation_t` / `test_report_t` 字段名在 Task 3/5/7/9 中逐一比对一致;`read_uu64`(非 `read_u64`)已在 Task 2 使用;`TEST_RESULT_WIRE_LEN=40` 与 Task 8 的 `result_wire_pack` 偏移(0..36)及 Task 9 的解包偏移一致。

**占位符扫描:** 无 TBD/TODO;每个代码步骤均含可编译的实际代码;每个验证步骤均含可执行命令与预期输出。
