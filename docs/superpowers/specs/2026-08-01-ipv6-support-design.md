# IPv6 支持设计

日期:2026-08-01
状态:已批准

## 0. 这是什么

这不是"增加 IPv6 支持"——**基础隧道已经支持 IPv6**。这是把后来两个功能弄丢的
IPv6 能力拾回来,并补上从来没有过的文档与测试。

### 实测现状

在 `::1` 上逐个跑过三个功能:

| 功能 | IPv6 实测 |
|---|---|
| 基础隧道(单端口) | **正常** —— 带 `-f2:1` 跑通 50/50 |
| port-range 模式 | **坏** —— 0/30,HELLO 发得出去,数据通不了 |
| test 模式 | **坏** —— prober 连 responder 都够不着 |
| 文档 | README 中 **零** 处提及 IPv6 |

`address_t` 早已具备 IPv6 能力:`from_str` 支持 `[::1]:port` 方括号语法
(`common.cpp:89-92`),`new_listen_socket2` 用 `addr.get_type()` 建 socket,
`new_connected_socket2` 同理。代码里大量 `AF_INET` 硬编码位于**注释掉的死代码**中。

### 根因

活的缺陷只有三处,且是同一个模式:**创建临时/绑定 socket 时用了 IPv4 字面量,
而不是从对端地址推导协议族**。

| 站点 | 现状 |
|---|---|
| `tunnel_client.cpp:447` | `ephemeral.from_str("0.0.0.0:0")`,数据与控制 socket 共用 |
| `tunnel_server.cpp:456` | `bind_base.from_ip_port_new(AF_INET, &INADDR_ANY, 0)` |
| `test_mode_net.cpp:1305` | `ephemeral.from_str("0.0.0.0:0")` |

共同点不是"族选错了",而是**根本没有推导这一步**——一个字符串字面量替代了本该
存在的逻辑。

同一处代码还压着一个非 IPv6 缺陷(既有代码审查 🟡 #9):port-range 客户端建
socket 时完全忽略 `--out-addr` / `--out-interface`,这两个选项在 port-range 下
静默失效。根因相同,一并修。

## 1. 范围

**做:**

- 三处族推导修复,使 port-range 与 test 模式恢复与基础隧道同等的 IPv6 地位。
- port-range 客户端支持 `--out-addr` / `--out-interface`。
- test 模式 prober 支持 `--out-addr` / `--out-interface`。
- IPv6 回归测试 + CI 接线。
- README 与 `--help` 文档。

**不做:**

- **不新增双栈相关代码。** ~~一个实例同时服务 v4 与 v6 客户端需要 `conn_manager`
  键值、NAT 端点表、source pinning 全部处理 `::ffff:1.2.3.4` 形式的 v4-mapped
  地址,复杂度与本次目标不成比例。每个实例仍是单协议族。~~

  > **修订(2026-08-02,评审后):上述论证的两个事实前提均已实测证伪。**
  >
  > 1. 本仓库从未设置 `IPV6_V6ONLY`(全树 grep 无命中),因此在默认 Linux 主机
  >    (`net.ipv6.bindv6only=0`)上,绑定 `[::]` 的服务端**本来就接受 IPv4 客户端**,
  >    以 v4-mapped 形式收到。实测:v4 客户端 → `[::]` 服务端,20/20 送达,
  >    服务端日志为 `new connection from [::ffff:127.0.0.1]:53372`,`conn_manager`
  >    直接以该地址为键正常建连。即上文所称"需要改造"的三处,实际上**已经在正确
  >    处理**这种地址,无需任何改动。
  > 2. 同一实例内各 socket 的协议族**互相独立**,代码中没有任何地方比较它们。
  >    实测:客户端 `-l 127.0.0.1` + `-r [::1]`,服务端 `-l [::1]` + `-r 127.0.0.1`,
  >    20/20 送达。故"每个实例仍是单协议族"亦不成立。
  >
  > 真正的限制比原文窄得多:只有**面向隧道的那一对**(客户端 `-r` 与服务端 `-l`)
  > 必须互相可达,其余 socket 的族彼此无关。
  >
  > 本次工作据此**不新增**任何双栈代码,也**不设置** `IPV6_V6ONLY`:后者是一次
  > 行为变更,超出本次批准范围,且会破坏当前依赖 `[::]` 接受 v4 客户端的部署
  > (该行为在本分支之前就已存在)。仅将文档改为描述真实行为。
- **port-range 服务端省略 `-l` 时不改默认。** 仍绑 IPv4 通配地址(见 §3)。

## 2. 组件与边界

**核心原则:协议族永远从对端地址推导,永不来自字面量。** 把推导做成具名函数,
下一个添加 socket 的人会在类型上被迫面对这个问题。

### 2.1 `address_t::wildcard_like`(`common.h`,纯地址运算)

```c
// 返回 family 族的通配绑定地址:AF_INET -> 0.0.0.0:port,AF_INET6 -> [::]:port
void wildcard_like(u32_t family, int port);
```

不碰 socket、不读全局、不记日志。内部复用既有的 `from_ip_port_new()`:
`AF_INET` 传一个值为 `INADDR_ANY` 的局部 `u32_t` 的地址(`INADDR_ANY` 是宏常量,
不能直接取址,现有代码 `tunnel_server.cpp:455` 已是此写法),`AF_INET6` 传
`&in6addr_any`(libc 提供的 `extern const struct in6_addr`)。不新增解析路径。
非法 family 走 `assert`,与 `get_len()` 现有风格一致。

做成纯函数的理由:**三处缺陷全部出在这一步**,纯函数可直接在
`test_mode_selftest()` 中断言(该处已有 `test_addr_same_ip` 的 `address_t`
断言先例),不必靠端到端测试去撞。

### 2.2 未连接路径补上 `out_interface`(`common.cpp`)

`new_listen_socket2(fd, addr)` 增加 `char *interface_string` 参数,现有调用点
传 `NULL`,内部照抄 `new_connected_socket2` 中的 `#ifdef __linux__` +
`SO_BINDTODEVICE` 段。

**不需要**单独的 `bind_addr` 参数:未连接 socket 只有一次 bind,`--out-addr`
就是那个 `addr` 本身,调用方传 `--out-addr` 的值代替通配地址即可。这与
`new_connected_socket2` 需要 `addr`(connect 目标)与 `bind_addr`(源)两个参数
不同,是两类 socket 的本质差别,不是遗漏。

### 2.3 三个调用点

每处收敛成同一形状:取对端地址的族 → `wildcard_like` 或 `--out-addr` → 建 socket。

## 3. 各调用点的族来源

| 站点 | 族来源 | 未设时 |
|---|---|---|
| port-range 客户端(数据 + 控制) | `ctrl_addr` | 不存在,`--control-host` 必填 |
| port-range 服务端 bind 基址 | `local_addr` | **保持 IPv4** |
| test-mode prober | `remote_addr` | 不存在,`-r` 必填 |

### 3.1 port-range 客户端的真相源是 `--control-host`,不是 `-r`

`tunnel_client.cpp:375-376` 把 `ctrl_addr` 作为基址交给
`port_range_mgr.set_from_ack()`,所有数据端口目的地址由它派生;port-range 模式下
`remote_addr` 在数据路径上未被使用(`:477` 的 `new_connected_socket2(remote_fd,
remote_addr, ...)` 属于非 port-range 分支)。故 `ctrl_addr` 是单一真相源,
无需校验其与 `-r` 的族是否一致。

这一点必须写进代码注释:读者会本能地认为 `-r` 是真相源。

### 3.2 test-mode responder 不需要改动

它绑 `local_addr` 并用 `set_port()` 派生数据端口,族天然跟随 `-l`。实测在
`[::1]:25030` 上监听正常;坏的只有 prober 一侧。明确记录,避免实现者改动一个
没有问题的地方。

### 3.3 服务端省略 `-l` 时必须主动声明

保持 IPv4 通配地址(向后兼容,现有部署不受影响),但**必须打一条 `log_info`**
说明绑的是 IPv4、需要 IPv6 请显式传 `-l"[::]:0"`。

理由:这是全设计中唯一一处"猜"协议族的地方,而猜错的表现是客户端连不上、
两端日志都正常——与防火墙拦截、密钥不匹配无法区分。让服务端日志自己说出来,
比让用户去比对文档便宜得多。

## 4. `--out-addr` / `--out-interface` 语义

port-range 客户端的**两个** socket(数据 + 控制)都按 `--out-addr` 绑定,都套用
`--out-interface`。两者都是打向服务端的出站 socket,只限制其一没有意义。

test 模式 prober 同样遵循这两个选项。理由:test 模式的意义是测出隧道**实际会走
的**那条路径的丢包;若隧道被 `--out-interface` 钉在某网卡而探测走默认路由,测出
的数字描述的是另一条链路——这正是本工具一直在防的那类"数字具体但不对"的错误,
只是错在路径而非算法。

### 4.1 族不匹配必须在启动时拦截

`--out-addr 1.2.3.4:0` 配 `--control-host [2001:db8::1]:4096`,当前会走到
`bind()` 失败并 `myexit(1)`,报 `socket bind error=...`——用户看不出是自己两个
参数的族对不上。

要求:在 `process_arg` 中比对 `out_addr` 与对端地址的族,不一致即 `log_fatal`,
**同时打出两个地址**,让冲突一眼可见。

"对端地址"按模式取,不可含糊:

| 模式 | 比对对象 | 理由 |
|---|---|---|
| 客户端,port-range | `ctrl_addr` | 数据目的地址由它派生(§3.1) |
| 客户端,非 port-range | `remote_addr` | 出站 socket connect 的目标 |
| 服务端 | `remote_addr` | `--out-addr` 作用于打向 `-r` 的那一端 |
| test 模式 prober | `remote_addr` | 探测目标 |

test 模式 responder 不建出站 socket,`--out-addr` 对它无意义,不做校验。

### 4.2 port-range 下 `--out-addr` 的端口必须为 0

帮助文本写的是 "port 0 for random port"。单端口模式只有一个出站 socket,指定
端口可行;port-range 有两个,同一非零端口绑两次必然 `EADDRINUSE`。

要求:**启动时拒绝并说明原因**,而不是"取 IP、静默忽略端口"——后者是拿用户明确
写下的值不当回事。该路径当前完全失效,故拒绝不会打断任何现存部署。

## 5. 测试

**本次最有价值的产物可能不是修复,而是回归护栏。** 基础隧道今天就能跑 IPv6,
但这件事既无文档也无测试。正因如此,后来的两个功能才能把它砸掉而无人察觉,且
砸掉的表现与防火墙拦截、密钥不匹配无法区分。修完不加测试,第三个功能会重演。

仓库有 CI(GitHub Actions,ubuntu-latest,`.github/workflows/ci.yml`),护栏能真正生效。

### 5.1 selftest(纯逻辑)

`wildcard_like` 断言:

- `AF_INET` → 地址为 `0.0.0.0`、`get_type() == AF_INET`
- `AF_INET6` → 地址为 `::`、`get_type() == AF_INET6`
- 端口如实带回(取一个非零值,避免 0 与未初始化混淆)
- `is_vaild()` 为真

§4.1 的族比对是 `a.get_type() != b.get_type()` 的一行判断,不值得为它造一个
谓词函数;它由 §5.2 的 smoke 轮次以及一次手工的错配启动验证覆盖(传一对
族不匹配的 `--out-addr` / `--control-host`,断言进程带着那条 fatal 文案退出,
而不是走到 `bind()` 才失败)。

### 5.2 `tests/smoke_ipv6.sh`(新增)

三轮,全部走 `::1`:

1. **基础隧道 —— 回归护栏。** 今天就该通过。这一轮的价值最高:它锁住的是本次
   之前就已存在、却从未被守护的能力。
2. **port-range 模式。** 复用 `smoke_port_range.sh` 的断言形状。
3. **test 模式。** 复用 `smoke_test_mode.sh` 的断言形状。

`tests/udp_echo.py` 当前写死 `AF_INET` + `127.0.0.1`,改为接受绑定地址并按其
推导协议族。这是唯一一处测试基建改动,`smoke.sh` 的现有调用需同步更新。

### 5.3 IPv6 不可用时必须显式跳过,且跳过要吵

GitHub runner 通常有 `::1`,但不保证。要求:检测不到 IPv6 环回即打印明确的
SKIP 行并以 0 退出——**不得静默通过**。一个悄悄不跑的测试比没有测试更糟,因为
它让绿色的 CI 说谎。

### 5.4 CI 接线

`smoke_ipv6.sh` 加入 `.github/workflows/ci.yml` 的测试步骤。

## 6. 文档

### README 新增 IPv6 一节

- `[::1]:port` 方括号语法(`from_str` 早已支持,从未记录)。
- 各功能的支持状态:基础隧道、port-range、test 模式均支持;不支持双栈,每实例
  单协议族。
- port-range 服务端省略 `-l` 时默认绑 IPv4,需 IPv6 请显式 `-l"[::]:0"`。
- `--out-addr` 的族必须与对端一致;port-range 下其端口必须为 0。

### `--help`

`-l` / `-r` / `--control-host` / `--out-addr` 的说明补上方括号语法。
