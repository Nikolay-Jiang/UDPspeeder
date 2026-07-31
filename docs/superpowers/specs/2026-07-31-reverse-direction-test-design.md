# 反向测量(server → client)设计

日期:2026-07-31
状态:已批准
前置:`docs/superpowers/specs/2026-07-30-fec-test-mode-design.md`(以下称"原 spec")

## 0. 这是什么

补完原 spec 中被推迟的 **S2 / S4** 两个阶段,让 `--test-mode` 同时测出
server → client 方向的丢包特征,并为服务端给出独立的 `-f` / `-i` 建议。

不是新功能:原 spec §3 的阶段编排表里 S2/S4 一直在,§4 的时序图画了
`PHASE_BEGIN(S2,down,single)`,协议头的 `dir` 字段就是为它保留的。当前
`test_mode_net.cpp` 的 `dir != 0` 分支只是 ACK 后返回,`test_report_t::have_down`
恒为 `false`。

### 为什么需要

`-f` 是**分方向独立生效**的:接收端从包头读 `data_num` / `redundant_num`
(`fec_manager.cpp:481-483`),不看本地配置,所以两端的 `-f` 本就不必相同。链路
两个方向的丢包又常常不对称(家宽上行受限、运营商单向整形)。只测上行,等于
拿上行的数字去配服务端的 `-f`。

客户端通常在 NAT 后、没有公网端口,所以反向探测必须复用握手时由客户端打洞
建立的映射,而不是让客户端监听。

## 1. 范围

| 阶段 | 方向 | 拓扑 | 记录方 | 本次 |
|---|---|---|---|---|
| R1..R3 | client → server | 单端口 | responder | 已有,不变 |
| S1 | client → server | 单端口 | responder | 已有,不变 |
| S2 | server → client | 单端口 | **prober** | **新增** |
| S3 | client → server | N 端口 | responder | 已有,**修缺陷** |
| S4 | server → client | N 端口 | **prober** | **新增** |

执行顺序 R1→R3, S1, S2, S3, S4。阶段编号沿用现有约定(扫描 90/91/92,
S1=1, S2=2, S3=3, S4=4)。S3/S4 仅在给了 `--data-port-range` 时执行;
S4 另需 S3 中至少一个数据端口收到过包(见 §4)。

### 默认行为与耗时

反向阶段**默认执行**,`--test-no-reverse` 关闭。

| 场景(默认 `--test-duration 30`) | 改动前 | 改动后 |
|---|---|---|
| 单端口 | 60s | **90s** |
| 多端口 | 90s | **150s** |
| `--test-no-reverse` 单/多端口 | — | 60s / 90s |

`--test-no-reverse` **只是 prober 侧的开关**,responder 不需要配置。responder
永远具备反向能力,跑不跑由 prober 的 `dir=1` 决定。刻意不往"两端必须一致"
那张清单里加项:每多一项,就多一种"配错了仍能跑起来、只是结果错"的方式。

CLI 侧新增全局 `int test_no_reverse`(默认 0),定义在 `misc.cpp`,声明在
`test_mode.h`,与既有 `test_*` 全局同样在 `process_arg` 后视为只读。

### 明确不做

- **速率扫描保持只测上行。** 它回答"链路是否在限速",30s 已是流程中最长的
  固定开销,为双向翻倍到 60s 不划算。**已知局限:若只有下行被限速,该判定
  看不出来**,而下行表仍会给出 FEC 推荐,其前提可能不成立。必须写进 README。
- 不做双向并发。并发会让两个方向互相干扰,污染归因(原 spec §3 已定)。
- 反向探测不做重放保护,与上行同一取舍(原 spec §4)。

## 2. 组件与边界

### 2.1 `pacer_t`(`test_mode.cpp`,纯逻辑)

不读时钟、不碰 socket、不知道 seq 是什么。

```c
struct pacer_t {
    double    pps;
    double    credit;
    my_time_t last_us;
    void init(double pps, my_time_t now_us);
    int  tick(my_time_t now_us);   // 返回此刻应发几个包
};
```

`tick()` 按**实际流逝时间**结算令牌(`credit += elapsed_us * pps / 1e6`),
而非假设"刚好过了 1ms"——定时器抖动自行抵消,调用方不需要补偿。

两条既有规则搬入并成为可测的:

- credit 上限 `pps/1000 + 1`:一次 tick 不许放出积压的一长串。
- 流逝超过 `PACER_SLIP_US`(50000)时重新对齐基线,**不补发**。

理由:发送端自身突发会自造时间相关丢包,污染突发长度测量,而 `-i` 推荐正是
从突发长度导出的。该逻辑目前内联在 `prober_run_phase()` 里,selftest 覆盖不到,
且已是本功能两次静默错误结果的发生地。反向路径需要第二份起搏器,抽出来共用
好过抄一遍。

返回值只是"该发几个";发给谁、发什么由调用方决定。

### 2.2 responder 发送侧(`test_mode_net.cpp`)

1ms repeat 的 `ev_timer`,仅在反向阶段进行中 start,阶段结束立即 stop。每次
触发:`pacer.tick()` 取 n,发 n 个带 `--test-pkt-size` padding 的 `TEST_PROBE`,
seq 为本阶段内 0..total-1 递增;发满 `total` 后进入 grace(§5.2),再发 3 份
`PHASE_END`,相隔 20ms(由同一个一次性定时器链驱动,不阻塞 ev 循环),与
prober 上行侧的 3 份间隔一致。

现有的 `responder_send()` 把 seq 硬编码为 0、`pad_to` 硬编码为 0,反向探测需要
两者皆可指定,故增加一个带 seq / pad_to 参数的发送辅助函数,`responder_send()`
成为它的薄封装。

**不采用**"在回调里阻塞发完"的方案(即复用 prober 的 `usleep` 循环):那会把
ev 循环堵死整个阶段(最长 600s),`PHASE_ACK` 一旦丢失,prober 重传
`PHASE_BEGIN` 要等发完才被处理,于是又开一个阶段。失败模式隐蔽,否决。

### 2.3 prober 接收侧(`test_mode_net.cpp`)

反向阶段从阻塞 `select` 循环收包,按 `h.seq` 落进本地 `trace_t`,收到
`PHASE_END` 或静默超时后就地 `trace_analyze` + `test_pick_tiers`。

**下行结果不过线**:记录方即评估方,`TEST_RESULT` 的 84 字节线格式一字节不改。

### 2.4 边界原则

**谁收包谁出结论。** 轨迹(可能上百万字节)永远不过线,只有结论过线,且只在
上行方向过。responder 不评估下行,prober 不评估上行。

## 3. 协议扩展与向后兼容

线上改动全部是向后兼容的追加(载荷末尾加字,老实现按长度检查照常解码)。

### 3.1 `TEST_PHASE_BEGIN` 载荷 12 → 20 字节

老 responder 的检查是 `pl_len < 12` 才拒,收到更长的载荷照常只读前 12 字节,
因此**前三字之后的每一字都是纯追加、双向兼容**。解码侧对每个可选字单独判长度
(`>=16` / `>=20`),永不越读实际收到的数据报。

```
off  0 : expected_n
off  4 : pps
off  8 : dir       (0 = prober->responder, 1 = responder->prober)
off 12 : spread    (0 = 单端口,1 = 按数据端口轮询)
off 16 : cookie    (会话 cookie,dir=1 必填;见 3.5.1)
```

`dir=1` 分支由"ACK 后返回"改为真正开阶段。

### 3.2 `TEST_PHASE_END` 在反向阶段携带 8 字节载荷

```
off 0 : sent_n        发送方地面真值
off 4 : send_fail_n   responder 本地被内核拒掉的包数
```

`send_fail_n` 会被 prober 计为丢包,故必须上报,与上行方向
`test_report_t::send_fail_n` 的处理对称。老 prober 不看 `PHASE_END` 载荷。

### 3.3 `TEST_HELLO_ACK` 接受路径 4 → 12 字节(能力位 + 会话 cookie)

| 路径 | 布局 | 老 prober 行为 |
|---|---|---|
| 接受 | `reject=0` + `caps` + `cookie` | 只读偏移 0 判 `!=0`,后面不看 → 正常 |
| 拒绝 | `reject` + 原因串(**永久冻结**) | 从偏移 4 读原因串 → 正常 |

能力位与 cookie 只出现在接受路径,而接受路径没有原因串,故新旧组合都不会把它们
当作文本打印。**拒绝路径不得再追加任何东西**,原因即此。`caps` 位 0 = 支持反向
阶段。解码侧短于 8 字节 → `caps = 0`,短于 12 字节 → `cookie = 0`,而 0 永远不是
合法 cookie,故绝不会被误判为匹配。

### 3.4 这一节存在的理由:一个静默错误结果

新 prober 对老 responder 发 `dir=1`,老 responder 会 ACK 然后什么都不发。
prober 于是记录 100% 丢包,报告打出"server → client 丢包 100.0000%,三档目标
均不可达"——数字具体,内容全假,且没有任何异常迹象。

两道独立的闸:

1. 能力位缺失 → 根本不发起反向阶段,报告说明对端不支持。
2. 能力位说支持但一个包都没到 → 打"未测出结果"及原因,**不打 100%**。

### 3.5 responder 首次成为流量源,必须自限

`TEST_MAX_EXPECTED_N`(1000 万)是为"记录轨迹"设的内存上限,拿来当"我要发多少
包"的上限过宽。反向阶段:

- `expected_n` 收紧到 `TEST_MAX_TOTAL_PROBES`(50 万,与 prober 侧 CLI 校验同
  一常量)。
- `pps` 收紧到 `TEST_PPS_MAX`(20000)。
- 超限即拒绝并记 `log_warn`。

持有 `-k` 的对端本就能驱动 responder,但不该能让它以任意速率无限量发送。

#### 3.5.1 速率/总量自限还不够:必须有回址可达性证明(per-session cookie)

**本节原先写的是"目的地址一项已被 source pinning 锁死",该论断是错的,正是它
放过了一个可被伪造源地址驱动的 UDP 放大器。**

source pinning 把反向探测的目的地址锁到 `TEST_HELLO` 的**源地址**上——而源地址
恰恰是链路外攻击者唯一能随意伪造的字段。整条时序是单向的,没有任何一步要求对
端证明自己真的收得到那个地址的包:

```
HELLO(伪造源=受害者)      -> pin g_resp.peer = 受害者
                           <- HELLO_ACK 发往受害者(攻击者收不到,也不需要)
PHASE_BEGIN(dir=1, ...)   -> 开始以 pps 速率向受害者发送 expected_n 个探测包
PHASE_BEGIN(每 5s 一次)   -> 喂 dead-man 开关,维持发送
```

按 3.5 的自限上限(50 万包 × 1400B,20000pps)算:约 316 字节的攻击流量换来约
614 MB / 约 196 Mbps 打向一个从未向攻击者发过任何东西的地址。`-k` 在服务端是与
**所有**隧道客户端共享的,所以这不需要运营者本人,任何一个合法用户即可。
`last_rev_phase_done` 只挡同一 phase 号的重放(还有 255 个可用),重发 HELLO 即
可清零。

**修法:每会话随机 cookie。**

| 步骤 | 行为 |
|---|---|
| responder 接受 `HELLO` | 用 `get_fake_random_number_nz()` 现取一个非零 32 位 cookie,存入会话状态 |
| `HELLO_ACK` **仅 accept 路径** | 在 `caps` 之后追加该 cookie(reject 路径**不动**:旧 prober 把偏移 4 之后全部当文本打印) |
| prober | 从 accept 中取出并保存,在**每个** `dir == 1` 的 `PHASE_BEGIN` 中回带 |
| responder | `dir == 1` 且 cookie 不匹配(含缺失=0)→ **静默拒绝**:不回 ACK、不起定时器、不改任何状态,仅记 `log_warn`。这与"无可用数据端口"的拒绝形状一致,prober 侧读作"该方向未测出" |
| 新的 `HELLO` | 重新铸一个 cookie,旧的立即失效,不可重放进后来的会话 |

cookie 只会发往 `HELLO_ACK` 的目的地址,因此收不到该地址流量的伪造者永远学不到
它;唯一手段是 2^32 盲猜,而猜错不产生任何回包可供校准。放大器由此关闭。

`dir == 0`(上行)**不做**该检查:上行的流量源是 prober 自己,不存在被放大的问
题,加检查只会破坏兼容性。

## 4. 对称 NAT 与 S4 回打路径

### 4.1 既有缺陷(S3,必须一并修)

source pinning 用 `src == g_resp.peer`,而 `address_t::operator==` 是对整个
sockaddr 做 `memcmp`(`common.h:301`),**端口计入**。对称 NAT 为每个目的端口
分配不同外部源端口,故 S3 中打到数据端口的探测包源地址 ≠ 控制面映射,
**当前代码在闸口(`test_mode_net.cpp:259`)将其全部丢弃**。responder 轨迹显示
~100% 丢包,报告输出"多端口未降低丢包,port-range 对该链路无收益"。

结论是反的:对称 NAT 正是 port-range 最该起作用的场景。cone 型 NAT(多数家用
路由)所有目的端口共用一个外部端口,故该路径上 S3 正常,缺陷只在对称 NAT 显形。
与隧道侧刚修复的 `conn_manager` 键值分裂同根同源(commit `342377b`)。

### 4.2 分层 pinning

| 流量 | 匹配方式 | 理由 |
|---|---|---|
| 控制面消息(`TEST_HELLO` 除外) | 完整 `(ip, port)` | 控制面走单一映射,收紧无代价 |
| `TEST_PROBE` | **仅 IP** | 数据端口的外部端口由 NAT 决定,不可预测 |

### 4.3 per-fd 源地址表

responder 为每个数据 fd 记录最近一次收到的、MAC 通过的、来自 pinned peer IP 的
源地址 `A_k`,**每次刷新**(NAT 可能中途重绑——隧道侧 `record_endpoint` 已踩过)。

**S4 从 fd k 发往 `A_k`。** 该二元组正是建立这条映射的那一对,对称 NAT 与端口
受限锥形 NAT 都放行。若从数据 fd 打向控制面 pinned 地址,对称 NAT 直接丢弃,
S4 又是一份 100% 丢包的假结论。

由此产生的约束:

- **S4 只在 S3 之后紧接着跑。** 映射由 S3 的上行探测建立,间隔数秒,远小于
  常见的 30s+ UDP NAT 空闲超时。
- **S3 中零收包的 fd 不进 S4 轮询**,报告给出"实际参与的端口数"而非 N。
  全部 fd 均无收包则跳过 S4 并说明原因,不出结论。
- per-fd 表随会话生命周期,`TEST_BYE` 与空闲过期时一并清除。

## 5. 失败模式与错误处理

| 场景 | 处理 |
|---|---|
| 对端旧构建(无能力位) | 不发起反向阶段,报告说明对端不支持 |
| 能力位支持但零收包 | "未测出结果"及原因,**不打 100% 丢包** |
| `PHASE_END` ×3 全丢 | prober 静默超时自行结算,复用 responder 侧 2s 下限 / 5 包间隔规则 |
| 重复 `PHASE_BEGIN` | 现有去重闸只判 `dir == 0`,扩到 `dir == 1`:重发 ACK,**不重置起搏器与计数** |
| responder 本地发送失败 | 经 `PHASE_END` 载荷上报;报告点明是**对端**发不出去 |

重复 `PHASE_BEGIN` 一条须强调:不做的话,就是把"重置轨迹造出巨量幻影丢包"这个
已踩过两次的坑在反向再踩一遍。

### 5.1 死人开关(prober 中途被杀)

反向阶段进行时 prober 不说话,而 responder 会话空闲上限是 45s。
`--test-duration 600` 时,正常运行的反向阶段会在第 45 秒被自己的空闲检测干掉。
反之,若把"反向阶段进行中"直接算作活跃,prober 被 `kill -9` 后 responder 会对
一个不存在的地址持续满速发送最长 600 秒。

方案:反向阶段期间 **prober 每秒发一个 keepalive**(它本就闲着),responder
连续 **5 秒**收不到即中止本阶段。正常运行不会误杀,prober 猝死的爆发窗口限制
在 5 秒内。

**keepalive 就是重发当前阶段的 `TEST_PHASE_BEGIN`**(phase 与 dir/spread 均与
本阶段相同),不新增消息类型:§5 表格第 4 行的去重闸已经使它幂等——responder
重发 `PHASE_ACK` 并忽略,既不重置起搏器也不重置计数,同时刷新
`last_rx_us`(`test_mode_net.cpp:267`)。

这里有两个独立的计时器,不要混淆:

| 计时器 | 时限 | 作用域 |
|---|---|---|
| 会话空闲过期 | 45s | 整个会话,既有逻辑不变 |
| 反向阶段死人开关 | 5s | **仅**反向阶段进行中 |

反向阶段进行时,每秒到达的 keepalive 同时喂饱两者,故 45s 那个不会再误杀长
阶段。

### 5.2 grace period 的对称处理

上行的做法是 prober 先 `usleep` 再发 `PHASE_END`,因为探测包与 `PHASE_END` 走
不同 socket,没有跨 socket 顺序保证。反向同理(S4 探测来自 N 个数据 fd,
`PHASE_END` 来自控制 fd),但 responder 不能 sleep,故用一次性 `ev_timer` 将
`PHASE_END` 延后 `max(500ms, 2×RTT)` 发出。

## 6. 报告

`have_down` 分节渲染(`test_mode.cpp:458`)与建议命令行的 `server:` 行(`:483`)
已实现,当前仅数据为空。新增部分:

1. port-range 对比一节增加下行行,上下行各一行,结论分开下。
   `test_report_t` 增加 `have_spread_down` / `spread_loss_down` /
   `spread_ports_down`(实际参与的端口数,见 §4.3)。
2. 新增 responder 侧发送失败警告,与现有本地发送失败警告对称。文案必须点明是
   **对端**发不出去,否则用户会去调自己这边的 `--test-pps`。
3. 反向阶段零收包时打"该方向未测出结果"及原因(§3.4 第二道闸的呈现端)。

最终报告同时给出两行建议,对应两端各自的 `-f`。

## 7. 测试

### 7.1 selftest(纯逻辑,无网络)

`pacer_t` 现在可测:

- 200pps 喂 1000 个合成 tick,必须恰好出 200 个包。
- 时间跳变 200ms 不得一次放出 40 个(credit 上限)。
- 超过 `PACER_SLIP_US` 后重新对齐,不补发积压。
- `pps=1` 的低速率不丢 token。

全部为确定性纯函数测试,时间由参数注入,不读时钟。

### 7.2 smoke(回环端到端)

`tests/smoke_test_mode.sh` 新增三轮:

- 反向阶段产出带数值 `-f` 的 `server -> client` 分节。
- `--random-drop` 注入的下行丢包能被测出。**需要把 `--random-drop` 接进
  responder 的发送路径**,同样只作用于 `TEST_PROBE`(控制消息被丢会破坏握手,
  而非模拟链路丢包)。
- `--test-no-reverse` 不产出下行分节。

### 7.3 向后兼容(可真跑)

把改动前的 HEAD 编译到 `/tmp` 充当"旧 responder",用新 prober 打它,断言输出为
"对端不支持反向"而**非** 100% 丢包。直接测 §3.4 描述的最恶劣失败形态,不依赖
肉眼审阅。

## 8. 文档

README 的 test-mode 一节需更新:

- 反向阶段默认执行及新的耗时表。
- `--test-no-reverse`(仅 prober 侧)。
- 报告新增的 `server -> client` 分节与第二行建议命令行。
- **已知局限:速率扫描只测上行**,只有下行被限速时该判定看不出来。
- 删除现有"only the client -> server direction is measured"的表述,以及
  `main.cpp:print_help` 中对应的 NOTE。
