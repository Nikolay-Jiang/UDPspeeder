# UDPspeeder
![image0](/images/cn/speedercn.PNG)

双边网络加速工具，软件本身的功能是加速UDP；不过，配合vpn可以加速全流量(包括TCP/UDP/ICMP)。通过合理配置，可以加速游戏，降低游戏的丢包和延迟；也可以加速下载和看视频这种大流量的应用。用1.5倍的流量，就可以把10%的丢包率降低到万分之一以下。跟 kcptun/finalspeed/BBR 等现有方案比，主要优势是可以加速 UDP 和 ICMP，现有方案几乎都只能加速 TCP。

我自己稳定用了几个月，用来加速美服的Brawl Stars和亚服的Mobile Legend，效果不错，加速前卡得几乎没法玩，加速后就没怎么卡过了。用来看视频也基本满速。

最新的版本是v3版，在v2版的基础上增加了可选的 XChaCha20-Poly1305 加密、定长填充和端口轮换功能；默认仍是混淆 + 认证，不加密。如果你用的是v1版（路由器固件里自带的集成版很可能是v1版的），请看[v1版主页](/doc/README.zh-cn.v1.md)

配合vpn加速全流量的原理图(已测试支持VPN的有OpenVPN、L2TP、$\*\*\*VPN):

![image0](/images/Capture2.PNG)

[English](/README.md)

[UDPspeeder Wiki](https://github.com/wangyu-/UDPspeeder/wiki)

##### 提示

如果你嫌UDPspeeder+OpenVPN麻烦，你可以尝试tinyfecVPN，一个集成了UDPspeeder功能的VPN：

tinyfecVPN的repo:

https://github.com/wangyu-/tinyfecVPN


#### 效果
![image0](/images/cn/ping_compare_cn.PNG)

![image0](/images/cn/scp_compare.PNG)


#### 原理简介
主要原理是通过冗余数据来对抗网络的丢包，发送冗余数据的方式支持FEC(Forward Error Correction)和多倍发包，其中FEC算法是Reed-Solomon。

FEC方式的原理图:

![image0](/images/en/fec.PNG)

#### 其他功能
对包的内容和长度做随机化（可以理解为混淆），从抓包看不出你发送了冗余数据，不用担心vps被封。

在多个冗余包之间引入延迟（时间可配）来对抗突发性的丢包，避开中间路由器因为瞬时buffer长度过长而连续丢掉所有副本。

模拟一定的延迟抖动（时间可配），这样上层应用计算出来的RTT方差会更大，以等待后续冗余包的到达，不至于发生在冗余包到达之前就触发重传的尴尬。

输出UDP收发情况报告，可以看出丢包率。

模拟丢包，模拟延迟，模拟jitter。便于通过实验找出应用卡顿的原因。

client支持多个udp连接，server也支持多个client

#### 关键词

UDP加速器、双边UDP加速、全流量加速、开源加速器、游戏加速、网游加速器

# 简明操作说明

### 环境要求
Linux主机，可以是桌面版，可以是android手机/平板，可以是openwrt路由器，也可以是树莓派。Release中提供了`amd64`、`x86`、`arm`、`mips_be`、`mips_le`的预编译binary.

android版需要通过terminal运行。

### 安装
下载编译好的二进制文件，解压到本地和服务器的任意目录。

https://github.com/wangyu-/UDPspeeder/releases

### 运行
假设你有一个server，ip为44.55.66.77，有一个服务监听在udp 7777端口。 假设你需要加速本地到44.55.66.77:7777的流量。
```
在server端运行:
./speederv2 -s -l0.0.0.0:4096 -r127.0.0.1:7777  -f20:10 -k 00112233445566778899aabbccddeeff --mode 0

在client端运行:
./speederv2 -c -l0.0.0.0:3333 -r44.55.66.77:4096 -f20:10 -k 00112233445566778899aabbccddeeff --mode 0
```

现在client和server之间建立起了tunnel。想要连接44.55.66.77:7777，只需要连接 127.0.0.1:3333。来回的所有的udp流量会被加速。

##### 备注

`-f20:10`表示对每20个原始数据发送10个冗余包。`-f20:10` 和`-f 20:10`都是可以的，空格可以省略，对于所有的单字节option都是如此。对于双字节option，例如后面会提到的`--mode 0`，空格不可以省略。

`-k`/`--key` 需要正好32个ASCII十六进制字符(16字节)，例如`00112233445566778899aabbccddeeff`。所有网络模式都必须提供该密钥，且两端必须完全一致。密钥用于认证数据包：使用不同密钥的对端(包括使用旧口令的旧版本)会被拒绝。密钥不加密数据，原有的异或和混淆只改变协议特征，并不提供机密性。

推荐使用`--mode 0`选项，否则你可能需要考虑MTU问题。

这里推荐的参数是给日常/非游戏情况下使用的；玩游戏请用 [使用经验](https://github.com/wangyu-/UDPspeeder/wiki/使用经验) 里推荐的参数。

### 加密与混淆

UDPspeeder V3 把“混淆”和“加密”分得很清楚：

- 默认模式只做混淆：对数据包做长度随机化和异或填充，并附加 8 字节 SipHash-2-4 认证标签。它改变抓包特征并认证每个包，但**不加密**数据，不提供机密性。
- 真正的加密是可选项，默认关闭，只有两端都设置 `--cipher xchacha20-ietf-poly1305` 时才启用。此时数据面使用 XChaCha20-Poly1305：24 字节随机 nonce + 密文 + 16 字节 Poly1305 标签，替换原来的 8 字节 SipHash 标签和混淆层，每个包增加 **40 字节**。两端必须设置相同的 `--cipher` 和相同的 `--pad`，否则会被拒绝：port-range 模式下握手直接拒绝；普通模式没有协商，不匹配的包会被丢弃并记录为 `auth_drop: plane=...`。
- 控制面始终使用 SipHash 认证（不是加密），测试面不变。

| 选项 | 默认 | 含义 |
|---|---|---|
| `--cipher <name>` | `none` | `none`（默认）= 只做混淆 + SipHash 认证，不是加密。`xchacha20-ietf-poly1305` = 数据面真正的 AEAD 加密，两端必须一致。 |
| `--pad <0\|16\|32\|64>` | `0` | 在 AEAD 之前把明文填充到固定大小的桶。需要 `--cipher`，两端必须一致。每个包增加 1 字节 `pad_len` 和最多 64 字节认证填充。 |
| `--port-rotate-sec <sec>` | `0` | 仅客户端、port-range 模式。每 `<sec>` 秒在服务端下发的端口列表内推进轮询发送的起始端口。`0` 表示关闭。 |

#### 可运行示例

以下示例使用固定的 32 位十六进制测试 key；请替换为你自己的 key。`-k` 只接受正好 32 个 ASCII 十六进制字符。

默认模式（混淆 + SipHash 认证，不加密）：

```bash
# 服务端
./speederv2 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff

# 客户端
./speederv2 -c -l0.0.0.0:3333 -r 44.55.66.77:4096 \
    -f20:10 -k 00112233445566778899aabbccddeeff
```

两端都启用真正的 AEAD 加密（`--cipher`，两端必须一致）：

```bash
# 服务端
./speederv2 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305

# 客户端
./speederv2 -c -l0.0.0.0:3333 -r 44.55.66.77:4096 \
    -f20:10 -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305
```

AEAD 加密 + 定长桶填充（`--cipher --pad 32`，两端必须一致）：

```bash
# 服务端
./speederv2 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 -f20:10 \
    -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305 --pad 32

# 客户端
./speederv2 -c -l0.0.0.0:3333 -r 44.55.66.77:4096 -f20:10 \
    -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305 --pad 32
```

`--pad 32` 不带 `--cipher` 会在启动时报错退出：

```bash
./speederv2 -s -l0.0.0.0:4096 -r 127.0.0.1:7777 \
    -k 00112233445566778899aabbccddeeff --pad 32
# fatal: --pad 32 requires --cipher
```

port-range 模式下按 `--port-rotate-sec` 轮换发送端口（仅客户端）：

```bash
# 服务端：控制端口 14096，数据端口 15000-15015
./speederv2 -s --port-range-mode --control-port 14096 \
    --data-port-range 15000-15015 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff --cipher xchacha20-ietf-poly1305

# 客户端：每 30 秒推进一次轮询起始端口
./speederv2 -c --port-range-mode --control-host 44.55.66.77:14096 \
    -l 0.0.0.0:3333 -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305 --pad 32 --port-rotate-sec 30
```

cipher/pad 不匹配会被拒绝。port-range 模式下服务端在握手时就拒绝能力不一致的 HELLO，客户端不会安装端口列表：

```bash
# 服务端：默认模式，不带 --cipher
./speederv2 -s --port-range-mode --control-port 14096 \
    --data-port-range 15000-15015 -r 127.0.0.1:7777 \
    -f20:10 -k 00112233445566778899aabbccddeeff

# 客户端：请求 AEAD 加密 -> 握手被拒绝
./speederv2 -c --port-range-mode --control-host 44.55.66.77:14096 \
    -l 0.0.0.0:3333 -f20:10 -k 00112233445566778899aabbccddeeff \
    --cipher xchacha20-ietf-poly1305
```

`--pad` 也必须一致：服务端 `--pad 32` 而客户端 `--pad 64`（或没有 `--pad`）属于同一种不匹配。普通模式没有握手，不匹配的包会被逐个丢弃并记录为 `auth_drop: plane=data ...`。

##### 提示

对于某些运营商，UDPspeeder跟udp2raw配合可以达到更好的速度，udp2raw负责把UDP伪装成TCP，来绕过运营商的UDP限速。

udp2raw的repo:

https://github.com/wangyu-/udp2raw-tunnel

# 进阶操作说明

### 命令选项
```
UDPspeeder V3
git version: 3e248b414c    build date: Aug  5 2018 21:59:52
repository: https://github.com/wangyu-/UDPspeeder

usage:
    run as client: ./this_program -c -l local_listen_ip:local_port -r server_ip:server_port  [options]
    run as server: ./this_program -s -l server_listen_ip:server_port -r remote_ip:remote_port  [options]

common options, must be same on both sides:
    -k,--key              <32 hex>        正好32个ASCII十六进制字符，两端必须一致；用于认证，不加密
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
log and help options:
    --log-level           <number>        0: never    1: fatal   2: error   3: warn 
                                          4: info (default)      5: debug   6: trace
    --log-position                        enable file name, function name, line number in log
    --disable-color                       disable log color
    -h,--help                             print this help message

```
### 包发送选项，两端设置可以不同。 只影响本地包发送。
##### `-f` 选项
设置fec参数，影响数据的冗余度。
##### `--timeout` 选项
指定fec编码器在编码时候最多可以引入多大的延迟。越高fec越有效率，调低可以降低延迟，但是会牺牲效率。
#####  `--mode` 选项 和 `--mtu`选项

简单来说`--mode 0`更省流量，没有mtu问题；`--mode 1`可以稍微降低一点延迟，需要考虑mtu；另外还有个`--mode 0 -q1`模式，多倍发包专用，没有延迟，也没有mtu问题，适合游戏，但是最耗流量。

具体见，https://github.com/wangyu-/UDPspeeder/wiki/mode和mtu选项

对于新手，建议不要纠结这些参数的具体含义，就用我在`使用经验`里推荐的设置，不要乱改参数，尤其是不要改`--mtu`。

##### `--report`  选项
数据发送和接受报告。开启后可以根据此数据推测出包速和丢包率等特征。`--report 10`表示每10秒生成一次报告。

##### `-i` 选项
指定一个时间窗口，长度为n毫秒。同一个fec分组的数据在发送时候会被均匀分散到这n毫秒中，可以对抗突发性的丢包，默认值是0(也就是不开启此功能)。 这个功能很有用，在推荐的参数效果不理想时可以尝试打开，比如用`-i 10`、`-i 20`。这个选项的跟通信原理上常说的`交错fec` `交织fec`的原理是差不多的。

##### `-j` 选项
为原始数据的发送，增加一个延迟抖动值。这样上层应用计算出来的RTT方差会更大，以等待后续冗余包的到达，不至于发生在冗余包到达之前就触发重传的尴尬。配合-t选项使用。正常情况下跨国网络本身的延迟抖动就很大，可以不用设-j。这个功能也需要时钟，默认关掉了，不过一般情况应该不需要这个功能。

-j选项不但可以模拟延迟抖动，也可以模拟延迟。

##### `--random-drop` 选项
随机丢包。模拟高丢包的网络环境时使用。 `--random-drop`和`-j`选项一起用，可以模拟高延迟（或者高延迟抖动）高丢包的网络，可用于测试FEC参数在各种网络环境下的表现。

##### `-q` 选项
仅对mode 0模式有用。设置fec编码器的最大队列长度。 比如`-q5`的意思是，在编码器积攒了5个数据包后，就立即发送。合理使用可以改善延迟。在下文的`使用经验`里有提到用`--mode 0 -q1` 来多倍发包。 

`-q`和 `--timeout`的作用类似。`-q`决定fec编码器积攒了多少个数据包之后，立即发送。`--timeout`决定编码器收到第一个数据包以后，最多延迟多少毫秒后发送。

默认值是200，也就是尽可能多得积攒数据。 

建议不要自己调整这个参数，除非是用我在`使用经验`里推荐给你的形式。

#### `--fifo` option
用fifo(命名管道)向运行中的程序发送command。例如`--fifo fifo.file`，可用的command有：
```
echo fec 19:9 > fifo.file
echo mtu 1100 > fifo.file
echo timeout 5 > fifo.file
echo queue-len 100 > fifo.file
echo mode 0 > fifo.file
```
可以动态改变fec编码器参数。可以从程序的log里看到command是否发送成功。

### 以下设置两端必须相同。 

##### `-k`选项
指定一个正好32个ASCII十六进制字符(16字节)的预共享密钥，server/client两端必须完全一致。该密钥用于认证双方收发的每个包，使用不同密钥的对端会被拒绝。它不加密数据；原有的异或只是混淆，用于改变协议特征，防止UDPspeeder的协议被运营商针对，并不提供机密性。

##### `--disable-obscure`
UDPspeeder默认情况下会对每个发出的数据包随机填充和异或一些字节(4~32字节)，这样通过抓包难以发现你发了冗余数据，防止VPS被封。这个功能只是为了小心谨慎，即使你关掉这个功能，基本上也没问题，关掉可以省一些带宽和CPU。`--disable-obscure`可以关掉这个功能。

# 推荐参数

https://github.com/wangyu-/UDPspeeder/wiki/推荐设置

# 使用经验

https://github.com/wangyu-/UDPspeeder/wiki/使用经验

# 编译教程
暂时先参考udp2raw的这篇教程，几乎一样的过程。

https://github.com/wangyu-/udp2raw-tunnel/blob/master/doc/build_guide.zh-cn.md

# wiki

更多内容请看 wiki:

https://github.com/wangyu-/UDPspeeder/wiki

