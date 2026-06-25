# Consensus Data-Plane Prototypes

本目录用于放置基于可编程交换机的共识协议相关实验代码。它是从原本 `exercises/` 教学练习目录中独立出来的研究原型目录，目标是逐步实现“交换机辅助识别共识流量中的疑似风险，并为后续调度、上送控制面或网内机制提供信号”。

当前阶段已经实现了最小可运行基础：

- 定义通用 BFT/共识专属包头。
- 在 P4 交换机中解析 Ethernet / IPv4 / UDP / BFT 共享包头。
- 保留普通 IPv4 LPM 转发逻辑。
- 在 ingress 中用 hash/register 记录 IORS 状态，识别 duplicate、conflict 和简单 reorder。
- 通过 `msg_flags` 和 IPv4 DSCP 对风险消息做可见标记。
- 提供主机侧 Scapy 发包、收包、攻击流量生成和轻量 PBFT 阶段流量生成脚本。

当前版本仍然是 MVP：交换机只发现疑似异常并打标，不做最终 Byzantine 判断，也不验证签名或完整共识协议状态。

## 与原始代码的关系

原仓库中的 `exercises/basic/basic.p4` 是一个单文件教学示例，主要逻辑是：

```text
Ethernet -> IPv4 parser
IPv4 LPM table
修改二层地址并转发
重新计算 IPv4 checksum
```

当前 `consensus/` 目录在这个基础上做了几类扩展：

1. 独立出研究原型目录

   新增顶层目录：

   ```text
   consensus/
   ```

   它与 `exercises/` 并列，不再作为某一道 tutorial exercise 的一部分。

2. 抽取共享 P4 定义

   原来 `basic.p4` 中的 `ethernet_t`、`ipv4_t` 等头部定义都写在一个文件中。现在把通用定义放到：

   ```text
   consensus/common/p4src/constants.p4
   consensus/common/p4src/headers.p4
   ```

   这样后续如果增加新的网内机制，例如 aggregation、ordering 或 quorum acceleration，可以共享同一套包头和常量。

3. 增加 UDP 和 BFT 头部解析

   当前 P4 parser 的解析链路变为：

   ```text
   Ethernet
     -> IPv4
       -> UDP
         -> IORS
   ```

   只有当 UDP 目的端口为 `5000` 时，交换机才继续解析 BFT 头部。

4. 保留基础 IPv4 转发

   当前 `iors.p4` 仍然使用和 `basic` 类似的 IPv4 LPM 表：

   ```text
   MyIngress.ipv4_lpm
   ```

   因此普通 IPv4 包和带 BFT 头部的 UDP 包都会根据目的 IP 正常转发。

5. 增加主机侧测试工具

   新增 Scapy 脚本，用于生成可控共识流量：

   ```text
   consensus/common/host/consensus_header.py
   consensus/common/host/send_consensus.py
   consensus/common/host/recv_consensus.py
   consensus/common/host/attack_sender.py
   consensus/common/host/bft_node.py
   ```

## 目录结构

当前目录结构如下：

```text
consensus/
├── README.md
├── common/
│   ├── host/
│   │   ├── consensus_header.py
│   │   ├── send_consensus.py
│   │   ├── recv_consensus.py
│   │   ├── attack_sender.py
│   │   ├── bft_node.py
│   │   ├── bidl_leader.py
│   │   ├── bidl_consensus.py
│   │   ├── bidl_execution.py
│   │   └── bidl_malicious.py
│   ├── p4src/
│   │   ├── constants.p4
│   │   └── headers.p4
│   └── topo/
│       └── single_switch.json
└── iors/
    ├── README.md
    ├── Makefile
    ├── p4src/
    │   └── iors.p4
    └── runtime/
        └── s1-runtime.json
```

各部分职责如下：

```text
common/
  放多个共识数据面机制都可能复用的代码。

common/p4src/
  放共享 P4 常量和包头定义。

common/host/
  放主机侧通用发包、收包和流量生成脚本。

common/topo/
  放通用 Mininet 拓扑。

iors/
  当前具体机制目录。IORS 暂时表示 In-network risk-aware scheduling 方向的原型。

iors/p4src/
  放 IORS 的具体 P4 数据面逻辑。

iors/runtime/
  放 BMv2/P4Runtime 加载的表项配置。
```

## BFT 包头格式

BFT 共享头部定义在：

```text
consensus/common/p4src/headers.p4
```

当前字段为：

```p4
header bft_t {
    bit<16> magic;
    bit<8>  msg_type;
    bit<8>  msg_flags;
    bit<8>  msg_version;

    bit<16> sender;
    bit<16> receiver;
    bit<16> leader;

    bit<16> epoch;
    bit<16> view;
    bit<32> sequence;
    bit<32> prev_digest;
    bit<32> curr_digest;
}
```

这些字段的含义是：

```text
magic
  BFT 头部魔数，用于标识自定义头部。

msg_type
  共识消息类型，例如 request、pre-prepare、prepare、commit、reply。

msg_flags
  主机侧标记，例如 test、attack、duplicate、conflict。
  当前交换机只解析该字段，尚未基于它做策略。

msg_version
  BFT 头部版本号。

sender / receiver / leader
  发送方、副本接收方和 leader/primary 标识。

epoch / view / sequence
  共识协议中的 epoch、view number 和序列号。

prev_digest / curr_digest
  前驱消息摘要和当前消息摘要。当前使用 32-bit digest，后续可以扩展为更长摘要。
```

对应的 Python/Scapy 定义在：

```text
consensus/common/host/consensus_header.py
```

P4 和 Python 的字段顺序需要保持一致。

## 数据面处理逻辑

核心 P4 程序在：

```text
consensus/iors/p4src/iors.p4
```

当前 pipeline 分为几部分。

1. Parser

   ```text
   parse_ethernet
     如果 etherType == 0x0800，进入 parse_ipv4

   parse_ipv4
     如果 protocol == UDP，进入 parse_udp

   parse_udp
     如果 dstPort == 5000，进入 parse_bft

   parse_bft
     提取 bft_t
   ```

2. Ingress

   当前 ingress 做两件事：

   ```text
   如果 hdr.bft.isValid():
     meta.risk_level = RISK_NORMAL

   如果 hdr.ipv4.isValid():
     执行 ipv4_lpm.apply()
   ```

   `risk_level` 目前只是预留字段，后续会用于表示：

   ```text
   RISK_NONE
   RISK_NORMAL
   RISK_DUPLICATE
   RISK_CONFLICT
   RISK_UNKNOWN
   ```

3. IPv4 LPM 转发

   `ipv4_lpm` 表根据目的 IP 选择端口，并重写 Ethernet 源/目的 MAC：

   ```text
   10.0.1.1 -> port 1
   10.0.2.2 -> port 2
   10.0.3.3 -> port 3
   ```

4. Checksum

   因为 ingress 中会减少 IPv4 TTL，所以 deparser 前会重新计算 IPv4 header checksum。

5. Deparser

   按顺序发出：

   ```text
   Ethernet -> IPv4 -> UDP -> IORS -> payload
   ```

## 当前拓扑

当前最小 BIDL 拓扑定义在：

```text
consensus/common/topo/single_switch.json
```

拓扑是四主机一交换机：

```text
h1 ----\
       s1
h2 ----/
       \
        h3
        |
        h4
```

端口映射：

```text
h1 <-> s1-p1
h2 <-> s1-p2
h3 <-> s1-p3
h4 <-> s1-p4
```

主机地址：

```text
h1: 10.0.1.1  bidl_leader
h2: 10.0.2.2  bidl_consensus
h3: 10.0.3.3  bidl_execution
h4: 10.0.4.4  bidl_malicious
```

## 编译

进入 IORS 目录：

```bash
cd /home/tongtao/Projects/bft-p4/consensus/iors
```

编译 P4：

```bash
make build
```

当前版本已经验证可以编译通过。编译时可能出现少量 unused warning，例如部分消息类型常量暂未使用，属于正常现象。

## 运行 Mininet

在 `consensus/iors` 目录下运行：

```bash
make run
```

该命令会：

```text
1. 编译 p4src/iors.p4
2. 启动 BMv2 simple_switch_grpc
3. 加载 common/topo/single_switch.json 拓扑
4. 使用 runtime/s1-runtime.json 下发表项
5. 进入 Mininet CLI
```

如果需要清理 Mininet：

```bash
make stop
```

或：

```bash
make clean
```

## 测试普通转发

进入 Mininet CLI 后，可以先测试普通 IP 连通性：

```text
mininet> h1 ping h2
```

如果普通转发正常，说明：

```text
拓扑正常
交换机启动正常
runtime 表项加载正常
ipv4_lpm 转发正常
```

## 测试 IORS 包转发

在 Mininet CLI 中，可以在 `h2` 上启动接收脚本：

```text
mininet> h2 python3 ../../common/host/recv_consensus.py
```

然后在另一个 Mininet CLI 命令中从 `h1` 发包到 `h2`：

```text
mininet> h1 python3 ../../common/host/send_consensus.py 10.0.2.2 --msg-type prepare --sender 1 --receiver 2 --leader 0 --view 0 --sequence 10 --payload hello --show
```

如果成功，`h2` 会打印类似信息：

```text
IORS 10.0.1.1 -> 10.0.2.2 type=prepare sender=1 receiver=2 leader=0 epoch=0 view=0 seq=10 ...
```

这说明：

```text
h1 构造了 UDP + IORS 包
s1 成功解析并转发
h2 成功收到并解析
```

## 生成测试流量

单包发送器：

```bash
python3 ../../common/host/send_consensus.py 10.0.2.2 \
  --msg-type prepare \
  --sender 1 \
  --receiver 2 \
  --leader 0 \
  --view 0 \
  --sequence 10 \
  --payload hello
```

生成正常流量：

```bash
python3 ../../common/host/attack_sender.py 10.0.2.2 --scenario normal
```

生成重复流量：

```bash
python3 ../../common/host/attack_sender.py 10.0.2.2 --scenario duplicate --sequence 10
```

生成冲突流量：

```bash
python3 ../../common/host/attack_sender.py 10.0.2.2 --scenario conflict --sequence 10
```

生成乱序流量：

```bash
python3 ../../common/host/attack_sender.py 10.0.2.2 --scenario reorder --sequence 10
```

当前数据面会对这些流量做基础识别：

```text
duplicate
  同一 (sender, view, sequence, msg_type) 的 curr_digest 相同。
  交换机会设置 IORS duplicate flag，并把 IPv4 DSCP 设置为 10。

conflict
  同一 (sender, view, sequence, msg_type) 的 curr_digest 不同。
  交换机会设置 IORS conflict flag，并把 IPv4 DSCP 设置为 46。

reorder
  同一 (sender, view, msg_type) 下，第一次看到一个比已记录最大 sequence 更小的 sequence。
  交换机会设置 IORS reorder flag，并把 IPv4 DSCP 设置为 8。
```

## 轻量 PBFT 阶段流量

`bft_node.py` 用于生成接近 PBFT 阶段的流量，但它不是完整 PBFT 节点，不维护完整状态机和安全性判断。

示例：

```bash
python3 ../../common/host/bft_node.py 10.0.2.2 --role full-demo --node-id 1 --sequence 10
```

支持的角色：

```text
client
  发送 request

primary
  发送 pre-prepare

replica
  发送 prepare 和 commit

full-demo
  依次发送 request、pre-prepare、prepare、commit、reply
```

这样设计的原因是：当前实验的核心是交换机数据面逻辑。主机侧先作为可控流量生成器，而不是完整共识协议实现，可以让调试更简单。

## BIDL 四类节点

当前也提供了更贴近实验叙事的四类 BIDL 节点：

```text
bidl_leader.py
  主节点。给事务分配 sequence，计算 digest，并按指定 tx_count、tx_rate 和 batch_size 通过应用层 fan-out 分别以 unicast 发送给共识节点和执行节点。

bidl_consensus.py
  共识节点。接收 leader 的事务，收齐一个 batch 后生成 batch commit/result 发给执行节点。

bidl_execution.py
  执行节点。收到 leader 事务后逐笔推测执行；收到 consensus batch commit 后校验 batch digest，一致则 commit，不一致则 re_execute。

bidl_malicious.py
  恶意节点。可以主动发送 duplicate/conflict/reorder，也可以监听 leader 事务后篡改或重复发送。
```

推荐的最小运行方式：

```text
mininet> h2 python3 /home/tongtao/Projects/bft-p4/consensus/common/host/bidl_consensus.py --execution-dest 10.0.3.3 --batch-size 2 &
mininet> h3 python3 /home/tongtao/Projects/bft-p4/consensus/common/host/bidl_execution.py &
mininet> h1 python3 /home/tongtao/Projects/bft-p4/consensus/common/host/bidl_leader.py --destinations 10.0.2.2,10.0.3.3 --start-sequence 1 --tx-count 4 --batch-size 2 --tx-rate 10
```

这个例子中，leader 以 10 tx/s 发送 4 笔事务，每 2 笔为一个 batch；consensus 收到每个完整 batch 后发送一个 commit，因此 execution 会看到 4 个 speculative transaction 和 2 个 batch commit。

`bidl_consensus.py` 和 `bidl_execution.py` 默认会一直在线运行。它们的 `--count` 参数只用于调试时自动退出；正式实验中通常不需要设置。

执行节点在每个 batch 成功提交时会打印：

```text
commit_time
batch_latency_ms
committed_batches
committed_txs
throughput_tps
```

其中 `throughput_tps` 基于 execution 节点已经提交的事务数和提交时间窗口计算，可用于初步观察吞吐量。

如果希望自动启动 Mininet、运行节点并收集日志，可以使用：

```text
python3 consensus/iors/scripts/run_experiment.py --batch-size 500 --tx-rate 1000 --tx-count 500 --attack none
```

常用参数包括：

```text
--batch-size
  每个 batch 的事务数量。

--tx-rate
  leader 发送事务的速率，单位为 tx/s。

--tx-count
  本轮实验发送的事务总数；不设置时默认等于 batch-size。

--attack
  可选 none、duplicate、conflict、reorder。

--attack-mode
  可选 active 或 listen。active 表示恶意节点主动注入，listen 表示监听 leader 事务后篡改。
```

脚本会把每轮实验输出到：

```text
consensus/iors/results/<experiment-id>/
```

其中包括：

```text
leader.log
consensus.log
execution.log
malicious.log
summary.csv
commits.csv
tx_latencies.csv
```

`summary.csv` 记录本轮总吞吐量和延迟汇总；`commits.csv` 记录每个 batch 的提交时间和吞吐；`tx_latencies.csv` 记录每笔事务从 execution 节点推测执行到 batch commit 的延迟。

主动攻击示例：

```text
mininet> h4 python3 /home/tongtao/Projects/bft-p4/consensus/common/host/bidl_malicious.py --mode active --attack conflict --destination 10.0.3.3 --spoof-sender 1 --sequence 10
```

监听后篡改示例：

```text
mininet> h4 python3 /home/tongtao/Projects/bft-p4/consensus/common/host/bidl_malicious.py --mode listen --attack conflict --destination 10.0.3.3 --leader-id 1 &
mininet> h1 python3 /home/tongtao/Projects/bft-p4/consensus/common/host/bidl_leader.py --destinations 10.0.3.3,10.0.4.4 --start-sequence 20 --tx-count 1 --batch-size 1
```

注意：第一版 `bidl_consensus.py` 不是完整 BFT 共识节点，只是把收到的 leader 事务转换为 commit/result 流量；`bidl_execution.py` 也只做 digest 级别的推测执行校验。

### Ethernet 目的地址

主机侧发送脚本默认不再使用二层广播 MAC。`consensus_header.py` 会根据发送接口 MAC 自动推导当前 host 的网关 MAC：

```text
08:00:00:00:01:11 -> 08:00:00:00:01:00
08:00:00:00:02:22 -> 08:00:00:00:02:00
```

这和 `single_switch.json` 中每个 host 的静态 ARP 网关配置一致。也就是说，应用层仍然可以对多个目标 IP 做 fan-out，但每个包在二层都是发往本机网关 MAC，而不是 `ff:ff:ff:ff:ff:ff`。

如果后续换拓扑，可以用各发送脚本的 `--dst-mac` 手动覆盖。

## 当前状态

当前已经完成：

```text
P4 头部定义
P4 parser
IPv4 LPM 正常转发
P4 checksum 更新
P4 deparser
三主机单交换机拓扑
P4Runtime runtime 表项
交换机 register 保存历史 digest
相同 view/sequence 但 digest 不同的冲突检测
duplicate / conflict / reorder 风险等级判断
基于风险等级改写 IORS msg_flags 和 IPv4 DSCP
Scapy BFT/IORS header
单包发送脚本
收包打印脚本
重复/冲突/乱序流量生成脚本
轻量 PBFT 阶段流量脚本
BIDL leader / consensus / execution / malicious 四类节点脚本
```

当前尚未完成：

```text
基于风险等级 drop / clone / priority queue
控制面接收疑似冲突事件
实验结果分析脚本
Mininet 端到端实际验收记录
```

## 当前风险检测逻辑

风险检测逻辑主要在：

```text
consensus/iors/p4src/iors.p4
```

当前使用两组 register。

第一组按具体共识实例记录 digest：

```p4
register<bit<1>>(N) seen_reg;
register<bit<32>>(N) key_tag_reg;
register<bit<32>>(N) digest_reg;
```

key 由以下字段 hash 得到：

```text
(sender, view, sequence, msg_type)
```

检测逻辑是：

```text
如果第一次见到:
  写入 digest
  risk = normal

如果再次见到且 digest 相同:
  risk = duplicate

如果再次见到但 digest 不同:
  risk = conflict

如果 hash/tag 不匹配:
  risk = unknown
```

第二组按发送者和消息类型记录最大 sequence：

```p4
register<bit<1>>(N) order_seen_reg;
register<bit<32>>(N) order_key_tag_reg;
register<bit<32>>(N) max_sequence_reg;
```

key 由以下字段 hash 得到：

```text
(sender, view, msg_type)
```

检测逻辑是：

```text
如果第一次见到:
  写入当前 sequence 作为最大 sequence

如果 sequence 小于已记录最大 sequence:
  risk = unknown/reorder

如果 sequence 大于已记录最大 sequence:
  更新最大 sequence
```

当前标记策略：

```text
risk = normal
  正常转发，DSCP = 0

risk = duplicate
  设置 IORS duplicate flag，DSCP = 10

risk = conflict
  设置 IORS conflict flag，DSCP = 46

risk = reorder / unknown
  设置 IORS reorder 或 unknown flag，DSCP = 8
```

## 后续扩展位置

后续更强的调度和控制面联动仍然主要修改：

```text
consensus/iors/p4src/iors.p4
consensus/iors/runtime/s1-runtime.json
consensus/iors/control/
```

可以继续加入：

```text
risk_policy table
priority queue
drop
clone to controller
counter
controller event logging
```

主机侧已有的 `attack_sender.py` 可以直接用于验证这些逻辑。
