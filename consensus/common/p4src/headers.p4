// SPDX-License-Identifier: Apache-2.0

// Common packet headers used by consensus data-plane prototypes.
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    l4Port_t srcPort;
    l4Port_t dstPort;
    bit<16>  length_;
    bit<16>  checksum;
}

header bft_t {
    bit<16> magic;          // fixed magic number, e.g., 0x10A5
    bit<8>  msg_type;       // 数据包类型，包括 REQUEST / PREPREPARE / PREPARE / COMMIT / REPLY / VIEWCHANGE
    bit<8>  msg_flags;      // 数据包的风险类型，包括 duplicate/conflict/priority/attack/test 等标志
    bit<8>  msg_version;    // 数据包头部版本，BFT header version

    // 发送方和接收方信息
    bit<16> sender;         // 发送方节点编号
    bit<16> receiver;       // target replica id, 0xffff means broadcast/group
    bit<16> leader;         // primary / proposer / sequencer id

    // 数据包信息
    bit<16> epoch;          // epoch 编号
    bit<16> view;           // 视图编号
    bit<32> sequence;       // 事务序列号，预分配顺序编号
    bit<32> prev_digest;    // 前驱事务的摘要信息，可使用 hash
    bit<32> curr_digest;    // 当前事务的摘要信息，可使用 hash
}
