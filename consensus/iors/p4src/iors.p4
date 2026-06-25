// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "../../common/p4src/constants.p4"
#include "../../common/p4src/headers.p4"

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// pipeline 中可能解析到的头部集合
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    bft_t      bft;
}

// 交换机内部临时变量，不会出现在数据包里
struct metadata {
    bit<8> risk_level;              // 当前包风险等级
    bit<32> state_index;
    bit<32> key_tag;
    bit<1> seen;
    bit<32> stored_key_tag;
    bit<32> stored_digest;
    bit<32> order_index;
    bit<1> order_seen;
    bit<32> stored_max_sequence;    // 已经出现过的最大的序列号
}

/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            CONSENSUS_UDP_PORT: parse_bft;
            default: accept;
        }
    }

    state parse_bft {
        packet.extract(hdr.bft);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<1>>(CONSENSUS_STATE_ENTRIES) seen_reg;             // 是否第一次见到这个共识实例
    register<bit<32>>(CONSENSUS_STATE_ENTRIES) key_tag_reg;
    register<bit<32>>(CONSENSUS_STATE_ENTRIES) digest_reg;
    register<bit<1>>(CONSENSUS_STATE_ENTRIES) order_seen_reg;
    register<bit<32>>(CONSENSUS_STATE_ENTRIES) max_sequence_reg;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_bft_state_keys() {
        hash(meta.state_index,
             HashAlgorithm.crc32,
             (bit<32>)0,
             { hdr.bft.sender,
               hdr.bft.receiver,
               hdr.bft.view,
               hdr.bft.sequence,
               hdr.bft.msg_type },
             (bit<32>)CONSENSUS_STATE_ENTRIES);

        hash(meta.key_tag,
             HashAlgorithm.crc32,
             (bit<32>)0,
             { hdr.bft.sender,
               hdr.bft.receiver,
               hdr.bft.view,
               hdr.bft.sequence,
               hdr.bft.msg_type },
             (bit<32>)0xffffffff);
    }

    action compute_bft_order_keys() {
        hash(meta.order_index,
             HashAlgorithm.crc32,
             (bit<32>)0,
             { hdr.bft.sender,
               hdr.bft.receiver,
               hdr.bft.view,
               hdr.bft.msg_type },
             (bit<32>)CONSENSUS_STATE_ENTRIES);
    }

    action mark_risk(bit<8> risk, bit<8> flag, bit<6> dscp) {
        meta.risk_level = risk;
        hdr.bft.msg_flags = hdr.bft.msg_flags | flag;
        hdr.ipv4.diffserv[7:2] = dscp;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        meta.risk_level = RISK_NONE;

        if (hdr.bft.isValid()) {
            compute_bft_state_keys();
            compute_bft_order_keys();

            seen_reg.read(meta.seen, meta.state_index);
            key_tag_reg.read(meta.stored_key_tag, meta.state_index);
            digest_reg.read(meta.stored_digest, meta.state_index);

            if (meta.seen == 0) {
                seen_reg.write(meta.state_index, 1);
                key_tag_reg.write(meta.state_index, meta.key_tag);
                digest_reg.write(meta.state_index, hdr.bft.curr_digest);
                mark_risk(RISK_NORMAL, 0, DSCP_NORMAL);
            } else if (meta.stored_key_tag != meta.key_tag) {
                mark_risk(RISK_UNKNOWN, BFT_FLAG_UNKNOWN, DSCP_UNKNOWN);
            } else if (meta.stored_digest == hdr.bft.curr_digest) {
                mark_risk(RISK_DUPLICATE, BFT_FLAG_DUPLICATE, DSCP_DUPLICATE);
            } else {
                mark_risk(RISK_CONFLICT, BFT_FLAG_CONFLICT, DSCP_CONFLICT);
            }

            if (meta.risk_level == RISK_NORMAL) {
                order_seen_reg.read(meta.order_seen, meta.order_index);
                max_sequence_reg.read(meta.stored_max_sequence, meta.order_index);

                if (meta.order_seen == 0) {
                    order_seen_reg.write(meta.order_index, 1);
                    max_sequence_reg.write(meta.order_index, hdr.bft.sequence);
                } else if (hdr.bft.sequence < meta.stored_max_sequence) {
                    mark_risk(RISK_UNKNOWN, BFT_FLAG_REORDER, DSCP_UNKNOWN);
                } else if (hdr.bft.sequence > meta.stored_max_sequence) {
                    max_sequence_reg.write(meta.order_index, hdr.bft.sequence);
                }
            }
        }

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.bft);
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
