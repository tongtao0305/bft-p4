#ifndef CONSENSUS_CONSTANTS_P4
#define CONSENSUS_CONSTANTS_P4

// Ethernet types
const bit<16> TYPE_IPV4 = 0x0800;

// IPv4 protocol numbers
const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;

// 共识数据包的固定端口号
const bit<16> CONSENSUS_UDP_PORT = 5000;

// Message Types 数据包类型，包括 REQUEST / PREPREPARE / PREPARE / COMMIT / REPLY / VIEWCHANGE
const bit<8> MSG_REQUEST = 1;
const bit<8> MSG_PRE_PREPARE = 2;
const bit<8> MSG_PREPARE = 3;
const bit<8> MSG_COMMIT = 4;
const bit<8> MSG_REPLY = 5;

// Risk Levels 数据包冲突风险，包括 无风险 / 正常数据包 / 重复数据包 / 冲突数据包 / 未知风险
const bit<8> RISK_NONE = 0;
const bit<8> RISK_NORMAL = 1;
const bit<8> RISK_DUPLICATE = 2;
const bit<8> RISK_CONFLICT = 3;
const bit<8> RISK_UNKNOWN = 4;

// BFT flags written by the data plane. Keep these aligned with
// consensus/common/host/consensus_header.py.
const bit<8> BFT_FLAG_DUPLICATE = 4;
const bit<8> BFT_FLAG_CONFLICT = 8;
const bit<8> BFT_FLAG_UNKNOWN = 16;
const bit<8> BFT_FLAG_REORDER = 32;

// DSCP values used as visible risk markers at receivers.
const bit<6> DSCP_NORMAL = 0;
const bit<6> DSCP_DUPLICATE = 10;
const bit<6> DSCP_CONFLICT = 46;
const bit<6> DSCP_UNKNOWN = 8;

// Number of state slots used by the in-switch IORS digest cache.
#define CONSENSUS_STATE_ENTRIES 65536

/* Common typedefs */
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> l4Port_t;
typedef bit<64> digestHalf_t;
typedef bit<32> view_t;
typedef bit<64> seq_t;
typedef bit<16> replicaId_t;

#endif
