#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import hashlib
import random
import socket
import struct

from scapy.all import (
    ByteEnumField,
    ByteField,
    Ether,
    IP,
    Packet,
    ShortField,
    IntField,
    Raw,
    UDP,
    bind_layers,
    get_if_hwaddr,
    get_if_list,
)


CONSENSUS_UDP_PORT = 5000
IORS_MAGIC = 0x10A5
IORS_VERSION = 1
BROADCAST_RECEIVER = 0xFFFF

MSG_REQUEST = 1
MSG_PRE_PREPARE = 2
MSG_PREPARE = 3
MSG_COMMIT = 4
MSG_REPLY = 5

MSG_TYPES = {
    "request": MSG_REQUEST,
    "pre-prepare": MSG_PRE_PREPARE,
    "pre_prepare": MSG_PRE_PREPARE,
    "prepare": MSG_PREPARE,
    "commit": MSG_COMMIT,
    "reply": MSG_REPLY,
}

MSG_TYPE_NAMES = {
    MSG_REQUEST: "request",
    MSG_PRE_PREPARE: "pre-prepare",
    MSG_PREPARE: "prepare",
    MSG_COMMIT: "commit",
    MSG_REPLY: "reply",
}

FLAG_NONE = 0
FLAG_TEST = 1 << 0
FLAG_ATTACK = 1 << 1
FLAG_DUPLICATE = 1 << 2
FLAG_CONFLICT = 1 << 3
FLAG_UNKNOWN = 1 << 4
FLAG_REORDER = 1 << 5


class BFT(Packet):
    name = "BFT"
    fields_desc = [
        ShortField("magic", IORS_MAGIC),
        ByteEnumField("msg_type", MSG_REQUEST, MSG_TYPE_NAMES),
        ByteField("msg_flags", FLAG_NONE),
        ByteField("msg_version", IORS_VERSION),
        ShortField("sender", 0),
        ShortField("receiver", BROADCAST_RECEIVER),
        ShortField("leader", 0),
        ShortField("epoch", 0),
        ShortField("view", 0),
        IntField("sequence", 0),
        IntField("prev_digest", 0),
        IntField("curr_digest", 0),
    ]


IORS = BFT

bind_layers(UDP, BFT, dport=CONSENSUS_UDP_PORT)
bind_layers(BFT, Raw)


def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    raise RuntimeError("Cannot find eth0 interface")


def resolve_ip(host):
    return socket.gethostbyname(host)


def parse_msg_type(value):
    if isinstance(value, int):
        return value
    normalized = value.lower()
    if normalized not in MSG_TYPES:
        choices = ", ".join(sorted(MSG_TYPES))
        raise ValueError(f"unknown message type '{value}', expected one of: {choices}")
    return MSG_TYPES[normalized]


def digest32(payload):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return struct.unpack("!I", hashlib.sha256(payload).digest()[:4])[0]


def parse_u32(value):
    if isinstance(value, int):
        return value & 0xFFFFFFFF
    return int(value, 0) & 0xFFFFFFFF


def build_consensus_packet(
    dst_ip,
    payload,
    *,
    iface=None,
    dst_mac="ff:ff:ff:ff:ff:ff",
    sport=None,
    dport=CONSENSUS_UDP_PORT,
    msg_type=MSG_REQUEST,
    msg_flags=FLAG_NONE,
    sender=0,
    receiver=BROADCAST_RECEIVER,
    leader=0,
    epoch=0,
    view=0,
    sequence=0,
    prev_digest=0,
    curr_digest=None,
):
    if iface is None:
        iface = get_if()
    if sport is None:
        sport = random.randint(49152, 65535)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if curr_digest is None:
        curr_digest = digest32(payload)

    return (
        Ether(src=get_if_hwaddr(iface), dst=dst_mac)
        / IP(dst=resolve_ip(dst_ip))
        / UDP(sport=sport, dport=dport)
        / BFT(
            msg_type=parse_msg_type(msg_type),
            msg_flags=msg_flags,
            sender=sender,
            receiver=receiver,
            leader=leader,
            epoch=epoch,
            view=view,
            sequence=sequence,
            prev_digest=parse_u32(prev_digest),
            curr_digest=parse_u32(curr_digest),
        )
        / Raw(payload)
    )


def describe_iors(pkt):
    iors = pkt[IORS]
    ip = pkt[IP] if IP in pkt else None
    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    dscp = (ip.tos >> 2) if ip is not None else 0
    ecn = (ip.tos & 0x03) if ip is not None else 0

    return {
        "src": ip.src if ip is not None else "",
        "dst": ip.dst if ip is not None else "",
        "dscp": dscp,
        "ecn": ecn,
        "msg_type": MSG_TYPE_NAMES.get(iors.msg_type, str(iors.msg_type)),
        "flags": iors.msg_flags,
        "sender": iors.sender,
        "receiver": iors.receiver,
        "leader": iors.leader,
        "epoch": iors.epoch,
        "view": iors.view,
        "sequence": iors.sequence,
        "prev_digest": f"0x{iors.prev_digest:08x}",
        "curr_digest": f"0x{iors.curr_digest:08x}",
        "payload": payload.decode("utf-8", errors="replace"),
    }
