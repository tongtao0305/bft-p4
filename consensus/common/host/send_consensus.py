#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse

from scapy.all import sendp

from consensus_header import (
    BROADCAST_RECEIVER,
    CONSENSUS_UDP_PORT,
    FLAG_TEST,
    build_consensus_packet,
    get_if,
    parse_u32,
)


def parse_args():
    parser = argparse.ArgumentParser(description="Send one consensus/IORS packet.")
    parser.add_argument("destination", help="Destination host name or IPv4 address")
    parser.add_argument("--payload", default="hello", help="Payload bytes as text")
    parser.add_argument("--msg-type", default="request",
                        help="request, pre-prepare, prepare, commit, or reply")
    parser.add_argument("--sender", type=int, default=1)
    parser.add_argument("--receiver", type=int, default=BROADCAST_RECEIVER)
    parser.add_argument("--leader", type=int, default=0)
    parser.add_argument("--epoch", type=int, default=0)
    parser.add_argument("--view", type=int, default=0)
    parser.add_argument("--sequence", type=int, default=1)
    parser.add_argument("--prev-digest", default="0",
                        help="Previous digest as decimal or 0x-prefixed integer")
    parser.add_argument("--curr-digest",
                        help="Override current digest as decimal or 0x-prefixed integer")
    parser.add_argument("--sport", type=int)
    parser.add_argument("--dport", type=int, default=CONSENSUS_UDP_PORT)
    parser.add_argument("--dst-mac",
                        help="Ethernet destination MAC, defaults to this host's gateway MAC")
    parser.add_argument("--flags", type=int, default=FLAG_TEST)
    parser.add_argument("--iface", help="Network interface, defaults to first eth0")
    parser.add_argument("--show", action="store_true", help="Print packet details")
    return parser.parse_args()


def main():
    args = parse_args()
    iface = args.iface or get_if()
    curr_digest = parse_u32(args.curr_digest) if args.curr_digest is not None else None

    pkt = build_consensus_packet(
        args.destination,
        args.payload,
        iface=iface,
        dst_mac=args.dst_mac,
        sport=args.sport,
        dport=args.dport,
        msg_type=args.msg_type,
        msg_flags=args.flags,
        sender=args.sender,
        receiver=args.receiver,
        leader=args.leader,
        epoch=args.epoch,
        view=args.view,
        sequence=args.sequence,
        prev_digest=parse_u32(args.prev_digest),
        curr_digest=curr_digest,
    )

    print(f"sending consensus packet on {iface} to {args.destination}")
    if args.show:
        pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == "__main__":
    main()
