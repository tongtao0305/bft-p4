#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import time

from scapy.all import sendp

from consensus_header import (
    BROADCAST_RECEIVER,
    FLAG_ATTACK,
    FLAG_CONFLICT,
    FLAG_DUPLICATE,
    build_consensus_packet,
    digest32,
    get_if,
)


def parse_args():
    parser = argparse.ArgumentParser(description="Generate duplicate/conflict/reorder consensus traffic.")
    parser.add_argument("destination", help="Destination host name or IPv4 address")
    parser.add_argument("--scenario", choices=["normal", "duplicate", "conflict", "reorder"],
                        default="conflict")
    parser.add_argument("--sender", type=int, default=1)
    parser.add_argument("--receiver", type=int, default=BROADCAST_RECEIVER)
    parser.add_argument("--leader", type=int, default=0)
    parser.add_argument("--epoch", type=int, default=0)
    parser.add_argument("--view", type=int, default=0)
    parser.add_argument("--sequence", type=int, default=10)
    parser.add_argument("--msg-type", default="prepare")
    parser.add_argument("--iface")
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--show", action="store_true")
    return parser.parse_args()


def make_packets(args, iface):
    base = {
        "iface": iface,
        "msg_type": args.msg_type,
        "sender": args.sender,
        "receiver": args.receiver,
        "leader": args.leader,
        "epoch": args.epoch,
        "view": args.view,
    }

    if args.scenario == "normal":
        return [
            build_consensus_packet(args.destination, "normal-a", sequence=args.sequence, **base),
            build_consensus_packet(args.destination, "normal-b", sequence=args.sequence + 1, **base),
        ]

    if args.scenario == "duplicate":
        payload = "duplicate-payload"
        curr_digest = digest32(payload)
        return [
            build_consensus_packet(
                args.destination, payload, sequence=args.sequence,
                msg_flags=FLAG_ATTACK | FLAG_DUPLICATE, curr_digest=curr_digest, **base
            ),
            build_consensus_packet(
                args.destination, payload, sequence=args.sequence,
                msg_flags=FLAG_ATTACK | FLAG_DUPLICATE, curr_digest=curr_digest, **base
            ),
        ]

    if args.scenario == "conflict":
        return [
            build_consensus_packet(
                args.destination, "conflict-value-a", sequence=args.sequence,
                msg_flags=FLAG_ATTACK | FLAG_CONFLICT, **base
            ),
            build_consensus_packet(
                args.destination, "conflict-value-b", sequence=args.sequence,
                msg_flags=FLAG_ATTACK | FLAG_CONFLICT, **base
            ),
        ]

    return [
        build_consensus_packet(args.destination, "reorder-later", sequence=args.sequence + 1, **base),
        build_consensus_packet(args.destination, "reorder-earlier", sequence=args.sequence, **base),
    ]


def main():
    args = parse_args()
    iface = args.iface or get_if()
    packets = make_packets(args, iface)

    print(f"sending {args.scenario} scenario on {iface} to {args.destination}")
    for pkt in packets:
        if args.show:
            pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
