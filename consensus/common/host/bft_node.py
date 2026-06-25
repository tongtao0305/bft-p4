#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import time

from scapy.all import sendp

from consensus_header import (
    BROADCAST_RECEIVER,
    build_consensus_packet,
    get_if,
)


PHASES = {
    "client": ["request"],
    "primary": ["pre-prepare"],
    "replica": ["prepare", "commit"],
    "full-demo": ["request", "pre-prepare", "prepare", "commit", "reply"],
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate lightweight PBFT-style phase traffic."
    )
    parser.add_argument("destination", help="Destination host name or IPv4 address")
    parser.add_argument("--role", choices=sorted(PHASES), default="full-demo")
    parser.add_argument("--node-id", type=int, default=1)
    parser.add_argument("--receiver", type=int, default=BROADCAST_RECEIVER)
    parser.add_argument("--leader", type=int, default=0)
    parser.add_argument("--epoch", type=int, default=0)
    parser.add_argument("--view", type=int, default=0)
    parser.add_argument("--sequence", type=int, default=1)
    parser.add_argument("--payload", default="operation")
    parser.add_argument("--iface")
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--show", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    iface = args.iface or get_if()
    phases = PHASES[args.role]

    print(f"sending PBFT-style {args.role} phases on {iface} to {args.destination}")
    for phase in phases:
        payload = f"{args.payload}:{phase}:seq={args.sequence}"
        pkt = build_consensus_packet(
            args.destination,
            payload,
            iface=iface,
            msg_type=phase,
            sender=args.node_id,
            receiver=args.receiver,
            leader=args.leader,
            epoch=args.epoch,
            view=args.view,
            sequence=args.sequence,
        )
        if args.show:
            pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
