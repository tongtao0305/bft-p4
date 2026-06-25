#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import time

from scapy.all import sendp

from consensus_header import BROADCAST_RECEIVER, build_consensus_packet, digest32, get_if


def receiver_id_from_ip(dst):
    try:
        return int(dst.split(".")[-1])
    except ValueError:
        return BROADCAST_RECEIVER


def parse_args():
    parser = argparse.ArgumentParser(description="BIDL leader: assign sequence numbers and fan out unicast transactions.")
    parser.add_argument("--destinations", default="10.0.2.2,10.0.3.3",
                        help="Comma-separated consensus/execution destination IPs")
    parser.add_argument("--leader-id", type=int, default=1)
    parser.add_argument("--view", type=int, default=0)
    parser.add_argument("--start-sequence", type=int, default=1)
    parser.add_argument("--tx-count", "--count", dest="tx_count", type=int, default=1,
                        help="Total number of transactions to send")
    parser.add_argument("--batch-size", type=int, default=1,
                        help="Number of consecutive transactions per batch")
    parser.add_argument("--tx-rate", type=float,
                        help="Transaction rate in transactions per second; overrides --interval")
    parser.add_argument("--payload-prefix", default="tx")
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--iface")
    parser.add_argument("--dst-mac",
                        help="Ethernet destination MAC, defaults to this host's gateway MAC")
    parser.add_argument("--show", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    iface = args.iface or get_if()
    destinations = [dst.strip() for dst in args.destinations.split(",") if dst.strip()]
    interval = (1.0 / args.tx_rate) if args.tx_rate and args.tx_rate > 0 else args.interval

    print(
        f"bidl_leader sending {args.tx_count} transaction(s) "
        f"batch_size={args.batch_size} interval={interval:.6f}s "
        f"via unicast fan-out to {destinations} on {iface}"
    )
    for offset in range(args.tx_count):
        sequence = args.start_sequence + offset
        batch_id = offset // args.batch_size
        batch_offset = offset % args.batch_size
        payload = (
            f"{args.payload_prefix}-{sequence}|"
            f"batch={batch_id}|batch_size={args.batch_size}|batch_offset={batch_offset}"
        )
        curr_digest = digest32(payload)

        for dst in destinations:
            pkt = build_consensus_packet(
                dst,
                payload,
                iface=iface,
                dst_mac=args.dst_mac,
                msg_type="pre-prepare",
                sender=args.leader_id,
                receiver=receiver_id_from_ip(dst),
                leader=args.leader_id,
                view=args.view,
                sequence=sequence,
                curr_digest=curr_digest,
            )
            if args.show:
                pkt.show2()
            sendp(pkt, iface=iface, verbose=False)
            print(
                f"leader tx seq={sequence} batch={batch_id} "
                f"offset={batch_offset}/{args.batch_size} digest=0x{curr_digest:08x} -> {dst}"
            )
        if interval > 0:
            time.sleep(interval)


if __name__ == "__main__":
    main()
