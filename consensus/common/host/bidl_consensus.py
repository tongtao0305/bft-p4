#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys
import time

from scapy.all import IP, Raw, sendp, sniff

from consensus_header import BFT, MSG_COMMIT, MSG_PRE_PREPARE, batch_digest32, build_consensus_packet, describe_iors


def receiver_id_from_ip(dst):
    try:
        return int(dst.split(".")[-1])
    except ValueError:
        return 0xFFFF


def default_iface():
    for iface in os.listdir("/sys/class/net/"):
        if "eth" in iface:
            return iface
    raise RuntimeError("Cannot find eth interface")


def parse_args():
    parser = argparse.ArgumentParser(description="BIDL consensus node: receive leader transactions and emit commit results.")
    parser.add_argument("--execution-dest", default="10.0.3.3")
    parser.add_argument("--node-id", type=int, default=2)
    parser.add_argument("--leader-id", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=1,
                        help="Send one commit result after this many leader proposals")
    parser.add_argument("--commit-delay", type=float, default=0.2,
                        help="Small delay before sending commit so execution can receive leader proposal first")
    parser.add_argument("--count", type=int, default=0,
                        help="Debug limit for received proposal packets, 0 means run forever")
    parser.add_argument("--iface")
    parser.add_argument("--dst-mac",
                        help="Ethernet destination MAC, defaults to this host's gateway MAC")
    return parser.parse_args()


def payload_field(payload, name, default=None):
    prefix = f"{name}="
    for part in payload.split("|"):
        if part.startswith(prefix):
            return part[len(prefix):]
    return default


def main():
    args = parse_args()
    iface = args.iface or default_iface()
    pending = {}

    print(
        f"bidl_consensus online on {iface}, "
        f"batch_size={args.batch_size}, commit destination={args.execution_dest}"
    )
    sys.stdout.flush()

    def handle(pkt):
        if BFT not in pkt or pkt[BFT].msg_type != MSG_PRE_PREPARE:
            return
        bft = pkt[BFT]
        info = describe_iors(pkt)
        batch_id = int(payload_field(info["payload"], "batch", bft.sequence // args.batch_size))
        batch_size = int(payload_field(info["payload"], "batch_size", args.batch_size))
        key = (bft.view, batch_id)
        pending[key] = pending.get(key, {})
        pending[key][bft.sequence] = bft.curr_digest
        print(
            "consensus received "
            f"batch={batch_id} seq={bft.sequence} digest=0x{bft.curr_digest:08x} "
            f"flags=0x{bft.msg_flags:02x} dscp={info['dscp']} payload={info['payload']!r}"
        )

        if len(pending[key]) >= batch_size:
            if args.commit_delay > 0:
                time.sleep(args.commit_delay)
            ordered_sequences = sorted(pending[key])
            ordered_digests = [pending[key][sequence] for sequence in ordered_sequences]
            commit_digest = batch_digest32(ordered_digests)
            first_sequence = ordered_sequences[0]
            last_sequence = ordered_sequences[-1]
            commit_payload = (
                f"commit|batch={batch_id}|batch_size={batch_size}|"
                f"first={first_sequence}|last={last_sequence}|"
                f"digest=0x{commit_digest:08x}"
            )
            commit = build_consensus_packet(
                args.execution_dest,
                commit_payload,
                iface=iface,
                dst_mac=args.dst_mac,
                msg_type=MSG_COMMIT,
                sender=args.node_id,
                receiver=receiver_id_from_ip(args.execution_dest),
                leader=args.leader_id,
                view=bft.view,
                sequence=last_sequence,
                curr_digest=commit_digest,
            )
            sendp(commit, iface=iface, verbose=False)
            print(
                f"consensus committed batch={batch_id} "
                f"seqs={first_sequence}-{last_sequence} digest=0x{commit_digest:08x}"
            )
            del pending[key]
        sys.stdout.flush()

    sniff(iface=iface, filter="udp port 5000", prn=handle, count=args.count)


if __name__ == "__main__":
    main()
