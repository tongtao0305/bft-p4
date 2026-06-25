#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys

from scapy.all import sniff

from consensus_header import BFT, MSG_COMMIT, MSG_PRE_PREPARE, batch_digest32, describe_iors, digest32


def default_iface():
    for iface in os.listdir("/sys/class/net/"):
        if "eth" in iface:
            return iface
    raise RuntimeError("Cannot find eth interface")


def parse_args():
    parser = argparse.ArgumentParser(description="BIDL execution node: speculative execution plus commit validation.")
    parser.add_argument("--node-id", type=int, default=3)
    parser.add_argument("--count", type=int, default=0,
                        help="Number of BFT packets to consume, 0 means forever")
    parser.add_argument("--iface")
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
    speculative = {}

    print(f"bidl_execution listening on {iface}")
    sys.stdout.flush()

    def handle(pkt):
        if BFT not in pkt:
            return
        bft = pkt[BFT]
        info = describe_iors(pkt)

        if bft.msg_type == MSG_PRE_PREPARE:
            batch_id = int(payload_field(info["payload"], "batch", bft.sequence))
            batch_size = int(payload_field(info["payload"], "batch_size", 1))
            key = (bft.view, batch_id)
            speculative[key] = speculative.get(key, {})
            speculative[key][bft.sequence] = {
                "digest": bft.curr_digest,
                "payload": info["payload"],
                "risk_flags": bft.msg_flags,
                "dscp": info["dscp"],
            }
            print(
                "execution speculative "
                f"batch={batch_id} seq={bft.sequence} digest=0x{bft.curr_digest:08x} "
                f"flags=0x{bft.msg_flags:02x} dscp={info['dscp']} payload={info['payload']!r}"
            )
        elif bft.msg_type == MSG_COMMIT:
            batch_id = int(payload_field(info["payload"], "batch", bft.sequence))
            first_sequence = int(payload_field(info["payload"], "first", bft.sequence))
            last_sequence = int(payload_field(info["payload"], "last", bft.sequence))
            key = (bft.view, batch_id)
            batch_state = speculative.get(key, {})
            missing = [sequence for sequence in range(first_sequence, last_sequence + 1)
                       if sequence not in batch_state]
            if missing:
                print(
                    "execution re_execute "
                    f"batch={batch_id} reason=missing speculative seqs={missing} "
                    f"commit_digest=0x{bft.curr_digest:08x}"
                )
            else:
                ordered_digests = [batch_state[sequence]["digest"]
                                   for sequence in range(first_sequence, last_sequence + 1)]
                speculative_digest = batch_digest32(ordered_digests)
                risk_flags = 0
                max_dscp = 0
                for sequence in range(first_sequence, last_sequence + 1):
                    risk_flags |= batch_state[sequence]["risk_flags"]
                    max_dscp = max(max_dscp, batch_state[sequence]["dscp"])
                if speculative_digest == bft.curr_digest:
                    print(
                        "execution commit "
                        f"batch={batch_id} seqs={first_sequence}-{last_sequence} "
                        f"digest=0x{bft.curr_digest:08x} "
                        f"spec_flags=0x{risk_flags:02x} max_dscp={max_dscp}"
                    )
                else:
                    corrected_result = digest32(f"reexec:{bft.curr_digest}")
                    print(
                        "execution re_execute "
                        f"batch={batch_id} seqs={first_sequence}-{last_sequence} "
                        f"speculative=0x{speculative_digest:08x} "
                        f"commit=0x{bft.curr_digest:08x} corrected=0x{corrected_result:08x}"
                    )
            if not missing and key in speculative:
                del speculative[key]
        sys.stdout.flush()

    sniff(iface=iface, filter="udp port 5000", prn=handle, count=args.count)


if __name__ == "__main__":
    main()
