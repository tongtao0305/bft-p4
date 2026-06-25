#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys
import time

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
                        help="Debug limit for received BFT packets, 0 means run forever")
    parser.add_argument("--iface")
    parser.add_argument("--print-tx-latency", action="store_true",
                        help="Print one tx_latency line per committed transaction")
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
    committed_batches = 0
    committed_txs = 0
    first_speculative_time = None

    print(f"bidl_execution online on {iface}")
    sys.stdout.flush()

    def handle(pkt):
        nonlocal committed_batches, committed_txs, first_speculative_time
        if BFT not in pkt:
            return
        bft = pkt[BFT]
        info = describe_iors(pkt)

        if bft.msg_type == MSG_PRE_PREPARE:
            now = time.time()
            if first_speculative_time is None:
                first_speculative_time = now
            batch_id = int(payload_field(info["payload"], "batch", bft.sequence))
            batch_size = int(payload_field(info["payload"], "batch_size", 1))
            key = (bft.view, batch_id)
            speculative[key] = speculative.get(key, {})
            speculative[key][bft.sequence] = {
                "digest": bft.curr_digest,
                "payload": info["payload"],
                "risk_flags": bft.msg_flags,
                "dscp": info["dscp"],
                "spec_time": now,
            }
            print(
                "execution speculative "
                f"batch={batch_id} seq={bft.sequence} digest=0x{bft.curr_digest:08x} "
                f"flags=0x{bft.msg_flags:02x} dscp={info['dscp']} "
                f"spec_time={now:.6f} payload={info['payload']!r}"
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
                    commit_time = time.time()
                    batch_tx_count = last_sequence - first_sequence + 1
                    first_spec_time = min(batch_state[sequence]["spec_time"]
                                          for sequence in range(first_sequence, last_sequence + 1))
                    batch_latency_ms = (commit_time - first_spec_time) * 1000
                    batch_throughput = batch_tx_count / max(commit_time - first_spec_time, 1e-9)
                    committed_batches += 1
                    committed_txs += batch_tx_count
                    elapsed = max(commit_time - first_speculative_time, 1e-9)
                    throughput = committed_txs / elapsed
                    print(
                        "execution commit "
                        f"batch={batch_id} seqs={first_sequence}-{last_sequence} "
                        f"digest=0x{bft.curr_digest:08x} "
                        f"spec_flags=0x{risk_flags:02x} max_dscp={max_dscp} "
                        f"commit_time={commit_time:.6f} "
                        f"batch_latency_ms={batch_latency_ms:.3f} "
                        f"batch_throughput_tps={batch_throughput:.2f} "
                        f"committed_batches={committed_batches} "
                        f"committed_txs={committed_txs} "
                        f"throughput_tps={throughput:.2f}"
                    )
                    if args.print_tx_latency:
                        for sequence in range(first_sequence, last_sequence + 1):
                            spec_time = batch_state[sequence]["spec_time"]
                            tx_latency_ms = (commit_time - spec_time) * 1000
                            print(
                                "tx_latency "
                                f"batch={batch_id} seq={sequence} "
                                f"spec_time={spec_time:.6f} "
                                f"commit_time={commit_time:.6f} "
                                f"latency_ms={tx_latency_ms:.3f}"
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
