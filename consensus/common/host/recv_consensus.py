#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys

from scapy.all import sniff

from consensus_header import CONSENSUS_UDP_PORT, IORS, describe_iors


def default_iface():
    for iface in os.listdir("/sys/class/net/"):
        if "eth" in iface:
            return iface
    raise RuntimeError("Cannot find eth interface")


def parse_args():
    parser = argparse.ArgumentParser(description="Receive and print consensus/IORS packets.")
    parser.add_argument("--iface", help="Network interface, defaults to first eth interface")
    parser.add_argument("--count", type=int, default=0,
                        help="Number of packets to capture, 0 means forever")
    return parser.parse_args()


def handle_pkt(pkt):
    if IORS not in pkt:
        return
    info = describe_iors(pkt)
    print(
        "IORS "
        f"{info['src']} -> {info['dst']} "
        f"type={info['msg_type']} sender={info['sender']} receiver={info['receiver']} "
        f"leader={info['leader']} epoch={info['epoch']} view={info['view']} "
        f"seq={info['sequence']} prev={info['prev_digest']} curr={info['curr_digest']} "
        f"flags=0x{info['flags']:02x} dscp={info['dscp']} ecn={info['ecn']} "
        f"payload={info['payload']!r}"
    )
    sys.stdout.flush()


def main():
    args = parse_args()
    iface = args.iface or default_iface()
    print(f"sniffing consensus packets on {iface}")
    sys.stdout.flush()
    sniff(
        iface=iface,
        filter=f"udp port {CONSENSUS_UDP_PORT}",
        prn=handle_pkt,
        count=args.count,
    )


if __name__ == "__main__":
    main()
