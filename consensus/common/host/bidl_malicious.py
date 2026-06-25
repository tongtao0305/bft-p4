#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys
import time

from scapy.all import Raw, sendp, sniff

from consensus_header import (
    BFT,
    FLAG_ATTACK,
    FLAG_CONFLICT,
    FLAG_DUPLICATE,
    FLAG_REORDER,
    build_consensus_packet,
    digest32,
    get_if,
)


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
    parser = argparse.ArgumentParser(description="BIDL malicious node: inject or mutate leader transactions.")
    parser.add_argument("--mode", choices=["active", "listen"], default="active")
    parser.add_argument("--attack", choices=["duplicate", "conflict", "reorder"], default="conflict")
    parser.add_argument("--destination", default="10.0.3.3",
                        help="Victim destination, usually execution or consensus node")
    parser.add_argument("--spoof-sender", type=int, default=1,
                        help="Sender id to write into forged packets; use leader id to emulate spoofing")
    parser.add_argument("--leader-id", type=int, default=1)
    parser.add_argument("--view", type=int, default=0)
    parser.add_argument("--sequence", type=int, default=10)
    parser.add_argument("--payload", default="malicious-tx")
    parser.add_argument("--iface")
    parser.add_argument("--dst-mac",
                        help="Ethernet destination MAC, defaults to this host's gateway MAC")
    parser.add_argument("--interval", type=float, default=0.2)
    parser.add_argument("--show", action="store_true")
    return parser.parse_args()


def send_attack(args, iface, *, sequence, payload, curr_digest=None, msg_type="pre-prepare"):
    if curr_digest is None:
        curr_digest = digest32(payload)
    pkt = build_consensus_packet(
        args.destination,
        payload,
        iface=iface,
        dst_mac=args.dst_mac,
        msg_type=msg_type,
        msg_flags=FLAG_ATTACK,
        sender=args.spoof_sender,
        receiver=receiver_id_from_ip(args.destination),
        leader=args.leader_id,
        view=args.view,
        sequence=sequence,
        curr_digest=curr_digest,
    )
    if args.show:
        pkt.show2()
    sendp(pkt, iface=iface, verbose=False)
    print(
        f"malicious sent attack={args.attack} seq={sequence} "
        f"digest=0x{curr_digest:08x} payload={payload!r} -> {args.destination}"
    )


def run_active(args, iface):
    if args.attack == "duplicate":
        digest = digest32(args.payload)
        send_attack(args, iface, sequence=args.sequence, payload=args.payload,
                    curr_digest=digest)
        time.sleep(args.interval)
        send_attack(args, iface, sequence=args.sequence, payload=args.payload,
                    curr_digest=digest)
    elif args.attack == "conflict":
        send_attack(args, iface, sequence=args.sequence,
                    payload=f"{args.payload}-a")
        time.sleep(args.interval)
        send_attack(args, iface, sequence=args.sequence,
                    payload=f"{args.payload}-b")
    else:
        send_attack(args, iface, sequence=args.sequence + 1,
                    payload=f"{args.payload}-later")
        time.sleep(args.interval)
        send_attack(args, iface, sequence=args.sequence,
                    payload=f"{args.payload}-earlier")


def run_listen(args, iface):
    print(f"malicious listening on {iface}, will mutate first observed leader transaction")
    sys.stdout.flush()
    done = {"sent": False}

    def handle(pkt):
        if done["sent"]:
            return
        if BFT not in pkt:
            return
        bft = pkt[BFT]
        if bft.sender != args.leader_id:
            return
        payload = bytes(pkt[Raw].load).decode("utf-8", errors="replace") if Raw in pkt else args.payload
        args.view = bft.view
        args.sequence = bft.sequence
        args.spoof_sender = bft.sender

        if args.attack == "duplicate":
            send_attack(args, iface, sequence=bft.sequence, payload=payload,
                        curr_digest=bft.curr_digest, msg_type=bft.msg_type)
        elif args.attack == "conflict":
            mutated = f"{payload}-tampered"
            send_attack(args, iface, sequence=bft.sequence, payload=mutated,
                        msg_type=bft.msg_type)
        else:
            mutated = f"{payload}-reordered"
            send_attack(args, iface, sequence=max(0, bft.sequence - 1), payload=mutated,
                        msg_type=bft.msg_type)
        done["sent"] = True
        sys.stdout.flush()

    sniff(iface=iface, filter="udp port 5000", prn=handle,
          stop_filter=lambda _pkt: done["sent"])


def main():
    args = parse_args()
    iface = args.iface or get_if()
    if args.mode == "active":
        run_active(args, iface)
    else:
        run_listen(args, iface)


if __name__ == "__main__":
    main()
