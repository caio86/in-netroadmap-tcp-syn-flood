#!/usr/bin/env python3
"""Receive BMv2 mirrored classification packets and write packet labels to CSV."""

import argparse
import csv
import ipaddress
import signal
import sys
from collections import Counter
from pathlib import Path

from scapy.all import (
    ByteField,
    Ether,
    IntField,
    Packet,
    XShortField,
    bind_layers,
    conf,
    sniff,
)

TYPE_MIRROR = 0x88B5
TYPE_IPV4 = 0x0800


class MirrorHdr(Packet):
    """Must match the 7-byte mirror_h header in decision_tree.p4."""

    name = "MirrorHdr"
    fields_desc = [
        IntField("srcAddr", 0),  # P4 ip4Addr_v: 32-bit IPv4 source address
        ByteField("result", 0),  # P4 bit<8>: classification result (0 or 1)
        XShortField("next_type", TYPE_IPV4),
    ]


def load_malicious_networks(path):
    """Load IPv4 addresses/CIDRs. Blank lines and comments are ignored."""
    exact_ips = set()
    networks = []

    with open(path, "r", encoding="utf-8") as ip_file:
        for line_number, raw_line in enumerate(ip_file, start=1):
            entry = raw_line.split("#", 1)[0].strip()
            if not entry:
                continue

            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid IP/CIDR on line {line_number} of {path}: {entry!r}"
                ) from exc

            if network.version != 4:
                raise ValueError(
                    f"Only IPv4 entries are supported ({path}:{line_number}): {entry}"
                )

            if network.prefixlen == 32:
                exact_ips.add(network.network_address)
            else:
                networks.append(network)

    return exact_ips, networks


def is_malicious(src_ip, exact_ips, networks):
    """Return True when src_ip matches an exact address or a configured CIDR."""
    return src_ip in exact_ips or any(src_ip in network for network in networks)


def outcome_for(actual_class, predicted_class):
    """Return the binary confusion-matrix outcome."""
    if actual_class == 1 and predicted_class == 1:
        return "TP"
    if actual_class == 0 and predicted_class == 0:
        return "TN"
    if actual_class == 0 and predicted_class == 1:
        return "FP"
    return "FN"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--iface", default="mir0", help="BMv2 mirror interface")
    parser.add_argument(
        "-o",
        "--out",
        default="classifications.csv",
        help="CSV output file (appended to)",
    )
    parser.add_argument(
        "--malicious-ips",
        required=True,
        help="text file with one malicious IPv4 address or CIDR per line",
    )
    args = parser.parse_args()

    try:
        exact_ips, networks = load_malicious_networks(args.malicious_ips)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    bind_layers(Ether, MirrorHdr, type=TYPE_MIRROR)
    conf.sniff_promisc = True

    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not output_path.exists() or output_path.stat().st_size == 0

    counts = Counter()
    total = 0

    # newline="" is recommended by Python's csv module. Line buffering flushes
    # each packet row promptly, which is useful if the experiment is interrupted.
    with open(output_path, "a", newline="", encoding="utf-8", buffering=1) as out:
        writer = csv.writer(out)
        if needs_header:
            writer.writerow(
                [
                    "timestamp",
                    "src_ip",
                    "predicted_class",
                    "actual_class",
                    "outcome",
                ]
            )

        def on_packet(pkt):
            nonlocal total

            mirror = pkt.getlayer(MirrorHdr)
            if mirror is None:
                return

            # IntField decodes the 32-bit P4 address as an integer. Convert it
            # to dotted-decimal notation before looking it up or writing CSV.
            src_ip = ipaddress.IPv4Address(int(mirror.srcAddr))
            predicted_class = int(mirror.result)
            actual_class = int(is_malicious(src_ip, exact_ips, networks))
            outcome = outcome_for(actual_class, predicted_class)

            writer.writerow(
                [
                    f"{float(pkt.time):.6f}",
                    str(src_ip),
                    predicted_class,
                    actual_class,
                    outcome,
                ]
            )

            counts[outcome] += 1
            total += 1

        def stop(*_):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, stop)

        try:
            sniff(
                iface=args.iface,
                prn=on_packet,
                store=False,
                lfilter=lambda pkt: pkt.haslayer(Ether) and pkt.type == TYPE_MIRROR,
            )
        except KeyboardInterrupt:
            pass

    summary = ", ".join(f"{name}: {counts[name]}" for name in ("TP", "TN", "FP", "FN"))
    print(f"Captured {total} mirrored classified packets ({summary})", file=sys.stderr)


if __name__ == "__main__":
    main()
