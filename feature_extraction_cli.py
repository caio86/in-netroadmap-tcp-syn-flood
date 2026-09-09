#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Extract TCP/IP packet features from a PCAP file and save them to CSV.

Example:
    python feature_extraction_cli.py \
        --input-pcap capture.pcap \
        --output-csv features.csv \
        --attacker-ip 10.0.0.11 \
        --attacker-ip 10.0.0.12
"""

import argparse
import csv
import sys
from pathlib import Path

from scapy.all import PcapReader


# Stores the timestamp of the previous packet seen for each flow.
flow_table = {}


def classify(srcip, attackers):
    """
    Classify a packet based on its source IP.

    Classification:
        1 = attacker
        0 = benign

    Source/destination ports are intentionally not used for classification.
    """
    return 1 if srcip in attackers else 0


def get_tcp(packet):
    """Extract TCP features from a TCP layer."""
    sport = packet.sport
    dport = packet.dport
    seq = packet.seq
    ack = packet.ack
    window = packet.window
    dataofs = packet.dataofs
    urgptr = packet.urgptr
    reserved = packet.reserved
    tcp_chk = packet.chksum

    return sport, dport, [
        seq,
        ack,
        window,
        dataofs,
        urgptr,
        reserved,
        tcp_chk,
    ]


def get_ip(packet):
    """Extract IP and TCP features and calculate the flow key."""
    src = packet.src
    dst = packet.dst
    proto = packet.proto
    version = packet.version
    ihl = packet.ihl
    tos = packet.tos
    length = packet.len
    ip_id = packet.id
    frag = packet.frag
    ttl = packet.ttl
    chksum = packet.chksum

    if proto == 6:  # TCP
        sport, dport, tcp = get_tcp(packet.payload)
        flow_key = [src, dst, sport, dport, proto]
    else:
        raise ValueError("Not a TCP packet.")

    return (
        hash(tuple(flow_key)),
        flow_key
        + [
            version,
            ihl,
            tos,
            length,
            ip_id,
            frag,
            ttl,
            chksum,
        ]
        + tcp,
    )


def get_features(packet):
    """Extract all features for one packet."""
    try:
        flow_key, tcpip = get_ip(packet.payload)

        src = packet.src
        dst = packet.dst
        typ = packet.type
        frame_size = len(packet)

        timestamp_us = int(packet.time * 1e6)

        if flow_key not in flow_table:
            flow_table[flow_key] = timestamp_us

        ipi = timestamp_us - flow_table[flow_key]
        flow_table[flow_key] = timestamp_us

    except Exception as exc:
        raise ValueError(str(exc)) from exc

    return [flow_key] + tcpip + [src, dst, typ, ipi, frame_size]


def process_pcap(file_path, writer, attackers, verbose=False):
    """Read a PCAP file and write extracted features to CSV."""
    print(f"Reading: {file_path}")

    processed = 0
    skipped = 0
    ipv6_skipped = 0

    with PcapReader(str(file_path)) as reader:
        for packet_number, packet in enumerate(reader, start=1):
            try:
                (
                    flow_key,
                    srcip,
                    dstip,
                    sport,
                    dport,
                    proto,
                    version,
                    ihl,
                    tos,
                    length,
                    ip_id,
                    frag,
                    ttl,
                    chksum,
                    seq,
                    ack,
                    window,
                    dataofs,
                    urgptr,
                    reserved,
                    tcp_chk,
                    srcmac,
                    dstmac,
                    typ,
                    ipi,
                    frame_size,
                ) = get_features(packet)

                features = [
                    flow_key,
                    srcip,
                    dstip,
                    sport,
                    dport,
                    proto,
                    version,
                    ihl,
                    tos,
                    length,
                    ip_id,
                    frag,
                    ttl,
                    chksum,
                    seq,
                    ack,
                    window,
                    dataofs,
                    urgptr,
                    reserved,
                    tcp_chk,
                    srcmac,
                    dstmac,
                    typ,
                    ipi,
                    frame_size,
                ]

            except Exception as exc:
                skipped += 1

                if verbose:
                    print(
                        f"Skipping packet {packet_number}: {exc}",
                        file=sys.stderr,
                    )
                    print(packet, file=sys.stderr)

                continue

            # Preserve the original behavior of ignoring IPv6 packets.
            if typ == "IPV6":
                ipv6_skipped += 1
                continue

            classification = classify(srcip, attackers)
            writer.writerow(features + [classification])
            processed += 1

    print(f"Finished reading: {file_path}")
    print(f"Processed packets: {processed}")
    print(f"Skipped packets:   {skipped}")
    print(f"IPv6 packets:      {ipv6_skipped}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract TCP/IP features from a PCAP file into a CSV file."
    )

    parser.add_argument(
        "-i",
        "--input-pcap",
        type=Path,
        required=True,
        help="Path to the input PCAP file.",
    )

    parser.add_argument(
        "-o",
        "--output-csv",
        type=Path,
        required=True,
        help="Path to the output CSV file.",
    )

    parser.add_argument(
        "-a",
        "--attacker-ip",
        dest="attacker_ips",
        action="append",
        default=[],
        help=(
            "Attacker source IP address. Can be specified multiple times. "
            "Example: --attacker-ip 10.0.0.11 --attacker-ip 10.0.0.12"
        ),
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print details about packets that cannot be processed.",
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting an existing output CSV.",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    input_pcap = args.input_pcap.expanduser().resolve()
    output_csv = args.output_csv.expanduser().resolve()

    if not input_pcap.is_file():
        print(
            f"Error: input PCAP does not exist: {input_pcap}",
            file=sys.stderr,
        )
        return 1

    if output_csv.exists() and not args.overwrite:
        print(
            f"Error: output file already exists: {output_csv}\n"
            "Use --overwrite to replace it.",
            file=sys.stderr,
        )
        return 1

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    # Reset state in case main() is called more than once.
    flow_table.clear()

    headers = [
        "flow_key",
        "srcip",
        "dstip",
        "sport",
        "dport",
        "proto",
        "version",
        "ihl",
        "tos",
        "length",
        "id",
        "frag",
        "ttl",
        "chksum",
        "seq",
        "ack",
        "window",
        "dataofs",
        "urgptr",
        "reserved",
        "tcp_chk",
        "srcmac",
        "dstmac",
        "typ",
        "ipi",
        "frame_size",
        "classification",
    ]

    attackers = set(args.attacker_ips)

    print("Starting PCAP processing")
    print(f"Input:     {input_pcap}")
    print(f"Output:    {output_csv}")
    print(f"Attackers: {', '.join(sorted(attackers)) or 'none'}")

    try:
        with output_csv.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(headers)

            process_pcap(
                input_pcap,
                writer,
                attackers,
                verbose=args.verbose,
            )

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except PermissionError as exc:
        print(f"Permission error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        return 1

    print(f"CSV written to: {output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
