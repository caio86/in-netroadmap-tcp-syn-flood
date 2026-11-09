#!/usr/bin/env python3

import argparse
import random
import socket
import struct
import sys
from time import sleep

from scapy.all import (
    IP,
    UDP,
    BitField,
    Ether,
    FieldLenField,
    IntField,
    Packet,
    PacketListField,
    Raw,
    ShortField,
    XByteField,
    bind_layers,
    get_if_hwaddr,
    sendp,
    sniff,
)


class InBandNetworkTelemetry(Packet):
    fields_desc = [
        BitField("switchID_t", 0, 31),
        BitField("ingress_port", 0, 9),
        BitField("egress_port", 0, 9),
        BitField("egress_spec", 0, 9),
        BitField("ingress_global_timestamp", 0, 48),
        BitField("egress_global_timestamp", 0, 48),
        BitField("enq_timestamp", 0, 32),
        BitField("enq_qdepth", 0, 19),
        BitField("deq_timedelta", 0, 32),
        BitField("deq_qdepth", 0, 19),
    ]

    def extract_padding(self, s):
        return b"", s


class nodeCount(Packet):
    name = "nodeCount"
    fields_desc = [
        ShortField("count", 0),
        PacketListField(
            "INT", [], InBandNetworkTelemetry, count_from=lambda pkt: (pkt.count * 1)
        ),
    ]


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-i", "--interface", default="eth1", help="Network interface to sniff"
    )

    args = parser.parse_args()

    addr = socket.gethostbyname(args.target)
    iface = args.interface

    bind_layers(IP, nodeCount, proto=253)
    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
        / IP(dst=addr, proto=253)
        / nodeCount(count=0, INT=[])
    )

    # sendp(pkt, iface=iface)
    # pkt.show2()

    qtd = 0
    try:
        while True:
            sendp(pkt, iface=iface, verbose=False)
            qtd += 1
            # pkt.show2()
            # sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        print("Packets sent:", qtd)


if __name__ == "__main__":
    main()
