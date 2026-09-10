#!/usr/bin/env python3
"""
Plot benign client web-latency logs against the SYN flood attack timeline.

Expects client logs named like: web-<timestamp>-<hostname>.csv
with rows of: <epoch_timestamp>,<http_status>,<time_total>
(the script ignores whatever the header row actually says and assigns
column names by position, so it works whether the header has 2 or 3 fields).

Expects an attacker log with lines like: [synflood] Start,<epoch_timestamp>
Any number of "[synflood] <Label>,<timestamp>" lines are picked up and drawn
as vertical markers (e.g. Start, Stop, Mitigation, ...) if you log more than
just the start.

Usage:
    python3 plot_experiment.py --logdir ./logs --attacker-log ./logs/attacker.log --out results.png
"""
import argparse
import glob
import os
import re

import matplotlib.pyplot as plt
import pandas as pd

HOSTNAME_RE = re.compile(r"web-.+-(.+)\.csv$")
EVENT_RE = re.compile(r"\[synflood\]\s*([A-Za-z_]+)\s*,\s*(\d+(?:\.\d+)?)")


def load_client_csv(path):
    """
    Reads a client CSV, skipping the header row and assigning column names
    by position: [timestamp, http_status, time_total]. This is robust
    whether the header text matches (3 columns) or is the older 2-column
    version -- either way the data rows themselves have 3 fields.
    """
    df = pd.read_csv(path, skiprows=1, names=["timestamp", "http_status", "time_total"])
    return df.sort_values("timestamp").reset_index(drop=True)


def hostname_from_path(path):
    m = HOSTNAME_RE.search(os.path.basename(path))
    return m.group(1) if m else os.path.splitext(os.path.basename(path))[0]


def load_attack_events(path):
    """Returns {event_label: epoch_timestamp} parsed from the attacker log."""
    events = {}
    if not path or not os.path.exists(path):
        return events
    with open(path) as f:
        for line in f:
            m = EVENT_RE.search(line)
            if m:
                events[m.group(1)] = float(m.group(2))
    return events


def plot(client_data, attack_events, out_path, title):
    for df in client_data.values():
        df['time_total'] = df['time_total'] * 1000

    t0 = min(df["timestamp"].min() for df in client_data.values())

    fig, ax = plt.subplots(figsize=(11, 6))

    failed_label_used = False
    for host in sorted(client_data):
        df = client_data[host]
        rel_t = df["timestamp"] - t0
        ax.plot(rel_t, df["time_total"], marker="o", markersize=3,
                linewidth=1, label=host)

        failed = df[df["http_status"] != 200]
        if not failed.empty:
            ax.scatter(failed["timestamp"] - t0, failed["time_total"],
                       color="red", zorder=5, s=45, marker="x",
                       label=None if failed_label_used else "Failed request")
            failed_label_used = True

    for label, ts in attack_events.items():
        rel_ts = ts - t0
        ax.axvline(rel_ts, color="black", linestyle="--", linewidth=1.5)

    ax.set_xlabel("Time since experiment start (s)")
    ax.set_ylabel("Request latency (ms)")
    ax.set_title(title)
    ax.grid(True, alpha=0.3)

    # Add event text labels after autoscaling so they sit at the top of the
    # final y-range instead of an intermediate one.
    ylim = ax.get_ylim()
    for label, ts in attack_events.items():
        rel_ts = ts - t0
        ax.text(rel_ts, ylim[1] * 0.97, f" {label}", rotation=90,
                va="top", ha="left", fontsize=9)

    ax.legend(loc="upper left", fontsize=8, ncol=2)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    print(f"Saved plot to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Plot client latency vs SYN flood timeline")
    parser.add_argument("--logdir", default=".", help="Directory containing web-*.csv logs")
    parser.add_argument("--pattern", default="web-*.csv", help="Glob pattern for client CSVs")
    parser.add_argument("--attacker-log", default="attacker.log", help="Path to attacker.log")
    parser.add_argument("--out", default="results.png", help="Output image path")
    parser.add_argument("--title", default="Client-observed web latency during SYN flood experiment")
    args = parser.parse_args()

    csv_paths = sorted(glob.glob(os.path.join(args.logdir, args.pattern)))
    if not csv_paths:
        raise SystemExit(f"No files matched {args.pattern} in {args.logdir}")

    client_data = {hostname_from_path(p): load_client_csv(p) for p in csv_paths}
    attack_events = load_attack_events(args.attacker_log)

    plot(client_data, attack_events, args.out, args.title)


if __name__ == "__main__":
    main()