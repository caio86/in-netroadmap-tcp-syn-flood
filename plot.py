#!/usr/bin/env python3
import argparse
import glob
import os
import re

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

HOSTNAME_RE = re.compile(r"web-.+-(.+)\.csv$")
EVENT_RE = re.compile(r"\[synflood\]\s*([A-Za-z_]+)\s*,\s*(\d+(?:\.\d+)?)")


def load_csv(path):
    df = pd.read_csv(path, skiprows=1, names=["timestamp", "http_status", "time_total"])

    df['time_total'] = df['time_total'] * 1000
    df["host"] = hostname_from_path(path)

    return df

def load_all_csvs(logdir, pattern):
    paths = sorted(glob.glob(os.path.join(logdir, pattern)))
    if not paths:
        raise SystemExit(f"No files matched {pattern} in {logdir}")

    data = [ load_csv(p) for p in paths]
    df = pd.concat(data, ignore_index=True)
    df["dt"] = pd.to_datetime(df["timestamp"], unit="s")

    return df


def hostname_from_path(path):
    m = HOSTNAME_RE.search(os.path.basename(path))
    return m.group(1) if m else os.path.splitext(os.path.basename(path))[0]


def load_attack_start(path):
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        for line in f:
            m = EVENT_RE.search(line)
            if m and m.group(1) == "Start":
                return float(m.group(2))
    return None


def stat_per_second(df):
    grouped = df.set_index("dt").groupby(pd.Grouper(freq="1s"))
    result = grouped.agg(
        n=("time_total", "count"),
        mean=("time_total", "mean"),
        median=("time_total", "median"),
        p95=("time_total", lambda s: s.quantile(0.95))
    )

    result = result[result["n"] > 0].reset_index().rename(columns={"dt": "timestamp"})
    result["timestamp"] = result["timestamp"].astype("int64") // 10**9

    return result

def process(label, logdir, pattern, attacker_log):
    df = load_all_csvs(logdir, pattern)
    stats = stat_per_second(df)
    attack_start = load_attack_start(attacker_log)

    stats["t_rel"] = stats["timestamp"] - stats["timestamp"].min()

    if attack_start is not None:
        stats["t_rel_at"] = stats["timestamp"] - attack_start

    return df, stats, attack_start


def plot_ecdf(df, df_ml, out_path="ecdf.png"):
    plt.figure(dpi=300)

    df["ML Usage"] = "Without ML"
    df_ml["ML Usage"] = "With ML"

    data = pd.concat([df, df_ml])

    sns.ecdfplot(
        data=data,
        x="time_total",
        hue="ML Usage",
        legend="brief",
    )

    plt.ylabel("Proportion")
    plt.xlabel("Request Latency (s)")
    plt.tight_layout()
    plt.grid(alpha=0.3)
    plt.savefig(f"{out_path}")


def plot(df, df_at_start, df_ml, df_ml_at_start, out_path="plot.png"):
    fig, ax = plt.subplots(figsize=(11, 6))

    rel_df_at_start = df_at_start - df["timestamp"].min()
    rel_df_ml_at_start = df_ml_at_start - df_ml["timestamp"].min()

    ax.axvline(rel_df_at_start, color="black", linestyle="--", linewidth=1.5)
    ax.axvline(rel_df_ml_at_start, color="black", linestyle="--", linewidth=1.5)

    ax.plot(df["t_rel"], df["mean"], markersize=3,
            linewidth=1, label="Without ML")

    ax.plot(df_ml["t_rel"], df_ml["mean"], markersize=3,
            linewidth=1, label="With ML")

    ylim = ax.get_ylim()
    ax.text(rel_df_at_start, ylim[1] * 0.97, f" Attack start", rotation=90,
                va="top", ha="left", fontsize=9)
    # ax.text(rel_df_ml_at_start, ylim[1] * 0.97, f" Attack start", rotation=90,
                # va="top", ha="left", fontsize=9)

    ax.set_xlabel("Time since experiment start (s)")
    ax.set_ylabel("Request latency (ms)")
    ax.set_title("LOREM IPSUM")
    ax.grid(True, alpha=0.3)

    ax.legend(loc="upper left", fontsize=8, ncol=2)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    print(f"Saved plot to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Plot client latency vs SYN flood timeline")
    parser.add_argument("--logdir", default=".", help="Directory containing web-*.csv logs")
    parser.add_argument("--logdir-ml", default=".", help="Directory containing web-*.csv logs")
    parser.add_argument("--pattern", default="web-*.csv", help="Glob pattern for client CSVs")
    parser.add_argument("--attacker-log", default=None, help="Path to attacker.log")
    parser.add_argument("--out", default="results.png", help="Output image path")
    args = parser.parse_args()

    base_attacker_log = os.path.join(args.logdir, "attacker.log")
    ml_attacker_log = os.path.join(args.logdir_ml, "attacker.log")

    base_raw, base_stats, base_start = process("base", args.logdir, args.pattern, base_attacker_log)
    ml_raw, ml_stats, ml_start = process("ml", args.logdir_ml, args.pattern, ml_attacker_log)


    plot_ecdf(base_raw, ml_raw, "/tmp/ecdf.png")

    plot(base_stats, base_start, ml_stats, ml_start, "/tmp/plot.png")


if __name__ == "__main__":
    main()
