#!/usr/bin/env python3
import argparse
import glob
import os
import re

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# Color palette: ML uses vibrant pink; No-ML uses cyan.
COLOR_ML = "#FF0072"
COLOR_NO_ML = "#00B9F6"

PALETTE = {
    "With ML": COLOR_ML,
    "Without ML": COLOR_NO_ML,
}


HOSTNAME_RE = re.compile(r"web-.+-(.+)\.csv$")
EVENT_RE = re.compile(r"\[synflood\]\s*([A-Za-z_]+)\s*,\s*(\d+(?:\.\d+)?)")


def load_csv(path):
    df = pd.read_csv(path, skiprows=1, names=["timestamp", "http_status", "time_total"])

    df["time_total"] = df["time_total"] * 1000
    df["host"] = hostname_from_path(path)

    return df


def load_all_csvs(logdir, pattern):
    paths = sorted(glob.glob(os.path.join(logdir, pattern)))

    if not paths:
        raise Exception(f"No files matched {pattern} in {logdir}")

    data = [load_csv(p) for p in paths]
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
        p95=("time_total", lambda s: s.quantile(0.95)),
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


# ---------------------------------------------------------
# Gradient helper
# ---------------------------------------------------------


def add_right_gradient(ax, x, y, color, x_max, n_steps=40, base_alpha=0.25):
    alpha_step = base_alpha / n_steps

    for i in range(n_steps):
        frac = i / (n_steps - 1) if n_steps > 1 else 1

        x_bound = x_max - (x_max - x) * frac

        ax.fill_betweenx(y, x, x_bound, color=color, alpha=alpha_step, linewidth=0)


def add_bottom_gradient(ax, x, y, color, y_min=0, n_steps=40, base_alpha=0.25):
    alpha_step = base_alpha / n_steps

    for i in range(n_steps):
        frac = i / (n_steps - 1)

        y_bound = y_min + (y - y_min) * frac

        ax.fill_between(x, y_bound, y, color=color, alpha=alpha_step, linewidth=0)


# ---------------------------------------------------------
# ECDF Plot
# ---------------------------------------------------------


def plot_ecdf(df, df_ml, label, out_path="ecdf.png"):
    fig, ax = plt.subplots(dpi=300)

    data = pd.concat([df, df_ml], ignore_index=True)

    conditions = ["With ML", "Without ML"]

    valid_times = data["time_total"].dropna()

    x_max = valid_times.max() * 1.05 if not valid_times.empty else 1

    # Plot each ECDF explicitly so each condition receives
    # its fixed color.
    for condition in conditions:
        subset = data.loc[data[label] == condition, "time_total"].dropna()

        x = np.sort(subset.to_numpy())

        if x.size == 0:
            continue

        y = np.arange(1, x.size + 1) / x.size

        color = PALETTE[condition]

        ax.plot(x, y, color=color, linewidth=1.5, label=condition)

        add_right_gradient(ax, x, y, color, x_max)

    ax.set_xlim(right=x_max)
    ax.set_ylim(0, 1.02)

    ax.set_ylabel("Proportion")
    ax.set_xlabel("Request Latency (ms)")

    ax.grid(True, alpha=0.3)
    ax.set_axisbelow(True)

    ax.legend(title="Machine Learning Usage")

    fig.tight_layout()
    fig.savefig(out_path, dpi=300)

    plt.close(fig)


# ---------------------------------------------------------
# Box Plot
# ---------------------------------------------------------


def plot_box(df, df_ml, label, out_path="box.png"):
    fig, ax = plt.subplots(dpi=300)

    data = pd.concat([df, df_ml], ignore_index=True)

    conditions = ["With ML", "Without ML"]

    sns.boxplot(
        data=data,
        y="time_total",
        x=label,
        hue=label,
        order=conditions,
        hue_order=conditions,
        palette=PALETTE,
        legend=False,
        ax=ax,
    )

    ax.set_ylabel("Request Latency (ms)")
    ax.set_xlabel("Machine Learning Usage")

    ax.grid(axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    fig.tight_layout()
    fig.savefig(out_path, dpi=300)

    plt.close(fig)


# ---------------------------------------------------------
# Line Plot
# ---------------------------------------------------------


def plot_line(df, df_at_start, df_ml, df_ml_at_start, out_path="plot.png"):
    fig, ax = plt.subplots(figsize=(11, 6))

    rel_df_at_start = df_at_start - df["timestamp"].min()
    rel_df_ml_at_start = df_ml_at_start - df_ml["timestamp"].min()

    ax.axvline(rel_df_at_start, color="black", linestyle="--", linewidth=1.5)
    ax.axvline(rel_df_ml_at_start, color="black", linestyle="--", linewidth=1.5)

    # Without ML data
    x_no_ml = df["t_rel"].to_numpy()
    y_no_ml = df["mean"].rolling(3).mean().to_numpy()

    # With ML data
    x_ml = df_ml["t_rel"].to_numpy()
    y_ml = df_ml["mean"].rolling(3).mean().to_numpy()

    # Bottom gradient: Without ML
    add_bottom_gradient(ax, x_no_ml, y_no_ml, COLOR_NO_ML)

    # Bottom gradient: With ML
    add_bottom_gradient(ax, x_ml, y_ml, COLOR_ML)

    # Without ML
    ax.plot(
        df["t_rel"],
        df["mean"].rolling(3).mean(),
        color=COLOR_NO_ML,
        markersize=3,
        linewidth=1,
        label="Without ML",
    )

    # With ML
    ax.plot(
        df_ml["t_rel"],
        df_ml["mean"].rolling(3).mean(),
        color=COLOR_ML,
        markersize=3,
        linewidth=1,
        label="With ML",
    )

    ax.set_ylim(bottom=0)
    ylim = ax.get_ylim()

    ax.text(
        rel_df_at_start,
        ylim[1] * 0.97,
        " Attack start",
        rotation=90,
        va="top",
        ha="left",
        fontsize=9,
    )

    # ax.text(
    #     rel_df_ml_at_start,
    #     ylim[1] * 0.97,
    #     " Attack start",
    #     rotation=90,
    #     va="top",
    #     ha="left",
    #     fontsize=9
    # )

    ax.set_xlabel("Time since experiment start (s)")
    ax.set_ylabel("Request latency (ms)")

    ax.grid(True, alpha=0.3)

    ax.legend(title="Machine Learning Usage", loc="upper left", fontsize=8, ncol=2)

    fig.tight_layout()
    fig.savefig(out_path, dpi=300)

    print(f"Saved plot to {out_path}")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Plot client latency vs SYN flood timeline"
    )

    parser.add_argument(
        "--logdir", default=".", help="Directory containing web-*.csv logs"
    )

    parser.add_argument(
        "--logdir-ml", default=".", help="Directory containing web-*.csv logs"
    )

    parser.add_argument(
        "--pattern", default="web-*.csv", help="Glob pattern for client CSVs"
    )

    parser.add_argument("--attacker-log", default=None, help="Path to attacker.log")

    parser.add_argument("--out", default="results.png", help="Output image path")

    args = parser.parse_args()

    base_attacker_log = os.path.join(args.logdir, "attacker.log")

    ml_attacker_log = os.path.join(args.logdir_ml, "attacker.log")

    base_raw, base_stats, base_start = process(
        "base", args.logdir, args.pattern, base_attacker_log
    )

    ml_raw, ml_stats, ml_start = process(
        "ml", args.logdir_ml, args.pattern, ml_attacker_log
    )

    label = "Machine Learning Usage"

    base_raw[label] = "Without ML"
    ml_raw[label] = "With ML"

    plot_ecdf(base_raw, ml_raw, label, "/tmp/ecdf.png")

    plot_box(base_raw, ml_raw, label, "/tmp/box_plot.png")

    plot_line(base_stats, base_start, ml_stats, ml_start, "/tmp/plot.png")


if __name__ == "__main__":
    main()
