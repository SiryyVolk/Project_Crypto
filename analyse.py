"""CryptoBench analysis: raw.csv -> tables (CSV + Markdown) and plots (PNG).

usage: python analyse.py <run-directory> [label]
e.g.   python analyse.py results/run-1 "Usual machine"

Reads <run-directory>/raw.csv and writes everything into
<run-directory>/analysis/.

For each measurement (part, algorithm, operation, message_bytes) it drops
run 0 (the warm-up), then reports the median and the interquartile range
(Q3 - Q1, from statistics.quantiles with n=4) in milliseconds
"""

import csv
import math
import os
import statistics
import sys
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")  # draw to files, no window needed
import matplotlib.pyplot as plt

# Algorithms in the order of the brief's Tables 1 to 3
KEM_ALGORITHMS = [
    "RSA-OAEP-3072", "RSA-OAEP-7680",
    "ECDH-P-256", "ECDH-P-384", "ECDH-P-521",
    "X25519",
    "ML-KEM-768", "ML-KEM-1024",
]
SIGNATURE_ALGORITHMS = [
    "RSA-PSS-3072", "RSA-PSS-7680",
    "ECDSA-P-256", "ECDSA-P-384", "ECDSA-P-521",
    "Ed25519",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
]
AEAD_ALGORITHMS = [
    "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-GCM-SIV",
]
AEAD_LENGTHS = [64, 1024, 16384, 1048576]

KEM_OPS = ["keygen", "encapsulate", "decapsulate"]
SIGNATURE_OPS = ["keygen", "sign", "verify"]
AEAD_OPS = ["encrypt", "decrypt"]


def sig(x, n=3):
    """Format x to n significant figures without scientific notation."""
    if x == 0:
        return "0"
    digits = n - int(math.floor(math.log10(abs(x)))) - 1
    rounded = round(x, digits)
    if digits <= 0:
        return str(int(rounded))
    return f"{rounded:.{digits}f}"


def load(path):
    """Return {(part, algorithm, operation, message_bytes): {run: ns}}."""
    data = defaultdict(dict)
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            key = (row["part"], row["algorithm"], row["operation"],
                   int(row["message_bytes"]))
            data[key][int(row["run"])] = int(row["nanoseconds"])
    return data


def summarise(data):
    """Return {key: (median_ms, iqr_ms)} using runs 1.. (run 0 is the warm-up)."""
    stats = {}
    for key, runs in data.items():
        values = [ns for run, ns in sorted(runs.items()) if run != 0]
        expected = 20 if key[2] == "keygen" and key[1].startswith("RSA-") else 100
        if len(values) != expected:
            print(f"WARNING: {key} has {len(values)} measured runs, expected {expected}")
        if len(values) < 2:
            continue
        q1, _, q3 = statistics.quantiles(values, n=4)
        stats[key] = (statistics.median(values) / 1e6, (q3 - q1) / 1e6)
    return stats


def write_table(path_base, header, rows):
    """Write rows (lists of strings) as <path_base>.csv and <path_base>.md."""
    with open(path_base + ".csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    with open(path_base + ".md", "w") as f:
        f.write("| " + " | ".join(header) + " |\n")
        f.write("|" + "|".join(["---"] * len(header)) + "|\n")
        for row in rows:
            f.write("| " + " | ".join(row) + " |\n")
    print(f"\n{os.path.basename(path_base)}")
    print("  " + " | ".join(header))
    for row in rows:
        print("  " + " | ".join(row))


def op_table_and_plot(stats, part, algorithms, ops, out_dir, name, label):
    """Table + grouped log-scale bar plot for the kem and signature parts."""
    header = ["Algorithm"]
    for op in ops:
        header += [f"{op} median (ms)", f"{op} IQR (ms)"]

    rows = []
    medians = {}  # (algorithm, op) -> median in ms, for the plot
    for alg in algorithms:
        if (part, alg, ops[0], 0) not in stats:
            print(f"WARNING: no data for {alg}, skipping")
            continue
        row = [alg]
        for op in ops:
            median, iqr = stats[(part, alg, op, 0)]
            row += [sig(median), sig(iqr)]
            medians[(alg, op)] = median
        rows.append(row)
    write_table(os.path.join(out_dir, f"{name}_table"), header, rows)

    present = [r[0] for r in rows]
    n = len(ops)
    width = 0.8 / n
    fig, ax = plt.subplots(figsize=(11, 5))
    for j, op in enumerate(ops):
        xs = [i + (j - (n - 1) / 2) * width for i in range(len(present))]
        ax.bar(xs, [medians[(a, op)] for a in present], width, label=op)
    ax.set_yscale("log")
    ax.set_xticks(range(len(present)))
    ax.set_xticklabels(present, rotation=45, ha="right")
    ax.set_xlabel("Algorithm")
    ax.set_ylabel("Median time (ms)")
    ax.set_title(f"{name.upper() if name == 'kem' else 'Signatures'}: median time per operation ({label})")
    ax.grid(axis="y", which="major", alpha=0.4)
    ax.legend(title="Operation")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, f"{name}_plot.png"), dpi=200)
    plt.close(fig)


def aead_table_and_plot(stats, out_dir, label):
    """16-row table + log-log line plot of median encrypt time vs message length."""
    header = ["Algorithm", "Message length (B)",
              "encrypt median (ms)", "encrypt IQR (ms)",
              "decrypt median (ms)", "decrypt IQR (ms)"]
    rows = []
    encrypt_medians = {}  # algorithm -> list of (length, median)
    for alg in AEAD_ALGORITHMS:
        for length in AEAD_LENGTHS:
            if ("aead", alg, "encrypt", length) not in stats:
                print(f"WARNING: no data for {alg} at {length} B, skipping")
                continue
            enc_median, enc_iqr = stats[("aead", alg, "encrypt", length)]
            dec_median, dec_iqr = stats[("aead", alg, "decrypt", length)]
            rows.append([alg, str(length), sig(enc_median), sig(enc_iqr),
                         sig(dec_median), sig(dec_iqr)])
            encrypt_medians.setdefault(alg, []).append((length, enc_median))
    write_table(os.path.join(out_dir, "aead_table"), header, rows)

    fig, ax = plt.subplots(figsize=(8, 5))
    for alg, points in encrypt_medians.items():
        ax.plot([p[0] for p in points], [p[1] for p in points],
                marker="o", label=alg)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Message length (bytes)")
    ax.set_ylabel("Median encrypt time (ms)")
    ax.set_title(f"Authenticated encryption: median encrypt time ({label})")
    ax.grid(which="both", alpha=0.3)
    ax.legend(title="Algorithm")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "aead_plot.png"), dpi=200)
    plt.close(fig)


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit('usage: python analyse.py <run-directory> ["label"]')
    run_dir = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) == 3 else os.path.basename(os.path.normpath(run_dir))
    out_dir = os.path.join(run_dir, "analysis")
    os.makedirs(out_dir, exist_ok=True)

    stats = summarise(load(os.path.join(run_dir, "raw.csv")))

    op_table_and_plot(stats, "kem", KEM_ALGORITHMS, KEM_OPS, out_dir, "kem", label)
    op_table_and_plot(stats, "signature", SIGNATURE_ALGORITHMS, SIGNATURE_OPS,
                      out_dir, "signature", label)
    aead_table_and_plot(stats, out_dir, label)
    print(f"\nWrote tables and plots to {out_dir}")


if __name__ == "__main__":
    main()
