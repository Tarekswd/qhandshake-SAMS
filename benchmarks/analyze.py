"""Summarise raw qh-bench CSV output. Stdlib only for statistics; matplotlib optional for the plot.

Usage: python benchmarks/analyze.py <raw.csv> <out_dir>
Writes <out_dir>/summary.md (and handshake_latency.png if matplotlib is installed).
95% CI of the mean uses the normal approximation (mean +/- 1.96*s/sqrt(n)); valid for the n>=500
runs produced by benchmarks/run.sh, stated so nobody mistakes it for a t-interval.
"""
import csv
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path


def pct(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def describe(xs):
    n, m, s = len(xs), st.fmean(xs), st.stdev(xs)
    h = 1.96 * s / n**0.5
    return dict(n=n, mean=m, median=st.median(xs), sd=s, ci=(m - h, m + h), p5=pct(xs, 5), p95=pct(xs, 95), p99=pct(xs, 99))


def main(raw, out):
    rows = list(csv.DictReader(open(raw, newline="")))
    data = defaultdict(lambda: defaultdict(list))
    bytes_ = {}
    for r in rows:
        key = (r["mode"], r["group"])
        for col in ("client_ns", "server_ns", "total_ns"):
            if r[col]:
                data[key][col].append(int(r[col]) / 1000)  # -> microseconds
        if r["c2s_bytes"]:
            bytes_[r["group"]] = (int(r["c2s_bytes"]), int(r["s2c_bytes"]))

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    lines = [f"# QHandshake benchmark summary\n\nSource: `{Path(raw).name}` (raw rows: {len(rows)}). All times in microseconds (us).\n"]
    lines.append("## Wire bytes per handshake (measured, deterministic)\n\n| group | client->server | server->client | total |\n|---|---|---|---|")
    for g, (a, b) in bytes_.items():
        lines.append(f"| {g} | {a} | {b} | {a + b} |")
    for mode, title in (("primitive", "Single primitive operations (attribution)"), ("inproc", "In-process CPU time (no network)"),("tcp", "Loopback TCP: connect() to first echoed app byte")):
        lines.append(f"\n## {title}\n\n| group | metric | n | mean | median | sd | 95% CI mean | p5 | p95 | p99 |\n|---|---|---|---|---|---|---|---|---|---|")
        for (m, g), cols in data.items():
            if m != mode:
                continue
            for col, xs in cols.items():
                d = describe(xs)
                lines.append(
                    f"| {g} | {col.removesuffix('_ns')} | {d['n']} | {d['mean']:.1f} | {d['median']:.1f} | {d['sd']:.1f} | "
                    f"[{d['ci'][0]:.1f}, {d['ci'][1]:.1f}] | {d['p5']:.1f} | {d['p95']:.1f} | {d['p99']:.1f} |"
                )
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    print((out / "summary.md").read_text())

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plot")
        return
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, mode, title in zip(axes, ("inproc", "tcp"), ("In-process total CPU", "Loopback TCP time-to-first-byte")):
        groups = [g for (m, g) in data if m == mode]
        ax.boxplot([data[(mode, g)]["total_ns"] for g in groups], showfliers=False)
        ax.set_xticks(range(1, len(groups) + 1), groups, fontsize=8)
        ax.set_title(title)
        ax.set_ylabel("microseconds (measured)")
        ax.grid(axis="y", alpha=0.3)
    fig.suptitle("QHandshake: X25519 vs ML-KEM-768 vs hybrid (outliers hidden; see summary.md for p99)")
    fig.tight_layout()
    fig.savefig(out / "handshake_latency.png", dpi=130)
    print(f"wrote {out / 'handshake_latency.png'}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
