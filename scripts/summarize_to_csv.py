# -*- coding: utf-8 -*-
"""Builds the F1/F2/F3 per-cell summary CSVs from the per-observation
CSVs in results/raw (completes the six-CSV summary set).

Pure deterministic aggregation: F1 = median + quartiles over the 50 obs
per cell; F2 = mean over 3 seeds x 30 reps; F3 = mean over 5 seeds.
F4/F5 CSVs are written directly by their own experiment scripts; F6 is
a JSON size check.
"""
import csv
import os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RAW = os.path.join(ROOT, "results", "raw")
SUM = os.path.join(ROOT, "results", "summary")


def rows(name):
    with open(os.path.join(RAW, name), encoding="utf-8") as f:
        r = list(csv.reader(f))
    return r[0], r[1:]


def q(xs, k):
    xs = sorted(xs)
    return xs[min(k, len(xs) - 1)]


# F1: op,F,n_obs,median_ms,q1_ms,q3_ms  (KEYGEN rows have F=0)
hdr, rs = rows("f1_fig2_qprss_raw.csv")
cells = defaultdict(list)
for r in rs:
    if r[3] == "formal":
        cells[(r[0], int(r[1]))].append(float(r[4]))
with open(os.path.join(SUM, "f1_fig2_qprss_summary.csv"), "w", newline="",
          encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["op", "F", "n_obs", "median_ms", "q1_ms", "q3_ms"])
    for (op, F), v in sorted(cells.items(), key=lambda x: (x[0][0], x[0][1])):
        w.writerow([op, F, len(v), f"{q(v, len(v) // 2):.3f}",
                    f"{q(v, len(v) // 4):.3f}", f"{q(v, 3 * len(v) // 4):.3f}"])

# F2: n,op,n_obs,mean_ms
hdr, rs = rows("f2_fig3a_fhir_raw.csv")
cells = defaultdict(list)
for r in rs:
    cells[(int(r[0]), r[3])].append(float(r[4]))
with open(os.path.join(SUM, "f2_fig3a_fhir_summary.csv"), "w", newline="",
          encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["n", "op", "n_obs", "mean_ms"])
    for (n, op), v in sorted(cells.items()):
        w.writerow([n, op, len(v), f"{sum(v) / len(v):.3f}"])

# F3: n,op,t,n_seeds,mean_ms
hdr, rs = rows("f3_fig3bc_multihop_raw.csv")
cells = defaultdict(list)
for r in rs:
    cells[(int(r[0]), r[3], int(r[2]))].append(float(r[4]))
with open(os.path.join(SUM, "f3_fig3bc_multihop_summary.csv"), "w", newline="",
          encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["n", "op", "t", "n_seeds", "mean_ms"])
    for (n, op, t), v in sorted(cells.items()):
        w.writerow([n, op, t, len(v), f"{sum(v) / len(v):.3f}"])

print("SUMMARY_CSV_DONE ->", SUM)
