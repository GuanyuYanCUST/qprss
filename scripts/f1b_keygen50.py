# -*- coding: utf-8 -*-
"""F1b = KeyGen 50-independent-session benchmark (Fig. 2a QPRSS arm).

Unifies the KeyGen repetition count with the other four Fig. 2 operations
(50 formal observations). Methodology is IDENTICAL to the archived F1 run
(results/formal_2026-11-01), which used 30 sessions:

  measured object : the B1-65 signer-role module-lattice keygen
                    (s5_sig.core("B1").keygen) — RA keygen excluded, exactly
                    as in F1;
  timing          : time.perf_counter_ns() around the single keygen call,
                    reported in ms;
  sessions        : one keygen per session with a per-session XOF seed
                    (FixedXofRng, fresh key material each session; all
                    public keys asserted pairwise distinct);
  warmup          : none (the F1 KeyGen regime had no warmup);
  statistics      : median is the reported metric (paper convention), with
                    mean/min/max/std/Q1/Q3/IQR recorded;
  fail-closed     : any size/assert failure aborts; no sample is dropped,
                    no outlier removal, raw observations all saved.

This is a COMPLETE new 50-session experiment (seed family "PA|F1|kg50|"),
not an append of 20 sessions to the archived 30. The archived
30-session data is kept untouched under results/formal_2026-11-01/.

Outputs (repo results/):
  keygen_50_raw.csv                 per-session observations (+ key digest)
  keygen_50_summary.csv             summary statistics
  keygen_30_vs_50_comparison.csv    old (archived 30) vs new (50) comparison

Run: python -I scripts/f1b_keygen50.py
"""
import csv
import hashlib
import io
import json
import os
import platform
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "run", "fixed_run"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_sig, s4compat as s4c                # noqa: E402

B1 = s5_sig.core("B1")
SESSIONS = 50
SEED_FAMILY = b"PA|F1|kg50|"        # new family: disjoint from F1's "PA|F1|kg|"
OLD_RAW = os.path.join(ROOT, "results", "formal_2026-11-01", "raw",
                       "f1_fig2_qprss_raw.csv")


def git_head():
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, cwd=ROOT
                              ).stdout.strip()
    except Exception:                                     # noqa: BLE001
        return "unavailable"


def run_sessions():
    rows, pks = [], []
    for i in range(SESSIONS):
        t0 = time.perf_counter_ns()
        sk, pk = B1.keygen(rng=s4c.FixedXofRng(
            SEED_FAMILY + i.to_bytes(4, "big")))
        el = (time.perf_counter_ns() - t0) / 1e6
        assert len(pk) == 3712 and len(sk) == 672, (i, len(pk), len(sk))
        rows.append([i, el, len(pk),
                     hashlib.sha256(pk).hexdigest()[:16]])
        pks.append(pk)
    assert len(set(pks)) == SESSIONS, "key material not independent"
    return rows


def stats_of(xs):
    xs = sorted(xs)
    n = len(xs)
    q1 = statistics.quantiles(xs, n=4, method="inclusive")[0]
    q3 = statistics.quantiles(xs, n=4, method="inclusive")[2]
    return dict(N=n, median_ms=round(statistics.median(xs), 4),
                mean_ms=round(statistics.mean(xs), 4),
                min_ms=round(xs[0], 4), max_ms=round(xs[-1], 4),
                std_ms=round(statistics.stdev(xs), 4),
                q1_ms=round(q1, 4), q3_ms=round(q3, 4),
                iqr_ms=round(q3 - q1, 4))


def old_keygen_rows():
    """Exact archived 30-session observations (B-class, never modified)."""
    out = []
    with io.open(OLD_RAW, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["op"] == "KEYGEN":
                out.append(float(r["ms"]))
    return out


def main():
    t0 = time.time()
    rows = run_sessions()
    xs = [r[1] for r in rows]
    new = stats_of(xs)

    out = os.path.join(ROOT, "results")
    with io.open(os.path.join(out, "keygen_50_raw.csv"), "w", newline="",
                 encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["session", "ms", "pk_bytes", "pk_sha256_16"])
        w.writerows(rows)
    with io.open(os.path.join(out, "keygen_50_summary.csv"), "w", newline="",
                 encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(list(new))
        w.writerow(list(new.values()))

    old_xs = old_keygen_rows()
    old = stats_of(old_xs) if old_xs else None
    with io.open(os.path.join(out, "keygen_30_vs_50_comparison.csv"), "w",
                 newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["metric", "archived_2026-11-01_n30", "new_n50"])
        if old:
            for k in new:
                w.writerow([k, old[k], new[k]])

    env = dict(cpu=platform.processor(), machine=platform.machine(),
               os=platform.platform(), python=platform.python_version(),
               numpy=__import__("numpy").__version__,
               git_head=git_head(), script="scripts/f1b_keygen50.py",
               ts=time.strftime("%Y-%m-%dT%H:%M:%S"),
               warmup_sessions=0, formal_sessions=SESSIONS,
               timing="time.perf_counter_ns around one B1-65 keygen call "
                      "(signer role, RA excluded)",
               seed_family=SEED_FAMILY.decode())
    with io.open(os.path.join(out, "keygen_50_summary.json"), "w",
                 encoding="utf-8") as f:
        json.dump(dict(environment=env, stats=new,
                       archived_n30_reference=old), f,
                  ensure_ascii=False, indent=1)

    print(f"KeyGen 50 sessions: median {new['median_ms']} ms "
          f"(mean {new['mean_ms']}, min {new['min_ms']}, max {new['max_ms']},"
          f" std {new['std_ms']}, IQR {new['iqr_ms']})")
    if old:
        print(f"archived 30 sessions: median {old['median_ms']} ms, "
              f"IQR {old['iqr_ms']} (reference only)")
    print(f"F1B_DONE elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
