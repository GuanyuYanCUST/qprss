# -*- coding: utf-8 -*-
"""F2 = Fig. 3(a) HL7 FHIR prototype: fields n=3..12, sign/verify time.

Regime: 3 seeds x 30 formal reps each, aggregated by mean (same regime
as the reference scheme's evaluation). ver=2 general encoding (explicit
M={1}; W={2..n} is non-empty for n>=3). Synthetic medical fields
(attr_j=A;val_j=V + SHAKE padding, exactly 32 B, same recipe as F1).
"""
import csv
import hashlib
import json
import os
import platform
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "run", "fixed_run"))

from s6t64 import canon                                   # noqa: E402
from s6t64 import policy as pol                          # noqa: E402
from s6t64 import s5_qprss as Q                          # noqa: E402
from s6t64 import s5_sig, s4compat as s4c                # noqa: E402

B1 = s5_sig.core("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
SEEDS = [1, 2, 3]
REPS = 30
WARMUP = 5
N_GRID = list(range(3, 13))
V2 = pol.POL_VER_GENERAL


def fields_for(n, seed):
    out = []
    for j in range(1, n + 1):
        core = f"attr_{j}=A;val_{j}=V".encode()
        pad = hashlib.shake_256(f"{seed}|{j}".encode()).digest(32)
        out.append((core + pad)[:32])
    return out


def world(n, seed):
    sdp = f"PA|F2|n{n}|s{seed}".encode()
    pp = Q.setup("B1", seed=sdp + b"|pp", pol_ver=V2)
    ra = Q.RA("B1")
    ra.sk, ra.pk = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg-ra"))
    sk_s, pk_s = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg0"))
    cert_s = ra.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID,), b"*"),
                      0, 1 << 62)
    ys = {k: v for k, v in enumerate(fields_for(n, seed), start=1)}
    sdig = canon.schema_digest(
        [(k, ("Patient", f"attr{k}"), "str") for k in range(1, n + 1)])
    P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, n + 1)), n, n,
                    m=frozenset({1}), ver=V2)
    vcfg = {"pk_ra": ra.pk}
    return pp, sk_s, cert_s, ys, P0, sdig, vcfg


def main():
    raw_path = os.path.join(ROOT, "results", "raw", "f2_fig3a_fhir_raw.csv")
    sum_path = os.path.join(ROOT, "results", "summary", "f2_fig3a_fhir_summary.json")
    os.makedirs(os.path.dirname(raw_path), exist_ok=True)
    rows = []
    print("== F2 Fig3(a) FHIR n=3..12, 3 seeds x 30 reps ==")
    for n in N_GRID:
        acc_sign, acc_verify = [], []
        for seed in SEEDS:
            pp, sk_s, cert_s, ys, P0, sdig, vcfg = world(n, seed)
            for rep in range(WARMUP + REPS):
                phase = "warmup" if rep < WARMUP else "formal"
                gsb = f"{seed}|{rep}".encode()
                t0 = time.perf_counter_ns()
                S = Q.signing(pp, sk_s, cert_s, RID, ys, P0,
                              rng=Q.make_rng(gsb + b"|sg"), schema_digest=sdig,
                              sig_rng=s4c.FixedXofRng(gsb + b"|sg0"))
                el_s = (time.perf_counter_ns() - t0) / 1e6
                assert Q.verify(vcfg, S, "hist"), (n, seed, rep)
                t0 = time.perf_counter_ns()
                ok = Q.verify(vcfg, S, "hist")
                el_v = (time.perf_counter_ns() - t0) / 1e6
                assert ok
                if phase == "formal":
                    acc_sign.append(el_s)
                    acc_verify.append(el_v)
                    rows.append([n, seed, rep, "sign", el_s])
                    rows.append([n, seed, rep, "verify", el_v])
        mean_s = sum(acc_sign) / len(acc_sign)
        mean_v = sum(acc_verify) / len(acc_verify)
        print(f"  n={n:2d}  sign mean {mean_s:7.3f} ms   verify mean {mean_v:7.3f} ms"
              f"   (3x30=90 obs/op)")
        rows_summary_note = None
    with open(raw_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["n", "seed", "rep", "op", "ms"])
        w.writerows(rows)
    cells = {}
    for n in N_GRID:
        for op in ("sign", "verify"):
            obs = [r[4] for r in rows if r[0] == n and r[3] == op]
            cells[f"{op}|n{n}"] = dict(mean_ms=round(sum(obs) / len(obs), 4),
                                       min_ms=round(min(obs), 4),
                                       max_ms=round(max(obs), 4), n_obs=len(obs))
    summary = dict(environment=dict(python=platform.python_version(),
                                    processor=platform.processor(),
                                    ts=time.strftime("%Y-%m-%dT%H:%M:%S")),
                   regime="3 seeds x 30 formal reps, mean aggregation",
                   cells=cells,
                   notes=["ver=2 general policy encoding (explicit M={1})",
                          "fields are synthetic 32 B FHIR records",
                          "no outlier removal; per-observation correctness "
                          "checks are fail-closed"])
    with open(sum_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print(f"\nF2_DONE raw={raw_path}\n      summary={sum_path}")


if __name__ == "__main__":
    main()
