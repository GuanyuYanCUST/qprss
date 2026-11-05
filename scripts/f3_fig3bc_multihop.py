# -*- coding: utf-8 -*-
"""F3 = Fig. 3(b)(c) multi-hop scalability: n=64/102, t=0..40 continuous
redaction chain, 5 seeds.

- (b) single-hop Redact time vs t (includes the audit signature);
- (c) Verify time vs t - hist and fresh timed separately (per the
  experiment protocol; they must not be merged into one number).
  The fresh timing covers the RA response signature, its verification
  and the status check (the whole verify("fresh") call), but no real
  network round-trip (no network deployment; no end-to-end latency
  claim).
One continuous chain per seed: t=0 registers via register_initial, then
each hop redacts field 2+t and calls register (advancing the fresh
chain head), after which hist and fresh are each timed once.
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
NSEEDS, T_MAX = 5, 40
V2 = pol.POL_VER_GENERAL


def fields_for(n, seed):
    out = []
    for j in range(1, n + 1):
        core = f"attr_{j}=A;val_{j}=V".encode()
        pad = hashlib.shake_256(f"{seed}|{j}".encode()).digest(32)
        out.append((core + pad)[:32])
    return out


def world(n, seed):
    sdp = f"PA|F3|n{n}|s{seed}".encode()
    pp = Q.setup("B1", seed=sdp + b"|pp", pol_ver=V2)
    ra = Q.RA("B1")
    ra.sk, ra.pk = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg-ra"))
    sk_s, pk_s = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg0"))
    cert_s = ra.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID,), b"*"),
                      0, 1 << 62)
    sk_r, pk_r = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg1"))
    cert_r = ra.issue(b"\x01" * 16, pk_r, b"physician", ((RID,), b"*"),
                      0, 1 << 62)
    ys = {k: v for k, v in enumerate(fields_for(n, seed), start=1)}
    sdig = canon.schema_digest(
        [(k, ("Patient", f"attr{k}"), "str") for k in range(1, n + 1)])
    P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, n + 1)), n, n,
                    m=frozenset({1}), ver=V2)
    S = Q.signing(pp, sk_s, cert_s, RID, ys, P0, rng=Q.make_rng(sdp + b"|sg"),
                  schema_digest=sdig, sig_rng=s4c.FixedXofRng(sdp + b"|sg0"))
    vcfg = {"pk_ra": ra.pk}
    sig_init = B1.sign(sk_s, pk_s,
                       canon.M_reginit(RID, n, S.acc0, S.P0,
                                       canon.H(cert_s.msg), sd=sdig),
                       canon.CTX_REG, rng=s4c.FixedXofRng(sdp + b"|rg0"))
    ra.register_initial(S, cert_s, sig_init)
    return pp, ra, sk_s, cert_s, sk_r, cert_r, S, P0, vcfg


def main():
    raw_path = os.path.join(ROOT, "results", "raw", "f3_fig3bc_multihop_raw.csv")
    sum_path = os.path.join(ROOT, "results", "summary", "f3_fig3bc_multihop_summary.json")
    os.makedirs(os.path.dirname(raw_path), exist_ok=True)
    rows = []
    for n in (64, 102):
        for seed in range(1, NSEEDS + 1):
            pp, ra, sk_s, cert_s, sk_r, cert_r, S, P, vcfg = world(n, seed)
            rid_state = ra.reg[RID]
            # t=0: one formal timing each for hist/fresh
            t0 = time.perf_counter_ns()
            assert Q.verify(vcfg, S, "hist") == "accept_historical"
            th = (time.perf_counter_ns() - t0) / 1e6
            t0 = time.perf_counter_ns()
            assert Q.verify(vcfg, S, "fresh", ra=ra, nonce=b"\x33" * 32,
                            revsnap=ra.revocation_snapshot()) == "accept_fresh"
            tf = (time.perf_counter_ns() - t0) / 1e6
            rows.append([n, seed, 0, "verify_hist", th])
            rows.append([n, seed, 0, "verify_fresh", tf])
            print(f"n={n} seed={seed} t=0  hist {th:7.2f} ms  fresh {tf:7.2f} ms")
            for t in range(1, T_MAX + 1):
                j = t + 1                                   # delete fields 2,3,...,41
                keep = set(S.It) - {j}
                Pn = pol.Policy(P.adm, P.w, P.d - 1, n, m=P.M, ver=V2)
                t0 = time.perf_counter_ns()
                S = Q.redact(pp, S, keep, Pn, cert_r, sk_r, 10_000 + t,
                             sig_rng=s4c.FixedXofRng(
                                 f"PA|F3|n{n}|s{seed}|rd{t}".encode()))
                tr = (time.perf_counter_ns() - t0) / 1e6
                P = Pn
                rid_state = ra.reg[RID]
                m_reg = canon.M_reg(RID, rid_state["ver"], rid_state["h"],
                                    rid_state["ver"] + 1, S.h_t, len(S.log),
                                    canon.H(cert_r.msg), cert_r.id, cert_r.role)
                ra.register(S, B1.sign(sk_r, cert_r.pk, m_reg, canon.CTX_REG,
                                       rng=s4c.FixedXofRng(
                                           f"PA|F3|n{n}|s{seed}|rg{t}".encode())),
                            cert_r)
                t0 = time.perf_counter_ns()
                assert Q.verify(vcfg, S, "hist") == "accept_historical"
                th = (time.perf_counter_ns() - t0) / 1e6
                t0 = time.perf_counter_ns()
                assert Q.verify(vcfg, S, "fresh", ra=ra,
                                nonce=(seed.to_bytes(4, "big") + t.to_bytes(4, "big")
                                       + b"\x33" * 24),
                                revsnap=ra.revocation_snapshot()) == "accept_fresh"
                tf = (time.perf_counter_ns() - t0) / 1e6
                rows.append([n, seed, t, "redact", tr])
                rows.append([n, seed, t, "verify_hist", th])
                rows.append([n, seed, t, "verify_fresh", tf])
                if t % 10 == 0:
                    print(f"n={n} seed={seed} t={t:2d} redact {tr:6.2f}  "
                          f"hist {th:7.2f}  fresh {tf:7.2f} (ms)")
    with open(raw_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["n", "seed", "t", "op", "ms"])
        w.writerows(rows)
    # per-(n, t, op) mean over the 5 seeds (paper regime: continuous chain, 5 seeds)
    cells = {}
    for n in (64, 102):
        for t in range(0, T_MAX + 1):
            for op in ("redact", "verify_hist", "verify_fresh"):
                obs = [r[4] for r in rows if r[0] == n and r[2] == t and r[3] == op]
                if obs:
                    cells[f"{op}|n{n}|t{t}"] = dict(
                        mean_ms=round(sum(obs) / len(obs), 4),
                        min_ms=round(min(obs), 4), max_ms=round(max(obs), 4),
                        n_seeds=len(obs))
    summary = dict(environment=dict(python=platform.python_version(),
                                    processor=platform.processor(),
                                    ts=time.strftime("%Y-%m-%dT%H:%M:%S")),
                   regime="continuous chain x 5 seeds; hist/fresh timed "
                          "separately",
                   cells=cells,
                   notes=["redact timing includes the audit signature",
                          "fresh timing includes the RA response signature, "
                          "verification and status check; no network "
                          "round-trip (no end-to-end latency claim)",
                          "each hop does redact->register (untimed) first, "
                          "then times hist/fresh separately"])
    with open(sum_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print(f"\nF3_DONE raw={raw_path}\n       summary={sum_path}")


if __name__ == "__main__":
    main()
