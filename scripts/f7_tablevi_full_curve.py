# -*- coding: utf-8 -*-
"""F7 = Table VI full legal-depth transmission curve: QPRSS Q(t) vs the
sequential full-document signature chain L(t), for n in {32, 64, 102} at
EVERY hop t = 0..n-1 (deletion order j = i+1; every state hist-verified).

Extends the archived F5 endpoints (n=64 t=63; n=102 t=80) with the two
crossover rows of the revised manuscript (n=64 t=12; n=102 t=15), the
n=32 arm of Fig. 3d (results/n32_storage_recomputed.csv, F4 schema), and
the crossover location per n. Seeds are the F5 family "PA|F5|n{n}", so
endpoints reproduce the archived formal results byte-exactly.

Accounting (identical to F5/F4):
  Q(t) = len(Sigma.serialize());
  L(t) = sigma0 + sum_{i=1..t}(tau_i + doc_i + pk_i + 16 B meta);
  base/log = independent re-decomposition of the serialized artifact
  (row-level base+log == total assert, fail-closed).

Paper anchors (revised TIFS manuscript, Table VI) are asserted, never
fitted: any deviation raises AssertionError.

Outputs: results/tablevi_full_curve.csv, results/n32_storage_recomputed.csv,
results/tablevi_full_curve.json.

Run: python -I scripts/f7_tablevi_full_curve.py   (~2 min, Windows py3.11)
"""
import csv
import hashlib
import io
import json
import os
import platform
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "run", "fixed_run"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import canon, l_chain as LC                   # noqa: E402
from s6t64 import policy as pol                          # noqa: E402
from s6t64 import s5_qprss as Q                          # noqa: E402
from s6t64 import s5_sig, s4compat as s4c                # noqa: E402

B1 = s5_sig.core("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
V2 = pol.POL_VER_GENERAL
PK_LEN = 3712

# Revised-manuscript Table VI rows + Fig. 3d n=32 endpoints + crossovers.
PAPER_ANCHORS = {
    (64, 12): (140500, 142138),
    (64, 63): (402028, 670192),
    (102, 15): (192455, 193744),
    (102, 80): (524605, 924994),
    (32, 0): (40956, None),
    (32, 31): (210240, None),
}
PAPER_CROSSOVERS = {32: 9, 64: 12, 102: 15}   # first t with L-Q > 0


def fields_for(n):
    out = []
    for j in range(1, n + 1):
        core = f"attr_{j}=A;val_{j}=V".encode()
        pad = hashlib.shake_256(f"PA|F5|{j}".encode()).digest(32)
        out.append((core + pad)[:32])
    return out


def decompose(S):
    """Independent base/log decomposition (F4 semantics); caller asserts sum."""
    js = sorted(S.It)
    head = (S.rid + canon.enc32(S.n)
            + Q.SCHEME_CHAR[S.scheme]
            + bytes([0x7]) + canon.enc32(len(js))
            + canon.enc32(len(S.log)) + canon.enc32(len(S.certs))
            + (S.sd or b"") + S.acc0 + canon.enc_pol(S.P0)
            + canon.bmp(set(range(1, S.n + 1)), S.n)
            + canon.enc_pol(S.Pt) + S.h_t)
    base = (len(head) + len(S.sigma0) + len(S.cert_s.bytes())
            + sum(len(canon.enc_field(j, S.fields[j][0])) for j in js)
            + sum(len(S.fields[j][1].core_bytes()) for j in js)
            + sum(len(b) for j in js for b in S.fields[j][1].path))
    log = (sum(len(e) for (e, _, _) in S.log)
           + sum(len(tau) for (_, tau, _) in S.log)
           + sum(len(S.certs[c].bytes()) for c in S.certs))
    return base, log, len(S.serialize())


def sweep(n, rows):
    sdp = f"PA|F5|n{n}".encode()
    pp = Q.setup("B1", seed=sdp + b"|pp", pol_ver=V2)
    ra = Q.RA("B1")
    ra.sk, ra.pk = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg-ra"))
    sk_s, pk_s = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg0"))
    cert_s = ra.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID,), b"*"),
                      0, 1 << 62)
    sk_r, pk_r = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg1"))
    cert_r = ra.issue(b"\x01" * 16, pk_r, b"physician", ((RID,), b"*"),
                      0, 1 << 62)
    ys = {k: v for k, v in enumerate(fields_for(n), start=1)}
    sdig = canon.schema_digest(
        [(k, ("Patient", f"attr{k}"), "str") for k in range(1, n + 1)])
    P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, n + 1)),
                    n, n, m=frozenset({1}), ver=V2)
    S = Q.signing(pp, sk_s, cert_s, RID, ys, P0, rng=Q.make_rng(sdp + b"|sg"),
                  schema_digest=sdig, sig_rng=s4c.FixedXofRng(sdp + b"|sg0"))
    vcfg = {"pk_ra": ra.pk}
    P = P0

    doc = b"".join(ys[j] for j in sorted(ys))
    sig0 = LC.l_sign_origin(sk_s, pk_s, doc, rng=s4c.FixedXofRng(sdp + b"|L0"))
    L = len(sig0)
    h = LC.h_doc(doc)

    assert Q.verify(vcfg, S, "hist"), (n, 0)
    base, logb, tot = decompose(S)
    assert base + logb == tot, (n, 0, base, logb, tot)
    rows.append(dict(n=n, t=0, Q_bytes=tot, L_bytes=L, sigma_base_B=base,
                     log_t_B=logb, reduction_pct=round((L - tot) / L * 100, 2)))

    for t in range(1, n):
        j = t + 1
        Pn = pol.Policy(P.adm, P.w, P.d - 1, n, m=P.M, ver=V2)
        S = Q.redact(pp, S, set(S.It) - {j}, Pn, cert_r, sk_r, 30_000 + t,
                     sig_rng=s4c.FixedXofRng(sdp + b"|rd%d" % t))
        P = Pn
        doc = b"".join(S.fields[k][0] for k in sorted(S.It))
        meta = b"\x01" * 16
        h, tau = LC.l_hop(h, doc, meta, sk_r, pk_r,
                          rng=s4c.FixedXofRng(sdp + b"|L%d" % t))
        L += len(tau) + len(doc) + PK_LEN + len(meta)
        assert Q.verify(vcfg, S, "hist"), (n, t)
        base, logb, tot = decompose(S)
        assert base + logb == tot, (n, t, base, logb, tot)
        rows.append(dict(n=n, t=t, Q_bytes=tot, L_bytes=L, sigma_base_B=base,
                         log_t_B=logb,
                         reduction_pct=round((L - tot) / L * 100, 2)))
        if t % 20 == 0:
            print(f"  n={n} t={t}: Q={tot:,} L={L:,} "
                  f"red={(L - tot) / L * 100:.2f}%")


def first_crossover(rows_n):
    """First t at which L-Q >= 0 after being negative (no presupposed count)."""
    prev_neg = None
    for r in rows_n:
        d = r["L_bytes"] - r["Q_bytes"]
        if d < 0:
            prev_neg = r["t"]
        elif prev_neg is not None:
            return r["t"]
    return None


def main():
    t0 = time.time()
    rows = []
    for n in (32, 64, 102):
        print(f"== F7 sweep n={n} ==")
        sweep(n, rows)
        print(f"  done ({time.time() - t0:.0f}s)")

    # Fail-closed paper-anchor checks (never adjusted).
    checks = []
    for (n, t), (q, l) in sorted(PAPER_ANCHORS.items()):
        r = next(r for r in rows if r["n"] == n and r["t"] == t)
        assert r["Q_bytes"] == q, (n, t, r["Q_bytes"], q)
        if l is not None:
            assert r["L_bytes"] == l, (n, t, r["L_bytes"], l)
        checks.append(f"n={n} t={t}: Q={q}" + (f" L={l}" if l else " OK"))
    xover = {}
    for n in (32, 64, 102):
        rn = [r for r in rows if r["n"] == n]
        x = first_crossover(rn)
        assert x == PAPER_CROSSOVERS[n], (n, x, PAPER_CROSSOVERS[n])
        xover[n] = x
        neg = [r for r in rn if r["reduction_pct"] < 0]
        checks.append(
            f"n={n}: single crossover t={x}; Q>L for t={neg[0]['t']}.."
            f"{neg[-1]['t']} (kept); max reduction "
            f"{max(rn, key=lambda r: r['reduction_pct'])['reduction_pct']}%")

    out = os.path.join(ROOT, "results")
    os.makedirs(out, exist_ok=True)
    cols = ["n", "t", "Q_bytes", "L_bytes", "sigma_base_B", "log_t_B",
            "reduction_pct"]
    with io.open(os.path.join(out, "tablevi_full_curve.csv"), "w",
                 newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    with io.open(os.path.join(out, "n32_storage_recomputed.csv"), "w",
                 newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["n", "t", "sigma_base_B", "log_t_B", "sigma_S_B"])
        for r in rows:
            if r["n"] == 32:
                w.writerow([r["n"], r["t"], r["sigma_base_B"], r["log_t_B"],
                            r["Q_bytes"]])
    with io.open(os.path.join(out, "tablevi_full_curve.json"), "w",
                 encoding="utf-8") as f:
        json.dump(dict(python=platform.python_version(),
                       ts=time.strftime("%Y-%m-%dT%H:%M:%S"),
                       n_rows=len(rows), crossovers=xover, checks=checks,
                       elapsed_s=round(time.time() - t0, 1)),
                  f, ensure_ascii=False, indent=1)
    print(f"F7_DONE rows={len(rows)} crossovers={xover} "
          f"elapsed={time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
