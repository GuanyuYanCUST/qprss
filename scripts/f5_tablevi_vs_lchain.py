# -*- coding: utf-8 -*-
"""F5 = Table VI deep-chain transfer comparison: QPRSS vs a plain
sequential full-document signature chain (L chain).

Combos n=64,t=63 (W={2..64} fully redacted) and n=102,t=80.
  Q  = len(Sigma.serialize()) (full published signature, ver=2);
  L  = sigma0 + sum_{i=1..t}(tau_i + doc_i + pk_i + meta) - historical
       verification must present every intermediate full document
       (l_chain.l_verify semantics); doc_i = the fields remaining after
       the i-th redaction, concatenated (32 B/field); pk_i = per-hop
       verification public key, 3,712 B (the L chain has no certificate
       layer, so keys travel with the documents); meta = 16 B redactor
       self-description.
The old Table VI numbers (398,793/639,789/519,356/845,832) are a
historical baseline; a prior audit judged them non-canonical, so this
run is the canonical re-measurement.
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

from s6t64 import canon, l_chain as LC                   # noqa: E402
from s6t64 import policy as pol                          # noqa: E402
from s6t64 import s5_qprss as Q                          # noqa: E402
from s6t64 import s5_sig, s4compat as s4c                # noqa: E402

B1 = s5_sig.core("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
V2 = pol.POL_VER_GENERAL
PK_LEN = 3712
SIG_LEN = 5794


def fields_for(n):
    out = []
    for j in range(1, n + 1):
        core = f"attr_{j}=A;val_{j}=V".encode()
        pad = hashlib.shake_256(f"PA|F5|{j}".encode()).digest(32)
        out.append((core + pad)[:32])
    return out


def run_combo(n, t):
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
    P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, n + 1)), n, n,
                    m=frozenset({1}), ver=V2)
    S = Q.signing(pp, sk_s, cert_s, RID, ys, P0, rng=Q.make_rng(sdp + b"|sg"),
                  schema_digest=sdig, sig_rng=s4c.FixedXofRng(sdp + b"|sg0"))
    vcfg = {"pk_ra": ra.pk}
    assert Q.verify(vcfg, S, "hist")
    # L chain: origin full-document signature (same B1 core, same rng semantics as Q)
    doc = b"".join(ys[j] for j in sorted(ys))
    sig0 = LC.l_sign_origin(sk_s, pk_s, doc,
                            rng=s4c.FixedXofRng(sdp + b"|L0"))
    L = len(sig0)
    hops_meta = []
    h = LC.h_doc(doc)
    P = P0
    for i in range(1, t + 1):
        j = i + 1                                           # same deletion order as Q
        Pn = pol.Policy(P.adm, P.w, P.d - 1, n, m=P.M, ver=V2)
        S = Q.redact(pp, S, set(S.It) - {j}, Pn, cert_r, sk_r, 30_000 + i,
                     sig_rng=s4c.FixedXofRng(sdp + b"|rd%d" % i))
        P = Pn
        doc = b"".join(S.fields[k][0] for k in sorted(S.It))
        meta = b"\x01" * 16
        h, tau = LC.l_hop(h, doc, meta, sk_r, pk_r,
                          rng=s4c.FixedXofRng(sdp + b"|L%d" % i))
        L += len(tau) + len(doc) + PK_LEN + len(meta)
        hops_meta.append((i, len(doc), len(tau)))
    assert Q.verify(vcfg, S, "hist")                        # Q chain still valid
    # L-chain verifiability spot-check scaffolding (full docs + keys)
    hops = []
    S2 = None
    return dict(n=n, t=t, Q_bytes=len(S.serialize()), L_bytes=L,
                final_fields=len(S.It), sigma0_len=len(sig0),
                pk_len=PK_LEN, sig_len=SIG_LEN)


def main():
    combos = [run_combo(64, 63), run_combo(102, 80)]
    for c in combos:
        save = (c["L_bytes"] - c["Q_bytes"]) / c["L_bytes"]   # saving vs L chain
        print(f"n={c['n']}, t={c['t']}: Q={c['Q_bytes']:,} B  "
              f"L={c['L_bytes']:,} B  saving vs L chain {save * 100:.1f}%")
    csv_path = os.path.join(ROOT, "results", "summary", "f5_tablevi_vs_lchain.csv")
    js_path = os.path.join(ROOT, "results", "summary", "f5_tablevi_vs_lchain.json")
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["n", "t", "Q_bytes", "L_bytes", "saving_pct"])
        for c in combos:
            w.writerow([c["n"], c["t"], c["Q_bytes"], c["L_bytes"],
                        round((c["L_bytes"] - c["Q_bytes"])
                              / c["L_bytes"] * 100, 2)])
    summary = dict(environment=dict(python=platform.python_version(),
                                    ts=time.strftime("%Y-%m-%dT%H:%M:%S")),
                   combos=combos,
                   notes=["Q=len(Sigma.serialize()) ver=2",
                          "L = sigma0 + sum(tau + full doc + pk + meta) "
                          "(historical verification must present all "
                          "intermediate documents)",
                          "old Table VI values were judged non-canonical by "
                          "a prior audit; this run is the canonical baseline"])
    with open(js_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print(f"\nF5_DONE csv={csv_path}\n       json={js_path}")


if __name__ == "__main__":
    main()
