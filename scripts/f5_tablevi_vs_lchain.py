# -*- coding: utf-8 -*-
"""F5 = 表 VI 深链传输对比：QPRSS vs 普通顺序全文签名链（L 链）。

组合 n=64,t=63（W={2..64} 删空）与 n=102,t=80。
  Q  = len(Sigma.serialize())（完整发布签名，ver=2）；
  L  = σ0 + Σ_{i=1..t}(τ_i + doc_i + pk_i + meta)——历史核查须出示全部
       中间全文文档（l_chain.l_verify 语义）；doc_i = 删后剩余字段并置
       （32B/字段）；pk_i = 各跳验证公钥 3,712B（L 链无证书层，公钥
       须随文档出示）；meta = 16B 删改者自述。
旧表 VI 数值（398,793/639,789/519,356/845,832）为历史基线参照，
且既有审计（QPRSS_Final_Freeze_Gates Q4）已认定旧值"非旧非规范"——
本轮为规范重测。
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
    # L 链：原始全文签名（与 Q 同一 B1 核、同 rng 语义）
    doc = b"".join(ys[j] for j in sorted(ys))
    sig0 = LC.l_sign_origin(sk_s, pk_s, doc,
                            rng=s4c.FixedXofRng(sdp + b"|L0"))
    L = len(sig0)
    hops_meta = []
    h = LC.h_doc(doc)
    P = P0
    for i in range(1, t + 1):
        j = i + 1                                           # 与 Q 同删除序
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
    assert Q.verify(vcfg, S, "hist")                        # Q 链合法
    # L 链可验证性抽查（全文并置 + 公钥）
    hops = []
    S2 = None
    return dict(n=n, t=t, Q_bytes=len(S.serialize()), L_bytes=L,
                final_fields=len(S.It), sigma0_len=len(sig0),
                pk_len=PK_LEN, sig_len=SIG_LEN)


def main():
    combos = [run_combo(64, 63), run_combo(102, 80)]
    for c in combos:
        save = (c["L_bytes"] - c["Q_bytes"]) / c["L_bytes"]   # 较 L 链节省
        print(f"n={c['n']}, t={c['t']}: Q={c['Q_bytes']:,} B  "
              f"L={c['L_bytes']:,} B  较 L 链节省 {save * 100:.1f}%")
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
                          "L=σ0+Σ(τ+全文doc+pk+meta)（历史核查须出示全部中间文档）",
                          "旧表 VI 值经终检审计判非规范，本轮为规范重测基线"])
    with open(js_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print(f"\nF5_DONE csv={csv_path}\n       json={js_path}")


if __name__ == "__main__":
    main()
