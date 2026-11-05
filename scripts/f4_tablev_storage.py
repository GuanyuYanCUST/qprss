# -*- coding: utf-8 -*-
"""F4 = Table V + Fig. 3(d) storage breakdown: (n,t) in {64,102}x{0..40},
row-level check that the full artifact size equals the sum of its
serialized parts.

Breakdown (mirrors the Sigma.serialize layout):
  sigma_base = head + sigma0 + Cert_S + sum of kept fields
               (y+witness+path) - everything but the audit log
  Log_t      = sum e_i + sum tau_i + sum redactor certificate bytes
               (the audit-log segment)
  sigma_S    = len(Sigma.serialize()) - each row asserts
               sigma_base + Log_t == sigma_S
t=0/20/40 give the six Table V rows; the full t series feeds Fig. 3(d).
The old numbers (104,433/316,693/...) are baseline reference only, not
targets.
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
T_MAX = 40
V2 = pol.POL_VER_GENERAL


def fields_for(n):
    out = []
    for j in range(1, n + 1):
        core = f"attr_{j}=A;val_{j}=V".encode()
        pad = hashlib.shake_256(f"PA|F4|{j}".encode()).digest(32)
        out.append((core + pad)[:32])
    return out


def decompose(S):
    """Recompute each segment's byte count independently (a parallel
    implementation of serialize, for the row-level check)."""
    js = sorted(S.It)
    head = (S.rid + canon.enc32(S.n)
            + Q.SCHEME_CHAR[S.scheme]
            + bytes([0x7]) + canon.enc32(len(js))       # cert_s|sd|include flags
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


def chain(n):
    sdp = f"PA|F4|n{n}".encode()
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
    out = []
    base, log, tot = decompose(S)
    assert base + log == tot, (base, log, tot)
    out.append((n, 0, base, log, tot))
    P = P0
    for t in range(1, T_MAX + 1):
        j = t + 1
        Pn = pol.Policy(P.adm, P.w, P.d - 1, n, m=P.M, ver=V2)
        S = Q.redact(pp, S, set(S.It) - {j}, Pn, cert_r, sk_r, 20_000 + t,
                     sig_rng=s4c.FixedXofRng(sdp + b"|rd%d" % t))
        P = Pn
        assert Q.verify(vcfg, S, "hist"), (n, t)
        base, log, tot = decompose(S)
        assert base + log == tot, (n, t, base, log, tot)
        out.append((n, t, base, log, tot))
    return out


def main():
    csv_path = os.path.join(ROOT, "results", "summary", "f4_tablev_storage.csv")
    js_path = os.path.join(ROOT, "results", "summary", "f4_tablev_storage.json")
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    rows = []
    for n in (64, 102):
        rows += chain(n)
        b0 = [r for r in rows if r[0] == n and r[1] == 0][0]
        b40 = [r for r in rows if r[0] == n and r[1] == 40][0]
        d1 = [r for r in rows if r[0] == n and r[1] == 1][0][4] - b0[4]
        print(f"n={n}: sigma_S {b0[4]:,} -> {b40[4]:,} B (40 hops); "
              f"first-hop delta={d1:,} B")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["n", "t", "sigma_base_B", "log_t_B", "sigma_S_B"])
        w.writerows(rows)
    tv = {}
    for n in (64, 102):
        for t in (0, 20, 40):
            r = [x for x in rows if x[0] == n and x[1] == t][0]
            tv[f"n{n}|t{t}"] = dict(sigma_base=r[2], log_t=r[3], sigma_S=r[4],
                                    row_sum_check=r[2] + r[3] == r[4])
    summary = dict(environment=dict(python=platform.python_version(),
                                    ts=time.strftime("%Y-%m-%dT%H:%M:%S")),
                   tableV_rows=tv, all_row_sum_checks_pass=True,
                   notes=["ver=2 general encoding: sigma_base/Log shift "
                          "predictably vs the old restricted encoding",
                          "each row asserts sigma_base+log_t == "
                          "len(serialize()) (all pass)",
                          "old Table V numbers are a historical baseline, "
                          "not targets"])
    with open(js_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print(f"\nF4_DONE csv={csv_path}\n       json={js_path}")


if __name__ == "__main__":
    main()
