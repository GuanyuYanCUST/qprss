# -*- coding: utf-8 -*-
"""Controlled baseline H (B1-65 signature core + salted hash commitments +
same policy/audit layer) end-to-end test.

The ONLY difference between H and the main scheme Q (B1-65 + C2 MLWE
commitment) is the commitment layer (an earlier "C" baseline also swapped the
signature core, so it cannot isolate the commitment layer as an ablation).
This test checks that the H stack keeps full protocol semantics identical to
Q: V1-V9, v5 serialization, RA registration/fresh, negative rejection steps.

Run: py -3.11 tests/test_h_e2e.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon, commit_c, fhir_codec
from s6t64.s5_qprss import VerifyReject, RedactRefused, CWitness
from s6t64.s5_sig import core
from s6t64.policy import Policy

R = {"tests": {}}


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": detail}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def expect_reject(name, fn, step):
    try:
        fn()
    except VerifyReject as e:
        ok = e.step == step
        record(name, ok, f"rejected at {e.step} (expect {step})" + ("" if ok else " WRONG STEP"))
        return
    except Exception as e:                                   # noqa: BLE001
        record(name, False, f"wrong exception {type(e).__name__}: {e}")
        return
    record(name, False, "accepted (no rejection)")


def main():
    t0 = time.time()
    n = 8
    rid = bytes([0xB7] * 16)
    V = frozenset(range(2, 9))                   # redactable whitelist (1 = mandatory retention)

    # ---- Setup / RA / certificates (all B1-65 core) ----
    ra = Q.RA("H")
    pp = Q.setup("H")
    record("T1 H setup: no algebraic pp (salt+hash commitment layer; pol_ver/B_max are paper §4.1 common parameters)",
           pp.get("scheme") == "H" and pp.get("G") is None and pp.get("D") is None
           and Q.cfg_pp["G"] is None and Q.cfg_pp["D"] is None)
    sk_s, pk_s = core("H").keygen()
    # signer certificate scope explicitly enumerates RIDs (wildcard signer certs
    # are rejected by RA.issue/verify V2.1 -- identity-substitution attack surface closed)
    cert_s = ra.issue(bytes(16), pk_s, b"signer", ((rid,), b"*"), 0, 2**40)
    record("T1 H certificate issue/verify (B1-65 core, pk=3,712 B)",
           cert_s.verify(ra.pk) and len(cert_s.pk) == 3712 and len(cert_s.sig) == 5794)
    c_b1 = Q.Cert(bytes(16), pk_s, b"signer", (b"*", b"*"), 0, 2**40, scheme="B1")
    record("T1 cross-scheme certificate rejected (B1 cert fails H RA)", not c_b1.verify(ra.pk))

    # ---- initial record + sigma0 ----
    sd = canon.schema_digest(fhir_codec.SCHEMA[:n])
    ys = {j: fhir_codec.example_field_bytes(j) for j in range(1, n + 1)}
    P0 = Policy([(b"physician", b"*"), (b"nurse", (b"\x22" * 16,))], V, n, n)
    S0 = Q.signing(pp, sk_s, cert_s, rid, ys, P0, rng=Q.make_rng(b"s56-h"),
                   schema_digest=sd)
    record("T2 H initial signature (sigma0=5,785 B; witness = 32 B salt per field)",
           len(S0.sigma0) == 5794 and all(len(S0.fields[j][1].salt) == 32 for j in S0.It))
    leaf_ok = all(commit_c.leaf_of(j, S0.fields[j][1].salt, ys[j]) is not None for j in S0.It)
    record("T2 salt commitment leaf computable (leaf_of = H(leaf|j|salt|y))", leaf_ok)

    sig_init = core("H").sign(
        sk_s, pk_s,
        canon.M_reginit(rid, n, S0.acc0, P0, canon.H(cert_s.msg), sd=sd), canon.CTX_REG)
    ra.register_initial(S0, cert_s, sig_init)
    record("T3 RegisterInitial (H stack initial RA registration)", ra.reg[rid]["t"] == 0)

    # ---- legal 3-hop chain, 2 redactors (same schedule as s5 e2e -- same policy/audit semantics) ----
    sk_r1, pk_r1 = core("H").keygen()
    sk_r2, pk_r2 = core("H").keygen()
    id1, id2 = b"\x11" * 16, b"\x22" * 16
    c1 = ra.issue(id1, pk_r1, b"physician", ((rid,), b"*"), 0, 2**40)
    c2 = ra.issue(id2, pk_r2, b"nurse", ((rid,), frozenset({5})), 0, 2**40)

    S1 = Q.redact(pp, S0, set(range(1, n + 1)) - {2},
                  Policy(P0.adm, V - {3}, n - 1, n), c1, sk_r1, 1001)
    S2 = Q.redact(pp, S1, S1.It - {5}, Policy(P0.adm, V - {3}, n - 2, n), c2, sk_r2, 1002)
    S3 = Q.redact(pp, S2, S2.It - {7},
                  Policy([(b"physician", b"*")], V - {3, 6}, n - 3, n), c1, sk_r1, 1003)
    tp = [Q.verify({"pk_ra": ra.pk}, Q.Sigma.deserialize(Sx.serialize()), "hist",
                   expected_sd=sd) for Sx in (S0, S1, S2, S3)]
    record("T4 H-stack third-party hist full-chain PASS (3 hops, 2 redactors)",
           all(x == "accept_historical" for x in tp), f"t={time.time()-t0:.1f}s")

    # ---- serialization round-trip + section accounting ----
    b3 = S3.serialize()
    S3b = Q.Sigma.deserialize(b3)
    _, secs = Q.parse_sigma(b3)
    record("T5 serialization round-trip byte-identical + sum(sections)==len",
           S3b.serialize() == b3 and sum(e - s for _, s, e in secs) == len(b3)
           and all(isinstance(S3b.fields[j][1], CWitness) for j in S3b.It),
           f"{len(b3)} B, {len(secs)} sections")

    # ---- RA registration + fresh ----
    m = canon.M_reg(rid, 0, ra.reg[rid]["h"], 1, S3.h_t, 3,
                    canon.H(c1.msg), c1.id, c1.role)
    sig_reg = core("H").sign(sk_r1, pk_r1, m, canon.CTX_REG)
    ra.register(S3, sig_reg, c1)
    nonce = os.urandom(32)                    # fresh nonce exactly 32 B
    snap = ra.revocation_snapshot()
    st = Q.verify({"pk_ra": ra.pk}, S3, "fresh", ra=ra, nonce=nonce, expected_sd=sd,
                  revsnap=snap)
    record("T6 RA register + fresh verification (H stack)", st == "accept_fresh")
    expect_reject("T6 stale state fresh -> V9",
                  lambda: Q.verify({"pk_ra": ra.pk}, S1, "fresh", ra=ra,
                                   nonce=os.urandom(32), expected_sd=sd,
                                   revsnap=snap), "V9")

    # ---- negative: commitment-layer (hash) attacks all rejected at V4 ----
    Sx = Q.Sigma.deserialize(S3.serialize())
    y5, w5 = Sx.fields[4]
    Sx.fields[4] = (y5 + b"X", w5)                     # change field value, keep salt
    expect_reject("T7 tamper retained field value -> V4", lambda: Q.verify({"pk_ra": ra.pk}, Sx, "hist"), "V4")
    Sy = Q.Sigma.deserialize(S3.serialize())
    (ya, wa), (yb, wb) = Sy.fields[4], Sy.fields[6]
    Sy.fields[4] = (ya, wb)                              # swap salts
    Sy.fields[6] = (yb, wa)
    expect_reject("T7 cross-field salt swap -> V4", lambda: Q.verify({"pk_ra": ra.pk}, Sy, "hist"), "V4")

    # ---- negative: out-of-scope redaction (forge_hop skips local prechecks; 4 in W but 4 not in J={5}) ----
    Sz = Q.forge_hop(S2, S2.It - {4}, Policy(P0.adm, V - {3}, n - 3, n), c2, sk_r2, 1004)
    expect_reject("T8 nurse redacts out-of-scope field -> V7.7",
                  lambda: Q.verify({"pk_ra": ra.pk}, Sz, "hist"), "V7.7")

    # ---- negative: sigma0 tamper -> V2.2 ----
    Sw = Q.Sigma.deserialize(S3.serialize())
    Sw.sigma0 = bytes([Sw.sigma0[0] ^ 1]) + Sw.sigma0[1:]
    expect_reject("T9 sigma0 tamper -> V2.2", lambda: Q.verify({"pk_ra": ra.pk}, Sw, "hist"), "V2.2")

    R["meta"] = {"scheme": "H", "n": n, "hops": 3, "bytes_sigma3": len(b3),
                 "wall_s": round(time.time() - t0, 2)}
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "s56_h_e2e_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    print(f"\nALL {len(R['tests'])} H-E2E tests passed in {time.time()-t0:.1f}s -> {out}")


if __name__ == "__main__":
    main()
