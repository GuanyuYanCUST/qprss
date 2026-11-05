# -*- coding: utf-8 -*-
"""Three-redactor identity-independence test (Q = B1+C2 primary scheme vs
H = controlled contrast, both stacks).

Goals (closes the earlier gap where multi-redactor semantics had only been
exercised on the ML-DSA core):
1. Three independent identities (physician J=* / admin J={6..30} /
   nurse J={10}), 6 real chain rounds, whole-chain hist verify PASS;
2. Each hop's tau_i verifies only under that hop's redactor's own pk and
   fails under every other redactor's pk (identity cannot be swapped);
3. forge_hop claiming another identity (id=R3 but signed with R1's key) ->
   honest Verify rejects at V5.4;
4. Out-of-scope deletion (nurse deletes {11}, outside J={10}) -> V7.7;
5. Serialization round-trip + RA fresh.

Run: py -3.11 tests/test_u3_redactors.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon, fhir_codec
from s6t64.s5_qprss import VerifyReject
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


def run_stack(scheme: str):
    t0 = time.time()
    n = 12                                          # full FHIR schema, 12 fields
    rid = bytes([0xC3] * 16)
    V = frozenset(range(2, 13))                  # 1 = mandatory retention

    ra = Q.RA(scheme)
    pp = Q.setup(scheme, seed=bytes(range(32))) if scheme == "B1" else Q.setup(scheme)
    sk_s, pk_s = core(scheme).keygen()
    # Issuance-side scope rule: the signer certificate scope explicitly
    # enumerates the RID
    cert_s = ra.issue(bytes(16), pk_s, b"signer", ((rid,), b"*"), 0, 2**40)

    sd = canon.schema_digest(fhir_codec.SCHEMA[:n])
    ys = {j: fhir_codec.example_field_bytes(j) for j in range(1, n + 1)}
    adm0 = [(b"physician", b"*"), (b"admin", b"*"), (b"nurse", (b"\x33" * 16,))]
    P0 = Policy(adm0, V, n, n)
    S = Q.signing(pp, sk_s, cert_s, rid, ys, P0, rng=Q.make_rng(b"s56-u3-" + scheme.encode()),
                  schema_digest=sd)
    record(f"[{scheme}] T1 initial signing (n={n}, sigma0={len(S.sigma0)} B)", len(S.sigma0) == 5794)
    sig_init = core(scheme).sign(
        sk_s, pk_s,
        canon.M_reginit(rid, n, S.acc0, P0, canon.H(cert_s.msg), sd=sd), canon.CTX_REG)
    ra.register_initial(S, cert_s, sig_init)

    # Three redactors: R1 physician J=*; R2 admin J={6..9,11,12}; R3 nurse J={10}
    keys, certs = {}, {}
    for tag, role, js in ((1, b"physician", b"*"),
                          (2, b"admin", frozenset({6, 7, 8, 9, 11, 12})),
                          (3, b"nurse", frozenset({10}))):
        sk, pk = core(scheme).keygen()
        keys[tag] = sk
        # nurse's id must match the adm0 enumeration pattern (b"\x33"*16,); physician/admin use b"*"
        cid_ = b"\x33" * 16 if tag == 3 else bytes([tag]) * 16
        certs[tag] = ra.issue(cid_, pk, role, ((rid,), js), 0, 2**40)

    # 6-round redaction schedule (d-1 each hop; W shrinks per hop; every
    # deleted index lies in the current W intersect the actor's J)
    #   hop redactor  delete  W tightened
    plan = [(1, {2}, {3}), (2, {6}, {4}), (3, {10}, {5}), (1, {7}, {8}),
            (2, {11}, {9}), (1, {12}, set())]
    chain = [S]
    Wcur, dcur = set(V), n
    for k, (who, dele, drop) in enumerate(plan, start=1):
        I_new = chain[-1].It - dele
        Wcur = Wcur - drop
        dcur -= 1
        P_new = Policy(adm0, frozenset(Wcur), dcur, n)
        chain.append(Q.redact(pp, chain[-1], I_new, P_new, certs[who], keys[who],
                              2000 + k))
    St = chain[-1]
    record(f"[{scheme}] T2 real 6-round three-redactor chain built", len(St.log) == 6, f"t={time.time()-t0:.1f}s")

    # whole-chain hist verify
    ok = Q.verify({"pk_ra": ra.pk}, Q.Sigma.deserialize(St.serialize()), "hist",
                  expected_sd=sd) == "accept_historical"
    record(f"[{scheme}] T3 whole-chain hist verify PASS (u=3 identity independence)", ok, f"t={time.time()-t0:.1f}s")

    # per-hop tau attribution: passes under the owner's pk, rejected under all others
    h = canon.h0_of(rid, n, St.acc0, P0, sd=sd)
    own_ok, cross_fail = True, True
    for i, (e_bytes, tau, cid) in enumerate(St.log, start=1):
        cert = St.certs[cid]
        m = canon.M_red(rid, i, e_bytes, h, canon.hi_of(e_bytes, h))
        own_ok &= core(scheme).verify(cert.pk, m, tau, canon.CTX_RED)
        for other in certs.values():
            if other.pk != cert.pk:
                cross_fail &= not core(scheme).verify(other.pk, m, tau, canon.CTX_RED)
        h = canon.hi_of(e_bytes, h)
    record(f"[{scheme}] T4 tau_i passes under own pk / rejected under others (6 hops x 2 cross)",
           own_ok and cross_fail)

    # Identity spoofing: the hop metadata keeps R3's id/role/cid (certificate
    # chain intact), but tau is replaced by the attacker's (R1 key) signature
    # on the same M_red -- without R3's key no valid tau can be made -> V5.4
    Sx = Q.forge_hop(chain[-2], chain[-2].It - {12},
                     Policy(adm0, frozenset(Wcur), dcur, n),
                     certs[3], keys[3], 2999)
    e6, _, cid6 = Sx.log[-1]
    m6 = canon.M_red(rid, len(Sx.log), e6, chain[-2].h_t, canon.hi_of(e6, chain[-2].h_t))
    tau_att = core(scheme).sign(keys[1], certs[1].pk, m6, canon.CTX_RED)
    Sx.log[-1] = (e6, tau_att, cid6)
    expect_reject(f"[{scheme}] T5 identity spoofing (R3's name, R1's key, tau) -> V5.4",
                  lambda: Q.verify({"pk_ra": ra.pk}, Sx, "hist"), "V5.4")

    # Out of scope: nurse (J={10}) deletes {12} (chain[-2]'s current W
    # contains 12; own key signs honestly) -> V7.7
    Sy = Q.forge_hop(chain[-2], chain[-2].It - {12},
                     Policy(adm0, frozenset(Wcur), dcur, n),
                     certs[3], keys[3], 3000)
    expect_reject(f"[{scheme}] T6 nurse out-of-scope delete {{12}} -> V7.7",
                  lambda: Q.verify({"pk_ra": ra.pk}, Sy, "hist"), "V7.7")

    # serialization round-trip + RA fresh
    bt = St.serialize()
    record(f"[{scheme}] T7 serialization round-trip byte-identical ({len(bt)} B)",
           Q.Sigma.deserialize(bt).serialize() == bt)
    m = canon.M_reg(rid, ra.reg[rid]["ver"], ra.reg[rid]["h"],
                    ra.reg[rid]["ver"] + 1, St.h_t, 6,
                    canon.H(certs[1].msg), certs[1].id, certs[1].role)
    sig_reg = core(scheme).sign(keys[1], certs[1].pk, m, canon.CTX_REG)
    ra.register(St, sig_reg, certs[1])
    snap = ra.revocation_snapshot()
    st = Q.verify({"pk_ra": ra.pk}, St, "fresh", ra=ra, nonce=os.urandom(32), expected_sd=sd,
                  revsnap=snap)
    record(f"[{scheme}] T8 RA register + fresh", st == "accept_fresh", f"t={time.time()-t0:.1f}s")
    return {"bytes_sigma_t6": len(bt), "wall_s": round(time.time() - t0, 2)}


def main():
    meta = {}
    for scheme in ("B1", "H"):
        meta[scheme] = run_stack(scheme)
    R["meta"] = meta
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "s56_u3_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    print(f"\nALL {len(R['tests'])} u3 tests passed -> {out}")


if __name__ == "__main__":
    main()
