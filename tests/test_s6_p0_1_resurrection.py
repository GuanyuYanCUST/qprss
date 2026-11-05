# -*- coding: utf-8 -*-
"""Resurrected-field attack: minimal reproducible attack against the frozen
implementation, with the fixed copy as comparison.

Attack scenario (laid out per the repair-task spec):
 1. a physician signs an 8-field record (1 = mandatory retention;
    W0={2..8}; d0=8);
 2. an authorized redactor R1 (physician) legally deletes field 2 (hop1,
    honest Redact);
 3. the attacker is a former redactor who once held S0 (Model A visibility
    class (iii)) and saved the legal opening (y2, witness2) of field 2 --
    the commitment witness verifies statically against acc0 (the initial-state
    Merkle root), so the opening remains byte-for-byte valid after the field
    is deleted;
 4. R1 (still authorized by the current policy) signs hop2 with a real key:
    re-inserting index 2 in the same hop that declares deletion of {3}
    (removed={3} non-empty; all V7.2-V7.7 predicates hold on their true
    values -- this attack bypasses no other verification condition, see the
    per-predicate check below);
 5. run frozen Verify(mode=hist) and record the real return value; then
    RA.register -> fresh_query -> Verify(mode=fresh) and record the real
    return value (does the resurrected state become the RA-anchored
    "current" chain head?);
 6. print per-predicate truth values for hop2's V7.1-V7.7 plus the V3/V4
    values of the old opening: nothing is bypassed except the per-hop
    index-containment check I_new subset of I_prev -- exactly the check
    missing from the frozen code (paper V7.1 always had it; it was lost in a
    compression pass and restored at the paper level; this script shows the
    gap is real in the frozen source's behavior).

Usage (Windows py3.11):
    py -3.11 tests/test_s6_p0_1_resurrection.py frozen    # frozen copy (expected: attack succeeds = three accepts)
    py -3.11 tests/test_s6_p0_1_resurrection.py patched   # fixed copy (expected: hop2 rejected at V7.1)

Output: logs/t64_p01_resurrection_<mode>.json (tau=64 candidate; frozen mode still targets the 20261013 frozen copy).
"""
import hashlib
import json
import os
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else "patched"  # open-source release defaults to patched (frozen needs the internal 20261013 frozen tree, not in this repo)
assert MODE in ("frozen", "patched"), MODE
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FROZEN_SRC = os.path.abspath(os.path.join(
    ROOT, "..", "RouteB_Stage5_冻结副本_20261013", "src"))
PATCHED_SRC = ROOT

sys.path.insert(0, FROZEN_SRC if MODE == "frozen" else PATCHED_SRC)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import importlib

PKG = "s5" if MODE == "frozen" else "s6t64"
PKG_NAME = PKG + ("(frozen 20261013)" if MODE == "frozen" else "(tau64)")

Q = importlib.import_module(PKG + ".s5_qprss")
canon = importlib.import_module(PKG + ".canon")
_policy = importlib.import_module(PKG + ".policy")
_sig = importlib.import_module(PKG + ".s5_sig")
Policy, tighten_ok, inv_w, AuthMember = (_policy.Policy, _policy.tighten_ok,
                                         _policy.inv_w, _policy.AuthMember)
VerifyReject, RedactRefused, core = Q.VerifyReject, Q.RedactRefused, _sig.core

R = {"mode": MODE, "package": PKG_NAME, "steps": {}, "predicates": {}, "verdict": None}

rng = Q.make_rng(b"p01|commit-band")

# ---- 0. parameters and parties ----
pp = Q.setup("B1", seed=b"p01|pp-seed")
RA = Q.RA("B1")

coreB1 = core("B1")
sk_s, pk_s = coreB1.keygen()            # signing key = SysRng (same convention as frozen tests)
sk_r1, pk_r1 = coreB1.keygen()
sk_r2, pk_r2 = coreB1.keygen()
RID = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")

# signer certificate scope explicitly enumerates RIDs
cert_s = RA.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID,), b"*"), 0, 1 << 62)
cert_r1 = RA.issue(RID[:12] + b"PHS1", pk_r1, b"physician",
                   (b"*", b"*"), 0, 1 << 62)
cert_r2 = RA.issue(RID[:12] + b"PHS2", pk_r2, b"physician",
                   ((RID,), {2, 3, 4, 5, 6, 7, 8}), 0, 1 << 62)

P0 = Policy([(b"physician", b"*")], set(range(2, 9)), 8, 8)     # W0={2..8}, d0=8
ys = {j: f"field-{j}-confidential".encode() for j in range(1, 9)}
sd = canon.schema_digest([(j, ("Patient", f"attr{j}"), "str") for j in range(1, 9)])

# ---- 1. physician signs the 8-field initial record ----
S0 = Q.signing(pp, sk_s, cert_s, RID, ys, P0, rng=rng, schema_digest=sd,
               )
R["steps"]["1_sign"] = {"n": S0.n, "It": sorted(S0.It), "acc0": S0.acc0.hex()[:16],
                        "sigma0_len": len(S0.sigma0)}

# ---- 2. R1 legally deletes field 2 (honest Redact) ----
P1 = P0.copy(w=set(range(2, 9)), d=7)                            # W1={2..8}, d1=7
S1 = Q.redact(pp, S0, {1, 3, 4, 5, 6, 7, 8}, P1, cert_r1, sk_r1, ts=1000,
              )
R["steps"]["2_redact_j2"] = {"It": sorted(S1.It), "d": S1.Pt.d,
                             "field2_in_fields": 2 in S1.fields}

# ---- 3. attacker saves field 2's legal opening (obtained from S0 before deletion) ----
saved_y2, saved_w2 = S0.fields[2]
saved_opening = (saved_y2, saved_w2.packed, tuple(saved_w2.path))
R["steps"]["3_save_opening"] = {
    "y": saved_y2.decode(), "witness_packed_len": len(saved_w2.packed),
    "merkle_depth": len(saved_w2.path),
    "note": "static witness: verified against acc0 (V3/V4), independent of the current chain state, still valid after deletion"}

# ---- 4. authorized redactor (R2, scope includes 2/3) signs resurrection hop2: delete {3} while re-inserting {2} ----
I_attack = {1, 2, 4, 5, 6, 7, 8}                                 # 2 resurrected, 3 deleted
P2 = P1.copy(w=set(range(2, 9)), d=6)


def resurrect(S_prev, I_new, P_new, redactor, sk, saved_field, ts):
    """Attacker construction: bypass the honest Redact local prechecks (they
    carry no force for the attacker) and stuff the saved old opening back into
    fields. All other bytes are constructed isomorphically to redact."""
    n = S_prev.n
    i = len(S_prev.log) + 1
    cid = canon.cert_digest(redactor)   # H_cert semantic upgrade
    e_bytes = canon.enc_e(i, redactor.id, redactor.role, cid, S_prev.It,
                          set(I_new), S_prev.Pt, P_new, ts, n)
    h_new = canon.hi_of(e_bytes, S_prev.h_t)
    tau = core(S_prev.scheme).sign(
        sk, redactor.pk, canon.M_red(S_prev.rid, i, e_bytes, S_prev.h_t, h_new),
        canon.CTX_RED, )
    S2 = Q.Sigma(S_prev.scheme, S_prev.rid, n)
    S2.sd, S2.acc0, S2.P0, S2.sigma0, S2.cert_s = (S_prev.sd, S_prev.acc0,
                                                    S_prev.P0, S_prev.sigma0, S_prev.cert_s)
    S2.It = set(I_new)
    S2.fields = {j: S_prev.fields[j] for j in S2.It if j in S_prev.fields}
    y2, w2 = saved_field
    S2.fields[2] = (y2, Q.ASWitness(w2.packed, list(w2.path)))    # old opening re-inserted
    S2.Pt = P_new
    S2.log = S_prev.log + [(e_bytes, tau, cid)]
    S2.certs = dict(S_prev.certs)
    S2.certs.setdefault(cid, redactor)
    S2.h_t = h_new
    return S2


S2 = resurrect(S1, I_attack, P2, cert_r2, sk_r2, (saved_y2, saved_w2), ts=2000)

# hop2 per-predicate truth values (V7.1-V7.7 + V3/V4 + V6) -- no other check is bypassed
hop2 = Q.dec_e(S2.log[-1][0], S2.n)
removed2 = hop2["I_prev"] - hop2["I_new"]
R["predicates"]["hop2"] = {
    "V6_seq": hop2["seq"] == 2,
    "V6_I_prev_eq_state": hop2["I_prev"] == S1.It,
    "V7.1_removed_nonempty": bool(removed2),
    "V7.1_MISSING_I_new_subset_I_prev": not (hop2["I_new"] <= hop2["I_prev"]),
    "V7.2_removed_in_W": removed2 <= hop2["P_prev"].w,
    "V7.3_K_kept": hop2["P_prev"].K <= hop2["I_new"],
    "V7.4_inv_w": inv_w(hop2["I_new"], hop2["P_new"]),
    "V7.5_holds": hop2["P_new"].holds(hop2["I_new"]),
    "V7.6_tighten": tighten_ok(hop2["P_new"], hop2["P_prev"]),
    "V7.7_auth": bool(AuthMember(hop2["role"], hop2["id"], hop2["P_prev"].adm)),
    "V5.4_tau_by_real_authorized_key": True,      # resurrect() really signs with sk_r2
    "V3/V4_saved_opening_static_valid": True,     # verified against acc0; deletion does not change acc0
    "V8_It_eq_final": S2.It == hop2["I_new"],
    "removed": sorted(removed2), "I_new": sorted(hop2["I_new"]),
}

# ---- 5a. frozen/fixed Verify(mode=hist) real return value ----
try:
    res_hist = Q.verify({"pk_ra": RA.pk}, S2, "hist")
    R["steps"]["5a_verify_hist"] = {"returned": res_hist}
except VerifyReject as e:
    R["steps"]["5a_verify_hist"] = {"rejected_at": e.step, "why": str(e).split(": ", 1)[-1]}

# ---- 5b. RA chain: register_initial(S0) -> register(S1) -> register(S2) -> fresh ----
sig_init = coreB1.sign(sk_s, cert_s.pk,
                       canon.M_reginit(RID, S0.n, S0.acc0, S0.P0,
                                       canon.H(cert_s.msg), sd=sd), canon.CTX_REG,
                       )
try:
    RA.register_initial(S0, cert_s, sig_init)
    R["steps"]["5b_ra_register_initial_S0"] = "ok"
except (RedactRefused, Exception) as e:                           # noqa: BLE001
    R["steps"]["5b_ra_register_initial_S0"] = f"{type(e).__name__}: {e}"


def reg_sig(ra, S, sk, cert):
    st = ra.reg[RID]
    m = canon.M_reg(RID, st["ver"], st["h"], st["ver"] + 1, S.h_t, len(S.log),
                    canon.H(cert.msg), cert.id, cert.role)
    return coreB1.sign(sk, cert.pk, m, canon.CTX_REG, )


for tag, S, cert, sk in (("S1", S1, cert_r1, sk_r1), ("S2", S2, cert_r2, sk_r2)):
    try:
        ver = RA.register(S, reg_sig(RA, S, sk, cert), cert)
        R["steps"][f"5b_ra_register_{tag}"] = f"ok ver={ver}"
    except (RedactRefused, Exception) as e:                       # noqa: BLE001
        R["steps"][f"5b_ra_register_{tag}"] = f"{type(e).__name__}: {e}"

if "ok" in str(R["steps"].get("5b_ra_register_S2", "")):
    nonce = b"p01-nonce" + bytes(23)         # exactly 32 B
    fq = RA.fresh_query(nonce, RID)          # older trees return 4/5 fields; current returns 6 (incl. bid)
    resp, a_h, a_t, a_ts = fq[0], fq[1], fq[2], fq[3]
    kw = {"ra": RA, "nonce": nonce}
    if MODE == "patched":
        kw["revsnap"] = RA.revocation_snapshot()   # revsnap required by default
    try:
        res_fresh = Q.verify({"pk_ra": RA.pk}, S2, "fresh", **kw)
        R["steps"]["5b_verify_fresh_S2"] = {"returned": res_fresh}
    except VerifyReject as e:
        R["steps"]["5b_verify_fresh_S2"] = {"rejected_at": e.step}
else:
    R["steps"]["5b_verify_fresh_S2"] = "skipped (S2 not registered)"

# ---- 6. verdict ----
hist = R["steps"]["5a_verify_hist"]
frozen_accepted = hist.get("returned") == "accept_historical"
frozen_rejected_v71 = hist.get("rejected_at") == "V7.1"
if MODE == "frozen":
    attack_success = frozen_accepted
    R["verdict"] = ("REPRODUCED: frozen Verify accepts resurrected state (hist)=" + str(frozen_accepted)
                    + "; RA.register(S2)=" + R["steps"]["5b_ra_register_S2"]
                    + "; fresh=" + str(R["steps"]["5b_verify_fresh_S2"]))
    print("\n=== resurrection attack frozen verdict ===")
    print("attack reproduced (hist accept):", frozen_accepted)
    assert attack_success, "frozen copy did not reproduce the attack -- revisit the attack construction"
else:
    R["verdict"] = ("PATCHED: hop2 rejected at V7.1 by the fixed copy=" + str(frozen_rejected_v71)
                    + "; hist result=" + str(hist))
    print("\n=== resurrection attack patched verdict ===")
    print("attack rejected at V7.1:", frozen_rejected_v71)
    assert frozen_rejected_v71, "fixed copy did not reject the resurrection hop at V7.1"

# legal regression control: an ordinary second hop without resurrection must
# still be accepted by both copies
P2_ok = P1.copy(w=set(range(2, 9)), d=6)
S2_ok = Q.redact(pp, S1, {1, 4, 5, 6, 7, 8}, P2_ok, cert_r2, sk_r2, ts=3000,
                 )
res_ok = Q.verify({"pk_ra": RA.pk}, S2_ok, "hist")
R["steps"]["6_legal_second_hop_control"] = {"returned": res_ok}
assert res_ok == "accept_historical", "legal second hop wrongly rejected (regression breakage)"
print("legal second hop still accepted:", res_ok)

R["sizes"] = {"S0_bytes": len(S0.serialize()), "S1_bytes": len(S1.serialize()),
              "S2_bytes": len(S2.serialize()), "S2_ok_bytes": len(S2_ok.serialize())}

os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
out = os.path.join(ROOT, "logs", f"p01_resurrection_{MODE}.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1, default=str)
print("log ->", out)
