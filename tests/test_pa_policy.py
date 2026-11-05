# -*- coding: utf-8 -*-
"""Paper-aligned suite, part 11: general policy P=(W,M,b) and eq.(2) encoding
(acceptance matrix).

Item-by-item coverage: legal deletion / deletion of must-keep fields /
unauthorized deletion / policy relaxation / budget increase and shortfall /
identity-role mismatch / legal successive tightening / itemized rejection of
non-canonical encodings + Verify step-(5) per-hop negatives (including forged
P_prev with shrunk M and mixed encoding versions) + encoding uniqueness.
Everything runs on real cryptographic paths (real RA issuance, real B1-65
signatures, real verify).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))          # run/fixed_run

from s6t64 import canon, policy as pol            # noqa: E402
from s6t64 import s5_qprss as Q                   # noqa: E402
import s6t64.s4compat as s4c                      # noqa: E402

B1 = Q.s5_sig.core("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
ID_R = b"\x01" * 16
N = 8
V2 = pol.POL_VER_GENERAL

R = {"tests": {}}


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  {note}" if note else ""))
    assert ok, name


def expect_reject(fn, name):
    """Passes only if fn raises ValueError (unit-level negative)."""
    try:
        fn()
        record(name, False, "accepted(!)")
    except ValueError as e:
        record(name, True, f"ValueError: {e}")


def world(ver=V2, M=frozenset({1, 2}), b=None, adm=None, n=N):
    """Deterministic world: pp/RA/signer/redactor, general or restricted policy
    (fixed seeds, reproducible). n may depart from the module default N=8
    (F3 regression: n=102 => n%8!=0, per-hop bitmaps take the padding-bit path)."""
    b = n if b is None else b
    pp = Q.setup("B1", seed=b"pa|pp", pol_ver=ver)
    ra = Q.RA("B1")
    ra.sk, ra.pk = B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-ra"))
    SK, PK = B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-s"))
    cert_s = ra.issue(RID[:12] + b"SGNR", PK, b"signer", ((RID,), b"*"), 0, 1 << 62)
    W = frozenset(range(2, n + 1))
    P0 = pol.Policy(adm or ((b"physician", b"*"),), W, b, n,
                    m=(None if ver == 1 else M), ver=ver)
    ys = {j: f"field-{j}".encode() for j in range(1, n + 1)}
    sd = canon.schema_digest([(j, ("Patient", f"a{j}"), "str")
                              for j in range(1, n + 1)])
    S = Q.signing(pp, SK, cert_s, RID, ys, P0,
                  rng=Q.make_rng(b"pa|commit"), schema_digest=sd,
                  sig_rng=s4c.FixedXofRng(b"pa|sig0"))
    skr, pkr = B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-r"))
    c_r = ra.issue(ID_R, pkr, b"physician", ((RID,), b"*"), 0, 1 << 62)
    c_nurse = ra.issue(b"\x02" * 16,
                       B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-n"))[1],
                       b"nurse", ((RID,), b"*"), 0, 1 << 62)
    return pp, ra, PK, SK, cert_s, c_r, c_nurse, skr, S, P0, sd


def must_redact_refuse(name, frag, pp, S, I_new, Pn, cert, key, ts=100):
    try:
        Q.redact(pp, S, I_new, Pn, cert, key, ts)
        record(name, False, "accepted(!)")
    except Q.RedactRefused as e:
        record(name, frag in str(e), str(e))


def must_verify_reject(name, steps, cfg, S, mode="hist", **kw):
    try:
        Q.verify(cfg, S, mode, **kw)
        record(name, False, "accepted(!)")
    except Q.VerifyReject as e:
        record(name, e.step in steps, f"@{e.step}: {e}")


# ---------- A. predicate and D(P) (eq.(1)/(3) units) ----------
W, Mg = frozenset(range(2, N + 1)), frozenset({1, 2})
P = pol.Policy(((b"physician", b"*"),), W, N, N, m=Mg, ver=V2)
U = frozenset(range(1, N + 1))
record("A1 legal construction with W and M overlapping (shared {2})", W & Mg == {2})
record("A2 D(P)=W-M (=U-M; must-keep removed from the redactable set)", P.D == W - Mg == frozenset(range(3, N + 1)))
record("A3 eq.(1): full retention = 1", P.holds(U))
record("A4 eq.(1): deleting inside D(P) = 1 (delete 5)", P.holds(U - {5}))
record("A5 eq.(1): deleting an M-and-W field = 0 (delete 2, must-keep wins)", not P.holds(U - {2}))
record("A6 eq.(1): deleting a gray-zone field = 0 (delete 1, 1 not in W or M)", not P.holds(U - {1}))
P2 = pol.Policy(P.adm, W, N - 1, N, m=Mg | {5}, ver=V2)
record("A7 eq.(3): D(P2) subset of D(P) is a tightening", P2.D <= P.D and Mg <= P2.M)
record("A8 tighten_ok legal tightening (W unchanged, M grows, b-1)", pol.tighten_ok(P2, P))
record("A9 tighten_ok rejects W relaxation", not pol.tighten_ok(
    pol.Policy(P.adm, W | {1}, N - 1, N, m=Mg, ver=V2), P))
record("A10 tighten_ok rejects M shrink", not pol.tighten_ok(
    pol.Policy(P.adm, W, N - 1, N, m=frozenset({1}), ver=V2), P))
record("A11 tighten_ok rejects non-decreasing budget (b'=b)", not pol.tighten_ok(
    pol.Policy(P.adm, W, N, N, m=Mg, ver=V2), P))
record("A12 tighten_ok rejects budget jump (b'>b)", not pol.tighten_ok(
    pol.Policy(P.adm, W, N + 1, N, m=Mg, ver=V2), P))
expect_reject(lambda: pol.Policy(P.adm, W, N, N, m=Mg | {9}, ver=V2),
              "A13 constructor rejects M not subset of [n]")
expect_reject(lambda: pol.Policy(P.adm, W, N, N, m=Mg, ver=1),
              "A14 ver=1 rejects explicit M != U-W (restricted subfamily uniqueness)")

# ---------- B. eq.(2) encoding and decoding strictness ----------
enc = canon.enc_pol(P)
Pd, off = Q.dec_pol(enc + b"TAIL", 0, N)
record("B1 encode/decode round-trip consistent + delimited", off == len(enc)
       and canon.enc_pol(Pd) == enc and Pd.M == Mg and Pd.w == W
       and Pd.d == N and Pd.ver == V2)
P_eq = pol.Policy(((b"physician", b"*"), (b"nurse", b"*")), W, N, N, m=Mg, ver=V2)
P_re = pol.Policy(((b"nurse", b"*"), (b"physician", b"*")), W, N, N, m=Mg, ver=V2)
record("B2 encoding uniqueness: different adm orderings -> identical bytes", canon.enc_pol(P_eq) == canon.enc_pol(P_re))
record("B3 enc_u minimal width", canon.enc_u(0) == b"\x00" and canon.enc_u(7) == b"\x01\x07"
       and canon.enc_u(256) == b"\x02\x01\x00")
expect_reject(lambda: canon.dec_u_at(b"\x02\x00\x05", 0),
              "B4 dec_u rejects non-minimal integer (leading zero)")
expect_reject(lambda: canon.dec_u_at(b"\x05" + b"\x00" * 5, 0),
              "B5 dec_u rejects overlong (L>4)")
expect_reject(lambda: canon.dec_u_at(b"\x02\x01", 0),
              "B6 dec_u rejects truncation")
expect_reject(lambda: canon.bmp_checked(b"\x00" * ((N + 7) // 8 + 1), N),
              "B7 bits_n rejects wrong length")
bad_pad = canon.bmp({1, 2, 3, 4}, 5)[:-1] + bytes(
    [canon.bmp({1, 2, 3, 4}, 5)[-1] | 0x80])      # bits 6..8 must be zero for n=5; set one
expect_reject(lambda: canon.bmp_checked(bad_pad, 5),
              "B8 bits_n rejects non-zero padding bits")
# B8 regression (real defect found at n=102): padding bits are the HIGH bits of
# the last byte; the low bits are data. Before the fix the mask direction was
# reversed -- a legal W containing {97,98} (n=102, pad=2) was wrongly rejected
# as "non-zero padding".
record("B8b bits_n does not reject legal low data bits (pad!=0 round-trip: n=5/10/102)",
       canon.bmp_checked(canon.bmp({1, 2, 3}, 5), 5) == {1, 2, 3}
       and canon.bmp_checked(canon.bmp({1, 10}, 10), 10) == {1, 10}
       and canon.bmp_checked(canon.bmp({97, 98, 102}, 102), 102) == {97, 98, 102})
# n mismatch (rewrite enc_u(n) inside the descriptor: n=8->9)
e9 = enc.replace(canon.POLV1 + canon.enc_u(N), canon.POLV1 + canon.enc_u(N + 1))
expect_reject(lambda: Q.dec_pol(e9, 0, N), "B9 dec_pol rejects decoded n != record universe")
# b>B_max (tail enc_u(b) enlarged, B_max temporarily lowered)
_q = Q.cfg_pp
_saved = _q.get("B_max")
_q["B_max"] = N
b_bad = enc[: -len(canon.enc_u(N))] + canon.enc_u(N + 1)
expect_reject(lambda: Q.dec_pol(b_bad, 0, N), "B10 dec_pol rejects b > B_max")
_q["B_max"] = _saved
# non-canonical adm (duplicate entries; entries must be strictly increasing by key)
_dup = canon.POL2_PREFIX + bytes([2]) \
    + canon.enc_adm_entry(b"physician", b"*") * 2 \
    + canon.POLV1 + canon.enc_u(N) + canon.bmp(W, N) + canon.bmp(Mg, N) \
    + canon.enc_u(N)
expect_reject(lambda: Q.dec_pol(_dup, 0, N), "B11 dec_pol rejects duplicate adm entries")
expect_reject(lambda: Q.dec_pol(canon.POL2_PREFIX + b"\x51\x50", 0, N),
              "B12 garbage pol2 stream rejected (truncated/illegal role code)")
# structural mutual exclusion: the restricted encoding does not start with the
# prefix; dec_pol dispatches back to the restricted parser
Pl, offl = Q.dec_pol(canon.enc_pol(pol.Policy(P.adm, W, N, N)), 0, N)
record("B13 restricted encoding dispatched by dec_pol back to ver=1 (structural exclusion)", Pl.ver == 1 and offl > 0)

# ---------- C. end-to-end general-policy artifacts (Redact R0-R6 positives/negatives) ----------
pp, ra, PK, SK, cert_s, c_r, c_nurse, skr, S, P0, sd = world()
cfg = {"pk_ra": ra.pk}
Q.verify(cfg, S, "hist")
record("C1 general policy (W and M overlap) t=0 hist accept", True)
W0, M0, b0 = P0.w, P0.M, P0.d
legal_P = lambda w, m, b: pol.Policy(P0.adm, w, b, N, m=m, ver=V2)
keep = lambda *gone: set(range(1, N + 1)) - set(gone)

S1 = Q.redact(pp, S, keep(5), legal_P(W0, M0, b0 - 1), c_r, skr, 100)
Q.verify(cfg, S1, "hist")
record("C2 legal deletion (5 in D(P)) + tightening hist accept", True)
must_redact_refuse("C3 R1 rejects deleting outside W (delete 1, gray zone)", "R1",
                   pp, S, keep(1), legal_P(W0, M0, b0 - 1), c_r, skr)
must_redact_refuse("C4 R2 rejects deleting must-keep field (2 in M and W)", "R2",
                   pp, S, keep(2), legal_P(W0, M0, b0 - 1), c_r, skr)
must_redact_refuse("C5 R5 rejects non-decreasing budget (b'=b)", "R5",
                   pp, S, keep(5), legal_P(W0, M0, b0), c_r, skr)
must_redact_refuse("C6 R5b rejects encoding-version mixing (ver=1 policy into ver=2 artifact)", "R5b",
                   pp, S, keep(5), pol.Policy(P0.adm, W0, b0 - 1, N), c_r, skr)
must_redact_refuse("C7 tighten rejects W relaxation (W' superset of W)", "R5",
                   pp, S, keep(5), legal_P(W0 | {1}, M0, b0 - 1), c_r, skr)
must_redact_refuse("C8 tighten rejects M shrink (M' subset of M)", "R5",
                   pp, S, keep(5), legal_P(W0, frozenset({1}), b0 - 1), c_r, skr)
must_redact_refuse("C9 R6 rejects role mismatch (nurse)", "R6",
                   pp, S, keep(5), legal_P(W0, M0, b0 - 1), c_nurse,
                   B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-n2"))[0])
sk_x, pk_x = B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-x"))
c_x = ra.issue(b"\x03" * 16, pk_x, b"physician",
               ((b"\xff" * 16,), b"*"), 0, 1 << 62)   # scope lacks this RID
must_redact_refuse("C10 R6 rejects certificate whose scope lacks this RID", "R6",
                   pp, S, keep(5), legal_P(W0, M0, b0 - 1), c_x, sk_x)
must_redact_refuse("C11 R0 rejects empty deletion (J=empty)", "R0",
                   pp, S, keep(), legal_P(W0, M0, b0 - 1), c_r, skr)
must_redact_refuse("C12 R0b rejects index resurrection (I_new not subset of I_t, re-inserting a deleted field)", "R0b",
                   pp, S1, keep(6), legal_P(W0, M0, b0 - 2), c_r, skr)

# ---------- D. Verify step-(5) forgery negatives (forge_hop + full verify) ----------
must_verify_reject("D1 V7.6 rejects forged hop with M shrink", {"V7.6"}, cfg,
                   Q.forge_hop(S, keep(5), legal_P(W0, frozenset({1}), b0 - 1),
                               c_r, skr, 200))
must_verify_reject("D2 V7.6 rejects forged hop with W relaxation", {"V7.6"}, cfg,
                   Q.forge_hop(S, keep(5), legal_P(W0 | {1}, M0, b0 - 1),
                               c_r, skr, 200))
must_verify_reject("D3 V7.6 rejects forged hop with non-decreasing budget", {"V7.6"}, cfg,
                   Q.forge_hop(S, keep(5), legal_P(W0, M0, b0), c_r, skr, 200))
must_verify_reject("D4 V7.3 rejects forged hop deleting must-keep M", {"V7.3"}, cfg,
                   Q.forge_hop(S, keep(2), legal_P(W0, M0, b0 - 1), c_r, skr, 200))
must_verify_reject("D5 V7.2 rejects forged hop deleting gray zone outside W", {"V7.2"}, cfg,
                   Q.forge_hop(S, keep(1), legal_P(W0, M0, b0 - 1), c_r, skr, 200))
# D6 forged P_prev with shrunk M: hand-re-encoded e (in-hop declared state !=
# chain state) + real re-signature
F6 = Q.forge_hop(S, keep(2), legal_P(W0, frozenset({1}), b0 - 1), c_r, skr, 200)
_e = Q.dec_e(F6.log[-1][0], N)
_e["P_prev"] = pol.Policy(P0.adm, W0, b0, N, m=frozenset({1}), ver=V2)
_e_bytes = canon.enc_e(_e["seq"], _e["id"], _e["role"], F6.log[-1][2],
                       _e["I_prev"], _e["I_new"], _e["P_prev"], _e["P_new"],
                       _e["ts"], N)
_h = canon.hi_of(_e_bytes, S.h_t)
_tau = B1.sign(skr, c_r.pk, canon.M_red(RID, 1, _e_bytes, S.h_t, _h),
               canon.CTX_RED, rng=s4c.FixedXofRng(b"pa|sig-d6"))
F6b = Q.forge_hop(S, keep(2), legal_P(W0, frozenset({1}), b0 - 1), c_r, skr, 200)
F6b.log = list(F6b.log)
F6b.log[-1] = (_e_bytes, _tau, F6.log[-1][2])
F6b.h_t = _h
must_verify_reject("D6 V6 rejects forged P_prev with shrunk M (full-state comparison)", {"V6"}, cfg, F6b)
# D7 mixed encoding-version artifact (forge ver=1 policy, all other semantics legal: W'={3..8})
F7 = Q.forge_hop(S, keep(5),
                 pol.Policy(P0.adm, frozenset(range(3, N + 1)), b0 - 1, N),
                 c_r, skr, 300)
must_verify_reject("D7 V6 rejects mixed encoding-version artifact (ver=1 P_new)", {"V6"}, cfg, F7)

# ---------- E. version coexistence and non-mixing ----------
pp1, ra1, PK1, SK1, cs1, cr1, _, skr1, S1v1, P0v1, sd1 = world(ver=1)
cfg1 = {"pk_ra": ra1.pk}
Q.verify(cfg1, S1v1, "hist")
record("E1 restricted (ver=1) artifact hist-accepted under the new decoder", True)
S2v1 = Q.redact(pp1, S1v1, keep(5),
                pol.Policy(P0v1.adm, P0v1.w, P0v1.d - 1, N), cr1, skr1, 100)
Q.verify(cfg1, S2v1, "hist")
record("E2 restricted artifact multi-hop chain hist accept (full ver=1 chain)", True)
record("E3 same-logic policy ver1/ver2 encodings byte-distinguishable",
       canon.enc_pol(pol.Policy(P0.adm, P0.w, P0.d, N))
       != canon.enc_pol(pol.Policy(P0.adm, P0.w, P0.d, N, m=P0.M, ver=V2)))

# ---------- F. multi-hop successive tightening + registration + fresh (general-policy full chain) ----------
Sc, Pc = S, P0
for k in range(1, 5):                              # delete 8,7,6,5 in turn (all in D(P))
    gone = {9 - k for k in range(1, k + 1)}
    Pn = pol.Policy(P0.adm, Pc.w, Pc.d - 1, N, m=Pc.M, ver=V2)
    Sc = Q.redact(pp, Sc, set(range(1, 9)) - gone, Pn, c_r, skr, 400 + k)
    Pc = Pn
    Q.verify(cfg, Sc, "hist")
record("F1 general-policy 4-hop tightening chain all hist accept (b decreasing, M stable)", True)
sig_init = B1.sign(SK, PK,
                   canon.M_reginit(RID, N, S.acc0, S.P0, canon.H(cert_s.msg), sd=sd),
                   canon.CTX_REG, rng=s4c.FixedXofRng(b"pa|sig-reg0"))
ra.register_initial(S, cert_s, sig_init)
m_reg = canon.M_reg(RID, ra.reg[RID]["ver"], ra.reg[RID]["h"],
                    ra.reg[RID]["ver"] + 1, Sc.h_t, len(Sc.log),
                    canon.H(c_r.msg), c_r.id, c_r.role)
ra.register(Sc, B1.sign(skr, c_r.pk, m_reg, canon.CTX_REG,
                        rng=s4c.FixedXofRng(b"pa|sig-reg")), c_r)
v = Q.verify(cfg, Sc, "fresh", ra=ra, nonce=b"\x77" * 32,
             revsnap=ra.revocation_snapshot())
record("F2 general-policy artifact fresh accept (bid/chain-head full chain)", v == "accept_fresh")

# ---------- F3. n=102 full-chain regression (n%8!=0: bitmap padding bits + per-hop dec_e_at) ----------
# F3 real crash path found in multi-hop experiments: at n=102 (pad=2) the first
# hop register->verify(hist) wrongly rejected "W contains {97,98} as non-zero
# padding" inside dec_e_at->_dec_pol2->bmp_checked (root cause of B8b).
N102 = 102
pp2, ra2, PK2, SK2, cs2, cr2, _, skr2, S102, P0102, sd2 = world(n=N102)
cfg2 = {"pk_ra": ra2.pk}
Q.verify(cfg2, S102, "hist")                       # P0 header decode (pad!=0 included)
Pn2 = pol.Policy(P0102.adm, P0102.w, N102 - 1, N102, m=P0102.M, ver=V2)
S1h = Q.redact(pp2, S102, set(range(1, N102 + 1)) - {50}, Pn2, cr2, skr2, 500)
Q.verify(cfg2, S1h, "hist")                        # first-hop audit-record decode = former crash point
sig_i2 = B1.sign(SK2, PK2,
                 canon.M_reginit(RID, N102, S102.acc0, S102.P0, canon.H(cs2.msg), sd=sd2),
                 canon.CTX_REG, rng=s4c.FixedXofRng(b"pa|sig-reg0-102"))
ra2.register_initial(S102, cs2, sig_i2)
m2 = canon.M_reg(RID, ra2.reg[RID]["ver"], ra2.reg[RID]["h"],
                 ra2.reg[RID]["ver"] + 1, S1h.h_t, len(S1h.log),
                 canon.H(cr2.msg), cr2.id, cr2.role)
ra2.register(S1h, B1.sign(skr2, cr2.pk, m2, canon.CTX_REG,
                          rng=s4c.FixedXofRng(b"pa|sig-reg-102")), cr2)
v2 = Q.verify(cfg2, S1h, "fresh", ra=ra2, nonce=b"\x88" * 32,
              revsnap=ra2.revocation_snapshot())
record("F3 n=102 (n%8!=0) redact->register->hist+fresh all accept", v2 == "accept_fresh")

R["verdict"] = "ALL_PA_POLICY_PASS" if all(t["pass"] for t in R["tests"].values()) \
    else "PA_POLICY_FAIL"
R["total"] = len(R["tests"])
out = os.path.join(HERE, "..", "data", "pa_policy_results.json")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(f"\nVERDICT: {R['verdict']} ({R['total']} tests) -> {os.path.abspath(out)}")
sys.exit(0 if R["verdict"] == "ALL_PA_POLICY_PASS" else 1)
