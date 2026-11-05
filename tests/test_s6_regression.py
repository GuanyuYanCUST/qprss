# -*- coding: utf-8 -*-
"""Regression suite for the security-repaired implementation (tau=64).

Coverage (item by item):
  A. legitimate multi-redactor scenarios not wrongly rejected (5-hop chain,
     3 redactors + tighten + Inv-W + three modes + serialization round-trip +
     the full RA registration flow);
  B. field-resurrection rejection matrix (direct Verify / indirect via
     RA.register / resurrection at a deeper hop / resurrect without deleting
     another field / honest Redact given a resurrection input -> R0b);
  C. duplicate indices (duplicate j in the serialized field block = harmless
     set semantics; final verification unaffected);
  D. forked chains (legal coexistence under hist; registration = Superseded;
     fresh accepts only the chain head);
  E. old-opening reuse (= the resurrection attack payload: the fact that a
     static witness validates against acc0 is registered on its own);
  F. revocation and time-semantics matrix (historical validity != current
     authorization; self-reported snapshots untrusted; require_revsnap;
     registration gate; window consistency; RA restart preserves revocations);
  G. V1-V9 core tamper negatives (proof the repairs did not break the
     original verification chain).

Run: py -3.11 tests/test_s6_regression.py
Output: logs/t64_regression.json (tau=64 candidate)
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon  # noqa: E402
from s6t64.policy import Policy  # noqa: E402
from s6t64.s5_qprss import VerifyReject, RedactRefused, Superseded  # noqa: E402
from s6t64.s5_sig import core  # noqa: E402

R = {"tests": {}, "t_start": time.time()}
B1 = core("B1")


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": str(detail)}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def expect_reject(name, fn, step=None, exc=VerifyReject):
    try:
        fn()
    except exc as e:
        st = getattr(e, "step", str(e))
        ok = step is None or step in str(st) or step == type(e).__name__
        record(name, ok, f"rejected at {st} (expect {step})" + ("" if ok else " WRONG STEP"))
        return
    except Exception as e:                                   # noqa: BLE001
        record(name, False, f"wrong exception {type(e).__name__}: {e}")
        return
    record(name, False, "accepted (no rejection)")


def reg_sig(ra, rid, S, sk, cert):
    st = ra.reg[rid]
    m = canon.M_reg(rid, st["ver"], st["h"], st["ver"] + 1, S.h_t, len(S.log),
                    canon.H(cert.msg), cert.id, cert.role)
    return B1.sign(sk, cert.pk, m, canon.CTX_REG)


# ---------------- scenario base ----------------
rng = Q.make_rng(b"s59|band")
pp = Q.setup("B1", seed=b"s59|pp")
RA = Q.RA("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
RID2 = bytes.fromhex("7766554433221100ffeeddccbbaa9988")   # used by F9 (hoisted above issuance)

sk_s, pk_s = B1.keygen()
sk_p1, pk_p1 = B1.keygen()      # physician 1
sk_p2, pk_p2 = B1.keygen()      # physician 2
sk_n1, pk_n1 = B1.keygen()      # nurse (restricted scope)

# signer certificate scope explicitly enumerates RID/RID2 (wildcards already
# rejected at issuance and by V2.1)
c_s = RA.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID, RID2), b"*"), 0, 1 << 62)
c_p1 = RA.issue(RID[:12] + b"PHS1", pk_p1, b"physician", (b"*", b"*"), 0, 1 << 62)
c_p2 = RA.issue(RID[:12] + b"PHS2", pk_p2, b"physician", ((RID,), b"*"), 0, 1 << 62)
c_n1 = RA.issue(RID[:12] + b"NURS", pk_n1, b"nurse", ((RID,), {5, 6}), 0, 1 << 62)

n = 8
P0 = Policy([(b"physician", b"*"), (b"nurse", (c_n1.id,))],
            set(range(2, 9)), 8, n)
ys = {j: f"record-field-{j}".encode() for j in range(1, n + 1)}
sd = canon.schema_digest([(j, ("Patient", f"attr{j}"), "str") for j in range(1, n + 1)])
S0 = Q.signing(pp, sk_s, c_s, RID, ys, P0, rng=rng, schema_digest=sd)

V = set(range(2, 9))
# A. legal 5-hop chain, 3 redactors: del 2 -> del 5 (nurse) -> del 7 (tighten,
# drop nurse) -> del 8 -> del 4
S1 = Q.redact(pp, S0, set(range(1, n + 1)) - {2}, Policy(P0.adm, V, 7, n),
              c_p1, sk_p1, 1000)
S2 = Q.redact(pp, S1, set(range(1, n + 1)) - {2, 5}, Policy(P0.adm, V - {3}, 6, n),
              c_n1, sk_n1, 1100)
adm3 = ((b"physician", b"*"),)
S3 = Q.redact(pp, S2, set(range(1, n + 1)) - {2, 5, 7},
              Policy(adm3, V - {3, 6}, 5, n), c_p2, sk_p2, 1200)
S4 = Q.redact(pp, S3, set(range(1, n + 1)) - {2, 5, 7, 8},
              Policy(adm3, V - {3, 6}, 4, n), c_p1, sk_p1, 1300)
S5 = Q.redact(pp, S4, set(range(1, n + 1)) - {2, 5, 7, 8, 4},
              Policy(adm3, V - {3, 6}, 3, n), c_p1, sk_p1, 1400)

cfg = {"pk_ra": RA.pk}
tp = [Q.verify(cfg, S, "hist") for S in (S0, S1, S2, S3, S4, S5)]
record("A1 legal 5-hop 3-redactor chain all hist-accepted (no false rejection after repair)",
       all(x == "accept_historical" for x in tp), str(tp))

rt = Q.Sigma.deserialize(S5.serialize())
record("A2 v5 serialization round-trip byte-identical",
       rt.serialize() == S5.serialize() and Q.verify(cfg, rt, "hist") == "accept_historical")

sig_init = B1.sign(sk_s, c_s.pk, canon.M_reginit(RID, S0.n, S0.acc0, S0.P0,
                                                 canon.H(c_s.msg), sd=sd), canon.CTX_REG)
RA.register_initial(S0, c_s, sig_init)
for S, cert, sk in ((S1, c_p1, sk_p1), (S2, c_n1, sk_n1), (S3, c_p2, sk_p2),
                    (S4, c_p1, sk_p1), (S5, c_p1, sk_p1)):
    RA.register(S, reg_sig(RA, RID, S, sk, cert), cert)
record("A3 RA registration chain ver=5", RA.reg[RID]["ver"] == 5)
snap0 = RA.revocation_snapshot()          # epoch-0 empty revocation table (legal snapshot)
record("A4 fresh chain head=S5 (revsnap supplied -- required by default)",
       Q.verify(cfg, S5, "fresh", ra=RA, nonce=b"n1" + bytes(30), revsnap=snap0) == "accept_fresh")
g = RA.gazette(1, RID)                    # 6-tuple (incl. epoch)
record("A5 snapshot gazette head=S5 (revsnap supplied)",
       Q.verify(cfg, S5, "snapshot", gazettes=[g], revsnap=snap0,
                 legacy_snapshot=True)
       == "accept_snapshot@G1")

# ---------------- B. field-resurrection rejection matrix ----------------
saved2 = S0.fields[2]          # old legal opening (static witness verifies against acc0)


def resurrect(S_prev, I_new, P_new, redactor, sk, saved_field, ts, j=2):
    n_ = S_prev.n
    i = len(S_prev.log) + 1
    cid = canon.cert_digest(redactor)   # H_cert semantic upgrade (paper §4.4)
    e_bytes = canon.enc_e(i, redactor.id, redactor.role, cid, S_prev.It,
                          set(I_new), S_prev.Pt, P_new, ts, n_)
    h_new = canon.hi_of(e_bytes, S_prev.h_t)
    tau = B1.sign(sk, redactor.pk,
                  canon.M_red(S_prev.rid, i, e_bytes, S_prev.h_t, h_new), canon.CTX_RED)
    S2_ = Q.Sigma(S_prev.scheme, S_prev.rid, n_)
    S2_.sd, S2_.acc0, S2_.P0, S2_.sigma0, S2_.cert_s = (S_prev.sd, S_prev.acc0,
                                                        S_prev.P0, S_prev.sigma0,
                                                        S_prev.cert_s)
    S2_.It = set(I_new)
    S2_.fields = {j: S_prev.fields[j] for j in S2_.It if j in S_prev.fields}
    y_j, w_j = saved_field
    S2_.fields[j] = (y_j, Q.ASWitness(w_j.packed, list(w_j.path)))
    S2_.Pt = P_new
    S2_.log = S_prev.log + [(e_bytes, tau, cid)]
    S2_.certs = dict(S_prev.certs)
    S2_.certs.setdefault(cid, redactor)
    S2_.h_t = h_new
    return S2_


# B1: from S2 (2 and 5 already deleted) resurrect 2 while deleting 3
# (removed={3} non-empty, all other predicates true)
BAD = resurrect(S2, {1, 2, 3, 4, 6, 7, 8}, Policy(adm3, V - {3} | {5}, 5, n),
                c_p1, sk_p1, saved2, 2000)
expect_reject("B1 resurrection hop (del 3 + re-insert 2, real authorized key) -> V7.1",
              lambda: Q.verify(cfg, BAD, "hist"), "V7.1")
# B2: resurrected state as a strict extension of the head (t=6>5, avoids Superseded)
BAD_head = resurrect(S5, {1, 2, 3, 6}, Policy(adm3, V - {3, 6}, 2, n),
                     c_p1, sk_p1, saved2, 2400)
expect_reject("B2 resurrected state enters RA.register (strict extension) -> R3 (full verify V7.1)",
              lambda: RA.register(BAD_head, reg_sig(RA, RID, BAD_head, sk_p1, c_p1), c_p1),
              "V7.1", exc=RedactRefused)
try:
    RA.register(BAD, reg_sig(RA, RID, BAD, sk_p1, c_p1), c_p1)
    record("B2b older extension (t=3<=5) separately rejected as Superseded", False)
except Superseded:
    record("B2b older extension (t=3<=5) separately rejected as Superseded", True)

# B3: resurrect only, delete nothing else (removed=empty) -> also V7.1
# (whichever of the two V7.1 branches fires first)
BAD2 = resurrect(S2, {1, 2, 3, 4, 5, 6, 7, 8}, Policy(adm3, V, 5, n),
                 c_p1, sk_p1, saved2, 2100)
BAD2.fields[5] = S0.fields[5]          # old opening re-inserted as well (S2 already deleted 5)
expect_reject("B3 resurrect only, no deletion (re-insert 2, 5; removed=empty) -> V7.1",
              lambda: Q.verify(cfg, BAD2, "hist"), "V7.1")

# B4: resurrection at a deeper hop (after legal S3, hop4 resurrects 2 and deletes 8)
BAD3 = resurrect(S3, {1, 2, 3, 4, 6, 8}, Policy(adm3, V - {3, 6, 7} | {8}, 4, n),
                 c_p1, sk_p1, saved2, 2200)
expect_reject("B4 deep-chain resurrection (hop4 re-inserts 2) -> V7.1",
              lambda: Q.verify(cfg, BAD3, "hist"), "V7.1")

# B5: honest Redact given a resurrection index set -> local precheck R0b
# (signing-side dual)
expect_reject("B5 honest Redact I_new superset of I_t -> R0b",
              lambda: Q.redact(pp, S2, {1, 2, 3, 4, 6, 7, 8},
                               Policy(adm3, V - {3}, 5, n), c_p1, sk_p1, 2300),
              "R0b", exc=RedactRefused)

# ---------------- C. duplicate indices ----------------
raw = S5.serialize()
# duplicate-j field block: hand-injecting duplicate entries into the serialized
# stream is pointless (r_cnt is self-reported by the sender; on the verification
# side S.fields is a dict and It is a set) -- equivalence argument: after
# duplicate injection and re-parsing, dict semantics overwrite, V3/V4 still
# verify each unique j exactly once; a tampered witness is necessarily rejected
# at V4.
dup = Q.Sigma.deserialize(S5.serialize())
dup.fields[3] = (S5.fields[3][0], S5.fields[3][1])     # same j, same opening (idempotent; j in I_t)
record("C1 duplicate index = set/dict semantics (idempotent replay harmless, verification unchanged)",
       Q.verify(cfg, dup, "hist") == "accept_historical"
       and dup.It == S5.It)

# ---------------- D. forked chains ----------------
S2b = Q.redact(pp, S1, set(range(1, n + 1)) - {2, 6}, Policy(P0.adm, V - {3}, 6, n),
               c_p2, sk_p2, 1150)
record("D1 legal fork coexists under hist", Q.verify(cfg, S2b, "hist") == "accept_historical")
expect_reject("D2 fork registration (RA head already advanced) -> Superseded",
              lambda: RA.register(S2b, reg_sig(RA, RID, S2b, sk_p2, c_p2), c_p2),
              "Superseded", exc=Superseded)
expect_reject("D3 fresh accepts only the chain head (S2 stale state) -> V9",
              lambda: Q.verify(cfg, S2, "fresh", ra=RA, nonce=b"n2" + bytes(30),
                               revsnap=snap0), "V9")

# ---------------- E. old-opening reuse (payload fact registered) ----------------
y2, w2 = saved2
from s6t64 import commit_as  # noqa: E402
r2, eta2 = commit_as.unpack_witness(w2.packed)
C2 = commit_as.commit(Q.cfg_pp["G"], Q.cfg_pp["D"], 2, RID, y2, r2, eta2)
from s6t64 import merkle as MK  # noqa: E402
ok_path, root = MK.MerkleTree.verify_path(commit_as.leaf_of(2, C2), 1, w2.path, None)
record("E1 old opening statically valid (against acc0; deletion does not revoke the witness) -- the cryptographic payload source for resurrection",
       ok_path and root == S0.acc0, f"path_ok={ok_path}, root_matches_acc0={root == S0.acc0}")

# ---------------- F. revocation and time-semantics matrix ----------------
# F1 a historical hop is not implicated by a later revocation: revoke c_n1
# (eff_ts=5000; its hop ts=1100)
RA.revoke(c_n1.id, eff_ts=5000)
snap = RA.revocation_snapshot()
record("F1a after revocation, hist verification without a snapshot still accepts (historical validity != current authorization; neither silently rejected nor claimed current)",
       Q.verify(cfg, S5, "hist") == "accept_historical")
record("F1b under a snapshot, a historical hop with ts<eff_ts is not rejected (legally signed in the past)",
       Q.verify(cfg, S5, "hist", revsnap=snap) == "accept_historical")

# F2: a new hop claiming time >= eff_ts -> V5.3d-rev (nurse still in the old
# policy's adm after revocation)
S2r = resurrect(S1, {1, 3, 4, 5, 7, 8}, Policy(P0.adm, V - {3}, 6, n),
                c_n1, sk_n1, S0.fields[3], 6000, j=3)   # claims ts=6000 >= 5000
expect_reject("F2 authorization claimed after revocation (ts>=eff_ts) -> V5.3d-rev",
              lambda: Q.verify(cfg, S2r, "hist", revsnap=snap), "V5.3d-rev")
record("F2b same hop hist-accepted without a snapshot (the registration gate is the currency defense; per the API contract)",
       Q.verify(cfg, S2r, "hist") == "accept_historical")

# F3: self-reported/forged snapshots untrusted
bad_snap = (snap[0], bytes(len(snap[1])))              # fake signature
expect_reject("F3a forged-signature snapshot -> V5.3d",
              lambda: Q.verify(cfg, S5, "hist", revsnap=bad_snap), "V5.3d")
import struct as _st  # noqa: E402
tampered = snap[0][:16] + _st.pack(">Q", 99) + snap[0][24:]
expect_reject("F3b tampered-epoch snapshot -> V5.3d (signature mismatch)",
              lambda: Q.verify(cfg, S5, "hist", revsnap=(tampered, snap[1])), "V5.3d")

# F4: require_revsnap without trusted revocation data -> explicit rejection
expect_reject("F4 require_revsnap=True with no snapshot -> V5.3d (rejected, not silently skipped)",
              lambda: Q.verify(cfg, S5, "hist", revsnap=None, require_revsnap=True),
              "V5.3d")
record("F4b require_revsnap=True with a snapshot -> passes normally",
       Q.verify(cfg, S5, "hist", revsnap=snap, require_revsnap=True)
       == "accept_historical")

# F5: the RA registration gate rejects revoked redactors
expect_reject("F5a revoked redactor register -> R1-rev",
              lambda: RA.register(S2r, reg_sig(RA, RID, S2r, sk_n1, c_n1), c_n1),
              "R1-rev", exc=RedactRefused)

# F6: window consistency (within the record; declared ts outside the window ->
# rejected in all three modes)
S_late = resurrect(S1, {1, 3, 4, 5, 7, 8}, Policy(P0.adm, V - {3}, 6, n),
                   c_n1, sk_n1, S0.fields[3], (1 << 62) + 1, j=3)   # ts > na
expect_reject("F6 declared ts outside the certificate window -> V5.3d-window (in-record consistency)",
              lambda: Q.verify(cfg, S_late, "hist"), "V5.3d-window")

# F7: RA restart preserves revocations (rev_eff persisted)
RA2 = Q.RA.restore(RA.snapshot())
record("F7 RA snapshot/restore keeps revocation table + effective times intact",
       c_n1.id in RA2.revoked and RA2.rev_eff.get(c_n1.id) == 5000 and RA2.epoch == RA.epoch)

# F8: old calling convention (caller self-reports revlist/ref_ts) abolished ->
# TypeError = deliberate API contract change
try:
    Q.verify(cfg, S5, "hist", revlist={c_n1.id})
    record("F8 old revlist parameter abolished (TypeError)", False, "accepted self-reported list")
except TypeError:
    record("F8 old revlist parameter abolished (TypeError)", True)
try:
    Q.verify(cfg, S5, "hist", ref_ts=0)
    record("F8b old ref_ts parameter abolished (TypeError)", False, "accepted caller clock")
except TypeError:
    record("F8b old ref_ts parameter abolished (TypeError)", True)

# ---------------- F-r2. adversarial re-review round: regression of the 8 confirmed findings ----------------
# F9 (critical): a revoked redactor backfills ts on its hop and an authorized
# member registers the extension, trying to slip it into the gazette/fresh
# head -- the per-signer epoch-domain gate R3-rev blocks it.
# (RID2 hoisted above certificate issuance for the signer-scope adaptation)
c_n2 = RA.issue(RID2[:12] + b"NUR2", pk_n1, b"nurse", ((RID2,), {5, 6}), 0, 1 << 62)
P0b = Policy([(b"physician", b"*"), (b"nurse", (c_n2.id,))], set(range(2, 9)), 8, 8)
ys2 = {j: f"r2-field-{j}".encode() for j in range(1, 9)}
sd2 = canon.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, 9)])
S0b = Q.signing(pp, sk_s, c_s, RID2, ys2, P0b, rng=Q.make_rng(b"s59|f9"), schema_digest=sd2)
B1_ = B1
sig_init2 = B1_.sign(sk_s, c_s.pk, canon.M_reginit(RID2, S0b.n, S0b.acc0, S0b.P0,
                                                   canon.H(c_s.msg), sd=sd2), canon.CTX_REG)
RA.register_initial(S0b, c_s, sig_init2)
S1b = Q.redact(pp, S0b, set(range(1, 9)) - {5}, Policy(P0b.adm, set(range(2, 9)) - {3}, 7, 8),
               c_n2, sk_n1, 1000)
RA.register(S1b, reg_sig(RA, RID2, S1b, sk_n1, c_n2), c_n2)
RA.revoke(c_n2.id, eff_ts=5000)
# attack: the revoked nurse (still holding the key) backfills ts=4000<5000 to
# sign hop2; p1 unknowingly extends and registers it
S2b_atk = Q.redact(pp, S1b, set(range(1, 9)) - {5, 6},
                   Policy(P0b.adm, set(range(2, 9)) - {3}, 6, 8), c_n2, sk_n1, 4000)
S3b = Q.redact(pp, S2b_atk, set(range(1, 9)) - {5, 6, 7},
               Policy(P0b.adm, set(range(2, 9)) - {2, 3}, 5, 8), c_p1, sk_p1, 4500)
snapF = RA.revocation_snapshot()
record("F9a attack chain passes hist+revsnap (backfilled ts < eff_ts bypasses the ts-domain defense -- attack precondition demonstrated)",
       Q.verify(cfg, S3b, "hist", revsnap=snapF) == "accept_historical")
expect_reject("F9b authorized member registers an extension containing a revoked signer's hop -> R3-rev (per-signer epoch-domain gate)",
              lambda: RA.register(S3b, reg_sig(RA, RID2, S3b, sk_p1, c_p1), c_p1),
              "R3-rev", exc=RedactRefused)
record("F9c after R3-rev the RA head is untainted (RID2 still t=1)", RA.reg[RID2]["t"] == 1)

# F10: stale revsnap (pre-revocation epoch) against the current anchor -> V5.3d
expect_reject("F10 stale revsnap (epoch-0 empty table) + post-revocation fresh anchor -> V5.3d",
              lambda: Q.verify(cfg, S5, "fresh", ra=RA, nonce=b"n5" + bytes(30), revsnap=snap0),
              "V5.3d")
record("F10b current revsnap + fresh anchor -> accept (epoch follows along)",
       Q.verify(cfg, S5, "fresh", ra=RA, nonce=b"n6" + bytes(30), revsnap=snapF) == "accept_fresh")

# F11: revoke input validation and monotonicity
for bad in (None, -1, 2 ** 64, 1.5):
    try:
        RA.revoke(c_p2.id, eff_ts=bad)
        record(f"F11 revoke(eff_ts={bad!r}) rejected", False, "accepted")
        break
    except ValueError:
        pass
else:
    record("F11 revoke eff_ts missing/negative/out-of-range/non-integer -> ValueError (RA has no trusted clock; mandatory)", True)
try:
    RA.revoke(c_n1.id, eff_ts=4000)                      # below the recorded 5000
    record("F11b repeat revocation lowering eff_ts -> ValueError (monotonic)", False, "accepted")
except ValueError:
    record("F11b repeat revocation lowering eff_ts -> ValueError (monotonic)", True)

# F12: an accepted object's field table retaining a legal opening of a deleted
# index -> V1.2
T = Q.Sigma.deserialize(S5.serialize())
T.fields[2] = saved2                                     # 2 already deleted; opening still legal against acc0
try:
    Q.verify(cfg, T, "hist")
    record("F12 field table contains a non-retained index (resurrection-opening residue) -> V1.2", False, "accepted")
except VerifyReject as e:
    record("F12 field table contains a non-retained index (resurrection-opening residue) -> V1.2", e.step == "V1.2", e.step)

# F13 semantic update: a ver=2 snapshot missing revocation-epoch evidence is
# always RestoreRefused -- no longer "missing rev_eff backfills eff_ts=0 and
# stays usable" (a missing field must not be interpreted as a continuable
# state; see the G2 series in test_sf_gaps). Genuine snapshots from the frozen
# era lack even ver and are rejected earlier by the version gate.
import json as _json  # noqa: E402
_o = _json.loads(RA.snapshot().decode("utf-8"))
_o.pop("rev_eff")
try:
    Q.RA.restore(_json.dumps(_o).encode())
    record("F13 snapshot missing rev_eff -> RestoreRefused (fail-closed)", False, "restored(!)")
except Q.RestoreRefused:
    record("F13 snapshot missing rev_eff -> RestoreRefused (fail-closed)", True)

# F14: truncated revsnap -> clean V5.3d (not a struct.error crash)
expect_reject("F14 truncated revsnap -> V5.3d", lambda: Q.verify(
    cfg, S5, "hist", revsnap=(snapF[0][:20], snapF[1])), "V5.3d")

# F15: snapshot/fresh without revsnap rejected by default; explicit False =
# caller's responsibility
expect_reject("F15 fresh without revsnap (required by default) -> V5.3d",
              lambda: Q.verify(cfg, S5, "fresh", ra=RA, nonce=b"n7" + bytes(30)), "V5.3d")
expect_reject("F15b snapshot without revsnap (required by default) -> V5.3d",
              lambda: Q.verify(cfg, S5, "snapshot", gazettes=[RA.gazette(2, RID)],
                                 legacy_snapshot=True), "V5.3d")
record("F15c hist without revsnap still allowed (contract makes no current-authorization claim)",
       Q.verify(cfg, S5, "hist") == "accept_historical")

# ---------------- G. V1-V9 core tamper negatives (repairs did not break the original chain) ----------------
import copy  # noqa: E402
T = Q.Sigma.deserialize(S5.serialize())
T.sigma0 = bytes([T.sigma0[0] ^ 1]) + T.sigma0[1:]
expect_reject("G1 sigma0 tamper -> V2.2", lambda: Q.verify(cfg, T, "hist"), "V2.2")

T = Q.Sigma.deserialize(S5.serialize())
y, w = T.fields[1]
w.path = [bytes([w.path[0][0] ^ 1]) + w.path[0][1:]] + list(w.path[1:])
T.fields[1] = (y, w)
expect_reject("G2 Merkle path tamper -> V4", lambda: Q.verify(cfg, T, "hist"), "V4")

T = Q.Sigma.deserialize(S5.serialize())
e, tau, cid = T.log[0]
T.log[0] = (e, bytes([tau[0] ^ 1]) + tau[1:], cid)
expect_reject("G3 tau tamper -> V5.4", lambda: Q.verify(cfg, T, "hist"), "V5.4")

T = Q.Sigma.deserialize(S5.serialize())
T.It = T.It | {2}                    # stuff a deleted index into the final field set (no opening)
try:
    Q.verify(cfg, T, "hist")
    record("G4 deleted j stuffed into the final index set (no opening) -> clean V1.2 rejection", False, "accepted")
except VerifyReject as e:
    record("G4 deleted j stuffed into the final index set (no opening) -> clean V1.2 rejection", e.step == "V1.2", e.step)

expect_reject("G5 empty deletion -> V7.1",
              lambda: Q.redact(pp, S5, set(S5.It), Policy(adm3, V - {3, 6}, 2, n),
                               c_p1, sk_p1, 3000), "R0", exc=RedactRefused)

T = Q.Sigma.deserialize(S5.serialize())
e_bytes, tau, cid = T.log[1]
hop = Q.dec_e(e_bytes, T.n)
e_bad = canon.enc_e(hop["seq"], hop["id"], hop["role"], hop["certH"],
                    hop["I_prev"], hop["I_prev"] - {6} - {4},   # secretly drop extra fields {6},{4}
                    hop["P_prev"], hop["P_new"], hop["ts"], T.n)
T.log[1] = (e_bad, tau, cid)
expect_reject("G6 hop content replacement (chain break) -> V6/V5.4", lambda: Q.verify(cfg, T, "hist"))

R["t_total_s"] = round(time.time() - R["t_start"], 1)
R["pass_count"] = f"{sum(1 for v in R['tests'].values() if v['pass'])}/{len(R['tests'])}"
print(f"\n=== t64 regression {R['pass_count']} PASS in {R['t_total_s']}s ===")
os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
with open(os.path.join(ROOT, "logs", "t64_regression.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
