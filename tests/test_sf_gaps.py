# -*- coding: utf-8 -*-
"""Two closing fixes: (1) a renewal-stable identity digest bid; (2) fail-closed
restoration of old RA snapshots.

Task 1 (G1): bid_S = BindId(RID, ID_S, PK) (canon.H_B domain, 384-bit; covers
  neither validity window, nor sequence number, nor issuance version, nor
  signature randomness); the fresh response M_resp5 (= the paper's EncResp_5)
  carries bid; V9 compares the response bid against the artifact's
  BindId(RID, ID_S, PK).
  Acceptance: after a legitimate renewal for the same RID and (ID_S,PK) (new
  validity window, new body, new administrator signature), the renewed
  artifact accepts hist and fresh, and the original artifact still accepts
  fresh; issuing under a different ID or PK is refused and the
  swapped-certificate artifact fails fresh; tampering with the response's
  bid/RID/nonce/chain head/epoch is always rejected.
Task 2 (G2): restore is fail-closed on version/signers/cid/bid/rollback/
  conflict; an old snapshot with missing evidence must not restore to a state
  that bypasses the unique binding; RA.issue refuses to sign on incomplete
  state; concurrent issuance for the same RID keeps a unique binding.
"""
import copy
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from s6t64 import s5_qprss as Q                      # noqa: E402
from s6t64 import canon, policy as pol               # noqa: E402

R = {"tests": {}}


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  {note}" if note else ""))


def vr(name, fn, step="V9", exc=Q.VerifyReject):
    """Assert that fn is rejected by exc; step=None means any rejection point."""
    try:
        fn()
        record(name, False, "accepted(!)")
    except exc as e:
        got = getattr(e, "step", "") or str(e)[:60]
        record(name, step is None or got == step or got.startswith(str(step)),
               f"@{got}: {str(e)[:70]}")


RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
N = 6
B1 = Q.s5_sig.core("B1")

pp = Q.setup("B1", seed=b"sf-gaps|pp")
RA = Q.RA("B1")
cfg = {"pk_ra": RA.pk}
skA, pkA = B1.keygen()
ys = {j: f"v{j}".encode() for j in range(1, N + 1)}
sd = canon.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, N + 1)])
P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, N + 1)), N, N)
certA = RA.issue(RID[:12] + b"SGNR", pkA, b"signer", ((RID,), b"*"), 0, 1 << 62)
sk_n, pk_n = B1.keygen()
c_n = RA.issue(b"\x44" * 16, pk_n, b"nurse", ((RID,), b"*"), 0, 1 << 62)
P0 = pol.Policy(((b"physician", b"*"), (b"nurse", (c_n.id,))),
                frozenset(range(2, N + 1)), N, N)
S1 = Q.signing(pp, skA, certA, RID, ys, P0, rng=Q.make_rng(b"sf-gaps|sg"),
               schema_digest=sd)
sig_init = B1.sign(skA, certA.pk,
                   canon.M_reginit(RID, N, S1.acc0, S1.P0, canon.H(certA.msg), sd=sd),
                   canon.CTX_REG)
n32 = b"sf-gaps-n1".ljust(32, b"|")


def clone_with_signer(S, skX, certX):
    """Same Theta0 with a swapped certificate (sigma0 re-signed under certX.pk; Theta0/h0/field values unchanged; t=0 artifact)."""
    S2 = Q.Sigma(S.scheme, S.rid, S.n)
    S2.sd, S2.acc0, S2.P0, S2.It = S.sd, S.acc0, S.P0, set(S.It)
    S2.fields = dict(S.fields)
    S2.Pt = S.Pt
    S2.sigma0 = B1.sign(skX, certX.pk,
                        canon.M_orig(S.rid, S.n, S.acc0, S.P0,
                                     set(range(1, S.n + 1)), sd=S.sd), canon.CTX_ORIG)
    S2.cert_s = certX
    S2.h_t = S.h_t
    return S2


def fresh(S, nonce=None, ra=None, snap=None):
    kw = {"ra": ra or RA, "nonce": nonce or os.urandom(32)}
    if snap is not None:
        kw["revsnap"] = snap
    return Q.verify({"pk_ra": (ra or RA).pk}, S, "fresh", **kw)


# ================= Task 1: G1 renewal-stable identity digest =================
# ---- G1-1 initial registration: cid/bid both recorded, hist+fresh both accept ----
vr("G1-1a fresh on an unregistered RID rejected first (no registration)",
   lambda: fresh(S1, snap=RA.revocation_snapshot()), step=None, exc=Q.RedactRefused)
RA.register_initial(S1, certA, sig_init)
snap0 = RA.revocation_snapshot()
record("G1-1b initial registration records cid=CertId(M_certS) and bid=BindId(RID,ID,PK)",
       RA.reg[RID]["cid"] == canon.CertId(certA.msg)
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, certA.pk)
       and len(RA.reg[RID]["bid"]) == 48)
record("G1-1c cid != bid (different domain tags/inputs; the three digests never conflate)",
       RA.reg[RID]["cid"] != RA.reg[RID]["bid"]
       and canon.CertId(certA.msg) == canon.H(certA.msg)
       and canon.BindId(RID, certA.id, certA.pk)
       == canon.H_B(RID + certA.id + certA.pk))
len_ok = True
for bad in ((RID[:15], certA.id, certA.pk), (RID, certA.id[:15], certA.pk)):
    try:
        canon.BindId(*bad)
        len_ok = False
    except ValueError:
        pass
record("G1-1d BindId domain separation (H_B != H != H_L), 16B input checks, 48B output",
       len_ok and canon.H_B(b"x") != canon.H(b"x") and canon.H_B(b"x") != canon.H_L(b"x")
       and len(canon.BindId(RID, certA.id, certA.pk)) == 48)
record("G1-1e initial artifact accepts hist+fresh",
       Q.verify(cfg, S1, "hist") == "accept_historical"
       and fresh(S1, n32, snap=snap0) == "accept_fresh")

# ---- G1-2 identical-certificate reuse (same params reissued -> same certificate body) ----
certA_dup = RA.issue(RID[:12] + b"SGNR", pkA, b"signer", ((RID,), b"*"), 0, 1 << 62)
record("G1-2 same parameters reissued = same certificate body (reuse does not change the binding)",
       certA_dup.msg == certA.msg and certA_dup.verify(RA.pk)
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, pkA)
       and fresh(S1, snap=snap0) == "accept_fresh")

# ---- G1-3 legitimate renewal, same RID and (ID,PK): new validity window/body/administrator signature ----
certA2 = RA.issue(certA.id, certA.pk, b"signer", ((RID,), b"*"), 0, 1 << 63)
record("G1-3a renewal issued, body/administrator signature both differ (same id+pk, new validity)",
       certA2.id == certA.id and certA2.pk == certA.pk
       and certA2.msg != certA.msg and certA2.sig != certA.sig
       and certA2.verify(RA.pk) and certA2.na == 1 << 63)
record("G1-3b reg.cid keeps the initial body digest (historical semantics unchanged); bid unchanged by renewal",
       RA.reg[RID]["cid"] == canon.H(certA.msg)
       and canon.H(certA2.msg) != RA.reg[RID]["cid"]
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, pkA))
S1r = clone_with_signer(S1, skA, certA2)
record("G1-3c renewed-certificate artifact accepts hist", Q.verify(cfg, S1r, "hist") == "accept_historical")
record("G1-3d renewed-certificate artifact accepts fresh (fix acceptance: no longer wrongly rejected because cid changed)",
       fresh(S1r, snap=snap0) == "accept_fresh")

# ---- G1-4 original-certificate artifact still accepts fresh after renewal ----
record("G1-4 original artifact still accepts fresh after renewal (neither cid nor bid drifts)",
       fresh(S1, snap=snap0) == "accept_fresh"
       and Q.verify(cfg, S1, "hist") == "accept_historical")

# ---- G1-5 different ID or PK: issuance refused + artifact not accepted ----
skB, pkB = B1.keygen()
vr("G1-5a renewal with a different ID for the same RID refused at issuance (IssuanceRefused)",
   lambda: RA.issue(b"\x77" * 16, pkA, b"signer", ((RID,), b"*"), 0, 1 << 62),
   step=None, exc=Q.IssuanceRefused)
vr("G1-5b renewal with a different PK for the same RID refused at issuance (IssuanceRefused)",
   lambda: RA.issue(certA.id, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62),
   step=None, exc=Q.IssuanceRefused)
# White-box swapped-certificate artifact (documented PKI collusion boundary):
# hist can pass (an honest RA would never issue this certificate); fresh is
# rejected by the V9 bid binding -- exactly the verification-side semantics
# of the cid->bid fix.
certD = Q.Cert(b"\x88" * 16, pkA, b"signer", ((RID,), b"*"), 0, 1 << 62, scheme="B1")
certD.sig = RA._sign(certD.msg, canon.CTX_CERT)
S1D = clone_with_signer(S1, skA, certD)
record("G1-5c white-box different-ID certificate accepted by hist (collusion boundary, recorded as-is)",
       Q.verify(cfg, S1D, "hist") == "accept_historical")
vr("G1-5d white-box different-ID certificate rejected by fresh (V9 bid identity mismatch)", lambda: fresh(S1D, snap=snap0))
certE = Q.Cert(certA.id, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62, scheme="B1")
certE.sig = RA._sign(certE.msg, canon.CTX_CERT)
S1E = clone_with_signer(S1, skB, certE)
vr("G1-5e white-box different-PK certificate rejected by fresh (V9 bid identity mismatch)", lambda: fresh(S1E, snap=snap0))

# ---- G1-6 every response-field tampering rejected (signature-recomputation layer; M_resp5 covers all seven fields + prefix) ----
resp, a_h, a_t, a_ts, a_ep, a_bid = RA.fresh_query(n32, RID)
xor = lambda b: bytes(x ^ 0xFF for x in b)               # noqa: E731
ok_tamper = True
for tampered in (
    canon.M_resp5(n32, RID, a_h, a_t, a_ts, a_ep, a_bid[::-1]),            # bid
    canon.M_resp5(n32, xor(RID), a_h, a_t, a_ts, a_ep, a_bid),             # RID
    canon.M_resp5(xor(n32), RID, a_h, a_t, a_ts, a_ep, a_bid),             # nonce
    canon.M_resp5(n32, RID, a_h[::-1], a_t, a_ts, a_ep, a_bid),             # chain head h*
    canon.M_resp5(n32, RID, a_h, a_t + 1, a_ts, a_ep, a_bid),               # t*
    canon.M_resp5(n32, RID, a_h, a_t, a_ts + 1, a_ep, a_bid),               # ts
    canon.M_resp5(n32, RID, a_h, a_t, a_ts, a_ep + 1, a_bid),               # epoch
    b"QPRSS-v4|resp" + canon.M_resp5(n32, RID, a_h, a_t, a_ts, a_ep,
                                     a_bid)[13:],                            # v4 prefix
):
    if B1.verify(RA.pk, tampered, resp, canon.CTX_ANC):
        ok_tamper = False
record("G1-6 any tampered response field (bid/RID/nonce/h*/t*/ts/epoch/prefix) fails signature verification", ok_tamper)
# The verify layer has no response-injection parameter (the fresh response is
# obtained only by the verifier querying the RA live): an external response
# cannot be passed in => no replay surface at the verifier interface
# (structural guarantee).
try:
    Q.verify({"pk_ra": RA.pk}, S1, "fresh", ra=RA, nonce=n32, revsnap=snap0,
             resp=resp)
    record("G1-6b verifier has no response-injection parameter (external response cannot be passed in => no replay surface)", False,
           "accepted(!)")
except TypeError:
    record("G1-6b verifier has no response-injection parameter (external response cannot be passed in => no replay surface)", True)

# ---- G1-7 M_resp5 byte layout (per-field offsets; 177B, same length as v4) ----
m5 = canon.M_resp5(n32, RID, a_h, a_t, a_ts, a_ep, a_bid)
record("G1-7 M_resp5 layout 13+32+16+48+4+8+8+48=177 (every field offset hits)",
       len(m5) == 177 and m5[:13] == b"QPRSS-v5|resp"
       and m5[13:45] == n32 and m5[45:61] == RID and m5[61:109] == a_h
       and m5[109:113] == canon.enc32(a_t) and m5[113:121] == canon.enc64(a_ts)
       and m5[121:129] == canon.enc64(a_ep) and m5[129:177] == a_bid)

# ================= Chain advance (G2 snapshots need t>=1, otherwise rollback is moot) =================
P1 = pol.Policy(P0.adm, P0.w - {4}, P0.d - 1, N)
S2 = Q.redact(pp, S1, set(range(1, N + 1)) - {2}, P1, c_n, sk_n, 100)
m_reg = canon.M_reg(RID, RA.reg[RID]["ver"], RA.reg[RID]["h"],
                    RA.reg[RID]["ver"] + 1, S2.h_t, len(S2.log),
                    canon.H(c_n.msg), c_n.id, c_n.role)
RA.register(S2, B1.sign(sk_n, pk_n, m_reg, canon.CTX_REG), c_n)
record("G0 after chain advance reg t=1/ver=1 (precondition for G2)",
       RA.reg[RID]["t"] == 1 and RA.reg[RID]["ver"] == 1)

# ================= Task 2: G2 fail-closed restoration of old state =================
snap_full = json.loads(RA.snapshot())


def try_restore(obj):
    try:
        Q.RA.restore(json.dumps(obj).encode())
        return ("ok", None)
    except Q.RestoreRefused as e:
        return ("RestoreRefused", str(e)[:80])
    except Exception as e:                          # noqa: BLE001
        return (type(e).__name__, str(e)[:80])


def variant(*ops):
    o = copy.deepcopy(snap_full)
    for op in ops:
        op(o)
    return o


def del_signers(o):
    o.pop("signers")


def del_ver(o):
    o.pop("ver")


def del_cid(o):
    o["reg"][RID.hex()].pop("cid")


def del_bid(o):
    o["reg"][RID.hex()].pop("bid")


def set_cid_none(o):
    o["reg"][RID.hex()]["cid"] = None


r1 = try_restore(variant(del_signers))
record("G2-1 old snapshot missing signers -> RestoreRefused (not interpreted as an empty registry)",
       r1[0] == "RestoreRefused", r1[1])
r2 = try_restore(variant(del_cid))
record("G2-2 old snapshot reg missing cid -> RestoreRefused (no KeyError leak)",
       r2[0] == "RestoreRefused", r2[1])
r3 = try_restore(variant(del_bid))
record("G2-3 old snapshot reg missing bid -> RestoreRefused", r3[0] == "RestoreRefused", r3[1])
r4 = try_restore(variant(set_cid_none))
record("G2-3b reg.cid=None (older format) -> RestoreRefused", r4[0] == "RestoreRefused",
       r4[1])
r5 = try_restore(variant(del_ver))
record("G2-4 versionless snapshot (frozen-era format) -> RestoreRefused", r5[0] == "RestoreRefused",
       r5[1])
try:
    Q.RA.restore(b"not-json{")
    r6 = ("accepted", None)
except Q.RestoreRefused as e:
    r6 = ("RestoreRefused", str(e)[:80])
except Exception as e:                              # noqa: BLE001
    r6 = (type(e).__name__, str(e)[:80])
record("G2-4b non-JSON/truncated blob -> RestoreRefused (not a crash)", r6[0] == "RestoreRefused",
       r6[1])


# ---- G2-5 registry-state conflict: signers binding vs reg.bid mutual exclusion ----
def conflict_signer(o):
    i = bytes.fromhex(o["signers"][0][1])
    o["signers"][0][1] = (i[:15] + b"\x99").hex()


def unregistered_binding(o):
    """Issue-only intermediate state: the RID has a binding but no registration (all traces of the RID removed from reg/log)."""
    del o["reg"][RID.hex()]
    o["log"] = [e for e in o["log"] if e[0] != RID.hex()]


def fake_bound_unregistered(o):
    unregistered_binding(o)
    o["signers"] = [[RID.hex(), (b"\x77" * 16).hex(), certA.pk.hex()]]


r7 = try_restore(variant(conflict_signer))
record("G2-5 signers binding differs from reg.bid (identity conflict) -> RestoreRefused",
       r7[0] == "RestoreRefused", r7[1])
# The other direction: a signers binding for an unregistered rid is a legal
# intermediate state (issue before RegisterInitial) and restores fine; but if
# the binding points to a different (id,pk), RegisterInitial on it is
# rejected by I1-bnd.
r8 = try_restore(variant(unregistered_binding))
record("G2-5b issue-only intermediate state (binding to an unregistered rid) restores", r8[0] == "ok", r8[1])
ra_io = Q.RA.restore(json.dumps(variant(fake_bound_unregistered)).encode())
vr("G2-5c RegisterInitial with a different (id,pk) on the restored state rejected (I1-bnd)",
   lambda: ra_io.register_initial(S1, certA, sig_init), "I1-bnd",
   exc=Q.RedactRefused)


# ---- G2-6 malicious rollback: roll back reg only (or drop the log tail) -> refused ----
def rollback_reg(o):
    o["reg"][RID.hex()]["t"] = 0                    # reg rolled back, log tail still truthful


def drop_log_tail(o):
    o["log"] = o["log"][:-1]                        # drop the tail entry (missing evidence)


r9 = try_restore(variant(rollback_reg))
record("G2-6a malicious reg rollback (log not rolled back) -> RestoreRefused", r9[0] == "RestoreRefused",
       r9[1])
r10 = try_restore(variant(drop_log_tail))
record("G2-6b dropping the registration-log tail entry (missing evidence) -> RestoreRefused",
       r10[0] == "RestoreRefused", r10[1])

# ---- G2-7 full new-snapshot restore: usable, unique binding kept, fresh passes ----
RA2 = Q.RA.restore(RA.snapshot())
record("G2-7a full new-snapshot restore succeeds (reg/log/signers/epoch faithful)",
       RA2.reg[RID]["bid"] == canon.BindId(RID, certA.id, pkA)
       and RA2.reg[RID]["cid"] == canon.H(certA.msg)
       and RA2.signers == RA.signers and RA2.epoch == RA.epoch)
vr("G2-7b after restore, issuing for the same RID under a different (id,pk) refused (unique binding cannot be bypassed)",
   lambda: RA2.issue(b"\x77" * 16, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62),
   step=None, exc=Q.IssuanceRefused)
record("G2-7c after restore, renewal with the same (id,pk) still legal (no false rejection)",
       RA2.issue(certA.id, certA.pk, b"signer", ((RID,), b"*"), 1, 1 << 62)
       .verify(RA2.pk))
record("G2-7d after restore fresh accept (M_resp5+bid chain intact, t=1 artifact)",
       Q.verify({"pk_ra": RA2.pk}, S2, "fresh", ra=RA2, nonce=os.urandom(32),
                revsnap=RA2.revocation_snapshot()) == "accept_fresh")

# ---- G2-8 identity-substitution loop closed: the old path (restore old
# snapshot -> second certificate -> swapped-certificate artifact) flips from
# accepted to rejected ----
# Attack chain against the frozen/first-round implementation (probe-verified):
# a field-stripped old snapshot restored with empty signers -> a second
# signer certificate for the same RID under a different (id,pk) honestly
# issued -> swapped-certificate artifact revived under hist.
# Now: the chain head (restore) itself raises RestoreRefused, so the later
# issue/hist steps can never happen.
attacker_states = [variant(del_signers), variant(del_cid, del_bid), variant(del_ver)]
closed = all(try_restore(s)[0] == "RestoreRefused" for s in attacker_states)
record("G2-8 identity-substitution attack chain closed at the restore entry (accept->RestoreRefused)", closed,
       f"all {len(attacker_states)} old-format snapshots rejected")

# ---- G2-9 incomplete state refuses issuance (_require_complete gate) ----
ra_inc = Q.RA("B1")
ra_inc._complete = False
vr("G2-9a issue on incomplete RA state refused (IssuanceRefused)",
   lambda: ra_inc.issue(b"\x11" * 16, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62),
   step=None, exc=Q.IssuanceRefused)
vr("G2-9b fresh_query on incomplete RA state refused",
   lambda: ra_inc.fresh_query(n32, RID), step=None, exc=Q.IssuanceRefused)
vr("G2-9c register_initial on incomplete RA state refused",
   lambda: ra_inc.register_initial(S1, certA, sig_init), step=None,
   exc=Q.IssuanceRefused)

# ---- G2-10 multithreaded issuance for the same RID: exactly one winner of the unique binding ----
RA3 = Q.RA("B1")
keys = [B1.keygen() for _ in range(8)]
results = []
lk = threading.Lock()


def worker(i):
    _sk, pk = keys[i]
    try:
        c = RA3.issue(bytes([0x30 + i]) * 16, pk, b"signer", ((RID,), b"*"),
                      0, 1 << 62)
        ok = c.verify(RA3.pk)
    except Q.IssuanceRefused:
        ok = False
    with lk:
        results.append(ok)


threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
record("G2-10 8-thread issuance for the same RID with distinct (id,pk): exactly 1 succeeds and the binding is unique",
       sum(results) == 1 and len(RA3.signers) == 1,
       f"ok={sum(results)}/8, bound={len(RA3.signers)}")

# Concurrent renewal with the same (id,pk) after binding: all allowed (same
# identity, legal); no racy state corruption
bound_id, bound_pk = next(iter(RA3.signers.values()))
results2 = []


def worker2(_i):
    try:
        RA3.issue(bound_id, bound_pk, b"signer", ((RID,), b"*"), 0, 1 << 62)
        ok = True
    except Q.IssuanceRefused:
        ok = False
    with lk:
        results2.append(ok)


threads = [threading.Thread(target=worker2, args=(i,)) for i in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
record("G2-10b after binding, 8 concurrent renewals with the same (id,pk) all succeed and the snapshot stays valid",
       all(results2) and len(RA3.signers) == 1
       and try_restore(json.loads(RA3.snapshot()))[0] == "ok")

R["verdict"] = "ALL_SF_GAPS_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "SF_GAPS_FAIL"
with open(os.path.join(os.path.dirname(HERE), "logs", "sf_gaps.json"), "w",
          encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(R["verdict"])
sys.exit(0 if R["verdict"] == "ALL_SF_GAPS_PASS" else 1)
