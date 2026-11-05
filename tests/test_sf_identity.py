# -*- coding: utf-8 -*-
"""Identity substitution (RID vs initial signer): verification of the fix.

Background: a prior code-verification audit demonstrated that the frozen
implementation accepted a "swapped key + swapped certificate + same Theta0"
substitution (both hist and fresh accept; a wildcard signer scope was the
formal-fixture shape). This test verifies the fixed behavior:

  A1  Issuance constraints: a signer certificate scope must enumerate RIDs
      explicitly; one RID binds one signer (id,pk); renewal is restricted to
      the same (id,pk); redactor certificates are unaffected.
  A2  Registration binding: reg[rid].cid = H(Cert_S.msg) (initial-body
      digest, historical semantics); reg[rid].bid = BindId(RID, ID_S, PK)
      (the renewal-stable identity digest); the fresh response (M_resp5)
      carries bid, and Verify(fresh) compares it against
      BindId(RID, ID_S, PK).
  A3  hist fix scope: wildcard signer certificates -> rejected at V2.1; a
      second scoped certificate for the same RID is unobtainable under an
      honest RA (issuance uniqueness); white-box collusion (using the RA
      signing key directly) is a documented PKI trust boundary -- hist
      accepts, fresh is rejected via the binding check (recorded as-is; no
      fake hist rejection).

Required six negatives: same-RID different-key substitution rejected by
hist / same substitution rejected by fresh / wildcard signer scope
rejected / other-RID scope rejected / second issuance by the administrator
refused / the honest path still passes.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from s6t64 import s5_qprss as Q                      # noqa: E402
from s6t64 import canon, policy as pol               # noqa: E402

R = {"tests": {}}


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  {note}" if note else ""))


def expect_reject(name, fn, step, exc=Q.VerifyReject):
    try:
        fn()
        record(name, False, "accepted(!)")
    except exc as e:
        got = getattr(e, "step", "") or ""
        record(name, step in got or step in str(e),
               f"{type(e).__name__}@{got}: {e}")


RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
RID_OTHER = bytes.fromhex("7766554433221100ffeeddccbbaa9988")
N = 6

pp = Q.setup("B1", seed=b"sf-a|pp")
RA = Q.RA("B1")
cfg = {"pk_ra": RA.pk}
B1 = Q.s5_sig.core("B1")

skA, pkA = B1.keygen()
skB, pkB = B1.keygen()
certA = RA.issue(RID[:12] + b"SGNR", pkA, b"signer", ((RID,), b"*"), 0, 1 << 62)

ys = {j: f"v{j}".encode() for j in range(1, N + 1)}
sd = canon.schema_digest([(j, ("Patient", f"a{j}"), "str") for j in range(1, N + 1)])
P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, N + 1)), N, N)
S1 = Q.signing(pp, skA, certA, RID, ys, P0, rng=Q.make_rng(b"sf-a|sg"), schema_digest=sd)
snap = RA.revocation_snapshot()

# ---------------- A1 issuance constraints ----------------
try:
    RA.issue(b"\x11" * 16, pkB, b"signer", (b"*", b"*"), 0, 1 << 62)
    record("A1-1 wildcard signer scope refused at issuance", False, "issued(!)")
except Q.IssuanceRefused as e:
    record("A1-1 wildcard signer scope refused at issuance", True, str(e))
try:
    RA.issue(b"\x11" * 16, pkB, b"signer", ((), b"*"), 0, 1 << 62)
    record("A1-2 empty RID enumeration refused at issuance", False, "issued(!)")
except Q.IssuanceRefused:
    record("A1-2 empty RID enumeration refused at issuance", True)
# Second issuance: same RID with a different (id,pk) -> refused; the same
# (id,pk) -> renewal allowed
try:
    RA.issue(RID[:12] + b"SGNB", pkB, b"signer", ((RID,), b"*"), 0, 1 << 62)
    record("A1-3 second issuance for the same RID with a different signer refused", False, "issued(!)")
except Q.IssuanceRefused as e:
    record("A1-3 second issuance for the same RID with a different signer refused", True, str(e))
try:
    certA2 = RA.issue(certA.id, certA.pk, b"signer", ((RID,), b"*"), 0, 1 << 63)
    record("A1-4 renewal with the same (id,pk) allowed (window extended)", certA2.verify(RA.pk))
except Q.IssuanceRefused as e:
    record("A1-4 renewal with the same (id,pk) allowed", False, str(e))
c_ed = RA.issue(b"\x22" * 16, pkB, b"physician", (b"*", b"*"), 0, 1 << 62)
record("A1-5 redactor wildcard scope unaffected", c_ed.verify(RA.pk) and c_ed.role == b"physician")
record("A1-6 binding table has exactly one entry, the (id,pk)",
       RA.signers == {RID: (certA.id, certA.pk)})

# ---------------- Honest path still passes ----------------
record("A2-1 honest path hist still accepts", Q.verify(cfg, S1, "hist") == "accept_historical")
sig_init = B1.sign(skA, certA.pk,
                   canon.M_reginit(RID, N, S1.acc0, S1.P0, canon.H(certA.msg), sd=sd),
                   canon.CTX_REG)
record("A2-2 RegisterInitial passes normally", RA.register_initial(S1, certA, sig_init) == 0)
record("A2-3 reg[rid].cid == H(Cert_S.msg) and bid == BindId(RID,ID,PK) (A2 registration)",
       RA.reg[RID]["cid"] == canon.H(certA.msg)
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, certA.pk)
       and canon.BindId(RID, certA.id, certA.pk) != canon.H(certA.msg))
n32 = b"sf-a-nonce".ljust(32, b"|")        # exactly 32B
record("A2-4 honest path fresh still accepts (M_resp5+bid)",
       Q.verify(cfg, S1, "fresh", ra=RA, nonce=n32, revsnap=snap) == "accept_fresh")

# ---------------- Identity-substitution attack (replicating the audited scenario) ----------------
def clone_with_signer(S, skX, certX):
    """Attacker copy: swap the sigma0 signer key + certificate, keep everything else (Theta0/h0/chain) as-is."""
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


# (a) wildcard-certificate substitution (the frozen implementation's accept path) -- hist rejects (V2.1 wildcard-signer rejection)
certB_wild = Q.Cert(b"\x99" * 16, pkB, b"signer", (b"*", b"*"), 0, 1 << 62, scheme="B1")
certB_wild.sig = RA._sign(certB_wild.msg, canon.CTX_CERT)   # white-box: signed directly with the RA key
S2w = clone_with_signer(S1, skB, certB_wild)
expect_reject("A3-1 wildcard-certificate substitution rejected by hist (V2.1-scope)",
              lambda: Q.verify(cfg, S2w, "hist"), "V2.1")
expect_reject("A3-2 wildcard-certificate substitution rejected by fresh (V2.1-scope)",
              lambda: Q.verify(cfg, S2w, "fresh", ra=RA, nonce=n32, revsnap=snap),
              "V2.1")

# (b) other-RID scope certificate substitution -- rejected by V2.1-scope (ScopeMatchRID)
certC = Q.Cert(b"\x88" * 16, pkB, b"signer", ((RID_OTHER,), b"*"), 0, 1 << 62, scheme="B1")
certC.sig = RA._sign(certC.msg, canon.CTX_CERT)
S3 = clone_with_signer(S1, skB, certC)
expect_reject("A3-3 other-RID scope certificate substitution rejected by hist",
              lambda: Q.verify(cfg, S3, "hist"), "V2.1")

# (c) a second certificate with a same-RID enumerated scope -- unobtainable
# under an honest RA (A1-3 above); white-box collusion (forging with the RA
# signing key directly) = documented PKI trust boundary: hist accepts, fresh
# rejects.
certD = Q.Cert(b"\x77" * 16, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62, scheme="B1")
certD.sig = RA._sign(certD.msg, canon.CTX_CERT)
S4 = clone_with_signer(S1, skB, certD)
try:
    r = Q.verify(cfg, S4, "hist")
    record("A3-4 white-box collusion enumerated certificate accepted by hist (PKI trust boundary, recorded as-is)",
           r == "accept_historical", "hist signature chain is self-consistent -- the defense is issuance uniqueness (honest RA)")
except Q.VerifyReject as e:
    record("A3-4 white-box collusion enumerated certificate accepted by hist (PKI trust boundary)", False, f"reject@{e.step}")
expect_reject("A3-5 same substitution rejected by fresh (cid binding: reg.cid != H(Cert_D.msg))",
              lambda: Q.verify(cfg, S4, "fresh", ra=RA, nonce=n32, revsnap=snap), "V9")

# (d) white-box substituter's RegisterInitial -- I1-bnd rejection (signers[RID] already bound to (id_A,pk_A))
sig_initD = B1.sign(skB, certD.pk,
                    canon.M_reginit(RID, N, S1.acc0, S1.P0, canon.H(certD.msg), sd=sd),
                    canon.CTX_REG)
expect_reject("A3-6 white-box substituter RegisterInitial rejected (I1-bnd)",
              lambda: RA.register_initial(S1, certD, sig_initD), "I1-bnd",
              exc=Q.RedactRefused)

# (e) forged (non-RA) certificate -- rejected by the V2.1 signature check
certE = Q.Cert(b"\x66" * 16, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62, scheme="B1")
certE.sig = b"\x00" * 5794
S5 = clone_with_signer(S1, skB, certE)
expect_reject("A3-7 non-RA-signed certificate rejected (V2.1 signature check)", lambda: Q.verify(cfg, S5, "hist"),
              "V2.1")

# (f) post-registration extension: an identity-swapped signer's forked chain
# cannot reach the registration gate (R2b)
# -- the editing chain follows the honest path:
sk_ed, pk_ed = B1.keygen()
c_ed2 = RA.issue(b"\x33" * 16, pk_ed, b"physician", ((RID,), b"*"), 0, 1 << 62)
S1b = Q.redact(pp, S1, set(range(1, N + 1)) - {2},
               pol.Policy(P0.adm, P0.w - {3}, P0.d - 1, N), c_ed2, sk_ed, 10)
m_reg = canon.M_reg(RID, RA.reg[RID]["ver"], RA.reg[RID]["h"],
                    RA.reg[RID]["ver"] + 1, S1b.h_t, len(S1b.log),
                    canon.H(c_ed2.msg), c_ed2.id, c_ed2.role)
RA.register(S1b, B1.sign(sk_ed, pk_ed, m_reg, canon.CTX_REG), c_ed2)
record("A2-5 honest redact + Register extension still passes", RA.reg[RID]["t"] == 1)
# White-box signer B signs M_reg with its own certificate (even a correctly
# forged M_reg) -> R2b
m_regB = canon.M_reg(RID, RA.reg[RID]["ver"], RA.reg[RID]["h"],
                     RA.reg[RID]["ver"] + 1, S1b.h_t, len(S1b.log),
                     canon.H(certD.msg), certD.id, certD.role)
sig_regB = B1.sign(skB, pkB, m_regB, canon.CTX_REG)
expect_reject("A3-8 white-box signer Register under a different bound identity rejected (R2b)",
              lambda: RA.register(S1b, sig_regB, certD), "R2b", exc=Q.RedactRefused)
record("A2-6 reg[rid].cid/bid unchanged by Register",
       RA.reg[RID]["cid"] == canon.H(certA.msg)
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, certA.pk))
snap2 = RA.revocation_snapshot()
record("A2-7 fresh still accepts after extension (bid retained)",
       Q.verify(cfg, S1b, "fresh", ra=RA, nonce=b"sf-a-nonce2".ljust(32, b"|"),
                revsnap=snap2) == "accept_fresh")

# ---------------- Snapshot/restore fidelity ----------------
ra2 = Q.RA.restore(RA.snapshot())
record("A4-1 snapshot/restore preserves signers+cid+bid",
       ra2.signers == RA.signers and ra2.reg[RID]["cid"] == RA.reg[RID]["cid"]
       and ra2.reg[RID]["bid"] == RA.reg[RID]["bid"])
record("A4-2 fresh still accepts after restore (same bid chain)",
       Q.verify({"pk_ra": ra2.pk}, S1b, "fresh", ra=ra2,
                nonce=b"sf-a-nonce3".ljust(32, b"|"), revsnap=snap2) == "accept_fresh")

R["verdict"] = "ALL_SF_IDENTITY_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "SF_IDENTITY_FAIL"
with open(os.path.join(os.path.dirname(HERE), "logs", "sf_identity.json"), "w",
          encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(R["verdict"])
sys.exit(0 if R["verdict"] == "ALL_SF_IDENTITY_PASS" else 1)
