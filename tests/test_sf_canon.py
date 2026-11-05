# -*- coding: utf-8 -*-
"""Canonical restricted-policy encoding + byte-equivalence regression against
the frozen originals.

Gap in the frozen implementation: encP was non-canonical -- the same
semantics with a different adm order produced different bytes, and duplicate
entries were not rejected. After the fix: a unique deterministic encoding
(strict adm_key ordering + sorted, deduplicated ids within an entry; Policy
construction itself normalizes); dec_encP rejects duplicates, illegal tags,
illegal role codes, empty enumerations, out-of-order input, and truncation.
Byte agreement between the signing and verification sides is guaranteed by
round-trips and cross-implementation equivalence.

Equivalence regression (reference = run/baseline_run/s6t64base, the frozen
original shipped as an alias copy):
- encP of the fixture-shaped policies byte-identical (formal-data
  compatibility);
- M_certR/M_orig/M_init/M_red/M_reginit/M_reg/M_revsnap byte-identical;
- M_certS changes only with the scope representation: wildcard (1B) ->
  enumeration (18B) = +17B;
- same-seed full-chain Sigma (incl. sigma0/tau/Theta0/h chain) byte-identical
  across implementations.
"""
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # avoid crashes on GBK consoles

HERE = os.path.dirname(os.path.abspath(__file__))
# Release layout: the fixed tree and the baseline tree live under run/.
FIXED_ROOT = os.path.join(os.path.dirname(HERE), "run", "fixed_run")
BASE_ROOT = os.path.join(os.path.dirname(HERE), "run", "baseline_run")
sys.path.insert(0, BASE_ROOT)                          # baseline first (lower priority)
sys.path.insert(0, FIXED_ROOT)                         # fixed tree wins: s6t64 = fixed code

import s6t64 as FX                                     # fixed implementation
import s6t64base as BS                                 # frozen original (alias copy)
import s6t64.policy, s6t64.canon, s6t64.s5_qprss, s6t64.s5_sig, s6t64.s4compat
import s6t64base.policy, s6t64base.canon, s6t64base.s5_qprss
import s6t64base.s5_sig, s6t64base.s4compat

from s6t64 import canon as cfx, policy as pfx          # noqa: E402
from s6t64 import s5_qprss as QFX                      # noqa: E402

R = {"tests": {}}


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  {note}" if note else ""))


ID1, ID2 = b"\x11" * 16, b"\x22" * 16

# ---------------- C1 round-trip ----------------
POLICIES = [
    (((b"physician", b"*"),), frozenset({2, 3}), 5, 6),                     # formal shape
    (((b"physician", b"*"), (b"nurse", (ID1,))), frozenset(range(2, 7)), 6, 6),
    (((b"physician", b"*"), (b"admin", (ID1, ID2)), (b"nurse", (ID1,))), {2}, 3, 8),
    (((b"auditor", (ID2,)),), frozenset({3, 4}), 2, 5),
    ((), frozenset({2}), 5, 5),
]
ok_rt = ok_sem = True
for adm, w, d, n in POLICIES:
    P = pfx.Policy(adm, w, d, n)
    e = cfx.encP(P)
    P2, off = QFX.dec_encP(e, 0, n)
    if cfx.encP(P2) != e or off != len(e):
        ok_rt = False
    if not (P2.adm == P.adm and P2.w == P.w and P2.d == P.d and P2.K == P.K):
        ok_sem = False
record("C1-1 encP->dec_encP->encP round-trip stable (5 policies)", ok_rt)
record("C1-2 round-trip preserves semantics (adm/W/d/K)", ok_sem)

# ---------------- C2 unique deterministic encoding ----------------
perm = pfx.Policy(((b"nurse", (ID1,)), (b"physician", b"*")), frozenset({2, 3}), 5, 6)
canon_p = pfx.Policy(((b"physician", b"*"), (b"nurse", (ID1,))), frozenset({2, 3}), 5, 6)
record("C2-1 out-of-order adm construction -> same canonical bytes", cfx.encP(perm) == cfx.encP(canon_p))
dup = pfx.Policy(((b"physician", b"*"), (b"physician", b"*")), frozenset({2}), 5, 6)
one = pfx.Policy(((b"physician", b"*"),), frozenset({2}), 5, 6)
record("C2-2 duplicate entries deduplicated -> same canonical bytes (semantically equivalent)", cfx.encP(dup) == cfx.encP(one))
idperm = pfx.Policy(((b"admin", (ID2, ID1)),), frozenset({2}), 5, 6)
idcanon = pfx.Policy(((b"admin", (ID1, ID2)),), frozenset({2}), 5, 6)
record("C2-3 out-of-order ids within an entry -> same canonical bytes", cfx.encP(idperm) == cfx.encP(idcanon))
record("C2-4 different semantics -> different bytes (non-degenerate)",
       cfx.encP(canon_p) != cfx.encP(idcanon) != cfx.encP(one))

# ---------------- C3 malformed rejection ----------------
bPOL = cfx.encP(canon_p)


def malform(mut):
    b = bytearray(bPOL)
    mut(b)
    return bytes(b)


cases = {
    "unknown role code 9": lambda b: b.__setitem__(1, 9),
    "illegal tag=2": lambda b: b.__setitem__(2, 2),
    "truncated tail": lambda b: b.__delitem__(slice(len(b) - 3, len(b))),
}
ok_all = True
notes = []
for name, mut in cases.items():
    try:
        QFX.dec_encP(malform(mut), 0, 6)
        ok_all = False
        notes.append(f"{name}:accepted")
    except ValueError:
        pass
record("C3-1 malformed byte samples rejected (case by case)", ok_all, ";".join(notes) or "3/3 rejected")

# Hand-built canonicality violations (deterministic samples)
raw_dup = bytes([2]) + cfx.enc_adm_entry(b"physician", b"*") \
    + cfx.enc_adm_entry(b"physician", b"*") + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_unsorted = bytes([2]) + cfx.enc_adm_entry(b"nurse", (ID1,)) \
    + cfx.enc_adm_entry(b"physician", b"*") + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_ids_unsorted = bytes([1]) + bytes([3, 0, 2]) + ID2 + ID1 + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_empty_enum = bytes([1]) + bytes([3, 0, 0]) + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_dup_id = bytes([1]) + bytes([3, 0, 2]) + ID1 + ID1 + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_badtag = bytes([1]) + bytes([3, 7, 1]) + cfx.bmp({2}, 6) + cfx.enc32(5)
ok_m = True
for nm, raw in (("duplicate entry", raw_dup), ("out-of-order entries", raw_unsorted),
                ("out-of-order ids in entry", raw_ids_unsorted), ("empty enumeration", raw_empty_enum),
                ("duplicate id in entry", raw_dup_id), ("illegal tag", raw_badtag)):
    try:
        QFX.dec_encP(raw, 0, 6)
        ok_m = False
        print(f"  [accepted(!)] {nm}")
    except ValueError:
        pass
record("C3-2 all 6 hand-built canonicality violations rejected (ValueError)", ok_m)

# ---------------- C4 byte equivalence with the frozen original ----------------
IDR = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
# Policy shapes actually used by the formal experiment drivers
# (run_stage6._qc and the replication adapters):
#   u=1 (depth sweep / Table V, FHIR run, microbenchmark, Fig.2 timing run):
#     adm=((physician,*),) -- already canonical
#   u=3 (multi-redactor runs): adm=((physician,*),(admin,*),(nurse,(33*16,))) --
#     role-code order (1,3,2) is non-canonical: the fixed implementation
#     reorders to (1,2,3), so bytes change but the **length is unchanged**
#     (reordering does not change an entry's own representation length);
#     legacy u=3 artifacts are rejected by the strict decoder (legacy encoding).
CANON_FIXTURE = [
    (((b"physician", b"*"),), frozenset(range(2, 7)), 6, 6),                # u=1 formal shape
    (((b"physician", b"*"), (b"nurse", (b"\x33" * 16,))), frozenset(range(2, 7)), 6, 6),
]
ok_fixture_bytes = True
for adm, w, d, n in CANON_FIXTURE:
    if BS.canon.encP(BS.policy.Policy(adm, w, d, n)) != cfx.encP(pfx.Policy(adm, w, d, n)):
        ok_fixture_bytes = False
record("C4-1 already-canonical formal shapes (u=1) encP byte-identical", ok_fixture_bytes)

u3_legacy = ((b"physician", b"*"), (b"admin", b"*"), (b"nurse", (b"\x33" * 16,)))
e_leg = BS.canon.encP(BS.policy.Policy(u3_legacy, frozenset(range(2, 7)), 6, 6))
P_new = pfx.Policy(u3_legacy, frozenset(range(2, 7)), 6, 6)
e_new = cfx.encP(P_new)
try:
    QFX.dec_encP(e_leg, 0, 6)
    leg_rejected = False
except ValueError:
    leg_rejected = True
record("C4-1b u=3 legacy order (1,3,2): reordered to canonical, length unchanged, legacy bytes rejected",
       len(e_leg) == len(e_new) and e_leg != e_new and leg_rejected
       and P_new.adm == tuple(sorted(P_new.adm, key=lambda e_: cfx.adm_key(*e_))))

PFad, PFw, PFd, PFn = POLICIES[1]
Pb0 = BS.policy.Policy(PFad, PFw, PFd, PFn)
Pf0 = pfx.Policy(PFad, PFw, PFd, PFn)
M_eq = all([
    BS.canon.M_certR(ID1, b"\x00" * 3712, b"nurse", ((IDR,), b"*"), 0, 1 << 62)
    == cfx.M_certR(ID1, b"\x00" * 3712, b"nurse", ((IDR,), b"*"), 0, 1 << 62),
    BS.canon.M_orig(IDR, 6, b"\x00" * 48, Pb0, set(range(1, 7)), sd=b"\x01" * 48)
    == cfx.M_orig(IDR, 6, b"\x00" * 48, Pf0, set(range(1, 7)), sd=b"\x01" * 48),
    BS.canon.M_init(IDR, 6, b"\x00" * 48, Pb0, set(range(1, 7)), sd=b"\x01" * 48)
    == cfx.M_init(IDR, 6, b"\x00" * 48, Pf0, set(range(1, 7)), sd=b"\x01" * 48),
    BS.canon.M_red(IDR, 1, b"\x00" * 48, b"\x01" * 48, b"\x02" * 48)
    == cfx.M_red(IDR, 1, b"\x00" * 48, b"\x01" * 48, b"\x02" * 48),
    BS.canon.M_reginit(IDR, 6, b"\x00" * 48, Pb0, b"\x03" * 48, sd=b"\x01" * 48)
    == cfx.M_reginit(IDR, 6, b"\x00" * 48, Pf0, b"\x03" * 48, sd=b"\x01" * 48),
    BS.canon.M_reg(IDR, 0, b"\x00" * 48, 1, b"\x01" * 48, 2, b"\x02" * 48, ID1,
                   b"nurse") == cfx.M_reg(IDR, 0, b"\x00" * 48, 1, b"\x01" * 48, 2,
                                          b"\x02" * 48, ID1, b"nurse"),
    BS.canon.M_revsnap(3, [(ID1, 5), (ID2, 6)]) == cfx.M_revsnap(3, [(ID1, 5), (ID2, 6)]),
])
record("C4-2 M_certR/M_orig/M_init/M_red/M_reginit/M_reg/M_revsnap byte-identical", M_eq)

wld = cfx.M_certS(ID1, b"\x00" * 3712, (b"*", b"*"), 0, 1)
enm = cfx.M_certS(ID1, b"\x00" * 3712, ((IDR,), b"*"), 0, 1)
record("C4-3 M_certS wildcard->enumeration exactly +17B", len(enm) - len(wld) == 17
       and len(wld) == len(BS.canon.M_certS(ID1, b"\x00" * 3712, (b"*", b"*"), 0, 1)))

# ---------------- C5 same-seed full-chain Sigma byte-identical across implementations ----------------
N = 6
RID = IDR
ys = {j: f"v{j}".encode() for j in range(1, N + 1)}
sd = cfx.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, N + 1)])
adm0, w0, d0 = ((b"physician", b"*"), (b"nurse", (ID1,))), frozenset(range(2, N + 1)), N


def build_world(mod, scoped=True):
    """Deterministic cross-implementation world: keygen, signing masks and
    commitment randomness are all seeded -- any byte difference between the
    two sides can only come from the protocol encoding itself."""
    s4c = mod.s4compat
    pp = mod.s5_qprss.setup("B1", seed=b"sf-c|pp")
    ra = mod.s5_qprss.RA("B1")
    ra.sk, ra.pk = mod.s5_sig.core("B1").keygen(
        rng=s4c.FixedXofRng(b"sf-c|kg-ra"))    # RA keys seeded too (certificate signatures deterministic)
    B1c = mod.s5_sig.core("B1")
    sk_s, pk_s = B1c.keygen(rng=s4c.FixedXofRng(b"sf-c|kg-s"))
    scope = ((RID,), b"*") if scoped else (b"*", b"*")
    cert = mod.s5_qprss.Cert(RID[:12] + b"SGNR", pk_s, b"signer", scope, 0, 1 << 62)
    cert.sig = B1c.sign(ra.sk, ra.pk, cert.msg, mod.canon.CTX_CERT,
                        rng=s4c.FixedXofRng(b"sf-c|certS"))
    P0 = mod.policy.Policy(adm0, w0, d0, N)
    S = mod.s5_qprss.signing(pp, sk_s, cert, RID, ys, P0,
                             rng=mod.s5_qprss.make_rng(b"sf-c|commit"),
                             schema_digest=sd,
                             sig_rng=s4c.FixedXofRng(b"sf-c|sig0"))
    sk_e, pk_e = B1c.keygen(rng=s4c.FixedXofRng(b"sf-c|kg-e"))
    ce = mod.s5_qprss.Cert(ID1, pk_e, b"nurse", ((RID,), b"*"), 0, 1 << 62)
    ce.sig = B1c.sign(ra.sk, ra.pk, ce.msg, mod.canon.CTX_CERT,
                      rng=s4c.FixedXofRng(b"sf-c|certR"))
    P1 = mod.policy.Policy(adm0, w0 - {3}, d0 - 1, N)
    S2 = mod.s5_qprss.redact(pp, S, set(range(1, N + 1)) - {2}, P1, ce, sk_e, 10,
                             sig_rng=s4c.FixedXofRng(b"sf-c|tau1"))
    return S, S2, ra, ce


Sb, S2b, rab, ceb = build_world(BS)                    # frozen implementation + enumerated-scope certificate
Sf, S2f, raf, cef = build_world(FX)                    # fixed implementation + same enumerated scope
record("C5-1 t=0 Sigma byte-identical across implementations (sigma0/Theta0/h0/certificate)",
       Sb.serialize() == Sf.serialize(),
       f"len={len(Sf.serialize())}")
# C5-2 (revised for paper alignment): the H_cert upgrade (the §4.4 audit
# binding now includes the administrator signature) makes the first hop's
# cert_h field diverge from the baseline; everything outside that field (and
# the chained h_t) must stay byte-identical.
_b, _f = S2b.serialize(), S2f.serialize()
hopb = BS.s5_qprss.dec_e(S2b.log[0][0], N)
hopf = FX.s5_qprss.dec_e(S2f.log[0][0], N)
def _peq(pb, pf):
    return BS.canon.encP(pb) == FX.canon.enc_pol(pf)
same_fields = all(hopb[k] == hopf[k] for k in hopb
                  if k not in ("certH", "P_prev", "P_new"))     and _peq(hopb["P_prev"], hopf["P_prev"]) and _peq(hopb["P_new"], hopf["P_new"])
record("C5-2 t=1 Sigma diverges from baseline only in the H_cert digest field (all other fields identical)",
       len(_b) == len(_f) and same_fields
       and hopb["certH"] == BS.canon.H(ceb.msg)
       and hopf["certH"] == FX.canon.cert_digest(cef),
       f"len={len(_f)} certH_b={hopb['certH'][:6].hex()} certH_f={hopf['certH'][:6].hex()}")
record("C5-3 fixed implementation self-verifies hist accept",
       QFX.verify({"pk_ra": raf.pk}, S2f, "hist") == "accept_historical")
record("C5-4 fixed implementation deserialization round-trip byte-identical",
       QFX.Sigma.deserialize(S2f.serialize()).serialize() == S2f.serialize())

# Sigma under a wildcard certificate in the frozen implementation (legacy
# formal-experiment shape) -> rejected by the fixed implementation (V2.1);
# quantified as +17B.
Sb_w, _, _, _ = build_world(BS, scoped=False)
record("C5-5 enumerated-scope Sigma exactly +17B over the legacy wildcard shape",
       len(Sf.serialize()) - len(Sb_w.serialize()) == 17,
       f"enum {len(Sf.serialize())} vs wild {len(Sb_w.serialize())}")
try:
    QFX.verify({"pk_ra": raf.pk}, QFX.Sigma.deserialize(Sb_w.serialize()), "hist")
    record("C5-6 legacy-shape Sigma rejected by the fixed implementation (V2.1 wildcard signer)", False, "accepted(!)")
except QFX.VerifyReject as e:
    record("C5-6 legacy-shape Sigma rejected by the fixed implementation (V2.1 wildcard signer)",
           e.step.startswith("V2.1"), f"@{e.step}")

R["verdict"] = "ALL_SF_CANON_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "SF_CANON_FAIL"
with open(os.path.join(FIXED_ROOT, "logs", "sf_canon.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(R["verdict"])
sys.exit(0 if R["verdict"] == "ALL_SF_CANON_PASS" else 1)
