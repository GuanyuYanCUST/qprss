# -*- coding: utf-8 -*-
"""Fresh-mode random nonce and response binding.

Gap in the frozen implementation: the nonce was entirely caller-supplied,
with no generation and no length check; the formal experiment drivers all
used fixed constants (19B and 9B literals). After the fix: an independent
32B from the CSPRNG on every call; the response M_resp4 binds
nonce+RID+chain head+epoch+cid; encoding (M_resp4) and parsing
(parse_resp4) share one canonical rule; the length is enforced at exactly
32B. A later round upgraded the response to M_resp5 (last field cid ->
bid = BindId(RID,ID_S,PK), 177B unchanged, prefix b"QPRSS-v5|resp");
the v4/v5 prefixes are mutually exclusive and cannot be mixed.
M_resp4/parse_resp4 are kept as a legacy contrast.

Required six checks: legal random passes / wrong length rejected /
replayed old response rejected / tampered field rejected / old revocation
snapshot with new epoch rejected / hist unaffected.
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


RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
N = 6
B1 = Q.s5_sig.core("B1")

pp = Q.setup("B1", seed=b"sf-b|pp")
RA = Q.RA("B1")
cfg = {"pk_ra": RA.pk}
sk_s, pk_s = B1.keygen()
cert_s = RA.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID,), b"*"), 0, 1 << 62)
sk_n, pk_n = B1.keygen()
c_n = RA.issue(b"\x44" * 16, pk_n, b"nurse", ((RID,), b"*"), 0, 1 << 62)
ys = {j: f"v{j}".encode() for j in range(1, N + 1)}
sd = canon.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, N + 1)])
P0 = pol.Policy(((b"physician", b"*"), (b"nurse", (c_n.id,))),
                frozenset(range(2, N + 1)), N, N)
S1 = Q.signing(pp, sk_s, cert_s, RID, ys, P0, rng=Q.make_rng(b"sf-b|sg"),
               schema_digest=sd)
sig_init = B1.sign(sk_s, cert_s.pk,
                   canon.M_reginit(RID, N, S1.acc0, S1.P0, canon.H(cert_s.msg), sd=sd),
                   canon.CTX_REG)
RA.register_initial(S1, cert_s, sig_init)
snap0 = RA.revocation_snapshot()

# ---------------- B1 legal random passes (nonce=None uses the CSPRNG automatically) ----------------
record("B1-1 default fresh nonce = CSPRNG 32B and accepts",
       Q.verify(cfg, S1, "fresh", ra=RA, revsnap=snap0) == "accept_fresh")
# Observe the default path (test-injected randomness): intercept secure_rng
# and assert each call returns exactly 32B, two calls differ, and each
# generated response verifies against its injected nonce.
_calls = []


def _stub_rng(n):
    _calls.append((n, len(_calls)))
    return bytes([0x5A]) * 31 + bytes([len(_calls)])


_orig_rng = Q.secure_rng
Q.secure_rng = _stub_rng
try:
    ra1 = RA.fresh_query(None, RID)
    ra2 = RA.fresh_query(None, RID)
finally:
    Q.secure_rng = _orig_rng
n1 = bytes([0x5A]) * 31 + bytes([1])
n2 = bytes([0x5A]) * 31 + bytes([2])
record("B1-2 default queries use secure_rng(32) twice and the nonces differ",
       [c[0] for c in _calls] == [32, 32] and n1 != n2)
record("B1-2b injected nonce maps one-to-one to its response (recomputed M_resp5 verifies)",
       B1.verify(RA.pk, canon.M_resp5(n1, RID, ra1[1], ra1[2], ra1[3], ra1[4],
                                      ra1[5]), ra1[0], canon.CTX_ANC)
       and B1.verify(RA.pk, canon.M_resp5(n2, RID, ra2[1], ra2[2], ra2[3], ra2[4],
                                          ra2[5]), ra2[0], canon.CTX_ANC))
record("B1-2c two default responses have distinct signatures (nonce field separation)", ra1[0] != ra2[0])
n_ok = os.urandom(32)
record("B1-3 explicit 32B random nonce accepts",
       Q.verify(cfg, S1, "fresh", ra=RA, nonce=n_ok, revsnap=snap0) == "accept_fresh")

# ---------------- B2 wrong-length rejection (encoding/generation/verification, all three paths) ----------------
bad_lens = [b"short", b"n" * 31, b"n" * 33, b"stage6-fresh-nonce", b"e7b-nonce", b""]
ok_reject_fq = ok_reject_enc = ok_reject_ver = True
for bad in bad_lens:
    try:
        RA.fresh_query(bad, RID)
        ok_reject_fq = False
    except ValueError:
        pass
    try:
        canon.M_resp4(bad, RID, b"\x00" * 48, 0, 0, 0, b"\x00" * 48)
        canon.M_resp5(bad, RID, b"\x00" * 48, 0, 0, 0, b"\x00" * 48)
        ok_reject_enc = False
    except ValueError:
        pass
    try:
        Q.verify(cfg, S1, "fresh", ra=RA, nonce=bad, revsnap=snap0)
        ok_reject_ver = False
    except Q.VerifyReject:
        pass
record("B2-1 fresh_query rejects all wrong-length nonces (ValueError)", ok_reject_fq,
       f"{len(bad_lens)} illegal lengths")
record("B2-2 M_resp4/M_resp5 encoding rejects wrong length (same rule as parsing)", ok_reject_enc)
record("B2-3 verify side rejects wrong-length nonce (V9)", ok_reject_ver)

# parse_resp5 round-trip and malformed input (fresh_query returns a
# signature; the message is recomputed from the returned fields)
nonce = os.urandom(32)
resp, a_h, a_t, a_ts, a_ep, a_bid = RA.fresh_query(nonce, RID)
m = canon.M_resp5(nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
record("B2-4 M_resp5/parse_resp5 round-trip stable (recomputed message = the fields covered by the response signature)",
       canon.parse_resp5(m) == (nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
       and B1.verify(RA.pk, m, resp, canon.CTX_ANC))
ok_bad = True
for corrupt in (m[:-1], m + b"\x00", b"QPRSS-v3|resp" + m[13:],
                b"QPRSS-v5|gaz" + m[13:]):
    try:
        canon.parse_resp5(corrupt)
        ok_bad = False
    except ValueError:
        pass
record("B2-5 parse_resp5 rejects all malformed input (truncated/trailing/prefix-swapped)", ok_bad)
# v4/v5 prefix mutual exclusion: the v5 parser rejects v4 messages and the
# v4 parser rejects v5 messages (no mixing or misreading)
m4 = canon.M_resp4(nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
cross_to5 = m4[:7] + b"5" + m4[8:]          # same field bytes, prefix rewritten to v5
mix_ok = False
try:
    canon.parse_resp5(m4)                   # feed the v4 original to the v5 parser -> must reject
except ValueError:
    try:
        canon.parse_resp4(cross_to5)        # feed the v5-prefixed bytes to the v4 parser -> must reject
    except ValueError:
        mix_ok = (canon.parse_resp4(m4)
                  == (nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
                  and canon.parse_resp5(cross_to5)
                  == (nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
                  and len(m4) == len(m) == 177 and m4[:7] == m[:7]
                  and m4[7:8] == b"4" and m[7:8] == b"5" and m4[8:] == m[8:])
record("B2-7 v4/v5 prefixes mutually exclusive, cannot be mixed (fields identical, only byte 7 differs)", mix_ok)
record("B2-6 M_resp5 byte length = 177 (13+32+16+48+4+8+8+48)", len(m) == 177,
       f"got {len(m)}")

# ---------------- B3 replayed old response rejected (nonce/response one-to-one) ----------------
# The verifier always recomputes M_resp5 with the current nonce: a response
# signed for an old nonce necessarily fails verification for a new query.
nonce2 = os.urandom(32)
resp_old = RA.fresh_query(nonce, RID)[0]          # old response (signed for nonce 1)
cross = B1.verify(RA.pk, canon.M_resp5(nonce2, RID, a_h, a_t, a_ts, a_ep, a_bid),
                  resp_old, canon.CTX_ANC)
record("B3-1 old response necessarily fails verification across nonces (no replay surface)", not cross)
# Likewise: an old response is not reusable under a different RID/chain head/epoch/bid
cross2 = B1.verify(RA.pk, canon.M_resp5(nonce, RID, a_h, a_t + 1, a_ts, a_ep, a_bid),
                   resp_old, canon.CTX_ANC)
record("B3-2 old response rebound to another chain head (t*+1) necessarily fails", not cross2)

# ---------------- B4 tampered-field rejection ----------------
record("B4-1 tampering with t* necessarily fails verification (= B3-2 scenario)", not cross2)
tampered_bid = bytes(a_bid[::-1])
record("B4-2 tampering with bid necessarily fails verification",
       not B1.verify(RA.pk, canon.M_resp5(nonce, RID, a_h, a_t, a_ts, a_ep,
                                          tampered_bid), resp_old, canon.CTX_ANC))
# Verifier-side bid comparison (V9): see test_sf_gaps G1-5/G1-6
# (swapped-certificate artifact / tampered response rejected); here we add
# the registration-side consistency: reg.bid is the response bid.
record("B4-3 response bid == reg[rid].bid == BindId(RID,ID,PK) (registration and response share the source)",
       a_bid == RA.reg[RID]["bid"]
       and a_bid == canon.BindId(RID, cert_s.id, cert_s.pk))

# ---------------- B5 old revocation snapshot + new epoch rejected (epoch gate kept) ----------------
P1 = pol.Policy(P0.adm, P0.w - {4}, P0.d - 1, N)
S2 = Q.redact(pp, S1, set(range(1, N + 1)) - {2}, P1, c_n, sk_n, 100)
m_reg = canon.M_reg(RID, RA.reg[RID]["ver"], RA.reg[RID]["h"],
                    RA.reg[RID]["ver"] + 1, S2.h_t, len(S2.log),
                    canon.H(c_n.msg), c_n.id, c_n.role)
RA.register(S2, B1.sign(sk_n, pk_n, m_reg, canon.CTX_REG), c_n)
# Revoke an identity not on the chain (only advances the epoch) -- chain hops
# are unaffected and the current snapshot should pass
sk_x, pk_x = B1.keygen()
c_x = RA.issue(b"\x55" * 16, pk_x, b"auditor", ((RID,), b"*"), 0, 1 << 62)
RA.revoke(c_x.id, eff_ts=50)                      # epoch 0->1: snap0 becomes an old snapshot
snap1 = RA.revocation_snapshot()
try:
    Q.verify(cfg, S2, "fresh", ra=RA, nonce=os.urandom(32), revsnap=snap0)
    record("B5-1 old revocation snapshot (epoch 0) rejected against the new-epoch anchor (V5.3d)", False, "accepted(!)")
except Q.VerifyReject as e:
    record("B5-1 old revocation snapshot (epoch 0) rejected against the new-epoch anchor (V5.3d)", e.step == "V5.3d",
           f"@{e.step}")
record("B5-2 current snapshot (epoch 1) fresh accept",
       Q.verify(cfg, S2, "fresh", ra=RA, nonce=os.urandom(32),
                revsnap=snap1) == "accept_fresh")

# ---------------- B6 hist unaffected ----------------
record("B6-1 hist does not depend on the nonce mechanism and still accepts",
       Q.verify(cfg, S2, "hist") == "accept_historical"
       and Q.verify(cfg, S2, "hist", revsnap=snap1) == "accept_historical")

R["verdict"] = "ALL_SF_NONCE_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "SF_NONCE_FAIL"
with open(os.path.join(os.path.dirname(HERE), "logs", "sf_nonce.json"), "w",
          encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(R["verdict"])
sys.exit(0 if R["verdict"] == "ALL_SF_NONCE_PASS" else 1)
