# -*- coding: utf-8 -*-
"""QPRSS protocol engine.

Three security-relevant deviations from the very first frozen version, each
carried with its own verification tests:

[Index monotonicity per hop] _check_hop_policy opens with I_new ⊆ I_prev
    (V7.1), and honest Redact has the dual local precheck R0b. Without it a
    previous editor can replay an old legitimate opening through a genuinely
    authorized hop to resurrect an already-deleted index — the original
    implementation accepted that end to end (demonstrated by the
    resurrection reproduction test).

[Revocation and time semantics] the caller-supplied revlist/ref_ts
parameters are gone, replaced by:
    - RA.revoke(id16, eff_ts): an explicit effective time in the same
      declared wall-clock domain as e.ts; revoked identities are also
      rejected at the RA registration gates;
    - RA.revocation_snapshot(): an RA-signed snapshot (epoch + per-id
      eff_ts);
    - verify(..., revsnap=(msg, sig)): only RA-signed snapshots count — a
      caller self-reported revocation list is not trusted input (bad
      signature ⇒ V5.3d reject);
    - V5.3d-window, all three modes: per-hop in-record window consistency
      (e.ts ∈ [nb, na]; everything comes from the record itself, no caller
      clock involved);
    - V5.3d-rev, when a revsnap is supplied: hops claiming a time ≥ the
      revocation effective time are rejected (records legitimately signed
      earlier stay valid — historical validity ≠ current authorization);
    - require_revsnap=True: refuse explicitly when trusted revocation data
      is needed but missing, instead of silently returning full validity.
    Adversarial re-review tightened this further: an epoch-domain
    per-signer gate on registration (revoked signers could otherwise
    backdate hops into the gazette/fresh head), mandatory monotone eff_ts,
    epoch anchored into the response domain (M_resp3/M_gaz3) with stale
    snapshots rejected, bidirectional field-table consistency at V1.2, and
    truncation guards in parse_revsnap.

[Signing-core XOF replay fix] the B1 path goes through s4compat (the
original ShakeRng buffer concatenation replays the XOF stream from byte
126 — see the header of s4compat.py).

Everything else — the V1–V9 numbering, serialization v5, RA registration
semantics, Inv-W, tightening, the three verification modes, M_* canonical
transcriptions from one source, schema_digest, SD-1 — matches the frozen
version verbatim. The protocol layering: B1 = the C2 MLWE structured
commitment (commit_as, C_j = G·r_j + D·H₂(j‖RID‖y_j) + η_j, q = 12289,
k = m = 4, d = 256, ternary) plus the B1-65 custom
Fiat–Shamir-with-aborts core; the comparison arms AS/C keep ML-DSA-44.

Honesty note: B1 signing is randomized (CSPRNG masks), so Σ bytes are not
reproducible across runs; reproducibility requires an explicitly injected
deterministic rng, which is test-only.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import threading

from . import canon, commit_as, commit_c, merkle, policy  # noqa: E402
from .policy import Policy, AuthMember, ScopeMatchRID, ScopeMatchJ, tighten_ok, inv_w  # noqa: E402
from . import s5_sig  # noqa: E402

SIG = s5_sig.SIG_LEN          # {"B1":5794(τ=64),"AS":2420,"C":2420}
PKL = s5_sig.PK_LEN           # {"B1":3712,"AS":1312,"C":1312}
WITNESS_CORE = {"B1": 512, "AS": 512, "C": 32, "H": 32}
SCHEME_CHAR = {"B1": b"B", "AS": b"A", "C": b"C", "H": b"H"}
CHAR_SCHEME = {v: k for k, v in SCHEME_CHAR.items()}


class VerifyReject(Exception):
    def __init__(self, step, why=""):
        super().__init__(f"{step}: {why}")
        self.step = step


class RedactRefused(Exception):
    pass


def make_rng(seed: bytes):
    """Seeded test PRNG — test-reproduction mode only. Real interfaces use
    secure_rng."""
    state = [0]

    def rng(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.shake_256(b"rng|" + seed + canon.enc32(state[0])).digest(64)
            state[0] += 1
        return out[:n]

    return rng


def secure_rng(n: int) -> bytes:
    return os.urandom(n)


# ---------------- certificates ----------------

class Cert:
    """Certificate (issued by the RA). scheme is the certificate's signing
    core ('B1' = the paper's stack; 'AS'/'C' = comparison arms)."""

    def __init__(self, id16, pk, role: bytes, scope, nb: int, na: int, sig=b"",
                 scheme: str = "B1"):
        assert len(id16) == 16, f"id must be 16B, got {len(id16)}"
        assert scheme in ("B1", "AS", "C", "H")
        self.id, self.pk, self.role, self.scope = id16, pk, role, scope
        self.nb, self.na, self.sig, self.scheme = nb, na, sig, scheme
        if role == b"signer":
            self.msg = canon.M_certS(id16, pk, scope, nb, na)
        else:
            self.msg = canon.M_certR(id16, pk, role, scope, nb, na)

    def bytes(self):
        return self.sig + self.msg

    @staticmethod
    def h(cert, lam=None):
        return canon.H(cert.msg)

    def verify(self, pk_ra) -> bool:
        return s5_sig.core(self.scheme).verify(pk_ra, self.msg, self.sig, canon.CTX_CERT)


# ---------------- RA ----------------

class Superseded(Exception):
    pass


class RA:
    """Registration authority: certificate issuance, revocation table,
    chain-head registration, FreshQuery, gazette.
    scheme defaults to 'B1' (the paper's full custom stack); the 'AS'/'C'
    comparison stacks get an ML-DSA-44 RA. Concurrency is the same as the
    prototype: a single-process threading.Lock (in-process CAS emulation) —
    no cross-process consistency or production-grade crash safety claimed."""

    def __init__(self, scheme: str = "B1"):
        self.scheme = scheme
        core = s5_sig.core(scheme)
        self.sk, self.pk = core.keygen()
        self.revoked = set()
        self.rev_eff = {}   # id16 -> eff_ts (revocation effective time, same
                            # domain as e.ts)
        self.epoch = 0
        self.reg = {}       # rid -> {h, t, I, P, ver}
        self.log = []       # append-only registration log
        self._lk = threading.Lock()

    def _sign(self, msg: bytes, ctx: bytes) -> bytes:
        core = s5_sig.core(self.scheme)
        return core.sign(self.sk, self.pk, msg, ctx)

    def _verify(self, pk, msg, sig, ctx) -> bool:
        return s5_sig.core(self.scheme).verify(pk, msg, sig, ctx)

    def issue(self, id16, pk, role, scope, nb, na) -> Cert:
        c = Cert(id16, pk, role, scope, nb, na, scheme=self.scheme)
        c.sig = self._sign(c.msg, canon.CTX_CERT)
        return c

    def revoke(self, id16, eff_ts: int = None):
        """Revoke with an explicit effective time eff_ts (same declared
        wall-clock domain as e.ts). Semantics: a hop claiming a time ≥ eff_ts
        is post-revocation authorization (rejected when a revsnap is
        supplied); a hop claiming < eff_ts was signed before revocation and
        is not implicated.

        eff_ts is mandatory (ValueError otherwise): the RA has no trusted
        clock in the e.ts domain, so "effective immediately" cannot be
        expressed implicitly — passing eff_ts=0 deliberately voids the
        identity's entire history (even already-registered pre-revocation
        hops are rejected once a revsnap is consumed); to preserve history,
        pass an eff_ts greater than every past hop's declared ts. Instant
        revocation in the epoch domain is handled by the registration gates.
        Re-revocation may not lower the recorded eff_ts (monotonic)."""
        if eff_ts is None:
            raise ValueError("eff_ts required: RA has no trusted clock in the "
                             "e.ts domain; pass explicit eff_ts (0 only as a "
                             "deliberate void-everything)")
        if not isinstance(eff_ts, int) or not 0 <= eff_ts < 2 ** 64:
            raise ValueError("eff_ts must be an integer in [0, 2^64)")
        with self._lk:
            if id16 in self.rev_eff and eff_ts < self.rev_eff[id16]:
                raise ValueError("re-revoke may not lower eff_ts (monotonic)")
            self.revoked.add(id16)
            self.rev_eff[id16] = eff_ts
            self.epoch += 1

    def revlist(self):
        with self._lk:
            msg = canon.M_revlist(self.epoch, sorted(self.revoked))
            return msg, self._sign(msg, canon.CTX_ANC)

    def revocation_snapshot(self):
        """Trusted revocation-state snapshot (RA-signed, CTX_ANC). verify's
        revsnap parameter accepts only this product — caller self-reported
        revocation lists are not trusted input."""
        with self._lk:
            msg = canon.M_revsnap(self.epoch,
                                  [(i, self.rev_eff[i]) for i in sorted(self.revoked)])
            return msg, self._sign(msg, canon.CTX_ANC)

    # ---- registration state ----
    def register_initial(self, S0, cert_s: Cert, sig_init: bytes):
        """RegisterInitial: the signer registers the round-zero state.
        First writer wins."""
        with self._lk:
            rid, n = S0.rid, S0.n
            if cert_s.scheme != self.scheme:
                raise RedactRefused("I1 cert scheme mismatch")
            if not cert_s.verify(self.pk) or cert_s.role != b"signer" \
                    or not ScopeMatchRID(cert_s.scope, rid):
                raise RedactRefused("I1 bad signer cert")
            if cert_s.id in self.revoked:                      # registration gate checks revocation
                raise RedactRefused("I1-rev signer revoked")
            m = canon.M_reginit(rid, n, S0.acc0, S0.P0, canon.H(cert_s.msg), sd=S0.sd)
            if not self._verify(cert_s.pk, m, sig_init, canon.CTX_REG):
                raise RedactRefused("I1 σ_init invalid under authenticated pk")
            if S0.log or S0.h_t != canon.h0_of(rid, n, S0.acc0, S0.P0, sd=S0.sd):
                raise RedactRefused("I2 not a t=0 state")
            try:
                verify({"pk_ra": self.pk}, S0, "hist")          # RA acts as the full verifier
            except VerifyReject as e:
                raise RedactRefused(f"I2 full verify failed: {e}")
            if rid in self.reg:
                raise Superseded("I3: RID already registered")
            self.reg[rid] = dict(h=S0.h_t, t=0, I=set(S0.It), P=S0.P0, ver=0)
            self.log.append((rid, S0.h_t, 0, 0))
            return 0

    def register(self, S, sig_reg: bytes, cert_req: Cert):
        """R1–R5: register a legal extension; concurrent forks race, first
        writer wins, losers get Superseded."""
        with self._lk:
            rid = S.rid
            if rid not in self.reg:
                raise RedactRefused("unregistered RID (RegisterInitial first)")
            st = self.reg[rid]
            if cert_req.scheme != self.scheme or not cert_req.verify(self.pk):
                raise RedactRefused("R1 cert not RA-signed")
            if cert_req.id in self.revoked:                    # registration gate checks revocation
                raise RedactRefused("R1-rev redactor revoked")
            t_new = len(S.log)
            if t_new <= st["t"]:
                raise Superseded(f"R2: no strict extension (t_new={t_new} ≤ t_reg={st['t']})")
            m = canon.M_reg(rid, st["ver"], st["h"], st["ver"] + 1, S.h_t, t_new,
                            canon.H(cert_req.msg), cert_req.id, cert_req.role)
            if not self._verify(cert_req.pk, m, sig_reg, canon.CTX_REG):
                raise RedactRefused("R1 σ_req invalid under authenticated pk (stale or forged)")
            if cert_req.role != b"signer" and not AuthMember(cert_req.role, cert_req.id, st["P"].adm):
                raise RedactRefused("R1 not authorized under registered policy")
            try:                                                    # full V1–V8 verification
                verify({"pk_ra": self.pk}, S, "hist")
            except VerifyReject as e:
                raise RedactRefused(f"R3 full verify failed: {e}")
            # Epoch-domain per-hop signer gate: only the NEWLY added hops are
            # checked (S.log[st.t:]; already-registered pre-revocation hops
            # are not retroactively implicated). The declared ts is untrusted
            # (it can be backdated), so ts is ignored and only the revocation
            # table counts — otherwise a revoked party's backdated hops could
            # sneak into the gazette/fresh head through any still-authorized
            # member's registration.
            for (_, _, cid_b) in S.log[st["t"]:]:
                cert_b = S.certs.get(cid_b)
                if cert_b is not None and cert_b.id in self.revoked:
                    raise RedactRefused(
                        "R3-rev: new hop signed by revoked identity "
                        "(declared ts is untrusted; epoch domain)")
            h = canon.h0_of(rid, S.n, S.acc0, S.P0, sd=S.sd)          # prefix binding (sd included)
            for (e_b, _, _) in S.log[: st["t"]]:
                h = canon.hi_of(e_b, h)
            if h != st["h"]:
                raise RedactRefused("R2 prefix head mismatch (fork)")
            st.update(h=S.h_t, t=t_new, I=set(S.It), P=S.Pt, ver=st["ver"] + 1)   # R4/R5
            self.log.append((rid, S.h_t, t_new, st["ver"]))
            return st["ver"]

    # ---- freshness sources ----
    def fresh_query(self, nonce: bytes, rid):
        """The response binds RA.epoch (M_resp3) — verifiers use it to
        reject stale revsnaps."""
        with self._lk:
            st = self.reg.get(rid)
            if st is None:
                raise RedactRefused("no registration for RID")
            ts = int.from_bytes(hashlib.shake_256(b"ts" + st["h"]).digest(4), "big")
            resp = self._sign(canon.M_resp3(nonce, rid, st["h"], st["t"], ts,
                                             self.epoch), canon.CTX_ANC)
            return resp, st["h"], st["t"], ts, self.epoch

    def gazette(self, period: int, rid):
        """The gazette binds RA.epoch (M_gaz3) — same purpose."""
        with self._lk:
            st = self.reg.get(rid)
            ts = int.from_bytes(hashlib.shake_256(b"gazts" + st["h"]).digest(4), "big")
            g = self._sign(canon.M_gaz3(period, rid, st["h"], st["t"], ts,
                                         self.epoch), canon.CTX_ANC)
            return g, st["h"], st["t"], ts, period, self.epoch

    # ---- state persistence (cross-restart continuity; non-transactional,
    # no production-grade crash safety claimed) ----
    def snapshot(self) -> bytes:
        with self._lk:
            reg = {rid.hex(): dict(h=st["h"].hex(), t=st["t"], ver=st["ver"], n=st["P"].n,
                                   P=canon.encP(st["P"]).hex(), I=sorted(st["I"]))
                   for rid, st in self.reg.items()}
            log = [[r.hex(), h.hex(), t, v] for (r, h, t, v) in self.log]
            return json.dumps(dict(scheme=self.scheme, pk=self.pk.hex(), sk=self.sk.hex(),
                                   revoked=[x.hex() for x in sorted(self.revoked)],
                                   rev_eff=[[k.hex(), v] for k, v in sorted(self.rev_eff.items())],
                                   epoch=self.epoch, reg=reg, log=log)).encode()

    @classmethod
    def restore(cls, blob: bytes):
        o = json.loads(blob)
        ra = cls.__new__(cls)
        ra.scheme = o.get("scheme", "AS")          # old snapshots without the
                                                   # scheme field predate the
                                                   # scheme split
        ra.pk, ra.sk = bytes.fromhex(o["pk"]), bytes.fromhex(o["sk"])
        ra.revoked = {bytes.fromhex(x) for x in o["revoked"]}
        ra.rev_eff = {bytes.fromhex(k): v for (k, v) in o.get("rev_eff", [])}
        for x in ra.revoked:                       # backfill for old snapshots
            ra.rev_eff.setdefault(x, 0)
        ra.epoch = o["epoch"]
        ra._lk = threading.Lock()
        ra.reg = {}
        for ridh, st in o["reg"].items():
            P, _ = dec_encP(bytes.fromhex(st["P"]), 0, st["n"])
            ra.reg[bytes.fromhex(ridh)] = dict(h=bytes.fromhex(st["h"]), t=st["t"],
                                               I=set(st["I"]), P=P, ver=st["ver"])
        ra.log = [(bytes.fromhex(r), bytes.fromhex(h), t, v) for (r, h, t, v) in o["log"]]
        return ra


def _check_hop_cert(rid, i, hop, cert, h_prev, e_bytes, tau, pk_ra, scheme,
                    selfverify=False):
    if not selfverify and not cert.verify(pk_ra):
        raise VerifyReject("V5.1", "cert not RA-signed")
    if hop["id"] != cert.id or hop["role"] != cert.role:
        raise VerifyReject("V5.2", "log/cert identity mismatch")
    if not s5_sig.core(scheme).verify(
            cert.pk, canon.M_red(rid, i, e_bytes, h_prev, canon.hi_of(e_bytes, h_prev)),
            tau, canon.CTX_RED):
        raise VerifyReject("V5.4", "tau invalid")


def forge_hop(S, I_new, P_new: Policy, redactor: Cert, sk, ts: int, e_id=None):
    """Attacker's Redact: skips all local prechecks (Redact has no binding
    force in the attacker's hands)."""
    n = S.n
    i = len(S.log) + 1
    cid = canon.H(redactor.msg)
    e_bytes = canon.enc_e(i, e_id or redactor.id, redactor.role, cid, S.It, set(I_new),
                          S.Pt, P_new, ts, n)
    h_new = canon.hi_of(e_bytes, S.h_t)
    tau = s5_sig.core(S.scheme).sign(sk, redactor.pk,
                                     canon.M_red(S.rid, i, e_bytes, S.h_t, h_new),
                                     canon.CTX_RED)
    S2 = Sigma(S.scheme, S.rid, n)
    S2.sd = S.sd
    S2.acc0, S2.P0, S2.sigma0, S2.cert_s = S.acc0, S.P0, S.sigma0, S.cert_s
    S2.It = set(I_new)
    S2.fields = {j: S.fields[j] for j in S2.It}
    S2.Pt = P_new
    S2.log = S.log + [(e_bytes, tau, cid)]
    S2.certs = dict(S.certs)
    S2.certs.setdefault(cid, redactor)
    S2.h_t = h_new
    return S2


def _check_hop_policy(n, hop, cert, rid, removed, I_prev, P_prev, I_new, P_new):
    if not I_new <= I_prev:
        # Per-hop index monotonicity — redaction may only remove indices.
        # Without this check, an old legitimate opening (a static witness
        # verifying against acc0) can re-insert an already-deleted field
        # through a genuinely authorized hop.
        raise VerifyReject("V7.1", "index resurrection: I_new ⊄ I_prev")
    if not removed:
        raise VerifyReject("V7.1", "empty redaction J=∅")   # SD-1: empty redactions are forbidden
    if not removed <= P_prev.w:
        raise VerifyReject("V7.2", "deleted non-whitelisted index")
    if not P_prev.K <= I_new:
        raise VerifyReject("V7.3", "mandatory field deleted")
    if not inv_w(I_new, P_new):
        raise VerifyReject("V7.4", "Inv-W violated")
    if not P_new.holds(I_new):
        raise VerifyReject("V7.5", "P_i(I_i) != 1")
    if not tighten_ok(P_new, P_prev):
        raise VerifyReject("V7.6", "not a tightening")
    if not (AuthMember(hop["role"], hop["id"], P_prev.adm)
            and ScopeMatchRID(cert.scope, rid) and ScopeMatchJ(cert.scope, removed)):
        raise VerifyReject("V7.7", "authorization failed")


# ---------------- Σ ----------------

class Sigma:
    def __init__(self, scheme, rid, n):
        assert scheme in ("B1", "AS", "C", "H")
        self.scheme = scheme            # "B1" (main) | "AS" | "C" (comparison)
        self.rid, self.n = rid, n
        self.sd = None                  # schema digest (v4; None = semantic
                                        # map not bound)
        self.acc0 = None                # initial block
        self.P0 = None
        self.sigma0 = None
        self.cert_s = None
        self.It = set()
        self.fields = {}                # j -> (y, witness)
        self.Pt = None
        self.h_t = None
        self.log = []                   # [(e_bytes, tau, certH)]
        self.certs = {}                 # certH -> Cert (dedup table)
        self.anchor = None              # legacy counterexamples only

    # ---------- serialization v5 (= v4 + scheme byte and per-scheme lengths) ----
    # flags bit0 = Cert_S included; bit1 = v3+ (enc32(j)‖enc32(len)‖y);
    # bit2 = sd included (48 B).
    # B1: sigma0/tau = 5,794 B (τ=64), pk inside a certificate = 3,712 B,
    # witness core r‖η 2-bit = 512 B (same as AS — the commitment layer is
    # the isomorphic C2). Structure/order/encodings agree with v4 field by
    # field.

    def serialize(self, include_cert_s=True) -> bytes:
        js = sorted(self.It)
        I0 = set(range(1, self.n + 1))
        flags = (1 if include_cert_s else 0) | 2 | (4 if self.sd else 0)
        head = (self.rid + canon.enc32(self.n)
                + SCHEME_CHAR[self.scheme]
                + bytes([flags])
                + canon.enc32(len(js)) + canon.enc32(len(self.log)) + canon.enc32(len(self.certs))
                + (self.sd if self.sd else b"")
                + self.acc0 + canon.encP(self.P0) + canon.bmp(I0, self.n)
                + canon.encP(self.Pt) + self.h_t)
        body_y = b"".join(canon.enc_field(j, self.fields[j][0]) for j in js)
        body_w = b"".join(self.fields[j][1].core_bytes() for j in js)
        body_p = b"".join(b"".join(self.fields[j][1].path) for j in js)
        body_e = b"".join(e for (e, _, _) in self.log)
        body_t = b"".join(tau for (_, tau, _) in self.log)
        body_c = b"".join(self.certs[c].bytes() for c in sorted(self.certs))
        out = head + self.sigma0
        if include_cert_s:
            out += self.cert_s.bytes()
        return out + body_y + body_w + body_p + body_e + body_t + body_c

    @staticmethod
    def deserialize(data: bytes):
        S, _ = parse_sigma(data)
        return S


class ASWitness:
    """C2 commitment witness: (2-bit packed r‖η, Merkle path). B1 and AS
    share it (same commitment layer)."""
    __slots__ = ("packed", "path")

    def __init__(self, packed, path):
        self.packed, self.path = packed, path

    def core_bytes(self):
        return self.packed

    def bytes(self):
        return self.packed + b"".join(self.path)


class CWitness:
    """Baseline C witness: (salt, Merkle path)."""
    __slots__ = ("salt", "path")

    def __init__(self, salt, path):
        self.salt, self.path = salt, path

    def core_bytes(self):
        return self.salt

    def bytes(self):
        return self.salt + b"".join(self.path)


# ---------------- Setup / Signing ----------------

def setup(scheme: str = "B1", seed: bytes = None):
    """Parameter generation. B1/AS: commitment-layer pp (G,D ∈ R_q^{4×4},
    D invertibility really checked + resampling on failure, coefficients
    exactly uniform by rejection sampling); C: no algebraic pp (salt +
    hash). seed=None (production) → CSPRNG; a fixed seed is for test
    reproduction only."""
    assert scheme in ("B1", "AS", "C", "H")
    if scheme in ("C", "H"):
        cfg_pp["G"], cfg_pp["D"] = None, None
        return dict(scheme=scheme)
    if seed is None:
        seed = secure_rng(32)
    G, D, iters = commit_as.sample_pp_checked(seed)
    cfg_pp["G"], cfg_pp["D"] = G, D
    return dict(scheme=scheme, G=G, D=D, resample_iters=iters)


def signing(pp, sk_s, cert_s, rid, ys: dict, P0: Policy, rng=None,
            schema_digest=None, sig_rng=None) -> Sigma:
    """Origin (physician) signature. ys: j -> y(bytes) (FHIR canonical_json
    output). rng: commitment randomness (None = secure_rng); sig_rng: B1
    signature-mask rng (None = CSPRNG; an explicit deterministic rng is
    test-reproduction mode only)."""
    if rng is None:
        rng = secure_rng
    scheme = pp["scheme"]
    n = P0.n
    S = Sigma(scheme, rid, n)
    S.sd = schema_digest
    S.P0, S.cert_s = P0, cert_s
    S.It = set(range(1, n + 1))
    S.Pt = P0.copy()
    if scheme in ("B1", "AS"):
        def leaf(j):
            r = commit_as.ternary_rand(rng(64))
            eta = commit_as.ternary_rand(rng(64))
            C = commit_as.commit(pp["G"], pp["D"], j, rid, ys[j], r, eta)
            S.fields[j] = (ys[j], ASWitness(commit_as.pack_witness(r, eta), None))
            return commit_as.leaf_of(j, C)
    else:
        def leaf(j):
            salt = commit_c.new_salt(rng)
            S.fields[j] = (ys[j], CWitness(salt, None))
            return commit_c.leaf_of(j, salt, ys[j])

    tree = merkle.make_tree(n, leaf)
    S.acc0 = tree.root
    for j in S.It:
        S.fields[j][1].path = tree.path(j - 1)
    S.sigma0 = s5_sig.core(scheme).sign(
        sk_s, cert_s.pk, canon.M_orig(rid, n, S.acc0, P0, S.It, sd=S.sd),
        canon.CTX_ORIG, rng=sig_rng)
    S.h_t = canon.h0_of(rid, n, S.acc0, P0, sd=S.sd)
    return S


# ---------------- Redact ----------------

def redact(pp, S: Sigma, I_new, P_new: Policy, redactor: Cert, sk_r, ts: int,
           *, legacy=False, sig_rng=None):
    """Honest Redact (local prechecks R0/R0b/R1–R6; R0b is the resurrection
    dual)."""
    n = S.n
    removed = S.It - set(I_new)
    if not set(I_new) <= S.It:
        # Honest Redact's dual precheck: the new index set may only be a
        # subset of the current one (the signer-side dual of V7.1; an
        # attacker can bypass local prechecks, so Verify checks it too).
        raise RedactRefused("R0b index resurrection (I_new ⊄ I_t)")
    if not removed:
        raise RedactRefused("R0 empty redaction (J=∅)")   # SD-1: dual of V7.1
    if not removed <= S.Pt.w:
        raise RedactRefused("R1 removed ⊄ W")
    if not S.Pt.K <= set(I_new):
        raise RedactRefused("R2 mandatory kept")
    if not legacy and not inv_w(I_new, P_new):
        raise RedactRefused("R3 Inv-W")
    if not legacy and not P_new.holds(I_new):
        raise RedactRefused("R4 P_new(I_new)!=1")
    if not tighten_ok(P_new, S.Pt):
        raise RedactRefused("R5 not tightening")
    if not (AuthMember(redactor.role, redactor.id, S.Pt.adm)
            and ScopeMatchRID(redactor.scope, S.rid) and ScopeMatchJ(redactor.scope, removed)):
        raise RedactRefused("R6 auth")
    i = len(S.log) + 1
    cid = canon.H(redactor.msg)
    e_bytes = canon.enc_e(i, redactor.id, redactor.role, cid, S.It, set(I_new),
                          S.Pt, P_new, ts, n)
    h_new = canon.hi_of(e_bytes, S.h_t)
    tau = s5_sig.core(S.scheme).sign(
        sk_r, redactor.pk, canon.M_red(S.rid, i, e_bytes, S.h_t, h_new),
        canon.CTX_RED, rng=sig_rng)
    S2 = Sigma(S.scheme, S.rid, n)
    S2.sd = S.sd
    S2.acc0, S2.P0, S2.sigma0, S2.cert_s = S.acc0, S.P0, S.sigma0, S.cert_s
    S2.It = set(I_new)
    S2.fields = {j: S.fields[j] for j in S2.It}
    S2.Pt = P_new
    S2.log = S.log + [(e_bytes, tau, cid)]
    S2.certs = dict(S.certs)
    if cid not in S2.certs:
        S2.certs[cid] = redactor
    S2.h_t = h_new
    return S2


# ---------------- e / certificate parsing ----------------

def dec_encP(buf, off, n):
    adm_len = buf[off]
    off += 1
    adm = []
    for _ in range(adm_len):
        code, tag = buf[off], buf[off + 1]
        off += 2
        if tag == 1:
            pat = b"*"
        else:
            cnt = buf[off]
            off += 1
            pat = tuple(buf[off + 16 * k: off + 16 * (k + 1)] for k in range(cnt))
            off += 16 * cnt
        adm.append((canon.ROLE_BY_CODE[code], pat))
    B = (n + 7) // 8
    w = canon.bmp_decode(buf[off:off + B], n)
    off += B
    d = struct.unpack(">I", buf[off:off + 4])[0]
    off += 4
    return Policy(adm, w, d, n), off


def dec_e_at(buf, off, n):
    lam = len(canon.H(b""))
    seq = struct.unpack(">I", buf[off:off + 4])[0]
    id16 = buf[off + 4:off + 20]
    role = canon.ROLE_BY_CODE[buf[off + 20]]
    cert_h = buf[off + 21:off + 21 + lam]
    p = off + 22 + lam
    B = (n + 7) // 8
    I_prev = canon.bmp_decode(buf[p:p + B], n)
    p += B
    I_new = canon.bmp_decode(buf[p:p + B], n)
    p += B
    P_prev, p = dec_encP(buf, p, n)
    P_new, p = dec_encP(buf, p, n)
    ts = struct.unpack(">Q", buf[p:p + 8])[0]
    p += 8
    return dict(seq=seq, id=id16, role=role, certH=cert_h,
                I_prev=I_prev, I_new=I_new, P_prev=P_prev, P_new=P_new, ts=ts), p


def dec_e(e_bytes, n):
    return dec_e_at(e_bytes, 0, n)[0]


def dec_cert_at(buf, off, scheme):
    """Parse certificate bytes (sig ‖ msg); returns (Cert, end offset).
    Re-encoding must be byte-identical. sig/pk lengths dispatch on scheme
    (B1: 5,785/3,712; AS/C: 2,420/1,312)."""
    p = off
    sig = buf[p:p + SIG[scheme]]
    p += SIG[scheme]
    if buf[p:p + 14] not in (b"QPRSS-v2|certS", b"QPRSS-v2|certR"):
        raise ValueError("bad cert prefix")
    is_signer = buf[p:p + 14] == b"QPRSS-v2|certS"
    id16 = buf[p + 14:p + 30]
    pk = buf[p + 30:p + 30 + PKL[scheme]]
    q = p + 30 + PKL[scheme]
    rolecode = buf[q]
    q += 1
    role = b"signer" if is_signer else canon.ROLE_BY_CODE[rolecode]
    if buf[q] == 1:
        rids, q = b"*", q + 1
    else:
        cnt = buf[q + 1]
        rids = tuple(buf[q + 2 + 16 * k: q + 2 + 16 * (k + 1)] for k in range(cnt))
        q += 2 + 16 * cnt
    if buf[q] == 1:
        jset, q = b"*", q + 1
    else:
        cnt = buf[q + 1]
        jset = {struct.unpack(">H", buf[q + 2 + 2 * k: q + 4 + 2 * k])[0] for k in range(cnt)}
        q += 2 + 2 * cnt
    nb = struct.unpack(">Q", buf[q:q + 8])[0]
    na = struct.unpack(">Q", buf[q + 8:q + 16])[0]
    q += 16
    c = Cert(id16, pk, role, (rids, jset), nb, na, scheme=scheme)
    c.sig = sig
    assert c.msg == buf[p:q], "cert re-encode mismatch"
    return c, q


def parse_sigma(data: bytes):
    """Deserialize + section accounting. Returns (Sigma, sections =
    [(name, start, stop)]). Offsets all come from real parse positions in
    the byte stream (measured, not formulaic)."""
    sec = []
    lam = len(canon.H(b""))
    rid = data[0:16]
    n = struct.unpack(">I", data[16:20])[0]
    if data[20:21] not in CHAR_SCHEME:
        raise ValueError(f"unknown scheme byte {data[20:21]!r}")
    scheme = CHAR_SCHEME[data[20:21]]
    incl = data[21] & 1
    if not data[21] & 2:
        raise ValueError("legacy v2 stream unsupported")
    r_cnt = struct.unpack(">I", data[22:26])[0]
    t_cnt = struct.unpack(">I", data[26:30])[0]
    u_cnt = struct.unpack(">I", data[30:34])[0]
    p = 34
    sd = None
    if data[21] & 4:                                # v4: optional schema digest
        if p + lam > len(data):
            raise ValueError("schema digest truncated")
        sd = data[p:p + lam]
        p += lam
    acc0 = data[p:p + lam]
    p += lam
    P0, p = dec_encP(data, p, n)
    p += (n + 7) // 8                                    # I₀ bitmap (re-derived at verify)
    Pt, p = dec_encP(data, p, n)
    h_t = data[p:p + lam]
    p += lam
    sec.append(("header", 0, p))
    sigma0 = data[p:p + SIG[scheme]]
    p += SIG[scheme]
    sec.append(("sigma0", sec[-1][2], p))
    S = Sigma(scheme, rid, n)
    S.sd = sd
    S.acc0, S.P0, S.Pt, S.h_t, S.sigma0 = acc0, P0, Pt, h_t, sigma0
    if incl:
        S.cert_s, p = dec_cert_at(data, p, scheme)
        sec.append(("cert_s", sec[-1][2], p))
    # idx+y block (v3+: enc32(j)‖enc32(len)‖y, variable length)
    y_off = p
    js, ys = [], []
    for _ in range(r_cnt):
        j, y, y_off = canon.dec_field(data, y_off)
        js.append(j)
        ys.append(y)
    sec.append(("fields:idx+y", p, y_off))
    # witness-core block (B1/AS = 2-bit packed r‖η 512 B; C = salt 32 B)
    core_len = WITNESS_CORE[scheme]
    w_off = y_off + r_cnt * core_len
    sec.append(("fields:witness-core", y_off, w_off))
    # Merkle path block
    depth = (n - 1).bit_length()
    p_off = w_off + r_cnt * depth * lam
    sec.append(("fields:merkle-path", w_off, p_off))
    # e block + τ block
    e_off = p_off
    hops = []
    for _ in range(t_cnt):
        hop, e_end = dec_e_at(data, e_off, n)
        hops.append((data[e_off:e_end], hop))
        e_off = e_end
    sec.append(("audit:e", p_off, e_off))
    tau_off = e_off + t_cnt * SIG[scheme]
    sec.append(("audit:tau", e_off, tau_off))
    # certificate table block
    c_off = tau_off
    certs = []
    for _ in range(u_cnt):
        c, c_end = dec_cert_at(data, c_off, scheme)
        certs.append(c)
        c_off = c_end
    sec.append(("certs", tau_off, c_off))
    assert c_off == len(data), f"trailing bytes: {len(data) - c_off}"
    # reassemble
    for k, j in enumerate(js):
        path = [data[w_off + (k * depth + d) * lam: w_off + (k * depth + d + 1) * lam]
                for d in range(depth)]
        core = data[y_off + k * core_len: y_off + (k + 1) * core_len]
        wit = ASWitness(core, path) if scheme in ("B1", "AS") else CWitness(core, path)
        S.fields[j] = (ys[k], wit)
    S.It = set(js)
    for k, (e_bytes, hop) in enumerate(hops):
        tau = data[e_off + k * SIG[scheme]: e_off + (k + 1) * SIG[scheme]]
        S.log.append((e_bytes, tau, hop["certH"]))
    for c in certs:
        S.certs[canon.H(c.msg)] = c
    return S, sec


# ---------------- Verify ----------------

def verify(cfg, S: Sigma, mode="hist", *, ra=None, nonce=None, gazettes=None,
           legacy_selfverify=False, legacy_no_invw=False, legacy_presented_anchor=False,
           revsnap=None, require_revsnap=None, expected_sd=None, legacy_no_sd=False):
    """cfg = {"pk_ra": bytes} (+ the module-level cfg_pp set by setup).
    V1–V9 follow the frozen copy (except the revocation/time semantics
    below); the signing core dispatches on S.scheme. Returns accept_*;
    malformed input raises VerifyReject(step).

    Revocation and time semantics:
    - revsnap = (msg, sig): must be a product of RA.revocation_snapshot()
      — the signature is verified under pk_ra, else V5.3d rejects
      (caller-self-reported revocation lists are not trusted);
    - V5.3d-window (all three modes): each hop declares ts ∈ [cert.nb,
      cert.na] (in-record consistency; every input comes from the record
      itself);
    - V5.3d-rev (when revsnap is supplied): hops with declared ts ≥ eff_ts
      are rejected (post-revocation authorization); hops with ts < eff_ts
      are unaffected by a later revocation (historical validity ≠ current
      authorization — consistent semantics across the three modes);
    - require_revsnap defaults to None → True for snapshot/fresh, False
      for hist: a mode claiming current authorization must be given
      trusted revocation state, else V5.3d rejects (never silently
      returns full-authorization-valid); the hist contract makes no
      current-authorization claim, so it stays permitted. Passing an
      explicit True/False overrides (caller owns the semantics);
    - stale snapshots: fresh/snapshot anchors (M_resp3/M_gaz3) carry
      RA.epoch; revsnap epoch < anchor epoch ⟹ V5.3d rejects (an old
      snapshot replayed to mask revocations). Legacy v2 anchors carry no
      epoch to compare against (legacy semantics retained);
    - the currency defenses of snapshot/fresh = the RA registration gate
      (R1-rev on the registrant + R3-rev per signer on new hops, epoch
      domain) + chain-head anchoring (an unregistered fork never reaches
      V9) + revsnap (ts domain, defense in depth).
    """
    n, rid = S.n, S.rid
    pk_ra = cfg["pk_ra"]
    core = s5_sig.core(S.scheme)

    if require_revsnap is None:               # default on for currency modes:
        require_revsnap = mode in ("snapshot", "fresh")   # they need revocation state
    rev_policy, rv_epoch = None, None
    if revsnap is not None:
        rv_msg, rv_sig = revsnap
        if not core.verify(pk_ra, rv_msg, rv_sig, canon.CTX_ANC):
            raise VerifyReject("V5.3d", "revocation snapshot not RA-signed "
                                      "(caller self-reported lists are not trusted)")
        try:
            rv_epoch, rev_policy = canon.parse_revsnap(rv_msg)
        except (ValueError, struct.error) as e:
            raise VerifyReject("V5.3d", f"malformed revocation snapshot: {e}")
    if require_revsnap and revsnap is None:
        raise VerifyReject("V5.3d", "trusted revocation state required "
                                  "but not supplied (refuse, not silent-skip)")

    # V1
    if S.acc0 is None or S.P0 is None or S.sigma0 is None or S.cert_s is None:
        raise VerifyReject("V1.2", "initial block incomplete")
    if not S.It <= set(range(1, n + 1)):
        raise VerifyReject("V1.1", "index out of range")

    # V2.1
    cert_s = S.cert_s
    if legacy_selfverify:
        pk_s = cert_s.pk
    else:
        if cert_s.scheme != S.scheme:
            raise VerifyReject("V2.1", "Cert_S scheme mismatch")
        if not cert_s.verify(pk_ra):
            raise VerifyReject("V2.1", "Cert_S not RA-signed")
        if cert_s.role != b"signer":
            raise VerifyReject("V2.1-role", "cert role != signer")
        if not ScopeMatchRID(cert_s.scope, rid):
            raise VerifyReject("V2.1-scope", "RID not in Cert_S scope")
        pk_s = cert_s.pk

    # V2.2 / V2.3
    if expected_sd is not None and S.sd != expected_sd:
        if not (S.sd is None and legacy_no_sd):
            raise VerifyReject("V2.2", "schema digest missing or mismatch "
                                      "(pinned mode requires signed schema)")
    if not core.verify(pk_s, canon.M_orig(rid, n, S.acc0, S.P0, set(range(1, n + 1)), sd=S.sd),
                       S.sigma0, canon.CTX_ORIG):
        raise VerifyReject("V2.2", "sigma0 invalid")
    h = canon.h0_of(rid, n, S.acc0, S.P0, sd=S.sd)

    # V3/V4 commitments and Merkle (B1/AS share the C2 commitment layer;
    # C = salt + hash)
    # Field table and retained-index set must agree in both directions —
    # extra entries (including legitimately disclosed already-deleted
    # fields) let an in-process consumer read resurrected content after
    # accept; reject.
    if not set(S.fields) <= S.It:
        raise VerifyReject("V1.2", "fields table contains non-retained indices")
    for j in sorted(S.It):
        if j not in S.fields:                    # malformed Σ missing a disclosure: clean reject
            raise VerifyReject("V1.2", f"missing opening for retained field {j}")
        y, w = S.fields[j]
        if S.scheme in ("B1", "AS"):
            r, eta = commit_as.unpack_witness(w.packed)
            if not (commit_as.norm_inf_ok(r) and commit_as.norm_inf_ok(eta)):
                raise VerifyReject("V3.1", "norm bound")
            C = commit_as.commit(cfg_pp["G"], cfg_pp["D"], j, rid, y, r, eta)
            leaf = commit_as.leaf_of(j, C)
        else:
            leaf = commit_c.leaf_of(j, w.salt, y)
        ok, root = merkle.MerkleTree.verify_path(leaf, j - 1, w.path, None)
        if not ok or root != S.acc0:
            raise VerifyReject("V4", f"merkle path field {j}")

    # V5/V6/V7 per hop
    I_prev_state, P_state = set(range(1, n + 1)), S.P0
    used_certs = set()
    for i, (e_bytes, tau, cid) in enumerate(S.log, start=1):
        hop = dec_e(e_bytes, n)
        if hop["seq"] != i:
            raise VerifyReject("V6", "seq")
        cert = S.certs.get(cid)
        if cert is None or canon.H(cert.msg) != cid:
            raise VerifyReject("V5.1", "cert table ref")
        if cert.scheme != S.scheme:
            raise VerifyReject("V5.1", "cert scheme mismatch")
        _check_hop_cert(rid, i, hop, cert, h, e_bytes, tau, pk_ra, S.scheme,
                        selfverify=legacy_selfverify)
        used_certs.add(cid)
        # V5.3d-window: in-record window consistency (declared ts ∈ [nb, na],
        # all modes alike; every input comes from the record itself, no
        # reliance on the caller's clock).
        if not (cert.nb <= hop["ts"] <= cert.na):
            raise VerifyReject("V5.3d-window", "hop declared ts outside cert window")
        # V5.3d-rev: under a trusted revocation snapshot, hops with declared
        # time ≥ effective time are rejected; earlier hops (ts < eff_ts) are
        # not implicated by a later revocation (historical validity ≠
        # current authorization).
        if rev_policy is not None:
            for (rev_id, eff_ts) in rev_policy:
                if cert.id == rev_id and hop["ts"] >= eff_ts:
                    raise VerifyReject("V5.3d-rev",
                                       "redactor revoked at declared hop time")
        removed = hop["I_prev"] - hop["I_new"]
        if hop["I_prev"] != I_prev_state or hop["P_prev"].adm != P_state.adm \
                or hop["P_prev"].w != P_state.w or hop["P_prev"].d != P_state.d:
            raise VerifyReject("V6", "chain state mismatch")
        if not legacy_no_invw:
            _check_hop_policy(n, hop, cert, rid, removed, hop["I_prev"], hop["P_prev"],
                              hop["I_new"], hop["P_new"])
        else:
            if not removed <= hop["P_prev"].w:
                raise VerifyReject("V7.2", "legacy")
            if not hop["P_prev"].K <= hop["I_new"]:
                raise VerifyReject("V7.3", "legacy")
            if not tighten_ok(hop["P_new"], hop["P_prev"]):
                raise VerifyReject("V7.6", "legacy")
        h = canon.hi_of(e_bytes, h)
        I_prev_state, P_state = hop["I_new"], hop["P_new"]
    if h != S.h_t:
        raise VerifyReject("V6", "h_t mismatch")
    if used_certs != set(S.certs.keys()):
        raise VerifyReject("V1.1", "cert table not exactly referenced")

    # V8 final state
    if P_state.adm != S.Pt.adm or P_state.w != S.Pt.w or P_state.d != S.Pt.d:
        raise VerifyReject("V8", "Pt mismatch")
    if S.It != I_prev_state:
        raise VerifyReject("V8", "I_t != chain final I")
    if not P_state.K <= S.It:
        raise VerifyReject("V8", "K_t not kept")
    if len(S.log) > S.P0.d:
        raise VerifyReject("V8", "t > d0")

    # V9
    if mode == "hist":
        return "accept_historical"
    if mode == "fresh":
        if legacy_presented_anchor:
            a_sig, a_h, a_t, a_ts = S.anchor
            if not core.verify(pk_ra, canon.M_resp(b"", rid, a_h, a_t, a_ts), a_sig,
                               canon.CTX_ANC):
                raise VerifyReject("V9", "legacy anchor sig")
            anchor_epoch = None                   # v2 anchors carry no epoch (legacy)
        else:
            if ra is None or nonce is None:
                raise VerifyReject("V9", "fresh requires RA query + nonce")
            resp, a_h, a_t, a_ts, anchor_epoch = ra.fresh_query(nonce, rid)
            if not core.verify(pk_ra, canon.M_resp3(nonce, rid, a_h, a_t, a_ts,
                                                    anchor_epoch), resp,
                               canon.CTX_ANC):
                raise VerifyReject("V9", "resp sig")
        if len(S.log) != a_t or S.h_t != a_h:
            raise VerifyReject("V9", "stale state")
        if rv_epoch is not None and anchor_epoch is not None \
                and rv_epoch < anchor_epoch:
            raise VerifyReject("V5.3d", "revocation snapshot older than anchor "
                                      "(stale snapshot replay)")
        return "accept_fresh"
    if mode == "snapshot":
        if not gazettes:
            raise VerifyReject("V9", "no gazette")
        g_sig, g_h, g_t, g_ts, period, anchor_epoch = gazettes[-1]
        if not core.verify(pk_ra, canon.M_gaz3(period, rid, g_h, g_t, g_ts,
                                               anchor_epoch), g_sig,
                           canon.CTX_ANC):
            raise VerifyReject("V9", "gazette sig")
        if len(S.log) != g_t or S.h_t != g_h:
            raise VerifyReject("V9", "not gazette-head state")
        if rv_epoch is not None and anchor_epoch is not None \
                and rv_epoch < anchor_epoch:
            raise VerifyReject("V5.3d", "revocation snapshot older than anchor "
                                      "(stale snapshot replay)")
        return f"accept_snapshot@G{period}"
    raise ValueError(mode)


cfg_pp = {"G": None, "D": None}   # module-level pp (Verify V3 needs G/D; single parameter set)
