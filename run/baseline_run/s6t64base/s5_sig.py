# -*- coding: utf-8 -*-
"""Signing-core registry: B1-65 custom FS (the paper's core) and ML-DSA-44
(comparison arm).

Uniform byte-level API (this is the only interface the protocol engine sees):
    keygen() -> (sk_bytes, pk_bytes)
    sign(sk, pk, msg, ctx, rng=None) -> sig_bytes
    verify(pk, msg, sig, ctx) -> bool
    SIG_LEN / PK_LEN

Context binding for B1: the H1 challenge covers (dom, w, msg), so ctx is
folded into msg as an explicit prefix ("QPRSS-B1ctx|"<ctx>"|"<msg>) —
cryptographically equivalent to a separate dom argument (domain separation).
The B1-65 parameter dependency (τ=64) is carried in-package via
.s4dep_core/.s4dep_fs, and SIG_LEN["B1"] is derived from the FS table.
ML-DSA-44 uses dilithium-py's native ctx parameter (FIPS 204 semantics).
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

# The B1 core routes through s4compat: the fix for the XOF replay defect in
# the original ShakeRng (deterministic expansions of expand_A/sample_in_ball
# now draw from a prefix-consistent stream). Algorithm, parameters, domain
# separation and encodings are unchanged; only the continuity semantics of
# the random stream differ — keys/signatures produced by the pre-fix path
# fail closed here (different A/c expansions).
from . import s4compat as b1  # noqa: E402

from .s4dep_core import FS as _FS64
_B1_SIG = (_FS64["k"] + _FS64["m"]) * _FS64["d"] * _FS64["zbits"] // 8 \
    + _FS64["cbytes"]          # 5760 + 34 = 5794 (τ=64, β=τη=64)
SIG_LEN = {"B1": _B1_SIG, "AS": 2420, "C": 2420, "H": _B1_SIG}
PK_LEN = {"B1": 3712, "AS": 1312, "C": 1312, "H": 3712}


class B1Core:
    """B1-65 custom Fiat–Shamir-with-aborts (the paper's signing core;
    fixed-XOF path)."""
    name = "B1"
    SIG_LEN = SIG_LEN["B1"]
    PK_LEN = PK_LEN["B1"]

    @staticmethod
    def keygen(rng=None):
        sk, pk = b1.keygen(rng=rng)
        return b1.sk_to_bytes(sk), b1.pk_to_bytes(pk)

    @staticmethod
    def _msg(msg: bytes, ctx: bytes) -> bytes:
        return b"QPRSS-B1ctx|" + ctx + b"|" + msg

    @staticmethod
    def sign(sk_b: bytes, pk_b: bytes, msg: bytes, ctx: bytes, rng=None) -> bytes:
        sk = b1.sk_from_bytes(sk_b)
        pk = b1.pk_from_bytes(pk_b)
        z1, z2, c = b1.sign(sk, pk, B1Core._msg(msg, ctx), rng=rng)
        assert b1.verify(pk, B1Core._msg(msg, ctx), z1, z2, c), "self-check"
        return b1.sig_to_bytes(z1, z2, c)

    @staticmethod
    def verify(pk_b: bytes, msg: bytes, sig_b: bytes, ctx: bytes) -> bool:
        try:
            pk = b1.pk_from_bytes(pk_b)
            z1, z2, c = b1.sig_from_bytes(sig_b)
            return b1.verify(pk, B1Core._msg(msg, ctx), z1, z2, c)
        except Exception:
            return False


class MLDSACore:
    """ML-DSA-44 (FIPS 204 reference implementation; signing core of the
    comparison arms AS/C)."""
    name = "MLDSA"
    SIG_LEN = SIG_LEN["AS"]
    PK_LEN = PK_LEN["AS"]

    @staticmethod
    def _dsa():
        deps = os.path.abspath(os.path.join(_HERE, "..", "..", "..",
                                            "Step2B_原型", "deps",
                                            "dilithium-py", "src"))
        if deps not in sys.path:
            sys.path.insert(0, deps)
        from dilithium_py.ml_dsa import ML_DSA_44
        return ML_DSA_44

    @staticmethod
    def keygen():
        dsa = MLDSACore._dsa()
        pk, sk = dsa.keygen()
        return sk, pk

    @staticmethod
    def sign(sk, pk, msg, ctx, rng=None):
        return MLDSACore._dsa().sign(sk, msg, ctx=ctx)

    @staticmethod
    def verify(pk, msg, sig, ctx):
        try:
            return MLDSACore._dsa().verify(pk, msg, sig, ctx=ctx)
        except Exception:
            return False


def core(scheme: str):
    """scheme ∈ {"B1", "H", "AS", "C"} → signing core. B1/H = the custom FS
    core (H is the commitment-layer ablation); AS/C = ML-DSA-44."""
    if scheme in ("B1", "H"):
        return B1Core
    if scheme in ("AS", "C"):
        return MLDSACore
    raise ValueError(f"unknown scheme {scheme!r}")
