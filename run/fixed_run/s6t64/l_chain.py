# -*- coding: utf-8 -*-
"""Baseline L: naive sequential multi-signature chain on the same signing
core (B1-65).

Minimal assembly of the "trivial multi-signature chain of sequential
modifications" named by the review: the original signer signs the hash of the
full document; every later editor signs (prev full-state hash | new full-state
hash | metadata) with **their own B1-65 key**. No commitments, no Merkle tree,
no policy state machine, no RA.

Why this baseline exists (it is a carrier for the comparison, not a feature
checklist):
- verifying provenance of the retained fields requires presenting **all
  intermediate full documents** — a structural requirement here, since each
  hop hashes the complete state. Redacted content therefore stays public in
  the verification material forever.
- anyone can forward the final document plus the whole chain, but "reveal
  only the retained fields" is impossible.

Honest boundary: no policy/audit layer at all; in the transport accounting it
is the no-policy lower bound, not a functionally equivalent rival to Q/H
(same policy and audit layer) — see the attribution note in the experiments
section.
"""
from __future__ import annotations

from . import canon, s5_sig

CTX_L_ORIG = b"Lorig"
CTX_L_HOP = b"Lhop"


def h_doc(doc: bytes) -> bytes:
    return canon.H(b"Ldoc|" + doc)


def l_sign_origin(sk_s: bytes, pk_s: bytes, doc0: bytes, rng=None) -> bytes:
    """Origin signature over version-0 of the full document."""
    return s5_sig.core("B1").sign(sk_s, pk_s, b"Lv1|" + h_doc(doc0), CTX_L_ORIG, rng=rng)


def l_hop(prev_h: bytes, doc_new: bytes, meta: bytes, sk_i: bytes, pk_i: bytes,
          rng=None):
    """One sequential hop. Returns (new chain-head hash, tau). meta carries
    the editor's self-description (unauthenticated)."""
    m = b"Lhop|" + prev_h + b"|" + h_doc(doc_new) + b"|" + meta
    tau = s5_sig.core("B1").sign(sk_i, pk_i, m, CTX_L_HOP, rng=rng)
    return canon.H(m), tau


def l_verify(pk_s: bytes, sigma0: bytes, doc0: bytes, hops) -> bool:
    """hops = [(doc_i, meta_i, tau_i, pk_i)] — all intermediate full documents
    must be presented."""
    core = s5_sig.core("B1")
    if not core.verify(pk_s, b"Lv1|" + h_doc(doc0), sigma0, CTX_L_ORIG):
        return False
    h = h_doc(doc0)
    for doc, meta, tau, pk in hops:
        m = b"Lhop|" + h + b"|" + h_doc(doc) + b"|" + meta
        if not core.verify(pk, m, tau, CTX_L_HOP):
            return False
        h = canon.H(m)
    return True


def l_keygen(rng=None):
    return s5_sig.core("B1").keygen(rng=rng)
