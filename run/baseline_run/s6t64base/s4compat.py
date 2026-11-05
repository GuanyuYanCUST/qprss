# -*- coding: utf-8 -*-
"""Compatibility layer: fixes the XOF replay defect of the original
ShakeRng used by the first implementation of the B1 core.

The defect (caught by statistical validation of the simulator):
  ShakeRng._take refilled its buffer with
      self._buf = self._buf[:self._pos] + self._h.digest(self._pos//64*64 + 128)
  but hashlib shake's digest(k) always returns the FIRST k bytes of the XOF
  stream — the concatenation appended XOF[0:...] after the already-consumed
  prefix, so the stream replayed from the start at every refill (the first
  at byte 126). Consequences, as measured:
  - marginal distributions stay uniform (each replayed block is itself
    uniform SHAKE output) ⇒ every marginal-statistics test passes;
  - cyclic correlations appear between draws ⇒ the per-signature z extrema
    are suppressed (max|z| runs systematically low);
  - the production path is affected: every polynomial entry p of
    expand_A(seed) satisfies p[42+k] == p[k] for k = 0..21 — the public
    matrix A is NOT rejection-uniform as claimed but carries repeated
    structure; sample_in_ball also replays once its internal RNG consumes
    more than 126 bytes, skewing the challenge support off the uniform
    ball. s/e (production uses SysRng = secrets) and H1_challenge (single
    digest, no streaming) are unaffected.

Fix semantics: digest is prefix-consistent — the buffer must be replaced
wholesale by a longer digest, never concatenated with the old prefix. This
module implements that semantics as FixedXofRng and rebuilds the
expand_A / keygen / sign / sim_sign / verify paths following the original
algorithm verbatim (rejection rules, encodings and domain separation all
unchanged). Output encodings are unchanged (SIG_LEN/PK_LEN and the
serializations agree field by field) — only the continuity semantics of
the random stream are fixed.
"""

# Copy of the compatibility layer with the τ=64 parameter dependency carried
# in-package: the absolute imports of s4_core/s4_fs became relative imports
# of .s4dep_core/.s4dep_fs, so this package can never silently pick up an
# external frozen parameter module. FixedXofRng and all algorithms verbatim.
from __future__ import annotations

import hashlib

from .s4dep_core import (FS, SysRng, polymul, vadd, mat_vec, vec_scal, center,
                        pack_signed, unpack_signed, c_encode, c_decode, shake_xof)

DOM = b"QPRSS-FS-B165"          # identical to s4dep_fs.DOM


class FixedXofRng:
    """Deterministic RNG with prefix-consistent XOF consumption (the
    ShakeRng interface with the fixed semantics).

    shake_256.digest(k) is always XOF[0:k]; _take(n) returns XOF[off:off+n]
    and advances off — no replay, ever. below/range keep the original
    semantics verbatim (rejection sampling, inclusive endpoints).

    _take uses a geometrically growing block buffer, which is a
    mathematically equivalent implementation: the stream of output bytes is
    byte-for-byte identical to digest(off+n)[off:] per call (verified by a
    stream identity test), it just avoids re-squeezing the whole prefix on
    every call — total squeezing is amortized O(n) (≤ 2× stream length
    + 8 KiB).
    """

    def __init__(self, *material):
        h = hashlib.shake_256()
        for m in material:
            if isinstance(m, int):
                m = m.to_bytes(8, "little")
            h.update(m)
        self._h = h
        self._off = 0
        self._buf = b""
        self._bpos = 0                      # read pointer inside the buffer

    def _take(self, n: int) -> bytes:
        if len(self._buf) - self._bpos < n:
            want = self._off + n + max(8192, 2 * self._off)
            self._buf = self._h.digest(want)
            self._bpos = self._off
        out = self._buf[self._bpos:self._bpos + n]
        self._bpos += n
        self._off += n
        return out

    def below(self, n: int) -> int:
        nbytes = (n.bit_length() + 7) // 8
        if nbytes == 0:
            return 0
        lim = (1 << (8 * nbytes)) // n * n
        while True:
            v = int.from_bytes(self._take(nbytes), "little")
            if v < lim:
                return v % n

    def range(self, lo: int, hi: int) -> int:          # inclusive both ends
        return lo + self.below(hi - lo + 1)


# ---------------- expand_A / sample_in_ball with the fixed RNG (algorithms
# verbatim from s4dep_fs / s4dep_core) ---------------------------------------

# expand_A memoization: A is fully determined by the pk seed (deterministic
# XOF expansion), so the same seed always yields the identical A — cache per
# seed, FIFO-capped at 256 entries. A is only ever read (mat_vec/polymul do
# not mutate; returned objects are treated as immutable and shared); a cache
# hit and a miss produce byte-identical output. Long-chain verification
# (reloading the same RA/signer/editor pks hop after hop) is the main
# beneficiary.
_A_CACHE = {}
_A_CACHE_MAX = 256


def expand_A(seed):
    """A ∈ R_q^{k×m} — same loops and rejection rule as s4dep_fs.expand_A,
    on the fixed RNG."""
    key = bytes(seed)
    hit = _A_CACHE.get(key)
    if hit is not None:
        return hit
    q, d = FS["q"], FS["d"]
    A = []
    for i in range(FS["k"]):
        row = []
        for j in range(FS["m"]):
            rng = FixedXofRng(b"QPRSS-ExpandA", seed, i, j)
            row.append([rng.below(q) for _ in range(d)])
        A.append(row)
    if len(_A_CACHE) >= _A_CACHE_MAX:
        _A_CACHE.pop(next(iter(_A_CACHE)))         # FIFO eviction
    _A_CACHE[key] = A
    return A


def sample_in_ball(seed_bytes, d, tau):
    """Deterministic exact-weight-τ ternary challenge (Fisher–Yates, in the
    FIPS 204 style) — on the fixed RNG."""
    rng = FixedXofRng(b"QPRSS-SampleInBall", seed_bytes)
    positions = list(range(d))
    for i in range(d - tau, d):
        j = rng.below(i + 1)
        positions[i], positions[j] = positions[j], positions[i]
    chosen = positions[d - tau:]
    assert len(set(chosen)) == tau, "SampleInBall produced wrong weight"
    signs = []
    while len(signs) < tau:
        b = rng._take(1)[0]
        for shift in range(8):
            if len(signs) < tau:
                signs.append((b >> shift) & 1)
    c = [0] * d
    for p, s in zip(chosen, signs):
        c[p] = -1 if s else 1
    return c


# ---------------- encodings reused as-is (independent of the A/c expansion;
# byte-identical to the original implementation) ----------------
from .s4dep_fs import (w_bytes, _z_norm_ok, sig_to_bytes, sig_from_bytes,
                       sk_to_bytes, pk_to_bytes, sk_from_bytes, to_mod)
from .s4dep_core import unpack_bits


def H1_challenge(dom, w, msg):
    """Same as s4dep_fs.H1_challenge; challenge sampling goes through the
    fixed sample_in_ball."""
    seed = shake_xof(b"QPRSS-H1", dom, w_bytes(w), msg).digest(48)
    return sample_in_ball(seed, FS["d"], FS["tau"])


def pk_from_bytes(buf):
    """Same as s4dep_fs.pk_from_bytes; the A expansion goes through the
    fixed expand_A (the same seed yields a DIFFERENT A on the pre-fix path —
    cross-path verification fails closed, no silent mixing)."""
    seed = buf[:32]
    tflat = unpack_bits(buf[32:], FS["tbits"], FS["k"] * FS["d"])
    d = FS["d"]
    t = [tflat[i * d:(i + 1) * d] for i in range(FS["k"])]
    return dict(seed=seed, t=t, A=expand_A(seed))


def keygen(rng=None):
    """Same as s4dep_fs.keygen; A via the fixed expand_A. rng must implement
    below/range (SysRng or FixedXofRng; handing in the original ShakeRng
    would reintroduce the replay defect in its own draws — use FixedXofRng
    for deterministic tests)."""
    rng = rng or SysRng()
    seed = bytes(rng.below(256) for _ in range(32))
    q, d, m = FS["q"], FS["d"], FS["m"]
    s = [[rng.range(-1, 1) for _ in range(d)] for _ in range(m)]
    e = [[rng.range(-1, 1) for _ in range(d)] for _ in range(FS["k"])]
    A = expand_A(seed)
    t = [vadd(wi, ei, q) for wi, ei in zip(mat_vec(A, s, q), e)]
    sk = dict(seed=seed, s=s, e=e)
    pk = dict(seed=seed, t=t, A=A)
    return sk, pk


def sign(sk, pk, msg, rng=None, stats=None):
    """Same rejection-sampling loop as s4dep_fs.sign (z-only acceptance
    rule unchanged)."""
    rng = rng or SysRng()
    q, d, g1 = FS["q"], FS["d"], FS["gamma1"]
    A = pk["A"] if "A" in pk else expand_A(pk["seed"])
    s, e = sk["s"], sk["e"]
    while True:
        if stats is not None:
            stats["attempts"] += 1
        y1 = [[rng.range(-g1, g1) for _ in range(d)] for _ in range(FS["m"])]
        y2 = [[rng.range(-g1, g1) for _ in range(d)] for _ in range(FS["k"])]
        w = [vadd(wi, y2i, q) for wi, y2i in zip(mat_vec(A, y1, q), y2)]
        c = H1_challenge(DOM, w, msg)
        z1 = [vadd(y1j, polymul(sj, c, q, d), q) for y1j, sj in zip(y1, s)]
        z2 = [vadd(y2i, polymul(ei, c, q, d), q) for y2i, ei in zip(y2, e)]
        if _z_norm_ok(z1, z2):
            return z1, z2, c


def verify(pk, msg, z1, z2, c, h1_override=None):
    """Same as s4dep_fs.verify; the A expansion goes through the fixed
    expand_A."""
    if not _z_norm_ok(z1, z2):
        return False
    q, d = FS["q"], FS["d"]
    A = pk["A"] if "A" in pk else expand_A(pk["seed"])
    from .s4dep_core import vec_add, vec_sub
    wp = vec_sub(vec_add(mat_vec(A, z1, q), z2, q), vec_scal(pk["t"], c, q), q)
    if h1_override is not None:
        key = (bytes(w_bytes(wp)), bytes(msg))
        if key in h1_override:
            return h1_override[key] == c
    return H1_challenge(DOM, wp, msg) == c


def sim_sign(pk, msg, rng=None):
    """Programming-style FS signing-oracle simulator, same as
    s4dep_fs.sim_sign (Sign→Prog step of the FS security proof); the
    challenge goes through the fixed sample_in_ball."""
    rng = rng or SysRng()
    q, d, g1, b = FS["q"], FS["d"], FS["gamma1"], FS["beta"]
    A = pk["A"] if "A" in pk else expand_A(pk["seed"])
    cseed = bytes(rng.below(256) for _ in range(48))
    c = sample_in_ball(cseed, d, FS["tau"])
    z1 = [[rng.range(-(g1 - b), g1 - b) for _ in range(d)] for _ in range(FS["m"])]
    z2 = [[rng.range(-(g1 - b), g1 - b) for _ in range(d)] for _ in range(FS["k"])]
    from .s4dep_core import vec_add, vec_sub
    w_sim = vec_sub(vec_add(mat_vec(A, z1, q), to_mod(z2, q), q),
                    vec_scal(pk["t"], c, q), q)
    override = {(bytes(w_bytes(w_sim)), bytes(msg)): c}
    return (z1, z2, c), override
