"""A-S commitment layer: C_j = G·r_j + D·H₂(j‖RID‖y_j) + η_j over
R_q = Z_q[x]/(x^256+1), q = 12289, k = m = 4.
Ternary masking bands r, η ∈ T^4; H₂ = deterministic rejection sampling into
T^4 via SHAKE256. Witness = (2-bit packed r‖η, Merkle path).
D invertibility: sample_pp_checked really checks it and resamples on
failure; a random D is invertible with probability ≈97.94%. Verify itself
never needs the inverse."""
import hashlib
import itertools

import numpy as np

from . import canon

Q = 12289
DEG = 256
KDIM = 4


def polymul(a, b):
    """Negacyclic convolution mod (x^256+1, q)."""
    conv = np.convolve(a.astype(np.int64), b.astype(np.int64))
    r = conv[:DEG].copy()
    r[: len(conv) - DEG] -= conv[DEG:]
    return r % Q


def _drbg(seed: bytes, n_bytes: int) -> bytes:
    out = b""
    ctr = 0
    while len(out) < n_bytes:
        out += hashlib.shake_256(seed + canon.enc32(ctr)).digest(256)
        ctr += 1
    return out[:n_bytes]


def _ternary_from_stream(stream: bytes, count: int):
    """2-bit-per-coefficient rejection sampling (reject v == 3); returns an
    int16 array in {-1, 0, 1}.

    Vectorized but equivalent to the plain loop: the four 2-bit candidates
    of byte b are bits [7:6][5:4][3:2][1:0] big-endian, i.e. exactly the
    2-bit groups of unpackbits — same stream bytes, same consumption order,
    same values."""
    u8 = np.frombuffer(stream, dtype=np.uint8)
    bits = np.unpackbits(u8[:, None], axis=1, bitorder="big").reshape(-1, 2)
    v = (bits[:, 0].astype(np.int16) << 1) | bits[:, 1]
    vals = v[v != 3][:count] - 1
    if len(vals) < count:
        raise ValueError("stream exhausted")
    return vals.astype(np.int16)


def _uniform_q_stream(seed: bytes, count: int):
    """Unbiased [0,Q) coefficient sampling: uint16 rejection, redraw when
    v ≥ 5Q = 61445.

    Why rejection: the naive (hi<<8|lo) % Q is biased — 65536 = 5·12289+4091,
    so 4091 residues have 6 preimages and 8198 have 5, a per-coefficient TVD
    of 4091·(6/65536−1/q)/2 + 8198·(1/q−5/65536)/2 = 4091/65536 ≈ 4.1643%.
    After rejecting, every residue has exactly 5 preimages ⇒ exactly uniform;
    rejection rate 4091/65536 ≈ 6.2401%. Deterministic: same seed, same
    output (fixed extension ladder)."""
    LIMIT = 5 * Q                                            # 61445
    vals, pos, buf, ext = [], 0, _drbg(seed, count * 2 + 4096), 0
    while len(vals) < count:
        if pos + 2 > len(buf):
            ext += 1
            buf = _drbg(seed + b"|ext" + canon.enc32(ext), count * 2 + 4096)
            pos = 0
        v = (buf[pos] << 8) | buf[pos + 1]
        pos += 2
        if v < LIMIT:
            vals.append(v % Q)
    return np.array(vals, dtype=np.int64)


def sample_pp(seed: bytes):
    """G, D ∈ R_q^{4×4} with every coefficient exactly uniform mod q
    (rejection sampling above; D invertibility NOT checked here).
    Note: the (G,D) bytes for a given seed differ from the very first
    implementation, which had the modular bias — size anchors are unaffected
    (sizes don't depend on coefficient values)."""
    coefs = _uniform_q_stream(b"QPRSS-pp|" + seed, 2 * KDIM * KDIM * DEG)
    mats = coefs.reshape(2, KDIM, KDIM, DEG)
    return mats[0], mats[1]


# ---------- D invertibility check ----------

def _negacyclic_roots():
    """The 256 roots of x^256+1 in F_q. q−1 = 12288 = 2^12·3, so 512 | q−1
    and the polynomial splits completely: R_q ≅ F_q^256 as rings. The roots
    are the odd powers of a primitive 512-th root of unity."""
    qm1 = Q - 1
    g = next(x for x in range(2, Q) if all(pow(x, qm1 // p, Q) != 1 for p in (2, 3)))
    zeta = pow(g, qm1 // 512, Q)                     # order exactly 512
    assert pow(zeta, 256, Q) == Q - 1                 # sanity: ζ^256 = −1
    return [pow(zeta, 2 * k + 1, Q) for k in range(DEG)]


_ROOTS = None


def _eval_poly(a, x: int) -> int:
    """Horner evaluation mod q."""
    acc = 0
    for c in a[::-1]:
        acc = (acc * x + int(c)) % Q
    return acc


def is_unit_poly(a) -> bool:
    """a ∈ R_q is a unit ⟺ gcd(a, x^256+1) = 1 ⟺ nonzero at all 256 roots."""
    global _ROOTS
    if _ROOTS is None:
        _ROOTS = _negacyclic_roots()
    return all(_eval_poly(a, r) != 0 for r in _ROOTS)


def _sign4(p) -> int:
    seen = [False] * 4
    s = 1
    for i in range(4):
        if not seen[i]:
            j, clen = i, 0
            while not seen[j]:
                seen[j] = True
                j = p[j]
                clen += 1
            if clen % 2 == 0:
                s = -s
    return s


def det4x4(M):
    """Determinant of a 4×4 matrix over the commutative ring R_q (24-term
    permutation expansion, 3 polynomial multiplications per term)."""
    acc = np.zeros(DEG, dtype=np.int64)
    for p in itertools.permutations(range(4)):
        term = M[0][p[0]].astype(np.int64)
        for row in (1, 2, 3):
            term = polymul(term, M[row][p[row]])
        acc += _sign4(p) * term
    return acc % Q


def is_invertible(D) -> bool:
    """D ∈ R_q^{4×4} is invertible ⟺ det(D) is a unit of R_q (valid over a
    commutative ring)."""
    return is_unit_poly(det4x4(D))


def sample_pp_checked(seed: bytes):
    """Parameter sampling with the D invertibility check: on failure,
    resample with seed‖enc32(ctr). Round 0 is exactly sample_pp(seed).
    Returns (G, D, number of resampling rounds)."""
    for ctr in range(1000):
        s = seed if ctr == 0 else seed + canon.enc32(ctr)
        G, D = sample_pp(s)
        if is_invertible(D):
            return G, D, ctr
    raise RuntimeError("pp resampling exhausted (1000 rounds)")


def H2_poly(j: int, rid: bytes, y: bytes):
    """Deterministic H₂(j‖RID‖y) → T^4 (4 ternary polynomials, rejection
    sampling with domain separation)."""
    stream = _drbg(b"QPRSS-H2|" + canon.enc32(j) + rid + y, 8192)
    t = _ternary_from_stream(stream, KDIM * DEG)
    return t.reshape(KDIM, DEG) % Q


def ternary_rand(rng_seed: bytes):
    """Returns literal {-1,0,1} values (pack2 requires them); commit()
    reduces mod q internally."""
    t = _ternary_from_stream(_drbg(b"QPRSS-rand|" + rng_seed, 8192), KDIM * DEG)
    return t.reshape(KDIM, DEG)


def commit(G, D, j: int, rid: bytes, y: bytes, r, eta):
    h2 = H2_poly(j, rid, y)
    C = np.zeros((KDIM, DEG), dtype=np.int64)
    for i in range(KDIM):
        acc = np.zeros(DEG, dtype=np.int64)
        for k_ in range(KDIM):
            acc += polymul(G[i][k_], r[k_]) + polymul(D[i][k_], h2[k_])
        C[i] = (acc + eta[i]) % Q
    return C


# ---------- encodings ----------

def pack2(polys) -> bytes:
    """Ternary 2-bit packing (value+1 ∈ {0,1,2}). Any 4×256 array → 256 B.

    Vectorized equivalent: take the top 2 bits of each v+1 (MSB first) and
    assemble bytes LSB-first — the same bit stream as the plain per-bit
    loop `out[i//8] |= bit << (i%8)`."""
    a = np.asarray(polys, dtype=np.int64).reshape(-1) + 1
    assert a.min() >= 0 and a.max() <= 2
    bits = np.unpackbits(a.astype(np.uint8)[:, None], axis=1,
                         bitorder="big")[:, -2:].reshape(-1)
    return np.packbits(bits, bitorder="little").tobytes()


def unpack2(buf: bytes, rows: int):
    assert len(buf) == rows * DEG // 4
    bits = np.unpackbits(np.frombuffer(buf, dtype=np.uint8), bitorder="little")
    v = (bits[0::2].astype(np.int16) << 1) | bits[1::2]
    return (v - 1).reshape(rows, DEG)


def pack14(C) -> bytes:
    """All coefficients of C_j in 14-bit encoding (4×256 → 1792 B).

    Bit order gotcha (bit us once): value bits are MSB-first (s = 13..0)
    but byte assembly is LSB-first — writing bitorder the wrong way round
    here was caught by a byte-level gate test, so keep this exact spelling."""
    flat = np.asarray(C, dtype=np.int64).reshape(-1)
    assert flat.min() >= 0 and flat.max() < Q
    be = flat.astype(">u2").view(np.uint8).reshape(-1, 2)   # high byte first
    bits = np.unpackbits(be, axis=1, bitorder="big").reshape(-1, 16)[:, 2:]
    return np.packbits(bits.reshape(-1), bitorder="little").tobytes()


def unpack14(buf: bytes):
    flat = np.zeros(KDIM * DEG, dtype=np.int64)
    for i in range(KDIM * DEG):
        v = 0
        base = i * 14
        for s in range(13, -1, -1):
            v = (v << 1) | ((buf[(base + 13 - s) // 8] >> ((base + 13 - s) % 8)) & 1)
        flat[i] = v
    return flat.reshape(KDIM, DEG)


def pack_witness(r, eta) -> bytes:
    """r‖η, 8 polynomials → 512 B."""
    return pack2(np.vstack([r, eta]))


def unpack_witness(buf):
    coefs = unpack2(buf, 8)
    return coefs[:4], coefs[4:]


def norm_inf_ok(coefs) -> bool:
    return int(np.max(np.abs(coefs))) <= 1


def leaf_of(j: int, C) -> bytes:
    return canon.H(b"leaf|" + canon.enc32(j) + pack14(C))
