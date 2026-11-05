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
    int16 array in {-1, 0, 1}."""
    vals = []
    for b in stream:
        for nib in (b >> 4, b & 0xF):
            for v in (nib >> 2, nib & 3):
                if v != 3:
                    vals.append(v - 1)
                if len(vals) == count:
                    return np.array(vals, dtype=np.int16)
    raise ValueError("stream exhausted")


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
    resample with seed‖enc32(ctr). Round 0 is exactly sample_pp(seed)
    (structural anchor; the coefficient bytes differ from the very first
    biased implementation — see _uniform_q_stream). Returns (G, D, number
    of resampling rounds ctr)."""
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
    """Returns literal {-1,0,1} values (pack2 requires them); commit() does
    its own mod q internally."""
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
    """Ternary 2-bit packing (value+1 ∈ {0,1,2}). Any 4×256 array → 256 B."""
    bits = []
    for row in polys:
        for c in row:
            v = int(c) + 1
            assert 0 <= v <= 2
            bits.append(v >> 1)
            bits.append(v & 1)
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def unpack2(buf: bytes, rows: int):
    assert len(buf) == rows * DEG // 4
    coefs = np.zeros((rows, DEG), dtype=np.int16)
    for i in range(rows * DEG):
        v = ((buf[i * 2 // 8] >> (i * 2 % 8)) & 1) << 1 | (buf[(i * 2 + 1) // 8] >> ((i * 2 + 1) % 8) & 1)
        coefs[i // DEG, i % DEG] = v - 1
    return coefs


def pack14(C) -> bytes:
    """All coefficients of C_j in 14-bit encoding (4×256 → 1792 B)."""
    flat = C.reshape(-1)
    assert all(0 <= int(v) < Q for v in flat)
    bits = []
    for v in flat:
        for s in range(13, -1, -1):
            bits.append((int(v) >> s) & 1)
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


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
    """r‖η, 8 polynomials total → 512 B."""
    return pack2(np.vstack([r, eta]))


def unpack_witness(buf):
    coefs = unpack2(buf, 8)
    return coefs[:4], coefs[4:]


def norm_inf_ok(coefs) -> bool:
    return int(np.max(np.abs(coefs))) <= 1


def leaf_of(j: int, C) -> bytes:
    return canon.H(b"leaf|" + canon.enc32(j) + pack14(C))
