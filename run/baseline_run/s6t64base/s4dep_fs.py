# -*- coding: utf-8 -*-
"""RouteB Stage-4 E0: custom Fiat-Shamir signature, B1-65 parameters.

Construction (Stage-3 01号 corrected spec, full-box masking):
  KeyGen: seed -> A in R^k x m; s,e ternary eta=1; t = A s + e
  Sign:   y1,y2 <- [-g1, g1] full box; w = A y1 + y2; c = H1(dom|w|M_*);
          z = y + (s,e)c; accept iff |z|_inf <= g1 - beta; output (z1, z2, c)
  Verify: |z|_inf <= g1 - beta; w' = A z1 + z2 - t c; accept iff c == H1(...)
Signature = (z1, z2, c): w is never transmitted (R1-C4).

E9-3 discipline: `verify` takes an optional h1_override table for the
FS signing-oracle simulation test; independent (z, c) without programming
must fail (tested in T4/T5).
"""

# [Stage-5.10.3 τ=64 候选] 本文件 = 冻结 s4_fs.py（sha256 0c80e1c5…）的副本，
# 唯一改动 = 导入行改相对导入 .s4dep_core（携带 τ=64 FS dict）；全部函数体
# 逐字不变——FS 以 call-time 查找消费，τ/β/γ₁/cbytes 全部经参数 dict 流动。
from .s4dep_core import (FS, ShakeRng, SysRng, polymul, vadd, vsub, mat_vec,
                        vec_scal, vec_add, vec_sub, center, pack_bits, unpack_bits,
                        pack_signed, unpack_signed, sample_in_ball, c_encode,
                        c_decode, shake_xof)

DOM = b"QPRSS-FS-B165"

# ---------------- KeyGen ------------------------------------------------------
def expand_A(seed):
    """A in R_q^{k x m} from pk seed (ExpandA analogue, rejection-uniform)."""
    q, d = FS["q"], FS["d"]
    A = []
    for i in range(FS["k"]):
        row = []
        for j in range(FS["m"]):
            rng = ShakeRng(b"QPRSS-ExpandA", seed, i, j)
            row.append([rng.below(q) for _ in range(d)])
        A.append(row)
    return A

def keygen(rng=None):
    """Returns (sk, pk). pk bytes = seed(32) || t packed 23-bit = 3712 B."""
    rng = rng or SysRng()
    seed = bytes(rng.below(256) for _ in range(32))
    A = expand_A(seed)
    q, d, m, k = FS["q"], FS["d"], FS["m"], FS["k"]
    s = [[rng.range(-1, 1) for _ in range(d)] for _ in range(m)]
    e = [[rng.range(-1, 1) for _ in range(d)] for _ in range(k)]
    t = [vadd(wi, ei, q) for wi, ei in zip(mat_vec(A, s, q), e)]
    sk = dict(seed=seed, s=s, e=e)
    pk = dict(seed=seed, t=t, A=A)          # A cached in memory only
    return sk, pk

def sk_to_bytes(sk):
    out = sk["seed"]
    for vec in (sk["s"], sk["e"]):
        trits = [v + 1 for poly in vec for v in poly]     # {0,1,2}
        out += pack_bits(trits, 2)
    return out                                            # 32 + 2560*2/8 = 672 B

def pk_to_bytes(pk):
    tflat = [c for poly in pk["t"] for c in poly]
    return pk["seed"] + pack_bits(tflat, FS["tbits"])     # 32 + 1280*23/8 = 3712 B

def pk_from_bytes(buf):
    seed = buf[:32]
    tflat = unpack_bits(buf[32:], FS["tbits"], FS["k"] * FS["d"])
    d = FS["d"]
    t = [tflat[i * d:(i + 1) * d] for i in range(FS["k"])]
    return dict(seed=seed, t=t, A=expand_A(seed))

def sk_from_bytes(buf, rng=None):
    seed = buf[:32]
    d = FS["d"]
    body = buf[32:]
    def take(nbytes, cnt):
        nonlocal body
        trits = unpack_bits(body[:nbytes], 2, cnt)
        body = body[nbytes:]
        return [[v - 1 for v in trits[i * d:(i + 1) * d]] for i in range(cnt // d)]
    s = take(FS["m"] * d * 2 // 8, FS["m"] * d)
    e = take(FS["k"] * d * 2 // 8, FS["k"] * d)
    return dict(seed=seed, s=s, e=e)

# ---------------- Hash / challenge --------------------------------------------
def w_bytes(w):
    """Canonical serialization of w for the H1 input (4 B LE per coefficient)."""
    q = FS["q"]
    out = bytearray()
    for poly in w:
        for c in poly:
            out += (c % q).to_bytes(4, "little")
    return bytes(out)

def H1_challenge(dom, w, msg):
    seed = shake_xof(b"QPRSS-H1", dom, w_bytes(w), msg).digest(48)
    return sample_in_ball(seed, FS["d"], FS["tau"])

# ---------------- Sign / Verify ------------------------------------------------
def _z_norm_ok(z1, z2):
    bound = FS["gamma1"] - FS["beta"]
    for poly in list(z1) + list(z2):
        for v in center(poly, FS["q"]):
            if abs(v) > bound:
                return False
    return True

def sign(sk, pk, msg, rng=None, stats=None):
    """Full-box rejection sampling; returns (z1, z2, c)."""
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
    """h1_override: {(w_bytes, msg): c} programming table (simulator test only)."""
    if not _z_norm_ok(z1, z2):
        return False
    q, d = FS["q"], FS["d"]
    A = pk["A"] if "A" in pk else expand_A(pk["seed"])
    wp = vec_sub(vec_add(mat_vec(A, z1, q), z2, q), vec_scal(pk["t"], c, q), q)
    if h1_override is not None:
        key = (bytes(w_bytes(wp)), bytes(msg))
        if key in h1_override:
            return h1_override[key] == c
    return H1_challenge(DOM, wp, msg) == c

def sig_to_bytes(z1, z2, c):
    zflat = [v for poly in list(z1) + list(z2) for v in center(poly, FS["q"])]
    return pack_signed(zflat, FS["zbits"]) + c_encode(c, FS["tau"])

def sig_from_bytes(buf):
    d = FS["d"]
    n = (FS["k"] + FS["m"]) * d
    zflat = unpack_signed(buf[:n * FS["zbits"] // 8], FS["zbits"], n)
    c = c_decode(buf[n * FS["zbits"] // 8:], FS["tau"])
    polys = [zflat[i * d:(i + 1) * d] for i in range(FS["k"] + FS["m"])]
    return polys[:FS["m"]], polys[FS["m"]:], c   # z1 (m), z2 (k)

# ---------------- FS signing-oracle simulator (E9-3) ---------------------------
def sim_sign(pk, msg, rng=None):
    """BBD'23 Thm 3 Sign->Prog step: sample (z,c) independently, PROGRAM H1.

    Returns ((z1, z2, c), override_table). Without inserting override_table
    into verify(), the pair fails (that failure is itself a test).
    """
    rng = rng or SysRng()
    q, d, g1, b = FS["q"], FS["d"], FS["gamma1"], FS["beta"]
    A = pk["A"] if "A" in pk else expand_A(pk["seed"])
    cseed = bytes(rng.below(256) for _ in range(48))
    c = sample_in_ball(cseed, d, FS["tau"])
    z1 = [[rng.range(-(g1 - b), g1 - b) for _ in range(d)] for _ in range(FS["m"])]
    z2 = [[rng.range(-(g1 - b), g1 - b) for _ in range(d)] for _ in range(FS["k"])]
    w_sim = vec_sub(vec_add(mat_vec(A, z1, q), to_mod(z2, q), q),
                    vec_scal(pk["t"], c, q), q)
    override = {(bytes(w_bytes(w_sim)), bytes(msg)): c}
    return (z1, z2, c), override

def to_mod(polys, q):
    return [[v % q for v in p] for p in polys]
