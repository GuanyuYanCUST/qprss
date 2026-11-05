# -*- coding: utf-8 -*-
"""RouteB Stage-4 E0 core: rings, packing, hashing, sampling (stdlib only).

Schoolbook negacyclic arithmetic over R_q = Z_q[x]/(x^d + 1).
Reference implementation: correctness first, no NTT. E0 gate for T-IFS-26973.
"""

# [Stage-5.10.3 τ=64 候选] 本文件 = 冻结 s4_core.py（sha256 c735976e…）的副本，
# 仅三处参数层改动（FS dict tau/beta/cbytes 与 c_encode/c_decode 字节宽度参数化），
# 算法/拒绝规则/域分隔逐字不变。原冻结件零改动；UPGRADE-64 依据 = 5.10.2/2a
# 量子成本核算（A 口径全档 +4.2~+5.4 bit）+ 用户指定的实施方向（正式签认待核验）。
import hashlib
import math

# ---------------- B1-65 (FS layer) and C2 (commitment layer) parameters ------
FS = dict(
    q=8380417,          # 2^23 - 2^13 + 1  (Stage-4 erratum: not 73*2^25+1)
    d=256,
    k=5, m=5,
    eta=1,
    gamma1=1 << 17,     # 131072
    tau=64,
    beta=64,            # tau*eta
    zbits=18,           # signed z packing: |z| <= gamma1-beta = 131033 < 2^17
    tbits=23,           # t coefficient packing (q < 2^23)
    cbytes=34,          # challenge encoding (rank*2^tau+signs < 2^267.57, fits 34B)
)
C2 = dict(
    q=12289, d=256, k=4, m=4, cbits=14,   # q < 2^14
)

def acceptance_closed(fs=FS):
    """acc = ((2(g1-b)+1)/(2g1+1))^((k+m)d); returns (per-coeff p, full acc)."""
    p = (2 * (fs["gamma1"] - fs["beta"]) + 1) / (2 * fs["gamma1"] + 1)
    n = (fs["k"] + fs["m"]) * fs["d"]
    return p, p ** n

def hinf_w_lower(fs=FS):
    """H_inf(w) >= k*d*log2(2*gamma1+1)  (Stage-4 erratum E9-2)."""
    return fs["k"] * fs["d"] * math.log2(2 * fs["gamma1"] + 1)

# ---------------- ring arithmetic --------------------------------------------
# [Stage-6 P0 性能优化·Opt1] polymul 增加 numpy int64 快路径（数学等价实现）：
# np.convolve 整数卷积 + 负循环折叠 + %q，与下方 schoolbook 逐位相同（整数精确
# 运算，无舍入）。溢出守卫：|a|∞·|b|∞·d < 2^62 方走 int64（本包最坏组合
# q≈2^23 与 γ₁≈2^17 → 256·2^23·2^17=2^48 ≪ 2^62）；超界或无 numpy 时回退
# 纯 Python 原实现。等价性证据 = Stage6 03号（字节级 identity 测试 + 回归）。
# 先例：commit_as.py（C2 层）自 Stage-5 起即用同型 np.convolve int64。
try:
    import numpy as _np
except ImportError:                                    # pragma: no cover
    _np = None

def polymul(a, b, q, d):
    """Negacyclic schoolbook product in Z_q[x]/(x^d+1)."""
    if _np is not None:
        aa = _np.asarray(a, dtype=_np.int64)
        bb = _np.asarray(b, dtype=_np.int64)
        ma = int(_np.max(_np.abs(aa))) if len(aa) else 0
        mb = int(_np.max(_np.abs(bb))) if len(bb) else 0
        if ma * mb * d < (1 << 62):
            res = _np.convolve(aa, bb)
            out = res[:d].copy()
            out[:d - 1] -= res[d:2 * d - 1]
            out %= q
            return out.tolist()
    res = [0] * (2 * d - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    res[i + j] += ai * bj
    out = [0] * d
    for kk in range(d - 1):
        out[kk] = res[kk] - res[kk + d]
    out[d - 1] = res[d - 1]
    return [v % q for v in out]

def vadd(u, v, q):
    return [(x + y) % q for x, y in zip(u, v)]

def vsub(u, v, q):
    return [(x - y) % q for x, y in zip(u, v)]

def vec_add(U, V, q):
    """Vector-of-polynomials addition."""
    return [vadd(u, v, q) for u, v in zip(U, V)]

def vec_sub(U, V, q):
    return [vsub(u, v, q) for u, v in zip(U, V)]

def mat_vec(A, x, q):
    """A: k x m list of polys; x: length-m vector of polys."""
    out = []
    for row in A:
        acc = [0] * len(row[0])
        for Aij, xj in zip(row, x):
            acc = vadd(acc, polymul(Aij, xj, q, len(Aij)), q)
        out.append(acc)
    return out

def vec_scal(t, c, q):
    return [polymul(ti, c, q, len(ti)) for ti in t]

def inf_norm(poly):
    # representatives already reduced mod q; use centered for the true norm
    return 0  # placeholder (unused; norms taken on centered values directly)

def center(v, q):
    """Map residues in [0,q) to centered representatives in (-(q/2), q/2]."""
    half = q // 2
    return [x - q if x > half else x for x in v]

# ---------------- bit packing ------------------------------------------------
def pack_bits(vals, bits):
    acc = 0
    n = 0
    out = bytearray()
    for v in vals:
        acc |= v << n
        n += bits
        while n >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            n -= 8
    if n:
        out.append(acc & 0xFF)
    return bytes(out)

def unpack_bits(buf, bits, count):
    acc = 0
    n = 0
    pos = 0
    vals = []
    for _ in range(count):
        while n < bits:
            acc |= buf[pos] << n
            pos += 1
            n += 8
        vals.append(acc & ((1 << bits) - 1))
        acc >>= bits
        n -= bits
    return vals

def pack_signed(vals, bits, bound_check=True):
    off = 1 << (bits - 1)
    if bound_check:
        assert all(-off <= v < off for v in vals), "signed packing overflow"
    return pack_bits([v + off for v in vals], bits)

def unpack_signed(buf, bits, count):
    off = 1 << (bits - 1)
    return [v - off for v in unpack_bits(buf, bits, count)]

# ---------------- XOF / DRBG -------------------------------------------------
class ShakeRng:
    """Deterministic DRBG from SHAKE256 (seed material -> unbiased integers)."""
    def __init__(self, *material):
        h = hashlib.shake_256()
        for m in material:
            if isinstance(m, int):
                m = m.to_bytes(8, "little")
            h.update(m)
        self._h = h
        self._buf = b""
        self._pos = 0

    def _take(self, n):
        while len(self._buf) - self._pos < n:
            # shake_256 digest(k) is a consistent prefix of the XOF stream
            self._buf = self._buf[:self._pos] + self._h.digest(self._pos // 64 * 64 + 128)
        out = self._buf[self._pos:self._pos + n]
        self._pos += n
        return out

    def below(self, n):
        """Uniform in [0, n) via rejection."""
        nbytes = (n.bit_length() + 7) // 8
        if nbytes == 0:
            return 0
        lim = (1 << (8 * nbytes)) // n * n
        while True:
            v = int.from_bytes(self._take(nbytes), "little")
            if v < lim:
                return v % n

    def ternary(self, d):
        """Uniform ternary polynomial via 2-bit rejection."""
        out = []
        tbl = [-1, 0, 1]
        while len(out) < d:
            byte = self._take(1)[0]
            for shift in (0, 2, 4, 6):
                v = (byte >> shift) & 3
                if v != 3:
                    out.append(tbl[v])
                    if len(out) == d:
                        break
        return out

def shake_xof(*material):
    h = hashlib.shake_256()
    for m in material:
        if isinstance(m, int):
            m = m.to_bytes(8, "little")
        h.update(m)
    return h

# ---------------- challenge space (exact weight tau) --------------------------
def sample_in_ball(seed_bytes, d, tau):
    """Deterministic exact-weight-tau ternary challenge from a seed.

    Partial Fisher-Yates over [0..d-1] selects a uniform tau-subset
    (FIPS 204 SampleInBall style); tau sign bits follow on the same stream.
    """
    rng = ShakeRng(b"QPRSS-SampleInBall", seed_bytes)
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
    for i, p in enumerate(chosen):
        c[p] = -1 if signs[i] else 1
    return c

def c_encode(c, tau):
    """25-byte fixed encoding: combinadic rank of support * 2^tau + sign bits."""
    pos = [i for i, v in enumerate(c) if v != 0]
    assert len(pos) == tau
    r = 0
    for i, p in enumerate(pos):
        r += math.comb(p, i + 1)
    s = 0
    for i, p in enumerate(pos):
        if c[p] < 0:
            s |= 1 << i
    v = (r << tau) | s
    n = FS["cbytes"]
    assert v.bit_length() <= 8 * n, "encoding must fit cbytes bytes"
    return v.to_bytes(n, "little")

def c_decode(buf, tau, d=256):
    v = int.from_bytes(buf, "little")
    s = v & ((1 << tau) - 1)
    r = v >> tau
    n = FS["cbytes"]
    assert len(buf) == n, f"encoding must be exactly {n} bytes"
    assert v.bit_length() <= 8 * n, "encoding must fit cbytes bytes"
    assert 0 <= r < math.comb(d, tau), "combinadic rank out of range (illegal encoding)"
    pos_desc = []
    for i in range(tau, 0, -1):
        lo, hi = i - 1, d
        while lo < hi:
            mid = (lo + hi) // 2
            if math.comb(mid, i) <= r:
                lo = mid + 1
            else:
                hi = mid
        p = lo - 1
        r -= math.comb(p, i)
        pos_desc.append(p)
    assert r == 0
    pos = pos_desc[::-1]                    # ascending, matching encode
    assert pos == sorted(pos)
    c = [0] * d
    for i, p in enumerate(pos):
        c[p] = -1 if (s >> i) & 1 else 1
    return c

# ---------------- CSPRNG wrapper ---------------------------------------------
class SysRng:
    """Default CSPRNG (secrets). Deterministic rng is test-only and must be
    passed explicitly (Step2B-2 discipline)."""
    def __init__(self):
        import secrets
        self._rng = secrets.SystemRandom()

    def below(self, n):
        return self._rng.randrange(n)

    def range(self, lo, hi):  # inclusive both ends
        return self._rng.randint(lo, hi)
