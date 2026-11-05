"""A-S 承诺层：C_j = G·r_j + D·H₂(j‖RID‖y_j) + η_j，R_q=Z_q[x]/(x^256+1)，q=12289，k=m=4。
三元随机带 r,η∈T^4；H₂=SHAKE256 确定性拒绝采样到 T^4。见证 = (2-bit 打包 r‖η, Merkle 路径)。
D 可逆性：sample_pp_checked 真实检查并在失败时重采样（2B-2 任务一(1)）；
随机 D 可逆概率 ≈97.94%（Step 1.7），Verify 本身不需求逆。"""
import hashlib
import itertools

import numpy as np

from . import canon

Q = 12289
DEG = 256
KDIM = 4


def polymul(a, b):
    """负循环卷积 mod (x^256+1, q)。"""
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
    """2-bit/系数拒绝采样（拒绝 3）；返回 int8 数组 ∈{-1,0,1}。"""
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
    """无偏 [0,Q) 系数采样（2B-3 P0）：uint16 拒绝采样，v ≥ 5Q=61445 拒绝重抽。
    旧实现 (hi<<8|lo)%Q：65536=5·12289+4091 ⇒ 4091 个余数 6 个原像、8198 个 5 个，
    每系数 TVD = 4091·(6/65536−1/q)/2 + 8198·(1/q−5/65536)/2 = 4091/65536 ≈ 4.1643%。
    拒绝后每余数恰 5 个原像 ⇒ 精确均匀；拒绝率 4091/65536 ≈ 6.2401%。
    确定性：同 seed 同输出（扩展 ladder 固定）。"""
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
    """G, D ∈ R_q^{4×4}（每系数精确均匀 mod q——2B-3 P0 拒绝采样；不检查 D 可逆性）。
    注：P0 修复后同一 seed 的 (G,D) 字节与旧实现不同（旧实现有模偏差）；
    尺寸/行为锚点不受影响（大小与系数值无关）。"""
    coefs = _uniform_q_stream(b"QPRSS-pp|" + seed, 2 * KDIM * KDIM * DEG)
    mats = coefs.reshape(2, KDIM, KDIM, DEG)
    return mats[0], mats[1]


# ---------- D 可逆性检查（2B-2 任务一(1)） ----------

def _negacyclic_roots():
    """x^256+1 在 F_q 的 256 个根。q−1=12288=2^12·3 ⇒ 512 | q−1，多项式完全分裂，
    R_q ≅ F_q^256 积环（Step 1.7 结论）；根 = 512 阶本原单位根的奇次幂。"""
    qm1 = Q - 1
    g = next(x for x in range(2, Q) if all(pow(x, qm1 // p, Q) != 1 for p in (2, 3)))
    zeta = pow(g, qm1 // 512, Q)                     # 阶恰为 512
    assert pow(zeta, 256, Q) == Q - 1                 # ζ^256 = −1 自检
    return [pow(zeta, 2 * k + 1, Q) for k in range(DEG)]


_ROOTS = None


def _eval_poly(a, x: int) -> int:
    """Horner 求值 mod q。"""
    acc = 0
    for c in a[::-1]:
        acc = (acc * x + int(c)) % Q
    return acc


def is_unit_poly(a) -> bool:
    """a ∈ R_q 是单位 ⇔ gcd(a, x^256+1)=1 ⇔ 在全部 256 个根处非零。"""
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
    """4×4 矩阵在交换环 R_q 上的行列式（置换展开 24 项，每项 3 次多项式乘）。"""
    acc = np.zeros(DEG, dtype=np.int64)
    for p in itertools.permutations(range(4)):
        term = M[0][p[0]].astype(np.int64)
        for row in (1, 2, 3):
            term = polymul(term, M[row][p[row]])
        acc += _sign4(p) * term
    return acc % Q


def is_invertible(D) -> bool:
    """D ∈ R_q^{4×4} 可逆 ⇔ det(D) 是 R_q 单位（交换环上成立）。"""
    return is_unit_poly(det4x4(D))


def sample_pp_checked(seed: bytes):
    """带 D 可逆性检查的参数采样：失败则 seed‖enc32(ctr) 重采样。
    首轮即 sample_pp(seed)（结构锚点；2B-3 P0 后系数字节与旧实现不同——旧实现
    模偏差 4.1643% TVD 已修复，见 _uniform_q_stream）。返回 (G, D, 重采样轮数 ctr)。"""
    for ctr in range(1000):
        s = seed if ctr == 0 else seed + canon.enc32(ctr)
        G, D = sample_pp(s)
        if is_invertible(D):
            return G, D, ctr
    raise RuntimeError("pp resampling exhausted (1000 rounds)")


def H2_poly(j: int, rid: bytes, y: bytes):
    """确定性 H₂(j‖RID‖y) → T^4（4 条三元多项式，域分隔拒绝采样）。"""
    stream = _drbg(b"QPRSS-H2|" + canon.enc32(j) + rid + y, 8192)
    t = _ternary_from_stream(stream, KDIM * DEG)
    return t.reshape(KDIM, DEG) % Q


def ternary_rand(rng_seed: bytes):
    """返回字面 {-1,0,1}（pack2 打包要求）；commit() 内部自行 mod q。"""
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


# ---------- 编码 ----------

def pack2(polys) -> bytes:
    """三元 2-bit 打包（值+1∈{0,1,2}）。任意数组 4×256 → 256 B。"""
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
    """C_j 全系数 14-bit 编码（4×256 → 1792 B）。"""
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
    """r‖η 共 8 条 → 512 B。"""
    return pack2(np.vstack([r, eta]))


def unpack_witness(buf):
    coefs = unpack2(buf, 8)
    return coefs[:4], coefs[4:]


def norm_inf_ok(coefs) -> bool:
    return int(np.max(np.abs(coefs))) <= 1


def leaf_of(j: int, C) -> bytes:
    return canon.H(b"leaf|" + canon.enc32(j) + pack14(C))
