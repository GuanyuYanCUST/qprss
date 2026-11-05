# -*- coding: utf-8 -*-
"""Stage-5.9 P0.4：冻结 s4_core.ShakeRng XOF 回放缺陷修复（兼容层）。

缺陷（2026-10-14 于 03号模拟器统计验证中发现，实证见
tests/test_s59_thm1_thm5_executable.py T0）：
  s4_core.ShakeRng._take 在缓冲耗尽时执行
      self._buf = self._buf[:self._pos] + self._h.digest(self._pos//64*64 + 128)
  hashlib shake 的 digest(k) 永远返回 XOF 流的前 k 字节——拼接把
  XOF[0:...] 追加到已消费前缀之后，导致流在每次 refill（首个在字节 126）
  从头回放。后果（实测）：
  - 边缘分布仍均匀（每次回放块本身是均匀 SHAKE 输出）⇒ 所有边缘统计通过；
  - 抽样间出现循环相关 ⇒ 签名内 z 极值被抑制（max|z| 分布系统性偏低）；
  - **生产路径受影响**：expand_A(seed) 的每个多项式条目 p 满足
    p[42+k]==p[k]（k=0..21 实测）——公钥矩阵 A 并非论文所称拒绝均匀，
    而是带重复结构；sample_in_ball 内部 RNG 消耗 >126B 亦触发回放，
    挑战 c 的支撑分布偏离均匀球。s/e（生产走 SysRng=secrets）与
    H1_challenge（单次 digest，无流式消费）不受影响。

修复语义：digest 是前缀一致的——正确做法是每次直接用更长的 digest
整体替换缓冲，不与旧前缀拼接。本模块以 FixedXofRng 实现该语义，并
按 s4_fs 的逐字算法（拒绝规则、编码、域分隔全部不变）重建
expand_A / keygen / sign / sim_sign / verify 路径。输出编码不变
（SIG_LEN/PK_LEN/序列化逐字段一致）——仅随机流的连续性语义修复。

导师约束合规：冻结原件（s4_core.py / s4_fs.py / Stage-5/5.6/5.8 副本）
零改动；本修复走 Stage59_Patched 新副本 + 独立测试 + 冻结候选更新
（FREEZE-CANDIDATE-MANIFEST.json）。E1–E7 正式实验必须在导师确认
本候选后以本路径执行。
"""

# [Stage-5.10.3 τ=64 候选] 本文件 = Stage-5.9 s4compat.py（冻结候选 sha256
# bf9da11c…）的副本，唯一改动 = 三处绝对导入 s4_core/s4_fs 改为相对导入
# .s4dep_core/.s4dep_fs（τ=64 参数依赖随包携带，杜绝静默导入冻结 τ=39 模块）。
# FixedXofRng 与全部算法逐字不变。
from __future__ import annotations

import hashlib

from .s4dep_core import (FS, SysRng, polymul, vadd, mat_vec, vec_scal, center,
                        pack_signed, unpack_signed, c_encode, c_decode, shake_xof)

DOM = b"QPRSS-FS-B165"          # 与 s4_fs.DOM 逐字一致


class FixedXofRng:
    """前缀一致 XOF 消费的确定性 RNG（ShakeRng 接口 + 修复语义）。

    shake_256.digest(k) 总是 XOF[0:k]；_take(n) 取 XOF[off:off+n] 后推进
    off——永不回放。below/range 语义与 s4_core 逐字一致（拒绝采样、含端点）。

    [Stage-6 P0 性能优化·Opt2] _take 增加几何增长的块缓冲（数学等价实现）：
    digest 仍是前缀一致（同一 XOF 流），仅把"每调用全前缀重挤"改为按
    max(8192, 2·off) 几何窗口重挤——总挤取量摊还 O(n)（≤2× 流长 + 8KiB）。
    输出字节流与逐调用 digest(off+n)[off:] 完全相同（等价性证据 = Stage6
    03号流逐字节 identity 测试 + 回归套件）。冻结件 s4dep_core.ShakeRng
    （回放缺陷历史对照件）保持逐字不动。
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
        self._bpos = 0                      # 缓冲内读指针（与 _off 同步推进）

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

    def range(self, lo: int, hi: int) -> int:          # 含双端
        return lo + self.below(hi - lo + 1)


# ---------------- patched expand_A / sample_in_ball（算法逐字同 s4_fs/s4_core） ----

# [Stage-6 P0 性能优化·Opt3] expand_A 公开可复用数据缓存：A 由 pk 种子完全
# 确定（确定性 XOF 展开），同一 seed 的 A 逐字节相同——缓存按 seed 复用，
# 上限 256 项 FIFO。A 仅被只读消费（mat_vec/polymul 不原地修改；返回对象
# 视为不可变共享），等价性 = 命中与未命中输出逐字节一致（Stage6 03号）。
# 长链验证（同 RA/签发者/删改者 pk 逐跳重载）为主要受益方。
_A_CACHE = {}
_A_CACHE_MAX = 256


def expand_A(seed):
    """A ∈ R_q^{k×m}——与 s4_fs.expand_A 相同的循环/拒绝规则，固定 RNG。"""
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
        _A_CACHE.pop(next(iter(_A_CACHE)))         # FIFO 淘汰
    _A_CACHE[key] = A
    return A


def sample_in_ball(seed_bytes, d, tau):
    """确定性精确重量 τ 三元挑战（Fisher–Yates，FIPS 204 风格）——固定 RNG。"""
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


# ---------------- 编码复用（与 A/c 展开无关，冻结实现逐字节一致） ----------------
from .s4dep_fs import (w_bytes, _z_norm_ok, sig_to_bytes, sig_from_bytes,
                       sk_to_bytes, pk_to_bytes, sk_from_bytes, to_mod)
from .s4dep_core import unpack_bits


def H1_challenge(dom, w, msg):
    """与 s4_fs.H1_challenge 相同；挑战采样经固定 sample_in_ball。"""
    seed = shake_xof(b"QPRSS-H1", dom, w_bytes(w), msg).digest(48)
    return sample_in_ball(seed, FS["d"], FS["tau"])


def pk_from_bytes(buf):
    """与 s4_fs.pk_from_bytes 相同；A 展开经固定 expand_A（同种子在冻结/固定
    两路径下得到不同 A——跨模式验证 fail-closed 拒绝，无静默混用）。"""
    seed = buf[:32]
    tflat = unpack_bits(buf[32:], FS["tbits"], FS["k"] * FS["d"])
    d = FS["d"]
    t = [tflat[i * d:(i + 1) * d] for i in range(FS["k"])]
    return dict(seed=seed, t=t, A=expand_A(seed))


def keygen(rng=None):
    """与 s4_fs.keygen 相同；A 经固定 expand_A。rng 需实现 below/range
    （SysRng 或 FixedXofRng；传入冻结 ShakeRng 时其自身消费亦带回放缺陷，
    测试请用 FixedXofRng）。"""
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
    """与 s4_fs.sign 相同的拒绝采样循环（z-only 接受规则不变）。"""
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
    """与 s4_fs.verify 相同；A 展开经固定 expand_A。"""
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
    """与 s4_fs.sim_sign 相同的编程式 FS 签名预言机模拟器（BBD'23 Thm3
    Sign→Prog）；挑战经固定 sample_in_ball。"""
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
