"""策略层：一般策略 P=(adm, W, M, b)（论文 §2.2），K=[n]\\W 为受限子族视图。

论文式(1)：P_T = 1 ⟺ (U∖T ⊆ W) ∧ (M ⊆ T)；D(P) = W∖M（有效可删集）。
式(3)：P' ≽ P ⟺ D(P') ⊆ D(P)；协议化收紧 = W'⊆W ∧ M⊆M' ∧ b>0 ∧ 0≤b'≤b−1。

受限子族（论文 §4.3"受限策略实例"）：M = U∖W（构造缺省 m=None）——此时
式(1) 两合取同真假（U∖T⊆W ⟺ U∖W⊆T），与历史 K⊆I 谓词逐点等价。

编码版本 ver（论文"Setup 固定的确定性编码版本；签名与验证不得混用"）：
  ver=1 受限实例编码（canon.encP 字节，无 M 位图）——要求 M=U∖W；
  ver=2 式(2) 一般编码（canon.enc_pol 的 pol-v1 描述符 + 规范 adm 档案）。
同工件内版本必须一致（redact/verify 拒混用）。

idpat ∈ {b"*"} ∪ (16B ID 的元组)：通配=整体全集值，无前缀/模式匹配。
SF-C：adm 构造即规范化（canon.adm_key 排序+去重）；解码端 dec_pol 对偶拒绝。
AdmLeq 为实现附加的授权面收紧检查（严格于论文 Auth 语义，不拒论文合法转移）。
"""
from . import canon

POL_VER_LEGACY = 1
POL_VER_GENERAL = 2


class Policy:
    __slots__ = ("adm", "w", "d", "n", "_m", "ver")

    def __init__(self, adm, w, d, n, m=None, ver=POL_VER_LEGACY):
        # SF-C：重复条目语义等价，去重无损；排序后编码唯一。
        self.adm = tuple(sorted(set(adm), key=lambda e: canon.adm_key(e[0], e[1])))
        self.w = frozenset(w)          # 允许删除集 W ⊆ [n]
        self.d = int(d)                # 剩余预算 b
        self.n = n
        U = frozenset(range(1, n + 1))
        if not self.w <= U:
            raise ValueError(f"W ⊄ [n]: extra={sorted(self.w - U)[:5]}")
        if m is None:
            self._m = None             # 受限子族：M = U∖W（派生）
        else:
            self._m = frozenset(m)
            if not self._m <= U:
                raise ValueError(f"M ⊄ [n]: extra={sorted(self._m - U)[:5]}")
            if ver == POL_VER_LEGACY and self._m != U - self.w:
                raise ValueError(
                    "ver=1 restricted encoding requires M=U\\W "
                    "(use ver=2 general descriptor)")
        self.ver = ver

    @property
    def K(self):
        """受限子族视图 K = [n]\\W（历史谓词；一般策略下请用 M/holds）。"""
        return frozenset(range(1, self.n + 1)) - self.w

    @property
    def M(self):
        """必留集 M（式(1) 第二合取）；受限子族派生 M = U∖W。"""
        if self._m is None:
            return frozenset(range(1, self.n + 1)) - self.w
        return self._m

    @property
    def D(self):
        """有效可删集 D(P) = W∖M（式(3) 收紧序的定义域）。"""
        return self.w - self.M

    def holds(self, I):
        """式(1)：P_I = 1 ⟺ (U∖I ⊆ W) ∧ (M ⊆ I)。"""
        U = frozenset(range(1, self.n + 1))
        return (U - frozenset(I)) <= self.w and self.M <= frozenset(I)

    def copy(self, adm=None, w=None, d=None, m=None, ver=None):
        return Policy(self.adm if adm is None else adm,
                      self.w if w is None else w,
                      self.d if d is None else d, self.n,
                      m=self._m if m is None else m,
                      ver=self.ver if ver is None else ver)

    def __repr__(self):
        m = "U\\W" if self._m is None else f"|M|={len(self._m)}"
        return f"P(adm={self.adm},|W|={len(self.w)},{m},d={self.d},ver={self.ver})"


def _pat_match(pat, rid_id: bytes) -> bool:
    if pat == b"*":
        return True
    return rid_id in pat  # 枚举元组


def IDMatch(a, rid_id: bytes) -> bool:
    return _pat_match(a, rid_id)


def AuthMember(role: bytes, rid_id: bytes, Adm) -> bool:
    return any(r == role and IDMatch(x, rid_id) for (r, x) in Adm)


def _entry_covered(x, x0) -> bool:
    """收紧方向单项覆盖：x 的每个 ID 被 x0 的模式覆盖；x 为通配须 x0 也通配。"""
    if x == b"*":
        return x0 == b"*"
    return all(_pat_match(x0, i) for i in x)


def AdmLeq(adm_new, adm_old) -> bool:
    return all(any(r0 == r and _entry_covered(x, x0) for (r0, x0) in adm_old)
               for (r, x) in adm_new)


def ScopeMatchRID(scope, rid: bytes) -> bool:
    rids, _ = scope
    return rids == b"*" or rid in rids


def ScopeMatchJ(scope, J) -> bool:
    _, jset = scope
    return jset == b"*" or frozenset(J) <= frozenset(jset)


def tighten_ok(P_new, P_old) -> bool:
    """式(3) 协议化收紧：W'⊆W ∧ M⊆M' ∧ b>0 ∧ 0≤b'≤b−1（R3/R4/R5）。
    附带 AdmLeq（实现附加授权面收紧，严格于论文）。"""
    return (P_new.w <= P_old.w
            and P_old.M <= P_new.M
            and P_old.d - P_new.d - 1 >= 0
            and P_new.d >= 0
            and AdmLeq(P_new.adm, P_old.adm))


def inv_w(I, P) -> bool:
    """Inv-W 不变式：[n]\\I ⊆ W（式(1) 第一合取的逐跳冗余检查，11/15 号方案 A）。"""
    return frozenset(range(1, P.n + 1)) - frozenset(I) <= P.w
