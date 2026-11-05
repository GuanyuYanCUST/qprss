"""策略层：P=(Adm,W,d)，K=[n]\W，P(I)=1 ⟺ K⊆I。15号 §二精确通配符语义。
idpat ∈ {b"*"} ∪ (16B ID 的元组)：通配=整体全集值，无前缀/模式匹配。"""


class Policy:
    __slots__ = ("adm", "w", "d", "n")

    def __init__(self, adm, w, d, n):
        self.adm = tuple(adm)          # ((role_bytes, idpat), ...)
        self.w = frozenset(w)          # 可删索引集 ⊆ [n]
        self.d = int(d)
        self.n = n

    @property
    def K(self):
        return frozenset(range(1, self.n + 1)) - self.w

    def holds(self, I):
        """P(I) = K ⊆ I"""
        return self.K <= frozenset(I)

    def copy(self, adm=None, w=None, d=None):
        return Policy(self.adm if adm is None else adm,
                      self.w if w is None else w,
                      self.d if d is None else d, self.n)

    def __repr__(self):
        return f"P(adm={self.adm},|W|={len(self.w)},d={self.d})"


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
    """P_new ⊑ P_old：AdmLeq ∧ W 收紧 ∧ d 每轮至少减 1。"""
    return (AdmLeq(P_new.adm, P_old.adm)
            and P_new.w <= P_old.w
            and P_old.d - P_new.d - 1 >= 0
            and P_new.d >= 0)


def inv_w(I, P) -> bool:
    """Inv-W 不变式：[n]\\I ⊆ W（已删索引永久驻留 W，11/15 号方案 A）。"""
    return frozenset(range(1, P.n + 1)) - frozenset(I) <= P.w
