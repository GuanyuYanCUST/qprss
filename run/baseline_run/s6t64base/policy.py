"""Policy layer: P = (Adm, W, d), K = [n]\W, P(I) = 1 ⟺ K ⊆ I.
idpat ∈ {b"*"} ∪ (tuple of 16 B IDs): the wildcard is the whole-universe
value — no prefix or pattern matching."""


class Policy:
    __slots__ = ("adm", "w", "d", "n")

    def __init__(self, adm, w, d, n):
        self.adm = tuple(adm)          # ((role_bytes, idpat), ...)
        self.w = frozenset(w)          # deletable index set ⊆ [n]
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
    return rid_id in pat  # enumerated tuple


def IDMatch(a, rid_id: bytes) -> bool:
    return _pat_match(a, rid_id)


def AuthMember(role: bytes, rid_id: bytes, Adm) -> bool:
    return any(r == role and IDMatch(x, rid_id) for (r, x) in Adm)


def _entry_covered(x, x0) -> bool:
    """Per-entry coverage in the tightening direction: every ID of x is
    covered by x0's pattern; a wildcard x requires x0 to be a wildcard too."""
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
    """P_new ⊑ P_old: AdmLeq ∧ W tightened ∧ d decreases by at least 1 per hop."""
    return (AdmLeq(P_new.adm, P_old.adm)
            and P_new.w <= P_old.w
            and P_old.d - P_new.d - 1 >= 0
            and P_new.d >= 0)


def inv_w(I, P) -> bool:
    """Inv-W invariant: [n]\\I ⊆ W (deleted indices stay in W permanently)."""
    return frozenset(range(1, P.n + 1)) - frozenset(I) <= P.w
