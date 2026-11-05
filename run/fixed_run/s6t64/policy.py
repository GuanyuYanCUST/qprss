"""Policy layer: general policy P = (adm, W, M, b) (§2.2 of the paper);
K = [n]\\W is the restricted-subfamily view.

Eq. (1): P_T = 1 ⟺ (U∖T ⊆ W) ∧ (M ⊆ T); D(P) = W∖M (the effectively
deletable set).
Eq. (3): P' ≽ P ⟺ D(P') ⊆ D(P); the protocol-level tightening is
W' ⊆ W ∧ M ⊆ M' ∧ b > 0 ∧ 0 ≤ b' ≤ b−1.

Restricted subfamily (§4.3 "restricted policy instances"): M = U∖W (the
default when m=None is omitted) — then both conjuncts of eq. (1) carry the
same truth value (U∖T ⊆ W ⟺ U∖W ⊆ T), matching the historical K ⊆ I
predicate pointwise.

Encoding version ver ("a deterministic encoding version fixed by Setup;
signing and verification must not mix versions"):
  ver=1 restricted-instance encoding (canon.encP bytes, no M bitmap) —
       requires M = U∖W;
  ver=2 general encoding of eq. (2) (canon.enc_pol: pol-v1 descriptor +
       canonical adm profiles).
Both versions must agree inside one artifact (redact/verify reject mixing).

idpat ∈ {b"*"} ∪ (tuple of 16 B IDs): the wildcard is the whole-universe
value — no prefix or pattern matching. adm is canonicalized at construction
(canon.adm_key sort + dedup); dec_pol rejects the dual on decode. AdmLeq is
an implementation-added tightening of the authorization surface (strictly
stronger than the paper's Auth semantics; it never rejects a legal paper
transition).
"""
from . import canon

POL_VER_LEGACY = 1
POL_VER_GENERAL = 2


class Policy:
    __slots__ = ("adm", "w", "d", "n", "_m", "ver")

    def __init__(self, adm, w, d, n, m=None, ver=POL_VER_LEGACY):
        # duplicate entries are semantically equivalent, so dedup is
        # lossless; sorting makes the encoding unique.
        self.adm = tuple(sorted(set(adm), key=lambda e: canon.adm_key(e[0], e[1])))
        self.w = frozenset(w)          # deletable set W ⊆ [n]
        self.d = int(d)                # remaining budget b
        self.n = n
        U = frozenset(range(1, n + 1))
        if not self.w <= U:
            raise ValueError(f"W ⊄ [n]: extra={sorted(self.w - U)[:5]}")
        if m is None:
            self._m = None             # restricted subfamily: M = U∖W (derived)
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
        """Restricted-subfamily view K = [n]\\W (historical predicate; for a
        general policy use M/holds)."""
        return frozenset(range(1, self.n + 1)) - self.w

    @property
    def M(self):
        """Must-keep set M (second conjunct of eq. (1)); derived M = U∖W for
        the restricted subfamily."""
        if self._m is None:
            return frozenset(range(1, self.n + 1)) - self.w
        return self._m

    @property
    def D(self):
        """Effectively deletable set D(P) = W∖M (domain of the eq. (3)
        tightening order)."""
        return self.w - self.M

    def holds(self, I):
        """Eq. (1): P_I = 1 ⟺ (U∖I ⊆ W) ∧ (M ⊆ I)."""
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
    """Eq. (3) protocol-level tightening: W'⊆W ∧ M⊆M' ∧ b>0 ∧ 0≤b'≤b−1,
    plus AdmLeq (an implementation-added authorization-surface tightening,
    strictly stronger than the paper's)."""
    return (P_new.w <= P_old.w
            and P_old.M <= P_new.M
            and P_old.d - P_new.d - 1 >= 0
            and P_new.d >= 0
            and AdmLeq(P_new.adm, P_old.adm))


def inv_w(I, P) -> bool:
    """Inv-W invariant: [n]\\I ⊆ W (per-hop redundant check of the first
    conjunct of eq. (1))."""
    return frozenset(range(1, P.n + 1)) - frozenset(I) <= P.w
