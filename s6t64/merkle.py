"""Fixed Merkle tree: N = 2^⌈log₂n⌉ leaves, position j fixed, j > n padded."""
from math import ceil, log2

from . import canon


class MerkleTree:
    def __init__(self, leaf_hashes):
        """leaf_hashes: list of N = 2^k leaf hashes."""
        self.N = len(leaf_hashes)
        assert self.N & (self.N - 1) == 0 and self.N > 0
        self.levels = [list(leaf_hashes)]
        cur = self.levels[0]
        while len(cur) > 1:
            nxt = [canon.H(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
            self.levels.append(nxt)
            cur = nxt

    @property
    def root(self):
        return self.levels[-1][0]

    def path(self, j0):
        """j0: 0-based leaf index → sibling hashes, leaf → root."""
        idx = j0
        out = []
        for lvl in self.levels[:-1]:
            out.append(lvl[idx ^ 1])
            idx //= 2
        return out

    @staticmethod
    def verify_path(leaf: bytes, j0: int, path, n_leaves: int) -> bool:
        """Check the path against the tree size; returns (ok, root)."""
        idx = j0
        cur = leaf
        for sib in path:
            cur = canon.H(cur + sib) if idx % 2 == 0 else canon.H(sib + cur)
            idx //= 2
        return idx == 0, cur


def pad_leaf(j: int) -> bytes:
    return canon.H(b"pad|" + canon.enc32(j))


def make_tree(n: int, real_leaf):
    """real_leaf(j) -> bytes for j = 1..n; positions j > n are padded."""
    N = 1 << ceil(log2(max(n, 1)))
    leaves = [real_leaf(j) if j <= n else pad_leaf(j) for j in range(1, N + 1)]
    return MerkleTree(leaves)
