"""Baseline C commitment layer: independent random salt (32 B, decoupled from
λ_H) + fixed Merkle. ℓ_j = H("leaf"‖enc32(j)‖salt_j‖y_j); witness =
(salt_j, path). Shares policy/audit/encoding with the A-S layer."""
from . import canon

SALT_LEN = 32


def new_salt(rng) -> bytes:
    return bytes(rng(SALT_LEN))


def leaf_of(j: int, salt: bytes, y: bytes) -> bytes:
    return canon.H(b"leaf|" + canon.enc32(j) + salt + y)
