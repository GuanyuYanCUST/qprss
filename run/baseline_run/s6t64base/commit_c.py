"""基线 C 承诺层：独立随机盐（32 B，与 λ_H 解耦，15号 §5.2）+ 固定 Merkle。
ℓ_j = H("leaf"‖enc32(j)‖salt_j‖y_j)；见证 = (salt_j, 路径)。与 A-S 共用策略/审计/编码。"""
from . import canon

SALT_LEN = 32


def new_salt(rng) -> bytes:
    return bytes(rng(SALT_LEN))


def leaf_of(j: int, salt: bytes, y: bytes) -> bytes:
    return canon.H(b"leaf|" + canon.enc32(j) + salt + y)
