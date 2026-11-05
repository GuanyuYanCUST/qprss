# -*- coding: utf-8 -*-
"""Stage-5 签名核注册表：B1-65 自定义 FS（主方案，导师红线）与 ML-DSA-44（对照）。

统一字节级 API（协议引擎只认这个）：
    keygen() -> (sk_bytes, pk_bytes)
    sign(sk, pk, msg, ctx, rng=None) -> sig_bytes
    verify(pk, msg, sig, ctx) -> bool
    SIG_LEN / PK_LEN

B1 上下文绑定：s4_fs 的 H1 挑战覆盖 (dom, w, msg)；ctx 以显式前缀并入 msg
（"QPRSS-B1ctx|"<ctx>"|"<msg>），与 dom 参数密码学等价（域分隔），且零改动
Stage-4 冻结源码（s4_fs/s4_core 以只读方式从 ../RouteB_Stage4_E0实施/src 引入）。
ML-DSA-44 用 dilithium-py 原生 ctx 参数（FIPS 204 语义）。
"""

# [Stage-5.10.3 τ=64 候选] 本文件 = Stage-5.9 s5_sig.py 副本，两处改动：
# (1) 删除 Stage-4 冻结目录 sys.path 注入与 import s4_fs——B1 参数依赖改为
#     随包 .s4dep_core/.s4dep_fs（相对导入，τ=64）；(2) SIG_LEN["B1"] 由
#     FS 推导 = (k+m)·d·zbits/8 + cbytes = 5760+34 = 5794。B1Core 逻辑、
#     ctx 前缀绑定、ML-DSA-44 对照路径逐字不变。
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
# Stage-5.10.3：不再注入 Stage-4 冻结目录——τ=64 参数依赖随包携带。

# Stage-5.9 P0.4：B1 签名核切换到 s4compat（冻结 s4_core.ShakeRng 的 XOF
# 回放缺陷修复——expand_A/sample_in_ball 的确定性展开走前缀一致 XOF）。
# 算法、参数、域分隔、编码与 s4_fs 逐字一致；仅随机流连续性语义修复。
# 冻结路径生成的密钥/签名在本路径下验证 fail-closed 拒绝（A/c 展开不同）。
from . import s4compat as b1  # noqa: E402

from .s4dep_core import FS as _FS64
_B1_SIG = (_FS64["k"] + _FS64["m"]) * _FS64["d"] * _FS64["zbits"] // 8 \
    + _FS64["cbytes"]          # 5760 + 34 = 5794 (τ=64, β=τη=64)
SIG_LEN = {"B1": _B1_SIG, "AS": 2420, "C": 2420, "H": _B1_SIG}
PK_LEN = {"B1": 3712, "AS": 1312, "C": 1312, "H": 3712}


class B1Core:
    """B1-65 自定义 Fiat–Shamir-with-aborts（主方案签名核；固定 XOF 路径）。"""
    name = "B1"
    SIG_LEN = SIG_LEN["B1"]
    PK_LEN = PK_LEN["B1"]

    @staticmethod
    def keygen(rng=None):
        sk, pk = b1.keygen(rng=rng)
        return b1.sk_to_bytes(sk), b1.pk_to_bytes(pk)

    @staticmethod
    def _msg(msg: bytes, ctx: bytes) -> bytes:
        return b"QPRSS-B1ctx|" + ctx + b"|" + msg

    @staticmethod
    def sign(sk_b: bytes, pk_b: bytes, msg: bytes, ctx: bytes, rng=None) -> bytes:
        sk = b1.sk_from_bytes(sk_b)
        pk = b1.pk_from_bytes(pk_b)
        z1, z2, c = b1.sign(sk, pk, B1Core._msg(msg, ctx), rng=rng)
        assert b1.verify(pk, B1Core._msg(msg, ctx), z1, z2, c), "self-check"
        return b1.sig_to_bytes(z1, z2, c)

    @staticmethod
    def verify(pk_b: bytes, msg: bytes, sig_b: bytes, ctx: bytes) -> bool:
        try:
            pk = b1.pk_from_bytes(pk_b)
            z1, z2, c = b1.sig_from_bytes(sig_b)
            return b1.verify(pk, B1Core._msg(msg, ctx), z1, z2, c)
        except Exception:
            return False


class MLDSACore:
    """ML-DSA-44（FIPS 204 参考实现；对照基线 AS/C 的签名核）。"""
    name = "MLDSA"
    SIG_LEN = SIG_LEN["AS"]
    PK_LEN = PK_LEN["AS"]

    @staticmethod
    def _dsa():
        deps = os.path.abspath(os.path.join(_HERE, "..", "..", "..",
                                            "Step2B_原型", "deps",
                                            "dilithium-py", "src"))
        if deps not in sys.path:
            sys.path.insert(0, deps)
        from dilithium_py.ml_dsa import ML_DSA_44
        return ML_DSA_44

    @staticmethod
    def keygen():
        dsa = MLDSACore._dsa()
        pk, sk = dsa.keygen()
        return sk, pk

    @staticmethod
    def sign(sk, pk, msg, ctx, rng=None):
        return MLDSACore._dsa().sign(sk, msg, ctx=ctx)

    @staticmethod
    def verify(pk, msg, sig, ctx):
        try:
            return MLDSACore._dsa().verify(pk, msg, sig, ctx=ctx)
        except Exception:
            return False


def core(scheme: str):
    """scheme ∈ {"B1", "H", "AS", "C"} → 签名核。B1/H=自定义 FS（H 仅承诺层消融）；AS/C=ML-DSA-44。"""
    if scheme in ("B1", "H"):
        return B1Core
    if scheme in ("AS", "C"):
        return MLDSACore
    raise ValueError(f"unknown scheme {scheme!r}")
