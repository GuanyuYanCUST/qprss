# -*- coding: utf-8 -*-
"""基线 L（Stage-5.6 P0-4）：同签名核（B1-65）的朴素顺序多签链。

R3-3 所指 "trivial multi-signature chain of sequential modifications" 的最小组装：
原始签发者对全文文档哈希签名；此后每跳删改者用**自己的 B1-65 密钥**对
(前一全文状态哈希 | 新全文状态哈希 | 元数据) 签名。无承诺、无 Merkle、
无策略状态机、无 RA。

对比属性（04 号设计文档的载体，非功能勾选）：
- 验证保留字段"来源真实性"必须出示**全部中间全文文档**（本实现的结构性
  要求：链上每跳哈希的都是全文状态）——删除内容因此随验证材料永久公开；
- 任何人可转发最终文档+全链材料验证，但无法做到"只揭示保留字段"。

诚实边界：本基线不实现策略/审计功能；E5 计费口径中它是"无策略层"的
下界参照，与 Q/H（同策略同审计层）不是功能等价对比——差异归因声明见
04 号 §3。
"""
from __future__ import annotations

from . import canon, s5_sig

CTX_L_ORIG = b"Lorig"
CTX_L_HOP = b"Lhop"


def h_doc(doc: bytes) -> bytes:
    return canon.H(b"Ldoc|" + doc)


def l_sign_origin(sk_s: bytes, pk_s: bytes, doc0: bytes, rng=None) -> bytes:
    """原始签发者对第 0 版全文的签名。"""
    return s5_sig.core("B1").sign(sk_s, pk_s, b"Lv1|" + h_doc(doc0), CTX_L_ORIG, rng=rng)


def l_hop(prev_h: bytes, doc_new: bytes, meta: bytes, sk_i: bytes, pk_i: bytes,
          rng=None):
    """一跳顺序多签。返回 (新链头哈希, tau)。meta 携带删改者自述（无认证）。"""
    m = b"Lhop|" + prev_h + b"|" + h_doc(doc_new) + b"|" + meta
    tau = s5_sig.core("B1").sign(sk_i, pk_i, m, CTX_L_HOP, rng=rng)
    return canon.H(m), tau


def l_verify(pk_s: bytes, sigma0: bytes, doc0: bytes, hops) -> bool:
    """hops = [(doc_i, meta_i, tau_i, pk_i)]——必须出示全部中间全文文档。"""
    core = s5_sig.core("B1")
    if not core.verify(pk_s, b"Lv1|" + h_doc(doc0), sigma0, CTX_L_ORIG):
        return False
    h = h_doc(doc0)
    for doc, meta, tau, pk in hops:
        m = b"Lhop|" + h + b"|" + h_doc(doc) + b"|" + meta
        if not core.verify(pk, m, tau, CTX_L_HOP):
            return False
        h = canon.H(m)
    return True


def l_keygen(rng=None):
    return s5_sig.core("B1").keygen(rng=rng)
