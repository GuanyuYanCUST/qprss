# -*- coding: utf-8 -*-
"""Stage-5.6 P2-4：三删改者身份独立性测试（Q=B1+C2 主方案 与 H=受控对照 双栈）。

验证目标（补 Stage-5.5 08号 M5 缺口——此前多删改者语义只在 ML-DSA 核上验过）：
1. 三个独立身份（physician J=* / admin J={6..30} / nurse J={10}）6 轮真实链，
   全链 hist 验证 PASS；
2. 每跳 τ_i 只在**该跳删改者本人的 pk** 下验证通过，在其他删改者 pk 下全部失败
   （身份不可替换）；
3. forge_hop 声称他人身份（id=R3 但用 R1 密钥签）→ 诚实 Verify 拒于 V5.4；
4. 越权删除（nurse 删 {11}，超出 J={10}）→ V7.7；
5. 序列化往返 + RA fresh。

Run: py -3.11 tests/test_u3_redactors.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon, fhir_codec
from s6t64.s5_qprss import VerifyReject
from s6t64.s5_sig import core
from s6t64.policy import Policy

R = {"tests": {}}


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": detail}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def expect_reject(name, fn, step):
    try:
        fn()
    except VerifyReject as e:
        ok = e.step == step
        record(name, ok, f"rejected at {e.step} (expect {step})" + ("" if ok else " WRONG STEP"))
        return
    except Exception as e:                                   # noqa: BLE001
        record(name, False, f"wrong exception {type(e).__name__}: {e}")
        return
    record(name, False, "accepted (no rejection)")


def run_stack(scheme: str):
    t0 = time.time()
    n = 12                                          # FHIR schema 全量 12 字段
    rid = bytes([0xC3] * 16)
    V = frozenset(range(2, 13))                  # 1 = 强制保留

    ra = Q.RA(scheme)
    pp = Q.setup(scheme, seed=bytes(range(32))) if scheme == "B1" else Q.setup(scheme)
    sk_s, pk_s = core(scheme).keygen()
    # SF-A1 适配：signer 证书 scope 显式枚举 RID
    cert_s = ra.issue(bytes(16), pk_s, b"signer", ((rid,), b"*"), 0, 2**40)

    sd = canon.schema_digest(fhir_codec.SCHEMA[:n])
    ys = {j: fhir_codec.example_field_bytes(j) for j in range(1, n + 1)}
    adm0 = [(b"physician", b"*"), (b"admin", b"*"), (b"nurse", (b"\x33" * 16,))]
    P0 = Policy(adm0, V, n, n)
    S = Q.signing(pp, sk_s, cert_s, rid, ys, P0, rng=Q.make_rng(b"s56-u3-" + scheme.encode()),
                  schema_digest=sd)
    record(f"[{scheme}] T1 初始签名（n={n}，σ₀={len(S.sigma0)} B）", len(S.sigma0) == 5794)
    sig_init = core(scheme).sign(
        sk_s, pk_s,
        canon.M_reginit(rid, n, S.acc0, P0, canon.H(cert_s.msg), sd=sd), canon.CTX_REG)
    ra.register_initial(S, cert_s, sig_init)

    # 三删改者：R1 physician J=*；R2 admin J={6..9,11,12}；R3 nurse J={10}
    keys, certs = {}, {}
    for tag, role, js in ((1, b"physician", b"*"),
                          (2, b"admin", frozenset({6, 7, 8, 9, 11, 12})),
                          (3, b"nurse", frozenset({10}))):
        sk, pk = core(scheme).keygen()
        keys[tag] = sk
        # nurse 的 id 须匹配 adm0 枚举模式 (b"\x33"*16,)；physician/admin 走 b"*"
        cid_ = b"\x33" * 16 if tag == 3 else bytes([tag]) * 16
        certs[tag] = ra.issue(cid_, pk, role, ((rid,), js), 0, 2**40)

    # 6 轮删改日程（每跳 d−1；W 逐跳收缩；删除索引均在当跳 W ∩ 本人 J 内）
    #   hop 删改者  删除   W 收紧
    plan = [(1, {2}, {3}), (2, {6}, {4}), (3, {10}, {5}), (1, {7}, {8}),
            (2, {11}, {9}), (1, {12}, set())]
    chain = [S]
    Wcur, dcur = set(V), n
    for k, (who, dele, drop) in enumerate(plan, start=1):
        I_new = chain[-1].It - dele
        Wcur = Wcur - drop
        dcur -= 1
        P_new = Policy(adm0, frozenset(Wcur), dcur, n)
        chain.append(Q.redact(pp, chain[-1], I_new, P_new, certs[who], keys[who],
                              2000 + k))
    St = chain[-1]
    record(f"[{scheme}] T2 6 轮三删改者真实链生成", len(St.log) == 6, f"t={time.time()-t0:.1f}s")

    # 全链 hist 验证
    ok = Q.verify({"pk_ra": ra.pk}, Q.Sigma.deserialize(St.serialize()), "hist",
                  expected_sd=sd) == "accept_historical"
    record(f"[{scheme}] T3 全链 hist 验证 PASS（u=3 身份独立）", ok, f"t={time.time()-t0:.1f}s")

    # 逐跳 τ 身份归属：本人 pk 过、他人 pk 全拒
    h = canon.h0_of(rid, n, St.acc0, P0, sd=sd)
    own_ok, cross_fail = True, True
    for i, (e_bytes, tau, cid) in enumerate(St.log, start=1):
        cert = St.certs[cid]
        m = canon.M_red(rid, i, e_bytes, h, canon.hi_of(e_bytes, h))
        own_ok &= core(scheme).verify(cert.pk, m, tau, canon.CTX_RED)
        for other in certs.values():
            if other.pk != cert.pk:
                cross_fail &= not core(scheme).verify(other.pk, m, tau, canon.CTX_RED)
        h = canon.hi_of(e_bytes, h)
    record(f"[{scheme}] T4 τ_i 本人 pk 全过 / 他人 pk 全拒（6 跳×2 交叉）",
           own_ok and cross_fail)

    # 身份冒充：hop 元数据保留 R3 的 id/role/cid（证书链完好），但 τ 换成
    # 攻击者（R1 密钥）对同一 M_red 的签名——不持有 R3 密钥者造不出有效 τ → V5.4
    Sx = Q.forge_hop(chain[-2], chain[-2].It - {12},
                     Policy(adm0, frozenset(Wcur), dcur, n),
                     certs[3], keys[3], 2999)
    e6, _, cid6 = Sx.log[-1]
    m6 = canon.M_red(rid, len(Sx.log), e6, chain[-2].h_t, canon.hi_of(e6, chain[-2].h_t))
    tau_att = core(scheme).sign(keys[1], certs[1].pk, m6, canon.CTX_RED)
    Sx.log[-1] = (e6, tau_att, cid6)
    expect_reject(f"[{scheme}] T5 身份冒充（R3 名义 R1 密钥 τ）→ V5.4",
                  lambda: Q.verify({"pk_ra": ra.pk}, Sx, "hist"), "V5.4")

    # 越权：nurse（J={10}）删 {12}（chain[-2] 当跳 W 含 12；本人密钥诚实签）→ V7.7
    Sy = Q.forge_hop(chain[-2], chain[-2].It - {12},
                     Policy(adm0, frozenset(Wcur), dcur, n),
                     certs[3], keys[3], 3000)
    expect_reject(f"[{scheme}] T6 nurse 越权删 {{12}} → V7.7",
                  lambda: Q.verify({"pk_ra": ra.pk}, Sy, "hist"), "V7.7")

    # 序列化往返 + RA fresh
    bt = St.serialize()
    record(f"[{scheme}] T7 序列化往返逐字节一致（{len(bt)} B）",
           Q.Sigma.deserialize(bt).serialize() == bt)
    m = canon.M_reg(rid, ra.reg[rid]["ver"], ra.reg[rid]["h"],
                    ra.reg[rid]["ver"] + 1, St.h_t, 6,
                    canon.H(certs[1].msg), certs[1].id, certs[1].role)
    sig_reg = core(scheme).sign(keys[1], certs[1].pk, m, canon.CTX_REG)
    ra.register(St, sig_reg, certs[1])
    snap = ra.revocation_snapshot()
    st = Q.verify({"pk_ra": ra.pk}, St, "fresh", ra=ra, nonce=os.urandom(32), expected_sd=sd,
                  revsnap=snap)
    record(f"[{scheme}] T8 RA register + fresh", st == "accept_fresh", f"t={time.time()-t0:.1f}s")
    return {"bytes_sigma_t6": len(bt), "wall_s": round(time.time() - t0, 2)}


def main():
    meta = {}
    for scheme in ("B1", "H"):
        meta[scheme] = run_stack(scheme)
    R["meta"] = meta
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "s56_u3_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    print(f"\nALL {len(R['tests'])} u3 tests passed -> {out}")


if __name__ == "__main__":
    main()
