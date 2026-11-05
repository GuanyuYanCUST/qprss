# -*- coding: utf-8 -*-
"""Stage-5.6 P2-3：受控 H 基线（B1-65 签名核 + 加盐哈希承诺 + 同策略/审计层）
端到端测试。

H 与主方案 Q（B1-65 + C2 MLWE 承诺）**唯一差异 = 承诺层**（Stage-5.6 P0-4：
Stage-5 的 "C" 方案同时换了签名核，不能做承诺层消融）。本测试验证 H 栈的
完整协议语义与 Q 一致：V1–V9、序列化 v5、RA 登记/fresh、负面拒绝步。

Run: py -3.11 tests/test_h_e2e.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon, commit_c, fhir_codec
from s6t64.s5_qprss import VerifyReject, RedactRefused, CWitness
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


def main():
    t0 = time.time()
    n = 8
    rid = bytes([0xB7] * 16)
    V = frozenset(range(2, 9))                   # 可删白名单（1 = 强制保留）

    # ---- Setup / RA / 证书（全部 B1-65 核） ----
    ra = Q.RA("H")
    pp = Q.setup("H")
    record("T1 H setup：无代数 pp（盐+哈希承诺层；pol_ver/B_max 为论文 §4.1 公共参数）",
           pp.get("scheme") == "H" and pp.get("G") is None and pp.get("D") is None
           and Q.cfg_pp["G"] is None and Q.cfg_pp["D"] is None)
    sk_s, pk_s = core("H").keygen()
    # SF-A1 适配：signer 证书 scope 显式枚举 RID（通配 signer 证书已被
    # RA.issue/verify V2.1 拒绝——身份替换攻击面封堵）
    cert_s = ra.issue(bytes(16), pk_s, b"signer", ((rid,), b"*"), 0, 2**40)
    record("T1 H 证书签发/验证（B1-65 核，pk=3,712 B）",
           cert_s.verify(ra.pk) and len(cert_s.pk) == 3712 and len(cert_s.sig) == 5794)
    c_b1 = Q.Cert(bytes(16), pk_s, b"signer", (b"*", b"*"), 0, 2**40, scheme="B1")
    record("T1 跨 scheme 证书被拒（B1 证书不通过 H RA）", not c_b1.verify(ra.pk))

    # ---- 初始记录 + σ₀ ----
    sd = canon.schema_digest(fhir_codec.SCHEMA[:n])
    ys = {j: fhir_codec.example_field_bytes(j) for j in range(1, n + 1)}
    P0 = Policy([(b"physician", b"*"), (b"nurse", (b"\x22" * 16,))], V, n, n)
    S0 = Q.signing(pp, sk_s, cert_s, rid, ys, P0, rng=Q.make_rng(b"s56-h"),
                   schema_digest=sd)
    record("T2 H 初始签名（σ₀=5,785 B；见证=盐 32 B/字段）",
           len(S0.sigma0) == 5794 and all(len(S0.fields[j][1].salt) == 32 for j in S0.It))
    leaf_ok = all(commit_c.leaf_of(j, S0.fields[j][1].salt, ys[j]) is not None for j in S0.It)
    record("T2 盐承诺叶可计算（leaf_of = H(leaf|j|salt|y)）", leaf_ok)

    sig_init = core("H").sign(
        sk_s, pk_s,
        canon.M_reginit(rid, n, S0.acc0, P0, canon.H(cert_s.msg), sd=sd), canon.CTX_REG)
    ra.register_initial(S0, cert_s, sig_init)
    record("T3 RegisterInitial（H 栈 RA 初登）", ra.reg[rid]["t"] == 0)

    # ---- 2 删改者 3 跳合法链（与 s5 e2e 同日程——同策略/审计语义） ----
    sk_r1, pk_r1 = core("H").keygen()
    sk_r2, pk_r2 = core("H").keygen()
    id1, id2 = b"\x11" * 16, b"\x22" * 16
    c1 = ra.issue(id1, pk_r1, b"physician", ((rid,), b"*"), 0, 2**40)
    c2 = ra.issue(id2, pk_r2, b"nurse", ((rid,), frozenset({5})), 0, 2**40)

    S1 = Q.redact(pp, S0, set(range(1, n + 1)) - {2},
                  Policy(P0.adm, V - {3}, n - 1, n), c1, sk_r1, 1001)
    S2 = Q.redact(pp, S1, S1.It - {5}, Policy(P0.adm, V - {3}, n - 2, n), c2, sk_r2, 1002)
    S3 = Q.redact(pp, S2, S2.It - {7},
                  Policy([(b"physician", b"*")], V - {3, 6}, n - 3, n), c1, sk_r1, 1003)
    tp = [Q.verify({"pk_ra": ra.pk}, Q.Sigma.deserialize(Sx.serialize()), "hist",
                   expected_sd=sd) for Sx in (S0, S1, S2, S3)]
    record("T4 H 栈第三方 hist 全链 PASS（3 跳 2 删改者）",
           all(x == "accept_historical" for x in tp), f"t={time.time()-t0:.1f}s")

    # ---- 序列化往返 + 分节对账 ----
    b3 = S3.serialize()
    S3b = Q.Sigma.deserialize(b3)
    _, secs = Q.parse_sigma(b3)
    record("T5 序列化往返逐字节一致 + sum(sections)==len",
           S3b.serialize() == b3 and sum(e - s for _, s, e in secs) == len(b3)
           and all(isinstance(S3b.fields[j][1], CWitness) for j in S3b.It),
           f"{len(b3)} B, {len(secs)} sections")

    # ---- RA 登记 + fresh ----
    m = canon.M_reg(rid, 0, ra.reg[rid]["h"], 1, S3.h_t, 3,
                    canon.H(c1.msg), c1.id, c1.role)
    sig_reg = core("H").sign(sk_r1, pk_r1, m, canon.CTX_REG)
    ra.register(S3, sig_reg, c1)
    nonce = os.urandom(32)                    # SF-B：fresh nonce 恰 32B
    snap = ra.revocation_snapshot()
    st = Q.verify({"pk_ra": ra.pk}, S3, "fresh", ra=ra, nonce=nonce, expected_sd=sd,
                  revsnap=snap)
    record("T6 RA register + fresh 验证（H 栈）", st == "accept_fresh")
    expect_reject("T6 陈旧状态 fresh → V9",
                  lambda: Q.verify({"pk_ra": ra.pk}, S1, "fresh", ra=ra,
                                   nonce=os.urandom(32), expected_sd=sd,
                                   revsnap=snap), "V9")

    # ---- 负面：承诺层（哈希）攻击全部被 V4 拒 ----
    Sx = Q.Sigma.deserialize(S3.serialize())
    y5, w5 = Sx.fields[4]
    Sx.fields[4] = (y5 + b"X", w5)                     # 改字段值不动盐
    expect_reject("T7 篡改保留字段值 → V4", lambda: Q.verify({"pk_ra": ra.pk}, Sx, "hist"), "V4")
    Sy = Q.Sigma.deserialize(S3.serialize())
    (ya, wa), (yb, wb) = Sy.fields[4], Sy.fields[6]
    Sy.fields[4] = (ya, wb)                              # 盐互换
    Sy.fields[6] = (yb, wa)
    expect_reject("T7 跨字段盐互换 → V4", lambda: Q.verify({"pk_ra": ra.pk}, Sy, "hist"), "V4")

    # ---- 负面：越权（forge_hop 跳过本地预检；4∈W 但 4∉J={5}） ----
    Sz = Q.forge_hop(S2, S2.It - {4}, Policy(P0.adm, V - {3}, n - 3, n), c2, sk_r2, 1004)
    expect_reject("T8 nurse 越权删非 scope 字段 → V7.7",
                  lambda: Q.verify({"pk_ra": ra.pk}, Sz, "hist"), "V7.7")

    # ---- 负面：σ₀ 篡改 → V2.2 ----
    Sw = Q.Sigma.deserialize(S3.serialize())
    Sw.sigma0 = bytes([Sw.sigma0[0] ^ 1]) + Sw.sigma0[1:]
    expect_reject("T9 σ₀ 篡改 → V2.2", lambda: Q.verify({"pk_ra": ra.pk}, Sw, "hist"), "V2.2")

    R["meta"] = {"scheme": "H", "n": n, "hops": 3, "bytes_sigma3": len(b3),
                 "wall_s": round(time.time() - t0, 2)}
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "s56_h_e2e_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    print(f"\nALL {len(R['tests'])} H-E2E tests passed in {time.time()-t0:.1f}s -> {out}")


if __name__ == "__main__":
    main()
