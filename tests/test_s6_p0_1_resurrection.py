# -*- coding: utf-8 -*-
"""P0.1 复活字段攻击——对冻结实现的最小可复现攻击 + 修复副本对照。

攻击场景（Stage-5.9 任务书逐句落地）：
 1. 医生签署 8 字段记录（1=强制保留；W₀={2..8}；d₀=8）；
 2. 授权删改者 R1（physician）合法删除字段 2（hop1，诚实 Redact）；
 3. 攻击者=曾持有 S₀ 的前删改者（Model A 可见性类 (iii)），事先保存了字段 2
    的合法开启 (y₂, witness₂)——承诺见证对 acc0（初态 Merkle 根）静态验证，
    字段被删后该开启依然逐字节有效；
 4. R1（仍被当前策略授权）用真实密钥签署 hop2：声明删除 {3} 的同一跳内
    重新插入索引 2（removed={3}≠∅；V7.2–V7.7 全部谓词按真值满足——本攻击
    不需要绕过任何其他验证条件，见 §逐谓词核验）；
 5. 运行冻结 Verify(mode=hist) 记录真实返回值；再走 RA.register →
    fresh_query → Verify(mode=fresh) 记录真实返回值（复活态是否成为
    RA 锚定的"当前"链头）；
 6. 逐谓词打印 hop2 的 V7.1–V7.7 真值与 V3/V4 旧开启真值：证明除
    I_new⊆I_prev 逐跳索引包含检查外没有任何检查被绕过——冻结代码缺失的
    正是该检查（论文 V7.1 本有，Stage-5.7 压缩丢失，Stage-5.8 已在论文层
    恢复；本脚本证明冻结源码行为侧确实存在该缺口）。

用法（Windows py3.11）：
    py -3.11 tests/test_p0_1_resurrection_repro.py frozen    # 冻结副本（预期：攻击成功=三处接受）
    py -3.11 tests/test_p0_1_resurrection_repro.py patched   # 修复副本（预期：hop2 V7.1 拒绝）

输出：logs/t64_p01_resurrection_<mode>.json（τ=64 候选；frozen 模式仍指 20261013 冻结副本）。
"""
import hashlib
import json
import os
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else "patched"  # 开源发布版默认 patched（frozen 需内部 20261013 冻结树，不在本仓库）
assert MODE in ("frozen", "patched"), MODE
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FROZEN_SRC = os.path.abspath(os.path.join(
    ROOT, "..", "RouteB_Stage5_冻结副本_20261013", "src"))
PATCHED_SRC = ROOT

sys.path.insert(0, FROZEN_SRC if MODE == "frozen" else PATCHED_SRC)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import importlib

PKG = "s5" if MODE == "frozen" else "s6t64"
PKG_NAME = PKG + ("(冻结副本_20261013)" if MODE == "frozen" else "(Stage5103_Tau64)")

Q = importlib.import_module(PKG + ".s5_qprss")
canon = importlib.import_module(PKG + ".canon")
_policy = importlib.import_module(PKG + ".policy")
_sig = importlib.import_module(PKG + ".s5_sig")
Policy, tighten_ok, inv_w, AuthMember = (_policy.Policy, _policy.tighten_ok,
                                         _policy.inv_w, _policy.AuthMember)
VerifyReject, RedactRefused, core = Q.VerifyReject, Q.RedactRefused, _sig.core

R = {"mode": MODE, "package": PKG_NAME, "steps": {}, "predicates": {}, "verdict": None}

rng = Q.make_rng(b"p01|commit-band")

# ---- 0. 参数与主体 ----
pp = Q.setup("B1", seed=b"p01|pp-seed")
RA = Q.RA("B1")

coreB1 = core("B1")
sk_s, pk_s = coreB1.keygen()            # 签名密钥=SysRng（冻结测试同口径）
sk_r1, pk_r1 = coreB1.keygen()
sk_r2, pk_r2 = coreB1.keygen()
RID = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")

# SF-A1 适配：signer 证书 scope 显式枚举 RID
cert_s = RA.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID,), b"*"), 0, 1 << 62)
cert_r1 = RA.issue(RID[:12] + b"PHS1", pk_r1, b"physician",
                   (b"*", b"*"), 0, 1 << 62)
cert_r2 = RA.issue(RID[:12] + b"PHS2", pk_r2, b"physician",
                   ((RID,), {2, 3, 4, 5, 6, 7, 8}), 0, 1 << 62)

P0 = Policy([(b"physician", b"*")], set(range(2, 9)), 8, 8)     # W₀={2..8}, d₀=8
ys = {j: f"field-{j}-confidential".encode() for j in range(1, 9)}
sd = canon.schema_digest([(j, ("Patient", f"attr{j}"), "str") for j in range(1, 9)])

# ---- 1. 医生签署 8 字段初始记录 ----
S0 = Q.signing(pp, sk_s, cert_s, RID, ys, P0, rng=rng, schema_digest=sd,
               )
R["steps"]["1_sign"] = {"n": S0.n, "It": sorted(S0.It), "acc0": S0.acc0.hex()[:16],
                        "sigma0_len": len(S0.sigma0)}

# ---- 2. R1 合法删除字段 2（诚实 Redact） ----
P1 = P0.copy(w=set(range(2, 9)), d=7)                            # W₁={2..8}, d₁=7
S1 = Q.redact(pp, S0, {1, 3, 4, 5, 6, 7, 8}, P1, cert_r1, sk_r1, ts=1000,
              )
R["steps"]["2_redact_j2"] = {"It": sorted(S1.It), "d": S1.Pt.d,
                             "field2_in_fields": 2 in S1.fields}

# ---- 3. 攻击者保存字段 2 的合法开启（删除前从 S₀ 获得） ----
saved_y2, saved_w2 = S0.fields[2]
saved_opening = (saved_y2, saved_w2.packed, tuple(saved_w2.path))
R["steps"]["3_save_opening"] = {
    "y": saved_y2.decode(), "witness_packed_len": len(saved_w2.packed),
    "merkle_depth": len(saved_w2.path),
    "note": "静态见证：对 acc0 验证（V3/V4），与当前链态无关，删除后依然有效"}

# ---- 4. 授权删改者（R2，scope 含 2/3）签署复活 hop2：删 {3} 同时重插 {2} ----
I_attack = {1, 2, 4, 5, 6, 7, 8}                                 # 2 复活，3 被删
P2 = P1.copy(w=set(range(2, 9)), d=6)


def resurrect(S_prev, I_new, P_new, redactor, sk, saved_field, ts):
    """攻击者构造：绕过诚实 Redact 的本地预检（攻击者手里预检无强制力），
    把保存的旧开启塞回 fields。其余字节构造与 redact 同构。"""
    n = S_prev.n
    i = len(S_prev.log) + 1
    cid = canon.cert_digest(redactor)   # H_cert 语义升级
    e_bytes = canon.enc_e(i, redactor.id, redactor.role, cid, S_prev.It,
                          set(I_new), S_prev.Pt, P_new, ts, n)
    h_new = canon.hi_of(e_bytes, S_prev.h_t)
    tau = core(S_prev.scheme).sign(
        sk, redactor.pk, canon.M_red(S_prev.rid, i, e_bytes, S_prev.h_t, h_new),
        canon.CTX_RED, )
    S2 = Q.Sigma(S_prev.scheme, S_prev.rid, n)
    S2.sd, S2.acc0, S2.P0, S2.sigma0, S2.cert_s = (S_prev.sd, S_prev.acc0,
                                                    S_prev.P0, S_prev.sigma0, S_prev.cert_s)
    S2.It = set(I_new)
    S2.fields = {j: S_prev.fields[j] for j in S2.It if j in S_prev.fields}
    y2, w2 = saved_field
    S2.fields[2] = (y2, Q.ASWitness(w2.packed, list(w2.path)))    # 旧开启回填
    S2.Pt = P_new
    S2.log = S_prev.log + [(e_bytes, tau, cid)]
    S2.certs = dict(S_prev.certs)
    S2.certs.setdefault(cid, redactor)
    S2.h_t = h_new
    return S2


S2 = resurrect(S1, I_attack, P2, cert_r2, sk_r2, (saved_y2, saved_w2), ts=2000)

# hop2 逐谓词真值（V7.1–V7.7 + V3/V4 + V6）——证明没有任何其他检查被绕过
hop2 = Q.dec_e(S2.log[-1][0], S2.n)
removed2 = hop2["I_prev"] - hop2["I_new"]
R["predicates"]["hop2"] = {
    "V6_seq": hop2["seq"] == 2,
    "V6_I_prev_eq_state": hop2["I_prev"] == S1.It,
    "V7.1_removed_nonempty": bool(removed2),
    "V7.1_MISSING_I_new_subset_I_prev": not (hop2["I_new"] <= hop2["I_prev"]),
    "V7.2_removed_in_W": removed2 <= hop2["P_prev"].w,
    "V7.3_K_kept": hop2["P_prev"].K <= hop2["I_new"],
    "V7.4_inv_w": inv_w(hop2["I_new"], hop2["P_new"]),
    "V7.5_holds": hop2["P_new"].holds(hop2["I_new"]),
    "V7.6_tighten": tighten_ok(hop2["P_new"], hop2["P_prev"]),
    "V7.7_auth": bool(AuthMember(hop2["role"], hop2["id"], hop2["P_prev"].adm)),
    "V5.4_tau_by_real_authorized_key": True,      # resurrect() 用 sk_r2 真实签署
    "V3/V4_saved_opening_static_valid": True,     # 对 acc0 验证，删除不改变 acc0
    "V8_It_eq_final": S2.It == hop2["I_new"],
    "removed": sorted(removed2), "I_new": sorted(hop2["I_new"]),
}

# ---- 5a. 冻结/修复 Verify(mode=hist) 真实返回值 ----
try:
    res_hist = Q.verify({"pk_ra": RA.pk}, S2, "hist")
    R["steps"]["5a_verify_hist"] = {"returned": res_hist}
except VerifyReject as e:
    R["steps"]["5a_verify_hist"] = {"rejected_at": e.step, "why": str(e).split(": ", 1)[-1]}

# ---- 5b. RA 链路：register_initial(S0) → register(S1) → register(S2) → fresh ----
sig_init = coreB1.sign(sk_s, cert_s.pk,
                       canon.M_reginit(RID, S0.n, S0.acc0, S0.P0,
                                       canon.H(cert_s.msg), sd=sd), canon.CTX_REG,
                       )
try:
    RA.register_initial(S0, cert_s, sig_init)
    R["steps"]["5b_ra_register_initial_S0"] = "ok"
except (RedactRefused, Exception) as e:                           # noqa: BLE001
    R["steps"]["5b_ra_register_initial_S0"] = f"{type(e).__name__}: {e}"


def reg_sig(ra, S, sk, cert):
    st = ra.reg[RID]
    m = canon.M_reg(RID, st["ver"], st["h"], st["ver"] + 1, S.h_t, len(S.log),
                    canon.H(cert.msg), cert.id, cert.role)
    return coreB1.sign(sk, cert.pk, m, canon.CTX_REG, )


for tag, S, cert, sk in (("S1", S1, cert_r1, sk_r1), ("S2", S2, cert_r2, sk_r2)):
    try:
        ver = RA.register(S, reg_sig(RA, S, sk, cert), cert)
        R["steps"][f"5b_ra_register_{tag}"] = f"ok ver={ver}"
    except (RedactRefused, Exception) as e:                       # noqa: BLE001
        R["steps"][f"5b_ra_register_{tag}"] = f"{type(e).__name__}: {e}"

if "ok" in str(R["steps"].get("5b_ra_register_S2", "")):
    nonce = b"p01-nonce" + bytes(23)         # SF-B：恰 32B
    fq = RA.fresh_query(nonce, RID)          # 冻结=4 元组；s59=5；SF=6（含 bid）
    resp, a_h, a_t, a_ts = fq[0], fq[1], fq[2], fq[3]
    kw = {"ra": RA, "nonce": nonce}
    if MODE == "patched":
        kw["revsnap"] = RA.revocation_snapshot()   # P0.2-r2 默认要求
    try:
        res_fresh = Q.verify({"pk_ra": RA.pk}, S2, "fresh", **kw)
        R["steps"]["5b_verify_fresh_S2"] = {"returned": res_fresh}
    except VerifyReject as e:
        R["steps"]["5b_verify_fresh_S2"] = {"rejected_at": e.step}
else:
    R["steps"]["5b_verify_fresh_S2"] = "skipped (S2 not registered)"

# ---- 6. 判定 ----
hist = R["steps"]["5a_verify_hist"]
frozen_accepted = hist.get("returned") == "accept_historical"
frozen_rejected_v71 = hist.get("rejected_at") == "V7.1"
if MODE == "frozen":
    attack_success = frozen_accepted
    R["verdict"] = ("REPRODUCED: 冻结 Verify 接受复活态(hist)=" + str(frozen_accepted)
                    + "；RA.register(S2)=" + R["steps"]["5b_ra_register_S2"]
                    + "；fresh=" + str(R["steps"]["5b_verify_fresh_S2"]))
    print("\n=== P0.1 frozen verdict ===")
    print("attack reproduced (hist accept):", frozen_accepted)
    assert attack_success, "冻结副本未复现攻击——需复查攻击构造"
else:
    R["verdict"] = ("PATCHED: hop2 被修复副本在 V7.1 拒绝=" + str(frozen_rejected_v71)
                    + "；hist 结果=" + str(hist))
    print("\n=== P0.1 patched verdict ===")
    print("attack rejected at V7.1:", frozen_rejected_v71)
    assert frozen_rejected_v71, "修复副本未在 V7.1 拒绝复活 hop"

# 合法回归对照：无复活的普通第二跳在两个副本都必须照常接受
P2_ok = P1.copy(w=set(range(2, 9)), d=6)
S2_ok = Q.redact(pp, S1, {1, 4, 5, 6, 7, 8}, P2_ok, cert_r2, sk_r2, ts=3000,
                 )
res_ok = Q.verify({"pk_ra": RA.pk}, S2_ok, "hist")
R["steps"]["6_legal_second_hop_control"] = {"returned": res_ok}
assert res_ok == "accept_historical", "合法第二跳被误拒（回归破坏）"
print("legal second hop still accepted:", res_ok)

R["sizes"] = {"S0_bytes": len(S0.serialize()), "S1_bytes": len(S1.serialize()),
              "S2_bytes": len(S2.serialize()), "S2_ok_bytes": len(S2_ok.serialize())}

os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
out = os.path.join(ROOT, "logs", f"p01_resurrection_{MODE}.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1, default=str)
print("log ->", out)
