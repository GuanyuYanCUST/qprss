# -*- coding: utf-8 -*-
"""论文对齐轮测试组 11：一般策略 P=(W,M,b) 与式(2) 编码（Task B 验收矩阵）。

覆盖任务书 §五/§四 Task B 逐项：合法删除/必留删除/未授权删除/策略放宽/
预算增加与不足/身份角色不匹配/合法连续收紧/非规范编码逐项拒绝 +
Verify 第(5)步逐跳负例（含伪造 P_prev 缩 M、混用编码版本）+ 编码唯一性。
全部走真实密码学路径（RA 真签发、B1-65 真签名、verify 真验签）。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))          # run/fixed_run

from s6t64 import canon, policy as pol            # noqa: E402
from s6t64 import s5_qprss as Q                   # noqa: E402
import s6t64.s4compat as s4c                      # noqa: E402

B1 = Q.s5_sig.core("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
ID_R = b"\x01" * 16
N = 8
V2 = pol.POL_VER_GENERAL

R = {"tests": {}}


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  {note}" if note else ""))
    assert ok, name


def expect_reject(fn, name):
    """fn 抛 ValueError 才算过（单元级负例）。"""
    try:
        fn()
        record(name, False, "accepted(!)")
    except ValueError as e:
        record(name, True, f"ValueError: {e}")


def world(ver=V2, M=frozenset({1, 2}), b=None, adm=None, n=N):
    """确定性世界：pp/RA/签名者/编辑者/一般或受限策略（种子固定可复现）。
    n 可脱离模块 N=8（F3 回归：n=102 ⟹ n%8≠0，逐跳位图含填充位路径）。"""
    b = n if b is None else b
    pp = Q.setup("B1", seed=b"pa|pp", pol_ver=ver)
    ra = Q.RA("B1")
    ra.sk, ra.pk = B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-ra"))
    SK, PK = B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-s"))
    cert_s = ra.issue(RID[:12] + b"SGNR", PK, b"signer", ((RID,), b"*"), 0, 1 << 62)
    W = frozenset(range(2, n + 1))
    P0 = pol.Policy(adm or ((b"physician", b"*"),), W, b, n,
                    m=(None if ver == 1 else M), ver=ver)
    ys = {j: f"field-{j}".encode() for j in range(1, n + 1)}
    sd = canon.schema_digest([(j, ("Patient", f"a{j}"), "str")
                              for j in range(1, n + 1)])
    S = Q.signing(pp, SK, cert_s, RID, ys, P0,
                  rng=Q.make_rng(b"pa|commit"), schema_digest=sd,
                  sig_rng=s4c.FixedXofRng(b"pa|sig0"))
    skr, pkr = B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-r"))
    c_r = ra.issue(ID_R, pkr, b"physician", ((RID,), b"*"), 0, 1 << 62)
    c_nurse = ra.issue(b"\x02" * 16,
                       B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-n"))[1],
                       b"nurse", ((RID,), b"*"), 0, 1 << 62)
    return pp, ra, PK, SK, cert_s, c_r, c_nurse, skr, S, P0, sd


def must_redact_refuse(name, frag, pp, S, I_new, Pn, cert, key, ts=100):
    try:
        Q.redact(pp, S, I_new, Pn, cert, key, ts)
        record(name, False, "accepted(!)")
    except Q.RedactRefused as e:
        record(name, frag in str(e), str(e))


def must_verify_reject(name, steps, cfg, S, mode="hist", **kw):
    try:
        Q.verify(cfg, S, mode, **kw)
        record(name, False, "accepted(!)")
    except Q.VerifyReject as e:
        record(name, e.step in steps, f"@{e.step}: {e}")


# ---------- A. 谓词与 D(P)（式(1)/(3) 单元） ----------
W, Mg = frozenset(range(2, N + 1)), frozenset({1, 2})
P = pol.Policy(((b"physician", b"*"),), W, N, N, m=Mg, ver=V2)
U = frozenset(range(1, N + 1))
record("A1 W∩M≠∅ 构造合法（W∩M={2}）", W & Mg == {2})
record("A2 D(P)=W∖M（=U∖M，必留从可删集剔除）", P.D == W - Mg == frozenset(range(3, N + 1)))
record("A3 式(1)：全保留=1", P.holds(U))
record("A4 式(1)：删 D(P) 内字段=1（删5）", P.holds(U - {5}))
record("A5 式(1)：删 M∩W 字段=0（删2，必留胜出）", not P.holds(U - {2}))
record("A6 式(1)：删灰域字段=0（删1，1∉W∪M）", not P.holds(U - {1}))
P2 = pol.Policy(P.adm, W, N - 1, N, m=Mg | {5}, ver=V2)
record("A7 式(3)：D(P2)⊆D(P) 为收紧", P2.D <= P.D and Mg <= P2.M)
record("A8 tighten_ok 合法收紧（W 不动、M 增、b−1）", pol.tighten_ok(P2, P))
record("A9 tighten_ok 拒 W 放宽", not pol.tighten_ok(
    pol.Policy(P.adm, W | {1}, N - 1, N, m=Mg, ver=V2), P))
record("A10 tighten_ok 拒 M 收缩", not pol.tighten_ok(
    pol.Policy(P.adm, W, N - 1, N, m=frozenset({1}), ver=V2), P))
record("A11 tighten_ok 拒预算不减（b'=b）", not pol.tighten_ok(
    pol.Policy(P.adm, W, N, N, m=Mg, ver=V2), P))
record("A12 tighten_ok 拒预算上跳（b'>b）", not pol.tighten_ok(
    pol.Policy(P.adm, W, N + 1, N, m=Mg, ver=V2), P))
expect_reject(lambda: pol.Policy(P.adm, W, N, N, m=Mg | {9}, ver=V2),
              "A13 构造拒 M⊄[n]")
expect_reject(lambda: pol.Policy(P.adm, W, N, N, m=Mg, ver=1),
              "A14 ver=1 拒显式 M≠U∖W（受限子族唯一性）")

# ---------- B. 式(2) 编码与解码严格性 ----------
enc = canon.enc_pol(P)
Pd, off = Q.dec_pol(enc + b"TAIL", 0, N)
record("B1 编解码往返一致 + 定界", off == len(enc)
       and canon.enc_pol(Pd) == enc and Pd.M == Mg and Pd.w == W
       and Pd.d == N and Pd.ver == V2)
P_eq = pol.Policy(((b"physician", b"*"), (b"nurse", b"*")), W, N, N, m=Mg, ver=V2)
P_re = pol.Policy(((b"nurse", b"*"), (b"physician", b"*")), W, N, N, m=Mg, ver=V2)
record("B2 编码唯一性：不同 adm 顺序构造 → 同一字节", canon.enc_pol(P_eq) == canon.enc_pol(P_re))
record("B3 enc_u 最小宽度", canon.enc_u(0) == b"\x00" and canon.enc_u(7) == b"\x01\x07"
       and canon.enc_u(256) == b"\x02\x01\x00")
expect_reject(lambda: canon.dec_u_at(b"\x02\x00\x05", 0),
              "B4 dec_u 拒非最小整数（前导零）")
expect_reject(lambda: canon.dec_u_at(b"\x05" + b"\x00" * 5, 0),
              "B5 dec_u 拒超长（L>4）")
expect_reject(lambda: canon.dec_u_at(b"\x02\x01", 0),
              "B6 dec_u 拒截断")
expect_reject(lambda: canon.bmp_checked(b"\x00" * ((N + 7) // 8 + 1), N),
              "B7 bits_n 拒长度不符")
bad_pad = canon.bmp({1, 2, 3, 4}, 5)[:-1] + bytes(
    [canon.bmp({1, 2, 3, 4}, 5)[-1] | 0x80])      # n=5 第 6..8 位须零，置 1
expect_reject(lambda: canon.bmp_checked(bad_pad, 5),
              "B8 bits_n 拒非零填充位")
# B8 回归（F3 n=102 实测缺陷）：填充位在末字节**高**位；低位是数据位。
# 修复前掩码方向反——合法 W∋{97,98}（n=102, pad=2）被误拒为"非零填充"。
record("B8b bits_n 合法低位数据位不误拒（pad≠0 往返：n=5/10/102）",
       canon.bmp_checked(canon.bmp({1, 2, 3}, 5), 5) == {1, 2, 3}
       and canon.bmp_checked(canon.bmp({1, 10}, 10), 10) == {1, 10}
       and canon.bmp_checked(canon.bmp({97, 98, 102}, 102), 102) == {97, 98, 102})
# n 不匹配（改描述符内 enc_u(n)：n=8→9）
e9 = enc.replace(canon.POLV1 + canon.enc_u(N), canon.POLV1 + canon.enc_u(N + 1))
expect_reject(lambda: Q.dec_pol(e9, 0, N), "B9 dec_pol 拒解码 n ≠ 记录全集")
# b>B_max（尾部 enc_u(b) 改大，临时压低 B_max）
_q = Q.cfg_pp
_saved = _q.get("B_max")
_q["B_max"] = N
b_bad = enc[: -len(canon.enc_u(N))] + canon.enc_u(N + 1)
expect_reject(lambda: Q.dec_pol(b_bad, 0, N), "B10 dec_pol 拒 b > B_max")
_q["B_max"] = _saved
# adm 非规范（重复条目；条目须按键严格递增）
_dup = canon.POL2_PREFIX + bytes([2]) \
    + canon.enc_adm_entry(b"physician", b"*") * 2 \
    + canon.POLV1 + canon.enc_u(N) + canon.bmp(W, N) + canon.bmp(Mg, N) \
    + canon.enc_u(N)
expect_reject(lambda: Q.dec_pol(_dup, 0, N), "B11 dec_pol 拒重复 adm 条目")
expect_reject(lambda: Q.dec_pol(canon.POL2_PREFIX + b"\x51\x50", 0, N),
              "B12 乱码 pol2 流拒（截断/非法角色码）")
# 结构性互斥：受限编码不以前缀开头，dec_pol 分派回受限解析器
Pl, offl = Q.dec_pol(canon.enc_pol(pol.Policy(P.adm, W, N, N)), 0, N)
record("B13 受限编码经 dec_pol 分派回 ver=1（结构互斥）", Pl.ver == 1 and offl > 0)

# ---------- C. 端到端一般策略工件（Redact R0–R6 正负） ----------
pp, ra, PK, SK, cert_s, c_r, c_nurse, skr, S, P0, sd = world()
cfg = {"pk_ra": ra.pk}
Q.verify(cfg, S, "hist")
record("C1 一般策略（W∩M≠∅）t=0 hist accept", True)
W0, M0, b0 = P0.w, P0.M, P0.d
legal_P = lambda w, m, b: pol.Policy(P0.adm, w, b, N, m=m, ver=V2)
keep = lambda *gone: set(range(1, N + 1)) - set(gone)

S1 = Q.redact(pp, S, keep(5), legal_P(W0, M0, b0 - 1), c_r, skr, 100)
Q.verify(cfg, S1, "hist")
record("C2 合法删除（5∈D(P)）+ 收紧 hist accept", True)
must_redact_refuse("C3 R1 拒删 W 外字段（删1，灰域）", "R1",
                   pp, S, keep(1), legal_P(W0, M0, b0 - 1), c_r, skr)
must_redact_refuse("C4 R2 拒删必留字段（2∈M∩W）", "R2",
                   pp, S, keep(2), legal_P(W0, M0, b0 - 1), c_r, skr)
must_redact_refuse("C5 R5 拒预算不减（b'=b）", "R5",
                   pp, S, keep(5), legal_P(W0, M0, b0), c_r, skr)
must_redact_refuse("C6 R5b 拒编码版本混用（ver=1 策略入 ver=2 工件）", "R5b",
                   pp, S, keep(5), pol.Policy(P0.adm, W0, b0 - 1, N), c_r, skr)
must_redact_refuse("C7 tighten 拒 W 放宽（W'⊃W）", "R5",
                   pp, S, keep(5), legal_P(W0 | {1}, M0, b0 - 1), c_r, skr)
must_redact_refuse("C8 tighten 拒 M 收缩（M'⊂M）", "R5",
                   pp, S, keep(5), legal_P(W0, frozenset({1}), b0 - 1), c_r, skr)
must_redact_refuse("C9 R6 拒角色不匹配（nurse）", "R6",
                   pp, S, keep(5), legal_P(W0, M0, b0 - 1), c_nurse,
                   B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-n2"))[0])
sk_x, pk_x = B1.keygen(rng=s4c.FixedXofRng(b"pa|kg-x"))
c_x = ra.issue(b"\x03" * 16, pk_x, b"physician",
               ((b"\xff" * 16,), b"*"), 0, 1 << 62)   # scope 不含本 RID
must_redact_refuse("C10 R6 拒证书 scope 不含本 RID", "R6",
                   pp, S, keep(5), legal_P(W0, M0, b0 - 1), c_x, sk_x)
must_redact_refuse("C11 R0 拒空删除（J=∅）", "R0",
                   pp, S, keep(), legal_P(W0, M0, b0 - 1), c_r, skr)
must_redact_refuse("C12 R0b 拒索引复活（I_new ⊄ I_t，重插已删字段）", "R0b",
                   pp, S1, keep(6), legal_P(W0, M0, b0 - 2), c_r, skr)

# ---------- D. Verify 第(5)步伪造负例（forge_hop + 完整 verify） ----------
must_verify_reject("D1 V7.6 拒伪造跳 M 收缩", {"V7.6"}, cfg,
                   Q.forge_hop(S, keep(5), legal_P(W0, frozenset({1}), b0 - 1),
                               c_r, skr, 200))
must_verify_reject("D2 V7.6 拒伪造跳 W 放宽", {"V7.6"}, cfg,
                   Q.forge_hop(S, keep(5), legal_P(W0 | {1}, M0, b0 - 1),
                               c_r, skr, 200))
must_verify_reject("D3 V7.6 拒伪造跳预算不减", {"V7.6"}, cfg,
                   Q.forge_hop(S, keep(5), legal_P(W0, M0, b0), c_r, skr, 200))
must_verify_reject("D4 V7.3 拒伪造跳删必留 M", {"V7.3"}, cfg,
                   Q.forge_hop(S, keep(2), legal_P(W0, M0, b0 - 1), c_r, skr, 200))
must_verify_reject("D5 V7.2 拒伪造跳删 W 外灰域", {"V7.2"}, cfg,
                   Q.forge_hop(S, keep(1), legal_P(W0, M0, b0 - 1), c_r, skr, 200))
# D6 伪造 P_prev 缩 M：手工重编 e（跳内声明状态 ≠ 链状态）+ 真实重签
F6 = Q.forge_hop(S, keep(2), legal_P(W0, frozenset({1}), b0 - 1), c_r, skr, 200)
_e = Q.dec_e(F6.log[-1][0], N)
_e["P_prev"] = pol.Policy(P0.adm, W0, b0, N, m=frozenset({1}), ver=V2)
_e_bytes = canon.enc_e(_e["seq"], _e["id"], _e["role"], F6.log[-1][2],
                       _e["I_prev"], _e["I_new"], _e["P_prev"], _e["P_new"],
                       _e["ts"], N)
_h = canon.hi_of(_e_bytes, S.h_t)
_tau = B1.sign(skr, c_r.pk, canon.M_red(RID, 1, _e_bytes, S.h_t, _h),
               canon.CTX_RED, rng=s4c.FixedXofRng(b"pa|sig-d6"))
F6b = Q.forge_hop(S, keep(2), legal_P(W0, frozenset({1}), b0 - 1), c_r, skr, 200)
F6b.log = list(F6b.log)
F6b.log[-1] = (_e_bytes, _tau, F6.log[-1][2])
F6b.h_t = _h
must_verify_reject("D6 V6 拒伪造 P_prev 缩 M（全量状态比对）", {"V6"}, cfg, F6b)
# D7 混用编码版本工件（forge ver=1 策略，其余语义全合法：W'={3..8}）
F7 = Q.forge_hop(S, keep(5),
                 pol.Policy(P0.adm, frozenset(range(3, N + 1)), b0 - 1, N),
                 c_r, skr, 300)
must_verify_reject("D7 V6 拒混用编码版本工件（ver=1 P_new）", {"V6"}, cfg, F7)

# ---------- E. 版本共存与不混用 ----------
pp1, ra1, PK1, SK1, cs1, cr1, _, skr1, S1v1, P0v1, sd1 = world(ver=1)
cfg1 = {"pk_ra": ra1.pk}
Q.verify(cfg1, S1v1, "hist")
record("E1 受限（ver=1）工件在新解码器下 hist accept", True)
S2v1 = Q.redact(pp1, S1v1, keep(5),
                pol.Policy(P0v1.adm, P0v1.w, P0v1.d - 1, N), cr1, skr1, 100)
Q.verify(cfg1, S2v1, "hist")
record("E2 受限工件多跳链 hist accept（ver=1 全链）", True)
record("E3 同逻辑策略 ver1/ver2 编码字节可区分",
       canon.enc_pol(pol.Policy(P0.adm, P0.w, P0.d, N))
       != canon.enc_pol(pol.Policy(P0.adm, P0.w, P0.d, N, m=P0.M, ver=V2)))

# ---------- F. 多跳连续收紧 + 登记 + fresh（一般策略全链） ----------
Sc, Pc = S, P0
for k in range(1, 5):                              # 依次删 8,7,6,5（皆 ∈ D(P)）
    gone = {9 - k for k in range(1, k + 1)}
    Pn = pol.Policy(P0.adm, Pc.w, Pc.d - 1, N, m=Pc.M, ver=V2)
    Sc = Q.redact(pp, Sc, set(range(1, 9)) - gone, Pn, c_r, skr, 400 + k)
    Pc = Pn
    Q.verify(cfg, Sc, "hist")
record("F1 一般策略 4 连跳收紧全 hist accept（b 递减、M 稳定）", True)
sig_init = B1.sign(SK, PK,
                   canon.M_reginit(RID, N, S.acc0, S.P0, canon.H(cert_s.msg), sd=sd),
                   canon.CTX_REG, rng=s4c.FixedXofRng(b"pa|sig-reg0"))
ra.register_initial(S, cert_s, sig_init)
m_reg = canon.M_reg(RID, ra.reg[RID]["ver"], ra.reg[RID]["h"],
                    ra.reg[RID]["ver"] + 1, Sc.h_t, len(Sc.log),
                    canon.H(c_r.msg), c_r.id, c_r.role)
ra.register(Sc, B1.sign(skr, c_r.pk, m_reg, canon.CTX_REG,
                        rng=s4c.FixedXofRng(b"pa|sig-reg")), c_r)
v = Q.verify(cfg, Sc, "fresh", ra=ra, nonce=b"\x77" * 32,
             revsnap=ra.revocation_snapshot())
record("F2 一般策略工件 fresh accept（bid/链头全链）", v == "accept_fresh")

# ---------- F3. n=102 全链回归（n%8≠0：位图填充位 + 逐跳 dec_e_at） ----------
# F3 多跳实验实测崩溃路径：n=102（pad=2）首跳 register→verify(hist) 在
# dec_e_at→_dec_pol2→bmp_checked 误拒"W∋{97,98} 非零填充位"（B8b 根因）。
N102 = 102
pp2, ra2, PK2, SK2, cs2, cr2, _, skr2, S102, P0102, sd2 = world(n=N102)
cfg2 = {"pk_ra": ra2.pk}
Q.verify(cfg2, S102, "hist")                       # P0 头部解码（含 pad≠0）
Pn2 = pol.Policy(P0102.adm, P0102.w, N102 - 1, N102, m=P0102.M, ver=V2)
S1h = Q.redact(pp2, S102, set(range(1, N102 + 1)) - {50}, Pn2, cr2, skr2, 500)
Q.verify(cfg2, S1h, "hist")                        # 首跳审计记录解码 = 崩溃点
sig_i2 = B1.sign(SK2, PK2,
                 canon.M_reginit(RID, N102, S102.acc0, S102.P0, canon.H(cs2.msg), sd=sd2),
                 canon.CTX_REG, rng=s4c.FixedXofRng(b"pa|sig-reg0-102"))
ra2.register_initial(S102, cs2, sig_i2)
m2 = canon.M_reg(RID, ra2.reg[RID]["ver"], ra2.reg[RID]["h"],
                 ra2.reg[RID]["ver"] + 1, S1h.h_t, len(S1h.log),
                 canon.H(cr2.msg), cr2.id, cr2.role)
ra2.register(S1h, B1.sign(skr2, cr2.pk, m2, canon.CTX_REG,
                          rng=s4c.FixedXofRng(b"pa|sig-reg-102")), cr2)
v2 = Q.verify(cfg2, S1h, "fresh", ra=ra2, nonce=b"\x88" * 32,
              revsnap=ra2.revocation_snapshot())
record("F3 n=102（n%8≠0）删跳→登记→hist+fresh 全 accept", v2 == "accept_fresh")

R["verdict"] = "ALL_PA_POLICY_PASS" if all(t["pass"] for t in R["tests"].values()) \
    else "PA_POLICY_FAIL"
R["total"] = len(R["tests"])
out = os.path.join(HERE, "..", "data", "pa_policy_results.json")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(f"\nVERDICT: {R['verdict']} ({R['total']} tests) -> {os.path.abspath(out)}")
sys.exit(0 if R["verdict"] == "ALL_PA_POLICY_PASS" else 1)
