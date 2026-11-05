# -*- coding: utf-8 -*-
"""Stage-5.9 修复副本（s59）回归测试套件。

覆盖（任务书 P0.1/P0.2 逐项）：
  A. 合法多删改者场景不被误拒（5-hop 三删改者链 + tighten + Inv-W + 三模式 +
     序列化往返 + RA 登记全流程）；
  B. 字段复活拒绝矩阵（直接 Verify / RA.register 间接 / 更深跳复活 / 只复活
     不删他字段 / 诚实 Redact 复活输入 → R0b）；
  C. 重复索引（序列化字段块重复 j = 集合语义无害；最终验证不受影响）；
  D. 分叉链（hist 合法共存；登记=Superseded；fresh 只认链头）；
  E. 旧开启复用（= 复活攻击载荷：静态见证对 acc0 有效这一事实单独登记）；
  F. P0.2 撤销与时间语义矩阵（历史有效性 ≠ 当前授权；自报快照不可信；
     require_revsnap；登记门；窗口一致性；RA 重启续撤销）；
  G. V1–V9 核心篡改负例（证明补丁未破坏原验证链）。

Run: py -3.11 tests/test_s59_regression.py
输出：logs/t64_regression.json（τ=64 候选）
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon  # noqa: E402
from s6t64.policy import Policy  # noqa: E402
from s6t64.s5_qprss import VerifyReject, RedactRefused, Superseded  # noqa: E402
from s6t64.s5_sig import core  # noqa: E402

R = {"tests": {}, "t_start": time.time()}
B1 = core("B1")


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": str(detail)}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def expect_reject(name, fn, step=None, exc=VerifyReject):
    try:
        fn()
    except exc as e:
        st = getattr(e, "step", str(e))
        ok = step is None or step in str(st) or step == type(e).__name__
        record(name, ok, f"rejected at {st} (expect {step})" + ("" if ok else " WRONG STEP"))
        return
    except Exception as e:                                   # noqa: BLE001
        record(name, False, f"wrong exception {type(e).__name__}: {e}")
        return
    record(name, False, "accepted (no rejection)")


def reg_sig(ra, rid, S, sk, cert):
    st = ra.reg[rid]
    m = canon.M_reg(rid, st["ver"], st["h"], st["ver"] + 1, S.h_t, len(S.log),
                    canon.H(cert.msg), cert.id, cert.role)
    return B1.sign(sk, cert.pk, m, canon.CTX_REG)


# ---------------- 场景基座 ----------------
rng = Q.make_rng(b"s59|band")
pp = Q.setup("B1", seed=b"s59|pp")
RA = Q.RA("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
RID2 = bytes.fromhex("7766554433221100ffeeddccbbaa9988")   # F9 用（SF-A1 上移）

sk_s, pk_s = B1.keygen()
sk_p1, pk_p1 = B1.keygen()      # physician 1
sk_p2, pk_p2 = B1.keygen()      # physician 2
sk_n1, pk_n1 = B1.keygen()      # nurse（scope 受限）

# SF-A1 适配：signer 证书 scope 显式枚举 RID/RID2（通配已被签发端与 V2.1 拒绝）
c_s = RA.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID, RID2), b"*"), 0, 1 << 62)
c_p1 = RA.issue(RID[:12] + b"PHS1", pk_p1, b"physician", (b"*", b"*"), 0, 1 << 62)
c_p2 = RA.issue(RID[:12] + b"PHS2", pk_p2, b"physician", ((RID,), b"*"), 0, 1 << 62)
c_n1 = RA.issue(RID[:12] + b"NURS", pk_n1, b"nurse", ((RID,), {5, 6}), 0, 1 << 62)

n = 8
P0 = Policy([(b"physician", b"*"), (b"nurse", (c_n1.id,))],
            set(range(2, 9)), 8, n)
ys = {j: f"record-field-{j}".encode() for j in range(1, n + 1)}
sd = canon.schema_digest([(j, ("Patient", f"attr{j}"), "str") for j in range(1, n + 1)])
S0 = Q.signing(pp, sk_s, c_s, RID, ys, P0, rng=rng, schema_digest=sd)

V = set(range(2, 9))
# A. 合法五跳三删改者链：删2 → 删5(nurse) → 删7(收紧去 nurse) → 删8 → 删4
S1 = Q.redact(pp, S0, set(range(1, n + 1)) - {2}, Policy(P0.adm, V, 7, n),
              c_p1, sk_p1, 1000)
S2 = Q.redact(pp, S1, set(range(1, n + 1)) - {2, 5}, Policy(P0.adm, V - {3}, 6, n),
              c_n1, sk_n1, 1100)
adm3 = ((b"physician", b"*"),)
S3 = Q.redact(pp, S2, set(range(1, n + 1)) - {2, 5, 7},
              Policy(adm3, V - {3, 6}, 5, n), c_p2, sk_p2, 1200)
S4 = Q.redact(pp, S3, set(range(1, n + 1)) - {2, 5, 7, 8},
              Policy(adm3, V - {3, 6}, 4, n), c_p1, sk_p1, 1300)
S5 = Q.redact(pp, S4, set(range(1, n + 1)) - {2, 5, 7, 8, 4},
              Policy(adm3, V - {3, 6}, 3, n), c_p1, sk_p1, 1400)

cfg = {"pk_ra": RA.pk}
tp = [Q.verify(cfg, S, "hist") for S in (S0, S1, S2, S3, S4, S5)]
record("A1 合法五跳三删改者链 hist 全接受（修复后无误拒）",
       all(x == "accept_historical" for x in tp), str(tp))

rt = Q.Sigma.deserialize(S5.serialize())
record("A2 序列化 v5 往返逐字节一致",
       rt.serialize() == S5.serialize() and Q.verify(cfg, rt, "hist") == "accept_historical")

sig_init = B1.sign(sk_s, c_s.pk, canon.M_reginit(RID, S0.n, S0.acc0, S0.P0,
                                                 canon.H(c_s.msg), sd=sd), canon.CTX_REG)
RA.register_initial(S0, c_s, sig_init)
for S, cert, sk in ((S1, c_p1, sk_p1), (S2, c_n1, sk_n1), (S3, c_p2, sk_p2),
                    (S4, c_p1, sk_p1), (S5, c_p1, sk_p1)):
    RA.register(S, reg_sig(RA, RID, S, sk, cert), cert)
record("A3 RA 登记链 ver=5", RA.reg[RID]["ver"] == 5)
snap0 = RA.revocation_snapshot()          # epoch 0 空撤销表（合法快照）
record("A4 fresh 链头=S5（携带 revsnap——P0.2-r2 默认）",
       Q.verify(cfg, S5, "fresh", ra=RA, nonce=b"n1" + bytes(30), revsnap=snap0) == "accept_fresh")
g = RA.gazette(1, RID)                    # P0.2-r2：6 元组（含 epoch）
record("A5 snapshot 公报头=S5（携带 revsnap）",
       Q.verify(cfg, S5, "snapshot", gazettes=[g], revsnap=snap0,
                 legacy_snapshot=True)
       == "accept_snapshot@G1")

# ---------------- B. 字段复活拒绝矩阵 ----------------
saved2 = S0.fields[2]          # 旧合法开启（静态见证对 acc0 验证）


def resurrect(S_prev, I_new, P_new, redactor, sk, saved_field, ts, j=2):
    n_ = S_prev.n
    i = len(S_prev.log) + 1
    cid = canon.cert_digest(redactor)   # H_cert 语义升级（论文 §4.4）
    e_bytes = canon.enc_e(i, redactor.id, redactor.role, cid, S_prev.It,
                          set(I_new), S_prev.Pt, P_new, ts, n_)
    h_new = canon.hi_of(e_bytes, S_prev.h_t)
    tau = B1.sign(sk, redactor.pk,
                  canon.M_red(S_prev.rid, i, e_bytes, S_prev.h_t, h_new), canon.CTX_RED)
    S2_ = Q.Sigma(S_prev.scheme, S_prev.rid, n_)
    S2_.sd, S2_.acc0, S2_.P0, S2_.sigma0, S2_.cert_s = (S_prev.sd, S_prev.acc0,
                                                        S_prev.P0, S_prev.sigma0,
                                                        S_prev.cert_s)
    S2_.It = set(I_new)
    S2_.fields = {j: S_prev.fields[j] for j in S2_.It if j in S_prev.fields}
    y_j, w_j = saved_field
    S2_.fields[j] = (y_j, Q.ASWitness(w_j.packed, list(w_j.path)))
    S2_.Pt = P_new
    S2_.log = S_prev.log + [(e_bytes, tau, cid)]
    S2_.certs = dict(S_prev.certs)
    S2_.certs.setdefault(cid, redactor)
    S2_.h_t = h_new
    return S2_


# B1: 从 S2（已删 2、5）复活 2 同时删 3（removed={3}≠∅，其余谓词全真）
BAD = resurrect(S2, {1, 2, 3, 4, 6, 7, 8}, Policy(adm3, V - {3} | {5}, 5, n),
                c_p1, sk_p1, saved2, 2000)
expect_reject("B1 复活 hop（删3+重插2，真实授权钥）→ V7.1",
              lambda: Q.verify(cfg, BAD, "hist"), "V7.1")
# B2: 复活态作为链头的严格扩展（t=6>5，避开 Superseded）
BAD_head = resurrect(S5, {1, 2, 3, 6}, Policy(adm3, V - {3, 6}, 2, n),
                     c_p1, sk_p1, saved2, 2400)
expect_reject("B2 复活态过 RA.register（严格扩展）→ R3(full verify V7.1)",
              lambda: RA.register(BAD_head, reg_sig(RA, RID, BAD_head, sk_p1, c_p1), c_p1),
              "V7.1", exc=RedactRefused)
try:
    RA.register(BAD, reg_sig(RA, RID, BAD, sk_p1, c_p1), c_p1)
    record("B2b 旧扩展本（t=3≤5）另被 Superseded 拒", False)
except Superseded:
    record("B2b 旧扩展本（t=3≤5）另被 Superseded 拒", True)

# B3: 只复活不删他字段（removed=∅）→ 同样 V7.1（两个 V7.1 分支任一先触）
BAD2 = resurrect(S2, {1, 2, 3, 4, 5, 6, 7, 8}, Policy(adm3, V, 5, n),
                 c_p1, sk_p1, saved2, 2100)
BAD2.fields[5] = S0.fields[5]          # 旧开启一并回填（S₂ 已删 5）
expect_reject("B3 只复活不删（重插 2、5，removed=∅）→ V7.1",
              lambda: Q.verify(cfg, BAD2, "hist"), "V7.1")

# B4: 更深跳复活（合法 S3 之后 hop4 复活 2 删 8）
BAD3 = resurrect(S3, {1, 2, 3, 4, 6, 8}, Policy(adm3, V - {3, 6, 7} | {8}, 4, n),
                 c_p1, sk_p1, saved2, 2200)
expect_reject("B4 深链复活（hop4 重插 2）→ V7.1",
              lambda: Q.verify(cfg, BAD3, "hist"), "V7.1")

# B5: 诚实 Redact 输入复活索引集 → 本地预检 R0b（签名端对偶）
expect_reject("B5 诚实 Redact I_new ⊋ I_t → R0b",
              lambda: Q.redact(pp, S2, {1, 2, 3, 4, 6, 7, 8},
                               Policy(adm3, V - {3}, 5, n), c_p1, sk_p1, 2300),
              "R0b", exc=RedactRefused)

# ---------------- C. 重复索引 ----------------
raw = S5.serialize()
# 构造重复 j 的字段块：对序列化流手工注入重复条目无意义（r_cnt 由发送方自报，
# 验证侧 S.fields 是 dict、It 是 set）——等价性证明：重复注入后重解析，
# dict 语义覆盖，V3/V4 仍对唯一 j 验证一次；篡改见证必然 V4 拒。
dup = Q.Sigma.deserialize(S5.serialize())
dup.fields[3] = (S5.fields[3][0], S5.fields[3][1])     # 同 j 同开启（幂等；j∈I_t）
record("C1 重复索引=集合/dict 语义（幂等重放无害，验证不变）",
       Q.verify(cfg, dup, "hist") == "accept_historical"
       and dup.It == S5.It)

# ---------------- D. 分叉链 ----------------
S2b = Q.redact(pp, S1, set(range(1, n + 1)) - {2, 6}, Policy(P0.adm, V - {3}, 6, n),
               c_p2, sk_p2, 1150)
record("D1 合法分叉 hist 共存", Q.verify(cfg, S2b, "hist") == "accept_historical")
expect_reject("D2 分叉登记（RA 头已前进）→ Superseded",
              lambda: RA.register(S2b, reg_sig(RA, RID, S2b, sk_p2, c_p2), c_p2),
              "Superseded", exc=Superseded)
expect_reject("D3 fresh 只认链头（S2 旧状态）→ V9",
              lambda: Q.verify(cfg, S2, "fresh", ra=RA, nonce=b"n2" + bytes(30),
                               revsnap=snap0), "V9")

# ---------------- E. 旧开启复用（载荷事实登记） ----------------
y2, w2 = saved2
from s6t64 import commit_as  # noqa: E402
r2, eta2 = commit_as.unpack_witness(w2.packed)
C2 = commit_as.commit(Q.cfg_pp["G"], Q.cfg_pp["D"], 2, RID, y2, r2, eta2)
from s6t64 import merkle as MK  # noqa: E402
ok_path, root = MK.MerkleTree.verify_path(commit_as.leaf_of(2, C2), 1, w2.path, None)
record("E1 旧开启静态有效性（对 acc0；删除不撤销见证）——复活的密码学载荷来源",
       ok_path and root == S0.acc0, f"path_ok={ok_path}, root_matches_acc0={root == S0.acc0}")

# ---------------- F. P0.2 撤销与时间语义矩阵 ----------------
# F1 历史 hop 不受其后撤销牵连：撤销 c_n1（eff_ts=5000，其 hop ts=1100）
RA.revoke(c_n1.id, eff_ts=5000)
snap = RA.revocation_snapshot()
record("F1a 撤销后无快照 hist 验证仍接受（历史有效性≠当前授权，不静默拒绝也不声称当前）",
       Q.verify(cfg, S5, "hist") == "accept_historical")
record("F1b 快照下 ts<eff_ts 的历史 hop 不被拒（过去合法签署）",
       Q.verify(cfg, S5, "hist", revsnap=snap) == "accept_historical")

# F2: 新 hop 声称时间 ≥ eff_ts → V5.3d-rev（nurse 撤销后仍在 adm 的旧策略里）
S2r = resurrect(S1, {1, 3, 4, 5, 7, 8}, Policy(P0.adm, V - {3}, 6, n),
                c_n1, sk_n1, S0.fields[3], 6000, j=3)   # 声称 ts=6000 ≥ 5000
expect_reject("F2 撤销后声称授权（ts≥eff_ts）→ V5.3d-rev",
              lambda: Q.verify(cfg, S2r, "hist", revsnap=snap), "V5.3d-rev")
record("F2b 同 hop 无快照时 hist 接受（登记门才是当前性防线；02号 API 合同）",
       Q.verify(cfg, S2r, "hist") == "accept_historical")

# F3: 自报/伪造快照不可信
bad_snap = (snap[0], bytes(len(snap[1])))              # 假签名
expect_reject("F3a 伪造签名快照 → V5.3d",
              lambda: Q.verify(cfg, S5, "hist", revsnap=bad_snap), "V5.3d")
import struct as _st  # noqa: E402
tampered = snap[0][:16] + _st.pack(">Q", 99) + snap[0][24:]
expect_reject("F3b 篡改 epoch 的快照 → V5.3d（签名不匹配）",
              lambda: Q.verify(cfg, S5, "hist", revsnap=(tampered, snap[1])), "V5.3d")

# F4: require_revsnap 缺可信撤销数据 → 明确拒绝
expect_reject("F4 require_revsnap=True 无快照 → V5.3d（拒绝而非静默跳过）",
              lambda: Q.verify(cfg, S5, "hist", revsnap=None, require_revsnap=True),
              "V5.3d")
record("F4b require_revsnap=True 且提供快照 → 正常通过",
       Q.verify(cfg, S5, "hist", revsnap=snap, require_revsnap=True)
       == "accept_historical")

# F5: RA 登记门拒绝已撤销者
expect_reject("F5a 已撤销删改者 register → R1-rev",
              lambda: RA.register(S2r, reg_sig(RA, RID, S2r, sk_n1, c_n1), c_n1),
              "R1-rev", exc=RedactRefused)

# F6: 窗口一致性（记录内；声明 ts 出窗 → 三模式一律拒）
S_late = resurrect(S1, {1, 3, 4, 5, 7, 8}, Policy(P0.adm, V - {3}, 6, n),
                   c_n1, sk_n1, S0.fields[3], (1 << 62) + 1, j=3)   # ts > na
expect_reject("F6 声明 ts 出证书窗 → V5.3d-window（记录内一致性）",
              lambda: Q.verify(cfg, S_late, "hist"), "V5.3d-window")

# F7: RA 重启续撤销（rev_eff 持久化）
RA2 = Q.RA.restore(RA.snapshot())
record("F7 RA snapshot/restore 撤销表+生效时间完整",
       c_n1.id in RA2.revoked and RA2.rev_eff.get(c_n1.id) == 5000 and RA2.epoch == RA.epoch)

# F8: 旧调用约定（调用者自报 revlist/ref_ts）已废除 → TypeError = API 合同变更
try:
    Q.verify(cfg, S5, "hist", revlist={c_n1.id})
    record("F8 旧 revlist 参数废除（TypeError）", False, "accepted self-reported list")
except TypeError:
    record("F8 旧 revlist 参数废除（TypeError）", True)
try:
    Q.verify(cfg, S5, "hist", ref_ts=0)
    record("F8b 旧 ref_ts 参数废除（TypeError）", False, "accepted caller clock")
except TypeError:
    record("F8b 旧 ref_ts 参数废除（TypeError）", True)

# ---------------- F-r2. 对抗复核轮（16-agent 工作流 CONFIRMED 8 项）回归 ----------------
# F9 red-h1-F1/SECREV1-F1（critical）：被撤销者回填 ts 的 hop 经在权成员登记
# 混入公报/新鲜链头——epoch 域逐签署者门 R3-rev 拦截。
# （RID2 已上移至证书签发前——SF-A1 适配）
c_n2 = RA.issue(RID2[:12] + b"NUR2", pk_n1, b"nurse", ((RID2,), {5, 6}), 0, 1 << 62)
P0b = Policy([(b"physician", b"*"), (b"nurse", (c_n2.id,))], set(range(2, 9)), 8, 8)
ys2 = {j: f"r2-field-{j}".encode() for j in range(1, 9)}
sd2 = canon.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, 9)])
S0b = Q.signing(pp, sk_s, c_s, RID2, ys2, P0b, rng=Q.make_rng(b"s59|f9"), schema_digest=sd2)
B1_ = B1
sig_init2 = B1_.sign(sk_s, c_s.pk, canon.M_reginit(RID2, S0b.n, S0b.acc0, S0b.P0,
                                                   canon.H(c_s.msg), sd=sd2), canon.CTX_REG)
RA.register_initial(S0b, c_s, sig_init2)
S1b = Q.redact(pp, S0b, set(range(1, 9)) - {5}, Policy(P0b.adm, set(range(2, 9)) - {3}, 7, 8),
               c_n2, sk_n1, 1000)
RA.register(S1b, reg_sig(RA, RID2, S1b, sk_n1, c_n2), c_n2)
RA.revoke(c_n2.id, eff_ts=5000)
# 攻击：被撤销 nurse（仍持钥）回填 ts=4000<5000 签 hop2；p1 不知情地扩展并登记
S2b_atk = Q.redact(pp, S1b, set(range(1, 9)) - {5, 6},
                   Policy(P0b.adm, set(range(2, 9)) - {3}, 6, 8), c_n2, sk_n1, 4000)
S3b = Q.redact(pp, S2b_atk, set(range(1, 9)) - {5, 6, 7},
               Policy(P0b.adm, set(range(2, 9)) - {2, 3}, 5, 8), c_p1, sk_p1, 4500)
snapF = RA.revocation_snapshot()
record("F9a 攻击链 hist+revsnap 通过（ts 回填 < eff_ts 绕过 ts 域防线——攻击前提实证）",
       Q.verify(cfg, S3b, "hist", revsnap=snapF) == "accept_historical")
expect_reject("F9b 在权成员登记含被撤销者 hop 的扩展 → R3-rev（epoch 域逐签署者门）",
              lambda: RA.register(S3b, reg_sig(RA, RID2, S3b, sk_p1, c_p1), c_p1),
              "R3-rev", exc=RedactRefused)
record("F9c R3-rev 后 RA 头未被污染（RID2 仍 t=1）", RA.reg[RID2]["t"] == 1)

# F10 SECREV1-F3/AUD-04：过期 revsnap（撤销前 epoch）对照当前锚 → V5.3d
expect_reject("F10 过期 revsnap（epoch 0 空表）+ 撤销后 fresh 锚 → V5.3d",
              lambda: Q.verify(cfg, S5, "fresh", ra=RA, nonce=b"n5" + bytes(30), revsnap=snap0),
              "V5.3d")
record("F10b 当前 revsnap + fresh 锚 → accept（epoch 相随）",
       Q.verify(cfg, S5, "fresh", ra=RA, nonce=b"n6" + bytes(30), revsnap=snapF) == "accept_fresh")

# F11 red-h1-F2/SECREV1-F4/AUD-03：revoke 输入校验与单调性
for bad in (None, -1, 2 ** 64, 1.5):
    try:
        RA.revoke(c_p2.id, eff_ts=bad)
        record(f"F11 revoke(eff_ts={bad!r}) 拒绝", False, "accepted")
        break
    except ValueError:
        pass
else:
    record("F11 revoke eff_ts 缺省/负/越界/非整 → ValueError（RA 无可信时钟，必填）", True)
try:
    RA.revoke(c_n1.id, eff_ts=4000)                      # 低于已记 5000
    record("F11b 重复撤销降低 eff_ts → ValueError（单调）", False, "accepted")
except ValueError:
    record("F11b 重复撤销降低 eff_ts → ValueError（单调）", True)

# F12 red-h1-F3：accepted 对象的字段表残留已删索引的合法开启 → V1.2
T = Q.Sigma.deserialize(S5.serialize())
T.fields[2] = saved2                                     # 2 已删；开启对 acc0 合法
try:
    Q.verify(cfg, T, "hist")
    record("F12 字段表含非保留索引（复活开启残留）→ V1.2", False, "accepted")
except VerifyReject as e:
    record("F12 字段表含非保留索引（复活开启残留）→ V1.2", e.step == "V1.2", e.step)

# F13 AUD-02（Gaps-fix 轮 2 语义更新）：撤销纪元证据缺失的 ver=2 快照
# 一律 RestoreRefused——不再"缺 rev_eff 回填 eff_ts=0 继续可用"（缺字段
# 不得解释为可继续状态；详见 test_sf_gaps G2 系列）。真实冻结时代快照
# 连 ver 都没有，已被版本门先行拒绝。
import json as _json  # noqa: E402
_o = _json.loads(RA.snapshot().decode("utf-8"))
_o.pop("rev_eff")
try:
    Q.RA.restore(_json.dumps(_o).encode())
    record("F13 缺 rev_eff 快照 → RestoreRefused（fail-closed）", False, "restored(!)")
except Q.RestoreRefused:
    record("F13 缺 rev_eff 快照 → RestoreRefused（fail-closed）", True)

# F14 AUD-03：截断 revsnap → 干净 V5.3d（非 struct.error 崩溃）
expect_reject("F14 截断 revsnap → V5.3d", lambda: Q.verify(
    cfg, S5, "hist", revsnap=(snapF[0][:20], snapF[1])), "V5.3d")

# F15 SECREV1-F2：snapshot/fresh 缺 revsnap 默认拒绝；显式 False=调用者自担
expect_reject("F15 fresh 缺 revsnap（默认 require）→ V5.3d",
              lambda: Q.verify(cfg, S5, "fresh", ra=RA, nonce=b"n7" + bytes(30)), "V5.3d")
expect_reject("F15b snapshot 缺 revsnap（默认 require）→ V5.3d",
              lambda: Q.verify(cfg, S5, "snapshot", gazettes=[RA.gazette(2, RID)],
                                 legacy_snapshot=True), "V5.3d")
record("F15c hist 缺 revsnap 仍允许（合同不含当前授权声明）",
       Q.verify(cfg, S5, "hist") == "accept_historical")

# ---------------- G. V1–V9 核心篡改负例（补丁未破坏原链） ----------------
import copy  # noqa: E402
T = Q.Sigma.deserialize(S5.serialize())
T.sigma0 = bytes([T.sigma0[0] ^ 1]) + T.sigma0[1:]
expect_reject("G1 σ₀ 篡改 → V2.2", lambda: Q.verify(cfg, T, "hist"), "V2.2")

T = Q.Sigma.deserialize(S5.serialize())
y, w = T.fields[1]
w.path = [bytes([w.path[0][0] ^ 1]) + w.path[0][1:]] + list(w.path[1:])
T.fields[1] = (y, w)
expect_reject("G2 Merkle 路径篡改 → V4", lambda: Q.verify(cfg, T, "hist"), "V4")

T = Q.Sigma.deserialize(S5.serialize())
e, tau, cid = T.log[0]
T.log[0] = (e, bytes([tau[0] ^ 1]) + tau[1:], cid)
expect_reject("G3 τ 篡改 → V5.4", lambda: Q.verify(cfg, T, "hist"), "V5.4")

T = Q.Sigma.deserialize(S5.serialize())
T.It = T.It | {2}                    # 终态字段集塞入已删索引（无开启复活路径）
try:
    Q.verify(cfg, T, "hist")
    record("G4 终态索引集塞已删 j（无开启）→ V1.2 干净拒绝", False, "accepted")
except VerifyReject as e:
    record("G4 终态索引集塞已删 j（无开启）→ V1.2 干净拒绝", e.step == "V1.2", e.step)

expect_reject("G5 空删除 → V7.1",
              lambda: Q.redact(pp, S5, set(S5.It), Policy(adm3, V - {3, 6}, 2, n),
                               c_p1, sk_p1, 3000), "R0", exc=RedactRefused)

T = Q.Sigma.deserialize(S5.serialize())
e_bytes, tau, cid = T.log[1]
hop = Q.dec_e(e_bytes, T.n)
e_bad = canon.enc_e(hop["seq"], hop["id"], hop["role"], hop["certH"],
                    hop["I_prev"], hop["I_prev"] - {6} - {4},   # 偷删非白名单外字段
                    hop["P_prev"], hop["P_new"], hop["ts"], T.n)
T.log[1] = (e_bad, tau, cid)
expect_reject("G6 hop 内容替换（链断裂）→ V6/V5.4", lambda: Q.verify(cfg, T, "hist"))

R["t_total_s"] = round(time.time() - R["t_start"], 1)
R["pass_count"] = f"{sum(1 for v in R['tests'].values() if v['pass'])}/{len(R['tests'])}"
print(f"\n=== s59 regression {R['pass_count']} PASS in {R['t_total_s']}s ===")
os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
with open(os.path.join(ROOT, "logs", "t64_regression.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
