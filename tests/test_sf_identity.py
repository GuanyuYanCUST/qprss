# -*- coding: utf-8 -*-
"""SF-A（安全修复 Task A）：RID↔初始签名者身份替换 P0 修复验证。

前置：Task G A1（QPRSS_Pending_Code_Verification.md）实证冻结实现接受
"换钥+换证+同 Θ0"的身份替换（hist 与 fresh 双 accept，通配 signer scope
= 正式 fixture 口径）。本测试验证修复后：

  A1  签发约束：signer 证书 scope 必须显式 RID；一 RID 一签名者 (id,pk)；
      续签仅限同 (id,pk)；编辑者证书不受影响。
  A2  登记绑定：reg[rid].cid = H(Cert_S.msg)（首登正文摘要，历史语义）；
      reg[rid].bid = BindId(RID, ID_S, PK)（Gaps-fix 轮 2 续签稳定身份摘要）；
      fresh 应答（M_resp5）携带 bid，Verify(fresh) 比对 BindId(RID, ID_S, PK)。
  A3  hist 修复口径：通配 signer 证书 → V2.1 拒；同 RID 第二份范围证书在
      诚实 RA 下不可获得（签发唯一性）；白盒共谋（直接动用 RA 签名密钥）
      是文档化 PKI 信任边界——hist 接受、fresh 因 cid 拒绝（如实记录，
      不伪造 hist 拒绝）。

必需六负向：同 RID 异密钥替换 hist 拒 / 同替换 fresh 拒 / 通配 signer
scope 拒 / 他 RID scope 拒 / 管理员二次签发拒 / 正常路径仍通。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from s6t64 import s5_qprss as Q                      # noqa: E402
from s6t64 import canon, policy as pol               # noqa: E402

R = {"tests": {}}


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  {note}" if note else ""))


def expect_reject(name, fn, step, exc=Q.VerifyReject):
    try:
        fn()
        record(name, False, "accepted(!)")
    except exc as e:
        got = getattr(e, "step", "") or ""
        record(name, step in got or step in str(e),
               f"{type(e).__name__}@{got}: {e}")


RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
RID_OTHER = bytes.fromhex("7766554433221100ffeeddccbbaa9988")
N = 6

pp = Q.setup("B1", seed=b"sf-a|pp")
RA = Q.RA("B1")
cfg = {"pk_ra": RA.pk}
B1 = Q.s5_sig.core("B1")

skA, pkA = B1.keygen()
skB, pkB = B1.keygen()
certA = RA.issue(RID[:12] + b"SGNR", pkA, b"signer", ((RID,), b"*"), 0, 1 << 62)

ys = {j: f"v{j}".encode() for j in range(1, N + 1)}
sd = canon.schema_digest([(j, ("Patient", f"a{j}"), "str") for j in range(1, N + 1)])
P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, N + 1)), N, N)
S1 = Q.signing(pp, skA, certA, RID, ys, P0, rng=Q.make_rng(b"sf-a|sg"), schema_digest=sd)
snap = RA.revocation_snapshot()

# ---------------- A1 签发约束 ----------------
try:
    RA.issue(b"\x11" * 16, pkB, b"signer", (b"*", b"*"), 0, 1 << 62)
    record("A1-1 signer 通配 scope 签发拒绝", False, "issued(!)")
except Q.IssuanceRefused as e:
    record("A1-1 signer 通配 scope 签发拒绝", True, str(e))
try:
    RA.issue(b"\x11" * 16, pkB, b"signer", ((), b"*"), 0, 1 << 62)
    record("A1-2 signer 空 RID 枚举签发拒绝", False, "issued(!)")
except Q.IssuanceRefused:
    record("A1-2 signer 空 RID 枚举签发拒绝", True)
# 管理员二次签发：同 RID 异 (id,pk) → 拒；同 (id,pk) → 续签允许
try:
    RA.issue(RID[:12] + b"SGNB", pkB, b"signer", ((RID,), b"*"), 0, 1 << 62)
    record("A1-3 同 RID 异签名者二次签发拒绝", False, "issued(!)")
except Q.IssuanceRefused as e:
    record("A1-3 同 RID 异签名者二次签发拒绝", True, str(e))
try:
    certA2 = RA.issue(certA.id, certA.pk, b"signer", ((RID,), b"*"), 0, 1 << 63)
    record("A1-4 同 (id,pk) 续签允许（窗口延长）", certA2.verify(RA.pk))
except Q.IssuanceRefused as e:
    record("A1-4 同 (id,pk) 续签允许", False, str(e))
c_ed = RA.issue(b"\x22" * 16, pkB, b"physician", (b"*", b"*"), 0, 1 << 62)
record("A1-5 编辑者通配 scope 不受影响", c_ed.verify(RA.pk) and c_ed.role == b"physician")
record("A1-6 绑定表恰一条且为 (id,pk)",
       RA.signers == {RID: (certA.id, certA.pk)})

# ---------------- 正常路径仍通 ----------------
record("A2-1 正常路径 hist 仍 accept", Q.verify(cfg, S1, "hist") == "accept_historical")
sig_init = B1.sign(skA, certA.pk,
                   canon.M_reginit(RID, N, S1.acc0, S1.P0, canon.H(certA.msg), sd=sd),
                   canon.CTX_REG)
record("A2-2 RegisterInitial 正常通过", RA.register_initial(S1, certA, sig_init) == 0)
record("A2-3 reg[rid].cid == H(Cert_S.msg) 且 bid == BindId(RID,ID,PK)（A2 登记）",
       RA.reg[RID]["cid"] == canon.H(certA.msg)
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, certA.pk)
       and canon.BindId(RID, certA.id, certA.pk) != canon.H(certA.msg))
n32 = b"sf-a-nonce".ljust(32, b"|")        # SF-B：恰 32B
record("A2-4 正常路径 fresh 仍 accept（M_resp5+bid）",
       Q.verify(cfg, S1, "fresh", ra=RA, nonce=n32, revsnap=snap) == "accept_fresh")

# ---------------- 身份替换攻击（Task G A1 场景复刻） ----------------
def clone_with_signer(S, skX, certX):
    """攻击者副本：换 σ0 签名者密钥+证书，其余（Θ0/h0/链）原样保留。"""
    S2 = Q.Sigma(S.scheme, S.rid, S.n)
    S2.sd, S2.acc0, S2.P0, S2.It = S.sd, S.acc0, S.P0, set(S.It)
    S2.fields = dict(S.fields)
    S2.Pt = S.Pt
    S2.sigma0 = B1.sign(skX, certX.pk,
                        canon.M_orig(S.rid, S.n, S.acc0, S.P0,
                                     set(range(1, S.n + 1)), sd=S.sd), canon.CTX_ORIG)
    S2.cert_s = certX
    S2.h_t = S.h_t
    return S2


# (a) 通配证书替换（冻结实现的 accept 路径）——hist 拒（V2.1 通配 signer 拒）
certB_wild = Q.Cert(b"\x99" * 16, pkB, b"signer", (b"*", b"*"), 0, 1 << 62, scheme="B1")
certB_wild.sig = RA._sign(certB_wild.msg, canon.CTX_CERT)   # 白盒： RA 钥匙直接签
S2w = clone_with_signer(S1, skB, certB_wild)
expect_reject("A3-1 通配证书替换 hist 拒（V2.1-scope）",
              lambda: Q.verify(cfg, S2w, "hist"), "V2.1")
expect_reject("A3-2 通配证书替换 fresh 拒（V2.1-scope）",
              lambda: Q.verify(cfg, S2w, "fresh", ra=RA, nonce=n32, revsnap=snap),
              "V2.1")

# (b) 他 RID scope 证书替换 —— V2.1-scope（ScopeMatchRID）拒
certC = Q.Cert(b"\x88" * 16, pkB, b"signer", ((RID_OTHER,), b"*"), 0, 1 << 62, scheme="B1")
certC.sig = RA._sign(certC.msg, canon.CTX_CERT)
S3 = clone_with_signer(S1, skB, certC)
expect_reject("A3-3 他 RID scope 证书替换 hist 拒",
              lambda: Q.verify(cfg, S3, "hist"), "V2.1")

# (c) 同 RID 枚举 scope 的第二份证书——诚实 RA 下不可获得（A1-3 已证）；
# 白盒共谋（直接动 RA 签名钥伪造）= 文档化 PKI 信任边界：hist 接受、fresh 拒。
certD = Q.Cert(b"\x77" * 16, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62, scheme="B1")
certD.sig = RA._sign(certD.msg, canon.CTX_CERT)
S4 = clone_with_signer(S1, skB, certD)
try:
    r = Q.verify(cfg, S4, "hist")
    record("A3-4 白盒共谋枚举证书 hist 接受（PKI 信任边界，如实记录）",
           r == "accept_historical", "hist 签名链自洽——防线=签发唯一性(诚实RA)")
except Q.VerifyReject as e:
    record("A3-4 白盒共谋枚举证书 hist 接受（PKI 信任边界）", False, f"reject@{e.step}")
expect_reject("A3-5 同替换 fresh 拒（cid 绑定：reg.cid≠H(Cert_D.msg)）",
              lambda: Q.verify(cfg, S4, "fresh", ra=RA, nonce=n32, revsnap=snap), "V9")

# (d) 白盒替换者的 RegisterInitial —— I1-bnd 拒（signers[RID] 已绑 (id_A,pk_A)）
sig_initD = B1.sign(skB, certD.pk,
                    canon.M_reginit(RID, N, S1.acc0, S1.P0, canon.H(certD.msg), sd=sd),
                    canon.CTX_REG)
expect_reject("A3-6 白盒替换者 RegisterInitial 拒（I1-bnd）",
              lambda: RA.register_initial(S1, certD, sig_initD), "I1-bnd",
              exc=Q.RedactRefused)

# (e) 伪造（非 RA 签名）证书 —— V2.1 验签拒
certE = Q.Cert(b"\x66" * 16, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62, scheme="B1")
certE.sig = b"\x00" * 5794
S5 = clone_with_signer(S1, skB, certE)
expect_reject("A3-7 非 RA 签名证书拒（V2.1 验签）", lambda: Q.verify(cfg, S5, "hist"),
              "V2.1")

# (f) 登记后扩展：换身份 signer 的分叉链到不了登记门（R2b）
# —— 编辑链走诚实路径：
sk_ed, pk_ed = B1.keygen()
c_ed2 = RA.issue(b"\x33" * 16, pk_ed, b"physician", ((RID,), b"*"), 0, 1 << 62)
S1b = Q.redact(pp, S1, set(range(1, N + 1)) - {2},
               pol.Policy(P0.adm, P0.w - {3}, P0.d - 1, N), c_ed2, sk_ed, 10)
m_reg = canon.M_reg(RID, RA.reg[RID]["ver"], RA.reg[RID]["h"],
                    RA.reg[RID]["ver"] + 1, S1b.h_t, len(S1b.log),
                    canon.H(c_ed2.msg), c_ed2.id, c_ed2.role)
RA.register(S1b, B1.sign(sk_ed, pk_ed, m_reg, canon.CTX_REG), c_ed2)
record("A2-5 诚实编辑+Register 扩展仍通过", RA.reg[RID]["t"] == 1)
# 白盒 signer B 用自己证书签的 M_reg（即使 M_reg 伪造正确）→ R2b
m_regB = canon.M_reg(RID, RA.reg[RID]["ver"], RA.reg[RID]["h"],
                     RA.reg[RID]["ver"] + 1, S1b.h_t, len(S1b.log),
                     canon.H(certD.msg), certD.id, certD.role)
sig_regB = B1.sign(skB, pkB, m_regB, canon.CTX_REG)
expect_reject("A3-8 白盒 signer 以异绑定身份 Register 拒（R2b）",
              lambda: RA.register(S1b, sig_regB, certD), "R2b", exc=Q.RedactRefused)
record("A2-6 reg[rid].cid/bid 不随 Register 变更",
       RA.reg[RID]["cid"] == canon.H(certA.msg)
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, certA.pk))
snap2 = RA.revocation_snapshot()
record("A2-7 扩展后 fresh 仍 accept（bid 保持）",
       Q.verify(cfg, S1b, "fresh", ra=RA, nonce=b"sf-a-nonce2".ljust(32, b"|"),
                revsnap=snap2) == "accept_fresh")

# ---------------- 快照/恢复保真 ----------------
ra2 = Q.RA.restore(RA.snapshot())
record("A4-1 snapshot/restore 保真 signers+cid+bid",
       ra2.signers == RA.signers and ra2.reg[RID]["cid"] == RA.reg[RID]["cid"]
       and ra2.reg[RID]["bid"] == RA.reg[RID]["bid"])
record("A4-2 restore 后 fresh 仍 accept（同 bid 链）",
       Q.verify({"pk_ra": ra2.pk}, S1b, "fresh", ra=ra2,
                nonce=b"sf-a-nonce3".ljust(32, b"|"), revsnap=snap2) == "accept_fresh")

R["verdict"] = "ALL_SF_IDENTITY_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "SF_IDENTITY_FAIL"
with open(os.path.join(os.path.dirname(HERE), "logs", "sf_identity.json"), "w",
          encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(R["verdict"])
sys.exit(0 if R["verdict"] == "ALL_SF_IDENTITY_PASS" else 1)
