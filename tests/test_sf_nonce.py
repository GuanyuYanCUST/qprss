# -*- coding: utf-8 -*-
"""SF-B（安全修复 Task B）：fresh 随机 nonce 与 v4 应答绑定。

冻结实现缺口（Task G A4）：nonce 完全由调用方传入，无生成、无长度校验，
正式实验全用固定常量（e2 "stage6-fresh-nonce" 19B、e7b "e7b-nonce" 9B）。
修复后：CSPRNG 每次独立 32B；应答 M_resp4 绑定 nonce+RID+链头+纪元+cid；
编码（M_resp4）与解析（parse_resp4）路径同规范；长度强制恰 32B。
Gaps-fix 轮 2：应答升级 M_resp5（末域 cid→bid=BindId(RID,ID_S,PK)，177B 不变，
前缀 b"QPRSS-v5|resp"）；v4/v5 前缀互斥不可混用。M_resp4/parse_resp4 保留作
一轮遗留对照。

必需六测：合法随机过 / 错长度拒 / 重放旧应答拒 / 篡改字段拒 /
旧撤销快照新纪元拒 / hist 不受影响。
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


RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
N = 6
B1 = Q.s5_sig.core("B1")

pp = Q.setup("B1", seed=b"sf-b|pp")
RA = Q.RA("B1")
cfg = {"pk_ra": RA.pk}
sk_s, pk_s = B1.keygen()
cert_s = RA.issue(RID[:12] + b"SGNR", pk_s, b"signer", ((RID,), b"*"), 0, 1 << 62)
sk_n, pk_n = B1.keygen()
c_n = RA.issue(b"\x44" * 16, pk_n, b"nurse", ((RID,), b"*"), 0, 1 << 62)
ys = {j: f"v{j}".encode() for j in range(1, N + 1)}
sd = canon.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, N + 1)])
P0 = pol.Policy(((b"physician", b"*"), (b"nurse", (c_n.id,))),
                frozenset(range(2, N + 1)), N, N)
S1 = Q.signing(pp, sk_s, cert_s, RID, ys, P0, rng=Q.make_rng(b"sf-b|sg"),
               schema_digest=sd)
sig_init = B1.sign(sk_s, cert_s.pk,
                   canon.M_reginit(RID, N, S1.acc0, S1.P0, canon.H(cert_s.msg), sd=sd),
                   canon.CTX_REG)
RA.register_initial(S1, cert_s, sig_init)
snap0 = RA.revocation_snapshot()

# ---------------- B1 合法随机过（nonce=None 自动 CSPRNG） ----------------
record("B1-1 fresh nonce 缺省 = CSPRNG 32B 且 accept",
       Q.verify(cfg, S1, "fresh", ra=RA, revsnap=snap0) == "accept_fresh")
# 缺省路径观察（任务书允许测试注入随机数）：拦截 secure_rng，断言每次调用
# 恰 32B、两次互异、且生成的应答与注入 nonce 一一验签通过。
_calls = []


def _stub_rng(n):
    _calls.append((n, len(_calls)))
    return bytes([0x5A]) * 31 + bytes([len(_calls)])


_orig_rng = Q.secure_rng
Q.secure_rng = _stub_rng
try:
    ra1 = RA.fresh_query(None, RID)
    ra2 = RA.fresh_query(None, RID)
finally:
    Q.secure_rng = _orig_rng
n1 = bytes([0x5A]) * 31 + bytes([1])
n2 = bytes([0x5A]) * 31 + bytes([2])
record("B1-2 缺省查询走 secure_rng(32)×2 且 nonce 互异",
       [c[0] for c in _calls] == [32, 32] and n1 != n2)
record("B1-2b 注入 nonce 与应答一一对应（重算 M_resp5 验签通过）",
       B1.verify(RA.pk, canon.M_resp5(n1, RID, ra1[1], ra1[2], ra1[3], ra1[4],
                                      ra1[5]), ra1[0], canon.CTX_ANC)
       and B1.verify(RA.pk, canon.M_resp5(n2, RID, ra2[1], ra2[2], ra2[3], ra2[4],
                                          ra2[5]), ra2[0], canon.CTX_ANC))
record("B1-2c 两次缺省应答签名互异（nonce 域分离）", ra1[0] != ra2[0])
n_ok = os.urandom(32)
record("B1-3 显式 32B 随机 nonce accept",
       Q.verify(cfg, S1, "fresh", ra=RA, nonce=n_ok, revsnap=snap0) == "accept_fresh")

# ---------------- B2 错长度拒（编码/生成/验证三路一致） ----------------
bad_lens = [b"short", b"n" * 31, b"n" * 33, b"stage6-fresh-nonce", b"e7b-nonce", b""]
ok_reject_fq = ok_reject_enc = ok_reject_ver = True
for bad in bad_lens:
    try:
        RA.fresh_query(bad, RID)
        ok_reject_fq = False
    except ValueError:
        pass
    try:
        canon.M_resp4(bad, RID, b"\x00" * 48, 0, 0, 0, b"\x00" * 48)
        canon.M_resp5(bad, RID, b"\x00" * 48, 0, 0, 0, b"\x00" * 48)
        ok_reject_enc = False
    except ValueError:
        pass
    try:
        Q.verify(cfg, S1, "fresh", ra=RA, nonce=bad, revsnap=snap0)
        ok_reject_ver = False
    except Q.VerifyReject:
        pass
record("B2-1 fresh_query 错长度 nonce 全拒（ValueError）", ok_reject_fq,
       f"{len(bad_lens)} 个非法长度")
record("B2-2 M_resp4/M_resp5 编码错长度拒（与解析同规范）", ok_reject_enc)
record("B2-3 verify 端错长度 nonce 拒（V9）", ok_reject_ver)

# parse_resp5 往返与畸形（fresh_query 返回签名；消息由返回域重算）
nonce = os.urandom(32)
resp, a_h, a_t, a_ts, a_ep, a_bid = RA.fresh_query(nonce, RID)
m = canon.M_resp5(nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
record("B2-4 M_resp5/parse_resp5 往返一致（消息重算=应答签名覆盖域）",
       canon.parse_resp5(m) == (nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
       and B1.verify(RA.pk, m, resp, canon.CTX_ANC))
ok_bad = True
for corrupt in (m[:-1], m + b"\x00", b"QPRSS-v3|resp" + m[13:],
                b"QPRSS-v5|gaz" + m[13:]):
    try:
        canon.parse_resp5(corrupt)
        ok_bad = False
    except ValueError:
        pass
record("B2-5 parse_resp5 畸形（截断/尾随/前缀替换）全拒", ok_bad)
# v4/v5 前缀互斥：v5 解析器拒 v4 消息、v4 解析器拒 v5 消息（不可混用/误读）
m4 = canon.M_resp4(nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
cross_to5 = m4[:7] + b"5" + m4[8:]          # 同域字节、前缀改成 v5
mix_ok = False
try:
    canon.parse_resp5(m4)                   # v4 原文喂 v5 解析器 → 必拒
except ValueError:
    try:
        canon.parse_resp4(cross_to5)        # v5 前缀喂 v4 解析器 → 必拒
    except ValueError:
        mix_ok = (canon.parse_resp4(m4)
                  == (nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
                  and canon.parse_resp5(cross_to5)
                  == (nonce, RID, a_h, a_t, a_ts, a_ep, a_bid)
                  and len(m4) == len(m) == 177 and m4[:7] == m[:7]
                  and m4[7:8] == b"4" and m[7:8] == b"5" and m4[8:] == m[8:])
record("B2-7 v4/v5 前缀互斥不可混用（同域仅 byte 7 异）", mix_ok)
record("B2-6 M_resp5 字节长 = 177（13+32+16+48+4+8+8+48）", len(m) == 177,
       f"got {len(m)}")

# ---------------- B3 重放旧应答拒（nonce/应答一一对应） ----------------
# 验证器总以"本次 nonce"重算 M_resp5 验签：旧 nonce 的应答对新查询必验签失败。
nonce2 = os.urandom(32)
resp_old = RA.fresh_query(nonce, RID)[0]          # 旧应答（nonce₁ 签名）
cross = B1.verify(RA.pk, canon.M_resp5(nonce2, RID, a_h, a_t, a_ts, a_ep, a_bid),
                  resp_old, canon.CTX_ANC)
record("B3-1 旧应答跨 nonce 验签必败（重放面=无）", not cross)
# 同理：不同 RID/链头/纪元/bid 下旧应答不可复用
cross2 = B1.verify(RA.pk, canon.M_resp5(nonce, RID, a_h, a_t + 1, a_ts, a_ep, a_bid),
                   resp_old, canon.CTX_ANC)
record("B3-2 旧应答改绑其它链头（t*+1）必败", not cross2)

# ---------------- B4 篡改字段拒 ----------------
record("B4-1 应答篡改 t* 后验签必败（=B3-2 场景）", not cross2)
tampered_bid = bytes(a_bid[::-1])
record("B4-2 应答篡改 bid 后验签必败",
       not B1.verify(RA.pk, canon.M_resp5(nonce, RID, a_h, a_t, a_ts, a_ep,
                                          tampered_bid), resp_old, canon.CTX_ANC))
# 验证器侧 bid 比对（V9）：见 test_sf_gaps G1-5/G1-6（换证工件/篡改应答拒），
# 此处补登记侧一致性：reg.bid 即应答 bid。
record("B4-3 应答 bid == reg[rid].bid == BindId(RID,ID,PK)（登记/应答同源）",
       a_bid == RA.reg[RID]["bid"]
       and a_bid == canon.BindId(RID, cert_s.id, cert_s.pk))

# ---------------- B5 旧撤销快照 + 新纪元拒（epoch 门保留） ----------------
P1 = pol.Policy(P0.adm, P0.w - {4}, P0.d - 1, N)
S2 = Q.redact(pp, S1, set(range(1, N + 1)) - {2}, P1, c_n, sk_n, 100)
m_reg = canon.M_reg(RID, RA.reg[RID]["ver"], RA.reg[RID]["h"],
                    RA.reg[RID]["ver"] + 1, S2.h_t, len(S2.log),
                    canon.H(c_n.msg), c_n.id, c_n.role)
RA.register(S2, B1.sign(sk_n, pk_n, m_reg, canon.CTX_REG), c_n)
# 撤销一个不在链上的身份（仅推 epoch）——链上 hop 不受牵连，当前快照应通过
sk_x, pk_x = B1.keygen()
c_x = RA.issue(b"\x55" * 16, pk_x, b"auditor", ((RID,), b"*"), 0, 1 << 62)
RA.revoke(c_x.id, eff_ts=50)                      # epoch 0→1：snap0 成为旧快照
snap1 = RA.revocation_snapshot()
try:
    Q.verify(cfg, S2, "fresh", ra=RA, nonce=os.urandom(32), revsnap=snap0)
    record("B5-1 旧撤销快照（epoch 0）配新纪元锚拒（V5.3d）", False, "accepted(!)")
except Q.VerifyReject as e:
    record("B5-1 旧撤销快照（epoch 0）配新纪元锚拒（V5.3d）", e.step == "V5.3d",
           f"@{e.step}")
record("B5-2 当前快照（epoch 1）fresh accept",
       Q.verify(cfg, S2, "fresh", ra=RA, nonce=os.urandom(32),
                revsnap=snap1) == "accept_fresh")

# ---------------- B6 hist 不受影响 ----------------
record("B6-1 hist 无 nonce 机制依赖、仍 accept",
       Q.verify(cfg, S2, "hist") == "accept_historical"
       and Q.verify(cfg, S2, "hist", revsnap=snap1) == "accept_historical")

R["verdict"] = "ALL_SF_NONCE_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "SF_NONCE_FAIL"
with open(os.path.join(os.path.dirname(HERE), "logs", "sf_nonce.json"), "w",
          encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(R["verdict"])
sys.exit(0 if R["verdict"] == "ALL_SF_NONCE_PASS" else 1)
