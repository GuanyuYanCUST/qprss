# -*- coding: utf-8 -*-
"""Gaps-fix（末两缺口修复）：任务 1 续签稳定身份摘要 bid / 任务 2 旧状态恢复 fail-closed。

任务 1（G1）：bid_S = BindId(RID, ID_S, PK)（canon.H_B 域，384-bit，不含有效期/
  序列号/签发版本/签名随机性）；fresh 应答 M_resp5（= 论文 EncResp_5）携带 bid；
  V9 比对应答 bid 与工件 BindId(RID, ID_S, PK)。
  验收：同 RID 同 (ID_S,PK) 合法续签（新有效期/新正文/新管理员签名）后，
  续签工件 hist+fresh 双 accept、原证工件 fresh 仍 accept；换 ID 或 PK 时
  签发拒绝且换证工件 fresh 拒；应答 bid/RID/nonce/链头/纪元篡改全拒。
任务 2（G2）：restore 入口对版本/signers/cid/bid/回滚/冲突 fail-closed；
  缺证据旧快照不得恢复出可绕过唯一绑定的状态；RA.issue 不完整状态拒签发；
  多线程同 RID 签发唯一性。
"""
import copy
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from s6t64 import s5_qprss as Q                      # noqa: E402
from s6t64 import canon, policy as pol               # noqa: E402

R = {"tests": {}}


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  {note}" if note else ""))


def vr(name, fn, step="V9", exc=Q.VerifyReject):
    """断言 fn 被 exc 拒绝；step=None 表示任意落点皆可。"""
    try:
        fn()
        record(name, False, "accepted(!)")
    except exc as e:
        got = getattr(e, "step", "") or str(e)[:60]
        record(name, step is None or got == step or got.startswith(str(step)),
               f"@{got}: {str(e)[:70]}")


RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
N = 6
B1 = Q.s5_sig.core("B1")

pp = Q.setup("B1", seed=b"sf-gaps|pp")
RA = Q.RA("B1")
cfg = {"pk_ra": RA.pk}
skA, pkA = B1.keygen()
ys = {j: f"v{j}".encode() for j in range(1, N + 1)}
sd = canon.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, N + 1)])
P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, N + 1)), N, N)
certA = RA.issue(RID[:12] + b"SGNR", pkA, b"signer", ((RID,), b"*"), 0, 1 << 62)
sk_n, pk_n = B1.keygen()
c_n = RA.issue(b"\x44" * 16, pk_n, b"nurse", ((RID,), b"*"), 0, 1 << 62)
P0 = pol.Policy(((b"physician", b"*"), (b"nurse", (c_n.id,))),
                frozenset(range(2, N + 1)), N, N)
S1 = Q.signing(pp, skA, certA, RID, ys, P0, rng=Q.make_rng(b"sf-gaps|sg"),
               schema_digest=sd)
sig_init = B1.sign(skA, certA.pk,
                   canon.M_reginit(RID, N, S1.acc0, S1.P0, canon.H(certA.msg), sd=sd),
                   canon.CTX_REG)
n32 = b"sf-gaps-n1".ljust(32, b"|")


def clone_with_signer(S, skX, certX):
    """同 Θ0 换证书副本（σ0 在 certX.pk 下重签；Θ0/h0/域值不变；t=0 工件）。"""
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


def fresh(S, nonce=None, ra=None, snap=None):
    kw = {"ra": ra or RA, "nonce": nonce or os.urandom(32)}
    if snap is not None:
        kw["revsnap"] = snap
    return Q.verify({"pk_ra": (ra or RA).pk}, S, "fresh", **kw)


# ================= 任务 1：G1 续签稳定身份摘要 =================
# ---- G1-1 首次登记：cid/bid 双记录，hist+fresh 双 accept ----
vr("G1-1a 未登记 RID 先 fresh 拒（no registration）",
   lambda: fresh(S1, snap=RA.revocation_snapshot()), step=None, exc=Q.RedactRefused)
RA.register_initial(S1, certA, sig_init)
snap0 = RA.revocation_snapshot()
record("G1-1b 首登记录 cid=CertId(M_certS) 与 bid=BindId(RID,ID,PK)",
       RA.reg[RID]["cid"] == canon.CertId(certA.msg)
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, certA.pk)
       and len(RA.reg[RID]["bid"]) == 48)
record("G1-1c cid ≠ bid（不同域标签/输入，三种摘要不混淆）",
       RA.reg[RID]["cid"] != RA.reg[RID]["bid"]
       and canon.CertId(certA.msg) == canon.H(certA.msg)
       and canon.BindId(RID, certA.id, certA.pk)
       == canon.H_B(RID + certA.id + certA.pk))
len_ok = True
for bad in ((RID[:15], certA.id, certA.pk), (RID, certA.id[:15], certA.pk)):
    try:
        canon.BindId(*bad)
        len_ok = False
    except ValueError:
        pass
record("G1-1d BindId 域分离（H_B≠H≠H_L）与 16B 输入校验、48B 输出",
       len_ok and canon.H_B(b"x") != canon.H(b"x") and canon.H_B(b"x") != canon.H_L(b"x")
       and len(canon.BindId(RID, certA.id, certA.pk)) == 48)
record("G1-1e 首登工件 hist+fresh 双 accept",
       Q.verify(cfg, S1, "hist") == "accept_historical"
       and fresh(S1, n32, snap=snap0) == "accept_fresh")

# ---- G1-2 相同证书重用（同参重发 → 同正文证书）----
certA_dup = RA.issue(RID[:12] + b"SGNR", pkA, b"signer", ((RID,), b"*"), 0, 1 << 62)
record("G1-2 相同参数重发 = 同证书正文（重用不改变绑定）",
       certA_dup.msg == certA.msg and certA_dup.verify(RA.pk)
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, pkA)
       and fresh(S1, snap=snap0) == "accept_fresh")

# ---- G1-3 同 RID 同 (ID,PK) 合法续签：新有效期/新正文/新管理员签名 ----
certA2 = RA.issue(certA.id, certA.pk, b"signer", ((RID,), b"*"), 0, 1 << 63)
record("G1-3a 续签签发成功且正文/管理员签名互异（同 id+pk、新有效期）",
       certA2.id == certA.id and certA2.pk == certA.pk
       and certA2.msg != certA.msg and certA2.sig != certA.sig
       and certA2.verify(RA.pk) and certA2.na == 1 << 63)
record("G1-3b reg.cid 保持首登正文摘要（历史语义不变）、bid 不随续签变",
       RA.reg[RID]["cid"] == canon.H(certA.msg)
       and canon.H(certA2.msg) != RA.reg[RID]["cid"]
       and RA.reg[RID]["bid"] == canon.BindId(RID, certA.id, pkA))
S1r = clone_with_signer(S1, skA, certA2)
record("G1-3c 续签证书工件 hist accept", Q.verify(cfg, S1r, "hist") == "accept_historical")
record("G1-3d 续签证书工件 fresh accept（修复验收：不再因 cid 变化错拒）",
       fresh(S1r, snap=snap0) == "accept_fresh")

# ---- G1-4 原证书工件在续签后 fresh 仍 accept ----
record("G1-4 原证书工件续签后 fresh 仍 accept（cid/bid 均不随续签漂移）",
       fresh(S1, snap=snap0) == "accept_fresh"
       and Q.verify(cfg, S1, "hist") == "accept_historical")

# ---- G1-5 换 ID 或换 PK：签发拒绝 + 工件不接受 ----
skB, pkB = B1.keygen()
vr("G1-5a 换 ID 续签同 RID 签发拒（IssuanceRefused）",
   lambda: RA.issue(b"\x77" * 16, pkA, b"signer", ((RID,), b"*"), 0, 1 << 62),
   step=None, exc=Q.IssuanceRefused)
vr("G1-5b 换 PK 续签同 RID 签发拒（IssuanceRefused）",
   lambda: RA.issue(certA.id, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62),
   step=None, exc=Q.IssuanceRefused)
# 白盒换证工件（文档化 PKI 共谋边界）：hist 可过（诚实 RA 不会签此证），
# fresh 因 V9 bid 绑定拒——这正是 cid→bid 修复的验签侧语义。
certD = Q.Cert(b"\x88" * 16, pkA, b"signer", ((RID,), b"*"), 0, 1 << 62, scheme="B1")
certD.sig = RA._sign(certD.msg, canon.CTX_CERT)
S1D = clone_with_signer(S1, skA, certD)
record("G1-5c 白盒换 ID 证 hist 接受（共谋边界，如实记录）",
       Q.verify(cfg, S1D, "hist") == "accept_historical")
vr("G1-5d 白盒换 ID 证 fresh 拒（V9 bid 身份不匹配）", lambda: fresh(S1D, snap=snap0))
certE = Q.Cert(certA.id, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62, scheme="B1")
certE.sig = RA._sign(certE.msg, canon.CTX_CERT)
S1E = clone_with_signer(S1, skB, certE)
vr("G1-5e 白盒换 PK 证 fresh 拒（V9 bid 身份不匹配）", lambda: fresh(S1E, snap=snap0))

# ---- G1-6 应答域篡改全拒（签名重算层，M_resp5 覆盖全部七域+前缀） ----
resp, a_h, a_t, a_ts, a_ep, a_bid = RA.fresh_query(n32, RID)
xor = lambda b: bytes(x ^ 0xFF for x in b)               # noqa: E731
ok_tamper = True
for tampered in (
    canon.M_resp5(n32, RID, a_h, a_t, a_ts, a_ep, a_bid[::-1]),            # bid
    canon.M_resp5(n32, xor(RID), a_h, a_t, a_ts, a_ep, a_bid),             # RID
    canon.M_resp5(xor(n32), RID, a_h, a_t, a_ts, a_ep, a_bid),             # nonce
    canon.M_resp5(n32, RID, a_h[::-1], a_t, a_ts, a_ep, a_bid),             # 链头 h*
    canon.M_resp5(n32, RID, a_h, a_t + 1, a_ts, a_ep, a_bid),               # t*
    canon.M_resp5(n32, RID, a_h, a_t, a_ts + 1, a_ep, a_bid),               # ts
    canon.M_resp5(n32, RID, a_h, a_t, a_ts, a_ep + 1, a_bid),               # epoch
    b"QPRSS-v4|resp" + canon.M_resp5(n32, RID, a_h, a_t, a_ts, a_ep,
                                     a_bid)[13:],                            # v4 前缀
):
    if B1.verify(RA.pk, tampered, resp, canon.CTX_ANC):
        ok_tamper = False
record("G1-6 应答任一域篡改（bid/RID/nonce/h*/t*/ts/epoch/前缀）验签全拒", ok_tamper)
# verify 层无应答注入口（fresh 应答只由验证器现场向 RA 查询获得）：
# 外部应答不可作为参数传入 ⇒ 重放在验证器接口层无攻击面（结构性保证）。
try:
    Q.verify({"pk_ra": RA.pk}, S1, "fresh", ra=RA, nonce=n32, revsnap=snap0,
             resp=resp)
    record("G1-6b 验证器无应答注入口（外部应答不可传入 ⇒ 无重放面）", False,
           "accepted(!)")
except TypeError:
    record("G1-6b 验证器无应答注入口（外部应答不可传入 ⇒ 无重放面）", True)

# ---- G1-7 M_resp5 字节布局（逐域偏移；177B 与 v4 等长）----
m5 = canon.M_resp5(n32, RID, a_h, a_t, a_ts, a_ep, a_bid)
record("G1-7 M_resp5 布局 13+32+16+48+4+8+8+48=177（域偏移逐一命中）",
       len(m5) == 177 and m5[:13] == b"QPRSS-v5|resp"
       and m5[13:45] == n32 and m5[45:61] == RID and m5[61:109] == a_h
       and m5[109:113] == canon.enc32(a_t) and m5[113:121] == canon.enc64(a_ts)
       and m5[121:129] == canon.enc64(a_ep) and m5[129:177] == a_bid)

# ================= 链推进（G2 快照需 t≥1，否则回滚无从谈起） =================
P1 = pol.Policy(P0.adm, P0.w - {4}, P0.d - 1, N)
S2 = Q.redact(pp, S1, set(range(1, N + 1)) - {2}, P1, c_n, sk_n, 100)
m_reg = canon.M_reg(RID, RA.reg[RID]["ver"], RA.reg[RID]["h"],
                    RA.reg[RID]["ver"] + 1, S2.h_t, len(S2.log),
                    canon.H(c_n.msg), c_n.id, c_n.role)
RA.register(S2, B1.sign(sk_n, pk_n, m_reg, canon.CTX_REG), c_n)
record("G0 链推进后 reg t=1/ver=1（G2 前置）",
       RA.reg[RID]["t"] == 1 and RA.reg[RID]["ver"] == 1)

# ================= 任务 2：G2 旧状态恢复 fail-closed =================
snap_full = json.loads(RA.snapshot())


def try_restore(obj):
    try:
        Q.RA.restore(json.dumps(obj).encode())
        return ("ok", None)
    except Q.RestoreRefused as e:
        return ("RestoreRefused", str(e)[:80])
    except Exception as e:                          # noqa: BLE001
        return (type(e).__name__, str(e)[:80])


def variant(*ops):
    o = copy.deepcopy(snap_full)
    for op in ops:
        op(o)
    return o


def del_signers(o):
    o.pop("signers")


def del_ver(o):
    o.pop("ver")


def del_cid(o):
    o["reg"][RID.hex()].pop("cid")


def del_bid(o):
    o["reg"][RID.hex()].pop("bid")


def set_cid_none(o):
    o["reg"][RID.hex()]["cid"] = None


r1 = try_restore(variant(del_signers))
record("G2-1 旧快照缺 signers → RestoreRefused（不解释为空登记态）",
       r1[0] == "RestoreRefused", r1[1])
r2 = try_restore(variant(del_cid))
record("G2-2 旧快照 reg 缺 cid → RestoreRefused（非 KeyError 泄漏）",
       r2[0] == "RestoreRefused", r2[1])
r3 = try_restore(variant(del_bid))
record("G2-3 旧快照 reg 缺 bid → RestoreRefused", r3[0] == "RestoreRefused", r3[1])
r4 = try_restore(variant(set_cid_none))
record("G2-3b reg.cid=None（一轮旧形制）→ RestoreRefused", r4[0] == "RestoreRefused",
       r4[1])
r5 = try_restore(variant(del_ver))
record("G2-4 无版本号快照（冻结时代形制）→ RestoreRefused", r5[0] == "RestoreRefused",
       r5[1])
try:
    Q.RA.restore(b"not-json{")
    r6 = ("accepted", None)
except Q.RestoreRefused as e:
    r6 = ("RestoreRefused", str(e)[:80])
except Exception as e:                              # noqa: BLE001
    r6 = (type(e).__name__, str(e)[:80])
record("G2-4b 非 JSON/截断 blob → RestoreRefused（非崩溃）", r6[0] == "RestoreRefused",
       r6[1])


# ---- G2-5 登记状态冲突：signers 绑定与 reg.bid 互斥 ----
def conflict_signer(o):
    i = bytes.fromhex(o["signers"][0][1])
    o["signers"][0][1] = (i[:15] + b"\x99").hex()


def unregistered_binding(o):
    """issue-only 中间态：RID 有绑定、无登记（去掉 reg/log 中 RID 的痕迹）。"""
    del o["reg"][RID.hex()]
    o["log"] = [e for e in o["log"] if e[0] != RID.hex()]


def fake_bound_unregistered(o):
    unregistered_binding(o)
    o["signers"] = [[RID.hex(), (b"\x77" * 16).hex(), certA.pk.hex()]]


r7 = try_restore(variant(conflict_signer))
record("G2-5 signers 绑定异于 reg.bid（身份冲突）→ RestoreRefused",
       r7[0] == "RestoreRefused", r7[1])
# 反方向：signers 绑定未登记 rid = issue 先于 RegisterInitial 的合法中间态，
# 可恢复；但绑定若指向异 (id,pk)，其上 RegisterInitial 被 I1-bnd 拒。
r8 = try_restore(variant(unregistered_binding))
record("G2-5b issue-only 中间态（绑定未登记 rid）可恢复", r8[0] == "ok", r8[1])
ra_io = Q.RA.restore(json.dumps(variant(fake_bound_unregistered)).encode())
vr("G2-5c 恢复态上异 (id,pk) RegisterInitial 拒（I1-bnd）",
   lambda: ra_io.register_initial(S1, certA, sig_init), "I1-bnd",
   exc=Q.RedactRefused)


# ---- G2-6 恶意回滚：只回滚 reg（或只删 log 尾）→ 拒 ----
def rollback_reg(o):
    o["reg"][RID.hex()]["t"] = 0                    # reg 回滚，log 尾仍是真值


def drop_log_tail(o):
    o["log"] = o["log"][:-1]                        # 删尾条（证据缺失）


r9 = try_restore(variant(rollback_reg))
record("G2-6a 恶意回滚 reg（log 未回滚）→ RestoreRefused", r9[0] == "RestoreRefused",
       r9[1])
r10 = try_restore(variant(drop_log_tail))
record("G2-6b 删除登记日志尾条（证据缺失）→ RestoreRefused",
       r10[0] == "RestoreRefused", r10[1])

# ---- G2-7 完整新快照恢复：可用、唯一绑定保持、fresh 通 ----
RA2 = Q.RA.restore(RA.snapshot())
record("G2-7a 完整新快照恢复成功（reg/log/signers/epoch 保真）",
       RA2.reg[RID]["bid"] == canon.BindId(RID, certA.id, pkA)
       and RA2.reg[RID]["cid"] == canon.H(certA.msg)
       and RA2.signers == RA.signers and RA2.epoch == RA.epoch)
vr("G2-7b 恢复后换 (id,pk) 签发同 RID 拒（唯一绑定不可绕过）",
   lambda: RA2.issue(b"\x77" * 16, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62),
   step=None, exc=Q.IssuanceRefused)
record("G2-7c 恢复后同 (id,pk) 续签仍合法（不误伤）",
       RA2.issue(certA.id, certA.pk, b"signer", ((RID,), b"*"), 1, 1 << 62)
       .verify(RA2.pk))
record("G2-7d 恢复后 fresh accept（M_resp5+bid 链完整，t=1 工件）",
       Q.verify({"pk_ra": RA2.pk}, S2, "fresh", ra=RA2, nonce=os.urandom(32),
                revsnap=RA2.revocation_snapshot()) == "accept_fresh")

# ---- G2-8 身份替换闭环：旧路径（恢复旧快照→第二证→换证工件）由接受变拒绝 ----
# 冻结/一轮实现的攻击链（Task G/Q2 探针实证）：缺字段旧快照恢复为空 signers
# → 同 RID 异 (id,pk) 第二张 signer 证书诚实签出 → 换证工件 hist 复活。
# 本轮：链首（restore）即 RestoreRefused，后续 issue/hist 无从发生。
attacker_states = [variant(del_signers), variant(del_cid, del_bid), variant(del_ver)]
closed = all(try_restore(s)[0] == "RestoreRefused" for s in attacker_states)
record("G2-8 身份替换攻击链在恢复入口闭合（accept→RestoreRefused）", closed,
       f"{len(attacker_states)} 个旧形制快照全拒")

# ---- G2-9 不完整状态拒签发（_require_complete 门）----
ra_inc = Q.RA("B1")
ra_inc._complete = False
vr("G2-9a 不完整 RA 状态 issue 拒（IssuanceRefused）",
   lambda: ra_inc.issue(b"\x11" * 16, pkB, b"signer", ((RID,), b"*"), 0, 1 << 62),
   step=None, exc=Q.IssuanceRefused)
vr("G2-9b 不完整 RA 状态 fresh_query 拒",
   lambda: ra_inc.fresh_query(n32, RID), step=None, exc=Q.IssuanceRefused)
vr("G2-9c 不完整 RA 状态 register_initial 拒",
   lambda: ra_inc.register_initial(S1, certA, sig_init), step=None,
   exc=Q.IssuanceRefused)

# ---- G2-10 多线程签发同 RID：唯一绑定恰好一个赢家 ----
RA3 = Q.RA("B1")
keys = [B1.keygen() for _ in range(8)]
results = []
lk = threading.Lock()


def worker(i):
    _sk, pk = keys[i]
    try:
        c = RA3.issue(bytes([0x30 + i]) * 16, pk, b"signer", ((RID,), b"*"),
                      0, 1 << 62)
        ok = c.verify(RA3.pk)
    except Q.IssuanceRefused:
        ok = False
    with lk:
        results.append(ok)


threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
record("G2-10 多线程 8 路同 RID 异 (id,pk) 签发：恰 1 成功且绑定唯一",
       sum(results) == 1 and len(RA3.signers) == 1,
       f"ok={sum(results)}/8, bound={len(RA3.signers)}")

# 已绑定后并发续签同 (id,pk)：全部允许（同身份合法），状态无竞态损坏
bound_id, bound_pk = next(iter(RA3.signers.values()))
results2 = []


def worker2(_i):
    try:
        RA3.issue(bound_id, bound_pk, b"signer", ((RID,), b"*"), 0, 1 << 62)
        ok = True
    except Q.IssuanceRefused:
        ok = False
    with lk:
        results2.append(ok)


threads = [threading.Thread(target=worker2, args=(i,)) for i in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
record("G2-10b 绑定后 8 路并发同 (id,pk) 续签全成功且快照仍合法",
       all(results2) and len(RA3.signers) == 1
       and try_restore(json.loads(RA3.snapshot()))[0] == "ok")

R["verdict"] = "ALL_SF_GAPS_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "SF_GAPS_FAIL"
with open(os.path.join(os.path.dirname(HERE), "logs", "sf_gaps.json"), "w",
          encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(R["verdict"])
sys.exit(0 if R["verdict"] == "ALL_SF_GAPS_PASS" else 1)
