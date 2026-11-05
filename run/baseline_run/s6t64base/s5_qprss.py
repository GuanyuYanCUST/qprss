# -*- coding: utf-8 -*-
"""Stage-5.9 修复副本（Stage59_Patched）QPRSS 协议引擎。

基底 = RouteB_Stage5_冻结副本_20261013/src/s5（零改动引入），本副本只改
安全语义两处（导师约束：冻结原件不动，修复走新副本+独立测试+重新冻结）：

[P0.1 逐跳索引单调性] Verify 的 _check_hop_policy 增加首检
    I_new ⊆ I_prev（V7.1，与论文 V7.1 对齐——原稿本有、Stage-5.7 压缩丢失、
    冻结代码从未实现）；Redact 本地预检对偶增加 R0b。
    修复对象：复活字段攻击（前删改者用旧合法开启经真实授权 hop 重插已删索引，
    冻结实现 hist/snapshot/fresh/RA.register 全链接受——见
    tests/test_p0_1_resurrection_repro.py frozen 模式实测记录）。

[P0.2 撤销与时间语义] revlist/ref_ts 调用方参数废除，替换为：
    - RA.revoke(id16, eff_ts)：显式生效时间（与 e.ts 同一声明性墙钟域）；
      已撤销者同时被 RA 登记门拒绝（register/register_initial 查撤销表）；
    - RA.revocation_snapshot()：RA 签名的撤销快照（epoch + 逐 id eff_ts）；
    - verify(..., revsnap=(msg, sig))：只接受 RA 签名快照——调用者自报的
      撤销列表不再是可信输入（快照签名验证失败 = V5.3d 拒绝）；
    - V5.3d-window：三模式一律执行记录内窗口一致性（e.ts ∈ [nb, na]，
      数据全部来自记录本身，不依赖调用者时间源）；
    - V5.3d-rev：提供 revsnap 时，拒绝"声称时间 ≥ 撤销生效时间"的 hop
      （过去合法签署的记录不受其后撤销牵连——历史有效性 ≠ 当前授权）；
    - require_revsnap=True：需要可信撤销数据而未提供时明确拒绝（不再静默
      跳过却返回完整授权有效）。
    时间语义表与 API 合同见 02_RA撤销与时间语义修复.md。

[P0.2-r2 对抗复核修订（2026-10-14，16-agent 攻击/验证工作流 CONFIRMED 8 项）]
    - RA.register 新增 R3-rev：epoch 域逐签署者门（只查新增 hop）——被撤销者
      回填 ts 的 hop 原可经任一在权成员的登记混入公报/新鲜链头（red-h1-F1/
      SECREV1-F1，critical）；
    - RA.revoke eff_ts 必填 + 域校验 + 单调（red-h1-F2/SECREV1-F4/AUD-01/03：
      缺省 0 是"追溯到纪元零"而非"立即生效"，且未校验输入可崩 revsnap）；
    - verify 默认 require_revsnap：snapshot/fresh=True（SECREV1-F2：声称当前
      授权却零撤销数据=任务书禁止的静默模式）；
    - 锚定域绑定 epoch（M_resp3/M_gaz3）+ 过期 revsnap 拒绝（SECREV1-F3/
      AUD-04：旧快照回放掩盖撤销）；
    - verify V1.2 双向字段表一致（red-h1-F3：多余开启条目在 accept 对象上
      残留复活内容）；
    - RA.restore 旧快照 rev_eff 回填（AUD-02）；canon.parse_revsnap 截断守卫
      （AUD-03）。

[P0.4 签名核 XOF 回放修复] B1 路径经 s5_sig 切换 s4compat（冻结
s4_core.ShakeRng 缓冲拼接使 XOF 流自字节 126 起周期性回放——expand_A 的
多项式条目带 p[42+k]==p[k] 重复结构、sample_in_ball 支撑分布偏离均匀球；
见 s4compat.py 头注与 03号 §5）。

其余（V1–V9 编号、序列化 v5、RA 登记语义、Inv-W、tighten、三模式、
M_* 规范转录单一来源、schema_digest v4、SD-1）与冻结副本逐字一致。
原 Stage-5 文档：在 Step2B 医疗协议骨架（2B-0/2B-1/2B-2/2B-3 全部 59 项
测试验证的 V1–V9 语义）上换签名核：B1 = C2 MLWE 结构化承诺（commit_as 层，
C_j=G·r_j+D·H₂(j‖RID‖y_j)+η_j，q=12289，k=m=4，d=256，三元）+ B1-65 自定义
Fiat–Shamir-with-aborts（s4_fs，只读引入）；对照 AS/C 维持 ML-DSA-44。
诚实声明：B1 签名随机化（CSPRNG 掩码）——Σ 字节不跨运行可复现；只有显式
传入确定性 rng 才可复现，仅限测试。
"""

# [Stage-5.10.3 τ=64 候选] 本文件 = Stage-5.9 s5_qprss.py 副本（V1–V9、
# P0.1 逐跳单调性、P0.2/r2 撤销语义全部原样携带——A9′-1/A9′-2 修复即在
# 该两处）。本轮零语义改动：尺寸经 s5_sig.SIG_LEN 流动（B1 5,785→5,794），
# 仅两处注释同步；文件头/docstring 的协议描述逐字保留。
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import threading

from . import canon, commit_as, commit_c, merkle, policy  # noqa: E402
from .policy import Policy, AuthMember, ScopeMatchRID, ScopeMatchJ, tighten_ok, inv_w  # noqa: E402
from . import s5_sig  # noqa: E402

SIG = s5_sig.SIG_LEN          # {"B1":5794(τ=64),"AS":2420,"C":2420}
PKL = s5_sig.PK_LEN           # {"B1":3712,"AS":1312,"C":1312}
WITNESS_CORE = {"B1": 512, "AS": 512, "C": 32, "H": 32}
SCHEME_CHAR = {"B1": b"B", "AS": b"A", "C": b"C", "H": b"H"}
CHAR_SCHEME = {v: k for k, v in SCHEME_CHAR.items()}


class VerifyReject(Exception):
    def __init__(self, step, why=""):
        super().__init__(f"{step}: {why}")
        self.step = step


class RedactRefused(Exception):
    pass


def make_rng(seed: bytes):
    """种子化测试 PRNG——仅限测试复现模式。正式接口用 secure_rng。"""
    state = [0]

    def rng(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.shake_256(b"rng|" + seed + canon.enc32(state[0])).digest(64)
            state[0] += 1
        return out[:n]

    return rng


def secure_rng(n: int) -> bytes:
    return os.urandom(n)


# ---------------- 证书 ----------------

class Cert:
    """证书（RA 签发）。scheme 为证书所属签名核（'B1' 主方案；'AS'/'C' 对照）。"""

    def __init__(self, id16, pk, role: bytes, scope, nb: int, na: int, sig=b"",
                 scheme: str = "B1"):
        assert len(id16) == 16, f"id must be 16B, got {len(id16)}"
        assert scheme in ("B1", "AS", "C", "H")
        self.id, self.pk, self.role, self.scope = id16, pk, role, scope
        self.nb, self.na, self.sig, self.scheme = nb, na, sig, scheme
        if role == b"signer":
            self.msg = canon.M_certS(id16, pk, scope, nb, na)
        else:
            self.msg = canon.M_certR(id16, pk, role, scope, nb, na)

    def bytes(self):
        return self.sig + self.msg

    @staticmethod
    def h(cert, lam=None):
        return canon.H(cert.msg)

    def verify(self, pk_ra) -> bool:
        return s5_sig.core(self.scheme).verify(pk_ra, self.msg, self.sig, canon.CTX_CERT)


# ---------------- RA ----------------

class Superseded(Exception):
    pass


class RA:
    """注册机构：证书签发/撤销表/链头登记/FreshQuery/公报。
    scheme 默认 'B1'（主方案全栈自定义格）；'AS'/'C' 对照栈用 ML-DSA-44 RA。
    并发层级与 2B 相同：单进程 threading.Lock（进程内 CAS 仿真），不声称
    跨进程一致/生产级崩溃安全。"""

    def __init__(self, scheme: str = "B1"):
        self.scheme = scheme
        core = s5_sig.core(scheme)
        self.sk, self.pk = core.keygen()
        self.revoked = set()
        self.rev_eff = {}   # Stage-5.9：id16 -> eff_ts（撤销生效时间，e.ts 同域）
        self.epoch = 0
        self.reg = {}       # rid -> {h, t, I, P, ver}
        self.log = []       # 追加式登记日志
        self._lk = threading.Lock()

    def _sign(self, msg: bytes, ctx: bytes) -> bytes:
        core = s5_sig.core(self.scheme)
        return core.sign(self.sk, self.pk, msg, ctx)

    def _verify(self, pk, msg, sig, ctx) -> bool:
        return s5_sig.core(self.scheme).verify(pk, msg, sig, ctx)

    def issue(self, id16, pk, role, scope, nb, na) -> Cert:
        c = Cert(id16, pk, role, scope, nb, na, scheme=self.scheme)
        c.sig = self._sign(c.msg, canon.CTX_CERT)
        return c

    def revoke(self, id16, eff_ts: int = None):
        """Stage-5.9（P0.2-r2 修订）：撤销带显式生效时间 eff_ts（与 e.ts 同一
        声明性墙钟域）。语义：hop 声称时间 ≥ eff_ts ⟹ 撤销后授权（提供 revsnap
        时验证侧拒绝）；hop 声称时间 < eff_ts ⟹ 撤销前签署（revsnap 下不牵连）。

        eff_ts 必填（ValueError）：RA 在 e.ts 域没有可信时钟，"立即生效"无法
        隐式表达——显式传 eff_ts=0 表示刻意作废该身份全部历史（revsnap 消费
        下连已登记的撤销前 hop 也拒绝）；要保留历史，传 > 全部既往 hop 声明
        ts 的 eff_ts。epoch 域的即时撤销由登记门（R1-rev/R3-rev/I1-rev）承担。
        重复撤销不得降低已记录的 eff_ts（单调性）。"""
        if eff_ts is None:
            raise ValueError("eff_ts required: RA has no trusted clock in the "
                             "e.ts domain; pass explicit eff_ts (0 only as a "
                             "deliberate void-everything)")
        if not isinstance(eff_ts, int) or not 0 <= eff_ts < 2 ** 64:
            raise ValueError("eff_ts must be an integer in [0, 2^64)")
        with self._lk:
            if id16 in self.rev_eff and eff_ts < self.rev_eff[id16]:
                raise ValueError("re-revoke may not lower eff_ts (monotonic)")
            self.revoked.add(id16)
            self.rev_eff[id16] = eff_ts
            self.epoch += 1

    def revlist(self):
        with self._lk:
            msg = canon.M_revlist(self.epoch, sorted(self.revoked))
            return msg, self._sign(msg, canon.CTX_ANC)

    def revocation_snapshot(self):
        """Stage-5.9：可信撤销状态快照（RA 签名，CTX_ANC）。verify 的 revsnap
        参数只接受本产物——调用者自报的撤销列表不是可信输入。"""
        with self._lk:
            msg = canon.M_revsnap(self.epoch,
                                  [(i, self.rev_eff[i]) for i in sorted(self.revoked)])
            return msg, self._sign(msg, canon.CTX_ANC)

    # ---- 登记状态（16号 §一–§四 最终版；语义与 2B 逐字一致） ----
    def register_initial(self, S0, cert_s: Cert, sig_init: bytes):
        """RegisterInitial：signer 登记第零轮状态。先到者胜。"""
        with self._lk:
            rid, n = S0.rid, S0.n
            if cert_s.scheme != self.scheme:
                raise RedactRefused("I1 cert scheme mismatch")
            if not cert_s.verify(self.pk) or cert_s.role != b"signer" \
                    or not ScopeMatchRID(cert_s.scope, rid):
                raise RedactRefused("I1 bad signer cert")
            if cert_s.id in self.revoked:                      # Stage-5.9：登记门查撤销
                raise RedactRefused("I1-rev signer revoked")
            m = canon.M_reginit(rid, n, S0.acc0, S0.P0, canon.H(cert_s.msg), sd=S0.sd)
            if not self._verify(cert_s.pk, m, sig_init, canon.CTX_REG):
                raise RedactRefused("I1 σ_init invalid under authenticated pk")
            if S0.log or S0.h_t != canon.h0_of(rid, n, S0.acc0, S0.P0, sd=S0.sd):
                raise RedactRefused("I2 not a t=0 state")
            try:
                verify({"pk_ra": self.pk}, S0, "hist")          # RA 充当完整验证者
            except VerifyReject as e:
                raise RedactRefused(f"I2 full verify failed: {e}")
            if rid in self.reg:
                raise Superseded("I3: RID already registered")
            self.reg[rid] = dict(h=S0.h_t, t=0, I=set(S0.It), P=S0.P0, ver=0)
            self.log.append((rid, S0.h_t, 0, 0))
            return 0

    def register(self, S, sig_reg: bytes, cert_req: Cert):
        """R1–R5：登记合法扩展；并发分叉=先到者胜，后到 Superseded。"""
        with self._lk:
            rid = S.rid
            if rid not in self.reg:
                raise RedactRefused("unregistered RID (RegisterInitial first)")
            st = self.reg[rid]
            if cert_req.scheme != self.scheme or not cert_req.verify(self.pk):
                raise RedactRefused("R1 cert not RA-signed")
            if cert_req.id in self.revoked:                    # Stage-5.9：登记门查撤销
                raise RedactRefused("R1-rev redactor revoked")
            t_new = len(S.log)
            if t_new <= st["t"]:
                raise Superseded(f"R2: no strict extension (t_new={t_new} ≤ t_reg={st['t']})")
            m = canon.M_reg(rid, st["ver"], st["h"], st["ver"] + 1, S.h_t, t_new,
                            canon.H(cert_req.msg), cert_req.id, cert_req.role)
            if not self._verify(cert_req.pk, m, sig_reg, canon.CTX_REG):
                raise RedactRefused("R1 σ_req invalid under authenticated pk (stale or forged)")
            if cert_req.role != b"signer" and not AuthMember(cert_req.role, cert_req.id, st["P"].adm):
                raise RedactRefused("R1 not authorized under registered policy")
            try:                                                    # Fix 4(i)：完整 V1–V8
                verify({"pk_ra": self.pk}, S, "hist")
            except VerifyReject as e:
                raise RedactRefused(f"R3 full verify failed: {e}")
            # P0.2-r2（red-h1-F1/SECREV1-F1）：epoch 域逐跳签署者门——只查
            # 本次新增的 hop（S.log[st.t:]，已登记的撤销前 hop 不追溯）。
            # 声明 ts 不可信（可回填），故忽略 ts、只认撤销表；否则被撤销者
            # 回填 ts 的 hop 可经任一在权成员的登记混入公报/新鲜链头。
            for (_, _, cid_b) in S.log[st["t"]:]:
                cert_b = S.certs.get(cid_b)
                if cert_b is not None and cert_b.id in self.revoked:
                    raise RedactRefused(
                        "R3-rev: new hop signed by revoked identity "
                        "(declared ts is untrusted; epoch domain)")
            h = canon.h0_of(rid, S.n, S.acc0, S.P0, sd=S.sd)          # Fix 4(ii)：前缀绑定（含 sd）
            for (e_b, _, _) in S.log[: st["t"]]:
                h = canon.hi_of(e_b, h)
            if h != st["h"]:
                raise RedactRefused("R2 prefix head mismatch (fork)")
            st.update(h=S.h_t, t=t_new, I=set(S.It), P=S.Pt, ver=st["ver"] + 1)   # R4/R5
            self.log.append((rid, S.h_t, t_new, st["ver"]))
            return st["ver"]

    # ---- 最新性来源 ----
    def fresh_query(self, nonce: bytes, rid):
        """P0.2-r2：响应绑定 RA.epoch（M_resp3）——验证器据以拒绝过期 revsnap。"""
        with self._lk:
            st = self.reg.get(rid)
            if st is None:
                raise RedactRefused("no registration for RID")
            ts = int.from_bytes(hashlib.shake_256(b"ts" + st["h"]).digest(4), "big")
            resp = self._sign(canon.M_resp3(nonce, rid, st["h"], st["t"], ts,
                                             self.epoch), canon.CTX_ANC)
            return resp, st["h"], st["t"], ts, self.epoch

    def gazette(self, period: int, rid):
        """P0.2-r2：公报绑定 RA.epoch（M_gaz3）——同上。"""
        with self._lk:
            st = self.reg.get(rid)
            ts = int.from_bytes(hashlib.shake_256(b"gazts" + st["h"]).digest(4), "big")
            g = self._sign(canon.M_gaz3(period, rid, st["h"], st["t"], ts,
                                         self.epoch), canon.CTX_ANC)
            return g, st["h"], st["t"], ts, period, self.epoch

    # ---- 状态持久化（进程重启连续性；非事务性，不声称生产级崩溃安全） ----
    def snapshot(self) -> bytes:
        with self._lk:
            reg = {rid.hex(): dict(h=st["h"].hex(), t=st["t"], ver=st["ver"], n=st["P"].n,
                                   P=canon.encP(st["P"]).hex(), I=sorted(st["I"]))
                   for rid, st in self.reg.items()}
            log = [[r.hex(), h.hex(), t, v] for (r, h, t, v) in self.log]
            return json.dumps(dict(scheme=self.scheme, pk=self.pk.hex(), sk=self.sk.hex(),
                                   revoked=[x.hex() for x in sorted(self.revoked)],
                                   rev_eff=[[k.hex(), v] for k, v in sorted(self.rev_eff.items())],
                                   epoch=self.epoch, reg=reg, log=log)).encode()

    @classmethod
    def restore(cls, blob: bytes):
        o = json.loads(blob)
        ra = cls.__new__(cls)
        ra.scheme = o.get("scheme", "AS")          # 旧快照无 scheme 字段=2B 时代
        ra.pk, ra.sk = bytes.fromhex(o["pk"]), bytes.fromhex(o["sk"])
        ra.revoked = {bytes.fromhex(x) for x in o["revoked"]}
        ra.rev_eff = {bytes.fromhex(k): v for (k, v) in o.get("rev_eff", [])}
        for x in ra.revoked:                       # P0.2-r2（AUD-02）：旧快照回填
            ra.rev_eff.setdefault(x, 0)
        ra.epoch = o["epoch"]
        ra._lk = threading.Lock()
        ra.reg = {}
        for ridh, st in o["reg"].items():
            P, _ = dec_encP(bytes.fromhex(st["P"]), 0, st["n"])
            ra.reg[bytes.fromhex(ridh)] = dict(h=bytes.fromhex(st["h"]), t=st["t"],
                                               I=set(st["I"]), P=P, ver=st["ver"])
        ra.log = [(bytes.fromhex(r), bytes.fromhex(h), t, v) for (r, h, t, v) in o["log"]]
        return ra


def _check_hop_cert(rid, i, hop, cert, h_prev, e_bytes, tau, pk_ra, scheme,
                    selfverify=False):
    if not selfverify and not cert.verify(pk_ra):
        raise VerifyReject("V5.1", "cert not RA-signed")
    if hop["id"] != cert.id or hop["role"] != cert.role:
        raise VerifyReject("V5.2", "log/cert identity mismatch")
    if not s5_sig.core(scheme).verify(
            cert.pk, canon.M_red(rid, i, e_bytes, h_prev, canon.hi_of(e_bytes, h_prev)),
            tau, canon.CTX_RED):
        raise VerifyReject("V5.4", "tau invalid")


def forge_hop(S, I_new, P_new: Policy, redactor: Cert, sk, ts: int, e_id=None):
    """攻击者版 Redact：跳过全部本地预检（Redact 在攻击者手里无强制力）。"""
    n = S.n
    i = len(S.log) + 1
    cid = canon.H(redactor.msg)
    e_bytes = canon.enc_e(i, e_id or redactor.id, redactor.role, cid, S.It, set(I_new),
                          S.Pt, P_new, ts, n)
    h_new = canon.hi_of(e_bytes, S.h_t)
    tau = s5_sig.core(S.scheme).sign(sk, redactor.pk,
                                     canon.M_red(S.rid, i, e_bytes, S.h_t, h_new),
                                     canon.CTX_RED)
    S2 = Sigma(S.scheme, S.rid, n)
    S2.sd = S.sd
    S2.acc0, S2.P0, S2.sigma0, S2.cert_s = S.acc0, S.P0, S.sigma0, S.cert_s
    S2.It = set(I_new)
    S2.fields = {j: S.fields[j] for j in S2.It}
    S2.Pt = P_new
    S2.log = S.log + [(e_bytes, tau, cid)]
    S2.certs = dict(S.certs)
    S2.certs.setdefault(cid, redactor)
    S2.h_t = h_new
    return S2


def _check_hop_policy(n, hop, cert, rid, removed, I_prev, P_prev, I_new, P_new):
    if not I_new <= I_prev:
        # P0.1（Stage-5.9）：逐跳索引单调性——删改只许移除索引。缺失本检查时，
        # 旧合法开启（静态见证对 acc0 验证）可经真实授权 hop 重插已删字段。
        raise VerifyReject("V7.1", "index resurrection: I_new ⊄ I_prev")
    if not removed:
        raise VerifyReject("V7.1", "empty redaction J=∅")   # SD-1：空删除被禁
    if not removed <= P_prev.w:
        raise VerifyReject("V7.2", "deleted non-whitelisted index")
    if not P_prev.K <= I_new:
        raise VerifyReject("V7.3", "mandatory field deleted")
    if not inv_w(I_new, P_new):
        raise VerifyReject("V7.4", "Inv-W violated")
    if not P_new.holds(I_new):
        raise VerifyReject("V7.5", "P_i(I_i) != 1")
    if not tighten_ok(P_new, P_prev):
        raise VerifyReject("V7.6", "not a tightening")
    if not (AuthMember(hop["role"], hop["id"], P_prev.adm)
            and ScopeMatchRID(cert.scope, rid) and ScopeMatchJ(cert.scope, removed)):
        raise VerifyReject("V7.7", "authorization failed")


# ---------------- Σ ----------------

class Sigma:
    def __init__(self, scheme, rid, n):
        assert scheme in ("B1", "AS", "C", "H")
        self.scheme = scheme            # "B1"（主）| "AS" | "C"（对照）
        self.rid, self.n = rid, n
        self.sd = None                  # schema_digest（v4；None=未绑定语义映射）
        self.acc0 = None                # 初态块
        self.P0 = None
        self.sigma0 = None
        self.cert_s = None
        self.It = set()
        self.fields = {}                # j -> (y, witness)
        self.Pt = None
        self.h_t = None
        self.log = []                   # [(e_bytes, tau, certH)]
        self.certs = {}                 # certH -> Cert（去重表）
        self.anchor = None              # 仅 legacy 反例用

    # ---------- 序列化 v5（=2B v4 + scheme 字节 'B' 与按 scheme 长度分派） ----------
    # flags bit0=含 Cert_S；bit1=v3+（enc32(j)‖enc32(len)‖y）；bit2=含 sd（48B）。
    # B1：sigma0/tau=5,794 B（τ=64 候选）、证书内 pk=3,712 B、见证核 r‖η 2-bit=512 B（与 AS 同，
    # 因承诺层同构 C2）。结构/顺序/编码与 2B v4 逐字段一致。

    def serialize(self, include_cert_s=True) -> bytes:
        js = sorted(self.It)
        I0 = set(range(1, self.n + 1))
        flags = (1 if include_cert_s else 0) | 2 | (4 if self.sd else 0)
        head = (self.rid + canon.enc32(self.n)
                + SCHEME_CHAR[self.scheme]
                + bytes([flags])
                + canon.enc32(len(js)) + canon.enc32(len(self.log)) + canon.enc32(len(self.certs))
                + (self.sd if self.sd else b"")
                + self.acc0 + canon.encP(self.P0) + canon.bmp(I0, self.n)
                + canon.encP(self.Pt) + self.h_t)
        body_y = b"".join(canon.enc_field(j, self.fields[j][0]) for j in js)
        body_w = b"".join(self.fields[j][1].core_bytes() for j in js)
        body_p = b"".join(b"".join(self.fields[j][1].path) for j in js)
        body_e = b"".join(e for (e, _, _) in self.log)
        body_t = b"".join(tau for (_, tau, _) in self.log)
        body_c = b"".join(self.certs[c].bytes() for c in sorted(self.certs))
        out = head + self.sigma0
        if include_cert_s:
            out += self.cert_s.bytes()
        return out + body_y + body_w + body_p + body_e + body_t + body_c

    @staticmethod
    def deserialize(data: bytes):
        S, _ = parse_sigma(data)
        return S


class ASWitness:
    """C2 承诺见证：(2-bit 打包 r‖η, Merkle 路径)。B1 与 AS 共用（同一承诺层）。"""
    __slots__ = ("packed", "path")

    def __init__(self, packed, path):
        self.packed, self.path = packed, path

    def core_bytes(self):
        return self.packed

    def bytes(self):
        return self.packed + b"".join(self.path)


class CWitness:
    """基线 C 见证：(盐, Merkle 路径)。"""
    __slots__ = ("salt", "path")

    def __init__(self, salt, path):
        self.salt, self.path = salt, path

    def core_bytes(self):
        return self.salt

    def bytes(self):
        return self.salt + b"".join(self.path)


# ---------------- Setup / Signing ----------------

def setup(scheme: str = "B1", seed: bytes = None):
    """参数生成。B1/AS：C2 承诺层 pp（G,D ∈ R_q^{4×4}，D 可逆真实检查+重采样，
    系数拒绝采样精确均匀——2B-3 P0）；C：无代数 pp（盐+哈希）。
    seed=None（正式）→ CSPRNG；固定 seed 仅测试复现。"""
    assert scheme in ("B1", "AS", "C", "H")
    if scheme in ("C", "H"):
        cfg_pp["G"], cfg_pp["D"] = None, None
        return dict(scheme=scheme)
    if seed is None:
        seed = secure_rng(32)
    G, D, iters = commit_as.sample_pp_checked(seed)
    cfg_pp["G"], cfg_pp["D"] = G, D
    return dict(scheme=scheme, G=G, D=D, resample_iters=iters)


def signing(pp, sk_s, cert_s, rid, ys: dict, P0: Policy, rng=None,
            schema_digest=None, sig_rng=None) -> Sigma:
    """原始医生签名。ys: j -> y(bytes)（FHIR canonical_json 产物）。
    rng：承诺随机带（None=secure_rng）；sig_rng：B1 签名掩码 rng（None=CSPRNG；
    显式确定性 rng 仅测试复现模式）。"""
    if rng is None:
        rng = secure_rng
    scheme = pp["scheme"]
    n = P0.n
    S = Sigma(scheme, rid, n)
    S.sd = schema_digest
    S.P0, S.cert_s = P0, cert_s
    S.It = set(range(1, n + 1))
    S.Pt = P0.copy()
    if scheme in ("B1", "AS"):
        def leaf(j):
            r = commit_as.ternary_rand(rng(64))
            eta = commit_as.ternary_rand(rng(64))
            C = commit_as.commit(pp["G"], pp["D"], j, rid, ys[j], r, eta)
            S.fields[j] = (ys[j], ASWitness(commit_as.pack_witness(r, eta), None))
            return commit_as.leaf_of(j, C)
    else:
        def leaf(j):
            salt = commit_c.new_salt(rng)
            S.fields[j] = (ys[j], CWitness(salt, None))
            return commit_c.leaf_of(j, salt, ys[j])

    tree = merkle.make_tree(n, leaf)
    S.acc0 = tree.root
    for j in S.It:
        S.fields[j][1].path = tree.path(j - 1)
    S.sigma0 = s5_sig.core(scheme).sign(
        sk_s, cert_s.pk, canon.M_orig(rid, n, S.acc0, P0, S.It, sd=S.sd),
        canon.CTX_ORIG, rng=sig_rng)
    S.h_t = canon.h0_of(rid, n, S.acc0, P0, sd=S.sd)
    return S


# ---------------- Redact ----------------

def redact(pp, S: Sigma, I_new, P_new: Policy, redactor: Cert, sk_r, ts: int,
           *, legacy=False, sig_rng=None):
    """诚实 Redact（本地预检 R0/R0b/R1–R6（R0b=Stage-5.9 复活对偶））。"""
    n = S.n
    removed = S.It - set(I_new)
    if not set(I_new) <= S.It:
        # P0.1（Stage-5.9）：诚实 Redact 的对偶预检——新索引集只许是当前索引
        # 集的子集（V7.1 的签名端对偶；攻击者可绕过本地预检，故 Verify 侧同检）。
        raise RedactRefused("R0b index resurrection (I_new ⊄ I_t)")
    if not removed:
        raise RedactRefused("R0 empty redaction (J=∅)")   # SD-1：与 V7.1 对偶
    if not removed <= S.Pt.w:
        raise RedactRefused("R1 removed ⊄ W")
    if not S.Pt.K <= set(I_new):
        raise RedactRefused("R2 mandatory kept")
    if not legacy and not inv_w(I_new, P_new):
        raise RedactRefused("R3 Inv-W")
    if not legacy and not P_new.holds(I_new):
        raise RedactRefused("R4 P_new(I_new)!=1")
    if not tighten_ok(P_new, S.Pt):
        raise RedactRefused("R5 not tightening")
    if not (AuthMember(redactor.role, redactor.id, S.Pt.adm)
            and ScopeMatchRID(redactor.scope, S.rid) and ScopeMatchJ(redactor.scope, removed)):
        raise RedactRefused("R6 auth")
    i = len(S.log) + 1
    cid = canon.H(redactor.msg)
    e_bytes = canon.enc_e(i, redactor.id, redactor.role, cid, S.It, set(I_new),
                          S.Pt, P_new, ts, n)
    h_new = canon.hi_of(e_bytes, S.h_t)
    tau = s5_sig.core(S.scheme).sign(
        sk_r, redactor.pk, canon.M_red(S.rid, i, e_bytes, S.h_t, h_new),
        canon.CTX_RED, rng=sig_rng)
    S2 = Sigma(S.scheme, S.rid, n)
    S2.sd = S.sd
    S2.acc0, S2.P0, S2.sigma0, S2.cert_s = S.acc0, S.P0, S.sigma0, S.cert_s
    S2.It = set(I_new)
    S2.fields = {j: S.fields[j] for j in S2.It}
    S2.Pt = P_new
    S2.log = S.log + [(e_bytes, tau, cid)]
    S2.certs = dict(S.certs)
    if cid not in S2.certs:
        S2.certs[cid] = redactor
    S2.h_t = h_new
    return S2


# ---------------- e / 证书解析 ----------------

def dec_encP(buf, off, n):
    adm_len = buf[off]
    off += 1
    adm = []
    for _ in range(adm_len):
        code, tag = buf[off], buf[off + 1]
        off += 2
        if tag == 1:
            pat = b"*"
        else:
            cnt = buf[off]
            off += 1
            pat = tuple(buf[off + 16 * k: off + 16 * (k + 1)] for k in range(cnt))
            off += 16 * cnt
        adm.append((canon.ROLE_BY_CODE[code], pat))
    B = (n + 7) // 8
    w = canon.bmp_decode(buf[off:off + B], n)
    off += B
    d = struct.unpack(">I", buf[off:off + 4])[0]
    off += 4
    return Policy(adm, w, d, n), off


def dec_e_at(buf, off, n):
    lam = len(canon.H(b""))
    seq = struct.unpack(">I", buf[off:off + 4])[0]
    id16 = buf[off + 4:off + 20]
    role = canon.ROLE_BY_CODE[buf[off + 20]]
    cert_h = buf[off + 21:off + 21 + lam]
    p = off + 22 + lam
    B = (n + 7) // 8
    I_prev = canon.bmp_decode(buf[p:p + B], n)
    p += B
    I_new = canon.bmp_decode(buf[p:p + B], n)
    p += B
    P_prev, p = dec_encP(buf, p, n)
    P_new, p = dec_encP(buf, p, n)
    ts = struct.unpack(">Q", buf[p:p + 8])[0]
    p += 8
    return dict(seq=seq, id=id16, role=role, certH=cert_h,
                I_prev=I_prev, I_new=I_new, P_prev=P_prev, P_new=P_new, ts=ts), p


def dec_e(e_bytes, n):
    return dec_e_at(e_bytes, 0, n)[0]


def dec_cert_at(buf, off, scheme):
    """解析证书字节（sig ‖ msg）；返回 (Cert, 结束偏移)。重编码必须逐字节一致。
    sig/pk 长度按 scheme 分派（B1: 5,785/3,712；AS/C: 2,420/1,312）。"""
    p = off
    sig = buf[p:p + SIG[scheme]]
    p += SIG[scheme]
    if buf[p:p + 14] not in (b"QPRSS-v2|certS", b"QPRSS-v2|certR"):
        raise ValueError("bad cert prefix")
    is_signer = buf[p:p + 14] == b"QPRSS-v2|certS"
    id16 = buf[p + 14:p + 30]
    pk = buf[p + 30:p + 30 + PKL[scheme]]
    q = p + 30 + PKL[scheme]
    rolecode = buf[q]
    q += 1
    role = b"signer" if is_signer else canon.ROLE_BY_CODE[rolecode]
    if buf[q] == 1:
        rids, q = b"*", q + 1
    else:
        cnt = buf[q + 1]
        rids = tuple(buf[q + 2 + 16 * k: q + 2 + 16 * (k + 1)] for k in range(cnt))
        q += 2 + 16 * cnt
    if buf[q] == 1:
        jset, q = b"*", q + 1
    else:
        cnt = buf[q + 1]
        jset = {struct.unpack(">H", buf[q + 2 + 2 * k: q + 4 + 2 * k])[0] for k in range(cnt)}
        q += 2 + 2 * cnt
    nb = struct.unpack(">Q", buf[q:q + 8])[0]
    na = struct.unpack(">Q", buf[q + 8:q + 16])[0]
    q += 16
    c = Cert(id16, pk, role, (rids, jset), nb, na, scheme=scheme)
    c.sig = sig
    assert c.msg == buf[p:q], "cert re-encode mismatch"
    return c, q


def parse_sigma(data: bytes):
    """反序列化 + 分节核算。返回 (Sigma, sections=[(名称, 起, 止)])。
    偏移全部来自真实字节流解析位置（实测口径，非公式）。"""
    sec = []
    lam = len(canon.H(b""))
    rid = data[0:16]
    n = struct.unpack(">I", data[16:20])[0]
    if data[20:21] not in CHAR_SCHEME:
        raise ValueError(f"unknown scheme byte {data[20:21]!r}")
    scheme = CHAR_SCHEME[data[20:21]]
    incl = data[21] & 1
    if not data[21] & 2:
        raise ValueError("legacy v2 stream unsupported")
    r_cnt = struct.unpack(">I", data[22:26])[0]
    t_cnt = struct.unpack(">I", data[26:30])[0]
    u_cnt = struct.unpack(">I", data[30:34])[0]
    p = 34
    sd = None
    if data[21] & 4:                                # v4：可选 schema_digest
        if p + lam > len(data):
            raise ValueError("schema digest truncated")
        sd = data[p:p + lam]
        p += lam
    acc0 = data[p:p + lam]
    p += lam
    P0, p = dec_encP(data, p, n)
    p += (n + 7) // 8                                    # I₀ 位图（验证时重导出）
    Pt, p = dec_encP(data, p, n)
    h_t = data[p:p + lam]
    p += lam
    sec.append(("header", 0, p))
    sigma0 = data[p:p + SIG[scheme]]
    p += SIG[scheme]
    sec.append(("sigma0", sec[-1][2], p))
    S = Sigma(scheme, rid, n)
    S.sd = sd
    S.acc0, S.P0, S.Pt, S.h_t, S.sigma0 = acc0, P0, Pt, h_t, sigma0
    if incl:
        S.cert_s, p = dec_cert_at(data, p, scheme)
        sec.append(("cert_s", sec[-1][2], p))
    # idx+y 块（v3+：enc32(j)‖enc32(len)‖y，可变长）
    y_off = p
    js, ys = [], []
    for _ in range(r_cnt):
        j, y, y_off = canon.dec_field(data, y_off)
        js.append(j)
        ys.append(y)
    sec.append(("fields:idx+y", p, y_off))
    # 见证核心块（B1/AS=2-bit 打包 r‖η 512 B；C=盐 32 B）
    core_len = WITNESS_CORE[scheme]
    w_off = y_off + r_cnt * core_len
    sec.append(("fields:witness-core", y_off, w_off))
    # Merkle 路径块
    depth = (n - 1).bit_length()
    p_off = w_off + r_cnt * depth * lam
    sec.append(("fields:merkle-path", w_off, p_off))
    # e 块 + τ 块
    e_off = p_off
    hops = []
    for _ in range(t_cnt):
        hop, e_end = dec_e_at(data, e_off, n)
        hops.append((data[e_off:e_end], hop))
        e_off = e_end
    sec.append(("audit:e", p_off, e_off))
    tau_off = e_off + t_cnt * SIG[scheme]
    sec.append(("audit:tau", e_off, tau_off))
    # 证书表块
    c_off = tau_off
    certs = []
    for _ in range(u_cnt):
        c, c_end = dec_cert_at(data, c_off, scheme)
        certs.append(c)
        c_off = c_end
    sec.append(("certs", tau_off, c_off))
    assert c_off == len(data), f"trailing bytes: {len(data) - c_off}"
    # 组装
    for k, j in enumerate(js):
        path = [data[w_off + (k * depth + d) * lam: w_off + (k * depth + d + 1) * lam]
                for d in range(depth)]
        core = data[y_off + k * core_len: y_off + (k + 1) * core_len]
        wit = ASWitness(core, path) if scheme in ("B1", "AS") else CWitness(core, path)
        S.fields[j] = (ys[k], wit)
    S.It = set(js)
    for k, (e_bytes, hop) in enumerate(hops):
        tau = data[e_off + k * SIG[scheme]: e_off + (k + 1) * SIG[scheme]]
        S.log.append((e_bytes, tau, hop["certH"]))
    for c in certs:
        S.certs[canon.H(c.msg)] = c
    return S, sec


# ---------------- Verify ----------------

def verify(cfg, S: Sigma, mode="hist", *, ra=None, nonce=None, gazettes=None,
           legacy_selfverify=False, legacy_no_invw=False, legacy_presented_anchor=False,
           revsnap=None, require_revsnap=None, expected_sd=None, legacy_no_sd=False):
    """cfg = {"pk_ra": bytes}（+ 模块级 cfg_pp，setup 时设置）。
    V1–V9 与冻结副本一致（除下述 Stage-5.9 撤销/时间语义）；签名核按
    S.scheme 分派。返回 accept_*；非法抛 VerifyReject(step)。

    Stage-5.9 撤销与时间语义（P0.2，r2 修订）：
    - revsnap = (msg, sig)：必须是 RA.revocation_snapshot() 的产物——
      签名经 pk_ra 验证，否则 V5.3d 拒绝（调用者自报撤销列表不可信）；
    - V5.3d-window（三模式一律）：每跳声明 ts ∈ [cert.nb, cert.na]
      （记录内一致性，全部数据来自记录本身）；
    - V5.3d-rev（提供 revsnap 时）：声明 ts ≥ eff_ts 的 hop 被拒
      （撤销后授权）；声明 ts < eff_ts 的 hop 不受其后撤销牵连
      （历史有效性 ≠ 当前授权——三模式一致语义）；
    - require_revsnap 默认 None → snapshot/fresh 为 True、hist 为 False：
      声称当前授权的模式缺可信撤销状态即 V5.3d 拒绝（不静默返回完整
      授权有效）；hist 合同本就不含当前授权声明，保持允许。显式传
      False/False 可覆盖（调用者自担语义）；
    - 过期快照（P0.2-r2，SECREV1-F3）：fresh/snapshot 锚（M_resp3/M_gaz3）
      携带 RA.epoch；revsnap 的 epoch < 锚 epoch ⟹ V5.3d 拒（旧快照
      回放掩盖撤销）。legacy v2 锚无 epoch 可比对（legacy 语义保留）；
    - snapshot/fresh 的当前性防线 = RA 登记门（R1-rev 登记者 + R3-rev
      新增 hop 逐签署者，epoch 域）+ 链头锚定（未登记分叉到不了 V9）
      + revsnap（ts 域，纵深防御）。
    """
    n, rid = S.n, S.rid
    pk_ra = cfg["pk_ra"]
    core = s5_sig.core(S.scheme)

    if require_revsnap is None:               # P0.2-r2（SECREV1-F2）：
        require_revsnap = mode in ("snapshot", "fresh")   # 当前性声明需撤销状态
    rev_policy, rv_epoch = None, None
    if revsnap is not None:
        rv_msg, rv_sig = revsnap
        if not core.verify(pk_ra, rv_msg, rv_sig, canon.CTX_ANC):
            raise VerifyReject("V5.3d", "revocation snapshot not RA-signed "
                                      "(caller self-reported lists are not trusted)")
        try:
            rv_epoch, rev_policy = canon.parse_revsnap(rv_msg)
        except (ValueError, struct.error) as e:
            raise VerifyReject("V5.3d", f"malformed revocation snapshot: {e}")
    if require_revsnap and revsnap is None:
        raise VerifyReject("V5.3d", "trusted revocation state required "
                                  "but not supplied (refuse, not silent-skip)")

    # V1
    if S.acc0 is None or S.P0 is None or S.sigma0 is None or S.cert_s is None:
        raise VerifyReject("V1.2", "initial block incomplete")
    if not S.It <= set(range(1, n + 1)):
        raise VerifyReject("V1.1", "index out of range")

    # V2.1
    cert_s = S.cert_s
    if legacy_selfverify:
        pk_s = cert_s.pk
    else:
        if cert_s.scheme != S.scheme:
            raise VerifyReject("V2.1", "Cert_S scheme mismatch")
        if not cert_s.verify(pk_ra):
            raise VerifyReject("V2.1", "Cert_S not RA-signed")
        if cert_s.role != b"signer":
            raise VerifyReject("V2.1-role", "cert role != signer")
        if not ScopeMatchRID(cert_s.scope, rid):
            raise VerifyReject("V2.1-scope", "RID not in Cert_S scope")
        pk_s = cert_s.pk

    # V2.2 / V2.3
    if expected_sd is not None and S.sd != expected_sd:
        if not (S.sd is None and legacy_no_sd):
            raise VerifyReject("V2.2", "schema digest missing or mismatch "
                                      "(pinned mode requires signed schema)")
    if not core.verify(pk_s, canon.M_orig(rid, n, S.acc0, S.P0, set(range(1, n + 1)), sd=S.sd),
                       S.sigma0, canon.CTX_ORIG):
        raise VerifyReject("V2.2", "sigma0 invalid")
    h = canon.h0_of(rid, n, S.acc0, S.P0, sd=S.sd)

    # V3/V4 承诺与 Merkle（B1/AS 同一 C2 承诺层；C 盐+哈希）
    # P0.2-r2（red-h1-F3）：字段表与保留索引集双向一致——多余条目（含已删
    # 字段的合法开启）使 in-process 消费者在 accept 后读到复活内容，拒。
    if not set(S.fields) <= S.It:
        raise VerifyReject("V1.2", "fields table contains non-retained indices")
    for j in sorted(S.It):
        if j not in S.fields:                    # Stage-5.9：缺开启的畸形 Σ 干净拒绝
            raise VerifyReject("V1.2", f"missing opening for retained field {j}")
        y, w = S.fields[j]
        if S.scheme in ("B1", "AS"):
            r, eta = commit_as.unpack_witness(w.packed)
            if not (commit_as.norm_inf_ok(r) and commit_as.norm_inf_ok(eta)):
                raise VerifyReject("V3.1", "norm bound")
            C = commit_as.commit(cfg_pp["G"], cfg_pp["D"], j, rid, y, r, eta)
            leaf = commit_as.leaf_of(j, C)
        else:
            leaf = commit_c.leaf_of(j, w.salt, y)
        ok, root = merkle.MerkleTree.verify_path(leaf, j - 1, w.path, None)
        if not ok or root != S.acc0:
            raise VerifyReject("V4", f"merkle path field {j}")

    # V5/V6/V7 逐跳
    I_prev_state, P_state = set(range(1, n + 1)), S.P0
    used_certs = set()
    for i, (e_bytes, tau, cid) in enumerate(S.log, start=1):
        hop = dec_e(e_bytes, n)
        if hop["seq"] != i:
            raise VerifyReject("V6", "seq")
        cert = S.certs.get(cid)
        if cert is None or canon.H(cert.msg) != cid:
            raise VerifyReject("V5.1", "cert table ref")
        if cert.scheme != S.scheme:
            raise VerifyReject("V5.1", "cert scheme mismatch")
        _check_hop_cert(rid, i, hop, cert, h, e_bytes, tau, pk_ra, S.scheme,
                        selfverify=legacy_selfverify)
        used_certs.add(cid)
        # V5.3d-window：记录内窗口一致性（声明 ts ∈ [nb, na]，三模式一律；
        # 全部输入来自记录本身，不依赖调用者时间源）。
        if not (cert.nb <= hop["ts"] <= cert.na):
            raise VerifyReject("V5.3d-window", "hop declared ts outside cert window")
        # V5.3d-rev：可信撤销快照下，声明时间 ≥ 生效时间的 hop 被拒；
        # 之前的 hop（ts < eff_ts）不受其后撤销牵连（历史有效性 ≠ 当前授权）。
        if rev_policy is not None:
            for (rev_id, eff_ts) in rev_policy:
                if cert.id == rev_id and hop["ts"] >= eff_ts:
                    raise VerifyReject("V5.3d-rev",
                                       "redactor revoked at declared hop time")
        removed = hop["I_prev"] - hop["I_new"]
        if hop["I_prev"] != I_prev_state or hop["P_prev"].adm != P_state.adm \
                or hop["P_prev"].w != P_state.w or hop["P_prev"].d != P_state.d:
            raise VerifyReject("V6", "chain state mismatch")
        if not legacy_no_invw:
            _check_hop_policy(n, hop, cert, rid, removed, hop["I_prev"], hop["P_prev"],
                              hop["I_new"], hop["P_new"])
        else:
            if not removed <= hop["P_prev"].w:
                raise VerifyReject("V7.2", "legacy")
            if not hop["P_prev"].K <= hop["I_new"]:
                raise VerifyReject("V7.3", "legacy")
            if not tighten_ok(hop["P_new"], hop["P_prev"]):
                raise VerifyReject("V7.6", "legacy")
        h = canon.hi_of(e_bytes, h)
        I_prev_state, P_state = hop["I_new"], hop["P_new"]
    if h != S.h_t:
        raise VerifyReject("V6", "h_t mismatch")
    if used_certs != set(S.certs.keys()):
        raise VerifyReject("V1.1", "cert table not exactly referenced")

    # V8 终态
    if P_state.adm != S.Pt.adm or P_state.w != S.Pt.w or P_state.d != S.Pt.d:
        raise VerifyReject("V8", "Pt mismatch")
    if S.It != I_prev_state:
        raise VerifyReject("V8", "I_t != chain final I")
    if not P_state.K <= S.It:
        raise VerifyReject("V8", "K_t not kept")
    if len(S.log) > S.P0.d:
        raise VerifyReject("V8", "t > d0")

    # V9
    if mode == "hist":
        return "accept_historical"
    if mode == "fresh":
        if legacy_presented_anchor:
            a_sig, a_h, a_t, a_ts = S.anchor
            if not core.verify(pk_ra, canon.M_resp(b"", rid, a_h, a_t, a_ts), a_sig,
                               canon.CTX_ANC):
                raise VerifyReject("V9", "legacy anchor sig")
            anchor_epoch = None                   # v2 锚无 epoch（legacy 语义）
        else:
            if ra is None or nonce is None:
                raise VerifyReject("V9", "fresh requires RA query + nonce")
            resp, a_h, a_t, a_ts, anchor_epoch = ra.fresh_query(nonce, rid)
            if not core.verify(pk_ra, canon.M_resp3(nonce, rid, a_h, a_t, a_ts,
                                                    anchor_epoch), resp,
                               canon.CTX_ANC):
                raise VerifyReject("V9", "resp sig")
        if len(S.log) != a_t or S.h_t != a_h:
            raise VerifyReject("V9", "stale state")
        if rv_epoch is not None and anchor_epoch is not None \
                and rv_epoch < anchor_epoch:
            raise VerifyReject("V5.3d", "revocation snapshot older than anchor "
                                      "(stale snapshot replay)")
        return "accept_fresh"
    if mode == "snapshot":
        if not gazettes:
            raise VerifyReject("V9", "no gazette")
        g_sig, g_h, g_t, g_ts, period, anchor_epoch = gazettes[-1]
        if not core.verify(pk_ra, canon.M_gaz3(period, rid, g_h, g_t, g_ts,
                                               anchor_epoch), g_sig,
                           canon.CTX_ANC):
            raise VerifyReject("V9", "gazette sig")
        if len(S.log) != g_t or S.h_t != g_h:
            raise VerifyReject("V9", "not gazette-head state")
        if rv_epoch is not None and anchor_epoch is not None \
                and rv_epoch < anchor_epoch:
            raise VerifyReject("V5.3d", "revocation snapshot older than anchor "
                                      "(stale snapshot replay)")
        return f"accept_snapshot@G{period}"
    raise ValueError(mode)


cfg_pp = {"G": None, "D": None}   # 模块级 pp（Verify V3 需要 G/D；原型单套参数）
