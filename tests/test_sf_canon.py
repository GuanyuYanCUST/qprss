# -*- coding: utf-8 -*-
"""SF-C（安全修复 Task C）：规范受限策略编码 + 冻结件字节等价回归。

冻结实现缺口（Task G A6）：encP 非规范——同语义不同 adm 序不同字节、
重复项不拒。修复后：唯一确定性编码（adm_key 严格序+条目内 id 排序去重，
Policy 构造即规范化）；dec_encP 拒绝重复/非法标签/非法角色码/空枚举/
乱序/截断。签名端与验证端字节一致由往返+跨实现等价保证。

等价回归（对照 = run/baseline_run/s6t64base，即冻结原件别名副本）：
- fixture 型策略 encP 逐字节不变（正式数据兼容）；
- M_certR/M_orig/M_init/M_red/M_reginit/M_reg/M_revsnap 逐字节不变；
- M_certS 仅随 scope 表示变化：通配(1B)→枚举(18B) = +17B；
- 同种子全链 Σ（含 σ0/τ/Θ0/h 链）跨实现逐字节一致。
"""
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # GBK 控制台防崩

HERE = os.path.dirname(os.path.abspath(__file__))
# 开源发布版：修复树与基线树固定为仓内 run/ 目录（原内部相对寻址改为显式路径）。
FIXED_ROOT = os.path.join(os.path.dirname(HERE), "run", "fixed_run")
BASE_ROOT = os.path.join(os.path.dirname(HERE), "run", "baseline_run")
sys.path.insert(0, BASE_ROOT)                          # 先基线（低位）
sys.path.insert(0, FIXED_ROOT)                         # 修复树优先：s6t64 = 修复件

import s6t64 as FX                                     # 修复后
import s6t64base as BS                                 # 冻结原件（别名副本）
import s6t64.policy, s6t64.canon, s6t64.s5_qprss, s6t64.s5_sig, s6t64.s4compat
import s6t64base.policy, s6t64base.canon, s6t64base.s5_qprss
import s6t64base.s5_sig, s6t64base.s4compat

from s6t64 import canon as cfx, policy as pfx          # noqa: E402
from s6t64 import s5_qprss as QFX                      # noqa: E402

R = {"tests": {}}


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(("[PASS] " if ok else "[FAIL] ") + name + (f"  {note}" if note else ""))


ID1, ID2 = b"\x11" * 16, b"\x22" * 16

# ---------------- C1 往返 ----------------
POLICIES = [
    (((b"physician", b"*"),), frozenset({2, 3}), 5, 6),                     # 正式口径
    (((b"physician", b"*"), (b"nurse", (ID1,))), frozenset(range(2, 7)), 6, 6),
    (((b"physician", b"*"), (b"admin", (ID1, ID2)), (b"nurse", (ID1,))), {2}, 3, 8),
    (((b"auditor", (ID2,)),), frozenset({3, 4}), 2, 5),
    ((), frozenset({2}), 5, 5),
]
ok_rt = ok_sem = True
for adm, w, d, n in POLICIES:
    P = pfx.Policy(adm, w, d, n)
    e = cfx.encP(P)
    P2, off = QFX.dec_encP(e, 0, n)
    if cfx.encP(P2) != e or off != len(e):
        ok_rt = False
    if not (P2.adm == P.adm and P2.w == P.w and P2.d == P.d and P2.K == P.K):
        ok_sem = False
record("C1-1 encP→dec_encP→encP 往返一致（5 组策略）", ok_rt)
record("C1-2 往返语义保持（adm/W/d/K）", ok_sem)

# ---------------- C2 唯一确定性编码 ----------------
perm = pfx.Policy(((b"nurse", (ID1,)), (b"physician", b"*")), frozenset({2, 3}), 5, 6)
canon_p = pfx.Policy(((b"physician", b"*"), (b"nurse", (ID1,))), frozenset({2, 3}), 5, 6)
record("C2-1 adm 乱序构造 → 同一规范字节", cfx.encP(perm) == cfx.encP(canon_p))
dup = pfx.Policy(((b"physician", b"*"), (b"physician", b"*")), frozenset({2}), 5, 6)
one = pfx.Policy(((b"physician", b"*"),), frozenset({2}), 5, 6)
record("C2-2 重复条目去重 → 同一规范字节（语义等价）", cfx.encP(dup) == cfx.encP(one))
idperm = pfx.Policy(((b"admin", (ID2, ID1)),), frozenset({2}), 5, 6)
idcanon = pfx.Policy(((b"admin", (ID1, ID2)),), frozenset({2}), 5, 6)
record("C2-3 条目内 id 乱序 → 同一规范字节", cfx.encP(idperm) == cfx.encP(idcanon))
record("C2-4 不同语义 → 不同字节（非退化）",
       cfx.encP(canon_p) != cfx.encP(idcanon) != cfx.encP(one))

# ---------------- C3 畸形拒绝 ----------------
bPOL = cfx.encP(canon_p)


def malform(mut):
    b = bytearray(bPOL)
    mut(b)
    return bytes(b)


cases = {
    "未知角色码 9": lambda b: b.__setitem__(1, 9),
    "非法 tag=2": lambda b: b.__setitem__(2, 2),
    "截断尾部": lambda b: b.__delitem__(slice(len(b) - 3, len(b))),
}
ok_all = True
notes = []
for name, mut in cases.items():
    try:
        QFX.dec_encP(malform(mut), 0, 6)
        ok_all = False
        notes.append(f"{name}:accepted")
    except ValueError:
        pass
record("C3-1 畸形字节样本拒（逐例）", ok_all, ";".join(notes) or "3/3 拒")

# 手工构造的规范违规（确定性样本）
raw_dup = bytes([2]) + cfx.enc_adm_entry(b"physician", b"*") \
    + cfx.enc_adm_entry(b"physician", b"*") + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_unsorted = bytes([2]) + cfx.enc_adm_entry(b"nurse", (ID1,)) \
    + cfx.enc_adm_entry(b"physician", b"*") + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_ids_unsorted = bytes([1]) + bytes([3, 0, 2]) + ID2 + ID1 + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_empty_enum = bytes([1]) + bytes([3, 0, 0]) + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_dup_id = bytes([1]) + bytes([3, 0, 2]) + ID1 + ID1 + cfx.bmp({2}, 6) + cfx.enc32(5)
raw_badtag = bytes([1]) + bytes([3, 7, 1]) + cfx.bmp({2}, 6) + cfx.enc32(5)
ok_m = True
for nm, raw in (("重复条目", raw_dup), ("乱序条目", raw_unsorted),
                ("条目内 id 乱序", raw_ids_unsorted), ("空枚举", raw_empty_enum),
                ("条目内重复 id", raw_dup_id), ("非法 tag", raw_badtag)):
    try:
        QFX.dec_encP(raw, 0, 6)
        ok_m = False
        print(f"  [accepted(!)] {nm}")
    except ValueError:
        pass
record("C3-2 手工规范违规 6 型全拒（ValueError）", ok_m)

# ---------------- C4 冻结件字节等价（对照 = 冻结原件） ----------------
IDR = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
# 正式实验实际策略形状（run_stage6._qc / K3 适配器 / e2-e7）：
#   u=1（E2 深度/Table V、E6 FHIR、emicro、K3 Fig2）adm=((physician,*),) —— 已规范
#   u=3（E3 多删改者、E5）adm=((physician,*),(admin,*),(nurse,(33*16,))) ——
#     角色码序 (1,3,2) 非规范：修复后按 (1,2,3) 重排，字节变化但**长度不变**
#     （重排不改变条目自身表示长度），旧 u=3 工件被严格解码器拒绝（遗留编码）。
CANON_FIXTURE = [
    (((b"physician", b"*"),), frozenset(range(2, 7)), 6, 6),                # u=1 正式口径
    (((b"physician", b"*"), (b"nurse", (b"\x33" * 16,))), frozenset(range(2, 7)), 6, 6),
]
ok_fixture_bytes = True
for adm, w, d, n in CANON_FIXTURE:
    if BS.canon.encP(BS.policy.Policy(adm, w, d, n)) != cfx.encP(pfx.Policy(adm, w, d, n)):
        ok_fixture_bytes = False
record("C4-1 已规范正式形状（u=1/E2/E6/emicro/K3）encP 逐字节一致", ok_fixture_bytes)

u3_legacy = ((b"physician", b"*"), (b"admin", b"*"), (b"nurse", (b"\x33" * 16,)))
e_leg = BS.canon.encP(BS.policy.Policy(u3_legacy, frozenset(range(2, 7)), 6, 6))
P_new = pfx.Policy(u3_legacy, frozenset(range(2, 7)), 6, 6)
e_new = cfx.encP(P_new)
try:
    QFX.dec_encP(e_leg, 0, 6)
    leg_rejected = False
except ValueError:
    leg_rejected = True
record("C4-1b u=3 遗留序（1,3,2）：重排为规范序、长度不变、遗留字节被拒",
       len(e_leg) == len(e_new) and e_leg != e_new and leg_rejected
       and P_new.adm == tuple(sorted(P_new.adm, key=lambda e_: cfx.adm_key(*e_))))

PFad, PFw, PFd, PFn = POLICIES[1]
Pb0 = BS.policy.Policy(PFad, PFw, PFd, PFn)
Pf0 = pfx.Policy(PFad, PFw, PFd, PFn)
M_eq = all([
    BS.canon.M_certR(ID1, b"\x00" * 3712, b"nurse", ((IDR,), b"*"), 0, 1 << 62)
    == cfx.M_certR(ID1, b"\x00" * 3712, b"nurse", ((IDR,), b"*"), 0, 1 << 62),
    BS.canon.M_orig(IDR, 6, b"\x00" * 48, Pb0, set(range(1, 7)), sd=b"\x01" * 48)
    == cfx.M_orig(IDR, 6, b"\x00" * 48, Pf0, set(range(1, 7)), sd=b"\x01" * 48),
    BS.canon.M_init(IDR, 6, b"\x00" * 48, Pb0, set(range(1, 7)), sd=b"\x01" * 48)
    == cfx.M_init(IDR, 6, b"\x00" * 48, Pf0, set(range(1, 7)), sd=b"\x01" * 48),
    BS.canon.M_red(IDR, 1, b"\x00" * 48, b"\x01" * 48, b"\x02" * 48)
    == cfx.M_red(IDR, 1, b"\x00" * 48, b"\x01" * 48, b"\x02" * 48),
    BS.canon.M_reginit(IDR, 6, b"\x00" * 48, Pb0, b"\x03" * 48, sd=b"\x01" * 48)
    == cfx.M_reginit(IDR, 6, b"\x00" * 48, Pf0, b"\x03" * 48, sd=b"\x01" * 48),
    BS.canon.M_reg(IDR, 0, b"\x00" * 48, 1, b"\x01" * 48, 2, b"\x02" * 48, ID1,
                   b"nurse") == cfx.M_reg(IDR, 0, b"\x00" * 48, 1, b"\x01" * 48, 2,
                                          b"\x02" * 48, ID1, b"nurse"),
    BS.canon.M_revsnap(3, [(ID1, 5), (ID2, 6)]) == cfx.M_revsnap(3, [(ID1, 5), (ID2, 6)]),
])
record("C4-2 M_certR/M_orig/M_init/M_red/M_reginit/M_reg/M_revsnap 逐字节不变", M_eq)

wld = cfx.M_certS(ID1, b"\x00" * 3712, (b"*", b"*"), 0, 1)
enm = cfx.M_certS(ID1, b"\x00" * 3712, ((IDR,), b"*"), 0, 1)
record("C4-3 M_certS 通配→枚举恰 +17B", len(enm) - len(wld) == 17
       and len(wld) == len(BS.canon.M_certS(ID1, b"\x00" * 3712, (b"*", b"*"), 0, 1)))

# ---------------- C5 同种子全链 Σ 跨实现逐字节一致 ----------------
N = 6
RID = IDR
ys = {j: f"v{j}".encode() for j in range(1, N + 1)}
sd = cfx.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, N + 1)])
adm0, w0, d0 = ((b"physician", b"*"), (b"nurse", (ID1,))), frozenset(range(2, N + 1)), N


def build_world(mod, scoped=True):
    """跨实现确定性世界：keygen/签名掩码/承诺随机带全种子化——
    两侧字节差只能来自协议编码本身。"""
    s4c = mod.s4compat
    pp = mod.s5_qprss.setup("B1", seed=b"sf-c|pp")
    ra = mod.s5_qprss.RA("B1")
    ra.sk, ra.pk = mod.s5_sig.core("B1").keygen(
        rng=s4c.FixedXofRng(b"sf-c|kg-ra"))    # RA 钥也种子化（证书签名确定）
    B1c = mod.s5_sig.core("B1")
    sk_s, pk_s = B1c.keygen(rng=s4c.FixedXofRng(b"sf-c|kg-s"))
    scope = ((RID,), b"*") if scoped else (b"*", b"*")
    cert = mod.s5_qprss.Cert(RID[:12] + b"SGNR", pk_s, b"signer", scope, 0, 1 << 62)
    cert.sig = B1c.sign(ra.sk, ra.pk, cert.msg, mod.canon.CTX_CERT,
                        rng=s4c.FixedXofRng(b"sf-c|certS"))
    P0 = mod.policy.Policy(adm0, w0, d0, N)
    S = mod.s5_qprss.signing(pp, sk_s, cert, RID, ys, P0,
                             rng=mod.s5_qprss.make_rng(b"sf-c|commit"),
                             schema_digest=sd,
                             sig_rng=s4c.FixedXofRng(b"sf-c|sig0"))
    sk_e, pk_e = B1c.keygen(rng=s4c.FixedXofRng(b"sf-c|kg-e"))
    ce = mod.s5_qprss.Cert(ID1, pk_e, b"nurse", ((RID,), b"*"), 0, 1 << 62)
    ce.sig = B1c.sign(ra.sk, ra.pk, ce.msg, mod.canon.CTX_CERT,
                      rng=s4c.FixedXofRng(b"sf-c|certR"))
    P1 = mod.policy.Policy(adm0, w0 - {3}, d0 - 1, N)
    S2 = mod.s5_qprss.redact(pp, S, set(range(1, N + 1)) - {2}, P1, ce, sk_e, 10,
                             sig_rng=s4c.FixedXofRng(b"sf-c|tau1"))
    return S, S2, ra, ce


Sb, S2b, rab, ceb = build_world(BS)                    # 冻结实现 + 枚举 scope 证书
Sf, S2f, raf, cef = build_world(FX)                    # 修复实现 + 同一枚举 scope
record("C5-1 t=0 Sigma 跨实现逐字节一致（sigma0/Theta0/h0/证书）",
       Sb.serialize() == Sf.serialize(),
       f"len={len(Sf.serialize())}")
# C5-2（论文对齐轮改写）：H_cert 升级（§4.4 审计绑定含管理员签名）使 e1 的
# cert_h 域与基线分歧；除该域（及链式依赖 h_t）外须逐字节一致。
_b, _f = S2b.serialize(), S2f.serialize()
hopb = BS.s5_qprss.dec_e(S2b.log[0][0], N)
hopf = FX.s5_qprss.dec_e(S2f.log[0][0], N)
def _peq(pb, pf):
    return BS.canon.encP(pb) == FX.canon.enc_pol(pf)
same_fields = all(hopb[k] == hopf[k] for k in hopb
                  if k not in ("certH", "P_prev", "P_new"))     and _peq(hopb["P_prev"], hopf["P_prev"]) and _peq(hopb["P_new"], hopf["P_new"])
record("C5-2 t=1 Sigma 与基线仅 H_cert 摘要域分歧（其余逐字段一致）",
       len(_b) == len(_f) and same_fields
       and hopb["certH"] == BS.canon.H(ceb.msg)
       and hopf["certH"] == FX.canon.cert_digest(cef),
       f"len={len(_f)} certH_b={hopb['certH'][:6].hex()} certH_f={hopf['certH'][:6].hex()}")
record("C5-3 修复实现自验证 hist accept",
       QFX.verify({"pk_ra": raf.pk}, S2f, "hist") == "accept_historical")
record("C5-4 修复实现反序列化往返逐字节一致",
       QFX.Sigma.deserialize(S2f.serialize()).serialize() == S2f.serialize())

# 通配证书在冻结实现的 Σ（正式实验旧口径）→ 修复实现拒绝（V2.1），+17B 量化
Sb_w, _, _, _ = build_world(BS, scoped=False)
record("C5-5 枚举 scope Σ 比通配旧口径恰 +17B",
       len(Sf.serialize()) - len(Sb_w.serialize()) == 17,
       f"enum {len(Sf.serialize())} vs wild {len(Sb_w.serialize())}")
try:
    QFX.verify({"pk_ra": raf.pk}, QFX.Sigma.deserialize(Sb_w.serialize()), "hist")
    record("C5-6 旧口径 Σ 在修复实现被拒（V2.1 通配 signer）", False, "accepted(!)")
except QFX.VerifyReject as e:
    record("C5-6 旧口径 Σ 在修复实现被拒（V2.1 通配 signer）",
           e.step.startswith("V2.1"), f"@{e.step}")

R["verdict"] = "ALL_SF_CANON_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "SF_CANON_FAIL"
with open(os.path.join(FIXED_ROOT, "logs", "sf_canon.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(R["verdict"])
sys.exit(0 if R["verdict"] == "ALL_SF_CANON_PASS" else 1)
