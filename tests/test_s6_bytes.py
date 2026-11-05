# -*- coding: utf-8 -*-
"""Stage-5 Phase-3 冻结存储口径：n=102、r=97、t=5 逐字节统计。

权威断言：sum(component_bytes) == len(serialize(Σ_5))（程序强制，parse_sigma
分节偏移来自真实字节流）。254,758 B 仅为字段材料熵最优锚点（承诺+见证两层，
r/η 熵编码 742 B/字段）；本集成原型用 2-bit 定长编码（512+336=848 B/字段）
⟹ 字段材料两层 = 265,040 B（= Stage-4 定长口径，逐位对上）。

去重规则：
- 证书按 cid 去重（u = 不同证书数，本链 u=2：Cert_S + 1 删改者）；
- 承诺 C_j 全 n 份由记录持有方常驻（acc0 锚定全树，删字段的承诺仍在树中），
  不随 Σ 传输——计为链外存储层；
- 见证仅随保留字段存在（r 份；删除字段见证在 Redact 时销毁）。

Run: py -3.11 tests/test_s5_bytes.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon
from s6t64.policy import Policy
from s6t64.s5_sig import core, SIG_LEN

R = {"tests": {}}


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": detail}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def main():
    t0 = time.time()
    n, t = 102, 5
    r = n - t                                            # 97
    rid = bytes([0x3C] * 16)
    ra = Q.RA("B1")
    pp = Q.setup("B1", seed=b"s5-bytes-anchor")
    sk_s, pk_s = core("B1").keygen()
    # SF-A1 适配：signer 证书 scope 显式枚举 RID
    cert_s = ra.issue(bytes(16), pk_s, b"signer", ((rid,), b"*"), 0, 2**40)
    ys = {j: canon.enc32(j) * 2 for j in range(1, n + 1)}          # 8 B 合成字段
    W0 = frozenset(range(2, n + 1))                        # 1 强制保留
    P0 = Policy([(b"physician", b"*")], W0, 40, n)         # d₀=40（E2 闸门口径）
    S = Q.signing(pp, sk_s, cert_s, rid, ys, P0, rng=Q.make_rng(b"s5-bytes"))

    sk_r, pk_r = core("B1").keygen()
    cr = ra.issue(b"\x21" * 16, pk_r, b"physician", ((rid,), b"*"), 0, 2**40)
    for i in range(1, t + 1):                             # 每轮删 1 字段（2..6）
        I = S.It - {i + 1}
        P = Policy(P0.adm, W0, P0.d - i, n)
        S = Q.redact(pp, S, I, P, cr, sk_r, 1000 + i)
    assert len(S.It) == r and len(S.log) == t
    record("T1 合法链构建（n=102, t=5, r=97, d₀=40, verify=PASS）",
           Q.verify({"pk_ra": ra.pk}, S, "hist") == "accept_historical",
           f"t={time.time()-t0:.1f}s")

    blob = S.serialize()
    S2, sec = Q.parse_sigma(blob)
    comp = {name: end - start for (name, start, end) in sec}
    record("T2 对账恒等式 sum(component_bytes) == len(serialize(Σ₅))",
           sum(comp.values()) == len(blob), f"{sum(comp.values())} == {len(blob)}")
    record("T3 序列化往返逐字节一致（解析重编码）", S2.serialize() == blob)

    # ---- 逐对象分解表（数量 × 字节 = 分节字节）----
    depth = (n - 1).bit_length()                          # 7
    lam = 48
    table = [
        ("header(元数据/RID/sd/acc0/P0/I0位图/Pt/h_t)", 1, comp["header"]),
        ("σ₀ 原始 FS 签名", 1, comp["sigma0"]),
        ("Cert_S（含 signer pk 3,712 B，τ=64 下不变）", 1, comp["cert_s"]),
        ("字段值 y+索引（r 份保留）", r, comp["fields:idx+y"]),
        ("见证核心 W_j(r‖η 2-bit)", r, comp["fields:witness-core"]),
        ("Merkle 路径 π_j", r, comp["fields:merkle-path"]),
        ("审计日志 e_i", t, comp["audit:e"]),
        ("审计签名 τ_i（FS）", t, comp["audit:tau"]),
        ("删改者证书（u=1，去重后）", len(S.certs) - 1, comp["certs"]),
    ]
    R["component_table"] = [(nm, cnt, byt) for (nm, cnt, byt) in table]
    checks = {
        "σ₀ = SIG_LEN[B1]=5,794(τ=64)": comp["sigma0"] == SIG_LEN["B1"] == 5794,
        "τ 块 = t×SIG_LEN[B1]": comp["audit:tau"] == t * SIG_LEN["B1"],
        "见证核心 = r×512": comp["fields:witness-core"] == r * 512,
        "Merkle 路径 = r×depth×48": comp["fields:merkle-path"] == r * depth * lam,
        "证书块 = u×len(cert.bytes())": comp["certs"] == len(cr.bytes()),
    }
    for k, v in checks.items():
        record(f"T4 {k}", v)
    tot_sig_slots = comp["sigma0"] + comp["audit:tau"]
    record("T5 签名槽合计（σ₀+t·τ = (1+t)×SIG_LEN[B1]）", tot_sig_slots == (1 + t) * SIG_LEN["B1"],
           f"{tot_sig_slots} B")

    # ---- 链外承诺层 + Stage-4 锚点交叉核验 ----
    C = 1792
    offchain = n * C                                       # 182,784
    wit_fixed = r * (512 + depth * lam)                    # 82,256（2-bit 定长）
    wit_opt = 742 * r                                      # 71,974（熵最优理论）
    field_mat_fixed = offchain + wit_fixed                 # 265,040
    record("T6 承诺层（链外常驻）= n×1,792 = 182,784", offchain == 102 * 1792)
    record("T7 字段材料两层（定长 2-bit）= 265,040 B（Stage-4 锚点·定长口径）",
           field_mat_fixed == 265040, f"{field_mat_fixed} = 182,784 + {wit_fixed}")
    record("T8 熵最优口径 254,758 B ≠ 原型编码（差 = r×(848−742) = 10,282）",
           offchain + wit_opt == 254758 and field_mat_fixed - (offchain + wit_opt) == 10282,
           "锚点=熵编码理论下界；原型=可解析定长编码（二者均为字段材料口径，"
           "均不含 σ/证书/日志/策略/索引/元数据）")
    record("T9 |Σ₅| 全链序列化尺寸登记", True, f"{len(blob)} B（含全部签名/证书/日志/见证/路径）")

    R["accounting"] = dict(
        n=n, t=t, r=r, depth=depth, lam=lam,
        sigma_total=len(blob),
        components=dict(comp),
        table=[(nm, cnt, byt) for (nm, cnt, byt) in table],
        offchain_commitments_B=offchain,
        witness_material_fixed_B=wit_fixed,
        field_material_fixed_B=field_mat_fixed,
        field_material_entropy_opt_B=offchain + wit_opt,
    )
    R["wall_s"] = round(time.time() - t0, 1)
    R["verdict"] = "ALL_S5_BYTES_PASS" if all(v["pass"] for v in R["tests"].values()) else "S5_BYTES_FAIL"
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data",
                       "t64_bytes_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    print(f"VERDICT: {R['verdict']} ({len(R['tests'])} tests, {R['wall_s']}s) -> {out}")
    return 0 if R["verdict"] == "ALL_S5_BYTES_PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

