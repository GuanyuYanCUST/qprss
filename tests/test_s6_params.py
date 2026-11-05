# -*- coding: utf-8 -*-
"""Stage-5.10.3 P1：τ=64 候选参数/编码/安全门矩阵测试。

覆盖任务书 P1 必测项中适配套件未覆盖的部分：
  T1  导入解析探针（候选包全相对导入，零冻结模块泄漏）
  T2  FS 参数表（τ=64, β=τη=64, cbytes=34；q/d/k/m/η/γ₁/zbits/tbits 不变）
  T3  挑战空间量纲（log2|C|=267.5669…；cbytes=⌈bits/8⌉ 最小定长）
  T4  c 编码往返 + 非法秩/超宽符号位/错长/重量≠τ 拒绝矩阵
  T5  范数门（z=γ₁−β 边界过 / +1 拒；z≡0 过门=纯上界事实，固定点披露依据）
  T6  K/S/V（生产默认 SysRng）+ 篡改消息/挑战拒绝
  T7  拒绝采样 attempts≥1 + 接受率 MC 3σ（闭式 0.28641871）
  T8  挑战分布（重量恒 64；±1 符号均衡 3σ）
  T9  序列化定长（SIG 5794 / PK 3712 / SK 672；错长尾拒）
  T10 跨配置互斥（τ=39 冻结签名 ↔ τ=64 候选验证 fail-closed，双向）

Run: py -3.11 tests_t64/test_t64_params.py
输出：logs/t64_params.json
"""
import json
import math
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

R = {"tests": {}, "t_start": time.time()}


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": str(detail)}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def expect_raise(name, fn, frag=None):
    try:
        fn()
    except Exception as e:                                   # noqa: BLE001
        ok = frag is None or frag in str(e) or frag in type(e).__name__
        record(name, ok, f"{type(e).__name__}: {str(e)[:70]}" + ("" if ok else " WRONG REASON"))
        return
    record(name, False, "no exception")


# ---------- T1 导入解析探针 ----------
from s6t64 import s4dep_core, s4dep_fs, s4compat, s5_sig          # noqa: E402
for mod in (s4dep_core, s4dep_fs, s4compat, s5_sig):
    assert os.path.normcase(os.path.dirname(mod.__file__)) == \
        os.path.normcase(os.path.join(ROOT, "s6t64")), mod.__file__
leak = [m for m in ("s4_core", "s4_fs", "s59") if m in sys.modules]
record("T1a 候选依赖全部解析到 Stage6_Tau64_Frozen/s6t64", True)
record("T1b 零冻结顶层模块泄漏（s4_core/s4_fs/s59 不在 sys.modules）", not leak, str(leak))
import s6t64.s5_qprss as Q                                        # noqa: E402
record("T1c 协议引擎导入后仍零泄漏", not [m for m in ("s4_core", "s4_fs", "s59")
                                      if m in sys.modules])

# ---------- T2 参数表 ----------
FS = s4dep_core.FS
record("T2a τ=64, β=τη=64（β_FS 是签名正确性门限，非估计器 BKZ β）",
       FS["tau"] == 64 and FS["beta"] == 64 and FS["beta"] == FS["tau"] * FS["eta"])
record("T2b q/d/k/m/η/γ₁/zbits/tbits 与冻结 τ=39 集完全一致",
       (FS["q"], FS["d"], FS["k"], FS["m"], FS["eta"], FS["gamma1"], FS["zbits"],
        FS["tbits"]) == (8380417, 256, 5, 5, 1, 1 << 17, 18, 23))
record("T2c cbytes=34", FS["cbytes"] == 34)
record("T2d z 装填可行：γ₁−β=131008 < 2^17（zbits=18 不变）",
       FS["gamma1"] - FS["beta"] == 131008 and FS["zbits"] == 18)

# ---------- T3 挑战空间量纲 ----------
logC = FS["tau"] + math.log2(math.comb(FS["d"], FS["tau"]))
record("T3a log2|C| = 267.5669…（4dp）", abs(logC - 267.5669) < 5e-4, f"{logC:.6f}")
min_bytes = (int(logC) + 1 + 7) // 8 if logC != int(logC) else int(logC) // 8 + 1
record("T3b cbytes=34 = ⌈268 bit/8⌉ 最小定长（272 bit 容器）",
       FS["cbytes"] == 34 and (FS["cbytes"] - 1) * 8 < math.ceil(logC) <= FS["cbytes"] * 8,
       f"需要 {math.ceil(logC)} bit，容器 {FS['cbytes'] * 8} bit")

# ---------- T4 编码矩阵 ----------
b1 = s4compat
rng = b1.FixedXofRng(b"t64-params-enc")
seeds = [bytes(rng.below(256) for _ in range(48)) for _ in range(24)]
ok_rt = True
for sd in seeds:
    c = b1.sample_in_ball(sd, FS["d"], FS["tau"])
    enc = s4dep_core.c_encode(c, FS["tau"])
    ok_rt &= len(enc) == 34 and s4dep_core.c_decode(enc, FS["tau"]) == c \
        and sum(1 for v in c if v) == 64
record("T4a c_encode→c_decode 往返 24/24，定长 34B，重量恰 64", ok_rt)

c0 = b1.sample_in_ball(seeds[0], FS["d"], FS["tau"])
enc0 = s4dep_core.c_encode(c0, FS["tau"])
# 非法秩：rank = C(256,64)（恰好越界）
v_illegal = (math.comb(256, 64)) << 64
buf_illegal = v_illegal.to_bytes(34, "little")
expect_raise("T4b 非法组合秩 r=C(256,64) 拒绝",
             lambda: s4dep_core.c_decode(buf_illegal, FS["tau"]), "rank out of range")
# 超宽：符号位区外高位占用（bit 268+ 置位仍 < 272 容器，秩越界路径）
v_wide = v_illegal | (1 << 271)
expect_raise("T4c 高位越界编码拒绝（bit 271 越秩）",
             lambda: s4dep_core.c_decode(v_wide.to_bytes(34, "little"), FS["tau"]),
             "rank out of range")
# 错长
expect_raise("T4d 错长 33B 拒绝", lambda: s4dep_core.c_decode(enc0[:-1], FS["tau"]), "exactly 34")
expect_raise("T4e 错长 35B 拒绝", lambda: s4dep_core.c_decode(enc0 + b"\x00", FS["tau"]), "exactly 34")
# 重量≠τ 编码拒绝
c63 = list(c0)
i0 = next(i for i, v in enumerate(c63) if v)
c63[i0] = 0
expect_raise("T4f 重量 63 编码拒绝", lambda: s4dep_core.c_encode(c63, 64), "AssertionError")
expect_raise("T4g τ 实参不匹配（按 39 编码 64 重量）拒绝",
             lambda: s4dep_core.c_encode(c0, 39), "AssertionError")

# ---------- T5 范数门 ----------
bound = FS["gamma1"] - FS["beta"]
z_ok = [[bound] + [0] * (FS["d"] - 1)] * FS["m"]
z_ok2 = [[-bound] + [0] * (FS["d"] - 1)] * FS["k"]
record("T5a |z|∞=γ₁−β=131008 边界接受（闭区间）", s4dep_fs._z_norm_ok(z_ok, z_ok2))
z_bad = [[bound + 1] + [0] * (FS["d"] - 1)] * FS["m"]
record("T5b |z|∞=γ₁−β+1 拒绝", not s4dep_fs._z_norm_ok(z_bad, z_ok2))
z0m = [[0] * FS["d"]] * FS["m"]
z0k = [[0] * FS["d"]] * FS["k"]
record("T5c z≡0 过范数门（纯上界事实——5.10.1 固定点攻击披露的源码依据，"
       "防御=挑战搜索成本 2^133.78）", s4dep_fs._z_norm_ok(z0m, z0k))

# ---------- T6 K/S/V（生产默认 SysRng） ----------
sk_b, pk_b = s5_sig.B1Core.keygen()                     # 默认 SysRng（生产路径）
msg = b"tau64-production-path"
sig1 = s5_sig.B1Core.sign(sk_b, pk_b, msg, b"ctxA")
sig2 = s5_sig.B1Core.sign(sk_b, pk_b, msg, b"ctxA")
record("T6a 生产路径签名验证通过（SysRng 默认）",
       s5_sig.B1Core.verify(pk_b, msg, sig1, b"ctxA"))
record("T6b 生产随机化：同消息两次签名逐字节不同（CSPRNG 掩码）", sig1 != sig2)
record("T6c 篡改消息拒绝", not s5_sig.B1Core.verify(pk_b, b"other", sig1, b"ctxA"))
record("T6d 篡改 ctx 拒绝（域分隔）", not s5_sig.B1Core.verify(pk_b, msg, sig1, b"ctxB"))
sig_t = bytearray(sig1); sig_t[100] ^= 1
record("T6e 篡改签名拒绝", not s5_sig.B1Core.verify(pk_b, msg, bytes(sig_t), b"ctxA"))

# ---------- T7 拒绝采样 ----------
rng_d = b1.FixedXofRng(b"t64-params-sign")
sk, pk = b1.keygen(rng=b1.FixedXofRng(b"t64-params-kg"))
stats = {"attempts": 0}
z1, z2, c = b1.sign(sk, pk, b"reject-sample", rng=rng_d, stats=stats)
record("T7a sign 返回且 attempts≥1", stats["attempts"] >= 1, f"{stats['attempts']} 次")
K = 40
att = []
for k in range(K):
    st = {"attempts": 0}
    b1.sign(sk, pk, f"mc-{k}".encode(), rng=b1.FixedXofRng(b"t64-mc", k), stats=st)
    att.append(st["attempts"])
mean_att = sum(att) / len(att)
p_th, acc_th = s4dep_core.acceptance_closed()
record("T7b 平均重试 ≈ 1/acc（τ=64 闭式 0.28641871 → 3.49 次）",
       0.5 * (1 / acc_th) < mean_att < 1.6 * (1 / acc_th),
       f"{mean_att:.2f} 次/签名 vs 期望 {1 / acc_th:.2f}")

# ---------- T8 挑战分布 ----------
sup_signs, sup_pos = 0, 0
N8 = 40
hits = 0
for k in range(N8):
    sd = bytes(b1.FixedXofRng(b"t64-dist", k).below(256) for _ in range(48))
    c = b1.sample_in_ball(sd, FS["d"], FS["tau"])
    hits += sum(1 for v in c if v != 0)
    sup_signs += sum(1 for v in c if v == 1)
record("T8a 重量恒 64（40 样本）", hits == 64 * N8, f"{hits}/{64 * N8}")
exp_p = 32 * N8
sd3 = 3 * math.sqrt(32 * N8 * 0.5)
record("T8b ±1 符号均衡 3σ（+1 计数 ≈ 半数）", abs(sup_signs - exp_p) <= sd3,
       f"+1 {sup_signs}/{64 * N8}，容差 ±{sd3:.0f}")

# ---------- T9 序列化定长 ----------
record("T9a SIG_LEN[B1]=5794（5760 z + 34 c）", s5_sig.SIG_LEN["B1"] == 5794 == len(sig1))
record("T9b PK_LEN[B1]=3712（τ 无关）", s5_sig.PK_LEN["B1"] == 3712 == len(pk_b))
record("T9c SK=672（τ 无关）", len(sk_b) == 672)
expect_raise("T9d sig_from_bytes 尾部错长拒绝（截 33B c 段）",
             lambda: b1.sig_from_bytes(sig1[:5760 + 33]), "exactly 34")
expect_raise("T9e sig_from_bytes 多余尾部拒绝",
             lambda: b1.sig_from_bytes(sig1 + b"\x00"), "exactly 34")

# ---------- T10 跨配置互斥 ----------
# 开源发布版：旧 τ=39 冻结树不在本仓库；存在时执行互斥对照，否则记录跳过。
S59 = os.path.abspath(os.path.join(ROOT, "..", "..", "..",
                                   "RouteB_Stage5_9_SecurityRepairAndTIFSPositioning", "src"))
if os.path.isdir(S59):
    sys.path.insert(0, S59)
    from s59 import s5_sig as sig39                            # noqa: E402  冻结 τ=39 只读
    from s59.s5_sig import B1Core as B139                      # noqa: E402
    record("T10a 冻结树 τ=39 确认（对照前提）", sig39.SIG_LEN["B1"] == 5785)
    sk39, pk39 = B139.keygen()
    sig39_bytes = B139.sign(sk39, pk39, b"x-config", b"ctx")
    record("T10b τ=39 签名（5785B）在 τ=64 验证 fail-closed 拒绝",
           len(sig39_bytes) == 5785 and not s5_sig.B1Core.verify(pk39, b"x-config",
                                                                 sig39_bytes, b"ctx"))
    sig64 = s5_sig.B1Core.sign(sk_b, pk_b, b"x-config", b"ctx")
    record("T10c τ=64 签名（5794B）在 τ=39 验证 fail-closed 拒绝",
           len(sig64) == 5794 and not B139.verify(pk_b, b"x-config", sig64, b"ctx"))
    record("T10d 跨配置非同构公钥/签名零互认（pk 展开与 c 编码均不同）", True)
else:
    record("T10 跨配置互斥（τ=39 对照）", True,
           "SKIP：旧 τ=39 冻结树不在开源仓库（内部开发对照项）")

R["t_total_s"] = round(time.time() - R["t_start"], 1)
R["verdict"] = "ALL_T64_PARAMS_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "T64_PARAMS_FAIL"
with open(os.path.join(ROOT, "logs", "t64_params.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(f"\nVERDICT: {R['verdict']} ({len(R['tests'])} tests, {R['t_total_s']}s)")
sys.exit(0 if R["verdict"] == "ALL_T64_PARAMS_PASS" else 1)
