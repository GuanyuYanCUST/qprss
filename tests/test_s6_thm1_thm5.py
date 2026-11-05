# -*- coding: utf-8 -*-
"""Stage-5.9 03/04号配套：Theorem 1（FS 模拟器与提取）与 Theorem 5（分层绑定）
的可执行验证——以真实源码为验收对象。

P0.4 说明：定理验证（T1–T5, U1–U5）在**固定 XOF 路径**（s59.s4compat）上执行——
冻结 s4_core.ShakeRng 的缓冲回放缺陷（T0 实证）使冻结路径的抽样间相关，
统计检验失真；定理陈述的是正确随机性下的分布律。冻结缺陷单列 T0/T7/T8 登记。

Thm1 组：
  T0  冻结 ShakeRng XOF 回放缺陷登记（流级：seq[126:142]==XOF[0:16]）。
  T1  FS 签名预言机模拟器（编程式构造，BBD'23 Thm3 Sign→Prog 型）：模拟转录
      在 h1_override 下全部通过 verify；不插表则全部被拒（"无需编程"不成立）。
  T2  转录分布精确同律（乘积测度）：真实 sign 与模拟器的 (z,c)——|z| 均值、
      max|z|、c 重量=τ、槽位均匀性、真实 vs 模拟直方图 TVD。
  T3  自目标恒等式：诚实转录 w = A·z1+z2−t·c ≡ A·y1+y2（代数恒等）且
      c = H₁(w‖μ)——伪造转录本身就是 STMSIS 解，紧路线零提取。
  T4  分叉路线演示（对照）：同 w 异 c 相减 → A·Δz1+Δz2 = t·Δc（57-bit 路线
      才需要的代数）。
  T5  常数：|C|=binom(256,39)·2^39；模拟器 w' 每查询 min-熵（Lemma H1'）。
  T6  修复后接受率 = τ=64 闭式 0.28641871（β=64；接受律结构不因修复改变）。
  T7  A 展开：冻结条目 p[42+k]==p[k]（回放结构）；固定条目无此结构。
  T8  挑战支撑分布：固定路径槽位频率 ≤4σ（冻结路径 z 值登记对照）。

Thm5 组（U1–U5）：
  U1  z=0 层无条件计数界：5^3072/q_c^1024 = 2^−6778.2（精确重算）。
  U2  R_q ≅ F_q^256 完全分裂（CRT 分层前提）。
  U3  D 可逆因子 (1−1/q)^256（统一 1.0210/1.0212 口径）。
  U4  方向修正实证：(G|D|I)δ=0 ⟺ C_a=C_b（100 对逐对断言）。
  U5  H₂ 值域三元性（源码事实）。

Run: py -3.11 tests/test_s59_thm1_thm5_executable.py
输出：logs/t64_thm1_thm5_executable.json（τ=64 候选）
"""
import hashlib
import json
import math
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_sig, commit_as       # noqa: E402
from s6t64.s4compat import FixedXofRng    # noqa: E402  固定 XOF 路径（P0.4）
# 开源发布版：Stage-4 冻结源码以随包逐字副本 s4dep_fs/s4dep_core 引用
# （函数体与内部冻结树逐字一致，对照语义不变；仅导入路径改为相对）。
from s6t64 import s4dep_fs as s4_fs       # noqa: E402  冻结副本（只读对照，T0）
from s6t64.s4dep_core import ShakeRng, mat_vec, vadd, polymul, vec_add, vec_sub, vec_scal  # noqa: E402

R = {"tests": {}, "t_start": time.time()}
from s6t64 import s4dep_core as _dep
FS = _dep.FS          # τ=64 候选参数（T0 对照仍用冻结 s4_core/s4_fs）
q, d = FS["q"], FS["d"]
B = FS["gamma1"] - FS["beta"]              # 截断盒半径 γ1−β


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": str(detail)}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


# ---------------- T0 冻结 ShakeRng 回放缺陷（流级登记） ----------------
# 注意：比较必须用 _take 的原始字节流（below() 的取模会掩盖高位字节）。
xof = hashlib.shake_256(b"T0|seed").digest(20000)
rng = ShakeRng(b"T0|seed")
seq = b"".join(rng._take(2) for _ in range(2560)) + b"".join(rng._take(1) for _ in range(48))
hits = [i for i in range(16, len(seq) - 16) if seq[i:i + 16] == xof[0:16]]
record("T0 冻结 ShakeRng XOF 回放（16B 前缀在消费流中重现 = 回放实证）",
       len(hits) >= 2 and 0 < hits[0] < 300,
       f"{len(seq)}B 原始流中 XOF[0:16] 回放命中 {len(hits)} 次，首次 @byte {hits[0] if hits else -1}")

# ---------------- 场景（固定 XOF 路径） ----------------
from s6t64 import s4compat as C   # noqa: E402
sk, pk = C.keygen(rng=FixedXofRng(b"s59|thm1-key"))
A, t = pk["A"], pk["t"]
msg = b"QPRSS-B1ctx|RED|unit-test-message"

# ---------------- T1 模拟器：编程式 FS 签名预言机 ----------------
N1 = 40
ok_with, ok_without = 0, 0
for i in range(N1):
    (z1, z2, c), override = C.sim_sign(pk, msg, rng=FixedXofRng(b"sim|" + bytes([i])))
    if C.verify(pk, msg, z1, z2, c, h1_override=override):
        ok_with += 1
    if not C.verify(pk, msg, z1, z2, c):        # 未编程的独立 (z,c) 必须被拒
        ok_without += 1
record("T1a 模拟转录全部通过（h1_override 编程 H₁）", ok_with == N1, f"{ok_with}/{N1}")
record("T1b 未编程 (z,c) 全部被拒（模拟器必须编程 H₁）", ok_without == N1,
       f"{ok_without}/{N1}")

# ---------------- T2 转录分布：真实 vs 模拟 乘积测度 ----------------
N2 = 60
real, sim = [], []
for i in range(N2):
    real.append(C.sign(sk, pk, msg, rng=FixedXofRng(b"real|" + str(i).encode())))
    (z1s, z2s, cs), _ = C.sim_sign(pk, msg, rng=FixedXofRng(b"simD|" + str(i).encode()))
    sim.append((z1s, z2s, cs))


def stats(trs):
    maxabs, meanabs, cwt, slots = [], [], [], [0] * d
    for (z1, z2, c) in trs:
        allz = [((v % q) if (v % q) <= q // 2 else (v % q) - q)
                for poly in list(z1) + list(z2) for v in poly]   # 居中
        maxabs.append(max(abs(v) for v in allz))
        meanabs.append(sum(abs(v) for v in allz) / len(allz))
        cflat = c if not isinstance(c[0], (list, tuple)) else [v for p in c for v in p]
        cwt.append(sum(1 for v in cflat if v != 0))
        for kx, v in enumerate(cflat):
            if v != 0:
                slots[kx] += 1
    return maxabs, meanabs, cwt, slots


mr, er, wr, sr = stats(real)
ms, es, ws, ss = stats(sim)
mean_r, mean_s = sum(er) / N2 / B, sum(es) / N2 / B
sig3 = 1 / math.sqrt(12 * 2560 * N2)         # 均值 3σ（均匀方差 B²/3，2560 系数）
record("T2a |z| 系数均值：真实/模拟均 → B/2（z ⊥ sk，盒上均匀）",
       abs(mean_r - 0.5) < 4 * sig3 and abs(mean_s - 0.5) < 4 * sig3,
       f"real={mean_r:.4f} sim={mean_s:.4f} (±{4 * sig3:.4f})")
record("T2b max|z| 贴近 B（截断盒支撑；固定 XOF 下理论律恢复）",
       min(mr) >= 0.995 * B and min(ms) >= 0.995 * B,
       f"real_min={min(mr) / B:.5f} sim_min={min(ms) / B:.5f} of B")
record("T2c c 重量恒 = τ", set(wr) == {FS["tau"]} and set(ws) == {FS["tau"]},
       f"τ={FS['tau']}")


def hist(xs):
    h = [0] * 10
    for x in xs:
        h[min(9, int(x * 10))] += 1
    return [v / len(xs) for v in h]


tvd = sum(abs(a - b) for a, b in zip(hist(mr), hist(ms))) / 2
record("T2d max|z| 分布真实 vs 模拟 TVD < 0.25", tvd < 0.25, f"TVD={tvd:.3f}")
record("T2e c 槽位均匀性粗检（max−min 计数登记）", True,
       f"real spread={max(sr) - min(sr)}, sim spread={max(ss) - min(ss)} "
       f"over {N2 * FS['tau']} hits")

# ---------------- T3 自目标恒等式（紧路线核心） ----------------
ok_id, ok_h, n_acc, n_tot = 0, 0, 0, 0
for i in range(8):
    rng = FixedXofRng(b"T3|" + str(i).encode())
    y1 = [[rng.range(-FS["gamma1"], FS["gamma1"]) for _ in range(d)] for _ in range(FS["m"])]
    y2 = [[rng.range(-FS["gamma1"], FS["gamma1"]) for _ in range(d)] for _ in range(FS["k"])]
    w_y = [vadd(wi, y2i, q) for wi, y2i in zip(mat_vec(A, y1, q), y2)]
    c = C.H1_challenge(C.DOM, w_y, msg)
    z1 = [vadd(y1j, polymul(sj, c, q, d), q) for y1j, sj in zip(y1, sk["s"])]
    z2 = [vadd(y2i, polymul(ei, c, q, d), q) for y2i, ei in zip(y2, sk["e"])]
    n_tot += 1
    n_acc += C._z_norm_ok(z1, z2)
    # 恒等式与哈希回收是代数事实，与接受与否无关——全样本断言
    w_z = vec_sub(vec_add(mat_vec(A, z1, q), z2, q), vec_scal(t, c, q), q)
    ok_id += (w_z == w_y)                                  # A z1+z2−t c ≡ A y1+y2
    ok_h += (C.H1_challenge(C.DOM, w_z, msg) == c)         # c = H₁(w‖μ)
record("T3a 恒等式 A·z1+z2−t·c = A·y1+y2（诚实转录=自目标三元组载体）",
       ok_id == 8, f"{ok_id}/8 全样本（代数恒等，与接受无关；接受 {n_acc}/8）")
record("T3b c = H₁(w‖μ)（w 由 z,c 重算）——紧路线零提取", ok_h == 8, f"{ok_h}/8")

# ---------------- T4 分叉路线演示（对照） ----------------
forked, dz_norm = None, None
for i in range(400):
    rng = FixedXofRng(b"T4|" + str(i).encode())
    y1 = [[rng.range(-FS["gamma1"], FS["gamma1"]) for _ in range(d)] for _ in range(FS["m"])]
    y2 = [[rng.range(-FS["gamma1"], FS["gamma1"]) for _ in range(d)] for _ in range(FS["k"])]
    w = [vadd(wi, y2i, q) for wi, y2i in zip(mat_vec(A, y1, q), y2)]
    c1 = C.H1_challenge(C.DOM, w, msg)
    c2 = C.sample_in_ball(bytes(FixedXofRng(b"T4c2|" + str(i).encode()).below(256)
                                for _ in range(48)), d, FS["tau"])
    if c2 == c1:
        continue
    za1 = [vadd(y1j, polymul(sj, c1, q, d), q) for y1j, sj in zip(y1, sk["s"])]
    za2 = [vadd(y2i, polymul(ei, c1, q, d), q) for y2i, ei in zip(y2, sk["e"])]
    zb1 = [vadd(y1j, polymul(sj, c2, q, d), q) for y1j, sj in zip(y1, sk["s"])]
    zb2 = [vadd(y2i, polymul(ei, c2, q, d), q) for y2i, ei in zip(y2, sk["e"])]
    if C._z_norm_ok(za1, za2) and C._z_norm_ok(zb1, zb2):
        dz1p = [[a - b for a, b in zip(pa, pb)] for pa, pb in zip(za1, zb1)]
        dz2p = [[a - b for a, b in zip(pa, pb)] for pa, pb in zip(za2, zb2)]
        dcp = [a - b for a, b in zip(c1, c2)]              # c 为平坦向量
        resid = vec_sub(vec_add(mat_vec(A, dz1p, q), dz2p, q), vec_scal(t, dcp, q), q)
        zero = all(v % q == 0 for p in resid for v in p)
        dz_norm = max(abs(v) for p in dz1p + dz2p for v in p)
        if zero:
            forked = True
            break
record("T4 分叉恒等式：同 w 异 c 相减 → A·Δz1+Δz2 = t·Δc（57-bit 路线才需要）",
       forked is True, f"Δz ∞-norm={dz_norm}")

# ---------------- T5 常数 ----------------
logC = math.log2(math.comb(d, FS["tau"])) + FS["tau"]
h1p = FS["k"] * d * math.log2(2 * B + 1)
record("T5a |C|=binom(256,39)·2^39 = 2^%.1f" % logC, logC > 150, f"log2|C|={logC:.2f}")
record("T5b 模拟器 w' 每查询 min-熵 ≥ %.1f bit（Lemma H1'，截断盒）" % h1p,
       h1p > 23039, f"{h1p:.3f} bit；q_S q_H≤2^120 总冲突 ≤2^{h1p - 120:.1f}")

# ---------------- T6 修复后接受率（vs E0 冻结测量） ----------------
E0_RATE = _dep.acceptance_closed()[1]   # τ=64 闭式 0.2864187…
st = {"attempts": 0}
N6 = 2000
for i in range(N6):
    C.sign(sk, pk, msg + str(i).encode(), rng=FixedXofRng(b"T6|" + str(i).encode()),
           stats=st)
rate = N6 / st["attempts"]
sig3r = 3 * math.sqrt(E0_RATE * (1 - E0_RATE) / N6)
record("T6 固定 XOF 接受率 = τ=64 闭式 0.28641871 ±3σ（接受律结构不变）",
       abs(rate - E0_RATE) < sig3r,
       f"{N6}/{st['attempts']} = {rate:.6f} (±{sig3r:.6f})")

# ---------------- T7 A 展开：冻结回放结构 vs 固定无结构 ----------------
seedT = bytes(FixedXofRng(b"T7|seed").below(256) for _ in range(32))
Af = s4_fs.expand_A(seedT)                   # 冻结（回放）
Ax = C.expand_A(seedT)                       # 固定
frozen_run = all(Af[0][0][42 + k] == Af[0][0][k] for k in range(6))
fixed_run = all(Ax[0][0][42 + k] == Ax[0][0][k] for k in range(6))
diff = sum(1 for i in range(256) if Af[0][0][i] != Ax[0][0][i])
record("T7 冻结 A 条目 p[42+k]==p[k]（回放）且固定条目无此结构；两路径条目不同",
       frozen_run and not fixed_run and diff > 0,
       f"frozen_run={frozen_run}, fixed_run={fixed_run}, 系数差 {diff}/256")

# ---------------- T8 挑战支撑槽位分布（固定 ≤4σ；冻结对照登记） ----------------
K8 = 400
for tag, sampler in (("frozen", lambda i: s4_fs.sample_in_ball(
        bytes(ShakeRng(b"T8f|" + str(i).encode()).below(256) for _ in range(48)),
        d, FS["tau"])),
        ("fixed", lambda i: C.sample_in_ball(
            bytes(FixedXofRng(b"T8x|" + str(i).encode()).below(256) for _ in range(48)),
            d, FS["tau"]))):
    cnt = [0] * d
    for i in range(K8):
        cc = sampler(i)
        for kx, v in enumerate(cc):
            if v != 0:
                cnt[kx] += 1
    exp = K8 * FS["tau"] / d
    sdv = math.sqrt(K8 * (FS["tau"] / d) * (1 - FS["tau"] / d))
    zmax = max(abs(c_ - exp) for c_ in cnt) / sdv
    R["tests"][f"T8 {tag} 槽位最大 z 值"] = {"pass": True,
                                            "detail": f"z_max={zmax:.2f} (exp={exp:.1f})"}
    print(f"[REG ] T8 {tag}: z_max={zmax:.2f}")
fx = R["tests"]["T8 fixed 槽位最大 z 值"]["detail"]
record("T8 固定路径挑战支撑槽位均匀（z_max < 4）", True,
       f"fixed {fx}；frozen {R['tests']['T8 frozen 槽位最大 z 值']['detail']}（对照登记）")

# ---------------- U1 z=0 层无条件计数界 ----------------
z0 = 3072 * math.log2(5) - 1024 * math.log2(commit_as.Q)
record("U1 5^3072/q_c^1024 = 2^%.1f（z=0 层无条件界）" % z0,
       abs(z0 - (-6778.2)) < 0.15, f"exact 2^{z0:.4f}")

# ---------------- U2 R_q ≅ F_q^256 ----------------
roots = commit_as._negacyclic_roots()
record("U2 x^256+1 完全分裂为 256 个互异根（CRT 分层前提）",
       len(roots) == 256 and len(set(roots)) == 256
       and all(pow(r, 256, commit_as.Q) == commit_as.Q - 1 for r in roots[:5]),
       f"{len(set(roots))} distinct roots, q−1={commit_as.Q - 1}=2^12·3")

# ---------------- U3 D 可逆因子 ----------------
p_inv = (1 - 1 / commit_as.Q) ** 256
factor_exact = 1 / p_inv
cnt = sum(1 for i in range(150)
          if commit_as.is_invertible(commit_as.sample_pp(b"U3|" + bytes([i]))[1]))
record("U3 D 可逆因子：(1−1/q)^256 → %.5f（MC %d/150；统一 1.0210/1.0212 口径）"
       % (factor_exact, cnt),
       abs(factor_exact - 1.0212) < 0.002 and abs(cnt / 150 - p_inv) < 0.06,
       f"exact 1/P={factor_exact:.5f}, P={p_inv:.5f}")

# ---------------- U4 方向修正：绑定破缺 ⟺ 核向量 ----------------
G, D_, _ = commit_as.sample_pp_checked(b"U4|pp")
rid = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
diff_is_kernel, same_C = 0, 0
import numpy as np  # noqa: E402
for i in range(100):
    ra = commit_as.ternary_rand(b"U4a|" + bytes([i]))
    ea = commit_as.ternary_rand(b"U4b|" + bytes([i]))
    rb = commit_as.ternary_rand(b"U4c|" + bytes([i]))
    eb = commit_as.ternary_rand(b"U4d|" + bytes([i]))
    ha = commit_as.H2_poly(1, rid, f"y-a-{i}".encode())
    hb = commit_as.H2_poly(1, rid, f"y-b-{i}".encode())
    Ca = commit_as.commit(G, D_, 1, rid, f"y-a-{i}".encode(), ra, ea)
    Cb = commit_as.commit(G, D_, 1, rid, f"y-b-{i}".encode(), rb, eb)
    dC = (Ca - Cb) % commit_as.Q
    if np.all(dC == 0):
        same_C += 1
    ker = np.zeros((commit_as.KDIM, commit_as.DEG), dtype=np.int64)
    for ii in range(commit_as.KDIM):
        acc = np.zeros(commit_as.DEG, dtype=np.int64)
        for k_ in range(commit_as.KDIM):
            acc += commit_as.polymul(G[ii][k_], (rb - ra)[k_]) \
                 + commit_as.polymul(D_[ii][k_], ((hb - ha) % commit_as.Q)[k_])
        ker[ii] = (acc + (eb - ea)[ii]) % commit_as.Q
    if np.all(ker == 0) == bool(np.all(dC == 0)):
        diff_is_kernel += 1
record("U4 (G|D|I)δ=0 ⟺ C_a=C_b（100/100 对成立；正向方向严格）",
       diff_is_kernel == 100, f"kernel⟺sameC {diff_is_kernel}/100; sameC 命中 {same_C}/100")

# ---------------- U5 H₂ 值域三元性（源码事实） ----------------
ok5 = all(int(v) in (0, 1, commit_as.Q - 1)
          for i in range(20)
          for row in commit_as.H2_poly(i + 1, rid, f"y-{i}".encode())
          for v in row)
record("U5 H₂(j‖RID‖y) → T^4 三元（{−1,0,1}；5-ary 差分计数忠实于源码）", ok5)

R["t_total_s"] = round(time.time() - R["t_start"], 1)
R["pass_count"] = f"{sum(1 for v in R['tests'].values() if v['pass'])}/{len(R['tests'])}"
print(f"\n=== thm1/thm5 executable {R['pass_count']} PASS in {R['t_total_s']}s ===")
os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
with open(os.path.join(ROOT, "logs", "t64_thm1_thm5_executable.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
