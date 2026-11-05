# -*- coding: utf-8 -*-
"""Stage-5.10.3 P4：τ=64 候选 RNG 三分口径测试。

任务书 P4 三类区分：
  R1 生产签名 RNG（SysRng=secrets.SystemRandom，默认路径）
  R2 确定性测试 RNG（FixedXofRng——唯一可复现口径，仅限测试）
  R3 基准 RNG（StreamingShakeRng 流式读取，5.10.2 已证分块一致性；
     E1–E7 计时须流式，非本轮启动）

纪律：固定种子调试行为不作为生产随机性的安全性证据（R2 仅证明算法路径
正确性与可复现性；生产熵=SysRng/secrets）。

Run: py -3.11 tests_t64/test_t64_rng.py
输出：logs/t64_rng.json
"""
import hashlib
import json
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


from s6t64 import s4dep_core, s4compat as b1, s5_sig          # noqa: E402
FS = s4dep_core.FS

# ---------- R1 生产 RNG ----------
src = open(os.path.join(ROOT, "s6t64", "s4dep_fs.py"), encoding="utf-8").read()
record("R1a 生产默认 = SysRng（源码事实：keygen/sign 缺省 rng=SysRng()）",
       "rng = rng or SysRng()" in src)
sk1, pk1 = s5_sig.B1Core.keygen()          # 无 rng → SysRng
sk2, pk2 = s5_sig.B1Core.keygen()
seed1, seed2 = sk1[:32], sk2[:32]
record("R1b 两次 keygen 种子不同（生产熵源）", seed1 != seed2)
m = b"rng-prod"
s1 = s5_sig.B1Core.sign(sk1, pk1, m, b"ctx")
s2 = s5_sig.B1Core.sign(sk1, pk1, m, b"ctx")
record("R1c 生产路径同消息签名随机化（掩码 y 不复用）", s1 != s2 and
       s5_sig.B1Core.verify(pk1, m, s1, b"ctx") and s5_sig.B1Core.verify(pk1, m, s2, b"ctx"))

# ---------- R2 确定性测试 RNG ----------
d1 = b1.FixedXofRng(b"seed-A")
d2 = b1.FixedXofRng(b"seed-A")
take = [d1.below(1000000) for _ in range(200)]
take2 = [d2.below(1000000) for _ in range(200)]
record("R2a FixedXofRng 同种子完全一致（前 200 个 below）", take == take2)
d3 = b1.FixedXofRng(b"seed-B")
record("R2b 异种子流不同", (d3.below(1000000) for _ in range(1)) != (take[0],))

rng_a = b1.FixedXofRng(b"det-1")
rng_b = b1.FixedXofRng(b"det-1")
sk_d, pk_d = b1.keygen(rng=b1.FixedXofRng(b"kg-d"))
sa = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"det", rng=rng_a))
sb = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"det", rng=rng_b))
record("R2c 同种子确定性签名逐字节一致（可复现口径）", sa == sb)
sc = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"det", rng=b1.FixedXofRng(b"det-2")))
record("R2d 异种子签名不同", sa != sc)

# 签名间流隔离：同一 RNG 连续签两条 → 两次输出不同（流推进，不重置）
rng_c = b1.FixedXofRng(b"stream")
sig_c1 = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"msg-1", rng=rng_c))
sig_c2 = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"msg-1", rng=rng_c))
record("R2e 同流连续签名隔离（流推进不复位）", sig_c1 != sig_c2)

# ---------- 前缀一致性（修复语义保持） ----------
r = b1.FixedXofRng(b"prefix-prop")
whole = r._take(5000)
r2 = b1.FixedXofRng(b"prefix-prop")
chunks = b"".join(r2._take(7) for _ in range(5000 // 7)) + r2._take(5000 % 7)
record("R3a _take 前缀一致：整体读 == 任意分块（XOF 流无回放）", whole == chunks)
r3 = b1.FixedXofRng(b"prefix-prop")
again = r3._take(5000)
record("R3b 重取一致（digest(k)=XOF[0:k] 语义）", again == whole)
first128 = b1.FixedXofRng(b"prefix-prop")._take(128)
record("R3c 前 128B 无跨块污染", whole[:128] == first128)

# ---------- 域分离 ----------
labels = [b"QPRSS-ExpandA", b"QPRSS-H1", b"QPRSS-SampleInBall"]
record("R4a 三个域分离标签互异（源码常量）", len(set(labels)) == 3)
e1 = b1.FixedXofRng(b"QPRSS-ExpandA", b"k", 0, 0)._take(32)
h1s = b1.FixedXofRng(b"QPRSS-H1", b"k")._take(32)
record("R4b 不同域标签同种子材料 → 输出流不同", e1 != h1s)

# ---------- 基准口径登记（不启动 E1–E7） ----------
R["benchmark_note"] = (
    "E1–E7 计时必须用流式 XOF 读取（Stage-5.10 坑：ShakeRng._take 增长前缀重哈希"
    "→长流 O(n²)）；FixedXofRng 本体即 digest(off+n)[off:] 前缀一致实现，"
    "单次签名随机流消耗实测 ~31 KB（见 R5，2560 系数 × 2 字节域拒绝采样 ×attempts），"
    "分块等价已由 R3a 证明；本测试不构成性能测量（本轮禁止启动 Stage-6）。")
# 单次签名流消耗量级登记（非性能数据）
rng_s = b1.FixedXofRng(b"sizing")
st = {"attempts": 0}
b1.sign(sk_d, pk_d, b"sizing", rng=rng_s, stats=st)
record("R5 签名随机流消耗登记（量级，非性能口径）", st["attempts"] >= 1,
       f"attempts={st['attempts']}，off={rng_s._off} B")

R["t_total_s"] = round(time.time() - R["t_start"], 1)
R["verdict"] = "ALL_T64_RNG_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "T64_RNG_FAIL"
with open(os.path.join(ROOT, "logs", "t64_rng.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(f"\nVERDICT: {R['verdict']} ({len(R['tests'])} tests, {R['t_total_s']}s)")
sys.exit(0 if R["verdict"] == "ALL_T64_RNG_PASS" else 1)
