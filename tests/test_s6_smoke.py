# -*- coding: utf-8 -*-
"""Stage-5 Phase-4 集成闸门冒烟（B1 主方案）。

1) n ∈ {16,64,102,256} 完整 Sign/Redact(t=5)/Verify；
2) t ∈ {1,5,10,20,40} 合法长链 @n=102，d₀=40，每跳 1 删除，逐链 verify=PASS；
3) n=102 固定最终 r=62：t=40（每轮 1）/t=8（每轮 5）/t=1（一次 40）→ 同一终态字段集；
4) 真实逐操作计时 + 字节统计；
5) 负测试抽查（篡改字段/非法三元/越权/重排）；
6) 定位声明：冒烟≠论文性能统计样本（E1–E7 正式实验另跑，同硬件/同 reps/交错）。

Run: py -3.11 tests/test_s5_smoke.py
"""
import hashlib
import json
import os
import platform
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon
from s6t64.policy import Policy
from s6t64.s5_qprss import VerifyReject
from s6t64.s5_sig import core

R = {"tests": {}, "grid": {}, "chains": [], "negatives": []}


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": detail}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def chain(n, t, per_hop, S0, pp, cr, sk_r, P0, dels):
    """从 S0 跑 t 跳、每跳删 per_hop 个（dels 展开平铺）。返回 (S_t, 计时, 尺寸)。"""
    S = S0
    hop_ms, sizes = [], [len(S.serialize())]
    it = iter(dels)
    for i in range(1, t + 1):
        J = [next(it) for _ in range(per_hop)]
        I = S.It - set(J)
        P = Policy(P0.adm, P0.w, P0.d - i, n)
        t1 = time.perf_counter()
        S = Q.redact(pp, S, I, P, cr, sk_r, 2000 + i)
        hop_ms.append(round((time.perf_counter() - t1) * 1000, 1))
        sizes.append(len(S.serialize()))
    return S, hop_ms, sizes


def main():
    t0 = time.time()
    ra = Q.RA("B1")
    pp = Q.setup("B1", seed=b"s5-smoke")
    sk_s, pk_s = core("B1").keygen()
    # SF-A1 适配：signer 证书 scope 显式枚举全部测试 RID（本测试按 n 派生 rid）
    _rids = tuple(bytes([n & 0xFF] * 16) for n in (16, 64, 102, 256))
    cert_s = ra.issue(bytes(16), pk_s, b"signer", (_rids, b"*"), 0, 2**40)
    sk_r, pk_r = core("B1").keygen()
    cr = ra.issue(b"\x21" * 16, pk_r, b"physician", (b"*", b"*"), 0, 2**40)

    def make_S0(n):
        ys = {j: canon.enc32(j) * 2 for j in range(1, n + 1)}
        P0 = Policy([(b"physician", b"*")], frozenset(range(2, n + 1)), 40, n)
        t1 = time.perf_counter()
        S0 = Q.signing(pp, sk_s, cert_s, bytes([n & 0xFF] * 16), ys, P0,
                       rng=Q.make_rng(b"s5-smoke-%d" % n))
        ms = round((time.perf_counter() - t1) * 1000, 1)
        return S0, P0, ms

    # ---- 1) 规模扫描 n×t=5 ----
    for n in (16, 64, 102, 256):
        S0, P0, ms_sign = make_S0(n)
        S, hop_ms, sizes = chain(n, 5, 1, S0, pp, cr, sk_r, P0, list(range(2, 7)))
        t1 = time.perf_counter()
        acc = Q.verify({"pk_ra": ra.pk}, S, "hist")
        ms_ver = round((time.perf_counter() - t1) * 1000, 1)
        assert acc == "accept_historical"
        assert len(S.It) == n - 5
        R["grid"][n] = dict(sign_ms=ms_sign, redact_hop_ms=hop_ms, verify_ms=ms_ver,
                            sigma_bytes=sizes[-1], sigma0_bytes=sizes[0], r=n - 5)
        record(f"S-n{n} Sign/Redact×5/Verify 全过",
               True, f"sign {ms_sign}ms, hop {min(hop_ms):.0f}–{max(hop_ms):.0f}ms, "
                     f"verify {ms_ver}ms, |Σ₅| {sizes[-1]} B (r={n-5})")

    # ---- 2) 深度扫描 t∈{1,5,10,20,40} @n=102（每跳 1 删）----
    S0_102, P0_102, _ = make_S0(102)
    for t in (1, 5, 10, 20, 40):
        S, hop_ms, sizes = chain(102, t, 1, S0_102, pp, cr, sk_r, P0_102,
                                 list(range(2, t + 2)))
        t1 = time.perf_counter()
        acc = Q.verify({"pk_ra": ra.pk}, S, "hist")
        ms_ver = round((time.perf_counter() - t1) * 1000, 1)
        assert acc == "accept_historical" and len(S.It) == 102 - t
        R["chains"].append(dict(n=102, t=t, per_hop=1, r=102 - t, verify="PASS",
                                redact_hop_ms=hop_ms, verify_ms=ms_ver,
                                sigma_bytes=sizes[-1], growth_per_hop=round(
                                    (sizes[-1] - sizes[0]) / t, 1)))
        record(f"D-t{t} 合法长链 verify=PASS（d₀=40，r={102-t}）", True,
               f"hop均值 {sum(hop_ms)/t:.0f}ms, verify {ms_ver}ms, "
               f"|Σ| {sizes[-1]} B, 每跳增量 {R['chains'][-1]['growth_per_hop']} B")

    # ---- 3) r=62 轮次-深度解耦（同一终态字段集 {1,42..102}）----
    D40 = list(range(2, 42))
    fin = frozenset({1} | set(range(42, 103)))
    for t, per in ((40, 1), (8, 5), (1, 40)):
        S, hop_ms, sizes = chain(102, t, per, S0_102, pp, cr, sk_r, P0_102, D40)
        t1 = time.perf_counter()
        acc = Q.verify({"pk_ra": ra.pk}, S, "hist")
        ms_ver = round((time.perf_counter() - t1) * 1000, 1)
        same = frozenset(S.It) == fin
        assert acc == "accept_historical" and same
        R["chains"].append(dict(n=102, t=t, per_hop=per, r=62, verify="PASS",
                                same_final_set=True, redact_hop_ms=hop_ms,
                                verify_ms=ms_ver, sigma_bytes=sizes[-1]))
        record(f"X-t{t}x{per} r=62 同一终态字段集 verify=PASS", True,
               f"终态一致={same}, |Σ| {sizes[-1]} B, verify {ms_ver}ms")

    # ---- 4) 负测试抽查（n=16 链上）----
    S0_16, P0_16, _ = make_S0(16)
    S16, _, _ = chain(16, 2, 1, S0_16, pp, cr, sk_r, P0_16, [2, 3])

    def neg(name, fn, step):
        try:
            fn()
            ok, det = False, "accepted"
        except VerifyReject as e:
            ok, det = e.step == step, f"rejected@{e.step}"
        R["negatives"].append(dict(name=name, ok=ok, step=det))
        record(f"N-{name}", ok, det)

    Sd = Q.Sigma.deserialize(S16.serialize())
    Sd.fields[1] = (b"x", Sd.fields[1][1])
    neg("tamper-field", lambda: Q.verify({"pk_ra": ra.pk}, Sd, "hist"), "V4")
    Sd = Q.Sigma.deserialize(S16.serialize())
    y, w = Sd.fields[1]
    p = bytearray(w.packed)
    p[0] = 0xFF
    Sd.fields[1] = (y, Q.ASWitness(bytes(p), w.path))
    neg("non-ternary-witness", lambda: Q.verify({"pk_ra": ra.pk}, Sd, "hist"), "V3.1")
    a, b = S16.log[0], S16.log[1]
    Sd = Q.Sigma.deserialize(S16.serialize())
    Sd.log[0], Sd.log[1] = b, a
    neg("log-reorder", lambda: Q.verify({"pk_ra": ra.pk}, Sd, "hist"), "V6")
    sk_x, pk_x = core("B1").keygen()
    cx = ra.issue(b"\x31" * 16, pk_x, b"nurse", ((b"\x00" * 16,), frozenset({9})), 0, 2**40)
    fn = Q.forge_hop(S16, S16.It - {4}, Policy([(b"physician", b"*")],
                                                frozenset(range(2, 17)), 37, 16), cx, sk_x, 999)
    neg("out-of-scope", lambda: Q.verify({"pk_ra": ra.pk}, fn, "hist"), "V7.7")

    # ---- 环境/摘要 ----
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    srcs = {}
    for f in os.listdir(os.path.join(base, "s6t64")):
        if f.endswith(".py"):
            p = os.path.join(base, "s6t64", f)
            srcs[f] = hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]
    R["env"] = dict(python=sys.version.split()[0], machine=platform.machine(),
                    system=platform.system(), numpy=__import__("numpy").__version__,
                    note="冒烟计时=单次墙钟，非 E1–E7 正式统计（正式实验需 ≥30 reps 交错+冻结）")
    R["source_sha256_16"] = srcs
    record("ENV 登记完成", True, f"{R['env']['python']} / numpy {R['env']['numpy']} / "
                                f"{len(srcs)} 源文件摘要")

    R["wall_s"] = round(time.time() - t0, 1)
    R["verdict"] = "ALL_S5_SMOKE_PASS" if all(v["pass"] for v in R["tests"].values()) else "S5_SMOKE_FAIL"
    out = os.path.join(base, "data", "t64_smoke_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    print(f"VERDICT: {R['verdict']} ({len(R['tests'])} tests, {R['wall_s']}s) -> {out}")
    return 0 if R["verdict"] == "ALL_S5_SMOKE_PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
