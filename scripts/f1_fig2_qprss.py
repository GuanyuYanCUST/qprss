# -*- coding: utf-8 -*-
"""F1 = 图 2 QPRSS 五阶段正式复测（论文对齐实现，pol_ver=2 一般编码）。

方法论镜像 R3.2K3 Q 臂（50 次正式观测/单元取中位数、25 次预热、
perf_counter_ns、无离值剔除、逐观测正确性 fail-closed），差异仅三处并全部
登记于输出 JSON：(1) 源 = 论文对齐修复实现（H_cert/BindId/M_resp5/一般
策略编码 ver=2）；(2) signer 证书 scope 为 RID 枚举（SF-A1 修复后强制，
工件绝对大小 +17B 级）；(3) 策略为显式 M={1} 的 ver=2 描述符。
KeyGen = 30 个独立会话（B1-65 keygen，不含 RA），中位数。
"""
import csv
import hashlib
import json
import os
import platform
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "run", "fixed_run"))

from s6t64 import canon                                   # noqa: E402
from s6t64 import policy as pol                          # noqa: E402
from s6t64 import s5_qprss as Q                          # noqa: E402
from s6t64 import s5_sig, s4compat as s4c                # noqa: E402

B1 = s5_sig.core("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
F_GRID = [8, 16, 32, 64, 128]
WARMUP, FORMAL = 25, 50
KG_SESSIONS = 30
FIELD_SEED = 20261015
OPS = ["SIGN", "VERIFY", "REDACT", "VVERIFY"]
V2 = pol.POL_VER_GENERAL


def gen_fields(F, seed=FIELD_SEED):
    """K3 fieldgen 同配方：attr_j=A;val_j=V + SHAKE 填充，恰 32B/字段。"""
    out = []
    for j in range(1, F + 1):
        core = f"attr_{j}=A;val_{j}=V".encode()
        pad = hashlib.shake_256(f"{seed}|{j}".encode()).digest(32)
        out.append((core + pad)[:32])
    assert all(len(r) == 32 for r in out)
    return out


def redact_j(F):
    """K3 规则：j* = ceil(F/2)（1 基）∈ W={2..F}。"""
    return (F + 1) // 2


class Fixture:
    def __init__(self, F):
        sd = int.from_bytes(hashlib.sha256(f"PA|F1|Q|{F}".encode()).digest()[:8], "big")
        sdp = sd.to_bytes(8, "big")
        self.pp = Q.setup("B1", seed=sdp + b"|pp", pol_ver=V2)
        self.ra = Q.RA("B1")
        self.ra.sk, self.ra.pk = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg-ra"))
        sk_s, pk_s = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg0"))
        self.cert_s = self.ra.issue(RID[:12] + b"SGNR", pk_s, b"signer",
                                    ((RID,), b"*"), 0, 1 << 62)
        sk_r, pk_r = B1.keygen(rng=s4c.FixedXofRng(sdp + b"|kg1"))
        self.cert_r = self.ra.issue(b"\x01" * 16, pk_r, b"physician",
                                    ((RID,), b"*"), 0, 1 << 62)
        self.sk_s, self.sk_r = sk_s, sk_r
        self.ys = {k: v for k, v in enumerate(gen_fields(F), start=1)}
        self.sdig = canon.schema_digest(
            [(k, ("Patient", f"attr{k}"), "str") for k in range(1, F + 1)])
        self.W = frozenset(range(2, F + 1))
        self.P0 = pol.Policy(((b"physician", b"*"),), self.W, F, F,
                             m=frozenset({1}), ver=V2)
        self.vcfg = {"pk_ra": self.ra.pk}
        self.S = self.sign(sdp + b"|sg-w", sdp + b"|sg0-w")
        assert Q.verify(self.vcfg, self.S, "hist")
        self.jstar = redact_j(F)
        self.S2 = self.redact(sdp + b"|rd-w", 999)
        assert Q.verify(self.vcfg, self.S2, "hist")

    def sign(self, seed_sg, seed_sg0):
        return Q.signing(self.pp, self.sk_s, self.cert_s, RID, self.ys, self.P0,
                         rng=Q.make_rng(seed_sg), schema_digest=self.sdig,
                         sig_rng=s4c.FixedXofRng(seed_sg0))

    def redact(self, seed_rd, ts):
        keep = set(range(1, len(self.ys) + 1)) - {self.jstar}
        P1 = pol.Policy(((b"physician", b"*"),), self.W, len(self.ys) - 1,
                        len(self.ys), m=frozenset({1}), ver=V2)
        return Q.redact(self.pp, self.S, keep, P1, self.cert_r, self.sk_r, ts,
                        sig_rng=s4c.FixedXofRng(seed_rd))


def one_call(fx, op, F, gseq):
    sb = gseq.to_bytes(8, "big")
    if op == "SIGN":
        t0 = time.perf_counter_ns()
        S = fx.sign(sb + b"|sg", sb + b"|sg0")
        el = time.perf_counter_ns() - t0
        ok = Q.verify(fx.vcfg, S, "hist")
        return el / 1e6, "OK" if ok else "SIGN_OUTPUT_REJECTED"
    if op == "VERIFY":
        t0 = time.perf_counter_ns()
        ok = Q.verify(fx.vcfg, fx.S, "hist")
        el = time.perf_counter_ns() - t0
        return el / 1e6, "ACCEPT" if ok else "VERIFY_RETURNED_FALSE"
    if op == "REDACT":
        t0 = time.perf_counter_ns()
        S2 = fx.redact(sb + b"|rd", 1000 + gseq)
        el = time.perf_counter_ns() - t0
        ok = Q.verify(fx.vcfg, S2, "hist")
        return el / 1e6, "OK" if ok else "REDACT_OUTPUT_REJECTED"
    t0 = time.perf_counter_ns()
    ok = Q.verify(fx.vcfg, fx.S2, "hist")
    el = time.perf_counter_ns() - t0
    return el / 1e6, "ACCEPT" if ok else "VERIFY_RETURNED_FALSE"


def main():
    raw_path = os.path.join(ROOT, "results", "raw", "f1_fig2_qprss_raw.csv")
    sum_path = os.path.join(ROOT, "results", "summary", "f1_fig2_qprss_summary.json")
    os.makedirs(os.path.dirname(raw_path), exist_ok=True)
    env = dict(python=platform.python_version(),
               machine=platform.machine(), processor=platform.processor(),
               ts=time.strftime("%Y-%m-%dT%H:%M:%S"))
    rows, summary = [], {"environment": env, "regime": "50-obs median/unit, "
                       "25 warmup, KeyGen=30 independent sessions median",
                         "cells": {}}
    print("== F1 KeyGen: 30 independent sessions ==")
    kg = []
    for i in range(KG_SESSIONS):
        t0 = time.perf_counter_ns()
        sk, pk = B1.keygen(rng=s4c.FixedXofRng(b"PA|F1|kg|" + i.to_bytes(4, "big")))
        el = time.perf_counter_ns() - t0
        assert len(pk) == 3712 and len(sk) == 672
        kg.append(el / 1e6)
        rows.append(["KEYGEN", 0, i, "formal", el / 1e6, len(pk)])
    kg.sort()
    med = kg[len(kg) // 2]
    summary["cells"]["KEYGEN"] = dict(median_ms=round(med, 4),
                                      min_ms=round(kg[0], 4),
                                      max_ms=round(kg[-1], 4), n=KG_SESSIONS)
    print(f"  KeyGen median {med:.3f} ms (n={KG_SESSIONS})")

    for F in F_GRID:
        print(f"== F1 F={F}: fixture ==")
        fx = Fixture(F)
        for op in OPS:
            for k in range(WARMUP):
                el, st = one_call(fx, op, F, 900_000 + k)
                assert st in ("OK", "ACCEPT"), (op, F, k, st)
            for g in range(FORMAL):
                el, st = one_call(fx, op, F, g)
                assert st in ("OK", "ACCEPT"), (op, F, g, st)
                rows.append([op, F, g, "formal", el, 32 * F])
        for op in OPS:
            obs = sorted(r[4] for r in rows
                         if r[0] == op and r[1] == F and r[3] == "formal")
            summary["cells"][f"{op}|F{F}"] = dict(
                median_ms=round(obs[len(obs) // 2], 4),
                p25=round(obs[len(obs) // 4], 4), p75=round(obs[3 * len(obs) // 4], 4),
                min_ms=round(obs[0], 4), max_ms=round(obs[-1], 4), n=len(obs))
            print(f"  {op:8s} F={F:3d} median {obs[len(obs)//2]:9.3f} ms  (n={len(obs)})")

    with open(raw_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["op", "F", "obs", "phase", "ms", "payload_B"])
        w.writerows(rows)
    summary["notes"] = [
        "源=论文对齐修复实现（H_cert/BindId/M_resp5/一般策略 ver=2 显式 M={1}）",
        "signer 证书 RID 枚举 scope（SF-A1）——与 K3 时期通配 scope 相比工件绝对大小略增",
        "计时口径同 [0276]：Redact 含审计签名；hist Verify 含证书/原始签名/逐跳验签",
        "无离值剔除，全部原始观测入 CSV；FAIL 即中止（fail-closed）",
    ]
    with open(sum_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print(f"\nF1_DONE raw={raw_path}\n      summary={sum_path}")


if __name__ == "__main__":
    main()
