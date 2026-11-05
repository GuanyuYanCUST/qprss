# -*- coding: utf-8 -*-
"""Stage-5.6 P0-4：基线 L（朴素顺序多签链，B1-65 同核）最小验证。

Run: py -3.11 tests/test_l_chain.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import l_chain as L

R = {"tests": {}}


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": detail}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def main():
    t0 = time.time()
    sk_s, pk_s = L.l_keygen()
    sk1, pk1 = L.l_keygen()
    sk2, pk2 = L.l_keygen()
    sk3, pk3 = L.l_keygen()

    doc0 = b"patient|fields|1..8|full-record-v0"
    sigma0 = L.l_sign_origin(sk_s, pk_s, doc0)
    record("T1 原始签（B1-65，5,785 B）", len(sigma0) == 5794)

    doc1 = b"patient|fields|1..8|full-record-v1-minus-field2"
    doc2 = b"patient|fields|1..8|full-record-v2-minus-field2-5"
    doc3 = b"patient|fields|1..8|full-record-v3-minus-field2-5-7"
    h1, t1 = L.l_hop(L.canon.H(b"Ldoc|" + doc0), doc1, b"redactor-1", sk1, pk1)
    h2, t2 = L.l_hop(h1, doc2, b"redactor-2", sk2, pk2)
    h3, t3 = L.l_hop(h2, doc3, b"redactor-3", sk3, pk3)
    hops = [(doc1, b"redactor-1", t1, pk1), (doc2, b"redactor-2", t2, pk2),
            (doc3, b"redactor-3", t3, pk3)]
    record("T2 3 跳顺序多签链验证 PASS", L.l_verify(pk_s, sigma0, doc0, hops),
           f"t={time.time()-t0:.1f}s")

    record("T3 篡改中间全文 → 拒",
           not L.l_verify(pk_s, sigma0, doc0,
                          [(doc1, b"redactor-1", t1, pk1),
                           (doc2 + b"X", b"redactor-2", t2, pk2), hops[2]]))
    record("T4 篡改 σ₀ → 拒",
           not L.l_verify(pk_s, bytes([sigma0[0] ^ 1]) + sigma0[1:], doc0, hops))
    record("T5 身份替换（hop2 用 pk1 验）→ 拒",
           not L.l_verify(pk_s, sigma0, doc0,
                          [hops[0], (doc2, b"redactor-2", t2, pk1), hops[2]]))
    # 关键对比属性：不出示中间全文（只给终态）则无法验证——链结构要求全历史
    record("T6 只出示终态文档（缺中间态）→ 拒",
           not L.l_verify(pk_s, sigma0, doc0, [(doc3, b"agg", t3, pk3)]))
    record("T7 τ 跨文档重放（hop2 τ 配 doc1'）→ 拒",
           not L.l_verify(pk_s, sigma0, doc0,
                          [hops[0], (b"other-doc", b"redactor-2", t2, pk2), hops[2]]))

    R["meta"] = {"per_hop_bytes": 5794, "note": "L 每跳=1 个 B1 签名；验证需全部中间全文文档",
                 "wall_s": round(time.time() - t0, 2)}
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "s56_l_chain_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    print(f"\nALL {len(R['tests'])} L-chain tests passed in {time.time()-t0:.1f}s -> {out}")


if __name__ == "__main__":
    main()
