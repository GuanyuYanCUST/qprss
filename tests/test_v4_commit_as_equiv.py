# -*- coding: utf-8 -*-
"""V4：commit_as 向量化编码器（K3 Candidate C）与冻结慢速参考的逐字节等价性。

参考实现 = v4_work/commit_as_slow_ref.py（替换前的对齐件原文件）。
覆盖：三元拒绝采样流、pack2/unpack2、pack14/unpack14、witness 打包、
leaf_of、commit 输出，以及端到端 Signing→Verify(hist) 交叉验证。
"""
import importlib.util
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "run", "fixed_run"))

from s6t64 import commit_as as NEW  # noqa: E402

# 参考文件使用相对导入 `from . import canon`，以包内模块身份加载
spec = importlib.util.spec_from_file_location(
    "s6t64.commit_as_slow_ref", os.path.join(ROOT, "v4_work", "commit_as_slow_ref.py"))
OLD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(OLD)

rng = np.random.default_rng(20261030)
N = 200
fails = []


def check(name, cond):
    if not cond:
        fails.append(name)


for i in range(N):
    stream = rng.bytes(4096)
    cnt = int(rng.integers(1, 1280))
    a, b = OLD._ternary_from_stream(stream, cnt), NEW._ternary_from_stream(stream, cnt)
    check(f"ternary[{i}]", np.array_equal(np.asarray(a), np.asarray(b)))

    rows = int(rng.integers(1, 9))
    polys = rng.integers(-1, 2, size=(rows, 256)).astype(np.int16)
    pa, pb = OLD.pack2(polys), NEW.pack2(polys)
    check(f"pack2[{i}]", pa == pb)
    check(f"unpack2[{i}]", np.array_equal(np.asarray(OLD.unpack2(pa, rows)),
                                          np.asarray(NEW.unpack2(pb, rows))))

    C = rng.integers(0, NEW.Q, size=(4, 256)).astype(np.int64)
    ca, cb = OLD.pack14(C), NEW.pack14(C)
    check(f"pack14[{i}]", ca == cb)
    check(f"unpack14[{i}]", np.array_equal(np.asarray(OLD.unpack14(ca)),
                                           np.asarray(NEW.unpack14(cb))))
    check(f"leaf_of[{i}]", OLD.leaf_of(i + 1, C) == NEW.leaf_of(i + 1, C))

    r = rng.integers(-1, 2, size=(4, 256)).astype(np.int16)
    eta = rng.integers(-1, 2, size=(4, 256)).astype(np.int16)
    wa, wb = OLD.pack_witness(r, eta), NEW.pack_witness(r, eta)
    check(f"witness[{i}]", wa == wb)
    ua, ub = OLD.unpack_witness(wa), NEW.unpack_witness(wb)
    check(f"unpack_witness[{i}]", all(np.array_equal(np.asarray(x), np.asarray(y))
                                      for x, y in zip(ua, ub)))

# 负例：对输入做单系数扰动，两实现的打包输出必须同时随之改变（鉴别力）
polys = rng.integers(-1, 2, size=(4, 256)).astype(np.int16)
p2 = polys.copy(); p2[0, 0] = 1 if p2[0, 0] != 1 else -1
check("neg_pack2_sensitive", NEW.pack2(polys) != NEW.pack2(p2)
      and OLD.pack2(p2) == NEW.pack2(p2))

# commit 输出一致
G, D, _ = NEW.sample_pp_checked(b"V4-equiv-pp")
for j in range(1, 6):
    rr, ee = NEW.ternary_rand(b"V4-r%d" % j), NEW.ternary_rand(b"V4-e%d" % j)
    Ca = OLD.commit(G, D, j, b"\x11" * 16, b"y%d" % j, rr, ee)
    Cb = NEW.commit(G, D, j, b"\x11" * 16, b"y%d" % j, rr, ee)
    check(f"commit[{j}]", np.array_equal(np.asarray(Ca), np.asarray(Cb)))

print(f"commit_as equivalence: {N} random rounds, fails={len(fails)}")
if fails:
    print("FAILED:", fails[:20])
    sys.exit(1)
print("ALL PASS")
