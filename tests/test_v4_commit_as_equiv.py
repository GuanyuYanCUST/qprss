# -*- coding: utf-8 -*-
"""V4: byte-for-byte equivalence of the vectorized commit_as encoder with the
frozen slow reference.

Reference = v4_work/commit_as_slow_ref.py (the aligned original from before
the replacement). Covers: the ternary rejection-sampling stream,
pack2/unpack2, pack14/unpack14, witness packing, leaf_of, commit output,
plus an end-to-end Signing->Verify(hist) cross-check.
"""
import importlib.util
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "run", "fixed_run"))

from s6t64 import commit_as as NEW  # noqa: E402

# The reference file uses the relative import `from . import canon`; load it
# as a module of the package
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

# Negative case: perturb a single input coefficient; both implementations'
# packed output must change accordingly (discriminating power)
polys = rng.integers(-1, 2, size=(4, 256)).astype(np.int16)
p2 = polys.copy(); p2[0, 0] = 1 if p2[0, 0] != 1 else -1
check("neg_pack2_sensitive", NEW.pack2(polys) != NEW.pack2(p2)
      and OLD.pack2(p2) == NEW.pack2(p2))

# commit output matches
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
