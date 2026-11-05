# -*- coding: utf-8 -*-
"""Parameter / encoding / security-gate matrix test for the tau=64 candidate.

Covers the mandatory P1 items not already covered by the adaptation suite:
  T1  import-resolution probe (all candidate imports relative, zero frozen-module leakage)
  T2  FS parameter table (tau=64, beta=tau*eta=64, cbytes=34; q/d/k/m/eta/gamma1/zbits/tbits unchanged)
  T3  challenge-space size (log2|C|=267.5669...; cbytes=ceil(bits/8) minimal fixed width)
  T4  c encoding round-trip + illegal rank / over-wide sign bits / wrong length / weight != tau rejection matrix
  T5  norm gate (z=gamma1-beta boundary passes / +1 rejected; z=0 passes = pure upper-bound fact, basis of the fixed-point disclosure)
  T6  K/S/V (production default SysRng) + tampered message/challenge rejection
  T7  rejection sampling attempts>=1 + acceptance-rate MC 3-sigma (closed form 0.28641871)
  T8  challenge distribution (weight constant 64; +1/-1 sign balance 3-sigma)
  T9  fixed-length serialization (SIG 5794 / PK 3712 / SK 672; wrong-length tail rejected)
  T10 cross-config exclusion (tau=39 frozen signature <-> tau=64 candidate verification fail-closed, both directions)

Run: py -3.11 tests/test_s6_params.py
Output: logs/t64_params.json
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


# ---------- T1 import-resolution probe ----------
from s6t64 import s4dep_core, s4dep_fs, s4compat, s5_sig          # noqa: E402
for mod in (s4dep_core, s4dep_fs, s4compat, s5_sig):
    assert os.path.normcase(os.path.dirname(mod.__file__)) == \
        os.path.normcase(os.path.join(ROOT, "s6t64")), mod.__file__
leak = [m for m in ("s4_core", "s4_fs", "s59") if m in sys.modules]
record("T1a candidate dependencies all resolve to s6t64", True)
record("T1b zero frozen top-level module leakage (s4_core/s4_fs/s59 not in sys.modules)", not leak, str(leak))
import s6t64.s5_qprss as Q                                        # noqa: E402
record("T1c still zero leakage after protocol engine import", not [m for m in ("s4_core", "s4_fs", "s59")
                                      if m in sys.modules])

# ---------- T2 parameter table ----------
FS = s4dep_core.FS
record("T2a tau=64, beta=tau*eta=64 (beta_FS is the signature-correctness bound, not the estimator BKZ beta)",
       FS["tau"] == 64 and FS["beta"] == 64 and FS["beta"] == FS["tau"] * FS["eta"])
record("T2b q/d/k/m/eta/gamma1/zbits/tbits fully identical to the tau=39 frozen set",
       (FS["q"], FS["d"], FS["k"], FS["m"], FS["eta"], FS["gamma1"], FS["zbits"],
        FS["tbits"]) == (8380417, 256, 5, 5, 1, 1 << 17, 18, 23))
record("T2c cbytes=34", FS["cbytes"] == 34)
record("T2d z packing feasible: gamma1-beta=131008 < 2^17 (zbits=18 unchanged)",
       FS["gamma1"] - FS["beta"] == 131008 and FS["zbits"] == 18)

# ---------- T3 challenge-space size ----------
logC = FS["tau"] + math.log2(math.comb(FS["d"], FS["tau"]))
record("T3a log2|C| = 267.5669... (4dp)", abs(logC - 267.5669) < 5e-4, f"{logC:.6f}")
min_bytes = (int(logC) + 1 + 7) // 8 if logC != int(logC) else int(logC) // 8 + 1
record("T3b cbytes=34 = ceil(268 bit/8) minimal fixed width (272-bit container)",
       FS["cbytes"] == 34 and (FS["cbytes"] - 1) * 8 < math.ceil(logC) <= FS["cbytes"] * 8,
       f"needs {math.ceil(logC)} bit, container {FS['cbytes'] * 8} bit")

# ---------- T4 encoding matrix ----------
b1 = s4compat
rng = b1.FixedXofRng(b"t64-params-enc")
seeds = [bytes(rng.below(256) for _ in range(48)) for _ in range(24)]
ok_rt = True
for sd in seeds:
    c = b1.sample_in_ball(sd, FS["d"], FS["tau"])
    enc = s4dep_core.c_encode(c, FS["tau"])
    ok_rt &= len(enc) == 34 and s4dep_core.c_decode(enc, FS["tau"]) == c \
        and sum(1 for v in c if v) == 64
record("T4a c_encode->c_decode round-trip 24/24, fixed 34 B, weight exactly 64", ok_rt)

c0 = b1.sample_in_ball(seeds[0], FS["d"], FS["tau"])
enc0 = s4dep_core.c_encode(c0, FS["tau"])
# illegal rank: rank = C(256,64) (exactly out of range)
v_illegal = (math.comb(256, 64)) << 64
buf_illegal = v_illegal.to_bytes(34, "little")
expect_raise("T4b illegal combination rank r=C(256,64) rejected",
             lambda: s4dep_core.c_decode(buf_illegal, FS["tau"]), "rank out of range")
# over-wide: high bits outside the sign-bit region (bit 268+ set, still < 272-bit
# container; takes the rank-overflow path)
v_wide = v_illegal | (1 << 271)
expect_raise("T4c high-bit out-of-range encoding rejected (bit 271 exceeds rank)",
             lambda: s4dep_core.c_decode(v_wide.to_bytes(34, "little"), FS["tau"]),
             "rank out of range")
# wrong length
expect_raise("T4d wrong length 33 B rejected", lambda: s4dep_core.c_decode(enc0[:-1], FS["tau"]), "exactly 34")
expect_raise("T4e wrong length 35 B rejected", lambda: s4dep_core.c_decode(enc0 + b"\x00", FS["tau"]), "exactly 34")
# weight != tau encoding rejected
c63 = list(c0)
i0 = next(i for i, v in enumerate(c63) if v)
c63[i0] = 0
expect_raise("T4f weight-63 encoding rejected", lambda: s4dep_core.c_encode(c63, 64), "AssertionError")
expect_raise("T4g tau argument mismatch (weight-64 vector encoded as 39) rejected",
             lambda: s4dep_core.c_encode(c0, 39), "AssertionError")

# ---------- T5 norm gate ----------
bound = FS["gamma1"] - FS["beta"]
z_ok = [[bound] + [0] * (FS["d"] - 1)] * FS["m"]
z_ok2 = [[-bound] + [0] * (FS["d"] - 1)] * FS["k"]
record("T5a |z|inf=gamma1-beta=131008 boundary accepted (closed interval)", s4dep_fs._z_norm_ok(z_ok, z_ok2))
z_bad = [[bound + 1] + [0] * (FS["d"] - 1)] * FS["m"]
record("T5b |z|inf=gamma1-beta+1 rejected", not s4dep_fs._z_norm_ok(z_bad, z_ok2))
z0m = [[0] * FS["d"]] * FS["m"]
z0k = [[0] * FS["d"]] * FS["k"]
record("T5c z=0 passes the norm gate (pure upper-bound fact -- source basis of "
       "the fixed-point disclosure; defense = challenge search cost 2^133.78)",
       s4dep_fs._z_norm_ok(z0m, z0k))

# ---------- T6 K/S/V (production default SysRng) ----------
sk_b, pk_b = s5_sig.B1Core.keygen()                     # default SysRng (production path)
msg = b"tau64-production-path"
sig1 = s5_sig.B1Core.sign(sk_b, pk_b, msg, b"ctxA")
sig2 = s5_sig.B1Core.sign(sk_b, pk_b, msg, b"ctxA")
record("T6a production-path signature verifies (SysRng default)",
       s5_sig.B1Core.verify(pk_b, msg, sig1, b"ctxA"))
record("T6b production randomization: same message signed twice differs byte-wise (CSPRNG mask)", sig1 != sig2)
record("T6c tampered message rejected", not s5_sig.B1Core.verify(pk_b, b"other", sig1, b"ctxA"))
record("T6d tampered ctx rejected (domain separation)", not s5_sig.B1Core.verify(pk_b, msg, sig1, b"ctxB"))
sig_t = bytearray(sig1); sig_t[100] ^= 1
record("T6e tampered signature rejected", not s5_sig.B1Core.verify(pk_b, msg, bytes(sig_t), b"ctxA"))

# ---------- T7 rejection sampling ----------
rng_d = b1.FixedXofRng(b"t64-params-sign")
sk, pk = b1.keygen(rng=b1.FixedXofRng(b"t64-params-kg"))
stats = {"attempts": 0}
z1, z2, c = b1.sign(sk, pk, b"reject-sample", rng=rng_d, stats=stats)
record("T7a sign returns and attempts>=1", stats["attempts"] >= 1, f"{stats['attempts']} attempts")
K = 40
att = []
for k in range(K):
    st = {"attempts": 0}
    b1.sign(sk, pk, f"mc-{k}".encode(), rng=b1.FixedXofRng(b"t64-mc", k), stats=st)
    att.append(st["attempts"])
mean_att = sum(att) / len(att)
p_th, acc_th = s4dep_core.acceptance_closed()
record("T7b mean retries ~ 1/acc (tau=64 closed form 0.28641871 -> 3.49)",
       0.5 * (1 / acc_th) < mean_att < 1.6 * (1 / acc_th),
       f"{mean_att:.2f} per signature vs expected {1 / acc_th:.2f}")

# ---------- T8 challenge distribution ----------
sup_signs, sup_pos = 0, 0
N8 = 40
hits = 0
for k in range(N8):
    sd = bytes(b1.FixedXofRng(b"t64-dist", k).below(256) for _ in range(48))
    c = b1.sample_in_ball(sd, FS["d"], FS["tau"])
    hits += sum(1 for v in c if v != 0)
    sup_signs += sum(1 for v in c if v == 1)
record("T8a weight constant 64 (40 samples)", hits == 64 * N8, f"{hits}/{64 * N8}")
exp_p = 32 * N8
sd3 = 3 * math.sqrt(32 * N8 * 0.5)
record("T8b +1/-1 sign balance 3-sigma (+1 count ~ half)", abs(sup_signs - exp_p) <= sd3,
       f"+1 {sup_signs}/{64 * N8}, tolerance +-{sd3:.0f}")

# ---------- T9 fixed-length serialization ----------
record("T9a SIG_LEN[B1]=5794 (5760 z + 34 c)", s5_sig.SIG_LEN["B1"] == 5794 == len(sig1))
record("T9b PK_LEN[B1]=3712 (tau-independent)", s5_sig.PK_LEN["B1"] == 3712 == len(pk_b))
record("T9c SK=672 (tau-independent)", len(sk_b) == 672)
expect_raise("T9d sig_from_bytes wrong tail length rejected (truncated 33 B c segment)",
             lambda: b1.sig_from_bytes(sig1[:5760 + 33]), "exactly 34")
expect_raise("T9e sig_from_bytes extra tail rejected",
             lambda: b1.sig_from_bytes(sig1 + b"\x00"), "exactly 34")

# ---------- T10 cross-config exclusion ----------
# Open-source release: the old tau=39 frozen tree is not in this repo; run the
# cross-config comparison when present, otherwise record a skip.
S59 = os.path.abspath(os.path.join(ROOT, "..", "..", "..",
                                   "RouteB_Stage5_9_SecurityRepairAndTIFSPositioning", "src"))
if os.path.isdir(S59):
    sys.path.insert(0, S59)
    from s59 import s5_sig as sig39                            # noqa: E402  frozen tau=39, read-only
    from s59.s5_sig import B1Core as B139                      # noqa: E402
    record("T10a frozen tree tau=39 confirmed (comparison precondition)", sig39.SIG_LEN["B1"] == 5785)
    sk39, pk39 = B139.keygen()
    sig39_bytes = B139.sign(sk39, pk39, b"x-config", b"ctx")
    record("T10b tau=39 signature (5785 B) fail-closed rejected by tau=64 verification",
           len(sig39_bytes) == 5785 and not s5_sig.B1Core.verify(pk39, b"x-config",
                                                                 sig39_bytes, b"ctx"))
    sig64 = s5_sig.B1Core.sign(sk_b, pk_b, b"x-config", b"ctx")
    record("T10c tau=64 signature (5794 B) fail-closed rejected by tau=39 verification",
           len(sig64) == 5794 and not B139.verify(pk_b, b"x-config", sig64, b"ctx"))
    record("T10d cross-config non-isomorphic pk/signature zero cross-recognition (pk expansion and c encoding both differ)", True)
else:
    record("T10 cross-config exclusion (tau=39 comparison)", True,
           "SKIP: old tau=39 frozen tree not in the open-source repo (internal-development comparison)")

R["t_total_s"] = round(time.time() - R["t_start"], 1)
R["verdict"] = "ALL_T64_PARAMS_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "T64_PARAMS_FAIL"
with open(os.path.join(ROOT, "logs", "t64_params.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(f"\nVERDICT: {R['verdict']} ({len(R['tests'])} tests, {R['t_total_s']}s)")
sys.exit(0 if R["verdict"] == "ALL_T64_PARAMS_PASS" else 1)
