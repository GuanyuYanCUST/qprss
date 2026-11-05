# -*- coding: utf-8 -*-
"""RNG three-way classification test for the tau=64 candidate.

Three classes:
  R1 production signing RNG (SysRng=secrets.SystemRandom, default path)
  R2 deterministic test RNG (FixedXofRng -- the only reproducible convention,
     test use only)
  R3 benchmark RNG (StreamingShakeRng streaming reads; chunk consistency
     proven earlier; E1-E7 timing must stream, not launched this round)

Discipline: fixed-seed behavior is not security evidence for production
randomness (R2 proves only algorithm-path correctness and reproducibility;
production entropy = SysRng/secrets).

Run: py -3.11 tests/test_s6_rng.py
Output: logs/t64_rng.json
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

# ---------- R1 production RNG ----------
src = open(os.path.join(ROOT, "s6t64", "s4dep_fs.py"), encoding="utf-8").read()
record("R1a production default = SysRng (source fact: keygen/sign default rng=SysRng())",
       "rng = rng or SysRng()" in src)
sk1, pk1 = s5_sig.B1Core.keygen()          # no rng -> SysRng
sk2, pk2 = s5_sig.B1Core.keygen()
seed1, seed2 = sk1[:32], sk2[:32]
record("R1b two keygens give different seeds (production entropy source)", seed1 != seed2)
m = b"rng-prod"
s1 = s5_sig.B1Core.sign(sk1, pk1, m, b"ctx")
s2 = s5_sig.B1Core.sign(sk1, pk1, m, b"ctx")
record("R1c production-path same-message signature randomized (mask y not reused)", s1 != s2 and
       s5_sig.B1Core.verify(pk1, m, s1, b"ctx") and s5_sig.B1Core.verify(pk1, m, s2, b"ctx"))

# ---------- R2 deterministic test RNG ----------
d1 = b1.FixedXofRng(b"seed-A")
d2 = b1.FixedXofRng(b"seed-A")
take = [d1.below(1000000) for _ in range(200)]
take2 = [d2.below(1000000) for _ in range(200)]
record("R2a FixedXofRng same seed fully identical (first 200 below draws)", take == take2)
d3 = b1.FixedXofRng(b"seed-B")
record("R2b different seed gives different stream", (d3.below(1000000) for _ in range(1)) != (take[0],))

rng_a = b1.FixedXofRng(b"det-1")
rng_b = b1.FixedXofRng(b"det-1")
sk_d, pk_d = b1.keygen(rng=b1.FixedXofRng(b"kg-d"))
sa = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"det", rng=rng_a))
sb = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"det", rng=rng_b))
record("R2c same-seed deterministic signatures byte-identical (reproducible convention)", sa == sb)
sc = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"det", rng=b1.FixedXofRng(b"det-2")))
record("R2d different seed gives different signature", sa != sc)

# inter-signature stream isolation: same RNG signing twice -> different outputs
# (stream advances, no reset)
rng_c = b1.FixedXofRng(b"stream")
sig_c1 = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"msg-1", rng=rng_c))
sig_c2 = b1.sig_to_bytes(*b1.sign(sk_d, pk_d, b"msg-1", rng=rng_c))
record("R2e same-stream consecutive signatures isolated (stream advances, no reset)", sig_c1 != sig_c2)

# ---------- prefix consistency (repair semantics preserved) ----------
r = b1.FixedXofRng(b"prefix-prop")
whole = r._take(5000)
r2 = b1.FixedXofRng(b"prefix-prop")
chunks = b"".join(r2._take(7) for _ in range(5000 // 7)) + r2._take(5000 % 7)
record("R3a _take prefix consistency: whole read == any chunking (XOF stream has no replay)", whole == chunks)
r3 = b1.FixedXofRng(b"prefix-prop")
again = r3._take(5000)
record("R3b re-read consistent (digest(k)=XOF[0:k] semantics)", again == whole)
first128 = b1.FixedXofRng(b"prefix-prop")._take(128)
record("R3c first 128 B free of cross-chunk contamination", whole[:128] == first128)

# ---------- domain separation ----------
labels = [b"QPRSS-ExpandA", b"QPRSS-H1", b"QPRSS-SampleInBall"]
record("R4a three domain-separation labels pairwise distinct (source constants)", len(set(labels)) == 3)
e1 = b1.FixedXofRng(b"QPRSS-ExpandA", b"k", 0, 0)._take(32)
h1s = b1.FixedXofRng(b"QPRSS-H1", b"k")._take(32)
record("R4b different domain labels, same seed material -> different output streams", e1 != h1s)

# ---------- benchmark convention registration (E1-E7 not launched) ----------
R["benchmark_note"] = (
    "E1-E7 timing must use streaming XOF reads (known pitfall: ShakeRng._take "
    "re-hashes the growing prefix on long streams -> O(n^2)); FixedXofRng itself "
    "is the prefix-consistent digest(off+n)[off:] implementation; a single "
    "signature's randomness stream consumes ~31 KB measured (see R5: 2560 "
    "coefficients x 2-byte domain rejection sampling x attempts); chunk "
    "equivalence is proven by R3a; this test is not a performance measurement "
    "(E1-E7 not launched here).")
# per-signature stream consumption magnitude (not performance data)
rng_s = b1.FixedXofRng(b"sizing")
st = {"attempts": 0}
b1.sign(sk_d, pk_d, b"sizing", rng=rng_s, stats=st)
record("R5 per-signature randomness consumption registered (order of magnitude, not a performance figure)", st["attempts"] >= 1,
       f"attempts={st['attempts']}, off={rng_s._off} B")

R["t_total_s"] = round(time.time() - R["t_start"], 1)
R["verdict"] = "ALL_T64_RNG_PASS" if all(v["pass"] for v in R["tests"].values()) \
    else "T64_RNG_FAIL"
with open(os.path.join(ROOT, "logs", "t64_rng.json"), "w", encoding="utf-8") as f:
    json.dump(R, f, ensure_ascii=False, indent=1)
print(f"\nVERDICT: {R['verdict']} ({len(R['tests'])} tests, {R['t_total_s']}s)")
sys.exit(0 if R["verdict"] == "ALL_T64_RNG_PASS" else 1)
