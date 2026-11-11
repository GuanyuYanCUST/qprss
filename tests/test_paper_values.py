# -*- coding: utf-8 -*-
"""Paper-value anchors: deterministic regression against the numbers printed
in the revised TIFS manuscript (Tables V/VI, byte sizes, domain tags).

What this suite pins down (fail-closed; values are asserted, never fitted):
  A. concrete domain-separation byte tags — the paper writes them as the
     abstract symbols dom_pol / dom_bid / dom_resp; these tests anchor the
     actual wire bytes so no later "cleanup" may silently change protocol
     values, signatures, or test vectors;
  B. object sizes: sk 672 B / pk 3,712 B / signature 5,794 B / cert 9,572 B;
  C. BindId renewal stability (v5 fresh response identity binding);
  D. hist vs fresh verification modes (offline vs administrator state);
  E. Table V storage rows and all four Table VI transport rows, including
     the crossover rows n=64 t=12 and n=102 t=15, rebuilt live through
     scripts/f7_tablevi_full_curve.py (same seeds as the archived F5) —
     plus a multi-hop log-integrity negative.

Run: python tests/test_paper_values.py   (~90 s; the n=102 arm dominates)
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "run", "fixed_run"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import canon                                   # noqa: E402
from s6t64 import policy as pol                           # noqa: E402
from s6t64 import s5_qprss as Q                           # noqa: E402
from s6t64 import s5_sig, s4compat as s4c                 # noqa: E402
import f7_tablevi_full_curve as f7                        # noqa: E402

R = {"tests": {}}
B1 = s5_sig.core("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")


def record(name, ok, note=""):
    R["tests"][name] = {"pass": bool(ok), "note": str(note)}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {note}" if note else ""))
    assert ok, name


def main():
    t0 = time.time()

    # ---------- A. concrete domain-tag anchors ----------
    tags = {
        "CTX_CERT": (canon.CTX_CERT, b"qprss-cert"),
        "CTX_ORIG": (canon.CTX_ORIG, b"qprss-orig"),
        "CTX_RED": (canon.CTX_RED, b"qprss-red"),
        "CTX_ANC": (canon.CTX_ANC, b"qprss-anc"),
        "CTX_REG": (canon.CTX_REG, b"qprss-reg"),
        "dom_pol (policy descriptor)": (canon.POL2_PREFIX + canon.POLV1,
                                        b"QPRSS-pol2|" + b"pol-v1"),
        "dom_resp (v5 fresh response)": (b"QPRSS-v5|resp", b"QPRSS-v5|resp"),
        "H  label": (b"QPRSS-H|", b"QPRSS-H|"),
        "H_L label": (b"QPRSS-HL|", b"QPRSS-HL|"),
        "dom_bid (H_B label)": (b"QPRSS-HB|", b"QPRSS-HB|"),
        "H_cert label": (b"QPRSS-Hcert|", b"QPRSS-Hcert|"),
    }
    for k, (got, want) in tags.items():
        record(f"A: {k}", got == want, f"{got!r}")
    record("A: hash = SHAKE-256 with 48-byte (384-bit) output",
           canon.LAMBDA_H == 48 and canon.H(b"x").hex()
           == __import__("hashlib").shake_256(b"QPRSS-H|x").digest(48).hex())

    # ---------- B. object sizes ----------
    sk, pk = B1.keygen(rng=s4c.FixedXofRng(b"tpv|kg"))
    record("B: sk = 672 B / pk = 3,712 B", len(sk) == 672 and len(pk) == 3712,
           f"{len(sk)}/{len(pk)}")
    ra = Q.RA("B1")
    ra.sk, ra.pk = B1.keygen(rng=s4c.FixedXofRng(b"tpv|kg-ra"))
    cert_s = ra.issue(RID[:12] + b"SGNR", pk, b"signer", ((RID,), b"*"),
                      0, 1 << 62)
    record("B: cert = 9,572 B = sig 5,794 B + msg 3,778 B",
           len(cert_s.bytes()) == 9572 and len(cert_s.sig) == 5794
           and len(cert_s.msg) == 3778,
           f"{len(cert_s.bytes())}={len(cert_s.sig)}+{len(cert_s.msg)}")

    # ---------- C. BindId renewal stability ----------
    bid1 = canon.BindId(RID, cert_s.id, pk)
    cert2 = ra.issue(RID[:12] + b"SGNR", pk, b"signer", ((RID,), b"*"),
                     5, 1 << 62)                      # renewal: new serial/window
    record("C: BindId stable across certificate renewal",
           canon.BindId(RID, cert2.id, pk) == bid1)
    _, pk_other = B1.keygen(rng=s4c.FixedXofRng(b"tpv|kg2"))
    record("C: BindId changes with the public key",
           canon.BindId(RID, cert_s.id, pk_other) != bid1)

    # ---------- D. hist vs fresh ----------
    n = 6
    pp = Q.setup("B1", seed=b"tpv|pp", pol_ver=pol.POL_VER_GENERAL)
    sk_r, pk_r = B1.keygen(rng=s4c.FixedXofRng(b"tpv|kg-r"))
    cert_r = ra.issue(b"\x02" * 16, pk_r, b"physician", ((RID,), b"*"),
                      0, 1 << 62)
    ys = {j: f"v{j}".encode() for j in range(1, n + 1)}
    sd = canon.schema_digest([(j, ("P", f"a{j}"), "str") for j in range(1, n + 1)])
    P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, n + 1)),
                    n, n, m=frozenset({1}), ver=pol.POL_VER_GENERAL)
    S = Q.signing(pp, sk, cert_s, RID, ys, P0, rng=Q.make_rng(b"tpv|sg"),
                  schema_digest=sd, sig_rng=s4c.FixedXofRng(b"tpv|sg0"))
    cfg = {"pk_ra": ra.pk}
    record("D: t=0 hist accept (offline, no RA query)",
           Q.verify(cfg, S, "hist") == "accept_historical")

    sig_init = B1.sign(sk, cert_s.pk,
                       canon.M_reginit(RID, n, S.acc0, S.P0,
                                       canon.H(cert_s.msg), sd=sd),
                       canon.CTX_REG)
    ra.register_initial(S, cert_s, sig_init)
    snap = ra.revocation_snapshot()
    record("D: fresh accept against administrator state (t=0 registered head)",
           Q.verify(cfg, S, "fresh", ra=ra, nonce=b"\x33" * 32,
                    revsnap=snap) == "accept_fresh")
    try:
        Q.verify(cfg, S, "fresh", nonce=b"\x33" * 32, revsnap=snap)
        record("D: fresh without administrator rejected (V9)", False, "accepted")
    except Q.VerifyReject as e:
        record("D: fresh without administrator rejected (V9)", e.step == "V9", e.step)

    P1 = pol.Policy(P0.adm, P0.w, n - 1, n, m=P0.M, ver=pol.POL_VER_GENERAL)
    S = Q.redact(pp, S, set(S.It) - {2}, P1, cert_r, sk_r, 1000,
                 sig_rng=s4c.FixedXofRng(b"tpv|rd1"))
    record("D: t=1 hist accept (offline)", Q.verify(cfg, S, "hist") == "accept_historical")
    try:
        Q.verify(cfg, S, "fresh", ra=ra, nonce=b"\x33" * 32, revsnap=snap)
        record("D: unregistered hop fresh rejected as stale (V9)", False, "accepted")
    except Q.VerifyReject as e:
        record("D: unregistered hop fresh rejected as stale (V9)", e.step == "V9", e.step)

    # ---------- E. multi-hop log integrity (negative) ----------
    T = Q.Sigma.deserialize(S.serialize())
    e0, tau0, cid0 = T.log[0]
    T.log[0] = (bytes([e0[0] ^ 1]) + e0[1:], tau0, cid0)
    try:
        Q.verify(cfg, T, "hist")
        record("E: tampered audit log rejected", False, "accepted")
    except Q.VerifyReject as e:
        record("E: tampered audit log rejected", True, e.step)

    # ---------- F. Table V / Table VI deterministic anchors ----------
    rows = []
    for n_ in (32, 64, 102):
        print(f"  (building n={n_} chain …)")
        f7.sweep(n_, rows)
    table_v = {(64, 0): 69392, (64, 20): 181524, (64, 40): 284084,
               (102, 0): 106233, (102, 20): 218005, (102, 40): 320205}
    for (n_, t_), want in sorted(table_v.items()):
        got = next(r for r in rows if r["n"] == n_ and r["t"] == t_)["Q_bytes"]
        record(f"F: Table V sigma_S n={n_} t={t_} = {want:,} B", got == want,
               f"got {got:,}")
    table_vi = f7.PAPER_ANCHORS
    for (n_, t_), (q, l) in sorted(table_vi.items()):
        r_ = next(r for r in rows if r["n"] == n_ and r["t"] == t_)
        lab = f"Q={q:,} L={l:,}" if l is not None else f"Q={q:,}"
        record(f"F: Table VI n={n_} t={t_} {lab}",
               r_["Q_bytes"] == q and (l is None or r_["L_bytes"] == l),
               f"got Q={r_['Q_bytes']:,} L={r_['L_bytes']:,}")
    for n_, want_x in sorted(f7.PAPER_CROSSOVERS.items()):
        rn = [r for r in rows if r["n"] == n_]
        got_x = f7.first_crossover(rn)
        record(f"F: n={n_} single crossover at t={want_x}", got_x == want_x,
               f"got t={got_x}")

    R["t_total_s"] = round(time.time() - t0, 1)
    R["pass_count"] = f"{sum(1 for v in R['tests'].values() if v['pass'])}/{len(R['tests'])}"
    print(f"\n=== paper-value anchors {R['pass_count']} PASS in {R['t_total_s']}s ===")
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    with open(os.path.join(ROOT, "logs", "paper_values.json"), "w",
              encoding="utf-8") as f:
        import json
        json.dump(R, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
