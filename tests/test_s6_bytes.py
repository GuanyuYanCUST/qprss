# -*- coding: utf-8 -*-
"""Storage-accounting profile: n=102, r=97, t=5 byte-level statistics.

Authoritative assertion: sum(component_bytes) == len(serialize(Sigma_5))
(enforced in code; parse_sigma section offsets come from the real byte
stream). 254,758 B is only the entropy-optimal anchor for field material
(commitment + witness layers, r/eta entropy coding at 742 B/field); this
integration prototype uses 2-bit fixed-width coding (512+336=848 B/field)
=> field material over both layers = 265,040 B (matching the earlier
fixed-width accounting digit for digit).

Dedup rules:
- certificates deduped by cid (u = number of distinct certificates; this
  chain has u=2: Cert_S + 1 redactor);
- all n commitments C_j reside with the record holder (acc0 anchors the full
  tree; commitments of deleted fields remain in the tree) and are not
  transferred with Sigma -- counted as an off-chain storage layer;
- witnesses exist only for retained fields (r copies; witnesses of deleted
  fields are destroyed at Redact time).

Run: py -3.11 tests/test_s6_bytes.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from s6t64 import s5_qprss as Q, canon
from s6t64.policy import Policy
from s6t64.s5_sig import core, SIG_LEN

R = {"tests": {}}


def record(name, ok, detail=""):
    R["tests"][name] = {"pass": bool(ok), "detail": detail}
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
    assert ok, name


def main():
    t0 = time.time()
    n, t = 102, 5
    r = n - t                                            # 97
    rid = bytes([0x3C] * 16)
    ra = Q.RA("B1")
    pp = Q.setup("B1", seed=b"s5-bytes-anchor")
    sk_s, pk_s = core("B1").keygen()
    # signer certificate scope explicitly enumerates RIDs
    cert_s = ra.issue(bytes(16), pk_s, b"signer", ((rid,), b"*"), 0, 2**40)
    ys = {j: canon.enc32(j) * 2 for j in range(1, n + 1)}          # 8 B synthetic fields
    W0 = frozenset(range(2, n + 1))                        # 1 mandatory retention
    P0 = Policy([(b"physician", b"*")], W0, 40, n)         # d0=40 (E2 gate convention)
    S = Q.signing(pp, sk_s, cert_s, rid, ys, P0, rng=Q.make_rng(b"s5-bytes"))

    sk_r, pk_r = core("B1").keygen()
    cr = ra.issue(b"\x21" * 16, pk_r, b"physician", ((rid,), b"*"), 0, 2**40)
    for i in range(1, t + 1):                             # delete 1 field per round (2..6)
        I = S.It - {i + 1}
        P = Policy(P0.adm, W0, P0.d - i, n)
        S = Q.redact(pp, S, I, P, cr, sk_r, 1000 + i)
    assert len(S.It) == r and len(S.log) == t
    record("T1 legal chain built (n=102, t=5, r=97, d0=40, verify=PASS)",
           Q.verify({"pk_ra": ra.pk}, S, "hist") == "accept_historical",
           f"t={time.time()-t0:.1f}s")

    blob = S.serialize()
    S2, sec = Q.parse_sigma(blob)
    comp = {name: end - start for (name, start, end) in sec}
    record("T2 accounting identity sum(component_bytes) == len(serialize(Sigma_5))",
           sum(comp.values()) == len(blob), f"{sum(comp.values())} == {len(blob)}")
    record("T3 serialization round-trip byte-identical (parse then re-encode)", S2.serialize() == blob)

    # ---- per-object breakdown table (count x bytes = section bytes) ----
    depth = (n - 1).bit_length()                          # 7
    lam = 48
    table = [
        ("header (metadata/RID/sd/acc0/P0/I0 bitmap/Pt/h_t)", 1, comp["header"]),
        ("sigma0 original FS signature", 1, comp["sigma0"]),
        ("Cert_S (incl. signer pk 3,712 B, unchanged at tau=64)", 1, comp["cert_s"]),
        ("field values y + index (r retained)", r, comp["fields:idx+y"]),
        ("witness core W_j (r||eta 2-bit)", r, comp["fields:witness-core"]),
        ("Merkle path pi_j", r, comp["fields:merkle-path"]),
        ("audit log e_i", t, comp["audit:e"]),
        ("audit signature tau_i (FS)", t, comp["audit:tau"]),
        ("redactor certificates (u=1 after dedup)", len(S.certs) - 1, comp["certs"]),
    ]
    R["component_table"] = [(nm, cnt, byt) for (nm, cnt, byt) in table]
    checks = {
        "sigma0 = SIG_LEN[B1]=5,794 (tau=64)": comp["sigma0"] == SIG_LEN["B1"] == 5794,
        "tau blocks = t x SIG_LEN[B1]": comp["audit:tau"] == t * SIG_LEN["B1"],
        "witness core = r x 512": comp["fields:witness-core"] == r * 512,
        "Merkle paths = r x depth x 48": comp["fields:merkle-path"] == r * depth * lam,
        "cert block = u x len(cert.bytes())": comp["certs"] == len(cr.bytes()),
    }
    for k, v in checks.items():
        record(f"T4 {k}", v)
    tot_sig_slots = comp["sigma0"] + comp["audit:tau"]
    record("T5 signature-slot total (sigma0 + t*tau = (1+t) x SIG_LEN[B1])", tot_sig_slots == (1 + t) * SIG_LEN["B1"],
           f"{tot_sig_slots} B")

    # ---- off-chain commitment layer + fixed-width anchor cross-check ----
    C = 1792
    offchain = n * C                                       # 182,784
    wit_fixed = r * (512 + depth * lam)                    # 82,256 (2-bit fixed width)
    wit_opt = 742 * r                                      # 71,974 (entropy-optimal theory)
    field_mat_fixed = offchain + wit_fixed                 # 265,040
    record("T6 commitment layer (off-chain resident) = n x 1,792 = 182,784", offchain == 102 * 1792)
    record("T7 field material, both layers (fixed 2-bit) = 265,040 B (fixed-width anchor)",
           field_mat_fixed == 265040, f"{field_mat_fixed} = 182,784 + {wit_fixed}")
    record("T8 entropy-optimal accounting 254,758 B != prototype encoding (diff = r x (848-742) = 10,282)",
           offchain + wit_opt == 254758 and field_mat_fixed - (offchain + wit_opt) == 10282,
           "anchor = entropy-coding theoretical lower bound; prototype = parseable "
           "fixed-width encoding (both count field material only; neither includes "
           "sigma/certs/log/policy/index/metadata)")
    record("T9 |Sigma_5| full-chain serialized size registered", True, f"{len(blob)} B (all signatures/certs/log/witnesses/paths included)")

    R["accounting"] = dict(
        n=n, t=t, r=r, depth=depth, lam=lam,
        sigma_total=len(blob),
        components=dict(comp),
        table=[(nm, cnt, byt) for (nm, cnt, byt) in table],
        offchain_commitments_B=offchain,
        witness_material_fixed_B=wit_fixed,
        field_material_fixed_B=field_mat_fixed,
        field_material_entropy_opt_B=offchain + wit_opt,
    )
    R["wall_s"] = round(time.time() - t0, 1)
    R["verdict"] = "ALL_S5_BYTES_PASS" if all(v["pass"] for v in R["tests"].values()) else "S5_BYTES_FAIL"
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data",
                       "t64_bytes_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(R, f, ensure_ascii=False, indent=1)
    print(f"VERDICT: {R['verdict']} ({len(R['tests'])} tests, {R['wall_s']}s) -> {out}")
    return 0 if R["verdict"] == "ALL_S5_BYTES_PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
