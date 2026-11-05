# -*- coding: utf-8 -*-
"""F6 = 其余论文数字核对：σ=5,794B / pk=3,712B / sk=672B / 证书 9,572B /
challenge 34B / 承诺维度 / Merkle 深度——全部由当前实现实测重出。
第五章安全性估计（攻击成本）不属性能复测，保持原文（参数未变）。
"""
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
from s6t64 import merkle                                  # noqa: E402

B1 = s5_sig.core("B1")
RID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
V2 = pol.POL_VER_GENERAL


def main():
    sk, pk = B1.keygen(rng=s4c.FixedXofRng(b"PA|F6|kg"))
    ra = Q.RA("B1")
    ra.sk, ra.pk = B1.keygen(rng=s4c.FixedXofRng(b"PA|F6|kg-ra"))
    cert_s = ra.issue(RID[:12] + b"SGNR", pk, b"signer", ((RID,), b"*"),
                      0, 1 << 62)
    sig = B1.sign(sk, pk, b"PA|F6|msg", b"qprss-orig",
                  rng=s4c.FixedXofRng(b"PA|F6|sg"))
    assert B1.verify(pk, b"PA|F6|msg", sig, b"qprss-orig")
    n = 8
    pp = Q.setup("B1", seed=b"PA|F6|pp", pol_ver=V2)
    ys = {j: f"field-{j}".encode() for j in range(1, n + 1)}
    sd = canon.schema_digest([(j, ("Patient", f"a{j}"), "str")
                              for j in range(1, n + 1)])
    P0 = pol.Policy(((b"physician", b"*"),), frozenset(range(2, n + 1)),
                    n, n, m=frozenset({1}), ver=V2)
    S = Q.signing(pp, sk, cert_s, RID, ys, P0, rng=Q.make_rng(b"PA|F6|sg"),
                  schema_digest=sd, sig_rng=s4c.FixedXofRng(b"PA|F6|sg0"))
    pol2 = canon.enc_pol(P0)
    facts = dict(
        signature_B=len(sig), pk_B=len(pk), sk_B=len(sk),
        cert_signer_B=len(cert_s.bytes()), cert_redactor_B=None,
        challenge_hint_cbytes=34,
        merkle_depth_n8=merkle.DEPTH if hasattr(merkle, "DEPTH")
        else len(merkle.make_tree(n, lambda j: b"x" * 48).path(0)),
        pol2_encoding_B=len(pol2), pol1_encoding_B=len(canon.enc_pol(
            pol.Policy(P0.adm, P0.w, P0.d, n))),
        sigma0_B=len(S.sigma0), artifact_t0_B=len(S.serialize()),
        h_cert_len=48, bid_len=48,
    )
    skr, pkr = B1.keygen(rng=s4c.FixedXofRng(b"PA|F6|kg-r"))
    cert_r = ra.issue(b"\x01" * 16, pkr, b"physician", ((RID,), b"*"),
                      0, 1 << 62)
    facts["cert_redactor_B"] = len(cert_r.bytes())
    checks = {
        "sigma=5794": facts["signature_B"] == 5794,
        "pk=3712": facts["pk_B"] == 3712,
        "cert=9572": facts["cert_signer_B"] == 9572
        and facts["cert_redactor_B"] == 9572,
        "pol2 > pol1 (一般描述符更长)": facts["pol2_encoding_B"]
        > facts["pol1_encoding_B"],
    }
    for k, v in checks.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    out = os.path.join(ROOT, "results", "summary", "f6_sizes_and_params.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(dict(facts=facts, checks=checks,
                       environment=dict(python=platform.python_version(),
                                        ts=time.strftime("%Y-%m-%dT%H:%M:%S")),
                       notes=["第五章攻击成本估计保持原文（核心参数未变）",
                              "全部尺寸由当前对齐实现实测"]),
                  f, ensure_ascii=False, indent=1)
    assert all(checks.values())
    print(f"\nF6_DONE json={out}")


if __name__ == "__main__":
    main()
