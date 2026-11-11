# PAPER_CODE_AUDIT — QPRSS paper ↔ implementation consistency audit

Date: 2026-11-11 · Repo HEAD at audit: `37a1d76` (+ this sync commit) ·
Manuscript audited: revised TIFS LaTeX (`main.tex` 99,246 B / supplementary
38,886 B, 2026-11-11 build, IEEEtran journal class; title *"QPRSS:
Quantum-Resistant Policy-Driven Redactable Signature Scheme for
Multi-Redactor Medical Data Sharing"*).

Verdict legend: ✅ consistent (verified against code and/or live run) ·
🟡 documentation-level issue (fixed in this sync) · 🔴 inconsistency
(needing code or paper change) — none found at the cryptographic level.

---

## 1. Algorithms ↔ code modules

| Paper object | Code location | Verdict |
|---|---|---|
| `Setup(1^λ)` (§IV-A; ring params, dom-separated H₁/H₂/H_M/H_L/H_cert, Π_R/Π_adm interfaces, pp) | `s6t64/s5_qprss.py::setup`, `s6t64/api.py::Setup` | ✅ |
| `KeyGen(pp)` — formal (b, A) vs prototype 32-B seed + packed b, "domain-separated XOF" expansion | `s5_sig.py::core(B1).keygen`; pk 3,712 B = 32-B seed + packed b | ✅ paper states prototype serialization explicitly (main.tex §IV-B) |
| `Signing(PK,SK,S,P;ρ)` incl. Fiat–Shamir-with-aborts loop, "at most J attempts" | `s5_qprss.py::signing`; rejection loop `s4dep_fs/s4dep_core` | ✅ formal-J vs prototype-unbounded distinction: supplementary C.2 (J=304 example, p_acc≈0.28642) matches code comment + `tests/test_s6_params.py` T7 acceptance rate 0.2864187138… |
| `Redact(S,σ,S',P',…;ρ)` with R0–R6 | `s5_qprss.py::redact` (local precheck R0b) + `_check_hop_policy` at verify | ✅ see §2 below |
| `Verify(PK,S,σ,mode;ρ)` hist/fresh | `s5_qprss.py::verify` | ✅ see §3 below |
| Commitments (MLWE C2: r_j←χ^kc, η_j, field commitment) + Merkle padding convention | `commit_c.py`, `commit_as.py`, `merkle.py` | ✅ q_c=12,289, k_c=4, d=256 match Table II; "pad to next power of two with distinct domain tags" = `merkle.py` leaf/node tagging |
| Sequential full-document baseline (Table VI L chain) | `l_chain.py` | ✅ L = σ₀+Σ(τᵢ+docᵢ+pkᵢ+16 B meta), `l_verify` replay semantics |
| Paper-facing five-algorithm API (Def. 5, §3.1 notation) | `api.py` (thin delegation, no new algorithms) | ✅ |

## 2. Redaction rules R0–R6 (main.tex eq. in §IV-C) ↔ `policy.py` + verify checks

| Paper rule | Verify-side enforcement (code) | Test evidence |
|---|---|---|
| R0: I(S')⊊I(S) | `V7.1` (also bans empty redaction) | test_s6_regression G5, test_pa_policy |
| R1: Δ⊆W | `V7.2` (+ `V7.3` mandatory-deleted via M, `V7.4` Inv-W) | 3+3+1 refs across suites |
| R2: P'(I(S'))=1 | `V7.5` (`Policy.holds` = eq. (1) both conjuncts) | test_pa_policy D-block |
| R3: W'⊆W · R4: M⊆M' · R5: 0≤b'≤b−1 | `V7.6` (`policy.tighten_ok`) | relaxation negatives test_pa_policy:213–218 |
| R6: Auth(ID,role,vk,…)=1 | `V7.7` (+ cert scope `V2.1-scope`, `AdmLeq` strictly-stronger surface, documented as implementation-added) | test_u3_redactors |
| Policy encoding `EncPol(P)=dom_pol∥enc_u(n)∥bits_n(W)∥bits_n(M)∥enc_u(b)` | `canon.enc_pol` ver=2 = `b"QPRSS-pol2|"+adm+len` + `b"pol-v1"+enc_u(n)+bits_n(W)+bits_n(M)+enc_u(b)`; decoder rejects non-minimal enc_u / wrong bitmap length / nonzero padding | test_sf_canon, test_pa_policy |

**Domain-separation symbols (paper → concrete wire bytes, anchored by
`tests/test_paper_values.py` §A so no later rename can change protocol
values):** `dom_pol` → `QPRSS-pol2|…pol-v1`; `dom_bid` → `QPRSS-HB|`
(inside `canon.BindId`, H_cert-form of eq., 48-B output); `dom_resp` →
`QPRSS-v5|resp` (`canon.M_resp5`). The paper's abstract symbols are
instantiation slots; the implementation's existing byte tags implement them
one-to-one. **No protocol byte, signature message, or test vector was
changed in this sync** (per revision policy: renaming constants without
changing values is documentation-only).

## 3. Verification path V1–V9 ↔ paper Verify itemization (§IV-D)

All paper-stated checks exist as named rejection steps:
V1.1/V1.2 (structure/field table), V2.1/V2.1-scope/V2.1-role/V2.2
(cert + σ₀ under pk_ra and RID scope, schema digest), V3.1 (commitment
norm bound), V4 (Merkle path per retained field), V5.1–V5.4 + V5.3d-window
/ V5.3d-rev (per-hop cert/identity/τ + validity window + revocation
snapshot), V6 (audit-chain state continuity, mixed-version ban, h_t), V7.1–
V7.7 (R0–R6), V8 (terminal state = (I(S), P̄), t ≤ b₀), V9 (fresh mode).
Hist mode accepts offline after V1–V8 — paper: "does not query an online
administrator". Fresh mode: 32-B nonce (NONCE_LEN), `M_resp5`
= dom_resp∥ν∥RID∥h∥t∥ts∥epoch∥bid, requires (h_t,t)=(h_reg,t_reg) and
bid_reg=BindId(RID,ID_S,PK) — matches the paper's verification-mode item
verbatim (main.tex ~:780).

## 4. Administrator (Π_adm) machinery

- Certificates: `RA.issue` → `M_certS/M_certR` ("QPRSS-v2|certS/certR"),
  signed under `CTX_CERT`; scopes (RID enumeration + index set) match
  "permitted deletion indices and policy transitions".
- Registration: `register_initial` (I1/I2/I3 checks incl. RID-bound identity
  and full verify) and `register` (R1/R2/R2b/R3/R4/R5 — strict extension,
  prefix-head fork ban), supersession errors.
- Revocation: `RA.revoke` with monotonic effective epoch, `revsnap`
  RA-signed snapshots, V5.3d-rev window checks; "administrator has no
  trusted clock" honored (`eff_ts` required).
- `fresh_query` nonce-bound response (V9), gazette mode kept explicitly
  non-paper (`"snapshot mode is not a formal paper mode"` — fail-closed).

## 5. Experiments ↔ scripts ↔ data

| Paper artifact | Script | Data (tracked) | Verdict |
|---|---|---|---|
| Fig. 2 (five ops; median of 50 + 25 warmup; KeyGen 30 sessions) | `scripts/f1_fig2_qprss.py` | `results/formal_2026-11-01/f1_*`, `results/fig2_plotted_data.csv` | ✅ provenance + sha256 locked (baseline arms frozen sessions, not in repo — stated in README) |
| Fig. 3a (FHIR 3..12; mean of 3 seeds × 30 reps) | `scripts/f2_fig3a_fhir.py` | `f2_*` | ✅ |
| Fig. 3b/3c (multi-hop; 5-seed means) | `scripts/f3_fig3bc_multihop.py` | `f3_*` | ✅ seed-mean citation values reproduce (295.77 / 341.24 ms endpoints) |
| Fig. 3d + Table V (storage; n=64/102) | `scripts/f4_tablev_storage.py` | `f4_*` | ✅ six rows byte-exact (re-verified live 2026-11-11, 82/82 rows) |
| Table VI deep chains (64,63)/(102,80) | `scripts/f5_tablevi_vs_lchain.py` | `f5_*` | ✅ byte-exact |
| Table VI **crossover rows** (64,12)=140,500/142,138 · (102,15)=192,455/193,744 + full curve + n=32 arm | **new** `scripts/f7_tablevi_full_curve.py` | `results/tablevi_full_curve.csv` (198 rows), `results/n32_storage_recomputed.csv`, `results/tablevi_full_curve.json` | ✅ this sync: live run asserts all four Table VI rows + single crossover t=9/12/15 + n=32 endpoints 40,956→210,240; negative-reduction (Q>L) region fully retained |
| Sizes (sk 672 / pk 3,712 / σ 5,794 / cert 9,572) | `scripts/f6_sizes_and_params.py` | `f6_sizes_and_params.json` | ✅ |
| Table III (estimator) | external lattice-estimator @53da598 | `estimator/` | ✅ six values match rough-core-SVP (classical β=504/676/595) + ADPS16 quantum (β=506/681/595); mapping documented in README |

## 6. Findings and resolutions (this sync)

1. 🟡→fixed README claimed 17 suites in layout but "(16 in total)" in the
   run section; actual = 17 before this sync, 18 after (new
   `tests/test_paper_values.py`). Both statements now say 18 and
   `tests/run_all.py` gives a unified entry writing `logs/run_all.json`.
2. 🟡→fixed README cited `results/n32_storage_recomputed.csv`, which was
   never committed. Now generated (F4 schema, F5 seed family) by the new
   F7 script and committed; provenance wording updated accordingly.
3. 🟡→fixed Citation placeholder replaced by manuscript title + "under
   review; citation added upon acceptance" (no fabricated DOI).
4. 🟡→documented `v4_work/` in the layout block (live dependency of
   `tests/test_v4_commit_as_equiv.py`, previously undocumented).
5. ✅ no cryptographic change was needed: the three signature roles are all
   the paper's B1-65 instance with independent keys and five protocol
   contexts (`qprss-orig/red/cert/reg/anc`) + B1-level folding
   (`QPRSS-B1ctx|`, DOM `QPRSS-FS-B165`); no classical fallback anywhere
   (`test_h_e2e` H-arm is an explicitly labeled ablation baseline, not a
   fallback); SHAKE-256 with 48-B output is uniformly described as
   "domain-separated SHAKE-256 with 384-bit outputs" — never "SHAKE-384".
6. 🔴 none. The previously reported legacy values (14,640 / 5,067–5,068 B)
   belong to a pre-identity-binding-fix encoding (ver=1 + wildcard scope),
   are superseded by the current measurements, and are not claimed anywhere
   in the current manuscript or this repository.

## 7. Out of scope / not re-executed (honesty notes)

- Fig. 2 baseline arms (Kissel/Yang/Zhao/Tang) are frozen external
  replications; their implementations are not in this repository and were
  not re-run here (README states this).
- The lattice estimator was not re-run in this sync; Table III is locked to
  the archived records at commit `53da598…` (re-verified independently on
  2026-11-06; see `estimator/`).
- The single-hop privacy proof in the paper is not extended by anything in
  this repository to arbitrary multi-hop or multi-receiver collusion; the
  multi-hop tests here are functional/security-mechanism tests only.
