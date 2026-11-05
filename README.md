# QPRSS — Policy-Driven Redactable Signatures over Module Lattices (Reference Implementation)

QPRSS is a post-quantum redactable signature scheme supporting policy-constrained
deletion of fields from signed records (target use case: multi-editor medical
record sharing, HL7 FHIR), with per-hop authenticated audit logs, an
administrator registration/revocation state machine, and history (`hist`) /
freshness (`fresh`) verification modes.

This repository is the reference implementation and experiment suite for the
manuscript "QPRSS: ..." (citation placeholder — add after acceptance).

## Cryptographic core (all post-quantum, no classical fallback)

All three signature roles — the original signer core σ₀, the per-hop editor
audit signature Π_R, and the administrator signatures Π_adm (certificates,
registration, freshness responses) — are instantiations of the same custom
B1-65 Fiat–Shamir-with-aborts module-lattice signature, under five domain
separation contexts (`qprss-orig / red / cert / reg / anc`).

| Parameter | Signing core | Commitment layer |
|---|---|---|
| modulus | q_s = 8,380,417 | q_c = 12,289 |
| ring / rank | d = 256, k = m = 5 | d = 256, k_c = 4 |
| distribution | ternary (η=1) | ternary |
| challenge / response bound | τ = 64, β = 64, γ₁ = 2¹⁷ | ‖r‖∞, ‖η‖∞ ≤ 1 |

Sizes: signature 5,794 B · public key 3,712 B · secret key 672 B ·
administrator-issued certificate 9,572 B. The acceptance rate of one
rejection-sampling round is exactly `((2(γ₁−β)+1)/(2γ₁+1))^(d(k+m))` =
0.2864187138… (mean 3.49 rounds per signature; see `tests/test_s6_params.py`, T7).

## Repository layout

```
s6t64/                     protocol package (pure Python stdlib)
  s5_qprss.py              Signing / Redact / Verify / RA registry (engine)
  s5_sig.py                signature-core registry (B1-65 lattice core)
  s4compat.py, s4dep_*.py  B1-65 FS core: rings, packing, XOF, sampling
  commit_as.py             C2 MLWE commitment layer + Merkle authentication
  canon.py                 canonical encodings, domain-separated messages
  policy.py, l_chain.py    restricted policy language / sequential-signature baseline
  fhir_codec.py            HL7 FHIR field codec (Fig. 3a experiment)
run/fixed_run/             frozen copy of the package used by experiment scripts
scripts/                   experiments F1–F6 (paper Figs. 2–3, Tables V–VI)
tests/                     17 standalone test suites (params, distributions,
                           bytes, regression, theorem-level executable checks)
results/formal_2026-11-01/ formal-run outputs (raw + processed, see provenance)
results/n32_storage_recomputed.csv  n=32 storage series (Fig. 3d)
results/fig2_plotted_data.csv      exact plotted values of paper Fig. 2 (all
                           five schemes, incl. baseline arms; see provenance)
estimator/                 lattice-estimator result records for Table III
                           (h2_rough.json / h2_full.json plus the cost-model
                           comparison task1_comparison.csv / task1_results.json)
```

## Requirements

Python 3.11+ with [NumPy](https://numpy.org) (reference experiments used
Python 3.11.8 / NumPy 1.26.4). `commit_as.py` (C2 commitment layer) and two
test suites import NumPy directly; everything else is standard library.

## Run the tests

Each test is a standalone script writing a JSON report to `logs/` and exiting
non-zero on failure:

```bash
python tests/test_s6_smoke.py        # end-to-end sign → redact → verify
python tests/test_s6_params.py       # parameters, acceptance-rate closed form,
                                     # challenge distribution, fixed-length encoding
python tests/test_s6_thm1_thm5.py    # theorem-level executable checks
                                     # (simulator/programming, fork extraction)
...                                   # (16 suites in total)
```

## Reproduce the paper experiments

```bash
python scripts/f1_fig2_qprss.py       # Fig. 2 timings (KeyGen/Sign/Verify/Redact/VVerify)
python scripts/f2_fig3a_fhir.py       # Fig. 3a HL7 FHIR fields 3..12
python scripts/f3_fig3bc_multihop.py  # Fig. 3b/3c multi-hop redact + history verify
python scripts/f4_tablev_storage.py   # Table V / Fig. 3d storage decomposition (n=64,102)
python scripts/f5_tablevi_vs_lchain.py# Table VI transport vs sequential-signature baseline
python scripts/f6_sizes_and_params.py # key/sig/cert byte lengths
python scripts/summarize_to_csv.py    # JSON → CSV postprocessing
```

Notes:
- F4/F6 are **byte-deterministic** (fixed XOF seeds): rerunning reproduces the
  archived Table V / Fig. 3d values exactly on any machine.
- F1–F3 are timing measurements and are machine/thermal-state dependent; the
  archived formal run (`results/formal_2026-11-01/`) was taken in a clean
  window on the reference machine (see provenance below).

## Data provenance

All numbers in the paper's experiment section trace to `results/`:
`formal_2026-11-01/raw/` (per-observation CSVs) and processed summaries, plus
`n32_storage_recomputed.csv` for the n=32 arm of Fig. 3d (regenerated
deterministically by the same construction as F4; chain ends at hop 31 by the
n=32 policy). The Table III concrete-security estimates were produced with the
[lattice-estimator](https://github.com/malb/lattice-estimator) at commit
`53da5982597709ba0fdf94ea37a84d822310fd84` (records in `estimator/`).

Table III column ↔ cost-model mapping (`estimator/task1_comparison.csv`):
the **classical** column is the "rough" Core-SVP metric 2^(0.292·β) of
`estimator/h2_rough.json` (β = 504 / 676 / 595), while the **quantum** column
uses the ADPS16 quantum cost model with independently re-optimized block size
(β = 506 / 681 / 595 → 134.15 / 180.66 / 157.68). The 2^(0.265·β) "quantum"
entries in `h2_rough.json` (133.56 / 179.14 / 157.68) are a rough sidebar and
are **not** the paper's quantum column; the Matzov-model values are also
recorded for completeness.

Fig. 2 provenance: the QPRSS arm is the formal rerun above (`f1_*` summaries);
the four baseline arms (Kissel et al. measured on Java 17 + JPBC; Yang, Zhao,
Tang re-implemented in Python) come from frozen replication sessions whose
per-point medians are recorded in `results/fig2_plotted_data.csv` — the exact
values plotted in the paper figure (see its `provenance` column). Those
baseline implementations are not part of this artifact.

## License

MIT — see [LICENSE](LICENSE).
