# REPRODUCIBILITY — how to regenerate every tracked result

Reference environment: Windows 11, Python 3.11.8, NumPy 1.26.4
(`python -I` recommended). Total wall time ≈ 10 minutes for everything
byte-deterministic below.

## 1. Tests (fail-closed; unified entry)

```bash
python tests/run_all.py            # all 18 suites → logs/run_all.json
python tests/test_paper_values.py  # paper-value anchors only (~70 s)
```

Each suite exits non-zero on first failure. `test_paper_values.py` asserts
the exact Table V/VI byte counts, the four Table VI transport rows, the
crossover depths (t = 9/12/15), object sizes (sk 672 / pk 3,712 /
sig 5,794 / cert 9,572 B), the concrete domain-separation tags, and
hist/fresh mode behavior.

## 2. Byte-deterministic experiments (fixed XOF seeds; any machine)

```bash
python -I scripts/f4_tablev_storage.py      # Table V / Fig. 3d (n=64,102)
python -I scripts/f6_sizes_and_params.py    # sizes & parameter snapshot
python -I scripts/f7_tablevi_full_curve.py  # Table VI full curve + n=32 arm
                                            # (~70 s; asserts paper anchors)
```

F4/F6/F7 reruns reproduce the committed `results/` values exactly. F7 also
re-derives `results/n32_storage_recomputed.csv` (F4 schema) and asserts, by
construction, the archived F5 endpoints — a third independent confirmation
of Table VI.

## 3. Timing experiments (machine-dependent; archived formal run is canonical)

```bash
python -I scripts/f1_fig2_qprss.py          # Fig. 2 five operations
python -I scripts/f2_fig3a_fhir.py          # Fig. 3a FHIR fields 3..12
python -I scripts/f3_fig3bc_multihop.py     # Fig. 3b/3c multi-hop timings
python -I scripts/summarize_to_csv.py       # JSON → CSV postprocessing
```

Statistical conventions: Fig. 2 = median of 50 formal observations after
25 warmup per configuration (KeyGen: 30 sessions); Fig. 3a = mean of
3 seeds × 30 repetitions; Fig. 3b/3c = mean over 5 random seeds
(1 observation each, t = 0..40, n = 64/102). Reruns vary with hardware and
thermal state; the paper cites `results/formal_2026-11-01/` (clean-window
formal run on the reference machine).

## 4. Table III (concrete security)

Produced externally with the lattice-estimator at commit
`53da5982597709ba0fdf94ea37a84d822310fd84`; records and the cost-model
mapping are committed under `estimator/` (classical = rough Core-SVP
2^{0.292β}, β = 504/676/595; quantum = ADPS16 with re-optimized
β = 506/681/595). See README "Data provenance".

## 5. Determinism classes

| Class | Meaning |
|---|---|
| F4/F6/F7 + all test suites | byte-deterministic (fixed XOF seed families, e.g. `PA\|F5\|n{n}`) |
| F1–F3 | timing measurements; distributions fixed by seed, wall times machine-dependent |
| Fig. 2 baseline arms | frozen external replication sessions (not in this repository); exact plotted values in `results/fig2_plotted_data.csv` |

## 6. Paper-value quick checks

```bash
python -I -c "import csv,io;rows=list(csv.DictReader(io.open(r'results/tablevi_full_curve.csv',encoding='utf-8')));print([ (r['Q_bytes'],r['L_bytes']) for r in rows if (r['n'],r['t']) in (('64','12'),('64','63'),('102','15'),('102','80'))])"
# → 140500/142138 · 402028/670192 · 192455/193744 · 524605/924994
```
