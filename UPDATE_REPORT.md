# UPDATE_REPORT — manuscript–repository synchronization (2026-11-11)

Scope: synchronize https://github.com/GuanyuYanCUST/qprss with the revised
TIFS manuscript (`main.tex`/`supplementary.tex` build of 2026-11-11),
without changing any cryptographic byte, protocol value, or archived
measurement. Companion documents: `PAPER_CODE_AUDIT.md` (item-by-item
paper↔code verdicts), `REPRODUCIBILITY.md` (regeneration commands).

## 1. What changed (files added/modified)

| File | Change | Reason |
|---|---|---|
| `scripts/f7_tablevi_full_curve.py` | new | Regenerates the full Table VI transmission curve at every legal depth (n = 32/64/102, 198 states, each hist-verified) and asserts the revised manuscript's four Table VI rows, the single crossover per n (t = 9/12/15), and the n = 32 Fig. 3d endpoints. F5 seed family `PA\|F5\|n{n}` ⇒ byte-identical to archived formal results. |
| `results/tablevi_full_curve.csv` | new (198 rows) | Full curve incl. the crossover rows (64,12) 140,500/142,138 and (102,15) 192,455/193,744 and the negative-reduction region (Q > L below the crossover — kept in full, nothing dropped). |
| `results/tablevi_full_curve.json` | new | Machine-readable run record: anchors, crossovers, environment. |
| `results/n32_storage_recomputed.csv` | new | The n = 32 arm of Fig. 3d, previously referenced by README but never committed (F4 schema: n,t,sigma_base_B,log_t_B,sigma_S_B; ends at hop 31 by the n=32 policy). |
| `tests/test_paper_values.py` | new (37 checks) | Paper-value anchors: domain-tag bytes (dom_pol/dom_bid/dom_resp concrete forms), sizes (sk 672 / pk 3,712 / sig 5,794 / cert 9,572 B), BindId renewal stability, hist/fresh mode behavior (incl. stale-state and no-RA negatives), audit-log tamper rejection (V6), Table V six rows, all four Table VI rows, crossover depths — rebuilt live through F7. |
| `tests/run_all.py` | new | Unified test entry; writes `logs/run_all.json`; forces UTF-8 child output. |
| `tests/test_pa_policy.py` | 1 line | `sys.stdout.reconfigure(encoding="utf-8")` — latent GBK-console `UnicodeEncodeError` crashed the suite's PASS prints on Chinese Windows (test logic was correct; suite could not complete locally). |
| `README.md` | edited | Test count corrected (was "17 … (16 in total)", actual 18 after this sync); citation placeholder → real manuscript title + under-review wording; F7 documented; provenance wording now points at the committed n=32/curve files; `v4_work/` documented as a live dependency. |
| `PAPER_CODE_AUDIT.md`, `REPRODUCIBILITY.md` | new | This sync's audit and regeneration guide. |

Not changed: `s6t64/` and its frozen copy `run/fixed_run/s6t64/` (verified
byte-identical), all archived results under
`results/formal_2026-11-01/`, `estimator/`, `v4_work/`, and every
pre-existing test suite except the one-line stdout fix above.
Untracked-and-left-so: `experiments/`, `results/delta_chain/` (separate
experiment line, not part of this manuscript sync).

## 2. Acceptance run (2026-11-11, Windows 11, Python 3.11.8)

- `python tests/run_all.py` → **18/18 suites PASS, 112 s**
  (`logs/run_all.json`; per-suite last lines recorded there). One suite
  needed the stdout-encoding fix above; after the fix it passes. Zero
  skips; no test was modified to make it pass other than the print-encoding
  line.
- `python -I scripts/f7_tablevi_full_curve.py` → 198 rows, all anchors OK,
  crossovers {32: 9, 64: 12, 102: 15}, 65 s. `tests/test_paper_values.py`
  independently rebuilds the same anchors: 37/37 PASS.
- Table-by-table: Table II ↔ code constants (params suite T1–T34);
  Table III ↔ `estimator/` records (classical rough Core-SVP β = 504/676/595
  → 147.17/197.49/173.74; quantum ADPS16 β = 506/681/595 →
  134.15/180.66/157.68); Table V ↔ F4 + live rebuild (six rows exact);
  Table VI ↔ F5 + F7 (four rows exact); Fig. 2/3 provenance unchanged.
- Sensitive-file check: new files contain code, docs, and size/timing CSVs
  only — no keys, credentials, or personal data.

## 3. Consistency conclusions

1. No cryptographic inconsistency between manuscript and implementation was
   found; no protocol byte was changed (revision policy: dom_pol/dom_bid/
   dom_resp are the paper's abstract symbols; the concrete tags
   `QPRSS-pol2|…pol-v1`, `QPRSS-HB|`, `QPRSS-v5|resp` implement them and are
   now pinned by `tests/test_paper_values.py`).
2. All four revised Table VI rows — including the new crossover rows —
   reproduce byte-exactly on the current code; the crossover is single per n
   and the QPRSS-larger region is preserved in the committed data.
3. The README's only factual defect (referencing a file that was never
   committed) is resolved by generating and committing that file; the
   test-count contradiction and citation placeholder are fixed.
4. Known superseded measurements (14,640 / 5,067–5,068 B first-hop /
   steady-state deltas; old Table VI 398,793/639,789/519,356/845,832) do
   not appear anywhere in the revised manuscript or this repository's
   current claims.
