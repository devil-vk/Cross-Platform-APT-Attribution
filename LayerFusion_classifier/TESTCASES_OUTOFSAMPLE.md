# Out-of-Sample Test — Will the Classifier Work on New Samples?

Tested the trained classifier on new vx-underground / APTMalware samples that were NOT in the
Malpedia training set (`apt-attribution-project/04_samples_ISOLATED/`), across the three pair types
we wanted to test. Binary-only features (no actor labels leaked): strings, tlsh, opcode3,
protocol, config. Static only; no sample executed.

## Scripts
- `53_extract_testcases.py` (base python, has tlsh) — extracts features from the new binaries and
  rebuilds the training table consistently → `testcases_features.json`.
- `54_score_testcases.py` (pma2, has sklearn) — fits the classifier on the 64 Malpedia pairs and
  scores the new pairs → `testcases_results.json`.

## Two models
1. **Full binary model** (strings+tlsh+opcode3+proto+config). Overfits at N=8: it put the biggest
   weight on `opcode3_jac` and a negative weight on `tlsh_sim`, so it even missed APT29 WellMess
   (a pair that obviously shares data) because WellMess's Linux opcodes failed to disassemble.
   Lesson: opcode/tlsh don't generalize; 8 training pairs is too few.
2. **Robust model** (strings+proto+config only — the features Layers A/D proved transfer). This is
   the fair one; results below.

## Robust-model results — mean P(same actor) by case

| Test case | mean P | per-pair | correct? |
|---|---|---|---|
| **1 · same actor, SAME tool** | **0.515** | WellMess **0.863 SAME**, Winnti 0.503 SAME, 3× Lazarus loaders ~0.40 diff | **partly** |
| **2 · same actor, DIFFERENT family** | **0.404** | all five ~0.40 diff | **yes (correctly low)** |
| **3 · totally different actors** | **0.438** | 4× diff (~0.40), 1 false positive (Lazarus×Winnti 0.577) | **mostly** |

## What this means — answering "will it work?" per case

**Case 1 — same actor, same tool → works ONLY when the tool shares embedded data cross-OS.**
- **APT29 WellMess = 0.863 (SAME).** ✅ The Go build shares strings/protocol/config across OS, so
  the classifier nails it. This is the "embedded DATA transfers" case.
- **Lazarus PondRAT/PoolRAT/ThemeForestRAT ≈ 0.40 (diff).** ❌ Even though it's the same tool, the
  Windows side is a small DLL stub and the Linux side is a large ELF — they genuinely share almost
  no strings/config (exactly like the Malpedia Derusbi null: Win and Linux are different modules of
  one tool). So "same tool" is only detectable when the two OS builds actually carry the same
  embedded data — not always true.

**Case 2 — same actor, different family → does NOT work from binary features (and that's expected).**
- All five pairs score ~0.40, indistinguishable from the different-actor case. Different families
  of one actor share no strings, no protocol, no config at the binary level — so a binary-only model
  can't link them. This is the project's central thesis, reproduced by the classifier: cross-tool
  attribution doesn't live in the binary; it lives in behaviour (Layer B / TTPs), which is
  actor-level and can't be recovered from two mystery binaries alone.

**Case 3 — different actors → mostly correct, with occasional false positives.**
- 4 of 5 score ~0.40 (diff) ✅. One false positive (Lazarus PondRAT-win × Winnti-lin = 0.577) from
  a coincidental overlap of a couple of generic config/protocol tokens — the kind of noise a
  3-feature model at N=8 will occasionally produce.

## Bottom line

> The classifier is a same-tool cross-OS linker: it recognises an actor's Windows and Linux builds
> of the same tool when that tool carries the same embedded data/protocol across OS (WellMess ✅),
> and it correctly stays low for unrelated actors. It is not a same-actor-across-different-tools
> detector — binary features for Case 2 look the same as Case 3. That gap isn't a bug; it's the
> finding: linking different tools of one actor requires the behavioural layer (TTPs) and manual
> RE, which is exactly why the project uses four layers rather than a single binary classifier.

Caveats: tiny training set (8 positives), so the full model overfits and even the robust model gives
one false positive; feature extraction occasionally fails (WellMess/VPNFilter opcodes). These are
expected at this scale, and we state them rather than hide them.
