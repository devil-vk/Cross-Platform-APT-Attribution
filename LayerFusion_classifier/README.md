# Layer-Fusion Classifier (Phase-1 "optional interpretable classifier")

**Course:** CS5103 Practical Malware Analysis · IIT Hyderabad
**Authors:** B. Saketh (CS25MTECH12016) · D. Vamsi Krishna (CS25MTECH11027) · Advisor: Prof. Saurabh Kumar

The Phase-1 plan (deck, Slide 16, step 4) promised an optional, interpretable classifier — a
simple logistic regression, not deep learning — whose purpose was *"to see which layer carries the
signal, not to chase a high accuracy number."* This folder delivers it, plus an out-of-sample
stress test on new samples.

## What is here
```
CLASSIFIER_SUMMARY.md      how the classifier works + which layer carries the signal (univariate, LOACV)
TESTCASES_OUTOFSAMPLE.md   3-test-case stress test on NEW vx-underground/APTMalware samples
scripts/
  51_build_layerB_matrix.py   rebuild Layer B's full 8x8 technique matrix (needs mitreattack+STIX)
  52_classifier.py            fit LR over the 4 layers' scores; univariate + LOACV + figure
  53_extract_testcases.py     extract binary features from new out-of-sample pairs
  54_score_testcases.py       fit binary-only model, score the 3 test-case types
results/
  classifier_results.json     coefficients, univariate AUC, leave-one-actor-out AUC
  testcases_results.json      out-of-sample P(same) per test case
  layerB_matrix.json          the rebuilt 8x8 Layer-B matrix
  classifier_figure.png       univariate AUC per layer + per-layer coefficients
```

## Headline findings
- **Which layers carry the signal** (univariate ROC-AUC):
  A_strings 0.78, B_ttp 0.73, D_proto 0.72, D_config 0.65 carry cross-platform signal;
  A_opcode 0.55 and C_infra 0.63 do not. The top three (0.78 / 0.73 / 0.72) are a statistical tie
  at N=8 (leave-one-actor-out jackknife overlaps), so read them together, not as a ranking.
  A_strings uses the stoplisted strings metric (Go-clean); D_proto/D_config still carry some
  Go-stdlib tokens, so those two are upper bounds. The classifier reproduces the per-layer story
  from the same matrices read a different way — a corroborating lens, not an independent witness.
- **Leave-one-actor-out AUC = 0.78**, ranking the held-out actor's own pair #1 for the shared-codebase
  actors (Earth Lusca, Turla, APT29) and failing on the genuinely weak ones (APT28, Lazarus).
- **Out-of-sample 3-test-case result:** the model is a same-tool cross-OS linker (recognises
  WellMess's Windows↔Linux builds at P=0.86 because they share embedded data), but it is not a
  same-actor-across-different-tools detector — same-actor-different-family pairs look just like
  different-actor pairs at the binary level. That gap is the finding: cross-tool attribution needs
  the behavioural layer (TTPs), which is why the project uses four layers, not one classifier.

## Honesty notes
- Tiny training set (8 positive pairs), so the full binary model overfits (leans on opcode,
  penalises TLSH); the multivariate coefficients are reported but not used as the headline
  (univariate + LOACV are). All limitations are stated in the two summary docs.
- **Data provenance:** training features derive from Malpedia (credited; samples not
  redistributed). The out-of-sample test samples are from the vx-underground / APTMalware
  reference set. Only derived features/results are included here — no binaries.

## How to reproduce
```bash
cd /home/ubuntu/malpedia/layerAD_paired/classifier
/home/ubuntu/miniconda3/bin/python        -I 51_build_layerB_matrix.py   # mitreattack + STIX
/home/ubuntu/miniconda3/envs/pma2/bin/python -I 52_classifier.py         # sklearn
/home/ubuntu/miniconda3/bin/python        -I 53_extract_testcases.py     # tlsh (base env)
/home/ubuntu/miniconda3/envs/pma2/bin/python -I 54_score_testcases.py    # sklearn
```
Static analysis only; every script run with `python3 -I`; no sample executed.
