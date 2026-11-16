# Layer-Fusion Classifier — "Which Layer Carries the Signal?"

**The Phase-1 optional interpretable classifier, now built on real data.**
Phase-1 deck (Slide 16, step 4) promised: *"(Optional) Interpretable classifier — a simple
logistic regression, not deep learning. The goal is to see which layer carries the signal — not
to chase a high accuracy number."* This delivers exactly that.

---

## 1. What it does (plain terms)

Each of our four evidence layers produced an 8×8 cross-OS similarity matrix (Windows actor *i*
vs Linux actor *j*). We flatten all of them into one table:

- Each row = one (Windows, Linux) actor pair → 64 rows (8×8).
- Label `y` = 1 if same actor (the 8 diagonal cells), 0 if different (the 56 control cells).
- Features `X` = that pair's similarity score in each layer: `A_strings, A_tlsh, A_opcode,
  B_ttp, C_infra, D_proto, D_config`.

A logistic regression learns `P(same actor | the layer scores)`. We read its coefficients and
the per-layer separation to see which layers actually distinguish a same-actor pair from a
control. Accuracy is explicitly not the goal — with only 8 positive examples it would be
meaningless; interpretability is.

## 2. How to run

```bash
# step 1 — rebuild Layer B's full 8x8 matrix (paired run saved only its diagonal)
cd /home/ubuntu/malpedia/layerAD_paired/classifier
/home/ubuntu/miniconda3/bin/python -I 51_build_layerB_matrix.py       # needs mitreattack + STIX

# step 2 — assemble features from all 4 layers, fit LR, univariate + LOACV + figure
/home/ubuntu/miniconda3/envs/pma2/bin/python -I 52_classifier.py      # needs numpy + sklearn
#   -> classifier_results.json, classifier_figure.png
```
Layers A/D read their saved matrices from `../results/layer{A,D}_results.json`; Layer C is
recomputed (exact-IOC Jaccard) from `../results/layerC_infra.json`; Layer B from `layerB_matrix.json`.

## 3. Dataset
64 pairs = 8 same-actor (positive) + 56 control (negative). Heavily imbalanced and tiny, so every
number below is read with that in mind.

## 4. RESULT 1 — univariate: which single layer separates same-actor from control? (most trustworthy)

For each feature: mean score on the 8 same-actor pairs vs the 56 controls, and the ranking AUC.

| Feature (layer) | same-actor mean | control mean | ratio | AUC | reads as |
|---|---|---|---|---|---|
| **A_strings** (code/data, **stoplisted+IDF**) | 0.091 | 0.013 | **6.8×** | **0.783** | strong (top-3 tier) |
| **B_ttp** (behaviour) | 0.533 | 0.375 | 1.4× | **0.734** | strong (top-3 tier) |
| **D_proto** (protocol) | 0.119 | 0.018 | **6.8×** | **0.717** | strong (top-3 tier)* |
| D_config (protocol) | 0.271 | 0.057 | 4.7× | 0.652 | good* |
| C_infra (infrastructure) | 0.082 | 0.000 | "∞" | 0.625 | **spurious — see §6** |
| A_tlsh (byte-shape) | 0.329 | 0.118 | 2.8× | 0.610 | weak (Go-driven) |
| A_opcode (compiled code) | 0.240 | 0.178 | 1.3× | 0.549 | ~none (code doesn't transfer) |

This table is the answer to the deck's question. The layers that carry cross-platform signal
are A_strings, B_ttp, D_proto and D_config — i.e. embedded data, behaviour, and custom protocol.
Compiled-code structure (A_opcode) and raw infrastructure (C_infra) do not. This matches every
per-layer finding.

Read the top three as a tie, not a ranking. A_strings (0.78), B_ttp (0.73) and D_proto (0.72)
are statistically indistinguishable at N=8: a leave-one-actor-out jackknife swings each AUC by
±0.05–0.10 (A_strings 0.71–0.86, B_ttp 0.70–0.78, D_proto 0.66–0.78 — fully overlapping), far more
than the 0.06 spread between them. So the honest statement is "embedded data, behaviour and
protocol all separate same-actor pairs strongly," not "strings is best."

**Two feature caveats:**
- A_strings here is the stoplisted + IDF strings metric (Go/compiler strings removed), so its
  separation isn't a Go-toolchain artifact. (Using the raw, non-stoplisted strings Jaccard gives a
  near-identical 0.757 — the stoplist doesn't change the picture.)
- \*D_proto / D_config still contain Go-stdlib tokens (the Layer D confound: the generic stoplist
  misses `*http.cookie`, `*tls.clientsessionstate`, …), so their AUCs are upper bounds — the
  confound-robust protocol evidence is Layer D's `proto_all` drop-Go result plus the manual RE.

## 5. RESULT 2 — leave-one-ACTOR-out cross-validation (the honest small-N test)

Drop **all** pairs involving one actor, train on the rest, then ask: is that held-out actor's own
(Win,Lin) pair ranked above its 14 controls? Repeat for all 8 actors.

| Held-out actor | P(same) for its own pair | rank / 15 | fold AUC |
|---|---|---|---|
| Earth Lusca | 1.000 | **1** | 1.000 |
| Turla | 0.787 | **1** | 1.000 |
| APT29 | 1.000 | **1** | 0.964 |
| Sandworm | 0.762 | 3 | 0.857 |
| Winnti/APT41 | 0.672 | 4 | 0.786 |
| APT27 | 0.304 | 7 | 0.571 |
| Lazarus | 0.069 | 7 | 0.571 |
| APT28 | 0.019 | 8 | 0.500 |

Leave-one-actor-out mean AUC = 0.781; the held-out pair is ranked #1 in 3/8 folds and in the
top-4 in 5/8. The model recovers exactly the actors our layer analysis said are linkable
(Earth Lusca, Turla, APT29 — shared codebase / protocol) and fails on the ones we already flagged
as weak (APT28, Lazarus). So the classifier reproduces the per-layer story using the same four
matrices read a different way (a multivariate fit rather than per-layer permutations) — a
corroborating lens, not an independent data source.

## 6. Honest caveat — why the multivariate coefficients are NOT the headline

The full 7-feature logistic-regression coefficients come out as:
`B_ttp +1.31, C_infra +0.86, D_config +0.80, A_tlsh +0.66, A_strings −0.46, …`
and the 4-feature model even makes C_infra the largest weight (+1.68). Don't trust these. Two
small-N pathologies:

1. **Collinearity.** `A_strings` and `D_proto` are highly correlated across pairs (both ~6–7× on
   the same actors), so L2 regularization arbitrarily splits weight between them and can even flip
   one negative. With 8 positives there isn't enough data to separate correlated layers.
2. **The Layer C quirk.** `C_infra` is exactly 0 for every control, so even a single nonzero
   same-actor value makes it a "perfect" in-sample separator and L2 piles weight on it — despite
   its univariate AUC being only 0.625. And that nonzero value is the ambiguous `lg.hk` token
   that the Layer C analysis already identified as a toolchain/obfuscation artifact, not real
   shared infrastructure (Layer C's verdict is a null). The classifier is capitalising on a data
   artifact, which is a textbook small-N overfit.

So the "which layer" conclusion rests on the univariate AUC table (§4) and the LOACV (§5), not on
the fitted coefficients. This is the disciplined reading the deck asked for ("not to chase a high
accuracy number").

## 7. Bottom line

> A simple, interpretable logistic regression over the four layer-similarity scores corroborates
> — reading the same four matrices a different way (a multivariate fit, not an independent data
> source) — that the cross-platform signal lives in embedded data (A_strings), behaviour (B_ttp)
> and custom protocol (D_proto/D_config), not in compiled-code structure or raw infrastructure.
> Those top three AUCs (0.78 / 0.73 / 0.72) are a statistical tie at N=8, so read them together,
> not as a ranking. Leave-one-actor-out AUC = 0.78, and the model links precisely the actors the
> per-layer reverse-engineering says are linkable. At N=8 it is a corroborating, interpretable lens
> — exactly the optional Phase-1 deliverable — not a production detector.

Figure: `classifier_figure.png` (left = univariate AUC per layer; right = 4-feature weights).
Numbers: `classifier_results.json`.
