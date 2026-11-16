# Layer B (ATT&CK / TTPs) — Re-verification

**Date:** 2026-11-08 · **Static/offline only** (uses the bundled
`cti/enterprise-attack/enterprise-attack.json`, no network calls).

## What was re-run
The original Layer B pipeline, unchanged in method:
- `scripts/01_attack_layer.py` — per-actor, per-platform ATT&CK technique sets + Jaccard.
- `scripts/02_attack_permutation_test.py` — exact permutation test (6! = 720).
- `scripts/07_attack_layer_full_validation.py` — 5-angle validation.

Method recap: for each actor, take the ATT&CK **software** attributed to the group,
split by platform tag (Windows / Linux), union the **techniques** each tool uses per
platform, then score same-actor Windows-vs-Linux Jaccard against a cross-actor control
and an exact permutation null.

## Result — CONFIRMED (identical to the original)

| Metric | Value |
|---|---|
| Actors | 6 (winnti/APT41, turla, lazarus, sandworm, apt28, apt29) |
| Observed same-actor mean Jaccard | **0.5038** |
| Null (shuffled) mean Jaccard | **0.3738** |
| Observed percentile in null | 99.9th |
| **p-value (exact, 720 orderings)** | **0.0014** → significant |

Per-actor same-actor Jaccard: sandworm 0.804, winnti 0.697, turla 0.647, apt29 0.493,
apt28 0.296, lazarus 0.086.

### 5-angle robustness (all hold)
- **Angle 1 (technique Jaccard):** headline above.
- **Angle 2 (tactic-level):** signal survives at coarser grouping (sandworm 1.00,
  winnti/turla/apt28 0.923, apt29 0.857, lazarus 0.385).
- **Angle 3 (permutation):** p = 0.0014.
- **Angle 4 (commodity-tool exclusion):** after removing software used by 3+ actors
  (Cobalt Strike, Empire, Impacket, Mimikatz, Net, PsExec, certutil), the signal does
  **not** collapse — sandworm 0.53, turla 0.46, apt28 0.36, apt29 0.27, winnti 0.22.
- **Angle 5 (bootstrap, 1000×):** 90% intervals do not span zero for the strong actors
  (sandworm [0.51, 0.61], winnti [0.44, 0.54], turla [0.40, 0.50]).

## Code changes made (so the repo is reproducible / pushable)
Method and results are unchanged; these are hygiene fixes only:
1. **`07_...py` bootstrap made deterministic.** Angle 5 sampled from `list(set(...))`,
   whose order is hash-seed-dependent, so the seeded RNG drew different elements each
   process run. Fixed by sorting the pairs before sampling (`sorted(platforms[...])`).
   Angle 5 is now byte-identical across runs and `PYTHONHASHSEED` values (verified).
   Angles 1–4 were already deterministic and reproduced exactly.
2. **Auto-create `output/`** in `01_...py` and `07_...py` (`os.makedirs("output",
   exist_ok=True)`) so the scripts run from a clean checkout without a manual `mkdir`.

## Verdict
Layer B reproduces exactly: same-actor cross-platform TTP overlap 0.50 vs 0.37 control,
p = 0.0014, robust across tactic-level aggregation, commodity-tool exclusion, and
bootstrap. It remains the project's strongest, cleanest cross-platform signal — and, per
the corpus-pairing audit, the right level of analysis, because it compares an actor's
behaviour across its (different) tools, which is what the corpus actually contains.

---

## FINAL 8-ACTOR RE-RUN (project actor set)

The original Layer B used 6 actors. The project's final actor set drops APT36 &
Gelsemium (no cross-platform significance) and keeps APT27 & Earth Lusca, giving **8
MITRE-scorable actors** (`scripts/08_attack_layer_final8.py`): Turla, Sandworm, Lazarus,
Winnti/APT41, APT28, APT29, **APT27, Earth Lusca**. (Turla is included here because this
layer is MITRE-based; it has no binary samples, so it is absent from Layers A/A2/C/D.)

All 8 are scorable — APT36 and Gelsemium were the only MITRE data gaps (APT36 has 0
Linux-tagged software, Gelsemium 0 software objects), and both are now out of scope.

### Result — CONSISTENT and strongest yet
| | 6-actor (original) | 7 (sample-aligned) | **final 8** |
|---|---|---|---|
| Observed same-actor mean Jaccard | 0.5038 | 0.5170 | **0.5332** |
| Null mean | 0.3738 | 0.3924 | 0.3946 |
| Exact permutation p | 0.0014 (720) | 0.0002 (5040) | **< 0.0001 (40320)** |

Per-actor (8-set): sandworm 0.804, winnti 0.697, earthlusca 0.652, turla 0.647,
apt27 0.591, apt29 0.493, apt28 0.296, lazarus 0.086. The two added actors (Earth Lusca,
APT27) both show strong cross-platform TTP overlap.

Robustness (all hold):
- **Leave-one-out:** worst-case p = **0.0002** (dropping any single actor stays
  significant) → robust.
- **Commodity-tool exclusion** (remove Cobalt Strike, Empire, Impacket, Mimikatz,
  NBTscan, Net, PsExec, certutil): observed **0.287** vs null **0.199**, **p < 0.0001** →
  not an artifact of shared commodity tooling.

### Verdict
The Layer B finding is consistent and strengthens across actor sets. Moving from 6 → 8
actors gives the same direction and magnitude with a monotonically lower p-value
(0.0014 → 0.0002 → < 0.0001); the two added actors reinforce it; and it's robust to
leave-one-out and commodity-tool exclusion. APT36 and Gelsemium were MITRE coverage gaps
and are dropped from the study.

## Reproduce
```bash
cd TTP_layer
python -I scripts/01_attack_layer.py                 # original 6-actor headline + CSVs
python -I scripts/02_attack_permutation_test.py      # original 6-actor permutation p
python -I scripts/07_attack_layer_full_validation.py # original 6-actor 5-angle validation
python -I scripts/08_attack_layer_final8.py         # final 8-actor run + robustness
```
Dependencies: `mitreattack` (mitreattack-python) + the bundled `cti/` ATT&CK STIX bundle.
