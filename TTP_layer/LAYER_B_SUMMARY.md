# Layer B — TTPs / MITRE ATT&CK Behaviour (Summary)

**Course:** CS5103 Practical Malware Analysis · IIT Hyderabad
**Authors:** B. Saketh (CS25MTECH12016) · D. Vamsi Krishna (CS25MTECH11027) · Advisor: Prof. Saurabh Kumar
**Source:** MITRE ATT&CK Enterprise STIX bundle (`cti/`, offline). No binaries needed.

---

## 1. What this layer is

Layer B asks: does an actor behave the same way on Windows and Linux, regardless of the specific binary? "Behaviour" here is the set of MITRE ATT&CK techniques the actor's tooling uses (e.g. T1071 Application-Layer Protocol, T1059 Command Interpreter, T1053 Scheduled Task). Two independently written binaries can share almost no bytes yet still do the same things — same persistence trick, same C2 style, same discovery sequence. That tradecraft is what Layer B measures.

This is the one layer that doesn't depend on having a binary sample, so it also covers actors (like Turla historically) that we could only reach through MITRE.

## 2. The approach

For each actor:
1. Take the ATT&CK **software** (malware/tools) attributed to the group in MITRE.
2. Split that software by **platform tag** (Windows vs Linux).
3. **Union the techniques** each tool uses, per platform → one Windows technique-set and one Linux technique-set per actor.
4. Score the **same-actor Windows-vs-Linux Jaccard** of those two sets.
5. Compare against an **exact permutation null** (all `8!` re-pairings of Windows-sets to Linux-sets).

Identical method to the original `01`+`02` scripts, so the 8-actor re-run is directly comparable to the earlier 6-actor one.

## 3. The metric

- **Technique-set Jaccard:** `|Win_techniques ∩ Lin_techniques| / |Win_techniques ∪ Lin_techniques|` per actor.
- **Null:** exact permutation over all `8! = 40,320` orderings; p = fraction of random pairings whose mean same-actor Jaccard ≥ observed.
- **Guards:**
  - **Leave-one-out (LOO):** drop each actor, re-test, report worst p.
  - **Commodity-tool exclusion:** re-run after removing shared/off-the-shelf tooling (Mimikatz, Cobalt Strike, PsExec, etc.) so the signal is not just "everyone uses the same public tools."

## 4. How to execute

```bash
# uses an offline MITRE ATT&CK STIX bundle (cti/enterprise-attack/enterprise-attack.json)
python3 -I scripts/08_attack_layer_final8.py   # 8-actor final run
#   -> results/attack_layer_final8.json, results/layerB_rerun_results.txt
```

Requires `mitreattack-python` (`from mitreattack.stix20 import MitreAttackData`) and an offline `cti/` STIX bundle. Fully offline and deterministic.

Scripts in `scripts/`:
- `01_attack_layer.py` + `02_attack_permutation_test.py` — the earlier 6-actor method (same algorithm, so directly comparable).
- `07_attack_layer_full_validation.py` — commodity-exclusion + LOO validation.
- `08_attack_layer_final8.py` — **the final 8-actor run** (the one reported).

The full 8×8 technique-overlap matrix used by the fusion classifier is in `results/layerB_matrix.json`.

## 5. The actor set

8 actors: Turla, Sandworm, Lazarus, Winnti/APT41, APT28, APT29, APT27, Earth Lusca.
(APT36 & Gelsemium were dropped — APT36 has 0 Linux-tagged software in MITRE, Gelsemium 0 software at all → not cross-platform-scorable.)

## 6. Results

| Measure | Observed | Null | p (8!) | Robustness |
|---|---|---|---|---|
| same-actor mean Jaccard | **0.533** | 0.395 | **< 0.0001** | LOO worst **0.0002** |
| commodity-tool excluded | 0.287 | 0.199 | **< 0.0001** | holds |

**Per-actor Win-vs-Lin technique Jaccard:**
sandworm 0.80 · winnti 0.70 · earthlusca 0.65 · turla 0.65 · apt27 0.59 · apt29 0.49 · apt28 0.30 · lazarus 0.09.

## 7. Verdict

> **Behaviour transfers across platforms — this is the strongest and most robust layer.**

Same-actor Windows and Linux tooling share significantly more ATT&CK techniques than random actor pairings (p < 0.0001), the result is leave-one-out robust, and it survives removing commodity tools — so it reflects the actor's own tradecraft, not shared public tooling. Put simply, an actor's habits (how they persist, communicate, and move) carry across OS even when the code does not. The paired Malpedia binaries didn't change this result; they just mean the 8 actors are now binary-backed rather than MITRE-only.

## 8. Folder map

```
LayerB_ttp/
  LAYER_B_SUMMARY.md          <- this file
  LayerB_REVERIFICATION.md    reproducibility re-verification notes
  scripts/                    01,02 (6-actor method), 07 (validation), 08 (final 8-actor)
  results/                    attack_layer_final8.json, attack_layer_full_validation.json,
                              layerB_matrix.json (8×8), layerB_rerun_results.txt (run log)
  intermediates/              attack_layer_control_pairs.csv, attack_layer_same_actor.csv,
                              candidate_samples.csv
```
