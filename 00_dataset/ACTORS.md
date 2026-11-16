# Project Actor List (canonical) — updated 2026-11-09

Cross-Platform APT Attribution (CS5103, IITH).

## Final actor set
**Old actors (Phase-1 six, untouched):**
1. Turla
2. Sandworm
3. Lazarus
4. Winnti / APT41
5. APT28 / Sednit
6. APT29 / Dukes / Cozy Bear

**New actors added & kept (significant in Layer B):**
7. APT27 / SysUpdate  (Layer B same-actor Jaccard 0.59)
8. Earth Lusca        (Layer B same-actor Jaccard 0.65)

→ 8 actors total.

## Removed (added but dropped — no genuine cross-platform significance)
- **APT36 / Transparent Tribe** — Layer B: MITRE data gap (0 Linux-tagged software);
  Layer A: 0.45 diagonal but Go-toolchain confound (Win/Linux are different Go programs,
  share only stdlib); Layer D: 0.12 but Go-runtime confound. No genuine signal.
- **Gelsemium** — Layer B: MITRE data gap (0 software objects); Layer A: 0.216 ≈ 0.202
  control (flat); Layer D: 0.006 ≈ 0.004 (flat); Windows samples contaminated with
  public tools (JuicyPotato etc.), no Gelsevirine present. No signal.

## Per-layer coverage of the final set
- **Layer B (TTP, MITRE-based):** Turla + the 7 sample actors are scorable. Current
  7-actor sample-set run: observed 0.517 vs null 0.392, p=0.0002 (robust).
- **Layers A / A2 / C / D (binary-sample-based):** 7 actors — APT27, APT28, APT29,
  Earth Lusca, Lazarus, Sandworm, Winnti. (Turla has no Linux samples → not in these
  layers; it remains an old actor in the Layer-B / conceptual set.)

## Note
Against the Phase-1 six, the sample work added 4 actors (APT27, APT36, Earth Lusca,
Gelsemium); 2 are removed here (APT36, Gelsemium), leaving 2 kept (APT27, Earth Lusca).
