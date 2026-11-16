# Layer A — Code / Binary Fingerprint (Summary)

**Course:** CS5103 Practical Malware Analysis · IIT Hyderabad
**Authors:** B. Saketh (CS25MTECH12016) · D. Vamsi Krishna (CS25MTECH11027) · Advisor: Prof. Saurabh Kumar
**Sample source (paired re-test):** Malpedia (Fraunhofer FKIE) — static analysis only, samples not redistributed, Malpedia credited per their terms.

---

## 1. What this layer is

Layer A asks the most literal attribution question: does an actor's Windows binary look like their Linux binary at the level of the compiled artifact itself — the strings baked into it, the fuzzy byte-shape of the file, the machine instructions, and the symbol/import tables?

If a signal survives here it's strong evidence, because it lives in the binary the actor actually shipped.

## 2. The approach

Same-actor Windows and Linux malware are usually compiled separately, from different source for different targets, so we never expect byte-for-byte identity. We measure relative similarity instead: is an actor's Windows build more similar to their own Linux build than to some other actor's Linux build?

We build an 8×8 cross-OS similarity matrix `M[win_i][lin_j]`, where the diagonal = same actor / same tool. Then we run an exact permutation test: over all `8! = 40,320` ways to pair the 8 Windows families to the 8 Linux families, how often does a random pairing score a diagonal mean ≥ the true one? That fraction is the p-value.

This submission reports the Malpedia same-tool run — genuine same-tool Windows↔Linux pairs for all 8 actors, which is the clean version of the test. (An earlier pre-Malpedia corpus had no guaranteed same-tool pairs and read mostly null, confounded by shared Go toolchain strings; it's archived outside this submission, and it's the reason we needed the same-tool dataset.)

## 3. The metrics (the "Jaccard and its different versions")

| Metric | What it compares | Formula |
|---|---|---|
| **strings Jaccard** | set of ASCII + UTF-16LE strings | `\|A∩B\| / \|A∪B\|` |
| **strings IDF-weighted (+ stoplist)** | same, but rare strings weigh more; Go/compiler/PE-runtime tokens removed first | weighted Jaccard, weight `= log(N/df)` |
| **TLSH best-match** | fuzzy hash of the whole file | `max(0, 1 − diff/300)` over best file pair |
| **opcode 3-gram TF-IDF cosine** | disassembled instruction mnemonic triples | cosine over TF-IDF vectors |
| **symbols / imports Jaccard** | PE imports (`dll!func`) vs ELF `nm`/`readelf` symbols | `\|A∩B\| / \|A∪B\|` |

**Why so many versions:** each isolates a different part of the binary. Plain Jaccard is raw string overlap; IDF stops common boilerplate from inflating the score; the stoplist is the critical guard, stripping Go-runtime/toolchain strings so a positive can't be a "both were built with Go" artifact. TLSH captures byte-shape, opcodes capture compiled-code structure, and symbols capture the API surface. Reporting all five is what lets us say precisely which part transfers.

### The two guards (why the result is defensible)
- **Leave-one-out (LOO):** drop each actor in turn, re-test, and report the worst p. A result that leans on one lucky actor fails here.
- **Drop-Go guard:** re-run with the 3 Go-involved pairs (APT29, Earth Lusca, Sandworm-Linux) removed. If the signal holds among the 5 non-Go pairs, it isn't a toolchain confound.

## 4. How to execute

> Static only. Never execute a sample. Run every script with `python3 -I`. Scripts live **outside** the sample directories. Raw binaries are git-ignored and never committed.

The three scripts are in this folder's `scripts/` (feature extraction `00`/`10` is shared with Layer D). The live working copy runs in `/home/ubuntu/malpedia/layerAD_paired/`, where features land in `feat/` and outputs in `results/`; here they are filed as `intermediates/feat/`, `results/`, and `figures/`.

```bash
# 1. inventory the extracted samples (format / variant / language)
python3 -I scripts/00_inventory.py            # -> feat/inventory.csv  (here: intermediates/feat/)

# 2. extract features per family (best variant per sample: unpacked>dumped>raw)
#    strings (ascii+utf16), symbols, TLSH, opcode 1-/3-grams
python3 -I scripts/10_features.py             # -> feat/<family>.json  (16 files, the intermediates)

# 3. Layer A: build matrices, permutation test, LOO, drop-Go guard, heatmaps
python3 -I scripts/12_layerA.py               # -> results/layerA_results.json + figures/heatmap_A_*.png
```

Required Python packages: `tlsh`, `pefile`, `capstone` (optional), `matplotlib`; CLI tools: `strings`, `objdump`, `nm`, `readelf`. If `tlsh`/`pefile` are missing the script degrades gracefully (that metric reports 0).

## 5. The dataset (8 same-tool pairs)

| Actor | Tool (Win / Lin) | Win lang | Lin lang |
|---|---|---|---|
| Sandworm | Exaramel | C/C++ | **Go** |
| Lazarus | BADCALL | C/C++ | C/C++ |
| APT28 | X-Agent | C/C++ | C/C++ |
| APT27 | HyperSSL | C/C++ | C/C++ |
| Turla | Uroburos / Penquin (Snake) | C/C++ | C/C++ |
| APT29 | WellMess | **Go** | **Go** |
| Earth Lusca | KTLVdoor | **Go** | **Go** |
| Winnti/APT41 | Derusbi | C/C++ | C/C++ |

## 6. Results (paired dataset)

| Metric | diag | offdiag | p (8!) | LOO worst | drop-Go p (n=5) | Verdict |
|---|---|---|---|---|---|---|
| strings Jaccard | 0.107 | 0.017 | **0.0008** | 0.0062 | **0.0083** | **SIG, robust, non-Go** |
| strings IDF+stoplist | 0.091 | 0.013 | **0.0057** | 0.0452 | **0.0083** | **SIG, robust, non-Go** |
| TLSH best-match | 0.329 | 0.118 | 0.0153 | 0.0976 | 0.400 | SIG overall, **Go-driven** |
| opcode 3-gram TF-IDF | 0.240 | 0.178 | 0.193 | — | 0.575 | null |
| symbols / imports | 0.000 | 0.000 | 1.0 | — | — | null (namespaces differ) |

`p = 0.0083` is the minimum achievable p for n=5 — it means every non-Go actor's Windows strings best-match their own Linux strings.

**Per-actor cross-OS similarity (diagonal = same tool):**

| Actor | strings | TLSH | opcode3 | reads as |
|---|---|---|---|---|
| APT29 WellMess | **0.710** | **0.887** | 0.003 | shared Go `botlib` codebase |
| Earth Lusca KTLVdoor | 0.095 | **0.877** | **0.989** | shared Go codebase/compiler |
| APT28 X-Agent | 0.000 | **0.533** | 0.220 | byte-level reuse (clean, non-Go) |
| Turla Snake | 0.013 | 0.333 | 0.117 | moderate |
| Winnti Derusbi | 0.015 | 0.000 | 0.014 | separately coded per OS |
| APT27 HyperSSL | 0.013 | 0.000 | 0.239 | separately coded per OS |
| Lazarus BADCALL | 0.011 | 0.000 | 0.145 | separately coded per OS |
| Sandworm Exaramel | 0.000 | 0.000 | 0.193 | cross-language (C++ vs Go) |

## 7. Verdict

> **Embedded DATA transfers cross-OS; compiled CODE does not.**

The strings fingerprint transfers and is significant even among the 5 non-Go pairs (p = 0.0083), so it's a genuine actor signal rather than a Go-toolchain artifact. Opcodes and import tables do not transfer — different compilers, ABIs and namespaces per OS. TLSH transfers only where there's a shared codebase (the Go pairs) or genuine byte reuse (X-Agent, TLSH 0.53). This is the project's core data-vs-code split, now shown on confound-free same-tool pairs; the earlier pre-Malpedia run couldn't show it because it had no same-tool pairs to compare.

## 8. Folder map

```
LayerA_code/
  LAYER_A_SUMMARY.md          <- this file
  scripts/                    00_inventory.py, 10_features.py, 12_layerA.py
  intermediates/feat/         16 per-sample feature JSONs + inventory.csv (strings/symbols/tlsh/opcodes)
  results/                    layerA_results.json  (8×8 matrices, p-values, LOO, drop-Go)
  figures/                    heatmap_A_{strings_jaccard,strings_idf,strings_idf_destop,symbols_jaccard,tlsh_bestmatch,opcode3_tfidf}.png
```
(The manual-RE confirmation for Layer A/D pairs lives in `LayerD_protocol/re_notes/`.)
