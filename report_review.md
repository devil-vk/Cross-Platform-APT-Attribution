# Review of *Cross-Platform APT Attribution* (report draft)

Checked the 14-page report against the project's actual result files
(`LayerA_code/results/layerA_results.json`, `TTP_layer/results/attack_layer_final8.json`,
`LayerD_protocol/results/layerD_results.json`, `LayerFusion_classifier/results/classifier_results.json`)
and the repo's own `README.md` / `summary.txt`.

**Good news first:** every numeric table in the report matches the computed data exactly —
Table 2 (Layer A diag/off/p), Table 3 (per-group strings/TLSH/opcode diagonals), Table 4
(Layer B per-actor Jaccard), Table 6 (Layer D per-category diag/p), Table 8 (all seven AUCs),
and the classifier numbers in §9 (in-sample AUC 0.902, LOACV 0.781, infra weight +1.68). The
APT29 Go-confound figures (own 0.710 vs Sandworm 0.723) are also exactly right. So the number
transcription is clean. The issues below are a factual overclaim, several internal
inconsistencies, and one scope gap.

---

## 1. Factual error — §4.4 "every non-Go group" overclaims (HIGH)

> §4.4: "Embedded data (strings) transfers across operating systems and survives the drop-Go
> guard. **Every non-Go group's Windows strings best-match its own Linux strings.**"

This is **false for APT28**. Checked against all three string matrices
(`strings_jaccard`, `strings_idf`, `strings_idf_destop`): for each non-Go group, is the Windows
row's highest-scoring Linux build its own?

| Non-Go group | own-pair strings | best match is… |
|---|---|---|
| Lazarus | 0.0109 | **own** ✓ |
| APT27 | 0.0128 | **own** ✓ |
| Turla | 0.0126 | **own** ✓ |
| Winnti | 0.0147 | **own** ✓ |
| **APT28** | **0.0005** | **APT27** (0.0051) ✗ |

APT28's own-pair strings diagonal is ≈ 0.000 (consistent with Table 3, where APT28 strings =
0.000), and its Windows build actually resembles APT27's Linux build slightly more. So the claim
holds for **4 of 5** non-Go groups, not all of them.

The *aggregate* drop-Go result (p = 0.0083) is unaffected — it survives because the other four
carry it — but the universal per-group sentence contradicts the report's own data (and its own
statements elsewhere that APT28 is "weaker" / ranks 8th in LOACV).
**Fix:** change to "four of the five non-Go groups' Windows strings best-match their own Linux
build (APT28 is the exception)," or drop the universal claim.

---

## 2. Factual/typo — the token is `lg.hk`, not `1g.hk` (HIGH, easy)

The report spells the ambiguous infrastructure token **three different ways across two
characters**:
- §6.2: "the ambiguous token **1g.hk**" (digit one)
- Table 5 caption: "artifact **lg.hk** only" (letter L)
- §9.4: "the **1g.hk** token" (digit one)

The repo is consistent: `LayerD_protocol/re_notes/per_pair_evidence.txt` shows the string as
**`LG.HK`** and `LayerFusion_classifier/CLASSIFIER_SUMMARY.md` calls it **`lg.hk`** (letter L).
So the digit-one spellings in §6.2 and §9.4 are wrong. **Fix:** use `lg.hk` everywhere (the
irony being that the report is calling it "ambiguous" while mis-rendering it).

---

## 3. Inconsistency — "nine groups" vs "ten groups" (MEDIUM)

- §2.1: "zero of the **nine** groups had a clean same-tool pair"
- §2.3: "We first looked at **ten** groups … removed [APT36, Gelsemium] … the final set is the
  **eight** groups."

Read together this looks contradictory (9? 10? and 10 − 2 = 8, not 9). From the repo these are
actually **two different corpora**: the pre-Malpedia audit had 9 groups (`README.md`: "audit:
0/9 clean same-tool cross-OS pairs"), and the Malpedia candidate set had 10 (→ 8 after dropping
two). The report never says so, so a reader sees a contradiction.
**Fix:** state explicitly that §2.1's "nine" is the old by-actor corpus and §2.3's "ten" is the
Malpedia candidate set.

---

## 4. Inconsistency + unverifiable numbers — Go string counts (MEDIUM)

- §3.3: "Large Go files all share about **thirteen thousand** built-in 'standard library' text
  strings."
- §4.3: "APT29 (both sides) and Sandworm's Linux build are all compiled with Go version 1.8.3,
  so they share about **16,752** built-in strings."

16,752 rounds to ~17,000, not ~13,000 — the two figures don't agree. Separately, **none** of
these specific numbers appears anywhere in the repo: `16,752`, `~13,000`, `~630` (Earth Lusca),
Go `1.8.3`, or Go `1.20.5` are not in any committed result, script, or note (grep returns
nothing). They may be correct hand-measured values, but they aren't backed by a project
artifact. **Fix:** reconcile the ~13k vs 16,752 wording and cite where these counts / Go
versions come from (or add the measurement to the repo).

---

## 5. Inconsistency — "behaviour is strongest" vs the report's own "statistical tie" (MEDIUM-HIGH)

The headline ranking is stated strictly in two places:
- Abstract: "**Behaviour is the strongest**, embedded data (strings) is next, and the custom
  protocol is third."
- §14 Conclusion: "Behaviour transfers the strongest, then embedded data, then the custom
  protocol."

But §9.2 — using what the report itself calls "the most trustworthy view" (univariate AUC) —
says the opposite:
> "The top three (strings 0.78, behaviour 0.73, protocol 0.72) are **a statistical tie** at this
> small size, so we read them together, **not as a strict ranking**."

And by that AUC metric (Table 8), **strings (0.783) actually edges out behaviour (0.734)** — the
reverse of "behaviour strongest, strings next." Calling behaviour "strongest" is defensible on
*robustness* grounds (p < 0.0001, LOO 0.0002, commodity-robust, no Go dependence), but the
abstract/conclusion present it as a confident 1-2-3 ordering that (a) contradicts §9.2's tie
statement and (b) isn't what the AUC numbers show.
**Fix:** either call the top three a tie in the abstract/conclusion too, or explicitly ground
"behaviour is the most *robust* signal" in the p-value/LOO evidence rather than implying an
AUC-style ranking — and don't rank strings and protocol against each other if they're tied.

---

## 6. Inconsistency — what the two Layer-C non-zero pairs are (MEDIUM)

- §6.2 + Table 5: the two strict-level cross-OS "matches" are "**both** … the ambiguous token
  1g.hk" / "artifact lg.hk **only**."
- §9.4: the infrastructure feature is "non-zero for only 2 same-group pairs, and both of those
  are artifacts (**the 1g.hk token, and two benign decoy domains for Lazarus**)."

These disagree on what the *second* non-zero pair is — "lg.hk only" vs "lg.hk **plus** Lazarus."
Also, Lazarus's "decoy domains" are the BADCALL fake-TLS SNI list (baidu/whatsapp/xbox/…), which
is a **Layer A/D strings artifact, not infrastructure**; in the repo, Lazarus's actual *infra*
signal is a hosting-provider (ASN) reuse from the enrichment analysis, not decoy domains.
**Fix:** reconcile these, and state clearly which Layer-C dataset feeds the classifier's
`C_infra` feature (see #7) and relabel the second artifact correctly.

---

## 7. Scope gap — Layer C in the report ≠ Layer C in the project (LOW-MEDIUM)

The report's Layer C (§6, Table 5, Fig 4) presents **only** the sample-derived analysis
(4 levels: exact domain/IP/URL, /16, 2nd-level domain, C2 URL path). The project's own
`summary.txt` and `infra_layer/` center a **different, 9-level external-IOC enrichment**
analysis (passive DNS, ASN, registrar, TLS cert/issuer, JARM, first-seen year), whose headline
finding is the one real caveat: a fragile **ASN / hosting-provider** exception (p = 0.017,
driven by APT28 + Lazarus). The report omits that enrichment work and its caveat entirely.

The final verdict is the same either way (infrastructure is null), so this isn't a wrong
*conclusion* — but if the report is meant to represent the whole project, it under-represents the
Layer C effort and drops its only interesting nuance. **Decide** whether that omission is
intentional; if so, maybe one sentence acknowledging the enrichment check and the ASN caveat.

---

## 8. Minor points (LOW)

- **Fig 5 vs Table 6 use different metrics.** Fig 5 is labeled `proto_all_idf` (IDF-weighted,
  diagonal 0.119) while Table 6 and the text report `proto_all` (unweighted, diagonal 0.137).
  Fine to do, but worth a note so a reader doesn't try to reconcile the figure cells with the
  table.
- **Table 10 "strings … p = 0.006"** is the IDF+stoplist p-value (0.0057); the plain strings
  Jaccard in Table 2 is p = 0.0008. Both are legitimately "strings," and 0.006 is the right
  Go-clean number to headline — just be explicit which metric it is.
- **§9.3** says LOACV "fails on the ones we already called weak (APT28, Lazarus)," but Table 9
  shows **APT27 also at rank 7** (tied with Lazarus). Either mention APT27 or soften to "the
  weakest-overlap actors."

---

## Priority order
1. **§4.4 "every non-Go group"** — factual, verifiable, and contradicts your own data (#1).
2. **`1g.hk` → `lg.hk`** — trivial fix, currently wrong in two places (#2).
3. **Abstract/Conclusion ranking vs "tie"** — it's the headline claim (#5).
4. **"nine" vs "ten" groups** and **13k vs 16,752** — quick clarifications (#3, #4).
5. **Layer C non-zero wording** and **Layer C scope** — reconcile/decide (#6, #7).
6. The three minor nits (#8).

*(This file is untracked and not part of the submission — delete it when done.)*
