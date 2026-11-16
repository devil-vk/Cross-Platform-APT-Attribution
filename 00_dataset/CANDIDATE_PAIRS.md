# Malpedia Same-Tool Cross-OS Pairing Map

**Project:** Cross-Platform APT Attribution — Windows vs. Linux (CS5103, IIT Hyderabad)
**Authors:** B. Saketh (CS25MTECH12016) · D. Vamsi Krishna (CS25MTECH11027)
**Source:** Malpedia (Fraunhofer FKIE) — actor pages, public library. Access granted 2026-11.
**Date:** 2026-11-09 · **Phase:** family mapping only — NO samples downloaded yet.

> **Malpedia must be credited as the sample source in the final write-up** (condition of
> access), and **samples must NOT be made public** — they stay git-ignored, static-only,
> never executed, exactly as our raw corpus already is.

---

## Why this map exists (the problem it fixes)

Our whole study carried one caveat: we had same-**actor** samples but not same-**tool**
cross-OS pairs. The corpus-pairing audit proved **0 of 9 actors** had a clean same-tool
Windows↔Linux pair, so Layer D collapsed to a Go-toolchain confound corpus-wide and only
survived on the *one accidental* clean pair (APT29 **WellMess**, Jaccard 0.46). Every null
we reported read "…but we couldn't source properly paired samples."

Malpedia fixes this directly: families are named by platform (`win.*`, `elf.*`), and
each actor page lists the families attributed to it. Cross-referencing the `win.*` and
`elf.*` lists yields genuine same-tool Windows↔Linux pairs — the WellMess situation,
on purpose, for every actor.

Result: all 8 actors now have ≥1 genuine same-tool cross-OS pair. Turla — which had
NO Linux samples and was MITRE-only in Layer B — gains a Linux binary (Penquin) that pairs
with Windows Uroburos (Snake).

---

## Candidate same-tool Windows↔Linux pairs

★ = identical family name across OS (cleanest possible pair). Sample counts to be read
from Malpedia at pull time.

| # | Actor | Windows family | Linux family | Tool | Grade | Notes |
|---|---|---|---|---|---|---|
| 1 | **Sandworm** | `win.exaramel` | `elf.exaramel` | Exaramel | ★★★ | Identical name; ESET-documented Win+Lin backdoor. **Not Go** → no Go confound. Gold reference pair. |
| 2 | **Lazarus** | `win.badcall` | `elf.badcall` | BADCALL | ★★★ | Identical name (also apk.badcall). |
| 3 | **APT28** | `win.xagent` | `elf.xagent` | X-Agent / Chopstick | ★★★ | Identical name; also osx/ios/apk. Classic cross-platform implant. |
| 4 | **APT27** | `win.hyperssl` | `elf.hyperssl` | HyperSSL | ★★★ | Identical name; sibling of win.hyperbro. |
| 5 | **Earth Lusca** | `win.ktlv_door` | `elf.ktlv_door` | KTLVdoor | ★★★ | Identical name; Trend-documented Win+Lin **Go** malware → expect Go-blob confound + encrypted config (we saw this before — but now we have BOTH sides). |
| 6 | **APT29** | `win.wellmess` | `elf.wellmess` | WellMess | ★★★ | Our existing pair, now both in Malpedia. Go `botlib`; already Jaccard 0.46. |
| 7 | **Winnti/APT41** | `win.winnti` | `elf.winnti` | Winnti rootkit | ★★★ | Identical name; classic cross-platform rootkit. Often packed. |
| 8 | **Turla** | `win.uroburos` | `elf.penquin_turla` | Snake / Uroburos | ★★ | Different Malpedia names, **same tool lineage** (Penquin = Snake's Linux port). Unlocks Turla for the binary layers for the first time. |

### Secondary / to-confirm pairs (bonus if the primary is thin)
| Actor | Windows family | Linux family | Tool | Status |
|---|---|---|---|---|
| Winnti/APT41 | `win.keyplug` *(confirm)* | `elf.keyplug` | KEYPLUG | elf confirmed; Windows KEYPLUG exists in reporting, confirm Malpedia filing |
| Earth Lusca | `win.sprysocks` *(confirm)* | `elf.spry_socks` / `elf.sprysocks` | SprySOCKS | Linux confirmed; confirm win side |
| Lazarus | — | `elf.simpletea` / `osx.simpletea` | SIMPLETEA | Linux+macOS; no win sibling listed (not a Win↔Lin pair) |
| Lazarus | `win.dacls` | `elf` dacls *(ref)* | Dacls/MATA | Dacls is cross-platform; confirm elf.dacls on Malpedia |

---

## What each layer gains

| Layer | Impact of these pairs |
|---|---|
| **A — code/strings/TLSH** | Big. On a true same-tool pair, embedded-data similarity (strings, TLSH) should be **high within pair, low across actors** — a clean, decisive test instead of the mixed-family one. Non-Go pairs (Exaramel, X-Agent, BADCALL, HyperSSL, Uroburos) avoid the Go-blob confound. |
| **D — protocol/config** | The main prize. Replaces 1 accidental pair with **up to 8 real same-tool pairs** → proper permutation test of custom-protocol reuse, finally answering slide 13 cleanly. Caveat: Go pairs (KTLVdoor, WellMess) and packed ones (Winnti) still fight encryption/packing — but the non-Go pairs give unconfounded signal. |
| **B — TTPs** | No change — MITRE-based, not binary-derived. Stays the strongest layer (p<0.0001). |
| **C — infrastructure** | No change — needs C2 IOCs, not binaries. Stays null. |

**Net:** Layers A and D get re-tested on confound-free same-tool pairs; B and C are untouched.

---

## Recommended analysis set (what's worth downloading)

**Tier 1 — pull first (clean, non-Go, decisive):**
Exaramel (Sandworm), X-Agent (APT28), BADCALL (Lazarus), HyperSSL (APT27), Uroburos/Penquin
(Turla). These five are the cleanest test of the hypothesis with no Go confound.

**Tier 2 — pull next (complete the 8, accept known confounds):**
WellMess (APT29, already have), KTLVdoor (Earth Lusca, Go+encrypted), Winnti (Winnti/APT41,
packed). These finish the 8-actor set and let us state the Go/packing caveat *with* the data.

**Per pair we need:** a few Windows samples of `win.X` + a few Linux samples of `elf.X`.
Small, targeted pulls — not the whole 46 GB corpus.

---

## Access / mechanics (next phase, on your go-ahead)
- Register with the invite token, **or** add a deploy SSH key and `git clone` the labelled
  corpus (per Malpedia's reply).
- Pull only the Tier-1/Tier-2 families above into a fresh, isolated dir (untrusted data
  rules: own directory, scripts elsewhere, `python -I`, **never executed**).
- Re-run Layer A (`layerA/` + finer_grained) and Layer D (`layerD/`) scoring on the paired
  sets; regenerate results + update READMEs; add the **Malpedia credit** line.
- Then fold into the repo and push (push is on hold until this is done, per decision).

## Source actor pages (public, fetched 2026-11-09)
turla · sandworm · lazarus_group · apt41 · sofacy (APT28) · apt29 · emissary_panda (APT27)
· earth_lusca — all under `malpedia.caad.fkie.fraunhofer.de/actor/<slug>`.
