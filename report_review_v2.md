# Submission-readiness review — *Cross-Platform APT Attribution* (revised, 15-page draft)

**Verdict: very close to submission-ready.** This revision fixed almost everything from the
first pass. All numeric tables still match the project's computed data exactly (they were
unchanged; only the prose/framing changed). There is **one new issue worth fixing before you
submit** (an IOC claim the repo data doesn't support), plus **two small leftovers** and a couple
of cosmetic notes. None of these undermines the findings — they're accuracy/consistency fixes.

---

## What this revision fixed (all confirmed) ✅

Compared against the earlier draft and the repo data:

| Earlier issue | Status in this draft |
|---|---|
| §4.4 "every non-Go group best-matches own" (false for APT28) | **Fixed** — now "four of the five… APT28 is the exception (closest match is APT27)." Exactly right. |
| "nine groups" vs "ten groups" contradiction | **Fixed** — §2.1/§2.3 now explicitly say these are two different corpora (9 = old by-actor; 10 = Malpedia candidate → 8). |
| "~13,000" vs "16,752" Go strings | **Fixed** — §3.3 now "sixteen to seventeen thousand," consistent with 16,752. |
| Abstract's strict ranking vs §9.2 "statistical tie" | **Fixed in the abstract** — now "read them together, not a strict first-second-third ranking… behaviour is the most *robust*." (But see leftover #2 — the Conclusion still ranks them.) |
| Layer C scope gap (enrichment/ASN omitted) | **Fixed** — §6.3 now reports the external-IOC enrichment check and the fragile ASN exception (p=0.017, APT28+Lazarus). |
| Fig 5 vs Table 6 metric mismatch | **Fixed** — Fig 5 caption now explains proto_all_idf (0.119) vs proto_all (0.137). |
| Table 10 "strings p=0.006" ambiguity | **Fixed** — now labeled "(IDF+stoplist p=0.006, non-Go p=0.008)." |
| §9.3 omitted APT27 | **Fixed** — now "(APT28, Lazarus, and APT27, which ties Lazarus at rank 7)." |

Nice work — that's a thorough revision pass.

---

## Remaining issues to fix before submitting

### 1. Unsupported IOC claim — `www.paypal.com` / `www.wetransfer.com` for Lazarus (HIGH — verify or correct)

New in this draft, §6.2 / Table 5 / §9.4 say:
> "Lazarus shares two benign domains (**www.paypal.com** and **www.wetransfer.com**) that BADCALL
> uses as cover traffic."

**These two domains do not appear anywhere in the committed repo data.** A full-repo grep for
`paypal`/`wetransfer` returns a single unrelated hit — an *APT28* passive-DNS domain
(`com.paypalsupport.availability-sfv.online` in `infra_layer/pdns_edges.csv`) — and nothing for
Lazarus. Meanwhile the project's own `README.md` and Appendix A consistently document BADCALL's
benign/decoy (fake-TLS SNI) domains as **baidu, whatsapp, xbox, bitcoin, comodo, debian, yahoo**
— not paypal/wetransfer.

So the *existence* of a Lazarus Layer-C non-zero is real (the classifier's `C_infra` feature does
have a Lazarus non-zero, same-mean 0.082 ≈ Table 5's exact level 0.082), but the **specific
domain names are not backed by your data and conflict with the list your own repo documents.**

This matters for submission because it's a concrete, checkable claim: a grader comparing the
report to your artifacts won't find support for it. **Fix:** either (a) replace the names with the
actual shared benign domains from your sample-derived Layer C extraction (likely from the
baidu/whatsapp/… SNI list), or (b) if paypal/wetransfer are genuinely what the extraction found,
add that evidence to the repo so it's reproducible. Right now the names look inserted rather than
measured.

*(Related: the report's §6/Table 5 is the "sample-derived" Layer C, but the repo only contains the
`infra_layer/` enrichment corpus — there is no `layerC_infra.json` in the folder. So Table 5's
numbers can't be reproduced from committed files at all. If reproducibility is graded, add the
sample-derived Layer C script/output.)*

### 2. Conclusion (§14) still gives a strict ranking (MEDIUM)

The abstract was fixed, but §14 still says:
> "Behaviour transfers the strongest, **then embedded data, then the custom protocol.**"

That re-imposes the exact first-second-third ordering the abstract and §9.2 now say *not* to use
("a statistical tie… read them together, not as a strict ranking"). So the abstract and the
conclusion now disagree with each other. **Fix:** align §14 with the abstract, e.g. "Behaviour is
the most robust of the three; at this sample size the three score close enough to read together."

### 3. §9.4 still spells the token `1g.hk` (digit one) (LOW — trivial)

The spelling was corrected to `lg.hk` (letter L) in §6.2 and Table 5, but §9.4 still reads "Earth
Lusca's **1g.hk** token." The repo confirms it's `lg.hk` (letter L) — and that it genuinely
belongs to **Earth Lusca** (`per_pair_evidence.txt`, the KTLVdoor pair, lists `LG.HK` as a shared
token). **Fix:** change the one remaining `1g.hk` in §9.4 to `lg.hk`.

---

## Cosmetic / optional

- **Signature date** reads `06/09/2026`, which is before today (2026-11-15). Confirm it's the
  intended submission date (and the format you want — DD/MM vs MM/DD is ambiguous).
- **Inline citations are sparse.** The reference list is fine (Malpedia, MITRE, TLSH, scikit-learn,
  ESET, NCSC, Trend Micro, Kaspersky), but methods/claims that rely on them (TLSH [3], scikit-learn
  LR/AUC [4], the WellMess build-path match to NCSC [6]) aren't cited at the point of use. Optional
  for a course report, but a quick pass of inline `[n]` markers would tighten it.
- The **author-contributions, anti-plagiarism statement, acknowledgments, and reproducibility
  appendix** are all present and well-formed — good for a course submission.

---

## Bottom line

Structurally and analytically this is submission-ready: complete sections, clean method, all
tables match the data, honest treatment of the Go confound and the null. **Fix #1 (the
paypal/wetransfer claim) before you submit** — it's the only one that could cost credibility if
checked. #2 and #3 are quick consistency edits. Everything else is optional polish.

**Priority:** (1) verify/correct the Lazarus domains → (2) align the §14 conclusion with the
abstract → (3) fix the one `1g.hk` → optional polish.

*(This file is untracked and not part of the submission — delete it when done.)*
