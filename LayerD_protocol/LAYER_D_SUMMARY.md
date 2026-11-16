# Layer D — Custom Protocol / Config Reuse (Summary)

**Course:** CS5103 Practical Malware Analysis · IIT Hyderabad
**Authors:** B. Saketh (CS25MTECH12016) · D. Vamsi Krishna (CS25MTECH11027) · Advisor: Prof. Saurabh Kumar
**Sample source (paired re-test):** Malpedia (Fraunhofer FKIE) — static only, not redistributed, credited.

---

## 1. What this layer is

Layer D sits between code (Layer A) and behaviour (Layer B). It asks: do an actor's Windows and Linux builds speak the same custom C2 protocol — the same command vocabulary, the same config-file schema, the same handshake/framing, the same crypto choices — even when the code that implements it is completely different?

This is the idea the project leans on: an actor can rewrite Exaramel from C++ to Go and still keep the exact same `server/proxy/check/report` config model and task/answer command loop. The design is the fingerprint, not the bytes.

## 2. The approach

For each family we take its extracted strings (ASCII + UTF-16) and classify every string into protocol categories with regex rules, after passing it through a toolchain stoplist that drops Go-source paths, runtime internals, and compiler junk (so a Go-path like `/usr/local/go/src/...` can't be miscounted as a C2 URI). Each family becomes a set of protocol tokens per category. Then the usual 8×8 cross-OS matrix + exact `8!` permutation test, diagonal = same tool.

This submission reports the Malpedia same-tool run (same-tool pairs + stoplist + drop-Go guard — the signal survives, headline below). On the earlier pre-Malpedia corpus the same protocol signal collapsed to p≈0.38 under the Go confound (no same-tool pairs, Go stdlib tokens dominating) — the documented lesson that leave-one-out alone isn't enough, you have to drop the whole Go class. That pre-Malpedia run is archived outside this submission.

## 3. The protocol categories (the "different versions")

| Category | What it captures | Example tokens |
|---|---|---|
| **config** | C2 config schema | `server`, `servers`, `proxy`, `check`, `report`, `interval`, `timeout`, `jitter`, `beacon` |
| **framing** | message framing/markers | magic hex, `-----`, `boundary`, `delimiter`, `checksum`, `header` |
| **session** | identity/session tokens | `session`, `token`, `bot_id`, `client_id`, `guid`, `campaign` |
| **http** | HTTP channel strings | `user-agent`, `content-type`, `content-length`, `mozilla/`, `multipart/`, `x-*:` |
| **crypto** | transport crypto | `rc4/rc6/aes/chacha20/...`, `base64`, `-----begin`, `cipher`, `hmac` |
| **c2_uri** | C2 request paths | `/gate`, `/api/`, `/upload`, `*.php`, `/cmd`, `/task` |
| **cmd_vocab** | command dispatch names | `upload/download`, `screenshot`, `readfile`, `shell/exec`, `App.Method` |

And two aggregate metrics:
- **proto_all** — Jaccard over *all* protocol tokens combined.
- **proto_all_idf** — IDF-weighted (rare protocol tokens weigh more; `weight = log(N/df)`).

**Why per-category matters:** the aggregate can be dragged around by one noisy category, and different actors reuse protocol in different places (Exaramel in config, HyperSSL in crypto, X-Agent in http). Reporting each category separately shows which facet of the protocol transfers and lets us name the specific robust ones.

### Guards
- **Toolchain stoplist** (`_STOP` regex) — removes Go/compiler/PE-runtime tokens before classification.
- **Leave-one-out** — worst-p across dropping each actor.
- **Drop-Go guard** — re-run with the Go-on-both-sides pairs (APT29, Earth Lusca) removed; the headline claim rests on this surviving.
- **Manual RE** — hand disassembly/string RE per pair, because the automated screen undercounts pairs whose protocol is the same but whose surface form differs (XML XPath vs Go struct field vs method name).

## 4. How to execute

Scripts are in this folder's `scripts/`; the live working copy runs in `/home/ubuntu/malpedia/layerAD_paired/`.

```bash
# (the per-family feature JSONs must already exist — from Layer A's 10_features.py;
#  here they are in LayerA_code/intermediates/feat/)

# automated protocol scorer: categories, perm test, LOO, drop-Go guard, heatmaps
python3 -I scripts/20_layerD.py        # -> results/layerD_results.json + figures/heatmap_D_*.png

# manual-RE evidence extractor (per-pair URIs/cmds/crypto/config dump)
python3 -I scripts/30_manual_re.py     # -> re_notes/per_pair_evidence.txt
# hand verdicts written up in re_notes/MANUAL_RE_FINDINGS.md
```

Static only; `-I`; no sample executed.

## 5. Results (paired dataset)

| Metric | diag | offdiag | p (8!) | LOO worst | Verdict |
|---|---|---|---|---|---|
| proto_all | 0.137 | 0.023 | 0.0003 | 0.0026 | SIG (Go-inflated → read drop-Go) |
| **proto_all — drop-Go guard (n=6)** | 0.026 | — | **0.0181** | — | **SIG without any Go pair** |
| cat_config | 0.271 | 0.057 | **0.0010** | 0.0083 | **SIG, robust** |
| cat_framing | 0.168 | 0.021 | **0.0030** | 0.0238 | **SIG, robust** |
| cat_session/token | 0.165 | 0.019 | **0.0030** | 0.0238 | **SIG, robust** |
| cat_crypto | 0.131 | 0.020 | 0.0262 | 0.167 | SIG |
| cat_http | 0.129 | 0.023 | 0.0196 | 0.157 | SIG |
| cat_c2_uri | 0.066 | 0.012 | 0.161 | — | ns (after Go-path strip) |
| cat_cmd_vocab | 0.073 | 0.063 | 0.316 | — | ns (surface forms differ) |

## 6. Manual RE — 7 of 8 pairs confirmed

| Actor | Tool | Protocol reuse found by hand |
|---|---|---|
| APT29 | WellMess | **decisive** — entire custom `botlib` C2 library (`rc6.go`, `transport.go`, `message.go`…) identical both OS |
| Earth Lusca | KTLVdoor | **decisive** — identical Go project + JSON config/telemetry schema (`json:"token/client_id/session/jitter"`) |
| APT28 | X-Agent | shared C++ class architecture (`HttpChannel.cpp`, `CryptoContainer.cpp`…) + HTTP channel; TLSH 0.53 |
| Sandworm | Exaramel | same `server/proxy/check/report` config model + task/answer loop (C++ XPath ↔ Go JSON) |
| Lazarus | BADCALL | identical FakeTLS decoy-SNI domain list (byte-identical across OS) |
| APT27 | HyperSSL | ChaCha20 + full PEM set + Boost.Asio networking stack on both |
| Turla | Snake | `content-type: text/plain`, `readfile`/`shell`/`beacon` command tokens shared |
| Winnti/APT41 | Derusbi | **honest null** — Malpedia's Win (HTTP backdoor) and Linux (LKM rootkit) are *different modules* |

The automated screen undercounts Exaramel/BADCALL/Derusbi because their shared protocol is expressed in different surface forms; manual RE recovers them.

## 7. Verdict

> **Custom-protocol / config reuse transfers across OS — and it survives the drop-Go guard (p = 0.018), where the old corpus collapsed to p = 0.38.**

The same-tool pairing fixed the confound. The config, framing, and session/token categories are independently significant and leave-one-out robust; crypto and http are significant; and manual RE confirms 7/8 pairs reuse protocol and/or code across OS. The one null (Derusbi) is a correct finding — different modules, not a failed test. This is the layer that captures what Layer A's byte-level metrics miss: actors keep their protocol design even when they rewrite the implementation.

## 8. Folder map

```
LayerD_protocol/
  LAYER_D_SUMMARY.md       <- this file
  scripts/                 20_layerD.py (scorer), 30_manual_re.py (evidence extractor)
  results/                 layerD_results.json  (per-category matrices, perm test, LOO, drop-Go)
  figures/                 heatmap_D_proto_all.png, heatmap_D_proto_all_idf.png
  re_notes/                MANUAL_RE_FINDINGS.md (hand verdicts), per_pair_evidence.txt
```
