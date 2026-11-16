# Cross-Platform APT Attribution — Final Submission

**Course:** CS5103 Practical Malware Analysis · IIT Hyderabad
**Authors:** B. Saketh (CS25MTECH12016) · D. Vamsi Krishna (CS25MTECH11027)
**Advisor:** Prof. Saurabh Kumar
**Sample source for the paired re-test:** **Malpedia (Fraunhofer FKIE)** — used under
invite access; samples are NOT redistributed here (only derived features/results), and
Malpedia is credited as the source per their terms.

## Research question
Do nation-state actors leave a recognizable fingerprint that links their independently built
Windows and Linux malware? We test four evidence layers, each with a controlled exact
permutation test, on a same-actor same-tool paired dataset sourced from Malpedia — genuine
same-tool Windows↔Linux pairs for all 8 actors, which is the clean way to run this test.

## The dataset that made it work
An earlier exploration used samples grouped by actor but not by tool (audit: 0/9 clean same-tool
cross-OS pairs), so Layers A/D were confounded by shared Go-toolchain strings and read null.
Malpedia access let us assemble genuine same-tool pairs for all 8 actors, which turned those
confounded nulls into clean, positive, confound-robust results. This submission contains only the
final Malpedia-based analysis; the earlier pre-Malpedia exploration is archived separately (outside
this folder) and isn't part of the submission. Layers B (MITRE behaviour) and C (infrastructure)
don't depend on paired binaries and stand on their own.

## Final dataset — 8 actors, same-tool pairs
Sandworm·Exaramel · Lazarus·BADCALL · APT28·X-Agent · APT27·HyperSSL · Turla·Snake
(Uroburos/Penquin) · APT29·WellMess · Earth Lusca·KTLVdoor · Winnti/APT41·Derusbi.
(APT36 and Gelsemium were evaluated and dropped — neither showed cross-platform significance.)
See `00_dataset/` for the pairing map, sample manifest, and inventory.

## Headline results (paired dataset)
| Layer | Evidence | Result | p / robustness |
|---|---|---|---|
| **A · code / binary** | strings, TLSH, opcodes, symbols | **embedded DATA transfers; compiled CODE doesn't** | strings p=0.006 (non-Go p=0.008); opcodes/symbols null |
| **B · TTPs** | MITRE ATT&CK techniques | **transfers — strongest** | p<0.0001, LOO 0.0002, commodity-robust |
| **C · infrastructure** | C2 domains/IPs/URIs from samples | **null** — OS-specific C2 | 0/8 at /16 & URI level |
| **D · protocol / config** | C2 cmds, crypto, config, framing | **transfers (aggregate)** | proto_all drop-Go p=0.018 (fragile → 0.042 at n=5); per-category config/framing/session NOT drop-Go-robust (Go-inflated); 7/8 by manual RE |

Three of the four layers carry a positive, confound-robust cross-platform signal (behaviour,
embedded data, custom protocol); only raw internet infrastructure does not. Full numbers and
per-pair evidence are in `RESULTS_SUMMARY.md`.

## Layout
Every layer folder is self-contained and holds only its own material, in a uniform shape:
`scripts/` · `results/` · `figures/` (heatmaps/maps) · `intermediates/` (generated JSON/CSV) ·
`logs/` or `re_notes/` where applicable · and one `LAYER_*_SUMMARY.md`.
```
00_dataset/            actor list, Malpedia pairing map, sample manifest + inventory
LayerA_code/           binary features — strings / TLSH / opcodes / symbols
  scripts/             00_inventory, 10_features, 12_layerA
  intermediates/feat/  16 per-sample feature JSONs (strings/symbols/tlsh/opcodes) + inventory.csv
  results/             layerA_results.json (8×8 matrices + p-values)
  figures/             6 heatmaps (strings/idf/destop, symbols, tlsh, opcode)
LayerB_ttp/            MITRE ATT&CK technique-set overlap (8 actors)
  scripts/             01/02 attack layer + permutation, 07 full-validation, 08 final-8
  results/             attack_layer_final8.json, full_validation.json, layerB_matrix.json, run log
  intermediates/       control-pair / same-actor / candidate-sample CSVs
LayerC_infra/          C2 infrastructure — null result, shown two ways (kept both)
  scripts/             40_layerC_infra (Malpedia sample-derived) + 06/09/03 + enrichment (external IOC)
  results/             layerC_infra.json (sample-derived) + external-IOC infra CSVs/validation
  figures/ logs/ intermediates/   infra heatmap · enrich/pdns logs · pDNS/Shodan/ThreatFox raw
LayerD_protocol/       custom C2 protocol / config design
  scripts/             20_layerD, 30_manual_re
  results/             layerD_results.json      figures/  2 protocol heatmaps
  re_notes/            MANUAL_RE_FINDINGS.md + per-pair evidence
LayerFusion_classifier/  Phase-1 interpretable logistic regression over all 4 layers' scores:
                       which layer carries the signal + out-of-sample 3-test-case stress test
RESULTS_SUMMARY.md     combined 4-layer results, per-metric and per-pair
```

## Layer-fusion classifier (the Phase-1 "optional interpretable classifier")
A simple logistic regression over the four layers' per-pair similarity scores corroborates —
reading the same four matrices a different way (a multivariate fit, not an independent data
source) — that the cross-platform signal lives in embedded data (strings), behaviour (TTPs) and
custom protocol, not in compiled-code structure or raw infrastructure (univariate AUC: strings
0.78, TTP 0.73, protocol 0.72 — a statistical tie at N=8, read together not as a ranking; opcode
0.55, infra 0.63; leave-one-actor-out AUC 0.78; strings uses the Go-clean stoplisted metric,
protocol is an upper bound as it still carries some Go-stdlib tokens). An out-of-sample test on new vx-underground samples shows it links
same-*tool* Windows↔Linux builds when they share embedded data (WellMess P=0.86) but cannot link
same-actor *different*-tool pairs from binary features alone — reproducing, at the model level, why
four layers are needed. See `LayerFusion_classifier/`.
Each layer folder keeps its own README/summary with detailed results and reproduce steps.

## Manual RE (paired)
`LayerD_protocol/re_notes/MANUAL_RE_FINDINGS.md` records hand disassembly/
string RE for every pair. Highlights: APT29 WellMess and Earth Lusca KTLVdoor share their
*entire* custom codebase across OS; APT28 X-Agent shares its C++ class architecture; Sandworm
Exaramel and Lazarus BADCALL share their custom protocol (config model / FakeTLS handshake)
despite different code.

## Reproduce the manual RE yourself (live, static-only) — commands **and** captured output
Every cross-OS claim above can be shown on screen with `strings` + `grep` alone — static analysis
only; no sample is ever executed. The binaries are not in this repo (Malpedia terms); point `$E` at
your own local extracted Malpedia samples. Windows PE strings are often UTF-16, so some Windows
greps use `strings -el` (wide); Linux ELF is ASCII (`strings -n`). The actual output captured on our
machine is shown under each command so it can be verified without running anything. Full guide:
`LayerD_protocol/re_notes/DEMO_GUIDE.md`.

```bash
E=/home/ubuntu/malpedia/layerAD_paired/extracted        # <- your local Malpedia extracted dir
```

**0 · Sandworm — Exaramel** — _same C2 config model in two languages (Windows C++ ↔ Linux Go)_
```bash
strings -el -n 5 $E/win.exaramel/* | grep -iE '/settings/(servers|proxy|check)|/commands/cmd|Check AV'
strings    -n 6 $E/elf.exaramel/* | grep -iE 'json:"(metod|guid|arguments|answer_async)"|/api/v1'
```
```text
WIN → /settings/servers/server[@current='true']   /settings/proxy/@password   /settings/check
      /commands/cmd   Windows Check AV service
LIN → https://176.31.225.204/api/v1   json:"guid"   json:"metod"(sic)   json:"arguments"   json:"answer_async"
```

**1 · Lazarus — BADCALL** — _identical FakeTLS decoy-SNI list_
```bash
strings -n 6 $E/win.badcall/* | grep -iE 'baidu|whatsapp|xbox|bitcoin|comodo|debian|yahoo'
strings -n 6 $E/elf.badcall/* | grep -iE 'baidu|whatsapp|xbox|bitcoin|comodo|debian|yahoo'
```
```text
WIN → baidu.com   bitcoin.org   comodo.com   debian.org   uk.yahoo.com   whatsapp.com
LIN → www.baidu.com   www.bitcoin.org   www.comodo.com   www.debian.org   uk.yahoo.com
      web.whatsapp.com   myservice.xbox.com
```

**2 · APT28 — X-Agent** — _same C++ class architecture + HTTP channel_
```bash
strings -n 6 $E/win.xagent/* | grep -iE 'AgentKernel|ChannelController|HttpChannel|CryptoContainer|multipart/mixed|octet-stream'
strings -n 6 $E/elf.xagent/* | grep -iE 'AgentKernel|ChannelController|HttpChannel|CryptoContainer'
```
```text
WIN → .?AVAgentKernel@@   .?AVChannelController@@   .?AVIChannelController@@
      Content-type: multipart/mixed;   Content-Type: application/octet-stream
LIN → AgentKernel.cpp   ChannelController.cpp   CryptoContainer.cpp   HttpChannel.cpp
      HttpChannel::createKeyToken / generateHttpMes / addHttpHeader   (same classes, demangled)
```

**3 · APT27 — HyperSSL** — _shared Boost.Asio + crypto/PEM transport_
```bash
strings -n 6 $E/win.hyperssl/* | grep -iE 'asio\.|BEGIN (CERTIFICATE|DH|EC|RSA)|sha256|chacha'
strings -n 6 $E/elf.hyperssl/* | grep -iE 'asio\.|BEGIN (CERTIFICATE|DH|EC|RSA)|sha256|chacha'
```
```text
WIN → asio.misc   asio.system   -----BEGIN CERTIFICATE/DH PARAMETERS/EC PRIVATE KEY/RSA PRIVATE KEY-----
      CHACHA20   "=> calc finished tls sha256"
LIN → asio.misc   asio.system   asio.ssl   asio.netdb   -----BEGIN CERTIFICATE-----
```

**4 · Turla — Snake** — _shared protocol primitives (modest)_
```bash
strings -el -n 5 $E/win.uroburos/*     | grep -iE 'text/plain|ReadFile'
strings    -n 5 $E/elf.penquin_turla/* | grep -iE 'text/plain|readfile|SHELL|beacon'
```
```text
WIN → Content-Type: text/plain   ReadFile
LIN → Content-Type: text/plain   readfile   SHELL   beacon
```

**5 · APT29 — WellMess** — _identical Go `botlib` source tree (incl. author build path)_
```bash
strings -n 6 $E/win.wellmess/* | grep -iE 'botlib|rc6|GoProject'
strings -n 6 $E/elf.wellmess/* | grep -iE 'botlib|rc6|GoProject'
```
```text
WIN → *botlib.rc6cipher   *botlib.KeySizeError   /home/ubuntu/GoProject/src/bot/botlib
      _/home/ubuntu/GoProject/src/bot/botlib.AES_Decrypt
LIN → botlib.AES_Decrypt   botlib.AES_Encrypt   botlib.Base64ToNormal   botlib.CalculateMD5Hash
(the /home/ubuntu path is the MALWARE AUTHOR's build machine, baked into the Malpedia sample — matches NCSC's WellMess report, not our environment)
```

**6 · Earth Lusca — KTLVdoor** — _identical Go package tree + config/telemetry schema_
```bash
strings -n 6 $E/win.ktlv_door/* | grep -iE 'bootTime|proto_model|server_agent|gopsutil'
strings -n 6 $E/elf.ktlv_door/* | grep -iE 'bootTime|proto_model|server_agent|gopsutil'
```
```text
WIN → tools/modules/accelerator/server_agent/transport/models
      tools/modules/accelerator/server_agent/protocol/proto_model
      github.com/shirou/gopsutil/v4/cpu   json:"bootTime"
LIN → (byte-for-byte the same four) tools/.../server_agent/transport/models ·
      .../protocol/proto_model · gopsutil/v4/cpu · json:"bootTime"
```

**7 · Winnti/APT41 — Derusbi** — _HONEST NEGATIVE: different modules, so no overlap (the documented null)_
```bash
strings -n 6 $E/win.derusbi/* | grep -iE 'Query.asp|loginid|MSIE 6.0'   # Windows = HTTP backdoor
strings -n 6 $E/elf.derusbi/* | grep -iE 'insmod|profile_log|/proc/'    # Linux  = kernel rootkit
```
```text
WIN → GET /Query.asp?loginid=112037 HTTP/1.1   User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
LIN → /sbin/insmod   /dev/shm/.profile_log   /proc/self/exe
```

7 of 8 pairs return the same artifact on both OSes; Derusbi returns two different module types —
the documented null, shown so the positives aren't cherry-picked. (Add `| sort -u` to any line to
dedupe; if a Windows grep is empty, re-run it with `strings -el` for wide/UTF-16 strings.)

## Ethics & data handling
Only derived features and published indicators are included — no malware binaries (raw samples are
excluded), no credentials. Malpedia samples were analysed statically only and are not redistributed;
Malpedia is credited as the source.

**Note on intermediates:** `LayerA_code/intermediates/feat/*.json` contain full *strings* dumps
extracted from the Malpedia samples (derived features, not the executables — the binaries cannot be
reconstructed from them). They are included for reproducibility, but because they are Malpedia-derived
this submission folder must not be published or made public (e.g. pushed to a public repository) per
Malpedia's access terms. It is intended for internal course submission only.
