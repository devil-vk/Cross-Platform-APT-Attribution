# Manual Reverse-Engineering — Per-Pair Cross-OS Findings

**Dataset:** 8 same-tool Windows↔Linux pairs (Malpedia). Static disassembly/string RE only;
no sample executed. Evidence dump: `per_pair_evidence.txt`. Malpedia credited as source.

**Method:** for each pair, read the actual protocol primitives out of BOTH binaries —
C2 URIs/handshake, command dispatch vocabulary, crypto, config schema, framing — and the
code-reuse markers (shared source paths, class/package names, library fingerprints), then
judge cross-OS reuse by hand (not just the automated screen).

## Verdict table
| Actor | Tool | Layer A (code) | Layer D (protocol) | Confidence |
|---|---|---|---|---|
| Sandworm | Exaramel | null (C++ vs Go) | ✅ **same protocol** | high |
| Lazarus | BADCALL | weak | ✅ **same FakeTLS handshake** | high |
| APT28 | X-Agent | ✅ **shared codebase** | ✅ same HTTP channel | high |
| APT27 | HyperSSL | weak (lib only) | ✅ **same crypto-transport** | high |
| Turla | Snake | libc only | ✅ same commands (modest) | medium |
| APT29 | WellMess | ✅ **identical codebase** | ✅ **identical C2 library** | decisive |
| Earth Lusca | KTLVdoor | ✅ **identical codebase** | ✅ **identical config/proto** | decisive |
| Winnti/APT41 | Derusbi | null (diff components) | null (diff components) | honest negative |

7 of 8 pairs confirm cross-OS reuse at the protocol and/or code level by hand. The one
negative (Derusbi) is because Malpedia's Windows and Linux Derusbi are different modules
(HTTP backdoor vs LKM rootkit), which is itself a correct, documented finding.

---

## Per pair

### Sandworm — Exaramel (win C/C++ ↔ elf Go)  →  PROTOCOL CONFIRMED
Same C2 command protocol expressed in two languages:
- **Windows (XML/XPath config):** `/settings/servers/server[@current='true']`, `/settings/proxy/@name`,
  `/settings/proxy/@password`, `/settings/check`, `/settings/interval`, `/commands/cmd`;
  service "Windows Check AV service"; UA `Mozilla/4.0 (compatible; MSIE 7.0...)`.
- **Linux (Go config + JSON):** keys `server/servers/proxy/check/report/timeout/session`;
  command JSON `guid, id, metod(sic), arguments, answer_async, answer_immediately, answer_wait,
  auth_result`; C2 `https://176.31.225.204/api/v1`.
- **Shared model:** the `servers / proxy / check / report` C2 config and the task/answer command
  loop are identical in design (ESET-documented). Code reuse: none (different languages) — this is
  the flagship case where **Layer A is null but Layer D confirms reuse**.

### Lazarus — BADCALL (win C/C++ ↔ elf C/C++)  →  PROTOCOL CONFIRMED
- **Shared FakeTLS handshake:** both OS embed the *same* decoy-SNI domain list used to
  disguise C2 as TLS — `www.apple.com, web.whatsapp.com, myservice.xbox.com, uk.yahoo.com,
  www.baidu.com, www.bing.com, www.bitcoin.org, www.facebook.com, www.github.com,
  www.dropbox.com, www.comodo.com, www.debian.org …`. This decoy list is BADCALL's signature
  custom protocol and it is byte-identical across OS. (Automated screen missed it — bucketed
  as host strings, not a protocol category.)

### APT28 — X-Agent / Chopstick (win C/C++ ↔ elf C/C++)  →  CODE + PROTOCOL CONFIRMED
- **Shared C++ codebase (architecture):** Linux exposes X-Agent's class/source names —
  `AgentKernel.cpp, ChannelController.cpp, HttpChannel.cpp, CryptoContainer.cpp, Cryptor.cpp,
  FSModule.cpp, LocalStorage.cpp`, methods `HttpChannel::addHttpHeader / createKeyToken /
  generateHttpMes / createEncodeData / createEncodeToken`. Same modular Kernel+Channels+Modules
  design as the Windows build.
- **Shared HTTP channel protocol:** both use Mozilla/Firefox UAs, `Accept`, `Content-Type:
  multipart/mixed`, `Content-Type: application/octet-stream`.
- Byte-level: **TLSH 0.53** cross-OS (highest of the non-Go pairs).

### APT27 — HyperSSL / HyperBro (win C/C++ ↔ elf C/C++)  →  PROTOCOL CONFIRMED
- **Shared crypto-transport:** both carry `CHACHA20` + `SHA256` and the full PEM set
  (`-----BEGIN CERTIFICATE / DH PARAMETERS / EC PRIVATE KEY / RSA PRIVATE KEY-----`).
- **Shared library fingerprint:** both built on **Boost.Asio** (`asio.misc`, `asio.system`,
  `asio.ssl`) — same C++ networking stack. Linux adds systemd persistence.

### Turla — Snake (win.uroburos C ↔ elf.penquin_turla C)  →  PROTOCOL (modest)
- **Shared:** `Content-Type: text/plain`; command tokens `readfile`, `SHELL`, `sleep`;
  config `beacon/sleep/timeout`; same lowercase base64 alphabet.
- Separately coded per OS (Penquin is a libc/cron-based Linux port; Uroburos is a Windows
  kernel/user toolkit) → code overlap is libc only. Protocol-level reuse is real but modest.

### APT29 — WellMess (win Go ↔ elf Go)  →  DECISIVE (code + protocol)
- **Identical custom C2 library across OS:** the entire `botlib` source tree is embedded in
  both — `/home/ubuntu/GoProject/src/bot/botlib/{rc6.go, symmcrypto.go, assymcrypto.go,
  transport.go, message.go, botchat.go, chat.go, chunks.go, choise.go, generatekey.go,
  normalbase64.go}` plus `*botlib.rc6cipher`, `*botlib.KeySizeError`.
- **Shared config:** `server/proxy/check/timeout/session/token/settings`. (The author build
  path `/home/ubuntu/GoProject` is in the Malpedia samples themselves — matches NCSC's WellMess
  report; not our environment.) Gold-standard positive.

### Earth Lusca — KTLVdoor (win Go ↔ elf Go)  →  DECISIVE (code + protocol)
- **Identical config/telemetry schema:** `json:"fd/ip/os/blocked/bootTime/caught/connect/
  cpu/data/device/disk_details"` identical across OS.
- **Identical custom codebase:** Go package tree `tools/modules/accelerator/server_agent/
  transport/{models,net/impl,net/register}`, protocol type `proto_model.MessPacket`, handlers
  `handler.handlePorts / handleInteractiveShell / handleFileDownload`, `startnode.AbstractDelivery`.
- **Shared obfuscated C2 URIs:** `/.7.?.G.O.W._.g.w.`, `/RVZL`, `/wxRB`; same `gopsutil` lib.

### Winnti/APT41 — Derusbi (win C/C++ ↔ elf C/C++)  →  HONEST NEGATIVE
- **Windows:** userland HTTP backdoor — `GET /Query.asp?loginid=112037 HTTP/1.1`,
  UA `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`, service-DLL persistence.
- **Linux:** a *different component* — a loadable kernel module rootkit (`/sbin/insmod`,
  `/dev/shm/.profile_log`, `/proc` hooking), not the HTTP backdoor.
- These are different Derusbi modules, so cross-OS reuse is genuinely absent for this pair.
  Reported as a null — the correct answer, not a failure.
