# Malpedia sample drop — folder manifest

Download each family from Malpedia (`/details/<id>`), then put the downloaded **zip(s)**
into the matching folder below. Zip password is `infected`. 2–3 samples per family each
side is plenty. I extract, verify, and pair `win.*` ↔ `elf.*` automatically.

| Actor | → put Windows zip in | → put Linux zip in |
|---|---|---|
| **Sandworm** | `win.exaramel/` | `elf.exaramel/` |
| **Lazarus** | `win.badcall/` | `elf.badcall/` |
| **APT28** | `win.xagent/` | `elf.xagent/` |
| **APT27** | `win.hyperssl/` | `elf.hyperssl/` |
| **Turla** | `win.uroburos/` | `elf.penquin_turla/` |
| **APT29** | `win.wellmess/` | `elf.wellmess/` |
| **Earth Lusca** | `win.ktlv_door/` | `elf.ktlv_door/` |
| **Winnti/APT41** | `win.derusbi/` | `elf.derusbi/` |

Note: Turla is the only pair with different names — Windows **Uroburos** ↔ Linux
**Penquin** (same Snake toolkit). Everything else is the same name on both sides.

Rules (unchanged): static analysis only, never executed, each folder is untrusted data,
samples never leave this git-ignored tree. Malpedia credited as source in the write-up.
