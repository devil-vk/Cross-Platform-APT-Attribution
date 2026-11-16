#!/usr/bin/env python3
# Manual-RE evidence extractor: per pair, surface the real protocol/code primitives
# from BOTH OS binaries side by side. Static only. Output feeds hand interpretation.
import os, re, json, subprocess
from collections import defaultdict

BASE="/home/ubuntu/malpedia/layerAD_paired"; EXT=os.path.join(BASE,"extracted"); FEAT=os.path.join(BASE,"feat")
OUT=os.path.join(BASE,"re_notes"); os.makedirs(OUT,exist_ok=True)
PAIRS=[("Sandworm","win.exaramel","elf.exaramel"),("Lazarus","win.badcall","elf.badcall"),
("APT28","win.xagent","elf.xagent"),("APT27","win.hyperssl","elf.hyperssl"),
("Turla","win.uroburos","elf.penquin_turla"),("APT29","win.wellmess","elf.wellmess"),
("EarthLusca","win.ktlv_door","elf.ktlv_door"),("WinntiAPT41","win.derusbi","elf.derusbi")]

def strings_of(fam):
    return set(json.load(open(os.path.join(FEAT,fam+".json")))["strings"])

# evidence extractors over a string set
RX = {
 "url":        re.compile(r'(?i)\bhttps?://[^\s"\'<>]{4,80}'),
 "uri_path":   re.compile(r'^/[A-Za-z0-9_./?=&%+-]{2,60}$'),
 "host_dom":   re.compile(r'(?i)\b([a-z0-9-]{2,}\.)+[a-z]{2,6}\b'),
 "ipv4":       re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
 "user_agent": re.compile(r'(?i)(mozilla/|curl/|wget/|python-requests|go-http-client)'),
 "http_hdr":   re.compile(r'(?i)^(user-agent|content-type|content-length|cookie|host|accept|authorization|x-[a-z-]+):'),
 "cmd_method": re.compile(r'^[A-Za-z][A-Za-z0-9]{1,20}\.[A-Za-z][A-Za-z0-9]{1,20}$'),
 "cmd_word":   re.compile(r'(?i)^(upload|download|screenshot|keylog(ger)?|shell|exec(ute)?|cmd|'
                          r'getfile|putfile|readfile|writefile|listdir|getdir|sleep|persist|'
                          r'uninstall|selfdelete|setproxy|setserver|settimeout|heartbeat|checkin)$'),
 "crypto":     re.compile(r'(?i)^(rc4|rc6|aes|des|3des|rsa|xor|blowfish|salsa20|chacha20|camellia|md5|sha1|sha256|hmac)$'),
 "pem":        re.compile(r'(?i)-----(begin|end) '),
 "b64alpha":   re.compile(r'[A-Za-z0-9+/]{32,}={0,2}$'),
 "config_key": re.compile(r'(?i)^(server|servers|proxy|check|report|interval|timeout|sleep|'
                          r'jitter|beacon|config|settings|port|host|url|c2|gate|session|token|'
                          r'client_id|bot_id|campaign|guid)$'),
 "config_json":re.compile(r'(?i)json:"[a-z_]+"'),
 "xpath_cfg":  re.compile(r'(?i)^/(settings|config)/'),
 "magic_hex":  re.compile(r'^0x[0-9a-fA-F]{6,}$'),
 "go_botlib":  re.compile(r'(?i)(botlib|rc6cipher|symmcrypto|assymcrypto|\btransport\b|messpacket)'),
}
def extract(S):
    ev=defaultdict(set)
    for s in S:
        for k,r in RX.items():
            if r.search(s): ev[k].add(s if len(s)<=80 else s[:80])
    return ev

def symbols_overlap(famw, faml):
    sw=set(json.load(open(os.path.join(FEAT,famw+".json")))["symbols"])
    sl=set(json.load(open(os.path.join(FEAT,faml+".json")))["symbols"])
    # strip library prefixes for comparison of meaningful names
    def core(s): return s.split("!")[-1]
    cw={core(x) for x in sw}; cl={core(x) for x in sl}
    return cw&cl

def show(title, items, cap=20):
    items=sorted(items)[:cap]
    return title+": "+(", ".join(items) if items else "(none)")

lines=[]
for actor,fw,fl in PAIRS:
    Sw=strings_of(fw); Sl=strings_of(fl)
    Ew=extract(Sw); El=extract(Sl)
    lines.append(f"\n{'='*78}\n## {actor}:  {fw}  (Windows)  ↔  {fl}  (Linux)\n{'='*78}")
    for cat in RX:
        w=Ew.get(cat,set()); l=El.get(cat,set())
        shared=w&l
        if not (w or l): continue
        lines.append(f"\n[{cat}]")
        lines.append("  WIN  "+show("", w, 12))
        lines.append("  LIN  "+show("", l, 12))
        if shared:
            lines.append("  ** SHARED ** "+", ".join(sorted(shared)[:12]))
    ov=symbols_overlap(fw,fl)
    ov=[x for x in ov if len(x)>4 and not x.startswith("_")][:30]
    lines.append("\n[symbol/function overlap (code reuse)]  "+(", ".join(sorted(ov)[:25]) if ov else "(none meaningful)"))

report="\n".join(lines)
open(os.path.join(OUT,"per_pair_evidence.txt"),"w").write(report)
print(report)
print(f"\n\nsaved {OUT}/per_pair_evidence.txt")
