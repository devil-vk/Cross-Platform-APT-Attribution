#!/usr/bin/env python3
# Inventory + classify every extracted sample. Static only; never executes a sample.
import os, csv, subprocess, re

BASE = "/home/ubuntu/malpedia/layerAD_paired"
EXT  = os.path.join(BASE, "extracted")
OUT  = os.path.join(BASE, "feat", "inventory.csv")

# actor <-> family pairing
PAIRS = [
    ("Sandworm",     "win.exaramel",  "elf.exaramel"),
    ("Lazarus",      "win.badcall",   "elf.badcall"),
    ("APT28",        "win.xagent",    "elf.xagent"),
    ("APT27",        "win.hyperssl",  "elf.hyperssl"),
    ("Turla",        "win.uroburos",  "elf.penquin_turla"),
    ("APT29",        "win.wellmess",  "elf.wellmess"),
    ("EarthLusca",   "win.ktlv_door", "elf.ktlv_door"),
    ("WinntiAPT41",  "win.derusbi",   "elf.derusbi"),
]
fam2actor = {}
fam2os = {}
for a,w,l in PAIRS:
    fam2actor[w]=a; fam2actor[l]=a; fam2os[w]="win"; fam2os[l]="linux"

def filetype(p):
    try:
        return subprocess.run(["file","-b",p],capture_output=True,text=True,timeout=30).stdout.strip()
    except Exception as e:
        return f"ERR:{e}"

def variant(name):
    n=name.lower()
    if "unpacked" in n: return "unpacked"
    if "dump" in n:     return "dumped"
    return "raw"

def detect_lang(p, ft):
    """Go / .NET / Delphi / C-C++ via cheap static markers."""
    try:
        with open(p,"rb") as f: b=f.read()
    except Exception:
        return "?"
    low = b.lower()
    if b"Go build ID:" in b or b"\x00go1." in b or b"/usr/local/go/" in b or b"runtime.main" in b:
        return "Go"
    if b"v4.0.30319" in b or b"mscoree.dll" in b or b"#Strings\x00" in b or b"_CorExeMain" in b or b"#~\x00" in b:
        return ".NET"
    if b"Borland" in b or b"Delphi" in b or b"SOFTWARE\\Borland\\" in b or b"TMethodImplementationIntercept" in b:
        return "Delphi"
    if "ELF" in ft: return "C/C++ (ELF)"
    if "PE32" in ft or "MS Windows" in ft: return "C/C++ (PE)"
    return "other"

rows=[]
for fam in sorted(os.listdir(EXT)):
    fd=os.path.join(EXT,fam)
    if not os.path.isdir(fd): continue
    for name in sorted(os.listdir(fd)):
        p=os.path.join(fd,name)
        if not os.path.isfile(p): continue
        ft=filetype(p)
        sha_stem=re.split(r"[._]",name)[0]
        rows.append(dict(
            family=fam, actor=fam2actor.get(fam,"?"), os=fam2os.get(fam,"?"),
            variant=variant(name), size=os.path.getsize(p),
            lang=detect_lang(p,ft), filetype=ft[:60], path=p, name=name,
        ))

os.makedirs(os.path.dirname(OUT),exist_ok=True)
with open(OUT,"w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=["actor","os","family","variant","lang","size","filetype","name","path"])
    w.writeheader(); w.writerows(rows)

# summary to stdout
print(f"{'ACTOR':12} {'OS':6} {'FAMILY':17} {'variants (lang)'}")
print("-"*78)
from collections import defaultdict
agg=defaultdict(list)
for r in rows: agg[(r['actor'],r['os'],r['family'])].append(r)
for a,w,l in PAIRS:
    for fam,osn in ((w,'win'),(l,'linux')):
        rs=agg.get((a,osn,fam),[])
        langs=sorted(set(r['lang'] for r in rs))
        vs=defaultdict(int)
        for r in rs: vs[r['variant']]+=1
        vtxt=", ".join(f"{k}:{v}" for k,v in sorted(vs.items()))
        print(f"{a:12} {osn:6} {fam:17} {len(rs):2d} files [{vtxt}]  lang={'/'.join(langs)}")
print(f"\nwrote {OUT}  ({len(rows)} files)")
