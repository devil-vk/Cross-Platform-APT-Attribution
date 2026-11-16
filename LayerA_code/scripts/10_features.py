#!/usr/bin/env python3
# Extract Layer-A/D features per family. STATIC ONLY — never executes a sample.
# Per sample we use the best variant (unpacked > dumped > raw); features are unioned per family.
import os, re, json, subprocess, csv
from collections import Counter, defaultdict

BASE = "/home/ubuntu/malpedia/layerAD_paired"
EXT  = os.path.join(BASE, "extracted")
FEAT = os.path.join(BASE, "feat")
INV  = os.path.join(FEAT, "inventory.csv")

try:
    import tlsh
except Exception:
    tlsh=None
try:
    import pefile
except Exception:
    pefile=None

RANK={"unpacked":3,"dumped":2,"raw":1}

def run(cmd, timeout=120):
    try:
        return subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,errors="replace").stdout
    except Exception:
        return ""

def get_strings(path):
    s=set()
    for args in (["strings","-n","5",path], ["strings","-e","l","-n","5",path]):
        out=run(args, timeout=90)
        for line in out.splitlines():
            t=line.strip()
            if 5<=len(t)<=200:
                s.add(t)
    return s

def get_symbols(path, is_pe):
    syms=set()
    if is_pe and pefile:
        try:
            pe=pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
            for entry in getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]):
                dll=(entry.dll or b"").decode("latin1").lower()
                for imp in entry.imports:
                    if imp.name:
                        syms.add(dll+"!"+imp.name.decode("latin1").lower())
            exp=getattr(pe,"DIRECTORY_ENTRY_EXPORT",None)
            if exp:
                for e in exp.symbols:
                    if e.name: syms.add("export!"+e.name.decode("latin1").lower())
            pe.close()
        except Exception:
            pass
    else:
        # ELF: dynamic + defined symbols
        for args in (["nm","-D","--no-sort",path],["nm","--defined-only","--no-sort",path],
                     ["readelf","-sW",path]):
            out=run(args, timeout=60)
            for line in out.splitlines():
                parts=line.split()
                if not parts: continue
                name=parts[-1]
                if re.match(r"^[A-Za-z_][\w@.]{2,}$",name):
                    syms.add(name.lower())
    return syms

def get_tlsh(path):
    if not tlsh: return None
    try:
        with open(path,"rb") as f: data=f.read()
        if len(data)<256: return None
        h=tlsh.hash(data)
        return h if h and h!="TNULL" else None
    except Exception:
        return None

OPRE=re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t([a-z][a-z0-9.]+)")
def get_opcodes(path):
    out=run(["objdump","-d","--no-show-raw-insn","-M","intel",path], timeout=120)
    # fallback with raw insn (format varies)
    if "\tpush" not in out and "\tmov" not in out:
        out=run(["objdump","-d",path], timeout=120)
    ops=[]
    for line in out.splitlines():
        # line like "  401000:\t55\tpush   ebp"  OR  "  401000:\tpush ebp"
        if ":\t" not in line: continue
        after=line.split(":\t",1)[1]
        # strip hex byte column if present
        fields=after.split("\t")
        mnem_field=fields[-1].strip()
        m=re.match(r"([a-z][a-z0-9.]+)",mnem_field)
        if m: ops.append(m.group(1))
    return ops

def pick_best(files):
    """group by sha stem, keep best variant per sample"""
    by=defaultdict(list)
    for r in files:
        stem=re.split(r"[._]",r["name"])[0]
        by[stem].append(r)
    best=[]
    for stem,rs in by.items():
        rs.sort(key=lambda r:RANK.get(r["variant"],0),reverse=True)
        best.append(rs[0])
    return best

def main():
    rows=list(csv.DictReader(open(INV)))
    byfam=defaultdict(list)
    for r in rows: byfam[r["family"]].append(r)

    for fam in sorted(byfam):
        files=pick_best(byfam[fam])
        is_pe = fam.startswith("win.")
        S=set(); SYM=set(); TL=[]; OP=Counter(); OP3=Counter(); used=[]
        for r in files:
            p=r["path"]
            S|=get_strings(p)
            SYM|=get_symbols(p,is_pe)
            h=get_tlsh(p)
            if h: TL.append(h)
            ops=get_opcodes(p)
            if ops:
                OP.update(ops)
                OP3.update(tuple(ops[i:i+3]) for i in range(len(ops)-2))
            used.append(r["name"])
        out=dict(
            family=fam, os=("win" if is_pe else "linux"),
            n_samples=len(files), used_files=used,
            strings=sorted(S), symbols=sorted(SYM), tlsh=TL,
            op1={k:v for k,v in OP.most_common(300)},
            op3={ " ".join(k):v for k,v in OP3.most_common(400)},
        )
        with open(os.path.join(FEAT,fam+".json"),"w") as f:
            json.dump(out,f)
        print(f"{fam:18} samples={len(files):2d} strings={len(S):6d} syms={len(SYM):5d} "
              f"tlsh={len(TL):2d} op1={len(OP):4d} op3={len(OP3):6d}")

if __name__=="__main__":
    main()
