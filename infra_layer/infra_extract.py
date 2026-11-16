#!/usr/bin/env python3
"""
Open-corpus infrastructure extractor for the cross-platform APT attribution project.
Parses vendor IOC repositories (ESET malware-ioc MISP events + AsciiDoc READMEs) into a
normalized, platform-labelled network-infrastructure dataset per actor.

No API keys, no network at run time -- operates on already-cloned repos.
Reproducible: same inputs -> same output JSON.
"""
import json, re, os, sys, glob
from collections import defaultdict

# ---- actor -> ESET folder(s) mapping (our 6 actors) ----
ACTOR_FOLDERS = {
    "Turla":            ["turla"],
    "Sandworm":         ["telebots", "industroyer"],   # TeleBots/Exaramel + Industroyer
    "Lazarus":          ["nukesped_lazarus", "deceptivedevelopment"],
    "Winnti_APT41":     ["winnti_group", "fishmonger"],
    "APT28_Sednit":     ["sednit"],
    "APT29_Dukes":      ["dukes"],
}

WIN_RE   = re.compile(r'\b(Win32|Win64|MSIL|BAT|PowerShell|VBS|VBA|PE32)\b', re.I)
LIN_RE   = re.compile(r'\b(Linux|ELF|Perl|SH\b|Shell)\b', re.I)
MAC_RE   = re.compile(r'\b(OSX|OS X|macOS|Mach-O|MacOS)\b', re.I)
PY_RE    = re.compile(r'\b(Python|JS|Node)\b', re.I)

# network-indicator regexes for free-text/adoc
DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I)
IP_RE     = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
# things that look like domains but are noise
NOISE_DOMAINS = {"welivesecurity.com","github.com","eset.com","virustotal.com","twitter.com",
                 "microsoft.com","google.com","mitre.org","attack.mitre.org","abuse.ch"}
NOISE_TLD_WORDS = {"php","html","exe","dll","py","sh","js","json","md5","sha1","sha256","adoc","yar"}

def classify(text):
    if LIN_RE.search(text): return "linux"
    if MAC_RE.search(text): return "macos"
    if WIN_RE.search(text): return "windows"
    if PY_RE.search(text):  return "script"   # cross-platform script
    return None

def clean_domain(d):
    d = d.strip().strip('.').lower()
    if d in NOISE_DOMAINS: return None
    tld = d.rsplit('.',1)[-1]
    if tld in NOISE_TLD_WORDS: return None
    if len(d) < 4 or '.' not in d: return None
    return d

# ---------- MISP JSON parsing ----------
def walk_attrs(o):
    out=[]
    if isinstance(o,dict):
        if 'type' in o and 'value' in o:
            out.append(o)
        for v in o.values(): out+=walk_attrs(v)
    elif isinstance(o,list):
        for v in o: out+=walk_attrs(v)
    return out

def parse_misp(path, actor):
    rows=[]
    try: d=json.load(open(path))
    except Exception: return rows
    for a in walk_attrs(d):
        t=a.get('type',''); v=str(a.get('value','')).strip()
        if t in ('domain','hostname'):
            cd=clean_domain(v);  kind='domain'
            if cd: v=cd
            else: continue
        elif t in ('ip-dst','ip-src'):
            kind='ip'
        elif t=='url':
            kind='url'
        elif t=='domain|ip':
            kind='domain'; v=v.split('|')[0]
        else:
            continue
        ctx=' '.join(str(a.get(k,'')) for k in ('comment','category','Tag'))
        rows.append({'actor':actor,'ioc':v,'kind':kind,'platform':classify(ctx+' '+v),
                     'source':os.path.basename(path),'src_type':'misp'})
    return rows

# ---------- AsciiDoc README parsing (section-aware) ----------
def parse_adoc(path, actor):
    rows=[]
    try: lines=open(path,encoding='utf-8',errors='ignore').read().splitlines()
    except Exception: return rows
    cur_platform=None
    in_cc=False
    for ln in lines:
        s=ln.strip()
        # section header resets / platform detection
        if re.match(r'^=+\s', ln) or s.lower().startswith('==== '):
            # new (sub)section: decide if it's a C&C/network block
            in_cc = bool(re.search(r'(C&C|C2|command|network|domain|server|infrastructure)', s, re.I))
            p=classify(s)
            if p: cur_platform=p
            continue
        # detection-name lines carry platform
        p=classify(s)
        if p and ('/' in s):  # looks like a detection name line
            cur_platform=p
        # harvest indicators from list items / monospace blocks, prefer C&C sections
        candidate = s.lstrip('-* `').rstrip('`')
        # ip:port or ip
        for m in IP_RE.findall(candidate):
            rows.append({'actor':actor,'ioc':m,'kind':'ip','platform':cur_platform,
                         'source':os.path.basename(path),'src_type':'adoc','in_cc':in_cc})
        # domain-ish (only in network/C&C sections to limit noise)
        if in_cc:
            for m in DOMAIN_RE.findall(candidate):
                cd=clean_domain(m)
                if cd:
                    rows.append({'actor':actor,'ioc':cd,'kind':'domain','platform':cur_platform,
                                 'source':os.path.basename(path),'src_type':'adoc','in_cc':in_cc})
    return rows

def main(base):
    all_rows=[]
    for actor,folders in ACTOR_FOLDERS.items():
        for fo in folders:
            fp=os.path.join(base,fo)
            if not os.path.isdir(fp):
                print(f"  [missing] {fp}",file=sys.stderr); continue
            for j in glob.glob(os.path.join(fp,'*.json')):
                all_rows+=parse_misp(j,actor)
            for a in glob.glob(os.path.join(fp,'*.adoc')):
                all_rows+=parse_adoc(a,actor)
    # dedupe
    seen=set(); rows=[]
    for r in all_rows:
        k=(r['actor'],r['ioc'],r['kind'])
        if k in seen: continue
        seen.add(k); rows.append(r)
    return rows

if __name__=='__main__':
    base=sys.argv[1]
    rows=main(base)
    # ----- availability matrix -----
    print("="*78)
    print("OPEN-CORPUS INFRASTRUCTURE AVAILABILITY MATRIX  (ESET malware-ioc)")
    print("="*78)
    hdr=f"{'Actor':<16}{'total':>6}{'win':>6}{'linux':>7}{'macos':>7}{'script':>8}{'unattr':>8}"
    print(hdr); print("-"*len(hdr))
    summary={}
    for actor in ACTOR_FOLDERS:
        ar=[r for r in rows if r['actor']==actor]
        def c(p): return sum(1 for r in ar if r['platform']==p)
        tot=len(ar); win=c('windows'); lin=c('linux'); mac=c('macos'); scr=c('script')
        un=sum(1 for r in ar if r['platform'] is None)
        summary[actor]={'total':tot,'windows':win,'linux':lin,'macos':mac,'script':scr,'unattributed':un}
        print(f"{actor:<16}{tot:>6}{win:>6}{lin:>7}{mac:>7}{scr:>8}{un:>8}")
    print()
    # show the actual linux/macos/script IOCs (the cross-platform-relevant ones)
    print("NON-WINDOWS network IOCs (the cross-platform-relevant infra):")
    for actor in ACTOR_FOLDERS:
        nz=[r for r in rows if r['actor']==actor and r['platform'] in ('linux','macos','script')]
        if nz:
            print(f"\n  {actor}:")
            for r in nz[:40]:
                print(f"     [{r['platform']:<6}] {r['kind']:<6} {r['ioc']}  ({r['source']})")
    out='infra_open_corpus.json'
    json.dump({'rows':rows,'summary':summary},open(out,'w'),indent=1)
    print(f"\nWrote {len(rows)} deduped IOC rows -> {out}")
