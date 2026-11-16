#!/usr/bin/env python3
# LAYER D (paired same-tool) — custom C2 protocol / config reuse across OS.
# Uses the strings already extracted per family (ascii+utf16). Static only.
import os, json, re, math, itertools
from collections import Counter, defaultdict

BASE="/home/ubuntu/malpedia/layerAD_paired"; FEAT=os.path.join(BASE,"feat"); RES=os.path.join(BASE,"results")
PAIRS=[("Sandworm","win.exaramel","elf.exaramel"),("Lazarus","win.badcall","elf.badcall"),
("APT28","win.xagent","elf.xagent"),("APT27","win.hyperssl","elf.hyperssl"),
("Turla","win.uroburos","elf.penquin_turla"),("APT29","win.wellmess","elf.wellmess"),
("EarthLusca","win.ktlv_door","elf.ktlv_door"),("WinntiAPT41","win.derusbi","elf.derusbi")]
ACTORS=[a for a,_,_ in PAIRS]; N=len(ACTORS)
def load(fam): return json.load(open(os.path.join(FEAT,fam+".json")))
STR={a:(set(load(w)["strings"]),set(load(l)["strings"])) for a,w,l in PAIRS}

# ---------- protocol feature categories (custom-protocol oriented) ----------
CAT_PATTERNS = {
 "c2_uri":   [r'^/[\w./?=&%+-]{2,}$', r'\.php($|\?)', r'/api/', r'/gate', r'/upload', r'/panel',
              r'/get\b', r'/post\b', r'/cmd', r'/task', r'index\.(php|asp|jsp)'],
 "http":     [r'(?i)user-agent', r'(?i)content-type', r'(?i)content-length', r'(?i)^accept',
              r'(?i)x-[a-z-]+:', r'(?i)^cookie', r'(?i)^host:', r'(?i)mozilla/', r'(?i)keep-alive',
              r'(?i)multipart/form', r'(?i)application/x-www', r'(?i)gzip', r'(?i)^authorization'],
 "session":  [r'(?i)session', r'(?i)token', r'(?i)\bbot[_-]?id', r'(?i)client[_-]?id',
              r'(?i)\bguid\b', r'(?i)campaign', r'(?i)victim', r'(?i)\bagent[_-]?id', r'(?i)cookie'],
 "cmd_vocab":[r'^[A-Z][a-zA-Z]+\.[A-Z][a-zA-Z]+$', r'(?i)shellexecute', r'(?i)^(upload|download)$',
              r'(?i)^(screenshot|keylog|keylogger)$', r'(?i)^(getfile|putfile|readfile|writefile)$',
              r'(?i)^(cmd|shell|exec|execute)$', r'(?i)^(sleep|persist|uninstall|selfdelete)$',
              r'(?i)^(listdir|getdir|setproxy|setserver|settimeout)$'],
 "framing":  [r'^0x[0-9a-fA-F]{6,}$', r'(?i)magic', r'(?i)delimiter', r'(?i)boundary',
              r'^-{3,}', r'(?i)packet', r'(?i)header', r'(?i)checksum'],
 "crypto":   [r'(?i)^(rc4|rc6|aes|des|3des|rsa|xor|blowfish|salsa20|chacha20|camellia)$',
              r'(?i)base64', r'(?i)-----begin', r'(?i)\b(encrypt|decrypt)\b', r'(?i)\bcipher\b',
              r'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', r'(?i)\bhmac\b', r'(?i)\bmd5\b'],
 "config":   [r'(?i)^(server|servers)$', r'(?i)^proxy$', r'(?i)^check$', r'(?i)^report',
              r'(?i)interval', r'(?i)timeout', r'(?i)^sleep$', r'(?i)jitter', r'(?i)beacon',
              r'(?i)^config', r'(?i)settings', r'(?i)^port$', r'(?i)^host$', r'(?i)heartbeat'],
}
COMP={c:[re.compile(p) for p in pats] for c,pats in CAT_PATTERNS.items()}

# toolchain / runtime stoplist — drop Go-source paths, runtime internals, compiler junk
# (keeps genuine protocol tokens like botlib.*, json:"token", /gate.php, rc6, etc.)
_STOP=re.compile(r"(?i)(/usr/local/go/|/go/src/|goproject|golang|runtime\.|reflectlite|"
 r"unsafeheader|cookiejar|internal/|vendor/|\.go$|\.s$|type\.\.|struct \{|uintptr|"
 r"reflect\.|sync\.|syscall\.|compress/|encoding/|mscoree|kernel32|advapi32|\bntdll)")
def is_stop(s):
    return bool(_STOP.search(s))

def classify(s):
    if is_stop(s): return set()
    out=set()
    for c,regs in COMP.items():
        for r in regs:
            if r.search(s):
                out.add((c, s.lower())); break
    return out

def proto_sets(strset):
    cats=defaultdict(set); allp=set()
    for s in strset:
        for (c,tok) in classify(s):
            cats[c].add(tok); allp.add(tok)
    return cats, allp

PROTO={}   # actor -> (win_cats, win_all, lin_cats, lin_all)
for a,_,_ in PAIRS:
    wc,wa=proto_sets(STR[a][0]); lc,la=proto_sets(STR[a][1])
    PROTO[a]=(wc,wa,lc,la)

# IDF over proto_all across 16 docs
df=Counter();
for a,_,_ in PAIRS:
    for allp in (PROTO[a][1],PROTO[a][3]):
        for t in allp: df[t]+=1
IDF={t:math.log(16/df[t]) for t in df}

def jac(A,B):
    A,B=set(A),set(B); u=len(A|B); return len(A&B)/u if u else 0.0
def wjac(A,B):
    A,B=set(A),set(B)
    if not A or not B: return 0.0
    num=sum(IDF.get(t,0) for t in A&B); den=sum(IDF.get(t,0) for t in A|B)
    return num/den if den else 0.0

def mat(fn):
    M=[[0.0]*N for _ in range(N)]
    for i,ai in enumerate(ACTORS):
        for j,aj in enumerate(ACTORS):
            M[i][j]=fn(ai,aj)
    return M

def fn_all(ai,aj):  return jac(PROTO[ai][1],PROTO[aj][3])
def fn_allidf(ai,aj): return wjac(PROTO[ai][1],PROTO[aj][3])
def fn_cat(cat):
    def f(ai,aj): return jac(PROTO[ai][0].get(cat,set()),PROTO[aj][2].get(cat,set()))
    return f

def perm_test(M, idx=None):
    idx=idx if idx is not None else list(range(len(M)))
    n=len(idx); obs=sum(M[idx[k]][idx[k]] for k in range(n))/n
    cnt=tot=0
    for perm in itertools.permutations(range(n)):
        s=sum(M[idx[k]][idx[perm[k]]] for k in range(n))/n; tot+=1
        if s>=obs-1e-12: cnt+=1
    return obs,cnt/tot
def offd(M):
    n=len(M); v=[M[i][j] for i in range(n) for j in range(n) if i!=j]; return sum(v)/len(v)
def dom(M):
    n=len(M); r=sum(1 for i in range(n) if M[i][i]>=max(M[i]))
    c=sum(1 for i in range(n) if M[i][i]>=max(M[k][i] for k in range(n))); return r,c

METRICS={"proto_all":fn_all,"proto_all_idf":fn_allidf}
for cat in CAT_PATTERNS: METRICS["cat_"+cat]=fn_cat(cat)

rep={}
print(f"{'METRIC':18} {'diag':>7} {'offdiag':>8} {'p_exact':>9} {'LOO_wp':>8} {'rowdom':>7} {'coldom':>7}")
print("-"*72)
for name,fn in METRICS.items():
    M=mat(fn); obs,p=perm_test(M); off=offd(M)
    loo=[perm_test(M,[x for x in range(N) if x!=k])[1] for k in range(N)]
    r,c=dom(M); rep[name]=dict(M=M,diag=obs,off=off,p=p,loo=loo,loo_worst=max(loo),rowdom=r,coldom=c)
    print(f"{name:18} {obs:7.3f} {off:8.3f} {p:9.4f} {max(loo):8.4f} {r:4d}/{N} {c:4d}/{N}")

# Go-confound guard: drop the Go actors (Sandworm-linux is Go, APT29 Go, EarthLusca Go)
GO_ACTORS={"APT29","EarthLusca"}  # pairs that are Go on both sides
idx=[i for i,a in enumerate(ACTORS) if a not in GO_ACTORS]
for name in ("proto_all","proto_all_idf"):
    M=rep[name]["M"]; obs,p=perm_test(M,idx)
    print(f"  [drop-Go guard] {name}: diag={obs:.3f} p={p:.4f} (n={len(idx)})")

print("\nPer-actor protocol similarity (diagonal = same tool), proto_all_idf:")
M=rep["proto_all_idf"]["M"]
for i,a in enumerate(ACTORS):
    print(f"  {a:12} diag={M[i][i]:.3f}  rowmax_other={max(M[i][j] for j in range(N) if j!=i):.3f}")

# per-pair shared protocol tokens (the evidence)
print("\nShared cross-OS protocol tokens per pair (top, IDF-ranked):")
for a,_,_ in PAIRS:
    shared=PROTO[a][1]&PROTO[a][3]
    shared=sorted(shared,key=lambda t:-IDF.get(t,0))
    print(f"  {a:12} ({len(shared)} shared): "+", ".join(shared[:12]))

json.dump({k:{kk:vv for kk,vv in v.items()} for k,v in rep.items()},
          open(os.path.join(RES,"layerD_results.json"),"w"),indent=1)

try:
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    for name in ("proto_all","proto_all_idf"):
        M=rep[name]["M"]; fig,ax=plt.subplots(figsize=(6,5)); im=ax.imshow(M,cmap="magma")
        ax.set_xticks(range(N));ax.set_xticklabels(ACTORS,rotation=45,ha="right",fontsize=7)
        ax.set_yticks(range(N));ax.set_yticklabels(ACTORS,fontsize=7)
        ax.set_xlabel("Linux");ax.set_ylabel("Windows");ax.set_title(f"Layer D — {name}")
        for i in range(N):
            for j in range(N):
                ax.text(j,i,f"{M[i][j]:.2f}",ha="center",va="center",
                        color="white" if M[i][j]<0.5 else "black",fontsize=6)
        fig.colorbar(im);fig.tight_layout();fig.savefig(os.path.join(RES,f"heatmap_D_{name}.png"),dpi=120);plt.close(fig)
    print(f"\nheatmaps saved {RES}/heatmap_D_*.png")
except Exception as e:
    print("heatmap skipped:",e)
print(f"saved {RES}/layerD_results.json")
