#!/usr/bin/env python3
# LAYER A (paired same-tool) — cross-OS code/binary similarity + exact permutation test.
import os, json, math, itertools
from collections import Counter, defaultdict

BASE="/home/ubuntu/malpedia/layerAD_paired"; FEAT=os.path.join(BASE,"feat"); RES=os.path.join(BASE,"results")
os.makedirs(RES,exist_ok=True)

PAIRS=[("Sandworm","win.exaramel","elf.exaramel"),("Lazarus","win.badcall","elf.badcall"),
("APT28","win.xagent","elf.xagent"),("APT27","win.hyperssl","elf.hyperssl"),
("Turla","win.uroburos","elf.penquin_turla"),("APT29","win.wellmess","elf.wellmess"),
("EarthLusca","win.ktlv_door","elf.ktlv_door"),("WinntiAPT41","win.derusbi","elf.derusbi")]
ACTORS=[a for a,_,_ in PAIRS]; N=len(ACTORS)

def load(fam): return json.load(open(os.path.join(FEAT,fam+".json")))
F={a:(load(w),load(l)) for a,w,l in PAIRS}   # actor -> (win_feat, lin_feat)

try:
    import tlsh
except Exception:
    tlsh=None

# ---------- IDF over all 16 families ----------
def build_idf(key):
    df=Counter(); docs=[]
    for a,w,l in PAIRS:
        for feat in (F[a][0],F[a][1]):
            s=set(feat.get(key,[])); docs.append(s)
            for t in s: df[t]+=1
    Ndoc=len(docs)
    return {t: math.log(Ndoc/df[t]) for t in df}, df
IDF_STR,DF_STR=build_idf("strings")
IDF_SYM,_=build_idf("symbols")

# ---- Go-runtime / library stoplist guard (prove strings signal isn't a toolchain confound) ----
import re as _re
STOP_SUB=("/go/src/","/usr/local/go/","runtime.","sync.","reflect.","syscall.","internal/",
 "go1.","golang","/root/go","type..","*type","go.buildid","bytes.","strconv.","fmt.",
 "net/http","crypto/","encoding/","gopkg.in","github.com/","vendor/","mscoree","kernel32",
 "ntdll","advapi32","msvcrt","oleaut32","user32","gcc","glibc","__libc","_cgo","libstdc++",
 "/lib/x86_64","ld-linux","glibc","0123456789abcdef","abcdefghijklmnop")
def destop(S):
    out=set()
    for t in S:
        tl=t.lower()
        if any(s in tl for s in STOP_SUB): continue
        if _re.fullmatch(r"[0-9a-f]{6,}",tl): continue
        if len(set(tl))<=2: continue
        out.add(t)
    return out
# rebuild IDF on stoplisted strings
def build_idf_stop():
    df=Counter(); docs=[]
    for a,w,l in PAIRS:
        for feat in (F[a][0],F[a][1]):
            s=destop(set(feat.get("strings",[]))); docs.append(s)
            for t in s: df[t]+=1
    Nd=len(docs); return {t:math.log(Nd/df[t]) for t in df}
IDF_STR_STOP=build_idf_stop()

def jaccard(A,B):
    A,B=set(A),set(B)
    if not A or not B: return 0.0
    u=len(A|B); return len(A&B)/u if u else 0.0

def wjaccard(A,B,W):
    A,B=set(A),set(B)
    if not A or not B: return 0.0
    inter=A&B; uni=A|B
    num=sum(W.get(t,0) for t in inter); den=sum(W.get(t,0) for t in uni)
    return num/den if den else 0.0

def tlsh_sim(La,Lb):
    if not tlsh or not La or not Lb: return 0.0
    best=0.0
    for a in La:
        for b in Lb:
            try: d=tlsh.diff(a,b)
            except Exception: continue
            best=max(best, max(0.0,1-d/300.0))
    return best

def cos_idf(d1,d2):
    # tf-idf cosine over opcode n-grams; idf from the 16 docs built lazily
    keys=set(d1)|set(d2)
    if not keys: return 0.0
    num=sum(d1.get(k,0)*d2.get(k,0)*OPIDF.get(k,1.0)**2 for k in keys)
    n1=math.sqrt(sum((d1.get(k,0)*OPIDF.get(k,1.0))**2 for k in keys))
    n2=math.sqrt(sum((d2.get(k,0)*OPIDF.get(k,1.0))**2 for k in keys))
    return num/(n1*n2) if n1 and n2 else 0.0

# opcode idf (op3)
opdf=Counter()
for a,w,l in PAIRS:
    for feat in (F[a][0],F[a][1]):
        for k in feat.get("op3",{}): opdf[k]+=1
OPIDF={k:math.log(16/v) for k,v in opdf.items()}

# ---------- build matrices: M[i][j] = sim(win_i, lin_j) ----------
def matrix(simfn):
    M=[[0.0]*N for _ in range(N)]
    for i,ai in enumerate(ACTORS):
        for j,aj in enumerate(ACTORS):
            M[i][j]=simfn(F[ai][0], F[aj][1])
    return M

METRICS={
 "strings_jaccard":   lambda w,l: jaccard(w["strings"],l["strings"]),
 "strings_idf":       lambda w,l: wjaccard(w["strings"],l["strings"],IDF_STR),
 "strings_idf_destop":lambda w,l: wjaccard(destop(w["strings"]),destop(l["strings"]),IDF_STR_STOP),
 "symbols_jaccard":   lambda w,l: jaccard(w["symbols"],l["symbols"]),
 "tlsh_bestmatch":    lambda w,l: tlsh_sim(w["tlsh"],l["tlsh"]),
 "opcode3_tfidf":     lambda w,l: cos_idf(w["op3"],l["op3"]),
}

def perm_test(M, idx=None):
    idx=idx if idx is not None else list(range(len(M)))
    n=len(idx)
    obs=sum(M[idx[k]][idx[k]] for k in range(n))/n
    cnt=0; tot=0
    for perm in itertools.permutations(range(n)):
        s=sum(M[idx[k]][idx[perm[k]]] for k in range(n))/n
        tot+=1
        if s>=obs-1e-12: cnt+=1
    return obs, cnt/tot, tot

def offdiag_mean(M):
    n=len(M); vals=[M[i][j] for i in range(n) for j in range(n) if i!=j]
    return sum(vals)/len(vals) if vals else 0.0

def diag_dominance(M):
    n=len(M); row=0; col=0
    for i in range(n):
        if M[i][i]>=max(M[i]): row+=1
        if M[i][i]>=max(M[k][i] for k in range(n)): col+=1
    return row,col

report={}
print(f"{'METRIC':18} {'diag':>7} {'offdiag':>8} {'p_exact':>9} {'LOO_wp':>8} {'rowdom':>7} {'coldom':>7}")
print("-"*72)
for name,fn in METRICS.items():
    M=matrix(fn)
    obs,p,tot=perm_test(M)
    off=offdiag_mean(M)
    # leave-one-out: worst p over dropping each actor
    loo=[]
    for k in range(N):
        idx=[x for x in range(N) if x!=k]
        _,pk,_=perm_test(M, idx)
        loo.append(pk)
    worst=max(loo)
    rdom,cdom=diag_dominance(M)
    report[name]=dict(M=M,diag=obs,off=off,p=p,loo=loo,loo_worst=worst,rowdom=rdom,coldom=cdom)
    print(f"{name:18} {obs:7.3f} {off:8.3f} {p:9.4f} {worst:8.4f} {rdom:4d}/{N} {cdom:4d}/{N}")

# per-actor diagonal values for the strongest metrics
print("\nPer-actor cross-OS similarity (diagonal = same tool):")
hdr=f"{'actor':12}"+"".join(f"{m.split('_')[0][:7]:>9}" for m in METRICS)
print(hdr); print("-"*len(hdr))
for i,a in enumerate(ACTORS):
    line=f"{a:12}"+"".join(f"{report[m]['M'][i][i]:9.3f}" for m in METRICS)
    print(line)

# drop-Go guard (match Layer D): remove the Go-on-both-sides pairs
GO={"APT29","EarthLusca","Sandworm"}  # Sandworm linux is Go too
idx=[i for i,a in enumerate(ACTORS) if a not in GO]
print("\n[drop-Go guard] remove APT29, EarthLusca, Sandworm (Go-involved pairs):")
for name in ("strings_jaccard","strings_idf_destop","tlsh_bestmatch","opcode3_tfidf"):
    M=report[name]["M"]; obs,p,_=perm_test(M, idx)
    print(f"   {name:20} diag={obs:.3f} p={p:.4f} (n={len(idx)} non-Go actors)")

# per-actor LOO detail for the two headline metrics
for name in ("strings_jaccard","tlsh_bestmatch","strings_idf_destop"):
    loo=report[name]["loo"]
    print(f"\nLOO detail — {name} (p when each actor is dropped):")
    print("  "+"  ".join(f"{ACTORS[k][:6]}:{loo[k]:.3f}" for k in range(N)))

# full matrices for the headline metrics
def show_matrix(name):
    M=report[name]["M"]
    print(f"\nMatrix {name}  (rows=Windows actor, cols=Linux actor; diagonal=same tool)")
    print("           "+"".join(f"{a[:6]:>8}" for a in ACTORS))
    for i,a in enumerate(ACTORS):
        cells="".join((f"[{M[i][j]:6.3f}]" if i==j else f"{M[i][j]:7.3f} ") for j in range(N))
        print(f"{a:10} {cells}")
for name in ("strings_idf_destop","tlsh_bestmatch"):
    show_matrix(name)

# heatmaps
try:
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    for name in METRICS:
        M=report[name]["M"]
        fig,ax=plt.subplots(figsize=(6,5))
        im=ax.imshow(M,cmap="viridis")
        ax.set_xticks(range(N)); ax.set_xticklabels(ACTORS,rotation=45,ha="right",fontsize=7)
        ax.set_yticks(range(N)); ax.set_yticklabels(ACTORS,fontsize=7)
        ax.set_xlabel("Linux"); ax.set_ylabel("Windows"); ax.set_title(f"Layer A — {name}")
        for i in range(N):
            for j in range(N):
                ax.text(j,i,f"{M[i][j]:.2f}",ha="center",va="center",
                        color="white" if M[i][j]<0.5 else "black",fontsize=6)
        fig.colorbar(im); fig.tight_layout()
        fig.savefig(os.path.join(RES,f"heatmap_A_{name}.png"),dpi=120); plt.close(fig)
    print(f"\nheatmaps saved to {RES}/heatmap_A_*.png")
except Exception as e:
    print("heatmap skipped:",e)

json.dump({k:{kk:vv for kk,vv in v.items()} for k,v in report.items()},
          open(os.path.join(RES,"layerA_results.json"),"w"), indent=1)
print(f"\nsaved {RES}/layerA_results.json")
