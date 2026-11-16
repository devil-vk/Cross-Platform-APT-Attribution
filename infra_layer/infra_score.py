#!/usr/bin/env python3
"""
Infrastructure layer (Layer C) scorer — cross-platform APT attribution.
Builds the normalized Win+Linux infra dataset and scores same-actor Windows-vs-Linux
infra similarity against a mismatched-pair control, with a permutation test.

Scores only the levels computable WITHOUT API keys:
  L0  literal indicator overlap (exact domain/IP)
  L1p IP /16 "hosting-neighbourhood" prefix overlap (keyless proxy for shared ASN/subnet)
  L3  domain naming/lexical similarity (char-3gram cosine)
PENDING (need enrichment run on the user's machine): L1 true-ASN, L2 registrar/NS, L4 cert, L5 temporal.
"""
import json, csv, re, random, math
from collections import defaultdict, Counter
random.seed(1337)

LINUX = {
 "Turla":        {"family":"Penquin","ip":["85.25.95.16","162.223.94.14"],"domain":[],
                  "source":"lab52 'Looking for Penquins in the Wild'"},
 "Sandworm":     {"family":"Exaramel-Linux","ip":["176.31.225.204"],"domain":[],
                  "source":"CERT-FR CERTFR-2021-CTI-005 (Sandworm/Centreon)"},
 "Lazarus":      {"family":"BeaverTail/InvisibleFerret",
                  "ip":["136.0.9.8","142.11.206.73"],
                  "domain":["ip-address-check-mo.vercel.app","precommit.vercel.app",
                            "vscode-ip-address-checking.vercel.app","vscode-ipchecking.vercel.app",
                            "vscode-settings-tasks-json.vercel.app","y-hazel-ten.vercel.app"],
                  "source":"ThreatFox/URLhaus (prior session) + ESET deceptivedevelopment"},
 "Winnti_APT41": {"family":"Melofee",
                  "ip":["156.67.208.192","5.61.57.80","173.209.62.188","173.209.62.190"],
                  "domain":["update.ankining.com","www.data-yuzefuji.com","ssm.awszonwork.com"],
                  "source":"ExaTrack Melofee report"},
 "APT28_Sednit": {"family":"Drovorub","ip":["185.86.149.125","82.118.242.171"],"domain":[],
                  "source":"NSA/FBI Drovorub advisory (via Red Sky Alliance)"},
 "APT29_Dukes":  {"family":"WellMess/WellMail",
                  "ip":["103.103.128.221","103.13.240.46","103.205.8.72","103.216.221.19","103.253.41.102",
                        "103.253.41.68","103.253.41.82","103.253.41.90","103.73.188.101","111.90.146.143",
                        "111.90.150.176","119.160.234.163","119.160.234.194","119.81.173.130","119.81.178.105",
                        "120.53.12.132","122.114.197.185","122.114.226.172","141.255.164.29","141.98.212.55",
                        "145.249.107.73","146.0.76.37","149.202.12.210","169.239.128.110","176.119.29.37",
                        "178.211.39.6","185.120.77.166","185.145.128.35","185.99.133.112","191.101.180.78",
                        "192.48.88.107","193.182.144.105","202.59.9.59","209.58.186.196","209.58.186.197",
                        "209.58.186.240","220.158.216.130","27.102.130.115","31.170.107.186","31.7.63.141",
                        "45.120.156.69","45.123.190.167","45.123.190.168","45.152.84.57","46.19.143.69",
                        "5.199.174.164","66.70.247.215","79.141.168.109","81.17.17.213","85.93.2.116"],
                  "domain":[],"source":"NCSC/CISA WellMess advisory IOC list"},
}

def load_windows(path):
    d=json.load(open(path)); by=defaultdict(lambda:{'domain':set(),'ip':set()})
    for r in d['rows']:
        if r['kind']=='domain': by[r['actor']]['domain'].add(r['ioc'].lower())
        elif r['kind']=='ip':   by[r['actor']]['ip'].add(r['ioc'].split(':')[0])
    return by

def jaccard(a,b):
    a,b=set(a),set(b)
    if not (a|b): return float('nan')
    return len(a&b)/len(a|b)

def ip16(ips):
    out=set()
    for ip in ips:
        m=re.match(r'(\d+\.\d+)\.',ip)
        if m: out.add(m.group(1))
    return out

def lexvec(domains):
    c=Counter()
    for d in domains:
        s='^'+re.sub(r'[^a-z0-9]','',d.lower())+'$'
        for i in range(len(s)-2): c[s[i:i+3]]+=1
    return c

def cosine(c1,c2):
    if not c1 or not c2: return float('nan')
    dot=sum(c1[k]*c2[k] for k in (set(c1)&set(c2)))
    n1=math.sqrt(sum(v*v for v in c1.values())); n2=math.sqrt(sum(v*v for v in c2.values()))
    return dot/(n1*n2) if n1 and n2 else float('nan')

def build_matrix(actors, W, L, level):
    wf={a:{'all':W[a]['domain']|W[a]['ip'],'ip16':ip16(W[a]['ip']),'lex':lexvec(W[a]['domain'])} for a in actors}
    lf={a:{'all':L[a]['domain']|L[a]['ip'],'ip16':ip16(L[a]['ip']),'lex':lexvec(L[a]['domain'])} for a in actors}
    n=len(actors); M=[[0.0]*n for _ in range(n)]
    for i,ai in enumerate(actors):
        for j,aj in enumerate(actors):
            if level=='L0_literal': M[i][j]=jaccard(wf[ai]['all'],lf[aj]['all'])
            elif level=='L1p_ip16': M[i][j]=jaccard(wf[ai]['ip16'],lf[aj]['ip16'])
            else: M[i][j]=cosine(wf[ai]['lex'],lf[aj]['lex'])
    return M

def perm_test(actors,W,L,level,iters=20000):
    M=build_matrix(actors,W,L,level); n=len(actors); idx=list(range(n))
    def stat(mp):
        same=[M[i][mp[i]] for i in range(n) if M[i][mp[i]]==M[i][mp[i]]]
        ctrl=[M[i][mp[j]] for i in range(n) for j in range(n) if j!=i and M[i][mp[j]]==M[i][mp[j]]]
        if len(same)<2 or len(ctrl)<2: return None,same,ctrl
        return sum(same)/len(same)-sum(ctrl)/len(ctrl),same,ctrl
    obs,same,ctrl=stat(idx)
    if obs is None: return None
    ge=valid=0
    for _ in range(iters):
        p=idx[:]; random.shuffle(p); st,_,_=stat(p)
        if st is None: continue
        valid+=1; ge+=(st>=obs)
    return {'same':sum(same)/len(same),'ctrl':sum(ctrl)/len(ctrl),'diff':obs,
            'p':(ge+1)/(valid+1) if valid else float('nan'),'ns':len(same),'nc':len(ctrl)}

if __name__=='__main__':
    win=load_windows('infra_open_corpus.json'); actors=list(LINUX.keys())
    W={a:{'domain':win[a]['domain'],'ip':win[a]['ip']} for a in actors}
    L={a:{'domain':set(d.lower() for d in LINUX[a]['domain']),'ip':set(LINUX[a]['ip'])} for a in actors}

    with open('infra_dataset.csv','w',newline='') as f:
        w=csv.writer(f); w.writerow(['actor','platform','family','ioc_type','ioc','source'])
        for a in actors:
            for t in ('domain','ip'):
                for v in sorted(W[a][t]): w.writerow([a,'windows','(open-corpus win families)',t,v,'ESET malware-ioc'])
                for v in sorted(L[a][t]): w.writerow([a,'linux',LINUX[a]['family'],t,v,LINUX[a]['source']])

    def fmt(x): return '   n/a' if x!=x else f'{x:6.3f}'
    print("="*96)
    print("SAME-ACTOR  Windows-vs-Linux infrastructure similarity  (keyless levels)")
    print("="*96)
    hdr=f"{'Actor':<15}{'win d/ip':>11}{'lin d/ip':>11}{'L0_literal':>12}{'L1p_ip/16':>11}{'L3_naming':>11}"
    print(hdr); print('-'*len(hdr))
    for a in actors:
        s={'L0_literal':jaccard(W[a]['domain']|W[a]['ip'],L[a]['domain']|L[a]['ip']),
           'L1p_ip16':jaccard(ip16(W[a]['ip']),ip16(L[a]['ip'])),
           'L3_naming':cosine(lexvec(W[a]['domain']),lexvec(L[a]['domain']))}
        wc="%d/%d"%(len(W[a]['domain']),len(W[a]['ip'])); lc="%d/%d"%(len(L[a]['domain']),len(L[a]['ip']))
        print(f"{a:<15}{wc:>11}{lc:>11}{fmt(s['L0_literal']):>12}{fmt(s['L1p_ip16']):>11}{fmt(s['L3_naming']):>11}")

    print("\n"+"="*96)
    print("PERMUTATION TEST  (same-actor pairs vs mismatched-control pairs, 20k iters)")
    print("="*96)
    for lv in ['L0_literal','L1p_ip16','L3_naming']:
        r=perm_test(actors,W,L,lv)
        if r is None: print(f"{lv:<12} insufficient non-null data"); continue
        print(f"{lv:<12} same_mean={r['same']:.4f}  ctrl_mean={r['ctrl']:.4f}  diff={r['diff']:+.4f}  "
              f"p={r['p']:.4f}  (n_same={r['ns']}, n_ctrl={r['nc']})")

    print("\nPENDING enrichment (run on your machine; sandbox can't reach these APIs):")
    print("  L1 true-ASN: VT/Shodan host->ASN ; L2 registrar/NS: VT historical_whois ;")
    print("  L4 TLS cert: VT/Shodan cert ; L5 temporal: first_seen. Cyclops Blink C2 list also pending.")
    print("Wrote infra_dataset.csv")

def render_heatmap():
    import matplotlib; matplotlib.use('Agg')
    import matplotlib.pyplot as plt, numpy as np
    win=load_windows('infra_open_corpus.json'); actors=list(LINUX.keys())
    short=[a.replace('_Sednit','').replace('_Dukes','').replace('_APT41','/41') for a in actors]
    W={a:{'domain':win[a]['domain'],'ip':win[a]['ip']} for a in actors}
    L={a:{'domain':set(d.lower() for d in LINUX[a]['domain']),'ip':set(LINUX[a]['ip'])} for a in actors}
    levels=[('L0  exact C2 overlap','L0_literal'),('L1p  IP /16 neighbourhood','L1p_ip16'),('L3  domain naming style','L3_naming')]
    fig,axs=plt.subplots(1,3,figsize=(15,5.2)); fig.patch.set_facecolor('white')
    for ax,(title,lv) in zip(axs,levels):
        M=np.array(build_matrix(actors,W,L,lv),dtype=float)
        im=ax.imshow(np.nan_to_num(M,nan=0.0),cmap='magma',vmin=0,vmax=max(0.05,np.nanmax(M) if np.isfinite(np.nanmax(M)) else 0.05))
        ax.set_xticks(range(6)); ax.set_yticks(range(6))
        ax.set_xticklabels(short,rotation=45,ha='right',fontsize=8); ax.set_yticklabels(short,fontsize=8)
        ax.set_xlabel('Linux toolset',fontsize=9); ax.set_ylabel('Windows toolset',fontsize=9)
        ax.set_title(title,fontsize=10,fontweight='bold')
        for i in range(6):
            ax.add_patch(plt.Rectangle((i-0.5,i-0.5),1,1,fill=False,edgecolor='#39d',lw=2))  # same-actor diagonal
            for j in range(6):
                v=M[i][j]; txt='–' if v!=v else ('%.2f'%v)
                ax.text(j,i,txt,ha='center',va='center',fontsize=7,color='#9fe' if (v==v and v<0.03) else 'k')
        fig.colorbar(im,ax=ax,fraction=0.046,pad=0.04)
    fig.suptitle('Layer C — Infrastructure similarity: Windows toolset vs Linux toolset (diagonal = same actor)\n'
                 'Preliminary, keyless levels. Diagonal does NOT stand out → no cross-platform infra signal (null, as hypothesised).',
                 fontsize=11)
    fig.tight_layout(rect=[0,0,1,0.93]); fig.savefig('infra_heatmap.png',dpi=140,bbox_inches='tight')
    print('wrote infra_heatmap.png')

render_heatmap()
