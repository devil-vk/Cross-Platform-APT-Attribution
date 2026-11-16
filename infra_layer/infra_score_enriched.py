#!/usr/bin/env python3
"""
Infra Layer C — ENRICHED scorer. Uses enrichment_summary.csv (VT ASN/registrar/cert/first-seen)
to score same-actor Windows-vs-Linux infrastructure similarity at the deep levels that the
keyless pass couldn't reach, then permutation-tests same-actor vs mismatched-control.

Levels:
  L1   shared hosting ASN            (vt_asn, from IPs)
  L1b  shared /16 subnet             (IP prefix)
  L2   shared registrar              (vt_registrar, from domains)
  L4a  shared TLS cert (exact sha256)(vt_cert_sha256)
  L4b  shared TLS cert issuer        (vt_cert_issuer)
  L5   overlapping first-seen year   (vt_created)
"""
import csv, re, itertools, random, statistics
from collections import defaultdict
random.seed(7)

import sys
CSV=sys.argv[1] if len(sys.argv)>1 else 'enrichment_summary.csv'
rows=list(csv.DictReader(open(CSV)))
def real(r):
    i=r['ioc']
    if r['ioc_type']=='ip': return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$',i))
    if '.' not in i: return False
    tld=i.rsplit('.',1)[-1].lower()
    return tld not in ('asp','tmp','webredirect','mywire','zyns','jkub','ikwb','accesscam','deactivate')
rows=[r for r in rows if real(r)]

# build per actor/platform feature sets
F=defaultdict(lambda: defaultdict(lambda: defaultdict(set)))  # actor->plat->level->set
for r in rows:
    a,p=r['actor'],r['platform']
    if p not in ('windows','linux'): continue
    if r['vt_asn'].strip():       F[a][p]['L1'].add(r['vt_asn'].strip())
    if r['ioc_type']=='ip':
        m=re.match(r'(\d+\.\d+)\.',r['ioc']);  F[a][p]['L1b'].add(m.group(1)) if m else None
    if r['vt_registrar'].strip(): F[a][p]['L2'].add(r['vt_registrar'].strip().lower())
    if r['vt_cert_sha256'].strip():F[a][p]['L4a'].add(r['vt_cert_sha256'].strip())
    if r['vt_cert_issuer'].strip():F[a][p]['L4b'].add(r['vt_cert_issuer'].strip().lower())
    if r['vt_created'].strip():   F[a][p]['L5'].add(r['vt_created'].strip()[:4])  # year

def jac(x,y): return len(x&y)/len(x|y) if (x|y) else float('nan')
actors=sorted(F)
LEVELS=[('L1','hosting ASN'),('L1b','/16 subnet'),('L2','registrar'),
        ('L4a','TLS cert sha256'),('L4b','cert issuer'),('L5','first-seen year')]

print("="*92)
print("INFRA LAYER C — ENRICHED same-actor Windows-vs-Linux similarity")
print("="*92)
hdr=f"{'Actor':<14}"+''.join(f"{n:>13}" for _,n in LEVELS)
print(hdr); print('-'*len(hdr))
for a in actors:
    cells=[]
    for lv,_ in LEVELS:
        w=F[a]['windows'][lv]; l=F[a]['linux'][lv]; v=jac(w,l)
        cells.append('   -' if v!=v else f'{v:.2f}')
    print(f"{a:<14}"+''.join(f"{c:>13}" for c in cells))

print("\n"+"="*92)
print("PERMUTATION TEST per level (same-actor vs mismatched control)")
print("="*92)
for lv,name in LEVELS:
    # actors with data on BOTH platforms at this level
    both=[a for a in actors if F[a]['windows'][lv] and F[a]['linux'][lv]]
    if len(both)<2: print(f"{lv:<4} {name:<18} only {len(both)} actor(s) with both-platform data — skip"); continue
    W={a:F[a]['windows'][lv] for a in both}; L={a:F[a]['linux'][lv] for a in both}
    m=len(both)
    same=[jac(W[a],L[a]) for a in both]; sm=statistics.mean(same)
    # exact if small, else sampled
    perms=list(itertools.permutations(range(m))) if m<=7 else [random.sample(range(m),m) for _ in range(5000)]
    nulls=[statistics.mean([jac(W[both[i]],L[both[p[i]]]) for i in range(m)]) for p in perms]
    ge=sum(1 for x in nulls if x>=sm-1e-12); pval=ge/len(nulls)
    ctrl=statistics.mean(nulls)
    print(f"{lv:<4} {name:<18} actors={m}  same={sm:.3f}  control={ctrl:.3f}  p={pval:.3f}  {'<-- signal' if pval<0.1 and sm>ctrl else ''}")
