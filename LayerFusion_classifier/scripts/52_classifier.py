#!/usr/bin/env python3
# Phase-1 "optional interpretable classifier": a simple L2 logistic regression over the
# four-layer similarity scores, to answer "WHICH LAYER CARRIES THE SIGNAL" — not to chase
# accuracy. Honest about small N (8 positives / 56 controls): leave-one-ACTOR-out CV,
# standardized features, balanced class weights, univariate separation per layer.
# Run with: /home/ubuntu/miniconda3/envs/pma2/bin/python -I 52_classifier.py
import os, json, itertools
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

BASE="/home/ubuntu/malpedia/layerAD_paired"
RES=os.path.join(BASE,"results"); CLF=os.path.join(BASE,"classifier")
ACTORS=["Sandworm","Lazarus","APT28","APT27","Turla","APT29","EarthLusca","WinntiAPT41"]
N=len(ACTORS)

# ---- load the four layers' 8x8 matrices (same actor order) ----
A=json.load(open(os.path.join(RES,"layerA_results.json")))
D=json.load(open(os.path.join(RES,"layerD_results.json")))
B=json.load(open(os.path.join(CLF,"layerB_matrix.json")))["M"]
Craw=json.load(open(os.path.join(RES,"layerC_infra.json")))

def feats_infra(side):   # exact-level IOC token set (most generous to Layer C)
    return set("d:"+x for x in side["dom"])|set("i:"+x for x in side["ip"])|set("u:"+x for x in side["uri"])
def jac(P,Q): P,Q=set(P),set(Q); u=len(P|Q); return len(P&Q)/u if u else 0.0
C=[[jac(feats_infra(Craw[ACTORS[i]]["win"]),feats_infra(Craw[ACTORS[j]]["lin"])) for j in range(N)] for i in range(N)]

# ---- feature set: one headline metric per evidence facet ----
# A = code/binary (3 facets), B = TTPs, C = infrastructure, D = protocol (2 facets)
MATS = {
 "A_strings": A["strings_idf_destop"]["M"],   # stoplisted + IDF — the confound-clean strings metric (was strings_jaccard, which left Go-stdlib overlap in)
 "A_tlsh":    A["tlsh_bestmatch"]["M"],
 "A_opcode":  A["opcode3_tfidf"]["M"],
 "B_ttp":     B,
 "C_infra":   C,
 "D_proto":   D["proto_all_idf"]["M"],
 "D_config":  D["cat_config"]["M"],
}
FEATS=list(MATS)

# ---- build the 64-row table: one row per (Win i, Lin j) pair ----
rows=[]; y=[]; meta=[]
for i in range(N):
    for j in range(N):
        rows.append([MATS[f][i][j] for f in FEATS])
        y.append(1 if i==j else 0)
        meta.append((ACTORS[i],ACTORS[j]))
X=np.array(rows,float); y=np.array(y)
print(f"dataset: {X.shape[0]} pairs, {int(y.sum())} same-actor (positive), {int((1-y).sum())} control")

# ======================================================================
# 1) UNIVARIATE: which single layer separates same-actor from control?
# ======================================================================
print("\n=== Univariate separation per feature (does this layer alone carry signal?) ===")
print(f"{'feature':10} {'same_mean':>10} {'ctrl_mean':>10} {'ratio':>7} {'AUC':>6}")
uni={}
for c,f in enumerate(FEATS):
    same=X[y==1,c]; ctrl=X[y==0,c]
    auc=roc_auc_score(y, X[:,c])              # univariate ranking AUC
    ratio=(same.mean()/ctrl.mean()) if ctrl.mean()>0 else float('inf')
    uni[f]=dict(same=float(same.mean()),ctrl=float(ctrl.mean()),auc=float(auc))
    print(f"{f:10} {same.mean():10.3f} {ctrl.mean():10.3f} {ratio:7.1f} {auc:6.3f}")

# ======================================================================
# 2) MULTIVARIATE logistic regression — standardized coefficients
#    (interpretability: sign & magnitude = how much each layer drives "same actor")
# ======================================================================
scaler=StandardScaler().fit(X)
Xs=scaler.transform(X)
clf=LogisticRegression(C=1.0,class_weight="balanced",max_iter=5000)   # L2 is the default
clf.fit(Xs,y)
coef=clf.coef_[0]
order=np.argsort(-np.abs(coef))
print("\n=== Logistic-regression standardized coefficients — ALL 7 features (full data) ===")
print("  NOTE: features are collinear and N=8 positives, so these weights are UNSTABLE")
print("  (L2 splits weight between correlated layers). Trust the univariate table above")
print("  and the 4-feature model below for the 'which layer' story.")
print(f"{'feature':10} {'coef':>8}   (positive => higher score pushes toward SAME actor)")
for k in order:
    print(f"{FEATS[k]:10} {coef[k]:+8.3f}")
insample_auc=roc_auc_score(y, clf.predict_proba(Xs)[:,1])
print(f"in-sample AUC = {insample_auc:.3f}  (optimistic — see LOACV below)")

# --- parsimonious model: ONE representative feature per evidence layer (A,B,C,D) ---
LAYER4=["A_strings","B_ttp","C_infra","D_proto"]
idx4=[FEATS.index(f) for f in LAYER4]
X4=X[:,idx4]; s4=StandardScaler().fit(X4)
clf4=LogisticRegression(C=1.0,class_weight="balanced",max_iter=5000).fit(s4.transform(X4),y)
coef4=clf4.coef_[0]
print("\n=== Parsimonious 4-feature model — one metric per LAYER (cleaner coefficients) ===")
print(f"{'layer feat':10} {'coef':>8}")
for f,cf in sorted(zip(LAYER4,coef4),key=lambda t:-abs(t[1])):
    print(f"{f:10} {cf:+8.3f}")
print(f"in-sample AUC = {roc_auc_score(y, clf4.predict_proba(s4.transform(X4))[:,1]):.3f}")

# ======================================================================
# 3) LEAVE-ONE-ACTOR-OUT CV (the honest small-N test)
#    fold k: train on the 49 pairs NOT involving actor k; score the 15 pairs involving k;
#    per-fold AUC = fraction of that fold's 14 controls ranked below its 1 true positive.
# ======================================================================
def fold_auc(pos_score, neg_scores):
    neg=np.array(neg_scores)
    return (np.sum(neg<pos_score)+0.5*np.sum(neg==pos_score))/len(neg)

print("\n=== Leave-one-ACTOR-out cross-validation ===")
print(f"{'held-out actor':14} {'P(same) for (k,k)':>18} {'rank/15':>8} {'fold_AUC':>9}")
fold_aucs=[]; top1=0
for k in range(N):
    tr=[r for r,(wi,li) in enumerate(meta) if wi!=ACTORS[k] and li!=ACTORS[k]]
    te=[r for r,(wi,li) in enumerate(meta) if wi==ACTORS[k] or li==ACTORS[k]]
    sc=StandardScaler().fit(X[tr])
    m=LogisticRegression(C=1.0,class_weight="balanced",max_iter=5000).fit(sc.transform(X[tr]),y[tr])
    p=m.predict_proba(sc.transform(X[te]))[:,1]
    yte=y[te]
    pos=p[yte==1][0]; negs=p[yte==0]
    rank=1+int(np.sum(negs>pos))            # rank of the true positive among the 15 held-out (1=best)
    fa=fold_auc(pos,negs); fold_aucs.append(fa); top1+= (rank==1)
    print(f"{ACTORS[k]:14} {pos:18.3f} {rank:5d}/15 {fa:9.3f}")
loacv=float(np.mean(fold_aucs))
print(f"\nLEAVE-ONE-ACTOR-OUT mean AUC = {loacv:.3f}   (1.0 = held-out actor's own pair always ranked #1)")
print(f"held-out same-actor pair ranked #1 in {top1}/{N} folds")

# ---- figure: univariate AUC + 4-layer coefficients ----
try:
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    fig,ax=plt.subplots(1,2,figsize=(11,4))
    aucs=[uni[f]["auc"] for f in FEATS]
    cols=["#2a9d8f" if a>=0.70 else ("#e9c46a" if a>=0.63 else "#e76f51") for a in aucs]
    ax[0].barh(FEATS[::-1],aucs[::-1],color=cols[::-1]); ax[0].axvline(0.5,ls="--",c="gray")
    ax[0].set_xlim(0.4,0.85); ax[0].set_xlabel("univariate ROC-AUC (same vs control)")
    ax[0].set_title("Which layer separates same-actor pairs?")
    for i,a in enumerate(aucs[::-1]): ax[0].text(a+0.005,i,f"{a:.2f}",va="center",fontsize=8)
    lab,cf=zip(*sorted(zip(LAYER4,coef4),key=lambda t:t[1]))
    ax[1].barh(lab,cf,color="#264653"); ax[1].axvline(0,c="gray")
    ax[1].set_xlabel("standardized coef (4-feature model)")
    ax[1].set_title("One-per-layer LR weights (unstable at N=8)")
    fig.tight_layout(); fig.savefig(os.path.join(CLF,"classifier_figure.png"),dpi=130); plt.close(fig)
    print("saved",os.path.join(CLF,"classifier_figure.png"))
except Exception as e:
    print("figure skipped:",e)

# save
json.dump({"features":FEATS,"n_pairs":int(X.shape[0]),"n_positive":int(y.sum()),
 "univariate":uni,
 "logreg_coef_all7":{FEATS[k]:float(coef[k]) for k in range(len(FEATS))},
 "logreg_coef_4layer":{LAYER4[k]:float(coef4[k]) for k in range(len(LAYER4))},
 "insample_auc":float(insample_auc),
 "loacv_mean_auc":loacv,"loacv_fold_aucs":[float(x) for x in fold_aucs],
 "loacv_top1_folds":int(top1)},
 open(os.path.join(CLF,"classifier_results.json"),"w"),indent=1)
print("\nsaved",os.path.join(CLF,"classifier_results.json"))
