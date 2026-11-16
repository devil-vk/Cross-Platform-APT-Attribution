#!/usr/bin/env python3
# Fit the BINARY-ONLY layer-fusion classifier on the Malpedia 64 pairs, then score the 3
# out-of-sample test-case types built from NEW vx-underground/APTMalware samples.
# Run with: /home/ubuntu/miniconda3/envs/pma2/bin/python -I 54_score_testcases.py
import json, numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

D=json.load(open("/home/ubuntu/malpedia/layerAD_paired/classifier/testcases_features.json"))
FN=D["fnames"]; X=np.array(D["train_X"],float); y=np.array(D["train_y"])
print(f"binary-only features: {FN}")
print(f"training: {len(y)} Malpedia pairs ({int(y.sum())} same-tool positive / {int((1-y).sum())} control)\n")

sc=StandardScaler().fit(X); clf=LogisticRegression(C=1.0,class_weight="balanced",max_iter=5000).fit(sc.transform(X),y)
print("standardized coefficients (binary-only model):")
for f,c in sorted(zip(FN,clf.coef_[0]),key=lambda t:-abs(t[1])): print(f"   {f:12} {c:+.3f}")

# reference: what the model scores the TRAINING same-tool positives vs controls
ptr=clf.predict_proba(sc.transform(X))[:,1]
print(f"\ntraining P(same): same-tool diag mean={ptr[y==1].mean():.3f}  control mean={ptr[y==0].mean():.3f}")
thr=0.5

def score(feats):
    return float(clf.predict_proba(sc.transform([feats]))[:,1][0])

print("\n"+"="*86)
print("OUT-OF-SAMPLE TEST CASES  (new vx-underground / APTMalware samples, not in training)")
print("="*86)
summ={}
for case in ["1_same_actor_same_tool","2_same_actor_diff_family","3_different_actors"]:
    rows=D["test"][case]; ps=[]
    print(f"\n### {case}")
    print(f"{'pair':52} {'strings':>7} {'tlsh':>6} {'op3':>6} {'proto':>6} {'cfg':>5} | {'P(same)':>8}")
    for r in rows:
        f=r["feats"]; p=score(f); ps.append(p)
        print(f"{r['note']:52} {f[0]:7.3f} {f[1]:6.3f} {f[2]:6.3f} {f[3]:6.3f} {f[4]:5.3f} | {p:8.3f} {'SAME' if p>=thr else 'diff'}")
    summ[case]=(np.mean(ps),np.max(ps),np.min(ps))
    print(f"{'-- mean P(same) for this case:':52} {np.mean(ps):.3f}   (max {np.max(ps):.3f}, min {np.min(ps):.3f})")

print("\n"+"="*86)
print("SUMMARY — mean P(same) by test-case type")
print("="*86)
for case,(m,mx,mn) in summ.items():
    verdict = "correctly SAME" if (case.startswith("1") and m>=thr) else ("correctly low" if not case.startswith("1") and m<thr else "see notes")
    print(f"  {case:28} mean P={m:.3f}  [{mn:.3f}..{mx:.3f}]   -> {verdict}")
# ================= ROBUST-FEATURE variant: only the features PROVEN to transfer ==========
# Layer A/D findings: embedded DATA (strings) + custom PROTOCOL/CONFIG transfer cross-OS;
# compiled CODE (opcode) and byte-shape (tlsh) do NOT. So drop opcode3 & tlsh and refit.
ROB=["strings_jac","proto_jac","config_jac"]; ri=[FN.index(f) for f in ROB]
Xr=X[:,ri]; scr=StandardScaler().fit(Xr)
clfr=LogisticRegression(C=1.0,class_weight="balanced",max_iter=5000).fit(scr.transform(Xr),y)
def scoreR(feats):
    sub=[feats[FN.index(f)] for f in ROB]
    return float(clfr.predict_proba(scr.transform([sub]))[:,1][0])
print("\n"+"="*86)
print("ROBUST-FEATURE MODEL  (strings + protocol + config only — the layers proven to transfer)")
print("="*86)
print("coefficients:", {f:round(float(c),3) for f,c in zip(ROB,clfr.coef_[0])})
summ2={}
for case in ["1_same_actor_same_tool","2_same_actor_diff_family","3_different_actors"]:
    rows=D["test"][case]; ps=[]
    print(f"\n### {case}")
    for r in rows:
        p=scoreR(r["feats"]); ps.append(p)
        print(f"  {r['note']:52} P(same)={p:6.3f} {'SAME' if p>=0.5 else 'diff'}")
    summ2[case]=(float(np.mean(ps)),float(np.max(ps)),float(np.min(ps)))
    print(f"  -- mean P(same): {np.mean(ps):.3f}")
print("\nROBUST-MODEL SUMMARY — mean P(same) by case:")
for case,(m,mx,mn) in summ2.items():
    print(f"  {case:28} mean P={m:.3f}  [{mn:.3f}..{mx:.3f}]")

json.dump({"full_coef":dict(zip(FN,[float(c) for c in clf.coef_[0]])),
           "full_summary":{k:[float(x) for x in v] for k,v in summ.items()},
           "robust_coef":dict(zip(ROB,[float(c) for c in clfr.coef_[0]])),
           "robust_summary":summ2},
          open("/home/ubuntu/malpedia/layerAD_paired/classifier/testcases_results.json","w"),indent=1)
print("\nsaved testcases_results.json")
