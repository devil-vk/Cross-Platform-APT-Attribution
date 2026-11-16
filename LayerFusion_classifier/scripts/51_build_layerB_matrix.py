#!/usr/bin/env python3
# Rebuild Layer B's FULL 8x8 cross-OS technique-Jaccard matrix (the paired-run script
# only saved the 8 diagonal values). Needs mitreattack-python + the offline STIX bundle.
# Run with: /home/ubuntu/miniconda3/bin/python -I 51_build_layerB_matrix.py
import os, json
from mitreattack.stix20 import MitreAttackData

TTP = "/home/ubuntu/pma_project/TTP_layer"
ATTACK_JSON = os.path.join(TTP, "cti/enterprise-attack/enterprise-attack.json")
OUT = "/home/ubuntu/malpedia/layerAD_paired/classifier/layerB_matrix.json"

# Common actor order = the Layer A/D PAIRS order; map to the MITRE alias used by script 08.
ACTOR_ORDER = ["Sandworm","Lazarus","APT28","APT27","Turla","APT29","EarthLusca","WinntiAPT41"]
ALIAS = {"Sandworm":"Sandworm Team","Lazarus":"Lazarus Group","APT28":"APT28","APT27":"APT27",
         "Turla":"Turla","APT29":"APT29","EarthLusca":"Earth Lusca","WinntiAPT41":"APT41"}

def platform_bucket(p):
    p=p.lower()
    if "windows" in p: yield "windows"
    if "linux" in p:   yield "linux"

def jaccard(a,b): return len(a&b)/len(a|b) if (a|b) else 0.0

def build_sets(mitre):
    win,lin={},{}
    for actor in ACTOR_ORDER:
        g=mitre.get_groups_by_alias(ALIAS[actor])
        wt,lt=set(),set()
        if g:
            gid=g[0]["id"]
            for s in mitre.get_software_used_by_group(gid):
                o=s["object"]
                buckets=set(platform_bucket("; ".join(o.get("x_mitre_platforms",[]))))
                if not buckets: continue
                techs=set()
                for t in mitre.get_techniques_used_by_software(o["id"]):
                    for ref in t["object"].get("external_references",[]):
                        if ref.get("source_name")=="mitre-attack":
                            techs.add(ref["external_id"]); break
                if "windows" in buckets: wt|=techs
                if "linux"   in buckets: lt|=techs
        win[actor],lin[actor]=wt,lt
    return win,lin

def main():
    mitre=MitreAttackData(ATTACK_JSON)
    win,lin=build_sets(mitre)
    N=len(ACTOR_ORDER)
    # M[i][j] = Jaccard(Win techniques of actor i, Lin techniques of actor j)
    M=[[jaccard(win[ACTOR_ORDER[i]],lin[ACTOR_ORDER[j]]) for j in range(N)] for i in range(N)]
    json.dump({"actors":ACTOR_ORDER,"M":M,
               "win_sizes":{a:len(win[a]) for a in ACTOR_ORDER},
               "lin_sizes":{a:len(lin[a]) for a in ACTOR_ORDER}},
              open(OUT,"w"),indent=1)
    print("actors:",ACTOR_ORDER)
    print("diagonal (same-actor) Jaccard:")
    for i,a in enumerate(ACTOR_ORDER):
        print(f"  {a:12} {M[i][i]:.4f}")
    off=[M[i][j] for i in range(N) for j in range(N) if i!=j]
    print(f"diag mean={sum(M[i][i] for i in range(N))/N:.4f}  offdiag mean={sum(off)/len(off):.4f}")
    print("saved",OUT)

if __name__=="__main__":
    main()
