#!/usr/bin/env python3
"""
Layer B (ATT&CK / TTPs) — rebuilt for the project's 9-ACTOR set (the same actors
used in Layers A / A2 / D), replacing the original 6-actor set.

Method is IDENTICAL to scripts/01+02 (so results are comparable): for each actor take
the ATT&CK software attributed to the group, split by platform tag (Windows/Linux),
union the techniques each tool uses per platform, score same-actor Win-vs-Lin Jaccard
vs an exact permutation null. Offline; uses the bundled cti/ STIX bundle.

Actors with no Linux-tagged software (or no software at all) in MITRE cannot be scored
by this method and are reported as data gaps, not failures.

Run from TTP_layer/: /home/ubuntu/miniconda3/bin/python -I scripts/08_attack_layer_final8.py
"""
import os, json, math, itertools, statistics
from mitreattack.stix20 import MitreAttackData

ATTACK_JSON = "cti/enterprise-attack/enterprise-attack.json"

# FINAL 8-actor set -> MITRE alias (APT36 & Gelsemium dropped: no cross-platform
# significance; APT36 has 0 Linux-tagged software and Gelsemium 0 software in MITRE).
# Turla is an old actor, MITRE-scorable, so it is included in this (MITRE-based) layer
# even though it has no binary samples for the sample-based layers A/A2/C/D.
ACTORS = {
    "turla":                  "Turla",
    "sandworm":               "Sandworm Team",
    "lazarus":                "Lazarus Group",
    "winnti_apt41":           "APT41",
    "apt28_sednit":           "APT28",
    "apt29_dukes":            "APT29",
    "apt27_sysupdate":        "APT27",
    "earthlusca":             "Earth Lusca",
}

def platform_bucket(platforms_str):
    p = platforms_str.lower()
    if "windows" in p: yield "windows"
    if "linux" in p:   yield "linux"

def jaccard(a, b):
    return len(a & b) / len(a | b) if (a | b) else 0.0

def build_sets(mitre):
    # win[actor]/lin[actor] = technique-id set; swmap[actor][platform] = {(sw_name, tech_id)}
    win, lin, diag, swmap = {}, {}, {}, {}
    for key, alias in ACTORS.items():
        g = mitre.get_groups_by_alias(alias)
        if not g:
            diag[key] = "no MITRE group"; continue
        gid = g[0]["id"]
        wt, lt = set(), set()
        swmap[key] = {"windows": set(), "linux": set()}
        nsw = nwin = nlin = 0
        for s in mitre.get_software_used_by_group(gid):
            o = s["object"]; nsw += 1
            swname = o.get("name", o["id"])
            buckets = set(platform_bucket("; ".join(o.get("x_mitre_platforms", []))))
            if not buckets: continue
            techs = set()
            for t in mitre.get_techniques_used_by_software(o["id"]):
                for ref in t["object"].get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        techs.add(ref["external_id"]); break
            if "windows" in buckets:
                wt |= techs; nwin += 1
                for tid in techs: swmap[key]["windows"].add((swname, tid))
            if "linux" in buckets:
                lt |= techs; nlin += 1
                for tid in techs: swmap[key]["linux"].add((swname, tid))
        win[key], lin[key] = wt, lt
        diag[key] = f"software={nsw} win-sw={nwin} lin-sw={nlin} win-tech={len(wt)} lin-tech={len(lt)}"
    return win, lin, diag, swmap

def permutation_test(actors, win, lin):
    n = len(actors)
    obs = [jaccard(win[a], lin[a]) for a in actors]
    obs_mean = statistics.mean(obs)
    nulls = []
    for perm in itertools.permutations(range(n)):
        nulls.append(statistics.mean([jaccard(win[actors[i]], lin[actors[perm[i]]]) for i in range(n)]))
    p = sum(1 for m in nulls if m >= obs_mean - 1e-12) / len(nulls)
    return obs, obs_mean, statistics.mean(nulls), p, len(nulls)

def main():
    os.makedirs("output", exist_ok=True)
    print("Loading ATT&CK dataset...")
    mitre = MitreAttackData(ATTACK_JSON)
    win, lin, diag, swmap = build_sets(mitre)

    print("\n=== Per-actor coverage (9 actors attempted) ===")
    for k in ACTORS:
        print(f"  {k:24} {diag.get(k,'?')}")

    scorable = [k for k in ACTORS if win.get(k) and lin.get(k)]
    dropped  = [k for k in ACTORS if k not in scorable]
    print(f"\nScorable (both Win & Linux technique sets): {len(scorable)} -> {scorable}")
    print(f"Dropped (MITRE data gap):                   {len(dropped)} -> {dropped}")

    print("\n=== Same-actor cross-platform Jaccard (scorable actors) ===")
    for a in sorted(scorable, key=lambda a: -jaccard(win[a], lin[a])):
        print(f"  {a:24} {jaccard(win[a], lin[a]):.4f}  (win={len(win[a])} lin={len(lin[a])} shared={len(win[a]&lin[a])})")

    obs, obs_mean, null_mean, p, n_perm = permutation_test(scorable, win, lin)
    print(f"\n=== Exact permutation test ({len(scorable)} actors, {n_perm} orderings) ===")
    print(f"  observed same-actor mean Jaccard : {obs_mean:.4f}")
    print(f"  null (shuffled) mean Jaccard     : {null_mean:.4f}")
    print(f"  p-value (one-sided, real>=shuffled): {p:.4f}")
    print(f"  --> {'SIGNIFICANT (p<0.05)' if p<0.05 else 'not significant'}")

    # --- robustness: leave-one-out ---
    print("\n=== Leave-one-out robustness (drop each actor, re-test remaining) ===")
    loo = {}
    for drop in scorable:
        sub = [a for a in scorable if a != drop]
        _, _, _, pp, _ = permutation_test(sub, win, lin)
        loo[drop] = round(pp, 4)
        print(f"  drop {drop:24} -> p={pp:.4f}")
    worst = max(loo.values())
    print(f"  worst-case LOO p = {worst:.4f} -> {'robust' if worst<0.05 else 'NOT robust'}")

    # --- robustness: commodity-tool exclusion (software used by >=3 scorable actors) ---
    from collections import Counter
    swcount = Counter()
    for a in scorable:
        names = {nm for pl in ("windows", "linux") for (nm, _) in swmap[a][pl]}
        for nm in names: swcount[nm] += 1
    commodity = {nm for nm, c in swcount.items() if c >= 3}
    winx = {a: {tid for (nm, tid) in swmap[a]["windows"] if nm not in commodity} for a in scorable}
    linx = {a: {tid for (nm, tid) in swmap[a]["linux"] if nm not in commodity} for a in scorable}
    scor2 = [a for a in scorable if winx[a] and linx[a]]
    print(f"\n=== Commodity-tool exclusion ({len(commodity)} shared tools removed) ===")
    print(f"  excluded: {sorted(commodity)}")
    if len(scor2) >= 3:
        _, om2, nm2, p2, _ = permutation_test(scor2, winx, linx)
        print(f"  after exclusion ({len(scor2)} actors): observed={om2:.4f} null={nm2:.4f} p={p2:.4f} "
              f"-> {'signal holds' if p2<0.05 else 'weakened'}")
    else:
        om2 = nm2 = p2 = None
        print("  too few actors retain non-commodity techniques on both platforms")

    out = {
        "actors_attempted": list(ACTORS),
        "coverage": diag,
        "scorable": scorable,
        "dropped_data_gap": dropped,
        "same_actor_jaccard": {a: round(jaccard(win[a], lin[a]), 4) for a in scorable},
        "permutation_test": {"n_actors": len(scorable), "n_orderings": n_perm,
                             "observed_mean": round(obs_mean, 4), "null_mean": round(null_mean, 4),
                             "p_value": round(p, 4)},
        "leave_one_out_p": loo,
        "commodity_excluded": {"tools_removed": sorted(commodity), "n_actors": len(scor2),
                               "observed_mean": (round(om2,4) if om2 is not None else None),
                               "null_mean": (round(nm2,4) if nm2 is not None else None),
                               "p_value": (round(p2,4) if p2 is not None else None)},
    }
    with open("output/attack_layer_final8.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\nSaved -> output/attack_layer_final8.json")

if __name__ == "__main__":
    main()
