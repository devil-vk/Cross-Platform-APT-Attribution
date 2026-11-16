#!/usr/bin/env python3
"""
Layer B (ATT&CK/TTP) — FULL multi-angle validation.

Angle 1: Technique-level Jaccard, same-actor cross-platform (the headline number).
Angle 2: Tactic-level Jaccard (coarser aggregation) — checks whether the
         technique-level signal survives at a coarser grouping, or is an
         artifact of how finely MITRE splits techniques.
Angle 3: Exact permutation test on technique-level Jaccard (n=6, 720 orderings)
         — statistical significance of the observed pairing vs. random.
Angle 4: Dual-use/commodity-tool sensitivity — software used by 3+ of the 6
         actors (e.g. generic admin tools, widely-shared frameworks) is
         flagged and EXCLUDED, then Jaccard is recomputed. If the signal
         survives exclusion, it's not just an artifact of shared commodity
         tooling.
Angle 5: Bootstrap stability check — resample (with replacement) the set of
         software per actor/platform 1000x and report the 90% interval for
         each actor's Jaccard score, so a single-tool fluke doesn't get
         over-interpreted as a stable finding.

Run from apt-attribution-project/ root:
    python3 06_pipeline_scripts/07_attack_layer_full_validation.py
Writes: output/attack_layer_full_validation.json (all results)
"""
import os
import csv
import itertools
import json
import random
from collections import Counter, defaultdict
from mitreattack.stix20 import MitreAttackData

ATTACK_JSON = "cti/enterprise-attack/enterprise-attack.json"

ACTORS = {
    "winnti_apt41": "APT41",
    "turla": "Turla",
    "lazarus": "Lazarus Group",
    "sandworm": "Sandworm Team",
    "apt28": "APT28",
    "apt29": "APT29",
}

COMMODITY_THRESHOLD = 3  # software used by this many actors (of 6) = commodity


def platform_bucket(platforms_str):
    p = platforms_str.lower()
    if "windows" in p:
        yield "windows"
    if "linux" in p:
        yield "linux"
    if "macos" in p or "mac" in p:
        yield "macos"


def jaccard(a, b):
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b) if (a | b) else 0.0


def load_attack_data(mitre):
    """Returns:
    actor -> platform -> set of technique IDs
    actor -> platform -> set of (software_name, technique_id) pairs (for commodity filtering)
    software_name -> set of actors using it (for commodity detection)
    technique_id -> tactic name (for tactic-level aggregation)
    """
    actor_platform_techs = {}
    actor_platform_software_techs = defaultdict(lambda: defaultdict(set))
    software_actor_count = defaultdict(set)
    tech_to_tactic = {}

    # build technique -> tactic lookup once
    for tech in mitre.get_techniques(remove_revoked_deprecated=True):
        tobj = tech
        tid = None
        for ref in tobj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref["external_id"]
                break
        if not tid:
            continue
        kill_chain = tobj.get("kill_chain_phases", [])
        tactics = sorted(set(kc["phase_name"] for kc in kill_chain if kc.get("kill_chain_name") == "mitre-attack"))
        tech_to_tactic[tid] = tactics

    for actor_key, alias in ACTORS.items():
        groups = mitre.get_groups_by_alias(alias)
        if not groups:
            print(f"!! No group found for {actor_key}")
            continue
        group_id = groups[0]["id"]
        software_used = mitre.get_software_used_by_group(group_id)

        platform_techs = {"windows": set(), "linux": set(), "macos": set()}

        for s in software_used:
            obj = s["object"]
            sw_name = obj.get("name", obj.get("id"))
            platforms_str = "; ".join(obj.get("x_mitre_platforms", []))
            buckets = list(platform_bucket(platforms_str))
            if not buckets:
                continue

            software_actor_count[sw_name].add(actor_key)

            techniques = mitre.get_techniques_used_by_software(obj["id"])
            tech_ids = set()
            for t in techniques:
                tobj = t["object"]
                for ref in tobj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tech_ids.add(ref["external_id"])
                        break

            for bucket in buckets:
                platform_techs[bucket] |= tech_ids
                for tid in tech_ids:
                    actor_platform_software_techs[actor_key][bucket].add((sw_name, tid))

        actor_platform_techs[actor_key] = platform_techs

    return actor_platform_techs, actor_platform_software_techs, software_actor_count, tech_to_tactic


def angle1_technique_jaccard(actor_platform_techs):
    results = {}
    for actor, platforms in actor_platform_techs.items():
        win, lin = platforms["windows"], platforms["linux"]
        if win and lin:
            results[actor] = round(jaccard(win, lin), 4)
    return results


def angle2_tactic_jaccard(actor_platform_techs, tech_to_tactic):
    results = {}
    for actor, platforms in actor_platform_techs.items():
        win_tactics = set()
        for t in platforms["windows"]:
            win_tactics |= set(tech_to_tactic.get(t, []))
        lin_tactics = set()
        for t in platforms["linux"]:
            lin_tactics |= set(tech_to_tactic.get(t, []))
        if win_tactics and lin_tactics:
            results[actor] = round(jaccard(win_tactics, lin_tactics), 4)
    return results


def angle3_permutation_test(actor_platform_techs):
    actor_names = list(actor_platform_techs.keys())
    windows_sets = [actor_platform_techs[a]["windows"] for a in actor_names]
    linux_sets = [actor_platform_techs[a]["linux"] for a in actor_names]
    n = len(actor_names)

    observed_per_actor = [jaccard(windows_sets[i], linux_sets[i]) for i in range(n)]
    observed_mean = sum(observed_per_actor) / n

    null_means = []
    for perm in itertools.permutations(range(n)):
        scores = [jaccard(windows_sets[i], linux_sets[perm[i]]) for i in range(n)]
        null_means.append(sum(scores) / n)

    total = len(null_means)
    at_least_as_high = sum(1 for m in null_means if m >= observed_mean - 1e-12)
    p_value = at_least_as_high / total
    null_mean_avg = sum(null_means) / total

    return {
        "n_actors": n,
        "n_orderings": total,
        "observed_mean": round(observed_mean, 4),
        "null_mean": round(null_mean_avg, 4),
        "p_value": round(p_value, 4),
        "per_actor": {name: round(score, 4) for name, score in zip(actor_names, observed_per_actor)},
    }


def angle4_commodity_sensitivity(actor_platform_software_techs, software_actor_count):
    commodity_software = {sw for sw, actors in software_actor_count.items() if len(actors) >= COMMODITY_THRESHOLD}
    print(f"\nCommodity software (used by {COMMODITY_THRESHOLD}+ of 6 actors), EXCLUDED in this angle:")
    for sw in sorted(commodity_software):
        print(f"  {sw} (used by: {sorted(software_actor_count[sw])})")

    results = {}
    for actor, platforms in actor_platform_software_techs.items():
        win_techs = {tid for sw, tid in platforms["windows"] if sw not in commodity_software}
        lin_techs = {tid for sw, tid in platforms["linux"] if sw not in commodity_software}
        if win_techs and lin_techs:
            results[actor] = round(jaccard(win_techs, lin_techs), 4)
        else:
            results[actor] = None  # no non-commodity techniques left on one side
    return results, sorted(commodity_software)


def angle5_bootstrap_stability(actor_platform_software_techs, n_iter=1000, seed=42):
    rng = random.Random(seed)
    results = {}
    for actor, platforms in actor_platform_software_techs.items():
        # sort to a deterministic order: set->list ordering is hash-seed dependent,
        # so without this the seeded RNG samples different elements each process run
        win_pairs = sorted(platforms["windows"])
        lin_pairs = sorted(platforms["linux"])
        if not win_pairs or not lin_pairs:
            continue
        scores = []
        for _ in range(n_iter):
            win_sample = [rng.choice(win_pairs) for _ in range(len(win_pairs))]
            lin_sample = [rng.choice(lin_pairs) for _ in range(len(lin_pairs))]
            win_techs = {tid for _, tid in win_sample}
            lin_techs = {tid for _, tid in lin_sample}
            scores.append(jaccard(win_techs, lin_techs))
        scores.sort()
        lo = scores[int(0.05 * n_iter)]
        hi = scores[int(0.95 * n_iter) - 1]
        results[actor] = {"median": round(scores[n_iter // 2], 4), "90pct_interval": [round(lo, 4), round(hi, 4)]}
    return results


def main():
    print("Loading ATT&CK dataset...")
    mitre = MitreAttackData(ATTACK_JSON)
    actor_platform_techs, actor_platform_software_techs, software_actor_count, tech_to_tactic = load_attack_data(mitre)
    print("Loaded.\n")

    print("=" * 70)
    print("ANGLE 1: Technique-level Jaccard (headline numbers)")
    print("=" * 70)
    a1 = angle1_technique_jaccard(actor_platform_techs)
    for actor, score in sorted(a1.items(), key=lambda x: -x[1]):
        print(f"  {actor}: {score}")

    print("\n" + "=" * 70)
    print("ANGLE 2: Tactic-level Jaccard (coarser aggregation)")
    print("=" * 70)
    a2 = angle2_tactic_jaccard(actor_platform_techs, tech_to_tactic)
    for actor, score in sorted(a2.items(), key=lambda x: -x[1]):
        print(f"  {actor}: {score}")
    print("  (compare to Angle 1 -- does the ranking/signal hold at coarser granularity?)")

    print("\n" + "=" * 70)
    print("ANGLE 3: Exact permutation test (statistical significance)")
    print("=" * 70)
    a3 = angle3_permutation_test(actor_platform_techs)
    print(f"  n={a3['n_actors']}, orderings={a3['n_orderings']}")
    print(f"  observed mean={a3['observed_mean']}, null mean={a3['null_mean']}, p={a3['p_value']}")

    print("\n" + "=" * 70)
    print("ANGLE 4: Commodity-tool sensitivity (exclude widely-shared software)")
    print("=" * 70)
    a4, commodity_list = angle4_commodity_sensitivity(actor_platform_software_techs, software_actor_count)
    print("\nJaccard after excluding commodity software:")
    for actor, score in sorted(a4.items(), key=lambda x: (x[1] is None, -(x[1] or 0))):
        orig = a1.get(actor)
        print(f"  {actor}: {score} (original: {orig})")

    print("\n" + "=" * 70)
    print("ANGLE 5: Bootstrap stability (1000 resamples, 90% interval)")
    print("=" * 70)
    a5 = angle5_bootstrap_stability(actor_platform_software_techs)
    for actor, stats in sorted(a5.items(), key=lambda x: -x[1]["median"]):
        print(f"  {actor}: median={stats['median']}, 90% interval={stats['90pct_interval']}")

    out = {
        "angle1_technique_jaccard": a1,
        "angle2_tactic_jaccard": a2,
        "angle3_permutation_test": a3,
        "angle4_commodity_excluded_jaccard": a4,
        "angle4_commodity_software_list": commodity_list,
        "angle5_bootstrap_stability": a5,
    }
    out_path = "output/attack_layer_full_validation.json"
    os.makedirs("output", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"\nFull results saved -> {out_path}")

    print("\n" + "=" * 70)
    print("INTERPRETATION SUMMARY")
    print("=" * 70)
    print("The Layer B finding is robust if: (a) technique- and tactic-level")
    print("rankings broadly agree, (b) the permutation test is significant,")
    print("(c) excluding commodity software doesn't collapse the signal to")
    print("near-zero, and (d) bootstrap intervals don't span zero for the")
    print("actors with the strongest headline scores.")


if __name__ == "__main__":
    main()
