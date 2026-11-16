#!/usr/bin/env python3
"""
Layer B (ATT&CK) of the Step 1-3 pipeline: for each actor, split their known
software/tools into Windows-side vs Linux-side (by platform tag), pull the
ATT&CK techniques used by EACH tool, union them per platform, then compute
same-actor cross-platform Jaccard + cross-actor control pairs.

Entirely offline -- uses the already-cloned cti/ repo, no network calls.
Run from apt-attribution-project/ root: python3 attack_layer_pipeline.py
"""
import csv
import itertools
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

def platform_bucket(platforms_str):
    p = platforms_str.lower()
    if "windows" in p:
        yield "windows"
    if "linux" in p:
        yield "linux"
    if "macos" in p or "mac" in p:
        yield "macos"

import os

def main():
    os.makedirs("output", exist_ok=True)
    print("Loading ATT&CK dataset...")
    mitre = MitreAttackData(ATTACK_JSON)
    print("Loaded.\n")

    # actor -> platform -> set of technique IDs
    actor_platform_techniques = {}

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
            platforms = obj.get("x_mitre_platforms", [])
            platforms_str = "; ".join(platforms)
            buckets = list(platform_bucket(platforms_str))
            if not buckets:
                continue

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

        actor_platform_techniques[actor_key] = platform_techs
        print(f"{actor_key}: windows={len(platform_techs['windows'])} techniques, "
              f"linux={len(platform_techs['linux'])} techniques, "
              f"macos={len(platform_techs['macos'])} techniques")

    def jaccard(a, b):
        if not a and not b:
            return 0.0
        return len(a & b) / len(a | b) if (a | b) else 0.0

    print("\n=== Layer B (ATT&CK): same-actor cross-platform pairs ===")
    same_actor_scores = []
    for actor_key, platforms in actor_platform_techniques.items():
        for p1, p2 in itertools.combinations(["windows", "linux", "macos"], 2):
            set1, set2 = platforms[p1], platforms[p2]
            if not set1 or not set2:
                continue
            score = jaccard(set1, set2)
            same_actor_scores.append((actor_key, p1, p2, score))
            print(f"  {actor_key}: {p1} vs {p2} = {round(score, 4)} "
                  f"(shared: {len(set1 & set2)}, {p1}-only: {len(set1-set2)}, {p2}-only: {len(set2-set1)})")

    print("\n=== Layer B (ATT&CK): cross-actor control pairs (windows vs windows, as baseline) ===")
    control_scores = []
    actor_keys = list(actor_platform_techniques.keys())
    for a1, a2 in itertools.combinations(actor_keys, 2):
        w1 = actor_platform_techniques[a1]["windows"]
        w2 = actor_platform_techniques[a2]["windows"]
        if not w1 or not w2:
            continue
        score = jaccard(w1, w2)
        control_scores.append((a1, a2, score))

    control_scores.sort(key=lambda x: -x[2])
    for a1, a2, score in control_scores:
        print(f"  {a1} (win) vs {a2} (win) = {round(score, 4)}")

    # Save everything to CSV
    with open("output/attack_layer_same_actor.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["actor", "platform_a", "platform_b", "jaccard"])
        w.writerows(same_actor_scores)

    with open("output/attack_layer_control_pairs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["actor_a", "actor_b", "jaccard_windows_vs_windows"])
        w.writerows(control_scores)

    print("\nSaved -> output/attack_layer_same_actor.csv")
    print("Saved -> output/attack_layer_control_pairs.csv")

    if same_actor_scores and control_scores:
        avg_same = sum(s[3] for s in same_actor_scores) / len(same_actor_scores)
        avg_control = sum(s[2] for s in control_scores) / len(control_scores)
        print(f"\n=== Headline comparison ===")
        print(f"Average same-actor cross-platform Jaccard: {round(avg_same, 4)}")
        print(f"Average cross-actor control Jaccard:        {round(avg_control, 4)}")
        if avg_same > avg_control:
            print("--> Same-actor pairs score HIGHER than random pairs. That's your preliminary signal.")
        else:
            print("--> Same-actor pairs do NOT score higher than random pairs here -- report this honestly as a null/weak result for this layer.")

if __name__ == "__main__":
    main()
