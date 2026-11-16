#!/usr/bin/env python3
"""
Permutation test for the Windows-vs-Linux ATT&CK technique-overlap layer.

Question: is the OBSERVED pairing (each actor's own Windows set matched with
its own Linux set) more similar, on average, than a RANDOM pairing of
Windows sets to Linux sets across actors?

Method (exact permutation test, n=6 so all 720 orderings are enumerable):
1. Compute the real same-actor mean Jaccard (the observed statistic).
2. Enumerate every possible way to shuffle which actor's Linux set gets
   matched to which actor's Windows set (720 total orderings for 6 actors).
3. For each shuffled matching, compute the mean Jaccard the same way.
4. The p-value is: what fraction of the 720 shuffled scores are >= the real
   score? If that fraction is small (e.g. < 0.05), the real pairing is
   unlikely to be that good by chance alone -- real signal.

No advanced stats needed: this is literally "try every other way to shuffle
the labels, see how often shuffled beats real."

Run from apt-attribution-project/ root: python3 permutation_test_attack.py
"""
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

def jaccard(a, b):
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b) if (a | b) else 0.0

def main():
    print("Loading ATT&CK dataset and rebuilding per-actor platform technique sets...")
    mitre = MitreAttackData(ATTACK_JSON)

    actor_names = []
    windows_sets = []
    linux_sets = []

    for actor_key, alias in ACTORS.items():
        groups = mitre.get_groups_by_alias(alias)
        if not groups:
            continue
        group_id = groups[0]["id"]
        software_used = mitre.get_software_used_by_group(group_id)

        win_techs, lin_techs = set(), set()
        for s in software_used:
            obj = s["object"]
            platforms_str = "; ".join(obj.get("x_mitre_platforms", []))
            buckets = set(platform_bucket(platforms_str))
            if not buckets:
                continue
            techniques = mitre.get_techniques_used_by_software(obj["id"])
            tech_ids = set()
            for t in techniques:
                for ref in t["object"].get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tech_ids.add(ref["external_id"])
                        break
            if "windows" in buckets:
                win_techs |= tech_ids
            if "linux" in buckets:
                lin_techs |= tech_ids

        actor_names.append(actor_key)
        windows_sets.append(win_techs)
        linux_sets.append(lin_techs)
        print(f"  {actor_key}: windows={len(win_techs)}, linux={len(lin_techs)}")

    n = len(actor_names)
    print(f"\n{n} actors loaded. Running exact permutation test ({__import__('math').factorial(n)} orderings)...\n")

    # Observed statistic: real same-actor pairing
    observed_per_actor = [jaccard(windows_sets[i], linux_sets[i]) for i in range(n)]
    observed_mean = sum(observed_per_actor) / n
    print("Observed same-actor Windows-vs-Linux Jaccard per actor:")
    for name, score in zip(actor_names, observed_per_actor):
        print(f"  {name}: {round(score, 4)}")
    print(f"Observed mean: {round(observed_mean, 4)}\n")

    # Exact permutation test: try every reassignment of linux_sets to windows_sets
    null_means = []
    identity = tuple(range(n))
    for perm in itertools.permutations(range(n)):
        scores = [jaccard(windows_sets[i], linux_sets[perm[i]]) for i in range(n)]
        null_means.append(sum(scores) / n)

    total = len(null_means)
    at_least_as_high = sum(1 for m in null_means if m >= observed_mean - 1e-12)
    p_value = at_least_as_high / total

    null_mean_avg = sum(null_means) / total
    sorted_nulls = sorted(null_means)
    percentile = sum(1 for m in sorted_nulls if m < observed_mean) / total * 100

    print("=== Permutation test result ===")
    print(f"Total orderings tested: {total} (exact, all permutations of {n} actors)")
    print(f"Average of ALL shuffled (null) means: {round(null_mean_avg, 4)}")
    print(f"Observed (real pairing) mean:          {round(observed_mean, 4)}")
    print(f"Observed sits at the {round(percentile, 1)}th percentile of the null distribution")
    print(f"p-value (one-sided, real >= shuffled):  {round(p_value, 4)}")
    print()
    if p_value < 0.05:
        print("--> p < 0.05: the real actor-to-actor pairing beats random shuffles significantly.")
        print("    This IS real, statistically defensible signal, even with only 6 actors.")
    elif p_value < 0.15:
        print("--> Borderline: some signal, but not conventionally significant at n=6.")
        print("    Report this honestly as 'suggestive but not conclusive' -- still a legitimate finding.")
    else:
        print("--> Not significant: the real pairing does not clearly beat random shuffles.")
        print("    Report this as a genuine null result for this layer -- driven by a few strong actors")
        print("    (Sandworm, Winnti, Turla) offset by contradicting ones (Lazarus, APT28).")

if __name__ == "__main__":
    main()
