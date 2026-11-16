#!/usr/bin/env python3
"""
Infra Layer C — passive-DNS & Shodan scoring (the deepest levels).
Reads pdns_edges.csv (VT resolutions) and shodan_hosts.csv; computes:
  L0b  shared RESOLVING IP across an actor's Windows vs Linux infra (pDNS)
  L0c  shared RESOLVING DOMAIN across platforms (pDNS)
  L4c  shared JARM TLS fingerprint (Shodan)   [no data: dead infra not in Shodan TLS history]
with a parking/sinkhole guard: an IP shared by >=3 actors (or >=10 domains) is commodity, not a link.
"""
import csv, itertools, statistics, sys
from collections import defaultdict

PDNS = sys.argv[1] if len(sys.argv) > 1 else "pdns_edges.csv"
SHODAN = sys.argv[2] if len(sys.argv) > 2 else "shodan_hosts.csv"

ips = defaultdict(lambda: defaultdict(set)); doms = defaultdict(lambda: defaultdict(set))
ip_actors = defaultdict(set); ip_domcount = defaultdict(int)
for r in csv.DictReader(open(PDNS)):
    a, p = r["actor"], r["platform"]
    if p not in ("windows", "linux"): continue
    if r["rel_type"] == "resolved_ip":
        ips[a][p].add(r["value"]); ip_actors[r["value"]].add(a); ip_domcount[r["value"]] += 1
    if r["rel_type"] == "resolved_domain": doms[a][p].add(r["value"].lower())
    if r["ioc_type"] == "ip": ips[a][p].add(r["ioc"])
    if r["ioc_type"] == "domain": doms[a][p].add(r["ioc"].lower())

def is_parking(ip): return len(ip_actors[ip]) >= 3 or ip_domcount[ip] >= 10
def jac(x, y): return len(x & y) / len(x | y) if (x | y) else float("nan")
actors = sorted(ips)

print("="*80); print("L0b — shared RESOLVING IP (raw, then parking/sinkhole-filtered)"); print("="*80)
for a in actors:
    w, l = ips[a]["windows"], ips[a]["linux"]; sh = w & l
    real = {ip for ip in sh if not is_parking(ip)}
    print(f"  {a:<14} win={len(w):<4} lin={len(l):<4} shared={len(sh)} (real,non-parking={len(real)})  J_raw={jac(w,l):.4f}")
    if sh: print(f"        shared IPs: {sorted(sh)}  -> {len(sh)-len(real)} are parking/sinkhole")

print("\n" + "="*80); print("L0c — shared RESOLVING DOMAIN"); print("="*80)
for a in actors:
    w, l = doms[a]["windows"], doms[a]["linux"]
    print(f"  {a:<14} win={len(w):<4} lin={len(l):<4} shared={len(w&l)}  J={jac(w,l):.4f}")

def perm(F, label):
    both = [a for a in actors if F[a]["windows"] and F[a]["linux"]]
    if len(both) < 2: print(f"{label}: <2 actors"); return
    W = {a: F[a]["windows"] for a in both}; L = {a: F[a]["linux"] for a in both}
    m = len(both); same = [jac(W[a], L[a]) for a in both]; sm = statistics.mean(same)
    nulls = [statistics.mean([jac(W[both[i]], L[both[p[i]]]) for i in range(m)])
             for p in itertools.permutations(range(m))]
    ge = sum(1 for x in nulls if x >= sm - 1e-12)
    print(f"{label}: actors={m}  same={sm:.4f}  control={statistics.mean(nulls):.4f}  p={ge/len(nulls):.4f}")

# parking-filtered IP sets for the honest permutation test
ipsf = defaultdict(lambda: defaultdict(set))
for a in actors:
    for p in ("windows", "linux"):
        ipsf[a][p] = {ip for ip in ips[a][p] if not is_parking(ip)}

print("\n" + "="*80); print("PERMUTATION TESTS"); print("="*80)
perm(ips,  "L0b shared-IP (raw)          ")
perm(ipsf, "L0b shared-IP (parking-filtered)")
perm(doms, "L0c shared-domain            ")

# Shodan / JARM
jarm = 0; hosts = 0
for r in csv.DictReader(open(SHODAN)):
    if r.get("asn"): hosts += 1
    if r.get("jarm"): jarm += 1
print("\n" + "="*80); print("L4c — JARM (Shodan)"); print("="*80)
print(f"  Shodan host data on {hosts} IPs, JARM fingerprints on {jarm}.")
print("  -> No JARM comparison possible: these old C2 IPs have no live TLS service in Shodan's history.")
