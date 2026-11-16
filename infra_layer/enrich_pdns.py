#!/usr/bin/env python3
"""
Infra Layer C — passive-DNS enrichment (VirusTotal relationships).
RUN ON YOUR MACHINE. Pulls, for every indicator, the IPs a domain ever resolved to (and the
domains ever seen on an IP). This catches cross-platform links that raw IOC matching misses:
if an actor's Windows C2 and Linux C2 ever resolved to the SAME IP, that is a direct link (L0b).

    export VT_KEY="your_NEW_virustotal_key"     # use a fresh account: ~395 calls fit in the 500/day free quota
    python3 enrich_pdns.py infra_dataset.csv
    # -> pdns_edges.csv   (send this back)

Optional (needs a 2nd day or 2nd key — adds ~another 395 calls):
    WITH_FILES=1 python3 enrich_pdns.py infra_dataset.csv   # also pulls communicating_files (shared samples)

Rate-limited to VT free tier (4 req/min => ~1h40m). Resumable: re-run to continue; done indicators are skipped.
No key is stored in this file.
"""
import os, sys, csv, json, time, urllib.request, urllib.error

VT = os.environ.get("VT_KEY", "").strip()
if not VT: sys.exit('Set VT_KEY first:  export VT_KEY="..."')
WITH_FILES = os.environ.get("WITH_FILES", "").strip() not in ("", "0", "false")
CSV_IN = sys.argv[1] if len(sys.argv) > 1 else "infra_dataset.csv"
RAW = "pdns_raw"; os.makedirs(RAW, exist_ok=True)
SLEEP = 16  # seconds between VT calls (free tier = 4/min)

def get(url):
    req = urllib.request.Request(url, headers={"x-apikey": VT})
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()

def vt_rel(kind, ioc, rel, limit=40):
    base = "domains" if kind == "domain" else "ip_addresses"
    cache = os.path.join(RAW, f"{kind}_{ioc.replace('/','_').replace(':','_')}_{rel}.json")
    if os.path.exists(cache):
        body = open(cache, "rb").read()
    else:
        st, body = get(f"https://www.virustotal.com/api/v3/{base}/{ioc}/{rel}?limit={limit}")
        open(cache, "wb").write(body); time.sleep(SLEEP)
        print(f"  {kind} {ioc[:30]:<30} {rel:<20} -> {st}")
    try: return json.loads(body).get("data", [])
    except Exception: return []

rows = list(csv.DictReader(open(CSV_IN)))
seen = set(); inds = []
for r in rows:
    k = (r["ioc_type"], r["ioc"])
    if k in seen: continue
    seen.add(k); inds.append(r)
print(f"{len(inds)} indicators; passive-DNS resolutions"
      + (" + communicating_files" if WITH_FILES else "")
      + f"  (~{len(inds)*(2 if WITH_FILES else 1)*SLEEP//60} min)")

edges = []
for r in inds:
    t, ioc, actor, plat = r["ioc_type"], r["ioc"], r["actor"], r["platform"]
    if t == "domain":
        for d in vt_rel("domain", ioc, "resolutions"):
            ip = (d.get("attributes", {}) or {}).get("ip_address", "")
            dt = (d.get("attributes", {}) or {}).get("date", "")
            if ip: edges.append([actor, plat, t, ioc, "resolved_ip", ip, dt])
    elif t == "ip":
        for d in vt_rel("ip", ioc, "resolutions"):
            host = (d.get("attributes", {}) or {}).get("host_name", "")
            dt = (d.get("attributes", {}) or {}).get("date", "")
            if host: edges.append([actor, plat, t, ioc, "resolved_domain", host, dt])
    if WITH_FILES:
        for d in vt_rel(t, ioc, "communicating_files", limit=20):
            h = d.get("id", "")
            if h: edges.append([actor, plat, t, ioc, "comm_file", h, ""])

with open("pdns_edges.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["actor","platform","ioc_type","ioc","rel_type","value","date"])
    w.writerows(edges)
print(f"\nDONE -> pdns_edges.csv  ({len(edges)} edges)  — send this file back")
