#!/usr/bin/env python3
"""
Infra Layer C — Shodan host + JARM enrichment.
RUN ON YOUR MACHINE. For every IP indicator, pulls Shodan host data: ASN/org, open ports,
service banners, TLS certificate, and the JARM fingerprint. JARM is a fingerprint of how a
server's TLS stack responds — if an actor's Windows-side C2 IP and Linux-side C2 IP share a
JARM, their servers are configured identically, a strong cross-platform tooling link (L4c).

    export SHODAN_KEY="your_NEW_shodan_key"
    python3 enrich_shodan.py infra_dataset.csv
    # -> shodan_hosts.csv   (send this back)

Shodan free credits are limited; the script is resumable (re-run to continue) and reports any
that fail. If you run out of credits, tell me how many IPs it got — even partial JARM data helps.
No key is stored in this file.
"""
import os, sys, csv, json, time, urllib.request, urllib.error

KEY = os.environ.get("SHODAN_KEY", "").strip()
if not KEY: sys.exit('Set SHODAN_KEY first:  export SHODAN_KEY="..."')
CSV_IN = sys.argv[1] if len(sys.argv) > 1 else "infra_dataset.csv"
RAW = "shodan_raw"; os.makedirs(RAW, exist_ok=True)

def host(ip):
    cache = os.path.join(RAW, ip.replace(".", "_") + ".json")
    if os.path.exists(cache):
        return json.loads(open(cache).read() or "{}")
    url = f"https://api.shodan.io/shodan/host/{ip}?key={KEY}"
    try:
        with urllib.request.urlopen(url, timeout=60) as r: body = r.read()
    except urllib.error.HTTPError as e: body = e.read()
    except Exception as e: body = str(e).encode()
    open(cache, "wb").write(body); time.sleep(1.2)
    try: return json.loads(body)
    except Exception: return {}

# unique IP indicators only
ips = []
seen = set()
for r in csv.DictReader(open(CSV_IN)):
    if r["ioc_type"] == "ip" and r["ioc"] not in seen:
        seen.add(r["ioc"]); ips.append((r["ioc"], r["actor"], r["platform"]))
print(f"{len(ips)} IPs to look up on Shodan")

rows = []
for ip, actor, plat in ips:
    d = host(ip)
    if "error" in d or not d.get("ip_str"):
        print(f"  [miss] {actor:<13} {ip:<16} {d.get('error','no data')[:40]}")
        rows.append({"actor":actor,"platform":plat,"ip":ip,"asn":"","org":"","ports":"",
                     "jarm":"","cert_sha256":"","cert_issuer":"","hostnames":"","vulns":""})
        continue
    jarm = ""; cs = ""; ci = ""
    for svc in d.get("data", []):
        if svc.get("jarm"): jarm = svc["jarm"]
        ssl = svc.get("ssl", {})
        if ssl:
            cs = cs or (ssl.get("cert", {}).get("fingerprint", {}).get("sha256", ""))
            ci = ci or ";".join((ssl.get("cert", {}).get("issuer", {}) or {}).values())
    rec = {"actor":actor,"platform":plat,"ip":ip,
           "asn":d.get("asn",""),"org":d.get("org",""),
           "ports":"|".join(str(p) for p in d.get("ports",[])),
           "jarm":jarm,"cert_sha256":cs,"cert_issuer":ci[:60],
           "hostnames":"|".join(d.get("hostnames",[]))[:120],
           "vulns":"|".join(d.get("vulns",[]))[:120]}
    rows.append(rec)
    print(f"  [ok]   {actor:<13} {ip:<16} ports={rec['ports'][:18]:<18} jarm={'yes' if jarm else 'no'}")

cols = ["actor","platform","ip","asn","org","ports","jarm","cert_sha256","cert_issuer","hostnames","vulns"]
with open("shodan_hosts.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)
got = sum(1 for r in rows if r["asn"])
print(f"\nDONE -> shodan_hosts.csv  ({got}/{len(ips)} with data, "
      f"{sum(1 for r in rows if r['jarm'])} with JARM) — send this file back")
