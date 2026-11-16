#!/usr/bin/env python3
"""
Layer C enrichment — RUN THIS ON YOUR OWN MACHINE (not in the Claude sandbox).
Reads infra_dataset.csv, enriches every domain/IP via VirusTotal (+ Shodan for IPs),
saves raw JSON, and writes a compact enrichment_summary.csv to send back.

Usage:
    export VT_KEY="your_virustotal_key"
    export SHODAN_KEY="your_shodan_key"          # optional; omit to skip Shodan
    python3 enrich_local.py infra_dataset.csv

Notes:
- VirusTotal public tier = 4 requests/min, 500/day. The script sleeps 16s between VT
  calls to stay under that, so a full run (~390 indicators) takes ~1.5-2 hours. It is
  RESUMABLE: already-saved indicators are skipped, so you can Ctrl-C and rerun anytime.
- Nothing here hardcodes a key; both are read from the environment. Rotate them when done.
- Send back ONLY  enrichment_summary.csv  (small). Keep the raw/ folder for your records.
"""
import csv, json, os, sys, time, urllib.request, urllib.error

VT_KEY     = os.environ.get("VT_KEY", "").strip()
SHODAN_KEY = os.environ.get("SHODAN_KEY", "").strip()
if not VT_KEY:
    sys.exit("Set VT_KEY first:  export VT_KEY=\"...\"")

CSV_IN  = sys.argv[1] if len(sys.argv) > 1 else "infra_dataset.csv"
RAW     = "enrichment_raw"
os.makedirs(f"{RAW}/vt", exist_ok=True)
os.makedirs(f"{RAW}/shodan", exist_ok=True)
SLEEP_VT = 16   # seconds; lower this only if you have a paid VT tier

def safe(s):      return s.replace("/", "_").replace(":", "_").replace(".", "_")
def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()

def vt_domain(d):   return get(f"https://www.virustotal.com/api/v3/domains/{d}",       {"x-apikey": VT_KEY})
def vt_ip(ip):      return get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", {"x-apikey": VT_KEY})
def shodan_ip(ip):  return get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}")

# ---- load indicators ----
rows = list(csv.DictReader(open(CSV_IN)))
seen = set(); inds = []
for r in rows:
    k = (r["ioc_type"], r["ioc"])
    if k in seen: continue
    seen.add(k); inds.append(r)
print(f"{len(inds)} unique indicators to enrich. Est. ~{len(inds)*SLEEP_VT//60} min for VT.")

def extract_vt(kind, body):
    try: a = json.loads(body)["data"]["attributes"]
    except Exception: return {}
    out = {}
    if kind == "ip":
        out["vt_asn"] = a.get("asn"); out["vt_as_owner"] = a.get("as_owner")
        out["vt_country"] = a.get("country"); out["vt_network"] = a.get("network")
    else:
        out["vt_registrar"] = a.get("registrar")
        cd = a.get("creation_date")
        out["vt_created"] = time.strftime("%Y-%m-%d", time.gmtime(cd)) if cd else ""
    cert = a.get("last_https_certificate") or {}
    out["vt_cert_sha256"] = cert.get("thumbprint_sha256", "")
    out["vt_cert_issuer"] = (cert.get("issuer") or {}).get("O", "")
    st = a.get("last_analysis_stats") or {}
    out["vt_malicious"] = st.get("malicious", "")
    return out

def extract_shodan(body):
    try: a = json.loads(body)
    except Exception: return {}
    return {"shodan_asn": a.get("asn", ""), "shodan_org": a.get("org", ""),
            "shodan_ports": "|".join(str(p) for p in a.get("ports", []))}

summary = []
for i, r in enumerate(inds, 1):
    typ, ioc = r["ioc_type"], r["ioc"]
    rec = {"actor": r["actor"], "platform": r["platform"], "family": r["family"],
           "ioc_type": typ, "ioc": ioc}
    vt_path = f"{RAW}/vt/{typ}_{safe(ioc)}.json"
    if os.path.exists(vt_path):
        body = open(vt_path, "rb").read()
    else:
        st, body = (vt_ip(ioc) if typ == "ip" else vt_domain(ioc))
        open(vt_path, "wb").write(body)
        print(f"[{i}/{len(inds)}] VT {typ} {ioc} -> {st}")
        time.sleep(SLEEP_VT)
    rec.update(extract_vt(typ, body))
    if typ == "ip" and SHODAN_KEY:
        sp = f"{RAW}/shodan/{safe(ioc)}.json"
        if os.path.exists(sp):
            sbody = open(sp, "rb").read()
        else:
            st, sbody = shodan_ip(ioc); open(sp, "wb").write(sbody)
            time.sleep(1.2)
        rec.update(extract_shodan(sbody))
    summary.append(rec)

cols = ["actor","platform","family","ioc_type","ioc","vt_asn","vt_as_owner","vt_country",
        "vt_network","vt_registrar","vt_created","vt_cert_sha256","vt_cert_issuer",
        "vt_malicious","shodan_asn","shodan_org","shodan_ports"]
with open("enrichment_summary.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
    for rec in summary: w.writerow({c: rec.get(c, "") for c in cols})
print("\nDONE -> enrichment_summary.csv  (send this one file back)")
