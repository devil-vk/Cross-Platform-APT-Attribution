#!/usr/bin/env python3
# OUT-OF-SAMPLE TEST for the layer-fusion classifier.
# Builds 3 kinds of (Windows, Linux) test pairs from NEW vx-underground/APTMalware samples
# (apt-attribution-project/04_samples_ISOLATED) that were NOT in the Malpedia training set:
#   (1) same actor, SAME tool        -> should look like a positive
#   (2) same actor, DIFFERENT family -> the hard case (binary features shouldn't transfer)
#   (3) totally DIFFERENT actors      -> should look like a control
# Uses ONLY binary-derived features (strings, tlsh, opcode3, protocol, config) computed the
# SAME way for training families and for the new samples -> a fair binary-only test.
# Static only; never executes a sample. Run with base python (has tlsh):
#   /home/ubuntu/miniconda3/bin/python -I 53_extract_testcases.py
import os, re, json, glob, subprocess
try:
    import tlsh
except Exception:
    tlsh=None

FEAT="/home/ubuntu/malpedia/layerAD_paired/feat"
OUT="/home/ubuntu/malpedia/layerAD_paired/classifier/testcases_features.json"
ISO="/home/ubuntu/apt-attribution-project/04_samples_ISOLATED"

# ---- Layer D protocol classifier (same patterns/stoplist as scripts/20_layerD.py) ----
CAT_PATTERNS = {
 "c2_uri":[r'^/[\w./?=&%+-]{2,}$',r'\.php($|\?)',r'/api/',r'/gate',r'/upload',r'/panel',r'/get\b',r'/post\b',r'/cmd',r'/task',r'index\.(php|asp|jsp)'],
 "http":[r'(?i)user-agent',r'(?i)content-type',r'(?i)content-length',r'(?i)^accept',r'(?i)x-[a-z-]+:',r'(?i)^cookie',r'(?i)^host:',r'(?i)mozilla/',r'(?i)keep-alive',r'(?i)multipart/form',r'(?i)application/x-www',r'(?i)gzip',r'(?i)^authorization'],
 "session":[r'(?i)session',r'(?i)token',r'(?i)\bbot[_-]?id',r'(?i)client[_-]?id',r'(?i)\bguid\b',r'(?i)campaign',r'(?i)victim',r'(?i)\bagent[_-]?id',r'(?i)cookie'],
 "cmd_vocab":[r'^[A-Z][a-zA-Z]+\.[A-Z][a-zA-Z]+$',r'(?i)shellexecute',r'(?i)^(upload|download)$',r'(?i)^(screenshot|keylog|keylogger)$',r'(?i)^(getfile|putfile|readfile|writefile)$',r'(?i)^(cmd|shell|exec|execute)$',r'(?i)^(sleep|persist|uninstall|selfdelete)$',r'(?i)^(listdir|getdir|setproxy|setserver|settimeout)$'],
 "framing":[r'^0x[0-9a-fA-F]{6,}$',r'(?i)magic',r'(?i)delimiter',r'(?i)boundary',r'^-{3,}',r'(?i)packet',r'(?i)header',r'(?i)checksum'],
 "crypto":[r'(?i)^(rc4|rc6|aes|des|3des|rsa|xor|blowfish|salsa20|chacha20|camellia)$',r'(?i)base64',r'(?i)-----begin',r'(?i)\b(encrypt|decrypt)\b',r'(?i)\bcipher\b',r'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',r'(?i)\bhmac\b',r'(?i)\bmd5\b'],
 "config":[r'(?i)^(server|servers)$',r'(?i)^proxy$',r'(?i)^check$',r'(?i)^report',r'(?i)interval',r'(?i)timeout',r'(?i)^sleep$',r'(?i)jitter',r'(?i)beacon',r'(?i)^config',r'(?i)settings',r'(?i)^port$',r'(?i)^host$',r'(?i)heartbeat'],
}
COMP={c:[re.compile(p) for p in pats] for c,pats in CAT_PATTERNS.items()}
_STOP=re.compile(r"(?i)(/usr/local/go/|/go/src/|goproject|golang|runtime\.|reflectlite|unsafeheader|cookiejar|internal/|vendor/|\.go$|\.s$|type\.\.|struct \{|uintptr|reflect\.|sync\.|syscall\.|compress/|encoding/|mscoree|kernel32|advapi32|\bntdll)")
def proto_sets(strset):
    allp=set(); cfg=set()
    for s in strset:
        if _STOP.search(s): continue
        for c,regs in COMP.items():
            for r in regs:
                if r.search(s):
                    allp.add(s.lower())
                    if c=="config": cfg.add(s.lower())
                    break
    return allp,cfg

# ---- raw feature extraction from a binary (same as scripts/10_features.py) ----
def run(cmd,t=120):
    try: return subprocess.run(cmd,capture_output=True,text=True,timeout=t,errors="replace").stdout
    except Exception: return ""
def get_strings(path):
    s=set()
    for args in (["strings","-n","5",path],["strings","-e","l","-n","5",path]):
        for line in run(args,90).splitlines():
            t=line.strip()
            if 5<=len(t)<=200: s.add(t)
    return s
def get_tlsh(path):
    if not tlsh: return None
    try:
        d=open(path,"rb").read()
        if len(d)<256: return None
        h=tlsh.hash(d); return h if h and h!="TNULL" else None
    except Exception: return None
def get_op3(path):
    out=run(["objdump","-d","--no-show-raw-insn","-M","intel",path],120)
    if "\tpush" not in out and "\tmov" not in out: out=run(["objdump","-d",path],120)
    ops=[]
    for line in out.splitlines():
        if ":\t" not in line: continue
        mnem=line.split(":\t",1)[1].split("\t")[-1].strip()
        m=re.match(r"([a-z][a-z0-9.]+)",mnem)
        if m: ops.append(m.group(1))
    return set(tuple(ops[i:i+3]) for i in range(len(ops)-2))

def features_from_sample(path):
    S=get_strings(path); proto,cfg=proto_sets(S)
    return dict(strings=S, tlsh=get_tlsh(path), op3=get_op3(path), proto=proto, config=cfg)

# ---- similarity functions (plain, vocabulary-independent, used for BOTH train & test) ----
def jac(A,B): A,B=set(A),set(B); u=len(A|B); return len(A&B)/u if u else 0.0
def tlsh_sim(a,b):
    if not tlsh or not a or not b: return 0.0
    try: return max(0.0,1-tlsh.diff(a,b)/300.0)
    except Exception: return 0.0
def pair_feats(w,l):
    return [jac(w["strings"],l["strings"]),
            tlsh_sim(w["tlsh"],l["tlsh"]),
            jac(w["op3"],l["op3"]),
            jac(w["proto"],l["proto"]),
            jac(w["config"],l["config"])]
FNAMES=["strings_jac","tlsh_sim","opcode3_jac","proto_jac","config_jac"]

# ================= TRAINING table: rebuild from Malpedia feat JSONs (same 8 actors) =======
PAIRS=[("Sandworm","win.exaramel","elf.exaramel"),("Lazarus","win.badcall","elf.badcall"),
("APT28","win.xagent","elf.xagent"),("APT27","win.hyperssl","elf.hyperssl"),
("Turla","win.uroburos","elf.penquin_turla"),("APT29","win.wellmess","elf.wellmess"),
("EarthLusca","win.ktlv_door","elf.ktlv_door"),("WinntiAPT41","win.derusbi","elf.derusbi")]
ACTORS=[a for a,_,_ in PAIRS]; N=len(ACTORS)
def feat_from_json(fam):
    d=json.load(open(os.path.join(FEAT,fam+".json")))
    S=set(d["strings"]); proto,cfg=proto_sets(S)
    return dict(strings=S, tlsh=(d["tlsh"][0] if d["tlsh"] else None),
                op3=set(tuple(k.split()) for k in d["op3"]), proto=proto, config=cfg)
WF={a:feat_from_json(w) for a,w,_ in PAIRS}; LF={a:feat_from_json(l) for a,_,l in PAIRS}
train_X=[]; train_y=[]
for i in range(N):
    for j in range(N):
        train_X.append(pair_feats(WF[ACTORS[i]],LF[ACTORS[j]]))
        train_y.append(1 if i==j else 0)

# ================= TEST samples (new, out-of-sample) =====================================
def sample(path_dir):
    fs=glob.glob(os.path.join(ISO,path_dir,"*"))
    fs=[f for f in fs if os.path.isfile(f)]
    return fs[0] if fs else None
SAMP={  # label -> extracted dir
 "lazarus_pondrat_win":"lazarus_pondrat_win_extracted","lazarus_pondrat_lin":"lazarus_pondrat_linux_extracted",
 "lazarus_poolrat_win":"lazarus_poolrat_win_extracted","lazarus_poolrat_lin":"lazarus_poolrat_linux_extracted",
 "lazarus_tfrat_win":"lazarus_themeforestrat_win_extracted","lazarus_tfrat_lin":"lazarus_themeforestrat_linux_extracted",
 "apt29_wellmess_win":"apt29_wellmess_win_extracted","apt29_wellmess_lin":"apt29_wellmess_linux_extracted",
 "winnti_winnti_win":"winnti_winnti_win_extracted","winnti_winnti_lin":"winnti_winnti_linux_extracted",
 "winnti_runningrat_win":"winnti_runningrat_win_extracted",
 "sandworm_industroyer_win":"sandworm_industroyer_win_extracted","sandworm_vpnfilter_lin":"sandworm_vpnfilter_linux_extracted",
}
print("extracting features from new samples...")
SF={}
for lab,d in SAMP.items():
    p=sample(d)
    if not p: print("  MISSING",lab); continue
    SF[lab]=features_from_sample(p)
    print(f"  {lab:26} strings={len(SF[lab]['strings']):6d} op3={len(SF[lab]['op3']):6d} proto={len(SF[lab]['proto']):4d} cfg={len(SF[lab]['config']):3d}")

# 3 test-case pair sets: (win_label, lin_label, note)
CASES={
 "1_same_actor_same_tool":[
    ("lazarus_pondrat_win","lazarus_pondrat_lin","Lazarus PondRAT win vs lin"),
    ("lazarus_poolrat_win","lazarus_poolrat_lin","Lazarus PoolRAT win vs lin"),
    ("lazarus_tfrat_win","lazarus_tfrat_lin","Lazarus ThemeForestRAT win vs lin"),
    ("apt29_wellmess_win","apt29_wellmess_lin","APT29 WellMess win vs lin"),
    ("winnti_winnti_win","winnti_winnti_lin","Winnti winnti win vs lin"),
 ],
 "2_same_actor_diff_family":[
    ("lazarus_pondrat_win","lazarus_poolrat_lin","Lazarus PondRAT(win) vs PoolRAT(lin)"),
    ("lazarus_poolrat_win","lazarus_tfrat_lin","Lazarus PoolRAT(win) vs ThemeForestRAT(lin)"),
    ("lazarus_tfrat_win","lazarus_pondrat_lin","Lazarus ThemeForestRAT(win) vs PondRAT(lin)"),
    ("winnti_runningrat_win","winnti_winnti_lin","Winnti RunningRAT(win) vs winnti(lin)"),
    ("sandworm_industroyer_win","sandworm_vpnfilter_lin","Sandworm Industroyer(win) vs VPNFilter(lin)"),
 ],
 "3_different_actors":[
    ("lazarus_pondrat_win","winnti_winnti_lin","Lazarus PondRAT(win) vs Winnti(lin)"),
    ("lazarus_poolrat_win","apt29_wellmess_lin","Lazarus PoolRAT(win) vs APT29 WellMess(lin)"),
    ("winnti_runningrat_win","lazarus_pondrat_lin","Winnti RunningRAT(win) vs Lazarus PondRAT(lin)"),
    ("sandworm_industroyer_win","lazarus_poolrat_lin","Sandworm Industroyer(win) vs Lazarus PoolRAT(lin)"),
    ("apt29_wellmess_win","winnti_winnti_lin","APT29 WellMess(win) vs Winnti(lin)"),
 ],
}
test={}
for case,pairs in CASES.items():
    test[case]=[]
    for wl,ll,note in pairs:
        if wl in SF and ll in SF:
            test[case].append(dict(note=note,win=wl,lin=ll,feats=pair_feats(SF[wl],SF[ll])))

json.dump(dict(fnames=FNAMES, train_X=train_X, train_y=train_y, test=test),
          open(OUT,"w"))
print("\nsaved",OUT)
