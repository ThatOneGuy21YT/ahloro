#!/usr/bin/env python3
"""Quick UG65 / ChirpStack diagnostic — run on a machine that can reach 192.168.1.1."""

import base64, hashlib, json, os, ssl, sys, urllib.error, urllib.request

DIR = os.path.dirname(os.path.abspath(__file__))
def _load(p):
    if not os.path.isfile(p): return
    for line in open(p):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ[k.strip()] = v.strip()

if len(sys.argv) >= 3 and sys.argv[1] == "--env-file":
    _load(sys.argv[2]); sys.argv = [sys.argv[0]] + sys.argv[3:]
_load(os.path.join(DIR, ".env.ug65"))
_load(os.path.join(DIR, ".env"))

HOST      = os.environ.get("GW_HOST",      "192.168.1.1")
EMAIL     = os.environ.get("GW_EMAIL",     "admin")
PASS_HASH = os.environ.get("GW_PASS_HASH", "")
PASS      = os.environ.get("GW_PASS",      "")
DEV_EUI   = (sys.argv[1] if len(sys.argv) > 1 else "").upper()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def req(method, path, body=None, token=None):
    url = f"https://{HOST}/api/{path}"
    hdrs = {"Content-Type": "application/json"}
    if token: hdrs["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(r, context=ctx, timeout=10) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return e.code, {}

pw = PASS_HASH if PASS_HASH else base64.b64encode(hashlib.md5(PASS.encode()).digest()).decode()
status, auth = req("POST", "internal/login", {"username": EMAIL, "password": pw})
if status != 200 or "jwt" not in auth:
    sys.exit(f"Login failed ({status})")
token = auth["jwt"]
print(f"Logged in OK\n")

# ── Applications ──────────────────────────────────────────────────────────────
_, apps_resp = req("GET", "applications?limit=20", token=token)
apps = apps_resp.get("result") or apps_resp.get("apps") or []
print(f"Applications ({len(apps)}):")
for a in apps:
    print(f"  ID={a['id']}  name={a['name']}")
print()

# ── Devices in each application ───────────────────────────────────────────────
for a in apps:
    aid = a["id"]
    _, dr = req("GET", f"devices?limit=50&applicationID={aid}", token=token)
    devs = dr.get("devices") or dr.get("result") or []
    print(f"Application {aid} ({a['name']}) — {len(devs)} device(s):")
    for d in devs:
        eui = d.get("devEUI","").upper()
        print(f"  {eui}  name={d.get('name','')}  lastSeen={d.get('lastSeenAt','never')}")
        # Check activation (session keys — only present after successful OTAA join)
        _, act = req("GET", f"devices/{eui}/activation", token=token)
        da = act.get("deviceActivation") or act
        if da.get("devAddr"):
            print(f"    ✓ Joined  devAddr={da['devAddr']}")
        else:
            print(f"    ✗ NOT joined (no active session)")
        # Check keys
        _, keys_resp = req("GET", f"devices/{eui}/keys", token=token)
        dk = keys_resp.get("deviceKeys") or {}
        if dk.get("appKey"):
            print(f"    AppKey={dk['appKey']}")
    print()

# ── HTTP integrations ─────────────────────────────────────────────────────────
print("HTTP integrations:")
for a in apps:
    aid = a["id"]
    sc, ir = req("GET", f"applications/{aid}/integrations/http", token=token)
    if sc == 200:
        intg = ir.get("integration") or ir
        print(f"  App {aid}: dataUpURL={intg.get('dataUpURL','(none)')}")
        hdrs = intg.get("headers") or intg.get("uplinkDataHeaders") or []
        for h in hdrs:
            print(f"    header: {h.get('key')}={h.get('value','')[:20]}...")
    else:
        print(f"  App {aid}: no HTTP integration (HTTP {sc})")
print()

# ── Device frames (if EUI given) ──────────────────────────────────────────────
if DEV_EUI:
    print(f"Recent frames for {DEV_EUI}:")
    sc, fr = req("GET", f"devices/{DEV_EUI}/frames", token=token)
    frames = fr.get("result") or fr.get("frames") or []
    for f in frames[:10]:
        print(f"  {f}")
