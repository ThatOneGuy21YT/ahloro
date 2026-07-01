#!/usr/bin/env python3
"""Probe which data-retrieval endpoints exist on the UG65 ChirpStack."""

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

HOST      = os.environ.get("GW_HOST",      "192.168.1.1")
EMAIL     = os.environ.get("GW_EMAIL",     "admin")
PASS_HASH = os.environ.get("GW_PASS_HASH", "")
PASS      = os.environ.get("GW_PASS",      "")
DEV_EUI   = "24E124535D418892"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

def req(method, path, token=None):
    url  = f"https://{HOST}/api/{path}"
    hdrs = {"Content-Type": "application/json"}
    if token: hdrs["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(url, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(r, context=ctx, timeout=8) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {}
        return e.code, body
    except Exception as e:
        return 0, {"error": str(e)}

pw = PASS_HASH if PASS_HASH else base64.b64encode(hashlib.md5(PASS.encode()).digest()).decode()
_, auth = req("POST", "internal/login")
# login needs body — redo properly
import urllib.request as _ur
def req2(method, path, body=None, token=None):
    url  = f"https://{HOST}/api/{path}"
    hdrs = {"Content-Type": "application/json"}
    if token: hdrs["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    r = _ur.Request(url, data=data, headers=hdrs, method=method)
    try:
        with _ur.urlopen(r, context=ctx, timeout=8) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try: body2 = json.loads(e.read())
        except: body2 = {}
        return e.code, body2
    except Exception as e:
        return 0, {"error": str(e)}

status, auth = req2("POST", "internal/login", {"username": EMAIL, "password": pw})
if "jwt" not in auth:
    sys.exit(f"Login failed ({status}): {auth}")
token = auth["jwt"]
print(f"Logged in OK\n")

paths = [
    f"devices/{DEV_EUI}/events",
    f"devices/{DEV_EUI}/events?limit=5",
    f"devices/{DEV_EUI}/frames",
    f"devices/{DEV_EUI}/frames?limit=5",
    f"devices/{DEV_EUI}/queue",
    f"applications/1/integrations",
    f"applications/1/integrations/http",
    f"applications/1/integrations/mqtt",
]

for path in paths:
    sc, resp = req2("GET", path, token=token)
    keys = list(resp.keys()) if isinstance(resp, dict) else "?"
    preview = ""
    if sc == 200:
        # Show first useful key
        for k in ("result","events","frames","items","integration","kind"):
            if k in resp:
                val = resp[k]
                if isinstance(val, list):
                    preview = f"  → {k}=[{len(val)} items]"
                    if val:
                        preview += f"  first={json.dumps(val[0])[:120]}"
                else:
                    preview += f"  → {k}={json.dumps(val)[:120]}"
                break
        if not preview:
            preview = f"  → {json.dumps(resp)[:150]}"
    print(f"  GET {path}  →  HTTP {sc}{preview}")
