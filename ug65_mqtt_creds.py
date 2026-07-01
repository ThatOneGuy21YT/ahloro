#!/usr/bin/env python3
"""Try additional MQTT credential sets for the UG65 and probe CGI for config."""

import base64, hashlib, json, os, ssl, socket, sys, time
import urllib.request, urllib.error

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

HOST     = os.environ.get("GW_HOST",  "192.168.1.1")
GW_PASS  = os.environ.get("GW_PASS",  "p0ssw0rd;")
GW_EMAIL = os.environ.get("GW_EMAIL", "admin")

try:
    import paho.mqtt.client as mqtt
    HAS_MQTT = True
except ImportError:
    HAS_MQTT = False

# ── MQTT credential brute-force ───────────────────────────────────────────────
if HAS_MQTT:
    CREDS = [
        ("loraserver",      "loraserver"),
        ("chirpstack",      "chirpstack"),
        ("mqtt",            "mqtt"),
        ("mosquitto",       "mosquitto"),
        ("root",            GW_PASS),
        ("root",            "root"),
        ("loraserver",      GW_PASS),
        ("chirpstack",      GW_PASS),
        ("admin",           ""),
        ("",                GW_PASS),
        # Milesight-specific candidates
        ("milesight",       "milesight"),
        ("milesight",       GW_PASS),
        (GW_EMAIL,          "milesight"),
        ("24e124535d418892",""),              # gateway EUI as username
        ("24e124535d418892", GW_PASS),
        ("ns",              "ns"),
        ("as",              "as"),
    ]
    print("Trying MQTT credentials...")
    for user, pw in CREDS:
        result = {"rc": None}
        def on_connect(c, u, f, rc, *a): result["rc"] = rc
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ds-probe")
        client.on_connect = on_connect
        if user or pw:
            client.username_pw_set(user or None, pw or None)
        try:
            client.connect(HOST, 1883, keepalive=5)
            for _ in range(15):
                client.loop(0.1)
                if result["rc"] is not None: break
            rc_val = getattr(result["rc"], "value", result["rc"])
            if rc_val == 0:
                print(f"  ✓ SUCCESS  user={user!r}  pass={pw!r}")
            else:
                print(f"  ✗ {result['rc']}  user={user!r}")
            client.disconnect()
        except Exception as e:
            print(f"  error: {e}")
    print()

# ── CGI: probe for config/file-read functions ─────────────────────────────────
import http.cookiejar

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

def aes_enc(pt):
    k, iv = b"1111111111111111", b"2222222222222222"
    p = sym_padding.PKCS7(128).padder()
    padded = p.update(pt.encode()) + p.finalize()
    e = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
    return base64.b64encode(e.update(padded) + e.finalize()).decode()

# Build an opener that keeps cookies across requests
_jar    = http.cookiejar.CookieJar()
_opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(_jar),
)

_id = [1]
def cgi(core, func, vals=None):
    b = {"id": str(_id[0]), "execute": 1, "core": core, "function": func,
         "values": vals or [{}]}
    _id[0] += 1
    req = urllib.request.Request(
        f"https://{HOST}/cgi", json.dumps(b).encode(),
        {"Content-Type": "application/json"}, method="POST")
    try:
        with _opener.open(req, timeout=8) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

# Login to CGI
r = cgi("user", "login", [{"username": GW_EMAIL, "password": aes_enc(GW_PASS)}])
print(f"CGI login response: {r}")
if r.get("status") != 0:
    print(f"CGI login failed: {r}")
else:
    print("CGI logged in. Probing for config/file functions...\n")

    # Try functions that might expose MQTT config or read files
    probes = [
        ("system",   "get_mqtt_config",   [{}]),
        ("system",   "get_lns_config",    [{}]),
        ("system",   "get_config",        [{}]),
        ("system",   "read_file",         [{"path": "/etc/mosquitto/passwd"}]),
        ("system",   "read_file",         [{"file": "/etc/mosquitto/passwd"}]),
        ("system",   "read_file",         [{"path": "/etc/mosquitto/mosquitto.conf"}]),
        ("system",   "read_file",         [{"path": "/etc/chirpstack-network-server/chirpstack-network-server.toml"}]),
        ("system",   "read_file",         [{"path": "/etc/chirpstack-application-server/chirpstack-application-server.toml"}]),
        ("system",   "cat",               [{"path": "/etc/mosquitto/passwd"}]),
        ("system",   "cat",               [{"file": "/etc/mosquitto/passwd"}]),
        ("lns",      "get_config",        [{}]),
        ("lns",      "info",              [{}]),
        ("lns",      "get_mqtt",          [{}]),
        ("mqtt",     "get_config",        [{}]),
        ("mqtt",     "info",              [{}]),
        ("lorawan",  "get_config",        [{}]),
        ("lorawan",  "info",              [{}]),
        ("lorawan",  "get_forwarder",     [{}]),
        ("loraserver","get_config",       [{}]),
        ("forwarder","get_config",        [{}]),
        ("forwarder","info",              [{}]),
        # Try to enumerate available modules
        ("system",   "get_module_list",   [{}]),
        ("system",   "modules",           [{}]),
    ]
    for core, func, vals in probes:
        r = cgi(core, func, vals)
        status = r.get("status", "?")
        result = r.get("result", r.get("error", ""))
        if status == 0 and result:
            print(f"  ✓ {core}/{func} → {json.dumps(result)[:250]}")
        elif status not in (-1, "?") and "Object not found" not in str(result):
            print(f"  {core}/{func} → status={status}  {result}")
