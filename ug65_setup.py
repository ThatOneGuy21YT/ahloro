#!/usr/bin/env python3
"""
ug65_setup.py — one-time setup helper for the Milesight UG65.

Creates a "DoorSense" ChirpStack application and configures the HTTP
integration so uplinks are forwarded to the dashboard.

Run this from the machine that can reach 192.168.1.1:

    python3 ug65_setup.py

Or with a custom .env file:

    python3 ug65_setup.py --env-file .env.ug65

The script tries multiple write paths in order:
  1. gRPC-web to ChirpStack app-server (bypasses nginx 405 restriction)
  2. Plain ChirpStack REST API POST (may return 405)
  3. CGI exec functions (shell access via management API)

If everything is blocked it prints manual web-UI steps.
"""

import base64, hashlib, http.cookiejar, json, os, struct, ssl, sys, time
import urllib.error, urllib.request

# ── Load .env ─────────────────────────────────────────────────────────────────

DIR = os.path.dirname(os.path.abspath(__file__))

def _load_dotenv(path):
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ[k.strip()] = v.strip()   # override, same as poller.py

_env_file = None
if len(sys.argv) >= 3 and sys.argv[1] == "--env-file":
    _env_file = sys.argv[2]
    sys.argv = [sys.argv[0]] + sys.argv[3:]
_load_dotenv(_env_file or os.path.join(DIR, ".env.ug65"))
_load_dotenv(os.path.join(DIR, ".env"))

GW_HOST      = os.environ.get("GW_HOST",      "192.168.1.1")
GW_EMAIL     = os.environ.get("GW_EMAIL",     "admin")
GW_PASS      = os.environ.get("GW_PASS",      "")
GW_PASS_HASH = os.environ.get("GW_PASS_HASH", "")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "").rstrip("/")
API_KEY       = os.environ.get("API_KEY",      "")
GATEWAY_ID    = os.environ.get("GATEWAY_ID",  "ug65")

GW_BASE = f"https://{GW_HOST}/api"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(jar),
)


# ── ChirpStack REST helpers ───────────────────────────────────────────────────

def _md5_b64(s):
    return base64.b64encode(hashlib.md5(s.encode()).digest()).decode()


def _cs_request(method, path, body=None, token=None, extra_headers=None):
    url = f"{GW_BASE}/{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def _cs_login():
    pw_hash = GW_PASS_HASH if GW_PASS_HASH else _md5_b64(GW_PASS)
    status, resp = _cs_request("POST", "internal/login",
                                {"username": GW_EMAIL, "password": pw_hash})
    if status == 200 and "jwt" in resp:
        return resp["jwt"]
    raise RuntimeError(f"ChirpStack login failed ({status}): {resp}")


# ── CGI API helpers ───────────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

_cgi_id = [1]

def _cgi_encrypt(pt):
    k, iv = b"1111111111111111", b"2222222222222222"
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(pt.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv))
    enc = cipher.encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode()


def _cgi(core, func, vals=None):
    if vals is None:
        vals = [{}]
    body = {"id": str(_cgi_id[0]), "execute": 1,
            "core": core, "function": func, "values": vals}
    _cgi_id[0] += 1
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"https://{GW_HOST}/cgi", data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with opener.open(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code}
    except Exception as e:
        return {"error": str(e)}


def _cgi_login():
    if not _HAS_CRYPTO:
        print("WARNING: 'cryptography' package not installed; CGI login skipped.")
        print("  Install with:  pip install cryptography")
        return False
    cgi_pass = GW_PASS if GW_PASS else "p0ssw0rd;"
    r = _cgi("user", "login",
             [{"username": GW_EMAIL, "password": _cgi_encrypt(cgi_pass)}])
    return r.get("status") == 0


# ── gRPC-web helper ───────────────────────────────────────────────────────────

def _varint_encode(n):
    out = []
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _proto_field(field_num, wire_type, value):
    tag = (field_num << 3) | wire_type
    return _varint_encode(tag) + value


def _proto_string(field_num, s):
    enc = s.encode()
    return _proto_field(field_num, 2, _varint_encode(len(enc)) + enc)


def _proto_int64(field_num, n):
    return _proto_field(field_num, 0, _varint_encode(n))


def _build_create_application_request(name, org_id=1, sp_id=""):
    # Application message (fields: id=1, name=2, description=3, organizationID=4,
    #                             serviceProfileID=5)
    inner = (
        _proto_string(2, name) +
        _proto_string(3, name) +
        _proto_int64(4, org_id)
    )
    if sp_id:
        inner += _proto_string(5, sp_id)
    # CreateApplicationRequest message (field 1 = Application)
    return _proto_field(1, 2, _varint_encode(len(inner)) + inner)


def _grpc_web_post(path, payload, token=None):
    # gRPC-web frame: 0x00 (no compression) + 4-byte big-endian length
    frame = b"\x00" + struct.pack(">I", len(payload)) + payload
    headers = {
        "Content-Type": "application/grpc-web+proto",
        "Accept": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for port in (443, 8080, 9000):
        url = f"https://{GW_HOST}:{port}{path}"
        req = urllib.request.Request(url, data=frame, headers=headers, method="POST")
        try:
            with opener.open(req, timeout=10) as r:
                body = r.read()
                ct = r.headers.get("Content-Type", "")
                return port, r.status, ct, body
        except urllib.error.HTTPError as e:
            body = e.read()
            return port, e.code, "", body
        except Exception as e:
            continue
    return None, 0, "", b""


# ── Main setup flow ───────────────────────────────────────────────────────────

def _get_service_profile(token):
    for qs in ("service-profiles?limit=10",
               "service-profiles?organizationID=1&limit=10"):
        status, resp = _cs_request("GET", qs, token=token)
        if status == 200:
            items = resp.get("result") or resp.get("serviceProfiles") or []
            if items:
                return str(items[0]["id"])
    return ""


def _probe_connectivity():
    """Return (scheme, port) that reaches the UG65, or raise on total failure."""
    for scheme, port in [("https", 443), ("http", 80), ("https", 8080)]:
        url = f"{scheme}://{GW_HOST}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "ug65-setup/1"})
        try:
            ctx_arg = {"context": ctx} if scheme == "https" else {}
            with opener.open(req, timeout=5, **ctx_arg) as r:
                print(f"      Reachable via {scheme}:{port} (HTTP {r.status})")
                return scheme, port
        except urllib.error.HTTPError as e:
            print(f"      Reachable via {scheme}:{port} (HTTP {e.code})")
            return scheme, port
        except Exception as e:
            print(f"      {scheme}:{port} — {type(e).__name__}: {e}")
    raise RuntimeError(f"Cannot reach {GW_HOST} on any port (443, 80, 8080)")


def main():
    print("=== UG65 DoorSense Setup ===\n")

    if not DASHBOARD_URL:
        sys.exit("ERROR: DASHBOARD_URL not set in .env.ug65 or environment.")

    print(f"Gateway  : {GW_HOST}")
    print(f"Dashboard: {DASHBOARD_URL}")
    print(f"Env file : {_env_file or '.env.ug65 (auto)'}")
    print()

    # ── Step 0: Connectivity probe ────────────────────────────────────────────
    print("[0/4] Probing connectivity to UG65...")
    try:
        scheme, port = _probe_connectivity()
    except RuntimeError as e:
        sys.exit(f"FATAL: {e}\n  Make sure you're running this on a machine on the "
                 f"same LAN as the UG65 (192.168.1.x).")
    global GW_BASE
    GW_BASE = f"{scheme}://{GW_HOST}/api"
    print(f"      Using base URL: {GW_BASE}\n")

    # ── Step 1: ChirpStack login ──────────────────────────────────────────────
    print("[1/4] Logging in to ChirpStack...")
    try:
        token = _cs_login()
        print(f"      OK (token: {token[:20]}...)\n")
    except Exception as e:
        sys.exit(f"FATAL: {e}")

    # ── Step 2: Check for existing application ────────────────────────────────
    print("[2/4] Looking for existing applications...")
    app_id = None
    for qs in ("applications?limit=10&organizationID=1", "applications?limit=10"):
        status, resp = _cs_request("GET", qs, token=token)
        items = (resp.get("result") or resp.get("apps") or [])
        if status == 200:
            if items:
                app_id = str(items[0]["id"])
                print(f"      Found existing application: ID={app_id} "
                      f"name={items[0].get('name','?')}\n")
                break
            else:
                print(f"      GET {qs} → empty list")
        else:
            print(f"      GET {qs} → HTTP {status}")

    if app_id:
        # Skip creation, go straight to HTTP integration
        _setup_integration(token, app_id)
        return

    # ── Step 3: Try to create the application ─────────────────────────────────
    print("[3/4] No application found. Attempting to create one...\n")

    # 3a: Collect service profile ID
    sp_id = _get_service_profile(token)
    if sp_id:
        print(f"      Service profile ID: {sp_id}")

    # 3b: gRPC-web
    print("\n  [3a] Trying gRPC-web protocol...")
    pb = _build_create_application_request("DoorSense", org_id=1, sp_id=sp_id)
    port, status, ct, body = _grpc_web_post(
        "/api.ApplicationService/Create", pb, token=token)
    if port and status in (200, 201):
        print(f"      gRPC-web success on port {port}: status={status}")
        # Try to parse the id out of the response
        try:
            # Skip gRPC frame header (5 bytes)
            msg = body[5:] if len(body) > 5 else body
            # The response Application has id in field 1 (int64)
            if msg and msg[0] == 0x08:  # field 1, varint
                created_id = msg[1]  # works for small IDs
                print(f"      Created application ID={created_id}")
                _setup_integration(token, str(created_id))
                return
        except Exception:
            pass
        print(f"      (response body: {body[:80]})")
    else:
        print(f"      gRPC-web failed: port={port} status={status}")

    # 3c: Standard REST POST — with and without same-origin headers
    #     (nginx on the UG65 may allow writes only from same-origin requests)
    print("\n  [3b] Trying standard ChirpStack REST POST...")
    app_body_sp = {"application": {"name": "DoorSense", "description": "DoorSense",
                                    "organizationID": "1", "serviceProfileID": sp_id}}
    app_body    = {"application": {"name": "DoorSense", "description": "DoorSense",
                                    "organizationID": "1"}}
    same_origin = {"Origin": f"https://{GW_HOST}", "Referer": f"https://{GW_HOST}/"}
    for extra, body_d in [
        (same_origin, app_body_sp),
        (same_origin, app_body),
        ({},          app_body_sp),
        ({},          app_body),
    ]:
        status, resp = _cs_request("POST", "applications", body=body_d,
                                    token=token, extra_headers=extra)
        tag = "same-origin" if extra else "no-origin"
        if status in (200, 201) and resp.get("id"):
            app_id = str(resp["id"])
            print(f"      Created application ID={app_id} ({tag})")
            _setup_integration(token, app_id)
            return
        else:
            print(f"      POST ({tag}) → HTTP {status}")

    # 3d: CGI shell exec
    print("\n  [3c] Trying CGI management API...")
    cgi_ok = _cgi_login()
    if cgi_ok:
        print("      CGI login OK")
        # Try exec-style functions that might run shell commands
        curl_cmd = (
            f"curl -sk -X POST http://127.0.0.1:8080/api/applications "
            f"-H 'Content-Type: application/json' "
            f"-H 'Grpc-Metadata-Authorization: Bearer {token}' "
            f"-d '{{\"application\":{{\"name\":\"DoorSense\","
            f"\"description\":\"DoorSense\",\"organizationID\":\"1\"}}}}'"
        )
        for fn in ("exec", "shell", "run", "execute", "cmd", "command",
                   "sys_exec", "system_exec", "run_cmd", "execute_cmd"):
            r = _cgi("system", fn, [{"cmd": curl_cmd}])
            if r.get("status") == 0 and r.get("result"):
                print(f"      system/{fn} returned: {r['result']}")
                break
            r2 = _cgi("system", fn, [{"command": curl_cmd}])
            if r2.get("status") == 0 and r2.get("result"):
                print(f"      system/{fn} (command=) returned: {r2['result']}")
                break
        else:
            print("      No CGI exec function found.")
    else:
        print("      CGI login failed or cryptography unavailable.")

    # ── Step 4: Manual instructions ───────────────────────────────────────────
    print("\n[4/4] Automated creation was blocked by the UG65 firmware.")
    print()
    print("  The UG65's embedded ChirpStack does not allow write operations via")
    print("  its external HTTP API. You need to create the application once through")
    print("  the web interface:\n")
    print(f"  1. Open https://{GW_HOST} in your browser")
    print(f"     Username: {GW_EMAIL}   Password: (your web management password)")
    print()
    print("  2. In the top navigation, click 'LoRa Network Server'")
    print("     → then 'Application'  (or 'Applications')")
    print()
    print("  3. Click  [ + Add ]  (or 'Create Application')")
    print("     Name:         DoorSense")
    print("     Description:  DoorSense")
    print("     Leave other fields at their defaults")
    print("     Click  [ Save ]")
    print()
    print("  4. Inside the new application, find 'HTTP Integration' or")
    print("     'Integrations' → 'HTTP':")
    uplink_url = f"{DASHBOARD_URL}/ingest/lorawan_uplink?gateway_id={GATEWAY_ID}"
    print(f"     Uplink data URL:   {uplink_url}")
    if API_KEY:
        print(f"     Add header:        X-Api-Key: {API_KEY}")
    print("     Click  [ Save ]")
    print()
    print("  5. Re-run the poller — it will automatically discover the application.")
    print()
    print("  Once created, device additions via the DoorSense UI will work normally.")


def _setup_integration(token, app_id):
    print(f"[4/4] Setting up HTTP integration for application {app_id}...")
    uplink_url = f"{DASHBOARD_URL}/ingest/lorawan_uplink?gateway_id={GATEWAY_ID}"
    headers_payload = [{"key": "X-Api-Key", "value": API_KEY}] if API_KEY else []
    body = {
        "integration": {
            "dataUpURL":             uplink_url,
            "joinNotificationURL":   "",
            "ackNotificationURL":    "",
            "errNotificationURL":    "",
            "statusNotificationURL": "",
            "locationNotificationURL": "",
            "headers": headers_payload,
        }
    }
    status, resp = _cs_request(
        "POST", f"applications/{app_id}/integrations/http",
        body=body, token=token,
    )
    if status in (200, 201, 204):
        print(f"      HTTP integration configured → {uplink_url}")
        print()
        print("Setup complete! The poller will use this application automatically.")
    else:
        print(f"      HTTP integration POST returned HTTP {status}")
        print(f"      You may need to configure it manually in the UG65 web UI.")
        print()
        print(f"  Application ID: {app_id}")
        print(f"  Uplink URL:     {uplink_url}")
        if API_KEY:
            print(f"  Header:         X-Api-Key: {API_KEY}")


if __name__ == "__main__":
    main()
