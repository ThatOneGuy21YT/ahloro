#!/usr/bin/env python3
"""
DoorSense poller — runs locally, next to the LoRaWAN gateway.

One poller instance per gateway.  Multiple pollers can share one dashboard.

Polls the gateway ChirpStack API for device management, decodes sensor payloads
(DFRobot type: via SIOT broker), and forwards events and device-list changes to
the remote dashboard server via HTTP POST.

Configuration (env vars, or a .env file in the same directory):
  GATEWAY_ID      Short unique name for this gateway (default: dfrobot)
  GW_DISPLAY_NAME Human-readable label shown in the UI (default: GATEWAY_ID)
  GW_TYPE         dfrobot | ug65  (default: dfrobot)
  GW_HOST         IP of the LoRaWAN gateway (default: 10.8.8.8)
  GW_EMAIL        ChirpStack admin email/username (default: admin)
  GW_PASS         ChirpStack admin password (plain text). For ug65 this is
                  the same password as the main web UI login — internal/login
                  expects it AES-CBC-encrypted (fixed key/iv, matching the
                  web UI's own CGI login), which poller.py does automatically.
  GW_STATIC_TOKEN ug65 only, optional fallback: a bearer JWT to use if
                  internal/login is ever unavailable — capture the "token"
                  cookie from an authenticated browser session on the web UI
  SIOT_USER       SIOT broker username (dfrobot only, default: siot)
  SIOT_PASS       SIOT broker password (dfrobot only)
  DASHBOARD_URL   Full base URL of the dashboard (required)
  API_KEY         Shared secret for ingest endpoints
"""

import base64
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import device_classifier

# ── Load .env ─────────────────────────────────────────────────────────────────

DIR = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv(path: str | None = None):
    if path is None:
        path = os.path.join(DIR, ".env")
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ[k.strip()] = v.strip()   # override, not setdefault


# Support --env-file <path> as first two args so multiple instances can share
# one script with different config files:
#   python3 poller.py --env-file .env.ug65
_env_file: str | None = None
if len(sys.argv) >= 3 and sys.argv[1] == "--env-file":
    _env_file = sys.argv[2]
    sys.argv = [sys.argv[0]] + sys.argv[3:]   # remove the two args

_load_dotenv(_env_file)

# ── Configuration ─────────────────────────────────────────────────────────────

GATEWAY_ID       = os.environ.get("GATEWAY_ID",       "dfrobot")
GW_DISPLAY_NAME  = os.environ.get("GW_DISPLAY_NAME",  GATEWAY_ID)
GW_TYPE          = os.environ.get("GW_TYPE",          "dfrobot")
GW_HOST          = os.environ.get("GW_HOST",          "10.8.8.8")
GW_EMAIL         = os.environ.get("GW_EMAIL",         "admin")
GW_PASS          = os.environ.get("GW_PASS",          "")
GW_STATIC_TOKEN  = os.environ.get("GW_STATIC_TOKEN",  "")   # ug65 only: bearer JWT fallback when internal/login is unavailable

GW_BASE = f"https://{GW_HOST}/api"

SIOT_BASE = f"http://{GW_HOST}:8080/api/v2"
SIOT_USER = os.environ.get("SIOT_USER", "siot")
SIOT_PASS = os.environ.get("SIOT_PASS", "dfrobot")

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "").rstrip("/")
if not DASHBOARD_URL:
    sys.exit("ERROR: DASHBOARD_URL is not set. Add it to .env or the environment.")

API_KEY = os.environ.get("API_KEY", "")

DEVICE_POLL_INTERVAL  = 1.0
DEVICE_STATUS_REFRESH = 0.5
ONLINE_TIMEOUT        = 900

_button_expire_seconds:    float = 1.0

_gw_ssl = ssl.create_default_context()
_gw_ssl.check_hostname = False
_gw_ssl.verify_mode    = ssl.CERT_NONE

# ── Gateway helpers ───────────────────────────────────────────────────────────


def _aes_enc(plaintext: str) -> str:
    """Encrypt with the UG65's fixed AES-CBC key/iv — the same scheme its own
    web UI uses for both the main CGI login and (per js/login.js's
    getToken()) the ChirpStack internal/login password. Not a secret key;
    it's hardcoded in the gateway's own JS."""
    key, iv = b"1111111111111111", b"2222222222222222"
    padder  = sym_padding.PKCS7(128).padder()
    padded  = padder.update(plaintext.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode()


def _gw_request(method, path, body=None, token=None):
    url     = f"{GW_BASE}/{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    # Only pass SSL context for HTTPS connections
    ctx = _gw_ssl if url.startswith("https://") else None
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def _siot_request(method, path, body=None, token=None):
    url     = f"{SIOT_BASE}/{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


# ── Dashboard HTTP helper ─────────────────────────────────────────────────────


def _post_to_dashboard(path: str, payload: dict):
    url     = f"{DASHBOARD_URL}{path}"
    data    = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-Api-Key"] = API_KEY
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except Exception as exc:
        print(f"POST {path} error: {exc}", file=sys.stderr)


def _get_from_dashboard(path: str) -> dict:
    url     = f"{DASHBOARD_URL}{path}"
    headers = {"X-Api-Key": API_KEY} if API_KEY else {}
    req     = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        print(f"GET {path} error: {exc}", file=sys.stderr)
        return {}


# ── Device type store ─────────────────────────────────────────────────────────

_device_type_store: dict[str, str] = {}


def _get_device_type(eui: str) -> str:
    return _device_type_store.get(eui.upper(), device_classifier.GENERIC)


def _classify_and_store(eui: str, name: str, raw_hex: str | None = None) -> str:
    dtype = device_classifier.classify_device(name, eui, raw_hex)
    _device_type_store[eui.upper()] = dtype
    return dtype


# ── Device registry ───────────────────────────────────────────────────────────

_device_registry      = []
_device_registry_lock = threading.Lock()
_devices_ready        = threading.Event()
_device_states: dict[str, dict] = {}


def _new_device_state() -> dict:
    return {
        "last_value":          None,
        "last_siot_ts":        None,
        "last_event_id":       None,   # for ug65 event dedup
        "last_new_data_at":    None,
        "ug65_last_seen_at":   None,   # tracks UG65 lastSeenAt for heartbeat detection
        "ug65_seen_fcnt":      {},     # devAddr -> highest uplink fCnt forwarded (dedup;
                                        # keyed per-session since a rejoin resets fCnt to 0)
        "ug65_primed":         False,  # True once the initial history baseline is set
        "button_expire_timer": None,
        "stats": {
            "opens": 0, "closes": 0, "holds": 0, "doubles": 0,
            "server_start": None, "last_change_ts": None,
            "min_value": None, "max_value": None,
            "sum_value": 0.0,   "count_value": 0,
        },
        "stats_lock": threading.Lock(),
    }


def _get_device_name(eui: str) -> str:
    with _device_registry_lock:
        for dev in _device_registry:
            if dev["devEUI"].upper() == eui:
                return dev.get("name", eui)
    return eui


def _is_online(ds: dict) -> bool:
    lnda = ds.get("last_new_data_at")
    return lnda is not None and (time.time() - lnda) < ONLINE_TIMEOUT


def _build_device_out(dev: dict) -> dict:
    eui   = dev["devEUI"].upper()
    ds    = _device_states.get(eui, {})
    dtype = _get_device_type(eui)
    l0, l1 = device_classifier.get_labels(dtype)
    return {
        **dev,
        "gateway_id":          GATEWAY_ID,
        "online":              _is_online(ds),
        "label_active":        l0,
        "label_inactive":      l1,
        "device_type":         dtype,
        "device_type_display": device_classifier.get_display_name(dtype),
        "is_analog":           device_classifier.is_analog(dtype),
    }


def _post_devices_update():
    with _device_registry_lock:
        registry_snap = list(_device_registry)
    _post_to_dashboard("/ingest/devices", {
        "gateway_id":    GATEWAY_ID,
        "gateway_name":  GW_DISPLAY_NAME,
        "devices":       [_build_device_out(d) for d in registry_snap],
        "device_types":  dict(_device_type_store),
    })


# ── Gateway login ─────────────────────────────────────────────────────────────


def _gw_login() -> str:
    if GW_TYPE == "ug65":
        # ChirpStack's internal/login on the UG65 expects the password
        # AES-CBC-encrypted with the gateway's fixed key/iv — the same
        # encoding its own web UI uses for the main login (see
        # js/login.js), not a password hash.
        auth = _gw_request("POST", "internal/login",
                            {"username": GW_EMAIL, "password": _aes_enc(GW_PASS)})
    else:
        auth = _gw_request("POST", "internal/login",
                            {"email": GW_EMAIL, "password": GW_PASS})
    return auth["jwt"]


# Cache the login token instead of re-logging in on every poll cycle: with
# internal/login broken (as it was during the UG65 credential investigation),
# calling _gw_login() every 0.5s would hammer the endpoint and re-trigger its
# lockout. We attempt a real login exactly once per process lifetime and fall
# back to GW_STATIC_TOKEN (a JWT captured from an already-authenticated
# browser session) if that attempt fails.
_cached_token: str | None = None
_token_lock   = threading.Lock()


def _get_token() -> str:
    global _cached_token
    with _token_lock:
        if _cached_token:
            return _cached_token
        try:
            _cached_token = _gw_login()
        except Exception as exc:
            if GW_TYPE == "ug65" and GW_STATIC_TOKEN:
                print(f"Gateway login failed ({exc}); using GW_STATIC_TOKEN fallback",
                      file=sys.stderr)
                _cached_token = GW_STATIC_TOKEN
            else:
                raise
        return _cached_token


# ── UG65 infrastructure setup ─────────────────────────────────────────────────

_ug65_app_id:        str | None = None
_ug65_app_lock       = threading.Lock()
_UG65_FAILED         = "__setup_failed__"   # sentinel: no app found this cycle
_ug65_no_app_warned  = 0.0                  # last time we printed the setup hint

# devEUIs the dashboard asked us to delete but the UG65's read-only ChirpStack
# API refused (404/405) to actually remove. Since the device stays in the
# gateway's own device list forever, we hide it ourselves so it doesn't keep
# reappearing on the dashboard after every device_status_refresh cycle.
_ug65_hidden_euis: set[str] = set()


def _ug65_get_list(resp: dict) -> list:
    return resp.get("result") or resp.get("devices") or resp.get("apps") or []


def _ug65_setup_http_integration(token: str, app_id: str):
    uplink_url = f"{DASHBOARD_URL}/ingest/lorawan_uplink?gateway_id={GATEWAY_ID}"
    integration_body = {
        "integration": {
            "dataUpURL":               uplink_url,
            "joinNotificationURL":      "",
            "ackNotificationURL":       "",
            "errNotificationURL":       "",
            "statusNotificationURL":    "",
            "locationNotificationURL":  "",
            "headers": [
                {"key": "X-Api-Key", "value": API_KEY},
            ] if API_KEY else [],
        }
    }

    # Check whether an HTTP integration already exists.
    try:
        existing = _gw_request("GET", f"applications/{app_id}/integrations/http",
                                token=token)
        current_url = (existing.get("integration") or existing).get("dataUpURL", "")
        if current_url == uplink_url:
            print(f"UG65: HTTP integration already configured → {uplink_url}")
            return
        # Wrong URL — try to update via PUT
        _gw_request("PUT", f"applications/{app_id}/integrations/http",
                    token=token, body=integration_body)
        print(f"UG65: HTTP integration updated → {uplink_url}")
        return
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            print(f"UG65: HTTP integration GET failed ({exc})", file=sys.stderr)

    # Integration doesn't exist — try to create it via POST
    try:
        _gw_request("POST", f"applications/{app_id}/integrations/http",
                    token=token, body=integration_body)
        print(f"UG65: HTTP integration created → {uplink_url}")
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 405):
            print(f"UG65: HTTP integration API is read-only (HTTP {exc.code}) — "
                  f"configure manually in the UG65 web UI:", file=sys.stderr)
            print(f"  Application {app_id} → HTTP Integration → Uplink URL: {uplink_url}",
                  file=sys.stderr)
        else:
            print(f"UG65: HTTP integration setup failed: {exc}", file=sys.stderr)
    except Exception as exc:
        print(f"UG65: HTTP integration setup failed: {exc}", file=sys.stderr)


def _ug65_ensure_infrastructure(token: str) -> str:
    """Return the UG65 ChirpStack application ID, or _UG65_FAILED if none exists.

    The UG65 firmware blocks write operations on its embedded ChirpStack API
    (POST /api/applications → 405).  The application must be created once via
    the web UI or by running ug65_setup.py.  Once it exists it is discovered
    here automatically on the next poll cycle.
    """
    global _ug65_app_id, _ug65_no_app_warned
    with _ug65_app_lock:
        if _ug65_app_id and _ug65_app_id != _UG65_FAILED:
            return _ug65_app_id
        _ug65_app_id = None   # always retry the GET each cycle

        # Check if an application already exists
        for qs in ("applications?limit=10&organizationID=1", "applications?limit=10"):
            try:
                resp = _gw_request("GET", qs, token=token)
                apps = _ug65_get_list(resp)
                if apps:
                    doorsense = next(
                        (a for a in apps if a.get("name", "").lower() == "doorsense"), None,
                    )
                    chosen = doorsense or apps[0]
                    _ug65_app_id = str(chosen["id"])
                    print(f"UG65: using existing application ID={_ug65_app_id} "
                          f"({chosen.get('name', '?')})")
                    _ug65_setup_http_integration(token, _ug65_app_id)
                    return _ug65_app_id
                break   # GET succeeded but empty — don't keep trying variants
            except Exception as exc:
                print(f"UG65: GET {qs} failed: {exc}", file=sys.stderr)
                continue

        # No application exists.  Print guidance at most once per 5 minutes.
        now = time.time()
        if now - _ug65_no_app_warned > 300:
            _ug65_no_app_warned = now
            print("UG65: no ChirpStack application found.", file=sys.stderr)
            print("  Run:  python3 ug65_setup.py --env-file .env.ug65", file=sys.stderr)
            print("  Or create an application named 'DoorSense' in the UG65 web UI",
                  file=sys.stderr)
            print(f"  at https://{GW_HOST}  → LoRa Network Server → Application",
                  file=sys.stderr)
        return _UG65_FAILED


# ── UG65 device add/delete via the "ur" web-UI API ────────────────────────────
#
# The stock ChirpStack REST paths (device-profiles, devices POST/keys/
# activation) are all blocked (404/405) on this firmware. The UG65 web UI's
# own "LoRa Network Server → Device" page instead calls a Milesight-specific
# API under /api/ur* (e.g. urpackets, urdevices) that IS writable. Captured
# from the browser: POST /api/urdevices to add, DELETE /api/urdevices/{eui}
# to remove — same Bearer-token auth as everything else.

def _ug65_get_ur_profiles(token: str) -> list:
    resp = _gw_request("GET", "urdevices?limit=1&offset=0&organizationID=1", token=token)
    return resp.get("profileResult") or []


def _ug65_match_ur_profile(profiles: list, wants_join: bool) -> str:
    """Return a profileID (UUID) matching the join mode, or '' if none fit."""
    candidates = [p for p in profiles if p.get("supportsJoin") == wants_join]
    if not candidates:
        return ""
    exact_name = "ClassA-OTAA" if wants_join else "ClassA-ABP"
    for p in candidates:
        if p.get("profileName") == exact_name:
            return p["profileID"]
    return candidates[0]["profileID"]


def _ug65_match_payload_codec(token: str, eui: str) -> str:
    """Look up the codec Milesight's own product database matches for this
    devEUI's OUI (e.g. "10"/WS101 for their own sensors). Falls back to "0"
    (no specific codec) for third-party devices — those require a real
    AppKey since isDefaultAppKey only works for recognized Milesight models."""
    resp = _gw_request("GET", f"payloadcodecs/{eui}/device", token=token)
    return str(resp.get("bestMatchID", "0"))


def _ug65_add_device_via_ur(token: str, app_id: str, addition: dict) -> None:
    """Add a device through the UG65's own web-UI API. Raises on failure —
    callers should fall back to printing manual instructions."""
    mode = addition.get("mode", "OTAA")
    if mode != "OTAA":
        raise NotImplementedError("urdevices ABP payload shape is unconfirmed")

    eui     = addition.get("devEUI", "").upper()
    name    = addition.get("name", eui)
    app_key = addition.get("appKey", "")

    profile_id = _ug65_match_ur_profile(_ug65_get_ur_profiles(token), wants_join=True)
    if not profile_id:
        raise RuntimeError("no matching OTAA device profile found")

    codec_id = _ug65_match_payload_codec(token, eui)
    if codec_id == "0" and not app_key:
        raise RuntimeError(
            f"{eui} isn't a recognized Milesight product — a real AppKey is "
            f"required (isDefaultAppKey only works for matched Milesight models)"
        )

    resp = _gw_request("POST", "urdevices", token=token, body={
        "name":            name,
        "description":     name,
        "devEUI":          eui,
        "profileID":       profile_id,
        "payloadCodecID":  codec_id,
        "isDefaultAppKey": not bool(app_key),
        "appKey":          app_key,
        "applicationID":   app_id,
        "skipFCntCheck":   True,
    })
    if resp.get("error"):
        raise RuntimeError(f"urdevices add rejected: {resp}")


# ── Device initialisation ─────────────────────────────────────────────────────


def _fetch_gateway_devices() -> list:
    token = _get_token()
    if GW_TYPE == "ug65":
        app_id = _ug65_ensure_infrastructure(token)
        if app_id == _UG65_FAILED:
            return []
        resp = _gw_request(
            "GET", f"devices?limit=100&applicationID={app_id}", token=token,
        )
        devices = _ug65_get_list(resp)
        if _ug65_hidden_euis:
            devices = [d for d in devices
                       if d.get("devEUI", "").upper() not in _ug65_hidden_euis]
        if not devices:
            # Show raw response keys so we can diagnose unexpected formats
            keys = list(resp.keys()) if isinstance(resp, dict) else repr(resp)[:80]
            total = resp.get("totalCount", "?") if isinstance(resp, dict) else "?"
            print(f"UG65: devices GET returned 0 — totalCount={total} keys={keys}",
                  file=sys.stderr)
        return devices
    else:
        resp = _gw_request("GET", "devices?limit=100&applicationID=1", token=token)
        return resp.get("result", [])


def _get_pending_gateway_deletions() -> list[str]:
    data = _get_from_dashboard(
        f"/pending_gateway_deletions?gateway_id={GATEWAY_ID}"
    )
    return data.get("euids", [])


def _ug65_print_manual_delete_steps(eui: str):
    print(f"UG65: ChirpStack API is read-only — remove device manually:", file=sys.stderr)
    print(f"  https://{GW_HOST}  → LoRa Network Server → Application → Device → {eui} → Delete",
          file=sys.stderr)


def _process_gateway_deletions():
    pending = _get_pending_gateway_deletions()
    if not pending:
        return
    try:
        token   = _get_token()
        deleted = []
        for eui in pending:
            delete_path = f"urdevices/{eui}" if GW_TYPE == "ug65" else f"devices/{eui}"
            try:
                _gw_request("DELETE", delete_path, token=token)
                _device_states.pop(eui, None)
                _device_type_store.pop(eui, None)
                deleted.append(eui)
                print(f"Gateway: deleted device {eui}")
            except urllib.error.HTTPError as exc:
                if GW_TYPE == "ug65" and exc.code in (404, 405):
                    # Fallback for anything the urdevices API itself won't
                    # remove — hide it locally so it stops reappearing on
                    # the dashboard even though it's still on the gateway.
                    _ug65_hidden_euis.add(eui)
                    _device_states.pop(eui, None)
                    _device_type_store.pop(eui, None)
                    _ug65_print_manual_delete_steps(eui)
                    deleted.append(eui)
                else:
                    print(f"Gateway: delete {eui} failed: {exc}", file=sys.stderr)
            except Exception as exc:
                print(f"Gateway: delete {eui} failed: {exc}", file=sys.stderr)
        if deleted:
            _post_to_dashboard("/confirm_gateway_deletions",
                               {"gateway_id": GATEWAY_ID, "euids": deleted})
    except Exception as exc:
        print(f"Gateway deletion login error: {exc}", file=sys.stderr)


def _get_pending_gateway_additions() -> list:
    data = _get_from_dashboard(
        f"/pending_gateway_additions?gateway_id={GATEWAY_ID}"
    )
    return data.get("additions", [])


def _process_gateway_additions():
    pending = _get_pending_gateway_additions()
    if not pending:
        return
    try:
        token = _get_token()

        if GW_TYPE == "ug65":
            _process_ug65_additions(token, pending)
        else:
            _process_dfrobot_additions(token, pending)

    except Exception as exc:
        print(f"Gateway additions error: {exc}", file=sys.stderr)


def _process_dfrobot_additions(token: str, pending: list):
    # Fetch full profile details (list endpoint omits macVersion)
    prof_list = _gw_request("GET", "device-profiles?applicationID=1&limit=100", token=token)
    profiles  = []
    for item in prof_list.get("result", []):
        try:
            detail = _gw_request("GET", f"device-profiles/{item['id']}", token=token)
            profiles.append(detail.get("deviceProfile", item))
        except Exception as exc:
            print(f"Gateway: profile detail {item['id']} failed: {exc}", file=sys.stderr)
            profiles.append(item)

    processed = []
    for addition in pending:
        eui          = addition.get("devEUI", "").upper()
        mode         = addition.get("mode", "OTAA")
        name         = addition.get("name", eui)
        lorawan_spec = addition.get("lorawanSpec", "")
        device_class = addition.get("deviceClass", "A")
        try:
            wants_join    = (mode == "OTAA")
            wants_class_c = (device_class == "C")

            def _profile_score(p):
                score = 0
                if p.get("supportsJoin") == wants_join:
                    score += 1000
                mac = p.get("macVersion", "")
                if mac and lorawan_spec:
                    if mac == lorawan_spec:
                        score += 100
                    else:
                        mp = mac.split(".")
                        sp = lorawan_spec.split(".")
                        if len(mp) >= 2 and len(sp) >= 2 and mp[:2] == sp[:2]:
                            score += 40
                        elif mp[:1] == sp[:1]:
                            score += 10
                if wants_class_c and p.get("supportsClassC"):
                    score += 20
                elif not wants_class_c and not p.get("supportsClassC"):
                    score += 20
                return score

            best = max(profiles, key=_profile_score) if profiles else None
            profile_id = best["id"] if best else None
            if not profile_id:
                print(f"Gateway add {eui}: no device profiles configured", file=sys.stderr)
                processed.append(eui)
                continue
            print(f"Gateway add {eui}: profile '{best.get('name')}' mac={best.get('macVersion')} join={best.get('supportsJoin')}")

            _gw_request("POST", "devices", token=token, body={
                "device": {
                    "applicationID":  "1",
                    "devEUI":          eui,
                    "name":            name,
                    "deviceProfileID": profile_id,
                    "description":     "",
                    "skipFCntCheck":   False,
                }
            })

            if mode == "OTAA":
                app_key  = addition.get("appKey", "")
                join_eui = addition.get("joinEUI") or "0000000000000000"
                print(f"Gateway add {eui}: OTAA joinEUI={join_eui} appKey={app_key[:8]}...")
                _gw_request("POST", f"devices/{eui}/keys", token=token, body={
                    "deviceKeys": {
                        "devEUI":  eui,
                        "appEUI":  join_eui,
                        "appEui":  join_eui,
                        "joinEUI": join_eui,
                        "nwkKey":  app_key,
                        "appKey":  app_key,
                    }
                })
            else:
                nwk = addition.get("nwkSKey", "")
                _gw_request("POST", f"devices/{eui}/activation", token=token, body={
                    "deviceActivation": {
                        "devEUI":        eui,
                        "devAddr":       addition.get("devAddr", ""),
                        "appSKey":       addition.get("appSKey", ""),
                        "nwkSKey":       nwk,
                        "fNwkSIntKey":   nwk,
                        "sNwkSIntKey":   nwk,
                        "nwkSessionKey": nwk,
                    }
                })

            print(f"Gateway: added device '{name}' ({eui}) [{mode}]")
        except Exception as exc:
            print(f"Gateway: add {eui} failed: {exc}", file=sys.stderr)
        finally:
            processed.append(eui)

    if processed:
        _post_to_dashboard("/confirm_gateway_additions",
                           {"gateway_id": GATEWAY_ID, "euids": processed})


def _process_ug65_additions(token: str, pending: list):
    app_id = _ug65_ensure_infrastructure(token)
    if app_id == _UG65_FAILED:
        print("UG65: skipping device additions — infrastructure not ready", file=sys.stderr)
        return
    processed = []

    for addition in pending:
        eui  = addition.get("devEUI", "").upper()
        mode = addition.get("mode", "OTAA")
        name = addition.get("name", eui)
        try:
            _ug65_add_device_via_ur(token, app_id, addition)
            print(f"UG65: added device '{name}' ({eui}) [{mode}] via urdevices API")
        except Exception as exc:
            print(f"UG65: automated add for {eui} failed ({exc}) — manual steps required:",
                  file=sys.stderr)
            _ug65_print_manual_device_steps(addition, app_id)
        finally:
            # Always confirm so the pending queue clears regardless. If the
            # automated add failed, the user still needs to register it
            # manually — see the printed instructions above.
            processed.append(eui)

    if processed:
        _post_to_dashboard("/confirm_gateway_additions",
                           {"gateway_id": GATEWAY_ID, "euids": processed})


def _ug65_print_manual_device_steps(addition: dict, app_id: str):
    eui      = addition.get("devEUI", "").upper()
    name     = addition.get("name", eui)
    mode     = addition.get("mode", "OTAA")
    print(f"UG65: ChirpStack API is read-only — add device manually:", file=sys.stderr)
    print(f"  https://{GW_HOST}  → LoRa Network Server → Application {app_id} → Device",
          file=sys.stderr)
    print(f"  Name:   {name}", file=sys.stderr)
    print(f"  DevEUI: {eui}", file=sys.stderr)
    if mode == "OTAA":
        app_key  = addition.get("appKey", "")
        join_eui = addition.get("joinEUI") or "0000000000000000"
        print(f"  Mode:    OTAA", file=sys.stderr)
        print(f"  JoinEUI: {join_eui}", file=sys.stderr)
        print(f"  AppKey:  {app_key}", file=sys.stderr)
    else:
        print(f"  Mode:    ABP", file=sys.stderr)
        print(f"  DevAddr: {addition.get('devAddr', '')}", file=sys.stderr)
        print(f"  NwkSKey: {addition.get('nwkSKey', '')}", file=sys.stderr)
        print(f"  AppSKey: {addition.get('appSKey', '')}", file=sys.stderr)


def init_devices():
    try:
        devices = _fetch_gateway_devices()
    except Exception as exc:
        print(f"init_devices error: {exc}", file=sys.stderr)
        devices = []

    with _device_registry_lock:
        _device_registry.clear()
        _device_registry.extend(devices)

    for dev in devices:
        eui = dev["devEUI"].upper()
        if eui not in _device_states:
            _device_states[eui] = _new_device_state()
        if eui not in _device_type_store:
            _classify_and_store(eui, dev.get("name", eui))

    _post_devices_update()
    print(f"Devices loaded ({len(devices)}): {[d['name'] for d in devices]}")
    _devices_ready.set()


# ── Device status refresh ─────────────────────────────────────────────────────


def device_status_refresh():
    while True:
        time.sleep(DEVICE_STATUS_REFRESH)
        try:
            _process_gateway_deletions()
            _process_gateway_additions()
            fresh       = _fetch_gateway_devices()
            fresh_euids = {d["devEUI"].upper() for d in fresh}

            added   = []
            removed = []
            with _device_registry_lock:
                current_euids = {d["devEUI"].upper() for d in _device_registry}
                removed_euids = current_euids - fresh_euids
                added_euids   = fresh_euids   - current_euids

                by_eui = {d["devEUI"].upper(): d for d in _device_registry}
                for dev in fresh:
                    eui = dev["devEUI"].upper()
                    by_eui[eui] = dev
                    # Recreate state whenever it's actually missing, not just
                    # on a registry-membership change — a delete+re-add that
                    # lands in the same poll cycle never registers as a
                    # membership change (the device never "left" the
                    # registry from this diff's perspective) even though
                    # _process_gateway_deletions() already popped its state.
                    if eui in added_euids or eui not in _device_states:
                        _device_states[eui] = _new_device_state()
                        if eui not in _device_type_store:
                            _classify_and_store(eui, dev.get("name", eui))
                        added.append(eui)
                for eui in removed_euids:
                    by_eui.pop(eui, None)
                    _device_states.pop(eui, None)
                    removed.append(eui)
                _device_registry.clear()
                _device_registry.extend(by_eui.values())

            for eui in added:
                if GW_TYPE != "ug65":
                    threading.Thread(
                        target=device_poller_thread, args=(eui,),
                        daemon=True, name=f"poll-{eui}"
                    ).start()
                print(f"Device added: {eui}")

            for eui in removed:
                _post_to_dashboard("/ingest/remove_device", {"devEUI": eui})
                print(f"Device removed: {eui}")

            # UG65: detect lastSeenAt changes and send heartbeats so devices
            # show online promptly. Actual events (with real hex payloads)
            # come from ug65_packets_poller() via /api/urpackets.
            if GW_TYPE == "ug65":
                now_ug65 = time.time()
                for dev in fresh:
                    eui      = dev["devEUI"].upper()
                    new_seen = dev.get("lastSeenAt")
                    if not new_seen:
                        continue
                    ds = _device_states.get(eui)
                    if ds is None:
                        continue
                    if new_seen == ds.get("ug65_last_seen_at"):
                        continue
                    ds["ug65_last_seen_at"] = new_seen
                    ds["last_new_data_at"]  = now_ug65
                    print(f"UG65: {eui} lastSeen → {new_seen}")
                    _post_to_dashboard(
                        f"/ingest/lorawan_uplink?gateway_id={GATEWAY_ID}",
                        {"devEUI": eui},
                    )

            _post_devices_update()

        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                # Cached token went bad (e.g. the gateway rebooted and reset
                # its session) — force a fresh login attempt next cycle.
                global _cached_token
                _cached_token = None
            print(f"device_status_refresh error: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"device_status_refresh error: {exc}", file=sys.stderr)


# ── UG65 raw packet polling ───────────────────────────────────────────────────
#
# The UG65's ChirpStack HTTP integration is read-only on this firmware (POST
# .../integrations/http → 405), so it can't be configured to push uplinks to
# the dashboard. Instead we poll the UG65's own web-UI "Packets" endpoint
# (/api/urpackets — the same call its "LoRa Network Server → Packets" page
# makes) and forward new uplinks to the dashboard ourselves, mimicking what
# the HTTP integration would have sent.

_UG65_PACKETS_POLL_INTERVAL = 1.0
_UG65_ORG_ID                = "1"


def _ug65_fetch_packets(token: str, limit: int = 20) -> list:
    resp = _gw_request(
        "GET", f"urpackets?offset=0&limit={limit}&organizationID={_UG65_ORG_ID}",
        token=token,
    )
    return resp.get("packets") or []   # .get(..., []) alone won't catch an explicit null


def ug65_packets_poller():
    global _cached_token
    while True:
        time.sleep(_UG65_PACKETS_POLL_INTERVAL)
        try:
            _ug65_packets_poll_once()
        except Exception as exc:
            # Never let one bad cycle kill this thread permanently — it runs
            # unsupervised as a daemon thread, so an uncaught exception here
            # would silently stop all future UG65 event forwarding while
            # device_status_refresh() keeps running fine in its own thread.
            print(f"UG65 packets: poll cycle failed: {exc}", file=sys.stderr)


def _ug65_packets_poll_once():
    global _cached_token
    try:
        token = _get_token()
    except Exception as exc:
        print(f"UG65 packets: no token available: {exc}", file=sys.stderr)
        return

    try:
        packets = _ug65_fetch_packets(token)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            _cached_token = None   # force a fresh login attempt next cycle
        print(f"UG65 packets: fetch failed ({exc})", file=sys.stderr)
        return
    except Exception as exc:
        print(f"UG65 packets: fetch failed ({exc})", file=sys.stderr)
        return

    now = time.time()
    _ug65_prime_new_devices(packets)
    # The endpoint returns newest-first; walk oldest-first so fCnt dedup
    # advances in order.
    for pkt in reversed(packets):
        try:
            _ug65_handle_packet(pkt, now)
        except Exception as exc:
            print(f"UG65 packets: failed to process packet ({exc}): {pkt}", file=sys.stderr)


def _ug65_prime_new_devices(packets: list):
    """The first time we see any packets for a given device in this process's
    lifetime, treat everything currently in the fetch window as history and
    mark it all "already seen" instead of forwarding it — the window can
    span several old join sessions (devAddrs) from earlier testing/rejoins,
    and only priming the device's *current* devAddr would let all those
    other old sessions replay as fresh events."""
    by_eui: dict[str, list] = {}
    for pkt in packets:
        eui = (pkt.get("devEUI") or "").upper()
        by_eui.setdefault(eui, []).append(pkt)

    for eui, pkts in by_eui.items():
        ds = _device_states.get(eui)
        if ds is None or ds.get("ug65_primed"):
            continue
        seen = ds["ug65_seen_fcnt"]
        for pkt in pkts:
            if not str(pkt.get("type", "")).startswith("Up"):
                continue
            dev_addr = pkt.get("devAddr") or ""
            try:
                fcnt = int(pkt.get("fCnt"))
            except (TypeError, ValueError):
                continue
            seen[dev_addr] = max(seen.get(dev_addr, -1), fcnt)
        ds["ug65_primed"] = True


def _ug65_handle_packet(pkt: dict, now: float):
    if not str(pkt.get("type", "")).startswith("Up"):
        return   # downlinks / acks carry no application payload
    raw_hex = pkt.get("payloadHex") or ""
    if not raw_hex:
        return

    eui = (pkt.get("devEUI") or "").upper()
    ds  = _device_states.get(eui)
    if ds is None:
        return

    try:
        fcnt = int(pkt.get("fCnt"))
    except (TypeError, ValueError):
        return
    dev_addr = pkt.get("devAddr") or ""
    seen     = ds["ug65_seen_fcnt"]
    if fcnt <= seen.get(dev_addr, -1):
        return   # already forwarded for this session

    seen[dev_addr]         = fcnt
    ds["last_new_data_at"] = now

    body = {
        "devEUI": eui,
        "data":   base64.b64encode(bytes.fromhex(raw_hex)).decode(),
    }
    fport = pkt.get("fPort")
    if fport not in (None, "-", ""):
        try:
            body["fPort"] = int(fport)
        except ValueError:
            pass

    _post_to_dashboard(f"/ingest/lorawan_uplink?gateway_id={GATEWAY_ID}", body)
    print(f"UG65: {eui} fCnt={fcnt} hex={raw_hex}")


# ── Button expiry ─────────────────────────────────────────────────────────────


def _button_expire_cb(dev_eui: str):
    ds = _device_states.get(dev_eui)
    if ds is None:
        return
    now = time.time()
    with ds["stats_lock"]:
        if ds["last_value"] != 0:
            return
        ds["last_value"] = 1
        ds["stats"]["closes"] += 1
        ds["stats"]["last_change_ts"] = now
        stats_snap = dict(ds["stats"])
    _post_to_dashboard("/ingest/event", {
        "devEUI":      dev_eui,
        "device_type": device_classifier.BUTTON,
        "value":       1,
        "timestamp":   now,
        "stats":       stats_snap,
    })


# ── Per-device poller thread (DFRobot / SIOT only) ───────────────────────────


def device_poller_thread(dev_eui: str):
    siot_token = None

    while True:
        if dev_eui not in _device_states:
            return

        try:
            if siot_token is None:
                auth       = _siot_request("POST", "login",
                                            {"username": SIOT_USER, "password": SIOT_PASS})
                siot_token = auth["data"]["token"]

            ds = _device_states.get(dev_eui)
            if ds is None:
                return

            resp = _siot_request(
                "POST", "messages/getMsgByTopic?length=1",
                body={"topic": f"siot/lora/{dev_eui}/raw"},
                token=siot_token,
            )
            messages = (resp.get("data") or {}).get("messages") or []
            if not messages:
                time.sleep(DEVICE_POLL_INTERVAL)
                continue

            msg     = messages[0]
            raw_hex = msg["content"]
            siot_ts = msg["timestamp"]
            now     = time.time()

            if siot_ts == ds["last_siot_ts"]:
                time.sleep(DEVICE_POLL_INTERVAL)
                continue

            ds["last_siot_ts"]     = siot_ts
            ds["last_new_data_at"] = now

            dtype = _get_device_type(dev_eui)
            if dtype == device_classifier.GENERIC:
                name      = _get_device_name(dev_eui)
                new_dtype = device_classifier.classify_device(name, dev_eui, raw_hex)
                if new_dtype != device_classifier.GENERIC:
                    _device_type_store[dev_eui] = new_dtype
                    dtype = new_dtype
                    _post_devices_update()
                    print(f"Reclassified {dev_eui} → {new_dtype}")

            decoded = device_classifier.decode_payload(dtype, dev_eui, raw_hex)
            _handle_decoded_event(dev_eui, dtype, decoded, now)

        except Exception as exc:
            siot_token = None
            print(f"Poller [{dev_eui}]: {exc}", file=sys.stderr)

        time.sleep(DEVICE_POLL_INTERVAL)


def _handle_decoded_event(dev_eui: str, dtype: str, decoded: dict, now: float):
    """Shared event handling for both DFRobot (SIOT) and UG65 paths."""
    ds = _device_states.get(dev_eui)
    if ds is None:
        return

    if device_classifier.is_analog(dtype):
        rv    = decoded.get("raw_value")
        event = {
            "devEUI":      dev_eui,
            "device_type": dtype,
            "timestamp":   now,
            "raw_value":   rv,
            "unit":        decoded.get("unit"),
        }
        if decoded.get("extra"):
            event["extra"] = decoded["extra"]

        if rv is not None:
            with ds["stats_lock"]:
                st = ds["stats"]
                if st["server_start"] is None:
                    st["server_start"] = now
                if st["min_value"] is None or rv < st["min_value"]:
                    st["min_value"] = rv
                if st["max_value"] is None or rv > st["max_value"]:
                    st["max_value"] = rv
                st["sum_value"]   = st.get("sum_value", 0.0) + rv
                st["count_value"] = st.get("count_value", 0) + 1
                event["stats"] = dict(st)

        _post_to_dashboard("/ingest/event", event)

    else:
        val   = decoded["value"]
        event = {
            "devEUI":      dev_eui,
            "device_type": dtype,
            "value":       val,
            "timestamp":   now,
        }
        if decoded.get("extra"):
            event["extra"] = decoded["extra"]

        is_button = (dtype == device_classifier.BUTTON)
        changed   = (val != ds["last_value"])

        if is_button:
            old_timer = ds["button_expire_timer"]
            if old_timer is not None:
                old_timer.cancel()
                ds["button_expire_timer"] = None

        if changed:
            ds["last_value"] = val

        if changed or is_button:
            with ds["stats_lock"]:
                if ds["stats"]["server_start"] is None:
                    ds["stats"]["server_start"] = now
                if val == 0:
                    ds["stats"]["opens"] += 1
                    ev_extra = event.get("extra", {})
                    if ev_extra.get("held"):
                        ds["stats"]["holds"] += 1
                    elif ev_extra.get("double"):
                        ds["stats"]["doubles"] += 1
                elif changed:
                    ds["stats"]["closes"] += 1
                ds["stats"]["last_change_ts"] = now
                event["stats"] = dict(ds["stats"])

            if is_button and val == 0:
                t = threading.Timer(_button_expire_seconds,
                                    _button_expire_cb, args=[dev_eui])
                t.daemon = True
                t.start()
                ds["button_expire_timer"] = t

        _post_to_dashboard("/ingest/event", event)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Poller starting: gateway_id={GATEWAY_ID} type={GW_TYPE} host={GW_HOST}")
    init_devices()
    _devices_ready.wait(timeout=15)

    if GW_TYPE != "ug65":
        # DFRobot: start per-device SIOT polling threads
        with _device_registry_lock:
            startup_devices = list(_device_registry)

        for dev in startup_devices:
            threading.Thread(
                target=device_poller_thread, args=(dev["devEUI"].upper(),),
                daemon=True, name=f"poll-{dev['devEUI']}"
            ).start()
    else:
        print("UG65 mode: polling /api/urpackets for real uplink payloads")
        threading.Thread(target=ug65_packets_poller, daemon=True, name="ug65-packets").start()

    threading.Thread(target=device_status_refresh, daemon=True).start()

    print(f"Poller running  →  {DASHBOARD_URL}  (gateway: {GATEWAY_ID})")
    threading.Event().wait()
