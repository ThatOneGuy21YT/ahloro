#!/usr/bin/env python3
"""
DoorSense poller — runs locally, next to the LoRaWAN gateway.

Polls the DFRobot gateway and SIOT broker, decodes sensor payloads, and
forwards every event and device-list change to the remote dashboard server
via HTTP POST.  No database access; no HTTP server.

Configuration (env vars, or a .env file in the same directory):
  GW_HOST        IP of the LoRaWAN gateway          (default: 10.8.8.8)
  GW_EMAIL       Gateway admin email                (default: admin)
  GW_PASS        Gateway admin password
  SIOT_USER      SIOT broker username               (default: siot)
  SIOT_PASS      SIOT broker password
  DASHBOARD_URL  Full base URL of the dashboard     (required)
  API_KEY        Shared secret for ingest endpoints (required if set on dashboard)
"""

import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

import device_classifier

# ── Load .env ─────────────────────────────────────────────────────────────────

DIR = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv():
    path = os.path.join(DIR, ".env")
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())


_load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

GW_HOST  = os.environ.get("GW_HOST",  "10.8.8.8")
GW_BASE  = f"https://{GW_HOST}/api"
GW_EMAIL = os.environ.get("GW_EMAIL", "admin")
GW_PASS  = os.environ.get("GW_PASS",  "")

SIOT_BASE = f"http://{GW_HOST}:8080/api/v2"
SIOT_USER = os.environ.get("SIOT_USER", "siot")
SIOT_PASS = os.environ.get("SIOT_PASS", "dfrobot")

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "").rstrip("/")
if not DASHBOARD_URL:
    sys.exit("ERROR: DASHBOARD_URL is not set. Add it to .env or the environment.")

API_KEY = os.environ.get("API_KEY", "")

DEVICE_POLL_INTERVAL  = 1.0
DEVICE_STATUS_REFRESH = 5
ONLINE_TIMEOUT        = 900

_button_expire_seconds: float = 1.0

_gw_ssl = ssl.create_default_context()
_gw_ssl.check_hostname = False
_gw_ssl.verify_mode    = ssl.CERT_NONE

# ── Gateway helpers ───────────────────────────────────────────────────────────


def _gw_request(method, path, body=None, token=None):
    url     = f"{GW_BASE}/{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, context=_gw_ssl, timeout=15) as resp:
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
    """POST a JSON payload to the remote dashboard. Silently logs errors."""
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
        "last_new_data_at":    None,
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
        "online":              _is_online(ds),
        "label_active":        l0,
        "label_inactive":      l1,
        "device_type":         dtype,
        "device_type_display": device_classifier.get_display_name(dtype),
        "is_analog":           device_classifier.is_analog(dtype),
    }


def _post_devices_update():
    """Send the current device list and type map to the dashboard."""
    with _device_registry_lock:
        registry_snap = list(_device_registry)
    _post_to_dashboard("/ingest/devices", {
        "devices":      [_build_device_out(d) for d in registry_snap],
        "device_types": dict(_device_type_store),
    })


# ── Device initialisation ─────────────────────────────────────────────────────


def _gw_login() -> str:
    auth = _gw_request("POST", "internal/login", {"email": GW_EMAIL, "password": GW_PASS})
    return auth["jwt"]


def _fetch_gateway_devices() -> list:
    token = _gw_login()
    resp  = _gw_request("GET", "devices?limit=100&applicationID=1", token=token)
    return resp.get("result", [])


def _get_pending_gateway_deletions() -> list[str]:
    url     = f"{DASHBOARD_URL}/pending_gateway_deletions"
    headers = {}
    if API_KEY:
        headers["X-Api-Key"] = API_KEY
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read()).get("euids", [])
    except Exception as exc:
        print(f"GET pending_gateway_deletions error: {exc}", file=sys.stderr)
        return []


def _process_gateway_deletions():
    """Delete any dashboard-requested devices from the gateway, then confirm."""
    pending = _get_pending_gateway_deletions()
    if not pending:
        return
    try:
        token   = _gw_login()
        deleted = []
        for eui in pending:
            try:
                _gw_request("DELETE", f"devices/{eui}", token=token)
                _device_states.pop(eui, None)
                _device_type_store.pop(eui, None)
                deleted.append(eui)
                print(f"Gateway: deleted device {eui}")
            except Exception as exc:
                print(f"Gateway: delete {eui} failed: {exc}", file=sys.stderr)
        if deleted:
            _post_to_dashboard("/confirm_gateway_deletions", {"euids": deleted})
    except Exception as exc:
        print(f"Gateway deletion login error: {exc}", file=sys.stderr)


def _get_pending_gateway_additions() -> list:
    url     = f"{DASHBOARD_URL}/pending_gateway_additions"
    headers = {"X-Api-Key": API_KEY} if API_KEY else {}
    req     = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read()).get("additions", [])
    except Exception as exc:
        print(f"GET pending_gateway_additions error: {exc}", file=sys.stderr)
        return []


def _process_gateway_additions():
    """Create any dashboard-requested devices on the gateway, then confirm."""
    pending = _get_pending_gateway_additions()
    if not pending:
        return
    try:
        token = _gw_login()

        # Fetch available device profiles once
        prof_resp = _gw_request("GET", "device-profiles?applicationID=1&limit=100", token=token)
        profiles  = prof_resp.get("result", [])

        processed = []
        for addition in pending:
            eui  = addition.get("devEUI", "").upper()
            mode = addition.get("mode", "OTAA")
            name = addition.get("name", eui)
            try:
                # Pick profile: prefer one whose supportsJoin matches mode
                wants_join = (mode == "OTAA")
                profile_id = next(
                    (p["id"] for p in profiles if p.get("supportsJoin") == wants_join),
                    profiles[0]["id"] if profiles else None,
                )
                if not profile_id:
                    print(f"Gateway add {eui}: no device profiles configured", file=sys.stderr)
                    processed.append(eui)   # remove from queue; user must fix profile
                    continue

                _gw_request("POST", "devices", token=token, body={
                    "device": {
                        "applicationID": "1",
                        "devEUI":         eui,
                        "name":           name,
                        "deviceProfileID": profile_id,
                        "description":    "",
                        "skipFCntCheck":  False,
                    }
                })

                if mode == "OTAA":
                    app_key = addition.get("appKey", "")
                    keys    = {"devEUI": eui, "nwkKey": app_key, "appKey": app_key}
                    if addition.get("joinEUI"):
                        keys["appEUI"] = addition["joinEUI"]
                    _gw_request("POST", f"devices/{eui}/keys", token=token,
                                body={"deviceKeys": keys})
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
                processed.append(eui)   # confirm regardless so queue doesn't grow

        if processed:
            _post_to_dashboard("/confirm_gateway_additions", {"euids": processed})

    except Exception as exc:
        print(f"Gateway additions error: {exc}", file=sys.stderr)


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
    """Periodically refresh device list; notify dashboard of adds/removes."""
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
                    if eui in added_euids:
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
                threading.Thread(
                    target=device_poller_thread, args=(eui,),
                    daemon=True, name=f"poll-{eui}"
                ).start()
                print(f"Device added: {eui}")

            for eui in removed:
                _post_to_dashboard("/ingest/remove_device", {"devEUI": eui})
                print(f"Device removed: {eui}")

            _post_devices_update()

        except Exception as exc:
            print(f"device_status_refresh error: {exc}", file=sys.stderr)


# ── Button expiry ─────────────────────────────────────────────────────────────


def _button_expire_cb(dev_eui: str):
    """Fire a synthetic RELEASED event if no real gateway update beats the timer."""
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


# ── Per-device poller thread ──────────────────────────────────────────────────


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

            # ── Analog path ───────────────────────────────────────────────────
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

            # ── Binary path ───────────────────────────────────────────────────
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

        except Exception as exc:
            siot_token = None
            print(f"Poller [{dev_eui}]: {exc}", file=sys.stderr)

        time.sleep(DEVICE_POLL_INTERVAL)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_devices()
    _devices_ready.wait(timeout=15)

    with _device_registry_lock:
        startup_devices = list(_device_registry)

    for dev in startup_devices:
        threading.Thread(
            target=device_poller_thread, args=(dev["devEUI"].upper(),),
            daemon=True, name=f"poll-{dev['devEUI']}"
        ).start()

    threading.Thread(target=device_status_refresh, daemon=True).start()

    print(f"Poller running  →  {DASHBOARD_URL}")
    threading.Event().wait()   # block forever; all work is in daemon threads
