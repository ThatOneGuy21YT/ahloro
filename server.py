#!/usr/bin/env python3
"""
LoRaWAN Dashboard — multi-device SSE streaming server.

Architecture:
  init_devices()             — Fetches the full device list from the gateway at
                               startup; spawns one poller thread per device.
  device_poller_thread(eui)  — Polls siot for one device's latest raw message,
                               decodes it via device_classifier, and broadcasts
                               SSE events. Binary sensors broadcast on transition
                               and steady-state; analog sensors broadcast every
                               reading with the full numeric value.
  device_status_refresh()    — Periodically re-fetches the device list to keep
                               battery / lastSeenAt / device type current.
  midnight_scheduler         — Appends a daily transition table to each log file.
  Handler                    — HTTP: static files, /events SSE, /devices JSON,
                               /add_device, /delete_device, /set_device_type POST.

SSE event protocol:
  On connect  → {"devices": [...], "history_by_device": {eui: [...]},
                 "stats_by_device": {eui: {...}}}
  Binary live → {"devEUI": "...", "device_type": "door", "value": 0|1,
                 "timestamp": float}
  Binary tran → {..., "stats": {...}}
  Analog live → {"devEUI": "...", "device_type": "temperature", "raw_value": 23.5,
                 "unit": "°C", "timestamp": float, ["extra": {...}], ["stats": {...}]}
  Dev update  → {"devices_update": [...]}
"""

import datetime
import decimal
import json
import os
import queue
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg2
import psycopg2.extras
import psycopg2.pool

import device_classifier


class _Encoder(json.JSONEncoder):
    """Extend the default encoder to handle types psycopg2 can return."""
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return float(o)
        return super().default(o)


def _json_dumps(obj) -> str:
    return json.dumps(obj, cls=_Encoder)


# ── Gateway / siot credentials ────────────────────────────────────────────────
GW_HOST  = "https://https://guided-prep-expects-src.trycloudflare.com"
GW_BASE  = f"https://{GW_HOST}/api"
GW_EMAIL = "admin"
GW_PASS  = "p0ssw0rd;"

SIOT_BASE = f"https://shoe-stability-pct-considerable.trycloudflare.com/api/v2"
SIOT_USER = "siot"
SIOT_PASS = "dfrobot"

_gw_ssl = ssl.create_default_context()
_gw_ssl.check_hostname = False
_gw_ssl.verify_mode    = ssl.CERT_NONE

DEVICE_POLL_INTERVAL   = 1.0    # seconds between per-device siot polls
DEVICE_STATUS_REFRESH  = 5      # seconds between gateway device-list refreshes
ONLINE_TIMEOUT         = 900    # 15 min: server seconds since last new siot msg

# Button press expiry — seconds after a press before a synthetic release is fired.
# Configurable at runtime via POST /set_button_expire_seconds.
_button_expire_seconds: float = 1.0


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


def _gw_add_device(payload: dict) -> dict:
    auth  = _gw_request("POST", "internal/login", {"email": GW_EMAIL, "password": GW_PASS})
    token = auth["jwt"]
    mode  = payload.pop("mode")
    return _gw_request("POST", "devices", {mode: payload}, token=token)


def _siot_request(method, path, body=None, token=None):
    url     = f"{SIOT_BASE}/{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


# ── Path constants ────────────────────────────────────────────────────────────
DIR      = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(DIR, "logs")
PORT     = 8765

def _load_dotenv():
    """Load .env file from project directory into os.environ if present."""
    env_path = os.path.join(DIR, ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

_load_dotenv()

DB_DSN = os.environ.get("DATABASE_URL")
if not DB_DSN:
    sys.exit("ERROR: DATABASE_URL environment variable is not set. Copy .env.example to .env and fill in your credentials.")


def _device_log_path(name: str, eui: str) -> str:
    safe = re.sub(r"[^\w\-]", "_", name)
    return os.path.join(LOGS_DIR, f"{safe}_{eui[-8:]}.log")


# ── PostgreSQL connection pool ─────────────────────────────────────────────────

_db_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def _db_connect():
    global _db_pool
    _db_pool = psycopg2.pool.ThreadedConnectionPool(1, 10, dsn=DB_DSN)
    print(f"Database connected: {DB_DSN.split('@')[-1]}")


def _db_execute(sql: str, params=None, fetch: bool = False):
    conn = _db_pool.getconn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                if fetch:
                    return cur.fetchall()
    finally:
        _db_pool.putconn(conn)


def _init_db():
    """Create database tables if they don't exist."""
    _db_execute("""
        CREATE TABLE IF NOT EXISTS device_table_map (
            dev_eui     TEXT PRIMARY KEY,
            table_name  TEXT NOT NULL,
            device_name TEXT
        )
    """)
    _db_execute("""
        CREATE TABLE IF NOT EXISTS device_stats (
            dev_eui        TEXT PRIMARY KEY,
            opens          INTEGER NOT NULL DEFAULT 0,
            closes         INTEGER NOT NULL DEFAULT 0,
            holds          INTEGER NOT NULL DEFAULT 0,
            doubles        INTEGER NOT NULL DEFAULT 0,
            server_start   DOUBLE PRECISION,
            last_change_ts DOUBLE PRECISION,
            min_value      DOUBLE PRECISION,
            max_value      DOUBLE PRECISION,
            sum_value      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            count_value    INTEGER NOT NULL DEFAULT 0
        )
    """)
    _db_execute("""
        CREATE TABLE IF NOT EXISTS device_types (
            dev_eui     TEXT PRIMARY KEY,
            device_type TEXT NOT NULL
        )
    """)
    _db_execute("""
        CREATE TABLE IF NOT EXISTS app_config (
            key   TEXT PRIMARY KEY,
            value JSONB NOT NULL
        )
    """)
    print("Database schema ready.")


# ── Per-device table management ───────────────────────────────────────────────

_device_tables: dict[str, str] = {}   # EUI → table name cache


def _table_name_for_device(name: str, eui: str) -> str:
    """Derive a safe PostgreSQL table name from a device name."""
    safe = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if not safe or safe[0].isdigit():
        safe = f"dev_{safe}"
    base = safe[:50] or "device"
    # Append last-4 of EUI if name is already used by another device
    if base in _device_tables.values():
        base = f"{base[:45]}_{eui[-4:].lower()}"
    return base


def _ensure_device_table(dev_eui: str) -> str:
    """Return the table name for a device, creating it in PostgreSQL if needed."""
    table = _device_tables.get(dev_eui)
    if table:
        return table

    # Check the persistent mapping first (handles restarts)
    rows = _db_execute(
        "SELECT table_name FROM device_table_map WHERE dev_eui = %s",
        (dev_eui,), fetch=True,
    )
    if rows:
        _device_tables[dev_eui] = rows[0][0]
        return rows[0][0]

    # New device — derive a table name and create the table
    name  = _get_device_name(dev_eui)
    table = _table_name_for_device(name, dev_eui)

    _db_execute(f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id          BIGSERIAL PRIMARY KEY,
            recorded_at TIMESTAMPTZ NOT NULL,
            device_type TEXT NOT NULL,
            value       INTEGER,
            raw_value   DOUBLE PRECISION,
            unit        TEXT,
            extra       JSONB
        )
    """)
    _db_execute(
        f"CREATE INDEX IF NOT EXISTS idx_{table}_ts ON {table} (recorded_at DESC)"
    )
    _db_execute(
        "INSERT INTO device_table_map (dev_eui, table_name, device_name) "
        "VALUES (%s, %s, %s) ON CONFLICT (dev_eui) DO NOTHING",
        (dev_eui, table, name),
    )
    print(f"Created device table: {table} for {dev_eui}")

    _device_tables[dev_eui] = table
    return table


def _remove_device_from_db(dev_eui: str):
    """Drop the device's event table and remove all its rows from support tables."""
    try:
        table = _device_tables.pop(dev_eui, None)
        if table is None:
            rows = _db_execute(
                "SELECT table_name FROM device_table_map WHERE dev_eui = %s",
                (dev_eui,), fetch=True,
            )
            table = rows[0][0] if rows else None

        if table:
            _db_execute(f"DROP TABLE IF EXISTS {table}")
            print(f"Dropped device table: {table}")

        _db_execute("DELETE FROM device_table_map WHERE dev_eui = %s", (dev_eui,))
        _db_execute("DELETE FROM device_stats   WHERE dev_eui = %s", (dev_eui,))
        _db_execute("DELETE FROM device_types   WHERE dev_eui = %s", (dev_eui,))
        _device_type_store.pop(dev_eui, None)
    except Exception as exc:
        print(f"DB remove_device error [{dev_eui}]: {exc}", file=sys.stderr)


# ── Device type store ─────────────────────────────────────────────────────────
_device_type_store: dict[str, str] = {}   # EUI (upper) → device type string


def _get_device_type(eui: str) -> str:
    return _device_type_store.get(eui.upper(), device_classifier.GENERIC)


def _classify_and_store(eui: str, name: str, raw_hex: str | None = None) -> str:
    dtype = device_classifier.classify_device(name, eui, raw_hex)
    _device_type_store[eui.upper()] = dtype
    return dtype


def _device_label(dev_eui: str) -> tuple[str, str]:
    return device_classifier.get_labels(_get_device_type(dev_eui))


def _get_device_name(eui: str) -> str:
    with _device_registry_lock:
        for dev in _device_registry:
            if dev["devEUI"].upper() == eui:
                return dev.get("name", eui)
    return eui


# ── Device registry ───────────────────────────────────────────────────────────
_device_registry      = []
_device_registry_lock = threading.Lock()
_devices_ready        = threading.Event()

_device_states: dict[str, dict] = {}


def _new_device_state() -> dict:
    return {
        "history":          deque(maxlen=1000),
        "history_lock":     threading.Lock(),
        "transitions":      [],
        "transitions_lock": threading.Lock(),
        "stats": {
            "opens":         0,
            "closes":        0,
            "holds":         0,
            "doubles":       0,
            "server_start":  None,
            "last_change_ts":None,
            "min_value":     None,   # analog only
            "max_value":     None,   # analog only
            "sum_value":     0.0,    # analog only
            "count_value":   0,      # analog only
        },
        "stats_lock":        threading.Lock(),
        "last_value":          None,
        "last_siot_ts":        None,
        "last_new_data_at":    None,
        "button_expire_timer": None,   # threading.Timer that fires a synthetic release
    }


# ── SSE client registry ───────────────────────────────────────────────────────
_clients_lock = threading.Lock()
_clients: list[queue.Queue] = []


def broadcast(event: dict):
    with _clients_lock:
        dead = []
        for q in _clients:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _clients.remove(q)


# ── Event log persistence (PostgreSQL) ───────────────────────────────────────

def _db_insert_event(event: dict):
    """Persist one decoded sensor event into the device's own table."""
    try:
        table = _ensure_device_table(event["devEUI"])
        _db_execute(
            f"INSERT INTO {table} (recorded_at, device_type, value, raw_value, unit, extra)"
            " VALUES (to_timestamp(%s), %s, %s, %s, %s, %s)",
            (
                event.get("timestamp"),
                event.get("device_type"),
                event.get("value"),
                event.get("raw_value"),
                event.get("unit"),
                psycopg2.extras.Json(event["extra"]) if event.get("extra") else None,
            ),
        )
    except Exception as exc:
        print(f"DB insert_event error: {exc}", file=sys.stderr)


def _load_events_from_db():
    """Populate device history deques from each device's table (last 1000 rows each)."""
    try:
        map_rows = _db_execute(
            "SELECT dev_eui, table_name FROM device_table_map", fetch=True
        )
    except Exception as exc:
        print(f"DB load_events error: {exc}", file=sys.stderr)
        return

    total = 0
    for dev_eui, table in (map_rows or []):
        _device_tables[dev_eui] = table   # warm the cache
        try:
            event_rows = _db_execute(
                f"""SELECT device_type,
                           extract(epoch from recorded_at)::float8,
                           value, raw_value, unit, extra
                    FROM (
                        SELECT *, ROW_NUMBER() OVER (ORDER BY recorded_at DESC) AS rn
                        FROM {table}
                    ) t
                    WHERE rn <= 1000
                    ORDER BY recorded_at ASC""",
                fetch=True,
            )
        except Exception as exc:
            print(f"DB load_events error for {table}: {exc}", file=sys.stderr)
            continue

        if dev_eui not in _device_states:
            _device_states[dev_eui] = _new_device_state()

        events = []
        for device_type, timestamp, value, raw_value, unit, extra in (event_rows or []):
            ev: dict = {"devEUI": dev_eui, "device_type": device_type, "timestamp": timestamp}
            if value     is not None: ev["value"]     = value
            if raw_value is not None: ev["raw_value"] = raw_value
            if unit      is not None: ev["unit"]      = unit
            if extra     is not None: ev["extra"]     = extra
            events.append(ev)

        with _device_states[dev_eui]["history_lock"]:
            _device_states[dev_eui]["history"].extend(events)
        total += len(events)

    print(f"Loaded {total} events from DB for {len(map_rows or [])} device(s)")


# ── Statistics persistence (PostgreSQL) ──────────────────────────────────────

def _load_stats_from_db():
    """Load per-device stats and device types from the database."""
    try:
        rows = _db_execute(
            "SELECT dev_eui, opens, closes, holds, doubles, server_start, "
            "last_change_ts, min_value, max_value, sum_value, count_value "
            "FROM device_stats",
            fetch=True,
        )
        for row in (rows or []):
            eui = row[0].upper()
            if eui not in _device_states:
                _device_states[eui] = _new_device_state()
            _device_states[eui]["stats"].update({
                "opens":         row[1],  "closes":        row[2],
                "holds":         row[3],  "doubles":       row[4],
                "server_start":  row[5],  "last_change_ts": row[6],
                "min_value":     row[7],  "max_value":     row[8],
                "sum_value":     row[9]  or 0.0,
                "count_value":   row[10] or 0,
            })

        rows = _db_execute("SELECT dev_eui, device_type FROM device_types", fetch=True)
        for dev_eui, dtype in (rows or []):
            if dtype == "humidity":
                dtype = device_classifier.TEMPERATURE
            if dtype in device_classifier.DEVICE_TYPES:
                _device_type_store[dev_eui.upper()] = dtype

        rows = _db_execute("SELECT key, value FROM app_config", fetch=True)
        config = {k: v for k, v in (rows or [])}

        tbc = config.get("tilt_byte_config", {})
        if all(k in tbc for k in ("x", "y", "z")):
            device_classifier.set_tilt_byte_config(tbc["x"], tbc["y"], tbc["z"])

        tc = config.get("temp_byte_config", {})
        _TEMP_KEYS = ("temp_start","temp_divisor","humid_start","humid_size","humid_divisor","little_endian")
        if all(k in tc for k in _TEMP_KEYS):
            device_classifier.set_temp_byte_config(
                tc["temp_start"], tc["temp_divisor"],
                tc["humid_start"], tc["humid_size"],
                tc["humid_divisor"], tc["little_endian"],
            )

        bc = config.get("button_byte_config", {})
        if "check_byte" in bc and "hold_value" in bc:
            device_classifier.set_button_byte_config(
                bc["check_byte"], bc["hold_value"],
                bc.get("double_value", 3),
            )

        global _button_expire_seconds
        bes = config.get("button_expire_seconds")
        if isinstance(bes, (int, float)) and 0.1 <= bes <= 3600:
            _button_expire_seconds = float(bes)

    except Exception as exc:
        print(f"DB load_stats error: {exc}", file=sys.stderr)

    now = time.time()
    for ds in _device_states.values():
        if ds["stats"]["server_start"] is None:
            ds["stats"]["server_start"] = now


def _persist_stats():
    """Upsert per-device stats, device types, and app config to the database."""
    try:
        for eui, ds in _device_states.items():
            with ds["stats_lock"]:
                st = dict(ds["stats"])
            _db_execute(
                """INSERT INTO device_stats
                       (dev_eui, opens, closes, holds, doubles,
                        server_start, last_change_ts,
                        min_value, max_value, sum_value, count_value)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (dev_eui) DO UPDATE SET
                       opens=EXCLUDED.opens, closes=EXCLUDED.closes,
                       holds=EXCLUDED.holds, doubles=EXCLUDED.doubles,
                       server_start=EXCLUDED.server_start,
                       last_change_ts=EXCLUDED.last_change_ts,
                       min_value=EXCLUDED.min_value, max_value=EXCLUDED.max_value,
                       sum_value=EXCLUDED.sum_value, count_value=EXCLUDED.count_value""",
                (eui,
                 st.get("opens", 0),   st.get("closes", 0),
                 st.get("holds", 0),   st.get("doubles", 0),
                 st.get("server_start"), st.get("last_change_ts"),
                 st.get("min_value"),  st.get("max_value"),
                 st.get("sum_value", 0.0), st.get("count_value", 0)),
            )

        for eui, dtype in _device_type_store.items():
            _db_execute(
                """INSERT INTO device_types (dev_eui, device_type) VALUES (%s,%s)
                   ON CONFLICT (dev_eui) DO UPDATE SET device_type=EXCLUDED.device_type""",
                (eui, dtype),
            )

        for key, value in {
            "tilt_byte_config":      device_classifier.get_tilt_byte_config(),
            "temp_byte_config":      device_classifier.get_temp_byte_config(),
            "button_byte_config":    device_classifier.get_button_byte_config(),
            "button_expire_seconds": _button_expire_seconds,
        }.items():
            _db_execute(
                """INSERT INTO app_config (key, value) VALUES (%s,%s)
                   ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value""",
                (key, psycopg2.extras.Json(value)),
            )
    except Exception as exc:
        print(f"DB persist_stats error: {exc}", file=sys.stderr)


# ── Online-status helper ──────────────────────────────────────────────────────

def _is_online(ds: dict) -> bool:
    lnda = ds.get("last_new_data_at")
    return lnda is not None and (time.time() - lnda) < ONLINE_TIMEOUT


# ── Device list helper ────────────────────────────────────────────────────────

def _build_device_out(dev: dict) -> dict:
    """Augment a gateway device dict with server-side fields."""
    eui = dev["devEUI"].upper()
    ds  = _device_states.get(eui, {})
    l0, l1 = _device_label(eui)
    dtype = _get_device_type(eui)
    return {
        **dev,
        "online":           _is_online(ds),
        "label_active":     l0,
        "label_inactive":   l1,
        "device_type":      dtype,
        "device_type_display": device_classifier.get_display_name(dtype),
        "is_analog":        device_classifier.is_analog(dtype),
    }


# ── Device initialisation ─────────────────────────────────────────────────────

def _fetch_gateway_devices() -> list:
    auth  = _gw_request("POST", "internal/login", {"email": GW_EMAIL, "password": GW_PASS})
    token = auth["jwt"]
    resp  = _gw_request("GET", "devices?limit=100&applicationID=1", token=token)
    return resp.get("result", [])


def init_devices():
    """Fetch device list, build state entries, classify types, signal pollers."""
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

    _load_stats_from_db()
    _load_events_from_db()

    names = [d["name"] for d in devices]
    print(f"Devices loaded ({len(devices)}): {names}")
    _devices_ready.set()


def device_status_refresh():
    """Periodically refresh device list; start/remove devices as gateway changes."""
    while True:
        time.sleep(DEVICE_STATUS_REFRESH)
        try:
            fresh      = _fetch_gateway_devices()
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
                _ensure_device_table(eui)   # create DB table immediately
                threading.Thread(
                    target=device_poller_thread, args=(eui,),
                    daemon=True, name=f"poll-{eui}"
                ).start()
                print(f"Device added: {eui}")

            for eui in removed:
                _remove_device_from_db(eui)

            if removed:
                _persist_stats()
                print(f"Devices removed: {removed}")

            # Always broadcast so clients get fresh online status, battery, and type
            with _device_registry_lock:
                registry_snap = list(_device_registry)
            devices_out = [_build_device_out(dev) for dev in registry_snap]
            broadcast({"devices_update": devices_out})

        except Exception as exc:
            print(f"device_status_refresh error: {exc}", file=sys.stderr)


# ── Button expiry (synthetic release after 3 s with no new gateway data) ─────

def _button_expire_cb(dev_eui: str):
    """Fire a synthetic RELEASED event if no real gateway update beats the timer."""
    ds = _device_states.get(dev_eui)
    if ds is None:
        return
    now = time.time()
    with ds["stats_lock"]:
        if ds["last_value"] != 0:
            return  # Real release already arrived — nothing to do.
        ds["last_value"] = 1
        ds["stats"]["closes"] += 1
        ds["stats"]["last_change_ts"] = now
        stats_snap = dict(ds["stats"])
    event = {
        "devEUI":      dev_eui,
        "device_type": device_classifier.BUTTON,
        "value":       1,
        "timestamp":   now,
    }
    with ds["history_lock"]:
        ds["history"].append(event)
    _db_insert_event(event)
    with ds["transitions_lock"]:
        ds["transitions"].append(event)
    _persist_stats()
    broadcast({**event, "stats": stats_snap})


# ── Per-device poller thread ──────────────────────────────────────────────────

def device_poller_thread(dev_eui: str):
    """
    Poll siot for one device at DEVICE_POLL_INTERVAL seconds.

    Binary sensors  — detect transitions, count opens/closes, broadcast events.
    Analog sensors  — broadcast every reading with the full decoded value.
    """
    siot_token = None

    while True:
        if dev_eui not in _device_states:
            return  # device was removed; exit thread

        try:
            if siot_token is None:
                auth       = _siot_request("POST", "login",
                                            {"username": SIOT_USER, "password": SIOT_PASS})
                siot_token = auth["data"]["token"]

            ds = _device_states.get(dev_eui)
            if ds is None:
                return

            resp = _siot_request(
                "POST",
                "messages/getMsgByTopic?length=1",
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

            # Skip processing entirely if the gateway hasn't produced new data.
            if siot_ts == ds["last_siot_ts"]:
                time.sleep(DEVICE_POLL_INTERVAL)
                continue

            ds["last_siot_ts"]     = siot_ts
            ds["last_new_data_at"] = now

            # ── Classify if still GENERIC (first payload with data) ──────────
            dtype = _get_device_type(dev_eui)
            if dtype == device_classifier.GENERIC:
                name = _get_device_name(dev_eui)
                new_dtype = device_classifier.classify_device(name, dev_eui, raw_hex)
                if new_dtype != device_classifier.GENERIC:
                    _device_type_store[dev_eui] = new_dtype
                    dtype = new_dtype
                    _persist_stats()
                    print(f"Reclassified {dev_eui} → {new_dtype} from payload")

            decoded = device_classifier.decode_payload(dtype, dev_eui, raw_hex)

            # ── Analog sensor path ───────────────────────────────────────────
            if device_classifier.is_analog(dtype):
                rv = decoded.get("raw_value")
                event: dict = {
                    "devEUI":      dev_eui,
                    "device_type": dtype,
                    "timestamp":   now,
                    "raw_value":   rv,
                    "unit":        decoded.get("unit"),
                }
                if decoded.get("extra"):
                    event["extra"] = decoded["extra"]

                with ds["history_lock"]:
                    ds["history"].append(event)
                _db_insert_event(event)

                if rv is not None:
                    with ds["stats_lock"]:
                        st = ds["stats"]
                        if st.get("server_start") is None:
                            st["server_start"] = now
                        if st["min_value"] is None or rv < st["min_value"]:
                            st["min_value"] = rv
                        if st["max_value"] is None or rv > st["max_value"]:
                            st["max_value"] = rv
                        st["sum_value"]   = st.get("sum_value", 0.0) + rv
                        st["count_value"] = st.get("count_value", 0) + 1
                        event["stats"] = dict(st)

                broadcast(event)

            # ── Binary sensor path ───────────────────────────────────────────
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

                with ds["history_lock"]:
                    ds["history"].append(event)
                _db_insert_event(event)

                # Button: fire on every new payload (timestamp change) so each
                # press/hold registers even if the previous state was also "pressed".
                # Other binary sensors only fire when the value changes.
                is_button = (dtype == device_classifier.BUTTON)
                changed   = (val != ds["last_value"])

                # Real new data — cancel any pending expiry timer.
                if is_button:
                    old_timer = ds["button_expire_timer"]
                    if old_timer is not None:
                        old_timer.cancel()
                        ds["button_expire_timer"] = None

                if changed:
                    with ds["transitions_lock"]:
                        ds["transitions"].append(event)
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
                            # Only count releases on an actual state transition.
                            ds["stats"]["closes"] += 1
                        ds["stats"]["last_change_ts"] = now
                        stats_snap = dict(ds["stats"])
                    _persist_stats()
                    broadcast({**event, "stats": stats_snap})
                    # Start expiry timer on each press so a release is always counted.
                    if is_button and val == 0:
                        t = threading.Timer(_button_expire_seconds, _button_expire_cb, args=[dev_eui])
                        t.daemon = True
                        t.start()
                        ds["button_expire_timer"] = t
                else:
                    broadcast(event)

        except Exception as exc:
            siot_token = None
            print(f"Poller [{dev_eui}]: {exc}", file=sys.stderr)

        time.sleep(DEVICE_POLL_INTERVAL)


# ── Auto-log helpers ──────────────────────────────────────────────────────────

def _fmt_dur(secs: int) -> str:
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {(secs % 3600) // 60}m"


def write_auto_log(date_label: str):
    written = []
    for eui, ds in _device_states.items():
        name = eui
        with _device_registry_lock:
            for dev in _device_registry:
                if dev["devEUI"].upper() == eui:
                    name = dev["name"]
                    break

        dtype   = _get_device_type(eui)
        analog  = device_classifier.is_analog(dtype)
        label0, label1 = _device_label(eui)

        if analog:
            with ds["history_lock"]:
                entries = [e for e in ds["history"]
                           if e.get("raw_value") is not None]
            rows = []
            for ev in entries:
                ts_str = datetime.datetime.fromtimestamp(ev["timestamp"]).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                )[:-4]
                unit = ev.get("unit") or ""
                rows.append(f"  {ts_str:<32} {ev['raw_value']}{unit}")
        else:
            with ds["transitions_lock"]:
                entries = list(ds["transitions"])
                ds["transitions"].clear()

            rows = []
            prev_ts = None
            for ev in entries:
                ts_str = datetime.datetime.fromtimestamp(ev["timestamp"]).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                )[:-4]
                state = label0 if ev["value"] == 0 else label1
                dur   = _fmt_dur(round(ev["timestamp"] - prev_ts)) if prev_ts else "—"
                rows.append(f"  {ts_str:<32} {state:<8} {dur}")
                prev_ts = ev["timestamp"]

        block = [
            f"\n{'=' * 60}",
            f"  {name} ({eui})  —  {date_label}",
            f"{'=' * 60}",
        ] + (rows if rows else ["  (no data)"])

        log_path = _device_log_path(name, eui)
        with open(log_path, "a") as f:
            f.write("\n".join(block) + "\n")
        written.append(name)

    print(f"Device logs written for {date_label}: {written}")


def midnight_scheduler():
    while True:
        now      = datetime.datetime.now()
        tomorrow = (now + datetime.timedelta(days=1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        time.sleep((tomorrow - now).total_seconds())
        write_auto_log(now.strftime("%Y-%m-%d"))


# ── HTTP handler ──────────────────────────────────────────────────────────────

MIME_TYPES = {
    ".html":  "text/html; charset=utf-8",
    ".png":   "image/png",
    ".jpg":   "image/jpeg",
    ".jpeg":  "image/jpeg",
    ".gif":   "image/gif",
    ".svg":   "image/svg+xml",
    ".ico":   "image/x-icon",
    ".css":   "text/css",
    ".js":    "application/javascript",
}


class Handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/events":
            self._serve_sse()
        elif self.path.startswith("/devices"):
            self._serve_devices()
        elif self.path == "/tilt_byte_config":
            self._json_response(200, device_classifier.get_tilt_byte_config())
        elif self.path == "/temp_byte_config":
            self._json_response(200, device_classifier.get_temp_byte_config())
        elif self.path == "/button_byte_config":
            self._json_response(200, device_classifier.get_button_byte_config())
        elif self.path == "/button_expire_seconds":
            self._json_response(200, {"seconds": _button_expire_seconds})
        else:
            self._serve_static()

    def do_POST(self):
        if self.path == "/add_device":
            self._handle_add_device()
        elif self.path == "/delete_device":
            self._handle_delete_device()
        elif self.path == "/set_device_type":
            self._handle_set_device_type()
        elif self.path == "/set_tilt_byte_config":
            self._handle_set_tilt_byte_config()
        elif self.path == "/set_temp_byte_config":
            self._handle_set_temp_byte_config()
        elif self.path == "/set_button_byte_config":
            self._handle_set_button_byte_config()
        elif self.path == "/set_button_expire_seconds":
            self._handle_set_button_expire_seconds()
        else:
            self.send_response(404)
            self.end_headers()

    # ── Static file serving ───────────────────────────────────────────────────

    def _serve_static(self):
        import urllib.parse, posixpath
        path     = urllib.parse.unquote(self.path.split("?")[0])
        filename = posixpath.basename(path) or "dashboard.html"
        filepath = os.path.join(DIR, filename)

        if not os.path.isfile(filepath):
            self.send_response(404)
            self.end_headers()
            return

        ext  = os.path.splitext(filename)[1].lower()
        mime = MIME_TYPES.get(ext, "application/octet-stream")

        with open(filepath, "rb") as f:
            data = f.read()

        self.send_response(200)
        self.send_header("Content-Type",   mime)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ── Device list endpoint ──────────────────────────────────────────────────

    def _serve_devices(self):
        with _device_registry_lock:
            registry_snap = list(_device_registry)

        devices_out = []
        for dev in registry_snap:
            eui = dev["devEUI"].upper()
            ds  = _device_states.get(eui, {})
            out = _build_device_out(dev)
            with ds.get("stats_lock", threading.Lock()):
                out["stats"] = dict(ds.get("stats", {}))
            devices_out.append(out)

        self._json_response(200, {"devices": devices_out})

    # ── SSE endpoint ──────────────────────────────────────────────────────────

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type",                "text/event-stream")
        self.send_header("Cache-Control",               "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Accel-Buffering",           "no")
        self.end_headers()

        q = queue.Queue(maxsize=500)
        with _clients_lock:
            _clients.append(q)

        try:
            with _device_registry_lock:
                registry_snap = list(_device_registry)

            devices_out = [_build_device_out(dev) for dev in registry_snap]

            hist_by_device  = {}
            stats_by_device = {}
            for eui, ds in _device_states.items():
                with ds["history_lock"]:
                    hist_by_device[eui] = list(ds["history"])[-200:]
                with ds["stats_lock"]:
                    stats_by_device[eui] = dict(ds["stats"])

            hydration = {
                "devices":           devices_out,
                "history_by_device": hist_by_device,
                "stats_by_device":   stats_by_device,
            }
            self.wfile.write(f"data: {_json_dumps(hydration)}\n\n".encode())
            self.wfile.flush()

            while True:
                try:
                    event = q.get(timeout=15)
                    self.wfile.write(f"data: {_json_dumps(event)}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _clients_lock:
                if q in _clients:
                    _clients.remove(q)

    # ── Add-device proxy ──────────────────────────────────────────────────────

    def _handle_add_device(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"success": False, "error": f"Bad JSON: {exc}"})
            return

        mode    = body.get("mode", "OTAA").upper()
        dev_eui = body.get("devEUI", "").upper().replace(" ", "")
        name    = body.get("name", "") or dev_eui or "device"

        gw_payload = {
            "mode":          mode,
            "applicationID": "1",
            "name":          name,
            "DEVEUI":        dev_eui,
            "MAC":           body.get("lorawanSpec",  "1.0.3"),
            "TYPE":          body.get("deviceClass",  "A"),
            "skipFCntCheck": True,
            "description":   body.get("description", ""),
        }

        if mode == "OTAA":
            gw_payload["APPKEY"] = body.get("appKey",  "").upper().replace(" ", "")
            gw_payload["APPEUI"] = body.get("joinEUI", "").upper().replace(" ", "")
        else:
            gw_payload["DEVADDR"] = body.get("devAddr", "").upper().replace(" ", "")
            gw_payload["NWKSKEY"] = body.get("nwkSKey", "").upper().replace(" ", "")
            gw_payload["APPSKEY"] = body.get("appSKey", "").upper().replace(" ", "")

        try:
            result = _gw_add_device(gw_payload)
            self._json_response(200, {"success": True, "result": result})
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            self._json_response(exc.code, {"success": False, "error": detail})
        except Exception as exc:
            self._json_response(500, {"success": False, "error": str(exc)})

    # ── Delete-device proxy ───────────────────────────────────────────────────

    def _handle_delete_device(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"success": False, "error": f"Bad JSON: {exc}"})
            return

        dev_eui = body.get("devEUI", "").upper().replace(" ", "")
        if not dev_eui:
            self._json_response(400, {"success": False, "error": "devEUI required"})
            return

        try:
            auth  = _gw_request("POST", "internal/login", {"email": GW_EMAIL, "password": GW_PASS})
            token = auth["jwt"]
            _gw_request("DELETE", f"devices/{dev_eui}", token=token)
            self._json_response(200, {"success": True})
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            self._json_response(exc.code, {"success": False, "error": detail})
        except Exception as exc:
            self._json_response(500, {"success": False, "error": str(exc)})

    # ── Set device type ───────────────────────────────────────────────────────

    def _handle_set_device_type(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"success": False, "error": f"Bad JSON: {exc}"})
            return

        dev_eui = body.get("devEUI", "").upper().replace(" ", "")
        dtype   = body.get("device_type", "")

        if not dev_eui:
            self._json_response(400, {"success": False, "error": "devEUI required"})
            return
        if dtype not in device_classifier.DEVICE_TYPES:
            self._json_response(400, {"success": False, "error": f"Unknown type '{dtype}'"})
            return

        _device_type_store[dev_eui] = dtype
        _persist_stats()
        print(f"Device type manually set: {dev_eui} → {dtype}")

        # Broadcast updated device list so all clients update immediately
        with _device_registry_lock:
            registry_snap = list(_device_registry)
        devices_out = [_build_device_out(dev) for dev in registry_snap]
        broadcast({"devices_update": devices_out})

        self._json_response(200, {
            "success":      True,
            "device_type":  dtype,
            "display_name": device_classifier.get_display_name(dtype),
        })

    def _handle_set_tilt_byte_config(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"success": False, "error": f"Bad JSON: {exc}"})
            return

        try:
            x, y, z = int(body["x"]), int(body["y"]), int(body["z"])
        except (KeyError, ValueError, TypeError):
            self._json_response(400, {"success": False, "error": "x, y, z must be integers"})
            return

        if not all(0 <= v <= 60 for v in (x, y, z)):
            self._json_response(400, {"success": False, "error": "Byte offsets must be 0–60"})
            return

        device_classifier.set_tilt_byte_config(x, y, z)
        _persist_stats()
        print(f"Tilt byte config updated: x={x}, y={y}, z={z}")
        self._json_response(200, {"success": True, **device_classifier.get_tilt_byte_config()})

    def _handle_set_temp_byte_config(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"success": False, "error": f"Bad JSON: {exc}"})
            return

        try:
            temp_start    = int(body["temp_start"])
            temp_divisor  = float(body["temp_divisor"])
            humid_start   = int(body["humid_start"])
            humid_size    = int(body["humid_size"])
            humid_divisor = float(body["humid_divisor"])
            little_endian = bool(body["little_endian"])
        except (KeyError, ValueError, TypeError) as exc:
            self._json_response(400, {"success": False, "error": f"Invalid field: {exc}"})
            return

        if not (0 <= temp_start <= 60 and 0 <= humid_start <= 60):
            self._json_response(400, {"success": False, "error": "Start bytes must be 0–60"})
            return
        if humid_size not in (1, 2):
            self._json_response(400, {"success": False, "error": "humid_size must be 1 or 2"})
            return
        if temp_divisor <= 0 or humid_divisor <= 0:
            self._json_response(400, {"success": False, "error": "Divisors must be > 0"})
            return

        device_classifier.set_temp_byte_config(
            temp_start, temp_divisor,
            humid_start, humid_size, humid_divisor,
            little_endian,
        )
        _persist_stats()
        print(f"Temp byte config updated: temp@{temp_start}/÷{temp_divisor}, "
              f"humid@{humid_start}({humid_size}b)/÷{humid_divisor}, "
              f"{'LE' if little_endian else 'BE'}")
        self._json_response(200, {"success": True, **device_classifier.get_temp_byte_config()})

    def _handle_set_button_byte_config(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"success": False, "error": f"Bad JSON: {exc}"})
            return

        try:
            check_byte   = int(body["check_byte"])
            hold_value   = int(body["hold_value"])
            double_value = int(body.get("double_value", 3))
        except (KeyError, ValueError, TypeError):
            self._json_response(400, {"success": False, "error": "check_byte, hold_value, and double_value must be integers"})
            return

        if check_byte < -1 or check_byte > 60:
            self._json_response(400, {"success": False, "error": "check_byte must be -1 (last) or 0–60"})
            return
        if not (1 <= hold_value <= 255):
            self._json_response(400, {"success": False, "error": "hold_value must be 1–255"})
            return
        if not (1 <= double_value <= 255):
            self._json_response(400, {"success": False, "error": "double_value must be 1–255"})
            return

        device_classifier.set_button_byte_config(check_byte, hold_value, double_value)
        _persist_stats()
        print(f"Button byte config updated: check_byte={check_byte}, hold_value={hold_value}, double_value={double_value}")
        self._json_response(200, {"success": True, **device_classifier.get_button_byte_config()})

    def _handle_set_button_expire_seconds(self):
        global _button_expire_seconds
        try:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            secs = float(body["seconds"])
        except (KeyError, ValueError, TypeError):
            self._json_response(400, {"success": False, "error": "seconds must be a number."})
            return
        if not (0.1 <= secs <= 3600):
            self._json_response(400, {"success": False, "error": "seconds must be between 0.1 and 3600."})
            return
        _button_expire_seconds = secs
        _persist_stats()
        print(f"Button expire duration updated: {secs}s")
        self._json_response(200, {"success": True, "seconds": _button_expire_seconds})

    # ── Shared response helper ────────────────────────────────────────────────

    def _json_response(self, code: int, obj: dict):
        data = _json_dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type",              "application/json")
        self.send_header("Content-Length",            str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(LOGS_DIR, exist_ok=True)

    _db_connect()
    _init_db()

    init_devices()

    _devices_ready.wait(timeout=15)
    with _device_registry_lock:
        startup_devices = list(_device_registry)

    for dev in startup_devices:
        eui = dev["devEUI"].upper()
        threading.Thread(
            target=device_poller_thread, args=(eui,), daemon=True, name=f"poll-{eui}"
        ).start()

    threading.Thread(target=device_status_refresh, daemon=True).start()
    threading.Thread(target=midnight_scheduler,    daemon=True).start()

    server = ThreadingHTTPServer(("", PORT), Handler)
    print(f"Dashboard   →  http://localhost:{PORT}")
    print(f"Database    →  {DB_DSN.split('@')[-1]}")
    print(f"Device logs →  {LOGS_DIR}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
