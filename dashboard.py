#!/usr/bin/env python3
"""
DoorSense dashboard — runs on Railway (or any internet-accessible host).

Receives sensor events from the local poller via HTTP POST, persists them
to PostgreSQL, and streams live updates to browsers over SSE.

Configuration (env vars, or a .env file in the same directory):
  DATABASE_URL   PostgreSQL connection string  (required)
  API_KEY        Shared secret; must match the poller's API_KEY
  PORT           HTTP port                     (default: 8765)

Ingest endpoints (called by poller.py):
  POST /ingest/event          — one decoded sensor event
  POST /ingest/devices        — current device list + type map
  POST /ingest/remove_device  — notify that a device was deleted

SSE / browser endpoints (unchanged from server.py):
  GET  /                      — dashboard.html
  GET  /events                — SSE stream
  GET  /devices               — device list JSON
  POST /set_device_type       — override device type
  POST /set_*_byte_config     — sensor byte-layout config
  POST /set_button_expire_seconds
"""

import contextlib
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
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return float(o)
        return super().default(o)


def _json_dumps(obj) -> str:
    return json.dumps(obj, cls=_Encoder)


# ── Configuration ─────────────────────────────────────────────────────────────

DIR      = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(DIR, "logs")
PORT     = int(os.environ.get("PORT", 8765))

ONLINE_TIMEOUT         = 900
_button_expire_seconds: float = 1.0


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

DB_DSN  = os.environ.get("DATABASE_URL")
API_KEY = os.environ.get("API_KEY", "")

if not DB_DSN:
    sys.exit("ERROR: DATABASE_URL is not set. Copy .env.example to .env.")


def _device_log_path(name: str, eui: str) -> str:
    safe = re.sub(r"[^\w\-]", "_", name)
    return os.path.join(LOGS_DIR, f"{safe}_{eui[-8:]}.log")


# ── PostgreSQL ────────────────────────────────────────────────────────────────

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


@contextlib.contextmanager
def _db_cursor():
    """Single connection for multiple queries in one transaction."""
    conn = _db_pool.getconn()
    try:
        with conn:
            with conn.cursor() as cur:
                yield cur
    finally:
        _db_pool.putconn(conn)


def _init_db():
    with _db_cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS device_table_map (
                dev_eui     TEXT PRIMARY KEY,
                table_name  TEXT NOT NULL,
                device_name TEXT
            )
        """)
        cur.execute("""
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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS device_types (
                dev_eui     TEXT PRIMARY KEY,
                device_type TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS app_config (
                key   TEXT PRIMARY KEY,
                value JSONB NOT NULL
            )
        """)
    print("Database schema ready.")


# ── Per-device table management ───────────────────────────────────────────────

_device_tables: dict[str, str] = {}


def _table_name_for_device(name: str, eui: str) -> str:
    safe = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if not safe or safe[0].isdigit():
        safe = f"dev_{safe}"
    base = safe[:50] or "device"
    if base in _device_tables.values():
        base = f"{base[:45]}_{eui[-4:].lower()}"
    return base


def _ensure_device_table(dev_eui: str) -> str:
    table = _device_tables.get(dev_eui)
    if table:
        return table

    rows = _db_execute(
        "SELECT table_name FROM device_table_map WHERE dev_eui = %s",
        (dev_eui,), fetch=True,
    )
    if rows:
        _device_tables[dev_eui] = rows[0][0]
        return rows[0][0]

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
    try:
        table = _device_tables.pop(dev_eui, None)
        if table is None:
            rows = _db_execute(
                "SELECT table_name FROM device_table_map WHERE dev_eui = %s",
                (dev_eui,), fetch=True,
            )
            table = rows[0][0] if rows else None

        with _db_cursor() as cur:
            if table:
                cur.execute(f"DROP TABLE IF EXISTS {table}")
                print(f"Dropped device table: {table}")
            cur.execute("DELETE FROM device_table_map WHERE dev_eui = %s", (dev_eui,))
            cur.execute("DELETE FROM device_stats   WHERE dev_eui = %s", (dev_eui,))
            cur.execute("DELETE FROM device_types   WHERE dev_eui = %s", (dev_eui,))
        _device_type_store.pop(dev_eui, None)
    except Exception as exc:
        print(f"DB remove_device error [{dev_eui}]: {exc}", file=sys.stderr)


# ── Device type store ─────────────────────────────────────────────────────────

_device_type_store: dict[str, str] = {}


def _get_device_type(eui: str) -> str:
    return _device_type_store.get(eui.upper(), device_classifier.GENERIC)


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
            "opens": 0, "closes": 0, "holds": 0, "doubles": 0,
            "server_start": None, "last_change_ts": None,
            "min_value": None, "max_value": None,
            "sum_value": 0.0,   "count_value": 0,
        },
        "stats_lock":       threading.Lock(),
        "last_value":       None,
        "last_new_data_at": None,
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


# ── Event log persistence ─────────────────────────────────────────────────────


def _db_insert_event(event: dict):
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
    try:
        map_rows = _db_execute(
            "SELECT dev_eui, table_name FROM device_table_map", fetch=True
        )
    except Exception as exc:
        print(f"DB load_events error: {exc}", file=sys.stderr)
        return

    total = 0
    for dev_eui, table in (map_rows or []):
        _device_tables[dev_eui] = table
        try:
            event_rows = _db_execute(
                f"""SELECT device_type,
                           extract(epoch from recorded_at)::float8,
                           value, raw_value, unit, extra
                    FROM (
                        SELECT device_type, recorded_at, value, raw_value, unit, extra
                        FROM {table}
                        ORDER BY recorded_at DESC
                        LIMIT 1000
                    ) t
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


# ── Statistics persistence ────────────────────────────────────────────────────


def _load_stats_from_db():
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
                "opens": row[1], "closes": row[2], "holds": row[3], "doubles": row[4],
                "server_start": row[5], "last_change_ts": row[6],
                "min_value": row[7], "max_value": row[8],
                "sum_value": row[9] or 0.0, "count_value": row[10] or 0,
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
        _TEMP_KEYS = ("temp_start", "temp_divisor", "humid_start",
                      "humid_size", "humid_divisor", "little_endian")
        if all(k in tc for k in _TEMP_KEYS):
            device_classifier.set_temp_byte_config(
                tc["temp_start"], tc["temp_divisor"],
                tc["humid_start"], tc["humid_size"],
                tc["humid_divisor"], tc["little_endian"],
            )

        bc = config.get("button_byte_config", {})
        if "check_byte" in bc and "hold_value" in bc:
            device_classifier.set_button_byte_config(
                bc["check_byte"], bc["hold_value"], bc.get("double_value", 3),
            )

        sc = config.get("sound_byte_config", {})
        _SOUND_KEYS = ("start", "size", "divisor", "little_endian", "loud_db")
        if all(k in sc for k in _SOUND_KEYS):
            device_classifier.set_sound_byte_config(
                sc["start"], sc["size"], sc["divisor"],
                sc["little_endian"], sc["loud_db"],
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


_last_persist_at: float = 0.0

def _persist_stats(*, immediate: bool = False):
    global _last_persist_at
    now = time.time()
    if not immediate and now - _last_persist_at < 5.0:
        return
    _last_persist_at = now
    try:
        with _db_cursor() as cur:
            for eui, ds in _device_states.items():
                with ds["stats_lock"]:
                    st = dict(ds["stats"])
                cur.execute(
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
                     st.get("opens", 0),    st.get("closes", 0),
                     st.get("holds", 0),    st.get("doubles", 0),
                     st.get("server_start"), st.get("last_change_ts"),
                     st.get("min_value"),   st.get("max_value"),
                     st.get("sum_value", 0.0), st.get("count_value", 0)),
                )
            for eui, dtype in _device_type_store.items():
                cur.execute(
                    "INSERT INTO device_types (dev_eui, device_type) VALUES (%s,%s) "
                    "ON CONFLICT (dev_eui) DO UPDATE SET device_type=EXCLUDED.device_type",
                    (eui, dtype),
                )
            for key, value in {
                "tilt_byte_config":      device_classifier.get_tilt_byte_config(),
                "temp_byte_config":      device_classifier.get_temp_byte_config(),
                "button_byte_config":    device_classifier.get_button_byte_config(),
                "sound_byte_config":     device_classifier.get_sound_byte_config(),
                "button_expire_seconds": _button_expire_seconds,
            }.items():
                cur.execute(
                    "INSERT INTO app_config (key, value) VALUES (%s,%s) "
                    "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                    (key, psycopg2.extras.Json(value)),
                )
    except Exception as exc:
        print(f"DB persist_stats error: {exc}", file=sys.stderr)


def _persist_loop():
    while True:
        time.sleep(60)
        _persist_stats(immediate=True)


# ── Online-status / device-list helpers ──────────────────────────────────────


def _is_online(ds: dict) -> bool:
    lnda = ds.get("last_new_data_at")
    return lnda is not None and (time.time() - lnda) < ONLINE_TIMEOUT


def _build_device_out(dev: dict) -> dict:
    eui = dev["devEUI"].upper()
    ds  = _device_states.get(eui, {})
    l0, l1 = _device_label(eui)
    dtype   = _get_device_type(eui)
    return {
        **dev,
        "online":              _is_online(ds),
        "label_active":        l0,
        "label_inactive":      l1,
        "device_type":         dtype,
        "device_type_display": device_classifier.get_display_name(dtype),
        "is_analog":           device_classifier.is_analog(dtype),
    }


# ── Startup initialisation (from DB — no gateway access needed) ───────────────


def init_dashboard():
    _load_stats_from_db()
    _load_events_from_db()
    print("Dashboard initialised from database.")
    _devices_ready.set()


# ── Auto-log helpers ──────────────────────────────────────────────────────────


def _fmt_dur(secs: int) -> str:
    if secs < 60:    return f"{secs}s"
    if secs < 3600:  return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {(secs % 3600) // 60}m"


def write_auto_log(date_label: str):
    written = []
    for eui, ds in _device_states.items():
        name = _get_device_name(eui)
        dtype  = _get_device_type(eui)
        analog = device_classifier.is_analog(dtype)
        label0, label1 = _device_label(eui)

        if analog:
            with ds["history_lock"]:
                entries = [e for e in ds["history"] if e.get("raw_value") is not None]
            rows = []
            for ev in entries:
                ts_str = datetime.datetime.fromtimestamp(ev["timestamp"]).strftime(
                    "%Y-%m-%d %H:%M:%S.%f")[:-4]
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
                    "%Y-%m-%d %H:%M:%S.%f")[:-4]
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
            hour=0, minute=0, second=0, microsecond=0)
        time.sleep((tomorrow - now).total_seconds())
        write_auto_log(now.strftime("%Y-%m-%d"))


# ── HTTP handler ──────────────────────────────────────────────────────────────

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
    ".svg":  "image/svg+xml",
    ".ico":  "image/x-icon",
    ".css":  "text/css",
    ".js":   "application/javascript",
}


class Handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Api-Key")
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
        elif self.path == "/sound_byte_config":
            self._json_response(200, device_classifier.get_sound_byte_config())
        else:
            self._serve_static()

    def do_POST(self):
        if self.path == "/ingest/event":
            self._handle_ingest_event()
        elif self.path == "/ingest/devices":
            self._handle_ingest_devices()
        elif self.path == "/ingest/remove_device":
            self._handle_ingest_remove_device()
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
        elif self.path == "/set_sound_byte_config":
            self._handle_set_sound_byte_config()
        else:
            self.send_response(404)
            self.end_headers()

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _check_api_key(self) -> bool:
        if not API_KEY:
            return True   # no key configured → open
        if self.headers.get("X-Api-Key", "") == API_KEY:
            return True
        self._json_response(401, {"error": "Unauthorized"})
        return False

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length))

    # ── Ingest endpoints (called by poller) ───────────────────────────────────

    def _handle_ingest_event(self):
        if not self._check_api_key():
            return
        try:
            event = self._read_json()
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"error": str(exc)})
            return

        eui = event.get("devEUI", "").upper()
        if not eui:
            self._json_response(400, {"error": "devEUI required"})
            return

        if eui not in _device_states:
            _device_states[eui] = _new_device_state()

        ds = _device_states[eui]
        ds["last_new_data_at"] = time.time()
        ds["last_value"]       = event.get("value", event.get("raw_value"))

        with ds["history_lock"]:
            ds["history"].append(event)

        # Track transitions for auto-log (transition events carry stats)
        dtype = event.get("device_type", "")
        if "stats" in event and not device_classifier.is_analog(dtype):
            with ds["transitions_lock"]:
                ds["transitions"].append(event)

        if "stats" in event:
            with ds["stats_lock"]:
                ds["stats"].update(event["stats"])
            _persist_stats()

        _db_insert_event(event)
        broadcast(event)
        self._json_response(200, {"ok": True})

    def _handle_ingest_devices(self):
        if not self._check_api_key():
            return
        try:
            body = self._read_json()
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"error": str(exc)})
            return

        devices      = body.get("devices", [])
        device_types = body.get("device_types", {})

        with _device_registry_lock:
            _device_registry.clear()
            _device_registry.extend(devices)

        for eui, dtype in device_types.items():
            _device_type_store[eui.upper()] = dtype

        for dev in devices:
            eui = dev["devEUI"].upper()
            if eui not in _device_states:
                _device_states[eui] = _new_device_state()
            _ensure_device_table(eui)

        broadcast({"devices_update": devices})
        self._json_response(200, {"ok": True})

    def _handle_ingest_remove_device(self):
        if not self._check_api_key():
            return
        try:
            body = self._read_json()
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"error": str(exc)})
            return

        eui = body.get("devEUI", "").upper()
        if not eui:
            self._json_response(400, {"error": "devEUI required"})
            return

        _remove_device_from_db(eui)
        _device_states.pop(eui, None)
        self._json_response(200, {"ok": True})

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
            out = _build_device_out(dev)
            ds  = _device_states.get(eui)
            if ds:
                with ds["stats_lock"]:
                    out["stats"] = dict(ds["stats"])
            else:
                out["stats"] = {}
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

            devices_out     = [_build_device_out(dev) for dev in registry_snap]
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

    # ── Config POST handlers ──────────────────────────────────────────────────

    def _handle_set_device_type(self):
        try:
            body = self._read_json()
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"success": False, "error": str(exc)})
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
        _persist_stats(immediate=True)

        with _device_registry_lock:
            registry_snap = list(_device_registry)
        broadcast({"devices_update": [_build_device_out(d) for d in registry_snap]})

        self._json_response(200, {
            "success":      True,
            "device_type":  dtype,
            "display_name": device_classifier.get_display_name(dtype),
        })

    def _handle_set_tilt_byte_config(self):
        try:
            body = self._read_json()
            x, y, z = int(body["x"]), int(body["y"]), int(body["z"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            self._json_response(400, {"success": False, "error": "x, y, z must be integers"})
            return
        if not all(0 <= v <= 60 for v in (x, y, z)):
            self._json_response(400, {"success": False, "error": "Byte offsets must be 0–60"})
            return
        device_classifier.set_tilt_byte_config(x, y, z)
        _persist_stats(immediate=True)
        self._json_response(200, {"success": True, **device_classifier.get_tilt_byte_config()})

    def _handle_set_temp_byte_config(self):
        try:
            body          = self._read_json()
            temp_start    = int(body["temp_start"])
            temp_divisor  = float(body["temp_divisor"])
            humid_start   = int(body["humid_start"])
            humid_size    = int(body["humid_size"])
            humid_divisor = float(body["humid_divisor"])
            little_endian = bool(body["little_endian"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            self._json_response(400, {"success": False, "error": str(exc)})
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
            temp_start, temp_divisor, humid_start, humid_size, humid_divisor, little_endian)
        _persist_stats(immediate=True)
        self._json_response(200, {"success": True, **device_classifier.get_temp_byte_config()})

    def _handle_set_button_byte_config(self):
        try:
            body         = self._read_json()
            check_byte   = int(body["check_byte"])
            hold_value   = int(body["hold_value"])
            double_value = int(body.get("double_value", 3))
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            self._json_response(400, {"success": False,
                                      "error": "check_byte, hold_value, double_value must be integers"})
            return
        if check_byte < -1 or check_byte > 60:
            self._json_response(400, {"success": False, "error": "check_byte must be -1 or 0–60"})
            return
        if not (1 <= hold_value <= 255) or not (1 <= double_value <= 255):
            self._json_response(400, {"success": False, "error": "hold/double_value must be 1–255"})
            return
        device_classifier.set_button_byte_config(check_byte, hold_value, double_value)
        _persist_stats(immediate=True)
        self._json_response(200, {"success": True, **device_classifier.get_button_byte_config()})

    def _handle_set_button_expire_seconds(self):
        global _button_expire_seconds
        try:
            body = self._read_json()
            secs = float(body["seconds"])
        except (KeyError, ValueError, TypeError):
            self._json_response(400, {"success": False, "error": "seconds must be a number."})
            return
        if not (0.1 <= secs <= 3600):
            self._json_response(400, {"success": False,
                                      "error": "seconds must be between 0.1 and 3600."})
            return
        _button_expire_seconds = secs
        _persist_stats(immediate=True)
        self._json_response(200, {"success": True, "seconds": _button_expire_seconds})

    def _handle_set_sound_byte_config(self):
        try:
            body         = self._read_json()
            start        = int(body["start"])
            size         = int(body["size"])
            divisor      = float(body["divisor"])
            little_endian = bool(body["little_endian"])
            loud_db      = float(body["loud_db"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
            self._json_response(400, {"success": False, "error": str(exc)})
            return
        if not (0 <= start <= 60):
            self._json_response(400, {"success": False, "error": "start must be 0–60"})
            return
        if size not in (1, 2):
            self._json_response(400, {"success": False, "error": "size must be 1 or 2"})
            return
        if divisor <= 0:
            self._json_response(400, {"success": False, "error": "divisor must be > 0"})
            return
        if not (0 <= loud_db <= 200):
            self._json_response(400, {"success": False, "error": "loud_db must be 0–200"})
            return
        device_classifier.set_sound_byte_config(start, size, divisor, little_endian, loud_db)
        _persist_stats(immediate=True)
        self._json_response(200, {"success": True, **device_classifier.get_sound_byte_config()})

    # ── Shared response helper ────────────────────────────────────────────────

    def _json_response(self, code: int, obj: dict):
        data = _json_dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type",               "application/json")
        self.send_header("Content-Length",             str(len(data)))
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
    init_dashboard()

    threading.Thread(target=midnight_scheduler, daemon=True).start()
    threading.Thread(target=_persist_loop, daemon=True).start()

    server = ThreadingHTTPServer(("", PORT), Handler)
    print(f"Dashboard   →  http://localhost:{PORT}")
    print(f"Database    →  {DB_DSN.split('@')[-1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
