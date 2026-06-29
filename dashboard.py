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

import base64
import contextlib
import datetime
import decimal
import json
import os
import queue
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
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

ONLINE_TIMEOUT         = 900
_button_expire_seconds: float = 1.0
_last_poller_contact:   float = 0.0
_POLLER_TIMEOUT               = 120.0   # seconds before poller is considered offline


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

PORT             = int(os.environ.get("PORT", 8765))
BIND_HOST        = os.environ.get("BIND_HOST", "")
CERT_FILE        = os.environ.get("CERT_FILE", "")
KEY_FILE         = os.environ.get("KEY_FILE", "")
DB_DSN           = os.environ.get("DATABASE_URL")
API_KEY               = os.environ.get("API_KEY", "")
BROWSER_PASSWORD      = os.environ.get("BROWSER_PASSWORD", "")
GOOGLE_CLIENT_ID      = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET  = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_ALLOWED_EMAILS = {
    e.strip() for e in os.environ.get("GOOGLE_ALLOWED_EMAILS", "").split(",") if e.strip()
}
OAUTH_REDIRECT_URI    = os.environ.get("OAUTH_REDIRECT_URI", "")

# ── Rate limiter (shared by API key + browser auth checks) ────────────────────
_rate_lock  = threading.Lock()
_auth_fails: dict[str, list[float]] = {}
_RATE_WINDOW   = 60.0   # seconds
_RATE_MAX_FAIL = 10     # max failures per IP per window

def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        times = [t for t in _auth_fails.get(ip, []) if now - t < _RATE_WINDOW]
        _auth_fails[ip] = times
        return len(times) >= _RATE_MAX_FAIL

def _record_auth_failure(ip: str) -> None:
    with _rate_lock:
        _auth_fails.setdefault(ip, []).append(time.time())


# ── Session helpers (Google OAuth) ────────────────────────────────────────────

_SESSION_TTL = 86400 * 30  # 30 days


def _create_session(email: str, name: str, picture: str = "") -> str:
    token = secrets.token_urlsafe(32)
    _db_execute("DELETE FROM sessions WHERE expires_at < now()")
    _db_execute(
        "INSERT INTO sessions (token, email, name, picture, expires_at)"
        " VALUES (%s, %s, %s, %s, to_timestamp(%s))",
        (token, email, name, picture, time.time() + _SESSION_TTL),
    )
    return token


def _get_session(token: str) -> dict | None:
    rows = _db_execute(
        "SELECT email, name, picture FROM sessions"
        " WHERE token = %s AND expires_at > now()",
        (token,), fetch=True,
    )
    if rows:
        return {"email": rows[0][0], "name": rows[0][1], "picture": rows[0][2] or ""}
    return None


def _delete_session(token: str) -> None:
    _db_execute("DELETE FROM sessions WHERE token = %s", (token,))


def _oauth_exchange_code(code: str) -> dict | None:
    data = urllib.parse.urlencode({
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  OAUTH_REDIRECT_URI,
        "grant_type":    "authorization_code",
    }).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as exc:
        print(f"OAuth token exchange error: {exc}", file=sys.stderr)
        return None


def _oauth_fetch_userinfo(access_token: str) -> dict | None:
    req = urllib.request.Request(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception as exc:
        print(f"OAuth userinfo error: {exc}", file=sys.stderr)
        return None


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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                email      TEXT NOT NULL,
                name       TEXT,
                picture    TEXT,
                expires_at TIMESTAMPTZ NOT NULL
            )
        """)
        # Add picture column to existing deployments that lack it
        cur.execute("""
            ALTER TABLE sessions ADD COLUMN IF NOT EXISTS picture TEXT
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
        # Auth routes bypass the session/password gate
        if self.path == "/auth/login":
            self._handle_auth_login()
            return
        if self.path == "/auth/google":
            self._handle_auth_google()
            return
        if self.path.startswith("/auth/callback"):
            self._handle_auth_callback()
            return
        if self.path == "/auth/logout":
            self._handle_auth_logout()
            return

        if not self._check_browser_auth():
            return

        if self.path == "/me":
            self._serve_me()
        elif self.path == "/events":
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
        elif self.path.startswith("/log_data"):
            self._serve_log_data()
        elif self.path == "/poller_status":
            self._serve_poller_status()
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
            if self._check_browser_auth(): self._handle_set_device_type()
        elif self.path == "/set_tilt_byte_config":
            if self._check_browser_auth(): self._handle_set_tilt_byte_config()
        elif self.path == "/set_temp_byte_config":
            if self._check_browser_auth(): self._handle_set_temp_byte_config()
        elif self.path == "/set_button_byte_config":
            if self._check_browser_auth(): self._handle_set_button_byte_config()
        elif self.path == "/set_button_expire_seconds":
            if self._check_browser_auth(): self._handle_set_button_expire_seconds()
        elif self.path == "/set_sound_byte_config":
            if self._check_browser_auth(): self._handle_set_sound_byte_config()
        elif self.path == "/delete_device":
            if self._check_browser_auth(): self._handle_delete_device()
        else:
            self.send_response(404)
            self.end_headers()

    # ── Auth ──────────────────────────────────────────────────────────────────

    _SEC_HEADERS = [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options",        "DENY"),
        ("Referrer-Policy",        "strict-origin-when-cross-origin"),
    ]

    def _send_security_headers(self):
        for k, v in self._SEC_HEADERS:
            self.send_header(k, v)

    def version_string(self):
        return "DoorSense"

    def _check_api_key(self) -> bool:
        if not API_KEY:
            return True
        ip  = self.client_address[0]
        key = self.headers.get("X-Api-Key", "")
        if _is_rate_limited(ip):
            self._json_response(429, {"error": "Too many requests"})
            return False
        if key == API_KEY:
            return True
        if key:  # only count failures when a key was actually presented
            _record_auth_failure(ip)
        self._json_response(401, {"error": "Unauthorized"})
        return False

    def _parse_cookies(self) -> dict:
        result: dict = {}
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k:
                result[k.strip()] = v.strip()
        return result

    def _check_browser_auth(self) -> bool:
        # ── Google OAuth session check ─────────────────────────────────────────
        if GOOGLE_CLIENT_ID:
            token   = self._parse_cookies().get("session", "")
            session = _get_session(token) if token else None
            if session:
                self._session = session
                return True
            # Redirect GET requests to login; tell AJAX/POST callers 401
            if self.command == "GET":
                self.send_response(302)
                self.send_header("Location", "/auth/login")
                self._send_security_headers()
                self.end_headers()
            else:
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self._send_security_headers()
                self.end_headers()
            return False

        # ── Basic Auth (fallback when Google OAuth not configured) ─────────────
        if not BROWSER_PASSWORD:
            return True
        ip   = self.client_address[0]
        auth = self.headers.get("Authorization", "")
        if _is_rate_limited(ip):
            self.send_response(429)
            self.send_header("Content-Length", "0")
            self._send_security_headers()
            self.end_headers()
            return False
        if auth.startswith("Basic "):
            try:
                decoded  = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
                _, _, pw = decoded.partition(":")
                if pw == BROWSER_PASSWORD:
                    return True
            except Exception:
                pass
            _record_auth_failure(ip)  # wrong credentials presented — count it
        # No credentials at all — reject without counting (not a brute-force attempt)
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="DoorSense"')
        self.send_header("Content-Length", "0")
        self._send_security_headers()
        self.end_headers()
        return False

    # ── Google OAuth handlers ─────────────────────────────────────────────────

    _LOGIN_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · DoorSense</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{min-height:100vh;display:flex;align-items:center;justify-content:center;
         background:#f0f4f4;font-family:'Google Sans',Roboto,system-ui,sans-serif}
    @media(prefers-color-scheme:dark){
      body{background:#191c1d}
      .card{background:#1d2021;border-color:#3f484a}
      .title{color:#e1e3e3}.subtitle{color:#899294}
      .google-btn{background:#1d2021;border-color:#3f484a;color:#e1e3e3}
      .google-btn:hover{background:#252a2b;border-color:#006874}
    }
    .card{background:#fff;border:1px solid #bfc8ca;border-radius:28px;
          padding:48px 40px;width:min(420px,90vw);display:flex;
          flex-direction:column;align-items:center;gap:24px;
          box-shadow:0 2px 12px rgba(0,0,0,.08)}
    .logo{width:56px;height:56px;background:#97f0ff;border-radius:50%;
          display:flex;align-items:center;justify-content:center;color:#001f24}
    .title{font-size:24px;font-weight:500;color:#191c1d}
    .subtitle{font-size:14px;color:#6f797a;text-align:center;line-height:1.5}
    .google-btn{display:flex;align-items:center;gap:12px;background:#fff;
                border:1.5px solid #bfc8ca;border-radius:20px;padding:10px 24px;
                font-size:14px;font-weight:500;font-family:inherit;color:#191c1d;
                cursor:pointer;text-decoration:none;transition:background .15s,
                border-color .15s,box-shadow .15s;width:100%;justify-content:center}
    .google-btn:hover{background:#f0f4f4;border-color:#006874;
                      box-shadow:0 1px 4px rgba(0,0,0,.12)}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor">
        <path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3a4.237 4.237 0 0 0-6 0zm-4-4 2 2a7.074 7.074 0 0 1 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/>
      </svg>
    </div>
    <div class="title">DoorSense</div>
    <div class="subtitle">Sign in with your Google account to access the dashboard.</div>
    <a class="google-btn" href="/auth/google">
      <svg width="18" height="18" viewBox="0 0 24 24">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
      </svg>
      Sign in with Google
    </a>
  </div>
</body>
</html>"""

    def _html_response(self, code: int, html: str, extra_headers: list[tuple] | None = None):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _serve_oauth_error(self, message: str):
        safe_msg = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self._html_response(403, f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access denied · DoorSense</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{min-height:100vh;display:flex;align-items:center;justify-content:center;
         background:#f0f4f4;font-family:'Google Sans',Roboto,system-ui,sans-serif}}
    @media(prefers-color-scheme:dark){{
      body{{background:#191c1d}}
      .card{{background:#1d2021;border-color:#3f484a}}
      .title{{color:#e1e3e3}}.msg{{color:#899294}}
      .btn{{background:#1d2021;border-color:#3f484a;color:#e1e3e3}}
      .btn:hover{{background:#252a2b;border-color:#006874}}
    }}
    .card{{background:#fff;border:1px solid #bfc8ca;border-radius:28px;
           padding:48px 40px;width:min(420px,90vw);display:flex;
           flex-direction:column;align-items:center;gap:20px;
           box-shadow:0 2px 12px rgba(0,0,0,.08)}}
    .logo{{width:56px;height:56px;background:#ffdad6;border-radius:50%;
           display:flex;align-items:center;justify-content:center;color:#ba1a1a}}
    .title{{font-size:22px;font-weight:500;color:#191c1d}}
    .msg{{font-size:14px;color:#6f797a;text-align:center;line-height:1.5}}
    .btn{{display:flex;align-items:center;justify-content:center;gap:8px;
          background:#fff;border:1.5px solid #bfc8ca;border-radius:20px;
          padding:10px 24px;font-size:14px;font-weight:500;font-family:inherit;
          color:#191c1d;cursor:pointer;text-decoration:none;width:100%;
          transition:background .15s,border-color .15s}}
    .btn:hover{{background:#f0f4f4;border-color:#006874}}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
      </svg>
    </div>
    <div class="title">Access denied</div>
    <div class="msg">{safe_msg}</div>
    <a class="btn" href="/auth/login">Try again</a>
  </div>
</body>
</html>""")

    def _handle_auth_login(self):
        """Show the static sign-in landing page."""
        if not GOOGLE_CLIENT_ID:
            self.send_response(302)
            self.send_header("Location", "/")
            self._send_security_headers()
            self.end_headers()
            return
        self._html_response(200, self._LOGIN_PAGE)

    def _handle_auth_google(self):
        """Redirect the browser to Google's OAuth consent screen."""
        if not GOOGLE_CLIENT_ID:
            self.send_response(302)
            self.send_header("Location", "/")
            self._send_security_headers()
            self.end_headers()
            return
        state  = secrets.token_urlsafe(16)
        params = {
            "client_id":     GOOGLE_CLIENT_ID,
            "redirect_uri":  OAUTH_REDIRECT_URI,
            "response_type": "code",
            "scope":         "openid email profile",
            "state":         state,
            "access_type":   "online",
            "prompt":        "select_account",
        }
        url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
        self.send_response(302)
        self.send_header("Location", url)
        self.send_header("Set-Cookie",
            f"oauth_state={state}; HttpOnly; SameSite=Lax; Max-Age=300; Path=/")
        self._send_security_headers()
        self.end_headers()

    def _handle_auth_callback(self):
        """Exchange the authorization code for a session cookie."""
        if not GOOGLE_CLIENT_ID:
            self.send_response(302)
            self.send_header("Location", "/")
            self._send_security_headers()
            self.end_headers()
            return
        qs    = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code  = (qs.get("code")  or [None])[0]
        state = (qs.get("state") or [None])[0]
        error = (qs.get("error") or [None])[0]

        if error:
            self._serve_oauth_error(f"Google returned an error: {error}")
            return

        cookies = self._parse_cookies()
        if not code or not state or state != cookies.get("oauth_state"):
            self._serve_oauth_error(
                "Invalid or missing OAuth state. Please try signing in again."
            )
            return

        token_data = _oauth_exchange_code(code)
        if not token_data or "access_token" not in token_data:
            self._serve_oauth_error("Failed to exchange authorisation code with Google.")
            return

        user = _oauth_fetch_userinfo(token_data["access_token"])
        if not user:
            self._serve_oauth_error("Failed to retrieve account information from Google.")
            return

        email   = user.get("email", "")
        name    = user.get("name", "")
        picture = user.get("picture", "")

        if GOOGLE_ALLOWED_EMAILS and email not in GOOGLE_ALLOWED_EMAILS:
            self._serve_oauth_error(
                f"The account {email} is not permitted to access this dashboard."
            )
            return

        session_token = _create_session(email, name, picture)
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie",
            f"session={session_token}; HttpOnly; SameSite=Lax;"
            f" Max-Age={_SESSION_TTL}; Path=/")
        self.send_header("Set-Cookie",
            "oauth_state=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/")
        self._send_security_headers()
        self.end_headers()

    def _handle_auth_logout(self):
        token = self._parse_cookies().get("session", "")
        if token:
            _delete_session(token)
        self.send_response(302)
        self.send_header("Location", "/auth/login")
        self.send_header("Set-Cookie",
            "session=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/")
        self._send_security_headers()
        self.end_headers()

    def _serve_me(self):
        if not GOOGLE_CLIENT_ID:
            self._json_response(404, {"error": "Google auth not enabled"})
            return
        session = getattr(self, "_session", None)
        if session:
            self._json_response(200, session)
        else:
            self._json_response(401, {"error": "Not authenticated"})

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length))

    # ── Ingest endpoints (called by poller) ───────────────────────────────────

    def _handle_ingest_event(self):
        if not self._check_api_key():
            return
        global _last_poller_contact
        _last_poller_contact = time.time()
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
        global _last_poller_contact
        _last_poller_contact = time.time()
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

    def _handle_delete_device(self):
        """Browser-initiated device deletion."""
        try:
            body = self._read_json()
        except (json.JSONDecodeError, ValueError) as exc:
            self._json_response(400, {"success": False, "error": str(exc)})
            return

        eui = body.get("devEUI", "").upper()
        if not eui:
            self._json_response(400, {"success": False, "error": "devEUI required"})
            return

        _remove_device_from_db(eui)
        _device_states.pop(eui, None)

        with _device_registry_lock:
            _device_registry[:] = [d for d in _device_registry
                                    if d.get("devEUI", "").upper() != eui]
            remaining = [_build_device_out(d) for d in _device_registry]

        broadcast({"devices_update": remaining})
        self._json_response(200, {"success": True})

    # ── Poller status API ─────────────────────────────────────────────────────

    def _serve_poller_status(self):
        now    = time.time()
        online = (_last_poller_contact > 0 and
                  (now - _last_poller_contact) < _POLLER_TIMEOUT)
        ago    = round(now - _last_poller_contact, 1) if _last_poller_contact else None
        self._json_response(200, {"online": online, "last_contact_ago": ago})

    # ── Log data API ──────────────────────────────────────────────────────────

    def _serve_log_data(self):
        from urllib.parse import urlparse, parse_qs
        qs      = parse_qs(urlparse(self.path).query)
        dev_eui = qs.get("devEUI", [None])[0]
        try:
            limit = min(int(qs.get("limit", ["500"])[0]), 5000)
        except (ValueError, TypeError):
            limit = 500

        if not dev_eui:
            rows = _db_execute(
                "SELECT dev_eui, device_name FROM device_table_map ORDER BY device_name",
                fetch=True,
            ) or []
            self._json_response(200, {
                "devices": [{"devEUI": r[0], "name": r[1] or r[0]} for r in rows],
            })
            return

        map_rows = _db_execute(
            "SELECT table_name, device_name FROM device_table_map WHERE dev_eui = %s",
            (dev_eui,), fetch=True,
        )
        if not map_rows:
            self._json_response(404, {"error": "Device not found"})
            return

        table, device_name = map_rows[0]
        device_name = device_name or dev_eui

        try:
            event_rows = _db_execute(
                "SELECT id,"
                " to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),"
                " device_type, value, raw_value, unit, extra"
                " FROM " + table + " ORDER BY recorded_at DESC LIMIT %s",
                (limit,), fetch=True,
            ) or []
        except Exception as exc:
            self._json_response(500, {"error": str(exc)})
            return

        self._json_response(200, {
            "rows": [
                {
                    "id":          r[0],
                    "recorded_at": r[1],
                    "device_type": r[2],
                    "value":       r[3],
                    "raw_value":   r[4],
                    "unit":        r[5],
                    "extra":       r[6],
                }
                for r in event_rows
            ],
            "device_name": device_name,
            "total":       len(event_rows),
        })

    # ── Static file serving ───────────────────────────────────────────────────

    def _serve_static(self):
        import posixpath
        path     = urllib.parse.unquote(self.path.split("?")[0])
        filename = posixpath.basename(path) or "dashboard.html"

        # Block hidden files/dirs (.env, .git, .., etc.) at every path segment
        if any(seg.startswith(".") for seg in path.split("/") if seg):
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()
            return

        ext  = os.path.splitext(filename)[1].lower()
        mime = MIME_TYPES.get(ext)           # None → not in allowlist

        # Reject unknown extensions (.py, .pyc, .log, .env …) and missing files
        filepath = os.path.join(DIR, filename)
        if not mime or not os.path.isfile(filepath):
            self.send_response(404)
            self._send_security_headers()
            self.end_headers()
            return

        with open(filepath, "rb") as f:
            data = f.read()

        self.send_response(200)
        self.send_header("Content-Type",   mime)
        self.send_header("Content-Length", str(len(data)))
        self._send_security_headers()
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
        self._send_security_headers()
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
        self._send_security_headers()
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

    server = ThreadingHTTPServer((BIND_HOST, PORT), Handler)

    scheme = "http"
    if CERT_FILE and KEY_FILE:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    elif CERT_FILE or KEY_FILE:
        print("WARNING: set both CERT_FILE and KEY_FILE to enable TLS", file=sys.stderr)

    bind_display = BIND_HOST or "0.0.0.0"
    print(f"Dashboard   →  {scheme}://localhost:{PORT}  (bound to {bind_display})")
    print(f"Database    →  {DB_DSN.split('@')[-1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
