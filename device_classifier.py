#!/usr/bin/env python3
"""
Device type classifier and payload decoder for DFRobot LoRaWAN sensors.

Exports:
  DEVICE_TYPES       — ordered list of type IDs
  classify_device()  — name + EUI + optional raw_hex → best type guess
  decode_payload()   — type + EUI + raw_hex → dict with value, raw_value, unit, extra
  get_labels()       — type → (label_active, label_inactive)
  get_display_name() — type → human-readable string
  is_analog()        — type → bool (True if sensor produces numeric readings)
  get_unit()         — type → unit string or None
"""

import math
import re
import struct

# ── Type constants ────────────────────────────────────────────────────────────
DOOR        = "door"
MOTION      = "motion"
TILT        = "tilt"
BUTTON      = "button"
TEMPERATURE = "temperature"   # covers temp + humidity combined
SOUND       = "sound"
GENERIC     = "generic"

# HUMIDITY is retired — any saved "humidity" type is treated as TEMPERATURE.
HUMIDITY = TEMPERATURE

DEVICE_TYPES = [DOOR, MOTION, TILT, BUTTON, TEMPERATURE, SOUND, GENERIC]

_TYPE_META = {
    DOOR:        {"display": "Door Sensor",        "unit": None,  "analog": False},
    MOTION:      {"display": "Motion Sensor",      "unit": None,  "analog": False},
    TILT:        {"display": "Tilt Sensor",        "unit": "°",   "analog": True},
    BUTTON:      {"display": "Button / Switch",    "unit": None,  "analog": False},
    TEMPERATURE: {"display": "Temp / Humidity",    "unit": "°C",  "analog": True},
    SOUND:       {"display": "Sound Sensor",       "unit": "dB",  "analog": True},
    GENERIC:     {"display": "Generic Sensor",     "unit": None,  "analog": False},
}

_LABELS = {
    DOOR:        ("OPEN",     "CLOSED"),
    MOTION:      ("DETECTED", "CLEAR"),
    TILT:        ("TILTED",   "LEVEL"),
    BUTTON:      ("PRESSED",  "RELEASED"),
    TEMPERATURE: ("HIGH",     "NORMAL"),
    SOUND:       ("LOUD",     "QUIET"),
    GENERIC:     ("ACTIVE",   "INACTIVE"),
}

# ── Name-based classification rules (checked in order) ───────────────────────
_NAME_RULES: list[tuple[str, re.Pattern]] = [
    (DOOR,        re.compile(r"door|contact|magnetic|reed|entry|window|gate", re.I)),
    (MOTION,      re.compile(r"motion|pir|presence|occupancy|movement|detect", re.I)),
    (TILT,        re.compile(r"tilt|gyro|accel|angle|inclin|orient|vibrat", re.I)),
    (BUTTON,      re.compile(r"button|btn|switch|remote|trigger|click|push", re.I)),
    (TEMPERATURE, re.compile(r"temp|thermo|thermal|climate|heat|cold|weather|environ|humid|moisture|damp|wet|rain", re.I)),
    (SOUND,       re.compile(r"sound|noise|audio|decibel|\bdb\b|acoustic|volume|snd", re.I)),
]

# Hard-coded EUI → type overrides (bypass all heuristics)
_EUI_OVERRIDES: dict[str, str] = {
    "A840411D595FBEFE": DOOR,
}

# ── Analog threshold defaults ─────────────────────────────────────────────────
_TEMP_HIGH_C    = 30.0    # above this → value=0 (HIGH)
_TILT_THRESHOLD = 15.0    # degrees from vertical → value=0 (TILTED)

# ── Per-device configuration ──────────────────────────────────────────────────
# Byte offsets, endianness, and type-specific tuning (button hold/double/
# expiry, temp display unit) are all per-device, keyed by devEUI — two devices
# of the same type can be wired or calibrated differently. _DEFAULT_CONFIGS is
# the fallback for any field a given device hasn't overridden yet.
_DEFAULT_CONFIGS: dict[str, dict] = {
    TILT: {
        "x": 5, "y": 7, "z": 9,   # start byte per axis, signed int16
        "little_endian": True,
    },
    TEMPERATURE: {
        "temp_start":    2,      # start byte of temperature field
        "temp_divisor":  10.0,   # divide raw temp int by this to get °C
        "humid_start":   6,      # start byte of humidity field
        "humid_size":    1,      # bytes to read for humidity: 1 (uint8) or 2 (uint16)
        "humid_divisor": 2.0,    # divide raw humid int by this to get %
        "little_endian": True,   # byte order for all multi-byte fields
        "unit":          "C",    # display unit: "C" or "F"
    },
    SOUND: {
        # Default: bytes 8-9 as little-endian uint16, dB×10 encoding.
        # Derived from live DFRobot Sound Sensor payloads (devEUI 24E124743C210453):
        # e.g. 017564055B052102A3012102 -> bytes[8:10] LE = 0x01A3 = 419 -> 41.9 dB.
        "start":         8,      # start byte of sound field
        "size":          2,      # bytes to read: 1 (uint8) or 2 (uint16)
        "divisor":       10.0,   # divide raw int by this to get dB (dB×10 → divisor 10)
        "little_endian": True,   # byte order for 2-byte reads
        "loud_db":       60.0,   # dB threshold above which is LOUD (value=0)
    },
    BUTTON: {
        "check_byte":     -1,   # which byte to inspect; -1 means last byte of payload
        "hold_value":      2,   # byte value that indicates a held press vs a normal press
        "double_value":    3,   # byte value that indicates a double press
        "expire_seconds":  1.0, # seconds PRESSED stays displayed before auto-reverting
    },
    DOOR:    {"check_byte": 0},   # non-zero → OPEN (value=0), zero → CLOSED (value=1)
    MOTION:  {"check_byte": 5},   # non-zero → DETECTED (value=0), zero → CLEAR (value=1)
    GENERIC: {"check_byte": 5},   # non-zero → ACTIVE (value=0), zero → INACTIVE (value=1)
}

# devEUI -> override fields (only keys that differ from _DEFAULT_CONFIGS[type])
_device_configs: dict[str, dict] = {}


def get_device_config(dev_eui: str, device_type: str) -> dict:
    """Merged config for one device: its type's defaults, overridden by
    whatever fields this specific devEUI has customized."""
    merged = dict(_DEFAULT_CONFIGS.get(device_type, {}))
    merged.update(_device_configs.get(dev_eui.upper(), {}))
    return merged


def set_device_config(dev_eui: str, device_type: str, fields: dict) -> dict:
    """Validate `fields` against the keys/types _DEFAULT_CONFIGS defines for
    `device_type`, store them as this device's overrides, and return the
    newly merged config. Keys that aren't part of that type's schema are
    silently ignored rather than rejected, so saving after switching a
    device's type doesn't require the caller to strip irrelevant fields."""
    schema = _DEFAULT_CONFIGS.get(device_type, {})
    eui = dev_eui.upper()
    overrides = _device_configs.setdefault(eui, {})
    for key, default_val in schema.items():
        if key not in fields:
            continue
        value = fields[key]
        if isinstance(default_val, bool):
            overrides[key] = bool(value)
        elif isinstance(default_val, int):
            overrides[key] = int(value)
        elif isinstance(default_val, float):
            overrides[key] = float(value)
        else:
            overrides[key] = str(value)
    return get_device_config(eui, device_type)


def load_device_config(dev_eui: str, config: dict) -> None:
    """Seed a device's stored overrides at startup — trusted data already
    validated when it was originally saved via set_device_config, so no
    re-validation here."""
    _device_configs[dev_eui.upper()] = dict(config)


# ── Public API ────────────────────────────────────────────────────────────────

def classify_device(name: str, dev_eui: str, raw_hex: str | None = None) -> str:
    """
    Return best-guess device type string.
    Priority: EUI override > name heuristic > payload structure > GENERIC.
    """
    eui = dev_eui.upper()

    if eui in _EUI_OVERRIDES:
        return _EUI_OVERRIDES[eui]

    for type_id, pattern in _NAME_RULES:
        if pattern.search(name):
            return type_id

    if raw_hex:
        guessed = _classify_by_payload(raw_hex)
        if guessed:
            return guessed

    return GENERIC


def decode_payload(device_type: str, dev_eui: str, raw_hex: str) -> dict:
    """
    Decode a raw hex payload string.

    Returns:
      {
        "value":     int,         # 0 = active/open/high, 1 = inactive/closed/normal
        "raw_value": float|None,  # numeric reading for analog types
        "unit":      str|None,    # unit for raw_value
        "extra":     dict,        # supplementary decoded fields
      }
    """
    result: dict = {"value": 1, "raw_value": None, "unit": None, "extra": {}}

    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return result

    cfg = get_device_config(dev_eui, device_type)

    if device_type == DOOR:
        _decode_binary_check(data, result, cfg["check_byte"])
    elif device_type == MOTION:
        _decode_binary_check(data, result, cfg["check_byte"])
    elif device_type == BUTTON:
        _decode_button(data, result, cfg)
    elif device_type == TEMPERATURE:
        result["unit"] = "°C"
        _decode_temperature(data, result, cfg)
    elif device_type == SOUND:
        result["unit"] = "dB"
        _decode_sound(data, result, cfg)
    elif device_type == TILT:
        result["unit"] = "°"
        _decode_tilt(data, result, cfg)
    elif device_type == GENERIC:
        _decode_binary_check(data, result, cfg["check_byte"])
    else:
        _decode_binary_generic(data, result)

    return result


def get_labels(device_type: str) -> tuple[str, str]:
    """Return (label_active, label_inactive) for the given type."""
    return _LABELS.get(device_type, _LABELS[GENERIC])


def get_display_name(device_type: str) -> str:
    return _TYPE_META.get(device_type, _TYPE_META[GENERIC])["display"]


def is_analog(device_type: str) -> bool:
    return _TYPE_META.get(device_type, _TYPE_META[GENERIC])["analog"]


def get_unit(device_type: str) -> str | None:
    return _TYPE_META.get(device_type, _TYPE_META[GENERIC])["unit"]


# ── Internal decoders ─────────────────────────────────────────────────────────

def _decode_binary_check(data: bytes, r: dict, check_byte: int, invert: bool = False) -> None:
    """Read one configurable byte; non-zero → active (value=0), zero → inactive (value=1).
    invert=True flips the sense: non-zero → inactive (value=1), zero → active (value=0).
    Falls back to the last byte when check_byte is out of range."""
    try:
        nonzero = data[check_byte] != 0
    except IndexError:
        nonzero = bool(data) and data[-1] != 0
    if invert:
        r["value"] = 1 if nonzero else 0
    else:
        r["value"] = 0 if nonzero else 1


def _decode_binary_generic(data: bytes, r: dict) -> None:
    """Legacy fallback for unknown types: byte[5] or last byte."""
    if len(data) > 5:
        r["value"] = 0 if data[5] != 0 else 1
    elif data:
        r["value"] = 0 if data[-1] != 0 else 1


def _decode_button(data: bytes, r: dict, cfg: dict) -> None:
    """
    Read the configured check_byte (-1 = last byte).
    0            → released     (value=1)
    non-zero     → pressed      (value=0)
    hold_value   → held         (value=0, extra["held"]=True)
    double_value → double press (value=0, extra["double"]=True)
    """
    try:
        byte_val = data[cfg["check_byte"]]
    except IndexError:
        return
    if byte_val == 0:
        r["value"] = 1
    else:
        r["value"] = 0
        if byte_val == cfg["hold_value"]:
            r["extra"]["held"] = True
        elif byte_val == cfg["double_value"]:
            r["extra"]["double"] = True


def _decode_temperature(data: bytes, r: dict, cfg: dict) -> None:
    """
    Decode temperature and optional humidity using this device's config.
    Default (Cayenne LPP / DFRobot environment sensor):
      temp_start=2, temp_divisor=10, little_endian=True  → LE int16 ÷ 10 = °C
      humid_start=6, humid_size=1, humid_divisor=2       → uint8 ÷ 2 = %
    """
    ts  = cfg["temp_start"]
    fmt = "<h" if cfg["little_endian"] else ">h"

    if len(data) >= ts + 2:
        try:
            temp_c = struct.unpack_from(fmt, data, ts)[0] / cfg["temp_divisor"]
            r["raw_value"] = round(temp_c, 1)
            r["value"] = 0 if temp_c >= _TEMP_HIGH_C else 1
        except struct.error:
            return

    hs   = cfg["humid_start"]
    hbytes = cfg["humid_size"]
    if len(data) >= hs + hbytes:
        try:
            if hbytes == 1:
                raw = data[hs]
            else:
                hfmt = ("<H" if cfg["little_endian"] else ">H")
                raw  = struct.unpack_from(hfmt, data, hs)[0]
            humid_pct = raw / cfg["humid_divisor"]
            if 0.0 <= humid_pct <= 100.0:
                r["extra"]["humidity"] = round(humid_pct, 1)
        except struct.error:
            pass


def _decode_sound(data: bytes, r: dict, cfg: dict) -> None:
    s    = cfg["start"]
    size = cfg["size"]
    if len(data) < s + size:
        return
    try:
        if size == 1:
            raw = data[s]
        else:
            fmt = "<H" if cfg["little_endian"] else ">H"
            raw = struct.unpack_from(fmt, data, s)[0]
        db = raw / cfg["divisor"]
        r["raw_value"] = round(db, 1)
        r["value"]     = 0 if db >= cfg["loud_db"] else 1
    except (struct.error, ZeroDivisionError):
        pass


def _decode_tilt(data: bytes, r: dict, cfg: dict) -> None:
    """
    DFRobot LoRaWAN gyroscope/tilt sensor:
      bytes 5-6 : X angle, signed int16, /100 = degrees
      bytes 7-8 : Y angle, signed int16, /100 = degrees
      bytes 9-10: Z angle, signed int16, /100 = degrees
    (byte order per-device, defaults to little-endian)

    raw_value is None; caller reads angles from extra {x, y, z}.
    value=0 (TILTED) when horizontal deviation exceeds threshold.
    """
    ox, oy, oz = cfg["x"], cfg["y"], cfg["z"]
    fmt = "<h" if cfg.get("little_endian", True) else ">h"
    if len(data) >= max(ox, oy, oz) + 2:
        try:
            x_deg = struct.unpack_from(fmt, data, ox)[0] / 100.0
            y_deg = struct.unpack_from(fmt, data, oy)[0] / 100.0
            z_deg = struct.unpack_from(fmt, data, oz)[0] / 100.0

            r["raw_value"] = None
            r["extra"] = {
                "x": round(x_deg, 2),
                "y": round(y_deg, 2),
                "z": round(z_deg, 2),
            }
            horiz = math.sqrt(x_deg ** 2 + y_deg ** 2)
            r["value"] = 0 if horiz >= _TILT_THRESHOLD else 1
            return
        except (struct.error, ValueError):
            pass

    if len(data) > 5:
        r["value"] = 0 if data[5] != 0 else 1


def _classify_by_payload(raw_hex: str) -> str | None:
    """
    Structural analysis of an unknown payload.
    Returns a type string on high-confidence match, else None.
    """
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return None

    n = len(data)

    # Temperature+humidity — try the default offsets first, then legacy DFRobot
    # format. This runs before a device has a confirmed type (that's what
    # we're guessing here), so there's no per-device override to consult yet.
    cfg = _DEFAULT_CONFIGS[TEMPERATURE]
    ts, hs = cfg["temp_start"], cfg["humid_start"]
    fmt = "<h" if cfg["little_endian"] else ">h"
    if n >= max(ts + 2, hs + cfg["humid_size"]):
        try:
            temp_c = struct.unpack_from(fmt, data, ts)[0] / cfg["temp_divisor"]
            if -40 <= temp_c <= 85:
                return TEMPERATURE
        except struct.error:
            pass
    # Cayenne LPP shorthand: type bytes 0x67 / 0x68 anywhere in payload
    if b'\x67' in data or b'\x68' in data:
        return TEMPERATURE

    # Door sensor: very large integer value
    if n >= 11:
        try:
            if int(raw_hex, 16) > 0x0001000000000000000000:
                return DOOR
        except ValueError:
            pass

    # Tilt: 11+ bytes with 3-axis data that looks like small int16 values
    if n >= 11:
        try:
            x = abs(struct.unpack(">h", data[5:7])[0])
            y = abs(struct.unpack(">h", data[7:9])[0])
            z = abs(struct.unpack(">h", data[9:11])[0])
            if max(x, y, z) < 20000 and (x or y or z):
                return TILT
        except struct.error:
            pass

    return None
