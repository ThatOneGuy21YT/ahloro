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

# ── Door sensor specifics (from dflorawan_probe.py) ───────────────────────────
_DOOR_THRESHOLD = 0x0050000000000000000000

# ── Analog threshold defaults ─────────────────────────────────────────────────
_TEMP_HIGH_C     = 30.0    # above this → value=0 (HIGH)
_SOUND_LOUD_DB   = 60.0    # above this → value=0 (LOUD)
_TILT_THRESHOLD  = 15.0    # degrees from vertical → value=0 (TILTED)

# ── Tilt/gyro byte offsets (configurable at runtime) ──────────────────────────
# Each offset is the start byte for a little-endian signed int16 (reads 2 bytes).
_tilt_byte_offsets: dict[str, int] = {"x": 5, "y": 7, "z": 9}


def get_tilt_byte_config() -> dict[str, int]:
    """Return the current {x, y, z} start-byte offsets for the tilt decoder."""
    return dict(_tilt_byte_offsets)


def set_tilt_byte_config(x: int, y: int, z: int) -> None:
    """Update the tilt decoder byte offsets at runtime."""
    _tilt_byte_offsets["x"] = int(x)
    _tilt_byte_offsets["y"] = int(y)
    _tilt_byte_offsets["z"] = int(z)


# ── Temp/humidity byte config (configurable at runtime) ───────────────────────
# Calibrated to Cayenne LPP format (DFRobot environment sensor):
#   temp : bytes 2-3, LE signed int16, ÷10  → °C
#   humid: byte  6,   uint8,           ÷2   → %
_temp_byte_config: dict = {
    "temp_start":    2,      # start byte of temperature field
    "temp_divisor":  10.0,   # divide raw temp int by this to get °C
    "humid_start":   6,      # start byte of humidity field
    "humid_size":    1,      # bytes to read for humidity: 1 (uint8) or 2 (uint16)
    "humid_divisor": 2.0,    # divide raw humid int by this to get %
    "little_endian": True,   # byte order for all multi-byte fields
}


def get_temp_byte_config() -> dict:
    """Return the current temp/humidity byte configuration."""
    return dict(_temp_byte_config)


def set_temp_byte_config(temp_start: int, temp_divisor: float,
                         humid_start: int, humid_size: int,
                         humid_divisor: float, little_endian: bool) -> None:
    """Update the temp/humidity decoder configuration at runtime."""
    _temp_byte_config["temp_start"]    = int(temp_start)
    _temp_byte_config["temp_divisor"]  = float(temp_divisor)
    _temp_byte_config["humid_start"]   = int(humid_start)
    _temp_byte_config["humid_size"]    = int(humid_size)
    _temp_byte_config["humid_divisor"] = float(humid_divisor)
    _temp_byte_config["little_endian"] = bool(little_endian)


# ── Button byte config (configurable at runtime) ──────────────────────────────
# By default, reads the last byte of the payload (-1 index).
# A value of 0 = released; non-zero = pressed; hold_value = held.
_button_byte_config: dict = {
    "check_byte":   -1,  # which byte to inspect; -1 means last byte of payload
    "hold_value":    2,  # byte value that indicates a held press vs a normal press
    "double_value":  3,  # byte value that indicates a double press
}


def get_button_byte_config() -> dict:
    """Return the current button press/hold/double byte configuration."""
    return dict(_button_byte_config)


def set_button_byte_config(check_byte: int, hold_value: int, double_value: int = 3) -> None:
    """Update the button decoder configuration at runtime."""
    _button_byte_config["check_byte"]   = int(check_byte)
    _button_byte_config["hold_value"]   = int(hold_value)
    _button_byte_config["double_value"] = int(double_value)


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

    if device_type == DOOR:
        _decode_door(raw_hex, result)
    elif device_type == BUTTON:
        _decode_button(data, result)
    elif device_type == TEMPERATURE:
        result["unit"] = "°C"
        _decode_temperature(data, result)
    elif device_type == SOUND:
        result["unit"] = "dB"
        _decode_sound(data, result)
    elif device_type == TILT:
        result["unit"] = "°"
        _decode_tilt(data, result)
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

def _decode_door(raw_hex: str, r: dict) -> None:
    try:
        r["value"] = 0 if int(raw_hex, 16) > _DOOR_THRESHOLD else 1
    except ValueError:
        pass


def _decode_binary_generic(data: bytes, r: dict) -> None:
    """byte[5] != 0 → active (value=0)."""
    if len(data) > 5:
        r["value"] = 0 if data[5] != 0 else 1
    elif data:
        r["value"] = 0 if data[-1] != 0 else 1


def _decode_button(data: bytes, r: dict) -> None:
    """
    Read the configured check_byte (-1 = last byte).
    0            → released     (value=1)
    non-zero     → pressed      (value=0)
    hold_value   → held         (value=0, extra["held"]=True)
    double_value → double press (value=0, extra["double"]=True)
    """
    cfg = _button_byte_config
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


def _decode_temperature(data: bytes, r: dict) -> None:
    """
    Decode temperature and optional humidity using the runtime _temp_byte_config.
    Default (Cayenne LPP / DFRobot environment sensor):
      temp_start=2, temp_divisor=10, little_endian=True  → LE int16 ÷ 10 = °C
      humid_start=6, humid_size=1, humid_divisor=2       → uint8 ÷ 2 = %
    """
    cfg = _temp_byte_config
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


def _decode_sound(data: bytes, r: dict) -> None:
    """
    bytes 5-6: uint16.
    Heuristic: if > 1000 assume raw ADC (0-4095 → scale to 0-120 dB),
    otherwise assume dB×10 encoding.
    """
    if len(data) >= 7:
        try:
            raw = struct.unpack(">H", data[5:7])[0]
            db = (raw / 4095.0) * 120.0 if raw > 1000 else raw / 10.0
            r["raw_value"] = round(db, 1)
            r["value"] = 0 if db >= _SOUND_LOUD_DB else 1
            return
        except struct.error:
            pass
    if len(data) > 5:
        db = (data[5] / 255.0) * 120.0
        r["raw_value"] = round(db, 1)
        r["value"] = 0 if db >= _SOUND_LOUD_DB else 1


def _decode_tilt(data: bytes, r: dict) -> None:
    """
    DFRobot LoRaWAN gyroscope/tilt sensor:
      bytes 5-6 : X angle, signed int16 little-endian, /100 = degrees
      bytes 7-8 : Y angle, signed int16 little-endian, /100 = degrees
      bytes 9-10: Z angle, signed int16 little-endian, /100 = degrees

    raw_value is None; caller reads angles from extra {x, y, z}.
    value=0 (TILTED) when horizontal deviation exceeds threshold.
    """
    ox, oy, oz = _tilt_byte_offsets["x"], _tilt_byte_offsets["y"], _tilt_byte_offsets["z"]
    if len(data) >= max(ox, oy, oz) + 2:
        try:
            x_deg = struct.unpack_from("<h", data, ox)[0] / 100.0
            y_deg = struct.unpack_from("<h", data, oy)[0] / 100.0
            z_deg = struct.unpack_from("<h", data, oz)[0] / 100.0

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

    # Temperature+humidity — try configured offsets first, then legacy DFRobot format
    cfg = _temp_byte_config
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
