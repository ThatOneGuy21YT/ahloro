#!/usr/bin/env python3
"""Continuously output threshold result from Door Sensor on DFRobot LoRaWAN Gateway at 10.8.8.8."""

import json
import sys
import time
import urllib.request
import urllib.error
import ssl

HOST = "10.8.8.8"
GW_BASE = f"https://{HOST}/api"
SIOT_BASE = f"http://{HOST}:8080/api/v2"
EMAIL = "admin"
PASSWORD = "p0ssw0rd;"
SIOT_USER = "siot"
SIOT_PASS = "dfrobot"
THRESHOLD = 0x0050000000000000000000
POLL_INTERVAL = 0.05

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def gw_request(method, path, body=None, token=None):
    url = f"{GW_BASE}/{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} on {method} {path}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)


def siot_request(method, path, body=None, token=None):
    url = f"{SIOT_BASE}/{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = token
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} on {method} {path}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)


def fetch_latest(siot_token, dev_eui):
    resp = siot_request(
        "POST",
        "messages/getMsgByTopic?length=1",
        body={"topic": f"siot/lora/{dev_eui}/raw"},
        token=siot_token,
    )
    messages = (resp.get("data") or {}).get("messages") or []
    if not messages:
        return None
    return messages[0]["content"]


def main():
    # Authenticate once at startup
    auth = gw_request("POST", "internal/login", {"email": EMAIL, "password": PASSWORD})
    gw_token = auth["jwt"]

    dev_resp = gw_request("GET", "devices?limit=100&applicationID=1", token=gw_token)
    devices = dev_resp.get("result", [])
    if not devices:
        print("No devices found.", file=sys.stderr)
        sys.exit(1)

    siot_auth = siot_request("POST", "login", {"username": SIOT_USER, "password": SIOT_PASS})
    siot_token = siot_auth["data"]["token"]

    dev_eui = devices[0]["devEUI"]

    try:
        while True:
            raw = fetch_latest(siot_token, dev_eui)
            if raw is not None:
                output = 0 if int(raw, 16) > THRESHOLD else 1
                print(output, flush=True)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
