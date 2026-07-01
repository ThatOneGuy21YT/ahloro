#!/usr/bin/env python3
"""Test MQTT connectivity to UG65 and sniff uplink topics."""

import os, socket, sys, time

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

HOST = os.environ.get("GW_HOST", "192.168.1.1")

# ── Port scan ─────────────────────────────────────────────────────────────────
print(f"Scanning {HOST} for MQTT ports...")
for port in (1883, 8883, 1884):
    s = socket.socket()
    s.settimeout(2)
    r = s.connect_ex((HOST, port))
    s.close()
    print(f"  port {port}: {'OPEN' if r == 0 else 'closed'}")
print()

# ── Try paho-mqtt ─────────────────────────────────────────────────────────────
try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("paho-mqtt not installed — run:  pip install paho-mqtt")

received = []

def on_connect(client, userdata, flags, rc):
    codes = {0:"OK",1:"bad protocol",2:"bad client id",3:"server unavailable",
             4:"bad credentials",5:"not authorised"}
    print(f"MQTT connect: {codes.get(rc, rc)}")
    if rc == 0:
        for topic in ("#", "application/#", "gateway/#"):
            client.subscribe(topic, qos=0)
            print(f"  Subscribed to: {topic}")

def on_message(client, userdata, msg):
    received.append((msg.topic, msg.payload[:200]))
    print(f"  MSG  topic={msg.topic}  payload={msg.payload[:120]}")

def on_disconnect(client, userdata, rc):
    print(f"MQTT disconnected (rc={rc})")

GW_PASS = os.environ.get("GW_PASS", "")

# Credentials to try: (username, password, label)
CRED_CANDIDATES = [
    ("",      "",           "anonymous"),
    ("admin", GW_PASS,      f"admin/{GW_PASS or '(empty)'}"),
    ("admin", "admin",      "admin/admin"),
    ("admin", "password",   "admin/password"),
]

connected_client = None
for user, pw, label in CRED_CANDIDATES:
    s = socket.socket(); s.settimeout(1)
    if s.connect_ex((HOST, 1883)) != 0:
        s.close(); sys.exit("Port 1883 closed")
    s.close()

    print(f"Trying credentials: {label}")
    result = {"rc": None}

    def on_connect(client, userdata, flags, rc, _props=None):
        result["rc"] = rc

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                         client_id="doorsense-diag")
    client.on_connect = on_connect
    if user:
        client.username_pw_set(user, pw)
    try:
        client.connect(HOST, 1883, keepalive=10)
    except Exception as e:
        print(f"  connect error: {e}")
        continue

    for _ in range(20):          # wait up to 2s for connect callback
        client.loop(timeout=0.1)
        if result["rc"] is not None:
            break

    rc_val = getattr(result["rc"], "value", result["rc"])
    if rc_val == 0:
        print(f"  ✓ Authenticated!\n")
        connected_client = client
        break
    else:
        print(f"  ✗ {result['rc']}")
        client.disconnect()

if not connected_client:
    sys.exit("\nAll credential attempts failed. Check GW_PASS in .env.ug65.")

connected_client.on_message    = on_message
connected_client.on_disconnect = on_disconnect
for topic in ("#",):
    connected_client.subscribe(topic, qos=0)
    print(f"Subscribed to: {topic}")

print("Listening for 20 seconds — press the button now...")
deadline = time.time() + 20
while time.time() < deadline:
    connected_client.loop(timeout=0.2)

connected_client.disconnect()
if received:
    print(f"\nCaptured {len(received)} message(s) — topics seen:")
    for t, _ in received:
        print(f"  {t}")
else:
    print("\nNo messages received — device may not be sending uplinks.")
