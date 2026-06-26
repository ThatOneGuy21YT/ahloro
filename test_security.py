#!/usr/bin/env python3
"""
Security test suite for the DoorSense dashboard.
Run against a local instance only — not against production.

Usage:
    python3 test_security.py
    python3 test_security.py --url http://localhost:8765 --api-key yourkey --browser-password yourpass
"""

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--url",              default="http://localhost:80")
    p.add_argument("--api-key",          default="1234")
    p.add_argument("--browser-password", default="")
    return p.parse_args()

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
results = []

def check(name, passed, detail=""):
    tag = PASS if passed else FAIL
    msg = f"  [{tag}] {name}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    results.append((name, passed))

def request(url, *, method="GET", headers=None, body=None, basic_pass=""):
    req = urllib.request.Request(url, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if basic_pass:
        creds = base64.b64encode(f":{basic_pass}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")
    if body:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", str(len(data)))
        req.data = data
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except Exception:
        return 0, b"", {}


def test_browser_auth(base, browser_pass):
    print("\n── Browser auth ──────────────────────────────────────────────────────")
    enabled = bool(browser_pass)

    code, _, _ = request(f"{base}/")
    check("GET / without credentials → 401" if enabled else "GET / open → 200",
          code == (401 if enabled else 200), f"got {code}")

    code, _, _ = request(f"{base}/events")
    check("GET /events without credentials → 401" if enabled else "GET /events open → 200",
          code == (401 if enabled else 200), f"got {code}")

    code, _, _ = request(f"{base}/devices")
    check("GET /devices without credentials → 401" if enabled else "GET /devices open → 200",
          code == (401 if enabled else 200), f"got {code}")

    if enabled:
        # Wrong password (this WILL consume a rate-limit slot)
        code, _, _ = request(f"{base}/", basic_pass="wrongpassword")
        check("GET / with wrong password → 401", code == 401, f"got {code}")

        code, _, _ = request(f"{base}/", basic_pass=browser_pass)
        check("GET / with correct password → 200", code == 200, f"got {code}")

        code, _, _ = request(f"{base}/devices", basic_pass=browser_pass)
        check("GET /devices with correct password → 200", code == 200, f"got {code}")


def test_api_key_auth(base, api_key):
    print("\n── API key auth (ingest endpoints) ───────────────────────────────────")
    payload = {"devices": [], "device_types": {}}

    # No key — not counted by rate limiter
    code, _, _ = request(f"{base}/ingest/devices", method="POST", body=payload)
    if api_key:
        check("POST /ingest/devices without key → 401", code == 401, f"got {code}")
    else:
        check("POST /ingest/devices with no key set → 200", code == 200, f"got {code}")

    if api_key:
        # Wrong key — this WILL consume a rate-limit slot
        code, _, _ = request(f"{base}/ingest/devices", method="POST",
                              headers={"X-Api-Key": "wrongkey"}, body=payload)
        check("POST /ingest/devices with wrong key → 401", code == 401, f"got {code}")

        code, _, _ = request(f"{base}/ingest/devices", method="POST",
                              headers={"X-Api-Key": api_key}, body=payload)
        check("POST /ingest/devices with correct key → 200", code == 200, f"got {code}")


def test_set_endpoints_auth(base, browser_pass):
    print("\n── Set endpoints require browser auth ────────────────────────────────")
    body = {"devEUI": "AABBCCDDEEFF0011", "device_type": "door"}

    # No credentials — not counted by rate limiter
    code, _, _ = request(f"{base}/set_device_type", method="POST", body=body)
    if browser_pass:
        check("POST /set_device_type without credentials → 401", code == 401, f"got {code}")
    else:
        check("POST /set_device_type with no password set → not 500",
              code != 500, f"got {code}")

    if browser_pass:
        code, _, _ = request(f"{base}/set_device_type", method="POST",
                              body=body, basic_pass=browser_pass)
        check("POST /set_device_type with correct password → 200 or 400",
              code in (200, 400), f"got {code}")


def test_security_headers(base, browser_pass):
    print("\n── Security headers ──────────────────────────────────────────────────")

    # Use correct API key so this doesn't consume a rate-limit slot
    code, _, headers = request(f"{base}/ingest/devices", method="POST",
                                body={"devices": [], "device_types": {}})
    check("X-Content-Type-Options: nosniff",
          headers.get("X-Content-Type-Options", "").lower() == "nosniff",
          repr(headers.get("X-Content-Type-Options")))
    check("X-Frame-Options: DENY",
          headers.get("X-Frame-Options", "").upper() == "DENY",
          repr(headers.get("X-Frame-Options")))
    check("Referrer-Policy present",
          "Referrer-Policy" in headers,
          repr(headers.get("Referrer-Policy")))

    code, _, headers = request(f"{base}/button_expire_seconds", basic_pass=browser_pass)
    check("Security headers on config GET",
          "X-Content-Type-Options" in headers,
          repr(headers.get("X-Content-Type-Options")))


def test_no_info_leakage(base, browser_pass):
    print("\n── Information leakage ───────────────────────────────────────────────")

    code, body, headers = request(f"{base}/nonexistent-path-xyz", basic_pass=browser_pass)
    check("404 for unknown path", code == 404, f"got {code}")
    check("404 body does not contain 'Traceback'",
          b"Traceback" not in body)

    server_hdr = headers.get("Server", "")
    check("Server header does not expose Python version",
          "Python" not in server_hdr,
          repr(server_hdr))


def test_rate_limiting(base, api_key):
    print("\n── Rate limiting (runs last — locks out this IP for 60s) ─────────────")
    # Earlier tests sent ~2 wrong credentials (1 wrong browser pw + 1 wrong api key).
    # Send enough bad keys to push past the 10-failure cap.
    print("  Sending bad API key requests until rate-limited...")

    got_429 = False
    for i in range(15):
        code, _, _ = request(f"{base}/ingest/devices", method="POST",
                              headers={"X-Api-Key": f"badkey-{i}"},
                              body={"devices": [], "device_types": {}})
        if code == 429:
            got_429 = True
            check(f"Rate limit triggered after {i+1} additional failures → 429",
                  True, f"hit on attempt {i+1}")
            break

    if not got_429:
        check("Rate limit triggered within 15 attempts", False, "never got 429")

    if got_429:
        code, _, _ = request(f"{base}/ingest/devices", method="POST",
                              headers={"X-Api-Key": api_key},
                              body={"devices": [], "device_types": {}})
        check("Correct key also blocked while rate limited → 429",
              code == 429, f"got {code}")
        print("  (wait 60 seconds before making further requests)")


def main():
    args = parse_args()
    base = args.url.rstrip("/")
    api_key = args.api_key
    browser_pass = args.browser_password

    print(f"Target:           {base}")
    print(f"API key set:      {'yes' if api_key else 'no'}")
    print(f"Browser password: {'yes' if browser_pass else 'no'}")

    code, _, _ = request(f"{base}/button_expire_seconds", basic_pass=browser_pass)
    if code == 0:
        print(f"\n\033[31mERROR: Cannot reach {base} — is the dashboard running?\033[0m")
        sys.exit(1)

    test_browser_auth(base, browser_pass)
    test_api_key_auth(base, api_key)
    test_set_endpoints_auth(base, browser_pass)
    test_security_headers(base, browser_pass)
    test_no_info_leakage(base, browser_pass)
    test_rate_limiting(base, api_key)   # always last — locks out the IP

    passed = sum(1 for _, ok in results if ok)
    failed = sum(1 for _, ok in results if not ok)
    total  = len(results)

    print(f"\n── Results ───────────────────────────────────────────────────────────")
    print(f"  {passed}/{total} passed", end="")
    if failed:
        print(f"  \033[31m{failed} failed\033[0m")
        for name, ok in results:
            if not ok:
                print(f"    \033[31m✗\033[0m {name}")
    else:
        print(f"  \033[32m✓ all passed\033[0m")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
