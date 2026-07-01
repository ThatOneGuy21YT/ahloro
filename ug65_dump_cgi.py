#!/usr/bin/env python3
"""Fetch login.html from the UG65 and extract all CGI core/function pairs."""

import base64, http.cookiejar, json, os, re, ssl, sys, urllib.request

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

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

jar    = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(jar),
)

def fetch(path):
    req = urllib.request.Request(f"https://{HOST}{path}")
    try:
        with opener.open(req, timeout=15) as r:
            return r.read().decode(errors="replace")
    except Exception as e:
        return ""

print("Fetching login.html...")
html = fetch("/login.html")
print(f"  {len(html)//1024}KB\n")

# Extract all inline <script> blocks
scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S)
js = "\n".join(scripts)
print(f"Inline JS: {len(js)//1024}KB across {len(scripts)} blocks\n")

# ── Pattern matching with DOTALL ─────────────────────────────────────────────
calls = set()

# "core":"X" ... "function":"Y"  (single line or multi-line, within 200 chars)
for m in re.finditer(r'"core"\s*:\s*"([^"]+)"(.{0,200}?)"function"\s*:\s*"([^"]+)"', js, re.S):
    calls.add((m.group(1), m.group(3)))

# Also reversed: "function":"Y" ... "core":"X"
for m in re.finditer(r'"function"\s*:\s*"([^"]+)"(.{0,200}?)"core"\s*:\s*"([^"]+)"', js, re.S):
    calls.add((m.group(3), m.group(1)))

# Single-quoted variants
for m in re.finditer(r"'core'\s*:\s*'([^']+)'(.{0,200}?)'function'\s*:\s*'([^']+)'", js, re.S):
    calls.add((m.group(1), m.group(3)))

print(f"Found {len(calls)} unique CGI core/function pairs:\n")

by_core = {}
for core, func in sorted(calls):
    by_core.setdefault(core, []).append(func)

for core in sorted(by_core):
    print(f"  {core}:")
    for func in sorted(by_core[core]):
        print(f"    {func}")

# ── Also save the full JS to a file for manual inspection ────────────────────
out = "/tmp/ug65_login_js.txt"
with open(out, "w") as f:
    f.write(js)
print(f"\nFull JS saved to {out}")
print("To search manually:")
print(f'  grep -o \'"core":"[^"]*"\' {out} | sort -u')
print(f'  grep -o \'"function":"[^"]*"\' {out} | sort -u')
