#!/usr/bin/env python3
"""Download the UG65 web UI JS files and extract all CGI core/function calls."""

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

HOST     = os.environ.get("GW_HOST",  "192.168.1.1")
GW_PASS  = os.environ.get("GW_PASS",  "p0ssw0rd;")
GW_EMAIL = os.environ.get("GW_EMAIL", "admin")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

jar    = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(jar),
)

def fetch(path, method="GET", data=None, extra_headers=None):
    url = f"https://{HOST}{path}"
    hdrs = {"Content-Type": "application/json"}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with opener.open(req, timeout=10) as r:
            return r.read()
    except Exception as e:
        return b""

# AES-CBC login
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

def aes_enc(pt):
    k, iv = b"1111111111111111", b"2222222222222222"
    p = sym_padding.PKCS7(128).padder()
    padded = p.update(pt.encode()) + p.finalize()
    e = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
    return base64.b64encode(e.update(padded) + e.finalize()).decode()

_id = [1]
def cgi(core, func, vals=None):
    b = {"id": str(_id[0]), "execute": 1, "core": core, "function": func,
         "values": vals or [{}]}
    _id[0] += 1
    raw = fetch("/cgi", "POST", json.dumps(b).encode())
    try:
        return json.loads(raw)
    except Exception:
        return {"error": raw[:200].decode(errors="replace")}

# Log in
r = cgi("user", "login", [{"username": GW_EMAIL, "password": aes_enc(GW_PASS)}])
if r.get("status") != 0:
    sys.exit(f"CGI login failed: {r}")
print(f"Logged in. Firmware: {r.get('rtver','?')}\n")

# ── Fetch main page and collect JS/HTML urls ───────────────────────────────────
print("Fetching main page...")
index_html = fetch("/").decode(errors="replace")

# Find all .js and .html references
js_refs  = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', index_html)
html_refs = re.findall(r'href=["\']([^"\']+\.html[^"\']*)["\']', index_html)

print(f"  Found {len(js_refs)} JS refs, {len(html_refs)} HTML refs")
print(f"  HTML refs: {html_refs}\n")

# Collect JS from the HTML pages too
extra_js_from_html = []
for href in html_refs:
    url = href if href.startswith("/") else "/" + href
    html = fetch(url).decode(errors="replace")
    sub_js = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
    extra_js_from_html.extend(sub_js)
    # Also capture inline JS from these pages
    inline = "\n".join(re.findall(r'<script[^>]*>(.*?)</script>', html, re.S))
    if inline.strip():
        print(f"  {url}: {len(html)//1024}KB HTML  inline JS: {len(inline)} chars")
        # Search inline JS for CGI patterns immediately
        for m in re.finditer(r'"core"\s*:\s*"([^"]+)".*?"function"\s*:\s*"([^"]+)"', inline):
            extra_js_from_html  # just collect below
        # store inline as pseudo-url
        extra_js_from_html.append(("__inline__" + url, inline))
    else:
        sub_js_refs = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
        print(f"  {url}: {len(html)//1024}KB HTML  {len(sub_js_refs)} JS refs")

# Also try common locations for chunked/hashed bundles
extra_js_urls = [
    "/js/app.js", "/js/main.js", "/js/chunk-vendors.js",
    "/static/js/app.js", "/static/js/main.js",
    "/js/lns.js", "/js/lorawan.js", "/js/network.js",
]

all_content = []  # list of (label, text)

# All plain JS urls
js_urls = list(dict.fromkeys(
    [r if r.startswith("/") else "/" + r for r in js_refs]
    + [r if isinstance(r, str) and r.startswith("/") else ("/" + r if isinstance(r, str) else None)
       for r in extra_js_from_html if isinstance(r, str)]
    + extra_js_urls
))
for url in js_urls[:50]:
    if not url: continue
    raw = fetch(url)
    if not raw or len(raw) < 100: continue
    all_content.append((url, raw.decode(errors="replace")))

# Inline JS from HTML pages
for item in extra_js_from_html:
    if isinstance(item, tuple):
        all_content.append(item)

# ── Search all collected content ───────────────────────────────────────────────
all_cgi_calls = set()
for label, text in all_content:
    before = len(all_cgi_calls)
    for m in re.finditer(r'"core"\s*:\s*"([^"]+)".*?"function"\s*:\s*"([^"]+)"', text):
        all_cgi_calls.add((m.group(1), m.group(2)))
    for m in re.finditer(r"core\s*:\s*['\"]([^'\"]+)['\"].*?function\s*:\s*['\"]([^'\"]+)['\"]", text):
        all_cgi_calls.add((m.group(1), m.group(2)))
    for m in re.finditer(r'\{[^}]*core:"([^"]+)"[^}]*function:"([^"]+)"', text):
        all_cgi_calls.add((m.group(1), m.group(2)))
    added = len(all_cgi_calls) - before
    src = label if label.startswith("__inline__") else label
    klen = len(text) // 1024
    print(f"  {src}: {klen}KB  +{added} calls (total {len(all_cgi_calls)})")

if not all_cgi_calls:
    print("\nNo structured calls found — dumping LoRa/MQTT keyword hits...")
    for label, text in all_content:
        hits = set(re.findall(
            r'"(lorawan|lns|lora|mqtt|forwarder|packet|app|network|device|http|integr)[^"]{0,30}"',
            text, re.I))
        if hits:
            print(f"  {label}: {hits}")

# ── Print grouped results ──────────────────────────────────────────────────────
if all_cgi_calls:
    by_core = {}
    for core, func in sorted(all_cgi_calls):
        by_core.setdefault(core, set()).add(func)
    print(f"\n=== {len(all_cgi_calls)} unique CGI calls across {len(by_core)} cores ===\n")
    for core in sorted(by_core):
        print(f"  {core}:")
        for func in sorted(by_core[core]):
            print(f"    {func}")

# ── Now try calling anything lns/lorawan/mqtt/http related ────────────────────
relevant_cores = {c for c, f in all_cgi_calls
                  if any(kw in c.lower() for kw in ("lns","lora","mqtt","http","forward","app","integr"))}
print(f"\n=== Calling relevant cores: {relevant_cores} ===\n")
for core, func in sorted(all_cgi_calls):
    if core not in relevant_cores:
        continue
    resp = cgi(core, func)
    if resp.get("status") == 0:
        print(f"  ✓ {core}/{func} → {json.dumps(resp.get('result',''))[:250]}")
