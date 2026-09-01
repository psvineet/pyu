#!/usr/bin/env python3
"""
pyu.py  (Python Upload)

Single-file, stdlib-only secure upload endpoint, with an optional
Cloudflare Tunnel auto-setup wizard. Works on Termux, Arch, Fedora, Debian
(and derivatives).

WHAT IT DOES
------------
- Serves ONE endpoint: POST /upload  (+ a small web upload page at GET /)
- Client must send header:  X-API-Key: <key>
- Only SHA-256(key) is ever stored -> raw key not recoverable from disk.
- Everything else (wrong path/method, bad/missing key, oversized body,
  bad content-type) -> identical generic 404, no info leakage.
- No domain is hardcoded anywhere in this script. You are asked for your
  own domain the first time you run --init, or you can skip it entirely
  and use your own reverse proxy / tunnel instead of the -c wizard.

FLAGS (all short, single letter)
---------------------------------
  -i    init: create config + first API key (asks for your domain once)
  -f    force, used with -i to wipe an existing config
  -k    issue an additional API key
  -r ID revoke a key by its id
  -p N  port to listen on (default 820)
  -d    daemonize: detach and keep running after terminal closes
  -c    Cloudflare wizard: install cloudflared if needed, log in,
        create a tunnel, add the DNS record, write cloudflared's config,
        and start the tunnel (backgrounded) alongside the server.
  -h    help

FIRST RUN
---------
    python3 pyu.py -i
Prompts once for your domain (e.g. example.com) and a subdomain (press
enter to auto-generate a random unguessable 4-char one). Prints your API
key ONCE - copy it now, only its hash is kept.

NORMAL RUN
----------
    python3 pyu.py
Listens on 0.0.0.0:820. Put this behind TLS (the -c wizard, or your own
reverse proxy) before exposing it to the internet.

CLOUDFLARE WIZARD
------------------
    python3 pyu.py -c
Detects your OS package manager (pacman / dnf / apt / Termux's pkg),
installs `cloudflared` if it's missing, runs `cloudflared tunnel login`
(you approve in the browser it opens/prints a link for), creates a named
tunnel, points your chosen subdomain.domain at it with
`cloudflared tunnel route dns`, writes cloudflared's config.yml, and
starts the tunnel in the background. Then start pyu itself with -d.

CLIENT SIDE
-----------
    curl -X POST https://<sub>.<domain>/upload \\
         -H "X-API-Key: <your-key>" \\
         -F "file=@/path/to/file"

API KEY DERIVATION
-------------------
    raw_key = "ep_" + base64url(HMAC-SHA256(server_secret, "issue:" + uuid4 + ":" + ts)) + extra
- server_secret: 32 random bytes, generated once at -i, kept in
  pyu_config.json (chmod 600). Keys are bound to it; only their SHA-256
  hash is stored, checked with a timing-safe compare.
"""

import os
import sys
import json
import time
import uuid
import hmac
import shutil
import base64
import hashlib
import secrets
import platform
import argparse
import subprocess
import cgi
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# CONFIG - edit these
# ---------------------------------------------------------------------------
PORT = 820
HOST = "0.0.0.0"
UPLOAD_DIR = "/storage/emulated/0/Android/endpoint"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "pyu_config.json")   # secrets + domain
# cloudflared's own config/creds/cert now live in the standard /etc location
# (or Termux's $PREFIX/etc equivalent) -- see etc_cloudflared_dir() below.
MAX_UPLOAD_BYTES = 200 * 1024 * 1024   # 200 MB hard cap, tune as needed
ALLOWED_PATH = "/upload"               # the ONLY POST route that exists
RATE_LIMIT_WINDOW = 10                 # seconds
RATE_LIMIT_MAX = 20                    # max requests per IP per window
TUNNEL_NAME = "pyu-tunnel"
# ---------------------------------------------------------------------------

_rate_state = {}  # ip -> [timestamps]

# ---------------------------------------------------------------------------
# Minimal upload page: cream/white bg, Noto Sans, navy + gold accent.
# ---------------------------------------------------------------------------
PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Upload</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;600;700&display=swap');
  :root{ --cream:#faf6ef; --navy:#0b2545; --gold:#c9a227; }
  *{box-sizing:border-box;}
  html,body{ height:100%; margin:0; background:var(--cream); font-family:'Noto Sans', sans-serif; color:var(--navy); }
  body{ display:flex; align-items:center; justify-content:center; flex-direction:column; gap:22px; padding:24px; text-align:center; }
  h1{ font-size:1.25rem; font-weight:700; margin:0; letter-spacing:.02em; }
  #status{ font-size:.9rem; color:var(--navy); opacity:.75; min-height:1.2em; }
  input[type=password], input[type=text]{
    font-family:inherit; font-size:.95rem; padding:10px 14px; border:1.5px solid var(--navy);
    border-radius:8px; background:#fff; color:var(--navy); width:min(320px,80vw); outline:none;
  }
  input[type=password]:focus, input[type=text]:focus{ border-color:var(--gold); box-shadow:0 0 0 3px rgba(201,162,39,.25); }
  button{
    font-family:inherit; font-weight:600; font-size:1rem; padding:14px 34px; border-radius:10px;
    border:none; background:var(--navy); color:var(--cream); cursor:pointer; transition:transform .12s ease, background .2s ease;
  }
  button:hover{ background:#123162; }
  button:active{ transform:scale(.97); }
  button.gold{ background:var(--gold); color:var(--navy); }
  button.gold:hover{ background:#d8b23a; }
  #fileInput{ display:none; }
  #picked{ font-size:.85rem; opacity:.7; }
  .hidden{ display:none !important; }
</style>
</head>
<body>
  <h1>Secure Upload</h1>
  <input id="apiKey" type="password" placeholder="API key" autocomplete="off">
  <div id="picked"></div>
  <button id="pickBtn" class="gold">Choose File</button>
  <button id="sendBtn" class="hidden">Upload</button>
  <div id="status"></div>
  <input type="file" id="fileInput">

<script>
  const fileInput = document.getElementById('fileInput');
  const pickBtn   = document.getElementById('pickBtn');
  const sendBtn   = document.getElementById('sendBtn');
  const status    = document.getElementById('status');
  const picked    = document.getElementById('picked');
  const apiKey    = document.getElementById('apiKey');

  function openPicker(){ fileInput.click(); }

  // Browsers generally block auto-opening the picker without a real click;
  // the gold button (always visible) is the fallback either way.
  window.addEventListener('load', () => {
    try { openPicker(); } catch (e) { /* fallback button stays visible */ }
  });

  pickBtn.addEventListener('click', openPicker);

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length){
      picked.textContent = fileInput.files[0].name;
      sendBtn.classList.remove('hidden');
    }
  });

  sendBtn.addEventListener('click', async () => {
    if (!fileInput.files.length){ status.textContent = 'Choose a file first.'; return; }
    if (!apiKey.value){ status.textContent = 'Enter API key.'; return; }
    status.textContent = 'Uploading...';
    sendBtn.disabled = true;
    try{
      // 1. get a one-time nonce
      const nonceRes = await fetch('/nonce', { cache: 'no-store' });
      if (!nonceRes.ok) throw new Error('nonce');
      const { nonce } = await nonceRes.json();

      // 2. prove knowledge of the key WITHOUT sending the key itself:
      //    HMAC-SHA256(rawKey, nonce), computed entirely in the browser.
      const enc = new TextEncoder();
      const cryptoKey = await crypto.subtle.importKey(
        'raw', enc.encode(apiKey.value), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      );
      const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(nonce));
      const authToken = Array.from(new Uint8Array(sigBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');

      // 3. send only the nonce + proof -- the raw key never touches the network
      const fd = new FormData();
      fd.append('file', fileInput.files[0]);
      const res = await fetch('/upload', {
        method: 'POST',
        headers: { 'X-Nonce': nonce, 'X-Auth-Token': authToken },
        body: fd
      });
      status.textContent = res.ok ? 'Uploaded.' : 'Failed (check key / file).';
    } catch(e){
      status.textContent = 'Network error.';
    }
    sendBtn.disabled = false;
  });
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Config / key management
# ---------------------------------------------------------------------------
def _now():
    return time.time()


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def save_config(data):
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)


def sha256_hex(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


def _keystream(server_secret: bytes, salt: bytes, length: int) -> bytes:
    """Deterministic stdlib-only keystream (SHA-256 counter mode) used to
    reversibly store the raw key so the web page can do challenge-response
    auth without ever putting the raw key on the wire. Anyone who can read
    pyu_config.json AND knows the server_secret it also contains can
    decrypt this -- same trust boundary as the rest of this file already
    assumes (if an attacker has full read access to your config, you have
    bigger problems). This defends against network interception, not
    local disk compromise.
    """
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(server_secret + salt + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def encrypt_for_storage(raw: bytes, server_secret: bytes):
    salt = os.urandom(16)
    ks = _keystream(server_secret, salt, len(raw))
    ct = bytes(a ^ b for a, b in zip(raw, ks))
    return base64.b64encode(salt).decode(), base64.b64encode(ct).decode()


def decrypt_from_storage(salt_b64: str, ct_b64: str, server_secret: bytes) -> bytes:
    salt = base64.b64decode(salt_b64)
    ct = base64.b64decode(ct_b64)
    ks = _keystream(server_secret, salt, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def gen_raw_key(server_secret: bytes) -> str:
    material = f"issue:{uuid.uuid4()}:{time.time_ns()}".encode()
    digest = hmac.new(server_secret, material, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    extra = secrets.token_urlsafe(8)
    return f"ep_{token}{extra}"[:64]


def gen_subdomain(length=4) -> str:
    """Random unguessable subdomain: lowercase letters + digits."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def init_config(force=False):
    if os.path.exists(CONFIG_FILE) and not force:
        print("pyu_config.json already exists. Use -k to add another key,")
        print("or pass -i -f to wipe it and start over (invalidates all keys).")
        return

    print("=== pyu setup ===")
    domain = input("Your domain (e.g. example.com), or leave blank to configure later: ").strip()
    subdomain = ""
    if domain:
        sub_in = input(f"Subdomain to use [enter for random 4-char]: ").strip()
        subdomain = sub_in if sub_in else gen_subdomain(4)
        print(f"Will use: {subdomain}.{domain}")

    server_secret = os.urandom(32)
    data = {
        "server_secret_b64": base64.b64encode(server_secret).decode(),
        "keys": [],
        "domain": domain,
        "subdomain": subdomain,
    }
    save_config(data)
    print("Initialized pyu_config.json.")
    add_new_key(data)


def add_new_key(data=None):
    if data is None:
        data = load_config()
        if data is None:
            print("No pyu_config.json found. Run with -i first.")
            sys.exit(1)
    server_secret = base64.b64decode(data["server_secret_b64"])
    raw_key = gen_raw_key(server_secret)
    salt_b64, enc_b64 = encrypt_for_storage(raw_key.encode(), server_secret)
    entry = {
        "id": secrets.token_hex(4),
        "hash": sha256_hex(raw_key.encode()),
        "salt": salt_b64,
        "enc": enc_b64,
        "created": int(_now()),
    }
    data["keys"].append(entry)
    save_config(data)
    print("\n=== NEW API KEY (copy now, shown once, not stored raw) ===")
    print(raw_key)
    print(f"key id: {entry['id']}")
    print("=== configure this in your trusted client, then discard this terminal output ===\n")


def revoke_key(key_id):
    data = load_config()
    if not data:
        print("No pyu_config.json found.")
        return
    before = len(data["keys"])
    data["keys"] = [k for k in data["keys"] if k["id"] != key_id]
    save_config(data)
    print(f"Removed {before - len(data['keys'])} key(s) with id '{key_id}'.")


def verify_key(presented: str, data) -> bool:
    if not presented or not data:
        return False
    presented_hash = sha256_hex(presented.encode())
    ok = False
    for entry in data["keys"]:
        if hmac.compare_digest(entry["hash"], presented_hash):
            ok = True
    return ok


# ---------------------------------------------------------------------------
# Challenge-response auth for the web page: the browser NEVER sends the raw
# key over the network. Instead:
#   1. it fetches a one-time nonce from GET /nonce
#   2. it computes HMAC-SHA256(raw_key, nonce) locally, in-browser
#   3. it sends only {nonce, hmac} to POST /upload
# An interceptor who captures this traffic gets a nonce that is deleted
# after first use and a proof tied to that single nonce -- neither is
# replayable and neither reveals the key. curl/API clients can keep using
# the plain X-API-Key header (that path is for trusted server-to-server
# use, not a browser sending credentials over a network you don't control).
# ---------------------------------------------------------------------------
_nonce_store = {}   # nonce -> expiry_timestamp
_NONCE_TTL = 60      # seconds
_NONCE_MAX = 500     # hard cap so a nonce-request flood can't grow memory unbounded


def issue_nonce() -> str:
    now = _now()
    # opportunistic cleanup of expired nonces so the dict doesn't grow forever
    for n in [n for n, exp in _nonce_store.items() if exp < now]:
        _nonce_store.pop(n, None)
    if len(_nonce_store) >= _NONCE_MAX:
        # drop the oldest-issued entries rather than let the store grow
        for n in sorted(_nonce_store, key=_nonce_store.get)[: len(_nonce_store) - _NONCE_MAX + 1]:
            _nonce_store.pop(n, None)
    nonce = secrets.token_urlsafe(24)
    _nonce_store[nonce] = now + _NONCE_TTL
    return nonce


def consume_nonce(nonce: str) -> bool:
    exp = _nonce_store.pop(nonce, None)
    return exp is not None and exp >= _now()


def verify_challenge(nonce: str, token_hex: str, data) -> bool:
    if not nonce or not token_hex or not data:
        return False
    if not consume_nonce(nonce):
        return False
    server_secret = base64.b64decode(data["server_secret_b64"])
    for entry in data["keys"]:
        if "enc" not in entry or "salt" not in entry:
            continue  # keys issued before this feature was added
        try:
            raw_key = decrypt_from_storage(entry["salt"], entry["enc"], server_secret)
        except Exception:
            continue
        expected = hmac.new(raw_key, nonce.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, token_hex):
            return True
    return False


def rate_limited(ip: str) -> bool:
    now = _now()
    window_start = now - RATE_LIMIT_WINDOW
    hits = [t for t in _rate_state.get(ip, []) if t > window_start]
    hits.append(now)
    _rate_state[ip] = hits
    return len(hits) > RATE_LIMIT_MAX


def safe_filename(original: str) -> str:
    ext = ""
    if original:
        _, dot, tail = original.rpartition(".")
        if dot and 1 <= len(tail) <= 10 and tail.isalnum():
            ext = "." + tail.lower()
    return f"{int(_now())}_{secrets.token_hex(8)}{ext}"


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "srv"
    sys_version = ""
    protocol_version = "HTTP/1.1"   # needed for correct keep-alive + Connection:close handling
    timeout = 15                    # seconds; mitigates slow-header / slowloris style connections

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _security_headers(self):
        # Defense-in-depth headers; irrelevant to API clients, cheap to send.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'")

    def _deny(self, code=404):
        body = b'{"error":"not found"}'
        self.send_response(code if code in (404, 400, 413, 429) else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _ok(self, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _serve_page(self):
        body = PAGE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _smuggling_guard(self) -> bool:
        """Reject requests that mix Transfer-Encoding with Content-Length, or
        use chunked/unsupported encodings -- classic request-smuggling vectors
        this server has no reason to ever need to support."""
        te = self.headers.get("Transfer-Encoding", "")
        cl = self.headers.get("Content-Length")
        if te:
            return False  # this server never supports Transfer-Encoding at all
        if cl is not None:
            try:
                if int(cl) < 0:
                    return False
            except ValueError:
                return False
        return True

    # Methods this server has no legitimate use for -- reject explicitly and
    # uniformly rather than letting the base handler improvise a response.
    def do_HEAD(self):
        self._deny(404)

    def do_OPTIONS(self):
        self._deny(404)

    def do_TRACE(self):
        self._deny(404)

    def do_PATCH(self):
        self._deny(404)

    def do_CONNECT(self):
        self._deny(404)

    def _nonce_response(self):
        data = load_config()
        if not data:
            self._deny(404)
            return
        nonce = issue_nonce()
        body = json.dumps({"nonce": nonce}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._smuggling_guard():
            self._deny(400)
            return
        if self.path == "/" or self.path.startswith("/?"):
            self._serve_page()
        elif self.path == "/nonce":
            if rate_limited(self.client_address[0]):
                self._deny(429)
                return
            self._nonce_response()
        else:
            self._deny(404)

    def do_PUT(self):
        self._deny(404)

    def do_DELETE(self):
        self._deny(404)

    def do_POST(self):
        if not self._smuggling_guard():
            self._deny(400)
            return
        client_ip = self.client_address[0]

        if rate_limited(client_ip):
            self._deny(429)
            return
        if self.path != ALLOWED_PATH:
            self._deny(404)
            return

        api_key = self.headers.get("X-API-Key", "")
        nonce = self.headers.get("X-Nonce", "")
        auth_token = self.headers.get("X-Auth-Token", "")
        data = load_config()

        authed = False
        if nonce and auth_token:
            authed = verify_challenge(nonce, auth_token, data)
        elif api_key:
            authed = verify_key(api_key, data)

        if not authed:
            time.sleep(0.3)
            self._deny(404)
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._deny(400)
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            self._deny(413)
            return

        try:
            body = self.rfile.read(length)
            fs = cgi.FieldStorage(
                fp=io.BytesIO(body), headers=self.headers,
                environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": content_type},
            )
            file_field = None
            for key in fs.keys():
                item = fs[key]
                if getattr(item, "filename", None):
                    file_field = item
                    break
            if file_field is None or not file_field.file:
                self._deny(400)
                return

            os.makedirs(UPLOAD_DIR, exist_ok=True)
            try:
                os.chmod(UPLOAD_DIR, 0o700)
            except Exception:
                pass

            fname = safe_filename(file_field.filename)
            dest = os.path.join(UPLOAD_DIR, fname)
            with open(dest, "wb") as out:
                out.write(file_field.file.read())
            os.chmod(dest, 0o600)

            self.log_message("upload ok from %s -> %s", client_ip, fname)
            self._ok({"status": "ok", "stored_as": fname})
        except Exception:
            self._deny(400)


def daemonize(log_path):
    """Classic double-fork so the server keeps running after the terminal closes."""
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    log_fd = open(log_path, "a+")
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())
    devnull = open(os.devnull, "r")
    os.dup2(devnull.fileno(), sys.stdin.fileno())


def run(port):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    try:
        os.chmod(UPLOAD_DIR, 0o700)
    except Exception:
        pass
    server = ThreadingHTTPServer((HOST, port), Handler)
    server.daemon_threads = True     # don't block process exit on stuck handlers
    server.request_queue_size = 32   # bound the backlog rather than accept unbounded
    print(f"Listening on {HOST}:{port}, uploads -> {UPLOAD_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


# ---------------------------------------------------------------------------
# Cloudflare Tunnel wizard
# ---------------------------------------------------------------------------
def _run(cmd, **kw):
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, **kw)


def detect_pkg_manager():
    if shutil.which("pkg") and "com.termux" in os.environ.get("PREFIX", ""):
        return "termux"
    if shutil.which("pacman"):
        return "pacman"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("apt") or shutil.which("apt-get"):
        return "apt"
    return None


def install_cloudflared():
    if shutil.which("cloudflared"):
        print("cloudflared already installed.")
        return True

    mgr = detect_pkg_manager()
    print(f"Detected package manager: {mgr or 'unknown'}")

    if mgr == "termux":
        r = _run(["pkg", "install", "-y", "cloudflared"])
        return r.returncode == 0 and bool(shutil.which("cloudflared"))

    if mgr == "pacman":
        # cloudflared is in the AUR on plain Arch; try pacman first in case
        # it's already provided by a mirror/repo, otherwise tell the user.
        r = _run(["sudo", "pacman", "-Sy", "--noconfirm", "cloudflared"])
        if r.returncode == 0 and shutil.which("cloudflared"):
            return True
        print("Could not install via pacman (cloudflared is usually in the AUR).")
        print("Install manually, e.g.: yay -S cloudflared   (or paru -S cloudflared)")
        return False

    if mgr == "dnf":
        _run(["sudo", "dnf", "install", "-y", "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-x86_64.rpm"])
        return bool(shutil.which("cloudflared"))

    if mgr == "apt":
        arch = platform.machine()
        deb_arch = "amd64" if "x86_64" in arch else ("arm64" if "aarch64" in arch or "arm" in arch else "amd64")
        deb_url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{deb_arch}.deb"
        deb_path = "/tmp/cloudflared.deb"
        _run(["curl", "-fsSL", "-o", deb_path, deb_url])
        _run(["sudo", "dpkg", "-i", deb_path])
        return bool(shutil.which("cloudflared"))

    print("Unknown OS/package manager. Install cloudflared manually:")
    print("  https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
    return False


def is_termux():
    return "com.termux" in os.environ.get("PREFIX", "")


def has_systemd():
    return bool(shutil.which("systemctl")) and os.path.exists("/run/systemd/system")


def etc_cloudflared_dir():
    """Standard location for cloudflared's config, adapted for Termux
    (which has no writable /etc) vs regular Linux (real /etc)."""
    if is_termux():
        prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
        return os.path.join(prefix, "etc", "cloudflared")
    return "/etc/cloudflared"


def maybe_sudo(cmd):
    """Prefix with sudo unless already root or on Termux (no sudo/root there)."""
    if is_termux() or os.geteuid() == 0:
        return cmd
    return ["sudo"] + cmd


def register_service_systemd(config_yml):
    """Use cloudflared's own systemd installer, which reads /etc/cloudflared/config.yml."""
    print("Registering systemd service (cloudflared)...")
    r = _run(maybe_sudo(["cloudflared", "--config", config_yml, "service", "install"]))
    if r.returncode != 0:
        print("`cloudflared service install` failed. You can retry manually:")
        print(f"  sudo cloudflared --config {config_yml} service install")
        return False
    _run(maybe_sudo(["systemctl", "enable", "--now", "cloudflared"]))
    print("Service 'cloudflared' enabled and started via systemd.")
    print("Check status with:  systemctl status cloudflared")
    print("Check logs with:    journalctl -u cloudflared -f")
    return True


def register_service_termux(config_yml):
    """Termux has no systemd; it uses runit via the termux-services package."""
    if not shutil.which("sv-enable"):
        print("Installing termux-services (provides runit-based service management)...")
        _run(["pkg", "install", "-y", "termux-services"])

    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    svdir = os.path.join(prefix, "var", "service", "cloudflared")
    os.makedirs(svdir, exist_ok=True)
    run_script = os.path.join(svdir, "run")
    with open(run_script, "w") as f:
        f.write(
            "#!/data/data/com.termux/files/usr/bin/sh\n"
            f'exec cloudflared --config "{config_yml}" tunnel run {TUNNEL_NAME} 2>&1\n'
        )
    os.chmod(run_script, 0o755)

    if shutil.which("sv-enable"):
        _run(["sv-enable", "cloudflared"])
        _run(["sv", "up", "cloudflared"])
        print("Service 'cloudflared' registered and started via termux-services (runit).")
        print("Check status with:  sv status cloudflared")
        print("Restart with:       sv restart cloudflared")
        print("NOTE: start the Termux:Boot app / enable 'Start services on boot' in")
        print("      Termux settings so this survives a device reboot, and run")
        print("      `termux-wake-lock` so Android doesn't kill it in the background.")
        return True

    print("termux-services unavailable; falling back to a plain background process.")
    log_path = os.path.join(SCRIPT_DIR, "cloudflared.log")
    with open(log_path, "a") as logf:
        subprocess.Popen(
            ["cloudflared", "--config", config_yml, "tunnel", "run", TUNNEL_NAME],
            stdout=logf, stderr=logf, stdin=subprocess.DEVNULL, start_new_session=True,
        )
    print(f"Started detached, logs -> {log_path} (will not survive a reboot).")
    return True


def register_cloudflared_service(config_yml):
    if has_systemd():
        return register_service_systemd(config_yml)
    if is_termux():
        return register_service_termux(config_yml)
    print("No systemd and not Termux: starting cloudflared as a plain background")
    print("process instead (won't auto-restart on reboot).")
    log_path = os.path.join(SCRIPT_DIR, "cloudflared.log")
    with open(log_path, "a") as logf:
        subprocess.Popen(
            ["cloudflared", "--config", config_yml, "tunnel", "run", TUNNEL_NAME],
            stdout=logf, stderr=logf, stdin=subprocess.DEVNULL, start_new_session=True,
        )
    print(f"Started detached, logs -> {log_path}")
    return True


def cloudflare_setup(port):
    data = load_config()
    if not data:
        print("No pyu_config.json found. Run with -i first (it also asks for your domain).")
        sys.exit(1)

    domain = data.get("domain", "")
    subdomain = data.get("subdomain", "")
    if not domain:
        domain = input("Your domain (e.g. example.com): ").strip()
    if not subdomain:
        sub_in = input("Subdomain to use [enter for random 4-char]: ").strip()
        subdomain = sub_in if sub_in else gen_subdomain(4)
    hostname = f"{subdomain}.{domain}"

    data["domain"] = domain
    data["subdomain"] = subdomain
    save_config(data)

    print(f"\nUsing hostname: {hostname}\n")

    if not install_cloudflared():
        print("cloudflared install failed or unsupported OS. Aborting wizard.")
        sys.exit(1)

    etc_dir = etc_cloudflared_dir()
    print(f"cloudflared config directory: {etc_dir}")
    mk = maybe_sudo(["mkdir", "-p", etc_dir])
    _run(mk)
    if not is_termux() and os.geteuid() != 0:
        _run(["sudo", "chown", "-R", os.environ.get("USER", "root"), etc_dir])

    cert_path = os.path.join(etc_dir, "cert.pem")
    creds_path = os.path.join(etc_dir, f"{TUNNEL_NAME}-creds.json")
    config_yml = os.path.join(etc_dir, "config.yml")

    env = os.environ.copy()
    env["TUNNEL_ORIGIN_CERT"] = cert_path

    # 1) Authorize (opens a browser link; user approves in the Cloudflare dashboard)
    print("\nStep 1/5: authorize with Cloudflare (approve the link that opens/prints below)...")
    _run(["cloudflared", "tunnel", "--origincert", cert_path, "login"], env=env)
    if not os.path.exists(cert_path):
        print("Authorization did not complete (no cert.pem found). Aborting.")
        sys.exit(1)

    # 2) Create the tunnel (safe to re-run; cloudflared errors harmlessly if it exists)
    print("Step 2/5: creating tunnel...")
    _run(["cloudflared", "tunnel", "--origincert", cert_path,
          "--credentials-file", creds_path,
          "create", TUNNEL_NAME], env=env)

    if not os.path.exists(creds_path):
        # fall back to wherever cloudflared actually put it (~/.cloudflared)
        default_dir = os.path.expanduser("~/.cloudflared")
        found = None
        if os.path.exists(default_dir):
            for fname in os.listdir(default_dir):
                if fname.endswith(".json"):
                    found = os.path.join(default_dir, fname)
        if not found:
            print("Could not locate tunnel credentials file. Aborting.")
            sys.exit(1)
        _run(maybe_sudo(["cp", found, creds_path]))

    tunnel_id = os.path.splitext(os.path.basename(creds_path))[0].replace(f"{TUNNEL_NAME}-creds", "")
    if not tunnel_id:
        # credentials file itself contains the TunnelID field; read it
        try:
            with open(creds_path) as f:
                tunnel_id = json.load(f).get("TunnelID", "")
        except Exception:
            tunnel_id = ""

    # 3) Route DNS: point hostname -> tunnel
    print("Step 3/5: creating DNS record...")
    _run(["cloudflared", "tunnel", "--origincert", cert_path,
          "route", "dns", TUNNEL_NAME, hostname], env=env)

    # 4) Write cloudflared config.yml in the standard /etc location
    print("Step 4/5: writing cloudflared config to standard location...")
    config_body = (
        f"tunnel: {tunnel_id or TUNNEL_NAME}\n"
        f"credentials-file: {creds_path}\n"
        f"origincert: {cert_path}\n"
        f"ingress:\n"
        f"  - hostname: {hostname}\n"
        f"    service: http://localhost:{port}\n"
        f"  - service: http_status:404\n"
    )
    tmp_cfg = os.path.join(SCRIPT_DIR, ".config_yml.tmp")
    with open(tmp_cfg, "w") as f:
        f.write(config_body)
    _run(maybe_sudo(["mv", tmp_cfg, config_yml]))
    print(f"Wrote {config_yml}")

    # keep a copy of key paths in pyu_config.json for reference
    data["cloudflared_config"] = config_yml
    data["cloudflared_hostname"] = hostname
    save_config(data)

    # 5) Register + start as a real service (systemd or Termux runit)
    print("Step 5/5: registering cloudflared as a background service...")
    register_cloudflared_service(config_yml)

    print(f"\nDone. Your endpoint should be reachable at: https://{hostname}/")
    print(f"Now start pyu itself, e.g.:  python3 pyu.py -d -p {port}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="pyu.py", add_help=True)
    ap.add_argument("-i", action="store_true", help="init: create config + first API key")
    ap.add_argument("-f", action="store_true", help="with -i, force-wipe existing config")
    ap.add_argument("-k", action="store_true", help="issue an additional API key")
    ap.add_argument("-r", metavar="KEY_ID", help="revoke a key by its id")
    ap.add_argument("-p", type=int, default=PORT, help="listen port (default 820)")
    ap.add_argument("-d", action="store_true", help="daemonize: run detached in background")
    ap.add_argument("-c", action="store_true", help="Cloudflare wizard: install, auth, tunnel, DNS, config, start")
    args = ap.parse_args()

    if args.i:
        init_config(force=args.f)
    elif args.k:
        add_new_key()
    elif args.r:
        revoke_key(args.r)
    elif args.c:
        cloudflare_setup(args.p)
    else:
        if not os.path.exists(CONFIG_FILE):
            print("No pyu_config.json found. Run with -i first to generate an API key.")
            sys.exit(1)
        if args.d:
            log_path = os.path.join(SCRIPT_DIR, "pyu.log")
            print(f"Starting in background, logs -> {log_path}")
            daemonize(log_path)
        run(args.p)
