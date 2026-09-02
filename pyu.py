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
  -w    set/replace a human-typable password (works alongside API keys)
  -r ID revoke a key by its id
  -p N  port to listen on (default 8820)
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
Listens on 0.0.0.0:8820. Put this behind TLS (the -c wizard, or your own
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

    Multiple files in one request (repeat -F "file=@...", same field name):
    curl -X POST https://<sub>.<domain>/upload \\
         -H "X-API-Key: <your-key>" \\
         -F "file=@/path/one.jpg" -F "file=@/path/two.pdf" -F "file=@/path/three.zip"

    All files in a directory (bash):
    curl -X POST https://<sub>.<domain>/upload -H "X-API-Key: <your-key>" \\
         $(for f in /path/to/dir/*; do printf ' -F file=@%q' "$f"; done)

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
import io
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# CONFIG - edit these
# ---------------------------------------------------------------------------
PORT = 8820
HOST = "0.0.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "pyu_config.json")   # secrets + domain
# cloudflared's own config/creds/cert now live in the standard /etc location
# (or Termux's $PREFIX/etc equivalent) -- see etc_cloudflared_dir() below.
MAX_UPLOAD_BYTES = 200 * 1024 * 1024   # 200 MB hard cap, tune as needed
MAX_FILES_PER_UPLOAD = 20              # cap on files accepted in a single multi-file request
ALLOWED_PATH = "/upload"               # the ONLY POST route that exists
RATE_LIMIT_WINDOW = 10                 # seconds
RATE_LIMIT_MAX = 20                    # max requests per IP per window
TUNNEL_NAME = "pyu-tunnel"
# ---------------------------------------------------------------------------


def _default_upload_dir() -> str:
    """The Android/Termux path only exists (and is only writable) inside
    Termux itself. On Arch/Fedora/Debian/regular Linux, /storage doesn't
    exist at all and creating it fails with PermissionError -- so pick a
    sensible default per platform instead of hardcoding the Termux path."""
    if "com.termux" in os.environ.get("PREFIX", ""):
        return "/storage/emulated/0/Android/endpoint"
    return os.path.join(SCRIPT_DIR, "uploads")


# Override by setting the PYU_UPLOAD_DIR environment variable, or by editing
# this line directly -- either works, env var takes precedence.
UPLOAD_DIR = os.environ.get("PYU_UPLOAD_DIR") or _default_upload_dir()

_rate_state = {}  # ip -> [timestamps]
_rate_lock = threading.Lock()
_auth_fail_state = {}  # ip -> [timestamps of failed auth attempts]
_auth_fail_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Tiny stdlib-only multipart/form-data parser (replaces removed `cgi` module,
# gone in Py3.13+). Returns every file field found, to support multi-file
# uploads in a single request.
# ---------------------------------------------------------------------------
def parse_multipart_files(body: bytes, content_type: str):
    """Tiny stdlib-only multipart/form-data parser. Locates the boundary
    delimiter by explicit byte search rather than str.split(), because a
    naive split() on the boundary sequence corrupts any file whose binary
    content happens to contain those same bytes (which is common for
    images, archives, and other binary formats at any real size) -- this
    finds only genuine boundary lines (delimiter followed by CRLF or
    "--" at the very end), not arbitrary occurrences inside file data.
    Returns a list of (filename, bytes) for every file field present, in
    the order they appear. Non-file fields are skipped. Empty list if the
    body has no file fields or can't be parsed.
    """
    m = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', content_type)
    if not m:
        return []
    boundary = (m.group(1) or m.group(2)).strip()
    delim = b"--" + boundary.encode()

    # Find every position where a genuine boundary line starts: the
    # delimiter bytes immediately followed by CRLF (a normal part
    # separator) or by "--" (the terminating boundary). This rejects
    # a delimiter-shaped byte sequence appearing mid-file, since real
    # boundary lines always sit on their own CRLF-terminated line.
    positions = []
    start = 0
    dlen = len(delim)
    while True:
        idx = body.find(delim, start)
        if idx == -1:
            break
        after = body[idx + dlen: idx + dlen + 2]
        if after in (b"\r\n", b"--"):
            positions.append(idx)
        start = idx + dlen
    if len(positions) < 2:
        return []

    files = []
    for i in range(len(positions) - 1):
        part_start = positions[i] + dlen
        # skip the CRLF right after the opening boundary line
        if body[part_start:part_start + 2] == b"\r\n":
            part_start += 2
        part_end = positions[i + 1]
        part = body[part_start:part_end]
        # strip the trailing CRLF that precedes the next boundary line
        if part.endswith(b"\r\n"):
            part = part[:-2]

        if b"\r\n\r\n" not in part:
            continue
        headers_raw, content = part.split(b"\r\n\r\n", 1)
        headers_txt = headers_raw.decode(errors="replace")
        fn_match = re.search(r'filename="([^"]*)"', headers_txt)
        if fn_match and fn_match.group(1):
            files.append((fn_match.group(1), content))
    return files

# ---------------------------------------------------------------------------
# Upload page: card layout, drag-and-drop, progress bar, responsive.
# ---------------------------------------------------------------------------
PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Upload</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Noto+Sans:wght@400;500;600;700&display=swap');
  :root{
    --cream:#faf6ef; --navy:#0b2545; --navy-2:#123162; --gold:#c9a227; --gold-2:#d8b23a;
    --line:#e4ddcf; --danger:#b3413a; --ok:#2f7d4f;
  }
  *{box-sizing:border-box;}
  html,body{ height:100%; margin:0; }
  body{
    min-height:100dvh; display:flex; align-items:center; justify-content:center;
    background:
      radial-gradient(1200px 600px at 15% -10%, rgba(201,162,39,.10), transparent 60%),
      radial-gradient(1000px 500px at 110% 110%, rgba(11,37,69,.08), transparent 55%),
      var(--cream);
    font-family:'Noto Sans', sans-serif; color:var(--navy); padding:20px;
  }
  .card{
    width:100%; max-width:460px; background:#fff; border-radius:20px;
    box-shadow:0 20px 50px -20px rgba(11,37,69,.25), 0 2px 8px rgba(11,37,69,.06);
    padding:32px 28px; border:1px solid var(--line);
  }
  .brand{ display:flex; align-items:center; gap:10px; margin-bottom:22px; }
  .brand-dot{
    width:10px; height:10px; border-radius:50%; background:var(--gold);
    box-shadow:0 0 0 4px rgba(201,162,39,.18);
  }
  h1{ font-size:1.15rem; font-weight:700; margin:0; letter-spacing:.01em; }
  .sub{ font-size:.82rem; color:var(--navy); opacity:.6; margin:2px 0 0; }

  label.field-label{
    display:block; font-size:.78rem; font-weight:600; text-transform:uppercase;
    letter-spacing:.06em; opacity:.55; margin:20px 0 8px;
  }

  .key-row{ position:relative; }
  input[type=password], input[type=text]{
    font-family:inherit; font-size:.95rem; padding:12px 42px 12px 14px; border:1.5px solid var(--line);
    border-radius:10px; background:#fcfbf8; color:var(--navy); width:100%; outline:none;
    transition:border-color .15s ease, box-shadow .15s ease;
  }
  input[type=password]:focus, input[type=text]:focus{
    border-color:var(--gold); box-shadow:0 0 0 3px rgba(201,162,39,.18); background:#fff;
  }
  .key-toggle{
    position:absolute; right:8px; top:50%; transform:translateY(-50%);
    background:none; border:none; padding:6px; cursor:pointer; opacity:.5; font-size:.85rem;
    color:var(--navy); border-radius:6px;
  }
  .key-toggle:hover{ opacity:.85; background:rgba(11,37,69,.06); }

  .dropzone{
    margin-top:20px; border:2px dashed var(--line); border-radius:14px;
    padding:26px 16px; text-align:center; cursor:pointer; background:#fcfbf8;
    transition:border-color .15s ease, background .15s ease;
  }
  .dropzone:hover{ border-color:var(--gold); background:#fffdf6; }
  .dropzone.drag{ border-color:var(--gold); background:#fff8e6; }
  .dz-icon{ margin-bottom:10px; display:flex; justify-content:center; }
  .dz-icon svg{ width:34px; height:34px; stroke:var(--navy); opacity:.55; }
  .dropzone:hover .dz-icon svg, .dropzone.drag .dz-icon svg{ opacity:.85; stroke:var(--gold); }
  .dz-main{ font-size:.9rem; font-weight:600; }
  .dz-sub{ font-size:.78rem; opacity:.55; margin-top:3px; }
  #fileInput{ display:none; }

  .file-list{ margin-top:14px; display:flex; flex-direction:column; gap:8px; max-height:260px; overflow-y:auto; }
  .file-row{
    display:flex; align-items:center; gap:10px; padding:10px 12px;
    background:#fcfbf8; border:1px solid var(--line); border-radius:10px; font-size:.85rem;
  }
  .file-row .ficon{ flex-shrink:0; width:18px; height:18px; opacity:.5; }
  .file-row .ficon svg{ width:100%; height:100%; }
  .file-row .meta{ flex:1; min-width:0; }
  .file-row .name{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:600; }
  .file-row .sub-line{ font-size:.75rem; opacity:.55; margin-top:1px; }
  .file-row .sub-line.err{ color:var(--danger); opacity:.9; }
  .file-row .sub-line.ok{ color:var(--ok); opacity:.9; }
  .file-row .row-track{ height:4px; background:var(--line); border-radius:99px; overflow:hidden; margin-top:5px; }
  .file-row .row-fill{
    height:100%; width:0%; background:linear-gradient(90deg, var(--gold), var(--gold-2));
    border-radius:99px; transition:width .12s ease;
  }
  .file-row.done .row-fill{ background:var(--ok); }
  .file-row.failed .row-fill{ background:var(--danger); }
  .file-row .remove{
    background:none; border:none; cursor:pointer; opacity:.4; padding:4px; flex-shrink:0;
    color:var(--navy); border-radius:6px; display:flex;
  }
  .file-row .remove:hover{ opacity:.85; background:rgba(11,37,69,.06); }
  .file-row .remove svg{ width:14px; height:14px; }
  .file-row .status-icon{ width:16px; height:16px; flex-shrink:0; display:none; }
  .file-row .status-icon svg{ width:100%; height:100%; }
  .file-row.done .status-icon{ display:block; }
  .file-row.done .status-icon svg{ stroke:var(--ok); }
  .file-row.failed .status-icon{ display:block; }
  .file-row.failed .status-icon svg{ stroke:var(--danger); }

  .btn-row{ display:flex; gap:10px; margin-top:18px; }
  button.primary{
    font-family:inherit; font-weight:700; font-size:.95rem; padding:14px 20px; border-radius:12px;
    border:none; background:var(--navy); color:var(--cream); cursor:pointer; flex:1;
    transition:transform .1s ease, background .2s ease, opacity .15s ease;
  }
  button.primary:hover:not(:disabled){ background:var(--navy-2); }
  button.primary:active:not(:disabled){ transform:scale(.98); }
  button.primary:disabled{ opacity:.5; cursor:not-allowed; }
  button.cancel{
    font-family:inherit; font-weight:600; font-size:.9rem; padding:14px 18px; border-radius:12px;
    border:1.5px solid var(--line); background:#fff; color:var(--navy); cursor:pointer;
    display:none;
  }
  button.cancel.show{ display:block; }
  button.cancel:hover{ border-color:var(--danger); color:var(--danger); }

  .overall{ margin-top:14px; display:none; }
  .overall.show{ display:block; }
  .overall-track{ height:8px; background:var(--line); border-radius:99px; overflow:hidden; }
  .overall-fill{
    height:100%; width:0%; background:linear-gradient(90deg, var(--gold), var(--gold-2));
    border-radius:99px; transition:width .15s ease;
  }
  .overall-label{ font-size:.78rem; opacity:.6; margin-top:6px; text-align:center; }

  #status{
    font-size:.85rem; margin-top:14px; min-height:1.3em; text-align:center; font-weight:600;
  }
  #status.ok{ color:var(--ok); }
  #status.err{ color:var(--danger); }
  #status.info{ color:var(--navy); opacity:.65; font-weight:500; }

  .hidden{ display:none !important; }

  @media (max-width:480px){
    .card{ padding:26px 20px; border-radius:16px; }
  }
</style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <div class="brand-dot"></div>
      <div>
        <h1>Secure Upload</h1>
        <p class="sub">Authenticated, single-endpoint transfer</p>
      </div>
    </div>

    <label class="field-label" for="apiKey">API key or password</label>
    <div class="key-row">
      <input id="apiKey" type="password" placeholder="API key or password" autocomplete="off" spellcheck="false">
      <button type="button" class="key-toggle" id="keyToggle" aria-label="Show key">show</button>
    </div>

    <label class="field-label">Files</label>
    <div class="dropzone" id="dropzone">
      <div class="dz-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 16V4"/>
          <path d="M7 9l5-5 5 5"/>
          <path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/>
        </svg>
      </div>
      <div class="dz-main">Tap to choose, or drag files here</div>
      <div class="dz-sub">Multiple files supported, up to 200&nbsp;MB total</div>
    </div>
    <input type="file" id="fileInput" multiple>

    <div class="file-list" id="fileList"></div>

    <div class="overall" id="overall">
      <div class="overall-track"><div class="overall-fill" id="overallFill"></div></div>
      <div class="overall-label" id="overallLabel">0%</div>
    </div>

    <div class="btn-row">
      <button type="button" class="primary" id="sendBtn" disabled>Upload</button>
      <button type="button" class="cancel" id="cancelBtn">Cancel</button>
    </div>
    <div id="status"></div>
  </div>

<script>
  const fileInput   = document.getElementById('fileInput');
  const dropzone    = document.getElementById('dropzone');
  const fileList    = document.getElementById('fileList');
  const sendBtn     = document.getElementById('sendBtn');
  const cancelBtn   = document.getElementById('cancelBtn');
  const statusEl    = document.getElementById('status');
  const apiKey      = document.getElementById('apiKey');
  const keyToggle   = document.getElementById('keyToggle');
  const overall     = document.getElementById('overall');
  const overallFill = document.getElementById('overallFill');
  const overallLabel= document.getElementById('overallLabel');

  // Each queued file is {id, file, xhr, status: 'queued'|'uploading'|'done'|'failed'|'canceled'}
  let queue = [];
  let uploading = false;
  let nextId = 1;

  const fileIconSvg =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>';
  const removeIconSvg =
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>';
  const okIconSvg =
    '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';
  const failIconSvg =
    '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>';

  function fmtSize(bytes){
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
    return (bytes/1024/1024).toFixed(1) + ' MB';
  }

  function setStatus(msg, kind){
    statusEl.textContent = msg || '';
    statusEl.className = kind || '';
  }

  function updateSendState(){
    const hasFiles = queue.some(q => q.status === 'queued' || q.status === 'failed' || q.status === 'canceled');
    sendBtn.disabled = uploading || !(hasFiles && apiKey.value);
  }

  function renderQueue(){
    fileList.innerHTML = '';
    queue.forEach(item => {
      const row = document.createElement('div');
      row.className = 'file-row' + (item.status === 'done' ? ' done' : item.status === 'failed' ? ' failed' : '');
      row.dataset.id = item.id;

      const icon = document.createElement('div');
      icon.className = 'ficon';
      icon.innerHTML = fileIconSvg;

      const meta = document.createElement('div');
      meta.className = 'meta';
      const nameEl = document.createElement('div');
      nameEl.className = 'name';
      nameEl.textContent = item.file.name;
      const subEl = document.createElement('div');
      subEl.className = 'sub-line' + (item.status === 'failed' ? ' err' : item.status === 'done' ? ' ok' : '');
      subEl.textContent = item.status === 'done' ? 'Uploaded \u00b7 ' + fmtSize(item.file.size)
                         : item.status === 'failed' ? (item.errorMsg || 'Failed')
                         : item.status === 'uploading' ? 'Uploading\u2026'
                         : item.status === 'canceled' ? 'Canceled'
                         : fmtSize(item.file.size);
      meta.appendChild(nameEl);
      meta.appendChild(subEl);

      if (item.status === 'uploading' || item.status === 'queued'){
        const track = document.createElement('div');
        track.className = 'row-track';
        const fill = document.createElement('div');
        fill.className = 'row-fill';
        fill.style.width = (item.pct || 0) + '%';
        track.appendChild(fill);
        meta.appendChild(track);
      }

      const statusIcon = document.createElement('div');
      statusIcon.className = 'status-icon';
      statusIcon.innerHTML = item.status === 'done' ? okIconSvg : item.status === 'failed' ? failIconSvg : '';

      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'remove';
      removeBtn.setAttribute('aria-label', 'Remove file');
      removeBtn.innerHTML = removeIconSvg;
      removeBtn.addEventListener('click', () => removeFile(item.id));
      // don't allow removing a file mid-flight; cancel the whole batch instead
      if (item.status === 'uploading') removeBtn.disabled = true, removeBtn.style.opacity = '0.2', removeBtn.style.cursor = 'default';

      row.appendChild(icon);
      row.appendChild(meta);
      row.appendChild(statusIcon);
      row.appendChild(removeBtn);
      fileList.appendChild(row);
    });
    updateSendState();
  }

  function addFiles(fileListObj){
    for (const f of fileListObj){
      queue.push({ id: nextId++, file: f, status: 'queued', pct: 0 });
    }
    renderQueue();
  }

  function removeFile(id){
    queue = queue.filter(q => q.id !== id);
    renderQueue();
  }

  dropzone.addEventListener('click', () => fileInput.click());

  ['dragenter','dragover'].forEach(evt => {
    dropzone.addEventListener(evt, e => {
      e.preventDefault(); e.stopPropagation();
      dropzone.classList.add('drag');
    });
  });
  ['dragleave','drop'].forEach(evt => {
    dropzone.addEventListener(evt, e => {
      e.preventDefault(); e.stopPropagation();
      dropzone.classList.remove('drag');
    });
  });
  dropzone.addEventListener('drop', e => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length) addFiles(dt.files);
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) addFiles(fileInput.files);
    fileInput.value = ''; // allow re-selecting the same file(s) later
  });

  keyToggle.addEventListener('click', () => {
    const showing = apiKey.type === 'text';
    apiKey.type = showing ? 'password' : 'text';
    keyToggle.textContent = showing ? 'show' : 'hide';
  });
  apiKey.addEventListener('input', updateSendState);

  function updateOverallProgress(){
    const total = queue.length;
    if (!total){ overall.classList.remove('show'); return; }
    const doneCount = queue.filter(q => q.status === 'done').length;
    const failedCount = queue.filter(q => q.status === 'failed' || q.status === 'canceled').length;
    const uploadingItem = queue.find(q => q.status === 'uploading');
    let pct;
    if (doneCount + failedCount === total){
      pct = 100;
    } else {
      const inProgress = uploadingItem ? (uploadingItem.pct || 0) / 100 : 0;
      pct = Math.round(((doneCount + failedCount + inProgress) / total) * 100);
    }
    overallFill.style.width = pct + '%';
    overallLabel.textContent = doneCount + ' / ' + total + ' uploaded' + (failedCount ? ' (' + failedCount + ' failed)' : '');
  }

  async function computeAuthHeaders(){
    const hasSubtle = window.isSecureContext && window.crypto && window.crypto.subtle;
    if (hasSubtle){
      const nonceRes = await fetch('/nonce', { cache: 'no-store' });
      if (!nonceRes.ok) throw new Error('nonce request failed: ' + nonceRes.status);
      const { nonce } = await nonceRes.json();
      const enc = new TextEncoder();
      const cryptoKey = await crypto.subtle.importKey(
        'raw', enc.encode(apiKey.value), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      );
      const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(nonce));
      const authToken = Array.from(new Uint8Array(sigBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      return { 'X-Nonce': nonce, 'X-Auth-Token': authToken };
    }
    // Insecure context (plain http:// on a LAN IP, etc): crypto.subtle is
    // unavailable outside secure contexts. Fall back to the same plain
    // X-API-Key header curl already uses.
    return { 'X-API-Key': apiKey.value };
  }

  function uploadOne(item, headers){
    return new Promise((resolve) => {
      const fd = new FormData();
      fd.append('file', item.file);
      const xhr = new XMLHttpRequest();
      item.xhr = xhr;
      xhr.open('POST', '/upload');
      Object.entries(headers).forEach(([k, v]) => xhr.setRequestHeader(k, v));
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable){
          item.pct = Math.round((e.loaded / e.total) * 100);
          renderQueue();
          updateOverallProgress();
        }
      });
      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300){
          item.status = 'done'; item.pct = 100;
        } else {
          item.status = 'failed'; item.errorMsg = 'HTTP ' + xhr.status;
        }
        resolve();
      });
      xhr.addEventListener('error', () => {
        item.status = 'failed'; item.errorMsg = 'Network error';
        resolve();
      });
      xhr.addEventListener('abort', () => {
        item.status = 'canceled';
        resolve();
      });
      xhr.send(fd);
    });
  }

  let canceledByUser = false;

  sendBtn.addEventListener('click', async () => {
    const pending = queue.filter(q => q.status === 'queued' || q.status === 'failed' || q.status === 'canceled');
    if (!pending.length){ setStatus('Choose at least one file.', 'err'); return; }
    if (!apiKey.value){ setStatus('Enter your API key or password.', 'err'); return; }

    uploading = true;
    canceledByUser = false;
    sendBtn.disabled = true;
    cancelBtn.classList.add('show');
    overall.classList.add('show');
    setStatus('Preparing upload...', 'info');

    pending.forEach(q => { q.status = 'queued'; q.pct = 0; q.errorMsg = null; });
    renderQueue();
    updateOverallProgress();

    try{
      const headers = await computeAuthHeaders();
      setStatus('Uploading...', 'info');

      for (const item of pending){
        if (canceledByUser){ item.status = 'canceled'; renderQueue(); continue; }
        item.status = 'uploading';
        renderQueue();
        await uploadOne(item, headers);
        renderQueue();
        updateOverallProgress();
      }

      const failedCount = queue.filter(q => q.status === 'failed').length;
      const canceledCount = queue.filter(q => q.status === 'canceled').length;
      if (canceledByUser){
        setStatus('Upload canceled.', 'err');
      } else if (failedCount){
        setStatus(failedCount + ' file(s) failed \u2014 check and retry.', 'err');
      } else {
        setStatus('All files uploaded successfully.', 'ok');
      }
    } catch(e){
      setStatus('Error: ' + (e && e.message ? e.message : 'request failed'), 'err');
    }

    uploading = false;
    cancelBtn.classList.remove('show');
    updateSendState();
  });

  cancelBtn.addEventListener('click', () => {
    canceledByUser = true;
    queue.forEach(item => {
      if (item.status === 'uploading' && item.xhr){
        item.xhr.abort();
      } else if (item.status === 'queued'){
        item.status = 'canceled';
      }
    });
    renderQueue();
    setStatus('Canceling...', 'info');
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


_PBKDF2_ITERATIONS = 310_000  # OWASP-recommended floor for PBKDF2-HMAC-SHA256 (2023+)


def pbkdf2_hash(password: bytes, salt: bytes) -> str:
    """Slow, salted hash for the human-typable password specifically.
    API keys are already high-entropy (128+ bits from HMAC-SHA256 output),
    so a fast SHA-256 hash of one is fine -- brute-forcing the hash is
    infeasible regardless of hash speed. A password is not: it depends on
    what the user chose, so if pyu_config.json is ever leaked, the hash
    itself must be slow to make offline guessing impractical."""
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, _PBKDF2_ITERATIONS)
    return dk.hex()


def verify_password_hash(password: bytes, salt_hex: str, stored_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    computed = pbkdf2_hash(password, salt)
    return hmac.compare_digest(computed, stored_hash_hex)


# Common/trivially-weak passwords rejected outright regardless of length.
_COMMON_WEAK_PASSWORDS = {
    "password", "password1", "12345678", "123456789", "1234567890",
    "qwertyui", "letmein1", "admin123", "welcome1", "changeme",
    "iloveyou", "password123", "qwerty123", "abc12345",
}


def password_strength_issue(pw: str) -> str:
    """Returns a human-readable reason the password is too weak, or ''
    if it passes. Checked at set time only -- never logged or stored."""
    if len(pw) < 12:
        return "must be at least 12 characters"
    if pw.lower() in _COMMON_WEAK_PASSWORDS:
        return "too common -- pick something less guessable"
    if pw.isdigit():
        return "can't be all digits"
    if len(set(pw)) <= 3:
        return "too repetitive -- use a wider mix of characters"
    return ""


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


def set_password(data=None):
    """Set/replace a human-typable password. Stored differently from API
    keys: verification uses a slow, salted PBKDF2 hash (pw_hash/pw_salt)
    instead of fast SHA-256, since a password's security depends on what
    the user chose rather than raw entropy -- if pyu_config.json ever
    leaks, a slow hash makes offline guessing far less practical. Still
    keeps an encrypted copy (salt/enc) for the browser's HMAC challenge,
    same as keys."""
    if data is None:
        data = load_config()
        if data is None:
            print("No pyu_config.json found. Run with -i first.")
            sys.exit(1)

    import getpass
    while True:
        pw1 = getpass.getpass("New password (min 12 chars): ")
        issue = password_strength_issue(pw1)
        if issue:
            print(f"Password rejected: {issue}. Try again.")
            continue
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("Passwords didn't match. Try again.")
            continue
        break

    server_secret = base64.b64decode(data["server_secret_b64"])
    salt_b64, enc_b64 = encrypt_for_storage(pw1.encode(), server_secret)

    pw_salt = os.urandom(16)
    pw_hash = pbkdf2_hash(pw1.encode(), pw_salt)

    # remove any existing password entry, then add the new one
    data["keys"] = [k for k in data["keys"] if not k.get("is_password")]
    entry = {
        "id": secrets.token_hex(4),
        "pw_hash": pw_hash,
        "pw_salt": pw_salt.hex(),
        "salt": salt_b64,
        "enc": enc_b64,
        "created": int(_now()),
        "is_password": True,
    }
    data["keys"].append(entry)
    save_config(data)
    print("\nPassword set. It can now be used in place of an API key on the web upload page.")
    print(f"key id: {entry['id']} (revoke with -r {entry['id']} same as any key)\n")


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
    presented_bytes = presented.encode()
    presented_hash = sha256_hex(presented_bytes)
    ok = False
    for entry in data["keys"]:
        if entry.get("is_password"):
            if "pw_hash" in entry and "pw_salt" in entry:
                if verify_password_hash(presented_bytes, entry["pw_salt"], entry["pw_hash"]):
                    ok = True
        elif hmac.compare_digest(entry.get("hash", ""), presented_hash):
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
_nonce_lock = threading.Lock()
_NONCE_TTL = 60      # seconds
_NONCE_MAX = 500     # hard cap so a nonce-request flood can't grow memory unbounded


def issue_nonce() -> str:
    now = _now()
    with _nonce_lock:
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
    with _nonce_lock:
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
    with _rate_lock:
        hits = [t for t in _rate_state.get(ip, []) if t > window_start]
        hits.append(now)
        _rate_state[ip] = hits
        return len(hits) > RATE_LIMIT_MAX


_AUTH_FAIL_WINDOW = 60     # seconds
_AUTH_FAIL_MAX = 5         # max failed-auth attempts per IP per window (tightened
                           # now that a lower-entropy password credential can exist)


def auth_fail_limited(ip: str) -> bool:
    """Stricter limit specifically on failed-auth attempts, separate from the
    general request rate limit -- slows down key-guessing / brute force."""
    now = _now()
    window_start = now - _AUTH_FAIL_WINDOW
    with _auth_fail_lock:
        hits = [t for t in _auth_fail_state.get(ip, []) if t > window_start]
        return len(hits) >= _AUTH_FAIL_MAX


def record_auth_failure(ip: str):
    now = _now()
    with _auth_fail_lock:
        hits = [t for t in _auth_fail_state.get(ip, []) if t > now - _AUTH_FAIL_WINDOW]
        hits.append(now)
        _auth_fail_state[ip] = hits


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
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'")

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
        this server has no reason to ever need to support. Also rejects
        duplicate Content-Length headers with conflicting values, since
        self.headers.get() silently returns only the first occurrence and
        would otherwise hide a smuggling attempt using a second header."""
        te = self.headers.get("Transfer-Encoding", "")
        if te:
            return False  # this server never supports Transfer-Encoding at all

        cl_values = self.headers.get_all("Content-Length")
        if cl_values:
            distinct = set(v.strip() for v in cl_values)
            if len(distinct) > 1:
                return False  # conflicting Content-Length headers -- smuggling attempt
            try:
                if int(cl_values[0]) < 0:
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

        if auth_fail_limited(client_ip):
            time.sleep(0.5)
            self._deny(429)
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
            record_auth_failure(client_ip)
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
            files = parse_multipart_files(body, content_type)
            if not files:
                self._deny(400)
                return
            if len(files) > MAX_FILES_PER_UPLOAD:
                self._deny(400)
                return

            os.makedirs(UPLOAD_DIR, exist_ok=True)
            try:
                os.chmod(UPLOAD_DIR, 0o700)
            except Exception:
                pass

            stored = []
            for filename, file_bytes in files:
                if not filename:
                    continue
                fname = safe_filename(filename)
                dest = os.path.join(UPLOAD_DIR, fname)
                with open(dest, "wb") as out:
                    out.write(file_bytes)
                os.chmod(dest, 0o600)
                stored.append(fname)
                self.log_message("upload ok from %s -> %s", client_ip, fname)

            if not stored:
                self._deny(400)
                return

            self._ok({"status": "ok", "stored_as": stored, "count": len(stored)})
        except Exception:
            self._deny(400)


def daemonize(log_path):
    """Classic double-fork so the server keeps running after the terminal closes."""
    if not hasattr(os, "fork"):
        print("Background mode (-d) needs os.fork(), which isn't available on")
        print("this platform. Run without -d instead (foreground).")
        sys.exit(1)
    try:
        if os.fork() > 0:
            sys.exit(0)
        os.setsid()
        if os.fork() > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Could not daemonize (fork failed: {e}). Running in the foreground instead.")
        return
    sys.stdout.flush()
    sys.stderr.flush()
    log_fd = open(log_path, "a+")
    os.dup2(log_fd.fileno(), sys.stdout.fileno())
    os.dup2(log_fd.fileno(), sys.stderr.fileno())
    devnull = open(os.devnull, "r")
    os.dup2(devnull.fileno(), sys.stdin.fileno())


def run(port):
    try:
        os.makedirs(UPLOAD_DIR, exist_ok=True)
    except PermissionError:
        print(f"Permission denied creating upload directory: {UPLOAD_DIR}")
        print("Set a writable location with the PYU_UPLOAD_DIR environment variable, e.g.:")
        print(f'  PYU_UPLOAD_DIR="$HOME/pyu-uploads" python3 {os.path.basename(__file__)} -p {port}')
        sys.exit(1)
    except OSError as e:
        print(f"Could not create upload directory {UPLOAD_DIR}: {e}")
        sys.exit(1)
    try:
        os.chmod(UPLOAD_DIR, 0o700)
    except Exception:
        pass
    try:
        server = ThreadingHTTPServer((HOST, port), Handler)
    except OSError as e:
        if e.errno == 98:  # EADDRINUSE
            print(f"Port {port} is already in use. Pick another with -p, or stop")
            print(f"whatever else is listening on it (e.g. an old pyu.py instance).")
        elif e.errno == 13:  # EACCES
            print(f"Permission denied binding port {port}. Ports below 1024 need")
            print("elevated privileges on most systems -- try a port above 1024.")
        else:
            print(f"Could not bind {HOST}:{port} -- {e}")
        sys.exit(1)
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


def _run_ok(cmd, **kw) -> bool:
    """Like _run, but returns True/False based on the exit code, so callers
    can't silently sail past a failed step."""
    r = _run(cmd, **kw)
    return r.returncode == 0


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
        if not shutil.which("cloudflared"):
            print("dnf install did not result in a `cloudflared` binary on PATH.")
            return False
        return True

    if mgr == "apt":
        arch = platform.machine()
        deb_arch = "amd64" if "x86_64" in arch else ("arm64" if "aarch64" in arch or "arm" in arch else "amd64")
        deb_url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{deb_arch}.deb"
        deb_path = "/tmp/cloudflared.deb"
        if not _run_ok(["curl", "-fsSL", "-o", deb_path, deb_url]):
            print(f"Could not download {deb_url}. Check your network connection.")
            return False
        _run(["sudo", "dpkg", "-i", deb_path])
        if not shutil.which("cloudflared"):
            print("dpkg install did not result in a `cloudflared` binary on PATH.")
            print("Try: sudo apt-get install -f   (to resolve missing dependencies)")
            return False
        return True

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
    if not _run_ok(maybe_sudo(["systemctl", "enable", "--now", "cloudflared"])):
        print("`systemctl enable --now cloudflared` failed. Check with:")
        print("  sudo systemctl status cloudflared")
        print("  sudo journalctl -u cloudflared -e")
        return False
    print("Service 'cloudflared' enabled and started via systemd.")
    print("Check status with:  systemctl status cloudflared")
    print("Check logs with:    journalctl -u cloudflared -f")
    return True


def register_service_termux(config_yml):
    """Termux has no systemd; it uses runit via the termux-services package."""
    if not shutil.which("sv-enable"):
        print("Installing termux-services (provides runit-based service management)...")
        if not _run_ok(["pkg", "install", "-y", "termux-services"]):
            print("Could not install termux-services. Falling back to a plain")
            print("background process (won't survive a reboot or crash-restart).")
        elif not shutil.which("sv-enable"):
            print("termux-services installed but sv-enable still not on PATH.")
            print("You may need to restart your Termux session, then re-run -c.")
            print("Falling back to a plain background process for now.")

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
        enable_ok = _run_ok(["sv-enable", "cloudflared"])
        up_ok = _run_ok(["sv", "up", "cloudflared"])
        if not (enable_ok and up_ok):
            print("sv-enable/sv up reported an error. Check with: sv status cloudflared")
            return False
        print("Service 'cloudflared' registered and started via termux-services (runit).")
        print("Check status with:  sv status cloudflared")
        print("Restart with:       sv restart cloudflared")
        print("NOTE: start the Termux:Boot app / enable 'Start services on boot' in")
        print("      Termux settings so this survives a device reboot, and run")
        print("      `termux-wake-lock` so Android doesn't kill it in the background.")
        return True

    print("termux-services unavailable; falling back to a plain background process.")
    log_path = os.path.join(SCRIPT_DIR, "cloudflared.log")
    try:
        with open(log_path, "a") as logf:
            subprocess.Popen(
                ["cloudflared", "--config", config_yml, "tunnel", "run", TUNNEL_NAME],
                stdout=logf, stderr=logf, stdin=subprocess.DEVNULL, start_new_session=True,
            )
    except Exception as e:
        print(f"Could not start cloudflared in the background: {e}")
        return False
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
    try:
        with open(log_path, "a") as logf:
            subprocess.Popen(
                ["cloudflared", "--config", config_yml, "tunnel", "run", TUNNEL_NAME],
                stdout=logf, stderr=logf, stdin=subprocess.DEVNULL, start_new_session=True,
            )
    except Exception as e:
        print(f"Could not start cloudflared in the background: {e}")
        return False
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
    if not domain:
        print("A domain is required to route DNS. Aborting.")
        sys.exit(1)
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
    if not _run_ok(maybe_sudo(["mkdir", "-p", etc_dir])):
        print(f"Could not create {etc_dir}. Check permissions and retry. Aborting.")
        sys.exit(1)
    if not is_termux() and os.geteuid() != 0:
        _run(["sudo", "chown", "-R", os.environ.get("USER", "root"), etc_dir])

    cert_path = os.path.join(etc_dir, "cert.pem")
    creds_path = os.path.join(etc_dir, f"{TUNNEL_NAME}-creds.json")
    config_yml = os.path.join(etc_dir, "config.yml")

    env = os.environ.copy()
    env["TUNNEL_ORIGIN_CERT"] = cert_path

    # 1) Authorize (opens a browser link; user approves in the Cloudflare dashboard).
    # Skip re-auth if we already have a valid cert from a previous run.
    if os.path.exists(cert_path):
        print("Step 1/5: existing cert.pem found, skipping re-authorization.")
    else:
        print("\nStep 1/5: authorize with Cloudflare (approve the link that opens/prints below)...")
        _run(["cloudflared", "tunnel", "--origincert", cert_path, "login"], env=env)
        if not os.path.exists(cert_path):
            print("Authorization did not complete (no cert.pem found). Aborting.")
            sys.exit(1)

    # 2) Create the tunnel. `cloudflared tunnel create` exits non-zero if a
    # tunnel with this name already exists -- that's expected on a re-run,
    # not a failure, as long as we can still find its credentials file.
    print("Step 2/5: creating tunnel...")
    create_result = _run(["cloudflared", "tunnel", "--origincert", cert_path,
                           "--credentials-file", creds_path,
                           "create", TUNNEL_NAME], env=env)
    tunnel_already_existed = create_result.returncode != 0

    if not os.path.exists(creds_path):
        # fall back to wherever cloudflared actually put it (~/.cloudflared),
        # covering both the "already existed" case and any path mismatch.
        default_dir = os.path.expanduser("~/.cloudflared")
        found = None
        if os.path.exists(default_dir):
            candidates = [f for f in os.listdir(default_dir) if f.endswith(".json") and f != "cert.pem"]
            if candidates:
                # newest credentials file, in case there are several tunnels
                candidates.sort(key=lambda f: os.path.getmtime(os.path.join(default_dir, f)), reverse=True)
                found = os.path.join(default_dir, candidates[0])
        if not found:
            if tunnel_already_existed:
                print(f"Tunnel '{TUNNEL_NAME}' already exists, but its credentials file")
                print("could not be located automatically. If you know where it lives,")
                print(f"copy it to {creds_path} and re-run. Otherwise delete the tunnel")
                print(f"first (cloudflared tunnel delete {TUNNEL_NAME}) and re-run this wizard.")
            else:
                print("Could not locate tunnel credentials file after creation. Aborting.")
            sys.exit(1)
        if not _run_ok(maybe_sudo(["cp", found, creds_path])):
            print(f"Could not copy credentials into {creds_path}. Aborting.")
            sys.exit(1)

    tunnel_id = ""
    try:
        with open(creds_path) as f:
            tunnel_id = json.load(f).get("TunnelID", "")
    except Exception:
        pass

    # 3) Route DNS: point hostname -> tunnel. Also idempotent-ish: cloudflared
    # errors if the exact record already points here, which is fine -- but a
    # genuine conflict (record exists pointing elsewhere) needs a human to see it.
    print("Step 3/5: creating DNS record...")
    dns_result = _run(["cloudflared", "tunnel", "--origincert", cert_path,
                        "route", "dns", TUNNEL_NAME, hostname], env=env)
    if dns_result.returncode != 0:
        print(f"\nWarning: DNS route step reported an error for '{hostname}'.")
        print("This is often harmless on a re-run (record already correct), but if")
        print(f"'{hostname}' doesn't resolve after this finishes, check the Cloudflare")
        print("DNS dashboard for a conflicting record and remove it, then re-run -c.\n")

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
    if not _run_ok(maybe_sudo(["mv", tmp_cfg, config_yml])):
        print(f"Could not write {config_yml}. Check permissions. Aborting.")
        sys.exit(1)
    print(f"Wrote {config_yml}")

    # keep a copy of key paths in pyu_config.json for reference
    data["cloudflared_config"] = config_yml
    data["cloudflared_hostname"] = hostname
    save_config(data)

    # 5) Register + start as a real service (systemd or Termux runit)
    print("Step 5/5: registering cloudflared as a background service...")
    service_ok = register_cloudflared_service(config_yml)

    if service_ok:
        print(f"\nDone. Your endpoint should be reachable at: https://{hostname}/")
    else:
        print(f"\nTunnel and DNS are configured for https://{hostname}/, but the")
        print("background service registration reported a problem above -- fix that")
        print("and start cloudflared manually, or re-run this wizard once it's resolved.")
    print(f"Now start pyu itself, e.g.:  python3 pyu.py -d -p {port}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="pyu.py", add_help=True)
    ap.add_argument("-i", action="store_true", help="init: create config + first API key")
    ap.add_argument("-f", action="store_true", help="with -i, force-wipe existing config")
    ap.add_argument("-k", action="store_true", help="issue an additional API key")
    ap.add_argument("-w", action="store_true", help="set/replace the web-page password")
    ap.add_argument("-r", metavar="KEY_ID", help="revoke a key by its id")
    ap.add_argument("-p", type=int, default=PORT, help="listen port (default 8820)")
    ap.add_argument("-d", action="store_true", help="daemonize: run detached in background")
    ap.add_argument("-c", action="store_true", help="Cloudflare wizard: install, auth, tunnel, DNS, config, start")
    args = ap.parse_args()

    if args.i:
        init_config(force=args.f)
    elif args.k:
        add_new_key()
    elif args.w:
        set_password()
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
