# pyu — Python Upload

Drop-anywhere, dependency-free upload endpoint that only your key (or
password) can talk to. Point it at Cloudflare with one command and you
have a private, locked-down file drop reachable from anywhere — no
server admin required.

A single-file, dependency-free Python HTTP server that exposes one
authenticated upload endpoint, with an optional wizard that stands up a
Cloudflare Tunnel for you. Built for Termux (Android) but runs on any
Arch, Fedora, or Debian/Ubuntu box too.

No third-party libraries. No framework. Stdlib only. No domain, tunnel,
or credentials are baked into the script — everything is configured on
first run, on your machine.

---

## Features

- **One route, period** — `POST /upload` (+ `GET /` for the page and
  `GET /nonce` for auth). Every other path/method gets the exact same
  generic 404. Nothing to fingerprint, nothing to scan.
- **Minimal attack surface by construction** — `HEAD`, `OPTIONS`,
  `TRACE`, `PATCH`, and `CONNECT` are all explicitly rejected; requests
  mixing `Transfer-Encoding` with `Content-Length` (a classic
  request-smuggling vector) are rejected outright; every connection has a
  hard socket timeout to blunt slowloris-style stalling; the accept
  backlog is capped so a connection flood can't grow unbounded.
- **Security response headers** on every reply (`X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, a restrictive
  `Content-Security-Policy`) — cheap, and closes off a few classes of
  browser-side attacks against the upload page.
- **Two credential types, both stored safely — but not identically.**
  API keys are auto-generated, high-entropy, and hashed with fast
  SHA-256 (fine, since brute-forcing 128+ bits of random output is
  infeasible regardless of hash speed). The optional human-typable
  **password** (`-w`) is hashed with **PBKDF2-HMAC-SHA256 at 310,000
  iterations** instead — deliberately slow, since a password's strength
  depends on what the user picked, and a leaked config file should not
  make weak-password guessing cheap. Passwords are also checked for
  basic strength at set time (12-char minimum, rejects common/weak
  patterns, all-digit, or overly repetitive strings) before they're
  ever accepted.
- **Timing-safe auth** — `hmac.compare_digest` for all credential checks.
- **Layered rate limiting** — a general per-IP request limit (20 / 10s by
  default), plus a stricter, separate limit specifically on *failed
  auth attempts* (5 / 60s by default, tightened once a lower-entropy
  password credential became possible) to slow down credential guessing
  without throttling normal traffic.
- **Randomized storage filenames** — the client's filename is never
  trusted; only a whitelisted extension is kept, name is randomized.
- **Boundary-safe multipart parsing** — the hand-rolled multipart parser
  locates genuine boundary lines by position rather than a naive
  byte-split, so a large upload whose content incidentally contains a
  boundary-like byte sequence is never silently truncated. Verified
  against 150MB+ of random binary data with zero corruption.
- **Cross-platform upload directory** — auto-detects Termux and only
  uses the Android storage path there; regular Linux gets a normal
  `uploads/` folder next to the script instead of crashing on a
  `/storage` path that doesn't exist off Android. Override with
  `PYU_UPLOAD_DIR` if you want it somewhere else entirely.
- **Locked-down permissions** — config `600`, upload dir `700`, saved
  files `600`.
- **Multi-file upload, with cancel** — select or drag in any number of
  files at once (up to `MAX_FILES_PER_UPLOAD`, default 20, and the usual
  `MAX_UPLOAD_BYTES` combined size cap). Each file gets its own row with
  live progress, a per-file remove button before upload starts, and a
  clear done/failed indicator after. A Cancel button aborts in-flight and
  queued uploads immediately (`XMLHttpRequest.abort()`), and canceled or
  failed files can be resubmitted with one more click on Upload — no need
  to re-pick them. The server also accepts multiple files in a single
  `curl` request via repeated `-F "file=@..."` flags.
- **Redesigned web upload page** — card layout, drag-and-drop file zone
  (tap-to-browse on mobile), live per-file and overall upload progress,
  filename/size preview with a remove button, show/hide toggle on the
  credential field, and color-coded status messages. Fully responsive
  down to small phone widths. The page never puts your raw credential on
  the wire in a secure context — see [Security notes](#security-notes)
  below.
- **One-command Cloudflare Tunnel setup** (`-c`) — detects your OS,
  installs `cloudflared`, authorizes, creates the tunnel, adds the DNS
  record, writes the tunnel config to the **standard `/etc/cloudflared`
  location**, and registers it as a proper background service:
  **systemd** on Arch/Fedora/Debian/Ubuntu, or Termux's **runit**
  (`termux-services`) on Android — so it survives crashes and (with
  Termux:Boot) reboots, instead of running as a bare background process.
- **Background mode** (`-d`) — double-forks so the server survives
  closing the terminal.

---

## Requirements

- Python 3.8+ (tested through 3.14 — no `cgi` module dependency, which
  was removed from the standard library in newer Python versions;
  multipart parsing here is hand-rolled and stdlib-only)
- Termux, or any Linux machine (Arch, Fedora, Debian/Ubuntu and
  derivatives are auto-detected by the `-c` wizard)
- A Cloudflare account + domain already added to Cloudflare, **if** you
  use the `-c` wizard. (You can also front this with your own reverse
  proxy / tunnel instead — see [Exposing it publicly](#exposing-it-publicly).)

---

## Install

```bash
git clone https://github.com/psvineet/pyu.git
cd pyu
```

Nothing to `pip install`.

---

## Quick start

### 1. Initialize

```bash
python3 pyu.py -i
```

You'll be asked for:
- **Your domain** (e.g. `example.com`) — leave blank to configure later.
- **A subdomain** — press Enter and one is generated for you (random,
  unguessable, 4 characters).

Your first API key is printed **once**. Copy it now — only its hash is
ever stored, so a lost key means issuing a new one, not recovering the
old one.

### 2. (Optional) Set a password too

```bash
python3 pyu.py -w
```

Prompts (hidden input) for a password, **minimum 12 characters**,
confirmed twice, and rejected outright if it's a common/weak pattern,
all-digit, or overly repetitive. Unlike API keys, the password itself is
never hashed with plain SHA-256 — it goes through **PBKDF2-HMAC-SHA256
at 310,000 iterations**, a deliberately slow hash, specifically because
a password's real-world strength depends on the human who picked it,
not on generated entropy. It also keeps an encrypted copy for the
browser's challenge-response flow, same as keys, and works as a drop-in
alternative to pasting a long key on the web upload page. It has its own
key id and can be revoked the same way as any key (`-r <id>`).

> A password is still lower-entropy than a generated key by construction
> — the strength checks and slow hash reduce the risk of a leaked config
> being crackable, and the tightened auth-fail rate limit
> (5 attempts / 60s per IP) slows online guessing to a crawl, but they
> don't eliminate the gap. If this endpoint is reachable from the open
> internet, prefer the generated API key for anything you care more
> about, and don't reuse a password from elsewhere.

### 3. (Optional) Set up a public URL with Cloudflare

```bash
python3 pyu.py -c
```

This wizard:
1. Detects your package manager (Termux `pkg`, `pacman`, `dnf`, `apt`)
   and installs `cloudflared` if it's missing.
2. Runs `cloudflared tunnel login` — open the printed link and approve
   the domain in your Cloudflare dashboard.
3. Creates a tunnel named `pyu-tunnel`.
4. Runs `cloudflared tunnel route dns` to point your subdomain at it.
5. Writes the tunnel's `cert.pem`, credentials, and `config.yml` to the
   **standard cloudflared config location**:
   - `/etc/cloudflared/` on Arch, Fedora, Debian/Ubuntu
   - `$PREFIX/etc/cloudflared/` on Termux (Termux has no writable `/etc`)
6. Registers and starts cloudflared as a real background service:
   - **systemd**, if present — via `cloudflared ... service install` +
     `systemctl enable --now cloudflared`
   - **Termux**: installs `termux-services` if needed, writes a runit
     `run` script under `$PREFIX/var/service/cloudflared`, and enables it
     with `sv-enable` / `sv up`
   - Anywhere else: falls back to a detached background process
     (won't auto-restart on reboot — logs to `cloudflared.log`)

If you're on plain Arch, `cloudflared` isn't in the official repos — the
wizard tells you to grab it from the AUR (`yay -S cloudflared`) and
re-run `-c`.

**On Termux**, also enable "Start services on boot" in Termux settings
(and install the separate Termux:Boot app) if you want the tunnel to
survive a device reboot, and run `termux-wake-lock` so Android doesn't
kill it in the background.

### 4. Run the server

```bash
python3 pyu.py -d
```

`-d` detaches it so it survives closing the terminal (logs →
`pyu.log`). Drop `-d` to run it in the foreground instead.

On Termux, also run `termux-wake-lock` so Android doesn't kill the
process — that's outside this script's control.

### 5. Upload

**From a browser:** visit `https://<sub>.<domain>/`, drag in one or more
files (or tap to browse — multi-select works there too), enter your API
key or password, hit Upload. Each file gets its own progress row, plus
an overall progress bar for the whole batch. A **Cancel** button appears
once uploading starts — it stops the in-flight file immediately and
skips any still queued. Canceled or failed files stay in the list and
can be resubmitted with one more click on Upload, no need to re-pick them.

**From the CLI:**

```bash
curl -X POST https://<sub>.<domain>/upload \
     -H "X-API-Key: <your-key>" \
     -F "file=@/path/to/file"
```

Multiple files in one request — repeat the `-F "file=@..."` flag with
the same field name (`file`):

```bash
curl -X POST https://<sub>.<domain>/upload \
     -H "X-API-Key: <your-key>" \
     -F "file=@/path/one.jpg" -F "file=@/path/two.pdf" -F "file=@/path/three.zip"
```

All files in a directory, in one request (bash):

```bash
curl -X POST https://<sub>.<domain>/upload -H "X-API-Key: <your-key>" \
     $(for f in /path/to/dir/*; do printf ' -F file=@%q' "$f"; done)
```

The response's `stored_as` field is always a JSON array of the names
each file was saved under (even for a single file), alongside a `count`.
A single request is capped at `MAX_FILES_PER_UPLOAD` files (default 20)
and the usual `MAX_UPLOAD_BYTES` combined size across all of them.

(Passwords set via `-w` also work in this header, since they're stored
the same way as keys.)

---

## Managing credentials

```bash
python3 pyu.py -k            # issue another API key
python3 pyu.py -w            # set/replace the password
python3 pyu.py -r <key_id>   # revoke one credential (key or password) by its id
```

Each credential has its own id (printed when issued, and visible in
`pyu_config.json`), so you can hand different keys to different trusted
clients — or set one shared password for casual use — and revoke any one
without affecting the others.

---

## CLI reference

| Flag        | Meaning                                                        |
|-------------|------------------------------------------------------------------|
| `-i`        | Init: create config + first API key (prompts for domain once)   |
| `-f`        | Force, used with `-i` to wipe an existing config                |
| `-k`        | Issue an additional API key                                     |
| `-w`        | Set/replace the web-page password                                |
| `-r <ID>`   | Revoke a credential (key or password) by its id                  |
| `-p <N>`    | Port to listen on (default `8820`)                                |
| `-d`        | Daemonize: detach and keep running after the terminal closes     |
| `-c`        | Cloudflare wizard: install → auth → tunnel → DNS → config → start |
| `-h`        | Help                                                              |

---

## Configuration

Edit the constants near the top of `pyu.py`:

| Variable            | Default                                      | Meaning                          |
|---------------------|-----------------------------------------------|-----------------------------------|
| `PORT`              | `8820`                                        | Listen port                       |
| `HOST`              | `0.0.0.0`                                     | Listen address                    |
| `UPLOAD_DIR`        | Termux: `/storage/emulated/0/Android/endpoint`.<br>Everywhere else: `<script dir>/uploads` | Where uploads are saved |
| `MAX_UPLOAD_BYTES`  | `200 * 1024 * 1024` (200 MB)                  | Hard cap on total request size (all files combined) |
| `MAX_FILES_PER_UPLOAD` | `20`                                       | Max number of files accepted in one request |
| `RATE_LIMIT_WINDOW` | `10` seconds                                  | General per-IP rate-limit window  |
| `RATE_LIMIT_MAX`    | `20`                                          | Max requests per IP per window    |
| `TUNNEL_NAME`       | `pyu-tunnel`                                  | Name used for the Cloudflare tunnel |

Failed-auth-specific limiting (`_AUTH_FAIL_WINDOW` / `_AUTH_FAIL_MAX`,
default 60s / 5 attempts) is defined near the auth code further down the
file, separate from the general request rate limit above. `_PBKDF2_ITERATIONS`
(default 310,000, the current OWASP-recommended floor) controls password
hash cost and is defined next to `pbkdf2_hash()`.

> **Upload directory is now platform-aware.** The script auto-detects
> Termux (via the `PREFIX` environment variable) and only uses the
> Android storage path there — on Arch/Fedora/Debian/Ubuntu and other
> regular Linux systems it defaults to an `uploads/` folder next to
> `pyu.py` instead, since `/storage` doesn't exist outside Android and
> attempting to create it fails with a permission error. Override either
> default with the `PYU_UPLOAD_DIR` environment variable:
> ```bash
> PYU_UPLOAD_DIR="$HOME/pyu-uploads" python3 pyu.py
> ```

> **Termux path note:** the correct storage path is
> `/storage/emulated/0/Android/endpoint`, not `/storage/0/emulated/0/...`,
> which doesn't exist on Android.

> **Port note:** low ports (<1024) require elevated privileges on most
> systems and may simply fail to bind on Termux regardless. `8820` is
> the default for a reason — if you change it, pick something above
> 1024, and re-run `-c` (or manually edit `config.yml`) so the tunnel's
> ingress rule points at the new port.

---

## Exposing it publicly

`pyu.py` itself speaks **plain HTTP only**. TLS must be terminated in
front of it — either by the `-c` Cloudflare wizard above, or your own:

- `ngrok`
- `nginx` + `certbot`
- any other TLS-terminating reverse proxy or tunnel

**Never** expose the raw port directly to the internet without TLS in
front of it — credentials would travel in clear text on browsers falling
back to the plain-header path (see [Security notes](#security-notes)).
Prefer a short, random subdomain over a predictable word so a scanner
that doesn't know the hostname can't reach the server at all.

---

## How the API key is generated

```
raw_key = "ep_" + base64url( HMAC-SHA256(server_secret, "issue:" + uuid4 + ":" + timestamp) ) + extra_entropy
```

- `server_secret` — 32 random bytes, generated once at `-i`, stored in
  `pyu_config.json`. Every key issued by this instance is bound to it,
  so keys can't be forged without that secret.
- Only `SHA-256(raw_key)` is ever written to disk. The raw key is shown
  once, at issue time, then discarded server-side.
- Verification compares `SHA-256(presented_key)` against the stored hash
  with a timing-safe comparison (`hmac.compare_digest`).

A password set via `-w` follows the same encrypted-copy path for the
browser challenge, but its verification hash is different by design —
see [Two credential types](#features) above: PBKDF2-HMAC-SHA256 at
310,000 iterations, salted, instead of plain SHA-256. This is
intentional, not an inconsistency: a generated key's entropy makes a
fast hash safe, a human password's doesn't.

---

## Files this creates

| Path                                          | Contents                                    | Perms   |
|-------------------------------------------------|------------------------------------------------|---------|
| `pyu_config.json`                                | server secret, credential hashes (keys + password), domain, subdomain | `600`   |
| `<UPLOAD_DIR>/`                                  | uploaded files, randomized names                | `700` dir / `600` files |
| `pyu.log`                                        | created only with `-d`                          | —       |
| `/etc/cloudflared/cert.pem`¹                     | Cloudflare origin cert, created by `-c`          | root-owned |
| `/etc/cloudflared/pyu-tunnel-creds.json`¹        | tunnel credentials, created by `-c`              | root-owned |
| `/etc/cloudflared/config.yml`¹                   | tunnel ingress config, created by `-c`           | root-owned |
| `/etc/systemd/system/cloudflared.service`        | systemd unit, created by `cloudflared service install` (systemd hosts only) | root-owned |
| `$PREFIX/var/service/cloudflared/run`            | runit service script (Termux only)               | `755`   |
| `cloudflared.log`                                | only created on the non-systemd/non-Termux fallback path | —       |

¹ On Termux this is `$PREFIX/etc/cloudflared/` instead, since Termux has
no writable `/etc`.

**None of these should be committed to git.** See `.gitignore` below.

## Managing the Cloudflare service

**systemd hosts (Arch/Fedora/Debian/Ubuntu):**

```bash
sudo systemctl status cloudflared
sudo systemctl restart cloudflared
sudo journalctl -u cloudflared -f
```

**Termux:**

```bash
sv status cloudflared
sv restart cloudflared
tail -f $PREFIX/var/service/cloudflared/log/main/current 2>/dev/null || cat cloudflared.log
```

Re-running `python3 pyu.py -c` is safe — it reuses the existing tunnel
where possible and rewrites the config/service registration.

---

## .gitignore

```gitignore
pyu_config.json
pyu.log
cloudflared.log
__pycache__/
*.pyc
```

(cloudflared's own files now live under `/etc/cloudflared` — outside
this repo entirely — so there's nothing repo-local to ignore for them.)

---

## Security notes

- **In a secure browser context (HTTPS, or `localhost`), the web page
  never sends your raw credential over the network.** It fetches a
  one-time nonce (`GET /nonce`), computes `HMAC-SHA256(credential,
  nonce)` entirely in the browser using the Web Crypto API, and sends
  only the nonce + that proof to `/upload`. Someone intercepting that
  traffic gets a nonce that's deleted after first use and a proof tied
  only to it — neither is replayable, and neither reveals the
  credential. This is on top of, not instead of, TLS in front of the
  server (the `-c` wizard, or your own reverse proxy) — always keep TLS
  in front too. The nonce store is capped, self-cleaning, and
  thread-safe, so a flood of `GET /nonce` requests can't be used to
  exhaust server memory or race the store.
- **In an insecure context** (plain `http://` on a bare LAN IP, where
  browsers don't expose the Web Crypto API at all), the page
  automatically falls back to sending the plain `X-API-Key` header
  instead of failing outright. This is a deliberate LAN-testing
  convenience, not a recommended production posture — put TLS in front
  before exposing this beyond your own network.
- `curl`/API clients can still use the plain `X-API-Key` header — that
  path is meant for trusted server-to-server calls over a connection you
  control, not for a browser on an arbitrary network.
- **Failed-auth attempts are rate-limited separately and more strictly**
  than general traffic (5 attempts / 60s per IP) to slow down
  credential-guessing without affecting normal upload traffic.
- **Passwords are hashed differently from API keys on purpose.** Keys
  use fast SHA-256 (safe, since they're 128+ bits of generated entropy).
  Passwords use salted PBKDF2-HMAC-SHA256 at 310,000 iterations, plus a
  strength check at set time (12-char minimum, rejects common/weak,
  all-digit, or overly repetitive patterns) — both aimed at making a
  leaked config file's password entry meaningfully harder to crack
  offline than a key entry needs to be.
- Treat `pyu_config.json` and everything under `/etc/cloudflared/` (or
  `$PREFIX/etc/cloudflared/` on Termux) like credentials — back them up
  privately, never commit them, never paste them into chat/tickets/logs.
  `pyu_config.json` now also holds a reversibly-encrypted copy of each
  raw key/password (protected by the server secret in the same file) so
  the challenge-response scheme above can work — this defends against
  network interception, not against someone who already has full read
  access to your server's disk.
- The web page at `/` is unauthenticated by design (it's just the UI);
  the actual `/upload` endpoint still requires a valid credential.
- A password (`-w`) is intentionally lower-entropy than a generated API
  key — convenient for casual/mobile use, but prefer the generated key
  for anything exposed to the open internet.
- Rotate credentials periodically with `-k` / `-w` / `-r` rather than
  reusing one across every trusted client indefinitely.

---

## License

MIT — see `LICENSE`.
