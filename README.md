# pyu — Python Upload

Drop-anywhere, dependency-free upload endpoint that only your key can talk
to. Point it at Cloudflare with one command and you have a private,
locked-down file drop reachable from anywhere — no server admin required.

A single-file, dependency-free Python HTTP server that exposes one
API-key-protected upload endpoint, with an optional wizard that stands up
a Cloudflare Tunnel for you. Built for Termux (Android) but runs on any
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
- **API keys, never stored raw** — only `SHA-256(key)` is written to
  disk. A full disk leak does not hand over a usable key.
- **Timing-safe auth** — `hmac.compare_digest` for key checks, plus a
  fixed delay on failed auth to slow brute-forcing.
- **Per-IP rate limiting** — 20 requests / 10s by default.
- **Randomized storage filenames** — the client's filename is never
  trusted; only a whitelisted extension is kept, name is randomized.
- **Locked-down permissions** — config `600`, upload dir `700`, saved
  files `600`.
- **Simple web upload page** — cream/white background, Noto Sans, navy +
  gold accent. Tries to auto-open the file picker on load; falls back to
  a single button when the browser blocks that (most do, by design). The
  page never puts your raw API key on the wire — see
  [Web page auth](#security-notes) below.
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

- Python 3.8+
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

### 2. (Optional) Set up a public URL with Cloudflare

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

### 3. Run the server

```bash
python3 pyu.py -d
```

`-d` detaches it so it survives closing the terminal (logs →
`pyu.log`). Drop `-d` to run it in the foreground instead.

On Termux, also run `termux-wake-lock` so Android doesn't kill the
process — that's outside this script's control.

### 4. Upload

**From a browser:** visit `https://<sub>.<domain>/`, pick a file, paste
your API key, hit Upload.

**From the CLI:**

```bash
curl -X POST https://<sub>.<domain>/upload \
     -H "X-API-Key: <your-key>" \
     -F "file=@/path/to/file"
```

---

## Managing keys

```bash
python3 pyu.py -k            # issue another key
python3 pyu.py -r <key_id>   # revoke one key by its id
```

Each key has its own id (printed when issued, and visible in
`pyu_config.json`), so you can hand different keys to different trusted
clients and revoke one without affecting the others.

---

## CLI reference

| Flag        | Meaning                                                        |
|-------------|------------------------------------------------------------------|
| `-i`        | Init: create config + first API key (prompts for domain once)   |
| `-f`        | Force, used with `-i` to wipe an existing config                |
| `-k`        | Issue an additional API key                                     |
| `-r <ID>`   | Revoke a key by its id                                           |
| `-p <N>`    | Port to listen on (default `820`)                                |
| `-d`        | Daemonize: detach and keep running after the terminal closes     |
| `-c`        | Cloudflare wizard: install → auth → tunnel → DNS → config → start |
| `-h`        | Help                                                              |

---

## Configuration

Edit the constants near the top of `pyu.py`:

| Variable            | Default                                      | Meaning                          |
|---------------------|-----------------------------------------------|-----------------------------------|
| `PORT`              | `820`                                         | Listen port                       |
| `HOST`              | `0.0.0.0`                                     | Listen address                    |
| `UPLOAD_DIR`        | `/storage/emulated/0/Android/endpoint`        | Where uploads are saved           |
| `MAX_UPLOAD_BYTES`  | `200 * 1024 * 1024` (200 MB)                  | Hard cap per upload               |
| `RATE_LIMIT_WINDOW` | `10` seconds                                  | Rate-limit window                 |
| `RATE_LIMIT_MAX`    | `20`                                          | Max requests per IP per window    |
| `TUNNEL_NAME`       | `pyu-tunnel`                                  | Name used for the Cloudflare tunnel |

> **Termux path note:** the correct storage path is
> `/storage/emulated/0/Android/endpoint`, not `/storage/0/emulated/0/...`,
> which doesn't exist on Android.

---

## Exposing it publicly

`pyu.py` itself speaks **plain HTTP only**. TLS must be terminated in
front of it — either by the `-c` Cloudflare wizard above, or your own:

- `ngrok`
- `nginx` + `certbot`
- any other TLS-terminating reverse proxy or tunnel

**Never** expose the raw port directly to the internet without TLS in
front of it — the API key would travel in clear text. Prefer a short,
random subdomain over a predictable word so a scanner that doesn't know
the hostname can't reach the server at all.

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

---

## Files this creates

| Path                                          | Contents                                    | Perms   |
|-------------------------------------------------|------------------------------------------------|---------|
| `pyu_config.json`                                | server secret, key hashes, domain, subdomain    | `600`   |
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

- **The web page never sends your raw API key over the network.** It
  fetches a one-time nonce (`GET /nonce`), computes
  `HMAC-SHA256(rawKey, nonce)` entirely in the browser using the Web
  Crypto API, and sends only the nonce + that proof to `/upload`. Someone
  intercepting that traffic gets a nonce that's deleted after first use
  and a proof tied only to it — neither is replayable, and neither
  reveals the key. This is on top of, not instead of, TLS in front of the
  server (the `-c` wizard, or your own reverse proxy) — always keep TLS
  in front too. The nonce store is capped and self-cleaning, so a flood
  of `GET /nonce` requests can't be used to exhaust server memory.
- `curl`/API clients can still use the plain `X-API-Key` header — that
  path is meant for trusted server-to-server calls over a connection you
  control, not for a browser on an arbitrary network.
- Treat `pyu_config.json` and everything under `/etc/cloudflared/` (or
  `$PREFIX/etc/cloudflared/` on Termux) like credentials — back them up
  privately, never commit them, never paste them into chat/tickets/logs.
  `pyu_config.json` now also holds a reversibly-encrypted copy of each
  raw key (protected by the server secret in the same file) so the
  challenge-response scheme above can work — this defends against
  network interception, not against someone who already has full read
  access to your server's disk.
- The web page at `/` is unauthenticated by design (it's just the UI);
  the actual `/upload` endpoint still requires a valid `X-API-Key`.
- Browsers generally block a page from opening the file picker without a
  real click — that's a browser security policy, not a bug here. The
  fallback button covers it.
- Rotate keys periodically with `-k` / `-r` rather than reusing one key
  across every trusted client indefinitely.

---

## License

MIT — see `LICENSE`.
