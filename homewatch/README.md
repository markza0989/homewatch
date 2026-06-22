# HomeWatch

A self-hosted web app that continuously inventories devices on a home LAN,
monitors their online/offline status, and flags new or unknown devices. Built as
a portfolio piece framed around **asset inventory** and **intrusion detection**
(SOC / GRC) — not just "a script that pings things."

> ⚠️ **Authorized use only.** HomeWatch performs active ARP and ICMP discovery.
> Only ever point it at a network you own or have **explicit written permission**
> to scan. Unauthorized scanning may be illegal in your jurisdiction. You are
> responsible for how you use this tool.

---

## What it does

- ARP-sweeps the local subnet every 60s and builds a device asset register
  (MAC, IP, vendor/OUI, hostname, first/last seen).
- Flags any **new or untrusted** device prominently — the core IDS signal.
- Tracks online → offline transitions (5-minute grace) and records a full
  **event timeline** of state changes.
- Keeps a separate **audit log** of admin actions and login attempts.
- Live dashboard (HTMX, auto-refresh every 15s).

## Architecture: two processes, one database

HomeWatch deliberately splits into two processes that share one SQLite DB:

| Process | Entry point | Privilege | Purpose |
|---|---|---|---|
| **Web app** | `wsgi.py` / `run.py` | **Unprivileged** | Flask UI, auth, CRUD, dashboards |
| **Scanner** | `scheduler.py` | **CAP_NET_RAW** | ARP/ICMP sweeps, writes results to DB |

Only the scanner needs raw-socket capability. The web app — which handles all
untrusted input — runs with no special privileges. SQLite runs in WAL mode so
the two processes can read/write concurrently. See **THREAT_MODEL.md** for the
full rationale.

## Prerequisites

- Python 3.11+
- A Linux host for real scanning (Raspberry Pi or always-on box). The `mock`
  backend runs anywhere (macOS/CI) with no privileges — great for development.

## Quick start (development, mock scanner)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into .env as SECRET_KEY

python manage.py init-db
python manage.py create-user admin                         # prompts for a password

# Terminal 1 — web app (http://127.0.0.1:8000)
python run.py
# Terminal 2 — scanner (mock backend by default; synthetic devices appear)
python scheduler.py
```

Log in, and within a second or two the mock devices appear flagged as unknown.

## Real scanning

Set the backend to Scapy and grant the scanner raw-socket capability. **MVP
approach** — `setcap` on the venv's Python binary:

```bash
sudo setcap cap_net_raw,cap_net_admin+ep $(readlink -f .venv/bin/python)
HOMEWATCH_SCAN_BACKEND=scapy python scheduler.py
```

> The trade-off: `setcap` grants the capability to *that python binary globally*,
> so anything it runs can open raw sockets. The production-grade alternative is
> the systemd unit below, which scopes the capability to just the scanner process
> via `AmbientCapabilities` — no global `setcap`. See THREAT_MODEL.md (EoP).

### Finding your subnet

Auto-detected from the primary interface as a /24. To override (e.g. a /23 or a
different interface), set it explicitly:

```bash
ip -o -f inet addr show            # find your address/prefix, e.g. 192.168.1.23/24
# in .env:
HOMEWATCH_SUBNET=192.168.1.0/24
```

## Production (systemd)

```bash
sudo useradd --system --home /opt/homewatch homewatch
sudo cp -r . /opt/homewatch && cd /opt/homewatch
sudo -u homewatch python3 -m venv .venv
sudo -u homewatch .venv/bin/pip install -r requirements.txt
# create .env (with SECRET_KEY, HOMEWATCH_CONFIG=production), init-db, create-user

sudo cp systemd/homewatch-web.service systemd/homewatch-scanner.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now homewatch-web homewatch-scanner
```

Both units are enabled, so the host comes back up automatically after a reboot.
The web unit runs gunicorn unprivileged; the scanner unit holds `CAP_NET_RAW`.

## Configuration

All config comes from `.env` (see `.env.example`).

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | — (required) | Flask session signing key; app refuses to start without it |
| `HOMEWATCH_CONFIG` | `development` | `development` / `production` / `testing` |
| `DATABASE_URL` | `sqlite:///homewatch.db` | DB location (relative paths anchored to project root) |
| `HOMEWATCH_BIND` | `127.0.0.1` | Bind address — see warning below |
| `HOMEWATCH_PORT` | `8000` | Listen port |
| `HOMEWATCH_SUBNET` | auto /24 | Subnet to scan |
| `HOMEWATCH_SCAN_BACKEND` | `mock` | `mock` or `scapy` |
| `HOMEWATCH_ICMP_CONFIRM` | `false` | Optional ICMP rescue before marking offline |

## Security design

Each item below is enforced in code; the threat model documents the residual risk.

- **Privilege separation.** Scanner (raw sockets) and web app (untrusted input)
  are separate processes. The web app never gets `CAP_NET_RAW`; the systemd web
  unit even sets an empty `CapabilityBoundingSet`. MVP uses `setcap`; production
  uses systemd `AmbientCapabilities` scoped to the scanner.
- **Auth.** Passwords hashed with **argon2id** (`argon2-cffi`), with transparent
  rehash on parameter change. Generic "invalid username or password" message —
  no user enumeration.
- **Session cookies.** `HttpOnly`, `SameSite=Lax`, and `Secure` in production
  (off in dev where there's no TLS) — set per config class.
- **CSRF.** Flask-WTF protection on every state-changing form. No exemptions.
  GET-only HTMX partials re-render fresh CSRF tokens for their action forms.
- **Rate limiting.** `/login` is limited to **5 POST attempts per minute per IP**
  (Flask-Limiter); the 6th returns 429. Failed attempts are recorded in the
  audit log with the attempted username and source IP.
- **Audit log.** Every login attempt (success/fail) and admin write action (add,
  trust, rename, delete) is recorded separately from device events. Read-only UI.
- **Input validation.** `friendly_name` capped at 64 chars, `notes` at 1000, MAC
  format validated and normalised on entry. Jinja autoescaping stays on.
- **Network exposure.** Binds to `127.0.0.1` by default. Exposing on the LAN
  requires explicitly setting `HOMEWATCH_BIND=0.0.0.0`. **Never expose HomeWatch
  to the public internet** — front it with a reverse proxy + TLS, ideally a VPN.
- **Secrets.** All via `.env` (gitignored). `.env.example` is committed with no
  real values.

## Tests

```bash
pytest
```

Covers OUI lookup + caching, ARP result parsing, the event-emission state
machine, the auth flow, and `/login` rate limiting.

## Documentation

- **THREAT_MODEL.md** — STRIDE analysis, assets, attacker scope, residual risks.
- **DEMO.md** — a script for demonstrating the tool in an interview or review.

## License / disclaimer

Provided as-is for educational and authorized use only.
