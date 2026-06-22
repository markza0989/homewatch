# HomeWatch — Demo Script

A ~5-minute walkthrough for an interview or a marker. The `mock` backend lets you
run the entire demo on any laptop with no hardware or privileges; notes for a
real LAN demo are included where they differ.

## 0. Before you start

```bash
source .venv/bin/activate
rm -f homewatch.db homewatch.db-wal homewatch.db-shm    # clean slate (optional)
python manage.py init-db
python manage.py create-user admin
```

Open two terminals:

```bash
python run.py          # terminal 1 — web app at http://127.0.0.1:8000
python scheduler.py    # terminal 2 — scanner (mock backend)
```

Log in at http://127.0.0.1:8000 as `admin`.

> **Talking point:** the scanner is a *separate process* from the web app. Only
> it touches raw sockets — the web app runs unprivileged. That's the
> privilege-separation story (see THREAT_MODEL.md, EoP).

## 1. The asset register populates

Within a second or two of the scanner starting, three devices appear in the
table with vendor/IP, and the **"Unknown / untrusted devices"** panel lights up
red at the top. The dashboard auto-refreshes every 15s (HTMX) — no manual reload.

> **Talking point:** every device starts **untrusted**. The panel is the IDS
> signal: anything you haven't vouched for is surfaced prominently.

## 2. A new device appears (the core IDS moment)

Simulate a phone joining the network. Create a mock device file and point the
scanner at it:

```bash
cat > /tmp/devices.json <<'JSON'
[
  {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.10"},
  {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.11"},
  {"mac": "de:ad:be:ef:00:99", "ip": "192.168.1.42"},
  {"mac": "f0:99:bf:11:22:33", "ip": "192.168.1.77"}
]
JSON
# restart the scanner with the file (or set it before starting):
HOMEWATCH_MOCK_FILE=/tmp/devices.json python scheduler.py
```

Within ~60s (one scan cycle), `f0:99:bf:11:22:33` appears in the table and in the
unknown panel with a **NEW / UNTRUSTED** badge.

> **Real LAN version:** plug in a phone you haven't catalogued (or change a known
> device's MAC). Same result, no mock file.

## 3. Trust a device

Click **Trust** on a device in the unknown panel. On the next refresh it leaves
the panel and shows a green *Trusted* badge in the table.

## 4. A device goes offline

Remove a device from `/tmp/devices.json` (delete its line) and let the scanner
run. After the 5-minute grace window, the offline sweep transitions it to
**offline** (grey pill) and records a `went_offline` event.

> For a faster demo, talk through it rather than waiting 5 minutes — or show the
> offline transition you triggered earlier.
>
> **Real LAN version:** unplug a known device and wait.

## 5. The event timeline

Open **Events** in the nav. Show the chronological timeline: `first_seen` when
each device appeared, `marked_trusted` from step 3, `went_offline` from step 4.
Demonstrate the **filters** — pick a single device, or set a date range.

> **Talking point:** this is the "when did this start?" forensic view. Every
> state change is recorded.

## 6. The audit log

Open **Audit**. Show that it captured your `login_success`, any `login_fail`
attempts, and the `device_trusted` action from step 3 — each with a source IP
and timestamp.

Optionally, demonstrate the **rate limit**: log out and submit a wrong password
six times quickly — the 6th returns *"Too many requests"* (HTTP 429), and the
failures show up in the audit log.

> **Talking point:** device events and admin actions are kept in *separate*
> tables. The audit log is read-only — it's evidence.

## 7. Walk through the threat model

Open **THREAT_MODEL.md** and hit the highlights:

- **MAC spoofing is trivial** — be honest about what L2 inventory can and can't
  detect. HomeWatch catches the unsophisticated new device, not a deliberate
  impersonator.
- **Privilege separation** — the `setcap` vs. scoped-`AmbientCapabilities`
  decision, and why the web app holds no capabilities.
- **Residual risks** — single subnet, host-compromise = game over, append-by-
  convention audit log. Knowing what you *don't* defend against is the point.
