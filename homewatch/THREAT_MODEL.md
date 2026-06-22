# HomeWatch — Threat Model

This document is half the point of the project. It uses **STRIDE** as a loose
structure to reason about what HomeWatch protects, who it defends against, and
what risks are explicitly accepted.

HomeWatch is a defensive asset-inventory and intrusion-detection tool for a
single home LAN. It is **not** a network access control system: it observes and
records, it does not block.

---

## 1. Assets being protected

| Asset | Why it matters |
|---|---|
| **The asset register** (`devices` table) | A map of every device on the network, its vendor, addresses, and when it's present. Sensitive: it reveals what hardware exists and home occupancy patterns. |
| **Admin credentials** (`users` table) | Control of the dashboard. argon2id-hashed; never stored or logged in plaintext. |
| **The audit log** (`audit_log` table) | The record of who did what and which logins were attempted. Its integrity is what makes it useful as evidence. |
| **The event timeline** (`events` table) | The history that lets an operator reconstruct "when did this unknown device first appear?" |

## 2. Attackers

**In scope** (HomeWatch aims to help against these):

- **A curious or malicious housemate** with LAN access who connects an
  unexpected device or tries to reach the dashboard.
- **A rogue IoT device** that joins the network (compromised smart bulb, guest's
  phone with malware) — HomeWatch surfaces it as new/untrusted.
- **An attacker with a foothold on one device** moving laterally — at minimum
  their presence as a known/unknown host is visible, and IP changes are logged.

**Out of scope** (HomeWatch does not defend against these):

- **Physical access to the host** — someone who can read the SQLite file or the
  `.env` off the disk has already won.
- **A state-level actor** with the means to defeat the host OS or supply chain.
- **Attacks from outside the LAN** — HomeWatch binds to loopback by default and
  is not designed to face the internet.

## 3. STRIDE walkthrough

### Spoofing
**MAC spoofing is trivial.** Any attacker can set their NIC's MAC to match a
trusted device, and HomeWatch — which identifies devices *by* MAC — will treat
them as that device. This is a fundamental limit of L2 inventory, not a bug.
HomeWatch's honest value is detecting devices that *don't* bother to spoof
(the common case: a new phone, a default-MAC IoT gadget) and logging IP changes
and re-appearances that a careful operator can correlate. It cannot
authenticate a device. *Auth to the dashboard itself* is protected by argon2id
passwords and a generic login error that prevents username enumeration.

### Tampering
Two surfaces: the **database file** and **inputs**.
- DB file: protected by OS file permissions (run as a dedicated `homewatch`
  user; the systemd units use `ProtectSystem=strict` and a scoped
  `ReadWritePaths`). Anyone who can write the file can rewrite history — this is
  accepted (see Residual risks).
- Inputs: all forms are CSRF-protected and length-capped; MACs are validated and
  normalised; Jinja autoescaping defends the rendered output against stored XSS
  via a malicious device hostname or notes field.
- **Audit log integrity** is *append-only by convention* — the app only ever
  inserts. A truly tamper-evident log (append-only storage, hash chaining, or
  shipping to a separate host) is the production-grade improvement; for a
  single-host home tool we accept convention-level integrity.

### Repudiation
The **audit log** exists specifically to counter repudiation: every login
attempt (success and failure, with attempted username and source IP) and every
admin write action (add, trust, rename, delete) is recorded with a timestamp.
The denormalised `username` on each row means the record survives a user
deletion. Within the trust boundary (an operator who hasn't rooted the host),
actions are attributable.

### Information disclosure
**The asset register is itself sensitive** — it discloses what devices exist and
when the home is occupied. Mitigations: loopback-only binding by default; auth
required on every page (`@login_required`); session cookies are `HttpOnly` +
`SameSite=Lax` + `Secure` in production; secrets live only in a gitignored
`.env`. The README explicitly warns against public-internet exposure without a
reverse proxy and TLS.

### Denial of service
- **Login brute-force**: `/login` is rate-limited to 5 POST/minute/IP (429 on
  the 6th), which also bounds argon2 CPU cost from forced hashing.
- **Scanner crashes**: each scheduled job runs inside a try/except that logs and
  rolls back, so a transient failure (bad packet, DB lock) can't kill the
  scheduler. systemd `Restart=on-failure` recovers a hard crash. A `scan_runs`
  row per sweep lets the operator confirm the scanner is alive.
- A hostile device flooding the LAN with spoofed ARP replies could bloat the
  device table — accepted residual risk for a home-scale tool.

### Elevation of privilege
The **`setcap` decision** is the central EoP trade-off. Scapy needs
`CAP_NET_RAW`. Options considered:
- **(a) MVP — `setcap cap_net_raw,cap_net_admin+ep` on the venv python.** Simple,
  but grants the capability to *that binary globally*: any script it runs gets
  raw sockets. Acceptable for a single-purpose host.
- **(b) Production — separate privileged scanner process.** HomeWatch already
  splits the scanner from the web app. The systemd scanner unit grants
  `CAP_NET_RAW` via `AmbientCapabilities` scoped to just that process, while the
  web unit runs with an **empty `CapabilityBoundingSet`** and `NoNewPrivileges`.
  The web app — the component exposed to untrusted input — therefore cannot open
  raw sockets even if compromised. This is the recommended deployment.

## 4. Residual risks (explicitly accepted)

- **MAC spoofing detection limit.** HomeWatch cannot distinguish a spoofed MAC
  from the genuine device. It detects *unsophisticated* new devices, not a
  deliberate impersonator. Accepted: defeating L2 spoofing needs 802.1X /
  port security, which is out of scope.
- **Single subnet / single broadcast domain.** ARP doesn't cross routers, so
  HomeWatch sees only its own L2 segment. Multi-VLAN scanning is out of scope.
- **Host compromise = game over.** An attacker who roots the host can read the
  `.env`, the DB, and rewrite the audit log. HomeWatch does not defend against
  this; it assumes a trusted host.
- **Audit log is not tamper-evident**, only append-by-convention (see Tampering).
- **No notifications by default.** Detection is pull-based (operator must look at
  the dashboard). Push alerting on new untrusted devices is the Slice 7 option.
