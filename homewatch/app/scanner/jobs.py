"""Scanner job logic and the state machine that emits events.

Two scheduled jobs (wired up in scheduler.py):
  * run_scan_job      — ARP sweep every 60s; insert/update devices, write scan_runs.
  * run_offline_job   — every 30s; mark devices stale for >5 min as offline.

`process_discovery` and `mark_offline` are the pure-ish, testable cores; the
`run_*_job` wrappers add an app context and crash isolation so a transient
failure can't kill the scheduler (DoS resilience — see THREAT_MODEL.md).
"""
import json
import logging
import os
import time
from datetime import timedelta

from ..audit import record_event
from ..extensions import db
from ..models import Device, ScanRun, normalize_mac, utcnow
from .arp_scanner import arp_sweep, detect_subnet, reverse_dns
from .oui_lookup import lookup_vendor
from .ping_monitor import icmp_ping

log = logging.getLogger(__name__)

OFFLINE_AFTER_MINUTES = 5

# Synthetic devices for the 'mock' backend so the app runs without raw sockets.
# Edit HOMEWATCH_MOCK_FILE (JSON list of {"mac","ip"}) to simulate devices
# joining/leaving for a demo — see DEMO.md.
DEFAULT_MOCK_DEVICES: list[tuple[str, str]] = [
    ("aa:bb:cc:00:00:01", "192.168.1.10"),
    ("aa:bb:cc:00:00:02", "192.168.1.11"),
    ("de:ad:be:ef:00:99", "192.168.1.42"),
]


def process_discovery(
    discovered,
    now=None,
    vendor_fn=lookup_vendor,
    hostname_fn=reverse_dns,
) -> int:
    """Apply a batch of discovered (mac, ip) pairs to the DB, emitting events on
    state changes. Returns the count processed. vendor_fn/hostname_fn are
    injectable so tests don't hit the network."""
    now = now or utcnow()
    for raw_mac, ip in discovered:
        mac = normalize_mac(raw_mac)
        device = Device.query.filter_by(mac_address=mac).first()

        if device is None:
            # New device: OUI + reverse DNS resolved at insert time, untrusted.
            vendor = vendor_fn(mac) if vendor_fn else None
            hostname = hostname_fn(ip) if hostname_fn else None
            device = Device(
                mac_address=mac,
                current_ip=ip,
                vendor=vendor,
                hostname=hostname,
                trusted=False,
                status="online",
                first_seen=now,
                last_seen=now,
            )
            db.session.add(device)
            db.session.flush()  # assign device.id for the event FK
            record_event("first_seen", mac, device.id, {"ip": ip, "vendor": vendor})
            continue

        # Known device.
        previous_status = device.status
        if device.current_ip and device.current_ip != ip:
            record_event("ip_changed", mac, device.id, {"old": device.current_ip, "new": ip})
        device.current_ip = ip
        device.last_seen = now
        if previous_status == "offline":
            record_event("came_online", mac, device.id, {"ip": ip})
        device.status = "online"
        # Backfill a hostname we couldn't get before.
        if not device.hostname and hostname_fn:
            resolved = hostname_fn(ip)
            if resolved:
                device.hostname = resolved

    db.session.commit()
    return len(discovered)


def mark_offline(now=None, icmp_confirm=False, ping_fn=icmp_ping) -> int:
    """Mark any non-offline device unseen for >OFFLINE_AFTER_MINUTES as offline.
    `went_offline` is emitted only for an online->offline transition (a device
    that was actually up and vanished) to keep the event timeline meaningful."""
    now = now or utcnow()
    cutoff = now - timedelta(minutes=OFFLINE_AFTER_MINUTES)
    stale = Device.query.filter(
        Device.status != "offline", Device.last_seen < cutoff
    ).all()

    changed = 0
    for device in stale:
        # Optional ICMP rescue: still reachable? refresh instead of flipping.
        if icmp_confirm and device.current_ip and ping_fn(device.current_ip):
            device.last_seen = now
            continue
        previous_status = device.status
        device.status = "offline"
        if previous_status == "online":
            last = device.last_seen.isoformat() if device.last_seen else None
            record_event("went_offline", device.mac_address, device.id, {"last_seen": last})
        changed += 1

    db.session.commit()
    return changed


def mock_discover(config) -> list[tuple[str, str]]:
    """Discovery for the 'mock' backend. Reads HOMEWATCH_MOCK_FILE if set so a
    demo can edit which devices are 'present'; otherwise a fixed sample set."""
    path = os.environ.get("HOMEWATCH_MOCK_FILE")
    if path and os.path.exists(path):
        try:
            with open(path) as fh:
                data = json.load(fh)
            return [(normalize_mac(d["mac"]), d.get("ip", "")) for d in data]
        except Exception:
            log.exception("failed to read mock device file %s", path)
            return []
    return list(DEFAULT_MOCK_DEVICES)


def discover(config) -> list[tuple[str, str]]:
    """Dispatch to the configured discovery backend."""
    if config.get("SCAN_BACKEND") == "scapy":
        subnet = detect_subnet(config.get("HOMEWATCH_SUBNET"))
        log.info("ARP sweep of %s", subnet)
        return arp_sweep(subnet)
    return mock_discover(config)


def run_scan_job(app) -> None:
    """Scheduled ARP-sweep job. Times itself and records a scan_runs row so the
    operator can confirm the scheduler is alive even when nothing changed."""
    with app.app_context():
        try:
            start = time.perf_counter()
            discovered = discover(app.config)
            process_discovery(discovered)
            duration_ms = int((time.perf_counter() - start) * 1000)
            db.session.add(
                ScanRun(
                    scan_time=utcnow(),
                    devices_found=len(discovered),
                    duration_ms=duration_ms,
                )
            )
            db.session.commit()
            log.info("scan complete: %d device(s) in %dms", len(discovered), duration_ms)
        except Exception:
            log.exception("scan job failed")
            db.session.rollback()


def run_offline_job(app) -> None:
    """Scheduled offline-sweep job."""
    with app.app_context():
        try:
            n = mark_offline(icmp_confirm=app.config.get("SCAN_ICMP_CONFIRM", False))
            if n:
                log.info("marked %d device(s) offline", n)
        except Exception:
            log.exception("offline job failed")
            db.session.rollback()
