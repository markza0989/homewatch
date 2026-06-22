"""Slice 3 tests: ARP parsing, OUI caching, and event-emitting state machine."""
from datetime import timedelta


from app.extensions import db
from app.models import Device, Event, utcnow
from app.scanner import jobs, oui_lookup
from app.scanner.arp_scanner import parse_arp_responses


# --- ARP result parsing ----------------------------------------------------

class _FakeReply:
    def __init__(self, hwsrc, psrc):
        self.hwsrc = hwsrc
        self.psrc = psrc


def test_parse_arp_responses_normalises_mac():
    answered = [
        (object(), _FakeReply("AA:BB:CC:DD:EE:FF", "192.168.1.5")),
        (object(), _FakeReply("a4-83-e7-1b-2c-9d", "192.168.1.6")),
    ]
    assert parse_arp_responses(answered) == [
        ("aa:bb:cc:dd:ee:ff", "192.168.1.5"),
        ("a4:83:e7:1b:2c:9d", "192.168.1.6"),
    ]


# --- OUI lookup caching ----------------------------------------------------

def test_lookup_vendor_caches_per_oui(monkeypatch):
    oui_lookup.clear_cache()
    calls = []

    def fake_raw(mac):
        calls.append(mac)
        return "ACME Corp"

    monkeypatch.setattr(oui_lookup, "_raw_lookup", fake_raw)

    # Two MACs sharing an OUI prefix -> underlying lookup hit once.
    assert oui_lookup.lookup_vendor("aa:bb:cc:00:00:01") == "ACME Corp"
    assert oui_lookup.lookup_vendor("aa:bb:cc:99:99:99") == "ACME Corp"
    assert len(calls) == 1


def test_lookup_vendor_caches_misses(monkeypatch):
    oui_lookup.clear_cache()
    calls = []

    def fake_raw(mac):
        calls.append(mac)
        return None

    monkeypatch.setattr(oui_lookup, "_raw_lookup", fake_raw)
    assert oui_lookup.lookup_vendor("de:ad:be:ef:00:01") is None
    assert oui_lookup.lookup_vendor("de:ad:be:ef:00:02") is None
    assert len(calls) == 1  # the None result is cached too


# --- State machine: process_discovery -------------------------------------

# No-op vendor/hostname resolvers so tests never touch the network.
_NO_VENDOR = lambda mac: None  # noqa: E731
_NO_HOST = lambda ip: None  # noqa: E731


def _discover(app, pairs, **kw):
    with app.app_context():
        jobs.process_discovery(
            pairs, vendor_fn=_NO_VENDOR, hostname_fn=_NO_HOST, **kw
        )


def test_new_device_inserted_untrusted_with_first_seen_event(app):
    _discover(app, [("AA:BB:CC:00:00:01", "192.168.1.10")])
    with app.app_context():
        d = Device.query.one()
        assert d.mac_address == "aa:bb:cc:00:00:01"
        assert d.trusted is False
        assert d.status == "online"
        assert d.current_ip == "192.168.1.10"
        ev = Event.query.filter_by(event_type="first_seen").one()
        assert ev.device_id == d.id
        assert ev.mac_address == d.mac_address


def test_known_device_updates_last_seen_without_spurious_events(app):
    _discover(app, [("aa:bb:cc:00:00:01", "192.168.1.10")])
    _discover(app, [("aa:bb:cc:00:00:01", "192.168.1.10")])  # same IP again
    with app.app_context():
        # Only the original first_seen — a steady-state re-sighting emits nothing.
        assert Event.query.count() == 1
        assert Event.query.filter_by(event_type="first_seen").count() == 1


def test_offline_device_coming_back_emits_came_online(app):
    _discover(app, [("aa:bb:cc:00:00:01", "192.168.1.10")])
    with app.app_context():
        db.session.get(Device, Device.query.one().id)
        d = Device.query.one()
        d.status = "offline"
        db.session.commit()
    _discover(app, [("aa:bb:cc:00:00:01", "192.168.1.10")])
    with app.app_context():
        assert Event.query.filter_by(event_type="came_online").count() == 1
        assert Device.query.one().status == "online"


def test_ip_change_emits_ip_changed_event(app):
    _discover(app, [("aa:bb:cc:00:00:01", "192.168.1.10")])
    _discover(app, [("aa:bb:cc:00:00:01", "192.168.1.55")])
    with app.app_context():
        ev = Event.query.filter_by(event_type="ip_changed").one()
        details = ev.details
        assert "192.168.1.10" in details and "192.168.1.55" in details
        assert Device.query.one().current_ip == "192.168.1.55"


# --- Offline sweep: mark_offline ------------------------------------------

def test_mark_offline_flips_stale_online_device_and_emits_event(app):
    with app.app_context():
        old = utcnow() - timedelta(minutes=10)
        d = Device(
            mac_address="aa:bb:cc:00:00:01",
            status="online",
            current_ip="192.168.1.10",
            first_seen=old,
            last_seen=old,
        )
        db.session.add(d)
        db.session.commit()

        changed = jobs.mark_offline()
        assert changed == 1
        assert db.session.get(Device, d.id).status == "offline"
        assert Event.query.filter_by(event_type="went_offline").count() == 1


def test_mark_offline_ignores_recently_seen_devices(app):
    with app.app_context():
        d = Device(
            mac_address="aa:bb:cc:00:00:02",
            status="online",
            last_seen=utcnow(),  # just seen
        )
        db.session.add(d)
        db.session.commit()
        assert jobs.mark_offline() == 0
        assert db.session.get(Device, d.id).status == "online"


def test_mark_offline_icmp_confirm_rescues_reachable_device(app):
    with app.app_context():
        old = utcnow() - timedelta(minutes=10)
        d = Device(
            mac_address="aa:bb:cc:00:00:03",
            status="online",
            current_ip="192.168.1.20",
            first_seen=old,
            last_seen=old,
        )
        db.session.add(d)
        db.session.commit()

        # Pretend the device answers ICMP -> it should be kept online.
        changed = jobs.mark_offline(icmp_confirm=True, ping_fn=lambda ip: True)
        assert changed == 0
        assert db.session.get(Device, d.id).status == "online"
